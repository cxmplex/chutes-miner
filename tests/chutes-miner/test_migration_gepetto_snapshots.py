import ast
from pathlib import Path
import re
from typing import Optional

import pytest

from chutes_miner.api.exceptions import DeploymentFailure


REPO_ROOT = Path(__file__).resolve().parents[2]
SNAPSHOTS = (
    REPO_ROOT / "ansible/k3s/tasks/migration/files/gepetto-k3s.py",
    REPO_ROOT / "ansible/k3s/tasks/migration/files/gepetto-microk8s.py",
)
LEGACY_SOURCE_FIELDS = {"code", "filename"}


def test_migration_playbook_installs_both_gepetto_snapshots():
    migrate_playbook = (REPO_ROOT / "ansible/k3s/playbooks/migrate.yml").read_text()
    verification_tasks = (REPO_ROOT / "ansible/k3s/tasks/migration/verify-chutes.yml").read_text()

    assert "gepetto-k3s.py" in migrate_playbook
    assert "gepetto-k3s.py" in verification_tasks
    assert "gepetto-microk8s.py" in verification_tasks


def _parse_snapshot(path: Path) -> tuple[str, ast.Module]:
    source = path.read_text()
    return source, ast.parse(source, filename=str(path))


def _function(tree: ast.Module, name: str) -> ast.AsyncFunctionDef | ast.FunctionDef:
    return next(
        node
        for node in tree.body
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == name
    )


def _method(tree: ast.Module, name: str) -> ast.AsyncFunctionDef | ast.FunctionDef:
    gepetto = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Gepetto"
    )
    return next(
        node
        for node in gepetto.body
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == name
    )


def _call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


def _version_guard(path: Path):
    _, tree = _parse_snapshot(path)
    selected_nodes = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name)
            and target.id in {"MIN_SUPPORTED_CHUTES_VERSION", "_CHUTES_VERSION_RE"}
            for target in node.targets
        ):
            selected_nodes.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name == "require_supported_chutes_version":
            selected_nodes.append(node)

    namespace = {
        "DeploymentFailure": DeploymentFailure,
        "Optional": Optional,
        "re": re,
    }
    module = ast.fix_missing_locations(ast.Module(body=selected_nodes, type_ignores=[]))
    exec(compile(module, str(path), "exec"), namespace)
    return namespace["require_supported_chutes_version"]


@pytest.mark.parametrize("snapshot", SNAPSHOTS, ids=lambda path: path.stem)
@pytest.mark.parametrize(
    "version",
    [None, "", "garbage", "0.3.60", "0.3.60.rc1", "0.3.61garbage"],
)
def test_migration_snapshot_rejects_unsupported_runtime(snapshot, version):
    with pytest.raises(DeploymentFailure, match="minimum supported version is 0.3.61"):
        _version_guard(snapshot)(version, "chute-1")


@pytest.mark.parametrize("snapshot", SNAPSHOTS, ids=lambda path: path.stem)
@pytest.mark.parametrize("version", ["0.3.61", "0.3.61.rc1", "0.3.61-rc1", "0.3.62"])
def test_migration_snapshot_accepts_supported_runtime_boundary(snapshot, version):
    _version_guard(snapshot)(version, "chute-1")


@pytest.mark.parametrize("snapshot", SNAPSHOTS, ids=lambda path: path.stem)
def test_migration_snapshot_has_no_legacy_source_delivery_path(snapshot):
    source, tree = _parse_snapshot(snapshot)
    forbidden_uses = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in LEGACY_SOURCE_FIELDS:
            forbidden_uses.append((node.lineno, f"attribute {node.attr}"))
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Constant)
            and node.slice.value in LEGACY_SOURCE_FIELDS
        ):
            forbidden_uses.append((node.lineno, f"subscript {node.slice.value}"))
        elif isinstance(node, ast.keyword) and node.arg in LEGACY_SOURCE_FIELDS:
            forbidden_uses.append((node.lineno, f"keyword {node.arg}"))
        elif isinstance(node, ast.Call) and _call_name(node) in {
            "create_code_config_map",
            "delete_code",
        }:
            forbidden_uses.append((node.lineno, f"call {_call_name(node)}"))

    assert forbidden_uses == []
    assert "chute-code-" not in source

    legacy_fields = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "LEGACY_SOURCE_FIELDS"
            for target in node.targets
        )
    )
    assert isinstance(legacy_fields.value, ast.Call)
    assert ast.literal_eval(legacy_fields.value.args[0]) == LEGACY_SOURCE_FIELDS

    remote_parser = _method(tree, "_remote_chute_values")
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "LEGACY_SOURCE_FIELDS"
        and node.func.attr == "intersection"
        for node in ast.walk(remote_parser)
    )

    stream_refresh = _method(tree, "_remote_refresh_objects")
    assert any(argument.arg == "forbidden_keys" for argument in stream_refresh.args.args)
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "intersection"
        and any(
            isinstance(candidate, ast.Name) and candidate.id == "forbidden_keys"
            for candidate in ast.walk(node.func.value)
        )
        for node in ast.walk(stream_refresh)
    )

    run = _method(tree, "run")
    awaited_calls = [
        _call_name(node.value.value)
        for node in run.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Await)
        and isinstance(node.value.value, ast.Call)
    ]
    assert awaited_calls.index("purge_legacy_source_config_maps") < awaited_calls.index("reconcile")

    if snapshot.name == "gepetto-k3s.py":
        run_calls = {
            _call_name(node): node.lineno
            for node in ast.walk(run)
            if isinstance(node, ast.Call)
            and _call_name(node) in {"run_validator_migrations", "purge_legacy_source_config_maps"}
        }
        assert run_calls["run_validator_migrations"] < run_calls["purge_legacy_source_config_maps"]
    else:
        purge = _function(tree, "purge_legacy_source_config_maps")
        purge_calls = {_call_name(node) for node in ast.walk(purge) if isinstance(node, ast.Call)}
        assert {"list_namespaced_config_map", "delete_namespaced_config_map"} <= purge_calls
        assert any(
            isinstance(node, ast.Constant) and node.value == "chutes/code=true"
            for node in ast.walk(purge)
        )


@pytest.mark.parametrize("snapshot", SNAPSHOTS, ids=lambda path: path.stem)
def test_migration_snapshot_requires_exact_launch_context(snapshot):
    source, tree = _parse_snapshot(snapshot)
    get_launch_token = _method(tree, "get_launch_token")
    assert any(
        isinstance(node, ast.Call) and _call_name(node) == "require_supported_chutes_version"
        for node in ast.walk(get_launch_token)
    )
    assert not any(
        isinstance(node, ast.Return)
        and (
            node.value is None or isinstance(node.value, ast.Constant) and node.value.value is None
        )
        for node in ast.walk(get_launch_token)
    )
    assert "expected exactly token and config_id" in source
    assert "token and config_id must be non-empty strings" in source
    assert any(
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Call)
        and _call_name(node.left) == "set"
        and len(node.left.args) == 1
        and isinstance(node.left.args[0], ast.Name)
        and node.left.args[0].id == "payload"
        and any(
            isinstance(comparator, ast.Set)
            and {ast.literal_eval(item) for item in comparator.elts} == {"token", "config_id"}
            for comparator in node.comparators
        )
        for node in ast.walk(get_launch_token)
    )

    deploy_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _call_name(node) == "deploy_chute"
    ]
    assert deploy_calls
    for call in deploy_calls:
        keywords = {keyword.arg: keyword.value for keyword in call.keywords}
        for field in ("token", "config_id"):
            value = keywords[field]
            assert isinstance(value, ast.Subscript)
            assert isinstance(value.value, ast.Name)
            assert value.value.id == "launch_token"
            assert isinstance(value.slice, ast.Constant)
            assert value.slice.value == field

    assert not any(
        isinstance(node, (ast.If, ast.IfExp))
        and any(
            isinstance(candidate, ast.Name) and candidate.id == "launch_token"
            for candidate in ast.walk(node.test)
        )
        for node in ast.walk(tree)
    )
    assert not any(
        isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
        and node.name in {"announce_deployment", "activate", "activator"}
        for node in ast.walk(tree)
    )

    reconcile = _method(tree, "reconcile")
    assert any(
        isinstance(node, ast.Call) and _call_name(node) == "require_supported_chutes_version"
        for node in ast.walk(reconcile)
    )
