import ast
import asyncio
import hashlib
import json
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from substrateinterface import Keypair

from chutes_miner_cli.constants import (
    MINER_HEADER,
    NONCE_HEADER,
    SIGNATURE_HEADER,
    SIG_VERSION_HEADER,
    SIG_VERSION_V2,
    VALIDATOR_HEADER,
)
from chutes_miner_cli.cli import _lock_or_unlock_server
from chutes_miner_cli.util import sign_management_request, sign_request


_TEST_SEED = "0xe031170f32b4cda05df2f3cf6bc8d7687b683bbce23d9fa960c0b3fc21641b8a"


@pytest.fixture
def signing_hotkey(tmp_path):
    keypair = Keypair.create_from_seed(_TEST_SEED)
    path = tmp_path / "hotkey.json"
    path.write_text(
        json.dumps(
            {
                "ss58Address": keypair.ss58_address,
                "secretSeed": _TEST_SEED,
            }
        )
    )
    return path, keypair


def _assert_signature(headers, keypair, method, path, body_sha256=""):
    nonce = headers[NONCE_HEADER]
    timestamp, separator, random_suffix = nonce.partition(".")
    assert separator == "."
    assert int(timestamp) > 0
    assert re.fullmatch(r"[0-9a-f]{16}", random_suffix)
    message = (
        f"v2:{keypair.ss58_address}:{keypair.ss58_address}:{method}:{path}:{nonce}:{body_sha256}"
    )
    assert keypair.verify(message, bytes.fromhex(headers[SIGNATURE_HEADER]))


def test_management_signer_binds_exact_request_identity_method_and_path(signing_hotkey):
    hotkey_path, keypair = signing_hotkey
    target = "/servers/node-a"

    headers, payload = sign_management_request(
        str(hotkey_path),
        method="DELETE",
        path=target,
    )

    assert payload is None
    assert headers[MINER_HEADER] == keypair.ss58_address
    assert headers[VALIDATOR_HEADER] == keypair.ss58_address
    assert headers[SIG_VERSION_HEADER] == SIG_VERSION_V2
    _assert_signature(headers, keypair, "DELETE", target)


def test_management_signer_binds_exact_body_bytes(signing_hotkey):
    hotkey_path, keypair = signing_hotkey
    target = "/management/action"

    headers, payload = sign_management_request(
        str(hotkey_path),
        method="POST",
        path=target,
        payload={"action": "retire", "generation": 7},
    )

    body_sha256 = hashlib.sha256(payload.encode()).hexdigest()
    _assert_signature(headers, keypair, "POST", target, body_sha256)


def test_legacy_signer_remains_available_for_read_only_management(signing_hotkey):
    hotkey_path, _ = signing_hotkey

    headers, _ = sign_request(str(hotkey_path), purpose="management")

    assert SIG_VERSION_HEADER not in headers
    assert "." not in headers[NONCE_HEADER]


def test_v2_signer_requires_complete_management_context(signing_hotkey):
    hotkey_path, _ = signing_hotkey

    with pytest.raises(ValueError, match="method and path"):
        sign_request(
            str(hotkey_path),
            management=True,
            method="DELETE",
        )
    with pytest.raises(ValueError, match="management requests"):
        sign_request(
            str(hotkey_path),
            remote=True,
            method="DELETE",
            path="/servers/node-a",
        )


@pytest.mark.parametrize(
    ("function_name", "method"),
    (
        ("add_node", "POST"),
        ("delete_node", "DELETE"),
        ("purge_deployments", "DELETE"),
        ("purge_deployment", "DELETE"),
        ("purge_server", "DELETE"),
        ("_lock_or_unlock_server", "GET"),
    ),
)
def test_state_changing_cli_producers_use_only_v2_management_signer(
    function_name,
    method,
):
    source_path = (
        Path(__file__).resolve().parents[2] / "src/chutes-miner-cli/chutes_miner_cli/cli.py"
    )
    tree = ast.parse(source_path.read_text())
    function = next(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name
    )
    signer_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"sign_request", "sign_management_request"}
    ]

    assert signer_calls
    assert {call.func.id for call in signer_calls} == {"sign_management_request"}
    for call in signer_calls:
        keywords = {keyword.arg: keyword.value for keyword in call.keywords}
        assert isinstance(keywords.get("method"), ast.Constant)
        assert keywords["method"].value == method
        assert "path" in keywords


@pytest.mark.parametrize(
    ("lock", "action"),
    ((True, "lock"), (False, "unlock")),
)
def test_lock_and_unlock_producers_sign_exact_v2_target(
    signing_hotkey,
    lock,
    action,
):
    hotkey_path, keypair = signing_hotkey
    response = MagicMock()
    response.json = AsyncMock(return_value={"name": "node-a", "locked": lock})
    response_context = MagicMock()
    response_context.__aenter__ = AsyncMock(return_value=response)
    response_context.__aexit__ = AsyncMock(return_value=None)
    session = MagicMock()
    session.get.return_value = response_context
    session_context = MagicMock()
    session_context.__aenter__ = AsyncMock(return_value=session)
    session_context.__aexit__ = AsyncMock(return_value=None)
    target = f"/servers/node-a/{action}"

    with (
        patch(
            "chutes_miner_cli.cli.aiohttp.ClientSession",
            return_value=session_context,
        ),
        patch("builtins.print"),
    ):
        asyncio.run(
            _lock_or_unlock_server(
                lock,
                "node-a",
                str(hotkey_path),
                "http://127.0.0.1:32000/",
            )
        )

    session.get.assert_called_once()
    request_url = session.get.call_args.args[0]
    headers = session.get.call_args.kwargs["headers"]
    assert request_url == f"http://127.0.0.1:32000{target}"
    _assert_signature(headers, keypair, "GET", target)


def test_maintenance_lock_producer_uses_exact_v2_management_signer():
    source_path = (
        Path(__file__).resolve().parents[2]
        / "src/chutes-miner-cli/chutes_miner_cli/tee_maintenance.py"
    )
    tree = ast.parse(source_path.read_text())
    target_assignment = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "lock_target" for target in node.targets
        )
    )
    assert ast.unparse(target_assignment.value) == "f'/servers/{name}/lock'"

    lock_assignment = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Tuple)
            and isinstance(target.elts[0], ast.Name)
            and target.elts[0].id == "lock_headers"
            for target in node.targets
        )
    )

    assert isinstance(lock_assignment.value, ast.Call)
    assert isinstance(lock_assignment.value.func, ast.Name)
    assert lock_assignment.value.func.id == "sign_management_request"
    keywords = {keyword.arg: keyword.value for keyword in lock_assignment.value.keywords}
    assert isinstance(keywords.get("method"), ast.Constant)
    assert keywords["method"].value == "GET"
    assert isinstance(keywords.get("path"), ast.Name)
    assert keywords["path"].id == "lock_target"

    legacy_local_signers = []
    for node in ast.walk(tree):
        if (
            not isinstance(node, ast.Call)
            or not isinstance(node.func, ast.Name)
            or node.func.id != "sign_request"
        ):
            continue
        call_keywords = {keyword.arg: keyword.value for keyword in node.keywords}
        remote = call_keywords.get("remote")
        if not isinstance(remote, ast.Constant) or remote.value is not True:
            legacy_local_signers.append(node)
    assert legacy_local_signers == []
