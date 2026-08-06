import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from starlette.requests import Request as StarletteRequest
from substrateinterface import Keypair
import yaml

import chutes_common.auth as auth_module
from chutes_common.auth import authorize
from chutes_common.constants import (
    MINER_HEADER,
    NONCE_HEADER,
    SIGNATURE_HEADER,
    SIG_VERSION_HEADER,
    SIG_VERSION_V2,
    VALIDATOR_HEADER,
)
from chutes_miner.api.config import Settings
from chutes_miner.api.config import settings as api_settings
from chutes_miner.api.database import get_db_session
from chutes_miner.api.deployment.router import router as deployment_router
from chutes_miner.api.main import app as assembled_miner_app
from chutes_miner.api.main import request_body_checksum
from chutes_miner.api.management_auth import destructive_management_authorization
from chutes_miner.api.server.router import router as server_router
from chutes_miner_cli.util import sign_management_request


_TEST_SEED = "0xe031170f32b4cda05df2f3cf6bc8d7687b683bbce23d9fa960c0b3fc21641b8a"
_REPO_ROOT = Path(__file__).resolve().parents[2]
_STACK_IMAGE = f"chutes.local/seedless-stack@sha256:{'a' * 64}"
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_DESIGNATED_STATE_CHANGING_GETS = frozenset(
    {
        "/servers/{id_or_name}/lock",
        "/servers/{id_or_name}/unlock",
    }
)
_EXPECTED_STATE_CHANGING_ROUTES = frozenset(
    {
        ("POST", "/servers/"),
        ("DELETE", "/servers/{id_or_name}"),
        ("DELETE", "/servers/{id_or_name}/deployments"),
        ("DELETE", "/deployments/purge"),
        ("DELETE", "/deployments/{deployment_id}"),
        (
            "POST",
            "/deployments/teardown-conflicts/{operation_kind}/{operation_id}/requeue",
        ),
        (
            "POST",
            "/deployments/teardown-conflicts/{operation_kind}/{operation_id}/resolve",
        ),
        ("GET", "/servers/{id_or_name}/lock"),
        ("GET", "/servers/{id_or_name}/unlock"),
    }
)


@pytest.fixture
def signing_identity(monkeypatch, tmp_path):
    keypair = Keypair.create_from_seed(_TEST_SEED)
    hotkey_path = tmp_path / "hotkey.json"
    hotkey_path.write_text(
        json.dumps(
            {
                "ss58Address": keypair.ss58_address,
                "secretSeed": _TEST_SEED,
            }
        )
    )
    monkeypatch.setattr(auth_module.miner_settings, "miner_ss58", keypair.ss58_address)
    auth_module.get_keypair.cache_clear()
    consumed = set()

    def consume(signer, nonce, ttl_seconds):
        assert 1 <= ttl_seconds <= 30
        key = (signer, nonce)
        if key in consumed:
            return False
        consumed.add(key)
        return True

    monkeypatch.setattr(auth_module, "_consume_v2_nonce", consume)
    yield hotkey_path, keypair
    auth_module.get_keypair.cache_clear()


def _request(method, target, body=b""):
    path, separator, query = target.partition("?")
    request = StarletteRequest(
        {
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": query.encode() if separator else b"",
            "headers": [],
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
        }
    )
    request.state.body_sha256 = hashlib.sha256(body).hexdigest() if body else None
    return request


def _authorize(headers, *, method, target, body=b""):
    dependency = authorize(
        allow_miner=True,
        allow_validator=False,
        purpose="management",
        require_v2=True,
    )
    return dependency(
        _request(method, target, body),
        validator=headers.get(VALIDATOR_HEADER),
        miner=headers.get(MINER_HEADER),
        nonce=headers.get(NONCE_HEADER),
        signature=headers.get(SIGNATURE_HEADER),
        sig_version=headers.get(SIG_VERSION_HEADER),
        attested_session=headers.get("X-Chutes-Attested-Session"),
    )


def _v1_headers(keypair, purpose="management", body=b""):
    nonce = str(int(time.time()))
    signed_value = hashlib.sha256(body).hexdigest() if body else purpose
    message = f"{keypair.ss58_address}:{keypair.ss58_address}:{nonce}:{signed_value}"
    return {
        MINER_HEADER: keypair.ss58_address,
        VALIDATOR_HEADER: keypair.ss58_address,
        NONCE_HEADER: nonce,
        SIGNATURE_HEADER: keypair.sign(message.encode()).hex(),
    }


def _v2_headers(keypair, nonce, *, method="DELETE", target="/servers/node-a", body=b""):
    body_sha256 = hashlib.sha256(body).hexdigest() if body else ""
    message = f"v2:{keypair.ss58_address}:{keypair.ss58_address}:{method}:{target}:{nonce}:{body_sha256}"
    return {
        MINER_HEADER: keypair.ss58_address,
        VALIDATOR_HEADER: keypair.ss58_address,
        NONCE_HEADER: nonce,
        SIGNATURE_HEADER: keypair.sign(message.encode()).hex(),
        SIG_VERSION_HEADER: SIG_VERSION_V2,
    }


def _database(deployment=None):
    result = MagicMock()
    result.unique.return_value = result
    result.scalars.return_value = result
    result.all.return_value = [] if deployment is None else [deployment]
    result.scalar_one_or_none.return_value = deployment
    database = MagicMock()
    database.execute = AsyncMock(return_value=result)
    database.commit = AsyncMock()
    database.refresh = AsyncMock()
    return database


def _test_app(database):
    application = FastAPI()
    application.middleware("http")(request_body_checksum)
    application.include_router(server_router, prefix="/servers")
    application.include_router(deployment_router, prefix="/deployments")
    application.dependency_overrides[get_db_session] = lambda: database
    return application


def _close_task(coroutine):
    coroutine.close()
    return MagicMock()


def _runtime_state_changing_routes(application):
    routes = []
    for route in application.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods or ():
            if method in _STATE_CHANGING_METHODS or (
                method == "GET" and route.path in _DESIGNATED_STATE_CHANGING_GETS
            ):
                routes.append((method, route.path, route))
    return routes


def _dependency_calls(dependant):
    for dependency in dependant.dependencies:
        yield dependency.call
        yield from _dependency_calls(dependency)


def _unprotected_state_changing_routes(application):
    return [
        (method, path)
        for method, path, route in _runtime_state_changing_routes(application)
        if destructive_management_authorization
        not in set(_dependency_calls(route.dependant))
    ]


def test_assembled_app_state_changing_route_inventory_is_complete_and_protected():
    routes = _runtime_state_changing_routes(assembled_miner_app)

    assert {(method, path) for method, path, _ in routes} == set(
        _EXPECTED_STATE_CHANGING_ROUTES
    )
    assert _unprotected_state_changing_routes(assembled_miner_app) == []


def test_runtime_inventory_detects_dynamic_and_included_route_evasions():
    application = FastAPI()
    included = APIRouter()

    async def mutation():
        return None

    included.api_route("/via-api-route", methods=["PATCH"])(mutation)
    included.add_api_route("/alias", mutation, methods=["DELETE"])
    application.include_router(included, prefix="/included")
    application.add_api_route("/via-add-api-route", mutation, methods=["PUT"])

    assert set(_unprotected_state_changing_routes(application)) == {
        ("PATCH", "/included/via-api-route"),
        ("DELETE", "/included/alias"),
        ("PUT", "/via-add-api-route"),
    }


def _render_management_v2_setting(value):
    if shutil.which("helm") is not None:
        command = [
            "helm",
            "template",
            "chutes-miner",
            str(_REPO_ROOT / "charts/chutes-miner"),
            "-f",
            str(_REPO_ROOT / "charts/chutes-miner/values.yaml"),
            "--set-string",
            "minerCredentials.ownerSs58=fixture-owner",
            "--set-string",
            f"seedlessStack.image={_STACK_IMAGE}",
            "--set-string",
            f"minerApi.requireV2ManagementSignatures={value}",
        ]
    elif shutil.which("docker") is not None and (
        subprocess.run(
            ["docker", "image", "inspect", "alpine/helm:latest"],
            check=False,
            capture_output=True,
        ).returncode
        == 0
    ):
        command = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{_REPO_ROOT}:/workspace:ro",
            "-w",
            "/workspace",
            "alpine/helm:latest",
            "template",
            "chutes-miner",
            "charts/chutes-miner",
            "-f",
            "charts/chutes-miner/values.yaml",
            "--set-string",
            "minerCredentials.ownerSs58=fixture-owner",
            "--set-string",
            f"seedlessStack.image={_STACK_IMAGE}",
            "--set-string",
            f"minerApi.requireV2ManagementSignatures={value}",
        ]
    else:
        pytest.skip("neither Helm nor the local alpine/helm image is available")
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )
    return result


@pytest.mark.parametrize("value", ("false", "true"))
def test_chart_renders_explicit_management_v2_cutover(value):
    result = _render_management_v2_setting(value)
    assert result.returncode == 0, result.stderr
    documents = [
        document
        for document in yaml.safe_load_all(result.stdout)
        if isinstance(document, dict)
    ]
    deployment = next(
        document
        for document in documents
        if document.get("kind") == "Deployment"
        and document.get("metadata", {}).get("name") == "api"
    )
    container = next(
        item
        for item in deployment["spec"]["template"]["spec"]["containers"]
        if item["name"] == "api"
    )
    environment = {item["name"]: item for item in container["env"]}
    assert environment["CHUTES_REQUIRE_V2_MANAGEMENT_SIGNATURES"] == {
        "name": "CHUTES_REQUIRE_V2_MANAGEMENT_SIGNATURES",
        "value": value,
    }


def test_chart_rejects_invalid_management_v2_cutover_value():
    result = _render_management_v2_setting("invalid")
    assert result.returncode != 0
    assert "must be explicitly true or false" in result.stderr


def test_exact_v2_request_is_accepted_once(signing_identity):
    hotkey_path, _ = signing_identity
    target = "/servers/node-a"
    headers, _ = sign_management_request(
        str(hotkey_path),
        method="DELETE",
        path=target,
    )

    assert _authorize(headers, method="DELETE", target=target) is None
    with pytest.raises(HTTPException) as replay:
        _authorize(headers, method="DELETE", target=target)
    assert replay.value.status_code == 401


@pytest.mark.parametrize(
    ("age_seconds", "expected_ttl"),
    ((0, 30), (1, 29), (29, 1)),
)
def test_v2_replay_ttl_covers_entire_remaining_acceptance_window(
    signing_identity,
    monkeypatch,
    age_seconds,
    expected_ttl,
):
    _, keypair = signing_identity
    now = 2_000_000_000
    nonce = f"{now - age_seconds}.0123456789abcdef"
    consumed = MagicMock(return_value=True)
    monkeypatch.setattr(auth_module.time, "time", lambda: now)
    monkeypatch.setattr(auth_module, "_consume_v2_nonce", consumed)

    assert (
        _authorize(
            _v2_headers(keypair, nonce),
            method="DELETE",
            target="/servers/node-a",
        )
        is None
    )
    consumed.assert_called_once_with(
        keypair.ss58_address,
        nonce,
        ttl_seconds=expected_ttl,
    )


@pytest.mark.parametrize(
    "suffix",
    (
        "0123456789abcde",
        "0123456789abcdef0",
        "0123456789abcdeF",
        "0123456789abcdeg",
        "01234567-9abcdef",
        "01234567.9abcdef",
        "",
    ),
)
def test_v2_nonce_rejects_malformed_random_suffix(
    signing_identity,
    monkeypatch,
    suffix,
):
    _, keypair = signing_identity
    now = 2_000_000_000
    nonce = f"{now}.{suffix}"
    consumed = MagicMock(return_value=True)
    monkeypatch.setattr(auth_module.time, "time", lambda: now)
    monkeypatch.setattr(auth_module, "_consume_v2_nonce", consumed)

    with pytest.raises(HTTPException) as rejected:
        _authorize(
            _v2_headers(keypair, nonce),
            method="DELETE",
            target="/servers/node-a",
        )

    assert rejected.value.status_code == 401
    consumed.assert_not_called()


def test_v2_nonce_rejects_noncanonical_timestamp(signing_identity, monkeypatch):
    _, keypair = signing_identity
    now = 2_000_000_000
    nonce = f"0{now}.0123456789abcdef"
    consumed = MagicMock(return_value=True)
    monkeypatch.setattr(auth_module.time, "time", lambda: now)
    monkeypatch.setattr(auth_module, "_consume_v2_nonce", consumed)

    with pytest.raises(HTTPException) as rejected:
        _authorize(
            _v2_headers(keypair, nonce),
            method="DELETE",
            target="/servers/node-a",
        )

    assert rejected.value.status_code == 401
    consumed.assert_not_called()


def test_v2_nonce_rejects_future_timestamp_without_consuming_cache(
    signing_identity,
    monkeypatch,
):
    _, keypair = signing_identity
    now = 2_000_000_000
    nonce = f"{now + 1}.0123456789abcdef"
    consumed = MagicMock(return_value=True)
    monkeypatch.setattr(auth_module.time, "time", lambda: now)
    monkeypatch.setattr(auth_module, "_consume_v2_nonce", consumed)

    with pytest.raises(HTTPException) as rejected:
        _authorize(
            _v2_headers(keypair, nonce),
            method="DELETE",
            target="/servers/node-a",
        )

    assert rejected.value.status_code == 401
    consumed.assert_not_called()


def test_v2_nonce_rejects_exact_expiration_boundary_without_consuming_cache(
    signing_identity,
    monkeypatch,
):
    _, keypair = signing_identity
    now = 2_000_000_000
    nonce = f"{now - 30}.0123456789abcdef"
    consumed = MagicMock(return_value=True)
    monkeypatch.setattr(auth_module.time, "time", lambda: now)
    monkeypatch.setattr(auth_module, "_consume_v2_nonce", consumed)

    with pytest.raises(HTTPException) as rejected:
        _authorize(
            _v2_headers(keypair, nonce),
            method="DELETE",
            target="/servers/node-a",
        )

    assert rejected.value.status_code == 401
    consumed.assert_not_called()


@pytest.mark.parametrize("mutation", ("method", "path", "body", "identity"))
def test_v2_request_mutation_is_rejected_before_nonce_consumption(
    signing_identity,
    mutation,
):
    hotkey_path, _ = signing_identity
    target = "/servers/node-a"
    document = {"reason": "operator-retirement"}
    headers, payload = sign_management_request(
        str(hotkey_path),
        method="DELETE",
        path=target,
        payload=document,
    )
    body = payload.encode()

    mutated_headers = dict(headers)
    method = "DELETE"
    request_target = target
    request_body = body
    if mutation == "method":
        method = "POST"
    elif mutation == "path":
        request_target = "/servers/node-b"
    elif mutation == "body":
        request_body = b'{"reason":"different"}'
    else:
        mutated_headers[VALIDATOR_HEADER] = "5WrongRequestIdentity"

    with pytest.raises(HTTPException) as rejected:
        _authorize(
            mutated_headers,
            method=method,
            target=request_target,
            body=request_body,
        )
    assert rejected.value.status_code == 401

    assert _authorize(headers, method="DELETE", target=target, body=body) is None


@pytest.mark.parametrize(
    ("method", "path"),
    (
        ("POST", "/servers/"),
        ("DELETE", "/servers/node-a"),
        ("DELETE", "/servers/node-a/deployments"),
        ("DELETE", "/deployments/purge"),
        ("DELETE", "/deployments/deployment-a"),
        ("GET", "/servers/node-a/lock"),
        ("GET", "/servers/node-a/unlock"),
    ),
)
def test_every_state_changing_management_route_rejects_v1(
    signing_identity,
    method,
    path,
    monkeypatch,
):
    _, keypair = signing_identity
    monkeypatch.setattr(api_settings, "require_v2_management_signatures", True)
    application = _test_app(_database())
    payload_document = (
        {
            "name": "node-a",
            "validator": keypair.ss58_address,
            "hourly_cost": 1.0,
            "gpu_short_ref": "h100",
        }
        if method == "POST"
        else None
    )
    body = json.dumps(payload_document).encode() if payload_document else b""

    response = TestClient(application).request(
        method,
        path,
        headers=_v1_headers(keypair, body=body),
        content=body,
    )

    assert response.status_code == 401


@pytest.mark.parametrize(
    ("method", "path", "expected_status"),
    (
        ("POST", "/servers/", 501),
        ("DELETE", "/servers/node-a", 200),
        ("DELETE", "/servers/node-a/deployments", 200),
        ("DELETE", "/deployments/purge", 200),
        ("DELETE", "/deployments/deployment-a", 200),
        ("GET", "/servers/node-a/lock", 200),
        ("GET", "/servers/node-a/unlock", 200),
    ),
)
def test_every_state_changing_management_route_accepts_v2(
    signing_identity,
    method,
    path,
    expected_status,
    monkeypatch,
):
    monkeypatch.setattr(api_settings, "require_v2_management_signatures", True)
    monkeypatch.setattr(api_settings, "gpu_tee_only", True)
    hotkey_path, keypair = signing_identity
    deployment = SimpleNamespace(
        deployment_id="deployment-a",
        chute_id="chute-a",
        server_id="server-1",
        chute=SimpleNamespace(name="chute-a"),
        server=SimpleNamespace(name="node-a"),
        gpus=[],
    )
    database = _database(deployment)
    application = _test_app(database)
    server = SimpleNamespace(server_id="server-1", name="node-a")
    teardown = SimpleNamespace(
        request=AsyncMock(return_value="operation-1"),
        run=AsyncMock(return_value=True),
        request_parent=AsyncMock(return_value="operation-1"),
        run_parent=AsyncMock(return_value=True),
    )
    gepetto = SimpleNamespace(teardown=teardown)
    if method == "POST":
        payload_document = {
            "name": "node-a",
            "validator": keypair.ss58_address,
            "hourly_cost": 1.0,
            "gpu_short_ref": "h100",
        }
    elif method == "DELETE":
        payload_document = {"reason": "signature-contract-regression"}
    else:
        payload_document = None
    headers, payload = sign_management_request(
        str(hotkey_path),
        method=method,
        path=path,
        payload=payload_document,
    )

    with (
        patch(
            "chutes_miner.api.server.router._get_server",
            new=AsyncMock(return_value=server),
        ),
        patch("chutes_miner.api.server.router.Gepetto", return_value=gepetto),
        patch("chutes_miner.api.deployment.router.Gepetto", return_value=gepetto),
        patch(
            "chutes_miner.api.server.router.asyncio.create_task",
            side_effect=_close_task,
        ),
        patch(
            "chutes_miner.api.deployment.router.asyncio.create_task",
            side_effect=_close_task,
        ),
    ):
        response = TestClient(application).request(
            method,
            path,
            headers=headers,
            content=payload,
        )

    assert response.status_code == expected_status


@pytest.mark.parametrize(
    ("method", "target", "payload_kind", "expected_status"),
    (
        ("POST", "/servers/", "server", 501),
        ("DELETE", "/servers/node-a", None, 200),
        ("GET", "/servers/node-a/lock", None, 200),
    ),
)
def test_pre_cutover_accepts_and_observes_v1_but_rejects_bearer(
    signing_identity,
    monkeypatch,
    method,
    target,
    payload_kind,
    expected_status,
):
    _, keypair = signing_identity
    monkeypatch.setattr(api_settings, "require_v2_management_signatures", False)
    monkeypatch.setattr(api_settings, "gpu_tee_only", True)
    database = _database()
    application = _test_app(database)
    server = SimpleNamespace(server_id="server-1", name="node-a")
    teardown = SimpleNamespace(
        request_parent=AsyncMock(return_value="operation-1"),
        run_parent=AsyncMock(return_value=True),
    )
    gepetto = SimpleNamespace(teardown=teardown)
    payload_document = (
        {
            "name": "node-a",
            "validator": keypair.ss58_address,
            "hourly_cost": 1.0,
            "gpu_short_ref": "h100",
        }
        if payload_kind == "server"
        else None
    )
    body = json.dumps(payload_document).encode() if payload_document else b""

    with (
        patch(
            "chutes_miner.api.server.router._get_server",
            new=AsyncMock(return_value=server),
        ),
        patch("chutes_miner.api.server.router.Gepetto", return_value=gepetto),
        patch(
            "chutes_miner.api.server.router.asyncio.create_task",
            side_effect=_close_task,
        ),
        patch.object(auth_module.logger, "warning") as warning,
    ):
        client = TestClient(application)
        accepted = client.request(
            method,
            target,
            headers=_v1_headers(keypair, body=body),
            content=body,
        )
        bearer = client.request(
            method,
            target,
            headers={
                MINER_HEADER: keypair.ss58_address,
                VALIDATOR_HEADER: keypair.ss58_address,
                "X-Chutes-Attested-Session": auth_module.miner_settings.attested_session,
            },
            content=body,
        )

    assert accepted.status_code == expected_status
    assert bearer.status_code == 401
    warning.assert_called_once_with(
        "legacy_v1_management_signature_accepted signer={} method={} target={}",
        keypair.ss58_address,
        method,
        target,
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    (("false", False), ("true", True), (" TRUE ", True)),
)
def test_settings_strictly_parses_explicit_management_v2_environment(
    monkeypatch,
    value,
    expected,
):
    monkeypatch.setenv("CHUTES_REQUIRE_V2_MANAGEMENT_SIGNATURES", value)
    monkeypatch.delenv("REQUIRE_V2_MANAGEMENT_SIGNATURES", raising=False)

    assert Settings().require_v2_management_signatures is expected


def test_settings_ignores_implicit_management_v2_environment_alias(monkeypatch):
    monkeypatch.delenv("CHUTES_REQUIRE_V2_MANAGEMENT_SIGNATURES", raising=False)
    monkeypatch.setenv("REQUIRE_V2_MANAGEMENT_SIGNATURES", "false")

    assert Settings().require_v2_management_signatures is True


def test_explicit_management_v2_environment_wins_over_invalid_implicit_alias(
    monkeypatch,
):
    monkeypatch.setenv("CHUTES_REQUIRE_V2_MANAGEMENT_SIGNATURES", "true")
    monkeypatch.setenv("REQUIRE_V2_MANAGEMENT_SIGNATURES", "off")

    assert Settings().require_v2_management_signatures is True


@pytest.mark.parametrize("invalid", ("off", "1", "tru", ""))
def test_settings_rejects_invalid_explicit_management_v2_environment(
    monkeypatch,
    invalid,
):
    monkeypatch.setenv("CHUTES_REQUIRE_V2_MANAGEMENT_SIGNATURES", invalid)
    monkeypatch.setenv("REQUIRE_V2_MANAGEMENT_SIGNATURES", "false")

    with pytest.raises(
        ValidationError,
        match="CHUTES_REQUIRE_V2_MANAGEMENT_SIGNATURES must be exactly true or false",
    ):
        Settings()


def test_server_delete_accepts_v2_and_rejects_attested_session_bypass(
    signing_identity,
    monkeypatch,
):
    monkeypatch.setattr(api_settings, "require_v2_management_signatures", True)
    hotkey_path, keypair = signing_identity
    database = _database()
    application = _test_app(database)
    server = SimpleNamespace(server_id="server-1", name="node-a")
    teardown = SimpleNamespace(
        request_parent=AsyncMock(return_value="operation-1"),
        run_parent=AsyncMock(return_value=True),
    )
    gepetto = SimpleNamespace(teardown=teardown)
    target = "/servers/node-a"
    headers, _ = sign_management_request(
        str(hotkey_path),
        method="DELETE",
        path=target,
    )

    with (
        patch(
            "chutes_miner.api.server.router._get_server",
            new=AsyncMock(return_value=server),
        ),
        patch("chutes_miner.api.server.router.Gepetto", return_value=gepetto),
        patch(
            "chutes_miner.api.server.router.asyncio.create_task",
            side_effect=_close_task,
        ),
    ):
        client = TestClient(application)
        accepted = client.delete(target, headers=headers)
        bypass = client.delete(
            target,
            headers={
                MINER_HEADER: keypair.ss58_address,
                VALIDATOR_HEADER: keypair.ss58_address,
                "X-Chutes-Attested-Session": auth_module.miner_settings.attested_session,
            },
        )

    assert accepted.status_code == 200
    assert accepted.json()["operation_id"] == "operation-1"
    assert bypass.status_code == 401


def test_read_only_management_route_remains_v1_compatible(signing_identity):
    _, keypair = signing_identity
    application = _test_app(_database())

    response = TestClient(application).get(
        "/servers/",
        headers=_v1_headers(keypair),
    )

    assert response.status_code == 200
    assert response.json() == []
