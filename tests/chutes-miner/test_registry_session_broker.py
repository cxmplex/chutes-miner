import base64
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[2] / "src/chutes-registry"),
)

from chutes_registry.api.registry import router as registry_broker


def _request():
    return SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        headers={},
    )


def _basic(config_id: str) -> str:
    value = base64.b64encode(f"{config_id}:chutes-registry-scope".encode("ascii")).decode("ascii")
    return f"Basic {value}"


@pytest.mark.asyncio
async def test_broker_mints_narrow_session_and_denies_cross_digest(
    monkeypatch,
    tmp_path,
):
    root = f"sha256:{'a' * 64}"
    blob = f"sha256:{'b' * 64}"
    signature = f"sha256:{'c' * 64}"
    expires = datetime.now(timezone.utc) + timedelta(minutes=5)
    closure = {
        "schema": "chutes.oci-descriptor-closure",
        "version": 1,
        "root_manifest": root,
        "manifests": [root, signature],
        "blobs": [blob],
        "manifest_tags": [f"sha256-{'a' * 64}.sig"],
        "manifest_tag_digests": {
            f"sha256-{'a' * 64}.sig": signature,
        },
    }
    result = {
        "schema": "chutes.registry-session-result",
        "version": 1,
        "token": "narrow-registry-session",
        "expires_at": expires.isoformat(),
        "launch_config_id": "config-1",
        "repository": "owner/image",
        "manifest_digest": root,
        "descriptor_closure_sha256": hashlib.sha256(
            json.dumps(
                closure,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        ).hexdigest(),
        "allowed_manifests": closure["manifests"],
        "allowed_blobs": closure["blobs"],
        "allowed_manifest_tags": closure["manifest_tags"],
        "manifest_tag_digests": closure["manifest_tag_digests"],
    }
    captured = {}
    cert_path = tmp_path / "server.crt"
    cert_path.write_bytes(b"attested certificate")

    class Context:
        def load_cert_chain(self, cert, key):
            captured["cert"] = (cert, key)

    class ApiResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return result

    class Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def post(self, url, data, headers, allow_redirects):
            captured.update(
                url=url,
                body=json.loads(data),
                headers=headers,
                allow_redirects=allow_redirects,
            )
            return ApiResponse()

    monkeypatch.setattr(
        registry_broker,
        "settings",
        SimpleNamespace(
            gpu_tee_only=True,
            attested_session="broad-attested-session",
            seedless_gpu_identity={
                "server_id": "logical-server",
                "attestation_id": "attestation-1",
            },
            validators=[SimpleNamespace(api="https://validator.example")],
            attested_cert_file=str(cert_path),
            attested_key_file=str(tmp_path / "server.key"),
            registry_scopes_file=str(tmp_path / "scopes.json"),
        ),
    )
    monkeypatch.setattr(
        registry_broker.ssl,
        "create_default_context",
        lambda: Context(),
    )
    monkeypatch.setattr(
        registry_broker.aiohttp,
        "TCPConnector",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        registry_broker.aiohttp,
        "ClientSession",
        Client,
    )
    registry_broker._scopes.clear()
    registry_broker._scopes_loaded = False
    scope = registry_broker.RegistryScopeRequest(
        schema_name="chutes.miner-registry-scope",
        version=1,
        server_id="logical-server",
        launch_config_id="config-1",
        repository="owner/image",
        manifest_digest=root,
    )
    registered = await registry_broker.register_registry_scope(
        scope,
        _request(),
        attested_session="broad-attested-session",
    )
    assert registered["launch_config_id"] == "config-1"
    assert captured["body"]["launch_config_id"] == "config-1"
    assert captured["headers"]["X-Chutes-Attested-Session"] == ("broad-attested-session")

    response = Response()
    authenticated = await registry_broker.registry_auth(
        _request(),
        response,
        original_method="GET",
        original_uri=f"/v2/owner/image/manifests/{root}",
        launch_config_id="config-1",
        authorization=_basic("config-1"),
    )
    assert authenticated["auth_type"] == "registry_session"
    assert response.headers["X-Chutes-Registry-Session"] == ("narrow-registry-session")
    assert response.headers["X-Chutes-Registry-Upstream-Uri"] == (
        f"/v2/owner/image/manifests/{root}"
    )
    signature_response = Response()
    await registry_broker.registry_auth(
        _request(),
        signature_response,
        original_method="GET",
        original_uri=(f"/v2/owner/image/manifests/{closure['manifest_tags'][0]}"),
        launch_config_id="config-1",
        authorization=_basic("config-1"),
    )
    assert (
        signature_response.headers["X-Chutes-Registry-Upstream-Uri"]
        == f"/v2/owner/image/manifests/{signature}"
    )

    with pytest.raises(HTTPException, match="No exact"):
        await registry_broker.registry_auth(
            _request(),
            Response(),
            original_method="GET",
            original_uri=f"/v2/owner/image/manifests/sha256:{'d' * 64}",
            launch_config_id="config-1",
            authorization=_basic("config-1"),
        )


@pytest.mark.asyncio
async def test_gpu_broker_never_falls_back_to_hotkey(monkeypatch, tmp_path):
    monkeypatch.setattr(
        registry_broker,
        "settings",
        SimpleNamespace(
            gpu_tee_only=True,
            registry_scopes_file=str(tmp_path / "scopes.json"),
        ),
    )
    registry_broker._scopes.clear()
    registry_broker._scopes_loaded = False
    with pytest.raises(HTTPException, match="launch-config credential"):
        await registry_broker.registry_auth(
            _request(),
            Response(),
            original_method="GET",
            original_uri="/v2/owner/image/manifests/latest",
        )


def test_registry_scopes_survive_restart_and_overlap_same_repository(
    monkeypatch,
    tmp_path,
):
    path = tmp_path / "scopes.json"
    monkeypatch.setattr(
        registry_broker,
        "settings",
        SimpleNamespace(registry_scopes_file=str(path)),
    )
    expires = datetime.now(timezone.utc) + timedelta(minutes=5)
    base = {
        "schema": "chutes.registry-session-result",
        "version": 1,
        "token": "token",
        "expires_at": expires.isoformat(),
        "expires_at_value": expires,
        "repository": "owner/image",
        "allowed_manifests": [f"sha256:{'a' * 64}"],
        "allowed_blobs": [],
        "allowed_manifest_tags": [],
        "manifest_tag_digests": {},
        "descriptor_closure_sha256": "b" * 64,
        "server_id": "logical-server",
        "attestation_id": "attestation-1",
        "attested_cert_sha256": "c" * 64,
    }
    registry_broker._scopes.clear()
    registry_broker._scopes.update(
        {
            "config-1": {
                **base,
                "launch_config_id": "config-1",
                "manifest_digest": f"sha256:{'a' * 64}",
            },
            "config-2": {
                **base,
                "launch_config_id": "config-2",
                "manifest_digest": f"sha256:{'c' * 64}",
                "allowed_manifests": [f"sha256:{'c' * 64}"],
            },
        }
    )
    registry_broker._persist_scopes()
    registry_broker._scopes.clear()
    registry_broker._scopes_loaded = False
    registry_broker._load_scopes()
    assert set(registry_broker._scopes) == {"config-1", "config-2"}


def test_registry_scope_persistence_cleans_crash_files_and_expired_entries(
    monkeypatch,
    tmp_path,
):
    path = tmp_path / "scopes.json"
    stale = tmp_path / ".scopes.json.crashed.tmp"
    stale.write_text("partial", encoding="ascii")
    monkeypatch.setattr(
        registry_broker,
        "settings",
        SimpleNamespace(registry_scopes_file=str(path)),
    )
    registry_broker._scopes.clear()
    registry_broker._scopes.update(
        {
            "expired": {
                "launch_config_id": "expired",
                "server_id": "logical-server",
                "attestation_id": "attestation-1",
                "attested_cert_sha256": "c" * 64,
                "repository": "owner/image",
                "manifest_digest": f"sha256:{'a' * 64}",
                "descriptor_closure_sha256": "d" * 64,
                "allowed_manifests": [f"sha256:{'a' * 64}"],
                "allowed_blobs": [],
                "allowed_manifest_tags": [],
                "manifest_tag_digests": {},
                "expires_at": "2000-01-01T00:00:00+00:00",
                "expires_at_value": datetime(2000, 1, 1, tzinfo=timezone.utc),
                "schema": "chutes.registry-session-result",
                "version": 1,
                "token": "expired",
            }
        }
    )
    registry_broker._persist_scopes()
    assert not stale.exists()
    assert not list(tmp_path.glob(".scopes.json.*.tmp"))
    registry_broker._scopes.clear()
    registry_broker._scopes_loaded = False
    registry_broker._load_scopes()
    assert registry_broker._scopes == {}


def test_overlapping_registry_scopes_select_exact_or_shared_descriptor(
    monkeypatch,
    tmp_path,
):
    cert_path = tmp_path / "server.crt"
    cert_path.write_bytes(b"attested certificate")
    cert_sha256 = hashlib.sha256(cert_path.read_bytes()).hexdigest()
    monkeypatch.setattr(
        registry_broker,
        "settings",
        SimpleNamespace(
            attested_cert_file=str(cert_path),
            seedless_gpu_identity={
                "server_id": "logical-server",
                "attestation_id": "attestation-1",
            },
        ),
    )
    now = datetime.now(timezone.utc)
    shared_blob = f"sha256:{'d' * 64}"
    shared_manifest = f"sha256:{'e' * 64}"

    def scope(config_id, root, unique_blob, expires_offset):
        return {
            "launch_config_id": config_id,
            "server_id": "logical-server",
            "attestation_id": "attestation-1",
            "attested_cert_sha256": cert_sha256,
            "repository": "owner/image",
            "manifest_digest": root,
            "descriptor_closure_sha256": hashlib.sha256(config_id.encode()).hexdigest(),
            "allowed_manifests": [root, shared_manifest],
            "allowed_blobs": [shared_blob, unique_blob],
            "allowed_manifest_tags": [],
            "manifest_tag_digests": {},
            "expires_at_value": now + timedelta(seconds=expires_offset),
        }

    root_one = f"sha256:{'a' * 64}"
    root_two = f"sha256:{'b' * 64}"
    unique_one = f"sha256:{'1' * 64}"
    unique_two = f"sha256:{'2' * 64}"
    scopes = [
        scope("config-1", root_one, unique_one, 300),
        scope("config-2", root_two, unique_two, 600),
    ]

    selected_root = registry_broker._select_scope(
        scopes,
        "GET",
        f"/v2/owner/image/manifests/{root_one}",
        now,
    )
    assert selected_root["launch_config_id"] == "config-1"

    selected_shared = registry_broker._select_scope(
        scopes,
        "GET",
        f"/v2/owner/image/blobs/{shared_blob}",
        now,
    )
    assert selected_shared["launch_config_id"] == "config-2"

    selected_manifest = registry_broker._select_scope(
        scopes,
        "GET",
        f"/v2/owner/image/manifests/{shared_manifest}",
        now,
    )
    assert selected_manifest["launch_config_id"] == "config-2"

    assert (
        registry_broker._select_scope(
            scopes,
            "GET",
            f"/v2/owner/image/blobs/{unique_one}",
            now,
            launch_config_id="config-2",
        )
        is None
    )
    selected_exact = registry_broker._select_scope(
        scopes,
        "GET",
        f"/v2/owner/image/blobs/{unique_one}",
        now,
        launch_config_id="config-1",
    )
    assert selected_exact["launch_config_id"] == "config-1"
