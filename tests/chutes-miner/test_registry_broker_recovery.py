"""Fail-closed cache recovery and ACK ordering for the registry broker."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[2] / "src/chutes-registry"),
)

from chutes_registry.api.registry import router as registry_broker


def _request():
    return SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"), headers={})


def test_corrupt_scope_cache_is_quarantined_for_database_reconstruction(
    monkeypatch,
    tmp_path,
):
    path = tmp_path / "scopes.json"
    path.write_text('{"schema":"chutes.registry-scopes","scopes":', encoding="ascii")
    monkeypatch.setattr(
        registry_broker,
        "settings",
        SimpleNamespace(registry_scopes_file=str(path)),
    )
    registry_broker._scopes.clear()
    registry_broker._scopes_loaded = False

    registry_broker._load_scopes()

    assert registry_broker._scopes == {}
    assert registry_broker._scopes_loaded is True
    assert not path.exists()
    quarantined = list(tmp_path.glob("scopes.json.corrupt-*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_text(encoding="ascii").endswith('"scopes":')


@pytest.mark.asyncio
async def test_validator_outage_does_not_remove_local_scope_before_ack(
    monkeypatch,
    tmp_path,
):
    path = tmp_path / "scopes.json"
    cert = tmp_path / "server.crt"
    cert.write_text("certificate", encoding="ascii")
    settings = SimpleNamespace(
        gpu_tee_only=True,
        attested_session="attested-session",
        validators=[SimpleNamespace(api="https://validator.example")],
        attested_cert_file=str(cert),
        attested_key_file=str(tmp_path / "server.key"),
        registry_scopes_file=str(path),
    )
    monkeypatch.setattr(registry_broker, "settings", settings)

    class Context:
        def load_cert_chain(self, _cert, _key):
            return None

    class Response:
        status = 503

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {
                "status": "already_absent",
                "revoked": True,
                "launch_config_id": "config-1",
                "server_id": "server-1",
            }

    class Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def delete(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(registry_broker.ssl, "create_default_context", Context)
    monkeypatch.setattr(
        registry_broker.aiohttp,
        "TCPConnector",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(registry_broker.aiohttp, "ClientSession", Client)
    registry_broker._scopes.clear()
    registry_broker._scopes["config-1"] = {
        "launch_config_id": "config-1",
        "token": "scope-token",
    }
    registry_broker._scopes_loaded = True

    with pytest.raises(HTTPException, match="Validator rejected"):
        await registry_broker.revoke_registry_scope(
            "config-1",
            _request(),
            attested_session="attested-session",
        )

    assert registry_broker._scopes["config-1"]["token"] == "scope-token"


@pytest.mark.asyncio
async def test_exact_validator_ack_removes_and_persists_local_scope(
    monkeypatch,
    tmp_path,
):
    path = tmp_path / "scopes.json"
    cert = tmp_path / "server.crt"
    cert.write_text("certificate", encoding="ascii")
    monkeypatch.setattr(
        registry_broker,
        "settings",
        SimpleNamespace(
            gpu_tee_only=True,
            attested_session="attested-session",
            validators=[SimpleNamespace(api="https://validator.example")],
            attested_cert_file=str(cert),
            attested_key_file=str(tmp_path / "server.key"),
            registry_scopes_file=str(path),
        ),
    )

    class Context:
        def load_cert_chain(self, _cert, _key):
            return None

    class Response:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {
                "status": "already_absent",
                "revoked": True,
                "launch_config_id": "config-1",
                "server_id": "server-1",
            }

    class Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def delete(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(registry_broker.ssl, "create_default_context", Context)
    monkeypatch.setattr(
        registry_broker.aiohttp, "TCPConnector", lambda **_kwargs: object()
    )
    monkeypatch.setattr(registry_broker.aiohttp, "ClientSession", Client)
    registry_broker._scopes.clear()
    registry_broker._scopes["config-1"] = {"launch_config_id": "config-1"}
    registry_broker._scopes_loaded = True

    result = await registry_broker.revoke_registry_scope(
        "config-1",
        _request(),
        attested_session="attested-session",
        expected_server_id="server-1",
    )
    assert result == {
        "status": "already_absent",
        "revoked": True,
        "launch_config_id": "config-1",
        "server_id": "server-1",
    }
    assert "config-1" not in registry_broker._scopes
    assert json.loads(path.read_text(encoding="ascii"))["scopes"] == {}
