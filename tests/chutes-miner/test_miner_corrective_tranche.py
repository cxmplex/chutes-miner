"""Regressions for the post-review miner corrective tranche."""

# ruff: noqa: E402

from __future__ import annotations

import asyncio
import inspect
import json
import shutil
import ssl
import subprocess
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src/chutes-registry"))

import pytest
import yaml
from chutes_common.schemas import Base
from chutes_common.settings import MinerSettings, SeedlessGPUConfigurationError
from chutes_miner import gepetto as gepetto_module
from chutes_miner.api.deployment import teardown
from chutes_miner.api.deployment.teardown import (
    DeploymentTeardownCoordinator,
    canonical_sha256,
)
from chutes_miner.api.exceptions import DeploymentFailure
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from chutes_registry.api.registry import router as registry_broker


STACK_IMAGE = f"chutes.local/seedless-stack@sha256:{'a' * 64}"


class _Result:
    def __init__(self, value):
        self.value = value

    def unique(self):
        return self

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        return self.value

    def __iter__(self):
        return iter(self.value)


def _decommission_operation() -> SimpleNamespace:
    operation_id = str(uuid.uuid4())
    request = teardown._gpu_decommission_request(
        operation_id=operation_id,
        reason="operator_requested",
    )
    return SimpleNamespace(
        operation_id=operation_id,
        parent_type="server",
        parent_id="server-1",
        validator="validator-1",
        reason="operator_requested",
        validator_server_decommission_request=request,
        validator_server_decommission_request_sha256=canonical_sha256(request),
    )


@pytest.mark.asyncio
async def test_gpu_decommission_replays_exact_uuid_over_current_mtls(monkeypatch):
    operation = _decommission_operation()
    captured: dict[str, object] = {"bodies": []}
    result = {
        "schema": "chutes.gpu-decommissioned",
        "version": 1,
        "server_id": "server-1",
        "request_id": operation.operation_id,
        "decommissioned_at": "2026-08-06T12:00:00+00:00",
        "status": "decommissioned",
    }

    class Context:
        def load_cert_chain(self, cert, key):
            captured["cert_chain"] = (cert, key)

    class Response:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def read(self):
            return json.dumps(result).encode()

    class Client:
        def __init__(self, **kwargs):
            captured["client"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def post(self, url, *, data, headers, allow_redirects):
            captured["url"] = url
            captured["headers"] = headers
            captured["allow_redirects"] = allow_redirects
            captured["bodies"].append(data)
            return Response()

    monkeypatch.setattr(
        teardown,
        "settings",
        SimpleNamespace(
            attested_cert_file="/current/client.crt",
            attested_key_file="/current/client.key",
        ),
    )
    monkeypatch.setattr(
        teardown,
        "validator_by_hotkey",
        lambda _hotkey: SimpleNamespace(api="https://validator.example/"),
    )
    monkeypatch.setattr(
        teardown,
        "sign_request",
        lambda **_kwargs: ({"X-Chutes-Attested-Session": "session"}, None),
    )
    monkeypatch.setattr(teardown.ssl, "create_default_context", Context)
    monkeypatch.setattr(teardown.aiohttp, "TCPConnector", lambda **kwargs: kwargs)
    monkeypatch.setattr(teardown.aiohttp, "ClientSession", Client)

    coordinator = DeploymentTeardownCoordinator(kubernetes=SimpleNamespace())
    assert await coordinator._decommission_validator_server(operation) == result
    assert await coordinator._decommission_validator_server(operation) == result
    assert captured["cert_chain"] == ("/current/client.crt", "/current/client.key")
    assert captured["url"] == (
        "https://validator.example/servers/gpu/server-1/decommission"
    )
    assert captured["allow_redirects"] is False
    assert captured["bodies"] == [captured["bodies"][0], captured["bodies"][0]]
    assert (
        json.loads(captured["bodies"][0])
        == operation.validator_server_decommission_request
    )


@pytest.mark.asyncio
async def test_gpu_decommission_active_409_and_stale_mtls_fail_closed(monkeypatch):
    operation = _decommission_operation()

    class Context:
        def load_cert_chain(self, _cert, _key):
            return None

    class Response:
        status = 409

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def read(self):
            return b'{"detail":"active reservations"}'

    class Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def post(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(
        teardown,
        "settings",
        SimpleNamespace(
            attested_cert_file="/current/client.crt",
            attested_key_file="/current/client.key",
        ),
    )
    monkeypatch.setattr(
        teardown,
        "validator_by_hotkey",
        lambda _hotkey: SimpleNamespace(api="https://validator.example"),
    )
    monkeypatch.setattr(teardown, "sign_request", lambda **_kwargs: ({}, None))
    monkeypatch.setattr(teardown.ssl, "create_default_context", Context)
    monkeypatch.setattr(teardown.aiohttp, "TCPConnector", lambda **_kwargs: object())
    monkeypatch.setattr(teardown.aiohttp, "ClientSession", Client)
    coordinator = DeploymentTeardownCoordinator(kubernetes=SimpleNamespace())

    with pytest.raises(DeploymentFailure, match="HTTP 409"):
        await coordinator._decommission_validator_server(operation)

    class StaleContext:
        def load_cert_chain(self, _cert, _key):
            raise ssl.SSLError("stale certificate")

    monkeypatch.setattr(teardown.ssl, "create_default_context", StaleContext)
    with pytest.raises(DeploymentFailure, match="mTLS identity is unavailable"):
        await coordinator._decommission_validator_server(operation)


@pytest.mark.asyncio
async def test_terminal_ack_clears_only_exact_local_allocation_generation(monkeypatch):
    coordinator = DeploymentTeardownCoordinator(kubernetes=SimpleNamespace())
    request = teardown._gpu_decommission_request(
        operation_id="parent-1",
        reason="operator_requested",
    )
    operation = SimpleNamespace(
        operation_id="parent-1",
        parent_type="server",
        parent_id="server-1",
        reason="operator_requested",
        retry_lease_owner=coordinator.worker_id,
        retry_lease_expires_at=None,
        snapshot={"allocation_group_id": "group-1", "allocation_group_generation": 7},
        validator_server_decommission_request=request,
        validator_server_decommission_request_sha256=canonical_sha256(request),
        validator_server_deletion_ack={
            "schema": "chutes.gpu-decommissioned",
            "version": 1,
            "server_id": "server-1",
            "request_id": "parent-1",
            "decommissioned_at": "2026-08-06T12:00:00+00:00",
            "status": "decommissioned",
        },
        allocation_release_evidence=None,
        allocation_release_evidence_sha256=None,
        allocation_release_verified_at=None,
    )
    server = SimpleNamespace(
        gpu_allocation_group_id="group-1",
        gpu_allocation_group_generation=7,
    )
    gpus = [
        SimpleNamespace(
            gpu_allocation_group_id="group-1",
            gpu_allocation_group_generation=7,
        )
        for _ in range(2)
    ]
    session = SimpleNamespace(
        get=AsyncMock(return_value=operation),
        execute=AsyncMock(side_effect=[_Result(server), _Result(gpus)]),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    await coordinator._record_parent_allocation_release("parent-1")
    assert (server.gpu_allocation_group_id, server.gpu_allocation_group_generation) == (
        None,
        None,
    )
    assert all(
        (gpu.gpu_allocation_group_id, gpu.gpu_allocation_group_generation)
        == (None, None)
        for gpu in gpus
    )
    assert operation.allocation_release_evidence_sha256 == canonical_sha256(
        operation.allocation_release_evidence
    )


@pytest.mark.asyncio
async def test_local_allocation_generation_mismatch_is_never_cleared(monkeypatch):
    coordinator = DeploymentTeardownCoordinator(kubernetes=SimpleNamespace())
    request = teardown._gpu_decommission_request(
        operation_id="parent-1",
        reason="operator_requested",
    )
    operation = SimpleNamespace(
        operation_id="parent-1",
        parent_type="server",
        parent_id="server-1",
        reason="operator_requested",
        retry_lease_owner=coordinator.worker_id,
        snapshot={"allocation_group_id": "group-1", "allocation_group_generation": 7},
        validator_server_decommission_request=request,
        validator_server_decommission_request_sha256=canonical_sha256(request),
        validator_server_deletion_ack={
            "schema": "chutes.gpu-decommissioned",
            "version": 1,
            "server_id": "server-1",
            "request_id": "parent-1",
            "decommissioned_at": "2026-08-06T12:00:00+00:00",
            "status": "decommissioned",
        },
        allocation_release_evidence=None,
        allocation_release_evidence_sha256=None,
        allocation_release_verified_at=None,
    )
    server = SimpleNamespace(
        gpu_allocation_group_id="group-1",
        gpu_allocation_group_generation=8,
    )
    gpu = SimpleNamespace(
        gpu_allocation_group_id="group-1",
        gpu_allocation_group_generation=8,
    )
    session = SimpleNamespace(
        get=AsyncMock(return_value=operation),
        execute=AsyncMock(side_effect=[_Result(server), _Result([gpu])]),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    with pytest.raises(DeploymentFailure, match="generation changed"):
        await coordinator._record_parent_allocation_release("parent-1")
    assert server.gpu_allocation_group_generation == 8
    assert gpu.gpu_allocation_group_generation == 8


@pytest.mark.asyncio
async def test_private_lan_bearer_without_workload_token_cannot_mutate_broker(
    monkeypatch,
):
    monkeypatch.setattr(
        registry_broker,
        "settings",
        SimpleNamespace(
            gpu_tee_only=True,
            registry_workload_token="w" * 64,
            attested_session="attested-session",
        ),
    )
    mint = AsyncMock()
    monkeypatch.setattr(registry_broker, "_mint_registry_scope", mint)
    body = registry_broker.RegistryScopeRequest(
        schema_name="chutes.miner-registry-scope",
        version=1,
        server_id="server-1",
        launch_config_id="config-1",
        repository="owner/image",
        manifest_digest=f"sha256:{'a' * 64}",
    )
    request = SimpleNamespace(client=SimpleNamespace(host="10.23.4.5"))
    with pytest.raises(HTTPException) as rejected:
        await registry_broker.register_registry_scope(
            body,
            request,
            attested_session="attested-session",
            workload_token="x" * 64,
        )
    assert rejected.value.status_code == 401
    mint.assert_not_awaited()


@pytest.mark.asyncio
async def test_teardown_registry_revoke_sends_exact_workload_token(monkeypatch):
    captured: dict[str, object] = {}
    operation = SimpleNamespace(
        config_id="config-1",
        validator="validator-1",
        server_id="server-1",
        deployment_id="deployment-1",
    )
    result = {
        "status": "revoked",
        "revoked": True,
        "launch_config_id": "config-1",
        "server_id": "server-1",
    }

    class Response:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return result

    class Client:
        def __init__(self, **kwargs):
            captured["client"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def delete(self, url, *, headers):
            captured["url"] = url
            captured["headers"] = dict(headers)
            return Response()

    request_revocation = AsyncMock()
    record_revoked = AsyncMock(return_value=result)
    monkeypatch.setattr(
        teardown,
        "request_registry_scope_revocation",
        request_revocation,
    )
    monkeypatch.setattr(teardown, "record_registry_scope_revoked", record_revoked)
    monkeypatch.setattr(
        teardown,
        "settings",
        SimpleNamespace(
            namespace="chutes",
            gpu_tee_only=True,
            registry_workload_token="w" * 64,
        ),
    )
    monkeypatch.setattr(
        teardown,
        "validator_by_hotkey",
        lambda _hotkey: SimpleNamespace(hotkey="VALIDATOR"),
    )
    monkeypatch.setattr(
        teardown,
        "sign_request",
        lambda **_kwargs: ({"X-Chutes-Attested-Session": "session"}, None),
    )
    monkeypatch.setattr(teardown.aiohttp, "ClientSession", Client)

    coordinator = DeploymentTeardownCoordinator(kubernetes=SimpleNamespace())
    assert await coordinator._revoke_registry(operation) == result
    assert captured["url"] == (
        "http://registry-validator.chutes.svc.cluster.local:5000/"
        "registry/scopes/config-1"
    )
    assert captured["headers"] == {
        "X-Chutes-Attested-Session": "session",
        "X-Chutes-Server-Id": "server-1",
        "X-Chutes-Registry-Workload-Token": "w" * 64,
    }
    request_revocation.assert_awaited_once_with(
        launch_config_id="config-1",
        validator="validator-1",
        server_id="server-1",
        deployment_id="deployment-1",
    )
    record_revoked.assert_awaited_once_with("config-1", result)


@pytest.mark.asyncio
async def test_teardown_registry_revoke_missing_workload_token_fails_before_http(
    monkeypatch,
):
    operation = SimpleNamespace(
        config_id="config-1",
        validator="validator-1",
        server_id="server-1",
        deployment_id="deployment-1",
    )

    class MissingTokenSettings:
        namespace = "chutes"
        gpu_tee_only = True

        @property
        def registry_workload_token(self):
            raise SeedlessGPUConfigurationError(
                "registry workload authentication token is unavailable"
            )

    client = AsyncMock()
    monkeypatch.setattr(
        teardown,
        "request_registry_scope_revocation",
        AsyncMock(),
    )
    monkeypatch.setattr(teardown, "settings", MissingTokenSettings())
    monkeypatch.setattr(
        teardown,
        "validator_by_hotkey",
        lambda _hotkey: SimpleNamespace(hotkey="VALIDATOR"),
    )
    monkeypatch.setattr(
        teardown,
        "sign_request",
        lambda **_kwargs: ({"X-Chutes-Attested-Session": "session"}, None),
    )
    monkeypatch.setattr(teardown.aiohttp, "ClientSession", client)

    coordinator = DeploymentTeardownCoordinator(kubernetes=SimpleNamespace())
    with pytest.raises(SeedlessGPUConfigurationError, match="unavailable"):
        await coordinator._revoke_registry(operation)
    client.assert_not_called()


@pytest.mark.asyncio
async def test_registry_scope_reconcile_reuses_authority_and_recovers_empty_cache(
    monkeypatch, tmp_path
):
    identity = ("server-1", "attestation-1", "c" * 64)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    scope = {
        "schema": "chutes.registry-session-result",
        "version": 1,
        "token": "narrow-token",
        "expires_at": expires_at.isoformat(),
        "expires_at_value": expires_at,
        "launch_config_id": "config-1",
        "repository": "owner/image",
        "manifest_digest": f"sha256:{'a' * 64}",
        "server_id": identity[0],
        "attestation_id": identity[1],
        "attested_cert_sha256": identity[2],
    }
    mint = AsyncMock(return_value=scope)
    monkeypatch.setattr(
        registry_broker,
        "settings",
        SimpleNamespace(
            gpu_tee_only=True,
            registry_workload_token="w" * 64,
            attested_session="attested-session",
            seedless_gpu_identity={"server_id": "server-1"},
            registry_scopes_file=str(tmp_path / "scopes.json"),
        ),
    )
    monkeypatch.setattr(registry_broker, "_current_scope_identity", lambda: identity)
    monkeypatch.setattr(registry_broker, "_mint_registry_scope", mint)
    monkeypatch.setattr(registry_broker, "_persist_scopes", lambda: None)
    registry_broker._scopes.clear()
    registry_broker._scopes_loaded = True
    body = registry_broker.RegistryScopeRequest(
        schema_name="chutes.miner-registry-scope",
        version=1,
        server_id="server-1",
        launch_config_id="config-1",
        repository="owner/image",
        manifest_digest=f"sha256:{'a' * 64}",
    )
    request = SimpleNamespace(client=SimpleNamespace(host="10.23.4.5"))
    for _ in range(2):
        result = await registry_broker.register_registry_scope(
            body,
            request,
            attested_session="attested-session",
            workload_token="w" * 64,
        )
        assert result["expires_at"] == scope["expires_at"]
    mint.assert_awaited_once()

    # A registry-only pod replacement can lose its ephemeral cache. The next
    # healthy Gepetto replay must reconstruct it promptly exactly once.
    registry_broker._scopes.clear()
    registry_broker._scopes_loaded = True
    await registry_broker.register_registry_scope(
        body,
        request,
        attested_session="attested-session",
        workload_token="w" * 64,
    )
    assert mint.await_count == 2


def test_registry_workload_token_file_is_strict_and_fail_closed(tmp_path):
    settings = MinerSettings.model_construct(
        registry_workload_token_file=str(tmp_path / "missing-token")
    )
    with pytest.raises(SeedlessGPUConfigurationError, match="unavailable"):
        _ = settings.registry_workload_token
    token_path = tmp_path / "token"
    token_path.write_text("short", encoding="ascii")
    settings.registry_workload_token_file = str(token_path)
    with pytest.raises(SeedlessGPUConfigurationError, match="invalid"):
        _ = settings.registry_workload_token


@pytest.mark.asyncio
async def test_bounded_launch_resume_isolates_hung_and_failed_items(monkeypatch):
    coordinator = object.__new__(gepetto_module.Gepetto)
    coordinator._claim_launch_intents = AsyncMock(
        return_value=[
            ("hung", "lease-hung"),
            ("failed", "lease-failed"),
            ("healthy", "lease-healthy"),
        ]
    )
    completed: list[str] = []

    async def resume(intent_id: str, *, lease_owner: str) -> bool:
        assert lease_owner == f"lease-{intent_id}"
        if intent_id == "hung":
            await asyncio.Event().wait()
        if intent_id == "failed":
            return False
        completed.append(intent_id)
        return True

    coordinator._resume_launch_intent = AsyncMock(side_effect=resume)
    coordinator._record_launch_intent_failure = AsyncMock()
    monkeypatch.setattr(gepetto_module, "RESUME_CONCURRENCY", 2)
    monkeypatch.setattr(gepetto_module, "RESUME_ITEM_TIMEOUT_SECONDS", 0.01)

    await coordinator.resume_launch_intents()
    assert completed == ["healthy"]
    assert coordinator._record_launch_intent_failure.await_count == 1
    assert isinstance(
        coordinator._record_launch_intent_failure.await_args.args[1],
        TimeoutError,
    )
    assert coordinator._record_launch_intent_failure.await_args.kwargs == {
        "lease_owner": "lease-hung"
    }


@pytest.mark.asyncio
async def test_bounded_teardown_resume_does_not_serialize_healthy_work(monkeypatch):
    session = SimpleNamespace(
        execute=AsyncMock(
            side_effect=[
                _Result(["hung"]),
                _Result(["healthy"]),
                _Result(["failed"]),
                _Result(["delayed-healthy"]),
                _Result(["rollback-hung"]),
            ]
        )
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    monkeypatch.setattr(teardown, "RESUME_CONCURRENCY", 2)
    monkeypatch.setattr(teardown, "RESUME_ITEM_TIMEOUT_SECONDS", 0.01)
    coordinator = DeploymentTeardownCoordinator(kubernetes=SimpleNamespace())
    completed: list[str] = []

    async def hung(_identity: str) -> bool:
        await asyncio.Event().wait()
        return False

    async def healthy(identity: str) -> bool:
        completed.append(identity)
        return True

    async def failed(_identity: str) -> bool:
        raise RuntimeError("one item failed")

    async def rollback_hung(_identity: str, _reason: str) -> bool:
        await asyncio.Event().wait()
        return False

    coordinator.run = AsyncMock(side_effect=hung)
    coordinator.run_parent = AsyncMock(side_effect=healthy)
    coordinator.run_orphan = AsyncMock(side_effect=failed)
    coordinator.run_delayed_instance_cleanup = AsyncMock(side_effect=healthy)
    coordinator.request_and_run = AsyncMock(side_effect=rollback_hung)
    coordinator._record_resume_timeout = AsyncMock()
    coordinator._record_resume_exception = AsyncMock()

    await coordinator.resume_pending()
    assert completed == ["healthy", "delayed-healthy"]
    assert coordinator._record_resume_timeout.await_count == 2
    coordinator._record_resume_timeout.assert_any_await("deployment", "hung")
    coordinator._record_resume_timeout.assert_any_await(
        "launch_rollback", "rollback-hung"
    )
    coordinator._record_resume_exception.assert_awaited_once()
    assert coordinator._record_resume_exception.await_args.args[:2] == (
        "orphan",
        "failed",
    )


@pytest.mark.asyncio
async def test_launch_rollback_failure_gets_durable_backoff(monkeypatch):
    launch = SimpleNamespace(
        attempt_count=0,
        next_retry_at=None,
        last_failure=None,
    )
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_Result(launch)),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator = DeploymentTeardownCoordinator(kubernetes=SimpleNamespace())
    await coordinator._record_resume_exception(
        "launch_rollback",
        "deployment-1",
        RuntimeError("rollback failed"),
    )
    assert launch.attempt_count == 1
    assert launch.next_retry_at > datetime.now(timezone.utc)
    assert launch.last_failure == "RuntimeError: rollback failed"
    session.commit.assert_awaited_once()


def test_steady_reconciliation_covers_all_launch_phases_and_active_scopes():
    source = inspect.getsource(gepetto_module.Gepetto.reconcile)
    assert "await self.resume_launch_intents()" in source
    assert "resume_aborted_launch_intents" not in source
    assert "reconstruct_active=True" in source
    registry_source = inspect.getsource(
        gepetto_module.Gepetto.reconcile_registry_scope_intents
    )
    assert "Semaphore(RESUME_CONCURRENCY)" in registry_source
    assert "wait_for(" in registry_source


@pytest.mark.asyncio
async def test_lineage_resolution_uses_exact_cas_and_immutable_audit(monkeypatch):
    conflict_at = datetime.now(timezone.utc)
    row = SimpleNamespace(
        operation_id="operation-1",
        deployment_id="deployment-1",
        phase="verifying",
        lineage_conflict_at=conflict_at,
        last_failure="same-name Pod changed UID",
        retry_lease_owner=None,
        retry_lease_expires_at=None,
        next_retry_at=None,
    )
    audits: list[object] = []
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_Result(row)),
        add=audits.append,
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator = DeploymentTeardownCoordinator(kubernetes=SimpleNamespace())
    authoritative = {
        "schema": "chutes.miner-authoritative-lineage.v1",
        "version": 1,
        "snapshot": {"operation_id": "operation-1", "phase": "verifying"},
        "authoritative": {
            "deployment": {"deployment_id": "deployment-1"},
            "server": {"server_id": "server-1"},
            "gpus": [],
            "registry_scope": None,
            "kubernetes": {"resources": []},
        },
    }
    coordinator._authoritative_lineage_document = AsyncMock(return_value=authoritative)
    inspection = await coordinator.inspect_lineage_conflict("deployment", "operation-1")
    result = await coordinator.recover_lineage_conflict(
        operation_kind="deployment",
        operation_id="operation-1",
        action="requeue",
        policy="exact_lineage_retry",
        expected_conflict_at=conflict_at,
        expected_lineage_sha256=inspection["lineage_sha256"],
        reason="exact lineage was repaired by the operator",
        actor="miner-hotkey",
    )
    assert result["audit_id"] == audits[0].audit_id
    assert audits[0].policy == "exact_lineage_retry"
    assert audits[0].observed_lineage_sha256 == inspection["lineage_sha256"]
    assert row.lineage_conflict_at is None

    row.lineage_conflict_at = conflict_at + timedelta(seconds=1)
    with pytest.raises(DeploymentFailure, match="timestamp changed"):
        await coordinator.recover_lineage_conflict(
            operation_kind="deployment",
            operation_id="operation-1",
            action="requeue",
            policy="exact_lineage_retry",
            expected_conflict_at=conflict_at,
            expected_lineage_sha256=inspection["lineage_sha256"],
            reason="stale operator request must be rejected",
            actor="miner-hotkey",
        )


@pytest.mark.asyncio
async def test_lineage_recovery_rejects_changed_live_authority(monkeypatch):
    conflict_at = datetime.now(timezone.utc)
    row = SimpleNamespace(
        operation_id="operation-1",
        deployment_id="deployment-1",
        phase="verifying",
        lineage_conflict_at=conflict_at,
        last_failure="lineage changed",
        retry_lease_owner=None,
        retry_lease_expires_at=None,
        next_retry_at=None,
    )
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_Result(row)),
        add=lambda _value: None,
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    first = {
        "schema": "chutes.miner-authoritative-lineage.v1",
        "version": 1,
        "snapshot": {"operation_id": "operation-1"},
        "authoritative": {"kubernetes": {"resources": []}},
    }
    changed = {
        **first,
        "authoritative": {
            "kubernetes": {"resources": [{"kind": "Pod", "uid": "new-uid"}]}
        },
    }
    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator = DeploymentTeardownCoordinator(kubernetes=SimpleNamespace())
    coordinator._authoritative_lineage_document = AsyncMock(
        side_effect=[first, changed]
    )
    inspection = await coordinator.inspect_lineage_conflict("deployment", "operation-1")
    with pytest.raises(DeploymentFailure, match="authoritative lineage changed"):
        await coordinator.recover_lineage_conflict(
            operation_kind="deployment",
            operation_id="operation-1",
            action="requeue",
            policy="exact_lineage_retry",
            expected_conflict_at=conflict_at,
            expected_lineage_sha256=inspection["lineage_sha256"],
            reason="live lineage changed after operator inspection",
            actor="miner-hotkey",
        )
    session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_verified_terminal_absence_resolves_normal_conflict(monkeypatch):
    monkeypatch.setattr(teardown.settings, "gpu_tee_only", True)
    conflict_at = datetime.now(timezone.utc)
    now = datetime.now(timezone.utc)
    registry_ack = {
        "status": "revoked",
        "revoked": True,
        "launch_config_id": "config-1",
        "server_id": "server-1",
    }
    row = SimpleNamespace(
        operation_id="operation-1",
        deployment_id="deployment-1",
        phase="verifying",
        validator="validator-1",
        server_id="server-1",
        chute_id="chute-1",
        config_id="config-1",
        job_id=None,
        instance_id=None,
        gpu_hardware_uuids=[],
        resources=[],
        controllers_absent_at=now,
        services_absent_at=now,
        pods_absent_at=now,
        pull_secret_deletion_ack={
            "status": "absent",
            "name": "registry-config-1",
            "config_id": "config-1",
        },
        pull_secret_deleted_at=now,
        registry_revocation_ack=registry_ack,
        registry_revoked_at=now,
        lineage_conflict_at=conflict_at,
        last_failure="benign replacement already terminal",
        retry_lease_owner=None,
        retry_lease_expires_at=None,
        next_retry_at=None,
    )
    lineage = {
        "schema": "chutes.miner-authoritative-lineage.v1",
        "version": 1,
        "snapshot": {
            "effective_node_lineage": {
                "kubernetes_node_uid": "node-uid",
                "kubernetes_node_generation": 4,
                "registration_attestation_id": "attestation-1",
                "gpu_allocation_group_id": "group-1",
                "gpu_allocation_group_generation": 7,
                "cluster_context_sha256": "a" * 64,
            }
        },
        "authoritative": {
            "deployment": {
                "deployment_id": "deployment-1",
                "validator": "validator-1",
                "server_id": "server-1",
                "chute_id": "chute-1",
                "config_id": "config-1",
                "job_id": None,
                "instance_id": None,
                "teardown_operation_id": "operation-1",
            },
            "server": {
                "server_id": "server-1",
                "validator": "validator-1",
                "cluster_context": "node-1",
                "kubernetes_node_uid": "node-uid",
                "kubernetes_node_generation": 4,
                "registration_attestation_id": "attestation-1",
                "gpu_allocation_group_id": "group-1",
                "gpu_allocation_group_generation": 7,
                "cluster_context_sha256": "a" * 64,
            },
            "gpus": [],
            "registry_scope": {
                "launch_config_id": "config-1",
                "deployment_id": "deployment-1",
                "validator": "validator-1",
                "server_id": "server-1",
                "desired_state": "revoked",
                "phase": "revoked",
                "revocation_ack": registry_ack,
                "revoked_at": now.isoformat(),
            },
            "kubernetes": {"resources": []},
        },
    }
    row.cluster_context = "node-1"
    audits: list[object] = []
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_Result(row)),
        add=audits.append,
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    monkeypatch.setattr(
        teardown,
        "registry_pull_secret_name",
        lambda _config_id: "registry-config-1",
    )
    coordinator = DeploymentTeardownCoordinator(kubernetes=SimpleNamespace())
    coordinator._authoritative_lineage_document = AsyncMock(return_value=lineage)
    result = await coordinator.recover_lineage_conflict(
        operation_kind="deployment",
        operation_id="operation-1",
        action="resolve",
        policy="verified_terminal_absence",
        expected_conflict_at=conflict_at,
        expected_lineage_sha256=canonical_sha256(lineage),
        reason="all external workload authority is terminally absent",
        actor="miner-hotkey",
    )
    assert result["phase"] == "finalizing"
    assert row.phase == "finalizing"
    assert audits[0].policy == "verified_terminal_absence"

    row.phase = "verifying"
    row.lineage_conflict_at = conflict_at
    lineage["authoritative"]["registry_scope"]["phase"] = "active"
    with pytest.raises(DeploymentFailure, match="terminal registry revocation"):
        await coordinator.recover_lineage_conflict(
            operation_kind="deployment",
            operation_id="operation-1",
            action="resolve",
            policy="verified_terminal_absence",
            expected_conflict_at=conflict_at,
            expected_lineage_sha256=canonical_sha256(lineage),
            reason="registry authority is not actually revoked",
            actor="miner-hotkey",
        )


def test_verified_terminal_absence_policy_is_shared_with_orphans(monkeypatch):
    monkeypatch.setattr(teardown.settings, "gpu_tee_only", True)
    now = datetime.now(timezone.utc)
    registry_ack = {
        "status": "revoked",
        "revoked": True,
        "launch_config_id": "config-1",
        "server_id": "server-1",
    }
    tombstone = SimpleNamespace(
        deployment_id="orphan-deployment",
        cluster_context="node-1",
        cluster_context_sha256="a" * 64,
        kubernetes_node_uid="node-uid",
        kubernetes_node_generation=4,
        immutable_labels={
            "chutes/deployment-id": "orphan-deployment",
            "chutes/config-id": "config-1",
        },
        resources=[],
    )
    lineage = {
        "snapshot": {"operation_kind": "orphan"},
        "authoritative": {
            "deployment": None,
            "server": {
                "server_id": "server-1",
                "validator": "validator-1",
                "cluster_context": "node-1",
                "cluster_context_sha256": "a" * 64,
                "kubernetes_node_uid": "node-uid",
                "kubernetes_node_generation": 4,
            },
            "gpus": [],
            "registry_scope": {
                "launch_config_id": "config-1",
                "deployment_id": "orphan-deployment",
                "validator": "validator-1",
                "server_id": "server-1",
                "desired_state": "revoked",
                "phase": "revoked",
                "revocation_ack": registry_ack,
                "revoked_at": now.isoformat(),
            },
            "kubernetes": {"resources": []},
        },
    }
    DeploymentTeardownCoordinator._require_verified_terminal_absence(
        "orphan",
        tombstone,
        lineage,
    )
    lineage["authoritative"]["registry_scope"]["revocation_ack"] = {}
    with pytest.raises(DeploymentFailure, match="terminal registry revocation"):
        DeploymentTeardownCoordinator._require_verified_terminal_absence(
            "orphan",
            tombstone,
            lineage,
        )
    lineage["authoritative"]["registry_scope"]["revocation_ack"] = registry_ack
    lineage["authoritative"]["registry_scope"]["phase"] = "active"
    with pytest.raises(DeploymentFailure, match="terminal registry revocation"):
        DeploymentTeardownCoordinator._require_verified_terminal_absence(
            "orphan",
            tombstone,
            lineage,
        )
    lineage["authoritative"]["registry_scope"]["phase"] = "revoked"
    lineage["authoritative"]["deployment"] = {"deployment_id": "orphan-deployment"}
    with pytest.raises(DeploymentFailure, match="local Deployment"):
        DeploymentTeardownCoordinator._require_verified_terminal_absence(
            "orphan",
            tombstone,
            lineage,
        )


def test_lineage_routes_are_v2_authenticated_before_resolution(monkeypatch):
    from chutes_miner.api.deployment.router import router

    application = FastAPI()
    application.include_router(router, prefix="/deployments")
    inspect_conflict = AsyncMock()
    monkeypatch.setattr(
        DeploymentTeardownCoordinator,
        "inspect_lineage_conflict",
        inspect_conflict,
    )
    response = TestClient(application).get(
        "/deployments/teardown-conflicts/deployment/operation-1"
    )
    assert response.status_code == 401
    inspect_conflict.assert_not_awaited()


def _render_template(
    chart: str, template: str, *extra: str
) -> subprocess.CompletedProcess[str]:
    if shutil.which("helm"):
        command = ["helm"]
        chart_path = str(ROOT / f"charts/{chart}")
    elif (
        shutil.which("docker")
        and subprocess.run(
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
            f"{ROOT}:/workspace:ro",
            "-w",
            "/workspace",
            "alpine/helm:latest",
        ]
        chart_path = f"charts/{chart}"
    else:
        pytest.skip("neither Helm nor the local alpine/helm image is available")
    command.extend(
        [
            "template",
            chart,
            chart_path,
            "--show-only",
            f"templates/{template}",
            "--set-string",
            f"seedlessStack.image={STACK_IMAGE}",
            "--set-string",
            "minerCredentials.ownerSs58=fixture-owner",
            *extra,
        ]
    )
    return subprocess.run(command, check=False, capture_output=True, text=True)


def _render_copied_chart_template(
    chart_path: Path, template: str, *extra: str
) -> subprocess.CompletedProcess[str]:
    if shutil.which("helm"):
        command = ["helm"]
        rendered_chart_path = str(chart_path)
    elif (
        shutil.which("docker")
        and subprocess.run(
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
            f"{chart_path}:/chart:ro",
            "alpine/helm:latest",
        ]
        rendered_chart_path = "/chart"
    else:
        pytest.skip("neither Helm nor the local alpine/helm image is available")
    command.extend(
        [
            "template",
            "chutes-miner",
            rendered_chart_path,
            "--namespace",
            "chutes",
            "--show-only",
            f"templates/{template}",
            "--set-string",
            f"seedlessStack.image={STACK_IMAGE}",
            "--set-string",
            "minerCredentials.ownerSs58=fixture-owner",
            *extra,
        ]
    )
    return subprocess.run(command, check=False, capture_output=True, text=True)


def _workload_pod_spec(document: dict) -> dict | None:
    if document["kind"] in {"Deployment", "DaemonSet", "StatefulSet", "Job"}:
        return document["spec"]["template"]["spec"]
    if document["kind"] == "CronJob":
        return document["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    return None


def _render_chart(chart: str, *extra: str) -> subprocess.CompletedProcess[str]:
    if shutil.which("helm"):
        command = ["helm"]
        chart_path = str(ROOT / f"charts/{chart}")
    elif (
        shutil.which("docker")
        and subprocess.run(
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
            f"{ROOT}:/workspace:ro",
            "-w",
            "/workspace",
            "alpine/helm:latest",
        ]
        chart_path = f"charts/{chart}"
    else:
        pytest.skip("neither Helm nor the local alpine/helm image is available")
    command.extend(
        [
            "template",
            chart,
            chart_path,
            "--namespace",
            "chutes",
            "--set-string",
            f"seedlessStack.image={STACK_IMAGE}",
            "--set-string",
            "minerCredentials.ownerSs58=fixture-owner",
            "--set-string",
            "redis.password.value=deterministic-test-password",
            *extra,
        ]
    )
    return subprocess.run(command, check=False, capture_output=True, text=True)


@pytest.mark.parametrize(
    ("chart", "template"),
    [
        ("chutes-miner", "api-deployment.yaml"),
        ("chutes-miner", "gepetto-deployment.yaml"),
        ("chutes-miner-gpu", "registry-daemonset.yaml"),
    ],
)
def test_workload_channel_templates_are_byte_deterministic(chart, template):
    first = _render_template(chart, template)
    second = _render_template(chart, template)
    assert first.returncode == second.returncode == 0
    assert first.stdout.encode() == second.stdout.encode()
    assert "kind: Secret" not in first.stdout
    assert "secretName: registry-workload-auth" in first.stdout


@pytest.mark.parametrize("chart", ["chutes-miner", "chutes-miner-gpu"])
def test_full_chart_render_is_byte_deterministic(chart):
    first = _render_chart(chart)
    second = _render_chart(chart)
    assert first.returncode == second.returncode == 0
    assert first.stdout.encode() == second.stdout.encode()


def test_registry_service_requires_the_nodeport_mirror_contract():
    default_render = _render_chart("chutes-miner-gpu")
    assert default_render.returncode == 0, default_render.stderr
    default_service = next(
        document
        for document in yaml.safe_load_all(default_render.stdout)
        if document
        and document.get("kind") == "Service"
        and document.get("metadata", {}).get("name", "").startswith("registry-")
    )
    assert default_service["spec"]["type"] == "NodePort"
    assert default_service["spec"]["internalTrafficPolicy"] == "Local"
    assert default_service["spec"]["externalTrafficPolicy"] == "Local"
    assert default_service["spec"]["ports"][0]["nodePort"] == 30500

    gpu_values = yaml.safe_load(
        (ROOT / "charts/chutes-miner-gpu/values.yaml").read_text(encoding="utf-8")
    )
    miner_values = yaml.safe_load(
        (ROOT / "charts/chutes-miner/values.yaml").read_text(encoding="utf-8")
    )
    assert "type" not in gpu_values["registry"]["service"]
    assert (
        gpu_values["registry"]["service"]["nodePort"]
        == miner_values["registry"]["service"]["nodePort"]
        == 30500
    )

    missing_nodeport = _render_chart(
        "chutes-miner-gpu",
        "--set-string",
        "registry.service.nodePort=",
    )
    assert missing_nodeport.returncode != 0
    assert (
        "registry.service.nodePort is required for the local registry mirror contract"
        in missing_nodeport.stderr
    )


@pytest.mark.parametrize(
    ("chart", "template"),
    [
        ("chutes-miner", "gepetto-deployment.yaml"),
        ("chutes-miner-gpu", "registry-daemonset.yaml"),
    ],
)
def test_workload_channel_missing_secret_config_fails_render(chart, template):
    result = _render_template(
        chart,
        template,
        "--set-string",
        "registryWorkloadAuth.existingSecret=",
    )
    assert result.returncode != 0
    assert "registryWorkloadAuth.existingSecret is required" in result.stderr


@pytest.mark.parametrize("template", ["api-deployment.yaml", "gepetto-deployment.yaml"])
def test_decommission_callers_cannot_render_without_current_mtls(template):
    result = _render_template(
        "chutes-miner",
        template,
        "--set-string",
        "seedlessStack.attestedKeyHostPath=",
    )
    assert result.returncode != 0
    assert "seedlessStack.attestedKeyHostPath is required" in result.stderr


def test_chart_mounts_exact_credentials_with_dedicated_supplemental_gid():
    for chart, template, credential_gid in (
        ("chutes-miner", "api-deployment.yaml", 65532),
        ("chutes-miner", "gepetto-deployment.yaml", 65532),
        ("chutes-miner-gpu", "registry-daemonset.yaml", 1000),
    ):
        result = _render_template(chart, template)
        assert result.returncode == 0, result.stderr
        document = next(item for item in yaml.safe_load_all(result.stdout) if item)
        pod = document["spec"]["template"]["spec"]
        assert 2000 in pod["securityContext"]["supplementalGroups"]
        assert pod["securityContext"]["fsGroup"] == credential_gid
        assert pod["securityContext"]["fsGroupChangePolicy"] == "OnRootMismatch"
        host_paths = {
            volume["hostPath"]["path"]
            for volume in pod["volumes"]
            if "hostPath" in volume
        }
        assert "/run/chutes-gpu" not in host_paths
        assert "/run/chutes-gpu/credentials/runtime-session.json" in host_paths


def test_workload_token_mount_is_confined_to_exact_three_consumers():
    miner = _render_chart("chutes-miner")
    gpu = _render_chart("chutes-miner-gpu")
    assert miner.returncode == gpu.returncode == 0

    consumers: set[tuple[str, str]] = set()
    for document in [
        *yaml.safe_load_all(miner.stdout),
        *yaml.safe_load_all(gpu.stdout),
    ]:
        if not document or not (pod := _workload_pod_spec(document)):
            continue
        containers = [
            *pod.get("initContainers", []),
            *pod.get("containers", []),
        ]
        pod_consumers = []
        for container in containers:
            mounts = container.get("volumeMounts", [])
            env = container.get("env", [])
            has_mount = any(
                item["name"] == "registry-workload-auth"
                and item["mountPath"] == "/var/run/secrets/chutes-registry-workload"
                and item["readOnly"] is True
                for item in mounts
            )
            has_env = any(
                item["name"] == "CHUTES_REGISTRY_WORKLOAD_TOKEN_FILE"
                and item["value"] == "/var/run/secrets/chutes-registry-workload/token"
                for item in env
            )
            assert has_mount is has_env
            if has_mount:
                identity = (document["metadata"]["name"], container["name"])
                consumers.add(identity)
                pod_consumers.append(identity)

        volumes = [
            item
            for item in pod.get("volumes", [])
            if item["name"] == "registry-workload-auth"
        ]
        assert bool(volumes) is bool(pod_consumers)
        if volumes:
            assert volumes == [
                {
                    "name": "registry-workload-auth",
                    "secret": {
                        "secretName": "registry-workload-auth",
                        "defaultMode": 288,
                        "items": [{"key": "token", "path": "token"}],
                    },
                }
            ]

    assert consumers == {
        ("api", "api"),
        ("gepetto", "api"),
        ("registry", "auth"),
    }


def test_cleanup_uses_dedicated_exact_rbac_and_projected_token():
    rbac = _render_template(
        "chutes-miner-gpu",
        "failed-chute-cleanup.rbac.yaml",
        "--namespace",
        "chutes",
    )
    cron = _render_template(
        "chutes-miner-gpu",
        "failed-chute-cleanup-cronjob.yaml",
        "--namespace",
        "chutes",
    )
    assert rbac.returncode == cron.returncode == 0
    documents = [item for item in yaml.safe_load_all(rbac.stdout) if item]
    account = next(item for item in documents if item["kind"] == "ServiceAccount")
    role = next(item for item in documents if item["kind"] == "Role")
    binding = next(item for item in documents if item["kind"] == "RoleBinding")
    assert account["metadata"]["name"] == "failed-chute-cleanup"
    assert account["automountServiceAccountToken"] is False
    assert role["rules"] == [
        {
            "apiGroups": [""],
            "resources": ["pods"],
            "verbs": ["list", "delete"],
        },
        {
            "apiGroups": [""],
            "resources": ["services"],
            "verbs": ["get", "list", "delete"],
        },
        {"apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["list"]},
    ]
    assert binding["subjects"] == [
        {
            "kind": "ServiceAccount",
            "name": "failed-chute-cleanup",
            "namespace": "chutes",
        }
    ]

    pod = next(yaml.safe_load_all(cron.stdout))["spec"]["jobTemplate"]["spec"][
        "template"
    ]["spec"]
    assert pod["serviceAccountName"] == "failed-chute-cleanup"
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["fsGroup"] == 1000
    assert pod["securityContext"]["fsGroupChangePolicy"] == "OnRootMismatch"
    container = pod["containers"][0]
    assert container["env"] == [
        {
            "name": "NAMESPACE",
            "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}},
        }
    ]
    assert container["volumeMounts"] == [
        {
            "name": "kube-api-access",
            "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
            "readOnly": True,
        }
    ]
    cleanup_script = (ROOT / "docker/chutes-failed-chute-cleanup/cleanup.sh").read_text(
        encoding="utf-8"
    )
    assert cleanup_script.count("--wait=false") == 2


def test_agent_secret_rbac_is_exact_and_cannot_enumerate_workload_token(tmp_path):
    # Multi-cluster mode is intentionally unreachable in the seedless chart;
    # isolate the dormant agent manifests from that registry fail gate so their
    # future-facing authority stays regression tested.
    chart_path = tmp_path / "chutes-miner-gpu"
    shutil.copytree(ROOT / "charts/chutes-miner-gpu", chart_path)
    (chart_path / "templates/registry-cm.yaml").unlink()
    rendered = _render_copied_chart_template(
        chart_path,
        "agent.rbac.yaml",
        "--set",
        "multiCluster=true",
    )
    assert rendered.returncode == 0, rendered.stderr
    documents = [item for item in yaml.safe_load_all(rendered.stdout) if item]
    secret_rules = [
        (document, rule)
        for document in documents
        if document["kind"] in {"Role", "ClusterRole"}
        for rule in document.get("rules", [])
        if "secrets" in rule.get("resources", [])
    ]
    assert len(secret_rules) == 1
    secret_role, secret_rule = secret_rules[0]
    assert secret_role["metadata"] == {
        "name": "agent-secret-access",
        "namespace": "default",
    }
    assert secret_rule == {
        "apiGroups": [""],
        "resources": ["secrets"],
        "resourceNames": ["miner-kubeconfig"],
        "verbs": ["get"],
    }
    for document in documents:
        for rule in document.get("rules", []):
            assert "*" not in rule.get("resources", [])
            assert "*" not in rule.get("verbs", [])
            if "pods" in rule.get("resources", []):
                assert "create" not in rule["verbs"]

    deployment = _render_copied_chart_template(
        chart_path,
        "agent.deploy.yaml",
        "--set",
        "multiCluster=true",
    )
    assert deployment.returncode == 0, deployment.stderr
    pod = next(yaml.safe_load_all(deployment.stdout))["spec"]["template"]["spec"]
    assert pod["serviceAccountName"] == "agent"
    assert "registry-workload-auth" not in deployment.stdout


def test_legacy_monitor_uses_get_node_only_identity(tmp_path):
    # The production chart rejects multi-cluster mode before rendering this
    # legacy-gated workload. Render an otherwise exact temporary chart without
    # that fail-closed API template so the dormant manifests remain tested.
    chart_path = tmp_path / "chutes-miner"
    shutil.copytree(ROOT / "charts/chutes-miner", chart_path)
    (chart_path / "templates/api-deployment.yaml").unlink()

    deployment = _render_copied_chart_template(
        chart_path,
        "monitor.deploy.yaml",
        "--set",
        "multiCluster=true",
        "--set",
        "monitor.enabled=true",
    )
    rbac = _render_copied_chart_template(
        chart_path,
        "monitor.rbac.yaml",
        "--set",
        "multiCluster=true",
        "--set",
        "monitor.enabled=true",
    )
    assert deployment.returncode == rbac.returncode == 0

    pod = next(yaml.safe_load_all(deployment.stdout))["spec"]["template"]["spec"]
    assert pod["serviceAccountName"] == "chutes-monitor"
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["fsGroup"] == 65532
    assert pod["securityContext"]["fsGroupChangePolicy"] == "OnRootMismatch"
    init_container = pod["initContainers"][0]
    monitor_container = pod["containers"][0]
    assert any(
        mount["name"] == "monitor-kube-api-access"
        and mount["mountPath"] == "/var/run/secrets/kubernetes.io/serviceaccount"
        and mount["readOnly"] is True
        for mount in init_container["volumeMounts"]
    )
    assert all(
        mount["name"] != "monitor-kube-api-access"
        for mount in monitor_container["volumeMounts"]
    )
    assert "registry-workload-auth" not in deployment.stdout

    documents = [item for item in yaml.safe_load_all(rbac.stdout) if item]
    account = next(item for item in documents if item["kind"] == "ServiceAccount")
    role = next(item for item in documents if item["kind"] == "ClusterRole")
    binding = next(item for item in documents if item["kind"] == "ClusterRoleBinding")
    assert account["metadata"]["name"] == "chutes-monitor"
    assert account["automountServiceAccountToken"] is False
    assert role["rules"] == [
        {"apiGroups": [""], "resources": ["nodes"], "verbs": ["get"]}
    ]
    assert binding["subjects"] == [
        {"kind": "ServiceAccount", "name": "chutes-monitor", "namespace": "chutes"}
    ]


def test_broad_chutes_service_account_is_used_only_by_api_and_gepetto():
    miner = _render_chart("chutes-miner")
    gpu = _render_chart("chutes-miner-gpu")
    assert miner.returncode == gpu.returncode == 0
    broad_consumers = set()
    for document in [
        *yaml.safe_load_all(miner.stdout),
        *yaml.safe_load_all(gpu.stdout),
    ]:
        if not document or not (pod := _workload_pod_spec(document)):
            continue
        if pod.get("serviceAccountName") == "chutes":
            broad_consumers.add(document["metadata"]["name"])
    assert broad_consumers == {"api", "gepetto"}


def test_corrective_schema_and_migration_are_durable():
    assert "next_retry_at" in Base.metadata.tables["deployment_teardown_operations"].c
    assert "next_retry_at" in Base.metadata.tables["deployment_launch_operations"].c
    launch_intents = Base.metadata.tables["miner_launch_intents"]
    assert {
        "next_retry_at",
        "retry_lease_owner",
        "retry_lease_expires_at",
    }.issubset(launch_intents.c.keys())
    assert any(
        constraint.name == "ck_miner_launch_intent_retry_lease"
        for constraint in launch_intents.constraints
    )
    retry_index = next(
        index
        for index in launch_intents.indexes
        if index.name == "miner_launch_intent_next_retry_idx"
    )
    assert [column.name for column in retry_index.columns] == [
        "next_retry_at",
        "retry_lease_expires_at",
        "created_at",
    ]
    assert (
        "validator_server_decommission_request"
        in Base.metadata.tables["parent_deletion_operations"].c
    )
    assert "teardown_lineage_resolution_audits" in Base.metadata.tables
    migration = (
        ROOT
        / "src/chutes-miner/chutes_miner/api/migrations/20260806120000_miner_corrective_tranche.sql"
    ).read_text(encoding="utf-8")
    assert "prevent_teardown_lineage_resolution_audit_mutation" in migration
    assert "validator_server_decommission_request_sha256" in migration
    assert "next_retry_at" in migration
    assert "ck_miner_launch_intent_retry_lease" in migration
    assert "retry_lease_expires_at" in migration
    assert "miner_launch_intent_next_retry_idx" in migration
