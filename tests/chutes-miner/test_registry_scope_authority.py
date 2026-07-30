"""Database authority/outbox regressions for registry scope lifecycle."""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import chutes_miner.api.registry_scopes as scope_module
import chutes_miner.gepetto as gepetto_module
from chutes_miner.api.exceptions import DeploymentFailure
from chutes_miner.api.registry_scopes import (
    RegistryScopeWorkItem,
    ensure_registry_scope_registration_in_session,
    record_registry_scope_registered,
    record_registry_scope_registered_in_session,
    record_registry_scope_revoked,
    request_registry_scope_revocation_in_session,
)
from chutes_miner.gepetto import Gepetto


DIGEST = f"sha256:{'a' * 64}"
DEPLOYMENT_ID = "11111111-1111-4111-8111-111111111111"


def _intent():
    return SimpleNamespace(
        intent_id="intent-1",
        deployment_id=DEPLOYMENT_ID,
        validator="validator-1",
        server_id="server-1",
    )


def _payload():
    return {
        "config_id": "config-1",
        "registry": {
            "repository": "owner/image",
            "manifest_digest": DIGEST,
        },
    }


@pytest.mark.asyncio
async def test_registration_authority_and_revocation_outbox_share_exact_identity():
    added = []
    session = SimpleNamespace(
        get=AsyncMock(return_value=None),
        add=added.append,
    )
    row = await ensure_registry_scope_registration_in_session(
        session,
        _intent(),
        _payload(),
    )
    assert added == [row]
    assert row.launch_config_id == "config-1"
    assert row.launch_intent_id == "intent-1"
    assert row.deployment_id == DEPLOYMENT_ID
    assert row.desired_state == "active"
    assert row.phase == "register_pending"

    session.get = AsyncMock(return_value=row)
    await request_registry_scope_revocation_in_session(
        session,
        launch_config_id="config-1",
        validator="validator-1",
        server_id="server-1",
        deployment_id=DEPLOYMENT_ID,
    )
    assert row.desired_state == "revoked"
    assert row.phase == "revoke_pending"
    assert row.revocation_ack is None


@pytest.mark.asyncio
async def test_scope_ack_state_machine_is_idempotent_and_fail_closed(monkeypatch):
    row = SimpleNamespace(
        launch_config_id="config-1",
        validator="validator-1",
        server_id="server-1",
        deployment_id=DEPLOYMENT_ID,
        desired_state="active",
        phase="register_pending",
        registration_ack=None,
        registered_at=None,
        revocation_ack=None,
        revoked_at=None,
        last_failure="old failure",
    )
    session = SimpleNamespace(
        get=AsyncMock(return_value=row),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(scope_module, "get_session", fake_session)
    registration_ack = {
        "registered": True,
        "launch_config_id": "config-1",
        "expires_at": "2030-01-01T00:00:00+00:00",
    }
    await record_registry_scope_registered("config-1", registration_ack)
    assert row.phase == "active"
    assert row.registration_ack == registration_ack
    assert row.registered_at is not None
    first_registered_at = row.registered_at

    renewed_ack = {
        **registration_ack,
        "expires_at": "2030-01-02T00:00:00+00:00",
    }
    await record_registry_scope_registered("config-1", renewed_ack)
    assert row.registration_ack == renewed_ack
    assert row.registered_at == first_registered_at

    await request_registry_scope_revocation_in_session(
        session,
        launch_config_id="config-1",
        validator="validator-1",
    )
    revocation_ack = {
        "status": "already_absent",
        "revoked": True,
        "launch_config_id": "config-1",
        "server_id": "server-1",
    }
    durable_ack = await record_registry_scope_revoked("config-1", revocation_ack)
    assert row.phase == "revoked"
    assert row.desired_state == "revoked"
    assert durable_ack == {
        **revocation_ack,
        "status": "revoked",
    }
    assert row.revocation_ack == durable_ack
    assert row.revoked_at is not None

    replay_ack = await record_registry_scope_revoked(
        "config-1",
        {**revocation_ack, "status": "revoked"},
    )
    assert replay_ack == durable_ack

    with pytest.raises(DeploymentFailure, match="malformed revocation ACK"):
        await record_registry_scope_revoked(
            "config-1",
            {
                "revoked": True,
                "launch_config_id": "config-1",
            },
        )
    with pytest.raises(DeploymentFailure, match="malformed revocation ACK"):
        await record_registry_scope_revoked(
            "config-1",
            {
                "status": "already_absent",
                "revoked": True,
                "launch_config_id": "other-config",
                "server_id": "server-1",
            },
        )
    with pytest.raises(DeploymentFailure, match="malformed revocation ACK"):
        await record_registry_scope_revoked(
            "config-1",
            {
                "status": "already_absent",
                "revoked": True,
                "launch_config_id": "config-1",
                "server_id": "server-other",
            },
        )


@pytest.mark.asyncio
async def test_registration_ack_is_bound_to_exact_launch_intent():
    row = SimpleNamespace(
        launch_intent_id="intent-1",
        desired_state="active",
        phase="register_pending",
        registration_ack=None,
        registered_at=None,
        last_failure=None,
    )
    session = SimpleNamespace(get=AsyncMock(return_value=row))
    ack = {
        "registered": True,
        "launch_config_id": "config-1",
        "expires_at": "2030-01-01T00:00:00+00:00",
    }

    with pytest.raises(DeploymentFailure, match="launch authority changed"):
        await record_registry_scope_registered_in_session(
            session,
            "config-1",
            ack,
            launch_intent_id="intent-2",
        )


@pytest.mark.asyncio
async def test_gepetto_restart_reconstructs_active_cache_and_replays_revocation(
    monkeypatch,
):
    active = RegistryScopeWorkItem(
        launch_config_id="config-active",
        validator="validator-1",
        server_id="server-1",
        repository="owner/image",
        manifest_digest=DIGEST,
        desired_state="active",
        phase="active",
    )
    revoked = RegistryScopeWorkItem(
        launch_config_id="config-revoked",
        validator="validator-1",
        server_id="server-1",
        repository="owner/image",
        manifest_digest=DIGEST,
        desired_state="revoked",
        phase="revoke_pending",
    )
    work_items = AsyncMock(return_value=[active, revoked])
    recorded = AsyncMock()
    failures = AsyncMock()
    monkeypatch.setattr(gepetto_module.settings, "gpu_tee_only", True)
    monkeypatch.setattr(gepetto_module, "registry_scope_work_items", work_items)
    monkeypatch.setattr(
        gepetto_module,
        "validator_by_hotkey",
        lambda hotkey: SimpleNamespace(hotkey=hotkey),
    )
    monkeypatch.setattr(gepetto_module, "record_registry_scope_registered", recorded)
    monkeypatch.setattr(gepetto_module, "record_registry_scope_failure", failures)
    coordinator = object.__new__(Gepetto)
    coordinator._send_registry_scope_registration = AsyncMock(
        return_value={
            "registered": True,
            "launch_config_id": "config-active",
            "expires_at": "2030-01-01T00:00:00+00:00",
        }
    )
    coordinator._revoke_registry_scope = AsyncMock()

    await coordinator.reconcile_registry_scope_intents(reconstruct_active=True)

    work_items.assert_awaited_once_with(reconstruct_active=True)
    coordinator._send_registry_scope_registration.assert_awaited_once()
    body = coordinator._send_registry_scope_registration.await_args.args[1]
    assert body == {
        "schema": "chutes.miner-registry-scope",
        "version": 1,
        "server_id": "server-1",
        "launch_config_id": "config-active",
        "repository": "owner/image",
        "manifest_digest": DIGEST,
    }
    recorded.assert_awaited_once()
    coordinator._revoke_registry_scope.assert_awaited_once_with(
        "validator-1", "config-revoked", "server-1"
    )
    failures.assert_not_awaited()


@pytest.mark.asyncio
async def test_registry_outage_keeps_scope_work_pending_for_retry(monkeypatch):
    item = RegistryScopeWorkItem(
        launch_config_id="config-1",
        validator="validator-1",
        server_id="server-1",
        repository="owner/image",
        manifest_digest=DIGEST,
        desired_state="active",
        phase="register_pending",
    )
    failure = ConnectionError("registry unavailable")
    recorded_failure = AsyncMock()
    monkeypatch.setattr(gepetto_module.settings, "gpu_tee_only", True)
    monkeypatch.setattr(
        gepetto_module,
        "registry_scope_work_items",
        AsyncMock(return_value=[item]),
    )
    monkeypatch.setattr(
        gepetto_module,
        "validator_by_hotkey",
        lambda hotkey: SimpleNamespace(hotkey=hotkey),
    )
    monkeypatch.setattr(
        gepetto_module,
        "record_registry_scope_failure",
        recorded_failure,
    )
    monkeypatch.setattr(
        gepetto_module,
        "record_registry_scope_registered",
        AsyncMock(),
    )
    coordinator = object.__new__(Gepetto)
    coordinator._send_registry_scope_registration = AsyncMock(side_effect=failure)

    await coordinator.reconcile_registry_scope_intents(reconstruct_active=False)

    recorded_failure.assert_awaited_once_with("config-1", failure)


def test_failed_and_terminating_pods_do_not_keep_registry_scope_live(monkeypatch):
    pods = [
        SimpleNamespace(
            metadata=SimpleNamespace(
                labels={"chutes/config-id": "running"},
                deletion_timestamp=None,
            ),
            status=SimpleNamespace(phase="Running"),
        ),
        SimpleNamespace(
            metadata=SimpleNamespace(
                labels={"chutes/config-id": "failed"},
                deletion_timestamp=None,
            ),
            status=SimpleNamespace(phase="Failed"),
        ),
        SimpleNamespace(
            metadata=SimpleNamespace(
                labels={"chutes/config-id": "terminating"},
                deletion_timestamp=object(),
            ),
            status=SimpleNamespace(phase="Running"),
        ),
    ]

    class K8s:
        def get_pods(self, **_kwargs):
            return SimpleNamespace(items=pods)

    monkeypatch.setattr(gepetto_module, "K8sOperator", K8s)
    assert Gepetto._k8s_config_ids() == {"running"}
