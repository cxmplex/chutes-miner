"""Focused trust-boundary tests for restartable miner teardown."""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from chutes_common.exceptions import AgentError
from chutes_miner.api.config import Settings
from chutes_miner.api.deployment import teardown
from chutes_miner.api.deployment.teardown import (
    DirectKubernetesClosure,
    LineageConflict,
    ResourceIdentity,
    UnresolvedOwnerLineage,
    authorized_node_incarnation_handoff_values,
    replacement_matches,
)
from chutes_miner.api.exceptions import DeploymentFailure
from chutes_miner.api.k8s import operator as k8s_operator
from chutes_miner.api.k8s.operator import K8sOperator
from chutes_miner.gepetto import Gepetto
from kubernetes.client import V1ObjectMeta, V1Service, V1ServiceSpec
from kubernetes.client.rest import ApiException
from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[2]


def _resource(
    kind: str,
    uid: str,
    *,
    owner_kind: str | None = None,
    owner_name: str | None = None,
    owner_uid: str | None = None,
    node_name: str | None = "node-a",
    labels: dict[str, str] | None = None,
) -> ResourceIdentity:
    return ResourceIdentity(
        api_version=(
            "batch/v1"
            if kind == "Job"
            else "apps/v1"
            if kind in {"Deployment", "ReplicaSet"}
            else "v1"
        ),
        kind=kind,
        name=f"resource-{kind.lower()}",
        namespace="chutes",
        uid=uid,
        labels=labels
        or {
            "chutes/deployment-id": "dep-1",
            "chutes/chute-id": "chute-1",
            "chutes/config-id": "config-1",
        },
        owner_api_version=(
            "batch/v1" if owner_kind == "Job" else "apps/v1" if owner_kind else None
        ),
        owner_kind=owner_kind,
        owner_name=owner_name
        or (f"resource-{owner_kind.lower()}" if owner_kind else None),
        owner_uid=owner_uid,
        node_name=node_name,
    )


EXPECTED_LABELS = {
    "chutes/deployment-id": "dep-1",
    "chutes/chute-id": "chute-1",
    "chutes/config-id": "config-1",
}


class _QueryResult:
    def __init__(self, value):
        self.value = value

    def unique(self):
        return self

    def scalar_one_or_none(self):
        return self.value

    def scalar_one(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        return self.value


def _rotation_lineage():
    operation = SimpleNamespace(
        operation_id="teardown-1",
        deployment_id="deployment-1",
        phase="discovering",
        retry_lease_owner=None,
        retry_lease_expires_at=None,
        lineage_conflict_at=None,
        last_failure=None,
        validator="validator-1",
        server_id="server-1",
        chute_id="chute-1",
        config_id="config-1",
        job_id=None,
        instance_id="instance-1",
        cluster_context="node-a",
        cluster_context_sha256="old-context-sha256",
        kubernetes_node_uid="node-uid-old",
        kubernetes_node_generation=3,
        registration_attestation_id="attestation-old",
        gpu_allocation_group_id="group-old",
        gpu_allocation_group_generation=7,
        gpu_hardware_uuids=["GPU-a", "GPU-b"],
    )
    deployment = SimpleNamespace(
        validator="validator-1",
        server_id="server-1",
        chute_id="chute-1",
        config_id="config-1",
        job_id=None,
        instance_id="instance-1",
    )
    server = SimpleNamespace(
        server_id="server-1",
        validator="validator-1",
        name="node-a",
        kubeconfig="new-kubeconfig",
        kubernetes_node_uid="node-uid-new",
        kubernetes_node_generation=4,
        registration_attestation_id="attestation-new",
        gpu_allocation_group_id="group-new",
        gpu_allocation_group_generation=8,
    )
    gpus = [
        SimpleNamespace(
            gpu_id=f"gpu-{suffix}",
            hardware_uuid=f"GPU-{suffix}",
            server_id="server-1",
            deployment_id="deployment-1",
            validator="validator-1",
            gpu_allocation_group_id="group-new",
            gpu_allocation_group_generation=8,
        )
        for suffix in ("a", "b")
    ]
    history = [
        SimpleNamespace(
            server_id="server-1",
            generation=3,
            kubernetes_node_uid="node-uid-old",
            registration_attestation_id="attestation-old",
            retired_at=object(),
        ),
        SimpleNamespace(
            server_id="server-1",
            generation=4,
            kubernetes_node_uid="node-uid-new",
            registration_attestation_id="attestation-new",
            retired_at=None,
        ),
    ]
    return operation, deployment, server, gpus, history


@pytest.mark.asyncio
async def test_teardown_snapshot_uses_locked_server_lineage_before_gpu_rows():
    stale_server = SimpleNamespace(
        name="stale-node",
        kubernetes_node_uid="stale-uid",
    )
    deployment = SimpleNamespace(
        launch_operation_id=None,
        teardown_operation_id=None,
        deployment_id="deployment-1",
        validator="validator-1",
        server_id="server-1",
        chute_id="chute-1",
        config_id="config-1",
        job_id=None,
        instance_id="instance-1",
        server=stale_server,
        active=True,
    )
    locked_server = SimpleNamespace(
        name="node-a",
        kubeconfig="locked-kubeconfig",
        kubernetes_node_uid="node-uid-3",
        kubernetes_node_generation=3,
        registration_attestation_id="attestation-3",
        gpu_allocation_group_id="group-3",
        gpu_allocation_group_generation=3,
    )
    gpu = SimpleNamespace(gpu_id="gpu-a", hardware_uuid="GPU-a")
    added = []
    session = SimpleNamespace(
        execute=AsyncMock(
            side_effect=[
                _QueryResult(None),
                _QueryResult(locked_server),
                _QueryResult([gpu]),
            ]
        ),
        add=lambda value: added.append(value),
        flush=AsyncMock(),
    )
    coordinator = teardown.DeploymentTeardownCoordinator()

    operation = await coordinator._request_in_session(session, deployment, "delete")

    statements = [str(call.args[0]) for call in session.execute.await_args_list]
    assert "FROM servers" in statements[1]
    assert "FOR UPDATE" in statements[1]
    assert "FROM gpus" in statements[2]
    assert operation.cluster_context == "node-a"
    assert operation.kubernetes_node_uid == "node-uid-3"
    assert operation.registration_attestation_id == "attestation-3"
    assert operation.gpu_allocation_group_id == "group-3"
    assert operation.gpu_allocation_group_generation == 3
    assert operation.gpu_hardware_uuids == ["GPU-a"]
    assert operation in added


@pytest.mark.asyncio
async def test_teardown_after_supported_rotation_uses_original_launch_lineage(
    monkeypatch,
):
    monkeypatch.setattr(teardown.settings, "gpu_tee_only", True)
    deployment_id = "11111111-1111-4111-8111-111111111111"
    monkeypatch.setattr(
        teardown,
        "request_registry_scope_revocation_in_session",
        AsyncMock(),
    )
    deployment = SimpleNamespace(
        launch_operation_id="launch-1",
        teardown_operation_id=None,
        deployment_id=deployment_id,
        validator="validator-1",
        server_id="server-1",
        chute_id="chute-1",
        version="1.0.0",
        config_id="config-1",
        job_id=None,
        instance_id=None,
        active=True,
    )
    old_server = SimpleNamespace(
        name="node-a",
        kubeconfig="old-kubeconfig",
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=1,
        registration_attestation_id="attestation-1",
        gpu_allocation_group_id="group-1",
        gpu_allocation_group_generation=1,
    )
    launch = SimpleNamespace(
        operation_id="launch-1",
        deployment_id=deployment_id,
        launch_intent_id="intent-1",
        phase="created",
        lease_owner=None,
        lease_expires_at=None,
        cluster_context="node-a",
        cluster_context_sha256=teardown.cluster_context_sha256(old_server),
        namespace="original-namespace",
        server_name="node-a",
        create_results={},
        service_name=None,
        service_uid=None,
        secret_name=None,
        secret_uid=None,
        job_name=None,
        job_uid=None,
    )
    lineage = {
        "schema": "chutes.miner-launch-lineage",
        "version": 1,
        "miner_hotkey": teardown.settings.miner_ss58,
        "validator": "validator-1",
        "deployment_id": deployment_id,
        "chute_id": "chute-1",
        "chute_version": "1.0.0",
        "server_id": "server-1",
        "kubernetes_node_uid": "node-uid-1",
        "kubernetes_node_generation": 1,
        "gpu_allocation_group_id": "group-1",
        "gpu_allocation_group_generation": 1,
        "job_id": None,
    }
    request = {
        "schema": "chutes.miner-launch-request.v1",
        "miner_launch_request_id": "intent-1",
        "lineage": lineage,
    }
    intent = SimpleNamespace(
        intent_id="intent-1",
        deployment_id=deployment_id,
        phase="completed",
        validator="validator-1",
        chute_id="chute-1",
        chute_version="1.0.0",
        server_id="server-1",
        job_id=None,
        job_cleanup_only=False,
        request_payload=request,
        request_sha256=teardown.canonical_sha256(request),
        lineage_sha256=teardown.canonical_sha256(lineage),
    )
    current_server = SimpleNamespace(
        server_id="server-1",
        validator="validator-1",
        name="node-a",
        kubeconfig="new-kubeconfig",
        kubernetes_node_uid="node-uid-2",
        kubernetes_node_generation=2,
        registration_attestation_id="attestation-2",
        gpu_allocation_group_id="group-2",
        gpu_allocation_group_generation=2,
    )
    predecessor = SimpleNamespace(
        server_id="server-1",
        generation=1,
        kubernetes_node_uid="node-uid-1",
        registration_attestation_id="attestation-1",
        retired_at=object(),
    )
    current_identity = SimpleNamespace(
        server_id="server-1",
        generation=2,
        kubernetes_node_uid="node-uid-2",
        registration_attestation_id="attestation-2",
        retired_at=None,
    )
    gpu = SimpleNamespace(
        gpu_id="gpu-1",
        hardware_uuid="GPU-1",
        server_id="server-1",
        deployment_id=deployment_id,
        validator="validator-1",
        gpu_allocation_group_id="group-2",
        gpu_allocation_group_generation=2,
    )

    async def get(model, *_args, **_kwargs):
        return launch if model.__name__ == "DeploymentLaunchOperation" else intent

    session = SimpleNamespace(
        get=AsyncMock(side_effect=get),
        execute=AsyncMock(
            side_effect=[
                _QueryResult(None),
                _QueryResult(current_server),
                _QueryResult(predecessor),
                _QueryResult([gpu]),
            ]
        ),
        add=Mock(),
        flush=AsyncMock(),
        scalar=AsyncMock(return_value=None),
    )

    operation = await teardown.DeploymentTeardownCoordinator()._request_in_session(
        session,
        deployment,
        "delete",
    )

    assert operation.cluster_context == "node-a"
    assert operation.cluster_context_sha256 == launch.cluster_context_sha256
    assert operation.namespace == "original-namespace"
    assert operation.kubernetes_node_uid == "node-uid-1"
    assert operation.kubernetes_node_generation == 1
    assert operation.registration_attestation_id == "attestation-1"
    assert operation.gpu_allocation_group_id == "group-1"
    assert operation.gpu_allocation_group_generation == 1
    handoff = authorized_node_incarnation_handoff_values(
        operation=operation,
        latest_handoff=None,
        deployment=deployment,
        server=current_server,
        gpu_rows=[gpu],
        node_history=[predecessor, current_identity],
    )
    assert handoff is not None
    assert handoff["from_kubernetes_node_uid"] == "node-uid-1"
    assert handoff["to_kubernetes_node_uid"] == "node-uid-2"


@pytest.mark.asyncio
async def test_replacement_adoption_commits_successor_predecessor_and_phase_atomically(
    monkeypatch,
):
    coordinator = teardown.DeploymentTeardownCoordinator()
    operation = SimpleNamespace(
        operation_id="operation-1",
        retry_lease_owner=coordinator.worker_id,
        retry_lease_expires_at=None,
        phase="verifying",
        cluster_context="node-a",
        namespace="chutes",
        last_failure="old",
    )
    predecessor = SimpleNamespace(
        resource_id="resource-old",
        operation_id="operation-1",
        state="delete_requested",
        replaced_by_resource_id=None,
    )
    added = []

    async def get(model, identity, **_kwargs):
        if model.__name__ == "DeploymentTeardownOperation":
            return operation
        return predecessor if identity == "resource-old" else None

    session = SimpleNamespace(
        get=AsyncMock(side_effect=get),
        execute=AsyncMock(return_value=_QueryResult(None)),
        add=lambda value: added.append(value),
        flush=AsyncMock(),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    replacement = _resource("Job", "job-new")
    await coordinator._adopt_replacement(
        "operation-1",
        replacement,
        predecessor_resource_id="resource-old",
    )

    assert len(added) == 1
    assert added[0].uid == "job-new"
    assert predecessor.state == "replaced"
    assert predecessor.replaced_by_resource_id == added[0].resource_id
    assert operation.phase == "deleting"
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_orphan_replacement_adoption_is_one_durable_transition(monkeypatch):
    coordinator = teardown.DeploymentTeardownCoordinator()
    tombstone = SimpleNamespace(
        tombstone_id="tombstone-1",
        retry_lease_owner=coordinator.worker_id,
        retry_lease_expires_at=None,
        phase="verifying",
        last_failure="old",
    )
    predecessor = SimpleNamespace(
        resource_id="resource-old",
        tombstone_id="tombstone-1",
        state="delete_requested",
        absent_at=None,
    )
    added = []

    async def get(model, identity, **_kwargs):
        if model.__name__ == "KubernetesOrphanTombstone":
            return tombstone
        return predecessor if identity == "resource-old" else None

    session = SimpleNamespace(
        get=AsyncMock(side_effect=get),
        execute=AsyncMock(return_value=_QueryResult(None)),
        add=lambda value: added.append(value),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    replacement = _resource("Job", "job-new")
    await coordinator._adopt_orphan_replacement(
        "tombstone-1",
        replacement,
        predecessor_resource_id="resource-old",
    )

    assert len(added) == 1
    assert added[0].uid == "job-new"
    assert predecessor.state == "absent"
    assert predecessor.absent_at is not None
    assert tombstone.phase == "deleting"
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_orphan_request_persists_exact_registry_revocation_outbox(monkeypatch):
    monkeypatch.setattr(teardown.settings, "gpu_tee_only", True)
    server = SimpleNamespace(
        server_id="server-1",
        validator="validator-1",
        name="node-a",
        kubeconfig="kubeconfig",
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
    )
    added = []
    session = SimpleNamespace(
        get=AsyncMock(return_value=None),
        execute=AsyncMock(side_effect=[_QueryResult(server), _QueryResult(None)]),
        add=added.append,
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    persist_revoke = AsyncMock()
    monkeypatch.setattr(teardown, "get_session", fake_session)
    monkeypatch.setattr(
        teardown,
        "request_registry_scope_revocation_in_session",
        persist_revoke,
    )
    coordinator = teardown.DeploymentTeardownCoordinator()

    tombstone_id = await coordinator.request_orphan(
        deployment_id="dep-1",
        cluster_context="node-a",
        immutable_labels=EXPECTED_LABELS,
    )

    assert tombstone_id == added[0].tombstone_id
    persist_revoke.assert_awaited_once_with(
        session,
        launch_config_id="config-1",
        validator="validator-1",
        server_id="server-1",
        deployment_id="dep-1",
    )
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_duplicate_orphan_request_rejects_changed_labels_before_outbox(
    monkeypatch,
):
    monkeypatch.setattr(teardown.settings, "gpu_tee_only", True)
    server = SimpleNamespace(
        server_id="server-1",
        validator="validator-1",
        name="node-a",
        kubeconfig="kubeconfig",
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
    )
    existing = SimpleNamespace(
        tombstone_id="tombstone-1",
        namespace="chutes",
        cluster_context_sha256=teardown.cluster_context_sha256(server),
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
        immutable_labels=EXPECTED_LABELS,
    )
    session = SimpleNamespace(
        get=AsyncMock(return_value=None),
        execute=AsyncMock(side_effect=[_QueryResult(server), _QueryResult(existing)]),
        add=Mock(),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    persist_revoke = AsyncMock()
    monkeypatch.setattr(teardown, "get_session", fake_session)
    monkeypatch.setattr(
        teardown,
        "request_registry_scope_revocation_in_session",
        persist_revoke,
    )
    coordinator = teardown.DeploymentTeardownCoordinator()

    with pytest.raises(LineageConflict, match="changed its immutable authority"):
        await coordinator.request_orphan(
            deployment_id="dep-1",
            cluster_context="node-a",
            immutable_labels={**EXPECTED_LABELS, "chutes/config-id": "config-2"},
        )

    persist_revoke.assert_not_awaited()
    session.add.assert_not_called()
    session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_orphan_request_rechecks_deployment_after_server_lock(monkeypatch):
    monkeypatch.setattr(teardown.settings, "gpu_tee_only", True)
    server = SimpleNamespace(
        server_id="server-1",
        validator="validator-1",
        name="node-a",
        kubeconfig="kubeconfig",
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
    )
    deployment = SimpleNamespace(deployment_id="dep-1")
    events: list[str] = []

    async def execute(_statement):
        if "server_locked" not in events:
            events.append("server_locked")
            return _QueryResult(server)
        return _QueryResult(None)

    async def get(_model, _identity, **_kwargs):
        # This models a placement that commits while the orphan requester is
        # waiting for the shared Server-row fence.
        if "server_locked" in events:
            events.append("deployment_read_after_lock")
            return deployment
        events.append("stale_deployment_read_before_lock")
        return None

    session = SimpleNamespace(
        get=AsyncMock(side_effect=get),
        execute=AsyncMock(side_effect=execute),
        add=Mock(),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    persist_revoke = AsyncMock()
    monkeypatch.setattr(teardown, "get_session", fake_session)
    monkeypatch.setattr(
        teardown,
        "request_registry_scope_revocation_in_session",
        persist_revoke,
    )
    coordinator = teardown.DeploymentTeardownCoordinator()

    assert (
        await coordinator.request_orphan(
            deployment_id="dep-1",
            cluster_context="node-a",
            immutable_labels=EXPECTED_LABELS,
        )
        is None
    )
    assert events == ["server_locked", "deployment_read_after_lock"]
    persist_revoke.assert_not_awaited()
    session.add.assert_not_called()
    session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_seedless_orphan_without_config_fails_before_outbox(monkeypatch):
    monkeypatch.setattr(teardown.settings, "gpu_tee_only", True)
    server = SimpleNamespace(
        server_id="server-1",
        validator="validator-1",
        name="node-a",
        kubeconfig="kubeconfig",
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
    )
    session = SimpleNamespace(
        get=AsyncMock(return_value=None),
        execute=AsyncMock(side_effect=[_QueryResult(server), _QueryResult(None)]),
        add=Mock(),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    persist_revoke = AsyncMock()
    monkeypatch.setattr(teardown, "get_session", fake_session)
    monkeypatch.setattr(
        teardown,
        "request_registry_scope_revocation_in_session",
        persist_revoke,
    )
    coordinator = teardown.DeploymentTeardownCoordinator()

    with pytest.raises(
        DeploymentFailure,
        match="lacks exact registry config authority",
    ):
        await coordinator.request_orphan(
            deployment_id="dep-1",
            cluster_context="node-a",
            immutable_labels={
                "chutes/deployment-id": "dep-1",
                "chutes/chute-id": "chute-1",
            },
        )

    persist_revoke.assert_not_awaited()
    session.add.assert_not_called()
    session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_orphan_registry_completion_reuses_durable_ack_after_crash(monkeypatch):
    monkeypatch.setattr(teardown.settings, "gpu_tee_only", True)
    server = SimpleNamespace(
        server_id="server-1",
        validator="validator-1",
        name="node-a",
        kubeconfig="kubeconfig",
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
    )
    tombstone = SimpleNamespace(
        deployment_id="dep-1",
        cluster_context="node-a",
        cluster_context_sha256=teardown.cluster_context_sha256(server),
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
        immutable_labels=EXPECTED_LABELS,
    )
    revoked_at = datetime.now(timezone.utc)
    intent = SimpleNamespace(
        launch_config_id="config-1",
        validator="validator-1",
        server_id="server-1",
        deployment_id="dep-1",
        desired_state="revoked",
        phase="revoked",
        revocation_ack={
            "status": "revoked",
            "revoked": True,
            "launch_config_id": "config-1",
            "server_id": "server-1",
        },
        revoked_at=revoked_at,
    )
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_QueryResult(server)),
        get=AsyncMock(return_value=intent),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator = teardown.DeploymentTeardownCoordinator()
    coordinator._revoke_registry_identity = AsyncMock()

    ack = await coordinator._ensure_orphan_registry_revoked(tombstone)

    assert ack == intent.revocation_ack
    coordinator._revoke_registry_identity.assert_not_awaited()


@pytest.mark.asyncio
async def test_orphan_retries_already_absent_after_ack_record_crash_before_completion(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(teardown.settings, "gpu_tee_only", True)
    token_file = tmp_path / "registry-workload-token"
    token_file.write_text("w" * 64, encoding="ascii")
    monkeypatch.setattr(
        teardown.settings,
        "registry_workload_token_file",
        str(token_file),
    )
    server = SimpleNamespace(
        server_id="server-1",
        validator="validator-1",
        hotkey="validator-1",
        name="node-a",
        kubeconfig="kubeconfig",
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
    )
    tombstone = SimpleNamespace(
        tombstone_id="tombstone-1",
        deployment_id="dep-1",
        cluster_context="node-a",
        cluster_context_sha256=teardown.cluster_context_sha256(server),
        namespace="chutes",
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
        immutable_labels=EXPECTED_LABELS,
        phase="verifying",
        retry_lease_owner=None,
        retry_lease_expires_at=None,
        next_retry_at=None,
        attempt_count=0,
        lineage_conflict_at=None,
        last_failure=None,
        completed_at=None,
    )
    intent = SimpleNamespace(
        launch_config_id="config-1",
        validator="validator-1",
        server_id="server-1",
        deployment_id="dep-1",
        desired_state="revoked",
        phase="revoke_pending",
        revocation_ack=None,
        revoked_at=None,
    )

    async def get(model, _identity, **_kwargs):
        if model is teardown.KubernetesOrphanTombstone:
            return tombstone
        if model is teardown.Deployment:
            return None
        if model is teardown.RegistryScopeIntent:
            return intent
        raise AssertionError(f"unexpected model lookup: {model}")

    class EmptyRows:
        @staticmethod
        def scalars():
            return iter(())

    async def execute(statement):
        sql = str(statement)
        if "FROM servers" in sql:
            return _QueryResult(server)
        if "FROM kubernetes_orphan_tombstones" in sql:
            return _QueryResult(tombstone)
        if "FROM kubernetes_orphan_tombstone_resources" in sql:
            return EmptyRows()
        raise AssertionError(f"unexpected statement: {sql}")

    session = SimpleNamespace(
        get=AsyncMock(side_effect=get),
        execute=AsyncMock(side_effect=execute),
        scalar=AsyncMock(return_value=None),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    broker_payloads = [
        {
            "status": "revoked",
            "revoked": True,
            "launch_config_id": "config-1",
            "server_id": "server-1",
        },
        {
            "status": "already_absent",
            "revoked": True,
            "launch_config_id": "config-1",
            "server_id": "server-1",
        },
    ]

    class Response:
        status = 200

        def __init__(self, payload):
            self.payload = payload

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return self.payload

    class Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def delete(self, *_args, **_kwargs):
            return Response(broker_payloads.pop(0))

    record_attempts = 0

    async def record_revoked(launch_config_id, payload):
        nonlocal record_attempts
        record_attempts += 1
        assert launch_config_id == "config-1"
        if record_attempts == 1:
            assert payload["status"] == "revoked"
            raise RuntimeError("simulated crash before durable registry ACK")
        assert payload["status"] == "already_absent"
        intent.phase = "revoked"
        intent.revocation_ack = {
            "status": "revoked",
            "revoked": True,
            "launch_config_id": "config-1",
            "server_id": "server-1",
        }
        intent.revoked_at = datetime.now(timezone.utc)
        return intent.revocation_ack

    request_revoke = AsyncMock()
    record_failure = AsyncMock()
    monkeypatch.setattr(teardown, "get_session", fake_session)
    monkeypatch.setattr(teardown, "validator_by_hotkey", lambda _hotkey: server)
    monkeypatch.setattr(teardown, "sign_request", lambda **_kwargs: ({}, None))
    monkeypatch.setattr(teardown.aiohttp, "ClientSession", Client)
    monkeypatch.setattr(
        teardown,
        "request_registry_scope_revocation",
        request_revoke,
    )
    monkeypatch.setattr(teardown, "record_registry_scope_revoked", record_revoked)
    monkeypatch.setattr(teardown, "record_registry_scope_failure", record_failure)
    coordinator = teardown.DeploymentTeardownCoordinator(
        kubernetes=SimpleNamespace(list_resources=Mock(return_value=[]))
    )
    coordinator._renew_orphan_lease = AsyncMock()

    assert await coordinator.run_orphan("tombstone-1") is False
    assert tombstone.phase == "verifying"
    assert tombstone.completed_at is None
    assert intent.phase == "revoke_pending"
    assert intent.revocation_ack is None
    record_failure.assert_awaited_once()

    # Model the durable backoff elapsing. The replay must consume the broker's
    # authenticated already_absent result and persist the canonical ACK before
    # the tombstone can cross its completion boundary.
    tombstone.next_retry_at = None
    assert await coordinator.run_orphan("tombstone-1") is True
    assert tombstone.phase == "completed"
    assert tombstone.completed_at is not None
    assert intent.phase == "revoked"
    assert intent.revocation_ack == {
        "status": "revoked",
        "revoked": True,
        "launch_config_id": "config-1",
        "server_id": "server-1",
    }
    assert record_attempts == 2
    assert request_revoke.await_count == 2
    assert broker_payloads == []


@pytest.mark.asyncio
async def test_orphan_registry_broker_outage_stays_in_durable_retry_outbox(monkeypatch):
    monkeypatch.setattr(teardown.settings, "gpu_tee_only", True)
    server = SimpleNamespace(
        server_id="server-1",
        validator="validator-1",
        name="node-a",
        kubeconfig="kubeconfig",
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
    )
    tombstone = SimpleNamespace(
        deployment_id="dep-1",
        cluster_context="node-a",
        cluster_context_sha256=teardown.cluster_context_sha256(server),
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
        immutable_labels=EXPECTED_LABELS,
    )
    intent = SimpleNamespace(
        launch_config_id="config-1",
        validator="validator-1",
        server_id="server-1",
        deployment_id="dep-1",
        desired_state="revoked",
        phase="revoke_pending",
        revocation_ack=None,
        revoked_at=None,
    )
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_QueryResult(server)),
        get=AsyncMock(return_value=intent),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    failure = DeploymentFailure("registry broker unavailable")
    record_failure = AsyncMock()
    monkeypatch.setattr(teardown, "get_session", fake_session)
    monkeypatch.setattr(teardown, "record_registry_scope_failure", record_failure)
    coordinator = teardown.DeploymentTeardownCoordinator()
    coordinator._revoke_registry_identity = AsyncMock(side_effect=failure)

    with pytest.raises(DeploymentFailure, match="registry broker unavailable"):
        await coordinator._ensure_orphan_registry_revoked(tombstone)

    record_failure.assert_awaited_once_with("config-1", failure)


@pytest.mark.asyncio
async def test_orphan_broker_outage_cannot_terminalize_tombstone(monkeypatch):
    monkeypatch.setattr(teardown.settings, "gpu_tee_only", True)
    server = SimpleNamespace(
        server_id="server-1",
        validator="validator-1",
        name="node-a",
        kubeconfig="kubeconfig",
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
    )
    coordinator = teardown.DeploymentTeardownCoordinator(
        kubernetes=SimpleNamespace(list_resources=Mock(return_value=[]))
    )
    tombstone = SimpleNamespace(
        tombstone_id="tombstone-1",
        deployment_id="dep-1",
        cluster_context="node-a",
        cluster_context_sha256=teardown.cluster_context_sha256(server),
        namespace="chutes",
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
        immutable_labels=EXPECTED_LABELS,
        phase="verifying",
        retry_lease_owner=None,
        retry_lease_expires_at=None,
        next_retry_at=None,
        attempt_count=0,
        lineage_conflict_at=None,
        last_failure=None,
        completed_at=None,
    )

    async def get(model, _identity, **_kwargs):
        if model.__name__ == "Deployment":
            return None
        return tombstone

    session = SimpleNamespace(
        get=AsyncMock(side_effect=get),
        execute=AsyncMock(
            side_effect=[
                _QueryResult(server),
                SimpleNamespace(scalars=lambda: iter(())),
            ]
        ),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator._renew_orphan_lease = AsyncMock()
    coordinator._ensure_orphan_registry_revoked = AsyncMock(
        side_effect=DeploymentFailure("registry broker unavailable")
    )

    assert await coordinator.run_orphan("tombstone-1") is False
    assert tombstone.phase == "verifying"
    assert tombstone.completed_at is None
    assert tombstone.retry_lease_owner is None
    assert tombstone.retry_lease_expires_at is None
    assert tombstone.next_retry_at is not None
    assert "registry broker unavailable" in tombstone.last_failure


@pytest.mark.asyncio
async def test_nonseedless_orphan_with_config_completes_without_registry_broker(monkeypatch):
    monkeypatch.setattr(teardown.settings, "gpu_tee_only", False)
    server = SimpleNamespace(
        server_id="server-1",
        validator="validator-1",
        name="node-a",
        kubeconfig="kubeconfig",
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
    )
    coordinator = teardown.DeploymentTeardownCoordinator(
        kubernetes=SimpleNamespace(list_resources=Mock(return_value=[]))
    )
    tombstone = SimpleNamespace(
        tombstone_id="tombstone-1",
        deployment_id="dep-1",
        cluster_context="node-a",
        cluster_context_sha256=teardown.cluster_context_sha256(server),
        namespace="chutes",
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
        immutable_labels=EXPECTED_LABELS,
        phase="verifying",
        retry_lease_owner=None,
        retry_lease_expires_at=None,
        next_retry_at=None,
        attempt_count=0,
        lineage_conflict_at=None,
        last_failure=None,
        completed_at=None,
    )

    async def get(model, _identity, **_kwargs):
        if model.__name__ == "Deployment":
            return None
        return tombstone

    def empty_rows():
        return SimpleNamespace(scalars=lambda: iter(()))

    session = SimpleNamespace(
        get=AsyncMock(side_effect=get),
        execute=AsyncMock(
            side_effect=[
                _QueryResult(server),
                empty_rows(),
                _QueryResult(server),
                _QueryResult(tombstone),
                empty_rows(),
            ]
        ),
        scalar=AsyncMock(return_value=None),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator._renew_orphan_lease = AsyncMock()
    coordinator._revoke_registry_identity = AsyncMock()

    assert await coordinator.run_orphan("tombstone-1") is True
    assert tombstone.phase == "completed"
    assert tombstone.completed_at is not None
    coordinator._revoke_registry_identity.assert_not_awaited()


@pytest.mark.asyncio
async def test_controller_is_directly_absent_before_child_delete(monkeypatch):
    coordinator = teardown.DeploymentTeardownCoordinator(
        kubernetes=SimpleNamespace(
            delete_resource=Mock(return_value="delete_requested")
        )
    )
    job = SimpleNamespace(
        resource_id="job-row",
        kind="Job",
        name="job-1",
        uid="job-uid",
        namespace="chutes",
        owner_uid=None,
        state="observed",
        delete_requested_at=None,
    )
    pod = SimpleNamespace(
        resource_id="pod-row",
        operation_id="operation-1",
        api_version="v1",
        kind="Pod",
        name="pod-1",
        uid="pod-uid",
        namespace="chutes",
        owner_uid="job-uid",
        state="observed",
        delete_requested_at=None,
    )
    operation = SimpleNamespace(
        operation_id="operation-1",
        cluster_context="node-a",
        resources=[pod, job],
    )
    by_id = {"job-row": job, "pod-row": pod}
    session = SimpleNamespace(
        get=AsyncMock(side_effect=lambda _model, identity, **_kwargs: by_id[identity]),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator._renew_operation_lease = AsyncMock()
    coordinator._advance = AsyncMock()
    coordinator._ensure_operation_pod_finalizers = AsyncMock()

    await coordinator._delete_resources(operation)
    assert coordinator.kubernetes.delete_resource.call_args.kwargs["kind"] == "Job"
    assert coordinator.kubernetes.delete_resource.call_count == 1
    assert pod.state == "observed"

    job.state = "absent"
    await coordinator._delete_resources(operation)
    assert coordinator.kubernetes.delete_resource.call_count == 2
    assert coordinator.kubernetes.delete_resource.call_args.kwargs["kind"] == "Pod"


@pytest.mark.asyncio
async def test_validator_job_release_ack_is_required_and_retryable(monkeypatch):
    coordinator = teardown.DeploymentTeardownCoordinator()
    operation = SimpleNamespace(
        operation_id="operation-1",
        phase="revoking",
        retry_lease_owner=coordinator.worker_id,
        retry_lease_expires_at=None,
        config_id=None,
        job_id="job-1",
        validator_job_release_ack=None,
        validator_job_released_at=None,
        instance_id=None,
    )
    coordinator._release_validator_job = AsyncMock(
        side_effect=DeploymentFailure("validator unavailable")
    )
    coordinator._advance = AsyncMock()
    with pytest.raises(DeploymentFailure, match="validator unavailable"):
        await coordinator._revoke(operation)
    assert operation.validator_job_release_ack is None
    coordinator._advance.assert_not_awaited()

    ack = {"status": "already_absent", "job_id": "job-1"}
    coordinator._release_validator_job = AsyncMock(return_value=ack)
    coordinator._load = AsyncMock(return_value=operation)
    session = SimpleNamespace(get=AsyncMock(return_value=operation), commit=AsyncMock())

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    await coordinator._revoke(operation)
    assert operation.validator_job_release_ack == ack
    assert operation.validator_job_released_at is not None
    coordinator._advance.assert_awaited_once_with(
        "operation-1",
        "revoking",
        "deleting",
        last_failure=None,
    )


@pytest.mark.asyncio
async def test_old_generation_teardown_persists_authorized_node_rotation(monkeypatch):
    operation, deployment, server, gpus, history = _rotation_lineage()
    added = []
    session = SimpleNamespace(
        execute=AsyncMock(
            side_effect=[
                _QueryResult(deployment),
                _QueryResult(operation),
                _QueryResult(None),
                _QueryResult(server),
                _QueryResult(gpus),
                _QueryResult(history),
            ]
        ),
        add=lambda value: added.append(value),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator = teardown.DeploymentTeardownCoordinator()
    operation.retry_lease_owner = coordinator.worker_id
    await coordinator._authorize_current_node_incarnation(operation.operation_id)

    assert len(added) == 1
    handoff = added[0]
    assert handoff.from_kubernetes_node_uid == "node-uid-old"
    assert handoff.from_kubernetes_node_generation == 3
    assert handoff.to_kubernetes_node_uid == "node-uid-new"
    assert handoff.to_kubernetes_node_generation == 4
    assert handoff.to_registration_attestation_id == "attestation-new"
    assert handoff.to_gpu_allocation_group_id == "group-new"
    assert operation.kubernetes_node_uid == "node-uid-old"
    assert operation.registration_attestation_id == "attestation-old"
    assert operation.lineage_conflict_at is None
    session.commit.assert_awaited_once()
    assert (
        authorized_node_incarnation_handoff_values(
            operation=operation,
            latest_handoff=handoff,
            deployment=deployment,
            server=server,
            gpu_rows=gpus,
            node_history=history,
        )
        is None
    )


@pytest.mark.asyncio
async def test_unattested_node_rotation_fences_unfinished_teardown(monkeypatch):
    operation, deployment, server, gpus, history = _rotation_lineage()
    history[-1].registration_attestation_id = "attestation-conflict"
    session = SimpleNamespace(
        execute=AsyncMock(
            side_effect=[
                _QueryResult(deployment),
                _QueryResult(operation),
                _QueryResult(None),
                _QueryResult(server),
                _QueryResult(gpus),
                _QueryResult(history),
            ]
        ),
        add=lambda _value: pytest.fail("conflicting rotation was persisted"),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator = teardown.DeploymentTeardownCoordinator()
    operation.retry_lease_owner = coordinator.worker_id
    with pytest.raises(DeploymentFailure, match="active node identity"):
        await coordinator._authorize_current_node_incarnation(operation.operation_id)

    assert operation.lineage_conflict_at is not None
    assert operation.retry_lease_owner is None
    assert "active node identity" in operation.last_failure
    session.commit.assert_awaited_once()


def test_handoff_requires_exact_current_gpu_ownership():
    operation, deployment, server, gpus, history = _rotation_lineage()
    gpus[1].deployment_id = "other-deployment"
    with pytest.raises(DeploymentFailure, match="assigned GPU lineage"):
        authorized_node_incarnation_handoff_values(
            operation=operation,
            latest_handoff=None,
            deployment=deployment,
            server=server,
            gpu_rows=gpus,
            node_history=history,
        )


def test_matching_controller_replacement_is_captured_but_conflicting_lineage_stops():
    replacement_job = _resource("Job", "job-new")
    assert replacement_matches(
        expected_labels=EXPECTED_LABELS,
        expected_node_name="node-a",
        accepted_owners={},
        resource=replacement_job,
    )
    replacement_pod = _resource(
        "Pod",
        "pod-new",
        owner_kind="Job",
        owner_uid="job-new",
    )
    assert replacement_matches(
        expected_labels=EXPECTED_LABELS,
        expected_node_name="node-a",
        accepted_owners={"job-new": ("batch/v1", "Job", "resource-job")},
        resource=replacement_pod,
    )
    with pytest.raises(UnresolvedOwnerLineage):
        replacement_matches(
            expected_labels=EXPECTED_LABELS,
            expected_node_name="node-a",
            accepted_owners={"job-new": ("batch/v1", "Job", "resource-job")},
            resource=_resource(
                "Pod",
                "pod-conflict",
                owner_kind="Job",
                owner_uid="other-job",
            ),
        )
    for conflict in (
        _resource("Job", "wrong-node", node_name="node-b"),
        _resource(
            "Service",
            "missing-config",
            labels={
                "chutes/deployment-id": "dep-1",
                "chutes/chute-id": "chute-1",
            },
        ),
        _resource(
            "Job",
            "wrong-job",
            labels={**EXPECTED_LABELS, "chutes/job-id": "job-2"},
        ),
    ):
        with pytest.raises(LineageConflict):
            replacement_matches(
                expected_labels={
                    **EXPECTED_LABELS,
                    **(
                        {"chutes/job-id": "job-1"}
                        if conflict.uid == "wrong-job"
                        else {}
                    ),
                },
                expected_node_name="node-a",
                accepted_owners={},
                resource=conflict,
            )


def test_registry_secret_replacement_requires_exact_launch_config_lineage():
    assert replacement_matches(
        expected_labels=EXPECTED_LABELS,
        expected_node_name="node-a",
        accepted_owners={},
        resource=_resource(
            "Secret",
            "secret-new",
            node_name=None,
            labels={"chutes/launch-config-id": "config-1"},
        ),
    )
    with pytest.raises(LineageConflict):
        replacement_matches(
            expected_labels=EXPECTED_LABELS,
            expected_node_name="node-a",
            accepted_owners={},
            resource=_resource(
                "Secret",
                "secret-conflict",
                node_name=None,
                labels={"chutes/launch-config-id": "config-2"},
            ),
        )


def test_direct_delete_uses_kubernetes_uid_precondition(monkeypatch):
    calls = []

    class Core:
        def delete_namespaced_pod(self, **kwargs):
            calls.append(kwargs)

    app = SimpleNamespace()
    batch = SimpleNamespace()
    core = Core()
    monkeypatch.setattr(teardown, "k8s_app_client", lambda: app)
    monkeypatch.setattr(teardown, "k8s_batch_client", lambda: batch)
    monkeypatch.setattr(teardown, "k8s_core_client", lambda: core)
    closure = DirectKubernetesClosure(operator=SimpleNamespace())
    assert (
        closure.delete_resource(
            cluster_context="node-a",
            namespace="chutes",
            kind="Pod",
            name="pod-a",
            uid="uid-a",
        )
        == "delete_requested"
    )
    assert len(calls) == 1
    assert calls[0]["body"].preconditions.uid == "uid-a"
    assert calls[0]["body"].propagation_policy == "Foreground"
    assert calls[0]["body"].grace_period_seconds > 0


def test_zero_shutdown_grace_is_rejected_at_config_and_delete_boundaries(monkeypatch):
    with pytest.raises(ValidationError, match="greater than 0"):
        Settings(chute_shutdown_time_seconds=0)

    calls = []

    class Core:
        def delete_namespaced_pod(self, **kwargs):
            calls.append(kwargs)

    monkeypatch.setattr(teardown, "k8s_app_client", lambda: SimpleNamespace())
    monkeypatch.setattr(teardown, "k8s_batch_client", lambda: SimpleNamespace())
    monkeypatch.setattr(teardown, "k8s_core_client", Core)
    monkeypatch.setattr(teardown.settings, "chute_shutdown_time_seconds", 0)
    closure = DirectKubernetesClosure(operator=SimpleNamespace())

    with pytest.raises(DeploymentFailure, match="must be a positive integer"):
        closure.delete_resource(
            cluster_context="node-a",
            namespace="chutes",
            kind="Pod",
            name="pod-a",
            uid="uid-a",
        )
    assert calls == []


def test_gpu_pod_evidence_requirement_uses_exact_launch_mutation_frontier():
    operation = SimpleNamespace(
        gpu_hardware_uuids=["GPU-a"],
        launch_operation_id="launch-1",
        launch_phase_at_request="reserved",
        launch_kubernetes_mutation_possible=False,
        launch_create_results_sha256=teardown.canonical_sha256({}),
    )
    assert not teardown._requires_pod_termination_evidence(operation)

    operation.launch_phase_at_request = "creating"
    operation.launch_kubernetes_mutation_possible = True
    assert teardown._requires_pod_termination_evidence(operation)

    operation.launch_phase_at_request = "reserved"
    operation.launch_kubernetes_mutation_possible = False
    operation.launch_create_results_sha256 = "0" * 64
    assert teardown._requires_pod_termination_evidence(operation)

    operation.launch_operation_id = None
    assert teardown._requires_pod_termination_evidence(operation)

    operation.gpu_hardware_uuids = []
    assert not teardown._requires_pod_termination_evidence(operation)


def test_uid_precondition_conflict_advances_to_direct_replacement_verification(
    monkeypatch,
):
    class Core:
        @staticmethod
        def delete_namespaced_pod(**kwargs):
            raise ApiException(status=409, reason="UID precondition failed")

    monkeypatch.setattr(teardown, "k8s_app_client", lambda: SimpleNamespace())
    monkeypatch.setattr(teardown, "k8s_batch_client", lambda: SimpleNamespace())
    monkeypatch.setattr(teardown, "k8s_core_client", Core)
    closure = DirectKubernetesClosure(operator=SimpleNamespace())
    assert (
        closure.delete_resource(
            cluster_context="node-a",
            namespace="chutes",
            kind="Pod",
            name="pod-a",
            uid="old-uid",
        )
        == "uid_changed"
    )


def _terminal_pod(*, finalizers=None, deletion_timestamp="2026-07-27T20:00:00Z"):
    terminated = SimpleNamespace(
        exit_code=0,
        signal=0,
        reason="Completed",
        started_at="2026-07-27T19:59:00Z",
        finished_at="2026-07-27T20:00:00Z",
    )
    return SimpleNamespace(
        api_version="v1",
        metadata=SimpleNamespace(
            name="pod-a",
            namespace="chutes",
            uid="pod-uid",
            resource_version="17",
            labels=dict(EXPECTED_LABELS),
            owner_references=[],
            finalizers=list(finalizers or []),
            deletion_timestamp=deletion_timestamp,
        ),
        spec=SimpleNamespace(
            node_name="node-a",
            init_containers=[],
            containers=[SimpleNamespace(name="worker")],
            ephemeral_containers=[],
        ),
        status=SimpleNamespace(
            init_container_statuses=[],
            container_statuses=[
                SimpleNamespace(
                    name="worker",
                    container_id="containerd://exact-container-id",
                    state=SimpleNamespace(terminated=terminated, running=None),
                )
            ],
            ephemeral_container_statuses=[],
        ),
    )


def test_pod_terminal_evidence_requires_our_finalizer_and_every_container_status():
    pod = _terminal_pod(finalizers=[teardown.POD_TEARDOWN_FINALIZER])
    evidence = teardown._pod_termination_evidence(pod)
    assert evidence["pod_uid"] == "pod-uid"
    assert evidence["node_name"] == "node-a"
    assert evidence["teardown_finalizer"] == teardown.POD_TEARDOWN_FINALIZER
    assert evidence["containers"] == [
        {
            "group": "container",
            "name": "worker",
            "outcome": "terminated",
            "container_id": "containerd://exact-container-id",
            "exit_code": 0,
            "signal": 0,
            "reason": "Completed",
            "started_at": "2026-07-27T19:59:00Z",
            "finished_at": "2026-07-27T20:00:00Z",
        }
    ]

    pod.metadata.finalizers = []
    assert teardown._pod_termination_evidence(pod) is None
    pod.metadata.finalizers = [teardown.POD_TEARDOWN_FINALIZER]
    pod.status.container_statuses = []
    assert teardown._pod_termination_evidence(pod) is None


def test_pending_pod_persists_exact_never_started_evidence():
    pod = _terminal_pod(finalizers=[teardown.POD_TEARDOWN_FINALIZER])
    pod.status.phase = "Pending"
    pod.status.container_statuses = [
        SimpleNamespace(
            name="worker",
            container_id=None,
            restart_count=0,
            state=SimpleNamespace(
                terminated=None,
                running=None,
                waiting=SimpleNamespace(reason="ImagePullBackOff"),
            ),
        )
    ]

    evidence = teardown._pod_termination_evidence(pod)

    assert evidence["schema"] == teardown.POD_TERMINATION_EVIDENCE_V2_SCHEMA
    assert evidence["outcome"] == "never_started"
    assert evidence["pod_phase"] == "Pending"
    assert evidence["containers"] == [
        {
            "group": "container",
            "name": "worker",
            "outcome": "never_started",
            "waiting_reason": "ImagePullBackOff",
            "restart_count": 0,
        }
    ]


def test_never_started_evidence_rejects_non_pending_phase_even_with_matching_hash():
    pod = _terminal_pod(finalizers=[teardown.POD_TEARDOWN_FINALIZER])
    pod.status.phase = "Pending"
    pod.status.container_statuses = []
    evidence = teardown._pod_termination_evidence(pod)
    resource = SimpleNamespace(
        kind="Pod",
        uid="pod-uid",
        node_name="node-a",
        pod_already_terminating=False,
        pod_termination_evidence=evidence,
        pod_termination_evidence_sha256=teardown.canonical_sha256(evidence),
    )

    assert teardown._verified_pod_termination_evidence(resource) == evidence

    tampered = {**evidence, "pod_phase": "Running"}
    resource.pod_termination_evidence = tampered
    resource.pod_termination_evidence_sha256 = teardown.canonical_sha256(tampered)
    with pytest.raises(LineageConflict, match="Pod termination evidence is invalid"):
        teardown._verified_pod_termination_evidence(resource)


def test_already_terminating_observation_is_first_class():
    pod = _terminal_pod(finalizers=[teardown.POD_TEARDOWN_FINALIZER])
    identity = teardown._identity("Pod", pod)
    assert identity.pod_already_terminating is True

    pod.metadata.deletion_timestamp = None
    identity = teardown._identity("Pod", pod)
    assert identity.pod_already_terminating is False


@pytest.mark.parametrize(
    ("job_uid", "outcome"),
    [(None, "never_started"), ("job-uid", "no_pod_observed")],
)
def test_zero_pod_lifecycle_is_bound_to_exact_launch_frontier(job_uid, outcome):
    launch = SimpleNamespace(
        operation_id="launch-1",
        deployment_id="deployment-1",
        phase="created",
        cluster_context="node-a",
        canonical_workload_spec_sha256="c" * 64,
        service_name="service-a",
        service_uid="service-uid",
        secret_name=None,
        secret_uid=None,
        job_name="job-a" if job_uid else None,
        job_uid=job_uid,
        create_results={},
    )
    frontier = teardown._launch_frontier_document(launch)
    operation = SimpleNamespace(
        operation_id="operation-1",
        deployment_id="deployment-1",
        launch_operation_id="launch-1",
        launch_phase_at_request="created",
        launch_create_results_sha256=teardown.canonical_sha256({}),
        launch_frontier=frontier,
        launch_frontier_sha256=teardown.canonical_sha256(frontier),
        cluster_context="node-a",
        resource_discovery_sha256="d" * 64,
        gpu_hardware_uuids=["GPU-1"],
        pod_lifecycle_evidence=None,
        pod_lifecycle_evidence_sha256=None,
        pod_lifecycle_evidence_recorded_at=None,
    )
    evidence = {
        "schema": teardown.POD_LIFECYCLE_EVIDENCE_SCHEMA,
        "outcome": outcome,
        "operation_id": "operation-1",
        "deployment_id": "deployment-1",
        "launch_frontier_sha256": operation.launch_frontier_sha256,
        "resource_discovery_sha256": operation.resource_discovery_sha256,
        "job_uid": job_uid,
        "controllers_absent": True,
        "selector_absent": True,
    }
    operation.pod_lifecycle_evidence = evidence
    operation.pod_lifecycle_evidence_sha256 = teardown.canonical_sha256(evidence)
    operation.pod_lifecycle_evidence_recorded_at = object()

    assert teardown._verified_launch_frontier(operation) == frontier
    assert teardown._verified_pod_lifecycle_evidence(operation) == evidence
    assert teardown._gpu_pod_lifecycle_closed(operation, [])

    operation.pod_lifecycle_evidence = {**evidence, "job_uid": "wrong-uid"}
    operation.pod_lifecycle_evidence_sha256 = teardown.canonical_sha256(
        operation.pod_lifecycle_evidence
    )
    with pytest.raises(LineageConflict, match="no-Pod lifecycle evidence"):
        teardown._verified_pod_lifecycle_evidence(operation)


def test_pending_pod_with_restart_history_is_not_never_started():
    pod = _terminal_pod(finalizers=[teardown.POD_TEARDOWN_FINALIZER])
    pod.status.phase = "Pending"
    pod.status.container_statuses = [
        SimpleNamespace(
            name="worker",
            container_id=None,
            restart_count=1,
            started=False,
            last_state=SimpleNamespace(
                running=None,
                terminated=SimpleNamespace(exit_code=1),
            ),
            state=SimpleNamespace(
                terminated=None,
                running=None,
                waiting=SimpleNamespace(reason="CrashLoopBackOff"),
            ),
        )
    ]

    assert teardown._pod_termination_evidence(pod) is None


@pytest.mark.parametrize(
    ("method", "finalizers"),
    [
        ("ensure_pod_teardown_finalizer", []),
        ("remove_pod_teardown_finalizer", [teardown.POD_TEARDOWN_FINALIZER]),
    ],
)
def test_pod_finalizer_resource_version_race_is_retryable(
    monkeypatch,
    method,
    finalizers,
):
    pod = _terminal_pod(finalizers=finalizers, deletion_timestamp=None)

    class Core:
        @staticmethod
        def read_namespaced_pod(**_kwargs):
            return pod

        @staticmethod
        def patch_namespaced_pod(**_kwargs):
            raise ApiException(status=409, reason="resourceVersion changed")

    monkeypatch.setattr(teardown, "k8s_app_client", lambda: SimpleNamespace())
    monkeypatch.setattr(teardown, "k8s_batch_client", lambda: SimpleNamespace())
    monkeypatch.setattr(teardown, "k8s_core_client", Core)
    closure = DirectKubernetesClosure(operator=SimpleNamespace())
    assert (
        getattr(closure, method)(
            cluster_context="node-a",
            namespace="chutes",
            name="pod-a",
            uid="pod-uid",
            node_name="node-a",
        )
        == "retryable"
    )


@pytest.mark.asyncio
async def test_pod_404_plus_selector_absence_persists_uid_closure(monkeypatch):
    pod = SimpleNamespace(
        resource_id="pod-row",
        operation_id="operation-1",
        api_version="v1",
        kind="Pod",
        name="pod-a",
        uid="pod-uid",
        namespace="chutes",
        node_name="node-a",
        state="delete_requested",
        owner_uid=None,
        pod_termination_evidence=None,
        pod_termination_evidence_sha256=None,
        pod_uid_absence_evidence=None,
        pod_uid_absence_evidence_sha256=None,
        pod_uid_absence_observed_at=None,
        pod_already_terminating=False,
        pod_teardown_finalizer_attached_at=object(),
        pod_teardown_finalizer_removal_requested_at=None,
        pod_teardown_finalizer_removed_at=None,
        absent_at=None,
    )
    operation = SimpleNamespace(
        operation_id="operation-1",
        deployment_id="deployment-1",
        cluster_context="node-a",
        namespace="chutes",
        config_id=None,
        immutable_labels=EXPECTED_LABELS,
        phase="verifying",
        retry_lease_owner=None,
        retry_lease_expires_at=None,
        resource_discovery_sha256="d" * 64,
        gpu_hardware_uuids=["GPU-1"],
        pod_lifecycle_evidence=None,
        resources=[pod],
    )
    coordinator = teardown.DeploymentTeardownCoordinator(
        kubernetes=SimpleNamespace(
            read_resource=Mock(return_value=None),
            list_resources=Mock(return_value=[]),
        )
    )
    operation.retry_lease_owner = coordinator.worker_id
    session = SimpleNamespace(
        get=AsyncMock(
            side_effect=lambda model, *_args, **_kwargs: (
                operation if model.__name__ == "DeploymentTeardownOperation" else pod
            )
        ),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator._renew_operation_lease = AsyncMock()
    coordinator._require_launch_quiesced = AsyncMock()
    coordinator._advance = AsyncMock()

    assert await coordinator._verify(operation) is True
    assert pod.state == "absent"
    assert pod.pod_uid_absence_evidence["outcome"] == "uid_absent"
    assert pod.pod_uid_absence_evidence["selector_absent"] is True
    coordinator._advance.assert_awaited_once()


@pytest.mark.asyncio
async def test_registry_outage_does_not_block_local_resource_deletion(monkeypatch):
    operation = SimpleNamespace(
        operation_id="operation-1",
        phase="revoking",
        config_id="config-1",
        registry_revocation_ack=None,
        job_id=None,
        instance_id=None,
    )
    coordinator = teardown.DeploymentTeardownCoordinator()
    coordinator._revoke_registry = AsyncMock(
        side_effect=DeploymentFailure("validator unavailable")
    )
    coordinator._advance = AsyncMock()
    record_failure = AsyncMock()
    monkeypatch.setattr(teardown, "record_registry_scope_failure", record_failure)

    await coordinator._revoke(operation)

    record_failure.assert_awaited_once()
    coordinator._advance.assert_awaited_once()
    call = coordinator._advance.await_args
    assert call.args == ("operation-1", "revoking", "deleting")
    assert "validator unavailable" in call.kwargs["last_failure"]


@pytest.mark.asyncio
async def test_local_closure_waits_in_registry_only_phase_before_finalization():
    operation = SimpleNamespace(
        operation_id="operation-1",
        deployment_id="deployment-1",
        cluster_context="node-a",
        namespace="chutes",
        config_id="config-1",
        immutable_labels=EXPECTED_LABELS,
        registry_revocation_ack=None,
        gpu_hardware_uuids=[],
        resources=[],
    )
    coordinator = teardown.DeploymentTeardownCoordinator(
        kubernetes=SimpleNamespace(list_resources=Mock(return_value=[]))
    )
    coordinator._require_launch_quiesced = AsyncMock()
    coordinator._renew_operation_lease = AsyncMock()
    coordinator._wait_for_registry_after_local_closure = AsyncMock()
    coordinator._advance = AsyncMock()

    assert await coordinator._verify(operation) is False
    coordinator._wait_for_registry_after_local_closure.assert_awaited_once()
    coordinator._advance.assert_not_awaited()


@pytest.mark.asyncio
async def test_registry_only_retry_advances_exact_ack_to_finalization(monkeypatch):
    operation = SimpleNamespace(
        operation_id="operation-1",
        phase="awaiting_registry",
        retry_lease_owner=None,
        retry_lease_expires_at=None,
        config_id="config-1",
        registry_revocation_ack=None,
        registry_revoked_at=None,
        last_failure="validator unavailable",
    )
    coordinator = teardown.DeploymentTeardownCoordinator()
    operation.retry_lease_owner = coordinator.worker_id
    ack = {
        "status": "revoked",
        "revoked": True,
        "launch_config_id": "config-1",
        "server_id": "server-1",
    }
    coordinator._revoke_registry = AsyncMock(return_value=ack)
    session = SimpleNamespace(get=AsyncMock(return_value=operation), commit=AsyncMock())

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)

    await coordinator._retry_registry_after_local_closure(operation)

    assert operation.registry_revocation_ack == ack
    assert operation.registry_revoked_at is not None
    assert operation.phase == "finalizing"
    assert operation.last_failure is None


@pytest.mark.asyncio
async def test_orphan_pod_finalizer_response_loss_replays_from_durable_evidence(
    monkeypatch,
):
    coordinator = teardown.DeploymentTeardownCoordinator(
        kubernetes=SimpleNamespace(
            remove_pod_teardown_finalizer=Mock(
                side_effect=ConnectionError("finalizer response lost")
            )
        )
    )
    tombstone = SimpleNamespace(
        tombstone_id="tombstone-1",
        cluster_context="node-a",
        namespace="chutes",
        phase="verifying",
        retry_lease_owner=coordinator.worker_id,
        retry_lease_expires_at=None,
    )
    resource = SimpleNamespace(
        resource_id="pod-row",
        tombstone_id="tombstone-1",
        api_version="v1",
        kind="Pod",
        name="pod-a",
        uid="pod-uid",
        node_name="node-a",
        state="delete_requested",
        absent_at=None,
        pod_termination_evidence=None,
        pod_termination_evidence_sha256=None,
        pod_teardown_finalizer_attached_at=object(),
        pod_teardown_finalizer_removal_requested_at=None,
        pod_teardown_finalizer_removed_at=None,
    )
    live = teardown._identity(
        "Pod",
        _terminal_pod(finalizers=[teardown.POD_TEARDOWN_FINALIZER]),
    )

    async def get(model, _identity, **_kwargs):
        if model.__name__ == "KubernetesOrphanTombstone":
            return tombstone
        return resource

    session = SimpleNamespace(get=AsyncMock(side_effect=get), commit=AsyncMock())

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    with pytest.raises(ConnectionError, match="response lost"):
        await coordinator._close_orphan_pod(tombstone, resource, live)
    assert resource.pod_termination_evidence == live.pod_termination_evidence
    assert resource.pod_teardown_finalizer_removal_requested_at is not None
    assert resource.pod_teardown_finalizer_removed_at is None
    assert resource.state == "delete_requested"

    coordinator.kubernetes.remove_pod_teardown_finalizer = Mock(return_value="absent")
    assert await coordinator._close_orphan_pod(tombstone, resource, None) == "absent"
    assert resource.pod_teardown_finalizer_removed_at is not None
    assert resource.state == "absent"


@pytest.mark.asyncio
async def test_gepetto_undeploy_only_returns_completed_after_coordinator_finishes():
    gepetto = Gepetto.__new__(Gepetto)
    gepetto.teardown = SimpleNamespace(request_and_run=AsyncMock(return_value=True))
    assert await gepetto.undeploy("dep-1", reason="job_deleted") is True
    gepetto.teardown.request_and_run.assert_awaited_once_with("dep-1", "job_deleted")


@pytest.mark.asyncio
async def test_kubernetes_orphan_without_cluster_lineage_is_not_deleted():
    gepetto = Gepetto.__new__(Gepetto)
    gepetto.teardown = SimpleNamespace(
        request_orphan=AsyncMock(),
        run_orphan=AsyncMock(),
    )
    assert (
        await gepetto.cleanup_kubernetes_orphan(
            {
                "deployment_id": "dep-1",
                "node": None,
                "labels": {"chutes/deployment-id": "dep-1"},
            }
        )
        is False
    )
    gepetto.teardown.request_orphan.assert_not_awaited()


@pytest.mark.asyncio
async def test_parent_deletion_remains_pending_while_child_teardown_is_incomplete(
    monkeypatch,
):
    operation = SimpleNamespace(
        operation_id="parent-1",
        phase="waiting_for_children",
        retry_lease_owner=None,
        retry_lease_expires_at=None,
        attempt_count=0,
        last_failure=None,
    )

    class Result:
        @staticmethod
        def scalars():
            return ["child-1"]

    session = SimpleNamespace(
        get=AsyncMock(return_value=operation),
        execute=AsyncMock(return_value=Result()),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator = teardown.DeploymentTeardownCoordinator(
        kubernetes=DirectKubernetesClosure(operator=SimpleNamespace())
    )
    coordinator._adopt_parent_children = AsyncMock(return_value=["child-1"])
    coordinator.run = AsyncMock(return_value=False)
    assert await coordinator.run_parent("parent-1") is False
    assert operation.phase == "waiting_for_children"
    assert "child teardown child-1 is incomplete" in operation.last_failure


@pytest.mark.asyncio
async def test_parent_deletion_readopts_children_before_external_work(monkeypatch):
    operation = SimpleNamespace(
        operation_id="parent-1",
        parent_type="chute",
        parent_id="chute-1",
        phase="waiting_for_children",
        retry_lease_owner=None,
        retry_lease_expires_at=None,
        attempt_count=0,
        last_failure=None,
    )
    session = SimpleNamespace(get=AsyncMock(return_value=operation), commit=AsyncMock())

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator = teardown.DeploymentTeardownCoordinator(
        kubernetes=DirectKubernetesClosure(operator=SimpleNamespace())
    )
    coordinator._adopt_parent_children = AsyncMock(
        side_effect=[["child-1"], ["child-1", "child-2"]]
    )
    coordinator.run = AsyncMock(return_value=True)
    coordinator._delete_validator_server = AsyncMock()

    assert await coordinator.run_parent("parent-1") is False
    coordinator._delete_validator_server.assert_not_awaited()
    assert "adopted a concurrent child" in operation.last_failure


@pytest.mark.asyncio
async def test_parent_request_locks_sorted_deployments_before_server(monkeypatch):
    deployment = SimpleNamespace(deployment_id="deployment-1")
    parent = SimpleNamespace(
        validator="validator-1",
        name="node-a",
        agent_api="https://agent",
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
    )
    child = SimpleNamespace(operation_id="child-operation-1")
    session = SimpleNamespace(
        execute=AsyncMock(
            side_effect=[
                _QueryResult(None),
                _QueryResult([deployment]),
                _QueryResult(parent),
            ]
        ),
        add=lambda _value: None,
        flush=AsyncMock(),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator = teardown.DeploymentTeardownCoordinator(
        kubernetes=DirectKubernetesClosure(operator=SimpleNamespace())
    )
    coordinator._request_in_session = AsyncMock(return_value=child)

    operation_id = await coordinator.request_parent(
        "server", "server-1", "management_delete_server"
    )

    statements = [str(call.args[0]) for call in session.execute.await_args_list]
    assert operation_id
    assert "FROM deployments" in statements[1]
    assert "ORDER BY deployments.deployment_id" in statements[1]
    assert "FROM servers" in statements[2]


@pytest.mark.asyncio
async def test_server_monitor_lost_response_replays_409_as_stable_ack(monkeypatch):
    operation = SimpleNamespace(
        operation_id="parent-1",
        parent_type="server",
        parent_id="server-1",
        phase="waiting_for_children",
        retry_lease_owner=None,
        retry_lease_expires_at=None,
        attempt_count=0,
        last_failure=None,
        validator="validator-1",
        snapshot={
            "agent_api": "https://agent",
            "name": "node-a",
            "node_uid": None,
            "node_generation": None,
        },
        monitor_stop_ack=None,
        monitor_stopped_at=None,
        validator_server_deletion_ack=None,
        validator_server_deleted_at=None,
    )
    session = SimpleNamespace(
        get=AsyncMock(return_value=operation),
        scalar=AsyncMock(return_value=None),
        execute=AsyncMock(side_effect=[_QueryResult(None), _QueryResult(None)]),
        flush=AsyncMock(),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    stop = AsyncMock(
        side_effect=[
            ConnectionError("response lost"),
            AgentError("monitor is already absent", status_code=409),
        ]
    )
    clear = AsyncMock()
    monkeypatch.setattr("chutes_miner.api.server.util.stop_server_monitoring", stop)
    monkeypatch.setattr("chutes_miner.api.server.util.clear_server_cache", clear)
    coordinator = teardown.DeploymentTeardownCoordinator(
        kubernetes=DirectKubernetesClosure(operator=SimpleNamespace())
    )
    coordinator._adopt_parent_children = AsyncMock(return_value=[])
    coordinator._record_parent_allocation_release = AsyncMock()
    coordinator._delete_validator_server = AsyncMock(
        return_value={"status": "already_absent", "server_id": "server-1"}
    )
    monkeypatch.setattr(
        teardown,
        "_assert_parent_allocation_released",
        Mock(),
    )
    session.execute.side_effect = [
        _QueryResult(None),
        _QueryResult([]),
        _QueryResult(None),
    ]

    assert await coordinator.run_parent("parent-1") is False
    assert operation.monitor_stop_ack is None
    assert operation.monitor_stopped_at is None
    assert "was not acknowledged" in operation.last_failure
    operation.next_retry_at = None
    assert await coordinator.run_parent("parent-1") is True
    assert operation.monitor_stop_ack == {
        "status": "already_absent",
        "agent_api": "https://agent",
    }
    assert operation.monitor_stopped_at is not None
    assert operation.phase == "completed"
    assert operation.last_failure is None
    assert stop.await_count == 2
    assert clear.await_count == 2


@pytest.mark.asyncio
async def test_parent_allocation_release_follows_terminal_validator_ack(monkeypatch):
    operation = SimpleNamespace(
        operation_id="parent-1",
        parent_type="server",
        parent_id="server-1",
        phase="waiting_for_children",
        retry_lease_owner=None,
        retry_lease_expires_at=None,
        attempt_count=0,
        last_failure=None,
        validator="validator-1",
        snapshot={
            "agent_api": None,
            "name": "node-a",
            "node_uid": None,
            "node_generation": None,
            "allocation_group_id": None,
            "allocation_group_generation": None,
        },
        monitor_stop_ack={"status": "already_stopped"},
        monitor_stopped_at=datetime.now(timezone.utc),
        validator_server_deletion_ack=None,
        validator_server_deleted_at=None,
    )
    session = SimpleNamespace(
        get=AsyncMock(return_value=operation),
        scalar=AsyncMock(return_value=None),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator = teardown.DeploymentTeardownCoordinator(
        kubernetes=DirectKubernetesClosure(operator=SimpleNamespace())
    )
    coordinator._adopt_parent_children = AsyncMock(return_value=[])
    coordinator._record_parent_allocation_release = AsyncMock(
        side_effect=DeploymentFailure(
            "server parent deletion is held by allocation-group ownership"
        )
    )
    coordinator._delete_validator_server = AsyncMock(
        return_value={"status": "already_absent", "server_id": "server-1"}
    )

    assert await coordinator.run_parent("parent-1") is False
    assert "held by allocation-group ownership" in operation.last_failure
    coordinator._delete_validator_server.assert_awaited_once()
    coordinator._record_parent_allocation_release.assert_awaited_once_with("parent-1")


def test_parent_allocation_release_evidence_rejects_any_owned_generation():
    operation = SimpleNamespace(
        operation_id="parent-1",
        parent_type="server",
        parent_id="server-1",
        snapshot={
            "allocation_group_id": "group-old",
            "allocation_group_generation": 7,
        },
        allocation_release_verified_at=object(),
    )
    evidence = teardown._parent_allocation_release_document(operation)
    operation.allocation_release_evidence = evidence
    operation.allocation_release_evidence_sha256 = teardown.canonical_sha256(evidence)
    server = SimpleNamespace(
        gpu_allocation_group_id=None,
        gpu_allocation_group_generation=None,
    )
    gpu = SimpleNamespace(
        gpu_allocation_group_id=None,
        gpu_allocation_group_generation=None,
    )

    teardown._assert_parent_allocation_released(operation, server, [gpu])

    gpu.gpu_allocation_group_id = "group-owned"
    gpu.gpu_allocation_group_generation = 8
    with pytest.raises(DeploymentFailure, match="held by allocation-group"):
        teardown._assert_parent_allocation_released(operation, server, [gpu])


@pytest.mark.asyncio
async def test_inflight_launch_finishes_into_exact_teardown_uid_closure(monkeypatch):
    token = "launch-token"
    deployment = SimpleNamespace(
        deployment_id="dep-1",
        teardown_operation_id="teardown-1",
        launch_operation_id="launch-1",
        server=SimpleNamespace(name="node-a"),
    )
    launch = SimpleNamespace(
        operation_id="launch-1",
        deployment_id="dep-1",
        phase="teardown_fenced",
        lease_owner=token,
        lease_expires_at=object(),
        immutable_labels=EXPECTED_LABELS,
        canonical_workload_spec={},
        canonical_workload_spec_sha256=None,
        server_name="node-a",
        cluster_context="node-a",
        service_name=None,
        service_uid=None,
        create_results={},
    )
    added = []

    async def get(model, *_args, **_kwargs):
        return deployment if model.__name__ == "Deployment" else launch

    session = SimpleNamespace(
        get=AsyncMock(side_effect=get),
        scalar=AsyncMock(return_value=None),
        add=lambda value: added.append(value),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(k8s_operator, "get_session", fake_session)
    service = V1Service(
        api_version="v1",
        kind="Service",
        metadata=V1ObjectMeta(
            name="chute-svc-dep-1",
            namespace="chutes",
            uid="service-uid",
            labels=EXPECTED_LABELS,
        ),
        spec=V1ServiceSpec(
            type="NodePort",
            external_traffic_policy="Local",
            selector={"chutes/deployment-id": "dep-1"},
            ports=[],
        ),
    )
    launch.canonical_workload_spec = {
        "service": k8s_operator.canonical_workload_resource("Service", service)
    }
    launch.canonical_workload_spec_sha256 = k8s_operator._canonical_document_sha256(
        launch.canonical_workload_spec
    )

    with pytest.raises(DeploymentFailure, match="fenced while Kubernetes create"):
        await K8sOperator._record_launch_resource(
            SimpleNamespace(), "dep-1", token, "Service", service
        )
    assert launch.service_uid == "service-uid"
    assert launch.lease_owner is None
    assert len(added) == 1
    assert added[0].operation_id == "teardown-1"
    assert added[0].uid == "service-uid"


@pytest.mark.asyncio
async def test_delayed_instance_event_rewinds_active_teardown_before_finalization(
    monkeypatch,
):
    deployment = SimpleNamespace(
        teardown_operation_id="operation-1",
        instance_id=None,
    )
    operation = SimpleNamespace(
        operation_id="operation-1",
        phase="finalizing",
        instance_id=None,
        validator_instance_deletion_ack={"status": "already_absent"},
        validator_instance_deleted_at=object(),
        retry_lease_owner="old-run",
        retry_lease_expires_at=object(),
    )

    class Result:
        def unique(self):
            return self

        def scalar_one_or_none(self):
            return deployment

    session = SimpleNamespace(
        execute=AsyncMock(return_value=Result()),
        get=AsyncMock(return_value=operation),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator = teardown.DeploymentTeardownCoordinator()
    assert await coordinator.bind_instance_created(
        config_id="config-1", instance_id="instance-late"
    ) == ("teardown", "operation-1")
    assert operation.phase == "revoking"
    assert operation.instance_id == "instance-late"
    assert operation.validator_instance_deletion_ack is None
    assert operation.retry_lease_owner is None


@pytest.mark.asyncio
async def test_instance_event_after_local_delete_creates_durable_exact_cleanup(
    monkeypatch,
):
    operation = SimpleNamespace(
        operation_id="operation-1",
        phase="completed",
        instance_id="instance-created-before-delete",
        validator="validator-1",
        chute_id="chute-1",
    )

    class Result:
        def __init__(self, value):
            self.value = value

        def unique(self):
            return self

        def scalar_one_or_none(self):
            return self.value

    added = []
    session = SimpleNamespace(
        execute=AsyncMock(side_effect=[Result(None), Result(operation), Result(None)]),
        add=lambda value: added.append(value),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator = teardown.DeploymentTeardownCoordinator()
    action = await coordinator.bind_instance_created(
        config_id="config-1", instance_id="instance-late"
    )
    assert action == ("cleanup", added[0].cleanup_id)
    assert added[0].source_teardown_operation_id == "operation-1"
    assert added[0].instance_id == "instance-late"


@pytest.mark.asyncio
async def test_delayed_instance_cleanup_retries_lost_response_with_same_identity(
    monkeypatch,
):
    cleanup = SimpleNamespace(
        cleanup_id="cleanup-1",
        phase="pending",
        retry_lease_owner=None,
        retry_lease_expires_at=None,
        attempt_count=0,
        validator="validator-1",
        chute_id="chute-1",
        instance_id="instance-1",
        deletion_ack=None,
        deleted_at=None,
        completed_at=None,
        last_failure=None,
    )
    session = SimpleNamespace(get=AsyncMock(return_value=cleanup), commit=AsyncMock())

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator = teardown.DeploymentTeardownCoordinator()
    coordinator._delete_validator_instance_exact = AsyncMock(
        side_effect=[
            ConnectionError("response lost"),
            {"status": "already_absent", "instance_id": "instance-1"},
        ]
    )
    assert await coordinator.run_delayed_instance_cleanup("cleanup-1") is False
    assert cleanup.phase == "pending"
    assert cleanup.retry_lease_owner is None
    cleanup.next_retry_at = None
    assert await coordinator.run_delayed_instance_cleanup("cleanup-1") is True
    assert cleanup.phase == "completed"
    assert cleanup.deletion_ack["instance_id"] == "instance-1"
    assert coordinator._delete_validator_instance_exact.await_count == 2


@pytest.mark.asyncio
async def test_concurrent_operations_use_distinct_compare_and_set_lease_owners():
    coordinator = teardown.DeploymentTeardownCoordinator()
    observed = {}
    both_claimed = asyncio.Event()

    async def claimed(operation_id):
        observed[operation_id] = coordinator.worker_id
        if len(observed) == 2:
            both_claimed.set()
        await both_claimed.wait()
        return True

    coordinator._run_claimed = claimed
    assert await asyncio.gather(coordinator.run("one"), coordinator.run("two")) == [
        True,
        True,
    ]
    assert observed["one"] != observed["two"]


@pytest.mark.asyncio
async def test_startup_resumes_deployment_parent_and_orphan_operations(monkeypatch):
    class Result:
        def __init__(self, values):
            self.values = values

        def scalars(self):
            return self.values

    session = SimpleNamespace(
        execute=AsyncMock(
            side_effect=[
                Result(["deployment-operation"]),
                Result(["parent-operation"]),
                Result(["orphan-tombstone"]),
                Result(["delayed-instance-cleanup"]),
                Result(["stale-launch-deployment"]),
            ]
        )
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(teardown, "get_session", fake_session)
    coordinator = teardown.DeploymentTeardownCoordinator(
        kubernetes=DirectKubernetesClosure(operator=SimpleNamespace())
    )
    coordinator.run = AsyncMock(return_value=True)
    coordinator.run_parent = AsyncMock(return_value=True)
    coordinator.run_orphan = AsyncMock(return_value=True)
    coordinator.run_delayed_instance_cleanup = AsyncMock(return_value=True)
    coordinator.request_and_run = AsyncMock(return_value=True)
    await coordinator.resume_pending()
    coordinator.run.assert_awaited_once_with("deployment-operation")
    coordinator.run_parent.assert_awaited_once_with("parent-operation")
    coordinator.run_orphan.assert_awaited_once_with("orphan-tombstone")
    coordinator.run_delayed_instance_cleanup.assert_awaited_once_with(
        "delayed-instance-cleanup"
    )
    coordinator.request_and_run.assert_awaited_once_with(
        "stale-launch-deployment", "launch_rollback"
    )


def test_gepetto_has_no_direct_deployment_delete_or_cache_proof_for_gpu_teardown():
    source = (ROOT / "src/chutes-miner/chutes_miner/gepetto.py").read_text(
        encoding="utf-8"
    )
    coordinator = (
        ROOT / "src/chutes-miner/chutes_miner/api/deployment/teardown.py"
    ).read_text(encoding="utf-8")
    assert "await session.delete(deployment)" not in source
    assert "asyncio.create_task(self.undeploy" not in source
    assert "V1Preconditions(uid=uid)" in coordinator
    assert "read_namespaced_job" in coordinator
    assert "read_namespaced_deployment" in coordinator
    assert "read_namespaced_service" in coordinator
    assert "read_namespaced_pod" in coordinator
