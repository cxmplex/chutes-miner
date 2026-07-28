"""Focused trust-boundary tests for restartable miner teardown."""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from chutes_common.exceptions import AgentError
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
            "batch/v1" if kind == "Job" else "apps/v1" if kind in {"Deployment", "ReplicaSet"} else "v1"
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
        owner_name=owner_name or (f"resource-{owner_kind.lower()}" if owner_kind else None),
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
    deployment = SimpleNamespace(
        launch_operation_id="launch-1",
        teardown_operation_id=None,
        deployment_id="deployment-1",
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
        deployment_id="deployment-1",
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
        deployment_id="deployment-1",
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
        deployment_id="deployment-1",
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
async def test_controller_is_directly_absent_before_child_delete(monkeypatch):
    coordinator = teardown.DeploymentTeardownCoordinator(
        kubernetes=SimpleNamespace(delete_resource=Mock(return_value="delete_requested"))
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
    coordinator._advance.assert_awaited_once_with("operation-1", "revoking", "deleting")


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
    assert closure.delete_resource(
        cluster_context="node-a",
        namespace="chutes",
        kind="Pod",
        name="pod-a",
        uid="uid-a",
    ) == "delete_requested"
    assert len(calls) == 1
    assert calls[0]["body"].preconditions.uid == "uid-a"
    assert calls[0]["body"].propagation_policy == "Foreground"
    assert calls[0]["body"].grace_period_seconds > 0


def test_uid_precondition_conflict_advances_to_direct_replacement_verification(monkeypatch):
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
async def test_pod_404_without_terminal_finalizer_closure_retains_ownership():
    pod = SimpleNamespace(
        resource_id="pod-row",
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
        pod_teardown_finalizer_attached_at=object(),
        pod_teardown_finalizer_removal_requested_at=None,
        pod_teardown_finalizer_removed_at=None,
    )
    operation = SimpleNamespace(
        operation_id="operation-1",
        deployment_id="deployment-1",
        cluster_context="node-a",
        namespace="chutes",
        config_id=None,
        immutable_labels=EXPECTED_LABELS,
        resources=[pod],
    )
    coordinator = teardown.DeploymentTeardownCoordinator(
        kubernetes=SimpleNamespace(read_resource=Mock(return_value=None))
    )
    coordinator._renew_operation_lease = AsyncMock()
    coordinator._pause_for_retry = AsyncMock()
    coordinator._advance = AsyncMock()

    assert await coordinator._verify(operation) is False
    assert pod.state == "delete_requested"
    coordinator._pause_for_retry.assert_awaited_once()
    coordinator._advance.assert_not_awaited()


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
async def test_parent_deletion_remains_pending_while_child_teardown_is_incomplete(monkeypatch):
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
        execute=AsyncMock(
            side_effect=[_QueryResult(None), _QueryResult(None)]
        ),
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
    coordinator._delete_validator_server = AsyncMock(
        return_value={"status": "already_absent", "server_id": "server-1"}
    )

    assert await coordinator.run_parent("parent-1") is False
    assert operation.monitor_stop_ack is None
    assert operation.monitor_stopped_at is None
    assert "was not acknowledged" in operation.last_failure
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
async def test_instance_event_after_local_delete_creates_durable_exact_cleanup(monkeypatch):
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
        execute=AsyncMock(
            side_effect=[Result(None), Result(operation), Result(None)]
        ),
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
async def test_delayed_instance_cleanup_retries_lost_response_with_same_identity(monkeypatch):
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
    source = (ROOT / "src/chutes-miner/chutes_miner/gepetto.py").read_text(encoding="utf-8")
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
