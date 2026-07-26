"""Focused trust-boundary tests for restartable miner teardown."""

from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from chutes_miner.api.deployment import teardown
from chutes_miner.api.deployment.teardown import (
    DirectKubernetesClosure,
    ResourceIdentity,
    replacement_matches,
)
from chutes_miner.gepetto import Gepetto
from kubernetes.client.rest import ApiException


ROOT = Path(__file__).resolve().parents[2]


def _resource(
    kind: str,
    uid: str,
    *,
    owner_kind: str | None = None,
    owner_uid: str | None = None,
    node_name: str | None = "node-a",
    labels: dict[str, str] | None = None,
) -> ResourceIdentity:
    return ResourceIdentity(
        api_version="v1",
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
        owner_kind=owner_kind,
        owner_name=f"owner-{owner_kind.lower()}" if owner_kind else None,
        owner_uid=owner_uid,
        node_name=node_name,
    )


EXPECTED_LABELS = {
    "chutes/deployment-id": "dep-1",
    "chutes/chute-id": "chute-1",
    "chutes/config-id": "config-1",
}


def test_matching_controller_replacement_is_captured_but_conflicting_lineage_stops():
    replacement_job = _resource("Job", "job-new")
    assert replacement_matches(
        expected_labels=EXPECTED_LABELS,
        expected_node_name="node-a",
        accepted_owner_uids=set(),
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
        accepted_owner_uids={"job-new"},
        resource=replacement_pod,
    )
    assert not replacement_matches(
        expected_labels=EXPECTED_LABELS,
        expected_node_name="node-a",
        accepted_owner_uids={"job-new"},
        resource=_resource(
            "Pod",
            "pod-conflict",
            owner_kind="Job",
            owner_uid="other-job",
        ),
    )
    assert not replacement_matches(
        expected_labels=EXPECTED_LABELS,
        expected_node_name="node-a",
        accepted_owner_uids=set(),
        resource=_resource("Job", "wrong-node", node_name="node-b"),
    )


def test_registry_secret_replacement_requires_exact_launch_config_lineage():
    assert replacement_matches(
        expected_labels=EXPECTED_LABELS,
        expected_node_name="node-a",
        accepted_owner_uids=set(),
        resource=_resource(
            "Secret",
            "secret-new",
            node_name=None,
            labels={"chutes/launch-config-id": "config-1"},
        ),
    )
    assert not replacement_matches(
        expected_labels=EXPECTED_LABELS,
        expected_node_name="node-a",
        accepted_owner_uids=set(),
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
    coordinator.run = AsyncMock(return_value=False)
    assert await coordinator.run_parent("parent-1") is False
    assert operation.phase == "waiting_for_children"
    assert "child teardown child-1 is incomplete" in operation.last_failure


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
    await coordinator.resume_pending()
    coordinator.run.assert_awaited_once_with("deployment-operation")
    coordinator.run_parent.assert_awaited_once_with("parent-operation")
    coordinator.run_orphan.assert_awaited_once_with("orphan-tombstone")


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
