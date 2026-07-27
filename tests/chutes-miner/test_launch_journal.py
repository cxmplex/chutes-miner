"""Focused crash/replay tests for the durable miner launch journal."""

from __future__ import annotations

from contextlib import asynccontextmanager
from copy import deepcopy
import hashlib
from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock

import pytest
from kubernetes.client import (
    V1Container,
    V1ContainerPort,
    V1EmptyDirVolumeSource,
    V1EnvVar,
    V1Job,
    V1JobSpec,
    V1LocalObjectReference,
    V1ObjectMeta,
    V1PodSecurityContext,
    V1PodSpec,
    V1PodTemplateSpec,
    V1ResourceRequirements,
    V1SecurityContext,
    V1Service,
    V1ServicePort,
    V1ServiceSpec,
    V1Volume,
    V1VolumeMount,
)

from chutes_miner.api.exceptions import DeploymentFailure
from chutes_miner.api.k8s import operator as operator_module
from chutes_miner.api.k8s.operator import K8sOperator, canonical_workload_resource
import chutes_miner.gepetto as gepetto_module
from chutes_miner.gepetto import Gepetto


LABELS = {
    "chutes/deployment-id": "deployment-1",
    "chutes/chute-id": "chute-1",
    "chutes/config-id": "config-1",
}


def _service() -> V1Service:
    return V1Service(
        api_version="v1",
        kind="Service",
        metadata=V1ObjectMeta(name="chute-svc-deployment-1", labels=LABELS),
        spec=V1ServiceSpec(
            type="NodePort",
            external_traffic_policy="Local",
            selector={"chutes/deployment-id": "deployment-1"},
            ports=[
                V1ServicePort(
                    name="chute-8000",
                    port=8000,
                    protocol="TCP",
                    target_port=8000,
                )
            ],
        ),
    )


def _job(token: str = "launch-token-1") -> V1Job:
    return V1Job(
        api_version="batch/v1",
        kind="Job",
        metadata=V1ObjectMeta(name="chute-deployment-1", labels=dict(LABELS)),
        spec=V1JobSpec(
            parallelism=1,
            completions=1,
            backoff_limit=0,
            ttl_seconds_after_finished=300,
            template=V1PodTemplateSpec(
                metadata=V1ObjectMeta(
                    labels=dict(LABELS),
                    annotations={"prometheus.io/scrape": "true"},
                ),
                spec=V1PodSpec(
                    node_name="node-1",
                    runtime_class_name="nvidia",
                    restart_policy="Never",
                    automount_service_account_token=False,
                    termination_grace_period_seconds=30,
                    image_pull_secrets=[V1LocalObjectReference(name="registry-config-1")],
                    security_context=V1PodSecurityContext(run_as_user=1000, run_as_group=1000),
                    volumes=[
                        V1Volume(
                            name="cache",
                            empty_dir=V1EmptyDirVolumeSource(size_limit="10Gi"),
                        )
                    ],
                    containers=[
                        V1Container(
                            name="chute",
                            image="registry/image@sha256:" + "a" * 64,
                            image_pull_policy="Always",
                            command=["chutes", "run", "chute:entrypoint"],
                            env=[
                                V1EnvVar(name="CHUTES_LAUNCH_JWT", value=token),
                                V1EnvVar(name="NVIDIA_VISIBLE_DEVICES", value="GPU-a,GPU-b"),
                                V1EnvVar(name="CHUTES_NVIDIA_DEVICES", value="GPU-a,GPU-b"),
                            ],
                            resources=V1ResourceRequirements(
                                requests={"cpu": "2", "memory": "8Gi"},
                                limits={"cpu": "2", "memory": "8Gi"},
                            ),
                            volume_mounts=[
                                V1VolumeMount(name="cache", mount_path="/cache")
                            ],
                            security_context=V1SecurityContext(
                                allow_privilege_escalation=False,
                                capabilities={"add": ["IPC_LOCK"]},
                            ),
                            ports=[{"containerPort": 8000}],
                        )
                    ],
                ),
            ),
        ),
    )


def test_canonical_job_accepts_only_known_api_defaults_and_fresh_launch_token():
    intended = _job("launch-token-1")
    readback = deepcopy(intended)
    readback.metadata.uid = "job-uid-1"
    readback.spec.selector = {"matchLabels": {"controller-uid": "job-uid-1"}}
    readback.spec.template.metadata.labels.update(
        {
            "controller-uid": "job-uid-1",
            "job-name": "chute-deployment-1",
            "batch.kubernetes.io/controller-uid": "job-uid-1",
            "batch.kubernetes.io/job-name": "chute-deployment-1",
        }
    )
    pod_spec = readback.spec.template.spec
    pod_spec.dns_policy = "ClusterFirst"
    pod_spec.scheduler_name = "default-scheduler"
    pod_spec.enable_service_links = True
    pod_spec.host_network = False
    pod_spec.host_pid = False
    pod_spec.host_ipc = False
    container = pod_spec.containers[0]
    container.env[0].value = "fresh-replay-token"
    container.ports = [V1ContainerPort(container_port=8000, protocol="TCP")]
    container.volume_mounts[0].read_only = False

    assert canonical_workload_resource("Job", readback) == canonical_workload_resource(
        "Job", intended
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda job: setattr(job.spec.template.spec.containers[0], "image", "other/image"),
        lambda job: setattr(
            next(
                item
                for item in job.spec.template.spec.containers[0].env
                if item.name == "NVIDIA_VISIBLE_DEVICES"
            ),
            "value",
            "GPU-a",
        ),
        lambda job: setattr(
            next(
                item
                for item in job.spec.template.spec.containers[0].env
                if item.name == "CHUTES_NVIDIA_DEVICES"
            ),
            "value",
            "GPU-b",
        ),
        lambda job: setattr(
            job.spec.template.spec.image_pull_secrets[0], "name", "other-secret"
        ),
        lambda job: job.spec.template.spec.containers[0].command.append("--unsafe"),
        lambda job: setattr(
            job.spec.template.spec.containers[0].security_context,
            "privileged",
            True,
        ),
        lambda job: job.spec.template.spec.containers[0].resources.limits.update(
            {"memory": "16Gi"}
        ),
    ],
)
def test_canonical_job_rejects_runtime_authority_or_placement_drift(mutate):
    intended = _job()
    conflicting = deepcopy(intended)
    mutate(conflicting)
    assert canonical_workload_resource("Job", conflicting) != canonical_workload_resource(
        "Job", intended
    )


def test_canonical_service_ignores_allocated_node_port_but_not_selector_or_target():
    intended = _service()
    readback = deepcopy(intended)
    readback.metadata.uid = "service-uid-1"
    readback.spec.cluster_ip = "10.96.0.10"
    readback.spec.cluster_i_ps = ["10.96.0.10"]
    readback.spec.ip_families = ["IPv4"]
    readback.spec.ip_family_policy = "SingleStack"
    readback.spec.session_affinity = "None"
    readback.spec.ports[0].node_port = 32001
    assert canonical_workload_resource(
        "Service", readback
    ) == canonical_workload_resource("Service", intended)

    readback.spec.selector = {"chutes/deployment-id": "other"}
    assert canonical_workload_resource(
        "Service", readback
    ) != canonical_workload_resource("Service", intended)
    readback.spec.selector = intended.spec.selector
    readback.spec.ports[0].target_port = 9000
    assert canonical_workload_resource(
        "Service", readback
    ) != canonical_workload_resource("Service", intended)


@pytest.mark.asyncio
async def test_first_captured_kubernetes_uid_is_immutable(monkeypatch):
    deployment = SimpleNamespace(
        launch_operation_id="launch-1",
        teardown_operation_id=None,
    )
    intended = _service()
    expected = canonical_workload_resource("Service", intended)
    launch = SimpleNamespace(
        lease_owner="lease-1",
        phase="creating",
        canonical_workload_spec={"service": expected},
        immutable_labels=LABELS,
        server_name="node-1",
        cluster_context="node-1",
        service_name="chute-svc-deployment-1",
        service_uid="first-uid",
        create_results={},
    )
    session = SimpleNamespace(commit=AsyncMock())

    async def get(model, *_args, **_kwargs):
        return deployment if model.__name__ == "Deployment" else launch

    session.get = AsyncMock(side_effect=get)

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(operator_module, "get_session", fake_session)
    readback = deepcopy(intended)
    readback.metadata.uid = "replacement-uid"
    with pytest.raises(DeploymentFailure, match="UID changed after capture"):
        await K8sOperator._record_launch_resource(
            SimpleNamespace(),
            "deployment-1",
            "lease-1",
            "Service",
            readback,
        )
    assert launch.service_uid == "first-uid"
    session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_launch_response_replay_accumulates_only_validator_returned_tokens(monkeypatch):
    intent = SimpleNamespace(
        phase="pending",
        response_payload=None,
        response_sha256=None,
        token_sha256=None,
        authorized_token_sha256s=[],
        last_failure=None,
    )
    session = SimpleNamespace(
        get=AsyncMock(return_value=intent),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(gepetto_module, "get_session", fake_session)
    gepetto = object.__new__(Gepetto)
    stable = {"config_id": "config-1"}
    await gepetto._record_launch_response(
        "intent-1",
        {**stable, "token": "token-1"},
    )
    await gepetto._record_launch_response(
        "intent-1",
        {**stable, "token": "token-2"},
    )

    assert intent.response_payload == {"config_id": "config-1", "registry": None}
    assert intent.authorized_token_sha256s == sorted(
        [
            hashlib.sha256(b"token-1").hexdigest(),
            hashlib.sha256(b"token-2").hexdigest(),
        ]
    )
    assert intent.token_sha256 == hashlib.sha256(b"token-2").hexdigest()
    assert session.commit.await_count == 2


class _IntentResult:
    def scalars(self):
        return ["intent-1"]


@pytest.mark.asyncio
async def test_pending_launch_recovery_replays_persisted_identity_not_current_rows(monkeypatch):
    intent = SimpleNamespace(
        intent_id="intent-1",
        phase="pending",
        chute_id="chute-original",
        server_id="server-original",
        job_id="job-1",
        validator="validator-original",
        response_payload=None,
        job_release_ack=None,
        job_released_at=None,
        completed_at=None,
        last_failure=None,
    )
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_IntentResult()),
        get=AsyncMock(return_value=intent),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(gepetto_module, "get_session", fake_session)
    monkeypatch.setattr(
        gepetto_module,
        "validator_by_hotkey",
        lambda hotkey: SimpleNamespace(hotkey=hotkey, api="https://validator"),
    )
    gepetto = object.__new__(Gepetto)
    payload = {"token": "fresh", "config_id": "config-1"}
    gepetto._fetch_launch_config = AsyncMock(return_value=payload)

    async def record_response(_intent_id, response):
        intent.phase = "response_persisted"
        intent.response_payload = {
            "config_id": response["config_id"],
            "registry": response.get("registry"),
        }

    gepetto._record_launch_response = AsyncMock(side_effect=record_response)
    gepetto._revoke_registry_scope = AsyncMock()
    gepetto._release_job_exact = AsyncMock(
        return_value={"status": "released", "job_id": "job-1"}
    )
    gepetto._record_launch_intent_failure = AsyncMock()

    await gepetto.resume_launch_intents()

    gepetto._fetch_launch_config.assert_awaited_once_with(
        validator=ANY,
        chute_id="chute-original",
        server_id="server-original",
        job_id="job-1",
        intent_id="intent-1",
    )
    assert intent.phase == "completed"
    assert intent.job_release_ack == {"status": "released", "job_id": "job-1"}
    assert intent.job_released_at is not None


@pytest.mark.asyncio
async def test_failed_job_release_keeps_launch_intent_retryable(monkeypatch):
    intent = SimpleNamespace(
        intent_id="intent-1",
        phase="cleanup_required",
        chute_id="chute-1",
        server_id="server-1",
        job_id="job-1",
        validator="validator-1",
        response_payload={"config_id": "config-1", "registry": None},
        job_release_ack=None,
        job_released_at=None,
        completed_at=None,
        last_failure=None,
    )
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_IntentResult()),
        get=AsyncMock(return_value=intent),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(gepetto_module, "get_session", fake_session)
    gepetto = object.__new__(Gepetto)
    gepetto._revoke_registry_scope = AsyncMock()
    gepetto._release_job_exact = AsyncMock(
        side_effect=DeploymentFailure("validator unavailable")
    )

    async def record_failure(_intent_id, exc):
        intent.last_failure = str(exc)

    gepetto._record_launch_intent_failure = AsyncMock(side_effect=record_failure)
    await gepetto.resume_launch_intents()

    assert intent.phase == "cleanup_required"
    assert intent.job_release_ack is None
    assert intent.completed_at is None
    assert intent.last_failure == "validator unavailable"
