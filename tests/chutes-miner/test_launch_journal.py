"""Focused crash/replay tests for the durable miner launch journal."""

from __future__ import annotations

import ast
import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import textwrap
from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock, Mock

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
    V1OwnerReference,
    V1PodSecurityContext,
    V1PodSpec,
    V1PodTemplateSpec,
    V1ResourceRequirements,
    V1SecurityContext,
    V1Secret,
    V1Service,
    V1ServicePort,
    V1ServiceSpec,
    V1Volume,
    V1VolumeMount,
)
from kubernetes.client.rest import ApiException
from sqlalchemy.dialects import postgresql

from chutes_miner.api.exceptions import DeploymentFailure
from chutes_miner.api.k8s import operator as operator_module
from chutes_miner.api.k8s.operator import (
    AmbiguousKubernetesCreate,
    K8sOperator,
    _canonical_document_sha256,
    _adopt_named_resource_after_create_error,
    canonical_workload_resource,
)
from chutes_miner.api.k8s.util import canonical_miner_launch_sha256
import chutes_miner.gepetto as gepetto_module
from chutes_miner.gepetto import Gepetto


LABELS = {
    "chutes/deployment-id": "deployment-1",
    "chutes/chute-id": "chute-1",
    "chutes/config-id": "config-1",
}

DEPLOYMENT_UUID = "11111111-1111-4111-8111-111111111111"


class _QueryResult:
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


def _canonical_intent(
    *,
    intent_id: str = "intent-1",
    phase: str,
    validator: str = "validator-1",
    chute_id: str = "chute-1",
    chute_version: str = "1.0.0",
    server_id: str = "server-1",
    job_id: str | None = None,
    job_cleanup_only: bool = False,
    **values,
) -> SimpleNamespace:
    lineage = {
        "schema": "chutes.miner-launch-lineage",
        "version": 1,
        "deployment_id": None if job_cleanup_only else DEPLOYMENT_UUID,
        "miner_hotkey": gepetto_module.settings.miner_ss58,
        "validator": validator,
        "chute_id": chute_id,
        "chute_version": chute_version,
        "server_id": server_id,
        "kubernetes_node_uid": "node-uid-1",
        "kubernetes_node_generation": 1,
        "gpu_allocation_group_id": "group-1",
        "gpu_allocation_group_generation": 1,
        "job_id": job_id,
    }
    request = {
        "schema": (
            "chutes.miner-job-release.v1" if job_cleanup_only else "chutes.miner-launch-request.v1"
        ),
        "miner_launch_request_id": intent_id,
        "lineage": lineage,
    }
    fields = {
        "intent_id": intent_id,
        "phase": phase,
        "validator": validator,
        "chute_id": chute_id,
        "chute_version": chute_version,
        "server_id": server_id,
        "job_id": job_id,
        "job_cleanup_only": job_cleanup_only,
        "request_payload": request,
        "request_sha256": canonical_miner_launch_sha256(request),
        "lineage_sha256": canonical_miner_launch_sha256(lineage),
        "response_payload": None,
        "response_sha256": None,
        "token_sha256": None,
        "authorized_token_sha256s": [],
        "registry_ack": None,
        "job_release_ack": None,
        "job_released_at": None,
        "deployment_id": None if job_cleanup_only else DEPLOYMENT_UUID,
        "retry_lease_owner": "lease-1",
        "retry_lease_expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
        "attempt_count": 1,
        "next_retry_at": None,
        "created_at": datetime.now(timezone.utc),
        "completed_at": None,
        "last_failure": None,
    }
    fields.update(values)
    return SimpleNamespace(**fields)


def test_every_gepetto_launch_intent_cas_uses_canonical_validator():
    for method in (
        Gepetto._begin_launch_intent,
        Gepetto._begin_job_cleanup_intent,
        Gepetto._record_launch_response,
        Gepetto._record_registry_ack,
        Gepetto._record_launch_intent_failure,
        Gepetto._resume_launch_intent,
        Gepetto.abort_launch_intent,
    ):
        assert "_validated_launch_intent" in inspect.getsource(method)


def test_gepetto_kubernetes_awaits_are_outside_database_session_scopes():
    for method in (Gepetto.optimal_scale_up_server, Gepetto.reconcile):
        tree = ast.parse(textwrap.dedent(inspect.getsource(method)))
        for context in (node for node in ast.walk(tree) if isinstance(node, ast.AsyncWith)):
            opens_database_session = any(
                isinstance(item.context_expr, ast.Call)
                and isinstance(item.context_expr.func, ast.Name)
                and item.context_expr.func.id == "get_session"
                for item in context.items
            )
            if not opens_database_session:
                continue
            forbidden = []
            for node in ast.walk(context):
                if not isinstance(node, ast.Await) or not isinstance(node.value, ast.Call):
                    continue
                function = node.value.func
                if (
                    isinstance(function, ast.Attribute)
                    and isinstance(function.value, ast.Name)
                    and function.value.id == "k8s"
                ):
                    forbidden.append(function.attr)
            assert forbidden == []


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
                            volume_mounts=[V1VolumeMount(name="cache", mount_path="/cache")],
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
        lambda job: setattr(job.spec.template.spec.image_pull_secrets[0], "name", "other-secret"),
        lambda job: job.spec.template.spec.containers[0].command.append("--unsafe"),
        lambda job: setattr(
            job.spec.template.spec.containers[0].security_context,
            "privileged",
            True,
        ),
        lambda job: job.spec.template.spec.containers[0].resources.limits.update(
            {"memory": "16Gi"}
        ),
        lambda job: setattr(job.spec, "suspend", True),
        lambda job: setattr(
            job.spec.template.spec.containers[0],
            "working_dir",
            "/other",
        ),
        lambda job: setattr(
            job.spec.template.spec.containers[0],
            "lifecycle",
            {"preStop": {"exec": {"command": ["sh", "-c", "sleep 30"]}}},
        ),
        lambda job: setattr(
            job.spec.template.spec.containers[0],
            "env_from",
            [{"secretRef": {"name": "foreign-secret"}}],
        ),
        lambda job: setattr(
            job.spec.template.spec,
            "host_aliases",
            [{"ip": "127.0.0.1", "hostnames": ["authority.local"]}],
        ),
        lambda job: setattr(
            job.spec.template.spec,
            "dns_config",
            {"nameservers": ["203.0.113.53"]},
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
    readback.spec.internal_traffic_policy = "Cluster"
    readback.spec.publish_not_ready_addresses = False
    readback.spec.ports[0].node_port = 32001
    assert canonical_workload_resource("Service", readback) == canonical_workload_resource(
        "Service", intended
    )

    readback.spec.selector = {"chutes/deployment-id": "other"}
    assert canonical_workload_resource("Service", readback) != canonical_workload_resource(
        "Service", intended
    )
    readback.spec.selector = intended.spec.selector
    readback.spec.ports[0].target_port = 9000
    assert canonical_workload_resource("Service", readback) != canonical_workload_resource(
        "Service", intended
    )

    readback = deepcopy(intended)
    readback.spec.publish_not_ready_addresses = True
    assert canonical_workload_resource("Service", readback) != canonical_workload_resource(
        "Service", intended
    )
    readback = deepcopy(intended)
    readback.spec.internal_traffic_policy = "Local"
    assert canonical_workload_resource("Service", readback) != canonical_workload_resource(
        "Service", intended
    )


@pytest.mark.parametrize("state", ["owned", "terminating"])
def test_canonical_adoption_rejects_foreign_ownership_and_deletion(state):
    intended = _job()
    conflicting = deepcopy(intended)
    if state == "owned":
        conflicting.metadata.owner_references = [
            V1OwnerReference(
                api_version="apps/v1",
                kind="Deployment",
                name="foreign",
                uid="foreign-uid",
            )
        ]
    else:
        conflicting.metadata.deletion_timestamp = "2026-07-27T12:00:00Z"
    assert canonical_workload_resource("Job", conflicting) != canonical_workload_resource(
        "Job", intended
    )


def test_service_timeout_after_create_adopts_exact_persisted_object(monkeypatch):
    intended = _service()
    persisted = deepcopy(intended)
    persisted.metadata.uid = "service-uid"
    core = SimpleNamespace(read_namespaced_service=Mock(return_value=persisted))
    monkeypatch.setattr(operator_module, "k8s_core_client", lambda: core)
    operator = object.__new__(operator_module.SingleClusterK8sOperator)
    operator._manager = None
    operator._deploy_service = Mock(side_effect=TimeoutError("response lost"))

    result = operator._create_service_for_deployment(
        SimpleNamespace(chute_id="chute-1"),
        SimpleNamespace(name="node-1"),
        "deployment-1",
        config_id="config-1",
        job_id=None,
        service_intent=intended,
    )
    assert result.metadata.uid == "service-uid"


def test_job_gateway_timeout_after_create_adopts_exact_persisted_object(monkeypatch):
    intended = _job()
    persisted = deepcopy(intended)
    persisted.metadata.uid = "job-uid"
    batch = SimpleNamespace(read_namespaced_job=Mock(return_value=persisted))
    monkeypatch.setattr(operator_module, "k8s_batch_client", lambda: batch)
    operator = object.__new__(operator_module.SingleClusterK8sOperator)
    operator._manager = None
    operator._get_probe_port = Mock(return_value=8001)
    operator._deploy_job_for_deployment = Mock(
        side_effect=ApiException(status=504, reason="response lost")
    )

    result = operator._create_job_for_deployment(
        "deployment-1",
        SimpleNamespace(chute_id="chute-1"),
        SimpleNamespace(name="node-1"),
        _service(),
        ["GPU-a", "GPU-b"],
        job_intent=intended,
    )
    assert result.metadata.uid == "job-uid"


def test_secret_timeout_after_create_adopts_exact_persisted_object(monkeypatch):
    intended = V1Secret(
        api_version="v1",
        kind="Secret",
        metadata=V1ObjectMeta(
            name="registry-config-1",
            labels={"chutes/launch-config-id": "config-1"},
        ),
        type="kubernetes.io/dockerconfigjson",
        data={".dockerconfigjson": "e30="},
    )
    persisted = deepcopy(intended)
    persisted.metadata.uid = "secret-uid"
    core = SimpleNamespace(
        create_namespaced_secret=Mock(side_effect=TimeoutError("response lost")),
        read_namespaced_secret=Mock(return_value=persisted),
    )
    monkeypatch.setattr(operator_module, "k8s_core_client", lambda: core)
    operator = object.__new__(operator_module.SingleClusterK8sOperator)
    result = operator._create_registry_pull_secret(
        "config-1",
        "validator-1",
        intended,
    )
    assert result.metadata.uid == "secret-uid"


def test_unresolved_ambiguous_create_is_not_treated_as_absent():
    intended = _service()

    def missing():
        raise ApiException(status=404, reason="not yet visible")

    with pytest.raises(AmbiguousKubernetesCreate, match="result is unknown"):
        _adopt_named_resource_after_create_error(
            kind="Service",
            intended=intended,
            create_error=TimeoutError("response lost"),
            read=missing,
        )


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
        canonical_workload_spec_sha256=_canonical_document_sha256({"service": expected}),
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
async def test_node_adoption_between_create_and_cas_persists_uid_and_fences(
    monkeypatch,
):
    monkeypatch.setattr(operator_module.settings, "gpu_tee_only", True)
    deployment = SimpleNamespace(
        deployment_id=DEPLOYMENT_UUID,
        launch_operation_id="launch-1",
        teardown_operation_id=None,
        validator="validator-1",
        chute_id="chute-1",
        version="1.0.0",
        server_id="server-1",
        job_id=None,
    )
    original_server = SimpleNamespace(
        server_id="server-1",
        validator="validator-1",
        name="node-1",
        kubeconfig=None,
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=1,
        registration_attestation_id="attestation-1",
        gpu_allocation_group_id="group-1",
        gpu_allocation_group_generation=1,
    )
    lineage = {
        "schema": "chutes.miner-launch-lineage",
        "version": 1,
        "deployment_id": DEPLOYMENT_UUID,
        "miner_hotkey": operator_module.settings.miner_ss58,
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
        deployment_id=DEPLOYMENT_UUID,
        validator="validator-1",
        chute_id="chute-1",
        chute_version="1.0.0",
        server_id="server-1",
        job_id=None,
        job_cleanup_only=False,
        request_payload=request,
        request_sha256=canonical_miner_launch_sha256(request),
        lineage_sha256=canonical_miner_launch_sha256(lineage),
    )
    intended = _service()
    canonical = canonical_workload_resource("Service", intended)
    launch = SimpleNamespace(
        launch_intent_id="intent-1",
        lease_owner="lease-1",
        lease_expires_at=object(),
        phase="creating",
        canonical_workload_spec={"service": canonical},
        canonical_workload_spec_sha256=_canonical_document_sha256({"service": canonical}),
        immutable_labels=LABELS,
        server_name="node-1",
        cluster_context="node-1",
        cluster_context_sha256=operator_module._launch_cluster_context_sha256(original_server),
        namespace=operator_module.settings.namespace,
        service_name=None,
        service_uid=None,
        create_results={},
        last_failure=None,
    )
    current_server = deepcopy(original_server)
    current_server.kubernetes_node_uid = "node-uid-2"
    current_server.kubernetes_node_generation = 2
    current_server.registration_attestation_id = "attestation-2"
    session = SimpleNamespace(
        get=AsyncMock(
            side_effect=lambda model, *_args, **_kwargs: {
                "Deployment": deployment,
                "DeploymentLaunchOperation": launch,
                "MinerLaunchIntent": intent,
            }[model.__name__]
        ),
        execute=AsyncMock(return_value=_QueryResult(current_server)),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(operator_module, "get_session", fake_session)
    readback = deepcopy(intended)
    readback.metadata.uid = "service-uid-1"
    operator = SimpleNamespace()
    operator._lock_current_miner_launch_lineage = (
        K8sOperator._lock_current_miner_launch_lineage.__get__(operator)
    )
    with pytest.raises(DeploymentFailure, match="server/node lineage changed"):
        await K8sOperator._record_launch_resource(
            operator, DEPLOYMENT_UUID, "lease-1", "Service", readback
        )

    assert launch.service_uid == "service-uid-1"
    assert launch.phase == "failed"
    assert launch.lease_owner is None
    assert "server/node lineage changed" in launch.last_failure
    session.commit.assert_awaited_once()


@pytest.mark.parametrize(
    "tamper",
    ["schema", "request_id", "extra_field", "request_digest", "lineage_digest"],
)
@pytest.mark.asyncio
async def test_noncanonical_launch_intent_fails_before_external_create(
    monkeypatch,
    tamper,
):
    monkeypatch.setattr(operator_module.settings, "gpu_tee_only", True)
    deployment = SimpleNamespace(
        deployment_id=DEPLOYMENT_UUID,
        launch_operation_id="launch-1",
        teardown_operation_id=None,
        validator="validator-1",
        chute_id="chute-1",
        version="1.0.0",
        server_id="server-1",
        job_id=None,
    )
    server = SimpleNamespace(
        server_id="server-1",
        validator="validator-1",
        name="node-1",
        kubeconfig=None,
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=1,
        registration_attestation_id="attestation-1",
        gpu_allocation_group_id="group-1",
        gpu_allocation_group_generation=1,
    )
    lineage = {
        "schema": "chutes.miner-launch-lineage",
        "version": 1,
        "miner_hotkey": operator_module.settings.miner_ss58,
        "deployment_id": DEPLOYMENT_UUID,
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
        deployment_id=DEPLOYMENT_UUID,
        validator="validator-1",
        chute_id="chute-1",
        chute_version="1.0.0",
        server_id="server-1",
        job_id=None,
        job_cleanup_only=False,
        request_payload=request,
        request_sha256=canonical_miner_launch_sha256(request),
        lineage_sha256=canonical_miner_launch_sha256(lineage),
    )
    if tamper == "schema":
        request["schema"] = "chutes.miner-launch-request.v0"
        intent.request_sha256 = canonical_miner_launch_sha256(request)
    elif tamper == "request_id":
        request["miner_launch_request_id"] = "other-intent"
        intent.request_sha256 = canonical_miner_launch_sha256(request)
    elif tamper == "extra_field":
        request["unexpected"] = True
        intent.request_sha256 = canonical_miner_launch_sha256(request)
    elif tamper == "request_digest":
        intent.request_sha256 = "0" * 64
    else:
        intent.lineage_sha256 = "0" * 64
    launch = SimpleNamespace(
        launch_intent_id="intent-1",
        lease_owner="lease-1",
        lease_expires_at=object(),
        phase="creating",
        canonical_workload_spec=None,
        canonical_workload_spec_sha256=None,
    )
    session = SimpleNamespace(
        get=AsyncMock(
            side_effect=lambda model, *_args, **_kwargs: {
                "Deployment": deployment,
                "DeploymentLaunchOperation": launch,
                "MinerLaunchIntent": intent,
            }[model.__name__]
        ),
        execute=AsyncMock(return_value=_QueryResult(server)),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(operator_module, "get_session", fake_session)
    external_create = Mock()
    operator = SimpleNamespace()
    operator._lock_current_miner_launch_lineage = (
        K8sOperator._lock_current_miner_launch_lineage.__get__(operator)
    )

    async def persist_then_create():
        await K8sOperator._persist_launch_resource_intent(
            operator,
            DEPLOYMENT_UUID,
            "lease-1",
            "Service",
            _service(),
        )
        external_create()

    with pytest.raises(DeploymentFailure, match="launch lineage is invalid"):
        await persist_then_create()
    external_create.assert_not_called()
    session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_canonical_digest_mismatch_fails_before_uid_capture(monkeypatch):
    deployment = SimpleNamespace(
        launch_operation_id="launch-1",
        teardown_operation_id=None,
    )
    intended = _service()
    intended.metadata.uid = "service-uid"
    launch = SimpleNamespace(
        lease_owner="lease-1",
        phase="creating",
        canonical_workload_spec={"service": canonical_workload_resource("Service", intended)},
        canonical_workload_spec_sha256="0" * 64,
        immutable_labels=LABELS,
        server_name="node-1",
        cluster_context="node-1",
        service_name=None,
        service_uid=None,
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
    with pytest.raises(DeploymentFailure, match="closure digest is invalid"):
        await K8sOperator._record_launch_resource(
            SimpleNamespace(),
            "deployment-1",
            "lease-1",
            "Service",
            intended,
        )
    assert launch.service_uid is None
    session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_ambiguous_create_retains_lease_until_teardown_can_prove_absence(
    monkeypatch,
):
    deployment = SimpleNamespace(launch_operation_id="launch-1")
    lease_expiry = object()
    launch = SimpleNamespace(
        lease_owner="lease-1",
        lease_expires_at=lease_expiry,
        phase="creating",
        last_failure=None,
    )
    session = SimpleNamespace(commit=AsyncMock())

    async def get(model, *_args, **_kwargs):
        return deployment if model.__name__ == "Deployment" else launch

    session.get = AsyncMock(side_effect=get)

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(operator_module, "get_session", fake_session)
    await K8sOperator._fail_launch(
        SimpleNamespace(),
        "deployment-1",
        "lease-1",
        AmbiguousKubernetesCreate("create response lost"),
    )
    assert launch.phase == "creating"
    assert launch.lease_owner == "lease-1"
    assert launch.lease_expires_at is lease_expiry
    assert "AmbiguousKubernetesCreate" in launch.last_failure
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_launch_response_replay_accumulates_only_validator_returned_tokens(
    monkeypatch,
):
    intent = _canonical_intent(
        phase="pending",
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
        lease_owner="lease-1",
    )
    await gepetto._record_launch_response(
        "intent-1",
        {**stable, "token": "token-2"},
        lease_owner="lease-1",
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


@pytest.mark.asyncio
async def test_tampered_launch_intent_stops_before_external_replay_or_failure_mutation(
    monkeypatch,
):
    intent = _canonical_intent(phase="pending")
    intent.request_payload["unexpected"] = True
    intent.request_sha256 = canonical_miner_launch_sha256(intent.request_payload)
    session = SimpleNamespace(
        get=AsyncMock(return_value=intent),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(gepetto_module, "get_session", fake_session)
    gepetto = object.__new__(Gepetto)
    gepetto._fetch_launch_config = AsyncMock()
    gepetto._revoke_registry_scope = AsyncMock()
    gepetto._release_job_exact = AsyncMock()

    assert (
        await gepetto._resume_launch_intent(
            "intent-1",
            lease_owner="lease-1",
        )
        is False
    )
    assert intent.phase == "pending"
    assert intent.last_failure is None
    gepetto._fetch_launch_config.assert_not_awaited()
    gepetto._revoke_registry_scope.assert_not_awaited()
    gepetto._release_job_exact.assert_not_awaited()
    session.commit.assert_not_awaited()
    assert all(call.kwargs.get("with_for_update") is True for call in session.get.await_args_list)


class _IntentResult:
    def __init__(self, intents):
        self.intents = list(intents)

    def scalars(self):
        return self

    def unique(self):
        return self

    def __iter__(self):
        return iter(self.intents)


@pytest.mark.asyncio
async def test_recovery_query_excludes_live_preemption_owner_and_uses_skip_locked(
    monkeypatch,
):
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_IntentResult([])),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(gepetto_module, "get_session", fake_session)
    gepetto = object.__new__(Gepetto)

    assert await gepetto._claim_launch_intents({"registry_acked"}) == []
    statement = session.execute.await_args.args[0]
    sql = str(
        statement.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": False},
        )
    )
    assert "retry_lease_owner IS NULL" in sql
    assert "retry_lease_expires_at IS NULL" in sql
    assert "retry_lease_expires_at <=" in sql
    assert "FOR UPDATE SKIP LOCKED" in sql
    assert statement._for_update_arg.skip_locked is True
    assert statement._limit_clause.value == gepetto_module.RESUME_CONCURRENCY
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_expired_launch_owner_is_atomically_reclaimed(monkeypatch):
    expired = _canonical_intent(
        phase="registry_acked",
        retry_lease_owner="crashed-producer",
        retry_lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        attempt_count=2,
        next_retry_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_IntentResult([expired])),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(gepetto_module, "get_session", fake_session)
    gepetto = object.__new__(Gepetto)
    gepetto._launch_intent_lease_owner = Mock(return_value="recovery-owner")

    assert await gepetto._claim_launch_intents({"registry_acked"}) == [
        ("intent-1", "recovery-owner")
    ]
    assert expired.retry_lease_owner == "recovery-owner"
    assert expired.retry_lease_expires_at > datetime.now(timezone.utc)
    assert expired.attempt_count == 3
    assert expired.next_retry_at is None
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_preemption_gap_heartbeat_keeps_exact_producer_lease_live(monkeypatch):
    intent = _canonical_intent(
        phase="registry_acked",
        retry_lease_owner="producer-owner",
        retry_lease_expires_at=datetime.now(timezone.utc) + timedelta(seconds=1),
    )
    session = SimpleNamespace(
        get=AsyncMock(return_value=intent),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(gepetto_module, "get_session", fake_session)
    monkeypatch.setattr(gepetto_module, "LAUNCH_INTENT_HEARTBEAT_SECONDS", 0.01)
    gepetto = object.__new__(Gepetto)

    async with gepetto._launch_intent_lease_guard(
        "intent-1",
        "producer-owner",
    ):
        # This sleep stands in for the long undeploy loop in preempting_deploy.
        await asyncio.sleep(0.035)
        assert intent.retry_lease_owner == "producer-owner"
        assert intent.retry_lease_expires_at > datetime.now(timezone.utc)

    assert session.commit.await_count >= 2
    source = inspect.getsource(Gepetto.preempting_deploy)
    guard = source.index("_launch_intent_lease_guard")
    preemption = source.index("await self.undeploy", guard)
    final_renewal = source.index("_renew_launch_intent_lease", preemption)
    consumption = source.index("k8s.deploy_chute", final_renewal)
    assert guard < preemption < final_renewal < consumption


@pytest.mark.asyncio
async def test_reclaimed_launch_fence_rejects_stale_producer_mutations(monkeypatch):
    intent = _canonical_intent(
        phase="registry_acked",
        retry_lease_owner="recovery-owner",
        retry_lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        response_payload={"config_id": "config-1", "registry": None},
    )
    session = SimpleNamespace(
        get=AsyncMock(return_value=intent),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(gepetto_module, "get_session", fake_session)
    monkeypatch.setattr(gepetto_module.settings, "gpu_tee_only", False)
    gepetto = object.__new__(Gepetto)

    with pytest.raises(DeploymentFailure, match="lease changed or expired"):
        await gepetto._renew_launch_intent_lease("intent-1", "stale-producer")
    with pytest.raises(DeploymentFailure, match="lease changed or expired"):
        await gepetto._record_launch_response(
            "intent-1",
            {"config_id": "config-1", "token": "new-token"},
            lease_owner="stale-producer",
        )
    with pytest.raises(DeploymentFailure, match="lease changed or expired"):
        await gepetto.abort_launch_intent(
            "intent-1",
            lease_owner="stale-producer",
        )

    assert intent.phase == "registry_acked"
    assert intent.retry_lease_owner == "recovery-owner"
    session.commit.assert_not_awaited()


class _NoIntentResult:
    @staticmethod
    def scalar_one_or_none():
        return None


@pytest.mark.asyncio
async def test_pre_request_job_cleanup_is_committed_before_external_release(
    monkeypatch,
):
    added = []
    session = SimpleNamespace(
        execute=AsyncMock(side_effect=[None, _NoIntentResult()]),
        add=lambda value: added.append(value),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(gepetto_module, "get_session", fake_session)
    gepetto = object.__new__(Gepetto)
    chute = SimpleNamespace(
        validator="validator-1",
        chute_id="chute-1",
        version="1.0.0",
    )
    server = SimpleNamespace(
        server_id="server-invalid",
        kubernetes_node_uid="node-uid",
        kubernetes_node_generation=1,
        gpu_allocation_group_id="group-1",
        gpu_allocation_group_generation=1,
    )

    intent_id = await gepetto._begin_job_cleanup_intent(
        chute,
        server,
        "job-1",
        lease_owner="lease-1",
    )
    assert intent_id == added[0].intent_id
    assert added[0].phase == "cleanup_required"
    assert added[0].job_cleanup_only is True
    assert added[0].job_id == "job-1"
    assert added[0].request_payload["schema"] == "chutes.miner-job-release.v1"
    assert len(added[0].request_sha256) == 64
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_pending_launch_recovery_replays_persisted_identity_not_current_rows(
    monkeypatch,
):
    intent = _canonical_intent(
        phase="pending",
        chute_id="chute-original",
        chute_version="1.0.0",
        server_id="server-original",
        job_id="job-1",
        validator="validator-original",
    )
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_IntentResult([intent])),
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

    async def record_response(_intent_id, response, *, lease_owner):
        assert lease_owner == intent.retry_lease_owner
        intent.phase = "response_persisted"
        intent.response_payload = {
            "config_id": response["config_id"],
            "registry": response.get("registry"),
        }

    gepetto._record_launch_response = AsyncMock(side_effect=record_response)
    gepetto._revoke_registry_scope = AsyncMock()
    gepetto._release_job_exact = AsyncMock(return_value={"status": "released", "job_id": "job-1"})
    gepetto._record_launch_intent_failure = AsyncMock()

    await gepetto.resume_launch_intents()

    gepetto._fetch_launch_config.assert_awaited_once_with(
        validator=ANY,
        chute_id="chute-original",
        server_id="server-original",
        job_id="job-1",
        intent_id="intent-1",
        deployment_id=DEPLOYMENT_UUID,
    )
    assert intent.phase == "completed"
    assert intent.job_release_ack == {"status": "released", "job_id": "job-1"}
    assert intent.job_released_at is not None


@pytest.mark.asyncio
async def test_failed_job_release_keeps_launch_intent_retryable(monkeypatch):
    intent = _canonical_intent(
        phase="cleanup_required",
        job_id="job-1",
        response_payload={"config_id": "config-1", "registry": None},
    )
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_IntentResult([intent])),
        get=AsyncMock(return_value=intent),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(gepetto_module, "get_session", fake_session)
    gepetto = object.__new__(Gepetto)
    gepetto._revoke_registry_scope = AsyncMock()
    gepetto._release_job_exact = AsyncMock(side_effect=DeploymentFailure("validator unavailable"))

    async def record_failure(_intent_id, exc, *, lease_owner):
        assert lease_owner == intent.retry_lease_owner
        intent.last_failure = str(exc)

    gepetto._record_launch_intent_failure = AsyncMock(side_effect=record_failure)
    await gepetto.resume_launch_intents()

    assert intent.phase == "cleanup_required"
    assert intent.job_release_ack is None
    assert intent.completed_at is None
    assert intent.last_failure == "validator unavailable"


@pytest.mark.asyncio
async def test_predeployment_abort_persists_before_cleanup_and_retries_in_reconcile(
    monkeypatch,
):
    intent = _canonical_intent(
        phase="registry_acked",
        job_id="job-1",
        response_payload={"config_id": "config-1", "registry": None},
    )
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_IntentResult([intent])),
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
        side_effect=[
            ConnectionError("release response lost"),
            {"status": "already_absent", "job_id": "job-1"},
        ]
    )

    async def record_failure(_intent_id, exc, *, lease_owner):
        assert lease_owner == intent.retry_lease_owner
        intent.last_failure = str(exc)

    gepetto._record_launch_intent_failure = AsyncMock(side_effect=record_failure)
    assert (
        await gepetto.abort_launch_intent(
            "intent-1",
            lease_owner="lease-1",
        )
        is False
    )
    assert intent.phase == "cleanup_required"
    assert intent.job_release_ack is None
    assert intent.last_failure == "release response lost"

    await gepetto.resume_aborted_launch_intents()
    assert intent.phase == "completed"
    assert intent.job_release_ack == {
        "status": "already_absent",
        "job_id": "job-1",
    }
    assert intent.completed_at is not None
    assert gepetto._release_job_exact.await_count == 2


@pytest.mark.asyncio
async def test_job_cleanup_only_intent_releases_without_requesting_launch_config(
    monkeypatch,
):
    intent = _canonical_intent(
        phase="cleanup_required",
        server_id="invalid-server",
        job_id="job-1",
        job_cleanup_only=True,
    )
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_IntentResult([intent])),
        get=AsyncMock(return_value=intent),
        commit=AsyncMock(),
    )

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(gepetto_module, "get_session", fake_session)
    gepetto = object.__new__(Gepetto)
    gepetto._fetch_launch_config = AsyncMock()
    gepetto._revoke_registry_scope = AsyncMock()
    gepetto._release_job_exact = AsyncMock(return_value={"status": "released", "job_id": "job-1"})
    gepetto._record_launch_intent_failure = AsyncMock()

    await gepetto.resume_aborted_launch_intents()
    assert intent.phase == "completed"
    assert intent.job_release_ack == {"status": "released", "job_id": "job-1"}
    gepetto._fetch_launch_config.assert_not_awaited()
    gepetto._revoke_registry_scope.assert_not_awaited()
