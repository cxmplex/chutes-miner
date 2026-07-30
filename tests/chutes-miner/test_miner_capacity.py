"""Fail-closed regressions for registrar GPU and chute disk capacity."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from kubernetes.client import V1Service, V1ServicePort, V1ServiceSpec

from chutes_miner.api.exceptions import DeploymentFailure
from chutes_miner.api.k8s import util
from chutes_miner.api.k8s.operator import K8sOperator
from chutes_miner.api.server import seedless_adoption


def _seedless_node(*, capacity_gpu: str = "2", allocatable_gpu: str | None = "1"):
    allocatable = (
        None if allocatable_gpu is None else {"nvidia.com/gpu": allocatable_gpu}
    )
    return SimpleNamespace(
        metadata=SimpleNamespace(
            name="k3s-node",
            uid="node-uid",
            labels={
                "node-role.kubernetes.io/control-plane": "true",
                "chutes/seedless-control-plane": "true",
            },
        ),
        status=SimpleNamespace(
            capacity={
                "nvidia.com/gpu": capacity_gpu,
                "cpu": "16",
                "memory": "65536Mi",
            },
            allocatable=allocatable,
            conditions=[SimpleNamespace(type="Ready", status="True")],
        ),
    )


def test_seedless_resources_use_exact_allocatable_gpu_cardinality():
    gpu_count, cpu_per_gpu, memory_per_gpu = seedless_adoption._node_resources(
        _seedless_node(capacity_gpu="2", allocatable_gpu="1"),
        assigned_gpu_count=1,
    )

    assert gpu_count == 1
    assert cpu_per_gpu == 4
    assert memory_per_gpu > 0


@pytest.mark.parametrize(
    ("capacity_gpu", "allocatable_gpu", "assigned_gpu_count", "message"),
    [
        ("2", "2", 1, "cardinality does not match"),
        ("2", "1", 2, "cardinality does not match"),
        ("2", None, 1, "capacity is invalid"),
        ("2", "not-a-number", 1, "capacity is invalid"),
        ("1", "2", 2, "capacity is invalid"),
    ],
)
def test_seedless_resources_reject_nonexact_or_invalid_allocatable_capacity(
    capacity_gpu,
    allocatable_gpu,
    assigned_gpu_count,
    message,
):
    with pytest.raises(RuntimeError, match=message):
        seedless_adoption._node_resources(
            _seedless_node(
                capacity_gpu=capacity_gpu,
                allocatable_gpu=allocatable_gpu,
            ),
            assigned_gpu_count=assigned_gpu_count,
        )


@pytest.mark.parametrize(
    ("gpu_uuids", "allocatable_gpu", "message"),
    [
        (["GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"], "2", "cardinality does not match"),
        (
            [
                "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            ],
            "1",
            "duplicate hardware UUIDs",
        ),
    ],
)
@pytest.mark.asyncio
async def test_seedless_adoption_rejects_cardinality_before_label_or_database_mutation(
    monkeypatch,
    gpu_uuids,
    allocatable_gpu,
    message,
):
    node = _seedless_node(capacity_gpu="2", allocatable_gpu=allocatable_gpu)
    identity = {
        "server_id": "logical-server",
        "attestation_id": "attestation-1",
        "allocation_group_id": "group-1",
        "allocation_group_generation": 1,
        "gpu_uuids": gpu_uuids,
        "gpu_identifiers": ["h100_sxm"] * len(gpu_uuids),
        "validator": {"hotkey": "5Validator"},
    }

    class CoreClient:
        def __init__(self):
            self.patch_calls = []

        def list_node(self):
            return SimpleNamespace(items=[node])

        def patch_node(self, name, body):
            self.patch_calls.append((name, body))
            return node

    core = CoreClient()
    monkeypatch.setattr(
        seedless_adoption,
        "settings",
        SimpleNamespace(seedless_gpu_identity=identity, miner_hourly_cost=1.0),
    )
    monkeypatch.setattr(seedless_adoption, "k8s_core_client", lambda: core)

    def unexpected_session():
        raise AssertionError(
            "database adoption must not start after a capacity mismatch"
        )

    monkeypatch.setattr(seedless_adoption, "get_session", unexpected_session)

    with pytest.raises(RuntimeError, match=message):
        await seedless_adoption.adopt_seedless_gpu_server()

    assert core.patch_calls == []
    assert node.metadata.labels == {
        "node-role.kubernetes.io/control-plane": "true",
        "chutes/seedless-control-plane": "true",
    }


def _job_inputs():
    chute = SimpleNamespace(
        chute_id="chute-1",
        version="1.0.0",
        chutes_version="0.8.0",
        ref_str="chute:chute",
        image="owner/image:latest",
        gpu_count=1,
        tee=False,
        validator="5Validator",
    )
    server = SimpleNamespace(
        server_id="server-1",
        cpu_per_gpu=2,
        memory_per_gpu=4,
        validator="5Validator",
        name="gpu-node-1",
        ip_address="192.0.2.10",
    )
    service = V1Service(
        spec=V1ServiceSpec(
            ports=[
                V1ServicePort(port=8000, node_port=30080),
                V1ServicePort(port=8001, node_port=30081),
            ]
        )
    )
    return chute, server, service


@pytest.mark.asyncio
async def test_pod_request_and_launch_admission_share_exact_disk_requirements(
    monkeypatch,
):
    chute, server, service = _job_inputs()
    monkeypatch.setattr(util.settings, "cache_overrides", {server.name: 37})
    monkeypatch.setattr(util.settings, "cache_max_size_gb", 500)
    monkeypatch.setattr(util.settings, "gpu_tee_only", False)
    monkeypatch.setattr(
        util,
        "resolve_deployment_validator",
        lambda _chute, _server: SimpleNamespace(api="https://validator.example"),
    )

    requirements = util.deployment_disk_requirements(server, 11)
    assert requirements.workload_gb == 11
    assert requirements.cache_gb == 37
    assert requirements.ephemeral_storage_gb == 48

    job = util.build_chute_job(
        deployment_id="deployment-1",
        chute=chute,
        server=server,
        service=service,
        gpu_uuids=["GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"],
        probe_port=8000,
        token="launch-token",
        config_id="config-1",
        disk_gb=11,
    )
    pod = job.spec.template.spec
    volumes = {volume.name: volume for volume in pod.volumes}
    assert volumes["cache"].empty_dir.size_limit == "37Gi"
    assert volumes["tmp"].empty_dir.size_limit == "11Gi"
    resources = pod.containers[0].resources
    assert resources.requests["ephemeral-storage"] == "48Gi"
    assert resources.limits["ephemeral-storage"] == "48Gi"

    disk_check = AsyncMock(return_value=True)
    operator = SimpleNamespace(check_node_has_disk_available=disk_check)
    await K8sOperator._verify_disk_space(operator, server, 11)
    disk_check.assert_awaited_once_with(server.name, 48)


@pytest.mark.asyncio
async def test_launch_admission_rejects_when_only_workload_disk_would_fit(monkeypatch):
    _chute, server, _service = _job_inputs()
    monkeypatch.setattr(util.settings, "cache_overrides", {server.name: 37})
    monkeypatch.setattr(util.settings, "cache_max_size_gb", 500)
    disk_check = AsyncMock(return_value=False)
    operator = SimpleNamespace(check_node_has_disk_available=disk_check)

    with pytest.raises(
        DeploymentFailure,
        match=r"48GB disk space available \(11GB workload \+ 37GB cache\)",
    ):
        await K8sOperator._verify_disk_space(operator, server, 11)

    disk_check.assert_awaited_once_with(server.name, 48)


@pytest.mark.parametrize("workload_disk_gb", [0, -1, True, 1.5, "1.5"])
def test_disk_requirements_reject_nonpositive_or_fractional_workload(
    monkeypatch,
    workload_disk_gb,
):
    _chute, server, _service = _job_inputs()
    monkeypatch.setattr(util.settings, "cache_overrides", {server.name: 37})

    with pytest.raises(DeploymentFailure, match="positive whole GiB"):
        util.deployment_disk_requirements(server, workload_disk_gb)


def test_disk_requirements_reject_invalid_cache_override(monkeypatch):
    _chute, server, _service = _job_inputs()
    monkeypatch.setattr(util.settings, "cache_overrides", {server.name: 0})

    with pytest.raises(DeploymentFailure, match="cache disk.*positive whole GiB"):
        util.deployment_disk_requirements(server, 11)
