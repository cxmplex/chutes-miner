import pytest
from types import SimpleNamespace

from kubernetes.client import V1Service, V1ServiceSpec, V1ServicePort

from chutes_miner.api.k8s.util import build_chute_job


def _make_service() -> V1Service:
    return V1Service(
        spec=V1ServiceSpec(
            type="NodePort",
            selector={"app": "chute"},
            external_traffic_policy="Local",
            ports=[
                V1ServicePort(
                    port=8000, target_port=8000, node_port=30080, protocol="TCP"
                ),
                V1ServicePort(
                    port=8001, target_port=8001, node_port=30081, protocol="TCP"
                ),
            ],
        )
    )


def _make_inputs(version: str, tee: bool = False):
    chute = SimpleNamespace(
        chute_id="chute-123",
        version=version,
        chutes_version=version,
        ref_str="gh://chutes/test",
        filename="main.py",
        image="parachutes/test:latest",
        gpu_count=1,
        tee=tee,
        validator="test_validator",
    )
    server = SimpleNamespace(
        server_id="server-uid-1",
        cpu_per_gpu=1,
        memory_per_gpu=2,
        seed=42,
        validator="test_validator",
        name="node-1",
        ip_address="10.0.0.10",
    )
    service = _make_service()
    return chute, server, service


def _build_job(version: str):
    chute, server, service = _make_inputs(version)
    return build_chute_job(
        deployment_id="deploy-1",
        chute=chute,
        server=server,
        service=service,
        gpu_uuids=["UUID-1"],
        probe_port=8000,
    )


def test_build_chute_job_attaches_code_volume_for_legacy_version():
    job = _build_job("0.3.59")
    volumes = job.spec.template.spec.volumes
    mounts = job.spec.template.spec.containers[0].volume_mounts

    assert any(volume.name == "code" for volume in volumes)
    assert any(mount.name == "code" for mount in mounts)


def test_build_chute_job_skips_code_volume_for_min_version():
    job = _build_job("0.3.61")
    volumes = job.spec.template.spec.volumes
    mounts = job.spec.template.spec.containers[0].volume_mounts

    assert all(volume.name != "code" for volume in volumes)
    assert all(mount.name != "code" for mount in mounts)


def test_build_chute_job_skips_code_volume_for_newer_version():
    job = _build_job("0.3.65")
    volumes = job.spec.template.spec.volumes
    mounts = job.spec.template.spec.containers[0].volume_mounts

    assert all(volume.name != "code" for volume in volumes)
    assert all(mount.name != "code" for mount in mounts)


@pytest.mark.parametrize("version", ["0.4.0.rc2", "0.4.0.rc16", "0.4.49.rc100"])
def test_build_chute_job_skips_code_volume_for_newer_rc_version(version):
    job = _build_job(version)
    volumes = job.spec.template.spec.volumes
    mounts = job.spec.template.spec.containers[0].volume_mounts

    assert all(volume.name != "code" for volume in volumes)
    assert all(mount.name != "code" for mount in mounts)


def test_build_chute_job_skips_code_volume_for_tee_chute():
    chute, server, service = _make_inputs("0.3.0", tee=True)
    job = build_chute_job(
        deployment_id="deploy-1",
        chute=chute,
        server=server,
        service=service,
        gpu_uuids=["UUID-1"],
        probe_port=8000,
    )
    volumes = job.spec.template.spec.volumes
    mounts = job.spec.template.spec.containers[0].volume_mounts

    assert all(volume.name != "code" for volume in volumes)
    assert all(mount.name != "code" for mount in mounts)


def test_build_chute_job_attaches_code_volume_for_legacy_non_tee():
    chute, server, service = _make_inputs("0.3.0", tee=False)
    job = build_chute_job(
        deployment_id="deploy-1",
        chute=chute,
        server=server,
        service=service,
        gpu_uuids=["UUID-1"],
        probe_port=8000,
    )
    volumes = job.spec.template.spec.volumes
    mounts = job.spec.template.spec.containers[0].volume_mounts

    assert any(volume.name == "code" for volume in volumes)
    assert any(mount.name == "code" for mount in mounts)


def _make_tee_service() -> V1Service:
    # TEE chutes on chutes runtime >= 0.6.0 expose an attestation port (8002).
    return V1Service(
        spec=V1ServiceSpec(
            type="NodePort",
            selector={"app": "chute"},
            external_traffic_policy="Local",
            ports=[
                V1ServicePort(
                    port=8000, target_port=8000, node_port=30080, protocol="TCP"
                ),
                V1ServicePort(
                    port=8001, target_port=8001, node_port=30081, protocol="TCP"
                ),
                V1ServicePort(
                    port=8002, target_port=8002, node_port=30082, protocol="TCP"
                ),
            ],
        )
    )


def _container_env(job):
    return {env.name: env.value for env in job.spec.template.spec.containers[0].env}


def test_build_chute_job_gpu_keeps_nvidia_runtime_and_env():
    chute, server, _ = _make_inputs("0.8.0", tee=True)
    service = _make_tee_service()
    job = build_chute_job(
        deployment_id="deploy-gpu",
        chute=chute,
        server=server,
        service=service,
        gpu_uuids=["GPU-UUID-1"],
        probe_port=8000,
        token="launch-token",
    )
    assert job.spec.template.spec.runtime_class_name == "nvidia"
    env = _container_env(job)
    assert env["NVIDIA_VISIBLE_DEVICES"] == "GPU-UUID-1"
    assert env["NCCL_P2P_DISABLE"] == "1"
    assert "CHUTES_HOST_ID" not in env
    assert env["CHUTES_API_URL"] == "http://test-api"
    assert env["CHUTES_LAUNCH_JWT"] == "launch-token"
    assert env["CHUTES_EXTERNAL_HOST"] == "10.0.0.10"
    assert job.spec.template.spec.containers[0].security_context.capabilities == {
        "add": ["IPC_LOCK"]
    }


def test_build_nontee_gpu_injects_launch_bound_model_access_without_host_claim():
    chute, server, service = _make_inputs("0.8.0", tee=False)
    job = build_chute_job(
        deployment_id="deploy-gpu",
        chute=chute,
        server=server,
        service=service,
        gpu_uuids=["GPU-UUID-1"],
        probe_port=8000,
        token="launch-token",
    )

    env = _container_env(job)
    assert env["CHUTES_API_URL"] == "http://test-api"
    assert env["CHUTES_LAUNCH_JWT"] == "launch-token"
    assert env["CHUTES_EXTERNAL_HOST"] == "10.0.0.10"
    assert "CHUTES_HOST_ID" not in env


@pytest.mark.parametrize(
    ("vm_version", "uses_xet"),
    [
        ("1.3.0", False),
        ("1.3.1", True),
        ("1.8.0", True),
        (None, False),
        ("unknown", False),
    ],
)
def test_build_tee_job_combines_vm_environment_with_launch_context(vm_version, uses_xet):
    chute, server, _ = _make_inputs("0.8.0", tee=True)
    job = build_chute_job(
        deployment_id="deploy-gpu",
        chute=chute,
        server=server,
        service=_make_tee_service(),
        gpu_uuids=["GPU-UUID-1"],
        probe_port=8000,
        token="launch-token",
        vm_version=vm_version,
    )

    env = _container_env(job)
    assert env["CHUTES_API_URL"] == "http://test-api"
    assert env["CHUTES_LAUNCH_JWT"] == "launch-token"
    assert env["CHUTES_EXTERNAL_HOST"] == server.ip_address
    assert "CHUTES_HOST_ID" not in env
    if uses_xet:
        assert env["HF_XET_FIXED_DOWNLOAD_CONCURRENCY"] == "16"
        assert env["TOKIO_WORKER_THREADS"] == "8"
        assert "HF_HUB_DISABLE_XET" not in env
        assert "HF_HUB_ENABLE_HF_TRANSFER" not in env
    else:
        assert env["HF_HUB_DISABLE_XET"] == "1"
        assert env["HF_HUB_ENABLE_HF_TRANSFER"] == "1"
        assert "HF_XET_FIXED_DOWNLOAD_CONCURRENCY" not in env
        assert "TOKIO_WORKER_THREADS" not in env


def test_build_job_without_launch_token_keeps_api_context_only():
    chute, server, service = _make_inputs("0.8.0")
    job = build_chute_job(
        deployment_id="deploy-gpu",
        chute=chute,
        server=server,
        service=service,
        gpu_uuids=["GPU-UUID-1"],
        probe_port=8000,
    )

    env = _container_env(job)
    assert env["CHUTES_API_URL"] == "http://test-api"
    assert "CHUTES_LAUNCH_JWT" not in env
    assert "CHUTES_EXTERNAL_HOST" not in env
    assert "CHUTES_HOST_ID" not in env
    assert "--graval-seed" in job.spec.template.spec.containers[0].command


def test_build_job_rejects_validator_mismatch():
    chute, server, service = _make_inputs("0.8.0")
    chute.validator = "different-validator"

    with pytest.raises(ValueError, match="does not match"):
        build_chute_job(
            deployment_id="deploy-gpu",
            chute=chute,
            server=server,
            service=service,
            gpu_uuids=["GPU-UUID-1"],
            probe_port=8000,
            token="launch-token",
        )


def test_build_job_rejects_unknown_validator():
    chute, server, service = _make_inputs("0.8.0")
    chute.validator = server.validator = "unknown-validator"

    with pytest.raises(ValueError, match="No configured validator API"):
        build_chute_job(
            deployment_id="deploy-gpu",
            chute=chute,
            server=server,
            service=service,
            gpu_uuids=["GPU-UUID-1"],
            probe_port=8000,
            token="launch-token",
        )
