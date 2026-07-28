import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from kubernetes.client import ApiClient, V1Service, V1ServicePort, V1ServiceSpec

from chutes_miner.api.exceptions import DeploymentFailure
from chutes_miner.api.k8s.util import POD_TEARDOWN_FINALIZER, build_chute_job
from cross_repo_tests import repository_root


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
        token="launch-token",
        config_id="config-1",
    )


@pytest.mark.parametrize("version", [None, "", "garbage", "0.3.60", "0.3.60.rc1"])
def test_build_chute_job_rejects_legacy_source_delivery_versions(version):
    chute, server, service = _make_inputs(version)
    with pytest.raises(DeploymentFailure, match="Unsupported chutes runtime version"):
        build_chute_job(
            deployment_id="deploy-1",
            chute=chute,
            server=server,
            service=service,
            gpu_uuids=["UUID-1"],
            probe_port=8000,
            token="launch-token",
            config_id="config-1",
        )


@pytest.mark.parametrize("version", ["0.3.61", "0.3.61.rc1", "0.3.62"])
def test_build_chute_job_supported_boundary_has_no_source_volume(version):
    job = _build_job(version)
    volumes = job.spec.template.spec.volumes
    mounts = job.spec.template.spec.containers[0].volume_mounts

    assert all(volume.name != "code" for volume in volumes)
    assert all(mount.name != "code" for mount in mounts)
    serialized = ApiClient().sanitize_for_serialization(job)
    assert "legacy placeholder" not in json.dumps(serialized)
    assert "configMap" not in json.dumps(serialized)
    assert "--graval-seed" not in job.spec.template.spec.containers[0].command


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
    chute, server, _ = _make_inputs("0.6.0", tee=True)
    job = build_chute_job(
        deployment_id="deploy-1",
        chute=chute,
        server=server,
        service=_make_tee_service(),
        gpu_uuids=["UUID-1"],
        probe_port=8000,
        token="launch-token",
        config_id="config-1",
    )
    volumes = job.spec.template.spec.volumes
    mounts = job.spec.template.spec.containers[0].volume_mounts

    assert all(volume.name != "code" for volume in volumes)
    assert all(mount.name != "code" for mount in mounts)


def test_build_chute_job_rejects_legacy_tee_without_source_fallback():
    chute, server, service = _make_inputs("0.3.60", tee=True)
    with pytest.raises(
        DeploymentFailure, match="Legacy source ConfigMap delivery has been removed"
    ):
        build_chute_job(
            deployment_id="deploy-1",
            chute=chute,
            server=server,
            service=service,
            gpu_uuids=["UUID-1"],
            probe_port=8000,
            token="launch-token",
            config_id="config-1",
        )


def _make_tee_service(include_extra_port: bool = False) -> V1Service:
    # TEE chutes on chutes runtime >= 0.6.0 expose an attestation port (8002).
    ports = [
        V1ServicePort(port=8000, target_port=8000, node_port=30080, protocol="TCP"),
        V1ServicePort(port=8001, target_port=8001, node_port=30081, protocol="TCP"),
        V1ServicePort(port=8002, target_port=8002, node_port=30082, protocol="TCP"),
    ]
    if include_extra_port:
        ports.append(
            V1ServicePort(port=9000, target_port=9000, node_port=30900, protocol="TCP")
        )
    return V1Service(
        spec=V1ServiceSpec(
            type="NodePort",
            selector={"app": "chute"},
            external_traffic_policy="Local",
            ports=ports,
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
        config_id="config-1",
    )
    assert job.spec.template.spec.runtime_class_name == "nvidia"
    env = _container_env(job)
    assert env["NVIDIA_VISIBLE_DEVICES"] == "GPU-UUID-1"
    assert env["CHUTES_NVIDIA_DEVICES"] == "GPU-UUID-1"
    assert env["NCCL_P2P_DISABLE"] == "1"
    assert "CHUTES_HOST_ID" not in env
    assert env["CHUTES_API_URL"] == "http://test-api"
    assert env["CHUTES_LAUNCH_JWT"] == "launch-token"
    assert "CHUTES_API_KEY" not in env
    assert "CHUTEFS_VOLUME_ID" not in env
    assert "CHUTEFS_STORAGE_SESSION" not in env
    assert "CHUTEFS_STORAGE_REFRESH" not in env
    assert env["CHUTES_EXTERNAL_HOST"] == "10.0.0.10"
    assert job.spec.template.spec.containers[0].security_context.capabilities == {
        "add": ["IPC_LOCK"]
    }
    assert job.spec.template.spec.automount_service_account_token is False


def test_seedless_job_uses_exact_registry_root_digest(monkeypatch):
    from chutes_miner.api.k8s import util

    chute, server, _ = _make_inputs("0.8.0", tee=True)
    service = _make_tee_service()
    monkeypatch.setattr(util.settings, "gpu_tee_only", True)
    monkeypatch.setattr(
        util,
        "resolve_deployment_validator",
        lambda _chute, _server: SimpleNamespace(api="http://test-api"),
    )
    root = f"sha256:{'a' * 64}"
    job = build_chute_job(
        deployment_id="deploy-scoped",
        chute=chute,
        server=server,
        service=service,
        gpu_uuids=["GPU-UUID-1"],
        probe_port=8000,
        token="launch-token",
        config_id="config-1",
        registry_repository="owner/image",
        registry_manifest_digest=root,
    )
    assert job.spec.template.spec.containers[0].image.endswith(f"/owner/image@{root}")
    assert job.spec.template.metadata.finalizers == [POD_TEARDOWN_FINALIZER]


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
        config_id="config-1",
    )

    env = _container_env(job)
    assert env["CHUTES_API_URL"] == "http://test-api"
    assert env["CHUTES_LAUNCH_JWT"] == "launch-token"
    assert env["CHUTES_EXTERNAL_HOST"] == "10.0.0.10"
    assert "CHUTES_HOST_ID" not in env
    assert "CHUTES_API_KEY" not in env
    assert "CHUTEFS_VOLUME_ID" not in env
    assert "CHUTEFS_STORAGE_SESSION" not in env
    assert "CHUTEFS_STORAGE_REFRESH" not in env


@pytest.mark.parametrize(
    ("vm_version", "download_mode"),
    [
        ("1.3.0", "plain-http"),
        ("1.3.1", "xet"),
        ("1.8.0", "xet"),
        (None, "default"),
        ("unknown", "default"),
    ],
)
def test_build_tee_job_combines_vm_environment_with_launch_context(
    vm_version, download_mode
):
    chute, server, _ = _make_inputs("0.8.0", tee=True)
    job = build_chute_job(
        deployment_id="deploy-gpu",
        chute=chute,
        server=server,
        service=_make_tee_service(),
        gpu_uuids=["GPU-UUID-1"],
        probe_port=8000,
        token="launch-token",
        config_id="config-1",
        vm_version=vm_version,
    )

    env = _container_env(job)
    assert env["CHUTES_API_URL"] == "http://test-api"
    assert env["CHUTES_LAUNCH_JWT"] == "launch-token"
    assert env["CHUTES_EXTERNAL_HOST"] == server.ip_address
    assert "CHUTES_HOST_ID" not in env
    assert "HF_HUB_ENABLE_HF_TRANSFER" not in env
    if download_mode == "xet":
        assert env["HF_XET_FIXED_DOWNLOAD_CONCURRENCY"] == "16"
        assert env["TOKIO_WORKER_THREADS"] == "8"
        assert "HF_HUB_DISABLE_XET" not in env
    elif download_mode == "plain-http":
        assert env["HF_HUB_DISABLE_XET"] == "1"
        assert "HF_XET_FIXED_DOWNLOAD_CONCURRENCY" not in env
        assert "TOKIO_WORKER_THREADS" not in env
    else:
        assert "HF_HUB_DISABLE_XET" not in env
        assert "HF_XET_FIXED_DOWNLOAD_CONCURRENCY" not in env
        assert "TOKIO_WORKER_THREADS" not in env


def _measured_policy_dir() -> Path:
    sek8s_root = repository_root("sek8s", start=Path(__file__))
    policy_dir = sek8s_root / "ansible/guest/roles/admission-controller/files/policies"
    assert policy_dir.is_dir(), f"measured policy directory is missing: {policy_dir}"
    return policy_dir


@pytest.mark.parametrize("vm_version", ["1.3.0", "1.8.0", None, "unknown"])
def test_generated_tee_job_is_admitted_by_measured_guest_policy(vm_version):
    policy_dir = _measured_policy_dir()
    opa = shutil.which("opa") or str(policy_dir.parents[5] / "bin/opa")
    if not Path(opa).is_file():
        pytest.skip("OPA executable unavailable")

    chute, server, _ = _make_inputs("0.8.0", tee=True)
    job = build_chute_job(
        deployment_id="deploy-policy-contract",
        chute=chute,
        server=server,
        service=_make_tee_service(include_extra_port=True),
        gpu_uuids=["GPU-UUID-1"],
        probe_port=8000,
        token="launch-token",
        config_id="config-1",
        vm_version=vm_version,
    )
    env = _container_env(job)
    assert env["CHUTES_API_URL"] == "http://test-api"
    assert env["CHUTES_LAUNCH_JWT"] == "launch-token"
    assert env["CHUTES_PORT_TCP_9000"] == "30900"
    assert "HF_HUB_ENABLE_HF_TRANSFER" not in env
    assert job.spec.template.spec.automount_service_account_token is False

    image = job.spec.template.spec.containers[0].image
    validator_registry = image.split("/", 1)[0]
    policy_query = f"data.kubernetes.admission.deny with data.config.validator_registry as {json.dumps(validator_registry)}"

    admission_input = {
        "request": {
            "operation": "CREATE",
            "kind": {"kind": "Job"},
            "namespace": "chutes",
            "name": job.metadata.name,
            "userInfo": {
                "username": "system:serviceaccount:chutes:chutes",
                "groups": [
                    "system:serviceaccounts",
                    "system:serviceaccounts:chutes",
                    "system:authenticated",
                ],
            },
            "object": ApiClient().sanitize_for_serialization(job),
        }
    }
    result = subprocess.run(
        [
            opa,
            "eval",
            "--format=json",
            "--data",
            str(policy_dir),
            "--stdin-input",
            policy_query,
        ],
        input=json.dumps(admission_input),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    evaluation = json.loads(result.stdout)
    denials = evaluation["result"][0]["expressions"][0]["value"]
    assert denials == []


@pytest.mark.parametrize(
    ("token", "config_id"),
    [(None, None), ("launch-token", None), (None, "config-1")],
)
def test_build_job_rejects_missing_launch_context(token, config_id):
    chute, server, service = _make_inputs("0.8.0")
    with pytest.raises(DeploymentFailure, match="Missing required launch config"):
        build_chute_job(
            deployment_id="deploy-gpu",
            chute=chute,
            server=server,
            service=service,
            gpu_uuids=["GPU-UUID-1"],
            probe_port=8000,
            token=token,
            config_id=config_id,
        )


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
            config_id="config-1",
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
            config_id="config-1",
        )
