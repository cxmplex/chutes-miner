import hashlib
import re
from typing import Any, Optional

import orjson
from chutes_common.schemas.chute import Chute
from chutes_common.schemas.server import Server
from chutes_miner.api.config import settings, validator_by_hotkey
from chutes_miner.api.exceptions import DeploymentFailure
from chutes_miner.api.k8s.constants import CHUTE_DEPLOY_PREFIX, CHUTE_SVC_PREFIX
from chutes_miner.api.util import semcomp
from kubernetes.client import (
    V1Container,
    V1EmptyDirVolumeSource,
    V1EnvVar,
    V1ExecAction,
    V1Job,
    V1JobSpec,
    V1LocalObjectReference,
    V1ObjectMeta,
    V1PodSecurityContext,
    V1PodSpec,
    V1PodTemplateSpec,
    V1Probe,
    V1ResourceRequirements,
    V1SecurityContext,
    V1Service,
    V1ServicePort,
    V1ServiceSpec,
    V1Volume,
    V1VolumeMount,
)

_VERSION_PREFIX_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+")
MIN_SUPPORTED_CHUTES_VERSION = "0.3.61"
POD_TEARDOWN_FINALIZER = "chutes.ai/gpu-teardown-v1"
MINER_LAUNCH_REQUEST_FIELDS = frozenset(
    {"schema", "miner_launch_request_id", "lineage"}
)
MINER_LAUNCH_LINEAGE_FIELDS = frozenset(
    {
        "schema",
        "version",
        "miner_hotkey",
        "validator",
        "chute_id",
        "chute_version",
        "server_id",
        "kubernetes_node_uid",
        "kubernetes_node_generation",
        "gpu_allocation_group_id",
        "gpu_allocation_group_generation",
        "job_id",
    }
)


def canonical_miner_launch_sha256(document: Any) -> str:
    return hashlib.sha256(orjson.dumps(document, option=orjson.OPT_SORT_KEYS)).hexdigest()


def validated_miner_launch_lineage(
    intent: Any,
    *,
    miner_hotkey: str,
    validator: str,
    chute_id: str,
    chute_version: str,
    server_id: str,
    job_id: str | None,
    require_gpu_lineage: bool,
) -> dict[str, Any]:
    """Return one byte-canonical, exact-schema durable launch lineage."""
    request = getattr(intent, "request_payload", None)
    lineage = request.get("lineage") if isinstance(request, dict) else None
    job_cleanup_only = bool(getattr(intent, "job_cleanup_only", False))
    expected_request_schema = (
        "chutes.miner-job-release.v1"
        if job_cleanup_only
        else "chutes.miner-launch-request.v1"
    )
    if (
        not isinstance(request, dict)
        or set(request) != MINER_LAUNCH_REQUEST_FIELDS
        or request.get("schema") != expected_request_schema
        or request.get("miner_launch_request_id") != getattr(intent, "intent_id", None)
        or not isinstance(lineage, dict)
        or set(lineage) != MINER_LAUNCH_LINEAGE_FIELDS
        or lineage.get("schema") != "chutes.miner-launch-lineage"
        or lineage.get("version") != 1
        or getattr(intent, "request_sha256", None)
        != canonical_miner_launch_sha256(request)
        or getattr(intent, "lineage_sha256", None)
        != canonical_miner_launch_sha256(lineage)
    ):
        raise DeploymentFailure("durable miner launch lineage is invalid")
    expected = {
        "miner_hotkey": miner_hotkey,
        "validator": validator,
        "chute_id": chute_id,
        "chute_version": chute_version,
        "server_id": server_id,
        "job_id": job_id,
    }
    if (
        any(lineage.get(key) != value for key, value in expected.items())
        or getattr(intent, "validator", None) != validator
        or getattr(intent, "chute_id", None) != chute_id
        or getattr(intent, "chute_version", None) != chute_version
        or getattr(intent, "server_id", None) != server_id
        or getattr(intent, "job_id", None) != job_id
        or (job_cleanup_only and not job_id)
    ):
        raise DeploymentFailure("durable miner launch lineage changed")
    if require_gpu_lineage:
        if any(
            not lineage.get(key)
            for key in ("kubernetes_node_uid", "gpu_allocation_group_id")
        ):
            raise DeploymentFailure("durable miner launch lineage changed")
        if any(
            type(lineage.get(key)) is not int or lineage[key] <= 0
            for key in (
                "kubernetes_node_generation",
                "gpu_allocation_group_generation",
            )
        ):
            raise DeploymentFailure("durable miner launch generation is invalid")
    return lineage


def registry_pull_secret_name(config_id: str) -> str:
    if not isinstance(config_id, str) or not config_id:
        raise DeploymentFailure("launch config ID is absent")
    return f"registry-scope-{hashlib.sha256(config_id.encode('utf-8')).hexdigest()[:40]}"


def resolve_deployment_validator(chute: Chute, server: Server):
    """Return the configured validator only for an exact chute/server match."""
    chute_validator = chute.validator
    server_validator = server.validator
    if not chute_validator:
        raise ValueError(f"Chute {chute.chute_id} has no validator.")
    if not server_validator:
        raise ValueError(f"Server {server.server_id} has no validator.")
    if chute_validator != server_validator:
        raise ValueError(
            f"Chute {chute.chute_id} validator {chute_validator!r} does not match "
            f"server {server.server_id} validator {server_validator!r}."
        )
    validator = validator_by_hotkey(chute_validator)
    if validator is None:
        raise ValueError(f"No configured validator API for hotkey {chute_validator!r}.")
    return validator


def require_supported_chutes_version(version: Optional[str], chute_id: str) -> None:
    if not version or semcomp(version, MIN_SUPPORTED_CHUTES_VERSION) < 0:
        raise DeploymentFailure(
            f"Unsupported chutes runtime version {version!r} for chute {chute_id}; "
            f"minimum supported version is {MIN_SUPPORTED_CHUTES_VERSION}. "
            "Legacy source ConfigMap delivery has been removed; rebuild the chute image."
        )


def _needs_attestation_port(chute: Chute) -> bool:
    """True when chute is TEE-enabled and chutes runtime version >= 0.6.0."""
    version_str = chute.chutes_version or chute.version or "0.0.0"
    return bool(chute.tee and semcomp(version_str, "0.6.0") >= 0)


def _tee_download_env(vm_version: Optional[str]) -> list[V1EnvVar]:
    """Select only download controls supported by the measured guest generation."""
    if not vm_version or _VERSION_PREFIX_RE.match(vm_version) is None:
        # An unknown image may contain either pre-Xet or Hub 1.x dependencies. Their
        # default downloader works in both cases, while forcing either transport does not.
        return []
    if semcomp(vm_version, "1.3.1") >= 0:
        return [
            V1EnvVar(name="HF_XET_FIXED_DOWNLOAD_CONCURRENCY", value="16"),
            V1EnvVar(name="TOKIO_WORKER_THREADS", value="8"),
        ]
    return [V1EnvVar(name="HF_HUB_DISABLE_XET", value="1")]


def build_chute_job(
    deployment_id,
    chute: Chute,
    server: Server,
    service: V1Service,
    gpu_uuids: list[str],
    probe_port: int,
    token: Optional[str] = None,
    job_id: Optional[str] = None,
    config_id: Optional[str] = None,
    registry_repository: Optional[str] = None,
    registry_manifest_digest: Optional[str] = None,
    disk_gb: int = 10,
    vm_version: Optional[str] = None,
) -> V1Job:
    require_supported_chutes_version(chute.chutes_version, chute.chute_id)
    if not token or not config_id:
        raise DeploymentFailure(
            f"Missing required launch config for chute {chute.chute_id}; "
            "source is delivered only through a validator-issued launch token."
        )

    cpu = str(server.cpu_per_gpu * chute.gpu_count)
    ram = str(server.memory_per_gpu * chute.gpu_count) + "Gi"
    validator = resolve_deployment_validator(chute, server)
    deployment_labels = {
        "chutes/deployment-id": deployment_id,
        "chutes/chute": "true",
        "chutes/chute-id": chute.chute_id,
        "chutes/version": chute.version,
    }

    deployment_labels["chutes/config-id"] = config_id
    if job_id:
        deployment_labels["chutes/job-id"] = job_id
        deployment_labels["chutes/job"] = "true"

    # GPU workloads use their validator-signed launch JWT for narrowly scoped model discovery and
    # one-use ensure authorization. They do not have a CPU-TD attestation cert/key, and a miner-set
    # host-id environment variable would not be possession proof.
    extra_env = [
        V1EnvVar(name="CHUTES_API_URL", value=validator.api.rstrip("/")),
    ]
    command = [
        "chutes",
        "run",
        chute.ref_str,
        "--port",
        "8000",
    ]
    extra_env += [
        V1EnvVar(
            name="CHUTES_LAUNCH_JWT",
            value=token,
        ),
        V1EnvVar(
            name="CHUTES_EXTERNAL_HOST",
            value=server.ip_address,
        ),
    ]

    # Port mappings must be in the environment variables.
    # Attestation port 8002 only for TEE chutes on chutes runtime >= 0.6.0.
    needs_attestation_port = _needs_attestation_port(chute)
    unique_ports = [8000, 8001]
    if needs_attestation_port:
        unique_ports.append(8002)
    for port_object in service.spec.ports[3:]:
        proto = (port_object.protocol or "TCP").upper()
        extra_env.append(
            V1EnvVar(
                name=f"CHUTES_PORT_{proto}_{port_object.port}",
                value=str(port_object.node_port),
            )
        )
        if port_object.port not in unique_ports:
            unique_ports.append(port_object.port)

    # Tack on the miner/validator addresses.
    command += [
        "--miner-ss58",
        settings.miner_ss58,
        "--validator-ss58",
        server.validator,
    ]

    if chute.tee:
        extra_env += _tee_download_env(vm_version)

    image = chute.image
    if settings.gpu_tee_only:
        if not registry_repository or not registry_manifest_digest:
            raise DeploymentFailure(
                f"Missing descriptor-closed registry scope for chute {chute.chute_id}."
            )
        image = f"{registry_repository}@{registry_manifest_digest}"
    cache_size_gb = max(
        1,
        int(settings.cache_overrides.get(server.name, settings.cache_max_size_gb)),
    )
    ephemeral_storage_gb = int(disk_gb) + cache_size_gb

    return V1Job(
        metadata=V1ObjectMeta(
            name=f"{CHUTE_DEPLOY_PREFIX}-{deployment_id}",
            labels=deployment_labels,
        ),
        spec=V1JobSpec(
            parallelism=1,
            completions=1,
            backoff_limit=0,
            ttl_seconds_after_finished=300,
            template=V1PodTemplateSpec(
                metadata=V1ObjectMeta(
                    labels=deployment_labels,
                    finalizers=(
                        [POD_TEARDOWN_FINALIZER] if settings.gpu_tee_only else None
                    ),
                    annotations={
                        "prometheus.io/scrape": "true",
                        "prometheus.io/path": "/_metrics",
                        "prometheus.io/port": "8000",
                    },
                ),
                spec=V1PodSpec(
                    restart_policy="Never",
                    automount_service_account_token=False,
                    termination_grace_period_seconds=settings.chute_shutdown_time_seconds,
                    node_name=server.name,  ## Start here
                    runtime_class_name=settings.nvidia_runtime,
                    image_pull_secrets=(
                        [V1LocalObjectReference(name=registry_pull_secret_name(config_id))]
                        if settings.gpu_tee_only
                        else None
                    ),
                    security_context=V1PodSecurityContext(
                        run_as_user=1000,
                        run_as_group=1000,
                    ),
                    volumes=[
                        V1Volume(
                            name="cache",
                            empty_dir=V1EmptyDirVolumeSource(
                                size_limit=f"{cache_size_gb}Gi",
                            ),
                        ),
                        V1Volume(
                            name="tmp",
                            empty_dir=V1EmptyDirVolumeSource(size_limit=f"{disk_gb}Gi"),
                        ),
                        V1Volume(
                            name="shm",
                            empty_dir=V1EmptyDirVolumeSource(medium="Memory", size_limit="16Gi"),
                        ),
                    ],
                    containers=[
                        V1Container(
                            name="chute",
                            image=(
                                f"{server.validator.lower()}.localregistry.chutes.ai:"
                                f"{settings.registry_proxy_port}/{image}"
                            ),
                            image_pull_policy="Always",
                            env=[
                                V1EnvVar(
                                    name="NCCL_P2P_DISABLE",
                                    value="1",
                                ),
                                V1EnvVar(
                                    name="NCCL_IB_DISABLE",
                                    value="1",
                                ),
                                V1EnvVar(
                                    name="NCCL_SHM_DISABLE",
                                    value="0",
                                ),
                                V1EnvVar(
                                    name="NCCL_NET_GDR_LEVEL",
                                    value="0",
                                ),
                                V1EnvVar(
                                    name="NVIDIA_VISIBLE_DEVICES",
                                    value=",".join(gpu_uuids),
                                ),
                                V1EnvVar(
                                    name="CHUTES_NVIDIA_DEVICES",
                                    value=",".join(gpu_uuids),
                                ),
                                V1EnvVar(
                                    name="CHUTES_PORT_PRIMARY",
                                    value=str(service.spec.ports[0].node_port),
                                ),
                                V1EnvVar(
                                    name="CHUTES_PORT_LOGGING",
                                    value=str(service.spec.ports[1].node_port),
                                ),
                                *(
                                    [
                                        V1EnvVar(
                                            name="CHUTES_PORT_ATTESTATION",
                                            value=str(service.spec.ports[2].node_port),
                                        )
                                    ]
                                    if needs_attestation_port
                                    else []
                                ),
                                V1EnvVar(
                                    name="CHUTES_EXECUTION_CONTEXT",
                                    value="REMOTE",
                                ),
                                V1EnvVar(
                                    name="VLLM_DISABLE_TELEMETRY",
                                    value="1",
                                ),
                                V1EnvVar(
                                    name="NCCL_DEBUG",
                                    value="INFO",
                                ),
                                V1EnvVar(
                                    name="NCCL_SOCKET_IFNAME",
                                    value="lo",
                                ),
                                V1EnvVar(
                                    name="NCCL_SOCKET_FAMILY",
                                    value="AF_INET",
                                ),
                                V1EnvVar(name="HF_HOME", value="/cache"),
                                V1EnvVar(name="CIVITAI_HOME", value="/cache/civitai"),
                            ]
                            + extra_env,
                            resources=V1ResourceRequirements(
                                requests={
                                    "cpu": cpu,
                                    "memory": ram,
                                    "ephemeral-storage": f"{ephemeral_storage_gb}Gi",
                                },
                                limits={
                                    "cpu": cpu,
                                    "memory": ram,
                                    "ephemeral-storage": f"{ephemeral_storage_gb}Gi",
                                },
                            ),
                            volume_mounts=[
                                V1VolumeMount(name="cache", mount_path="/cache"),
                                V1VolumeMount(name="tmp", mount_path="/tmp"),
                                V1VolumeMount(name="shm", mount_path="/dev/shm"),
                            ],
                            security_context=V1SecurityContext(
                                # XXX Would love to add this, but vllm (and likely other libraries) love writing files...
                                # read_only_root_filesystem=True,
                                # IPC_LOCK is only needed for GPU workloads (pinned memory).
                                capabilities={"add": ["IPC_LOCK"]},
                            ),
                            command=command,
                            ports=[{"containerPort": port} for port in unique_ports],
                            readiness_probe=V1Probe(
                                _exec=V1ExecAction(
                                    command=[
                                        "/bin/sh",
                                        "-c",
                                        f"curl -f http://127.0.0.1:{probe_port}/_alive || exit 1",
                                    ]
                                ),
                                initial_delay_seconds=15,
                                period_seconds=15,
                                timeout_seconds=1,
                                success_threshold=1,
                                failure_threshold=60,
                            ),
                        )
                    ],
                ),
            ),
        ),
    )


def build_chute_service(
    chute: Chute,
    deployment_id: str,
    extra_service_ports: list[dict[str, Any]] = [],
    *,
    config_id: str,
    job_id: str | None = None,
):
    needs_attestation_port = _needs_attestation_port(chute)
    immutable_labels = {
        "chutes/deployment-id": deployment_id,
        "chutes/chute": "true",
        "chutes/chute-id": chute.chute_id,
        "chutes/version": chute.version,
        "chutes/config-id": config_id,
    }
    if job_id:
        immutable_labels["chutes/job-id"] = job_id
    return V1Service(
        metadata=V1ObjectMeta(
            name=f"{CHUTE_SVC_PREFIX}-{deployment_id}",
            labels=immutable_labels,
        ),
        spec=V1ServiceSpec(
            type="NodePort",
            external_traffic_policy="Local",
            selector={
                "chutes/deployment-id": deployment_id,
            },
            ports=[
                V1ServicePort(port=8000, target_port=8000, protocol="TCP", name="chute-8000"),
                V1ServicePort(port=8001, target_port=8001, protocol="TCP", name="chute-8001"),
                *(
                    [
                        V1ServicePort(
                            port=8002,
                            target_port=8002,
                            protocol="TCP",
                            name="chute-8002",
                        )
                    ]
                    if needs_attestation_port
                    else []
                ),
            ]
            + [
                V1ServicePort(
                    port=svc["port"],
                    target_port=svc["port"],
                    protocol=svc["proto"],
                    name=f"chute-{svc['port']}",
                )
                for svc in extra_service_ports
            ],
        ),
    )
