"""
Helper for kubernetes interactions.
"""

from typing import Any, List, Dict, Tuple, Union
from chutes_common.schemas.deployment import Deployment
from chutes_miner.api.k8s.operator import K8sOperator
from chutes_common.schemas.chute import Chute
from chutes_common.schemas.server import Server
from kubernetes.client import V1Job


async def get_kubernetes_nodes() -> List[Dict]:
    """
    Get all Kubernetes nodes via k8s client, optionally filtering by GPU nodes.
    """
    return await K8sOperator().get_kubernetes_nodes()


async def get_deployment(deployment_id: str):
    """
    Get a single deployment by ID.
    """
    return await K8sOperator().get_deployment(deployment_id)


async def get_deployed_chutes() -> List[Dict]:
    """
    Get all chutes deployments from kubernetes.
    """
    return await K8sOperator().get_deployed_chutes()


async def get_deployed_chutes_legacy() -> List[Dict]:
    """
    Get all chutes deployments from kubernetes.
    """
    return await K8sOperator()._get_chute_deployments()


async def purge_legacy_source_config_maps() -> None:
    """Remove ConfigMaps left by retired miner-mounted source delivery."""
    await K8sOperator().purge_legacy_source_config_maps()


async def wait_for_deletion(label_selector: str, timeout_seconds: int = 120):
    """
    Wait for a deleted pod to be fully removed.
    """
    return await K8sOperator().wait_for_deletion(label_selector, timeout_seconds)


async def undeploy(
    deployment_id: str,
    timeout_seconds: int | None = None,
    config_id: str | None = None,
):
    """
    Delete a deployment, and associated service.
    Uses chute_shutdown_time_seconds when timeout not specified.
    """
    return await K8sOperator().undeploy(
        deployment_id,
        timeout_seconds=timeout_seconds,
        config_id=config_id,
    )


async def delete_preflight(deployment_id: str, timeout_seconds: int = 120) -> bool:
    """Verify it's safe to delete a deployment before touching local state."""
    return await K8sOperator().delete_preflight(deployment_id, timeout_seconds=timeout_seconds)


async def deploy_chute(
    chute_id: Union[str | Chute],
    server_id: Union[str | Server],
    token: str = None,
    launch_intent_id: str = None,
    job_id: str = None,
    config_id: str = None,
    registry_repository: str = None,
    registry_manifest_digest: str = None,
    disk_gb: int = 10,
    extra_labels: dict[str, str] = {},
    extra_service_ports: list[dict[str, Any]] = [],
    vm_version: str = None,
) -> Tuple[Deployment, V1Job]:
    """
    Deploy a chute!
    """
    return await K8sOperator().deploy_chute(
        chute_id,
        server_id,
        token=token,
        launch_intent_id=launch_intent_id,
        job_id=job_id,
        config_id=config_id,
        registry_repository=registry_repository,
        registry_manifest_digest=registry_manifest_digest,
        disk_gb=disk_gb,
        extra_labels=extra_labels,
        extra_service_ports=extra_service_ports,
        vm_version=vm_version,
    )


async def check_node_has_disk_available(node_name: str, required_disk_gb: int) -> bool:
    """
    Check if a node has sufficient disk space available for a deployment.
    """
    disk_info = await K8sOperator().get_node_disk_info(node_name)
    return disk_info.get("available_gb", 0) >= required_disk_gb
