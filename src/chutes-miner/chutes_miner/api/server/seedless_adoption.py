"""Adopt the registrar-created GPU server into the local miner inventory."""

import math
import uuid
from datetime import datetime, timezone

from chutes_common.schemas.gpu import GPU
from chutes_common.schemas.gpu_adoption import GPUAdoptionRetirement
from chutes_common.schemas.server import Server, ServerNodeIdentity
from chutes_miner.api.config import k8s_core_client, settings
from chutes_miner.api.database import get_session
from sqlalchemy import or_, select, text


class SeedlessAdoptionBlocked(RuntimeError):
    """A retryable adoption barrier caused by deployment-owned stale GPU rows."""


def _control_plane_node():
    nodes = k8s_core_client().list_node().items
    control_planes = [
        node
        for node in nodes
        if node.metadata and "node-role.kubernetes.io/control-plane" in (node.metadata.labels or {})
    ]
    if len(control_planes) != 1:
        raise RuntimeError(
            "seedless GPU adoption requires exactly one Kubernetes control-plane node"
        )
    node = control_planes[0]
    if (
        not node.metadata.name
        or not node.metadata.uid
        or not node.status
        or not node.status.capacity
    ):
        raise RuntimeError("seedless GPU Kubernetes node identity is incomplete")
    ready = any(
        condition.type == "Ready" and condition.status == "True"
        for condition in (node.status.conditions or [])
    )
    if not ready:
        raise RuntimeError("seedless GPU Kubernetes node is not ready")
    return node


def _node_resources(node, *, assigned_gpu_count: int) -> tuple[int, int, int]:
    capacity = node.status.capacity
    allocatable = getattr(node.status, "allocatable", None)
    try:
        capacity_gpu_count = int(capacity.get("nvidia.com/gpu", "0"))
        gpu_count = int((allocatable or {}).get("nvidia.com/gpu", "0"))
        cpu_count = int(capacity.get("cpu", "0")) - 2
    except (AttributeError, TypeError, ValueError) as exc:
        raise RuntimeError("seedless GPU Kubernetes capacity is invalid") from exc
    memory = capacity.get("memory", "")
    if capacity_gpu_count < 1 or gpu_count < 1 or gpu_count > capacity_gpu_count or cpu_count < 1:
        raise RuntimeError("seedless GPU Kubernetes capacity is invalid")
    if assigned_gpu_count != gpu_count:
        raise RuntimeError(
            "Registrar-assigned GPU UUID cardinality does not match Kubernetes "
            f"allocatable GPU capacity: assigned={assigned_gpu_count} allocatable={gpu_count}"
        )
    if memory.endswith("Ki"):
        memory_gib = int(memory[:-2]) // 1024 // 1024
    elif memory.endswith("Mi"):
        memory_gib = int(memory[:-2]) // 1024
    elif memory.endswith("Gi"):
        memory_gib = int(memory[:-2])
    else:
        raise RuntimeError("seedless GPU Kubernetes memory capacity is invalid")
    memory_gib -= 6
    if memory_gib < 1:
        raise RuntimeError("seedless GPU Kubernetes memory capacity is too small")
    return (
        gpu_count,
        max(1, min(4, math.floor(cpu_count / gpu_count))),
        max(1, math.floor(memory_gib * 0.8 / gpu_count)),
    )


def _canonical_gpu_id(logical_server_id: str, hardware_uuid: str) -> str:
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"chutes:nvidia:{logical_server_id}:{hardware_uuid}",
        )
    )


def _tracked_hardware_uuid(item, canonical_hardware_by_gpu_id: dict[str, str]) -> str | None:
    device_info = item.device_info if isinstance(item.device_info, dict) else {}
    return (
        item.hardware_uuid
        or device_info.get("uuid")
        or (item.gpu_id if item.gpu_id.startswith("GPU-") else None)
        or canonical_hardware_by_gpu_id.get(item.gpu_id)
    )


async def _retire_unassigned_tracked_gpus(
    session,
    *,
    tracked: list[GPU],
    identity: dict,
    logical_server_id: str,
) -> list[str]:
    """Audit and remove stale rows only after proving they have no deployment."""

    assigned = set(identity["gpu_uuids"])
    canonical_hardware_by_gpu_id = {
        _canonical_gpu_id(logical_server_id, hardware_uuid): hardware_uuid
        for hardware_uuid in assigned
    }
    retireable: list[tuple[GPU, str | None]] = []
    blockers: list[tuple[str, str]] = []
    for item in tracked:
        hardware_uuid = _tracked_hardware_uuid(item, canonical_hardware_by_gpu_id)
        if hardware_uuid in assigned:
            item.hardware_uuid = hardware_uuid
            continue
        if item.deployment_id is not None:
            blockers.append((item.gpu_id, item.deployment_id))
        else:
            retireable.append((item, hardware_uuid))

    if blockers:
        summary = ", ".join(
            f"gpu={gpu_id} deployment={deployment_id}" for gpu_id, deployment_id in sorted(blockers)
        )
        raise SeedlessAdoptionBlocked(
            "seedless GPU adoption is blocked by active/nonterminal deployment "
            f"assignments outside the registrar GPU set: {summary}"
        )

    retired_ids: list[str] = []
    for item, hardware_uuid in retireable:
        session.add(
            GPUAdoptionRetirement(
                retirement_id=str(uuid.uuid4()),
                server_id=logical_server_id,
                gpu_id=item.gpu_id,
                hardware_uuid=hardware_uuid,
                deployment_id=item.deployment_id,
                validator=item.validator,
                device_info=item.device_info,
                model_short_ref=item.model_short_ref,
                verified=item.verified,
                prior_gpu_allocation_group_id=item.gpu_allocation_group_id,
                prior_gpu_allocation_group_generation=item.gpu_allocation_group_generation,
                replacement_registration_attestation_id=identity["attestation_id"],
                replacement_gpu_allocation_group_id=identity["allocation_group_id"],
                replacement_gpu_allocation_group_generation=identity["allocation_group_generation"],
            )
        )
        await session.delete(item)
        retired_ids.append(item.gpu_id)
    return retired_ids


async def adopt_seedless_gpu_server() -> str:
    """Bind one K3s node UID to the authenticated logical validator server."""

    identity = settings.seedless_gpu_identity
    hourly_cost = settings.miner_hourly_cost
    validator = identity["validator"]["hotkey"]
    logical_server_id = identity["server_id"]
    node = _control_plane_node()
    node_uid = str(node.metadata.uid)
    labels = dict(node.metadata.labels or {})
    if labels.get("chutes/seedless-control-plane") != "true":
        raise RuntimeError("seedless GPU node lacks the measured control-plane label")
    bound_id = labels.get("chutes/logical-server-id")
    if bound_id not in {None, logical_server_id}:
        raise RuntimeError("Kubernetes node is bound to another logical GPU server")
    adopted_id = labels.get("chutes/seedless-adopted")
    if adopted_id not in {None, logical_server_id}:
        raise RuntimeError("Kubernetes node was adopted by another logical GPU server")
    if len(set(identity["gpu_uuids"])) != len(identity["gpu_uuids"]):
        raise RuntimeError("Registrar GPU assignment contains duplicate hardware UUIDs")
    gpu_count, cpu_per_gpu, memory_per_gpu = _node_resources(
        node,
        assigned_gpu_count=len(identity["gpu_uuids"]),
    )
    async with get_session() as session:
        candidates = (
            (
                await session.execute(
                    select(Server)
                    .where(
                        or_(
                            Server.server_id == logical_server_id,
                            Server.kubernetes_node_uid == node_uid,
                            Server.name == node.metadata.name,
                        )
                    )
                    .with_for_update()
                )
            )
            .unique()
            .scalars()
            .all()
        )
        logical = [item for item in candidates if item.server_id == logical_server_id]
        legacy = [item for item in candidates if item.server_id != logical_server_id]
        if len(logical) > 1 or len(legacy) > 1 or (logical and legacy):
            raise RuntimeError(
                "legacy and logical GPU server identities conflict in the persisted database"
            )
        if not logical and legacy:
            old_server = legacy[0]
            if (
                old_server.kubernetes_node_uid not in {None, node_uid}
                or old_server.name != node.metadata.name
                or old_server.validator not in {None, validator}
            ):
                raise RuntimeError(
                    "persisted legacy server does not exactly match this Kubernetes node"
                )
            old_server_id = old_server.server_id
            session.expunge(old_server)
            result = await session.execute(
                text(
                    "UPDATE servers SET server_id = :logical_server_id "
                    "WHERE server_id = :old_server_id AND NOT EXISTS "
                    "(SELECT 1 FROM servers WHERE server_id = :logical_server_id)"
                ),
                {
                    "logical_server_id": logical_server_id,
                    "old_server_id": old_server_id,
                },
            )
            if result.rowcount != 1:
                raise RuntimeError("legacy local server rekey lost its transactional ownership")
            server = (
                (
                    await session.execute(
                        select(Server)
                        .where(Server.server_id == logical_server_id)
                        .with_for_update()
                    )
                )
                .unique()
                .scalar_one()
            )
        else:
            server = logical[0] if logical else None
        node_history_owner = (
            await session.execute(
                select(ServerNodeIdentity)
                .where(ServerNodeIdentity.kubernetes_node_uid == node_uid)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if node_history_owner is not None and node_history_owner.server_id != logical_server_id:
            raise RuntimeError(
                "Kubernetes node UID was previously adopted by another logical server"
            )
        if (
            node_history_owner is not None
            and node_history_owner.server_id == logical_server_id
            and node_history_owner.retired_at is not None
        ):
            raise RuntimeError("A retired Kubernetes node UID cannot be adopted again")
        if (
            server is not None
            and server.kubernetes_node_uid not in {None, node_uid}
            and server.registration_attestation_id == identity["attestation_id"]
        ):
            raise RuntimeError("Kubernetes node UID rotation requires a new registrar attestation")
        if server is None:
            server = Server(server_id=logical_server_id)
            session.add(server)
        current_node_identity = (
            await session.execute(
                select(ServerNodeIdentity)
                .where(
                    ServerNodeIdentity.server_id == logical_server_id,
                    ServerNodeIdentity.retired_at.is_(None),
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if server.kubernetes_node_uid != node_uid:
            if current_node_identity is not None:
                current_node_identity.retired_at = datetime.now(timezone.utc)
            generation = int(server.kubernetes_node_generation or 0) + 1
            session.add(
                ServerNodeIdentity(
                    server_id=logical_server_id,
                    generation=generation,
                    kubernetes_node_uid=node_uid,
                    registration_attestation_id=identity["attestation_id"],
                )
            )
            server.kubernetes_node_generation = generation
        elif current_node_identity is None:
            generation = max(1, int(server.kubernetes_node_generation or 0))
            session.add(
                ServerNodeIdentity(
                    server_id=logical_server_id,
                    generation=generation,
                    kubernetes_node_uid=node_uid,
                    registration_attestation_id=identity["attestation_id"],
                )
            )
            server.kubernetes_node_generation = generation
        elif (
            current_node_identity.generation != server.kubernetes_node_generation
            or current_node_identity.kubernetes_node_uid != node_uid
        ):
            raise RuntimeError("Logical GPU node-incarnation metadata is inconsistent")
        server.kubernetes_node_uid = node_uid
        server.registration_attestation_id = identity["attestation_id"]
        server.gpu_allocation_group_id = identity["allocation_group_id"]
        server.gpu_allocation_group_generation = identity["allocation_group_generation"]
        server.validator = validator
        server.name = node.metadata.name
        server.status = "Ready"
        server.gpu_count = gpu_count
        server.cpu_per_gpu = cpu_per_gpu
        server.memory_per_gpu = memory_per_gpu
        server.hourly_cost = hourly_cost
        server.is_tee = True
        tracked = (
            (
                await session.execute(
                    select(GPU).where(GPU.server_id == logical_server_id).with_for_update(of=GPU)
                )
            )
            .unique()
            .scalars()
            .all()
        )
        await _retire_unassigned_tracked_gpus(
            session,
            tracked=tracked,
            identity=identity,
            logical_server_id=logical_server_id,
        )
        for gpu_uuid, identifier in zip(
            identity["gpu_uuids"],
            identity["gpu_identifiers"],
            strict=True,
        ):
            local_gpu_id = _canonical_gpu_id(logical_server_id, gpu_uuid)
            gpu = (
                await session.execute(select(GPU).where(GPU.hardware_uuid == gpu_uuid))
            ).scalar_one_or_none()
            if gpu is not None and gpu.server_id != logical_server_id:
                raise RuntimeError("Registrar-assigned GPU belongs to another local logical server")
            if gpu is None:
                gpu = GPU(
                    gpu_id=local_gpu_id,
                    hardware_uuid=gpu_uuid,
                    server_id=logical_server_id,
                )
                session.add(gpu)
            elif gpu.gpu_id != local_gpu_id:
                canonical_owner = (
                    await session.execute(
                        select(GPU).where(GPU.gpu_id == local_gpu_id).with_for_update()
                    )
                ).scalar_one_or_none()
                if canonical_owner is not None and canonical_owner is not gpu:
                    raise RuntimeError(
                        "Canonical registrar GPU identity conflicts with another local row"
                    )
                gpu.gpu_id = local_gpu_id
            gpu.validator = validator
            gpu.device_info = {
                "uuid": gpu_uuid,
                "local_gpu_id": local_gpu_id,
                "identifier": identifier,
                "source": "attested_gpu_registration",
            }
            gpu.model_short_ref = identifier
            gpu.verified = True
            gpu.gpu_allocation_group_id = identity["allocation_group_id"]
            gpu.gpu_allocation_group_generation = identity["allocation_group_generation"]

        # The node labels are the external commit marker. Publish them only after every locked DB
        # precondition (especially deployment-owned stale GPUs) has passed. GPU rows remain locked
        # through the patch and commit, so a deployment cannot appear in the intervening window.
        desired_labels = dict(labels)
        desired_labels["chutes/logical-server-id"] = logical_server_id
        desired_labels["chutes/seedless-adopted"] = logical_server_id
        if desired_labels != labels:
            node = k8s_core_client().patch_node(
                node.metadata.name,
                {"metadata": {"labels": desired_labels}},
            )
            labels = dict(getattr(node.metadata, "labels", None) or {})
        if (
            labels.get("chutes/logical-server-id") != logical_server_id
            or labels.get("chutes/seedless-adopted") != logical_server_id
        ):
            raise RuntimeError("Kubernetes node did not persist the exact adoption labels")
        server.ip_address = labels.get("chutes/external-ip")
        server.labels = labels
        await session.commit()
    return logical_server_id
