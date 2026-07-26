"""Crash-safe miner teardown and Kubernetes orphan cleanup."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import aiohttp
from chutes_common.auth import sign_request
from chutes_common.schemas.chute import Chute
from chutes_common.schemas.deployment import Deployment
from chutes_common.schemas.gpu import GPU
from chutes_common.schemas.server import Server
from chutes_common.schemas.teardown import (
    DeploymentTeardownK8sResource,
    DeploymentTeardownOperation,
    KubernetesOrphanTombstone,
    KubernetesOrphanTombstoneResource,
    ParentDeletionChild,
    ParentDeletionOperation,
)
from chutes_miner.api.config import (
    k8s_app_client,
    k8s_batch_client,
    k8s_core_client,
    settings,
    validator_by_hotkey,
)
from chutes_miner.api.database import get_session
from chutes_miner.api.exceptions import DeploymentFailure
from chutes_miner.api.k8s.util import registry_pull_secret_name
from kubernetes.client import V1DeleteOptions, V1Preconditions
from kubernetes.client.rest import ApiException
from loguru import logger
from sqlalchemy import delete, select, update
from sqlalchemy.orm import selectinload


LEASE_SECONDS = 300
EXTERNAL_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=30, connect=10)
DELETE_ORDER = {
    "Pod": 0,
    "ReplicaSet": 1,
    "Job": 2,
    "Deployment": 2,
    "Service": 3,
    "Secret": 4,
}
VERIFY_ORDER = {
    "Job": 0,
    "Deployment": 0,
    "Service": 0,
    "Secret": 0,
    "ReplicaSet": 1,
    "Pod": 2,
}
CONTROLLER_KINDS = frozenset({"Job", "Deployment", "ReplicaSet"})
EXPECTED_OWNER_KINDS = {
    "ReplicaSet": frozenset({"Deployment"}),
    "Pod": frozenset({"Job", "ReplicaSet"}),
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_sha256(document: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


def cluster_context_sha256(server: Server) -> str:
    return canonical_sha256(
        {
            "context": server.name,
            "kubeconfig_sha256": (
                hashlib.sha256(server.kubeconfig.encode()).hexdigest()
                if server.kubeconfig
                else None
            ),
            "node_uid": server.kubernetes_node_uid,
            "node_generation": server.kubernetes_node_generation,
            "namespace": settings.namespace,
        }
    )


@dataclass(frozen=True, slots=True)
class ResourceIdentity:
    api_version: str
    kind: str
    name: str
    namespace: str
    uid: str
    labels: dict[str, str]
    owner_kind: str | None
    owner_name: str | None
    owner_uid: str | None
    node_name: str | None

    @property
    def labels_sha256(self) -> str:
        return canonical_sha256(self.labels)


def _owner(metadata: Any) -> tuple[str | None, str | None, str | None]:
    references = list(getattr(metadata, "owner_references", None) or [])
    if not references:
        return None, None, None
    controller = next((ref for ref in references if getattr(ref, "controller", False)), None)
    reference = controller or references[0]
    return str(reference.kind), str(reference.name), str(reference.uid)


def _identity(kind: str, resource: Any) -> ResourceIdentity:
    metadata = resource.metadata
    owner_kind, owner_name, owner_uid = _owner(metadata)
    node_name = None
    if kind == "Pod":
        node_name = getattr(resource.spec, "node_name", None)
    elif kind in {"Job", "Deployment"}:
        template = getattr(getattr(resource, "spec", None), "template", None)
        node_name = getattr(getattr(template, "spec", None), "node_name", None)
    return ResourceIdentity(
        api_version=str(getattr(resource, "api_version", None) or "v1"),
        kind=kind,
        name=str(metadata.name),
        namespace=str(metadata.namespace),
        uid=str(metadata.uid),
        labels=dict(metadata.labels or {}),
        owner_kind=owner_kind,
        owner_name=owner_name,
        owner_uid=owner_uid,
        node_name=str(node_name) if node_name else None,
    )


def replacement_matches(
    *,
    expected_labels: dict[str, str],
    expected_node_name: str,
    accepted_owner_uids: set[str],
    resource: ResourceIdentity,
) -> bool:
    """Return true only for a replacement in the immutable workload lineage."""
    if resource.kind == "Secret":
        config_id = expected_labels.get("chutes/config-id")
        return bool(
            config_id
            and resource.labels.get("chutes/launch-config-id") == config_id
            and resource.owner_uid is None
        )
    for key in ("chutes/deployment-id", "chutes/chute-id"):
        if resource.labels.get(key) != expected_labels.get(key):
            return False
    for key in ("chutes/config-id", "chutes/job-id"):
        if key in resource.labels and resource.labels[key] != expected_labels.get(key):
            return False
    if resource.node_name and resource.node_name != expected_node_name:
        return False
    expected_owner_kinds = EXPECTED_OWNER_KINDS.get(resource.kind)
    if expected_owner_kinds is None:
        return resource.owner_uid is None
    return bool(
        resource.owner_kind in expected_owner_kinds
        and resource.owner_uid in accepted_owner_uids
    )


class DirectKubernetesClosure:
    """Kubernetes reads/deletes that never use Redis/watch state as proof."""

    def __init__(self, operator: Any | None = None):
        self._operator = operator

    @property
    def operator(self):
        if self._operator is None:
            from chutes_miner.api.k8s.operator import K8sOperator

            self._operator = K8sOperator()
        return self._operator

    def _clients(self, cluster_context: str):
        manager = getattr(self.operator, "_manager", None)
        if manager is not None:
            app = manager.get_app_client(cluster_context)
            batch = manager.get_batch_client(cluster_context)
            core = manager.get_core_client(cluster_context)
        else:
            app = k8s_app_client()
            batch = k8s_batch_client()
            core = k8s_core_client()
        if app is None or batch is None or core is None:
            raise DeploymentFailure(
                f"direct Kubernetes clients unavailable for context {cluster_context}"
            )
        return app, batch, core

    def list_resources(
        self,
        *,
        cluster_context: str,
        namespace: str,
        deployment_id: str,
        config_id: str | None,
    ) -> list[ResourceIdentity]:
        app, batch, core = self._clients(cluster_context)
        selector = f"chutes/deployment-id={deployment_id}"
        resources: list[ResourceIdentity] = []
        for kind, values in (
            (
                "Job",
                batch.list_namespaced_job(
                    namespace=namespace,
                    label_selector=selector,
                    _request_timeout=30,
                ).items,
            ),
            (
                "Deployment",
                app.list_namespaced_deployment(
                    namespace=namespace,
                    label_selector=selector,
                    _request_timeout=30,
                ).items,
            ),
            (
                "ReplicaSet",
                app.list_namespaced_replica_set(
                    namespace=namespace,
                    label_selector=selector,
                    _request_timeout=30,
                ).items,
            ),
            (
                "Service",
                core.list_namespaced_service(
                    namespace=namespace,
                    label_selector=selector,
                    _request_timeout=30,
                ).items,
            ),
            (
                "Pod",
                core.list_namespaced_pod(
                    namespace=namespace,
                    label_selector=selector,
                    _request_timeout=30,
                ).items,
            ),
        ):
            resources.extend(_identity(kind, resource) for resource in values)
        if config_id:
            secret_selector = f"chutes/launch-config-id={config_id}"
            secrets = core.list_namespaced_secret(
                namespace=namespace,
                label_selector=secret_selector,
                _request_timeout=30,
            )
            resources.extend(_identity("Secret", secret) for secret in secrets.items)
        deduplicated = {(resource.kind, resource.uid): resource for resource in resources}
        return sorted(
            deduplicated.values(),
            key=lambda item: (DELETE_ORDER[item.kind], item.name, item.uid),
        )

    def read_resource(
        self,
        *,
        cluster_context: str,
        namespace: str,
        kind: str,
        name: str,
    ) -> ResourceIdentity | None:
        app, batch, core = self._clients(cluster_context)
        reader_specs = {
            "Job": (batch, "read_namespaced_job"),
            "Deployment": (app, "read_namespaced_deployment"),
            "ReplicaSet": (app, "read_namespaced_replica_set"),
            "Service": (core, "read_namespaced_service"),
            "Pod": (core, "read_namespaced_pod"),
            "Secret": (core, "read_namespaced_secret"),
        }
        client, method = reader_specs[kind]
        try:
            resource = getattr(client, method)(
                name=name,
                namespace=namespace,
                _request_timeout=30,
            )
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise
        return _identity(kind, resource)

    def delete_resource(
        self,
        *,
        cluster_context: str,
        namespace: str,
        kind: str,
        name: str,
        uid: str,
    ) -> str:
        app, batch, core = self._clients(cluster_context)
        deleter_specs = {
            "Job": (batch, "delete_namespaced_job"),
            "Deployment": (app, "delete_namespaced_deployment"),
            "ReplicaSet": (app, "delete_namespaced_replica_set"),
            "Service": (core, "delete_namespaced_service"),
            "Pod": (core, "delete_namespaced_pod"),
            "Secret": (core, "delete_namespaced_secret"),
        }
        client, method = deleter_specs[kind]
        options = V1DeleteOptions(
            preconditions=V1Preconditions(uid=uid),
            propagation_policy="Foreground",
            grace_period_seconds=(
                settings.chute_shutdown_time_seconds if kind in CONTROLLER_KINDS else 0
            ),
        )
        try:
            getattr(client, method)(
                name=name,
                namespace=namespace,
                body=options,
                _request_timeout=30,
            )
        except ApiException as exc:
            if exc.status == 404:
                return "absent"
            if exc.status == 409:
                return "uid_changed"
            raise
        return "delete_requested"


class DeploymentTeardownCoordinator:
    """Persist each teardown boundary before moving to the next one."""

    def __init__(self, kubernetes: DirectKubernetesClosure | None = None):
        self.kubernetes = kubernetes or DirectKubernetesClosure()
        self.worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4()}"

    @staticmethod
    def _operation_labels(deployment: Deployment) -> dict[str, str]:
        labels = {
            "chutes/deployment-id": deployment.deployment_id,
            "chutes/chute-id": deployment.chute_id,
        }
        if deployment.config_id:
            labels["chutes/config-id"] = deployment.config_id
        if deployment.job_id:
            labels["chutes/job-id"] = deployment.job_id
        return labels

    async def _request_in_session(
        self,
        session: Any,
        deployment: Deployment,
        reason: str,
    ) -> DeploymentTeardownOperation:
        existing = (
            (
                await session.execute(
                    select(DeploymentTeardownOperation)
                    .where(
                        DeploymentTeardownOperation.deployment_id
                        == deployment.deployment_id,
                        DeploymentTeardownOperation.phase != "completed",
                    )
                    .with_for_update()
                )
            )
            .unique()
            .scalar_one_or_none()
        )
        if existing is not None:
            if deployment.teardown_operation_id != existing.operation_id:
                deployment.teardown_operation_id = existing.operation_id
            deployment.active = False
            return existing

        gpu_rows = (
            (
                await session.execute(
                    select(GPU)
                    .where(GPU.deployment_id == deployment.deployment_id)
                    .order_by(GPU.gpu_id)
                    .with_for_update()
                )
            )
            .unique()
            .scalars()
            .all()
        )
        server = deployment.server
        operation = DeploymentTeardownOperation(
            operation_id=str(uuid.uuid4()),
            deployment_id=deployment.deployment_id,
            phase="requested",
            reason=reason,
            validator=deployment.validator,
            server_id=deployment.server_id,
            chute_id=deployment.chute_id,
            config_id=deployment.config_id,
            job_id=deployment.job_id,
            instance_id=deployment.instance_id,
            cluster_context=server.name,
            cluster_context_sha256=cluster_context_sha256(server),
            namespace=settings.namespace,
            kubernetes_node_uid=server.kubernetes_node_uid,
            kubernetes_node_generation=server.kubernetes_node_generation,
            gpu_hardware_uuids=sorted(
                str(gpu.hardware_uuid or gpu.gpu_id) for gpu in gpu_rows
            ),
            immutable_labels=self._operation_labels(deployment),
        )
        session.add(operation)
        await session.flush()
        deployment.teardown_operation_id = operation.operation_id
        deployment.active = False
        return operation

    async def request(self, deployment_id: str, reason: str) -> str | None:
        async with get_session() as session:
            deployment = (
                (
                    await session.execute(
                        select(Deployment)
                        .where(Deployment.deployment_id == deployment_id)
                        .options(selectinload(Deployment.server))
                        .with_for_update()
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            if deployment is None:
                completed = await session.scalar(
                    select(DeploymentTeardownOperation.operation_id)
                    .where(
                        DeploymentTeardownOperation.deployment_id == deployment_id,
                        DeploymentTeardownOperation.phase == "completed",
                    )
                    .order_by(DeploymentTeardownOperation.completed_at.desc())
                )
                return completed
            operation = await self._request_in_session(session, deployment, reason)
            await session.commit()
            return operation.operation_id

    async def _claim(self, operation_id: str) -> bool:
        now = utc_now()
        async with get_session() as session:
            operation = (
                await session.execute(
                    select(DeploymentTeardownOperation)
                    .where(DeploymentTeardownOperation.operation_id == operation_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if operation is None or operation.phase == "completed":
                return False
            if operation.lineage_conflict_at is not None:
                return False
            if (
                operation.retry_lease_expires_at is not None
                and operation.retry_lease_expires_at > now
                and operation.retry_lease_owner != self.worker_id
            ):
                return False
            operation.retry_lease_owner = self.worker_id
            operation.retry_lease_expires_at = now + timedelta(seconds=LEASE_SECONDS)
            operation.attempt_count += 1
            if operation.phase == "requested":
                operation.phase = "discovering"
            await session.commit()
            return True

    async def _load(self, operation_id: str) -> DeploymentTeardownOperation | None:
        async with get_session() as session:
            return (
                (
                    await session.execute(
                        select(DeploymentTeardownOperation)
                        .where(DeploymentTeardownOperation.operation_id == operation_id)
                        .options(selectinload(DeploymentTeardownOperation.resources))
                    )
                )
                .unique()
                .scalar_one_or_none()
            )

    async def _renew_operation_lease(self, operation_id: str, phase: str) -> None:
        async with get_session() as session:
            operation = await session.get(
                DeploymentTeardownOperation,
                operation_id,
                with_for_update=True,
            )
            if (
                operation is None
                or operation.retry_lease_owner != self.worker_id
                or operation.phase != phase
            ):
                raise DeploymentFailure("teardown lease or phase changed during external work")
            operation.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
            await session.commit()

    async def _renew_orphan_lease(self, tombstone_id: str, phase: str) -> None:
        async with get_session() as session:
            tombstone = await session.get(
                KubernetesOrphanTombstone,
                tombstone_id,
                with_for_update=True,
            )
            if (
                tombstone is None
                or tombstone.retry_lease_owner != self.worker_id
                or tombstone.phase != phase
            ):
                raise DeploymentFailure("orphan lease or phase changed during external work")
            tombstone.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
            await session.commit()

    async def _advance(self, operation_id: str, expected: str, next_phase: str, **values):
        async with get_session() as session:
            operation = (
                await session.execute(
                    select(DeploymentTeardownOperation)
                    .where(DeploymentTeardownOperation.operation_id == operation_id)
                    .with_for_update()
                )
            ).scalar_one()
            if operation.retry_lease_owner != self.worker_id or operation.phase != expected:
                raise DeploymentFailure("teardown lease or phase changed concurrently")
            for key, value in values.items():
                setattr(operation, key, value)
            operation.phase = next_phase
            operation.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
            await session.commit()

    async def _record_resources(
        self,
        operation_id: str,
        resources: Iterable[ResourceIdentity],
    ) -> None:
        async with get_session() as session:
            operation = (
                await session.execute(
                    select(DeploymentTeardownOperation)
                    .where(DeploymentTeardownOperation.operation_id == operation_id)
                    .with_for_update()
                )
            ).scalar_one()
            if operation.retry_lease_owner != self.worker_id:
                raise DeploymentFailure("teardown lease changed during discovery")
            known = {
                (resource.kind, resource.uid)
                for resource in (
                    await session.execute(
                        select(DeploymentTeardownK8sResource).where(
                            DeploymentTeardownK8sResource.operation_id == operation_id
                        )
                    )
                ).scalars()
            }
            for resource in resources:
                if (resource.kind, resource.uid) in known:
                    continue
                session.add(
                    DeploymentTeardownK8sResource(
                        resource_id=str(uuid.uuid4()),
                        operation_id=operation_id,
                        cluster_context=operation.cluster_context,
                        namespace=resource.namespace,
                        api_version=resource.api_version,
                        kind=resource.kind,
                        name=resource.name,
                        uid=resource.uid,
                        owner_kind=resource.owner_kind,
                        owner_name=resource.owner_name,
                        owner_uid=resource.owner_uid,
                        node_name=resource.node_name,
                        labels=resource.labels,
                        labels_sha256=resource.labels_sha256,
                    )
                )
            operation.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
            await session.commit()

    async def _discover(self, operation: DeploymentTeardownOperation) -> None:
        resources = await asyncio.to_thread(
            self.kubernetes.list_resources,
            cluster_context=operation.cluster_context,
            namespace=operation.namespace,
            deployment_id=operation.deployment_id,
            config_id=operation.config_id,
        )
        await self._renew_operation_lease(operation.operation_id, "discovering")
        accepted_owner_uids: set[str] = set()
        for resource in resources:
            if resource.kind in {"Job", "Deployment", "Service", "Secret"} and replacement_matches(
                expected_labels=operation.immutable_labels,
                expected_node_name=operation.cluster_context,
                accepted_owner_uids=accepted_owner_uids,
                resource=resource,
            ):
                accepted_owner_uids.add(resource.uid)
        pending = list(resources)
        changed = True
        while changed:
            changed = False
            for resource in list(pending):
                if replacement_matches(
                    expected_labels=operation.immutable_labels,
                    expected_node_name=operation.cluster_context,
                    accepted_owner_uids=accepted_owner_uids,
                    resource=resource,
                ):
                    accepted_owner_uids.add(resource.uid)
                    pending.remove(resource)
                    changed = True
        if pending:
            identities = ", ".join(
                f"{resource.kind}/{resource.name}:{resource.uid}" for resource in pending
            )
            await self._record_conflict(operation.operation_id, f"lineage conflict: {identities}")
            raise DeploymentFailure("Kubernetes resource lineage conflict")
        await self._record_resources(operation.operation_id, resources)
        await self._advance(operation.operation_id, "discovering", "revoking")

    async def _revoke_registry(self, operation: DeploymentTeardownOperation) -> dict[str, Any]:
        if not operation.config_id or not settings.gpu_tee_only:
            return {"status": "not_required", "config_id": operation.config_id}
        validator = validator_by_hotkey(operation.validator)
        if validator is None:
            raise DeploymentFailure("registry scope validator is unavailable")
        headers, _ = sign_request(purpose="registry")
        service = f"registry-{validator.hotkey.lower()}.{settings.namespace}.svc.cluster.local:5000"
        async with aiohttp.ClientSession(
            raise_for_status=False,
            timeout=EXTERNAL_HTTP_TIMEOUT,
        ) as http:
            async with http.delete(
                f"http://{service}/registry/scopes/{operation.config_id}",
                headers=headers,
            ) as response:
                payload = await response.json()
                if response.status != 200 or payload != {
                    "revoked": True,
                    "launch_config_id": operation.config_id,
                }:
                    raise DeploymentFailure("registry scope revocation was not acknowledged")
        return payload

    async def _delete_validator_instance(
        self, operation: DeploymentTeardownOperation
    ) -> dict[str, Any]:
        if not operation.instance_id:
            return {"status": "not_required", "instance_id": None}
        validator = validator_by_hotkey(operation.validator)
        if validator is None:
            raise DeploymentFailure("validator instance owner is unavailable")
        headers, _ = sign_request(purpose="instances")
        async with aiohttp.ClientSession(
            raise_for_status=False,
            timeout=EXTERNAL_HTTP_TIMEOUT,
        ) as http:
            async with http.delete(
                f"{validator.api}/instances/{operation.chute_id}/{operation.instance_id}",
                headers=headers,
            ) as response:
                body = await response.read()
                if response.status not in (200, 404):
                    raise DeploymentFailure(
                        f"validator instance deletion returned HTTP {response.status}"
                    )
        return {
            "status": "deleted" if response.status == 200 else "already_absent",
            "instance_id": operation.instance_id,
            "response_sha256": hashlib.sha256(body).hexdigest(),
        }

    async def _revoke(self, operation: DeploymentTeardownOperation) -> None:
        if operation.config_id and operation.registry_revocation_ack is None:
            ack = await self._revoke_registry(operation)
            async with get_session() as session:
                current = await session.get(
                    DeploymentTeardownOperation,
                    operation.operation_id,
                    with_for_update=True,
                )
                if current.retry_lease_owner != self.worker_id or current.phase != "revoking":
                    raise DeploymentFailure("teardown changed during registry revocation")
                current.registry_revocation_ack = ack
                current.registry_revoked_at = utc_now()
                current.retry_lease_expires_at = utc_now() + timedelta(
                    seconds=LEASE_SECONDS
                )
                await session.commit()
            operation = await self._load(operation.operation_id)
        if operation.instance_id and operation.validator_instance_deletion_ack is None:
            ack = await self._delete_validator_instance(operation)
            async with get_session() as session:
                current = await session.get(
                    DeploymentTeardownOperation,
                    operation.operation_id,
                    with_for_update=True,
                )
                if current.retry_lease_owner != self.worker_id or current.phase != "revoking":
                    raise DeploymentFailure("teardown changed during validator deletion")
                current.validator_instance_deletion_ack = ack
                current.validator_instance_deleted_at = utc_now()
                current.retry_lease_expires_at = utc_now() + timedelta(
                    seconds=LEASE_SECONDS
                )
                await session.commit()
        await self._advance(operation.operation_id, "revoking", "deleting")

    async def _delete_resources(self, operation: DeploymentTeardownOperation) -> None:
        resources = sorted(
            (
                resource
                for resource in operation.resources
                if resource.state not in {"absent", "replaced"}
            ),
            key=lambda item: (DELETE_ORDER[item.kind], item.name, item.uid),
        )
        for resource in resources:
            outcome = await asyncio.to_thread(
                self.kubernetes.delete_resource,
                cluster_context=operation.cluster_context,
                namespace=resource.namespace,
                kind=resource.kind,
                name=resource.name,
                uid=resource.uid,
            )
            await self._renew_operation_lease(operation.operation_id, "deleting")
            async with get_session() as session:
                current = await session.get(
                    DeploymentTeardownK8sResource,
                    resource.resource_id,
                    with_for_update=True,
                )
                if current and outcome == "absent":
                    current.state = "absent"
                    current.absent_at = utc_now()
                elif current and outcome == "delete_requested" and current.state == "observed":
                    current.state = "delete_requested"
                    current.delete_requested_at = utc_now()
                await session.commit()
        await self._advance(operation.operation_id, "deleting", "verifying")

    async def _record_conflict(self, operation_id: str, message: str) -> None:
        async with get_session() as session:
            operation = await session.get(
                DeploymentTeardownOperation,
                operation_id,
                with_for_update=True,
            )
            operation.lineage_conflict_at = utc_now()
            operation.last_failure = message
            operation.retry_lease_owner = None
            operation.retry_lease_expires_at = None
            await session.commit()

    async def _verify(self, operation: DeploymentTeardownOperation) -> bool:
        accepted_owner_uids = {
            resource.uid
            for resource in operation.resources
            if resource.state != "replaced"
        }
        delete_needed = False
        absence_pending = False
        for resource in sorted(
            operation.resources,
            key=lambda item: (VERIFY_ORDER[item.kind], item.name, item.uid),
        ):
            if resource.state in {"absent", "replaced"}:
                continue
            live = await asyncio.to_thread(
                self.kubernetes.read_resource,
                cluster_context=operation.cluster_context,
                namespace=resource.namespace,
                kind=resource.kind,
                name=resource.name,
            )
            await self._renew_operation_lease(operation.operation_id, "verifying")
            if live is None:
                async with get_session() as session:
                    current = await session.get(
                        DeploymentTeardownK8sResource,
                        resource.resource_id,
                        with_for_update=True,
                    )
                    current.state = "absent"
                    current.absent_at = utc_now()
                    await session.commit()
                continue
            if live.uid == resource.uid:
                absence_pending = True
                continue
            if not replacement_matches(
                expected_labels=operation.immutable_labels,
                expected_node_name=operation.cluster_context,
                accepted_owner_uids=accepted_owner_uids,
                resource=live,
            ):
                await self._record_conflict(
                    operation.operation_id,
                    f"lineage conflict for replacement {live.kind}/{live.name}:{live.uid}",
                )
                return False
            await self._record_resources(operation.operation_id, [live])
            async with get_session() as session:
                old = await session.get(
                    DeploymentTeardownK8sResource,
                    resource.resource_id,
                    with_for_update=True,
                )
                replacement_id = await session.scalar(
                    select(DeploymentTeardownK8sResource.resource_id).where(
                        DeploymentTeardownK8sResource.operation_id == operation.operation_id,
                        DeploymentTeardownK8sResource.kind == live.kind,
                        DeploymentTeardownK8sResource.uid == live.uid,
                    )
                )
                old.state = "replaced"
                old.replaced_by_resource_id = replacement_id
                await session.commit()
            accepted_owner_uids.add(live.uid)
            delete_needed = True

        current = await asyncio.to_thread(
            self.kubernetes.list_resources,
            cluster_context=operation.cluster_context,
            namespace=operation.namespace,
            deployment_id=operation.deployment_id,
            config_id=operation.config_id,
        )
        await self._renew_operation_lease(operation.operation_id, "verifying")
        known_uids = {resource.uid for resource in operation.resources}
        for resource in sorted(
            current,
            key=lambda item: (VERIFY_ORDER[item.kind], item.name, item.uid),
        ):
            if resource.uid in known_uids:
                absence_pending = True
                continue
            if not replacement_matches(
                expected_labels=operation.immutable_labels,
                expected_node_name=operation.cluster_context,
                accepted_owner_uids=accepted_owner_uids,
                resource=resource,
            ):
                await self._record_conflict(
                    operation.operation_id,
                    f"lineage conflict for new {resource.kind}/{resource.name}:{resource.uid}",
                )
                return False
            await self._record_resources(operation.operation_id, [resource])
            accepted_owner_uids.add(resource.uid)
            delete_needed = True

        if delete_needed:
            await self._advance(operation.operation_id, "verifying", "deleting")
            return True
        if absence_pending:
            await self._pause_for_retry(
                operation.operation_id,
                "awaiting direct Kubernetes absence checks",
            )
            return False

        now = utc_now()
        values: dict[str, Any] = {
            "controllers_absent_at": now,
            "services_absent_at": now,
            "pods_absent_at": now,
        }
        if operation.config_id:
            values.update(
                pull_secret_deletion_ack={
                    "status": "absent",
                    "name": registry_pull_secret_name(operation.config_id),
                    "config_id": operation.config_id,
                },
                pull_secret_deleted_at=now,
            )
        await self._advance(operation.operation_id, "verifying", "finalizing", **values)
        return True

    async def _finalize(self, operation: DeploymentTeardownOperation) -> None:
        async with get_session() as session:
            current = (
                await session.execute(
                    select(DeploymentTeardownOperation)
                    .where(DeploymentTeardownOperation.operation_id == operation.operation_id)
                    .with_for_update()
                )
            ).scalar_one()
            if current.retry_lease_owner != self.worker_id or current.phase != "finalizing":
                raise DeploymentFailure("teardown changed before finalization")
            if not (
                current.controllers_absent_at
                and current.services_absent_at
                and current.pods_absent_at
                and (not current.config_id or current.registry_revocation_ack)
                and (not current.config_id or current.pull_secret_deletion_ack)
                and (not current.instance_id or current.validator_instance_deletion_ack)
            ):
                raise DeploymentFailure("teardown finalization lacks persisted acknowledgements")
            deployment = (
                (
                    await session.execute(
                        select(Deployment)
                        .where(Deployment.deployment_id == current.deployment_id)
                        .with_for_update()
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            server = (
                (
                    await session.execute(
                        select(Server)
                        .where(Server.server_id == current.server_id)
                        .with_for_update()
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            gpu_rows = (
                (
                    await session.execute(
                        select(GPU)
                        .where(GPU.deployment_id == current.deployment_id)
                        .order_by(GPU.gpu_id)
                        .with_for_update()
                    )
                )
                .unique()
                .scalars()
                .all()
            )
            lineage_errors = []
            if deployment is not None:
                expected_deployment = (
                    current.validator,
                    current.server_id,
                    current.chute_id,
                    current.config_id,
                    current.job_id,
                    current.instance_id,
                )
                actual_deployment = (
                    deployment.validator,
                    deployment.server_id,
                    deployment.chute_id,
                    deployment.config_id,
                    deployment.job_id,
                    deployment.instance_id,
                )
                if actual_deployment != expected_deployment:
                    lineage_errors.append("Deployment lineage changed")
            if server is None or cluster_context_sha256(server) != current.cluster_context_sha256:
                lineage_errors.append("server/node lineage changed")
            actual_gpu_uuids = sorted(
                str(gpu.hardware_uuid or gpu.gpu_id) for gpu in gpu_rows
            )
            if actual_gpu_uuids != list(current.gpu_hardware_uuids):
                lineage_errors.append("assigned GPU UUID closure changed")
            if lineage_errors:
                current.lineage_conflict_at = utc_now()
                current.last_failure = "; ".join(lineage_errors)
                current.retry_lease_owner = None
                current.retry_lease_expires_at = None
                await session.commit()
                raise DeploymentFailure(current.last_failure)
            await session.execute(
                update(GPU)
                .where(GPU.deployment_id == current.deployment_id)
                .values(deployment_id=None)
            )
            if deployment is not None:
                if deployment.teardown_operation_id != current.operation_id:
                    raise DeploymentFailure("deployment is bound to another teardown")
                await session.delete(deployment)
            current.phase = "completed"
            current.completed_at = utc_now()
            current.retry_lease_owner = None
            current.retry_lease_expires_at = None
            current.last_failure = None
            await session.commit()

    async def _record_failure(self, operation_id: str, exc: Exception) -> None:
        async with get_session() as session:
            operation = await session.get(
                DeploymentTeardownOperation,
                operation_id,
                with_for_update=True,
            )
            if operation and operation.lineage_conflict_at is None:
                operation.last_failure = f"{type(exc).__name__}: {exc}"[:8000]
                operation.retry_lease_owner = None
                operation.retry_lease_expires_at = None
                await session.commit()

    async def _pause_for_retry(self, operation_id: str, message: str) -> None:
        async with get_session() as session:
            operation = await session.get(
                DeploymentTeardownOperation,
                operation_id,
                with_for_update=True,
            )
            if operation and operation.retry_lease_owner == self.worker_id:
                operation.last_failure = message
                operation.retry_lease_owner = None
                operation.retry_lease_expires_at = None
                await session.commit()

    async def run(self, operation_id: str) -> bool:
        if not await self._claim(operation_id):
            operation = await self._load(operation_id)
            return bool(operation and operation.phase == "completed")
        try:
            while True:
                operation = await self._load(operation_id)
                if operation is None:
                    return False
                if operation.phase == "completed":
                    return True
                if operation.phase == "discovering":
                    await self._discover(operation)
                elif operation.phase == "revoking":
                    await self._revoke(operation)
                elif operation.phase == "deleting":
                    await self._delete_resources(operation)
                elif operation.phase == "verifying":
                    if not await self._verify(operation):
                        return False
                elif operation.phase == "finalizing":
                    await self._finalize(operation)
                else:
                    raise DeploymentFailure(f"unsupported teardown phase {operation.phase}")
        except Exception as exc:
            await self._record_failure(operation_id, exc)
            logger.warning(f"Durable teardown {operation_id} paused for retry: {exc}")
            return False

    async def request_and_run(self, deployment_id: str, reason: str) -> bool:
        operation_id = await self.request(deployment_id, reason)
        return bool(operation_id and await self.run(operation_id))

    async def resume_pending(self) -> None:
        now = utc_now()
        async with get_session() as session:
            operation_ids = list(
                (
                    await session.execute(
                        select(DeploymentTeardownOperation.operation_id).where(
                            DeploymentTeardownOperation.phase != "completed",
                            DeploymentTeardownOperation.lineage_conflict_at.is_(None),
                            (
                                DeploymentTeardownOperation.retry_lease_expires_at.is_(None)
                                | (DeploymentTeardownOperation.retry_lease_expires_at <= now)
                            ),
                        )
                    )
                ).scalars()
            )
            parent_operation_ids = list(
                (
                    await session.execute(
                        select(ParentDeletionOperation.operation_id).where(
                            ParentDeletionOperation.phase != "completed",
                            (
                                ParentDeletionOperation.retry_lease_expires_at.is_(None)
                                | (ParentDeletionOperation.retry_lease_expires_at <= now)
                            ),
                        )
                    )
                ).scalars()
            )
            orphan_ids = list(
                (
                    await session.execute(
                        select(KubernetesOrphanTombstone.tombstone_id).where(
                            KubernetesOrphanTombstone.phase != "completed",
                            KubernetesOrphanTombstone.lineage_conflict_at.is_(None),
                            (
                                KubernetesOrphanTombstone.retry_lease_expires_at.is_(None)
                                | (KubernetesOrphanTombstone.retry_lease_expires_at <= now)
                            ),
                        )
                    )
                ).scalars()
            )
        for operation_id in operation_ids:
            await self.run(operation_id)
        for operation_id in parent_operation_ids:
            await self.run_parent(operation_id)
        for tombstone_id in orphan_ids:
            await self.run_orphan(tombstone_id)

    async def request_parent(
        self,
        parent_type: str,
        parent_id: str,
        reason: str,
        *,
        expected_validator: str | None = None,
        expected_chute_version: str | None = None,
    ) -> str | None:
        if parent_type not in {"server", "chute"}:
            raise ValueError("parent_type must be server or chute")
        async with get_session() as session:
            existing = (
                await session.execute(
                    select(ParentDeletionOperation)
                    .where(
                        ParentDeletionOperation.parent_type == parent_type,
                        ParentDeletionOperation.parent_id == parent_id,
                        ParentDeletionOperation.phase != "completed",
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if existing:
                if expected_validator and existing.validator != expected_validator:
                    return None
                if (
                    expected_chute_version
                    and existing.snapshot.get("version") != expected_chute_version
                ):
                    return None
                return existing.operation_id
            if parent_type == "server":
                parent = (
                    (
                        await session.execute(
                            select(Server)
                            .where(Server.server_id == parent_id)
                            .with_for_update()
                        )
                    )
                    .unique()
                    .scalar_one_or_none()
                )
                deployments = (
                    (
                        await session.execute(
                            select(Deployment)
                            .where(Deployment.server_id == parent_id)
                            .options(selectinload(Deployment.server))
                            .order_by(Deployment.deployment_id)
                            .with_for_update()
                        )
                    )
                    .unique()
                    .scalars()
                    .all()
                )
                snapshot = {
                    "name": parent.name,
                    "agent_api": parent.agent_api,
                    "node_uid": parent.kubernetes_node_uid,
                    "node_generation": parent.kubernetes_node_generation,
                } if parent else None
            else:
                parent = (
                    await session.execute(
                        select(Chute)
                        .where(Chute.chute_id == parent_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                deployments = (
                    (
                        await session.execute(
                            select(Deployment)
                            .where(Deployment.chute_id == parent_id)
                            .options(selectinload(Deployment.server))
                            .order_by(Deployment.deployment_id)
                            .with_for_update()
                        )
                    )
                    .unique()
                    .scalars()
                    .all()
                )
                snapshot = {"version": parent.version, "name": parent.name} if parent else None
            if parent is None:
                return None
            if expected_validator and parent.validator != expected_validator:
                return None
            if (
                parent_type == "chute"
                and expected_chute_version
                and parent.version != expected_chute_version
            ):
                return None
            parent_operation = ParentDeletionOperation(
                operation_id=str(uuid.uuid4()),
                parent_type=parent_type,
                parent_id=parent_id,
                validator=parent.validator,
                reason=reason,
                phase="requested",
                snapshot=snapshot,
            )
            session.add(parent_operation)
            await session.flush()
            for deployment in deployments:
                child = await self._request_in_session(session, deployment, reason)
                session.add(
                    ParentDeletionChild(
                        parent_operation_id=parent_operation.operation_id,
                        child_operation_id=child.operation_id,
                    )
                )
            parent_operation.phase = "waiting_for_children"
            await session.commit()
            return parent_operation.operation_id

    async def _delete_validator_server(self, operation: ParentDeletionOperation) -> dict[str, Any]:
        validator = validator_by_hotkey(operation.validator)
        if validator is None:
            raise DeploymentFailure("validator server owner is unavailable")
        headers, _ = sign_request(purpose="tee")
        async with aiohttp.ClientSession(
            raise_for_status=False,
            timeout=EXTERNAL_HTTP_TIMEOUT,
        ) as http:
            async with http.delete(
                f"{validator.api}/servers/{operation.parent_id}",
                headers=headers,
            ) as response:
                body = await response.read()
                if response.status not in (200, 404):
                    raise DeploymentFailure(
                        f"validator server deletion returned HTTP {response.status}"
                    )
        return {
            "status": "deleted" if response.status == 200 else "already_absent",
            "server_id": operation.parent_id,
            "response_sha256": hashlib.sha256(body).hexdigest(),
        }

    async def run_parent(self, operation_id: str) -> bool:
        async with get_session() as session:
            operation = await session.get(
                ParentDeletionOperation,
                operation_id,
                with_for_update=True,
            )
            if operation is None or operation.phase == "completed":
                return bool(operation)
            now = utc_now()
            if operation.retry_lease_expires_at and operation.retry_lease_expires_at > now:
                if operation.retry_lease_owner != self.worker_id:
                    return False
            operation.retry_lease_owner = self.worker_id
            operation.retry_lease_expires_at = now + timedelta(seconds=LEASE_SECONDS)
            operation.attempt_count += 1
            child_ids = list(
                (
                    await session.execute(
                        select(ParentDeletionChild.child_operation_id).where(
                            ParentDeletionChild.parent_operation_id == operation_id
                        )
                    )
                ).scalars()
            )
            await session.commit()
        try:
            for child_id in child_ids:
                if not await self.run(child_id):
                    raise DeploymentFailure(f"child teardown {child_id} is incomplete")
            async with get_session() as session:
                operation = await session.get(
                    ParentDeletionOperation,
                    operation_id,
                    with_for_update=True,
                )
                if operation.retry_lease_owner != self.worker_id:
                    raise DeploymentFailure("parent deletion lease changed concurrently")
                incomplete = await session.scalar(
                    select(DeploymentTeardownOperation.operation_id)
                    .join(
                        ParentDeletionChild,
                        ParentDeletionChild.child_operation_id
                        == DeploymentTeardownOperation.operation_id,
                    )
                    .where(
                        ParentDeletionChild.parent_operation_id == operation_id,
                        DeploymentTeardownOperation.phase != "completed",
                    )
                    .limit(1)
                )
                if incomplete:
                    raise DeploymentFailure("parent deletion still has incomplete children")
                operation.retry_lease_expires_at = utc_now() + timedelta(
                    seconds=LEASE_SECONDS
                )
                await session.commit()
            if operation.parent_type == "server":
                from chutes_miner.api.server.util import (
                    clear_server_cache,
                    stop_server_monitoring,
                )

                snapshot = dict(operation.snapshot)
                if operation.monitor_stop_ack is None:
                    agent_api = snapshot.get("agent_api")
                    if agent_api:
                        try:
                            await stop_server_monitoring(agent_api)
                            monitor_ack = {"status": "stopped", "agent_api": agent_api}
                        except Exception as exc:
                            await clear_server_cache(snapshot["name"])
                            monitor_ack = {
                                "status": "cache_cleared_after_agent_error",
                                "agent_api": agent_api,
                                "error": str(exc)[:1000],
                            }
                    else:
                        await clear_server_cache(snapshot["name"])
                        monitor_ack = {"status": "cache_cleared", "agent_api": None}
                    async with get_session() as session:
                        current = await session.get(
                            ParentDeletionOperation,
                            operation_id,
                            with_for_update=True,
                        )
                        if current.retry_lease_owner != self.worker_id:
                            raise DeploymentFailure(
                                "parent deletion lease changed during monitor stop"
                            )
                        current.monitor_stop_ack = monitor_ack
                        current.monitor_stopped_at = utc_now()
                        current.retry_lease_expires_at = utc_now() + timedelta(
                            seconds=LEASE_SECONDS
                        )
                        await session.commit()
                    operation = current
                if operation.validator_server_deletion_ack is None:
                    validator_ack = await self._delete_validator_server(operation)
                    async with get_session() as session:
                        current = await session.get(
                            ParentDeletionOperation,
                            operation_id,
                            with_for_update=True,
                        )
                        if current.retry_lease_owner != self.worker_id:
                            raise DeploymentFailure(
                                "parent deletion lease changed during validator deletion"
                            )
                        current.validator_server_deletion_ack = validator_ack
                        current.validator_server_deleted_at = utc_now()
                        current.retry_lease_expires_at = utc_now() + timedelta(
                            seconds=LEASE_SECONDS
                        )
                        await session.commit()
            async with get_session() as session:
                current = await session.get(
                    ParentDeletionOperation,
                    operation_id,
                    with_for_update=True,
                )
                if current.retry_lease_owner != self.worker_id:
                    raise DeploymentFailure("parent deletion lease changed before finalization")
                current.phase = "finalizing"
                await session.flush()
                if current.parent_type == "server":
                    parent = (
                        (
                            await session.execute(
                                select(Server)
                                .where(Server.server_id == current.parent_id)
                                .with_for_update()
                            )
                        )
                        .unique()
                        .scalar_one_or_none()
                    )
                    if parent is not None:
                        snapshot = dict(current.snapshot)
                        if (
                            parent.validator != current.validator
                            or parent.name != snapshot.get("name")
                            or parent.kubernetes_node_uid != snapshot.get("node_uid")
                            or parent.kubernetes_node_generation
                            != snapshot.get("node_generation")
                        ):
                            raise DeploymentFailure("server parent lineage changed")
                    await session.execute(
                        delete(GPU).where(
                            GPU.server_id == current.parent_id,
                            GPU.deployment_id.is_(None),
                        )
                    )
                else:
                    parent = (
                        await session.execute(
                            select(Chute)
                            .where(Chute.chute_id == current.parent_id)
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    if parent is not None:
                        snapshot = dict(current.snapshot)
                        if (
                            parent.validator != current.validator
                            or parent.version != snapshot.get("version")
                            or parent.name != snapshot.get("name")
                        ):
                            raise DeploymentFailure("chute parent lineage changed")
                if parent is not None:
                    await session.delete(parent)
                current.phase = "completed"
                current.completed_at = utc_now()
                current.retry_lease_owner = None
                current.retry_lease_expires_at = None
                current.last_failure = None
                await session.commit()
            return True
        except Exception as exc:
            async with get_session() as session:
                current = await session.get(
                    ParentDeletionOperation,
                    operation_id,
                    with_for_update=True,
                )
                if current:
                    current.last_failure = f"{type(exc).__name__}: {exc}"[:8000]
                    current.retry_lease_owner = None
                    current.retry_lease_expires_at = None
                    await session.commit()
            logger.warning(f"Parent deletion {operation_id} paused for retry: {exc}")
            return False

    async def request_orphan(
        self,
        *,
        deployment_id: str,
        cluster_context: str,
        immutable_labels: dict[str, str],
    ) -> str | None:
        async with get_session() as session:
            if await session.get(Deployment, deployment_id) is not None:
                return None
            server = (
                (
                    await session.execute(
                        select(Server)
                        .where(Server.name == cluster_context)
                        .with_for_update()
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            if server is None:
                raise DeploymentFailure("orphan cleanup has no stable server lineage")
            existing = (
                await session.execute(
                    select(KubernetesOrphanTombstone)
                    .where(
                        KubernetesOrphanTombstone.deployment_id == deployment_id,
                        KubernetesOrphanTombstone.cluster_context == cluster_context,
                        KubernetesOrphanTombstone.phase != "completed",
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if existing:
                return existing.tombstone_id
            tombstone = KubernetesOrphanTombstone(
                tombstone_id=str(uuid.uuid4()),
                deployment_id=deployment_id,
                cluster_context=cluster_context,
                cluster_context_sha256=cluster_context_sha256(server),
                namespace=settings.namespace,
                kubernetes_node_uid=server.kubernetes_node_uid,
                kubernetes_node_generation=server.kubernetes_node_generation,
                phase="recorded",
                immutable_labels=immutable_labels,
            )
            session.add(tombstone)
            await session.commit()
            return tombstone.tombstone_id

    async def run_orphan(self, tombstone_id: str) -> bool:
        now = utc_now()
        async with get_session() as session:
            tombstone = await session.get(
                KubernetesOrphanTombstone,
                tombstone_id,
                with_for_update=True,
            )
            if tombstone is None or tombstone.phase == "completed":
                return bool(tombstone)
            if await session.get(Deployment, tombstone.deployment_id) is not None:
                tombstone.last_failure = "local Deployment appeared; orphan cleanup stopped"
                tombstone.lineage_conflict_at = now
                await session.commit()
                return False
            server = (
                (
                    await session.execute(
                        select(Server).where(Server.name == tombstone.cluster_context)
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            if (
                server is None
                or server.kubernetes_node_uid != tombstone.kubernetes_node_uid
                or server.kubernetes_node_generation != tombstone.kubernetes_node_generation
                or cluster_context_sha256(server) != tombstone.cluster_context_sha256
            ):
                tombstone.last_failure = "orphan cluster/node lineage changed"
                tombstone.lineage_conflict_at = now
                await session.commit()
                return False
            if tombstone.lineage_conflict_at is not None:
                return False
            if tombstone.retry_lease_expires_at and tombstone.retry_lease_expires_at > now:
                if tombstone.retry_lease_owner != self.worker_id:
                    return False
            tombstone.retry_lease_owner = self.worker_id
            tombstone.retry_lease_expires_at = now + timedelta(seconds=LEASE_SECONDS)
            tombstone.attempt_count += 1
            await session.commit()
        try:
            if tombstone.phase == "recorded":
                resources = await asyncio.to_thread(
                    self.kubernetes.list_resources,
                    cluster_context=tombstone.cluster_context,
                    namespace=tombstone.namespace,
                    deployment_id=tombstone.deployment_id,
                    config_id=tombstone.immutable_labels.get("chutes/config-id"),
                )
                await self._renew_orphan_lease(tombstone_id, "recorded")
                accepted: set[str] = set()
                pending = list(resources)
                changed = True
                while changed:
                    changed = False
                    for resource in list(pending):
                        if replacement_matches(
                            expected_labels=tombstone.immutable_labels,
                            expected_node_name=tombstone.cluster_context,
                            accepted_owner_uids=accepted,
                            resource=resource,
                        ):
                            accepted.add(resource.uid)
                            pending.remove(resource)
                            changed = True
                if pending:
                    raise DeploymentFailure("orphan resource lineage conflict")
                async with get_session() as session:
                    current = await session.get(
                        KubernetesOrphanTombstone,
                        tombstone_id,
                        with_for_update=True,
                    )
                    for resource in resources:
                        session.add(
                            KubernetesOrphanTombstoneResource(
                                resource_id=str(uuid.uuid4()),
                                tombstone_id=tombstone_id,
                                api_version=resource.api_version,
                                kind=resource.kind,
                                name=resource.name,
                                uid=resource.uid,
                                owner_kind=resource.owner_kind,
                                owner_name=resource.owner_name,
                                owner_uid=resource.owner_uid,
                                node_name=resource.node_name,
                                labels=resource.labels,
                                labels_sha256=resource.labels_sha256,
                            )
                        )
                    current.phase = "deleting"
                    await session.commit()
                return await self.run_orphan(tombstone_id)

            async with get_session() as session:
                resources = list(
                    (
                        await session.execute(
                            select(KubernetesOrphanTombstoneResource)
                            .where(
                                KubernetesOrphanTombstoneResource.tombstone_id == tombstone_id,
                                KubernetesOrphanTombstoneResource.state != "absent",
                            )
                        )
                    ).scalars()
                )
            if tombstone.phase == "deleting":
                for resource in sorted(
                    resources,
                    key=lambda item: (DELETE_ORDER[item.kind], item.name, item.uid),
                ):
                    outcome = await asyncio.to_thread(
                        self.kubernetes.delete_resource,
                        cluster_context=tombstone.cluster_context,
                        namespace=tombstone.namespace,
                        kind=resource.kind,
                        name=resource.name,
                        uid=resource.uid,
                    )
                    await self._renew_orphan_lease(tombstone_id, "deleting")
                    async with get_session() as session:
                        current = await session.get(
                            KubernetesOrphanTombstoneResource,
                            resource.resource_id,
                            with_for_update=True,
                        )
                        if outcome == "absent":
                            current.state = "absent"
                            current.absent_at = utc_now()
                        elif outcome == "delete_requested":
                            current.state = "delete_requested"
                        await session.commit()
                async with get_session() as session:
                    current = await session.get(
                        KubernetesOrphanTombstone,
                        tombstone_id,
                        with_for_update=True,
                    )
                    current.phase = "verifying"
                    await session.commit()
                return await self.run_orphan(tombstone_id)

            accepted_owner_uids = {resource.uid for resource in resources}
            replacement_uids: set[str] = set()
            delete_needed = False
            absence_pending = False
            for resource in sorted(
                resources,
                key=lambda item: (VERIFY_ORDER[item.kind], item.name, item.uid),
            ):
                live = await asyncio.to_thread(
                    self.kubernetes.read_resource,
                    cluster_context=tombstone.cluster_context,
                    namespace=tombstone.namespace,
                    kind=resource.kind,
                    name=resource.name,
                )
                await self._renew_orphan_lease(tombstone_id, "verifying")
                if live is None:
                    async with get_session() as session:
                        current = await session.get(
                            KubernetesOrphanTombstoneResource,
                            resource.resource_id,
                            with_for_update=True,
                        )
                        current.state = "absent"
                        current.absent_at = utc_now()
                        await session.commit()
                    continue
                if live.uid == resource.uid:
                    absence_pending = True
                    continue
                if not replacement_matches(
                    expected_labels=tombstone.immutable_labels,
                    expected_node_name=tombstone.cluster_context,
                    accepted_owner_uids=accepted_owner_uids,
                    resource=live,
                ):
                    raise DeploymentFailure("orphan object replacement has conflicting lineage")
                async with get_session() as session:
                    old = await session.get(
                        KubernetesOrphanTombstoneResource,
                        resource.resource_id,
                        with_for_update=True,
                    )
                    old.state = "absent"
                    old.absent_at = utc_now()
                    session.add(
                        KubernetesOrphanTombstoneResource(
                            resource_id=str(uuid.uuid4()),
                            tombstone_id=tombstone_id,
                            api_version=live.api_version,
                            kind=live.kind,
                            name=live.name,
                            uid=live.uid,
                            owner_kind=live.owner_kind,
                            owner_name=live.owner_name,
                            owner_uid=live.owner_uid,
                            node_name=live.node_name,
                            labels=live.labels,
                            labels_sha256=live.labels_sha256,
                        )
                    )
                    await session.commit()
                accepted_owner_uids.add(live.uid)
                replacement_uids.add(live.uid)
                delete_needed = True
            current_resources = await asyncio.to_thread(
                self.kubernetes.list_resources,
                cluster_context=tombstone.cluster_context,
                namespace=tombstone.namespace,
                deployment_id=tombstone.deployment_id,
                config_id=tombstone.immutable_labels.get("chutes/config-id"),
            )
            await self._renew_orphan_lease(tombstone_id, "verifying")
            known_uids = {resource.uid for resource in resources}
            known_uids.update(replacement_uids)
            for resource in sorted(
                current_resources,
                key=lambda item: (VERIFY_ORDER[item.kind], item.name, item.uid),
            ):
                if resource.uid in known_uids:
                    absence_pending = True
                    continue
                if not replacement_matches(
                    expected_labels=tombstone.immutable_labels,
                    expected_node_name=tombstone.cluster_context,
                    accepted_owner_uids=accepted_owner_uids,
                    resource=resource,
                ):
                    raise DeploymentFailure("new orphan object has conflicting lineage")
                async with get_session() as session:
                    session.add(
                        KubernetesOrphanTombstoneResource(
                            resource_id=str(uuid.uuid4()),
                            tombstone_id=tombstone_id,
                            api_version=resource.api_version,
                            kind=resource.kind,
                            name=resource.name,
                            uid=resource.uid,
                            owner_kind=resource.owner_kind,
                            owner_name=resource.owner_name,
                            owner_uid=resource.owner_uid,
                            node_name=resource.node_name,
                            labels=resource.labels,
                            labels_sha256=resource.labels_sha256,
                        )
                    )
                    await session.commit()
                accepted_owner_uids.add(resource.uid)
                delete_needed = True
            if delete_needed:
                async with get_session() as session:
                    current = await session.get(
                        KubernetesOrphanTombstone,
                        tombstone_id,
                        with_for_update=True,
                    )
                    current.phase = "deleting"
                    await session.commit()
                return await self.run_orphan(tombstone_id)
            if absence_pending:
                async with get_session() as session:
                    current = await session.get(
                        KubernetesOrphanTombstone,
                        tombstone_id,
                        with_for_update=True,
                    )
                    if current.retry_lease_owner == self.worker_id:
                        current.last_failure = "awaiting direct Kubernetes absence checks"
                        current.retry_lease_owner = None
                        current.retry_lease_expires_at = None
                        await session.commit()
                return False
            async with get_session() as session:
                current = await session.get(
                    KubernetesOrphanTombstone,
                    tombstone_id,
                    with_for_update=True,
                )
                current.phase = "completed"
                current.completed_at = utc_now()
                current.retry_lease_owner = None
                current.retry_lease_expires_at = None
                current.last_failure = None
                await session.commit()
            return True
        except Exception as exc:
            async with get_session() as session:
                current = await session.get(
                    KubernetesOrphanTombstone,
                    tombstone_id,
                    with_for_update=True,
                )
                if current:
                    current.last_failure = f"{type(exc).__name__}: {exc}"[:8000]
                    if "lineage" in str(exc):
                        current.lineage_conflict_at = utc_now()
                    current.retry_lease_owner = None
                    current.retry_lease_expires_at = None
                    await session.commit()
            logger.warning(f"Orphan tombstone {tombstone_id} paused: {exc}")
            return False
