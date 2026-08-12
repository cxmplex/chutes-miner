"""Crash-safe miner teardown and Kubernetes orphan cleanup."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import ssl
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import aiohttp
from chutes_common.auth import sign_request
from chutes_common.exceptions import AgentError
from chutes_common.schemas.chute import Chute
from chutes_common.schemas.deployment import Deployment
from chutes_common.schemas.gpu import GPU
from chutes_common.schemas.server import Server, ServerNodeIdentity
from chutes_common.schemas.teardown import (
    DelayedValidatorInstanceCleanup,
    DeploymentLaunchOperation,
    DeploymentTeardownK8sResource,
    DeploymentTeardownNodeIncarnationHandoff,
    DeploymentTeardownOperation,
    KubernetesOrphanTombstone,
    KubernetesOrphanTombstoneResource,
    MinerLaunchIntent,
    ParentDeletionChild,
    ParentDeletionOperation,
    RegistryScopeIntent,
    TeardownLineageResolutionAudit,
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
from chutes_miner.api.k8s.util import (
    POD_TEARDOWN_FINALIZER,
    registry_pull_secret_name,
    validated_miner_launch_lineage,
)
from chutes_miner.api.registry_scopes import (
    record_registry_scope_failure,
    record_registry_scope_revoked,
    request_registry_scope_revocation,
    request_registry_scope_revocation_in_session,
)
from kubernetes.client import V1DeleteOptions, V1Preconditions
from kubernetes.client.rest import ApiException
from loguru import logger
from sqlalchemy import delete, or_, select, update
from sqlalchemy.orm import selectinload


LEASE_SECONDS = 300
RETRY_BASE_SECONDS = 5
RETRY_MAX_SECONDS = 15 * 60
RESUME_CONCURRENCY = 8
RESUME_ITEM_TIMEOUT_SECONDS = 60
EXTERNAL_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=30, connect=10)
POD_TERMINATION_EVIDENCE_SCHEMA = "chutes.miner-pod-termination.v1"
POD_TERMINATION_EVIDENCE_V2_SCHEMA = "chutes.miner-pod-termination.v2"
POD_UID_ABSENCE_EVIDENCE_SCHEMA = "chutes.miner-pod-uid-absence.v1"
POD_LIFECYCLE_EVIDENCE_SCHEMA = "chutes.miner-pod-lifecycle.v1"
LAUNCH_FRONTIER_SCHEMA = "chutes.miner-launch-frontier.v1"
PARENT_ALLOCATION_RELEASE_SCHEMA = "chutes.miner-parent-allocation-release.v1"
GPU_DECOMMISSION_REQUEST_SCHEMA = "chutes.gpu-decommission-request"
GPU_DECOMMISSION_RESPONSE_SCHEMA = "chutes.gpu-decommissioned"
LINEAGE_INSPECTION_SCHEMA = "chutes.miner-lineage-conflict.v1"
LINEAGE_AUTHORITY_SCHEMA = "chutes.miner-authoritative-lineage.v1"
RESOURCE_DISCOVERY_SCHEMA = "chutes.miner-k8s-resource-discovery.v1"
DELETE_ORDER = {
    "Job": 0,
    "Deployment": 0,
    "Service": 1,
    "ReplicaSet": 2,
    "Pod": 3,
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
    "ReplicaSet": frozenset({("apps/v1", "Deployment")}),
    "Pod": frozenset({("batch/v1", "Job"), ("apps/v1", "ReplicaSet")}),
}


class LineageConflict(DeploymentFailure):
    """A cryptographically/immutably conflicting Kubernetes lineage."""


class UnresolvedOwnerLineage(DeploymentFailure):
    """A same-lineage child whose controller was not in this non-atomic list."""


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


def retry_at(attempt_count: int, *, now: datetime | None = None) -> datetime:
    """Return a deterministic, capped exponential retry deadline."""

    count = max(1, int(attempt_count or 1))
    delay = min(RETRY_MAX_SECONDS, RETRY_BASE_SECONDS * (2 ** min(count - 1, 20)))
    return (now or utc_now()) + timedelta(seconds=delay)


def _teardown_grace_period_seconds() -> int:
    """Fail closed rather than turning a bad setting into force deletion."""
    value = settings.chute_shutdown_time_seconds
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise DeploymentFailure(
            "CHUTE_SHUTDOWN_TIME_SECONDS must be a positive integer for teardown"
        )
    return value


def _timestamp_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _pod_termination_evidence(resource: Any) -> dict[str, Any] | None:
    """Return exact terminal or provably-never-started container evidence."""
    metadata = getattr(resource, "metadata", None)
    spec = getattr(resource, "spec", None)
    status = getattr(resource, "status", None)
    pod_uid = str(getattr(metadata, "uid", "") or "")
    node_name = str(getattr(spec, "node_name", "") or "")
    if not pod_uid or not node_name or status is None:
        return None

    deletion_timestamp = _timestamp_text(getattr(metadata, "deletion_timestamp", None))
    finalizers = {str(value) for value in (getattr(metadata, "finalizers", None) or [])}
    if deletion_timestamp is None or POD_TEARDOWN_FINALIZER not in finalizers:
        return None
    groups = (
        (
            "init",
            list(getattr(spec, "init_containers", None) or []),
            list(getattr(status, "init_container_statuses", None) or []),
        ),
        (
            "container",
            list(getattr(spec, "containers", None) or []),
            list(getattr(status, "container_statuses", None) or []),
        ),
        (
            "ephemeral",
            list(getattr(spec, "ephemeral_containers", None) or []),
            list(getattr(status, "ephemeral_container_statuses", None) or []),
        ),
    )
    records: list[dict[str, Any]] = []
    expected_count = 0
    for group, containers, statuses in groups:
        expected_names = [str(getattr(container, "name", "") or "") for container in containers]
        if any(not name for name in expected_names) or len(set(expected_names)) != len(
            expected_names
        ):
            return None
        expected_count += len(expected_names)
        by_name = {
            str(getattr(container_status, "name", "") or ""): container_status
            for container_status in statuses
        }
        if set(by_name).difference(expected_names):
            return None
        for name in expected_names:
            container_status = by_name.get(name)
            state = getattr(container_status, "state", None) if container_status else None
            terminated = getattr(state, "terminated", None) if state else None
            running = getattr(state, "running", None) if state else None
            container_id = (
                str(getattr(container_status, "container_id", "") or "") if container_status else ""
            )
            if terminated is not None:
                finished_at = _timestamp_text(getattr(terminated, "finished_at", None))
                if not container_id or not finished_at:
                    return None
                records.append(
                    {
                        "group": group,
                        "name": name,
                        "outcome": "terminated",
                        "container_id": container_id,
                        "exit_code": int(getattr(terminated, "exit_code", 0)),
                        "signal": int(getattr(terminated, "signal", 0) or 0),
                        "reason": str(getattr(terminated, "reason", "") or ""),
                        "started_at": _timestamp_text(getattr(terminated, "started_at", None)),
                        "finished_at": finished_at,
                    }
                )
                continue
            if running is not None or container_id:
                return None
            waiting = getattr(state, "waiting", None) if state else None
            restart_count = (
                int(getattr(container_status, "restart_count", 0) or 0) if container_status else 0
            )
            last_state = getattr(container_status, "last_state", None) if container_status else None
            if (
                restart_count != 0
                or bool(getattr(container_status, "started", False))
                or (
                    last_state is not None
                    and (
                        getattr(last_state, "running", None) is not None
                        or getattr(last_state, "terminated", None) is not None
                    )
                )
                or (container_status is not None and waiting is None)
            ):
                return None
            records.append(
                {
                    "group": group,
                    "name": name,
                    "outcome": "never_started",
                    "waiting_reason": str(getattr(waiting, "reason", "") or "status_absent"),
                    "restart_count": restart_count,
                }
            )
    if expected_count == 0:
        return None
    outcomes = {record["outcome"] for record in records}
    outcome = (
        "terminated"
        if outcomes == {"terminated"}
        else "never_started"
        if outcomes == {"never_started"}
        else "mixed_terminal"
    )
    if outcome != "terminated" and str(getattr(status, "phase", "") or "") != "Pending":
        return None
    ordered = sorted(records, key=lambda item: (item["group"], item["name"]))
    if outcome == "terminated":
        return {
            "schema": POD_TERMINATION_EVIDENCE_SCHEMA,
            "pod_uid": pod_uid,
            "node_name": node_name,
            "teardown_finalizer": POD_TEARDOWN_FINALIZER,
            "deletion_timestamp": deletion_timestamp,
            "containers": ordered,
        }
    return {
        "schema": POD_TERMINATION_EVIDENCE_V2_SCHEMA,
        "outcome": outcome,
        "pod_phase": "Pending",
        "pod_uid": pod_uid,
        "node_name": node_name,
        "teardown_finalizer": POD_TEARDOWN_FINALIZER,
        "deletion_timestamp": deletion_timestamp,
        "termination_origin": "teardown",
        "containers": ordered,
    }


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
    owner_api_version: str | None
    owner_kind: str | None
    owner_name: str | None
    owner_uid: str | None
    node_name: str | None
    pod_termination_evidence: dict[str, Any] | None = None
    pod_already_terminating: bool = False

    @property
    def labels_sha256(self) -> str:
        return canonical_sha256(self.labels)

    @property
    def pod_termination_evidence_sha256(self) -> str | None:
        if self.pod_termination_evidence is None:
            return None
        return canonical_sha256(self.pod_termination_evidence)


def _verified_pod_termination_evidence(resource: Any) -> dict[str, Any] | None:
    evidence = getattr(resource, "pod_termination_evidence", None)
    digest = getattr(resource, "pod_termination_evidence_sha256", None)
    if getattr(resource, "kind", None) != "Pod":
        if evidence is not None or digest is not None:
            raise LineageConflict("non-Pod resource has Pod termination evidence")
        return None
    if evidence is None and digest is None:
        return None
    if (
        not isinstance(evidence, dict)
        or not isinstance(digest, str)
        or evidence.get("pod_uid") != getattr(resource, "uid", None)
        or evidence.get("node_name") != getattr(resource, "node_name", None)
        or evidence.get("teardown_finalizer") != POD_TEARDOWN_FINALIZER
        or not evidence.get("deletion_timestamp")
        or not isinstance(evidence.get("containers"), list)
        or not evidence["containers"]
        or canonical_sha256(evidence) != digest
    ):
        raise LineageConflict("Pod termination evidence is invalid")
    legacy = evidence.get("schema") == POD_TERMINATION_EVIDENCE_SCHEMA
    if legacy:
        if set(evidence) != {
            "schema",
            "pod_uid",
            "node_name",
            "teardown_finalizer",
            "deletion_timestamp",
            "containers",
        }:
            raise LineageConflict("Pod termination evidence is invalid")
    elif (
        evidence.get("schema") != POD_TERMINATION_EVIDENCE_V2_SCHEMA
        or set(evidence)
        != {
            "schema",
            "outcome",
            "pod_phase",
            "pod_uid",
            "node_name",
            "teardown_finalizer",
            "deletion_timestamp",
            "termination_origin",
            "containers",
        }
        or evidence.get("pod_phase") != "Pending"
        or evidence.get("termination_origin") not in {"teardown", "already_terminating"}
        or evidence.get("termination_origin")
        != (
            "already_terminating"
            if getattr(resource, "pod_already_terminating", False)
            else "teardown"
        )
    ):
        raise LineageConflict("Pod termination evidence is invalid")
    container_outcomes: set[str] = set()
    identities: set[tuple[str, str]] = set()
    for container in evidence["containers"]:
        if not isinstance(container, dict):
            raise LineageConflict("Pod container termination evidence is invalid")
        group = container.get("group")
        name = container.get("name")
        outcome = container.get("outcome")
        if (
            group not in {"init", "container", "ephemeral"}
            or not name
            or (group, name) in identities
        ):
            raise LineageConflict("Pod container termination evidence is invalid")
        identities.add((group, name))
        container_outcomes.add(outcome)
        if outcome == "terminated":
            if (
                set(container)
                != {
                    "group",
                    "name",
                    "outcome",
                    "container_id",
                    "exit_code",
                    "signal",
                    "reason",
                    "started_at",
                    "finished_at",
                }
                or not container.get("container_id")
                or not container.get("finished_at")
            ):
                raise LineageConflict("Pod container termination evidence is invalid")
        elif not legacy and outcome == "never_started":
            if (
                set(container)
                != {
                    "group",
                    "name",
                    "outcome",
                    "waiting_reason",
                    "restart_count",
                }
                or not container.get("waiting_reason")
                or not isinstance(container.get("restart_count"), int)
                or isinstance(container.get("restart_count"), bool)
                or container["restart_count"] != 0
            ):
                raise LineageConflict("Pod never-started evidence is invalid")
        else:
            raise LineageConflict("Pod container termination evidence is invalid")
    expected_outcome = (
        "terminated"
        if container_outcomes == {"terminated"}
        else "never_started"
        if container_outcomes == {"never_started"}
        else "mixed_terminal"
    )
    if legacy and expected_outcome != "terminated":
        raise LineageConflict("legacy Pod termination evidence is invalid")
    if not legacy and evidence.get("outcome") != expected_outcome:
        raise LineageConflict("Pod aggregate terminal outcome is invalid")
    return evidence


def _verified_pod_uid_absence_evidence(resource: Any) -> dict[str, Any] | None:
    evidence = getattr(resource, "pod_uid_absence_evidence", None)
    digest = getattr(resource, "pod_uid_absence_evidence_sha256", None)
    observed_at = getattr(resource, "pod_uid_absence_observed_at", None)
    if evidence is None and digest is None and observed_at is None:
        return None
    if (
        getattr(resource, "kind", None) != "Pod"
        or not isinstance(evidence, dict)
        or not isinstance(digest, str)
        or observed_at is None
        or set(evidence)
        != {
            "schema",
            "outcome",
            "operation_id",
            "pod_uid",
            "node_name",
            "resource_discovery_sha256",
            "read_status",
            "selector_absent",
        }
        or evidence.get("schema") != POD_UID_ABSENCE_EVIDENCE_SCHEMA
        or evidence.get("outcome") != "uid_absent"
        or evidence.get("operation_id") != getattr(resource, "operation_id", None)
        or evidence.get("pod_uid") != getattr(resource, "uid", None)
        or evidence.get("node_name") != getattr(resource, "node_name", None)
        or not isinstance(evidence.get("resource_discovery_sha256"), str)
        or len(evidence["resource_discovery_sha256"]) != 64
        or evidence.get("read_status") != 404
        or evidence.get("selector_absent") is not True
        or canonical_sha256(evidence) != digest
    ):
        raise LineageConflict("Pod UID-absence evidence is invalid")
    return evidence


def _pod_absence_proven(resource: Any) -> bool:
    """Require either finalizer closure or a durable exact-UID absence witness."""
    if getattr(resource, "kind", None) != "Pod":
        return True
    terminal = _verified_pod_termination_evidence(resource)
    uid_absent = _verified_pod_uid_absence_evidence(resource)
    return bool(
        (
            terminal
            and getattr(resource, "pod_teardown_finalizer_attached_at", None)
            and getattr(resource, "pod_teardown_finalizer_removal_requested_at", None)
            and getattr(resource, "pod_teardown_finalizer_removed_at", None)
        )
        or uid_absent
    )


def _launch_definitively_pre_kubernetes_mutation(operation: Any) -> bool:
    """Return true only for the durable launch phase before any API mutation."""
    return bool(getattr(operation, "launch_operation_id", None)) and (
        getattr(operation, "launch_phase_at_request", None) == "reserved"
        and getattr(operation, "launch_kubernetes_mutation_possible", None) is False
        and getattr(operation, "launch_create_results_sha256", None) == canonical_sha256({})
    )


def _requires_pod_termination_evidence(operation: Any) -> bool:
    """GPU ownership requires an exact Pod closure unless launch never started."""
    hardware_uuids = getattr(operation, "gpu_hardware_uuids", None)
    return bool(hardware_uuids) and not _launch_definitively_pre_kubernetes_mutation(operation)


def _launch_frontier_document(launch: DeploymentLaunchOperation) -> dict[str, Any]:
    create_results = dict(launch.create_results or {})
    return {
        "schema": LAUNCH_FRONTIER_SCHEMA,
        "operation_id": launch.operation_id,
        "deployment_id": launch.deployment_id,
        "phase": launch.phase,
        "cluster_context": launch.cluster_context,
        "canonical_workload_spec_sha256": getattr(launch, "canonical_workload_spec_sha256", None),
        "service": {"name": launch.service_name, "uid": launch.service_uid},
        "secret": {"name": launch.secret_name, "uid": launch.secret_uid},
        "job": {"name": launch.job_name, "uid": launch.job_uid},
        "create_results": create_results,
        "create_results_sha256": canonical_sha256(create_results),
    }


def _verified_launch_frontier(operation: Any) -> dict[str, Any] | None:
    frontier = getattr(operation, "launch_frontier", None)
    digest = getattr(operation, "launch_frontier_sha256", None)
    if frontier is None and digest is None:
        return None
    if (
        not isinstance(frontier, dict)
        or not isinstance(digest, str)
        or set(frontier)
        != {
            "schema",
            "operation_id",
            "deployment_id",
            "phase",
            "cluster_context",
            "canonical_workload_spec_sha256",
            "service",
            "secret",
            "job",
            "create_results",
            "create_results_sha256",
        }
        or frontier.get("schema") != LAUNCH_FRONTIER_SCHEMA
        or frontier.get("operation_id") != getattr(operation, "launch_operation_id", None)
        or frontier.get("deployment_id") != getattr(operation, "deployment_id", None)
        or frontier.get("phase") != getattr(operation, "launch_phase_at_request", None)
        or frontier.get("cluster_context") != getattr(operation, "cluster_context", None)
        or any(
            not isinstance(frontier.get(kind), dict)
            or set(frontier[kind]) != {"name", "uid"}
            or ((frontier[kind]["name"] is None) != (frontier[kind]["uid"] is None))
            for kind in ("service", "secret", "job")
        )
        or not isinstance(frontier.get("create_results"), dict)
        or frontier.get("create_results_sha256") != canonical_sha256(frontier.get("create_results"))
        or frontier.get("create_results_sha256")
        != getattr(operation, "launch_create_results_sha256", None)
        or canonical_sha256(frontier) != digest
    ):
        raise LineageConflict("durable launch frontier is invalid")
    return frontier


def _verified_pod_lifecycle_evidence(operation: Any) -> dict[str, Any] | None:
    evidence = getattr(operation, "pod_lifecycle_evidence", None)
    digest = getattr(operation, "pod_lifecycle_evidence_sha256", None)
    recorded_at = getattr(operation, "pod_lifecycle_evidence_recorded_at", None)
    if evidence is None and digest is None and recorded_at is None:
        return None
    frontier = _verified_launch_frontier(operation)
    if (
        frontier is None
        or not isinstance(evidence, dict)
        or not isinstance(digest, str)
        or recorded_at is None
        or set(evidence)
        != {
            "schema",
            "outcome",
            "operation_id",
            "deployment_id",
            "launch_frontier_sha256",
            "resource_discovery_sha256",
            "job_uid",
            "controllers_absent",
            "selector_absent",
        }
        or evidence.get("schema") != POD_LIFECYCLE_EVIDENCE_SCHEMA
        or evidence.get("outcome") not in {"never_started", "no_pod_observed"}
        or evidence.get("operation_id") != getattr(operation, "operation_id", None)
        or evidence.get("deployment_id") != getattr(operation, "deployment_id", None)
        or evidence.get("launch_frontier_sha256")
        != getattr(operation, "launch_frontier_sha256", None)
        or evidence.get("resource_discovery_sha256")
        != getattr(operation, "resource_discovery_sha256", None)
        or evidence.get("job_uid") != frontier["job"]["uid"]
        or evidence.get("controllers_absent") is not True
        or evidence.get("selector_absent") is not True
        or (evidence.get("outcome") == "never_started" and frontier["job"]["uid"] is not None)
        or (evidence.get("outcome") == "no_pod_observed" and frontier["job"]["uid"] is None)
        or canonical_sha256(evidence) != digest
    ):
        raise LineageConflict("durable no-Pod lifecycle evidence is invalid")
    return evidence


def _gpu_pod_lifecycle_closed(operation: Any, resources: Iterable[Any]) -> bool:
    if not getattr(operation, "gpu_hardware_uuids", None):
        return True
    pods = [resource for resource in resources if getattr(resource, "kind", None) == "Pod"]
    if pods:
        return all(_pod_absence_proven(resource) for resource in pods)
    return _verified_pod_lifecycle_evidence(operation) is not None


def _parent_allocation_release_document(operation: Any) -> dict[str, Any]:
    snapshot = dict(getattr(operation, "snapshot", None) or {})
    return {
        "schema": PARENT_ALLOCATION_RELEASE_SCHEMA,
        "operation_id": operation.operation_id,
        "server_id": operation.parent_id,
        "snapshot_allocation_group_id": snapshot.get("allocation_group_id"),
        "snapshot_allocation_group_generation": snapshot.get("allocation_group_generation"),
        "server_allocation_released": True,
        "gpu_allocation_generations_owned": [],
    }


def _gpu_decommission_request(
    *,
    operation_id: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "schema": GPU_DECOMMISSION_REQUEST_SCHEMA,
        "version": 1,
        "request_id": operation_id,
        "reason": reason,
    }


def _verified_gpu_decommission_request(operation: Any) -> dict[str, Any]:
    request = getattr(operation, "validator_server_decommission_request", None)
    digest = getattr(operation, "validator_server_decommission_request_sha256", None)
    expected = _gpu_decommission_request(
        operation_id=operation.operation_id,
        reason=operation.reason,
    )
    if (
        getattr(operation, "parent_type", None) != "server"
        or not isinstance(request, dict)
        or request != expected
        or not isinstance(digest, str)
        or canonical_sha256(request) != digest
    ):
        raise DeploymentFailure("durable GPU decommission request is invalid")
    return request


def _verified_gpu_decommission_ack(operation: Any) -> dict[str, Any]:
    request = _verified_gpu_decommission_request(operation)
    ack = getattr(operation, "validator_server_deletion_ack", None)
    if (
        not isinstance(ack, dict)
        or set(ack)
        != {
            "schema",
            "version",
            "server_id",
            "request_id",
            "decommissioned_at",
            "status",
        }
        or ack.get("schema") != GPU_DECOMMISSION_RESPONSE_SCHEMA
        or ack.get("version") != 1
        or ack.get("server_id") != operation.parent_id
        or ack.get("request_id") != request["request_id"]
        or ack.get("status") != "decommissioned"
        or not isinstance(ack.get("decommissioned_at"), str)
        or not ack["decommissioned_at"]
    ):
        raise DeploymentFailure("durable GPU decommission ACK is invalid")
    return ack


def _deployment_lineage_document(operation: Any) -> dict[str, Any]:
    resources = sorted(
        (
            {
                "api_version": resource.api_version,
                "kind": resource.kind,
                "namespace": resource.namespace,
                "name": resource.name,
                "uid": resource.uid,
                "owner_api_version": resource.owner_api_version,
                "owner_kind": resource.owner_kind,
                "owner_name": resource.owner_name,
                "owner_uid": resource.owner_uid,
                "node_name": resource.node_name,
                "labels_sha256": resource.labels_sha256,
                "state": resource.state,
                "absent_at": _timestamp_text(resource.absent_at),
                "replaced_by_resource_id": resource.replaced_by_resource_id,
                "pod_termination_evidence_sha256": (resource.pod_termination_evidence_sha256),
                "pod_uid_absence_evidence_sha256": (resource.pod_uid_absence_evidence_sha256),
                "pod_uid_absence_observed_at": _timestamp_text(
                    resource.pod_uid_absence_observed_at
                ),
                "pod_teardown_finalizer_attached_at": _timestamp_text(
                    resource.pod_teardown_finalizer_attached_at
                ),
                "pod_teardown_finalizer_removal_requested_at": _timestamp_text(
                    resource.pod_teardown_finalizer_removal_requested_at
                ),
                "pod_teardown_finalizer_removed_at": _timestamp_text(
                    resource.pod_teardown_finalizer_removed_at
                ),
            }
            for resource in list(getattr(operation, "resources", None) or [])
        ),
        key=lambda item: (
            item["api_version"],
            item["kind"],
            item["namespace"],
            item["name"],
            item["uid"],
        ),
    )
    handoffs = sorted(
        (
            {
                "sequence": handoff.sequence,
                "from_kubernetes_node_uid": handoff.from_kubernetes_node_uid,
                "from_kubernetes_node_generation": (handoff.from_kubernetes_node_generation),
                "from_registration_attestation_id": (handoff.from_registration_attestation_id),
                "from_gpu_allocation_group_id": handoff.from_gpu_allocation_group_id,
                "from_gpu_allocation_group_generation": (
                    handoff.from_gpu_allocation_group_generation
                ),
                "from_cluster_context_sha256": handoff.from_cluster_context_sha256,
                "to_kubernetes_node_uid": handoff.to_kubernetes_node_uid,
                "to_kubernetes_node_generation": handoff.to_kubernetes_node_generation,
                "to_registration_attestation_id": (handoff.to_registration_attestation_id),
                "to_gpu_allocation_group_id": handoff.to_gpu_allocation_group_id,
                "to_gpu_allocation_group_generation": (handoff.to_gpu_allocation_group_generation),
                "to_cluster_context_sha256": handoff.to_cluster_context_sha256,
            }
            for handoff in list(getattr(operation, "node_incarnation_handoffs", None) or [])
        ),
        key=lambda item: item["sequence"],
    )
    latest_handoff = (
        max(
            list(getattr(operation, "node_incarnation_handoffs", None) or []),
            key=lambda handoff: handoff.sequence,
        )
        if getattr(operation, "node_incarnation_handoffs", None)
        else None
    )
    effective_lineage = _operation_node_lineage(operation, latest_handoff)
    return {
        "schema": LINEAGE_INSPECTION_SCHEMA,
        "version": 1,
        "operation_kind": "deployment",
        "operation_id": operation.operation_id,
        "phase": operation.phase,
        "deployment_id": operation.deployment_id,
        "validator": operation.validator,
        "server_id": operation.server_id,
        "chute_id": operation.chute_id,
        "config_id": operation.config_id,
        "job_id": operation.job_id,
        "instance_id": operation.instance_id,
        "cluster_context": operation.cluster_context,
        "cluster_context_sha256": operation.cluster_context_sha256,
        "namespace": operation.namespace,
        "kubernetes_node_uid": operation.kubernetes_node_uid,
        "kubernetes_node_generation": operation.kubernetes_node_generation,
        "registration_attestation_id": operation.registration_attestation_id,
        "gpu_allocation_group_id": operation.gpu_allocation_group_id,
        "gpu_allocation_group_generation": operation.gpu_allocation_group_generation,
        "gpu_hardware_uuids": list(operation.gpu_hardware_uuids),
        "immutable_labels": dict(operation.immutable_labels),
        "effective_node_lineage": {
            "kubernetes_node_uid": effective_lineage.kubernetes_node_uid,
            "kubernetes_node_generation": effective_lineage.kubernetes_node_generation,
            "registration_attestation_id": (effective_lineage.registration_attestation_id),
            "gpu_allocation_group_id": effective_lineage.gpu_allocation_group_id,
            "gpu_allocation_group_generation": (effective_lineage.gpu_allocation_group_generation),
            "cluster_context_sha256": effective_lineage.cluster_context_sha256,
        },
        "node_incarnation_handoffs": handoffs,
        "resource_discovery_sha256": operation.resource_discovery_sha256,
        "pod_lifecycle_evidence_sha256": operation.pod_lifecycle_evidence_sha256,
        "pod_lifecycle_evidence_recorded_at": _timestamp_text(
            operation.pod_lifecycle_evidence_recorded_at
        ),
        "registry_revocation_ack": operation.registry_revocation_ack,
        "registry_revoked_at": _timestamp_text(operation.registry_revoked_at),
        "validator_job_release_ack": operation.validator_job_release_ack,
        "validator_job_released_at": _timestamp_text(operation.validator_job_released_at),
        "validator_instance_deletion_ack": operation.validator_instance_deletion_ack,
        "validator_instance_deleted_at": _timestamp_text(operation.validator_instance_deleted_at),
        "controllers_absent_at": _timestamp_text(operation.controllers_absent_at),
        "services_absent_at": _timestamp_text(operation.services_absent_at),
        "pods_absent_at": _timestamp_text(operation.pods_absent_at),
        "pull_secret_deletion_ack": operation.pull_secret_deletion_ack,
        "pull_secret_deleted_at": _timestamp_text(operation.pull_secret_deleted_at),
        "resources": resources,
    }


def _orphan_lineage_document(tombstone: Any) -> dict[str, Any]:
    resources = sorted(
        (
            {
                "api_version": resource.api_version,
                "kind": resource.kind,
                "name": resource.name,
                "uid": resource.uid,
                "owner_api_version": resource.owner_api_version,
                "owner_kind": resource.owner_kind,
                "owner_name": resource.owner_name,
                "owner_uid": resource.owner_uid,
                "node_name": resource.node_name,
                "labels_sha256": resource.labels_sha256,
                "state": resource.state,
                "absent_at": _timestamp_text(resource.absent_at),
                "pod_termination_evidence_sha256": (resource.pod_termination_evidence_sha256),
                "pod_teardown_finalizer_attached_at": _timestamp_text(
                    resource.pod_teardown_finalizer_attached_at
                ),
                "pod_teardown_finalizer_removal_requested_at": _timestamp_text(
                    resource.pod_teardown_finalizer_removal_requested_at
                ),
                "pod_teardown_finalizer_removed_at": _timestamp_text(
                    resource.pod_teardown_finalizer_removed_at
                ),
            }
            for resource in list(getattr(tombstone, "resources", None) or [])
        ),
        key=lambda item: (
            item["api_version"],
            item["kind"],
            item["name"],
            item["uid"],
        ),
    )
    return {
        "schema": LINEAGE_INSPECTION_SCHEMA,
        "version": 1,
        "operation_kind": "orphan",
        "operation_id": tombstone.tombstone_id,
        "phase": tombstone.phase,
        "deployment_id": tombstone.deployment_id,
        "cluster_context": tombstone.cluster_context,
        "cluster_context_sha256": tombstone.cluster_context_sha256,
        "namespace": tombstone.namespace,
        "kubernetes_node_uid": tombstone.kubernetes_node_uid,
        "kubernetes_node_generation": tombstone.kubernetes_node_generation,
        "immutable_labels": dict(tombstone.immutable_labels),
        "resources": resources,
    }


def _live_resource_document(resource: ResourceIdentity) -> dict[str, Any]:
    return {
        "api_version": resource.api_version,
        "kind": resource.kind,
        "namespace": resource.namespace,
        "name": resource.name,
        "uid": resource.uid,
        "owner_api_version": resource.owner_api_version,
        "owner_kind": resource.owner_kind,
        "owner_name": resource.owner_name,
        "owner_uid": resource.owner_uid,
        "node_name": resource.node_name,
        "labels_sha256": resource.labels_sha256,
    }


def _server_authority_document(server: Server | None) -> dict[str, Any] | None:
    if server is None:
        return None
    return {
        "server_id": server.server_id,
        "validator": server.validator,
        "cluster_context": server.name,
        "cluster_context_sha256": cluster_context_sha256(server),
        "kubernetes_node_uid": server.kubernetes_node_uid,
        "kubernetes_node_generation": server.kubernetes_node_generation,
        "registration_attestation_id": server.registration_attestation_id,
        "gpu_allocation_group_id": server.gpu_allocation_group_id,
        "gpu_allocation_group_generation": server.gpu_allocation_group_generation,
    }


def _deployment_authority_document(
    deployment: Deployment | None,
) -> dict[str, Any] | None:
    if deployment is None:
        return None
    return {
        "deployment_id": deployment.deployment_id,
        "validator": deployment.validator,
        "server_id": deployment.server_id,
        "chute_id": deployment.chute_id,
        "config_id": deployment.config_id,
        "job_id": deployment.job_id,
        "instance_id": deployment.instance_id,
        "teardown_operation_id": deployment.teardown_operation_id,
        "launch_operation_id": deployment.launch_operation_id,
    }


def _gpu_authority_document(gpu: GPU) -> dict[str, Any]:
    return {
        "gpu_id": gpu.gpu_id,
        "hardware_uuid": gpu.hardware_uuid,
        "validator": gpu.validator,
        "server_id": gpu.server_id,
        "deployment_id": gpu.deployment_id,
        "gpu_allocation_group_id": gpu.gpu_allocation_group_id,
        "gpu_allocation_group_generation": gpu.gpu_allocation_group_generation,
    }


def _registry_authority_document(
    intent: RegistryScopeIntent | None,
) -> dict[str, Any] | None:
    if intent is None:
        return None
    return {
        "launch_config_id": intent.launch_config_id,
        "launch_intent_id": intent.launch_intent_id,
        "deployment_id": intent.deployment_id,
        "validator": intent.validator,
        "server_id": intent.server_id,
        "repository": intent.repository,
        "manifest_digest": intent.manifest_digest,
        "desired_state": intent.desired_state,
        "phase": intent.phase,
        "registration_ack": intent.registration_ack,
        "registered_at": _timestamp_text(intent.registered_at),
        "revocation_ack": intent.revocation_ack,
        "revoked_at": _timestamp_text(intent.revoked_at),
    }


def _assert_parent_allocation_released(
    operation: Any,
    server: Any,
    gpu_rows: Iterable[Any],
) -> None:
    if getattr(operation, "parent_type", None) != "server":
        return
    if server is None:
        raise DeploymentFailure("server disappeared before allocation release audit")
    owned = sorted(
        {
            (
                str(gpu.gpu_allocation_group_id),
                str(gpu.gpu_allocation_group_generation),
            )
            for gpu in gpu_rows
            if gpu.gpu_allocation_group_id is not None
            or gpu.gpu_allocation_group_generation is not None
        }
    )
    if (
        server.gpu_allocation_group_id is not None
        or server.gpu_allocation_group_generation is not None
        or owned
    ):
        raise DeploymentFailure("server parent deletion is held by allocation-group ownership")
    evidence = getattr(operation, "allocation_release_evidence", None)
    digest = getattr(operation, "allocation_release_evidence_sha256", None)
    verified_at = getattr(operation, "allocation_release_verified_at", None)
    expected = _parent_allocation_release_document(operation)
    if (
        evidence is None
        or digest is None
        or verified_at is None
        or evidence != expected
        or canonical_sha256(evidence) != digest
    ):
        raise DeploymentFailure("server allocation release evidence is invalid")


def _resource_discovery_document(
    operation: DeploymentTeardownOperation,
    resources: Iterable[DeploymentTeardownK8sResource],
) -> dict[str, Any]:
    identities = [
        {
            "api_version": resource.api_version,
            "kind": resource.kind,
            "name": resource.name,
            "namespace": resource.namespace,
            "uid": resource.uid,
            "owner_api_version": resource.owner_api_version,
            "owner_kind": resource.owner_kind,
            "owner_name": resource.owner_name,
            "owner_uid": resource.owner_uid,
            "node_name": resource.node_name,
            "labels_sha256": resource.labels_sha256,
        }
        for resource in resources
    ]
    identities.sort(
        key=lambda item: (
            item["api_version"],
            item["kind"],
            item["namespace"],
            item["name"],
            item["uid"],
        )
    )
    return {
        "schema": RESOURCE_DISCOVERY_SCHEMA,
        "operation_id": operation.operation_id,
        "deployment_id": operation.deployment_id,
        "cluster_context": operation.cluster_context,
        "cluster_context_sha256": operation.cluster_context_sha256,
        "namespace": operation.namespace,
        "config_id": operation.config_id,
        "immutable_labels_sha256": canonical_sha256(operation.immutable_labels),
        "launch_operation_id": getattr(operation, "launch_operation_id", None),
        "launch_phase_at_request": getattr(operation, "launch_phase_at_request", None),
        "launch_kubernetes_mutation_possible": (
            getattr(operation, "launch_kubernetes_mutation_possible", None)
        ),
        "launch_create_results_sha256": getattr(operation, "launch_create_results_sha256", None),
        "resources": identities,
    }


@dataclass(frozen=True, slots=True)
class NodeIncarnationLineage:
    kubernetes_node_uid: str | None
    kubernetes_node_generation: int
    registration_attestation_id: str | None
    gpu_allocation_group_id: str | None
    gpu_allocation_group_generation: int | None
    cluster_context_sha256: str


def _operation_node_lineage(
    operation: DeploymentTeardownOperation,
    handoff: DeploymentTeardownNodeIncarnationHandoff | None,
) -> NodeIncarnationLineage:
    if handoff is not None:
        return NodeIncarnationLineage(
            kubernetes_node_uid=handoff.to_kubernetes_node_uid,
            kubernetes_node_generation=handoff.to_kubernetes_node_generation,
            registration_attestation_id=handoff.to_registration_attestation_id,
            gpu_allocation_group_id=handoff.to_gpu_allocation_group_id,
            gpu_allocation_group_generation=handoff.to_gpu_allocation_group_generation,
            cluster_context_sha256=handoff.to_cluster_context_sha256,
        )
    return NodeIncarnationLineage(
        kubernetes_node_uid=operation.kubernetes_node_uid,
        kubernetes_node_generation=operation.kubernetes_node_generation,
        registration_attestation_id=operation.registration_attestation_id,
        gpu_allocation_group_id=operation.gpu_allocation_group_id,
        gpu_allocation_group_generation=operation.gpu_allocation_group_generation,
        cluster_context_sha256=operation.cluster_context_sha256,
    )


def _server_node_lineage(server: Server) -> NodeIncarnationLineage:
    return NodeIncarnationLineage(
        kubernetes_node_uid=server.kubernetes_node_uid,
        kubernetes_node_generation=server.kubernetes_node_generation,
        registration_attestation_id=server.registration_attestation_id,
        gpu_allocation_group_id=server.gpu_allocation_group_id,
        gpu_allocation_group_generation=server.gpu_allocation_group_generation,
        cluster_context_sha256=cluster_context_sha256(server),
    )


def authorized_node_incarnation_handoff_values(
    *,
    operation: DeploymentTeardownOperation,
    latest_handoff: DeploymentTeardownNodeIncarnationHandoff | None,
    deployment: Deployment | None,
    server: Server | None,
    gpu_rows: Iterable[GPU],
    node_history: Iterable[ServerNodeIdentity],
) -> dict[str, Any] | None:
    """Validate one registrar-backed transition without mutating original lineage."""
    if server is None:
        raise DeploymentFailure("teardown logical server no longer exists")
    expected = _operation_node_lineage(operation, latest_handoff)
    current = _server_node_lineage(server)
    if current == expected:
        return None

    if deployment is None:
        raise DeploymentFailure("unfinished teardown deployment no longer exists")
    expected_deployment = (
        operation.validator,
        operation.server_id,
        operation.chute_id,
        operation.config_id,
        operation.job_id,
        operation.instance_id,
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
        raise DeploymentFailure("Deployment lineage changed during node rotation")
    if server.server_id != operation.server_id or server.validator != operation.validator:
        raise DeploymentFailure("logical server ownership changed during node rotation")
    if server.name != operation.cluster_context:
        raise DeploymentFailure("Kubernetes context changed during node rotation")

    required_expected = (
        expected.kubernetes_node_uid,
        expected.registration_attestation_id,
        expected.gpu_allocation_group_id,
        expected.gpu_allocation_group_generation,
    )
    required_current = (
        current.kubernetes_node_uid,
        current.registration_attestation_id,
        current.gpu_allocation_group_id,
        current.gpu_allocation_group_generation,
    )
    if (
        not all(required_expected)
        or not all(required_current)
        or expected.kubernetes_node_generation <= 0
        or current.kubernetes_node_generation <= expected.kubernetes_node_generation
        or current.registration_attestation_id == expected.registration_attestation_id
    ):
        raise DeploymentFailure("node rotation lacks complete monotonic attested lineage")

    rows = sorted(node_history, key=lambda row: row.generation)
    expected_generations = list(
        range(expected.kubernetes_node_generation, current.kubernetes_node_generation + 1)
    )
    if [row.generation for row in rows] != expected_generations:
        raise DeploymentFailure("node rotation history is incomplete")
    previous_attestation = None
    for index, row in enumerate(rows):
        if row.server_id != operation.server_id or not row.registration_attestation_id:
            raise DeploymentFailure("node rotation history has conflicting ownership")
        if index == 0 and (
            row.kubernetes_node_uid != expected.kubernetes_node_uid
            or row.registration_attestation_id != expected.registration_attestation_id
        ):
            raise DeploymentFailure("node rotation predecessor does not match teardown lineage")
        if previous_attestation == row.registration_attestation_id:
            raise DeploymentFailure("node rotation reused a registrar attestation")
        if index < len(rows) - 1 and row.retired_at is None:
            raise DeploymentFailure("node rotation predecessor is not retired")
        if index == len(rows) - 1 and (
            row.retired_at is not None
            or row.kubernetes_node_uid != current.kubernetes_node_uid
            or row.registration_attestation_id != current.registration_attestation_id
        ):
            raise DeploymentFailure("active node identity does not match logical server")
        previous_attestation = row.registration_attestation_id

    gpus = list(gpu_rows)
    actual_gpu_uuids = sorted(str(gpu.hardware_uuid or gpu.gpu_id) for gpu in gpus)
    if not actual_gpu_uuids or actual_gpu_uuids != list(operation.gpu_hardware_uuids):
        raise DeploymentFailure("assigned GPU UUID closure changed during node rotation")
    if any(
        gpu.server_id != operation.server_id
        or gpu.deployment_id != operation.deployment_id
        or gpu.validator != operation.validator
        or gpu.gpu_allocation_group_id != current.gpu_allocation_group_id
        or gpu.gpu_allocation_group_generation != current.gpu_allocation_group_generation
        for gpu in gpus
    ):
        raise DeploymentFailure("assigned GPU lineage changed during node rotation")

    return {
        "handoff_id": str(uuid.uuid4()),
        "operation_id": operation.operation_id,
        "sequence": (latest_handoff.sequence + 1) if latest_handoff else 1,
        "from_kubernetes_node_uid": expected.kubernetes_node_uid,
        "from_kubernetes_node_generation": expected.kubernetes_node_generation,
        "from_registration_attestation_id": expected.registration_attestation_id,
        "from_gpu_allocation_group_id": expected.gpu_allocation_group_id,
        "from_gpu_allocation_group_generation": expected.gpu_allocation_group_generation,
        "from_cluster_context_sha256": expected.cluster_context_sha256,
        "to_kubernetes_node_uid": current.kubernetes_node_uid,
        "to_kubernetes_node_generation": current.kubernetes_node_generation,
        "to_registration_attestation_id": current.registration_attestation_id,
        "to_gpu_allocation_group_id": current.gpu_allocation_group_id,
        "to_gpu_allocation_group_generation": current.gpu_allocation_group_generation,
        "to_cluster_context_sha256": current.cluster_context_sha256,
    }


def _owner(
    metadata: Any,
) -> tuple[str | None, str | None, str | None, str | None]:
    references = list(getattr(metadata, "owner_references", None) or [])
    if not references:
        return None, None, None, None
    controller = next((ref for ref in references if getattr(ref, "controller", False)), None)
    reference = controller or references[0]
    return (
        str(reference.api_version),
        str(reference.kind),
        str(reference.name),
        str(reference.uid),
    )


def _identity(kind: str, resource: Any) -> ResourceIdentity:
    metadata = resource.metadata
    owner_api_version, owner_kind, owner_name, owner_uid = _owner(metadata)
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
        owner_api_version=owner_api_version,
        owner_kind=owner_kind,
        owner_name=owner_name,
        owner_uid=owner_uid,
        node_name=str(node_name) if node_name else None,
        pod_termination_evidence=(_pod_termination_evidence(resource) if kind == "Pod" else None),
        pod_already_terminating=bool(
            kind == "Pod" and getattr(metadata, "deletion_timestamp", None) is not None
        ),
    )


def replacement_matches(
    *,
    expected_labels: dict[str, str],
    expected_node_name: str,
    accepted_owners: dict[str, tuple[str, str, str]],
    resource: ResourceIdentity,
) -> bool:
    """Validate the full typed owner chain for a same-lineage resource."""
    if resource.kind == "Secret":
        config_id = expected_labels.get("chutes/config-id")
        if not config_id or resource.labels.get("chutes/launch-config-id") != config_id:
            raise LineageConflict("Secret launch configuration lineage conflicts")
        if any(
            value is not None
            for value in (
                resource.owner_api_version,
                resource.owner_kind,
                resource.owner_name,
                resource.owner_uid,
            )
        ):
            raise LineageConflict("Secret unexpectedly has an owner")
        return True
    for key in expected_labels:
        if resource.labels.get(key) != expected_labels.get(key):
            raise LineageConflict(f"{resource.kind} immutable labels conflict")
    if resource.kind in {"Job", "Deployment", "Pod"}:
        if resource.node_name != expected_node_name:
            raise LineageConflict(f"{resource.kind} stable node lineage conflicts")
    expected_owner_kinds = EXPECTED_OWNER_KINDS.get(resource.kind)
    if expected_owner_kinds is None:
        if any(
            value is not None
            for value in (
                resource.owner_api_version,
                resource.owner_kind,
                resource.owner_name,
                resource.owner_uid,
            )
        ):
            raise LineageConflict(f"{resource.kind} unexpectedly has an owner")
        return True
    owner_type = (resource.owner_api_version, resource.owner_kind)
    if owner_type not in expected_owner_kinds:
        raise LineageConflict(f"{resource.kind} owner type conflicts")
    if not resource.owner_uid:
        raise LineageConflict(f"{resource.kind} owner UID is missing")
    accepted = accepted_owners.get(resource.owner_uid)
    if accepted is None:
        raise UnresolvedOwnerLineage(f"{resource.kind} owner {resource.owner_uid} was not observed")
    if accepted != (
        resource.owner_api_version,
        resource.owner_kind,
        resource.owner_name,
    ):
        raise LineageConflict(f"{resource.kind} owner identity conflicts")
    return True


def _accept_owner(accepted: dict[str, tuple[str, str, str]], resource: ResourceIdentity) -> None:
    accepted[resource.uid] = (resource.api_version, resource.kind, resource.name)


def _resource_delete_ready(resource: Any, resources: Iterable[Any]) -> bool:
    """Delete children only after their captured controller deletion is durable."""
    by_uid = {item.uid: item for item in resources}
    if resource.owner_uid:
        owner = by_uid.get(resource.owner_uid)
        if owner is not None and owner.state not in {
            "delete_requested",
            "absent",
            "replaced",
        }:
            return False
    if resource.kind == "Secret":
        return all(
            item.state in {"absent", "replaced"}
            for item in resources
            if item.kind in {"Job", "Deployment", "ReplicaSet", "Pod"}
        )
    return True


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

    def ensure_pod_teardown_finalizer(
        self,
        *,
        cluster_context: str,
        namespace: str,
        name: str,
        uid: str,
        node_name: str,
    ) -> str:
        """Attach our exact-UID deletion fence before any controller is deleted."""
        _, _, core = self._clients(cluster_context)
        try:
            pod = core.read_namespaced_pod(
                name=name,
                namespace=namespace,
                _request_timeout=30,
            )
        except ApiException as exc:
            if exc.status == 404:
                return "absent"
            raise
        metadata = pod.metadata
        if str(metadata.uid) != uid:
            return "uid_changed"
        if str(getattr(pod.spec, "node_name", "") or "") != node_name:
            raise LineageConflict("Pod node changed before teardown fencing")
        finalizers = [str(value) for value in (metadata.finalizers or [])]
        if POD_TEARDOWN_FINALIZER in finalizers:
            return "present"
        resource_version = str(getattr(metadata, "resource_version", "") or "")
        if not resource_version:
            raise DeploymentFailure("Pod resourceVersion is missing before finalizer attach")
        try:
            patched = core.patch_namespaced_pod(
                name=name,
                namespace=namespace,
                body={
                    "metadata": {
                        "uid": uid,
                        "resourceVersion": resource_version,
                        "finalizers": [*finalizers, POD_TEARDOWN_FINALIZER],
                    }
                },
                _content_type="application/merge-patch+json",
                _request_timeout=30,
            )
        except ApiException as exc:
            if exc.status == 404:
                return "absent"
            if exc.status in {409, 422}:
                return "retryable"
            raise
        if str(patched.metadata.uid) != uid or POD_TEARDOWN_FINALIZER not in {
            str(value) for value in (patched.metadata.finalizers or [])
        }:
            raise DeploymentFailure("Pod teardown finalizer attach was not acknowledged")
        return "attached"

    def remove_pod_teardown_finalizer(
        self,
        *,
        cluster_context: str,
        namespace: str,
        name: str,
        uid: str,
        node_name: str,
    ) -> str:
        """Remove only our finalizer after exact terminal evidence is durable."""
        _, _, core = self._clients(cluster_context)
        try:
            pod = core.read_namespaced_pod(
                name=name,
                namespace=namespace,
                _request_timeout=30,
            )
        except ApiException as exc:
            if exc.status == 404:
                return "absent"
            raise
        metadata = pod.metadata
        if str(metadata.uid) != uid:
            return "uid_changed"
        if str(getattr(pod.spec, "node_name", "") or "") != node_name:
            raise LineageConflict("Pod node changed before teardown finalizer removal")
        finalizers = [str(value) for value in (metadata.finalizers or [])]
        if POD_TEARDOWN_FINALIZER not in finalizers:
            return "removed"
        resource_version = str(getattr(metadata, "resource_version", "") or "")
        if not resource_version:
            raise DeploymentFailure("Pod resourceVersion is missing before finalizer removal")
        try:
            patched = core.patch_namespaced_pod(
                name=name,
                namespace=namespace,
                body={
                    "metadata": {
                        "uid": uid,
                        "resourceVersion": resource_version,
                        "finalizers": [
                            value for value in finalizers if value != POD_TEARDOWN_FINALIZER
                        ],
                    }
                },
                _content_type="application/merge-patch+json",
                _request_timeout=30,
            )
        except ApiException as exc:
            if exc.status == 404:
                return "absent"
            if exc.status in {409, 422}:
                return "retryable"
            raise
        if str(patched.metadata.uid) != uid:
            return "uid_changed"
        if POD_TEARDOWN_FINALIZER in {str(value) for value in (patched.metadata.finalizers or [])}:
            raise DeploymentFailure("Pod teardown finalizer removal was not acknowledged")
        return "removed"

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
                _teardown_grace_period_seconds() if kind in CONTROLLER_KINDS or kind == "Pod" else 0
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
        self._base_worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4()}"
        self._claim_owner: ContextVar[str | None] = ContextVar(
            f"teardown-claim-{id(self)}", default=None
        )
        self._run_locks: dict[tuple[str, str], asyncio.Lock] = {}

    @property
    def _lease_owner(self) -> str:
        owner = self._claim_owner.get()
        if owner is None:
            raise DeploymentFailure("durable operation has no per-run claim token")
        return owner

    @property
    def worker_id(self) -> str:
        """Base worker identity outside a run, exact claim token inside one."""
        return self._claim_owner.get() or self._base_worker_id

    def _run_lock(self, kind: str, identity: str) -> asyncio.Lock:
        return self._run_locks.setdefault((kind, identity), asyncio.Lock())

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
        if settings.gpu_tee_only and deployment.config_id:
            await request_registry_scope_revocation_in_session(
                session,
                launch_config_id=deployment.config_id,
                validator=deployment.validator,
                server_id=deployment.server_id,
                deployment_id=deployment.deployment_id,
            )
        launch = None
        launch_intent = None
        launch_phase_at_request = None
        launch_kubernetes_mutation_possible = None
        launch_create_results_sha256 = None
        launch_frontier = None
        launch_frontier_sha256 = None
        if deployment.launch_operation_id:
            launch = await session.get(
                DeploymentLaunchOperation,
                deployment.launch_operation_id,
                with_for_update=True,
            )
            if launch is None or launch.deployment_id != deployment.deployment_id:
                raise DeploymentFailure("deployment launch journal binding is invalid")
            if launch.launch_intent_id and not all(
                (
                    launch.cluster_context,
                    launch.cluster_context_sha256,
                    launch.namespace,
                    launch.server_name,
                )
            ):
                raise DeploymentFailure(
                    "durable miner launch lacks its original Kubernetes context closure"
                )
            launch_phase_at_request = launch.phase
            launch_kubernetes_mutation_possible = launch.phase != "reserved"
            launch_create_results_sha256 = canonical_sha256(launch.create_results or {})
            launch_frontier = _launch_frontier_document(launch)
            launch_frontier_sha256 = canonical_sha256(launch_frontier)
            was_creating = launch.phase == "creating"
            launch.phase = "teardown_fenced"
            if not was_creating:
                launch.lease_owner = None
                launch.lease_expires_at = None
            if launch.launch_intent_id:
                launch_intent = await session.get(
                    MinerLaunchIntent,
                    launch.launch_intent_id,
                    with_for_update=True,
                )
                if launch_intent is not None:
                    validated_miner_launch_lineage(
                        launch_intent,
                        miner_hotkey=settings.miner_ss58,
                        validator=deployment.validator,
                        chute_id=deployment.chute_id,
                        chute_version=deployment.version,
                        server_id=deployment.server_id,
                        job_id=deployment.job_id,
                        require_gpu_lineage=settings.gpu_tee_only,
                    )
                if (
                    launch_intent is None
                    or launch_intent.deployment_id != deployment.deployment_id
                    or launch_intent.job_cleanup_only
                ):
                    raise DeploymentFailure("deployment launch intent binding is invalid")
                if launch_intent.phase != "completed":
                    launch_intent.phase = "cleanup_required"
        existing = (
            (
                await session.execute(
                    select(DeploymentTeardownOperation)
                    .where(
                        DeploymentTeardownOperation.deployment_id == deployment.deployment_id,
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
            await self._seed_launch_resources(session, existing, launch)
            return existing

        server = (
            (
                await session.execute(
                    select(Server)
                    .where(Server.server_id == deployment.server_id)
                    .with_for_update(of=Server)
                )
            )
            .unique()
            .scalar_one()
        )
        snapshot_lineage = _server_node_lineage(server)
        if settings.gpu_tee_only and launch is not None and launch_intent is not None:
            lineage = validated_miner_launch_lineage(
                launch_intent,
                miner_hotkey=settings.miner_ss58,
                validator=deployment.validator,
                chute_id=deployment.chute_id,
                chute_version=deployment.version,
                server_id=deployment.server_id,
                job_id=deployment.job_id,
                require_gpu_lineage=True,
            )
            predecessor = (
                await session.execute(
                    select(ServerNodeIdentity)
                    .where(
                        ServerNodeIdentity.server_id == deployment.server_id,
                        ServerNodeIdentity.generation == lineage["kubernetes_node_generation"],
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if (
                predecessor is None
                or predecessor.kubernetes_node_uid != lineage["kubernetes_node_uid"]
                or not predecessor.registration_attestation_id
                or server.kubernetes_node_generation < lineage["kubernetes_node_generation"]
                or (
                    server.kubernetes_node_generation == lineage["kubernetes_node_generation"]
                    and predecessor.retired_at is not None
                )
                or (
                    server.kubernetes_node_generation > lineage["kubernetes_node_generation"]
                    and predecessor.retired_at is None
                )
            ):
                raise DeploymentFailure("original registrar lineage is unavailable")
            snapshot_lineage = NodeIncarnationLineage(
                kubernetes_node_uid=lineage["kubernetes_node_uid"],
                kubernetes_node_generation=lineage["kubernetes_node_generation"],
                registration_attestation_id=predecessor.registration_attestation_id,
                gpu_allocation_group_id=lineage["gpu_allocation_group_id"],
                gpu_allocation_group_generation=lineage["gpu_allocation_group_generation"],
                cluster_context_sha256=launch.cluster_context_sha256,
            )
        gpu_rows = (
            (
                await session.execute(
                    select(GPU)
                    .where(GPU.deployment_id == deployment.deployment_id)
                    .order_by(GPU.gpu_id)
                    .with_for_update(of=GPU)
                )
            )
            .unique()
            .scalars()
            .all()
        )
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
            cluster_context=(launch.cluster_context if launch else None) or server.name,
            cluster_context_sha256=snapshot_lineage.cluster_context_sha256,
            namespace=(launch.namespace if launch else None) or settings.namespace,
            kubernetes_node_uid=snapshot_lineage.kubernetes_node_uid,
            kubernetes_node_generation=snapshot_lineage.kubernetes_node_generation,
            registration_attestation_id=snapshot_lineage.registration_attestation_id,
            gpu_allocation_group_id=snapshot_lineage.gpu_allocation_group_id,
            gpu_allocation_group_generation=snapshot_lineage.gpu_allocation_group_generation,
            gpu_hardware_uuids=sorted(str(gpu.hardware_uuid or gpu.gpu_id) for gpu in gpu_rows),
            immutable_labels=self._operation_labels(deployment),
            launch_operation_id=launch.operation_id if launch else None,
            launch_phase_at_request=launch_phase_at_request,
            launch_kubernetes_mutation_possible=launch_kubernetes_mutation_possible,
            launch_create_results_sha256=launch_create_results_sha256,
            launch_frontier=launch_frontier,
            launch_frontier_sha256=launch_frontier_sha256,
        )
        session.add(operation)
        await session.flush()
        await self._seed_launch_resources(session, operation, launch)
        deployment.teardown_operation_id = operation.operation_id
        deployment.active = False
        return operation

    async def _seed_launch_resources(
        self,
        session: Any,
        operation: DeploymentTeardownOperation,
        launch: DeploymentLaunchOperation | None,
    ) -> None:
        """Bind exact primary-object UIDs to teardown before ownership can clear."""
        if launch is None:
            return
        results = dict(launch.create_results or {})
        for kind, api_version in (
            ("Service", "v1"),
            ("Secret", "v1"),
            ("Job", "batch/v1"),
        ):
            prefix = kind.lower()
            name = getattr(launch, f"{prefix}_name")
            uid = getattr(launch, f"{prefix}_uid")
            if not name or not uid:
                continue
            known = await session.scalar(
                select(DeploymentTeardownK8sResource.resource_id).where(
                    DeploymentTeardownK8sResource.operation_id == operation.operation_id,
                    DeploymentTeardownK8sResource.kind == kind,
                    DeploymentTeardownK8sResource.uid == uid,
                )
            )
            if known is not None:
                continue
            result = results.get(prefix) if isinstance(results.get(prefix), dict) else {}
            labels = result.get("labels") if isinstance(result.get("labels"), dict) else {}
            session.add(
                DeploymentTeardownK8sResource(
                    resource_id=str(uuid.uuid4()),
                    operation_id=operation.operation_id,
                    cluster_context=operation.cluster_context,
                    namespace=operation.namespace,
                    api_version=api_version,
                    kind=kind,
                    name=name,
                    uid=uid,
                    owner_kind=None,
                    owner_name=None,
                    owner_uid=None,
                    node_name=operation.cluster_context if kind == "Job" else None,
                    labels=labels,
                    labels_sha256=canonical_sha256(labels),
                )
            )

    async def request(self, deployment_id: str, reason: str) -> str | None:
        async with get_session() as session:
            deployment = (
                (
                    await session.execute(
                        select(Deployment)
                        .where(Deployment.deployment_id == deployment_id)
                        .options(selectinload(Deployment.server))
                        .with_for_update(of=Deployment)
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
            next_retry_at = getattr(operation, "next_retry_at", None)
            if next_retry_at is not None and next_retry_at > now:
                return False
            if (
                operation.retry_lease_expires_at is not None
                and operation.retry_lease_expires_at > now
                and operation.retry_lease_owner != self.worker_id
            ):
                return False
            operation.retry_lease_owner = self.worker_id
            operation.retry_lease_expires_at = now + timedelta(seconds=LEASE_SECONDS)
            operation.next_retry_at = None
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

    async def _authorize_current_node_incarnation(self, operation_id: str) -> None:
        """Persist an attested same-server handoff before resumed external work."""
        async with get_session() as session:
            deployment = (
                (
                    await session.execute(
                        select(Deployment)
                        .where(Deployment.teardown_operation_id == operation_id)
                        .with_for_update(of=Deployment)
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            operation = (
                await session.execute(
                    select(DeploymentTeardownOperation)
                    .where(DeploymentTeardownOperation.operation_id == operation_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if operation is None or operation.phase == "completed":
                return
            if (
                operation.retry_lease_owner != self.worker_id
                or operation.lineage_conflict_at is not None
            ):
                raise DeploymentFailure("teardown lease or lineage changed before node check")
            latest_handoff = (
                await session.execute(
                    select(DeploymentTeardownNodeIncarnationHandoff)
                    .where(DeploymentTeardownNodeIncarnationHandoff.operation_id == operation_id)
                    .order_by(DeploymentTeardownNodeIncarnationHandoff.sequence.desc())
                    .limit(1)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            server = (
                (
                    await session.execute(
                        select(Server)
                        .where(Server.server_id == operation.server_id)
                        .with_for_update(of=Server)
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            if server is not None and _server_node_lineage(server) == _operation_node_lineage(
                operation, latest_handoff
            ):
                return

            gpu_rows = (
                (
                    await session.execute(
                        select(GPU)
                        .where(GPU.deployment_id == operation.deployment_id)
                        .order_by(GPU.gpu_id)
                        .with_for_update(of=GPU)
                    )
                )
                .unique()
                .scalars()
                .all()
            )
            node_history = []
            if server is not None:
                expected = _operation_node_lineage(operation, latest_handoff)
                node_history = (
                    (
                        await session.execute(
                            select(ServerNodeIdentity)
                            .where(
                                ServerNodeIdentity.server_id == operation.server_id,
                                ServerNodeIdentity.generation
                                >= expected.kubernetes_node_generation,
                                ServerNodeIdentity.generation <= server.kubernetes_node_generation,
                            )
                            .order_by(ServerNodeIdentity.generation)
                            .with_for_update()
                        )
                    )
                    .unique()
                    .scalars()
                    .all()
                )
            try:
                values = authorized_node_incarnation_handoff_values(
                    operation=operation,
                    latest_handoff=latest_handoff,
                    deployment=deployment,
                    server=server,
                    gpu_rows=gpu_rows,
                    node_history=node_history,
                )
            except DeploymentFailure as exc:
                operation.lineage_conflict_at = utc_now()
                operation.last_failure = str(exc)
                operation.retry_lease_owner = None
                operation.retry_lease_expires_at = None
                await session.commit()
                raise
            if values is not None:
                session.add(DeploymentTeardownNodeIncarnationHandoff(**values))
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
            if operation.retry_lease_owner != self.worker_id or operation.phase != "discovering":
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
                if resource.namespace != operation.namespace:
                    raise LineageConflict("Kubernetes resource namespace changed during discovery")
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
                        owner_api_version=resource.owner_api_version,
                        owner_kind=resource.owner_kind,
                        owner_name=resource.owner_name,
                        owner_uid=resource.owner_uid,
                        node_name=resource.node_name,
                        labels=resource.labels,
                        labels_sha256=resource.labels_sha256,
                        pod_already_terminating=resource.pod_already_terminating,
                    )
                )
            await session.flush()
            captured = list(
                (
                    await session.execute(
                        select(DeploymentTeardownK8sResource).where(
                            DeploymentTeardownK8sResource.operation_id == operation_id
                        )
                    )
                ).scalars()
            )
            discovery = _resource_discovery_document(operation, captured)
            discovery_sha256 = canonical_sha256(discovery)
            if operation.resource_discovery is None:
                operation.resource_discovery = discovery
                operation.resource_discovery_sha256 = discovery_sha256
                operation.resource_discovered_at = utc_now()
            elif (
                not isinstance(operation.resource_discovery, dict)
                or operation.resource_discovery_sha256
                != canonical_sha256(operation.resource_discovery)
                or operation.resource_discovered_at is None
            ):
                raise LineageConflict("durable resource discovery witness changed")
            operation.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
            await session.commit()

    async def _ensure_operation_pod_finalizers(
        self,
        operation_id: str,
        phase: str,
    ) -> None:
        """Attach every Pod fence before controller deletion can begin."""
        async with get_session() as session:
            resources = list(
                (
                    await session.execute(
                        select(DeploymentTeardownK8sResource).where(
                            DeploymentTeardownK8sResource.operation_id == operation_id,
                            DeploymentTeardownK8sResource.kind == "Pod",
                            DeploymentTeardownK8sResource.state.notin_(("absent", "replaced")),
                            DeploymentTeardownK8sResource.pod_teardown_finalizer_attached_at.is_(
                                None
                            ),
                        )
                    )
                ).scalars()
            )
        for resource in resources:
            outcome = await asyncio.to_thread(
                self.kubernetes.ensure_pod_teardown_finalizer,
                cluster_context=resource.cluster_context,
                namespace=resource.namespace,
                name=resource.name,
                uid=resource.uid,
                node_name=resource.node_name,
            )
            async with get_session() as session:
                operation = await session.get(
                    DeploymentTeardownOperation,
                    operation_id,
                    with_for_update=True,
                )
                current = await session.get(
                    DeploymentTeardownK8sResource,
                    resource.resource_id,
                    with_for_update=True,
                )
                if (
                    operation is None
                    or operation.retry_lease_owner != self.worker_id
                    or operation.phase != phase
                    or current is None
                    or current.operation_id != operation_id
                    or current.uid != resource.uid
                ):
                    raise DeploymentFailure("teardown changed during Pod finalizer attachment")
                if outcome == "retryable":
                    raise DeploymentFailure(
                        f"Pod finalizer attach raced a Kubernetes update: {resource.uid}"
                    )
                if outcome == "absent":
                    operation.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
                    await session.commit()
                    continue
                if outcome not in {"attached", "present"}:
                    raise LineageConflict(
                        f"Pod disappeared or changed UID before teardown fence: {resource.uid}"
                    )
                current.pod_teardown_finalizer_attached_at = (
                    current.pod_teardown_finalizer_attached_at or utc_now()
                )
                operation.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
                await session.commit()

    async def _close_operation_pod(
        self,
        operation: DeploymentTeardownOperation,
        resource: DeploymentTeardownK8sResource,
        live: ResourceIdentity | None,
    ) -> str | None:
        """Persist exact termination, then remove the deletion fence, crash-safely."""
        evidence = getattr(resource, "pod_termination_evidence", None)
        digest = getattr(resource, "pod_termination_evidence_sha256", None)
        if evidence is not None or digest is not None:
            _verified_pod_termination_evidence(resource)
        elif live is not None and live.pod_termination_evidence is not None:
            evidence = dict(live.pod_termination_evidence)
            if evidence.get("schema") == POD_TERMINATION_EVIDENCE_V2_SCHEMA:
                evidence["termination_origin"] = (
                    "already_terminating"
                    if getattr(resource, "pod_already_terminating", False)
                    else "teardown"
                )
            digest = canonical_sha256(evidence)
        else:
            return None
        if not getattr(resource, "pod_teardown_finalizer_attached_at", None):
            raise LineageConflict("Pod terminal evidence predates teardown finalizer")

        async with get_session() as session:
            current_operation = await session.get(
                DeploymentTeardownOperation,
                operation.operation_id,
                with_for_update=True,
            )
            current = await session.get(
                DeploymentTeardownK8sResource,
                resource.resource_id,
                with_for_update=True,
            )
            if (
                current_operation is None
                or current_operation.retry_lease_owner != self.worker_id
                or current_operation.phase != "verifying"
                or current is None
                or current.operation_id != operation.operation_id
                or current.uid != resource.uid
                or current.state in {"absent", "replaced"}
            ):
                raise DeploymentFailure("teardown changed before Pod terminal evidence")
            if not current.pod_teardown_finalizer_attached_at:
                raise LineageConflict("Pod terminal evidence has no durable finalizer")
            if current.pod_termination_evidence is not None and (
                current.pod_termination_evidence != evidence
                or current.pod_termination_evidence_sha256 != digest
            ):
                raise LineageConflict("Pod terminal evidence changed during replay")
            current.pod_termination_evidence = evidence
            current.pod_termination_evidence_sha256 = digest
            current.pod_teardown_finalizer_removal_requested_at = (
                current.pod_teardown_finalizer_removal_requested_at or utc_now()
            )
            current_operation.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
            await session.commit()

        outcome = await asyncio.to_thread(
            self.kubernetes.remove_pod_teardown_finalizer,
            cluster_context=resource.cluster_context,
            namespace=resource.namespace,
            name=resource.name,
            uid=resource.uid,
            node_name=resource.node_name,
        )
        async with get_session() as session:
            current_operation = await session.get(
                DeploymentTeardownOperation,
                operation.operation_id,
                with_for_update=True,
            )
            current = await session.get(
                DeploymentTeardownK8sResource,
                resource.resource_id,
                with_for_update=True,
            )
            if (
                current_operation is None
                or current_operation.retry_lease_owner != self.worker_id
                or current_operation.phase != "verifying"
                or current is None
                or current.operation_id != operation.operation_id
                or current.uid != resource.uid
                or current.pod_termination_evidence != evidence
                or current.pod_termination_evidence_sha256 != digest
            ):
                raise DeploymentFailure("teardown changed during Pod finalizer removal")
            if outcome == "uid_changed":
                raise LineageConflict("same-name Pod replaced during teardown finalizer removal")
            if outcome == "retryable":
                raise DeploymentFailure("Pod finalizer removal raced a Kubernetes update")
            current.pod_teardown_finalizer_removed_at = (
                current.pod_teardown_finalizer_removed_at or utc_now()
            )
            resource.pod_termination_evidence = evidence
            resource.pod_termination_evidence_sha256 = digest
            resource.pod_teardown_finalizer_removal_requested_at = (
                current.pod_teardown_finalizer_removal_requested_at
            )
            resource.pod_teardown_finalizer_removed_at = current.pod_teardown_finalizer_removed_at
            if outcome == "absent":
                current.state = "absent"
                current.absent_at = current.absent_at or utc_now()
                resource.state = "absent"
            current_operation.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
            await session.commit()
        return outcome

    async def _adopt_replacement(
        self,
        operation_id: str,
        live: ResourceIdentity,
        *,
        predecessor_resource_id: str | None = None,
    ) -> None:
        """Atomically bind a successor and return the operation to deletion."""
        async with get_session() as session:
            operation = await session.get(
                DeploymentTeardownOperation,
                operation_id,
                with_for_update=True,
            )
            if (
                operation is None
                or operation.retry_lease_owner != self.worker_id
                or operation.phase != "verifying"
            ):
                raise DeploymentFailure("teardown changed during replacement adoption")
            if live.namespace != operation.namespace:
                raise LineageConflict("replacement Kubernetes resource changed namespace")
            successor = (
                await session.execute(
                    select(DeploymentTeardownK8sResource)
                    .where(
                        DeploymentTeardownK8sResource.operation_id == operation_id,
                        DeploymentTeardownK8sResource.kind == live.kind,
                        DeploymentTeardownK8sResource.uid == live.uid,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if successor is None:
                successor = DeploymentTeardownK8sResource(
                    resource_id=str(uuid.uuid4()),
                    operation_id=operation_id,
                    cluster_context=operation.cluster_context,
                    namespace=live.namespace,
                    api_version=live.api_version,
                    kind=live.kind,
                    name=live.name,
                    uid=live.uid,
                    owner_api_version=live.owner_api_version,
                    owner_kind=live.owner_kind,
                    owner_name=live.owner_name,
                    owner_uid=live.owner_uid,
                    node_name=live.node_name,
                    labels=live.labels,
                    labels_sha256=live.labels_sha256,
                    pod_already_terminating=live.pod_already_terminating,
                )
                session.add(successor)
                await session.flush()
            if predecessor_resource_id:
                predecessor = await session.get(
                    DeploymentTeardownK8sResource,
                    predecessor_resource_id,
                    with_for_update=True,
                )
                if predecessor is None or predecessor.operation_id != operation_id:
                    raise DeploymentFailure("replacement predecessor binding changed")
                if getattr(predecessor, "kind", None) == "Pod" and not _pod_absence_proven(
                    predecessor
                ):
                    raise LineageConflict("same-name Pod replaced before exact termination closure")
                predecessor.state = "replaced"
                predecessor.replaced_by_resource_id = successor.resource_id
            operation.phase = "deleting"
            operation.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
            operation.last_failure = None
            await session.commit()

    async def _require_launch_quiesced(self, deployment_id: str) -> None:
        now = utc_now()
        async with get_session() as session:
            launch = (
                await session.execute(
                    select(DeploymentLaunchOperation)
                    .where(DeploymentLaunchOperation.deployment_id == deployment_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if launch is None:
                return
            if launch.phase != "teardown_fenced":
                raise DeploymentFailure("launch journal is not fenced for teardown")
            if launch.lease_expires_at and launch.lease_expires_at > now:
                raise DeploymentFailure("in-flight Kubernetes create has not quiesced")
            if launch.lease_owner is not None:
                launch.lease_owner = None
                launch.lease_expires_at = None
                launch.last_failure = "launch lease expired under teardown fence"
                await session.commit()

    async def _discover(self, operation: DeploymentTeardownOperation) -> None:
        await self._require_launch_quiesced(operation.deployment_id)
        resources = await asyncio.to_thread(
            self.kubernetes.list_resources,
            cluster_context=operation.cluster_context,
            namespace=operation.namespace,
            deployment_id=operation.deployment_id,
            config_id=operation.config_id,
        )
        await self._renew_operation_lease(operation.operation_id, "discovering")
        accepted_owners: dict[str, tuple[str, str, str]] = {}
        pending = list(resources)
        changed = True
        while changed:
            changed = False
            for resource in list(pending):
                try:
                    replacement_matches(
                        expected_labels=operation.immutable_labels,
                        expected_node_name=operation.cluster_context,
                        accepted_owners=accepted_owners,
                        resource=resource,
                    )
                except UnresolvedOwnerLineage:
                    continue
                except LineageConflict as exc:
                    await self._record_conflict(operation.operation_id, str(exc))
                    raise
                _accept_owner(accepted_owners, resource)
                pending.remove(resource)
                changed = True
        if pending:
            identities = ", ".join(
                f"{resource.kind}/{resource.name}:{resource.uid}" for resource in pending
            )
            raise UnresolvedOwnerLineage(f"Kubernetes owner lineage was not observed: {identities}")
        await self._record_resources(operation.operation_id, resources)
        await self._ensure_operation_pod_finalizers(
            operation.operation_id,
            "discovering",
        )
        await self._advance(operation.operation_id, "discovering", "revoking")

    async def _revoke_registry_identity(
        self,
        *,
        launch_config_id: str,
        validator_hotkey: str,
        server_id: str,
        deployment_id: str,
    ) -> dict[str, Any]:
        """Persist and obtain one exact registry-scope revocation ACK."""

        await request_registry_scope_revocation(
            launch_config_id=launch_config_id,
            validator=validator_hotkey,
            server_id=server_id,
            deployment_id=deployment_id,
        )
        validator = validator_by_hotkey(validator_hotkey)
        if validator is None:
            raise DeploymentFailure("registry scope validator is unavailable")
        headers, _ = sign_request(purpose="registry")
        headers["X-Chutes-Server-Id"] = server_id
        headers["X-Chutes-Registry-Workload-Token"] = settings.registry_workload_token
        service = f"registry-{validator.hotkey.lower()}.{settings.namespace}.svc.cluster.local:5000"
        async with aiohttp.ClientSession(
            raise_for_status=False,
            timeout=EXTERNAL_HTTP_TIMEOUT,
        ) as http:
            async with http.delete(
                f"http://{service}/registry/scopes/{launch_config_id}",
                headers=headers,
            ) as response:
                payload = await response.json()
                expected = {
                    "status": payload.get("status") if isinstance(payload, dict) else None,
                    "revoked": True,
                    "launch_config_id": launch_config_id,
                    "server_id": server_id,
                }
                if (
                    expected["status"] not in {"revoked", "already_absent"}
                    or response.status != 200
                    or payload != expected
                ):
                    raise DeploymentFailure("registry scope revocation was not acknowledged")
        return await record_registry_scope_revoked(launch_config_id, payload)

    async def _revoke_registry(self, operation: DeploymentTeardownOperation) -> dict[str, Any]:
        if not operation.config_id or not settings.gpu_tee_only:
            return {"status": "not_required", "config_id": operation.config_id}
        return await self._revoke_registry_identity(
            launch_config_id=operation.config_id,
            validator_hotkey=operation.validator,
            server_id=operation.server_id,
            deployment_id=operation.deployment_id,
        )

    async def _delete_validator_instance(
        self, operation: DeploymentTeardownOperation
    ) -> dict[str, Any]:
        if not operation.instance_id:
            return {"status": "not_required", "instance_id": None}
        return await self._delete_validator_instance_exact(
            validator_hotkey=operation.validator,
            chute_id=operation.chute_id,
            instance_id=operation.instance_id,
        )

    async def _release_validator_job(
        self,
        operation: DeploymentTeardownOperation,
    ) -> dict[str, Any]:
        if not operation.job_id:
            return {"status": "not_required", "job_id": None}
        validator = validator_by_hotkey(operation.validator)
        if validator is None:
            raise DeploymentFailure("validator job owner is unavailable")
        headers, _ = sign_request(purpose="miner")
        async with aiohttp.ClientSession(
            raise_for_status=False,
            timeout=EXTERNAL_HTTP_TIMEOUT,
        ) as http:
            async with http.delete(
                f"{validator.api}/miner/jobs/{operation.job_id}",
                headers=headers,
            ) as response:
                body = await response.read()
                if response.status not in {200, 404}:
                    raise DeploymentFailure(
                        f"validator job release returned HTTP {response.status}"
                    )
        return {
            "status": "released" if response.status == 200 else "already_absent",
            "job_id": operation.job_id,
            "response_sha256": hashlib.sha256(body).hexdigest(),
        }

    async def _delete_validator_instance_exact(
        self,
        *,
        validator_hotkey: str,
        chute_id: str,
        instance_id: str,
    ) -> dict[str, Any]:
        validator = validator_by_hotkey(validator_hotkey)
        if validator is None:
            raise DeploymentFailure("validator instance owner is unavailable")
        headers, _ = sign_request(purpose="instances")
        async with aiohttp.ClientSession(
            raise_for_status=False,
            timeout=EXTERNAL_HTTP_TIMEOUT,
        ) as http:
            async with http.delete(
                f"{validator.api}/instances/{chute_id}/{instance_id}",
                headers=headers,
            ) as response:
                body = await response.read()
                if response.status not in (200, 404):
                    raise DeploymentFailure(
                        f"validator instance deletion returned HTTP {response.status}"
                    )
        return {
            "status": "deleted" if response.status == 200 else "already_absent",
            "instance_id": instance_id,
            "response_sha256": hashlib.sha256(body).hexdigest(),
        }

    async def bind_instance_created(
        self,
        *,
        config_id: str,
        instance_id: str,
    ) -> tuple[str, str] | None:
        """Bind a delayed validator instance before any cleanup side effect."""
        async with get_session() as session:
            deployment = (
                (
                    await session.execute(
                        select(Deployment)
                        .where(Deployment.config_id == config_id)
                        .with_for_update(of=Deployment)
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            if deployment is not None and not deployment.teardown_operation_id:
                if deployment.instance_id and deployment.instance_id != instance_id:
                    raise DeploymentFailure("launch config produced conflicting instance IDs")
                deployment.instance_id = instance_id
                await session.commit()
                return None

            operation = None
            if deployment is not None:
                operation = await session.get(
                    DeploymentTeardownOperation,
                    deployment.teardown_operation_id,
                    with_for_update=True,
                )
            if operation is None:
                operation = (
                    await session.execute(
                        select(DeploymentTeardownOperation)
                        .where(DeploymentTeardownOperation.config_id == config_id)
                        .order_by(DeploymentTeardownOperation.created_at.desc())
                        .limit(1)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
            if operation is None:
                return None
            if (
                operation.phase != "completed"
                and operation.instance_id
                and operation.instance_id != instance_id
            ):
                operation.lineage_conflict_at = utc_now()
                operation.last_failure = "launch config produced conflicting instance IDs"
                await session.commit()
                raise DeploymentFailure(operation.last_failure)

            if operation.phase != "completed":
                operation.instance_id = instance_id
                operation.validator_instance_deletion_ack = None
                operation.validator_instance_deleted_at = None
                if operation.phase not in {"requested", "discovering", "revoking"}:
                    operation.phase = "revoking"
                operation.retry_lease_owner = None
                operation.retry_lease_expires_at = None
                if deployment is not None:
                    deployment.instance_id = instance_id
                await session.commit()
                return "teardown", operation.operation_id

            cleanup = (
                await session.execute(
                    select(DelayedValidatorInstanceCleanup)
                    .where(
                        DelayedValidatorInstanceCleanup.config_id == config_id,
                        DelayedValidatorInstanceCleanup.instance_id == instance_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if cleanup is None:
                cleanup = DelayedValidatorInstanceCleanup(
                    cleanup_id=str(uuid.uuid4()),
                    source_teardown_operation_id=operation.operation_id,
                    validator=operation.validator,
                    chute_id=operation.chute_id,
                    config_id=config_id,
                    instance_id=instance_id,
                    phase="pending",
                )
                session.add(cleanup)
            await session.commit()
            return "cleanup", cleanup.cleanup_id

    async def run_delayed_instance_cleanup(self, cleanup_id: str) -> bool:
        now = utc_now()
        claim_token = f"{self.worker_id}:{uuid.uuid4()}"
        async with get_session() as session:
            cleanup = await session.get(
                DelayedValidatorInstanceCleanup,
                cleanup_id,
                with_for_update=True,
            )
            if cleanup is None or cleanup.phase == "completed":
                return bool(cleanup)
            next_retry_at = getattr(cleanup, "next_retry_at", None)
            if next_retry_at is not None and next_retry_at > now:
                return False
            if cleanup.retry_lease_expires_at and cleanup.retry_lease_expires_at > now:
                return False
            cleanup.retry_lease_owner = claim_token
            cleanup.retry_lease_expires_at = now + timedelta(seconds=LEASE_SECONDS)
            cleanup.next_retry_at = None
            cleanup.attempt_count += 1
            await session.commit()
        try:
            ack = await self._delete_validator_instance_exact(
                validator_hotkey=cleanup.validator,
                chute_id=cleanup.chute_id,
                instance_id=cleanup.instance_id,
            )
            async with get_session() as session:
                current = await session.get(
                    DelayedValidatorInstanceCleanup,
                    cleanup_id,
                    with_for_update=True,
                )
                if current.retry_lease_owner != claim_token:
                    raise DeploymentFailure("delayed instance cleanup lease changed")
                current.deletion_ack = ack
                current.deleted_at = utc_now()
                current.phase = "completed"
                current.completed_at = utc_now()
                current.retry_lease_owner = None
                current.retry_lease_expires_at = None
                current.next_retry_at = None
                current.last_failure = None
                await session.commit()
            return True
        except Exception as exc:
            async with get_session() as session:
                current = await session.get(
                    DelayedValidatorInstanceCleanup,
                    cleanup_id,
                    with_for_update=True,
                )
                if current and current.retry_lease_owner == claim_token:
                    current.last_failure = f"{type(exc).__name__}: {exc}"[:8000]
                    current.retry_lease_owner = None
                    current.retry_lease_expires_at = None
                    current.next_retry_at = retry_at(current.attempt_count)
                    await session.commit()
            return False

    async def _revoke(self, operation: DeploymentTeardownOperation) -> None:
        registry_failure: str | None = None
        if operation.config_id and operation.registry_revocation_ack is None:
            try:
                ack = await self._revoke_registry(operation)
            except Exception as exc:
                registry_failure = (
                    f"registry revocation pending after local workload closure: "
                    f"{type(exc).__name__}: {exc}"
                )[:8000]
                try:
                    await record_registry_scope_failure(operation.config_id, exc)
                except Exception as record_exc:
                    logger.warning(
                        "Could not annotate registry revocation intent {}: {}",
                        operation.config_id,
                        record_exc,
                    )
            else:
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
                    current.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
                    await session.commit()
                operation = await self._load(operation.operation_id)
        if operation.job_id and operation.validator_job_release_ack is None:
            ack = await self._release_validator_job(operation)
            async with get_session() as session:
                current = await session.get(
                    DeploymentTeardownOperation,
                    operation.operation_id,
                    with_for_update=True,
                )
                if current.retry_lease_owner != self.worker_id or current.phase != "revoking":
                    raise DeploymentFailure("teardown changed during validator job release")
                current.validator_job_release_ack = ack
                current.validator_job_released_at = utc_now()
                current.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
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
                current.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
                await session.commit()
        await self._advance(
            operation.operation_id,
            "revoking",
            "deleting",
            last_failure=registry_failure,
        )

    async def _wait_for_registry_after_local_closure(
        self,
        operation_id: str,
        **values: Any,
    ) -> None:
        async with get_session() as session:
            operation = await session.get(
                DeploymentTeardownOperation,
                operation_id,
                with_for_update=True,
            )
            if (
                operation is None
                or operation.retry_lease_owner != self.worker_id
                or operation.phase != "verifying"
            ):
                raise DeploymentFailure("teardown changed before registry-only recovery")
            for key, value in values.items():
                setattr(operation, key, value)
            operation.phase = "awaiting_registry"
            operation.last_failure = (
                operation.last_failure
                or "registry revocation ACK is pending after local workload closure"
            )
            operation.retry_lease_owner = None
            operation.retry_lease_expires_at = None
            await session.commit()

    async def _retry_registry_after_local_closure(
        self,
        operation: DeploymentTeardownOperation,
    ) -> None:
        if not operation.config_id:
            await self._advance(
                operation.operation_id,
                "awaiting_registry",
                "finalizing",
                last_failure=None,
            )
            return
        ack = await self._revoke_registry(operation)
        async with get_session() as session:
            current = await session.get(
                DeploymentTeardownOperation,
                operation.operation_id,
                with_for_update=True,
            )
            if (
                current is None
                or current.retry_lease_owner != self.worker_id
                or current.phase != "awaiting_registry"
            ):
                raise DeploymentFailure("teardown changed during registry-only recovery")
            current.registry_revocation_ack = ack
            current.registry_revoked_at = current.registry_revoked_at or utc_now()
            current.phase = "finalizing"
            current.last_failure = None
            current.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
            await session.commit()

    async def _delete_resources(self, operation: DeploymentTeardownOperation) -> None:
        await self._ensure_operation_pod_finalizers(operation.operation_id, "deleting")
        resources = sorted(
            (
                resource
                for resource in operation.resources
                if resource.state == "observed"
                and _resource_delete_ready(resource, operation.resources)
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
                if (
                    current
                    and outcome == "absent"
                    and (current.kind != "Pod" or _pod_absence_proven(current))
                ):
                    current.state = "absent"
                    current.absent_at = utc_now()
                    resource.state = "absent"
                elif current and outcome == "delete_requested" and current.state == "observed":
                    current.state = "delete_requested"
                    current.delete_requested_at = utc_now()
                    resource.state = "delete_requested"
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

    async def _record_pod_uid_absence(
        self,
        operation: DeploymentTeardownOperation,
        resource: DeploymentTeardownK8sResource,
    ) -> None:
        """Close one captured Pod UID only after read-404 plus selector absence."""
        evidence = {
            "schema": POD_UID_ABSENCE_EVIDENCE_SCHEMA,
            "outcome": "uid_absent",
            "operation_id": operation.operation_id,
            "pod_uid": resource.uid,
            "node_name": resource.node_name,
            "resource_discovery_sha256": operation.resource_discovery_sha256,
            "read_status": 404,
            "selector_absent": True,
        }
        digest = canonical_sha256(evidence)
        async with get_session() as session:
            current_operation = await session.get(
                DeploymentTeardownOperation,
                operation.operation_id,
                with_for_update=True,
            )
            current = await session.get(
                DeploymentTeardownK8sResource,
                resource.resource_id,
                with_for_update=True,
            )
            if (
                current_operation is None
                or current_operation.retry_lease_owner != self.worker_id
                or current_operation.phase != "verifying"
                or current_operation.resource_discovery_sha256
                != operation.resource_discovery_sha256
                or current is None
                or current.operation_id != operation.operation_id
                or current.kind != "Pod"
                or current.uid != resource.uid
            ):
                raise DeploymentFailure("teardown changed before Pod UID absence witness")
            if current.pod_termination_evidence is not None:
                raise LineageConflict("Pod UID absence conflicts with terminal evidence")
            if current.pod_uid_absence_evidence is not None and (
                current.pod_uid_absence_evidence != evidence
                or current.pod_uid_absence_evidence_sha256 != digest
            ):
                raise LineageConflict("Pod UID absence witness changed during replay")
            now = utc_now()
            current.pod_uid_absence_evidence = evidence
            current.pod_uid_absence_evidence_sha256 = digest
            current.pod_uid_absence_observed_at = current.pod_uid_absence_observed_at or now
            current.state = "absent"
            current.absent_at = current.absent_at or now
            current_operation.retry_lease_expires_at = now + timedelta(seconds=LEASE_SECONDS)
            await session.commit()
        resource.pod_uid_absence_evidence = evidence
        resource.pod_uid_absence_evidence_sha256 = digest
        resource.pod_uid_absence_observed_at = now
        resource.state = "absent"
        resource.absent_at = resource.absent_at or now

    async def _record_no_pod_lifecycle(
        self,
        operation: DeploymentTeardownOperation,
    ) -> None:
        """Persist an exact zero-Pod closure after controller and selector absence."""
        frontier = _verified_launch_frontier(operation)
        if frontier is None:
            raise LineageConflict("GPU-owned zero-Pod teardown lacks a launch frontier")
        evidence = {
            "schema": POD_LIFECYCLE_EVIDENCE_SCHEMA,
            "outcome": ("never_started" if frontier["job"]["uid"] is None else "no_pod_observed"),
            "operation_id": operation.operation_id,
            "deployment_id": operation.deployment_id,
            "launch_frontier_sha256": operation.launch_frontier_sha256,
            "resource_discovery_sha256": operation.resource_discovery_sha256,
            "job_uid": frontier["job"]["uid"],
            "controllers_absent": True,
            "selector_absent": True,
        }
        digest = canonical_sha256(evidence)
        async with get_session() as session:
            current = await session.get(
                DeploymentTeardownOperation,
                operation.operation_id,
                with_for_update=True,
            )
            if (
                current is None
                or current.retry_lease_owner != self.worker_id
                or current.phase != "verifying"
                or current.launch_frontier_sha256 != operation.launch_frontier_sha256
                or current.resource_discovery_sha256 != operation.resource_discovery_sha256
            ):
                raise DeploymentFailure("teardown changed before zero-Pod witness")
            if current.pod_lifecycle_evidence is not None and (
                current.pod_lifecycle_evidence != evidence
                or current.pod_lifecycle_evidence_sha256 != digest
            ):
                raise LineageConflict("zero-Pod lifecycle witness changed during replay")
            now = utc_now()
            current.pod_lifecycle_evidence = evidence
            current.pod_lifecycle_evidence_sha256 = digest
            current.pod_lifecycle_evidence_recorded_at = (
                current.pod_lifecycle_evidence_recorded_at or now
            )
            current.retry_lease_expires_at = now + timedelta(seconds=LEASE_SECONDS)
            await session.commit()
        operation.pod_lifecycle_evidence = evidence
        operation.pod_lifecycle_evidence_sha256 = digest
        operation.pod_lifecycle_evidence_recorded_at = now

    async def _verify(self, operation: DeploymentTeardownOperation) -> bool:
        accepted_owners = {
            resource.uid: (resource.api_version, resource.kind, resource.name)
            for resource in operation.resources
        }
        delete_needed = False
        absence_pending = False
        missing_pods: list[DeploymentTeardownK8sResource] = []
        for resource in sorted(
            operation.resources,
            key=lambda item: (VERIFY_ORDER[item.kind], item.name, item.uid),
        ):
            if resource.state in {"absent", "replaced"}:
                if resource.kind == "Pod" and not _pod_absence_proven(resource):
                    await self._record_conflict(
                        operation.operation_id,
                        "terminal Pod row lacks exact termination closure",
                    )
                    return False
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
                if resource.kind == "Pod":
                    if (
                        resource.pod_termination_evidence is not None
                        and resource.pod_teardown_finalizer_removal_requested_at
                    ):
                        await self._close_operation_pod(operation, resource, None)
                        continue
                    missing_pods.append(resource)
                    continue
                async with get_session() as session:
                    current = await session.get(
                        DeploymentTeardownK8sResource,
                        resource.resource_id,
                        with_for_update=True,
                    )
                    current.state = "absent"
                    current.absent_at = utc_now()
                    await session.commit()
                resource.state = "absent"
                continue
            if live.uid == resource.uid:
                if resource.kind == "Pod":
                    outcome = await self._close_operation_pod(
                        operation,
                        resource,
                        live,
                    )
                    if outcome is not None:
                        if resource.state != "absent":
                            absence_pending = True
                        continue
                if resource.state == "observed" and _resource_delete_ready(
                    resource, operation.resources
                ):
                    delete_needed = True
                else:
                    absence_pending = True
                continue
            if resource.kind == "Pod" and not _pod_absence_proven(resource):
                await self._record_conflict(
                    operation.operation_id,
                    "same-name Pod appeared before exact predecessor termination closure",
                )
                return False
            try:
                replacement_matches(
                    expected_labels=operation.immutable_labels,
                    expected_node_name=operation.cluster_context,
                    accepted_owners=accepted_owners,
                    resource=live,
                )
            except UnresolvedOwnerLineage as exc:
                await self._pause_for_retry(operation.operation_id, str(exc))
                return False
            except LineageConflict as exc:
                await self._record_conflict(
                    operation.operation_id,
                    str(exc),
                )
                return False
            await self._adopt_replacement(
                operation.operation_id,
                live,
                predecessor_resource_id=resource.resource_id,
            )
            return True

        await self._require_launch_quiesced(operation.deployment_id)
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
            try:
                replacement_matches(
                    expected_labels=operation.immutable_labels,
                    expected_node_name=operation.cluster_context,
                    accepted_owners=accepted_owners,
                    resource=resource,
                )
            except UnresolvedOwnerLineage as exc:
                await self._pause_for_retry(operation.operation_id, str(exc))
                return False
            except LineageConflict as exc:
                await self._record_conflict(
                    operation.operation_id,
                    str(exc),
                )
                return False
            await self._adopt_replacement(operation.operation_id, resource)
            return True

        if delete_needed:
            await self._advance(operation.operation_id, "verifying", "deleting")
            return True
        if absence_pending:
            await self._pause_for_retry(
                operation.operation_id,
                "awaiting direct Kubernetes absence checks",
            )
            return False

        for resource in missing_pods:
            await self._record_pod_uid_absence(operation, resource)

        if (
            operation.gpu_hardware_uuids
            and not any(resource.kind == "Pod" for resource in operation.resources)
            and operation.pod_lifecycle_evidence is None
        ):
            if any(
                resource.kind in CONTROLLER_KINDS and resource.state not in {"absent", "replaced"}
                for resource in operation.resources
            ):
                await self._pause_for_retry(
                    operation.operation_id,
                    "zero-Pod launch still has a live controller",
                )
                return False
            await self._record_no_pod_lifecycle(operation)

        if not _gpu_pod_lifecycle_closed(operation, operation.resources):
            await self._pause_for_retry(
                operation.operation_id,
                "GPU-owned workload lacks exact Pod lifecycle evidence",
            )
            return False

        for resource in operation.resources:
            if resource.kind == "Pod" and not _pod_absence_proven(resource):
                await self._record_conflict(
                    operation.operation_id,
                    "Pod closure became incomplete before teardown finalization",
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
        if operation.config_id and operation.registry_revocation_ack is None:
            await self._wait_for_registry_after_local_closure(
                operation.operation_id,
                **values,
            )
            return False
        await self._advance(operation.operation_id, "verifying", "finalizing", **values)
        return True

    async def _finalize(self, operation: DeploymentTeardownOperation) -> None:
        async with get_session() as session:
            # Deployment is the shared lock root for request, late instance events,
            # launch fencing, and finalization. Keep it ahead of the operation row.
            deployment = (
                (
                    await session.execute(
                        select(Deployment)
                        .where(Deployment.deployment_id == operation.deployment_id)
                        .with_for_update(of=Deployment)
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            current = (
                await session.execute(
                    select(DeploymentTeardownOperation)
                    .where(DeploymentTeardownOperation.operation_id == operation.operation_id)
                    .with_for_update()
                )
            ).scalar_one()
            if current.retry_lease_owner != self.worker_id or current.phase != "finalizing":
                raise DeploymentFailure("teardown changed before finalization")
            if current.deployment_id != operation.deployment_id:
                raise DeploymentFailure("teardown deployment lineage changed")
            if not (
                current.controllers_absent_at
                and current.services_absent_at
                and current.pods_absent_at
                and (not current.config_id or current.registry_revocation_ack)
                and (not current.config_id or current.pull_secret_deletion_ack)
                and (not current.job_id or current.validator_job_release_ack)
                and (not current.instance_id or current.validator_instance_deletion_ack)
            ):
                raise DeploymentFailure("teardown finalization lacks persisted acknowledgements")
            resources = list(
                (
                    await session.execute(
                        select(DeploymentTeardownK8sResource)
                        .where(DeploymentTeardownK8sResource.operation_id == current.operation_id)
                        .with_for_update()
                    )
                ).scalars()
            )
            if any(
                resource.state not in {"absent", "replaced"}
                or resource.cluster_context != current.cluster_context
                or resource.namespace != current.namespace
                or (resource.kind == "Pod" and not _pod_absence_proven(resource))
                or (
                    resource.kind == "Pod"
                    and resource.pod_uid_absence_evidence is not None
                    and resource.pod_uid_absence_evidence.get("resource_discovery_sha256")
                    != current.resource_discovery_sha256
                )
                for resource in resources
            ):
                raise DeploymentFailure("teardown finalization lacks exact Kubernetes UID closure")
            if not _gpu_pod_lifecycle_closed(current, resources):
                raise DeploymentFailure("GPU-owned teardown lacks exact Pod lifecycle evidence")
            latest_handoff = (
                await session.execute(
                    select(DeploymentTeardownNodeIncarnationHandoff)
                    .where(
                        DeploymentTeardownNodeIncarnationHandoff.operation_id
                        == current.operation_id
                    )
                    .order_by(DeploymentTeardownNodeIncarnationHandoff.sequence.desc())
                    .limit(1)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            server = (
                (
                    await session.execute(
                        select(Server)
                        .where(Server.server_id == current.server_id)
                        .with_for_update(of=Server)
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
                        .with_for_update(of=GPU)
                    )
                )
                .unique()
                .scalars()
                .all()
            )
            expected_node_lineage = _operation_node_lineage(current, latest_handoff)
            if server is None or _server_node_lineage(server) != expected_node_lineage:
                current.last_failure = (
                    "server/node incarnation changed after teardown authorization; retry required"
                )
                current.retry_lease_owner = None
                current.retry_lease_expires_at = None
                await session.commit()
                raise DeploymentFailure(current.last_failure)
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
            actual_gpu_uuids = sorted(str(gpu.hardware_uuid or gpu.gpu_id) for gpu in gpu_rows)
            if actual_gpu_uuids != list(current.gpu_hardware_uuids):
                lineage_errors.append("assigned GPU UUID closure changed")
            if any(
                gpu.server_id != current.server_id
                or gpu.deployment_id != current.deployment_id
                or gpu.validator != current.validator
                or gpu.gpu_allocation_group_id != expected_node_lineage.gpu_allocation_group_id
                or gpu.gpu_allocation_group_generation
                != expected_node_lineage.gpu_allocation_group_generation
                for gpu in gpu_rows
            ):
                lineage_errors.append("assigned GPU lineage changed")
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
            if current.config_id:
                launch_intent_id = await session.scalar(
                    select(DeploymentLaunchOperation.launch_intent_id).where(
                        DeploymentLaunchOperation.deployment_id == current.deployment_id
                    )
                )
                if launch_intent_id:
                    intent = await session.get(
                        MinerLaunchIntent,
                        launch_intent_id,
                        with_for_update=True,
                    )
                    if intent is not None:
                        validated_miner_launch_lineage(
                            intent,
                            miner_hotkey=settings.miner_ss58,
                            validator=intent.validator,
                            chute_id=intent.chute_id,
                            chute_version=intent.chute_version,
                            server_id=intent.server_id,
                            job_id=intent.job_id,
                            require_gpu_lineage=settings.gpu_tee_only,
                        )
                    if intent is not None and intent.phase == "cleanup_required":
                        intent.phase = "completed"
                        intent.completed_at = utc_now()
                        intent.last_failure = None
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
            if (
                operation
                and operation.lineage_conflict_at is None
                and operation.retry_lease_owner == self.worker_id
            ):
                operation.last_failure = f"{type(exc).__name__}: {exc}"[:8000]
                operation.retry_lease_owner = None
                operation.retry_lease_expires_at = None
                operation.next_retry_at = retry_at(operation.attempt_count)
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
                operation.next_retry_at = retry_at(operation.attempt_count)
                await session.commit()

    async def run(self, operation_id: str) -> bool:
        async with self._run_lock("teardown", operation_id):
            marker = self._claim_owner.set(f"{self.worker_id}:{uuid.uuid4()}")
            try:
                return await self._run_claimed(operation_id)
            finally:
                self._claim_owner.reset(marker)

    async def _run_claimed(self, operation_id: str) -> bool:
        if not await self._claim(operation_id):
            operation = await self._load(operation_id)
            return bool(operation and operation.phase == "completed")
        try:
            while True:
                await self._authorize_current_node_incarnation(operation_id)
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
                elif operation.phase == "awaiting_registry":
                    await self._retry_registry_after_local_closure(operation)
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
                                DeploymentTeardownOperation.next_retry_at.is_(None)
                                | (DeploymentTeardownOperation.next_retry_at <= now)
                            ),
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
                                ParentDeletionOperation.next_retry_at.is_(None)
                                | (ParentDeletionOperation.next_retry_at <= now)
                            ),
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
                                KubernetesOrphanTombstone.next_retry_at.is_(None)
                                | (KubernetesOrphanTombstone.next_retry_at <= now)
                            ),
                            (
                                KubernetesOrphanTombstone.retry_lease_expires_at.is_(None)
                                | (KubernetesOrphanTombstone.retry_lease_expires_at <= now)
                            ),
                        )
                    )
                ).scalars()
            )
            delayed_cleanup_ids = list(
                (
                    await session.execute(
                        select(DelayedValidatorInstanceCleanup.cleanup_id).where(
                            DelayedValidatorInstanceCleanup.phase != "completed",
                            (
                                DelayedValidatorInstanceCleanup.next_retry_at.is_(None)
                                | (DelayedValidatorInstanceCleanup.next_retry_at <= now)
                            ),
                            (
                                DelayedValidatorInstanceCleanup.retry_lease_expires_at.is_(None)
                                | (DelayedValidatorInstanceCleanup.retry_lease_expires_at <= now)
                            ),
                        )
                    )
                ).scalars()
            )
            stale_launch_deployment_ids = list(
                (
                    await session.execute(
                        select(DeploymentLaunchOperation.deployment_id).where(
                            or_(
                                (
                                    (DeploymentLaunchOperation.phase == "reserved")
                                    & (
                                        DeploymentLaunchOperation.created_at
                                        <= now - timedelta(seconds=300)
                                    )
                                ),
                                (
                                    (DeploymentLaunchOperation.phase == "creating")
                                    & (DeploymentLaunchOperation.lease_expires_at <= now)
                                ),
                                DeploymentLaunchOperation.phase == "failed",
                            ),
                            (
                                DeploymentLaunchOperation.next_retry_at.is_(None)
                                | (DeploymentLaunchOperation.next_retry_at <= now)
                            ),
                        )
                    )
                ).scalars()
            )
        work: list[tuple[str, str, Any]] = [
            *(("deployment", operation_id, self.run) for operation_id in operation_ids),
            *(("parent", operation_id, self.run_parent) for operation_id in parent_operation_ids),
            *(("orphan", tombstone_id, self.run_orphan) for tombstone_id in orphan_ids),
            *(
                ("delayed", cleanup_id, self.run_delayed_instance_cleanup)
                for cleanup_id in delayed_cleanup_ids
            ),
            *(
                (
                    "launch_rollback",
                    deployment_id,
                    lambda identity: self.request_and_run(identity, "launch_rollback"),
                )
                for deployment_id in stale_launch_deployment_ids
            ),
        ]
        semaphore = asyncio.Semaphore(RESUME_CONCURRENCY)

        async def resume_one(kind: str, identity: str, runner: Any) -> None:
            async with semaphore:
                try:
                    await asyncio.wait_for(
                        runner(identity),
                        timeout=RESUME_ITEM_TIMEOUT_SECONDS,
                    )
                except TimeoutError:
                    try:
                        await self._record_resume_timeout(kind, identity)
                    except Exception as record_exc:
                        logger.exception(
                            "Could not persist timeout backoff for durable {} {}: {}",
                            kind,
                            identity,
                            record_exc,
                        )
                    logger.warning("Durable {} {} timed out and was backed off", kind, identity)
                except Exception as exc:
                    try:
                        await self._record_resume_exception(kind, identity, exc)
                    except Exception as record_exc:
                        logger.exception(
                            "Could not persist failure backoff for durable {} {}: {}",
                            kind,
                            identity,
                            record_exc,
                        )
                    logger.warning("Durable {} {} failed independently: {}", kind, identity, exc)

        await asyncio.gather(
            *(resume_one(kind, identity, runner) for kind, identity, runner in work)
        )

    async def _record_resume_timeout(self, kind: str, identity: str) -> None:
        await self._record_resume_failure(
            kind,
            identity,
            TimeoutError(f"durable {kind} item exceeded {RESUME_ITEM_TIMEOUT_SECONDS} seconds"),
        )

    async def _record_resume_exception(
        self,
        kind: str,
        identity: str,
        exc: Exception,
    ) -> None:
        await self._record_resume_failure(kind, identity, exc)

    async def _record_resume_failure(
        self,
        kind: str,
        identity: str,
        exc: Exception,
    ) -> None:
        if kind == "launch_rollback":
            async with get_session() as session:
                row = (
                    await session.execute(
                        select(DeploymentLaunchOperation)
                        .where(
                            DeploymentLaunchOperation.deployment_id == identity,
                            DeploymentLaunchOperation.phase.in_({"reserved", "creating", "failed"}),
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if row is None:
                    return
                row.attempt_count += 1
                row.last_failure = f"{type(exc).__name__}: {exc}"[:8000]
                row.next_retry_at = retry_at(row.attempt_count)
                await session.commit()
            return
        model_and_key = {
            "deployment": (DeploymentTeardownOperation, "operation_id"),
            "parent": (ParentDeletionOperation, "operation_id"),
            "orphan": (KubernetesOrphanTombstone, "tombstone_id"),
            "delayed": (DelayedValidatorInstanceCleanup, "cleanup_id"),
        }.get(kind)
        if model_and_key is None:
            return
        model, _key = model_and_key
        async with get_session() as session:
            row = await session.get(model, identity, with_for_update=True)
            owner = getattr(row, "retry_lease_owner", None) if row is not None else None
            if row is None or not owner or not owner.startswith(self._base_worker_id):
                return
            row.last_failure = f"{type(exc).__name__}: {exc}"[:8000]
            row.retry_lease_owner = None
            row.retry_lease_expires_at = None
            row.next_retry_at = retry_at(row.attempt_count)
            await session.commit()

    @staticmethod
    async def _lineage_conflict_row(
        session: Any,
        operation_kind: str,
        operation_id: str,
        *,
        for_update: bool,
    ) -> Any:
        if operation_kind == "deployment":
            statement = (
                select(DeploymentTeardownOperation)
                .where(DeploymentTeardownOperation.operation_id == operation_id)
                .options(
                    selectinload(DeploymentTeardownOperation.resources),
                    selectinload(DeploymentTeardownOperation.node_incarnation_handoffs),
                )
            )
        elif operation_kind == "orphan":
            statement = (
                select(KubernetesOrphanTombstone)
                .where(KubernetesOrphanTombstone.tombstone_id == operation_id)
                .options(selectinload(KubernetesOrphanTombstone.resources))
            )
        else:
            raise DeploymentFailure("lineage operation kind must be deployment or orphan")
        if for_update:
            statement = statement.with_for_update().execution_options(populate_existing=True)
        return (await session.execute(statement)).unique().scalar_one_or_none()

    async def _lineage_recovery_row(
        self,
        session: Any,
        operation_kind: str,
        operation_id: str,
    ) -> Any:
        """Lock orphan recovery Server-first to match placement/finalization."""

        if operation_kind != "orphan":
            return await self._lineage_conflict_row(
                session,
                operation_kind,
                operation_id,
                for_update=True,
            )
        snapshot = await self._lineage_conflict_row(
            session,
            operation_kind,
            operation_id,
            for_update=False,
        )
        if snapshot is None:
            return None
        snapshot_cluster_context = snapshot.cluster_context
        locked_server_id = await session.scalar(
            select(Server.server_id)
            .where(Server.name == snapshot_cluster_context)
            .with_for_update(of=Server)
        )
        if locked_server_id is None:
            raise LineageConflict("orphan recovery has no stable Server-row fence")
        row = await self._lineage_conflict_row(
            session,
            operation_kind,
            operation_id,
            for_update=True,
        )
        if row is not None:
            if row.cluster_context != snapshot_cluster_context:
                raise LineageConflict("orphan recovery cluster context changed")
            # A supported placement cannot appear after the Server lock. If
            # one is already visible, neither requeue nor terminal resolution
            # is valid. Fail before taking RegistryScopeIntent because normal
            # teardown locks Deployment -> RegistryScopeIntent -> Server.
            deployment_id = await session.scalar(
                select(Deployment.deployment_id).where(
                    Deployment.deployment_id == row.deployment_id
                )
            )
            if deployment_id is not None:
                raise LineageConflict("orphan recovery conflicts with a local Deployment")
        return row

    async def _authoritative_lineage_document(
        self,
        session: Any,
        operation_kind: str,
        row: Any,
        *,
        for_update: bool,
        server_fenced: bool = False,
    ) -> dict[str, Any]:
        """Observe durable, relational, registry, and live Kubernetes lineage."""

        deployment_statement = select(Deployment).where(
            Deployment.deployment_id == row.deployment_id
        )
        if operation_kind == "deployment":
            server_statement = select(Server).where(Server.server_id == row.server_id)
            config_id = row.config_id
            snapshot = _deployment_lineage_document(row)
        else:
            server_statement = select(Server).where(Server.name == row.cluster_context)
            config_id = row.immutable_labels.get("chutes/config-id")
            snapshot = _orphan_lineage_document(row)
        gpu_statement = (
            select(GPU).where(GPU.deployment_id == row.deployment_id).order_by(GPU.gpu_id)
        )
        lock_related_rows = for_update and not server_fenced
        if lock_related_rows:
            deployment_statement = deployment_statement.with_for_update(of=Deployment)
            server_statement = server_statement.with_for_update(of=Server)
            gpu_statement = gpu_statement.with_for_update(of=GPU)
        deployment = (await session.execute(deployment_statement)).unique().scalar_one_or_none()
        server = (await session.execute(server_statement)).unique().scalar_one_or_none()
        gpus = list((await session.execute(gpu_statement)).unique().scalars().all())
        registry_intent = (
            await session.get(
                RegistryScopeIntent,
                config_id,
                # A registry reconciler/revoker does not take the Server fence.
                # Recovery must therefore still lock and revalidate this row;
                # only Deployment/GPU reads become MVCC under Server-first
                # orphan recovery to avoid their normal teardown lock cycle.
                with_for_update=for_update,
            )
            if config_id
            else None
        )
        try:
            live_resources = await asyncio.to_thread(
                self.kubernetes.list_resources,
                cluster_context=row.cluster_context,
                namespace=row.namespace,
                deployment_id=row.deployment_id,
                config_id=config_id,
            )
        except Exception as exc:
            raise DeploymentFailure(
                "fresh authoritative Kubernetes lineage observation failed"
            ) from exc
        resources = sorted(
            (_live_resource_document(resource) for resource in live_resources),
            key=lambda item: (
                item["api_version"],
                item["kind"],
                item["namespace"],
                item["name"],
                item["uid"],
            ),
        )
        gpu_documents = sorted(
            (_gpu_authority_document(gpu) for gpu in gpus),
            key=lambda item: item["gpu_id"],
        )
        return {
            "schema": LINEAGE_AUTHORITY_SCHEMA,
            "version": 1,
            "snapshot": snapshot,
            "authoritative": {
                "deployment": _deployment_authority_document(deployment),
                "server": _server_authority_document(server),
                "gpus": gpu_documents,
                "registry_scope": _registry_authority_document(registry_intent),
                "kubernetes": {
                    "cluster_context": row.cluster_context,
                    "namespace": row.namespace,
                    "resources": resources,
                },
            },
        }

    @staticmethod
    def _require_verified_terminal_absence(
        operation_kind: str,
        row: Any,
        lineage: dict[str, Any],
    ) -> None:
        """Apply the single fail-closed terminal policy to normal and orphan rows."""

        snapshot = lineage["snapshot"]
        authoritative = lineage["authoritative"]
        if authoritative["kubernetes"]["resources"]:
            raise DeploymentFailure(
                "verified terminal absence requires an empty live Kubernetes scope"
            )
        server = authoritative["server"]
        if operation_kind == "deployment":
            expected_node = snapshot["effective_node_lineage"]
            if server is None or any(
                server.get(key) != value
                for key, value in {
                    "server_id": row.server_id,
                    "validator": row.validator,
                    "cluster_context": row.cluster_context,
                    **expected_node,
                }.items()
            ):
                raise DeploymentFailure("verified terminal absence observed changed server lineage")
            deployment = authoritative["deployment"]
            expected_deployment = {
                "deployment_id": row.deployment_id,
                "validator": row.validator,
                "server_id": row.server_id,
                "chute_id": row.chute_id,
                "config_id": row.config_id,
                "job_id": row.job_id,
                "instance_id": row.instance_id,
                "teardown_operation_id": row.operation_id,
            }
            if deployment is None or any(
                deployment.get(key) != value for key, value in expected_deployment.items()
            ):
                raise DeploymentFailure(
                    "verified terminal absence observed changed Deployment lineage"
                )
            gpus = authoritative["gpus"]
            if sorted(str(gpu["hardware_uuid"] or gpu["gpu_id"]) for gpu in gpus) != sorted(
                str(value) for value in row.gpu_hardware_uuids
            ) or any(
                gpu["validator"] != row.validator
                or gpu["server_id"] != row.server_id
                or gpu["deployment_id"] != row.deployment_id
                or gpu["gpu_allocation_group_id"] != expected_node["gpu_allocation_group_id"]
                or gpu["gpu_allocation_group_generation"]
                != expected_node["gpu_allocation_group_generation"]
                for gpu in gpus
            ):
                raise DeploymentFailure("verified terminal absence observed changed GPU lineage")
            if not all(
                (
                    row.controllers_absent_at,
                    row.services_absent_at,
                    row.pods_absent_at,
                )
            ):
                raise DeploymentFailure("verified terminal absence lacks durable workload absence")
            if row.config_id and (
                row.pull_secret_deletion_ack
                != {
                    "status": "absent",
                    "name": registry_pull_secret_name(row.config_id),
                    "config_id": row.config_id,
                }
                or row.pull_secret_deleted_at is None
            ):
                raise DeploymentFailure("verified terminal absence lacks pull-secret closure")
            if row.job_id and (
                row.validator_job_release_ack is None or row.validator_job_released_at is None
            ):
                raise DeploymentFailure("verified terminal absence lacks validator job closure")
            if row.instance_id and (
                row.validator_instance_deletion_ack is None
                or row.validator_instance_deleted_at is None
            ):
                raise DeploymentFailure(
                    "verified terminal absence lacks validator instance closure"
                )
            if any(
                resource.state not in {"absent", "replaced"}
                or (resource.state == "absent" and resource.absent_at is None)
                or (resource.state == "replaced" and resource.replaced_by_resource_id is None)
                or (resource.kind == "Pod" and not _pod_absence_proven(resource))
                for resource in row.resources
            ) or not _gpu_pod_lifecycle_closed(row, row.resources):
                raise DeploymentFailure("verified terminal absence lacks exact durable UID closure")
            config_id = row.config_id
            expected_registry_identity = {
                "launch_config_id": config_id,
                "deployment_id": row.deployment_id,
                "validator": row.validator,
                "server_id": row.server_id,
            }
            operation_registry_ack = row.registry_revocation_ack
            operation_registry_at = row.registry_revoked_at
        else:
            if authoritative["deployment"] is not None:
                raise DeploymentFailure("verified terminal absence observed a local Deployment")
            if authoritative["gpus"]:
                raise DeploymentFailure("verified terminal absence observed local GPU ownership")
            if server is None or any(
                server.get(key) != value
                for key, value in {
                    "cluster_context": row.cluster_context,
                    "cluster_context_sha256": row.cluster_context_sha256,
                    "kubernetes_node_uid": row.kubernetes_node_uid,
                    "kubernetes_node_generation": row.kubernetes_node_generation,
                }.items()
            ):
                raise DeploymentFailure(
                    "verified terminal absence observed changed orphan server lineage"
                )
            if any(
                resource.state != "absent"
                or resource.absent_at is None
                or (resource.kind == "Pod" and not _pod_absence_proven(resource))
                for resource in row.resources
            ):
                raise DeploymentFailure("verified terminal absence lacks exact orphan UID closure")
            config_id = row.immutable_labels.get("chutes/config-id")
            expected_registry_identity = {
                "launch_config_id": config_id,
                "deployment_id": row.deployment_id,
                "validator": server["validator"] if server else None,
                "server_id": server["server_id"] if server else None,
            }
            operation_registry_ack = None
            operation_registry_at = None
        if operation_kind == "orphan" and settings.gpu_tee_only and not config_id:
            raise DeploymentFailure(
                "verified terminal absence lacks exact registry config authority"
            )
        if config_id and settings.gpu_tee_only:
            registry = authoritative["registry_scope"]
            expected_registry_ack = {
                "status": "revoked",
                "revoked": True,
                "launch_config_id": config_id,
                "server_id": expected_registry_identity["server_id"],
            }
            if (
                registry is None
                or any(
                    registry.get(key) != value for key, value in expected_registry_identity.items()
                )
                or registry["desired_state"] != "revoked"
                or registry["phase"] != "revoked"
                or registry["revocation_ack"] != expected_registry_ack
                or registry["revoked_at"] is None
                or (
                    operation_kind == "deployment"
                    and (
                        operation_registry_ack != registry["revocation_ack"]
                        or operation_registry_at is None
                    )
                )
            ):
                raise DeploymentFailure(
                    "verified terminal absence lacks terminal registry revocation"
                )

    async def inspect_lineage_conflict(
        self,
        operation_kind: str,
        operation_id: str,
    ) -> dict[str, Any] | None:
        async with get_session() as session:
            row = await self._lineage_conflict_row(
                session,
                operation_kind,
                operation_id,
                for_update=False,
            )
            if row is None:
                return None
            lineage = await self._authoritative_lineage_document(
                session,
                operation_kind,
                row,
                for_update=False,
            )
            conflict_at = row.lineage_conflict_at
            return {
                "schema": LINEAGE_INSPECTION_SCHEMA,
                "version": 1,
                "operation_kind": operation_kind,
                "operation_id": operation_id,
                "phase": row.phase,
                "conflict_at": conflict_at.isoformat() if conflict_at else None,
                "last_failure": row.last_failure,
                "lineage": lineage,
                "lineage_sha256": canonical_sha256(lineage),
                "recoverable": conflict_at is not None and row.phase != "completed",
                "resolution_policies": {
                    "requeue": "exact_lineage_retry",
                    "resolve": "verified_terminal_absence",
                },
            }

    async def recover_lineage_conflict(
        self,
        *,
        operation_kind: str,
        operation_id: str,
        action: str,
        policy: str,
        expected_conflict_at: datetime,
        expected_lineage_sha256: str,
        reason: str,
        actor: str,
    ) -> dict[str, Any] | None:
        """CAS one conflict into retryable state and write immutable audit first."""

        expected_policy = {
            "requeue": "exact_lineage_retry",
            "resolve": "verified_terminal_absence",
        }.get(action)
        if expected_policy is None:
            raise DeploymentFailure("lineage recovery action is invalid")
        if policy != expected_policy:
            raise DeploymentFailure("lineage recovery policy does not match action")
        async with get_session() as session:
            row = await self._lineage_recovery_row(
                session,
                operation_kind,
                operation_id,
            )
            if row is None:
                return None
            if row.phase == "completed" or row.lineage_conflict_at is None:
                raise DeploymentFailure("lineage conflict is no longer recoverable")
            if row.lineage_conflict_at != expected_conflict_at:
                raise DeploymentFailure("lineage conflict timestamp changed")
            lineage = await self._authoritative_lineage_document(
                session,
                operation_kind,
                row,
                for_update=True,
                server_fenced=operation_kind == "orphan",
            )
            observed_sha256 = canonical_sha256(lineage)
            if observed_sha256 != expected_lineage_sha256:
                raise DeploymentFailure("authoritative lineage changed")
            if action == "resolve":
                self._require_verified_terminal_absence(
                    operation_kind,
                    row,
                    lineage,
                )
            audit_id = str(uuid.uuid4())
            session.add(
                TeardownLineageResolutionAudit(
                    audit_id=audit_id,
                    operation_kind=operation_kind,
                    operation_id=operation_id,
                    action=action,
                    policy=policy,
                    conflict_at=row.lineage_conflict_at,
                    expected_lineage_sha256=expected_lineage_sha256,
                    observed_lineage=lineage,
                    observed_lineage_sha256=observed_sha256,
                    reason=reason,
                    actor=actor,
                )
            )
            row.lineage_conflict_at = None
            row.last_failure = None
            row.retry_lease_owner = None
            row.retry_lease_expires_at = None
            row.next_retry_at = None
            if action == "resolve":
                if operation_kind == "deployment":
                    row.phase = "finalizing"
                else:
                    row.phase = "completed"
                    row.completed_at = utc_now()
            await session.commit()
        return {
            "schema": LINEAGE_INSPECTION_SCHEMA,
            "version": 1,
            "operation_kind": operation_kind,
            "operation_id": operation_id,
            "phase": row.phase,
            "conflict_at": None,
            "last_failure": None,
            "lineage": lineage,
            "lineage_sha256": observed_sha256,
            "recoverable": False,
            "audit_id": audit_id,
            "action": action,
            "resolution_policy": policy,
        }

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
                deployments = (
                    (
                        await session.execute(
                            select(Deployment)
                            .where(Deployment.server_id == parent_id)
                            .options(selectinload(Deployment.server))
                            .order_by(Deployment.deployment_id)
                            .with_for_update(of=Deployment)
                        )
                    )
                    .unique()
                    .scalars()
                    .all()
                )
                parent = (
                    (
                        await session.execute(
                            select(Server)
                            .where(Server.server_id == parent_id)
                            .with_for_update(of=Server)
                        )
                    )
                    .unique()
                    .scalar_one_or_none()
                )
                snapshot = (
                    {
                        "name": parent.name,
                        "agent_api": parent.agent_api,
                        "node_uid": parent.kubernetes_node_uid,
                        "node_generation": parent.kubernetes_node_generation,
                        "allocation_group_id": getattr(parent, "gpu_allocation_group_id", None),
                        "allocation_group_generation": (
                            getattr(parent, "gpu_allocation_group_generation", None)
                        ),
                    }
                    if parent
                    else None
                )
            else:
                deployments = (
                    (
                        await session.execute(
                            select(Deployment)
                            .where(Deployment.chute_id == parent_id)
                            .options(selectinload(Deployment.server))
                            .order_by(Deployment.deployment_id)
                            .with_for_update(of=Deployment)
                        )
                    )
                    .unique()
                    .scalars()
                    .all()
                )
                parent = (
                    await session.execute(
                        select(Chute).where(Chute.chute_id == parent_id).with_for_update(of=Chute)
                    )
                ).scalar_one_or_none()
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
            operation_id = str(uuid.uuid4())
            decommission_request = (
                _gpu_decommission_request(operation_id=operation_id, reason=reason)
                if parent_type == "server" and snapshot.get("allocation_group_id") is not None
                else None
            )
            parent_operation = ParentDeletionOperation(
                operation_id=operation_id,
                parent_type=parent_type,
                parent_id=parent_id,
                validator=parent.validator,
                reason=reason,
                phase="requested",
                snapshot=snapshot,
                validator_server_decommission_request=decommission_request,
                validator_server_decommission_request_sha256=(
                    canonical_sha256(decommission_request) if decommission_request else None
                ),
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
        """Delete a non-allocation-backed server through the legacy endpoint."""

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

    async def _decommission_validator_server(
        self,
        operation: ParentDeletionOperation,
    ) -> dict[str, Any]:
        """Replay one canonical GPU decommission request over current mTLS."""

        validator = validator_by_hotkey(operation.validator)
        if validator is None:
            raise DeploymentFailure("validator server owner is unavailable")
        request = _verified_gpu_decommission_request(operation)
        payload = json.dumps(
            request,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        headers, _ = sign_request(purpose="gpu-decommission")
        headers["Content-Type"] = "application/json"
        context = ssl.create_default_context()
        try:
            context.load_cert_chain(
                settings.attested_cert_file,
                settings.attested_key_file,
            )
        except (OSError, ssl.SSLError) as exc:
            raise DeploymentFailure(
                "current GPU decommission mTLS identity is unavailable"
            ) from exc
        async with aiohttp.ClientSession(
            raise_for_status=False,
            timeout=EXTERNAL_HTTP_TIMEOUT,
            connector=aiohttp.TCPConnector(ssl=context),
        ) as http:
            async with http.post(
                f"{validator.api.rstrip('/')}/servers/gpu/{operation.parent_id}/decommission",
                data=payload,
                headers=headers,
                allow_redirects=False,
            ) as response:
                body = await response.read()
                if response.status != 200:
                    raise DeploymentFailure(
                        f"validator GPU decommission returned HTTP {response.status}"
                    )
        try:
            result = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DeploymentFailure("validator GPU decommission returned malformed JSON") from exc
        if (
            not isinstance(result, dict)
            or set(result)
            != {
                "schema",
                "version",
                "server_id",
                "request_id",
                "decommissioned_at",
                "status",
            }
            or result.get("schema") != GPU_DECOMMISSION_RESPONSE_SCHEMA
            or result.get("version") != 1
            or result.get("server_id") != operation.parent_id
            or result.get("request_id") != request["request_id"]
            or result.get("status") != "decommissioned"
            or not isinstance(result.get("decommissioned_at"), str)
            or not result["decommissioned_at"]
        ):
            raise DeploymentFailure("validator GPU decommission ACK is malformed")
        return result

    async def _adopt_parent_children(self, operation_id: str) -> list[str]:
        async with get_session() as session:
            operation = await session.get(
                ParentDeletionOperation,
                operation_id,
                with_for_update=True,
            )
            if operation is None or operation.retry_lease_owner != self.worker_id:
                raise DeploymentFailure("parent deletion lease changed during child adoption")
            predicate = (
                Deployment.server_id == operation.parent_id
                if operation.parent_type == "server"
                else Deployment.chute_id == operation.parent_id
            )
            deployments = (
                (
                    await session.execute(
                        select(Deployment)
                        .where(predicate)
                        .options(selectinload(Deployment.server))
                        .order_by(Deployment.deployment_id)
                        .with_for_update(of=Deployment)
                    )
                )
                .unique()
                .scalars()
                .all()
            )
            child_ids = set(
                (
                    await session.execute(
                        select(ParentDeletionChild.child_operation_id).where(
                            ParentDeletionChild.parent_operation_id == operation_id
                        )
                    )
                ).scalars()
            )
            for deployment in deployments:
                child = await self._request_in_session(
                    session,
                    deployment,
                    operation.reason,
                )
                if child.operation_id not in child_ids:
                    session.add(
                        ParentDeletionChild(
                            parent_operation_id=operation_id,
                            child_operation_id=child.operation_id,
                        )
                    )
                    child_ids.add(child.operation_id)
            operation.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
            await session.commit()
            return sorted(child_ids)

    async def _record_parent_allocation_release(self, operation_id: str) -> None:
        """Clear only the snapshotted allocation generation after terminal ACK."""
        async with get_session() as session:
            operation = await session.get(
                ParentDeletionOperation,
                operation_id,
                with_for_update=True,
            )
            if (
                operation is None
                or operation.retry_lease_owner != self.worker_id
                or operation.parent_type != "server"
            ):
                raise DeploymentFailure("parent deletion changed before allocation release audit")
            server = (
                (
                    await session.execute(
                        select(Server)
                        .where(Server.server_id == operation.parent_id)
                        .with_for_update(of=Server)
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            gpu_rows = (
                (
                    await session.execute(
                        select(GPU)
                        .where(GPU.server_id == operation.parent_id)
                        .order_by(GPU.gpu_id)
                        .with_for_update(of=GPU)
                    )
                )
                .unique()
                .scalars()
                .all()
            )
            if server is None:
                raise DeploymentFailure("server disappeared before allocation release audit")
            snapshot = dict(operation.snapshot)
            expected_group = snapshot.get("allocation_group_id")
            expected_generation = snapshot.get("allocation_group_generation")
            if (expected_group is None) != (expected_generation is None):
                raise DeploymentFailure("server allocation snapshot is incomplete")
            if expected_group is not None:
                _verified_gpu_decommission_ack(operation)
            if operation.allocation_release_evidence is None:
                if (
                    server.gpu_allocation_group_id != expected_group
                    or server.gpu_allocation_group_generation != expected_generation
                    or any(
                        gpu.gpu_allocation_group_id != expected_group
                        or gpu.gpu_allocation_group_generation != expected_generation
                        for gpu in gpu_rows
                    )
                ):
                    raise DeploymentFailure(
                        "server allocation generation changed before exact local release"
                    )
                server.gpu_allocation_group_id = None
                server.gpu_allocation_group_generation = None
                for gpu in gpu_rows:
                    gpu.gpu_allocation_group_id = None
                    gpu.gpu_allocation_group_generation = None
            elif (
                server.gpu_allocation_group_id is not None
                or server.gpu_allocation_group_generation is not None
                or any(
                    gpu.gpu_allocation_group_id is not None
                    or gpu.gpu_allocation_group_generation is not None
                    for gpu in gpu_rows
                )
            ):
                raise DeploymentFailure("released allocation generation reappeared during replay")
            evidence = _parent_allocation_release_document(operation)
            digest = canonical_sha256(evidence)
            if operation.allocation_release_evidence is not None and (
                operation.allocation_release_evidence != evidence
                or operation.allocation_release_evidence_sha256 != digest
            ):
                raise DeploymentFailure("server allocation release evidence changed during replay")
            now = utc_now()
            operation.allocation_release_evidence = evidence
            operation.allocation_release_evidence_sha256 = digest
            operation.allocation_release_verified_at = (
                operation.allocation_release_verified_at or now
            )
            operation.retry_lease_expires_at = now + timedelta(seconds=LEASE_SECONDS)
            await session.commit()

    async def run_parent(self, operation_id: str) -> bool:
        async with self._run_lock("parent", operation_id):
            marker = self._claim_owner.set(f"{self.worker_id}:{uuid.uuid4()}")
            try:
                return await self._run_parent_claimed(operation_id)
            finally:
                self._claim_owner.reset(marker)

    async def _run_parent_claimed(self, operation_id: str) -> bool:
        async with get_session() as session:
            operation = await session.get(
                ParentDeletionOperation,
                operation_id,
                with_for_update=True,
            )
            if operation is None or operation.phase == "completed":
                return bool(operation)
            now = utc_now()
            next_retry_at = getattr(operation, "next_retry_at", None)
            if next_retry_at is not None and next_retry_at > now:
                return False
            if operation.retry_lease_expires_at and operation.retry_lease_expires_at > now:
                if operation.retry_lease_owner != self.worker_id:
                    return False
            operation.retry_lease_owner = self.worker_id
            operation.retry_lease_expires_at = now + timedelta(seconds=LEASE_SECONDS)
            operation.next_retry_at = None
            operation.attempt_count += 1
            await session.commit()
        try:
            child_ids = await self._adopt_parent_children(operation_id)
            for child_id in child_ids:
                if not await self.run(child_id):
                    raise DeploymentFailure(f"child teardown {child_id} is incomplete")
            adopted_after_children = await self._adopt_parent_children(operation_id)
            if set(adopted_after_children) != set(child_ids):
                raise DeploymentFailure("parent deletion adopted a concurrent child")
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
                operation.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
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
                            await asyncio.wait_for(stop_server_monitoring(agent_api), timeout=30)
                            monitor_ack = {"status": "stopped", "agent_api": agent_api}
                        except AgentError as exc:
                            try:
                                await asyncio.wait_for(
                                    clear_server_cache(snapshot["name"]), timeout=30
                                )
                            except Exception as cache_exc:
                                raise DeploymentFailure(
                                    "server monitor cache clear was not acknowledged"
                                ) from cache_exc
                            if exc.status_code == 409:
                                monitor_ack = {
                                    "status": "already_absent",
                                    "agent_api": agent_api,
                                }
                            else:
                                raise DeploymentFailure(
                                    f"server monitor stop was not acknowledged: {exc}"
                                ) from exc
                        except Exception as exc:
                            try:
                                await asyncio.wait_for(
                                    clear_server_cache(snapshot["name"]), timeout=30
                                )
                            except Exception:
                                pass
                            raise DeploymentFailure(
                                f"server monitor stop was not acknowledged: {exc}"
                            ) from exc
                    else:
                        await asyncio.wait_for(clear_server_cache(snapshot["name"]), timeout=30)
                        monitor_ack = {
                            "status": "monitor_not_configured",
                            "agent_api": None,
                        }
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
                    validator_ack = (
                        await self._decommission_validator_server(operation)
                        if getattr(operation, "validator_server_decommission_request", None)
                        is not None
                        else await self._delete_validator_server(operation)
                    )
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
                    operation = current
                await self._record_parent_allocation_release(operation_id)
            async with get_session() as session:
                # The placement trigger prevents new children once this operation exists;
                # refetch here still catches a transaction that committed before the fence.
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
                                .with_for_update(of=Server)
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
                            or parent.kubernetes_node_generation != snapshot.get("node_generation")
                        ):
                            raise DeploymentFailure("server parent lineage changed")
                    parent_gpu_rows = (
                        (
                            await session.execute(
                                select(GPU)
                                .where(GPU.server_id == current.parent_id)
                                .order_by(GPU.gpu_id)
                                .with_for_update(of=GPU)
                            )
                        )
                        .unique()
                        .scalars()
                        .all()
                    )
                    _assert_parent_allocation_released(
                        current,
                        parent,
                        parent_gpu_rows,
                    )
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
                            .with_for_update(of=Chute)
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
                current.next_retry_at = None
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
                if current and current.retry_lease_owner == self.worker_id:
                    current.last_failure = f"{type(exc).__name__}: {exc}"[:8000]
                    current.retry_lease_owner = None
                    current.retry_lease_expires_at = None
                    current.next_retry_at = retry_at(current.attempt_count)
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
            server = (
                (
                    await session.execute(
                        select(Server)
                        .where(Server.name == cluster_context)
                        .with_for_update(of=Server)
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            if server is None:
                raise DeploymentFailure("orphan cleanup has no stable server lineage")
            # Placement serializes on this same Server row before inserting a
            # Deployment. Recheck only after owning that fence so a winning
            # concurrent launch cannot have its registry authority revoked.
            if await session.get(Deployment, deployment_id) is not None:
                return None
            context_sha256 = cluster_context_sha256(server)
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
                if (
                    existing.namespace != settings.namespace
                    or existing.cluster_context_sha256 != context_sha256
                    or existing.kubernetes_node_uid != server.kubernetes_node_uid
                    or existing.kubernetes_node_generation != server.kubernetes_node_generation
                    or existing.immutable_labels != immutable_labels
                ):
                    raise LineageConflict(
                        "duplicate orphan request changed its immutable authority"
                    )
                config_id = existing.immutable_labels.get("chutes/config-id")
            else:
                config_id = immutable_labels.get("chutes/config-id")
            if settings.gpu_tee_only and not config_id:
                raise DeploymentFailure(
                    "GPU TEE orphan cleanup lacks exact registry config authority"
                )
            if config_id and settings.gpu_tee_only:
                # An orphan is deletion authority too. Fence registry pulls in
                # the same transaction that creates (or rediscovers) its
                # durable tombstone so a later lineage conflict cannot strand
                # an active scope outside the retry outbox.
                await request_registry_scope_revocation_in_session(
                    session,
                    launch_config_id=config_id,
                    validator=server.validator,
                    server_id=server.server_id,
                    deployment_id=deployment_id,
                )
            if existing:
                await session.commit()
                return existing.tombstone_id
            tombstone = KubernetesOrphanTombstone(
                tombstone_id=str(uuid.uuid4()),
                deployment_id=deployment_id,
                cluster_context=cluster_context,
                cluster_context_sha256=context_sha256,
                namespace=settings.namespace,
                kubernetes_node_uid=server.kubernetes_node_uid,
                kubernetes_node_generation=server.kubernetes_node_generation,
                phase="recorded",
                immutable_labels=immutable_labels,
            )
            session.add(tombstone)
            await session.commit()
            return tombstone.tombstone_id

    @staticmethod
    def _terminal_orphan_registry_ack(
        intent: RegistryScopeIntent | None,
        *,
        launch_config_id: str,
        validator: str,
        server_id: str,
        deployment_id: str,
    ) -> dict[str, Any] | None:
        """Validate exact durable registry closure, returning its stable ACK."""

        if intent is None:
            return None
        if any(
            getattr(intent, field) != value
            for field, value in {
                "launch_config_id": launch_config_id,
                "validator": validator,
                "server_id": server_id,
                "deployment_id": deployment_id,
            }.items()
        ):
            raise LineageConflict("orphan registry revocation authority changed")
        if intent.desired_state != "revoked" or intent.phase != "revoked":
            return None
        expected = {
            "status": "revoked",
            "revoked": True,
            "launch_config_id": launch_config_id,
            "server_id": server_id,
        }
        if intent.revocation_ack != expected or intent.revoked_at is None:
            raise DeploymentFailure("orphan registry revocation ACK is malformed")
        return expected

    async def _ensure_orphan_registry_revoked(
        self,
        tombstone: KubernetesOrphanTombstone,
    ) -> dict[str, Any] | None:
        """Replay pending orphan revocation or consume its already durable ACK."""

        launch_config_id = tombstone.immutable_labels.get("chutes/config-id")
        if not settings.gpu_tee_only:
            return None
        if not launch_config_id:
            raise LineageConflict("GPU TEE orphan lacks exact registry config authority")
        async with get_session() as session:
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
                raise LineageConflict(
                    "orphan cluster/node lineage changed before registry revocation"
                )
            validator = server.validator
            server_id = server.server_id
            intent = await session.get(RegistryScopeIntent, launch_config_id)
            durable_ack = self._terminal_orphan_registry_ack(
                intent,
                launch_config_id=launch_config_id,
                validator=validator,
                server_id=server_id,
                deployment_id=tombstone.deployment_id,
            )
            if durable_ack is not None:
                return durable_ack
        try:
            return await self._revoke_registry_identity(
                launch_config_id=launch_config_id,
                validator_hotkey=validator,
                server_id=server_id,
                deployment_id=tombstone.deployment_id,
            )
        except Exception as exc:
            try:
                await record_registry_scope_failure(launch_config_id, exc)
            except Exception as record_exc:
                logger.warning(
                    "Could not annotate orphan registry revocation intent {}: {}",
                    launch_config_id,
                    record_exc,
                )
            raise

    async def _ensure_orphan_pod_finalizers(
        self,
        tombstone_id: str,
        phase: str,
    ) -> None:
        async with get_session() as session:
            tombstone = await session.get(KubernetesOrphanTombstone, tombstone_id)
            resources = list(
                (
                    await session.execute(
                        select(KubernetesOrphanTombstoneResource).where(
                            KubernetesOrphanTombstoneResource.tombstone_id == tombstone_id,
                            KubernetesOrphanTombstoneResource.kind == "Pod",
                            KubernetesOrphanTombstoneResource.state != "absent",
                            KubernetesOrphanTombstoneResource.pod_teardown_finalizer_attached_at.is_(
                                None
                            ),
                        )
                    )
                ).scalars()
            )
        if tombstone is None:
            raise DeploymentFailure("orphan tombstone disappeared before Pod fencing")
        for resource in resources:
            outcome = await asyncio.to_thread(
                self.kubernetes.ensure_pod_teardown_finalizer,
                cluster_context=tombstone.cluster_context,
                namespace=tombstone.namespace,
                name=resource.name,
                uid=resource.uid,
                node_name=resource.node_name,
            )
            async with get_session() as session:
                current_tombstone = await session.get(
                    KubernetesOrphanTombstone,
                    tombstone_id,
                    with_for_update=True,
                )
                current = await session.get(
                    KubernetesOrphanTombstoneResource,
                    resource.resource_id,
                    with_for_update=True,
                )
                if (
                    current_tombstone is None
                    or current_tombstone.retry_lease_owner != self.worker_id
                    or current_tombstone.phase != phase
                    or current is None
                    or current.tombstone_id != tombstone_id
                    or current.uid != resource.uid
                ):
                    raise DeploymentFailure("orphan changed during Pod finalizer attachment")
                if outcome == "retryable":
                    raise DeploymentFailure(
                        f"orphan Pod finalizer attach raced a Kubernetes update: {resource.uid}"
                    )
                if outcome not in {"attached", "present"}:
                    raise LineageConflict(
                        f"orphan Pod disappeared before teardown fence: {resource.uid}"
                    )
                current.pod_teardown_finalizer_attached_at = (
                    current.pod_teardown_finalizer_attached_at or utc_now()
                )
                current_tombstone.retry_lease_expires_at = utc_now() + timedelta(
                    seconds=LEASE_SECONDS
                )
                await session.commit()

    async def _close_orphan_pod(
        self,
        tombstone: KubernetesOrphanTombstone,
        resource: KubernetesOrphanTombstoneResource,
        live: ResourceIdentity | None,
    ) -> str | None:
        evidence = getattr(resource, "pod_termination_evidence", None)
        digest = getattr(resource, "pod_termination_evidence_sha256", None)
        if evidence is not None or digest is not None:
            _verified_pod_termination_evidence(resource)
        elif live is not None and live.pod_termination_evidence is not None:
            evidence = live.pod_termination_evidence
            digest = live.pod_termination_evidence_sha256
        else:
            return None
        if not getattr(resource, "pod_teardown_finalizer_attached_at", None):
            raise LineageConflict("orphan Pod terminal evidence predates finalizer")

        async with get_session() as session:
            current_tombstone = await session.get(
                KubernetesOrphanTombstone,
                tombstone.tombstone_id,
                with_for_update=True,
            )
            current = await session.get(
                KubernetesOrphanTombstoneResource,
                resource.resource_id,
                with_for_update=True,
            )
            if (
                current_tombstone is None
                or current_tombstone.retry_lease_owner != self.worker_id
                or current_tombstone.phase != "verifying"
                or current is None
                or current.tombstone_id != tombstone.tombstone_id
                or current.uid != resource.uid
                or current.state == "absent"
            ):
                raise DeploymentFailure("orphan changed before Pod terminal evidence")
            if not current.pod_teardown_finalizer_attached_at:
                raise LineageConflict("orphan Pod evidence has no durable finalizer")
            if current.pod_termination_evidence is not None and (
                current.pod_termination_evidence != evidence
                or current.pod_termination_evidence_sha256 != digest
            ):
                raise LineageConflict("orphan Pod terminal evidence changed")
            current.pod_termination_evidence = evidence
            current.pod_termination_evidence_sha256 = digest
            current.pod_teardown_finalizer_removal_requested_at = (
                current.pod_teardown_finalizer_removal_requested_at or utc_now()
            )
            current_tombstone.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
            await session.commit()

        outcome = await asyncio.to_thread(
            self.kubernetes.remove_pod_teardown_finalizer,
            cluster_context=tombstone.cluster_context,
            namespace=tombstone.namespace,
            name=resource.name,
            uid=resource.uid,
            node_name=resource.node_name,
        )
        async with get_session() as session:
            current_tombstone = await session.get(
                KubernetesOrphanTombstone,
                tombstone.tombstone_id,
                with_for_update=True,
            )
            current = await session.get(
                KubernetesOrphanTombstoneResource,
                resource.resource_id,
                with_for_update=True,
            )
            if (
                current_tombstone is None
                or current_tombstone.retry_lease_owner != self.worker_id
                or current_tombstone.phase != "verifying"
                or current is None
                or current.tombstone_id != tombstone.tombstone_id
                or current.uid != resource.uid
                or current.pod_termination_evidence != evidence
                or current.pod_termination_evidence_sha256 != digest
            ):
                raise DeploymentFailure("orphan changed during Pod finalizer removal")
            if outcome == "uid_changed":
                raise LineageConflict("same-name orphan Pod replaced during finalizer removal")
            if outcome == "retryable":
                raise DeploymentFailure("orphan Pod finalizer removal raced a Kubernetes update")
            current.pod_teardown_finalizer_removed_at = (
                current.pod_teardown_finalizer_removed_at or utc_now()
            )
            resource.pod_termination_evidence = evidence
            resource.pod_termination_evidence_sha256 = digest
            resource.pod_teardown_finalizer_removal_requested_at = (
                current.pod_teardown_finalizer_removal_requested_at
            )
            resource.pod_teardown_finalizer_removed_at = current.pod_teardown_finalizer_removed_at
            if outcome == "absent":
                current.state = "absent"
                current.absent_at = current.absent_at or utc_now()
                resource.state = "absent"
            current_tombstone.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
            await session.commit()
        return outcome

    async def _adopt_orphan_replacement(
        self,
        tombstone_id: str,
        live: ResourceIdentity,
        *,
        predecessor_resource_id: str | None = None,
    ) -> None:
        """Atomically bind an orphan successor and resume UID-scoped deletion."""
        async with get_session() as session:
            tombstone = await session.get(
                KubernetesOrphanTombstone,
                tombstone_id,
                with_for_update=True,
            )
            if (
                tombstone is None
                or tombstone.retry_lease_owner != self.worker_id
                or tombstone.phase != "verifying"
            ):
                raise DeploymentFailure("orphan changed during replacement adoption")
            successor = (
                await session.execute(
                    select(KubernetesOrphanTombstoneResource)
                    .where(
                        KubernetesOrphanTombstoneResource.tombstone_id == tombstone_id,
                        KubernetesOrphanTombstoneResource.kind == live.kind,
                        KubernetesOrphanTombstoneResource.uid == live.uid,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if successor is None:
                successor = KubernetesOrphanTombstoneResource(
                    resource_id=str(uuid.uuid4()),
                    tombstone_id=tombstone_id,
                    api_version=live.api_version,
                    kind=live.kind,
                    name=live.name,
                    uid=live.uid,
                    owner_api_version=live.owner_api_version,
                    owner_kind=live.owner_kind,
                    owner_name=live.owner_name,
                    owner_uid=live.owner_uid,
                    node_name=live.node_name,
                    labels=live.labels,
                    labels_sha256=live.labels_sha256,
                )
                session.add(successor)
            if predecessor_resource_id:
                predecessor = await session.get(
                    KubernetesOrphanTombstoneResource,
                    predecessor_resource_id,
                    with_for_update=True,
                )
                if predecessor is None or predecessor.tombstone_id != tombstone_id:
                    raise DeploymentFailure("orphan replacement predecessor changed")
                if getattr(predecessor, "kind", None) == "Pod" and not _pod_absence_proven(
                    predecessor
                ):
                    raise LineageConflict(
                        "same-name orphan Pod replaced before exact termination closure"
                    )
                predecessor.state = "absent"
                predecessor.absent_at = utc_now()
            tombstone.phase = "deleting"
            tombstone.retry_lease_expires_at = utc_now() + timedelta(seconds=LEASE_SECONDS)
            tombstone.last_failure = None
            await session.commit()

    async def run_orphan(self, tombstone_id: str) -> bool:
        async with self._run_lock("orphan", tombstone_id):
            marker = self._claim_owner.set(f"{self.worker_id}:{uuid.uuid4()}")
            try:
                return await self._run_orphan_claimed(tombstone_id)
            finally:
                self._claim_owner.reset(marker)

    async def _complete_orphan_in_session(
        self,
        session: Any,
        tombstone: KubernetesOrphanTombstone,
    ) -> None:
        """Commit orphan closure behind the placement Server-row fence."""

        # Placement owns this same Server row before it can examine an orphan
        # tombstone, registry authority, or insert Deployment. Lock it first
        # here as well so absence and terminalization are one serializable
        # decision at the application fence.
        server = (
            (
                await session.execute(
                    select(Server)
                    .where(Server.name == tombstone.cluster_context)
                    .with_for_update(of=Server)
                )
            )
            .unique()
            .scalar_one_or_none()
        )
        current = (
            await session.execute(
                select(KubernetesOrphanTombstone)
                .where(KubernetesOrphanTombstone.tombstone_id == tombstone.tombstone_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if (
            current is None
            or current.retry_lease_owner != self.worker_id
            or current.phase != "verifying"
            or current.deployment_id != tombstone.deployment_id
            or current.cluster_context != tombstone.cluster_context
            or current.namespace != tombstone.namespace
            or current.immutable_labels != tombstone.immutable_labels
        ):
            raise DeploymentFailure("orphan lease changed before completion")
        if (
            server is None
            or server.kubernetes_node_uid != current.kubernetes_node_uid
            or server.kubernetes_node_generation != current.kubernetes_node_generation
            or cluster_context_sha256(server) != current.cluster_context_sha256
        ):
            raise LineageConflict("orphan cluster/node lineage changed before completion")
        # Server is the insertion fence for every supported placement path.
        # An unlocked MVCC read is deliberate: a normal teardown may already
        # own the Deployment row while waiting for Server, and waiting back on
        # that row would create Deployment -> Server / Server -> Deployment.
        deployment_id = await session.scalar(
            select(Deployment.deployment_id).where(
                Deployment.deployment_id == current.deployment_id
            )
        )
        if deployment_id is not None:
            raise LineageConflict("local Deployment appeared before orphan completion")
        config_id = current.immutable_labels.get("chutes/config-id")
        if config_id and settings.gpu_tee_only:
            registry_intent = await session.get(
                RegistryScopeIntent,
                config_id,
                with_for_update=True,
            )
            if (
                self._terminal_orphan_registry_ack(
                    registry_intent,
                    launch_config_id=config_id,
                    validator=server.validator,
                    server_id=server.server_id,
                    deployment_id=current.deployment_id,
                )
                is None
            ):
                raise DeploymentFailure("orphan completion is awaiting registry revocation ACK")
        all_resources = list(
            (
                await session.execute(
                    select(KubernetesOrphanTombstoneResource)
                    .where(KubernetesOrphanTombstoneResource.tombstone_id == tombstone.tombstone_id)
                    .with_for_update()
                )
            ).scalars()
        )
        if any(
            resource.state != "absent"
            or (resource.kind == "Pod" and not _pod_absence_proven(resource))
            for resource in all_resources
        ):
            raise DeploymentFailure("orphan completion lacks exact Kubernetes UID closure")
        current.phase = "completed"
        current.completed_at = utc_now()
        current.retry_lease_owner = None
        current.retry_lease_expires_at = None
        current.next_retry_at = None
        current.last_failure = None

    async def _run_orphan_claimed(self, tombstone_id: str) -> bool:
        now = utc_now()
        async with get_session() as session:
            tombstone = await session.get(
                KubernetesOrphanTombstone,
                tombstone_id,
                with_for_update=True,
            )
            if tombstone is None or tombstone.phase == "completed":
                return bool(tombstone)
            next_retry_at = getattr(tombstone, "next_retry_at", None)
            if next_retry_at is not None and next_retry_at > now:
                return False
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
            tombstone.next_retry_at = None
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
                accepted: dict[str, tuple[str, str, str]] = {}
                pending = list(resources)
                changed = True
                while changed:
                    changed = False
                    for resource in list(pending):
                        try:
                            replacement_matches(
                                expected_labels=tombstone.immutable_labels,
                                expected_node_name=tombstone.cluster_context,
                                accepted_owners=accepted,
                                resource=resource,
                            )
                        except UnresolvedOwnerLineage:
                            continue
                        _accept_owner(accepted, resource)
                        pending.remove(resource)
                        changed = True
                if pending:
                    raise UnresolvedOwnerLineage(
                        "orphan owner lineage was not observed in one direct list"
                    )
                async with get_session() as session:
                    current = await session.get(
                        KubernetesOrphanTombstone,
                        tombstone_id,
                        with_for_update=True,
                    )
                    known = {
                        (item.kind, item.uid)
                        for item in (
                            await session.execute(
                                select(KubernetesOrphanTombstoneResource).where(
                                    KubernetesOrphanTombstoneResource.tombstone_id == tombstone_id
                                )
                            )
                        ).scalars()
                    }
                    for resource in resources:
                        if (resource.kind, resource.uid) in known:
                            continue
                        session.add(
                            KubernetesOrphanTombstoneResource(
                                resource_id=str(uuid.uuid4()),
                                tombstone_id=tombstone_id,
                                api_version=resource.api_version,
                                kind=resource.kind,
                                name=resource.name,
                                uid=resource.uid,
                                owner_api_version=resource.owner_api_version,
                                owner_kind=resource.owner_kind,
                                owner_name=resource.owner_name,
                                owner_uid=resource.owner_uid,
                                node_name=resource.node_name,
                                labels=resource.labels,
                                labels_sha256=resource.labels_sha256,
                            )
                        )
                    await session.commit()
                await self._ensure_orphan_pod_finalizers(tombstone_id, "recorded")
                async with get_session() as session:
                    current = await session.get(
                        KubernetesOrphanTombstone,
                        tombstone_id,
                        with_for_update=True,
                    )
                    if current.retry_lease_owner != self.worker_id or current.phase != "recorded":
                        raise DeploymentFailure("orphan changed after Pod finalizer attachment")
                    current.phase = "deleting"
                    await session.commit()
                return await self._run_orphan_claimed(tombstone_id)

            async with get_session() as session:
                resources = list(
                    (
                        await session.execute(
                            select(KubernetesOrphanTombstoneResource).where(
                                KubernetesOrphanTombstoneResource.tombstone_id == tombstone_id,
                            )
                        )
                    ).scalars()
                )
            if tombstone.phase == "deleting":
                await self._ensure_orphan_pod_finalizers(tombstone_id, "deleting")
                for resource in sorted(
                    (
                        resource
                        for resource in resources
                        if resource.state == "observed"
                        and _resource_delete_ready(resource, resources)
                    ),
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
                        if outcome == "absent" and (
                            current.kind != "Pod" or _pod_absence_proven(current)
                        ):
                            current.state = "absent"
                            current.absent_at = utc_now()
                            resource.state = "absent"
                        elif outcome == "delete_requested":
                            current.state = "delete_requested"
                            resource.state = "delete_requested"
                        await session.commit()
                async with get_session() as session:
                    current = await session.get(
                        KubernetesOrphanTombstone,
                        tombstone_id,
                        with_for_update=True,
                    )
                    current.phase = "verifying"
                    await session.commit()
                return await self._run_orphan_claimed(tombstone_id)

            accepted_owners = {
                resource.uid: (resource.api_version, resource.kind, resource.name)
                for resource in resources
            }
            delete_needed = False
            absence_pending = False
            for resource in sorted(
                resources,
                key=lambda item: (VERIFY_ORDER[item.kind], item.name, item.uid),
            ):
                if resource.state == "absent":
                    if resource.kind == "Pod" and not _pod_absence_proven(resource):
                        raise LineageConflict(
                            "terminal orphan Pod row lacks exact termination closure"
                        )
                    continue
                live = await asyncio.to_thread(
                    self.kubernetes.read_resource,
                    cluster_context=tombstone.cluster_context,
                    namespace=tombstone.namespace,
                    kind=resource.kind,
                    name=resource.name,
                )
                await self._renew_orphan_lease(tombstone_id, "verifying")
                if live is None:
                    if resource.kind == "Pod":
                        if (
                            resource.pod_termination_evidence is not None
                            and resource.pod_teardown_finalizer_removal_requested_at
                        ):
                            await self._close_orphan_pod(tombstone, resource, None)
                            continue
                        raise LineageConflict(
                            f"orphan Pod {resource.uid} is absent without terminal evidence"
                        )
                    async with get_session() as session:
                        current = await session.get(
                            KubernetesOrphanTombstoneResource,
                            resource.resource_id,
                            with_for_update=True,
                        )
                        current.state = "absent"
                        current.absent_at = utc_now()
                        await session.commit()
                    resource.state = "absent"
                    continue
                if live.uid == resource.uid:
                    if resource.kind == "Pod":
                        outcome = await self._close_orphan_pod(
                            tombstone,
                            resource,
                            live,
                        )
                        if outcome is not None:
                            if resource.state != "absent":
                                absence_pending = True
                            continue
                    if resource.state == "observed" and _resource_delete_ready(resource, resources):
                        delete_needed = True
                    else:
                        absence_pending = True
                    continue
                if resource.kind == "Pod" and not _pod_absence_proven(resource):
                    raise LineageConflict(
                        "same-name orphan Pod appeared before predecessor termination closure"
                    )
                replacement_matches(
                    expected_labels=tombstone.immutable_labels,
                    expected_node_name=tombstone.cluster_context,
                    accepted_owners=accepted_owners,
                    resource=live,
                )
                await self._adopt_orphan_replacement(
                    tombstone_id,
                    live,
                    predecessor_resource_id=resource.resource_id,
                )
                return await self._run_orphan_claimed(tombstone_id)
            current_resources = await asyncio.to_thread(
                self.kubernetes.list_resources,
                cluster_context=tombstone.cluster_context,
                namespace=tombstone.namespace,
                deployment_id=tombstone.deployment_id,
                config_id=tombstone.immutable_labels.get("chutes/config-id"),
            )
            await self._renew_orphan_lease(tombstone_id, "verifying")
            known_uids = {resource.uid for resource in resources}
            for resource in sorted(
                current_resources,
                key=lambda item: (VERIFY_ORDER[item.kind], item.name, item.uid),
            ):
                if resource.uid in known_uids:
                    absence_pending = True
                    continue
                replacement_matches(
                    expected_labels=tombstone.immutable_labels,
                    expected_node_name=tombstone.cluster_context,
                    accepted_owners=accepted_owners,
                    resource=resource,
                )
                await self._adopt_orphan_replacement(tombstone_id, resource)
                return await self._run_orphan_claimed(tombstone_id)
            if delete_needed:
                async with get_session() as session:
                    current = await session.get(
                        KubernetesOrphanTombstone,
                        tombstone_id,
                        with_for_update=True,
                    )
                    current.phase = "deleting"
                    await session.commit()
                return await self._run_orphan_claimed(tombstone_id)
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
                        current.next_retry_at = retry_at(current.attempt_count)
                        await session.commit()
                return False
            # Kubernetes absence is not terminal while registry pull authority
            # remains live. The durable outbox was written with the tombstone;
            # consume its ACK or replay the exact idempotent revoke now.
            await self._ensure_orphan_registry_revoked(tombstone)
            async with get_session() as session:
                await self._complete_orphan_in_session(session, tombstone)
                await session.commit()
            return True
        except Exception as exc:
            async with get_session() as session:
                current = await session.get(
                    KubernetesOrphanTombstone,
                    tombstone_id,
                    with_for_update=True,
                )
                if current and current.retry_lease_owner == self.worker_id:
                    current.last_failure = f"{type(exc).__name__}: {exc}"[:8000]
                    if isinstance(exc, LineageConflict):
                        current.lineage_conflict_at = utc_now()
                    current.retry_lease_owner = None
                    current.retry_lease_expires_at = None
                    current.next_retry_at = (
                        None
                        if isinstance(exc, LineageConflict)
                        else retry_at(current.attempt_count)
                    )
                    await session.commit()
            logger.warning(f"Orphan tombstone {tombstone_id} paused: {exc}")
            return False
