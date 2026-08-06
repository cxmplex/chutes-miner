"""Durable teardown must be the only route that releases miner GPU ownership."""

from pathlib import Path

import chutes_common.schemas.orms  # noqa: F401
from chutes_common.schemas import Base
from sqlalchemy.orm import configure_mappers


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = (
    ROOT / "src/chutes-miner/chutes_miner/api/migrations/"
    "20260726120000_durable_deployment_teardown.sql"
)
FOLLOWUP_MIGRATION = (
    ROOT / "src/chutes-miner/chutes_miner/api/migrations/"
    "20260727120000_miner_lifecycle_followup.sql"
)
FRONTIER_MIGRATION = (
    ROOT / "src/chutes-miner/chutes_miner/api/migrations/"
    "20260730140000_teardown_frontier_parent_hold.sql"
)


def _ondelete(table: str, column: str) -> str:
    foreign_key = next(iter(Base.metadata.tables[table].c[column].foreign_keys))
    return foreign_key.ondelete


def test_ownership_foreign_keys_are_restrictive_and_mappers_configure():
    configure_mappers()
    assert _ondelete("deployments", "server_id") == "RESTRICT"
    assert _ondelete("deployments", "chute_id") == "RESTRICT"
    assert _ondelete("gpus", "server_id") == "RESTRICT"
    assert _ondelete("gpus", "deployment_id") == "RESTRICT"
    assert _ondelete("deployments", "teardown_operation_id") == "RESTRICT"
    assert _ondelete("deployments", "launch_operation_id") == "RESTRICT"


def test_teardown_operation_outlives_deployment_and_has_normalized_closures():
    operation = Base.metadata.tables["deployment_teardown_operations"]
    assert not operation.c.deployment_id.foreign_keys
    assert {
        "registry_revocation_ack",
        "registry_revoked_at",
        "validator_job_release_ack",
        "validator_job_released_at",
        "validator_instance_deletion_ack",
        "validator_instance_deleted_at",
        "controllers_absent_at",
        "services_absent_at",
        "pods_absent_at",
        "pull_secret_deletion_ack",
        "pull_secret_deleted_at",
        "lineage_conflict_at",
        "registration_attestation_id",
        "gpu_allocation_group_id",
        "gpu_allocation_group_generation",
        "launch_operation_id",
        "launch_phase_at_request",
        "launch_kubernetes_mutation_possible",
        "launch_create_results_sha256",
        "launch_frontier",
        "launch_frontier_sha256",
        "resource_discovery",
        "resource_discovery_sha256",
        "resource_discovered_at",
        "pod_lifecycle_evidence",
        "pod_lifecycle_evidence_sha256",
        "pod_lifecycle_evidence_recorded_at",
    }.issubset(operation.c.keys())
    assert _ondelete("deployment_teardown_operations", "launch_operation_id") == "RESTRICT"
    assert "parent_deletion_children" in Base.metadata.tables
    resource = Base.metadata.tables["deployment_teardown_k8s_resources"]
    assert {
        "owner_api_version",
        "owner_kind",
        "owner_name",
        "owner_uid",
        "node_name",
        "pod_termination_evidence",
        "pod_termination_evidence_sha256",
        "pod_uid_absence_evidence",
        "pod_uid_absence_evidence_sha256",
        "pod_uid_absence_observed_at",
        "pod_already_terminating",
        "pod_teardown_finalizer_attached_at",
        "pod_teardown_finalizer_removal_requested_at",
        "pod_teardown_finalizer_removed_at",
    }.issubset(resource.c.keys())
    unique_columns = {
        tuple(column.name for column in constraint.columns)
        for constraint in resource.constraints
        if constraint.name == "deployment_teardown_resource_uid_key"
    }
    assert unique_columns == {("operation_id", "cluster_context", "namespace", "kind", "uid")}
    handoff = Base.metadata.tables["deployment_teardown_node_incarnation_handoffs"]
    assert _ondelete("deployment_teardown_node_incarnation_handoffs", "operation_id") == "RESTRICT"
    assert {
        "from_kubernetes_node_uid",
        "from_kubernetes_node_generation",
        "from_registration_attestation_id",
        "from_gpu_allocation_group_id",
        "from_gpu_allocation_group_generation",
        "from_cluster_context_sha256",
        "to_kubernetes_node_uid",
        "to_kubernetes_node_generation",
        "to_registration_attestation_id",
        "to_gpu_allocation_group_id",
        "to_gpu_allocation_group_generation",
        "to_cluster_context_sha256",
    }.issubset(handoff.c.keys())
    parent = Base.metadata.tables["parent_deletion_operations"]
    assert {
        "allocation_release_evidence",
        "allocation_release_evidence_sha256",
        "allocation_release_verified_at",
    }.issubset(parent.c.keys())


def test_launch_fence_and_delayed_instance_cleanup_outlive_deployment():
    launch = Base.metadata.tables["deployment_launch_operations"]
    assert not launch.c.deployment_id.foreign_keys
    assert {
        "phase",
        "lease_owner",
        "lease_expires_at",
        "service_uid",
        "secret_uid",
        "job_uid",
        "create_results",
        "cluster_context",
        "cluster_context_sha256",
        "namespace",
        "server_name",
        "canonical_workload_spec",
        "canonical_workload_spec_sha256",
        "launch_intent_id",
    }.issubset(launch.c.keys())
    cleanup = Base.metadata.tables["delayed_validator_instance_cleanups"]
    assert (
        _ondelete("delayed_validator_instance_cleanups", "source_teardown_operation_id")
        == "RESTRICT"
    )
    assert {"validator", "chute_id", "config_id", "instance_id", "deletion_ack"}.issubset(
        cleanup.c.keys()
    )


def test_miner_launch_intent_is_durable_and_has_one_active_lineage():
    intent = Base.metadata.tables["miner_launch_intents"]
    assert {
        "intent_id",
        "phase",
        "validator",
        "chute_id",
        "chute_version",
        "server_id",
        "job_id",
        "job_cleanup_only",
        "request_payload",
        "request_sha256",
        "lineage_sha256",
        "response_payload",
        "response_sha256",
        "token_sha256",
        "authorized_token_sha256s",
        "registry_ack",
        "job_release_ack",
        "job_released_at",
        "deployment_id",
        "retry_lease_owner",
        "retry_lease_expires_at",
        "attempt_count",
        "next_retry_at",
        "last_failure",
        "completed_at",
    }.issubset(intent.c.keys())
    active_index = next(
        index for index in intent.indexes if index.name == "miner_launch_intent_active_lineage_key"
    )
    assert active_index.unique
    assert "phase NOT IN ('completed', 'failed')" in str(
        active_index.dialect_options["postgresql"]["where"]
    )
    constraints = {
        constraint.name: str(constraint.sqltext)
        for constraint in intent.constraints
        if hasattr(constraint, "sqltext")
    }
    assert "ck_miner_launch_intent_retry_lease" in constraints
    assert "retry_lease_owner IS NULL" in constraints[
        "ck_miner_launch_intent_retry_lease"
    ]
    retry_index = next(
        index for index in intent.indexes if index.name == "miner_launch_intent_next_retry_idx"
    )
    assert [column.name for column in retry_index.columns] == [
        "next_retry_at",
        "retry_lease_expires_at",
        "created_at",
    ]
    assert _ondelete("deployment_launch_operations", "launch_intent_id") == "RESTRICT"


def test_migration_guards_release_and_has_migration_specific_down_guard():
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "deployments_require_teardown" in sql
    assert "gpus_require_teardown" in sql
    assert "servers_require_parent_deletion" in sql
    assert "chutes_require_parent_deletion" in sql
    assert "deployments_fence_parent_deletion" in sql
    assert "deployment_launch_recovery_idx" in sql
    assert "deployment_teardown_node_incarnation_handoffs" in sql
    assert "LOCK TABLE deployments, gpus, servers, chutes" in sql
    assert "cannot remove durable teardown schema while teardown history exists" in sql
    assert "phase IN ('finalizing', 'completed')" in sql
    assert "'blocked'" not in sql


def test_orphan_tombstone_binds_cluster_and_node_lineage():
    table = Base.metadata.tables["kubernetes_orphan_tombstones"]
    assert {
        "cluster_context",
        "cluster_context_sha256",
        "kubernetes_node_uid",
        "kubernetes_node_generation",
        "lineage_conflict_at",
    }.issubset(table.c.keys())
    resource = Base.metadata.tables["kubernetes_orphan_tombstone_resources"]
    assert {
        "pod_termination_evidence",
        "pod_termination_evidence_sha256",
        "pod_teardown_finalizer_attached_at",
        "pod_teardown_finalizer_removal_requested_at",
        "pod_teardown_finalizer_removed_at",
    }.issubset(resource.c.keys())
    assert "lineage_conflict_at" not in Base.metadata.tables["parent_deletion_operations"].c
    assert "owner_api_version" in Base.metadata.tables["kubernetes_orphan_tombstone_resources"].c


def test_followup_migration_has_specific_locked_down_guard():
    sql = FOLLOWUP_MIGRATION.read_text(encoding="utf-8")
    assert "IN ACCESS EXCLUSIVE MODE" in sql
    assert "canonical launch intents exist" in sql
    assert "owner_api_version" in sql
    assert "canonical_workload_spec_sha256" in sql
    assert "miner_launch_intent_active_lineage_key" in sql
    assert "launch intent history exists" in sql
    assert "validator job release history exists" in sql
    assert "deployment_teardown_closure_complete" in sql
    assert "deployment_teardown_resource_chain_closed" in sql
    assert "canonical_miner_teardown_jsonb" in sql
    assert "resource_discovery_sha256" in sql
    assert "launch_kubernetes_mutation_possible" in sql


def test_frontier_migration_guards_new_closure_and_parent_allocation():
    sql = FRONTIER_MIGRATION.read_text(encoding="utf-8")
    assert "chutes.miner-launch-frontier.v1" in sql
    assert "chutes.miner-pod-uid-absence.v1" in sql
    assert "chutes.miner-pod-lifecycle.v1" in sql
    assert "deployment_teardown_extended_closure_complete" in sql
    assert "'awaiting_registry'" in sql
    assert "fence_parent_allocation_ownership" in sql
    assert "gpus_fence_parent_allocation" in sql
    assert "servers_fence_parent_allocation" in sql
    assert "allocation_release_evidence_sha256" in sql
    assert "cannot remove teardown frontier authority while lifecycle history exists" in sql
