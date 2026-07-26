"""Durable teardown must be the only route that releases miner GPU ownership."""

from pathlib import Path

import chutes_common.schemas.orms  # noqa: F401
from chutes_common.schemas import Base
from sqlalchemy.orm import configure_mappers


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = (
    ROOT
    / "src/chutes-miner/chutes_miner/api/migrations/"
    "20260726120000_durable_deployment_teardown.sql"
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
    }.issubset(operation.c.keys())
    assert "parent_deletion_children" in Base.metadata.tables
    resource = Base.metadata.tables["deployment_teardown_k8s_resources"]
    assert {"owner_kind", "owner_name", "owner_uid", "node_name"}.issubset(
        resource.c.keys()
    )
    unique_columns = {
        tuple(column.name for column in constraint.columns)
        for constraint in resource.constraints
        if constraint.name == "deployment_teardown_resource_uid_key"
    }
    assert unique_columns == {
        ("operation_id", "cluster_context", "namespace", "kind", "uid")
    }
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
    }.issubset(launch.c.keys())
    cleanup = Base.metadata.tables["delayed_validator_instance_cleanups"]
    assert _ondelete(
        "delayed_validator_instance_cleanups", "source_teardown_operation_id"
    ) == "RESTRICT"
    assert {"validator", "chute_id", "config_id", "instance_id", "deletion_ack"}.issubset(
        cleanup.c.keys()
    )


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
    assert "lineage_conflict_at" not in Base.metadata.tables[
        "parent_deletion_operations"
    ].c
