"""Durable miner deployment and Kubernetes teardown state."""

from __future__ import annotations

import uuid

from chutes_common.schemas import Base
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func


def _uuid() -> str:
    return str(uuid.uuid4())


class DeploymentTeardownOperation(Base):
    """Restartable teardown whose ownership snapshot outlives Deployment."""

    __tablename__ = "deployment_teardown_operations"

    operation_id = Column(String, primary_key=True, default=_uuid)
    deployment_id = Column(String, nullable=False)
    phase = Column(String, nullable=False, default="requested", server_default="requested")
    reason = Column(String, nullable=False)
    retry_lease_owner = Column(String, nullable=True)
    retry_lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    attempt_count = Column(Integer, nullable=False, default=0, server_default="0")

    validator = Column(String, nullable=False)
    server_id = Column(String, nullable=False)
    chute_id = Column(String, nullable=False)
    config_id = Column(String, nullable=True)
    job_id = Column(String, nullable=True)
    instance_id = Column(String, nullable=True)
    cluster_context = Column(String, nullable=False)
    cluster_context_sha256 = Column(String, nullable=False)
    namespace = Column(String, nullable=False)
    kubernetes_node_uid = Column(String, nullable=True)
    kubernetes_node_generation = Column(Integer, nullable=False)
    registration_attestation_id = Column(String, nullable=True)
    gpu_allocation_group_id = Column(String, nullable=True)
    gpu_allocation_group_generation = Column(Integer, nullable=True)
    gpu_hardware_uuids = Column(JSONB, nullable=False)
    immutable_labels = Column(JSONB, nullable=False)

    registry_revocation_ack = Column(JSONB, nullable=True)
    registry_revoked_at = Column(DateTime(timezone=True), nullable=True)
    validator_job_release_ack = Column(JSONB, nullable=True)
    validator_job_released_at = Column(DateTime(timezone=True), nullable=True)
    validator_instance_deletion_ack = Column(JSONB, nullable=True)
    validator_instance_deleted_at = Column(DateTime(timezone=True), nullable=True)
    controllers_absent_at = Column(DateTime(timezone=True), nullable=True)
    services_absent_at = Column(DateTime(timezone=True), nullable=True)
    pods_absent_at = Column(DateTime(timezone=True), nullable=True)
    pull_secret_deletion_ack = Column(JSONB, nullable=True)
    pull_secret_deleted_at = Column(DateTime(timezone=True), nullable=True)
    lineage_conflict_at = Column(DateTime(timezone=True), nullable=True)
    last_failure = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)

    resources = relationship(
        "DeploymentTeardownK8sResource",
        back_populates="operation",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    node_incarnation_handoffs = relationship(
        "DeploymentTeardownNodeIncarnationHandoff",
        back_populates="operation",
        order_by="DeploymentTeardownNodeIncarnationHandoff.sequence",
        lazy="selectin",
    )

    __table_args__ = (
        CheckConstraint(
            "phase IN ('requested', 'discovering', 'revoking', 'deleting', "
            "'verifying', 'finalizing', 'completed')",
            name="ck_deployment_teardown_phase",
        ),
        CheckConstraint(
            "kubernetes_node_generation >= 0",
            name="ck_deployment_teardown_node_generation",
        ),
        CheckConstraint(
            "(gpu_allocation_group_id IS NULL "
            "AND gpu_allocation_group_generation IS NULL) OR "
            "(gpu_allocation_group_id IS NOT NULL "
            "AND gpu_allocation_group_generation IS NOT NULL "
            "AND gpu_allocation_group_generation > 0)",
            name="ck_deployment_teardown_allocation_group",
        ),
        Index(
            "deployment_teardown_active_deployment_idx",
            "deployment_id",
            unique=True,
            postgresql_where=text("phase <> 'completed'"),
        ),
        Index(
            "deployment_teardown_retry_idx",
            "phase",
            "retry_lease_expires_at",
            postgresql_where=text("phase <> 'completed'"),
        ),
        CheckConstraint(
            "(retry_lease_owner IS NULL) = (retry_lease_expires_at IS NULL)",
            name="ck_deployment_teardown_retry_lease",
        ),
        CheckConstraint(
            "(registry_revocation_ack IS NULL) = (registry_revoked_at IS NULL)",
            name="ck_deployment_teardown_registry_ack",
        ),
        CheckConstraint(
            "(validator_instance_deletion_ack IS NULL) = "
            "(validator_instance_deleted_at IS NULL)",
            name="ck_deployment_teardown_validator_ack",
        ),
        CheckConstraint(
            "(validator_job_release_ack IS NULL) = "
            "(validator_job_released_at IS NULL)",
            name="ck_deployment_teardown_job_ack",
        ),
        CheckConstraint(
            "(pull_secret_deletion_ack IS NULL) = (pull_secret_deleted_at IS NULL)",
            name="ck_deployment_teardown_secret_ack",
        ),
    )


class DeploymentTeardownNodeIncarnationHandoff(Base):
    """Attested node-incarnation transition accepted by an unfinished teardown."""

    __tablename__ = "deployment_teardown_node_incarnation_handoffs"

    handoff_id = Column(String, primary_key=True, default=_uuid)
    operation_id = Column(
        String,
        ForeignKey("deployment_teardown_operations.operation_id", ondelete="RESTRICT"),
        nullable=False,
    )
    sequence = Column(Integer, nullable=False)
    from_kubernetes_node_uid = Column(String, nullable=False)
    from_kubernetes_node_generation = Column(Integer, nullable=False)
    from_registration_attestation_id = Column(String, nullable=False)
    from_gpu_allocation_group_id = Column(String, nullable=False)
    from_gpu_allocation_group_generation = Column(Integer, nullable=False)
    from_cluster_context_sha256 = Column(String, nullable=False)
    to_kubernetes_node_uid = Column(String, nullable=False)
    to_kubernetes_node_generation = Column(Integer, nullable=False)
    to_registration_attestation_id = Column(String, nullable=False)
    to_gpu_allocation_group_id = Column(String, nullable=False)
    to_gpu_allocation_group_generation = Column(Integer, nullable=False)
    to_cluster_context_sha256 = Column(String, nullable=False)
    authorized_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    operation = relationship(
        "DeploymentTeardownOperation",
        back_populates="node_incarnation_handoffs",
    )

    __table_args__ = (
        CheckConstraint("sequence > 0", name="ck_teardown_node_handoff_sequence"),
        CheckConstraint(
            "from_kubernetes_node_generation > 0 "
            "AND to_kubernetes_node_generation > from_kubernetes_node_generation",
            name="ck_teardown_node_handoff_generation",
        ),
        CheckConstraint(
            "from_gpu_allocation_group_generation > 0 AND to_gpu_allocation_group_generation > 0",
            name="ck_teardown_node_handoff_group_generation",
        ),
        UniqueConstraint(
            "operation_id",
            "sequence",
            name="deployment_teardown_node_handoff_sequence_key",
        ),
        UniqueConstraint(
            "operation_id",
            "from_kubernetes_node_generation",
            name="deployment_teardown_node_handoff_from_generation_key",
        ),
        UniqueConstraint(
            "operation_id",
            "to_kubernetes_node_generation",
            name="deployment_teardown_node_handoff_to_generation_key",
        ),
    )


class DeploymentTeardownK8sResource(Base):
    """Exact Kubernetes UID closure observed for one teardown."""

    __tablename__ = "deployment_teardown_k8s_resources"

    resource_id = Column(String, primary_key=True, default=_uuid)
    operation_id = Column(
        String,
        ForeignKey("deployment_teardown_operations.operation_id", ondelete="CASCADE"),
        nullable=False,
    )
    cluster_context = Column(String, nullable=False)
    namespace = Column(String, nullable=False)
    api_version = Column(String, nullable=False)
    kind = Column(String, nullable=False)
    name = Column(String, nullable=False)
    uid = Column(String, nullable=False)
    owner_api_version = Column(String, nullable=True)
    owner_kind = Column(String, nullable=True)
    owner_name = Column(String, nullable=True)
    owner_uid = Column(String, nullable=True)
    node_name = Column(String, nullable=True)
    labels = Column(JSONB, nullable=False)
    labels_sha256 = Column(String, nullable=False)
    pod_termination_evidence = Column(JSONB, nullable=True)
    pod_termination_evidence_sha256 = Column(String, nullable=True)
    pod_teardown_finalizer_attached_at = Column(DateTime(timezone=True), nullable=True)
    pod_teardown_finalizer_removal_requested_at = Column(
        DateTime(timezone=True), nullable=True
    )
    pod_teardown_finalizer_removed_at = Column(DateTime(timezone=True), nullable=True)
    state = Column(
        String, nullable=False, default="observed", server_default="observed"
    )
    observed_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    delete_requested_at = Column(DateTime(timezone=True), nullable=True)
    absent_at = Column(DateTime(timezone=True), nullable=True)
    replaced_by_resource_id = Column(
        String,
        ForeignKey("deployment_teardown_k8s_resources.resource_id", ondelete="RESTRICT"),
        nullable=True,
    )

    operation = relationship("DeploymentTeardownOperation", back_populates="resources")

    __table_args__ = (
        CheckConstraint(
            "kind IN ('Job', 'Deployment', 'ReplicaSet', 'Service', 'Pod', 'Secret')",
            name="ck_deployment_teardown_resource_kind",
        ),
        CheckConstraint(
            "state IN ('observed', 'delete_requested', 'absent', 'replaced')",
            name="ck_deployment_teardown_resource_state",
        ),
        CheckConstraint(
            "((pod_termination_evidence IS NULL) = "
            "(pod_termination_evidence_sha256 IS NULL)) AND "
            "((pod_termination_evidence IS NULL) = "
            "(pod_teardown_finalizer_removal_requested_at IS NULL)) AND "
            "(kind = 'Pod' OR pod_termination_evidence IS NULL) AND "
            "(kind = 'Pod' OR (pod_teardown_finalizer_attached_at IS NULL AND "
            "pod_teardown_finalizer_removal_requested_at IS NULL AND "
            "pod_teardown_finalizer_removed_at IS NULL)) AND "
            "(pod_teardown_finalizer_removal_requested_at IS NULL OR "
            "pod_teardown_finalizer_attached_at IS NOT NULL) AND "
            "(pod_teardown_finalizer_removed_at IS NULL OR "
            "pod_teardown_finalizer_removal_requested_at IS NOT NULL) AND "
            "(kind <> 'Pod' OR state NOT IN ('absent', 'replaced') OR "
            "(pod_termination_evidence IS NOT NULL AND "
            "pod_teardown_finalizer_removed_at IS NOT NULL))",
            name="ck_deployment_teardown_resource_pod_termination",
        ),
        CheckConstraint(
            "pod_termination_evidence_sha256 IS NULL OR "
            "pod_termination_evidence_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_deployment_teardown_resource_pod_termination_sha256",
        ),
        CheckConstraint(
            "(owner_api_version IS NULL AND owner_kind IS NULL "
            "AND owner_name IS NULL AND owner_uid IS NULL) OR "
            "(owner_api_version IS NOT NULL AND owner_kind IS NOT NULL "
            "AND owner_name IS NOT NULL AND owner_uid IS NOT NULL)",
            name="ck_deployment_teardown_resource_owner",
        ),
        UniqueConstraint(
            "operation_id",
            "cluster_context",
            "namespace",
            "kind",
            "uid",
            name="deployment_teardown_resource_uid_key",
        ),
        Index(
            "deployment_teardown_resource_lookup_idx",
            "operation_id",
            "kind",
            "name",
        ),
    )


class DeploymentLaunchOperation(Base):
    """Durable fence around Kubernetes creation after GPU ownership is claimed."""

    __tablename__ = "deployment_launch_operations"

    operation_id = Column(String, primary_key=True, default=_uuid)
    deployment_id = Column(String, nullable=False, unique=True)
    phase = Column(String, nullable=False, default="reserved", server_default="reserved")
    lease_owner = Column(String, nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    immutable_labels = Column(JSONB, nullable=False)
    launch_intent_id = Column(
        String,
        ForeignKey("miner_launch_intents.intent_id", ondelete="RESTRICT"),
        nullable=True,
    )
    cluster_context = Column(String, nullable=True)
    cluster_context_sha256 = Column(String, nullable=True)
    namespace = Column(String, nullable=True)
    server_name = Column(String, nullable=True)
    canonical_workload_spec = Column(JSONB, nullable=True)
    canonical_workload_spec_sha256 = Column(String, nullable=True)
    service_name = Column(String, nullable=True)
    service_uid = Column(String, nullable=True)
    secret_name = Column(String, nullable=True)
    secret_uid = Column(String, nullable=True)
    job_name = Column(String, nullable=True)
    job_uid = Column(String, nullable=True)
    create_results = Column(JSONB, nullable=False, default=dict, server_default="{}")
    last_failure = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "phase IN ('reserved', 'creating', 'created', 'teardown_fenced', 'failed')",
            name="ck_deployment_launch_phase",
        ),
        CheckConstraint(
            "(lease_owner IS NULL) = (lease_expires_at IS NULL)",
            name="ck_deployment_launch_lease",
        ),
        CheckConstraint(
            "(canonical_workload_spec IS NULL) = "
            "(canonical_workload_spec_sha256 IS NULL)",
            name="ck_deployment_launch_canonical_workload",
        ),
        CheckConstraint(
            "canonical_workload_spec_sha256 IS NULL OR "
            "canonical_workload_spec_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_deployment_launch_canonical_workload_sha256",
        ),
        CheckConstraint(
            "cluster_context_sha256 IS NULL OR "
            "cluster_context_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_deployment_launch_cluster_context_sha256",
        ),
        CheckConstraint(
            "(service_name IS NULL) = (service_uid IS NULL)",
            name="ck_deployment_launch_service",
        ),
        CheckConstraint(
            "(secret_name IS NULL) = (secret_uid IS NULL)",
            name="ck_deployment_launch_secret",
        ),
        CheckConstraint(
            "(job_name IS NULL) = (job_uid IS NULL)",
            name="ck_deployment_launch_job",
        ),
        Index(
            "deployment_launch_recovery_idx",
            "phase",
            "lease_expires_at",
            postgresql_where=text("phase IN ('reserved', 'creating', 'failed')"),
        ),
        Index(
            "deployment_launch_intent_key",
            "launch_intent_id",
            unique=True,
            postgresql_where=text("launch_intent_id IS NOT NULL"),
        ),
    )


class MinerLaunchIntent(Base):
    """Local authority persisted before requesting a validator launch config."""

    __tablename__ = "miner_launch_intents"

    intent_id = Column(String, primary_key=True, default=_uuid)
    phase = Column(String, nullable=False, default="pending", server_default="pending")
    validator = Column(String, nullable=False)
    chute_id = Column(String, nullable=False)
    chute_version = Column(String, nullable=False)
    server_id = Column(String, nullable=False)
    job_id = Column(String, nullable=True)
    job_cleanup_only = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("FALSE"),
    )
    request_payload = Column(JSONB, nullable=False)
    request_sha256 = Column(String, nullable=False)
    lineage_sha256 = Column(String, nullable=False)
    response_payload = Column(JSONB, nullable=True)
    response_sha256 = Column(String, nullable=True)
    token_sha256 = Column(String, nullable=True)
    authorized_token_sha256s = Column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    registry_ack = Column(JSONB, nullable=True)
    job_release_ack = Column(JSONB, nullable=True)
    job_released_at = Column(DateTime(timezone=True), nullable=True)
    deployment_id = Column(String, nullable=True)
    last_failure = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "phase IN ('pending', 'response_persisted', 'registry_acked', "
            "'consumed', 'cleanup_required', 'completed', 'failed')",
            name="ck_miner_launch_intent_phase",
        ),
        CheckConstraint(
            "request_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_miner_launch_intent_request_sha256",
        ),
        CheckConstraint(
            "lineage_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_miner_launch_intent_lineage_sha256",
        ),
        CheckConstraint(
            "(response_payload IS NULL AND response_sha256 IS NULL "
            "AND token_sha256 IS NULL) OR "
            "(response_payload IS NOT NULL "
            "AND response_sha256 ~ '^[0-9a-f]{64}$' "
            "AND token_sha256 ~ '^[0-9a-f]{64}$')",
            name="ck_miner_launch_intent_response",
        ),
        CheckConstraint(
            "jsonb_typeof(authorized_token_sha256s) = 'array'",
            name="ck_miner_launch_intent_authorized_tokens",
        ),
        CheckConstraint(
            "(job_release_ack IS NULL) = (job_released_at IS NULL)",
            name="ck_miner_launch_intent_job_ack",
        ),
        CheckConstraint(
            "NOT job_cleanup_only OR (job_id IS NOT NULL "
            "AND response_payload IS NULL AND response_sha256 IS NULL "
            "AND token_sha256 IS NULL AND registry_ack IS NULL "
            "AND deployment_id IS NULL)",
            name="ck_miner_launch_intent_job_cleanup_only",
        ),
        Index(
            "miner_launch_intent_recovery_idx",
            "phase",
            "created_at",
            postgresql_where=text("phase NOT IN ('completed', 'failed')"),
        ),
        Index(
            "miner_launch_intent_active_lineage_key",
            "lineage_sha256",
            unique=True,
            postgresql_where=text("phase NOT IN ('completed', 'failed')"),
        ),
    )


class DelayedValidatorInstanceCleanup(Base):
    """Idempotent validator cleanup for instance-created events after local deletion."""

    __tablename__ = "delayed_validator_instance_cleanups"

    cleanup_id = Column(String, primary_key=True, default=_uuid)
    source_teardown_operation_id = Column(
        String,
        ForeignKey("deployment_teardown_operations.operation_id", ondelete="RESTRICT"),
        nullable=False,
    )
    validator = Column(String, nullable=False)
    chute_id = Column(String, nullable=False)
    config_id = Column(String, nullable=False)
    instance_id = Column(String, nullable=False)
    phase = Column(String, nullable=False, default="pending", server_default="pending")
    retry_lease_owner = Column(String, nullable=True)
    retry_lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    attempt_count = Column(Integer, nullable=False, default=0, server_default="0")
    deletion_ack = Column(JSONB, nullable=True)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    last_failure = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "config_id",
            "instance_id",
            name="delayed_validator_instance_cleanup_identity_key",
        ),
        CheckConstraint(
            "phase IN ('pending', 'completed')",
            name="ck_delayed_validator_instance_cleanup_phase",
        ),
        CheckConstraint(
            "(retry_lease_owner IS NULL) = (retry_lease_expires_at IS NULL)",
            name="ck_delayed_validator_instance_cleanup_lease",
        ),
        CheckConstraint(
            "(deletion_ack IS NULL) = (deleted_at IS NULL)",
            name="ck_delayed_validator_instance_cleanup_ack",
        ),
    )


class ParentDeletionOperation(Base):
    """Durable Server/Chute deletion that waits for child teardown."""

    __tablename__ = "parent_deletion_operations"

    operation_id = Column(String, primary_key=True, default=_uuid)
    parent_type = Column(String, nullable=False)
    parent_id = Column(String, nullable=False)
    validator = Column(String, nullable=False)
    reason = Column(String, nullable=False)
    phase = Column(String, nullable=False, default="requested", server_default="requested")
    retry_lease_owner = Column(String, nullable=True)
    retry_lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    attempt_count = Column(Integer, nullable=False, default=0, server_default="0")
    snapshot = Column(JSONB, nullable=False)
    monitor_stop_ack = Column(JSONB, nullable=True)
    monitor_stopped_at = Column(DateTime(timezone=True), nullable=True)
    validator_server_deletion_ack = Column(JSONB, nullable=True)
    validator_server_deleted_at = Column(DateTime(timezone=True), nullable=True)
    last_failure = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "parent_type IN ('server', 'chute')",
            name="ck_parent_deletion_type",
        ),
        CheckConstraint(
            "phase IN ('requested', 'waiting_for_children', 'finalizing', 'completed')",
            name="ck_parent_deletion_phase",
        ),
        Index(
            "parent_deletion_active_idx",
            "parent_type",
            "parent_id",
            unique=True,
            postgresql_where=text("phase <> 'completed'"),
        ),
        CheckConstraint(
            "(retry_lease_owner IS NULL) = (retry_lease_expires_at IS NULL)",
            name="ck_parent_deletion_retry_lease",
        ),
        CheckConstraint(
            "(monitor_stop_ack IS NULL) = (monitor_stopped_at IS NULL)",
            name="ck_parent_deletion_monitor_ack",
        ),
        CheckConstraint(
            "(validator_server_deletion_ack IS NULL) = "
            "(validator_server_deleted_at IS NULL)",
            name="ck_parent_deletion_validator_ack",
        ),
    )


class ParentDeletionChild(Base):
    """Normalized dependency from a parent deletion to child teardown."""

    __tablename__ = "parent_deletion_children"

    parent_operation_id = Column(
        String,
        ForeignKey("parent_deletion_operations.operation_id", ondelete="CASCADE"),
        primary_key=True,
    )
    child_operation_id = Column(
        String,
        ForeignKey("deployment_teardown_operations.operation_id", ondelete="RESTRICT"),
        primary_key=True,
    )
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class KubernetesOrphanTombstone(Base):
    """Deletion authority for Kubernetes objects lacking a local Deployment."""

    __tablename__ = "kubernetes_orphan_tombstones"

    tombstone_id = Column(String, primary_key=True, default=_uuid)
    deployment_id = Column(String, nullable=False)
    cluster_context = Column(String, nullable=False)
    cluster_context_sha256 = Column(String, nullable=False)
    namespace = Column(String, nullable=False)
    kubernetes_node_uid = Column(String, nullable=True)
    kubernetes_node_generation = Column(Integer, nullable=False)
    phase = Column(String, nullable=False, default="recorded", server_default="recorded")
    retry_lease_owner = Column(String, nullable=True)
    retry_lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    attempt_count = Column(Integer, nullable=False, default=0, server_default="0")
    immutable_labels = Column(JSONB, nullable=False)
    last_failure = Column(Text, nullable=True)
    lineage_conflict_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    resources = relationship(
        "KubernetesOrphanTombstoneResource",
        back_populates="tombstone",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    __table_args__ = (
        CheckConstraint(
            "phase IN ('recorded', 'deleting', 'verifying', 'completed')",
            name="ck_kubernetes_orphan_tombstone_phase",
        ),
        Index(
            "kubernetes_orphan_active_idx",
            "deployment_id",
            "cluster_context",
            unique=True,
            postgresql_where=text("phase <> 'completed'"),
        ),
        CheckConstraint(
            "kubernetes_node_generation >= 0",
            name="ck_kubernetes_orphan_node_generation",
        ),
        CheckConstraint(
            "(retry_lease_owner IS NULL) = (retry_lease_expires_at IS NULL)",
            name="ck_kubernetes_orphan_retry_lease",
        ),
    )


class KubernetesOrphanTombstoneResource(Base):
    __tablename__ = "kubernetes_orphan_tombstone_resources"

    resource_id = Column(String, primary_key=True, default=_uuid)
    tombstone_id = Column(
        String,
        ForeignKey("kubernetes_orphan_tombstones.tombstone_id", ondelete="CASCADE"),
        nullable=False,
    )
    api_version = Column(String, nullable=False)
    kind = Column(String, nullable=False)
    name = Column(String, nullable=False)
    uid = Column(String, nullable=False)
    owner_api_version = Column(String, nullable=True)
    owner_kind = Column(String, nullable=True)
    owner_name = Column(String, nullable=True)
    owner_uid = Column(String, nullable=True)
    node_name = Column(String, nullable=True)
    labels = Column(JSONB, nullable=False)
    labels_sha256 = Column(String, nullable=False)
    pod_termination_evidence = Column(JSONB, nullable=True)
    pod_termination_evidence_sha256 = Column(String, nullable=True)
    pod_teardown_finalizer_attached_at = Column(DateTime(timezone=True), nullable=True)
    pod_teardown_finalizer_removal_requested_at = Column(
        DateTime(timezone=True), nullable=True
    )
    pod_teardown_finalizer_removed_at = Column(DateTime(timezone=True), nullable=True)
    state = Column(
        String, nullable=False, default="observed", server_default="observed"
    )
    observed_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    absent_at = Column(DateTime(timezone=True), nullable=True)

    tombstone = relationship("KubernetesOrphanTombstone", back_populates="resources")

    __table_args__ = (
        CheckConstraint(
            "kind IN ('Job', 'Deployment', 'ReplicaSet', 'Service', 'Pod', 'Secret')",
            name="ck_kubernetes_orphan_resource_kind",
        ),
        CheckConstraint(
            "state IN ('observed', 'delete_requested', 'absent')",
            name="ck_kubernetes_orphan_resource_state",
        ),
        CheckConstraint(
            "((pod_termination_evidence IS NULL) = "
            "(pod_termination_evidence_sha256 IS NULL)) AND "
            "((pod_termination_evidence IS NULL) = "
            "(pod_teardown_finalizer_removal_requested_at IS NULL)) AND "
            "(kind = 'Pod' OR pod_termination_evidence IS NULL) AND "
            "(kind = 'Pod' OR (pod_teardown_finalizer_attached_at IS NULL AND "
            "pod_teardown_finalizer_removal_requested_at IS NULL AND "
            "pod_teardown_finalizer_removed_at IS NULL)) AND "
            "(pod_teardown_finalizer_removal_requested_at IS NULL OR "
            "pod_teardown_finalizer_attached_at IS NOT NULL) AND "
            "(pod_teardown_finalizer_removed_at IS NULL OR "
            "pod_teardown_finalizer_removal_requested_at IS NOT NULL) AND "
            "(kind <> 'Pod' OR state <> 'absent' OR "
            "(pod_termination_evidence IS NOT NULL AND "
            "pod_teardown_finalizer_removed_at IS NOT NULL))",
            name="ck_kubernetes_orphan_resource_pod_termination",
        ),
        CheckConstraint(
            "pod_termination_evidence_sha256 IS NULL OR "
            "pod_termination_evidence_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_kubernetes_orphan_resource_pod_termination_sha256",
        ),
        CheckConstraint(
            "(owner_api_version IS NULL AND owner_kind IS NULL "
            "AND owner_name IS NULL AND owner_uid IS NULL) OR "
            "(owner_api_version IS NOT NULL AND owner_kind IS NOT NULL "
            "AND owner_name IS NOT NULL AND owner_uid IS NOT NULL)",
            name="ck_kubernetes_orphan_resource_owner",
        ),
        UniqueConstraint(
            "tombstone_id",
            "kind",
            "uid",
            name="kubernetes_orphan_tombstone_resource_uid_key",
        ),
    )
