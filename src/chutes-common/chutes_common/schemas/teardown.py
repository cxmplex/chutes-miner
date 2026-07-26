"""Durable miner deployment and Kubernetes teardown state."""

from __future__ import annotations

import uuid

from chutes_common.schemas import Base
from sqlalchemy import (
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
    gpu_hardware_uuids = Column(JSONB, nullable=False)
    immutable_labels = Column(JSONB, nullable=False)

    registry_revocation_ack = Column(JSONB, nullable=True)
    registry_revoked_at = Column(DateTime(timezone=True), nullable=True)
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
            "(pull_secret_deletion_ack IS NULL) = (pull_secret_deleted_at IS NULL)",
            name="ck_deployment_teardown_secret_ack",
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
    owner_kind = Column(String, nullable=True)
    owner_name = Column(String, nullable=True)
    owner_uid = Column(String, nullable=True)
    node_name = Column(String, nullable=True)
    labels = Column(JSONB, nullable=False)
    labels_sha256 = Column(String, nullable=False)
    state = Column(String, nullable=False, default="observed", server_default="observed")
    observed_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
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
            "(owner_kind IS NULL AND owner_name IS NULL AND owner_uid IS NULL) OR "
            "(owner_kind IS NOT NULL AND owner_name IS NOT NULL AND owner_uid IS NOT NULL)",
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
    owner_kind = Column(String, nullable=True)
    owner_name = Column(String, nullable=True)
    owner_uid = Column(String, nullable=True)
    node_name = Column(String, nullable=True)
    labels = Column(JSONB, nullable=False)
    labels_sha256 = Column(String, nullable=False)
    state = Column(String, nullable=False, default="observed", server_default="observed")
    observed_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
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
            "(owner_kind IS NULL AND owner_name IS NULL AND owner_uid IS NULL) OR "
            "(owner_kind IS NOT NULL AND owner_name IS NOT NULL AND owner_uid IS NOT NULL)",
            name="ck_kubernetes_orphan_resource_owner",
        ),
        UniqueConstraint(
            "tombstone_id",
            "kind",
            "uid",
            name="kubernetes_orphan_tombstone_resource_uid_key",
        ),
    )
