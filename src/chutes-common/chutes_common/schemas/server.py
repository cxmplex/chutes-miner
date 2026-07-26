"""
Server (kubernetes node) tracking ORM.
"""

from typing import Optional

from chutes_common.schemas import Base
from pydantic import BaseModel
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
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


class ServerArgs(BaseModel):
    name: str
    validator: str
    hourly_cost: float
    gpu_short_ref: str
    agent_api: Optional[str] = None


class Server(Base):
    __tablename__ = "servers"

    server_id = Column(String, primary_key=True)
    kubernetes_node_uid = Column(String, nullable=True)
    kubernetes_node_generation = Column(Integer, nullable=False, default=0, server_default="0")
    registration_attestation_id = Column(String, nullable=True)
    gpu_allocation_group_id = Column(String, nullable=True)
    gpu_allocation_group_generation = Column(Integer, nullable=True)
    validator = Column(String, nullable=False)
    name = Column(String, unique=True, nullable=False)
    ip_address = Column(String)
    agent_api = Column(String, nullable=True)
    verification_port = Column(Integer)
    status = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    labels = Column(JSONB, nullable=False)
    seed = Column(BigInteger)
    gpu_count = Column(Integer, nullable=False)
    cpu_per_gpu = Column(Integer, nullable=False, default=1)
    memory_per_gpu = Column(Integer, nullable=False, default=1)
    hourly_cost = Column(Float, nullable=False)
    locked = Column(Boolean, default=False)
    kubeconfig = Column(Text, nullable=True)  # Make this false if enforicng migration
    is_tee = Column(Boolean, default=False)

    gpus = relationship("GPU", back_populates="server", lazy="joined")
    deployments = relationship(
        "Deployment",
        back_populates="server",
        lazy="joined",
    )

    __table_args__ = (
        CheckConstraint(
            "(kubernetes_node_uid IS NULL AND kubernetes_node_generation = 0) OR "
            "(kubernetes_node_uid IS NOT NULL AND kubernetes_node_generation > 0)",
            name="ck_servers_kubernetes_node_generation",
        ),
        Index(
            "servers_kubernetes_node_uid_idx",
            "kubernetes_node_uid",
            unique=True,
            postgresql_where=text("kubernetes_node_uid IS NOT NULL"),
        ),
        Index(
            "servers_registration_attestation_id_idx",
            "registration_attestation_id",
            unique=True,
            postgresql_where=text("registration_attestation_id IS NOT NULL"),
        ),
        Index(
            "servers_gpu_allocation_group_id_idx",
            "gpu_allocation_group_id",
            unique=True,
            postgresql_where=text("gpu_allocation_group_id IS NOT NULL"),
        ),
    )


class ServerNodeIdentity(Base):
    """Monotonic Kubernetes node incarnations for one logical GPU server."""

    __tablename__ = "server_node_identities"

    server_id = Column(
        String,
        ForeignKey("servers.server_id", onupdate="CASCADE", ondelete="CASCADE"),
        primary_key=True,
    )
    generation = Column(Integer, primary_key=True)
    kubernetes_node_uid = Column(String, nullable=False)
    registration_attestation_id = Column(String, nullable=True)
    adopted_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    retired_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "kubernetes_node_uid", name="server_node_identities_kubernetes_node_uid_key"
        ),
        CheckConstraint(
            "generation > 0",
            name="ck_server_node_identity_generation",
        ),
    )
