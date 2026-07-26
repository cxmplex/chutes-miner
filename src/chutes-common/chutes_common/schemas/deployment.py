"""
Deployment ORM.
"""

from chutes_common.schemas import Base
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func


class Deployment(Base):
    __tablename__ = "deployments"

    deployment_id = Column(String, primary_key=True, nullable=False)
    instance_id = Column(String)
    validator = Column(String, nullable=False)
    host = Column(String)
    port = Column(Integer)
    chute_id = Column(String, ForeignKey("chutes.chute_id", ondelete="RESTRICT"), nullable=False)
    server_id = Column(
        String,
        ForeignKey("servers.server_id", onupdate="CASCADE", ondelete="RESTRICT"),
        nullable=False,
    )
    version = Column(String, nullable=False)
    active = Column(Boolean, default=False)
    verified_at = Column(DateTime(timezone=True))
    activated_at = Column(DateTime(timezone=True))
    stub = Column(Boolean, default=False)
    job_id = Column(String, nullable=True)
    config_id = Column(String, nullable=True)
    registry_repository = Column(String, nullable=True)
    registry_manifest_digest = Column(String, nullable=True)
    teardown_operation_id = Column(
        String,
        ForeignKey("deployment_teardown_operations.operation_id", ondelete="RESTRICT"),
        nullable=True,
    )
    launch_operation_id = Column(
        String,
        ForeignKey("deployment_launch_operations.operation_id", ondelete="RESTRICT"),
        nullable=True,
    )
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    preemptible = Column(Boolean, default=True)

    gpus = relationship("GPU", back_populates="deployment", lazy="joined")
    chute = relationship("Chute", back_populates="deployments", lazy="joined")
    server = relationship("Server", back_populates="deployments", lazy="joined")
    teardown_operation = relationship(
        "DeploymentTeardownOperation",
        foreign_keys=[teardown_operation_id],
        lazy="joined",
    )
    launch_operation = relationship(
        "DeploymentLaunchOperation",
        foreign_keys=[launch_operation_id],
        lazy="joined",
    )

    __table_args__ = (
        Index(
            "deployments_teardown_operation_id_key",
            "teardown_operation_id",
            unique=True,
            postgresql_where=text("teardown_operation_id IS NOT NULL"),
        ),
        Index(
            "deployments_launch_operation_id_key",
            "launch_operation_id",
            unique=True,
            postgresql_where=text("launch_operation_id IS NOT NULL"),
        ),
    )
