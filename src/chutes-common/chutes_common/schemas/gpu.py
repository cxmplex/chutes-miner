"""
Individual GPU ORM.
"""

from chutes_common.schemas import Base
from pydantic import BaseModel
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship


class VerificationArgs(BaseModel):
    verified: bool


class GPU(Base):
    __tablename__ = "gpus"

    gpu_id = Column(String, primary_key=True, nullable=False)
    hardware_uuid = Column(String, nullable=True)
    validator = Column(String)
    server_id = Column(
        String,
        ForeignKey("servers.server_id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=False,
    )
    deployment_id = Column(
        String,
        ForeignKey("deployments.deployment_id", ondelete="SET NULL"),
        nullable=True,
    )

    device_info = Column(JSONB, nullable=False)
    model_short_ref = Column(String, nullable=False)
    verified = Column(Boolean, default=False)
    gpu_allocation_group_id = Column(String, nullable=True)
    gpu_allocation_group_generation = Column(Integer, nullable=True)

    server = relationship("Server", back_populates="gpus", lazy="joined")
    deployment = relationship(
        "Deployment",
        back_populates="gpus",
        foreign_keys=[deployment_id],
    )

    __table_args__ = (
        CheckConstraint(
            "(gpu_allocation_group_id IS NULL "
            "AND gpu_allocation_group_generation IS NULL) OR "
            "(gpu_allocation_group_id IS NOT NULL "
            "AND gpu_allocation_group_generation IS NOT NULL "
            "AND gpu_allocation_group_generation > 0)",
            name="ck_gpus_allocation_group_lineage",
        ),
        Index(
            "gpus_hardware_uuid_idx",
            "hardware_uuid",
            unique=True,
            postgresql_where=text("hardware_uuid IS NOT NULL"),
        ),
        Index(
            "gpus_allocation_group_idx",
            "gpu_allocation_group_id",
            "gpu_allocation_group_generation",
            postgresql_where=text("gpu_allocation_group_id IS NOT NULL"),
        ),
    )
