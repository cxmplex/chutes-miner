"""Immutable audit records for local seedless GPU assignment retirement."""

from __future__ import annotations

import uuid

from chutes_common.schemas import Base
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Index,
    Integer,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func


def _uuid() -> str:
    return str(uuid.uuid4())


class GPUAdoptionRetirement(Base):
    """Non-FK snapshot retained after an unused local GPU row is removed."""

    __tablename__ = "gpu_adoption_retirements"

    retirement_id = Column(String, primary_key=True, default=_uuid)
    server_id = Column(String, nullable=False)
    gpu_id = Column(String, nullable=False)
    hardware_uuid = Column(String, nullable=True)
    deployment_id = Column(String, nullable=True)
    validator = Column(String, nullable=True)
    device_info = Column(JSONB, nullable=True)
    model_short_ref = Column(String, nullable=True)
    verified = Column(Boolean, nullable=True)
    prior_gpu_allocation_group_id = Column(String, nullable=True)
    prior_gpu_allocation_group_generation = Column(Integer, nullable=True)
    replacement_registration_attestation_id = Column(String, nullable=False)
    replacement_gpu_allocation_group_id = Column(String, nullable=False)
    replacement_gpu_allocation_group_generation = Column(Integer, nullable=False)
    reason = Column(
        String,
        nullable=False,
        default="registrar_assignment_shrink",
        server_default="registrar_assignment_shrink",
    )
    retired_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint(
            "deployment_id IS NULL",
            name="ck_gpu_adoption_retirement_unassigned",
        ),
        CheckConstraint(
            "replacement_gpu_allocation_group_generation > 0",
            name="ck_gpu_adoption_retirement_replacement_generation",
        ),
        CheckConstraint(
            "(prior_gpu_allocation_group_id IS NULL "
            "AND prior_gpu_allocation_group_generation IS NULL) OR "
            "(prior_gpu_allocation_group_id IS NOT NULL "
            "AND prior_gpu_allocation_group_generation IS NOT NULL "
            "AND prior_gpu_allocation_group_generation > 0)",
            name="ck_gpu_adoption_retirement_prior_lineage",
        ),
        CheckConstraint(
            "reason = 'registrar_assignment_shrink'",
            name="ck_gpu_adoption_retirement_reason",
        ),
        Index(
            "gpu_adoption_retirements_server_time_idx",
            "server_id",
            "retired_at",
        ),
    )
