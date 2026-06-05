"""
ORM definitions for Chutes.
"""

from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from sqlalchemy import Column, String, DateTime, Integer, Boolean, Float
from sqlalchemy.dialects.postgresql import ARRAY
from chutes_common.schemas import Base


class Chute(Base):
    __tablename__ = "chutes"

    chute_id = Column(String, primary_key=True, nullable=False)
    validator = Column(String, nullable=False)
    name = Column(String)
    image = Column(String, nullable=False)
    code = Column(String, nullable=False)
    filename = Column(String, nullable=False)
    ref_str = Column(String, nullable=False)
    version = Column(String, nullable=False)
    supported_gpus = Column(ARRAY(String), nullable=False)
    gpu_count = Column(Integer, nullable=False)
    compute_type = Column(String, nullable=False, server_default="gpu")
    # CPU (GPU-less) node selector requirements, populated for compute_type == "cpu".
    cpu_cores = Column(Integer, nullable=True)
    ram_gb = Column(Integer, nullable=True)
    min_benchmark_score = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now())
    ban_reason = Column(String, nullable=True)
    chutes_version = Column(String)
    preemptible = Column(Boolean, default=True)
    tee = Column(Boolean, default=False)

    deployments = relationship("Deployment", back_populates="chute", cascade="all, delete-orphan")
