"""
Server (kubernetes node) tracking ORM.
"""

from typing import Optional
from pydantic import BaseModel
from sqlalchemy import Column, String, DateTime, Integer, BigInteger, Float, Boolean, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from chutes_common.schemas import Base


class ServerArgs(BaseModel):
    name: str
    validator: str
    hourly_cost: float
    compute_type: str = "gpu"
    gpu_short_ref: Optional[str] = None
    agent_api: Optional[str] = None


class Server(Base):
    __tablename__ = "servers"

    server_id = Column(String, primary_key=True)
    validator = Column(String, nullable=False)
    name = Column(String, unique=True, nullable=False)
    ip_address = Column(String)
    agent_api = Column(String, nullable=True)
    verification_port = Column(Integer)
    status = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    labels = Column(JSONB, nullable=False)
    seed = Column(BigInteger)
    compute_type = Column(String, nullable=False, server_default="gpu")
    gpu_count = Column(Integer, nullable=True)
    cpu_per_gpu = Column(Integer, nullable=True, default=1)
    memory_per_gpu = Column(Integer, nullable=True, default=1)
    # Total usable CPU/RAM capacity for CPU-only (GPU-less) servers.
    cpu_count = Column(Integer, nullable=True)
    ram_gb = Column(Integer, nullable=True)
    # Composite CPU benchmark score from the TEE attestation service (CPU servers only).
    benchmark_score = Column(Float, nullable=True)
    hourly_cost = Column(Float, nullable=False)
    locked = Column(Boolean, default=False)
    kubeconfig = Column(Text, nullable=True)  # Make this false if enforicng migration
    is_tee = Column(Boolean, default=False)

    gpus = relationship("GPU", back_populates="server", lazy="joined", cascade="all, delete-orphan")
    deployments = relationship(
        "Deployment",
        back_populates="server",
        lazy="joined",
        cascade="all, delete-orphan",
    )
