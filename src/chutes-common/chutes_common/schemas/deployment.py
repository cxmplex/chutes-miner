"""
Deployment ORM.
"""

from chutes_common.schemas import Base
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func


class Deployment(Base):
    __tablename__ = "deployments"

    deployment_id = Column(String, primary_key=True, nullable=False)
    instance_id = Column(String)
    validator = Column(String, nullable=False)
    host = Column(String)
    port = Column(Integer)
    chute_id = Column(String, ForeignKey("chutes.chute_id", ondelete="CASCADE"), nullable=False)
    server_id = Column(
        String,
        ForeignKey("servers.server_id", onupdate="CASCADE", ondelete="CASCADE"),
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
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    preemptible = Column(Boolean, default=True)

    gpus = relationship("GPU", back_populates="deployment", lazy="joined", passive_deletes=True)
    chute = relationship("Chute", back_populates="deployments", lazy="joined")
    server = relationship("Server", back_populates="deployments", lazy="joined")
