"""
Routes for deployments.
"""

import asyncio
from datetime import datetime
from typing import Literal

from loguru import logger
from chutes_miner.gepetto import Gepetto
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from chutes_miner.api.config import settings
from chutes_miner.api.database import get_db_session
from chutes_miner.api.deployment.teardown import DeploymentTeardownCoordinator
from chutes_miner.api.exceptions import DeploymentFailure
from chutes_miner.api.management_auth import destructive_management_authorization
from chutes_common.schemas.deployment import Deployment

router = APIRouter()


class LineageCASRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_conflict_at: datetime
    expected_lineage_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=8, max_length=2000)


class LineageRequeueRequest(LineageCASRequest):
    policy: Literal["exact_lineage_retry"] = "exact_lineage_retry"


class LineageResolveRequest(LineageCASRequest):
    policy: Literal["verified_terminal_absence"] = "verified_terminal_absence"


@router.get("/teardown-conflicts/{operation_kind}/{operation_id}")
async def inspect_teardown_conflict(
    operation_kind: Literal["deployment", "orphan"],
    operation_id: str,
    _: None = Depends(destructive_management_authorization),
):
    try:
        result = await DeploymentTeardownCoordinator().inspect_lineage_conflict(
            operation_kind,
            operation_id,
        )
    except DeploymentFailure as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Conflict not found"
        )
    return result


async def _recover_teardown_conflict(
    *,
    operation_kind: str,
    operation_id: str,
    action: str,
    body: LineageCASRequest,
) -> dict:
    coordinator = DeploymentTeardownCoordinator()
    try:
        result = await coordinator.recover_lineage_conflict(
            operation_kind=operation_kind,
            operation_id=operation_id,
            action=action,
            policy=body.policy,
            expected_conflict_at=body.expected_conflict_at,
            expected_lineage_sha256=body.expected_lineage_sha256,
            reason=body.reason,
            actor=settings.miner_ss58,
        )
    except DeploymentFailure as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Conflict not found"
        )
    if action == "requeue" or operation_kind == "deployment":
        runner = (
            coordinator.run
            if operation_kind == "deployment"
            else coordinator.run_orphan
        )
        asyncio.create_task(runner(operation_id))
    response_status = (
        "requeued"
        if action == "requeue"
        else ("finalizing" if operation_kind == "deployment" else "resolved")
    )
    return {**result, "status": response_status}


@router.post("/teardown-conflicts/{operation_kind}/{operation_id}/requeue")
async def requeue_teardown_conflict(
    operation_kind: Literal["deployment", "orphan"],
    operation_id: str,
    body: LineageRequeueRequest,
    _: None = Depends(destructive_management_authorization),
):
    return await _recover_teardown_conflict(
        operation_kind=operation_kind,
        operation_id=operation_id,
        action="requeue",
        body=body,
    )


@router.post("/teardown-conflicts/{operation_kind}/{operation_id}/resolve")
async def resolve_teardown_conflict(
    operation_kind: Literal["deployment", "orphan"],
    operation_id: str,
    body: LineageResolveRequest,
    _: None = Depends(destructive_management_authorization),
):
    return await _recover_teardown_conflict(
        operation_kind=operation_kind,
        operation_id=operation_id,
        action="resolve",
        body=body,
    )


@router.delete("/purge")
async def purge(
    db: AsyncSession = Depends(get_db_session),
    _: None = Depends(destructive_management_authorization),
):
    """
    Purge all deployments, allowing gepetto to re-scale for max $$$
    """
    deployments = []
    operation_ids = []
    gepetto = Gepetto()
    for deployment in (await db.execute(select(Deployment))).unique().scalars().all():
        deployments.append(
            {
                "chute_id": deployment.chute_id,
                "chute_name": deployment.chute.name,
                "server_id": deployment.server_id,
                "server_name": deployment.server.name,
                "gpu_count": len(deployment.gpus),
            }
        )
        logger.warning(
            f"Initiating deletion of {deployment.deployment_id}: {deployment.chute.name} from server {deployment.server.name}"
        )
        operation_id = await gepetto.teardown.request(
            deployment.deployment_id, "management_purge_all"
        )
        if operation_id:
            operation_ids.append(operation_id)
    for operation_id in operation_ids:
        asyncio.create_task(gepetto.teardown.run(operation_id))
    return {
        "status": "initiated",
        "deployments_purged": deployments,
    }


@router.delete("/{deployment_id}")
async def purge_deployment(
    deployment_id: str,
    db: AsyncSession = Depends(get_db_session),
    _: None = Depends(destructive_management_authorization),
):
    """
    Purge the target deployment
    """
    gepetto = Gepetto()
    deployment = (
        (
            await db.execute(
                select(Deployment).where(Deployment.deployment_id == deployment_id)
            )
        )
        .unique()
        .scalar_one_or_none()
    )

    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No deploymentwith id {deployment_id} found!",
        )

    logger.warning(
        f"Initiating deletion of {deployment.deployment_id}: {deployment.chute.name} from server {deployment.server.name}"
    )

    operation_id = await gepetto.teardown.request(
        deployment.deployment_id, "management_purge_single"
    )
    if not operation_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Deployment teardown could not be persisted",
        )
    asyncio.create_task(gepetto.teardown.run(operation_id))
    return {
        "status": "initiated",
        "deployment_purged": deployment,
    }
