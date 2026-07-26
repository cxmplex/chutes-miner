"""
Routes for deployments.
"""

import asyncio
from loguru import logger
from chutes_miner.gepetto import Gepetto
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from chutes_miner.api.database import get_db_session
from chutes_common.auth import authorize
from chutes_common.schemas.deployment import Deployment

router = APIRouter()


@router.delete("/purge")
async def purge(
    db: AsyncSession = Depends(get_db_session),
    _: None = Depends(authorize(allow_miner=True, purpose="management")),
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
    _: None = Depends(authorize(allow_miner=True, purpose="management")),
):
    """
    Purge the target deployment
    """
    gepetto = Gepetto()
    deployment = (
        (await db.execute(select(Deployment).where(Deployment.deployment_id == deployment_id)))
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
