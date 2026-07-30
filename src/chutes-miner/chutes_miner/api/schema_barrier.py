"""Exact database-schema barrier shared by API workers and Gepetto."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from loguru import logger
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine


REQUIRED_SCHEMA_VERSION = "20260730140000"
_SCHEMA_MIGRATIONS_PRESENT = text(
    "SELECT to_regclass('schema_migrations') IS NOT NULL"
)
_REQUIRED_SCHEMA_VERSION_PRESENT = text(
    """
    SELECT EXISTS (
        SELECT 1
        FROM schema_migrations
        WHERE version = :required_version
    )
    """
)
_SEEDLESS_ADOPTION_PRESENT = text(
    """
    SELECT EXISTS (
        SELECT 1
        FROM servers AS server
        WHERE server.server_id = :server_id
          AND server.validator = :validator
          AND server.is_tee IS TRUE
          AND server.status = 'Ready'
          AND server.registration_attestation_id = :attestation_id
          AND server.gpu_allocation_group_id = :allocation_group_id
          AND server.gpu_allocation_group_generation = :allocation_group_generation
          AND server.kubernetes_node_uid IS NOT NULL
          AND server.kubernetes_node_generation > 0
          AND server.labels ->> 'chutes/seedless-adopted' = :server_id
          AND (
              SELECT COALESCE(
                  array_agg(gpu.hardware_uuid ORDER BY gpu.hardware_uuid),
                  ARRAY[]::text[]
              )
              FROM gpus AS gpu
              WHERE gpu.server_id = server.server_id
          ) = CAST(:gpu_uuids AS text[])
          AND NOT EXISTS (
              SELECT 1
              FROM gpus AS gpu
              WHERE gpu.server_id = server.server_id
                AND (
                    gpu.verified IS NOT TRUE
                    OR gpu.validator IS DISTINCT FROM :validator
                    OR gpu.gpu_allocation_group_id IS DISTINCT FROM :allocation_group_id
                    OR gpu.gpu_allocation_group_generation
                        IS DISTINCT FROM :allocation_group_generation
                )
          )
    )
    """
)


async def required_schema_is_present(engine: AsyncEngine) -> bool:
    """Check for the exact required dbmate migration without using the ORM."""
    async with engine.connect() as connection:
        if not bool(await connection.scalar(_SCHEMA_MIGRATIONS_PRESENT)):
            return False
        return bool(
            await connection.scalar(
                _REQUIRED_SCHEMA_VERSION_PRESENT,
                {"required_version": REQUIRED_SCHEMA_VERSION},
            )
        )


async def wait_for_required_schema(
    engine: AsyncEngine,
    *,
    poll_seconds: float = 0.25,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> None:
    """Keep process readiness closed until the exact required schema is installed."""
    announced = False
    while not await required_schema_is_present(engine):
        if not announced:
            logger.warning(
                "waiting for required database schema version {}",
                REQUIRED_SCHEMA_VERSION,
            )
            announced = True
        await sleep(poll_seconds)
    if announced:
        logger.success(
            "required database schema version {} is present",
            REQUIRED_SCHEMA_VERSION,
        )


async def seedless_adoption_is_present(engine: AsyncEngine, identity: dict) -> bool:
    """Check the exact registrar-backed local server/GPU closure using raw SQL."""
    async with engine.connect() as connection:
        return bool(
            await connection.scalar(
                _SEEDLESS_ADOPTION_PRESENT,
                {
                    "server_id": identity["server_id"],
                    "validator": identity["validator"]["hotkey"],
                    "attestation_id": identity["attestation_id"],
                    "allocation_group_id": identity["allocation_group_id"],
                    "allocation_group_generation": identity[
                        "allocation_group_generation"
                    ],
                    "gpu_uuids": sorted(identity["gpu_uuids"]),
                },
            )
        )


async def wait_for_seedless_adoption(
    engine: AsyncEngine,
    identity: dict,
    *,
    poll_seconds: float = 0.25,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> None:
    """Keep every API worker unready until exact seedless adoption commits."""
    announced = False
    while not await seedless_adoption_is_present(engine, identity):
        if not announced:
            logger.warning("waiting for exact seedless GPU server adoption")
            announced = True
        await sleep(poll_seconds)
    if announced:
        logger.success("exact seedless GPU server adoption is present")
