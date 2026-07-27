"""Exact database-schema barrier shared by API workers and Gepetto."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from loguru import logger
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine


REQUIRED_SCHEMA_VERSION = "20260727120000"
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
