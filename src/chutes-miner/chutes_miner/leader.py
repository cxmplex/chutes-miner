"""Dedicated PostgreSQL leadership for the singleton Gepetto control plane."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from contextlib import suppress

from loguru import logger
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine


GEPETTO_LEADER_LOCK = text(
    "SELECT pg_try_advisory_lock(hashtextextended('chutes:gepetto-leader:v1', 0))"
)
GEPETTO_LEADER_UNLOCK = text(
    "SELECT pg_advisory_unlock(hashtextextended('chutes:gepetto-leader:v1', 0))"
)
GEPETTO_LEADER_HEARTBEAT = text("SELECT 1")


class GepettoLeaderConnectionLost(RuntimeError):
    """The dedicated connection holding Gepetto leadership is no longer usable."""


async def _watch_leader_connection(
    connection: AsyncConnection,
    *,
    heartbeat_seconds: float,
    sleep: Callable[[float], Awaitable[None]],
) -> None:
    while True:
        await sleep(heartbeat_seconds)
        try:
            heartbeat = await connection.scalar(GEPETTO_LEADER_HEARTBEAT)
        except Exception as exc:
            raise GepettoLeaderConnectionLost(
                "dedicated Gepetto leader connection failed"
            ) from exc
        if heartbeat != 1:
            raise GepettoLeaderConnectionLost(
                "dedicated Gepetto leader connection returned an invalid heartbeat"
            )


async def run_gepetto_leader_session(
    connection: AsyncConnection,
    worker: Callable[[], Awaitable[None]],
    *,
    heartbeat_seconds: float = 5.0,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> None:
    """Run leader work only while the exact lock-holding connection is alive."""
    leader_work = asyncio.create_task(worker(), name="gepetto-leader-work")
    connection_watch = asyncio.create_task(
        _watch_leader_connection(
            connection,
            heartbeat_seconds=heartbeat_seconds,
            sleep=sleep,
        ),
        name="gepetto-leader-connection-watch",
    )
    try:
        done, _ = await asyncio.wait(
            {leader_work, connection_watch},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if connection_watch in done:
            try:
                connection_watch.result()
            except GepettoLeaderConnectionLost:
                leader_work.cancel()
                with suppress(asyncio.CancelledError):
                    await leader_work
                raise
            raise GepettoLeaderConnectionLost(
                "dedicated Gepetto leader watcher stopped unexpectedly"
            )
        connection_watch.cancel()
        with suppress(asyncio.CancelledError):
            await connection_watch
        await leader_work
    finally:
        for task in (leader_work, connection_watch):
            if not task.done():
                task.cancel()
        for task in (leader_work, connection_watch):
            with suppress(asyncio.CancelledError, GepettoLeaderConnectionLost):
                await task


def _bounded_retry_delay(
    attempt: int,
    *,
    minimum: float,
    maximum: float,
    jitter: Callable[[float, float], float],
) -> float:
    base = min(maximum, minimum * (2 ** min(attempt, 8)))
    return min(maximum, base + jitter(0.0, min(base * 0.2, maximum - base)))


async def run_gepetto_leader_loop(
    engine: AsyncEngine,
    worker: Callable[[], Awaitable[None]],
    *,
    heartbeat_seconds: float = 5.0,
    retry_min_seconds: float = 0.5,
    retry_max_seconds: float = 15.0,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    jitter: Callable[[float, float], float] = random.uniform,
) -> None:
    """Elect one Gepetto process, stopping work immediately on lease loss."""
    attempt = 0
    while True:
        connection = await engine.connect()
        acquired = False
        connection_lost = False
        work_completed = False
        try:
            acquired = bool(await connection.scalar(GEPETTO_LEADER_LOCK))
            if not acquired:
                logger.info("Gepetto leadership is held by another replica")
            else:
                logger.success("acquired dedicated Gepetto PostgreSQL leadership")
                attempt = 0
                try:
                    await run_gepetto_leader_session(
                        connection,
                        worker,
                        heartbeat_seconds=heartbeat_seconds,
                        sleep=sleep,
                    )
                except GepettoLeaderConnectionLost:
                    connection_lost = True
                    logger.exception(
                        "lost dedicated Gepetto PostgreSQL leadership; leader work stopped"
                    )
                else:
                    work_completed = True
        finally:
            try:
                if acquired and not connection_lost:
                    unlocked = bool(await connection.scalar(GEPETTO_LEADER_UNLOCK))
                    if not unlocked:
                        raise RuntimeError(
                            "Gepetto advisory leadership unlock was not acknowledged"
                        )
            finally:
                await connection.close()
        if work_completed:
            return
        delay = _bounded_retry_delay(
            attempt,
            minimum=retry_min_seconds,
            maximum=retry_max_seconds,
            jitter=jitter,
        )
        attempt += 1
        await sleep(delay)
