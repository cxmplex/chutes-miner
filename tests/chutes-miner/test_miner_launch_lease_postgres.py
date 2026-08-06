"""Real-PostgreSQL concurrency checks for miner launch recovery leases."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import json
import os
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from chutes_common.schemas.teardown import MinerLaunchIntent
import chutes_miner.gepetto as gepetto_module
from chutes_miner.gepetto import Gepetto


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for miner launch lease concurrency tests",
)


def _asyncpg_url() -> str:
    assert TEST_DATABASE_URL is not None
    if TEST_DATABASE_URL.startswith("postgresql+asyncpg://"):
        return TEST_DATABASE_URL
    return TEST_DATABASE_URL.replace(
        "postgresql://",
        "postgresql+asyncpg://",
        1,
    )


@pytest.mark.asyncio
async def test_cross_session_claim_has_one_winner_and_skips_live_producer(
    monkeypatch,
):
    engine = create_async_engine(_asyncpg_url(), pool_size=4, max_overflow=0)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    schema = f"test_miner_launch_lease_{uuid.uuid4().hex}"
    now = datetime.now(timezone.utc)
    request = json.dumps(
        {
            "schema": "chutes.miner-launch-request.v1",
            "miner_launch_request_id": "placeholder",
            "lineage": {},
        }
    )

    try:
        async with engine.begin() as connection:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
            await connection.execute(
                text(f'SET LOCAL search_path TO "{schema}", public')
            )
            await connection.run_sync(
                lambda sync_connection: MinerLaunchIntent.__table__.create(
                    sync_connection
                )
            )
            await connection.execute(
                text(
                    """
                    INSERT INTO miner_launch_intents (
                        intent_id,
                        phase,
                        validator,
                        chute_id,
                        chute_version,
                        server_id,
                        request_payload,
                        request_sha256,
                        lineage_sha256,
                        deployment_id,
                        retry_lease_owner,
                        retry_lease_expires_at,
                        attempt_count,
                        created_at
                    ) VALUES (
                        :intent_id,
                        'pending',
                        'validator-1',
                        'chute-1',
                        '1.0.0',
                        'server-1',
                        CAST(:request_payload AS JSONB),
                        :request_sha256,
                        :lineage_sha256,
                        :deployment_id,
                        :retry_lease_owner,
                        :retry_lease_expires_at,
                        0,
                        :created_at
                    )
                    """
                ),
                [
                    {
                        "intent_id": "live-producer",
                        "request_payload": request.replace(
                            "placeholder", "live-producer"
                        ),
                        "request_sha256": "a" * 64,
                        "lineage_sha256": "b" * 64,
                        "deployment_id": str(uuid.uuid4()),
                        "retry_lease_owner": "producer-owner",
                        "retry_lease_expires_at": now + timedelta(minutes=5),
                        "created_at": now - timedelta(minutes=2),
                    },
                    {
                        "intent_id": "expired-producer",
                        "request_payload": request.replace(
                            "placeholder", "expired-producer"
                        ),
                        "request_sha256": "c" * 64,
                        "lineage_sha256": "d" * 64,
                        "deployment_id": str(uuid.uuid4()),
                        "retry_lease_owner": "crashed-owner",
                        "retry_lease_expires_at": now - timedelta(seconds=1),
                        "created_at": now - timedelta(minutes=1),
                    },
                ],
            )

        @asynccontextmanager
        async def isolated_session():
            async with session_factory() as session:
                await session.execute(text(f'SET search_path TO "{schema}", public'))
                try:
                    yield session
                finally:
                    if session.in_transaction():
                        await session.rollback()

        monkeypatch.setattr(gepetto_module, "get_session", isolated_session)
        owner_sequence = iter(("recovery-owner-a", "recovery-owner-b"))
        gepetto = object.__new__(Gepetto)
        gepetto._launch_intent_lease_owner = lambda _kind: next(owner_sequence)

        first, second = await asyncio.gather(
            gepetto._claim_launch_intents({"pending"}),
            gepetto._claim_launch_intents({"pending"}),
        )
        winners = [claim for batch in (first, second) for claim in batch]
        assert len(winners) == 1
        assert winners[0][0] == "expired-producer"
        assert winners[0][1] in {"recovery-owner-a", "recovery-owner-b"}

        async with engine.connect() as connection:
            await connection.execute(text(f'SET search_path TO "{schema}", public'))
            rows = {
                row.intent_id: row
                for row in (
                    await connection.execute(
                        text(
                            """
                            SELECT intent_id,
                                   retry_lease_owner,
                                   retry_lease_expires_at,
                                   attempt_count
                            FROM miner_launch_intents
                            ORDER BY intent_id
                            """
                        )
                    )
                )
            }
        assert rows["live-producer"].retry_lease_owner == "producer-owner"
        assert rows["live-producer"].attempt_count == 0
        assert rows["live-producer"].retry_lease_expires_at > now
        assert rows["expired-producer"].retry_lease_owner == winners[0][1]
        assert rows["expired-producer"].attempt_count == 1
        assert rows["expired-producer"].retry_lease_expires_at > now
    finally:
        async with engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await engine.dispose()
