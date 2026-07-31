"""Regression tests for singleton Gepetto PostgreSQL leadership."""

from __future__ import annotations

import asyncio
from contextlib import suppress

import pytest

from chutes_miner.leader import (
    GepettoLeaderConnectionLost,
    run_gepetto_leader_loop,
    run_gepetto_leader_session,
)


class _SharedAdvisoryLock:
    def __init__(self):
        self.owner = None
        self.follower_observed = asyncio.Event()
        self.unlocks = 0


class _Connection:
    def __init__(self, lock: _SharedAdvisoryLock, *, unlock_result: bool = True):
        self.lock = lock
        self.unlock_result = unlock_result
        self.closed = False

    async def scalar(self, statement):
        sql = str(statement)
        if "pg_try_advisory_lock" in sql:
            if self.lock.owner is None:
                self.lock.owner = self
                return True
            self.lock.follower_observed.set()
            return False
        if "pg_advisory_unlock" in sql:
            if self.lock.owner is self and self.unlock_result:
                self.lock.owner = None
                self.lock.unlocks += 1
                return True
            return False
        if sql.strip() == "SELECT 1":
            return 1
        raise AssertionError(sql)

    async def close(self):
        self.closed = True


class _Engine:
    def __init__(self, lock: _SharedAdvisoryLock, *, unlock_result: bool = True):
        self.lock = lock
        self.unlock_result = unlock_result
        self.connections = []

    async def connect(self):
        connection = _Connection(self.lock, unlock_result=self.unlock_result)
        self.connections.append(connection)
        return connection


@pytest.mark.asyncio
async def test_two_replicas_only_the_dedicated_lock_holder_runs():
    lock = _SharedAdvisoryLock()
    engine = _Engine(lock)
    first_started = asyncio.Event()
    release_first = asyncio.Event()
    second_started = asyncio.Event()
    retry_block = asyncio.Event()

    async def first_worker():
        first_started.set()
        await release_first.wait()

    async def second_worker():
        second_started.set()

    async def blocked_sleep(_delay):
        await retry_block.wait()

    first = asyncio.create_task(run_gepetto_leader_loop(engine, first_worker, sleep=blocked_sleep))
    await first_started.wait()
    second = asyncio.create_task(
        run_gepetto_leader_loop(engine, second_worker, sleep=blocked_sleep)
    )
    await lock.follower_observed.wait()
    assert not second_started.is_set()

    second.cancel()
    with suppress(asyncio.CancelledError):
        await second
    release_first.set()
    await first

    assert lock.unlocks == 1
    assert lock.owner is None
    assert all(connection.closed for connection in engine.connections)


@pytest.mark.asyncio
async def test_connection_loss_cancels_leader_work_before_returning():
    worker_started = asyncio.Event()
    worker_cancelled = asyncio.Event()

    class LostConnection:
        async def scalar(self, _statement):
            raise ConnectionError("database connection dropped")

    async def yield_once(_delay):
        await asyncio.sleep(0)

    async def worker():
        worker_started.set()
        try:
            await asyncio.Event().wait()
        finally:
            worker_cancelled.set()

    with pytest.raises(GepettoLeaderConnectionLost):
        await run_gepetto_leader_session(
            LostConnection(),
            worker,
            heartbeat_seconds=0.001,
            sleep=yield_once,
        )

    assert worker_started.is_set()
    assert worker_cancelled.is_set()


@pytest.mark.asyncio
async def test_clean_leader_exit_fails_if_exact_unlock_is_not_acknowledged():
    lock = _SharedAdvisoryLock()
    engine = _Engine(lock, unlock_result=False)

    async def worker():
        return None

    async def no_sleep(_delay):
        raise AssertionError("leader should not enter retry backoff")

    with pytest.raises(RuntimeError, match="unlock was not acknowledged"):
        await run_gepetto_leader_loop(engine, worker, sleep=no_sleep)

    assert engine.connections[0].closed is True
