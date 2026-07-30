"""Seedless startup must not replay retired pre-seedless validator migrations."""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from chutes_miner import validator_migrations


def test_sync_server_keys_is_retired_without_legacy_tee_authority():
    assert validator_migrations.RETIRED_MIGRATION_KEYS == frozenset({"2025013101"})
    assert "2025013101" not in validator_migrations.MIGRATIONS

    implementation = (
        Path(__file__).resolve().parents[2]
        / "src/chutes-miner/chutes_miner/validator_migrations/migrations.py"
    ).read_text()
    assert "sign_request" not in implementation
    assert 'purpose="tee"' not in implementation


def test_retired_migration_audit_history_is_read_but_not_rewritten(monkeypatch):
    sessions = []

    class Result:
        @staticmethod
        def all():
            return [("2025013101",)]

    class Session:
        def __init__(self):
            self.executions = 0
            self.added = []
            self.commits = 0

        async def execute(self, _statement):
            self.executions += 1
            return Result()

        def add(self, value):
            self.added.append(value)

        async def commit(self):
            self.commits += 1

    @asynccontextmanager
    async def get_session():
        session = Session()
        sessions.append(session)
        yield session

    monkeypatch.setattr(validator_migrations, "get_session", get_session)
    asyncio.run(validator_migrations.run_validator_migrations())

    assert len(sessions) == 1
    assert sessions[0].executions == 1
    assert sessions[0].added == []
    assert sessions[0].commits == 0
