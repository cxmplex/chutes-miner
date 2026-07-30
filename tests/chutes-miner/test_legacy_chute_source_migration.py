"""The unshipped seedless migration must retain production chute source data."""

import os
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import pytest


MIGRATION = (
    Path(__file__).resolve().parents[2]
    / "src/chutes-miner/chutes_miner/api/migrations/"
    "20260717221400_remove_legacy_chute_source.sql"
)
TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")


def _migration_sql() -> tuple[str, str]:
    return MIGRATION.read_text().split("-- migrate:down", 1)


def _connection() -> tuple[str, dict[str, str]]:
    parsed = urlsplit(TEST_DATABASE_URL.replace("+asyncpg", ""))
    url = f"postgresql://{parsed.username}@{parsed.hostname}:{parsed.port}{parsed.path}"
    return url, {**os.environ, "PGPASSWORD": parsed.password or ""}


def _psql(
    sql: str,
    *,
    schema: str | None = None,
    tuples_only: bool = False,
) -> subprocess.CompletedProcess:
    url, environment = _connection()
    if schema:
        environment["PGOPTIONS"] = f"-c search_path={schema}"
    command = ["psql", url, "-v", "ON_ERROR_STOP=1"]
    if tuples_only:
        command.extend(["-A", "-t"])
    return subprocess.run(
        command,
        input=sql.encode(),
        capture_output=True,
        env=environment,
        check=False,
    )


def test_unshipped_legacy_source_migration_is_non_destructive():
    up_sql, down_sql = _migration_sql()
    assert "DROP COLUMN" not in up_sql.upper()
    assert "DROP COLUMN" not in down_sql.upper()
    assert "SELECT 1" in up_sql.upper()
    assert "SELECT 1" in down_sql.upper()


@pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for miner migration tests",
)
def test_unshipped_legacy_source_migration_preserves_columns_and_rows():
    schema = f"miner_chute_source_{uuid.uuid4().hex}"
    up_sql, down_sql = _migration_sql()
    created = _psql(f'CREATE SCHEMA "{schema}";')
    assert created.returncode == 0, created.stderr.decode()
    try:
        baseline = _psql(
            """
            CREATE TABLE chutes (
                chute_id TEXT PRIMARY KEY,
                code TEXT,
                filename TEXT
            );
            INSERT INTO chutes (chute_id, code, filename)
            VALUES ('chute-1', 'print(42)', 'entrypoint.py');
            """,
            schema=schema,
        )
        assert baseline.returncode == 0, baseline.stderr.decode()

        for migration_sql in (up_sql, down_sql):
            migrated = _psql(migration_sql, schema=schema)
            assert migrated.returncode == 0, migrated.stderr.decode()
            inspected = _psql(
                """
                SELECT string_agg(column_name, ',' ORDER BY column_name)
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'chutes'
                  AND column_name IN ('code', 'filename');
                SELECT code, filename FROM chutes WHERE chute_id = 'chute-1';
                """,
                schema=schema,
                tuples_only=True,
            )
            assert inspected.returncode == 0, inspected.stderr.decode()
            assert [
                line.strip()
                for line in inspected.stdout.decode().splitlines()
                if line.strip()
            ] == ["code,filename", "print(42)|entrypoint.py"]
    finally:
        dropped = _psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;')
        assert dropped.returncode == 0, dropped.stderr.decode()
