"""Real-Postgres parity for seedless GPU adoption columns."""

import os
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import pytest

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for miner migration tests",
)


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


def test_seedless_gpu_migration_has_live_and_fresh_schema_parity():
    schema = f"miner_gpu_{uuid.uuid4().hex}"
    migration = (
        Path(__file__).resolve().parents[2] / "src/chutes-miner/chutes_miner/api/migrations/"
        "20260724090000_seedless_gpu_identity.sql"
    )
    up_sql, down_sql = migration.read_text().split("-- migrate:down", 1)
    create = _psql(f'CREATE SCHEMA "{schema}";')
    assert create.returncode == 0, create.stderr.decode()
    try:
        baseline = _psql(
            """
            CREATE TABLE servers (
                server_id TEXT PRIMARY KEY,
                gpu_allocation_group_id TEXT,
                gpu_allocation_group_generation INTEGER
            );
            CREATE TABLE deployments (
                deployment_id TEXT PRIMARY KEY,
                server_id TEXT NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE
            );
            CREATE TABLE gpus (
                gpu_id TEXT PRIMARY KEY,
                server_id TEXT NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE
            );
            INSERT INTO servers VALUES ('server-1', 'group-1', 7);
            INSERT INTO deployments VALUES ('deployment-1', 'server-1');
            INSERT INTO gpus VALUES (
                'GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                'server-1'
            );
            """,
            schema=schema,
        )
        assert baseline.returncode == 0, baseline.stderr.decode()

        migrated = _psql(up_sql, schema=schema)
        assert migrated.returncode == 0, migrated.stderr.decode()
        inspected = _psql(
            """
            SELECT
                hardware_uuid,
                gpu_allocation_group_id,
                gpu_allocation_group_generation
            FROM gpus;
            SELECT kubernetes_node_generation FROM servers;
            SELECT conname
            FROM pg_constraint
            WHERE conname = 'ck_gpus_allocation_group_lineage';
            SELECT indexname
            FROM pg_indexes
            WHERE indexname IN (
                'gpus_hardware_uuid_idx',
                'gpus_allocation_group_idx'
            )
            ORDER BY indexname;
            """,
            schema=schema,
            tuples_only=True,
        )
        assert inspected.returncode == 0, inspected.stderr.decode()
        lines = {line.strip() for line in inspected.stdout.decode().splitlines() if line.strip()}
        assert ("GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee|group-1|7") in lines
        assert "0" in lines
        assert "ck_gpus_allocation_group_lineage" in lines
        assert "gpus_allocation_group_idx" in lines
        assert "gpus_hardware_uuid_idx" in lines

        rekeyed = _psql(
            """
            UPDATE servers
            SET server_id = 'logical-server'
            WHERE server_id = 'server-1';
            SELECT server_id FROM deployments WHERE deployment_id = 'deployment-1';
            SELECT server_id FROM gpus
            WHERE gpu_id = 'GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
            """,
            schema=schema,
            tuples_only=True,
        )
        assert rekeyed.returncode == 0, rekeyed.stderr.decode()
        assert [line.strip() for line in rekeyed.stdout.decode().splitlines() if line.strip()][
            -2:
        ] == [
            "logical-server",
            "logical-server",
        ]

        invalid = _psql(
            """
            UPDATE gpus
            SET gpu_allocation_group_id = 'partial',
                gpu_allocation_group_generation = NULL;
            """,
            schema=schema,
        )
        assert invalid.returncode != 0
        assert b"ck_gpus_allocation_group_lineage" in invalid.stderr

        reverted = _psql(down_sql, schema=schema)
        assert reverted.returncode == 0, reverted.stderr.decode()
        absent = _psql(
            """
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND (
                  (
                      table_name = 'gpus'
                      AND column_name IN (
                          'hardware_uuid',
                          'gpu_allocation_group_id',
                          'gpu_allocation_group_generation'
                      )
                  )
                  OR (
                      table_name = 'servers'
                      AND column_name = 'kubernetes_node_generation'
                  )
              );
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = 'server_node_identities';
            """,
            schema=schema,
            tuples_only=True,
        )
        assert absent.returncode == 0, absent.stderr.decode()
        assert [line.strip() for line in absent.stdout.decode().splitlines() if line.strip()] == [
            "0",
            "0",
        ]
    finally:
        dropped = _psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;')
        assert dropped.returncode == 0, dropped.stderr.decode()
