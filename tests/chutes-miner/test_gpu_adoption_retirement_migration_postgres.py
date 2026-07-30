"""Real-PostgreSQL checks for immutable seedless GPU retirement history."""

from __future__ import annotations

import os
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.schema import CreateIndex, CreateTable

from chutes_common.schemas.gpu_adoption import GPUAdoptionRetirement
from chutes_miner.api.schema_barrier import seedless_adoption_blockers


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for miner migration tests",
)
ROOT = Path(__file__).resolve().parents[2]
MIGRATION = (
    ROOT
    / "src/chutes-miner/chutes_miner/api/migrations/"
    "20260730160000_gpu_adoption_retirement.sql"
)
UP_SQL, DOWN_SQL = MIGRATION.read_text(encoding="utf-8").split("-- migrate:down", 1)


def _connection(*, schema: str | None = None) -> tuple[str, dict[str, str]]:
    parsed = urlsplit(TEST_DATABASE_URL.replace("+asyncpg", ""))
    url = f"postgresql://{parsed.username}@{parsed.hostname}:{parsed.port}{parsed.path}"
    environment = {**os.environ, "PGPASSWORD": parsed.password or ""}
    if schema:
        environment["PGOPTIONS"] = f"-c search_path={schema}"
    return url, environment


def _psql(
    sql: str,
    *,
    schema: str | None = None,
    tuples_only: bool = False,
) -> subprocess.CompletedProcess:
    url, environment = _connection(schema=schema)
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


def _assert_ok(result: subprocess.CompletedProcess) -> None:
    assert result.returncode == 0, result.stderr.decode()


def _asyncpg_url() -> str:
    if TEST_DATABASE_URL.startswith("postgresql+asyncpg://"):
        return TEST_DATABASE_URL
    return TEST_DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)


def _metadata_ddl() -> str:
    table = GPUAdoptionRetirement.__table__
    dialect = postgresql.dialect()
    statements = [str(CreateTable(table).compile(dialect=dialect))]
    statements.extend(
        str(CreateIndex(index).compile(dialect=dialect)) for index in table.indexes
    )
    return ";\n".join(statements) + ";"


@pytest.mark.parametrize("baseline", ["migration", "metadata"])
def test_retirement_audit_has_no_fks_and_rejects_update_or_delete(baseline: str):
    schema = f"miner_gpu_retirement_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    try:
        if baseline == "metadata":
            _assert_ok(_psql(_metadata_ddl(), schema=schema))
        _assert_ok(_psql(UP_SQL, schema=schema))
        # UP is reentrant on both a pure migration and a create_all-first catalog. Empty history
        # can roll back, but once audit data exists DOWN must preserve it.
        _assert_ok(_psql(UP_SQL, schema=schema))
        _assert_ok(_psql(DOWN_SQL, schema=schema))
        _assert_ok(_psql(UP_SQL, schema=schema))
        _assert_ok(
            _psql(
                """
                INSERT INTO gpu_adoption_retirements (
                    retirement_id,
                    server_id,
                    gpu_id,
                    hardware_uuid,
                    deployment_id,
                    validator,
                    device_info,
                    model_short_ref,
                    verified,
                    prior_gpu_allocation_group_id,
                    prior_gpu_allocation_group_generation,
                    replacement_registration_attestation_id,
                    replacement_gpu_allocation_group_id,
                    replacement_gpu_allocation_group_generation
                ) VALUES (
                    'retirement-1',
                    'deleted-server',
                    'local-gpu-1',
                    'GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                    NULL,
                    'validator-1',
                    '{"uuid":"GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}'::JSONB,
                    'h100_sxm',
                    TRUE,
                    'group-1',
                    7,
                    'attestation-2',
                    'group-2',
                    8
                );
                """,
                schema=schema,
            )
        )
        inspected = _psql(
            """
            SELECT COUNT(*)
            FROM pg_constraint
            WHERE conrelid = 'gpu_adoption_retirements'::regclass
              AND contype = 'f';
            SELECT deployment_id IS NULL, reason
            FROM gpu_adoption_retirements
            WHERE retirement_id = 'retirement-1';
            """,
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(inspected)
        assert [
            line.strip()
            for line in inspected.stdout.decode().splitlines()
            if line.strip()
        ] == ["0", "t|registrar_assignment_shrink"]

        for mutation in (
            "UPDATE gpu_adoption_retirements SET validator = 'changed';",
            "DELETE FROM gpu_adoption_retirements;",
            "TRUNCATE gpu_adoption_retirements;",
        ):
            rejected = _psql(mutation, schema=schema)
            assert rejected.returncode != 0
            assert b"gpu adoption retirement audit rows are immutable" in rejected.stderr

        remaining = _psql(
            "SELECT COUNT(*) FROM gpu_adoption_retirements;",
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(remaining)
        assert remaining.stdout.decode().strip() == "1"

        rejected_down = _psql(DOWN_SQL, schema=schema)
        assert rejected_down.returncode != 0
        assert (
            b"cannot roll back GPU adoption retirement audit while history exists"
            in rejected_down.stderr
        )
        preserved = _psql(
            "SELECT COUNT(*) FROM gpu_adoption_retirements;",
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(preserved)
        assert preserved.stdout.decode().strip() == "1"
    finally:
        _assert_ok(_psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;'))


@pytest.mark.asyncio
async def test_uuid_null_deployment_row_is_an_exact_adoption_blocker():
    schema = f"miner_gpu_blocker_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    engine = create_async_engine(
        _asyncpg_url(),
        connect_args={"server_settings": {"search_path": schema}},
    )
    try:
        _assert_ok(
            _psql(
                """
                CREATE TABLE gpus (
                    gpu_id TEXT PRIMARY KEY,
                    server_id TEXT NOT NULL,
                    deployment_id TEXT,
                    hardware_uuid TEXT,
                    device_info JSONB
                );
                INSERT INTO gpus (
                    gpu_id, server_id, deployment_id, hardware_uuid, device_info
                ) VALUES (
                    'legacy-local-id', 'logical-server', 'deployment-live', NULL, '{}'::JSONB
                );
                """,
                schema=schema,
            )
        )
        identity = {
            "server_id": "logical-server",
            "validator": {"hotkey": "validator-1"},
            "attestation_id": "attestation-1",
            "allocation_group_id": "group-1",
            "allocation_group_generation": 2,
            "gpu_uuids": ["GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"],
        }
        assert await seedless_adoption_blockers(engine, identity) == [
            ("legacy-local-id", "deployment-live")
        ]
    finally:
        await engine.dispose()
        _assert_ok(_psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;'))
