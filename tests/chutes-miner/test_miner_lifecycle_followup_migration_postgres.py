"""Real-PostgreSQL parity and locking tests for the miner lifecycle follow-up."""

from __future__ import annotations

import asyncio
import os
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import chutes_common.schemas.orms  # noqa: F401
import pytest
from chutes_common.schemas import Base
from sqlalchemy.ext.asyncio import create_async_engine


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for miner migration tests",
)
ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "src/chutes-miner/chutes_miner/api/migrations"
DURABLE_SQL = (MIGRATIONS / "20260726120000_durable_deployment_teardown.sql").read_text(
    encoding="utf-8"
)
DURABLE_UP = DURABLE_SQL.split("-- migrate:down", 1)[0]
FOLLOWUP_SQL = (MIGRATIONS / "20260727120000_miner_lifecycle_followup.sql").read_text(
    encoding="utf-8"
)
FOLLOWUP_UP, FOLLOWUP_DOWN = FOLLOWUP_SQL.split("-- migrate:down", 1)


def _connection(
    *,
    schema: str | None = None,
    lock_timeout: str | None = None,
) -> tuple[str, dict[str, str]]:
    parsed = urlsplit(TEST_DATABASE_URL.replace("+asyncpg", ""))
    url = f"postgresql://{parsed.username}@{parsed.hostname}:{parsed.port}{parsed.path}"
    environment = {**os.environ, "PGPASSWORD": parsed.password or ""}
    options = []
    if schema:
        options.append(f"-c search_path={schema}")
    if lock_timeout:
        options.append(f"-c lock_timeout={lock_timeout}")
    if options:
        environment["PGOPTIONS"] = " ".join(options)
    return url, environment


def _psql(
    sql: str,
    *,
    schema: str | None = None,
    lock_timeout: str | None = None,
    tuples_only: bool = False,
) -> subprocess.CompletedProcess:
    url, environment = _connection(schema=schema, lock_timeout=lock_timeout)
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


def _create_deployed_baseline(schema: str) -> None:
    _assert_ok(
        _psql(
            """
            CREATE TABLE servers (server_id TEXT PRIMARY KEY);
            CREATE TABLE chutes (chute_id TEXT PRIMARY KEY);
            CREATE TABLE deployments (
                deployment_id TEXT PRIMARY KEY,
                chute_id TEXT NOT NULL REFERENCES chutes(chute_id) ON DELETE CASCADE,
                server_id TEXT NOT NULL REFERENCES servers(server_id)
                    ON UPDATE CASCADE ON DELETE CASCADE
            );
            CREATE TABLE gpus (
                gpu_id TEXT PRIMARY KEY,
                server_id TEXT NOT NULL REFERENCES servers(server_id)
                    ON UPDATE CASCADE ON DELETE CASCADE,
                deployment_id TEXT REFERENCES deployments(deployment_id) ON DELETE SET NULL
            );
            """,
            schema=schema,
        )
    )
    _assert_ok(_psql(f"BEGIN;\n{DURABLE_UP}\nCOMMIT;", schema=schema))


def _asyncpg_url() -> str:
    if TEST_DATABASE_URL.startswith("postgresql+asyncpg://"):
        return TEST_DATABASE_URL
    return TEST_DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)


def _create_all(schema: str) -> None:
    async def create() -> None:
        engine = create_async_engine(
            _asyncpg_url(),
            connect_args={"server_settings": {"search_path": schema}},
        )
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
        finally:
            await engine.dispose()

    asyncio.run(create())


@pytest.mark.parametrize("baseline", ["deployed", "metadata"])
def test_followup_applies_and_downs_on_both_supported_starting_schemas(baseline: str):
    schema = f"miner_lifecycle_{baseline}_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    try:
        if baseline == "deployed":
            _create_deployed_baseline(schema)
        else:
            _create_all(schema)

        _assert_ok(_psql(f"BEGIN;\n{FOLLOWUP_UP}\nCOMMIT;", schema=schema))
        inspected = _psql(
            """
            SELECT to_regclass('miner_launch_intents') IS NOT NULL;
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'deployment_launch_operations'
              AND column_name IN (
                  'cluster_context', 'cluster_context_sha256', 'namespace', 'server_name',
                  'canonical_workload_spec', 'canonical_workload_spec_sha256',
                  'launch_intent_id'
              );
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name IN (
                  'deployment_teardown_k8s_resources',
                  'kubernetes_orphan_tombstone_resources'
              )
              AND column_name = 'owner_api_version';
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name IN (
                  'deployment_teardown_k8s_resources',
                  'kubernetes_orphan_tombstone_resources'
              )
              AND column_name IN (
                  'pod_termination_evidence',
                  'pod_termination_evidence_sha256',
                  'pod_teardown_finalizer_attached_at',
                  'pod_teardown_finalizer_removal_requested_at',
                  'pod_teardown_finalizer_removed_at'
              );
            """,
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(inspected)
        assert [
            line.strip()
            for line in inspected.stdout.decode().splitlines()
            if line.strip()
        ] == ["t", "7", "2", "10"]

        _assert_ok(_psql(f"BEGIN;\n{FOLLOWUP_DOWN}\nCOMMIT;", schema=schema))
        restored = _psql(
            """
            SELECT to_regclass('miner_launch_intents') IS NULL;
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'deployment_launch_operations'
              AND column_name IN (
                  'cluster_context', 'cluster_context_sha256', 'namespace', 'server_name',
                  'canonical_workload_spec', 'canonical_workload_spec_sha256',
                  'launch_intent_id'
              );
            """,
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(restored)
        assert [
            line.strip() for line in restored.stdout.decode().splitlines() if line.strip()
        ] == ["t", "0"]
    finally:
        _assert_ok(_psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;'))


def test_followup_failed_down_preserves_catalog_and_history():
    schema = f"miner_lifecycle_guard_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    try:
        _create_deployed_baseline(schema)
        _assert_ok(_psql(f"BEGIN;\n{FOLLOWUP_UP}\nCOMMIT;", schema=schema))
        _assert_ok(
            _psql(
                """
                INSERT INTO miner_launch_intents (
                    intent_id, validator, chute_id, chute_version, server_id,
                    request_payload, request_sha256, lineage_sha256
                ) VALUES (
                    'intent-1', 'validator-1', 'chute-1', '1.0.0', 'server-1',
                    '{"schema":"chutes.miner-launch-request.v1"}',
                    repeat('a', 64), repeat('b', 64)
                );
                """,
                schema=schema,
            )
        )

        failed = _psql(f"BEGIN;\n{FOLLOWUP_DOWN}\nCOMMIT;", schema=schema)
        assert failed.returncode != 0
        assert b"launch intent history exists" in failed.stderr
        preserved = _psql(
            """
            SELECT COUNT(*) FROM miner_launch_intents;
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'deployment_launch_operations'
              AND column_name = 'launch_intent_id';
            """,
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(preserved)
        assert [
            line.strip() for line in preserved.stdout.decode().splitlines() if line.strip()
        ] == ["1", "1"]
    finally:
        _assert_ok(_psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;'))


def test_followup_triggers_require_validator_job_release_ack():
    schema = f"miner_lifecycle_job_ack_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    try:
        _create_deployed_baseline(schema)
        _assert_ok(_psql(f"BEGIN;\n{FOLLOWUP_UP}\nCOMMIT;", schema=schema))
        _assert_ok(
            _psql(
                """
                INSERT INTO servers (server_id) VALUES ('server-1');
                INSERT INTO chutes (chute_id) VALUES ('chute-1');
                INSERT INTO deployments (deployment_id, chute_id, server_id)
                VALUES
                    ('deployment-gpu', 'chute-1', 'server-1'),
                    ('deployment-delete', 'chute-1', 'server-1');
                INSERT INTO gpus (gpu_id, server_id, deployment_id)
                VALUES ('gpu-1', 'server-1', 'deployment-gpu');
                INSERT INTO deployment_teardown_operations (
                    operation_id, deployment_id, phase, reason, validator,
                    server_id, chute_id, job_id, cluster_context,
                    cluster_context_sha256, namespace,
                    kubernetes_node_generation, gpu_hardware_uuids,
                    immutable_labels, controllers_absent_at,
                    services_absent_at, pods_absent_at
                ) VALUES
                    (
                        'operation-gpu', 'deployment-gpu', 'finalizing', 'delete',
                        'validator-1', 'server-1', 'chute-1', 'job-gpu', 'node-1',
                        repeat('a', 64), 'chutes', 1, '["GPU-1"]', '{}',
                        NOW(), NOW(), NOW()
                    ),
                    (
                        'operation-delete', 'deployment-delete', 'finalizing', 'delete',
                        'validator-1', 'server-1', 'chute-1', 'job-delete', 'node-1',
                        repeat('b', 64), 'chutes', 1, '[]', '{}',
                        NOW(), NOW(), NOW()
                    );
                UPDATE deployments
                SET teardown_operation_id = CASE deployment_id
                    WHEN 'deployment-gpu' THEN 'operation-gpu'
                    ELSE 'operation-delete'
                END;
                """,
                schema=schema,
            )
        )

        gpu_release = _psql(
            "UPDATE gpus SET deployment_id = NULL WHERE gpu_id = 'gpu-1';",
            schema=schema,
        )
        assert gpu_release.returncode != 0
        assert b"cannot be released before teardown" in gpu_release.stderr
        deployment_delete = _psql(
            "DELETE FROM deployments WHERE deployment_id = 'deployment-delete';",
            schema=schema,
        )
        assert deployment_delete.returncode != 0
        assert b"has no verified durable teardown" in deployment_delete.stderr

        _assert_ok(
            _psql(
                """
                UPDATE deployment_teardown_operations
                SET validator_job_release_ack = '{"status":"released"}',
                    validator_job_released_at = NOW();
                UPDATE gpus SET deployment_id = NULL WHERE gpu_id = 'gpu-1';
                DELETE FROM deployments
                WHERE deployment_id IN ('deployment-gpu', 'deployment-delete');
                """,
                schema=schema,
            )
        )
    finally:
        _assert_ok(_psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;'))


def test_followup_down_lock_blocks_concurrent_writer_without_catalog_changes():
    schema = f"miner_lifecycle_lock_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    holder = None
    try:
        _create_deployed_baseline(schema)
        _assert_ok(_psql(f"BEGIN;\n{FOLLOWUP_UP}\nCOMMIT;", schema=schema))
        url, environment = _connection(schema=schema)
        holder = subprocess.Popen(
            ["psql", url, "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        holder.stdin.write(
            "BEGIN; LOCK TABLE miner_launch_intents IN ROW EXCLUSIVE MODE; "
            "SELECT 'LOCKED';\n"
        )
        holder.stdin.flush()
        assert holder.stdout.readline().strip() == "LOCKED"

        blocked = _psql(
            f"BEGIN;\n{FOLLOWUP_DOWN}\nCOMMIT;",
            schema=schema,
            lock_timeout="250ms",
        )
        assert blocked.returncode != 0
        assert b"lock timeout" in blocked.stderr
        preserved = _psql(
            "SELECT to_regclass('miner_launch_intents') IS NOT NULL;",
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(preserved)
        assert preserved.stdout.decode().strip() == "t"
    finally:
        if holder is not None:
            if holder.poll() is None:
                holder.stdin.write("ROLLBACK;\\q\n")
                holder.stdin.flush()
            holder.communicate(timeout=5)
        _assert_ok(_psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;'))
