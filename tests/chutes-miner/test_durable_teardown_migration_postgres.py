"""Real-PostgreSQL parity and locking tests for durable miner teardown."""

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
MIGRATION = (
    ROOT
    / "src/chutes-miner/chutes_miner/api/migrations/"
    "20260726120000_durable_deployment_teardown.sql"
)
UP_SQL, DOWN_SQL = MIGRATION.read_text(encoding="utf-8").split("-- migrate:down", 1)


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
def test_teardown_migration_applies_to_both_supported_starting_schemas(baseline: str):
    schema = f"miner_teardown_{baseline}_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    try:
        if baseline == "deployed":
            _create_deployed_baseline(schema)
        else:
            _create_all(schema)

        _assert_ok(_psql(f"BEGIN;\n{UP_SQL}\nCOMMIT;", schema=schema))
        inspected = _psql(
            """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name IN (
                  'deployment_teardown_operations',
                  'deployment_teardown_node_incarnation_handoffs',
                  'deployment_teardown_k8s_resources',
                  'deployment_launch_operations',
                  'delayed_validator_instance_cleanups',
                  'parent_deletion_operations',
                  'parent_deletion_children',
                  'kubernetes_orphan_tombstones',
                  'kubernetes_orphan_tombstone_resources'
              );
            SELECT COUNT(*)
            FROM information_schema.triggers
            WHERE event_object_schema = current_schema()
              AND trigger_name IN (
                  'deployments_require_teardown',
                  'gpus_require_teardown',
                  'servers_require_parent_deletion',
                  'chutes_require_parent_deletion',
                  'deployments_fence_parent_deletion'
              );
            """,
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(inspected)
        assert [
            line.strip() for line in inspected.stdout.decode().splitlines() if line.strip()
        ] == ["9", "5"]

        _assert_ok(_psql(f"BEGIN;\n{DOWN_SQL}\nCOMMIT;", schema=schema))
        restored = _psql(
            """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name IN (
                  'deployment_teardown_operations',
                  'deployment_teardown_node_incarnation_handoffs',
                  'deployment_teardown_k8s_resources',
                  'deployment_launch_operations',
                  'delayed_validator_instance_cleanups',
                  'parent_deletion_operations',
                  'parent_deletion_children',
                  'kubernetes_orphan_tombstones',
                  'kubernetes_orphan_tombstone_resources'
              );
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'deployments'
              AND column_name IN ('teardown_operation_id', 'launch_operation_id');
            """,
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(restored)
        assert [
            line.strip() for line in restored.stdout.decode().splitlines() if line.strip()
        ] == ["0", "0"]
    finally:
        _assert_ok(_psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;'))


def test_teardown_guards_require_the_bound_operation_and_failed_down_is_atomic():
    schema = f"miner_teardown_guard_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    try:
        _create_deployed_baseline(schema)
        _assert_ok(_psql(f"BEGIN;\n{UP_SQL}\nCOMMIT;", schema=schema))
        _assert_ok(
            _psql(
                """
                INSERT INTO servers VALUES ('server-1');
                INSERT INTO chutes VALUES ('chute-1');
                INSERT INTO deployments (deployment_id, chute_id, server_id)
                    VALUES ('deployment-1', 'chute-1', 'server-1');
                INSERT INTO gpus VALUES ('gpu-1', 'server-1', 'deployment-1');
                INSERT INTO deployment_teardown_operations (
                    operation_id, deployment_id, phase, reason, validator,
                    server_id, chute_id, cluster_context, cluster_context_sha256,
                    namespace, kubernetes_node_generation, gpu_hardware_uuids,
                    immutable_labels, controllers_absent_at, services_absent_at,
                    pods_absent_at
                ) VALUES (
                    'operation-1', 'deployment-1', 'finalizing', 'test', 'validator-1',
                    'server-1', 'chute-1', 'node-1', repeat('a', 64), 'chutes', 1,
                    '["GPU-1"]', '{"chutes/deployment-id":"deployment-1"}',
                    NOW(), NOW(), NOW()
                );
                """,
                schema=schema,
            )
        )
        unbound_gpu_release = _psql(
            "UPDATE gpus SET deployment_id = NULL WHERE gpu_id = 'gpu-1';",
            schema=schema,
        )
        assert unbound_gpu_release.returncode != 0
        assert b"cannot be released before teardown" in unbound_gpu_release.stderr
        unbound_delete = _psql(
            "DELETE FROM deployments WHERE deployment_id = 'deployment-1';",
            schema=schema,
        )
        assert unbound_delete.returncode != 0
        assert b"no verified durable teardown" in unbound_delete.stderr

        _assert_ok(
            _psql(
                """
                UPDATE deployments SET teardown_operation_id = 'operation-1'
                WHERE deployment_id = 'deployment-1';
                UPDATE gpus SET deployment_id = NULL WHERE gpu_id = 'gpu-1';
                DELETE FROM deployments WHERE deployment_id = 'deployment-1';
                """,
                schema=schema,
            )
        )

        failed_down = _psql(f"BEGIN;\n{DOWN_SQL}\nCOMMIT;", schema=schema)
        assert failed_down.returncode != 0
        assert b"cannot remove durable teardown schema" in failed_down.stderr
        preserved = _psql(
            """
            SELECT COUNT(*) FROM deployment_teardown_operations;
            SELECT COUNT(*) FROM information_schema.triggers
            WHERE event_object_schema = current_schema()
              AND trigger_name = 'gpus_require_teardown';
            SELECT COUNT(*) FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'deployments'
              AND column_name = 'teardown_operation_id';
            """,
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(preserved)
        assert [
            line.strip() for line in preserved.stdout.decode().splitlines() if line.strip()
        ] == ["1", "1", "1"]
    finally:
        _assert_ok(_psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;'))


def test_down_exclusive_lock_blocks_concurrent_writer_without_catalog_changes():
    schema = f"miner_teardown_lock_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    holder = None
    try:
        _create_deployed_baseline(schema)
        _assert_ok(_psql(f"BEGIN;\n{UP_SQL}\nCOMMIT;", schema=schema))
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
            "BEGIN; LOCK TABLE deployments IN ROW EXCLUSIVE MODE; SELECT 'LOCKED';\n"
        )
        holder.stdin.flush()
        assert holder.stdout.readline().strip() == "LOCKED"

        blocked_down = _psql(
            f"BEGIN;\n{DOWN_SQL}\nCOMMIT;",
            schema=schema,
            lock_timeout="250ms",
        )
        assert blocked_down.returncode != 0
        assert b"lock timeout" in blocked_down.stderr
        preserved = _psql(
            "SELECT to_regclass('deployment_teardown_operations') IS NOT NULL;",
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
