"""Real-PostgreSQL checks for teardown frontier and parent allocation fencing."""

from __future__ import annotations

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
ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "src/chutes-miner/chutes_miner/api/migrations"
DURABLE_UP = (
    (MIGRATIONS / "20260726120000_durable_deployment_teardown.sql")
    .read_text(encoding="utf-8")
    .split("-- migrate:down", 1)[0]
)
FOLLOWUP_UP = (
    (MIGRATIONS / "20260727120000_miner_lifecycle_followup.sql")
    .read_text(encoding="utf-8")
    .split("-- migrate:down", 1)[0]
)
FRONTIER_UP, FRONTIER_DOWN = (
    (MIGRATIONS / "20260730140000_teardown_frontier_parent_hold.sql")
    .read_text(encoding="utf-8")
    .split("-- migrate:down", 1)
)


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


def _create_baseline(schema: str) -> None:
    _assert_ok(
        _psql(
            """
            CREATE EXTENSION IF NOT EXISTS pgcrypto;
            CREATE TABLE servers (
                server_id TEXT PRIMARY KEY,
                gpu_allocation_group_id TEXT,
                gpu_allocation_group_generation INTEGER
            );
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
                deployment_id TEXT REFERENCES deployments(deployment_id) ON DELETE SET NULL,
                gpu_allocation_group_id TEXT,
                gpu_allocation_group_generation INTEGER
            );
            """,
            schema=schema,
        )
    )
    _assert_ok(_psql(f"BEGIN;\n{DURABLE_UP}\nCOMMIT;", schema=schema))
    _assert_ok(_psql(f"BEGIN;\n{FOLLOWUP_UP}\nCOMMIT;", schema=schema))


def test_frontier_backfill_and_parent_allocation_fence_are_enforced():
    schema = f"miner_teardown_frontier_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    try:
        _create_baseline(schema)
        _assert_ok(
            _psql(
                """
                INSERT INTO servers (server_id) VALUES ('server-1');
                INSERT INTO chutes (chute_id) VALUES ('chute-1');
                INSERT INTO deployments (deployment_id, chute_id, server_id)
                VALUES ('deployment-1', 'chute-1', 'server-1');
                INSERT INTO gpus (gpu_id, server_id, deployment_id)
                VALUES ('gpu-1', 'server-1', 'deployment-1');
                INSERT INTO deployment_launch_operations (
                    operation_id, deployment_id, phase, immutable_labels,
                    cluster_context, namespace, server_name, create_results
                ) VALUES (
                    'launch-1', 'deployment-1', 'teardown_fenced', '{}'::JSONB,
                    'node-a', 'chutes', 'node-a', '{}'::JSONB
                );
                INSERT INTO deployment_teardown_operations (
                    operation_id, deployment_id, phase, reason, validator,
                    server_id, chute_id, cluster_context, cluster_context_sha256,
                    namespace, kubernetes_node_generation, gpu_hardware_uuids,
                    immutable_labels, launch_operation_id, launch_phase_at_request,
                    launch_kubernetes_mutation_possible,
                    launch_create_results_sha256
                ) VALUES (
                    'teardown-1', 'deployment-1', 'requested', 'test', 'validator-1',
                    'server-1', 'chute-1', 'node-a', repeat('a', 64), 'chutes', 0,
                    '["GPU-1"]'::JSONB, '{}'::JSONB, 'launch-1', 'created', TRUE,
                    encode(sha256(convert_to('{}', 'UTF8')), 'hex')
                );
                UPDATE deployments
                SET launch_operation_id = 'launch-1',
                    teardown_operation_id = 'teardown-1'
                WHERE deployment_id = 'deployment-1';
                """,
                schema=schema,
            )
        )

        _assert_ok(_psql(f"BEGIN;\n{FRONTIER_UP}\nCOMMIT;", schema=schema))
        inspected = _psql(
            """
            SELECT
                launch_frontier ->> 'schema',
                launch_frontier ->> 'operation_id',
                launch_frontier_sha256 = encode(
                    sha256(
                        convert_to(
                            canonical_miner_teardown_jsonb(launch_frontier),
                            'UTF8'
                        )
                    ),
                    'hex'
                ),
                deployment_teardown_launch_frontier_complete(
                    deployment_id,
                    operation_id
                )
            FROM deployment_teardown_operations
            WHERE operation_id = 'teardown-1';
            """,
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(inspected)
        assert inspected.stdout.decode().strip() == (
            "chutes.miner-launch-frontier.v1|launch-1|t|t"
        )

        _assert_ok(
            _psql(
                """
                UPDATE deployment_teardown_operations
                SET phase = 'discovering',
                    retry_lease_owner = 'test-worker',
                    retry_lease_expires_at = NOW() + INTERVAL '5 minutes'
                WHERE operation_id = 'teardown-1';

                INSERT INTO deployment_teardown_k8s_resources (
                    resource_id, operation_id, cluster_context, namespace,
                    api_version, kind, name, uid, node_name, labels,
                    labels_sha256, state
                ) VALUES (
                    'pod-row', 'teardown-1', 'node-a', 'chutes', 'v1', 'Pod',
                    'pod-a', 'pod-uid', 'node-a', '{}'::JSONB,
                    encode(sha256(convert_to('{}', 'UTF8')), 'hex'),
                    'delete_requested'
                );

                WITH discovery AS (
                    SELECT jsonb_build_object(
                        'schema', 'chutes.miner-k8s-resource-discovery.v1',
                        'operation_id', 'teardown-1',
                        'deployment_id', 'deployment-1',
                        'cluster_context', 'node-a',
                        'cluster_context_sha256', repeat('a', 64),
                        'namespace', 'chutes',
                        'config_id', NULL,
                        'immutable_labels_sha256',
                            encode(sha256(convert_to('{}', 'UTF8')), 'hex'),
                        'launch_operation_id', 'launch-1',
                        'launch_phase_at_request', 'created',
                        'launch_kubernetes_mutation_possible', TRUE,
                        'launch_create_results_sha256',
                            encode(sha256(convert_to('{}', 'UTF8')), 'hex'),
                        'resources', jsonb_build_array(jsonb_build_object(
                            'api_version', 'v1',
                            'kind', 'Pod',
                            'name', 'pod-a',
                            'namespace', 'chutes',
                            'uid', 'pod-uid',
                            'owner_api_version', NULL,
                            'owner_kind', NULL,
                            'owner_name', NULL,
                            'owner_uid', NULL,
                            'node_name', 'node-a',
                            'labels_sha256',
                                encode(sha256(convert_to('{}', 'UTF8')), 'hex')
                        ))
                    ) AS document
                )
                UPDATE deployment_teardown_operations op
                SET resource_discovery = discovery.document,
                    resource_discovery_sha256 = encode(
                        sha256(
                            convert_to(
                                canonical_miner_teardown_jsonb(discovery.document),
                                'UTF8'
                            )
                        ),
                        'hex'
                    ),
                    resource_discovered_at = NOW()
                FROM discovery
                WHERE op.operation_id = 'teardown-1';

                WITH evidence AS (
                    SELECT jsonb_build_object(
                        'schema', 'chutes.miner-pod-uid-absence.v1',
                        'outcome', 'uid_absent',
                        'operation_id', op.operation_id,
                        'pod_uid', 'pod-uid',
                        'node_name', 'node-a',
                        'resource_discovery_sha256', op.resource_discovery_sha256,
                        'read_status', 404,
                        'selector_absent', TRUE
                    ) AS document
                    FROM deployment_teardown_operations op
                    WHERE op.operation_id = 'teardown-1'
                )
                UPDATE deployment_teardown_k8s_resources resource
                SET pod_uid_absence_evidence = evidence.document,
                    pod_uid_absence_evidence_sha256 = encode(
                        sha256(
                            convert_to(
                                canonical_miner_teardown_jsonb(evidence.document),
                                'UTF8'
                            )
                        ),
                        'hex'
                    ),
                    pod_uid_absence_observed_at = NOW(),
                    state = 'absent',
                    absent_at = NOW()
                FROM evidence
                WHERE resource.resource_id = 'pod-row';

                UPDATE deployment_teardown_operations
                SET phase = 'finalizing',
                    controllers_absent_at = NOW(),
                    services_absent_at = NOW(),
                    pods_absent_at = NOW(),
                    retry_lease_owner = NULL,
                    retry_lease_expires_at = NULL
                WHERE operation_id = 'teardown-1';
                """,
                schema=schema,
            )
        )
        closure = _psql(
            """
            SELECT deployment_teardown_extended_closure_complete(
                'deployment-1', 'teardown-1'
            );
            """,
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(closure)
        assert closure.stdout.decode().strip() == "t"
        released = _psql(
            """
            UPDATE gpus SET deployment_id = NULL WHERE gpu_id = 'gpu-1';
            SELECT deployment_id IS NULL FROM gpus WHERE gpu_id = 'gpu-1';
            """,
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(released)
        assert released.stdout.decode().splitlines()[-1] == "t"

        immutable_absence = _psql(
            """
            UPDATE deployment_teardown_k8s_resources
            SET pod_uid_absence_evidence = jsonb_set(
                pod_uid_absence_evidence,
                '{selector_absent}',
                'false'::JSONB
            )
            WHERE resource_id = 'pod-row';
            """,
            schema=schema,
        )
        assert immutable_absence.returncode != 0
        assert b"Pod lifecycle observation is immutable" in immutable_absence.stderr

        _assert_ok(
            _psql(
                """
                INSERT INTO parent_deletion_operations (
                    operation_id, parent_type, parent_id, validator, reason,
                    phase, snapshot
                ) VALUES (
                    'parent-1', 'server', 'server-1', 'validator-1', 'node_missing',
                    'waiting_for_children',
                    '{"name":"node-a","allocation_group_id":null,
                      "allocation_group_generation":null}'::JSONB
                );
                """,
                schema=schema,
            )
        )
        blocked_server = _psql(
            """
            UPDATE servers
            SET gpu_allocation_group_id = 'group-1',
                gpu_allocation_group_generation = 1
            WHERE server_id = 'server-1';
            """,
            schema=schema,
        )
        assert blocked_server.returncode != 0
        assert b"allocation ownership is fenced by parent deletion" in blocked_server.stderr

        blocked_gpu = _psql(
            """
            UPDATE gpus
            SET gpu_allocation_group_id = 'group-1',
                gpu_allocation_group_generation = 1
            WHERE gpu_id = 'gpu-1';
            """,
            schema=schema,
        )
        assert blocked_gpu.returncode != 0
        assert b"allocation ownership is fenced by parent deletion" in blocked_gpu.stderr

        _assert_ok(
            _psql(
                """
                INSERT INTO servers (server_id) VALUES ('server-2');
                INSERT INTO parent_deletion_operations (
                    operation_id, parent_type, parent_id, validator, reason,
                    phase, snapshot, monitor_stop_ack, monitor_stopped_at,
                    validator_server_deletion_ack, validator_server_deleted_at
                ) VALUES (
                    'parent-2', 'server', 'server-2', 'validator-1', 'node_missing',
                    'finalizing',
                    '{"name":"node-b","allocation_group_id":null,
                      "allocation_group_generation":null}'::JSONB,
                    '{"status":"stopped"}'::JSONB, NOW(),
                    '{"status":"deleted"}'::JSONB, NOW()
                );
                """,
                schema=schema,
            )
        )
        missing_release = _psql(
            "DELETE FROM servers WHERE server_id = 'server-2';",
            schema=schema,
        )
        assert missing_release.returncode != 0
        assert b"has no durable parent deletion" in missing_release.stderr

        deleted = _psql(
            """
            WITH evidence AS (
                SELECT jsonb_build_object(
                    'schema', 'chutes.miner-parent-allocation-release.v1',
                    'operation_id', op.operation_id,
                    'server_id', op.parent_id,
                    'snapshot_allocation_group_id',
                        op.snapshot -> 'allocation_group_id',
                    'snapshot_allocation_group_generation',
                        op.snapshot -> 'allocation_group_generation',
                    'server_allocation_released', TRUE,
                    'gpu_allocation_generations_owned', '[]'::JSONB
                ) AS document
                FROM parent_deletion_operations op
                WHERE op.operation_id = 'parent-2'
            )
            UPDATE parent_deletion_operations op
            SET allocation_release_evidence = evidence.document,
                allocation_release_evidence_sha256 = encode(
                    sha256(
                        convert_to(
                            canonical_miner_teardown_jsonb(evidence.document),
                            'UTF8'
                        )
                    ),
                    'hex'
                ),
                allocation_release_verified_at = NOW()
            FROM evidence
            WHERE op.operation_id = 'parent-2';
            DELETE FROM servers WHERE server_id = 'server-2';
            SELECT COUNT(*) FROM servers WHERE server_id = 'server-2';
            """,
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(deleted)
        assert deleted.stdout.decode().splitlines()[-1] == "0"

        chute_deleted = _psql(
            """
            INSERT INTO chutes (chute_id) VALUES ('chute-2');
            INSERT INTO parent_deletion_operations (
                operation_id, parent_type, parent_id, validator, reason,
                phase, snapshot
            ) VALUES (
                'parent-chute-2', 'chute', 'chute-2', 'validator-1',
                'operator_delete', 'finalizing',
                '{"name":"chute-2","version":"1"}'::JSONB
            );
            DELETE FROM chutes WHERE chute_id = 'chute-2';
            SELECT COUNT(*) FROM chutes WHERE chute_id = 'chute-2';
            """,
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(chute_deleted)
        assert chute_deleted.stdout.decode().splitlines()[-1] == "0"
    finally:
        _assert_ok(_psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;'))


def test_empty_frontier_migration_round_trip_restores_prior_contract():
    schema = f"miner_teardown_frontier_down_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    try:
        _create_baseline(schema)
        _assert_ok(_psql(f"BEGIN;\n{FRONTIER_UP}\nCOMMIT;", schema=schema))
        _assert_ok(_psql(f"BEGIN;\n{FRONTIER_DOWN}\nCOMMIT;", schema=schema))
        inspected = _psql(
            """
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND column_name IN (
                  'launch_frontier',
                  'pod_uid_absence_evidence',
                  'allocation_release_evidence'
              );
            SELECT COUNT(*)
            FROM pg_constraint
            WHERE connamespace = current_schema()::regnamespace
              AND conname IN (
                  'ck_deployment_teardown_launch_snapshot',
                  'ck_deployment_teardown_resource_pod_termination'
              );
            """,
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(inspected)
        assert [line for line in inspected.stdout.decode().splitlines() if line] == [
            "0",
            "2",
        ]
    finally:
        _assert_ok(_psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;'))
