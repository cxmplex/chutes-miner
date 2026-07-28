"""Real-PostgreSQL parity and locking tests for the miner lifecycle follow-up."""

from __future__ import annotations

import asyncio
import hashlib
import json
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


def _canonical_sha256(document: object) -> str:
    return hashlib.sha256(
        json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


def _jsonb(document: object) -> str:
    return (
        "$document$"
        + json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "$document$::jsonb"
    )


def _resource_witness(
    *,
    api_version: str,
    kind: str,
    name: str,
    uid: str,
    node_name: str | None,
) -> dict[str, object]:
    return {
        "api_version": api_version,
        "kind": kind,
        "name": name,
        "namespace": "chutes",
        "uid": uid,
        "owner_api_version": None,
        "owner_kind": None,
        "owner_name": None,
        "owner_uid": None,
        "node_name": node_name,
        "labels_sha256": _canonical_sha256({}),
    }


def _discovery_witness(
    *,
    operation_id: str,
    deployment_id: str,
    cluster_context_sha256: str,
    resources: list[dict[str, object]],
    launch_operation_id: str | None = None,
    launch_phase_at_request: str | None = None,
    launch_kubernetes_mutation_possible: bool | None = None,
    launch_create_results_sha256: str | None = None,
) -> tuple[dict[str, object], str]:
    document = {
        "schema": "chutes.miner-k8s-resource-discovery.v1",
        "operation_id": operation_id,
        "deployment_id": deployment_id,
        "cluster_context": "node-1",
        "cluster_context_sha256": cluster_context_sha256,
        "namespace": "chutes",
        "config_id": None,
        "immutable_labels_sha256": _canonical_sha256({}),
        "launch_operation_id": launch_operation_id,
        "launch_phase_at_request": launch_phase_at_request,
        "launch_kubernetes_mutation_possible": (launch_kubernetes_mutation_possible),
        "launch_create_results_sha256": launch_create_results_sha256,
        "resources": resources,
    }
    return document, _canonical_sha256(document)


def _pod_termination_evidence(uid: str) -> tuple[dict[str, object], str]:
    document = {
        "schema": "chutes.miner-pod-termination.v1",
        "pod_uid": uid,
        "node_name": "node-1",
        "teardown_finalizer": "chutes.ai/gpu-teardown-v1",
        "deletion_timestamp": "2026-07-28T10:00:00Z",
        "containers": [
            {
                "group": "container",
                "name": "worker",
                "outcome": "terminated",
                "container_id": "containerd://terminated-worker",
                "exit_code": 0,
                "signal": 0,
                "reason": "Completed",
                "started_at": "2026-07-28T09:59:00Z",
                "finished_at": "2026-07-28T10:00:00Z",
            }
        ],
    }
    return document, _canonical_sha256(document)


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
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'deployment_teardown_operations'
              AND column_name IN (
                  'launch_operation_id', 'launch_phase_at_request',
                  'launch_kubernetes_mutation_possible',
                  'launch_create_results_sha256', 'resource_discovery',
                  'resource_discovery_sha256', 'resource_discovered_at'
              );
            """,
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(inspected)
        assert [
            line.strip() for line in inspected.stdout.decode().splitlines() if line.strip()
        ] == ["t", "7", "2", "10", "7"]

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
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'deployment_teardown_operations'
              AND column_name IN (
                  'launch_operation_id', 'launch_phase_at_request',
                  'launch_kubernetes_mutation_possible',
                  'launch_create_results_sha256', 'resource_discovery',
                  'resource_discovery_sha256', 'resource_discovered_at'
              );
            """,
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(restored)
        assert [line.strip() for line in restored.stdout.decode().splitlines() if line.strip()] == [
            "t",
            "0",
            "0",
        ]
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
                INSERT INTO deployment_launch_operations (
                    operation_id, deployment_id, phase, immutable_labels,
                    create_results
                ) VALUES (
                    'launch-gpu', 'deployment-gpu', 'teardown_fenced', '{}', '{}'
                );
                INSERT INTO deployment_teardown_operations (
                    operation_id, deployment_id, phase, reason, validator,
                    server_id, chute_id, job_id, cluster_context,
                    cluster_context_sha256, namespace,
                    kubernetes_node_generation, gpu_hardware_uuids,
                    immutable_labels, launch_operation_id,
                    launch_phase_at_request,
                    launch_kubernetes_mutation_possible,
                    launch_create_results_sha256,
                    controllers_absent_at, services_absent_at, pods_absent_at
                ) VALUES
                    (
                        'operation-gpu', 'deployment-gpu', 'discovering', 'delete',
                        'validator-1', 'server-1', 'chute-1', 'job-gpu', 'node-1',
                        repeat('a', 64), 'chutes', 1, '["gpu-1"]', '{}',
                        'launch-gpu', 'reserved', FALSE,
                        encode(sha256(convert_to('{}', 'UTF8')), 'hex'),
                        NOW(), NOW(), NOW()
                    ),
                    (
                        'operation-delete', 'deployment-delete', 'discovering',
                        'delete', 'validator-1', 'server-1', 'chute-1',
                        'job-delete', 'node-1', repeat('b', 64), 'chutes', 1,
                        '[]', '{}', NULL, NULL, NULL, NULL,
                        NOW(), NOW(), NOW()
                    );
                UPDATE deployments
                SET teardown_operation_id = CASE deployment_id
                    WHEN 'deployment-gpu' THEN 'operation-gpu'
                    ELSE 'operation-delete'
                END;
                WITH discovery AS (
                    SELECT
                        operation_id,
                        jsonb_build_object(
                            'schema', 'chutes.miner-k8s-resource-discovery.v1',
                            'operation_id', operation_id,
                            'deployment_id', deployment_id,
                            'cluster_context', cluster_context,
                            'cluster_context_sha256', cluster_context_sha256,
                            'namespace', namespace,
                            'config_id', config_id,
                            'immutable_labels_sha256', encode(
                                sha256(convert_to(
                                    canonical_miner_teardown_jsonb(immutable_labels),
                                    'UTF8'
                                )),
                                'hex'
                            ),
                            'launch_operation_id', launch_operation_id,
                            'launch_phase_at_request', launch_phase_at_request,
                            'launch_kubernetes_mutation_possible',
                                launch_kubernetes_mutation_possible,
                            'launch_create_results_sha256',
                                launch_create_results_sha256,
                            'resources', '[]'::jsonb
                        ) AS document
                    FROM deployment_teardown_operations
                )
                UPDATE deployment_teardown_operations operation
                SET resource_discovery = discovery.document,
                    resource_discovery_sha256 = encode(
                        sha256(convert_to(
                            canonical_miner_teardown_jsonb(discovery.document),
                            'UTF8'
                        )),
                        'hex'
                    ),
                    resource_discovered_at = NOW()
                FROM discovery
                WHERE discovery.operation_id = operation.operation_id;
                UPDATE deployment_teardown_operations SET phase = 'finalizing';
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


def test_release_guard_rejects_empty_gpu_discovery_after_mutation_frontier():
    schema = f"miner_lifecycle_empty_closure_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    unsafe_discovery, unsafe_discovery_sha256 = _discovery_witness(
        operation_id="operation-unsafe",
        deployment_id="deployment-unsafe",
        cluster_context_sha256="a" * 64,
        resources=[],
    )
    safe_discovery, safe_discovery_sha256 = _discovery_witness(
        operation_id="operation-safe",
        deployment_id="deployment-safe",
        cluster_context_sha256="b" * 64,
        resources=[],
        launch_operation_id="launch-safe",
        launch_phase_at_request="reserved",
        launch_kubernetes_mutation_possible=False,
        launch_create_results_sha256=_canonical_sha256({}),
    )
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
                    ('deployment-unsafe', 'chute-1', 'server-1'),
                    ('deployment-safe', 'chute-1', 'server-1');
                INSERT INTO gpus (gpu_id, server_id, deployment_id)
                VALUES
                    ('gpu-unsafe', 'server-1', 'deployment-unsafe'),
                    ('gpu-safe', 'server-1', 'deployment-safe');
                INSERT INTO deployment_launch_operations (
                    operation_id, deployment_id, phase, immutable_labels,
                    create_results
                ) VALUES (
                    'launch-safe', 'deployment-safe', 'teardown_fenced', '{}', '{}'
                );
                INSERT INTO deployment_teardown_operations (
                    operation_id, deployment_id, phase, reason, validator,
                    server_id, chute_id, cluster_context,
                    cluster_context_sha256, namespace,
                    kubernetes_node_generation, gpu_hardware_uuids,
                    immutable_labels, controllers_absent_at,
                    services_absent_at, pods_absent_at,
                    launch_operation_id,
                    launch_phase_at_request,
                    launch_kubernetes_mutation_possible,
                    launch_create_results_sha256
                ) VALUES
                    (
                        'operation-unsafe', 'deployment-unsafe', 'discovering',
                        'delete', 'validator-1', 'server-1', 'chute-1', 'node-1',
                        repeat('a', 64), 'chutes', 1, '["gpu-unsafe"]', '{}',
                        NOW(), NOW(), NOW(), NULL, NULL, NULL, NULL
                    ),
                    (
                        'operation-safe', 'deployment-safe', 'discovering',
                        'delete', 'validator-1', 'server-1', 'chute-1', 'node-1',
                        repeat('b', 64), 'chutes', 1, '["gpu-safe"]', '{}',
                        NOW(), NOW(), NOW(), 'launch-safe', 'reserved', FALSE,
                        encode(sha256(convert_to('{}', 'UTF8')), 'hex')
                    );
                UPDATE deployments SET teardown_operation_id = CASE deployment_id
                    WHEN 'deployment-unsafe' THEN 'operation-unsafe'
                    ELSE 'operation-safe'
                END;
                """,
                schema=schema,
            )
        )
        _assert_ok(
            _psql(
                f"""
                UPDATE deployment_teardown_operations SET
                    resource_discovery = CASE operation_id
                        WHEN 'operation-unsafe' THEN {_jsonb(unsafe_discovery)}
                        ELSE {_jsonb(safe_discovery)}
                    END,
                    resource_discovery_sha256 = CASE operation_id
                        WHEN 'operation-unsafe' THEN '{unsafe_discovery_sha256}'
                        ELSE '{safe_discovery_sha256}'
                    END,
                    resource_discovered_at = NOW();
                UPDATE deployment_teardown_operations SET phase = 'finalizing';
                """,
                schema=schema,
            )
        )

        unsafe_release = _psql(
            "UPDATE gpus SET deployment_id = NULL WHERE gpu_id = 'gpu-unsafe';",
            schema=schema,
        )
        assert unsafe_release.returncode != 0
        assert b"cannot be released before teardown" in unsafe_release.stderr
        unsafe_delete = _psql(
            "DELETE FROM deployments WHERE deployment_id = 'deployment-unsafe';",
            schema=schema,
        )
        assert unsafe_delete.returncode != 0
        assert b"has no verified durable teardown" in unsafe_delete.stderr

        _assert_ok(
            _psql(
                """
                UPDATE gpus SET deployment_id = NULL WHERE gpu_id = 'gpu-safe';
                DELETE FROM deployments WHERE deployment_id = 'deployment-safe';
                """,
                schema=schema,
            )
        )
    finally:
        _assert_ok(_psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;'))


def test_release_guard_requires_exact_pod_termination_evidence():
    schema = f"miner_lifecycle_pod_closure_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    resource = _resource_witness(
        api_version="v1",
        kind="Pod",
        name="pod-1",
        uid="pod-uid",
        node_name="node-1",
    )
    discovery, discovery_sha256 = _discovery_witness(
        operation_id="operation-pod",
        deployment_id="deployment-pod",
        cluster_context_sha256="b" * 64,
        resources=[resource],
    )
    evidence, evidence_sha256 = _pod_termination_evidence("pod-uid")
    try:
        _create_deployed_baseline(schema)
        _assert_ok(_psql(f"BEGIN;\n{FOLLOWUP_UP}\nCOMMIT;", schema=schema))
        _assert_ok(
            _psql(
                f"""
                INSERT INTO servers (server_id) VALUES ('server-1');
                INSERT INTO chutes (chute_id) VALUES ('chute-1');
                INSERT INTO deployments (deployment_id, chute_id, server_id)
                VALUES ('deployment-pod', 'chute-1', 'server-1');
                INSERT INTO gpus (gpu_id, server_id, deployment_id)
                VALUES ('gpu-pod', 'server-1', 'deployment-pod');
                INSERT INTO deployment_teardown_operations (
                    operation_id, deployment_id, phase, reason, validator,
                    server_id, chute_id, cluster_context,
                    cluster_context_sha256, namespace,
                    kubernetes_node_generation, gpu_hardware_uuids,
                    immutable_labels, controllers_absent_at,
                    services_absent_at, pods_absent_at
                ) VALUES (
                    'operation-pod', 'deployment-pod', 'discovering', 'delete',
                    'validator-1', 'server-1', 'chute-1', 'node-1',
                    repeat('b', 64), 'chutes', 1, '["gpu-pod"]', {_jsonb({})},
                    NOW(), NOW(), NOW()
                );
                INSERT INTO deployment_teardown_k8s_resources (
                    resource_id, operation_id, cluster_context, namespace,
                    api_version, kind, name, uid, node_name, labels,
                    labels_sha256, state, delete_requested_at
                ) VALUES (
                    'resource-pod', 'operation-pod', 'node-1', 'chutes',
                    'v1', 'Pod', 'pod-1', 'pod-uid', 'node-1', {_jsonb({})},
                    '{resource["labels_sha256"]}', 'delete_requested', NOW()
                );
                UPDATE deployment_teardown_operations
                SET resource_discovery = {_jsonb(discovery)},
                    resource_discovery_sha256 = '{discovery_sha256}',
                    resource_discovered_at = NOW()
                WHERE operation_id = 'operation-pod';
                UPDATE deployment_teardown_operations SET phase = 'finalizing'
                WHERE operation_id = 'operation-pod';
                UPDATE deployments SET teardown_operation_id = 'operation-pod'
                WHERE deployment_id = 'deployment-pod';
                """,
                schema=schema,
            )
        )

        no_evidence_release = _psql(
            "UPDATE gpus SET deployment_id = NULL WHERE gpu_id = 'gpu-pod';",
            schema=schema,
        )
        assert no_evidence_release.returncode != 0
        assert b"cannot be released before teardown" in no_evidence_release.stderr
        no_evidence_delete = _psql(
            "DELETE FROM deployments WHERE deployment_id = 'deployment-pod';",
            schema=schema,
        )
        assert no_evidence_delete.returncode != 0
        assert b"has no verified durable teardown" in no_evidence_delete.stderr

        wrong_digest_release = _psql(
            f"""
            BEGIN;
            UPDATE deployment_teardown_k8s_resources
            SET state = 'absent',
                absent_at = NOW(),
                pod_termination_evidence = {_jsonb(evidence)},
                pod_termination_evidence_sha256 = repeat('0', 64),
                pod_teardown_finalizer_attached_at = NOW(),
                pod_teardown_finalizer_removal_requested_at = NOW(),
                pod_teardown_finalizer_removed_at = NOW()
            WHERE resource_id = 'resource-pod';
            UPDATE gpus SET deployment_id = NULL WHERE gpu_id = 'gpu-pod';
            COMMIT;
            """,
            schema=schema,
        )
        assert wrong_digest_release.returncode != 0
        assert b"cannot be released before teardown" in wrong_digest_release.stderr

        _assert_ok(
            _psql(
                f"""
                UPDATE deployment_teardown_k8s_resources
                SET state = 'absent',
                    absent_at = NOW(),
                    pod_termination_evidence = {_jsonb(evidence)},
                    pod_termination_evidence_sha256 = '{evidence_sha256}',
                    pod_teardown_finalizer_attached_at = NOW(),
                    pod_teardown_finalizer_removal_requested_at = NOW(),
                    pod_teardown_finalizer_removed_at = NOW()
                WHERE resource_id = 'resource-pod';
                UPDATE gpus SET deployment_id = NULL WHERE gpu_id = 'gpu-pod';
                DELETE FROM deployments WHERE deployment_id = 'deployment-pod';
                """,
                schema=schema,
            )
        )
    finally:
        _assert_ok(_psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;'))


@pytest.mark.parametrize("chain_case", ["nonterminal", "cycle", "unrelated"])
def test_release_guard_rejects_invalid_replacement_chains(chain_case: str):
    schema = f"miner_lifecycle_{chain_case}_closure_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    old = _resource_witness(
        api_version="v1",
        kind="Service",
        name="service-1",
        uid="service-old",
        node_name=None,
    )
    successor_kind = "Secret" if chain_case == "unrelated" else "Service"
    successor_name = "secret-other" if chain_case == "unrelated" else "service-1"
    successor = _resource_witness(
        api_version="v1",
        kind=successor_kind,
        name=successor_name,
        uid="resource-new-uid",
        node_name=None,
    )
    discovery, discovery_sha256 = _discovery_witness(
        operation_id="operation-chain",
        deployment_id="deployment-chain",
        cluster_context_sha256="c" * 64,
        resources=[old, successor],
        launch_operation_id="launch-chain",
        launch_phase_at_request="reserved",
        launch_kubernetes_mutation_possible=False,
        launch_create_results_sha256=_canonical_sha256({}),
    )
    successor_state = "observed" if chain_case in {"nonterminal", "cycle"} else "absent"
    successor_absent = "NULL" if chain_case in {"nonterminal", "cycle"} else "NOW()"
    predecessor_update = (
        "UPDATE deployment_teardown_k8s_resources "
        "SET state = 'replaced', replaced_by_resource_id = 'resource-new' "
        "WHERE resource_id = 'resource-old';"
    )
    if chain_case == "cycle":
        predecessor_update += (
            " UPDATE deployment_teardown_k8s_resources "
            "SET state = 'replaced', absent_at = NULL, "
            "replaced_by_resource_id = 'resource-old' "
            "WHERE resource_id = 'resource-new';"
        )
    try:
        _create_deployed_baseline(schema)
        _assert_ok(_psql(f"BEGIN;\n{FOLLOWUP_UP}\nCOMMIT;", schema=schema))
        _assert_ok(
            _psql(
                f"""
                INSERT INTO servers (server_id) VALUES ('server-1');
                INSERT INTO chutes (chute_id) VALUES ('chute-1');
                INSERT INTO deployments (deployment_id, chute_id, server_id)
                VALUES ('deployment-chain', 'chute-1', 'server-1');
                INSERT INTO gpus (gpu_id, server_id, deployment_id)
                VALUES ('gpu-chain', 'server-1', 'deployment-chain');
                INSERT INTO deployment_launch_operations (
                    operation_id, deployment_id, phase, immutable_labels,
                    create_results
                ) VALUES (
                    'launch-chain', 'deployment-chain', 'teardown_fenced',
                    {_jsonb({})}, {_jsonb({})}
                );
                INSERT INTO deployment_teardown_operations (
                    operation_id, deployment_id, phase, reason, validator,
                    server_id, chute_id, cluster_context,
                    cluster_context_sha256, namespace,
                    kubernetes_node_generation, gpu_hardware_uuids,
                    immutable_labels, controllers_absent_at,
                    services_absent_at, pods_absent_at,
                    launch_operation_id, launch_phase_at_request,
                    launch_kubernetes_mutation_possible,
                    launch_create_results_sha256
                ) VALUES (
                    'operation-chain', 'deployment-chain', 'discovering', 'delete',
                    'validator-1', 'server-1', 'chute-1', 'node-1',
                    repeat('c', 64), 'chutes', 1, '["gpu-chain"]', {_jsonb({})},
                    NOW(), NOW(), NOW(), 'launch-chain', 'reserved', FALSE,
                    '{_canonical_sha256({})}'
                );
                INSERT INTO deployment_teardown_k8s_resources (
                    resource_id, operation_id, cluster_context, namespace,
                    api_version, kind, name, uid, labels, labels_sha256, state
                ) VALUES (
                    'resource-old', 'operation-chain', 'node-1', 'chutes',
                    'v1', 'Service', 'service-1', 'service-old', {_jsonb({})},
                    '{old["labels_sha256"]}', 'observed'
                ), (
                    'resource-new', 'operation-chain', 'node-1', 'chutes',
                    'v1', '{successor_kind}', '{successor_name}',
                    'resource-new-uid', {_jsonb({})},
                    '{successor["labels_sha256"]}', '{successor_state}'
                );
                UPDATE deployment_teardown_k8s_resources
                SET absent_at = {successor_absent}
                WHERE resource_id = 'resource-new';
                UPDATE deployment_teardown_operations
                SET resource_discovery = {_jsonb(discovery)},
                    resource_discovery_sha256 = '{discovery_sha256}',
                    resource_discovered_at = NOW()
                WHERE operation_id = 'operation-chain';
                {predecessor_update}
                UPDATE deployment_teardown_operations SET phase = 'finalizing'
                WHERE operation_id = 'operation-chain';
                UPDATE deployments SET teardown_operation_id = 'operation-chain'
                WHERE deployment_id = 'deployment-chain';
                """,
                schema=schema,
            )
        )

        invalid_release = _psql(
            "UPDATE gpus SET deployment_id = NULL WHERE gpu_id = 'gpu-chain';",
            schema=schema,
        )
        assert invalid_release.returncode != 0
        assert b"cannot be released before teardown" in invalid_release.stderr
        invalid_delete = _psql(
            "DELETE FROM deployments WHERE deployment_id = 'deployment-chain';",
            schema=schema,
        )
        assert invalid_delete.returncode != 0
        assert b"has no verified durable teardown" in invalid_delete.stderr
    finally:
        _assert_ok(_psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;'))


def test_release_guard_accepts_exact_replacement_chain_ending_absent():
    schema = f"miner_lifecycle_valid_chain_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    old = _resource_witness(
        api_version="v1",
        kind="Service",
        name="service-1",
        uid="service-old",
        node_name=None,
    )
    successor = _resource_witness(
        api_version="v1",
        kind="Service",
        name="service-1",
        uid="service-new",
        node_name=None,
    )
    discovery, discovery_sha256 = _discovery_witness(
        operation_id="operation-valid",
        deployment_id="deployment-valid",
        cluster_context_sha256="d" * 64,
        resources=[old, successor],
        launch_operation_id="launch-valid",
        launch_phase_at_request="reserved",
        launch_kubernetes_mutation_possible=False,
        launch_create_results_sha256=_canonical_sha256({}),
    )
    try:
        _create_deployed_baseline(schema)
        _assert_ok(_psql(f"BEGIN;\n{FOLLOWUP_UP}\nCOMMIT;", schema=schema))
        _assert_ok(
            _psql(
                f"""
                INSERT INTO servers (server_id) VALUES ('server-1');
                INSERT INTO chutes (chute_id) VALUES ('chute-1');
                INSERT INTO deployments (deployment_id, chute_id, server_id)
                VALUES ('deployment-valid', 'chute-1', 'server-1');
                INSERT INTO gpus (gpu_id, server_id, deployment_id)
                VALUES ('gpu-valid', 'server-1', 'deployment-valid');
                INSERT INTO deployment_launch_operations (
                    operation_id, deployment_id, phase, immutable_labels,
                    create_results
                ) VALUES (
                    'launch-valid', 'deployment-valid', 'teardown_fenced',
                    {_jsonb({})}, {_jsonb({})}
                );
                INSERT INTO deployment_teardown_operations (
                    operation_id, deployment_id, phase, reason, validator,
                    server_id, chute_id, cluster_context,
                    cluster_context_sha256, namespace,
                    kubernetes_node_generation, gpu_hardware_uuids,
                    immutable_labels, controllers_absent_at,
                    services_absent_at, pods_absent_at,
                    launch_operation_id, launch_phase_at_request,
                    launch_kubernetes_mutation_possible,
                    launch_create_results_sha256
                ) VALUES (
                    'operation-valid', 'deployment-valid', 'discovering', 'delete',
                    'validator-1', 'server-1', 'chute-1', 'node-1',
                    repeat('d', 64), 'chutes', 1, '["gpu-valid"]', {_jsonb({})},
                    NOW(), NOW(), NOW(), 'launch-valid', 'reserved', FALSE,
                    '{_canonical_sha256({})}'
                );
                INSERT INTO deployment_teardown_k8s_resources (
                    resource_id, operation_id, cluster_context, namespace,
                    api_version, kind, name, uid, labels, labels_sha256, state,
                    absent_at
                ) VALUES
                    (
                        'resource-old', 'operation-valid', 'node-1', 'chutes',
                        'v1', 'Service', 'service-1', 'service-old', {_jsonb({})},
                        '{old["labels_sha256"]}', 'observed', NULL
                    ),
                    (
                        'resource-new', 'operation-valid', 'node-1', 'chutes',
                        'v1', 'Service', 'service-1', 'service-new', {_jsonb({})},
                        '{successor["labels_sha256"]}', 'absent', NOW()
                    );
                UPDATE deployment_teardown_operations
                SET resource_discovery = {_jsonb(discovery)},
                    resource_discovery_sha256 = '{discovery_sha256}',
                    resource_discovered_at = NOW()
                WHERE operation_id = 'operation-valid';
                UPDATE deployment_teardown_k8s_resources
                SET state = 'replaced', replaced_by_resource_id = 'resource-new'
                WHERE resource_id = 'resource-old';
                UPDATE deployment_teardown_operations SET phase = 'finalizing'
                WHERE operation_id = 'operation-valid';
                UPDATE deployments SET teardown_operation_id = 'operation-valid'
                WHERE deployment_id = 'deployment-valid';
                UPDATE gpus SET deployment_id = NULL WHERE gpu_id = 'gpu-valid';
                DELETE FROM deployments WHERE deployment_id = 'deployment-valid';
                """,
                schema=schema,
            )
        )
    finally:
        _assert_ok(_psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;'))


def test_resource_history_binds_context_and_write_once_discovery():
    schema = f"miner_lifecycle_resource_history_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    resource = _resource_witness(
        api_version="v1",
        kind="Service",
        name="service-1",
        uid="service-uid",
        node_name=None,
    )
    discovery, discovery_sha256 = _discovery_witness(
        operation_id="operation-history",
        deployment_id="deployment-history",
        cluster_context_sha256="e" * 64,
        resources=[resource],
    )
    try:
        _create_deployed_baseline(schema)
        _assert_ok(_psql(f"BEGIN;\n{FOLLOWUP_UP}\nCOMMIT;", schema=schema))
        _assert_ok(
            _psql(
                f"""
                INSERT INTO deployment_teardown_operations (
                    operation_id, deployment_id, phase, reason, validator,
                    server_id, chute_id, cluster_context,
                    cluster_context_sha256, namespace,
                    kubernetes_node_generation, gpu_hardware_uuids,
                    immutable_labels
                ) VALUES (
                    'operation-history', 'deployment-history', 'discovering',
                    'delete', 'validator-1', 'server-1', 'chute-1', 'node-1',
                    repeat('e', 64), 'chutes', 1, '[]', {_jsonb({})}
                );
                """,
                schema=schema,
            )
        )

        wrong_context = _psql(
            f"""
            INSERT INTO deployment_teardown_k8s_resources (
                resource_id, operation_id, cluster_context, namespace,
                api_version, kind, name, uid, labels, labels_sha256
            ) VALUES (
                'wrong-context', 'operation-history', 'other-node', 'chutes',
                'v1', 'Service', 'service-1', 'wrong-context-uid', {_jsonb({})},
                '{resource["labels_sha256"]}'
            );
            """,
            schema=schema,
        )
        assert wrong_context.returncode != 0
        assert b"resource context differs from operation" in wrong_context.stderr

        _assert_ok(
            _psql(
                f"""
                INSERT INTO deployment_teardown_k8s_resources (
                    resource_id, operation_id, cluster_context, namespace,
                    api_version, kind, name, uid, labels, labels_sha256
                ) VALUES (
                    'resource-history', 'operation-history', 'node-1', 'chutes',
                    'v1', 'Service', 'service-1', 'service-uid', {_jsonb({})},
                    '{resource["labels_sha256"]}'
                );
                UPDATE deployment_teardown_operations
                SET resource_discovery = {_jsonb(discovery)},
                    resource_discovery_sha256 = '{discovery_sha256}',
                    resource_discovered_at = NOW()
                WHERE operation_id = 'operation-history';
                """,
                schema=schema,
            )
        )

        rewritten_witness = _psql(
            """
            UPDATE deployment_teardown_operations
            SET resource_discovery = jsonb_set(
                resource_discovery, '{namespace}', '"other"'::jsonb
            )
            WHERE operation_id = 'operation-history';
            """,
            schema=schema,
        )
        assert rewritten_witness.returncode != 0
        assert b"discovery witness is immutable" in rewritten_witness.stderr

        late_insert = _psql(
            f"""
            INSERT INTO deployment_teardown_k8s_resources (
                resource_id, operation_id, cluster_context, namespace,
                api_version, kind, name, uid, labels, labels_sha256
            ) VALUES (
                'late-resource', 'operation-history', 'node-1', 'chutes',
                'v1', 'Secret', 'late-secret', 'late-uid', {_jsonb({})},
                '{resource["labels_sha256"]}'
            );
            """,
            schema=schema,
        )
        assert late_insert.returncode != 0
        assert b"lacks a durable lease fence" in late_insert.stderr

        changed_identity = _psql(
            """
            UPDATE deployment_teardown_k8s_resources
            SET namespace = 'other'
            WHERE resource_id = 'resource-history';
            """,
            schema=schema,
        )
        assert changed_identity.returncode != 0
        assert b"resource context differs from operation" in changed_identity.stderr
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
            "BEGIN; LOCK TABLE miner_launch_intents IN ROW EXCLUSIVE MODE; SELECT 'LOCKED';\n"
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
