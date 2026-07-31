"""Real-PostgreSQL history preservation for registry scope authority."""

from __future__ import annotations

import hashlib
import json
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
SCOPE_UP, SCOPE_DOWN = (
    (MIGRATIONS / "20260730120000_registry_scope_authority.sql")
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


def _create_followup_baseline(schema: str) -> None:
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
    _assert_ok(_psql(f"BEGIN;\n{FOLLOWUP_UP}\nCOMMIT;", schema=schema))


def test_scope_migration_transforms_history_without_reset_or_deletion():
    schema = f"miner_scope_authority_{uuid.uuid4().hex}"
    _assert_ok(_psql(f'CREATE SCHEMA "{schema}";'))
    try:
        _create_followup_baseline(schema)
        old_lineage = {
            "schema": "chutes.miner-launch-lineage",
            "version": 1,
            "miner_hotkey": "miner-1",
            "validator": "validator-1",
            "chute_id": "chute-1",
            "chute_version": "1.0.0",
            "server_id": "server-1",
            "kubernetes_node_uid": "node-uid-1",
            "kubernetes_node_generation": 1,
            "gpu_allocation_group_id": "group-1",
            "gpu_allocation_group_generation": 1,
            "job_id": None,
        }
        old_request = {
            "schema": "chutes.miner-launch-request.v1",
            "miner_launch_request_id": "11111111-1111-4111-8111-111111111111",
            "lineage": old_lineage,
        }
        response = {
            "config_id": "config-1",
            "registry": {
                "repository": "owner/image",
                "manifest_digest": f"sha256:{'a' * 64}",
            },
        }
        _assert_ok(
            _psql(
                f"""
                INSERT INTO miner_launch_intents (
                    intent_id, phase, validator, chute_id, chute_version, server_id,
                    request_payload, request_sha256, lineage_sha256, response_payload,
                    response_sha256, token_sha256
                ) VALUES (
                    '11111111-1111-4111-8111-111111111111',
                    'response_persisted', 'validator-1', 'chute-1', '1.0.0', 'server-1',
                    {_jsonb(old_request)}, '{_canonical_sha256(old_request)}',
                    '{_canonical_sha256(old_lineage)}', {_jsonb(response)},
                    '{_canonical_sha256(response)}',
                    '{hashlib.sha256(b"token-1").hexdigest()}'
                );
                """,
                schema=schema,
            )
        )

        _assert_ok(_psql(f"BEGIN;\n{SCOPE_UP}\nCOMMIT;", schema=schema))
        inspected = _psql(
            """
            SELECT request_payload::text, request_sha256, lineage_sha256, deployment_id
            FROM miner_launch_intents;
            SELECT launch_config_id, launch_intent_id, deployment_id, desired_state, phase
            FROM registry_scope_intents;
            """,
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(inspected)
        lines = [line for line in inspected.stdout.decode().splitlines() if line.strip()]
        request_text, request_hash, lineage_hash, deployment_id = lines[0].split("|", 3)
        transformed_request = json.loads(request_text)
        assert deployment_id == "11111111-1111-4111-8111-111111111111"
        assert transformed_request["lineage"]["deployment_id"] == deployment_id
        assert request_hash == _canonical_sha256(transformed_request)
        assert lineage_hash == _canonical_sha256(transformed_request["lineage"])
        assert lines[1] == (
            "config-1|11111111-1111-4111-8111-111111111111|"
            "11111111-1111-4111-8111-111111111111|revoked|revoke_pending"
        )

        invalid = _psql(
            f"""
            INSERT INTO miner_launch_intents (
                intent_id, phase, validator, chute_id, chute_version, server_id,
                request_payload, request_sha256, lineage_sha256
            ) VALUES (
                'invalid', 'pending', 'validator-1', 'chute-1', '1.0.0', 'server-1',
                {_jsonb(transformed_request)}, '{"0" * 64}', '{"0" * 64}'
            );
            """,
            schema=schema,
        )
        assert invalid.returncode != 0
        assert b"ck_miner_launch_intent_deployment_authority" in invalid.stderr

        blocked_down = _psql(f"BEGIN;\n{SCOPE_DOWN}\nCOMMIT;", schema=schema)
        assert blocked_down.returncode != 0
        assert b"scope history exists" in blocked_down.stderr
        preserved = _psql(
            "SELECT COUNT(*) FROM miner_launch_intents;",
            schema=schema,
            tuples_only=True,
        )
        _assert_ok(preserved)
        assert preserved.stdout.decode().strip() == "1"
    finally:
        _assert_ok(_psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;'))
