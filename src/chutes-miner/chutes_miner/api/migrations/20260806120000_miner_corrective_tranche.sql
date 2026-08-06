-- migrate:up

LOCK TABLE deployment_teardown_operations,
    deployment_launch_operations,
    parent_deletion_operations,
    kubernetes_orphan_tombstones,
    delayed_validator_instance_cleanups,
    miner_launch_intents,
    registry_scope_intents IN ACCESS EXCLUSIVE MODE;

ALTER TABLE deployment_teardown_operations
    ADD COLUMN next_retry_at TIMESTAMPTZ;

ALTER TABLE deployment_launch_operations
    ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN next_retry_at TIMESTAMPTZ,
    ADD CONSTRAINT ck_deployment_launch_attempt_count CHECK (attempt_count >= 0);

ALTER TABLE parent_deletion_operations
    ADD COLUMN next_retry_at TIMESTAMPTZ,
    ADD COLUMN validator_server_decommission_request JSONB,
    ADD COLUMN validator_server_decommission_request_sha256 VARCHAR(64);

UPDATE parent_deletion_operations
SET validator_server_decommission_request = jsonb_build_object(
        'reason', reason,
        'request_id', operation_id,
        'schema', 'chutes.gpu-decommission-request',
        'version', 1
    )
WHERE parent_type = 'server'
  AND snapshot ->> 'allocation_group_id' IS NOT NULL;

UPDATE parent_deletion_operations
SET validator_server_decommission_request_sha256 = encode(
        sha256(
            convert_to(
                canonical_miner_teardown_jsonb(validator_server_decommission_request),
                'UTF8'
            )
        ),
        'hex'
    )
WHERE validator_server_decommission_request IS NOT NULL;

-- Any nonterminal ACK was produced by the legacy endpoint and cannot authorize
-- allocation release under the new typed decommission contract.
UPDATE parent_deletion_operations
SET validator_server_deletion_ack = NULL,
    validator_server_deleted_at = NULL
WHERE phase <> 'completed'
  AND validator_server_decommission_request IS NOT NULL;

ALTER TABLE parent_deletion_operations
    ADD CONSTRAINT ck_parent_deletion_decommission_request CHECK (
        (
            validator_server_decommission_request IS NULL
            AND validator_server_decommission_request_sha256 IS NULL
        ) OR (
            parent_type = 'server'
            AND jsonb_typeof(validator_server_decommission_request) = 'object'
            AND validator_server_decommission_request = jsonb_build_object(
                'reason', reason,
                'request_id', operation_id,
                'schema', 'chutes.gpu-decommission-request',
                'version', 1
            )
            AND validator_server_decommission_request_sha256 ~ '^[0-9a-f]{64}$'
            AND validator_server_decommission_request_sha256 = encode(
                sha256(
                    convert_to(
                        canonical_miner_teardown_jsonb(
                            validator_server_decommission_request
                        ),
                        'UTF8'
                    )
                ),
                'hex'
            )
        )
    );

ALTER TABLE kubernetes_orphan_tombstones
    ADD COLUMN next_retry_at TIMESTAMPTZ;

ALTER TABLE delayed_validator_instance_cleanups
    ADD COLUMN next_retry_at TIMESTAMPTZ;

ALTER TABLE miner_launch_intents
    ADD COLUMN retry_lease_owner TEXT,
    ADD COLUMN retry_lease_expires_at TIMESTAMPTZ,
    ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN next_retry_at TIMESTAMPTZ,
    ADD CONSTRAINT ck_miner_launch_intent_retry_lease CHECK (
        (retry_lease_owner IS NULL) = (retry_lease_expires_at IS NULL)
        AND (
            phase NOT IN ('consumed', 'completed', 'failed')
            OR retry_lease_owner IS NULL
        )
    ),
    ADD CONSTRAINT ck_miner_launch_intent_attempt_count CHECK (attempt_count >= 0);

ALTER TABLE registry_scope_intents
    ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN next_retry_at TIMESTAMPTZ,
    ADD CONSTRAINT ck_registry_scope_intent_attempt_count CHECK (attempt_count >= 0);

CREATE INDEX deployment_teardown_next_retry_idx
    ON deployment_teardown_operations(next_retry_at, retry_lease_expires_at)
    WHERE phase <> 'completed' AND lineage_conflict_at IS NULL;

CREATE INDEX deployment_launch_next_retry_idx
    ON deployment_launch_operations(next_retry_at, created_at)
    WHERE phase IN ('reserved', 'creating', 'failed');

CREATE INDEX parent_deletion_next_retry_idx
    ON parent_deletion_operations(next_retry_at, retry_lease_expires_at)
    WHERE phase <> 'completed';

CREATE INDEX kubernetes_orphan_next_retry_idx
    ON kubernetes_orphan_tombstones(next_retry_at, retry_lease_expires_at)
    WHERE phase <> 'completed' AND lineage_conflict_at IS NULL;

CREATE INDEX delayed_validator_cleanup_next_retry_idx
    ON delayed_validator_instance_cleanups(next_retry_at, retry_lease_expires_at)
    WHERE phase <> 'completed';

CREATE INDEX miner_launch_intent_next_retry_idx
    ON miner_launch_intents(next_retry_at, retry_lease_expires_at, created_at)
    WHERE phase NOT IN ('completed', 'failed');

CREATE INDEX registry_scope_intent_next_retry_idx
    ON registry_scope_intents(next_retry_at, updated_at)
    WHERE phase <> 'revoked';

CREATE TABLE teardown_lineage_resolution_audits (
    audit_id TEXT PRIMARY KEY,
    operation_kind TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    action TEXT NOT NULL,
    policy TEXT NOT NULL,
    conflict_at TIMESTAMPTZ NOT NULL,
    expected_lineage_sha256 VARCHAR(64) NOT NULL,
    observed_lineage JSONB NOT NULL,
    observed_lineage_sha256 VARCHAR(64) NOT NULL,
    reason TEXT NOT NULL,
    actor TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_teardown_lineage_resolution_kind
        CHECK (operation_kind IN ('deployment', 'orphan')),
    CONSTRAINT ck_teardown_lineage_resolution_action
        CHECK (action IN ('requeue', 'resolve')),
    CONSTRAINT ck_teardown_lineage_resolution_policy
        CHECK (policy IN ('exact_lineage_retry', 'verified_terminal_absence')),
    CONSTRAINT ck_teardown_lineage_resolution_expected_sha256
        CHECK (expected_lineage_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_teardown_lineage_resolution_observed_sha256
        CHECK (observed_lineage_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_teardown_lineage_resolution_reason
        CHECK (length(btrim(reason)) >= 8),
    CONSTRAINT ck_teardown_lineage_resolution_actor
        CHECK (length(btrim(actor)) > 0)
);

CREATE INDEX teardown_lineage_resolution_operation_idx
    ON teardown_lineage_resolution_audits(operation_kind, operation_id, created_at);

CREATE FUNCTION prevent_teardown_lineage_resolution_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'teardown lineage resolution audit is immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER teardown_lineage_resolution_audit_immutable
BEFORE UPDATE OR DELETE ON teardown_lineage_resolution_audits
FOR EACH ROW EXECUTE FUNCTION prevent_teardown_lineage_resolution_audit_mutation();

-- migrate:down

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM teardown_lineage_resolution_audits)
       OR EXISTS (
            SELECT 1
            FROM parent_deletion_operations
            WHERE validator_server_decommission_request IS NOT NULL
       )
       OR EXISTS (
            SELECT 1
            FROM deployment_launch_operations
            WHERE attempt_count > 0 OR next_retry_at IS NOT NULL
       )
       OR EXISTS (
            SELECT 1
            FROM miner_launch_intents
            WHERE attempt_count > 0
               OR next_retry_at IS NOT NULL
               OR retry_lease_owner IS NOT NULL
               OR retry_lease_expires_at IS NOT NULL
       )
       OR EXISTS (
            SELECT 1
            FROM registry_scope_intents
            WHERE attempt_count > 0 OR next_retry_at IS NOT NULL
       )
       OR EXISTS (
            SELECT 1
            FROM deployment_teardown_operations
            WHERE next_retry_at IS NOT NULL
       )
       OR EXISTS (
            SELECT 1
            FROM parent_deletion_operations
            WHERE next_retry_at IS NOT NULL
       )
       OR EXISTS (
            SELECT 1
            FROM kubernetes_orphan_tombstones
            WHERE next_retry_at IS NOT NULL
       )
       OR EXISTS (
            SELECT 1
            FROM delayed_validator_instance_cleanups
            WHERE next_retry_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION
            'cannot remove miner corrective tranche while decommission or lineage audit history exists';
    END IF;
END;
$$;

DROP TRIGGER teardown_lineage_resolution_audit_immutable
    ON teardown_lineage_resolution_audits;
DROP FUNCTION prevent_teardown_lineage_resolution_audit_mutation();
DROP TABLE teardown_lineage_resolution_audits;

DROP INDEX registry_scope_intent_next_retry_idx;
DROP INDEX miner_launch_intent_next_retry_idx;
DROP INDEX delayed_validator_cleanup_next_retry_idx;
DROP INDEX kubernetes_orphan_next_retry_idx;
DROP INDEX parent_deletion_next_retry_idx;
DROP INDEX deployment_teardown_next_retry_idx;
DROP INDEX deployment_launch_next_retry_idx;

ALTER TABLE registry_scope_intents
    DROP CONSTRAINT ck_registry_scope_intent_attempt_count,
    DROP COLUMN next_retry_at,
    DROP COLUMN attempt_count;

ALTER TABLE miner_launch_intents
    DROP CONSTRAINT ck_miner_launch_intent_retry_lease,
    DROP CONSTRAINT ck_miner_launch_intent_attempt_count,
    DROP COLUMN next_retry_at,
    DROP COLUMN attempt_count,
    DROP COLUMN retry_lease_expires_at,
    DROP COLUMN retry_lease_owner;

ALTER TABLE delayed_validator_instance_cleanups
    DROP COLUMN next_retry_at;

ALTER TABLE kubernetes_orphan_tombstones
    DROP COLUMN next_retry_at;

ALTER TABLE parent_deletion_operations
    DROP CONSTRAINT ck_parent_deletion_decommission_request,
    DROP COLUMN validator_server_decommission_request_sha256,
    DROP COLUMN validator_server_decommission_request,
    DROP COLUMN next_retry_at;

ALTER TABLE deployment_teardown_operations
    DROP COLUMN next_retry_at;

ALTER TABLE deployment_launch_operations
    DROP CONSTRAINT ck_deployment_launch_attempt_count,
    DROP COLUMN next_retry_at,
    DROP COLUMN attempt_count;
