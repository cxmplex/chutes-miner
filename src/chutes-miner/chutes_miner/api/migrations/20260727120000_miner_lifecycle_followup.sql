-- migrate:up

CREATE TABLE IF NOT EXISTS miner_launch_intents (
    intent_id TEXT PRIMARY KEY,
    phase TEXT NOT NULL DEFAULT 'pending',
    validator TEXT NOT NULL,
    chute_id TEXT NOT NULL,
    chute_version TEXT NOT NULL,
    server_id TEXT NOT NULL,
    job_id TEXT,
    job_cleanup_only BOOLEAN NOT NULL DEFAULT FALSE,
    request_payload JSONB NOT NULL,
    request_sha256 TEXT NOT NULL,
    lineage_sha256 TEXT NOT NULL,
    response_payload JSONB,
    response_sha256 TEXT,
    token_sha256 TEXT,
    authorized_token_sha256s JSONB NOT NULL DEFAULT '[]'::jsonb,
    registry_ack JSONB,
    job_release_ack JSONB,
    job_released_at TIMESTAMPTZ,
    deployment_id TEXT,
    last_failure TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT ck_miner_launch_intent_phase CHECK (
        phase IN (
            'pending',
            'response_persisted',
            'registry_acked',
            'consumed',
            'cleanup_required',
            'completed',
            'failed'
        )
    ),
    CONSTRAINT ck_miner_launch_intent_request_sha256 CHECK (
        request_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_miner_launch_intent_lineage_sha256 CHECK (
        lineage_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_miner_launch_intent_response CHECK (
        (response_payload IS NULL AND response_sha256 IS NULL AND token_sha256 IS NULL)
        OR (
            response_payload IS NOT NULL
            AND response_sha256 ~ '^[0-9a-f]{64}$'
            AND token_sha256 ~ '^[0-9a-f]{64}$'
        )
    ),
    CONSTRAINT ck_miner_launch_intent_authorized_tokens CHECK (
        jsonb_typeof(authorized_token_sha256s) = 'array'
    ),
    CONSTRAINT ck_miner_launch_intent_job_ack CHECK (
        (job_release_ack IS NULL) = (job_released_at IS NULL)
    ),
    CONSTRAINT ck_miner_launch_intent_job_cleanup_only CHECK (
        NOT job_cleanup_only OR (
            job_id IS NOT NULL
            AND response_payload IS NULL
            AND response_sha256 IS NULL
            AND token_sha256 IS NULL
            AND registry_ack IS NULL
            AND deployment_id IS NULL
        )
    )
);
ALTER TABLE miner_launch_intents
    ADD COLUMN IF NOT EXISTS authorized_token_sha256s JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS job_cleanup_only BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS job_release_ack JSONB,
    ADD COLUMN IF NOT EXISTS job_released_at TIMESTAMPTZ;
ALTER TABLE miner_launch_intents
    DROP CONSTRAINT IF EXISTS ck_miner_launch_intent_authorized_tokens,
    DROP CONSTRAINT IF EXISTS ck_miner_launch_intent_job_ack,
    DROP CONSTRAINT IF EXISTS ck_miner_launch_intent_job_cleanup_only;
ALTER TABLE miner_launch_intents
    ADD CONSTRAINT ck_miner_launch_intent_authorized_tokens CHECK (
        jsonb_typeof(authorized_token_sha256s) = 'array'
    ),
    ADD CONSTRAINT ck_miner_launch_intent_job_ack CHECK (
        (job_release_ack IS NULL) = (job_released_at IS NULL)
    ),
    ADD CONSTRAINT ck_miner_launch_intent_job_cleanup_only CHECK (
        NOT job_cleanup_only OR (
            job_id IS NOT NULL
            AND response_payload IS NULL
            AND response_sha256 IS NULL
            AND token_sha256 IS NULL
            AND registry_ack IS NULL
            AND deployment_id IS NULL
        )
    );
CREATE INDEX IF NOT EXISTS miner_launch_intent_recovery_idx
    ON miner_launch_intents (phase, created_at)
    WHERE phase NOT IN ('completed', 'failed');
CREATE UNIQUE INDEX IF NOT EXISTS miner_launch_intent_active_lineage_key
    ON miner_launch_intents (lineage_sha256)
    WHERE phase NOT IN ('completed', 'failed');

ALTER TABLE deployment_launch_operations
    ADD COLUMN IF NOT EXISTS cluster_context TEXT,
    ADD COLUMN IF NOT EXISTS cluster_context_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS namespace TEXT,
    ADD COLUMN IF NOT EXISTS server_name TEXT,
    ADD COLUMN IF NOT EXISTS canonical_workload_spec JSONB,
    ADD COLUMN IF NOT EXISTS canonical_workload_spec_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS launch_intent_id TEXT;

ALTER TABLE deployment_launch_operations
    DROP CONSTRAINT IF EXISTS deployment_launch_operations_launch_intent_id_fkey;
ALTER TABLE deployment_launch_operations
    ADD CONSTRAINT deployment_launch_operations_launch_intent_id_fkey
    FOREIGN KEY (launch_intent_id)
    REFERENCES miner_launch_intents(intent_id)
    ON DELETE RESTRICT;
CREATE UNIQUE INDEX IF NOT EXISTS deployment_launch_intent_key
    ON deployment_launch_operations (launch_intent_id)
    WHERE launch_intent_id IS NOT NULL;

ALTER TABLE deployment_launch_operations
    DROP CONSTRAINT IF EXISTS ck_deployment_launch_canonical_workload;
ALTER TABLE deployment_launch_operations
    ADD CONSTRAINT ck_deployment_launch_canonical_workload CHECK (
        (canonical_workload_spec IS NULL) =
        (canonical_workload_spec_sha256 IS NULL)
    );
ALTER TABLE deployment_launch_operations
    DROP CONSTRAINT IF EXISTS ck_deployment_launch_canonical_workload_sha256;
ALTER TABLE deployment_launch_operations
    ADD CONSTRAINT ck_deployment_launch_canonical_workload_sha256 CHECK (
        canonical_workload_spec_sha256 IS NULL
        OR canonical_workload_spec_sha256 ~ '^[0-9a-f]{64}$'
    );
ALTER TABLE deployment_launch_operations
    DROP CONSTRAINT IF EXISTS ck_deployment_launch_cluster_context_sha256;
ALTER TABLE deployment_launch_operations
    ADD CONSTRAINT ck_deployment_launch_cluster_context_sha256 CHECK (
        cluster_context_sha256 IS NULL
        OR cluster_context_sha256 ~ '^[0-9a-f]{64}$'
    );

ALTER TABLE deployment_teardown_k8s_resources
    ADD COLUMN IF NOT EXISTS owner_api_version TEXT;
UPDATE deployment_teardown_k8s_resources
SET owner_api_version = CASE
    WHEN owner_kind = 'Job' THEN 'batch/v1'
    WHEN owner_kind IN ('Deployment', 'ReplicaSet') THEN 'apps/v1'
    ELSE owner_api_version
END
WHERE owner_kind IS NOT NULL
  AND owner_api_version IS NULL;
ALTER TABLE deployment_teardown_k8s_resources
    DROP CONSTRAINT IF EXISTS ck_deployment_teardown_resource_owner;
ALTER TABLE deployment_teardown_k8s_resources
    ADD CONSTRAINT ck_deployment_teardown_resource_owner CHECK (
        (
            owner_api_version IS NULL
            AND owner_kind IS NULL
            AND owner_name IS NULL
            AND owner_uid IS NULL
        ) OR (
            owner_api_version IS NOT NULL
            AND owner_kind IS NOT NULL
            AND owner_name IS NOT NULL
            AND owner_uid IS NOT NULL
        )
    );

ALTER TABLE deployment_teardown_operations
    ADD COLUMN IF NOT EXISTS validator_job_release_ack JSONB,
    ADD COLUMN IF NOT EXISTS validator_job_released_at TIMESTAMPTZ;
ALTER TABLE deployment_teardown_operations
    DROP CONSTRAINT IF EXISTS ck_deployment_teardown_job_ack;
ALTER TABLE deployment_teardown_operations
    ADD CONSTRAINT ck_deployment_teardown_job_ack CHECK (
        (validator_job_release_ack IS NULL) =
        (validator_job_released_at IS NULL)
    );

CREATE OR REPLACE FUNCTION require_finished_deployment_teardown()
RETURNS TRIGGER AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM deployment_teardown_operations op
        WHERE op.deployment_id = OLD.deployment_id
          AND op.operation_id = OLD.teardown_operation_id
          AND op.phase IN ('finalizing', 'completed')
          AND op.lineage_conflict_at IS NULL
          AND (op.config_id IS NULL OR op.registry_revocation_ack IS NOT NULL)
          AND (op.instance_id IS NULL OR op.validator_instance_deletion_ack IS NOT NULL)
          AND (op.job_id IS NULL OR op.validator_job_release_ack IS NOT NULL)
          AND op.controllers_absent_at IS NOT NULL
          AND op.services_absent_at IS NOT NULL
          AND op.pods_absent_at IS NOT NULL
          AND (op.config_id IS NULL OR op.pull_secret_deletion_ack IS NOT NULL)
    ) THEN
        RAISE EXCEPTION 'deployment % has no verified durable teardown', OLD.deployment_id
            USING ERRCODE = '23503';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION require_finished_gpu_teardown()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.deployment_id IS NULL OR (
        TG_OP = 'UPDATE' AND NEW.deployment_id IS NOT DISTINCT FROM OLD.deployment_id
    ) THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM deployments deployment
        JOIN deployment_teardown_operations op
          ON op.operation_id = deployment.teardown_operation_id
        WHERE deployment.deployment_id = OLD.deployment_id
          AND op.deployment_id = OLD.deployment_id
          AND op.phase IN ('finalizing', 'completed')
          AND op.lineage_conflict_at IS NULL
          AND (op.config_id IS NULL OR op.registry_revocation_ack IS NOT NULL)
          AND (op.instance_id IS NULL OR op.validator_instance_deletion_ack IS NOT NULL)
          AND (op.job_id IS NULL OR op.validator_job_release_ack IS NOT NULL)
          AND op.controllers_absent_at IS NOT NULL
          AND op.services_absent_at IS NOT NULL
          AND op.pods_absent_at IS NOT NULL
          AND (op.config_id IS NULL OR op.pull_secret_deletion_ack IS NOT NULL)
    ) THEN
        RAISE EXCEPTION 'GPU ownership for deployment % cannot be released before teardown',
            OLD.deployment_id USING ERRCODE = '23503';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

ALTER TABLE kubernetes_orphan_tombstone_resources
    ADD COLUMN IF NOT EXISTS owner_api_version TEXT;
UPDATE kubernetes_orphan_tombstone_resources
SET owner_api_version = CASE
    WHEN owner_kind = 'Job' THEN 'batch/v1'
    WHEN owner_kind IN ('Deployment', 'ReplicaSet') THEN 'apps/v1'
    ELSE owner_api_version
END
WHERE owner_kind IS NOT NULL
  AND owner_api_version IS NULL;
ALTER TABLE kubernetes_orphan_tombstone_resources
    DROP CONSTRAINT IF EXISTS ck_kubernetes_orphan_resource_owner;
ALTER TABLE kubernetes_orphan_tombstone_resources
    ADD CONSTRAINT ck_kubernetes_orphan_resource_owner CHECK (
        (
            owner_api_version IS NULL
            AND owner_kind IS NULL
            AND owner_name IS NULL
            AND owner_uid IS NULL
        ) OR (
            owner_api_version IS NOT NULL
            AND owner_kind IS NOT NULL
            AND owner_name IS NOT NULL
            AND owner_uid IS NOT NULL
        )
    );

-- migrate:down

LOCK TABLE
    deployment_launch_operations,
    deployment_teardown_operations,
    deployment_teardown_k8s_resources,
    kubernetes_orphan_tombstone_resources,
    miner_launch_intents
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM deployment_launch_operations
        WHERE canonical_workload_spec IS NOT NULL
           OR canonical_workload_spec_sha256 IS NOT NULL
           OR cluster_context IS NOT NULL
           OR cluster_context_sha256 IS NOT NULL
           OR namespace IS NOT NULL
           OR server_name IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'cannot remove miner lifecycle follow-up schema while canonical launch intents exist';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM deployment_teardown_operations
        WHERE validator_job_release_ack IS NOT NULL
           OR validator_job_released_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'cannot remove miner lifecycle follow-up schema while validator job release history exists';
    END IF;
    IF EXISTS (SELECT 1 FROM miner_launch_intents) THEN
        RAISE EXCEPTION
            'cannot remove miner lifecycle follow-up schema while launch intent history exists';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION require_finished_deployment_teardown()
RETURNS TRIGGER AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM deployment_teardown_operations op
        WHERE op.deployment_id = OLD.deployment_id
          AND op.operation_id = OLD.teardown_operation_id
          AND op.phase IN ('finalizing', 'completed')
          AND op.lineage_conflict_at IS NULL
          AND (op.config_id IS NULL OR op.registry_revocation_ack IS NOT NULL)
          AND (op.instance_id IS NULL OR op.validator_instance_deletion_ack IS NOT NULL)
          AND op.controllers_absent_at IS NOT NULL
          AND op.services_absent_at IS NOT NULL
          AND op.pods_absent_at IS NOT NULL
          AND (op.config_id IS NULL OR op.pull_secret_deletion_ack IS NOT NULL)
    ) THEN
        RAISE EXCEPTION 'deployment % has no verified durable teardown', OLD.deployment_id
            USING ERRCODE = '23503';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION require_finished_gpu_teardown()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.deployment_id IS NULL OR (
        TG_OP = 'UPDATE' AND NEW.deployment_id IS NOT DISTINCT FROM OLD.deployment_id
    ) THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM deployments deployment
        JOIN deployment_teardown_operations op
          ON op.operation_id = deployment.teardown_operation_id
        WHERE deployment.deployment_id = OLD.deployment_id
          AND op.deployment_id = OLD.deployment_id
          AND op.phase IN ('finalizing', 'completed')
          AND op.lineage_conflict_at IS NULL
          AND (op.config_id IS NULL OR op.registry_revocation_ack IS NOT NULL)
          AND (op.instance_id IS NULL OR op.validator_instance_deletion_ack IS NOT NULL)
          AND op.controllers_absent_at IS NOT NULL
          AND op.services_absent_at IS NOT NULL
          AND op.pods_absent_at IS NOT NULL
          AND (op.config_id IS NULL OR op.pull_secret_deletion_ack IS NOT NULL)
    ) THEN
        RAISE EXCEPTION 'GPU ownership for deployment % cannot be released before teardown',
            OLD.deployment_id USING ERRCODE = '23503';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

ALTER TABLE deployment_teardown_operations
    DROP CONSTRAINT IF EXISTS ck_deployment_teardown_job_ack,
    DROP COLUMN IF EXISTS validator_job_released_at,
    DROP COLUMN IF EXISTS validator_job_release_ack;

ALTER TABLE kubernetes_orphan_tombstone_resources
    DROP CONSTRAINT IF EXISTS ck_kubernetes_orphan_resource_owner;
ALTER TABLE kubernetes_orphan_tombstone_resources
    ADD CONSTRAINT ck_kubernetes_orphan_resource_owner CHECK (
        (owner_kind IS NULL AND owner_name IS NULL AND owner_uid IS NULL) OR
        (owner_kind IS NOT NULL AND owner_name IS NOT NULL AND owner_uid IS NOT NULL)
    );
ALTER TABLE kubernetes_orphan_tombstone_resources
    DROP COLUMN IF EXISTS owner_api_version;

ALTER TABLE deployment_teardown_k8s_resources
    DROP CONSTRAINT IF EXISTS ck_deployment_teardown_resource_owner;
ALTER TABLE deployment_teardown_k8s_resources
    ADD CONSTRAINT ck_deployment_teardown_resource_owner CHECK (
        (owner_kind IS NULL AND owner_name IS NULL AND owner_uid IS NULL) OR
        (owner_kind IS NOT NULL AND owner_name IS NOT NULL AND owner_uid IS NOT NULL)
    );
ALTER TABLE deployment_teardown_k8s_resources
    DROP COLUMN IF EXISTS owner_api_version;

ALTER TABLE deployment_launch_operations
    DROP CONSTRAINT IF EXISTS deployment_launch_operations_launch_intent_id_fkey;
DROP INDEX IF EXISTS deployment_launch_intent_key;
ALTER TABLE deployment_launch_operations
    DROP CONSTRAINT IF EXISTS ck_deployment_launch_canonical_workload,
    DROP CONSTRAINT IF EXISTS ck_deployment_launch_canonical_workload_sha256,
    DROP CONSTRAINT IF EXISTS ck_deployment_launch_cluster_context_sha256,
    DROP COLUMN IF EXISTS canonical_workload_spec_sha256,
    DROP COLUMN IF EXISTS canonical_workload_spec,
    DROP COLUMN IF EXISTS server_name,
    DROP COLUMN IF EXISTS namespace,
    DROP COLUMN IF EXISTS cluster_context_sha256,
    DROP COLUMN IF EXISTS cluster_context,
    DROP COLUMN IF EXISTS launch_intent_id;

DROP TABLE IF EXISTS miner_launch_intents;
