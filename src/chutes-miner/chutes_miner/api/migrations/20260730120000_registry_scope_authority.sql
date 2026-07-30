-- migrate:up

LOCK TABLE miner_launch_intents IN ACCESS EXCLUSIVE MODE;

UPDATE miner_launch_intents
SET deployment_id = intent_id
WHERE job_cleanup_only IS FALSE
  AND deployment_id IS NULL;

WITH transformed AS (
    SELECT
        intent_id,
        jsonb_set(
            request_payload,
            '{lineage,deployment_id}',
            CASE
                WHEN job_cleanup_only THEN 'null'::jsonb
                ELSE to_jsonb(deployment_id)
            END,
            TRUE
        ) AS request_payload
    FROM miner_launch_intents
)
UPDATE miner_launch_intents AS intent
SET
    request_payload = transformed.request_payload,
    request_sha256 = encode(
        sha256(convert_to(canonical_miner_teardown_jsonb(transformed.request_payload), 'UTF8')),
        'hex'
    ),
    lineage_sha256 = encode(
        sha256(
            convert_to(
                canonical_miner_teardown_jsonb(transformed.request_payload -> 'lineage'),
                'UTF8'
            )
        ),
        'hex'
    )
FROM transformed
WHERE transformed.intent_id = intent.intent_id;

ALTER TABLE miner_launch_intents
    DROP CONSTRAINT IF EXISTS ck_miner_launch_intent_deployment_authority;
ALTER TABLE miner_launch_intents
    ADD CONSTRAINT ck_miner_launch_intent_deployment_authority CHECK (
        job_cleanup_only OR deployment_id IS NOT NULL
    );

CREATE TABLE registry_scope_intents (
    launch_config_id TEXT PRIMARY KEY,
    launch_intent_id TEXT,
    deployment_id TEXT,
    validator TEXT NOT NULL,
    server_id TEXT,
    repository TEXT,
    manifest_digest TEXT,
    desired_state TEXT NOT NULL DEFAULT 'active',
    phase TEXT NOT NULL DEFAULT 'register_pending',
    registration_ack JSONB,
    registered_at TIMESTAMPTZ,
    revocation_ack JSONB,
    revoked_at TIMESTAMPTZ,
    last_failure TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT registry_scope_intents_launch_intent_id_fkey
        FOREIGN KEY (launch_intent_id)
        REFERENCES miner_launch_intents(intent_id)
        ON DELETE RESTRICT,
    CONSTRAINT ck_registry_scope_desired_state CHECK (
        desired_state IN ('active', 'revoked')
    ),
    CONSTRAINT ck_registry_scope_phase CHECK (
        phase IN ('register_pending', 'active', 'revoke_pending', 'revoked')
    ),
    CONSTRAINT ck_registry_scope_state_phase CHECK (
        (desired_state = 'active' AND phase IN ('register_pending', 'active'))
        OR (desired_state = 'revoked' AND phase IN ('revoke_pending', 'revoked'))
    ),
    CONSTRAINT ck_registry_scope_active_identity CHECK (
        desired_state = 'revoked' OR (
            launch_intent_id IS NOT NULL
            AND deployment_id IS NOT NULL
            AND server_id IS NOT NULL
            AND repository IS NOT NULL
            AND manifest_digest ~ '^sha256:[0-9a-f]{64}$'
        )
    ),
    CONSTRAINT ck_registry_scope_registration_ack CHECK (
        (registration_ack IS NULL) = (registered_at IS NULL)
    ),
    CONSTRAINT ck_registry_scope_revocation_ack CHECK (
        (revocation_ack IS NULL) = (revoked_at IS NULL)
    ),
    CONSTRAINT ck_registry_scope_active_ack CHECK (
        phase <> 'active' OR registration_ack IS NOT NULL
    ),
    CONSTRAINT ck_registry_scope_revoked_ack CHECK (
        phase <> 'revoked' OR revocation_ack IS NOT NULL
    )
);

CREATE UNIQUE INDEX registry_scope_launch_intent_key
    ON registry_scope_intents (launch_intent_id)
    WHERE launch_intent_id IS NOT NULL;
CREATE INDEX registry_scope_recovery_idx
    ON registry_scope_intents (desired_state, phase, updated_at)
    WHERE phase <> 'revoked';

INSERT INTO registry_scope_intents (
    launch_config_id,
    launch_intent_id,
    deployment_id,
    validator,
    server_id,
    repository,
    manifest_digest,
    desired_state,
    phase,
    registration_ack,
    registered_at,
    created_at,
    updated_at
)
SELECT
    intent.response_payload ->> 'config_id',
    intent.intent_id,
    intent.deployment_id,
    intent.validator,
    intent.server_id,
    intent.response_payload -> 'registry' ->> 'repository',
    intent.response_payload -> 'registry' ->> 'manifest_digest',
    CASE WHEN deployment.deployment_id IS NULL THEN 'revoked' ELSE 'active' END,
    CASE
        WHEN deployment.deployment_id IS NULL THEN 'revoke_pending'
        WHEN intent.registry_ack IS NULL THEN 'register_pending'
        ELSE 'active'
    END,
    intent.registry_ack,
    CASE WHEN intent.registry_ack IS NULL THEN NULL ELSE intent.updated_at END,
    intent.created_at,
    intent.updated_at
FROM miner_launch_intents AS intent
LEFT JOIN deployments AS deployment
  ON deployment.deployment_id = intent.deployment_id
WHERE intent.job_cleanup_only IS FALSE
  AND jsonb_typeof(intent.response_payload) = 'object'
  AND jsonb_typeof(intent.response_payload -> 'registry') = 'object'
  AND COALESCE(intent.response_payload ->> 'config_id', '') <> ''
  AND COALESCE(intent.response_payload -> 'registry' ->> 'repository', '') <> ''
  AND COALESCE(intent.response_payload -> 'registry' ->> 'manifest_digest', '')
      ~ '^sha256:[0-9a-f]{64}$'
ON CONFLICT (launch_config_id) DO NOTHING;

-- migrate:down

LOCK TABLE registry_scope_intents, miner_launch_intents IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM registry_scope_intents) THEN
        RAISE EXCEPTION
            'cannot remove registry scope authority while scope history exists';
    END IF;
    IF EXISTS (SELECT 1 FROM miner_launch_intents) THEN
        RAISE EXCEPTION
            'cannot remove deployment nonce authority while launch history exists';
    END IF;
END
$$;

DROP TABLE registry_scope_intents;
ALTER TABLE miner_launch_intents
    DROP CONSTRAINT IF EXISTS ck_miner_launch_intent_deployment_authority;
