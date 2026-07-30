-- migrate:up
CREATE TABLE IF NOT EXISTS gpu_adoption_retirements (
    retirement_id VARCHAR PRIMARY KEY,
    server_id VARCHAR NOT NULL,
    gpu_id VARCHAR NOT NULL,
    hardware_uuid VARCHAR,
    deployment_id VARCHAR,
    validator VARCHAR,
    device_info JSONB,
    model_short_ref VARCHAR,
    verified BOOLEAN,
    prior_gpu_allocation_group_id VARCHAR,
    prior_gpu_allocation_group_generation INTEGER,
    replacement_registration_attestation_id VARCHAR NOT NULL,
    replacement_gpu_allocation_group_id VARCHAR NOT NULL,
    replacement_gpu_allocation_group_generation INTEGER NOT NULL,
    reason VARCHAR NOT NULL DEFAULT 'registrar_assignment_shrink',
    retired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_gpu_adoption_retirement_unassigned CHECK (
        deployment_id IS NULL
    ),
    CONSTRAINT ck_gpu_adoption_retirement_replacement_generation CHECK (
        replacement_gpu_allocation_group_generation > 0
    ),
    CONSTRAINT ck_gpu_adoption_retirement_prior_lineage CHECK (
        (
            prior_gpu_allocation_group_id IS NULL
            AND prior_gpu_allocation_group_generation IS NULL
        )
        OR
        (
            prior_gpu_allocation_group_id IS NOT NULL
            AND prior_gpu_allocation_group_generation IS NOT NULL
            AND prior_gpu_allocation_group_generation > 0
        )
    ),
    CONSTRAINT ck_gpu_adoption_retirement_reason CHECK (
        reason = 'registrar_assignment_shrink'
    )
);

CREATE INDEX IF NOT EXISTS gpu_adoption_retirements_server_time_idx
    ON gpu_adoption_retirements (server_id, retired_at);

CREATE OR REPLACE FUNCTION reject_gpu_adoption_retirement_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'gpu adoption retirement audit rows are immutable';
END;
$$;

DROP TRIGGER IF EXISTS gpu_adoption_retirements_immutable
    ON gpu_adoption_retirements;
CREATE TRIGGER gpu_adoption_retirements_immutable
BEFORE UPDATE OR DELETE ON gpu_adoption_retirements
FOR EACH ROW
EXECUTE FUNCTION reject_gpu_adoption_retirement_mutation();

DROP TRIGGER IF EXISTS gpu_adoption_retirements_immutable_truncate
    ON gpu_adoption_retirements;
CREATE TRIGGER gpu_adoption_retirements_immutable_truncate
BEFORE TRUNCATE ON gpu_adoption_retirements
FOR EACH STATEMENT
EXECUTE FUNCTION reject_gpu_adoption_retirement_mutation();

-- migrate:down
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM gpu_adoption_retirements) THEN
        RAISE EXCEPTION
            'cannot roll back GPU adoption retirement audit while history exists';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS gpu_adoption_retirements_immutable_truncate
    ON gpu_adoption_retirements;
DROP TRIGGER IF EXISTS gpu_adoption_retirements_immutable
    ON gpu_adoption_retirements;
DROP FUNCTION IF EXISTS reject_gpu_adoption_retirement_mutation();
DROP TABLE IF EXISTS gpu_adoption_retirements;
