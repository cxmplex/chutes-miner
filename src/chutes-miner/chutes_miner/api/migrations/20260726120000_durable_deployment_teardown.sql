-- migrate:up
CREATE TABLE IF NOT EXISTS deployment_teardown_operations (
    operation_id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    phase TEXT NOT NULL DEFAULT 'requested',
    reason TEXT NOT NULL,
    retry_lease_owner TEXT,
    retry_lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    validator TEXT NOT NULL,
    server_id TEXT NOT NULL,
    chute_id TEXT NOT NULL,
    config_id TEXT,
    job_id TEXT,
    instance_id TEXT,
    cluster_context TEXT NOT NULL,
    cluster_context_sha256 TEXT NOT NULL,
    namespace TEXT NOT NULL,
    kubernetes_node_uid TEXT,
    kubernetes_node_generation INTEGER NOT NULL,
    registration_attestation_id TEXT,
    gpu_allocation_group_id TEXT,
    gpu_allocation_group_generation INTEGER,
    gpu_hardware_uuids JSONB NOT NULL,
    immutable_labels JSONB NOT NULL,
    registry_revocation_ack JSONB,
    registry_revoked_at TIMESTAMPTZ,
    validator_instance_deletion_ack JSONB,
    validator_instance_deleted_at TIMESTAMPTZ,
    controllers_absent_at TIMESTAMPTZ,
    services_absent_at TIMESTAMPTZ,
    pods_absent_at TIMESTAMPTZ,
    pull_secret_deletion_ack JSONB,
    pull_secret_deleted_at TIMESTAMPTZ,
    lineage_conflict_at TIMESTAMPTZ,
    last_failure TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT ck_deployment_teardown_phase CHECK (
        phase IN (
            'requested', 'discovering', 'revoking', 'deleting',
            'verifying', 'finalizing', 'completed'
        )
    ),
    CONSTRAINT ck_deployment_teardown_node_generation CHECK (
        kubernetes_node_generation >= 0
    ),
    CONSTRAINT ck_deployment_teardown_allocation_group CHECK (
        (
            gpu_allocation_group_id IS NULL
            AND gpu_allocation_group_generation IS NULL
        )
        OR
        (
            gpu_allocation_group_id IS NOT NULL
            AND gpu_allocation_group_generation IS NOT NULL
            AND gpu_allocation_group_generation > 0
        )
    ),
    CONSTRAINT ck_deployment_teardown_retry_lease CHECK (
        (retry_lease_owner IS NULL) = (retry_lease_expires_at IS NULL)
    ),
    CONSTRAINT ck_deployment_teardown_registry_ack CHECK (
        (registry_revocation_ack IS NULL) = (registry_revoked_at IS NULL)
    ),
    CONSTRAINT ck_deployment_teardown_validator_ack CHECK (
        (validator_instance_deletion_ack IS NULL) =
        (validator_instance_deleted_at IS NULL)
    ),
    CONSTRAINT ck_deployment_teardown_secret_ack CHECK (
        (pull_secret_deletion_ack IS NULL) = (pull_secret_deleted_at IS NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS deployment_teardown_active_deployment_idx
    ON deployment_teardown_operations (deployment_id)
    WHERE phase <> 'completed';
CREATE INDEX IF NOT EXISTS deployment_teardown_retry_idx
    ON deployment_teardown_operations (phase, retry_lease_expires_at)
    WHERE phase <> 'completed';

CREATE TABLE IF NOT EXISTS deployment_teardown_node_incarnation_handoffs (
    handoff_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL REFERENCES deployment_teardown_operations(operation_id)
        ON DELETE RESTRICT,
    sequence INTEGER NOT NULL,
    from_kubernetes_node_uid TEXT NOT NULL,
    from_kubernetes_node_generation INTEGER NOT NULL,
    from_registration_attestation_id TEXT NOT NULL,
    from_gpu_allocation_group_id TEXT NOT NULL,
    from_gpu_allocation_group_generation INTEGER NOT NULL,
    from_cluster_context_sha256 TEXT NOT NULL,
    to_kubernetes_node_uid TEXT NOT NULL,
    to_kubernetes_node_generation INTEGER NOT NULL,
    to_registration_attestation_id TEXT NOT NULL,
    to_gpu_allocation_group_id TEXT NOT NULL,
    to_gpu_allocation_group_generation INTEGER NOT NULL,
    to_cluster_context_sha256 TEXT NOT NULL,
    authorized_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_teardown_node_handoff_sequence CHECK (sequence > 0),
    CONSTRAINT ck_teardown_node_handoff_generation CHECK (
        from_kubernetes_node_generation > 0
        AND to_kubernetes_node_generation > from_kubernetes_node_generation
    ),
    CONSTRAINT ck_teardown_node_handoff_group_generation CHECK (
        from_gpu_allocation_group_generation > 0
        AND to_gpu_allocation_group_generation > 0
    ),
    CONSTRAINT deployment_teardown_node_handoff_sequence_key
        UNIQUE (operation_id, sequence),
    CONSTRAINT deployment_teardown_node_handoff_from_generation_key
        UNIQUE (operation_id, from_kubernetes_node_generation),
    CONSTRAINT deployment_teardown_node_handoff_to_generation_key
        UNIQUE (operation_id, to_kubernetes_node_generation)
);

CREATE TABLE IF NOT EXISTS deployment_teardown_k8s_resources (
    resource_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL REFERENCES deployment_teardown_operations(operation_id)
        ON DELETE CASCADE,
    cluster_context TEXT NOT NULL,
    namespace TEXT NOT NULL,
    api_version TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    uid TEXT NOT NULL,
    owner_kind TEXT,
    owner_name TEXT,
    owner_uid TEXT,
    node_name TEXT,
    labels JSONB NOT NULL,
    labels_sha256 TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'observed',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delete_requested_at TIMESTAMPTZ,
    absent_at TIMESTAMPTZ,
    replaced_by_resource_id TEXT REFERENCES deployment_teardown_k8s_resources(resource_id)
        ON DELETE RESTRICT,
    CONSTRAINT ck_deployment_teardown_resource_kind CHECK (
        kind IN ('Job', 'Deployment', 'ReplicaSet', 'Service', 'Pod', 'Secret')
    ),
    CONSTRAINT ck_deployment_teardown_resource_state CHECK (
        state IN ('observed', 'delete_requested', 'absent', 'replaced')
    ),
    CONSTRAINT ck_deployment_teardown_resource_owner CHECK (
        (owner_kind IS NULL AND owner_name IS NULL AND owner_uid IS NULL)
        OR
        (owner_kind IS NOT NULL AND owner_name IS NOT NULL AND owner_uid IS NOT NULL)
    ),
    CONSTRAINT deployment_teardown_resource_uid_key UNIQUE (
        operation_id, cluster_context, namespace, kind, uid
    )
);
CREATE INDEX IF NOT EXISTS deployment_teardown_resource_lookup_idx
    ON deployment_teardown_k8s_resources (operation_id, kind, name);

CREATE TABLE IF NOT EXISTS deployment_launch_operations (
    operation_id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL UNIQUE,
    phase TEXT NOT NULL DEFAULT 'reserved',
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    immutable_labels JSONB NOT NULL,
    service_name TEXT,
    service_uid TEXT,
    secret_name TEXT,
    secret_uid TEXT,
    job_name TEXT,
    job_uid TEXT,
    create_results JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_failure TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT ck_deployment_launch_phase CHECK (
        phase IN ('reserved', 'creating', 'created', 'teardown_fenced', 'failed')
    ),
    CONSTRAINT ck_deployment_launch_lease CHECK (
        (lease_owner IS NULL) = (lease_expires_at IS NULL)
    ),
    CONSTRAINT ck_deployment_launch_service CHECK (
        (service_name IS NULL) = (service_uid IS NULL)
    ),
    CONSTRAINT ck_deployment_launch_secret CHECK (
        (secret_name IS NULL) = (secret_uid IS NULL)
    ),
    CONSTRAINT ck_deployment_launch_job CHECK (
        (job_name IS NULL) = (job_uid IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS deployment_launch_recovery_idx
    ON deployment_launch_operations (phase, lease_expires_at)
    WHERE phase IN ('reserved', 'creating', 'failed');

CREATE TABLE IF NOT EXISTS delayed_validator_instance_cleanups (
    cleanup_id TEXT PRIMARY KEY,
    source_teardown_operation_id TEXT NOT NULL
        REFERENCES deployment_teardown_operations(operation_id) ON DELETE RESTRICT,
    validator TEXT NOT NULL,
    chute_id TEXT NOT NULL,
    config_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    phase TEXT NOT NULL DEFAULT 'pending',
    retry_lease_owner TEXT,
    retry_lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    deletion_ack JSONB,
    deleted_at TIMESTAMPTZ,
    last_failure TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT delayed_validator_instance_cleanup_identity_key
        UNIQUE (config_id, instance_id),
    CONSTRAINT ck_delayed_validator_instance_cleanup_phase CHECK (
        phase IN ('pending', 'completed')
    ),
    CONSTRAINT ck_delayed_validator_instance_cleanup_lease CHECK (
        (retry_lease_owner IS NULL) = (retry_lease_expires_at IS NULL)
    ),
    CONSTRAINT ck_delayed_validator_instance_cleanup_ack CHECK (
        (deletion_ack IS NULL) = (deleted_at IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS parent_deletion_operations (
    operation_id TEXT PRIMARY KEY,
    parent_type TEXT NOT NULL,
    parent_id TEXT NOT NULL,
    validator TEXT NOT NULL,
    reason TEXT NOT NULL,
    phase TEXT NOT NULL DEFAULT 'requested',
    retry_lease_owner TEXT,
    retry_lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    snapshot JSONB NOT NULL,
    monitor_stop_ack JSONB,
    monitor_stopped_at TIMESTAMPTZ,
    validator_server_deletion_ack JSONB,
    validator_server_deleted_at TIMESTAMPTZ,
    last_failure TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT ck_parent_deletion_type CHECK (parent_type IN ('server', 'chute')),
    CONSTRAINT ck_parent_deletion_phase CHECK (
        phase IN ('requested', 'waiting_for_children', 'finalizing', 'completed')
    ),
    CONSTRAINT ck_parent_deletion_retry_lease CHECK (
        (retry_lease_owner IS NULL) = (retry_lease_expires_at IS NULL)
    ),
    CONSTRAINT ck_parent_deletion_monitor_ack CHECK (
        (monitor_stop_ack IS NULL) = (monitor_stopped_at IS NULL)
    ),
    CONSTRAINT ck_parent_deletion_validator_ack CHECK (
        (validator_server_deletion_ack IS NULL) = (validator_server_deleted_at IS NULL)
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS parent_deletion_active_idx
    ON parent_deletion_operations (parent_type, parent_id)
    WHERE phase <> 'completed';

CREATE TABLE IF NOT EXISTS parent_deletion_children (
    parent_operation_id TEXT NOT NULL REFERENCES parent_deletion_operations(operation_id)
        ON DELETE CASCADE,
    child_operation_id TEXT NOT NULL REFERENCES deployment_teardown_operations(operation_id)
        ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (parent_operation_id, child_operation_id)
);

CREATE TABLE IF NOT EXISTS kubernetes_orphan_tombstones (
    tombstone_id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    cluster_context TEXT NOT NULL,
    cluster_context_sha256 TEXT NOT NULL,
    namespace TEXT NOT NULL,
    kubernetes_node_uid TEXT,
    kubernetes_node_generation INTEGER NOT NULL,
    phase TEXT NOT NULL DEFAULT 'recorded',
    retry_lease_owner TEXT,
    retry_lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    immutable_labels JSONB NOT NULL,
    last_failure TEXT,
    lineage_conflict_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT ck_kubernetes_orphan_tombstone_phase CHECK (
        phase IN ('recorded', 'deleting', 'verifying', 'completed')
    ),
    CONSTRAINT ck_kubernetes_orphan_node_generation CHECK (
        kubernetes_node_generation >= 0
    ),
    CONSTRAINT ck_kubernetes_orphan_retry_lease CHECK (
        (retry_lease_owner IS NULL) = (retry_lease_expires_at IS NULL)
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS kubernetes_orphan_active_idx
    ON kubernetes_orphan_tombstones (deployment_id, cluster_context)
    WHERE phase <> 'completed';
CREATE INDEX IF NOT EXISTS kubernetes_orphan_deployment_history_idx
    ON kubernetes_orphan_tombstones (deployment_id);

CREATE TABLE IF NOT EXISTS kubernetes_orphan_tombstone_resources (
    resource_id TEXT PRIMARY KEY,
    tombstone_id TEXT NOT NULL REFERENCES kubernetes_orphan_tombstones(tombstone_id)
        ON DELETE CASCADE,
    api_version TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    uid TEXT NOT NULL,
    owner_kind TEXT,
    owner_name TEXT,
    owner_uid TEXT,
    node_name TEXT,
    labels JSONB NOT NULL,
    labels_sha256 TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'observed',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    absent_at TIMESTAMPTZ,
    CONSTRAINT ck_kubernetes_orphan_resource_kind CHECK (
        kind IN ('Job', 'Deployment', 'ReplicaSet', 'Service', 'Pod', 'Secret')
    ),
    CONSTRAINT ck_kubernetes_orphan_resource_state CHECK (
        state IN ('observed', 'delete_requested', 'absent')
    ),
    CONSTRAINT ck_kubernetes_orphan_resource_owner CHECK (
        (owner_kind IS NULL AND owner_name IS NULL AND owner_uid IS NULL)
        OR
        (owner_kind IS NOT NULL AND owner_name IS NOT NULL AND owner_uid IS NOT NULL)
    ),
    CONSTRAINT kubernetes_orphan_tombstone_resource_uid_key UNIQUE (
        tombstone_id, kind, uid
    )
);

ALTER TABLE deployments DROP CONSTRAINT IF EXISTS deployments_chute_id_fkey;
ALTER TABLE deployments ADD CONSTRAINT deployments_chute_id_fkey
    FOREIGN KEY (chute_id) REFERENCES chutes(chute_id) ON DELETE RESTRICT;
ALTER TABLE deployments DROP CONSTRAINT IF EXISTS deployments_server_id_fkey;
ALTER TABLE deployments ADD CONSTRAINT deployments_server_id_fkey
    FOREIGN KEY (server_id) REFERENCES servers(server_id)
    ON UPDATE CASCADE ON DELETE RESTRICT;
ALTER TABLE gpus DROP CONSTRAINT IF EXISTS gpus_server_id_fkey;
ALTER TABLE gpus ADD CONSTRAINT gpus_server_id_fkey
    FOREIGN KEY (server_id) REFERENCES servers(server_id)
    ON UPDATE CASCADE ON DELETE RESTRICT;
ALTER TABLE gpus DROP CONSTRAINT IF EXISTS gpus_deployment_id_fkey;
ALTER TABLE gpus ADD CONSTRAINT gpus_deployment_id_fkey
    FOREIGN KEY (deployment_id) REFERENCES deployments(deployment_id) ON DELETE RESTRICT;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS teardown_operation_id TEXT;
ALTER TABLE deployments DROP CONSTRAINT IF EXISTS deployments_teardown_operation_id_fkey;
ALTER TABLE deployments ADD CONSTRAINT deployments_teardown_operation_id_fkey
    FOREIGN KEY (teardown_operation_id)
    REFERENCES deployment_teardown_operations(operation_id) ON DELETE RESTRICT;
CREATE UNIQUE INDEX IF NOT EXISTS deployments_teardown_operation_id_key
    ON deployments (teardown_operation_id) WHERE teardown_operation_id IS NOT NULL;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS launch_operation_id TEXT;
ALTER TABLE deployments DROP CONSTRAINT IF EXISTS deployments_launch_operation_id_fkey;
ALTER TABLE deployments ADD CONSTRAINT deployments_launch_operation_id_fkey
    FOREIGN KEY (launch_operation_id)
    REFERENCES deployment_launch_operations(operation_id) ON DELETE RESTRICT;
CREATE UNIQUE INDEX IF NOT EXISTS deployments_launch_operation_id_key
    ON deployments (launch_operation_id) WHERE launch_operation_id IS NOT NULL;

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

CREATE OR REPLACE FUNCTION require_finished_parent_deletion()
RETURNS TRIGGER AS $$
DECLARE
    expected_type TEXT := CASE TG_TABLE_NAME WHEN 'servers' THEN 'server' ELSE 'chute' END;
    expected_id TEXT := CASE TG_TABLE_NAME WHEN 'servers' THEN OLD.server_id ELSE OLD.chute_id END;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM parent_deletion_operations op
        WHERE op.parent_type = expected_type
          AND op.parent_id = expected_id
          AND op.phase IN ('finalizing', 'completed')
          AND NOT EXISTS (
              SELECT 1
              FROM parent_deletion_children child
              JOIN deployment_teardown_operations teardown
                ON teardown.operation_id = child.child_operation_id
              WHERE child.parent_operation_id = op.operation_id
                AND teardown.phase <> 'completed'
          )
          AND NOT EXISTS (
              SELECT 1
              FROM deployments deployment
              WHERE (expected_type = 'server' AND deployment.server_id = expected_id)
                 OR (expected_type = 'chute' AND deployment.chute_id = expected_id)
          )
          AND (
              expected_type <> 'server'
              OR (
                  op.monitor_stop_ack IS NOT NULL
                  AND op.validator_server_deletion_ack IS NOT NULL
              )
          )
    ) THEN
        RAISE EXCEPTION '% % has no durable parent deletion', expected_type, expected_id
            USING ERRCODE = '23503';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fence_parent_deletion_placement()
RETURNS TRIGGER AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM parent_deletion_operations op
        WHERE op.phase <> 'completed'
          AND (
              (op.parent_type = 'server' AND op.parent_id = NEW.server_id)
              OR (op.parent_type = 'chute' AND op.parent_id = NEW.chute_id)
          )
    ) THEN
        RAISE EXCEPTION 'deployment placement is fenced by parent deletion'
            USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS deployments_require_teardown ON deployments;
CREATE TRIGGER deployments_require_teardown
    BEFORE DELETE ON deployments
    FOR EACH ROW EXECUTE FUNCTION require_finished_deployment_teardown();
DROP TRIGGER IF EXISTS gpus_require_teardown ON gpus;
CREATE TRIGGER gpus_require_teardown
    BEFORE UPDATE OF deployment_id OR DELETE ON gpus
    FOR EACH ROW EXECUTE FUNCTION require_finished_gpu_teardown();
DROP TRIGGER IF EXISTS servers_require_parent_deletion ON servers;
CREATE TRIGGER servers_require_parent_deletion
    BEFORE DELETE ON servers
    FOR EACH ROW EXECUTE FUNCTION require_finished_parent_deletion();
DROP TRIGGER IF EXISTS chutes_require_parent_deletion ON chutes;
CREATE TRIGGER chutes_require_parent_deletion
    BEFORE DELETE ON chutes
    FOR EACH ROW EXECUTE FUNCTION require_finished_parent_deletion();
DROP TRIGGER IF EXISTS deployments_fence_parent_deletion ON deployments;
CREATE TRIGGER deployments_fence_parent_deletion
    BEFORE INSERT OR UPDATE OF server_id, chute_id ON deployments
    FOR EACH ROW EXECUTE FUNCTION fence_parent_deletion_placement();

-- migrate:down
LOCK TABLE deployments, gpus, servers, chutes,
    deployment_teardown_operations, deployment_teardown_k8s_resources,
    deployment_teardown_node_incarnation_handoffs,
    deployment_launch_operations, delayed_validator_instance_cleanups,
    parent_deletion_operations, parent_deletion_children, kubernetes_orphan_tombstones,
    kubernetes_orphan_tombstone_resources IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM deployment_teardown_operations)
       OR EXISTS (SELECT 1 FROM deployment_launch_operations)
       OR EXISTS (SELECT 1 FROM delayed_validator_instance_cleanups)
       OR EXISTS (SELECT 1 FROM parent_deletion_operations)
       OR EXISTS (SELECT 1 FROM kubernetes_orphan_tombstones) THEN
        RAISE EXCEPTION 'cannot remove durable teardown schema while teardown history exists';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS deployments_require_teardown ON deployments;
DROP TRIGGER IF EXISTS gpus_require_teardown ON gpus;
DROP TRIGGER IF EXISTS servers_require_parent_deletion ON servers;
DROP TRIGGER IF EXISTS chutes_require_parent_deletion ON chutes;
DROP TRIGGER IF EXISTS deployments_fence_parent_deletion ON deployments;
DROP FUNCTION IF EXISTS require_finished_deployment_teardown();
DROP FUNCTION IF EXISTS require_finished_gpu_teardown();
DROP FUNCTION IF EXISTS require_finished_parent_deletion();
DROP FUNCTION IF EXISTS fence_parent_deletion_placement();

DROP INDEX IF EXISTS deployments_launch_operation_id_key;
ALTER TABLE deployments DROP CONSTRAINT IF EXISTS deployments_launch_operation_id_fkey;
ALTER TABLE deployments DROP COLUMN IF EXISTS launch_operation_id;
DROP INDEX IF EXISTS deployments_teardown_operation_id_key;
ALTER TABLE deployments DROP CONSTRAINT IF EXISTS deployments_teardown_operation_id_fkey;
ALTER TABLE deployments DROP COLUMN IF EXISTS teardown_operation_id;

ALTER TABLE deployments DROP CONSTRAINT IF EXISTS deployments_chute_id_fkey;
ALTER TABLE deployments ADD CONSTRAINT deployments_chute_id_fkey
    FOREIGN KEY (chute_id) REFERENCES chutes(chute_id) ON DELETE CASCADE;
ALTER TABLE deployments DROP CONSTRAINT IF EXISTS deployments_server_id_fkey;
ALTER TABLE deployments ADD CONSTRAINT deployments_server_id_fkey
    FOREIGN KEY (server_id) REFERENCES servers(server_id)
    ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE gpus DROP CONSTRAINT IF EXISTS gpus_server_id_fkey;
ALTER TABLE gpus ADD CONSTRAINT gpus_server_id_fkey
    FOREIGN KEY (server_id) REFERENCES servers(server_id)
    ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE gpus DROP CONSTRAINT IF EXISTS gpus_deployment_id_fkey;
ALTER TABLE gpus ADD CONSTRAINT gpus_deployment_id_fkey
    FOREIGN KEY (deployment_id) REFERENCES deployments(deployment_id) ON DELETE SET NULL;

DROP TABLE IF EXISTS kubernetes_orphan_tombstone_resources;
DROP TABLE IF EXISTS kubernetes_orphan_tombstones;
DROP TABLE IF EXISTS parent_deletion_children;
DROP TABLE IF EXISTS parent_deletion_operations;
DROP TABLE IF EXISTS delayed_validator_instance_cleanups;
ALTER TABLE deployment_teardown_operations
    DROP CONSTRAINT IF EXISTS deployment_teardown_operations_launch_operation_id_fkey;
DROP TABLE IF EXISTS deployment_launch_operations;
DROP TABLE IF EXISTS deployment_teardown_k8s_resources;
DROP TABLE IF EXISTS deployment_teardown_node_incarnation_handoffs;
DROP TABLE IF EXISTS deployment_teardown_operations;
