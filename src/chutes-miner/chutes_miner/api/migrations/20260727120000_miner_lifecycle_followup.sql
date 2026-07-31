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
    ADD COLUMN IF NOT EXISTS owner_api_version TEXT,
    ADD COLUMN IF NOT EXISTS pod_termination_evidence JSONB,
    ADD COLUMN IF NOT EXISTS pod_termination_evidence_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS pod_teardown_finalizer_attached_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS pod_teardown_finalizer_removal_requested_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS pod_teardown_finalizer_removed_at TIMESTAMPTZ;
UPDATE deployment_teardown_k8s_resources
SET owner_api_version = CASE
    WHEN owner_kind = 'Job' THEN 'batch/v1'
    WHEN owner_kind IN ('Deployment', 'ReplicaSet') THEN 'apps/v1'
    ELSE owner_api_version
END
WHERE owner_kind IS NOT NULL
  AND owner_api_version IS NULL;
ALTER TABLE deployment_teardown_k8s_resources
    DROP CONSTRAINT IF EXISTS ck_deployment_teardown_resource_owner,
    DROP CONSTRAINT IF EXISTS ck_deployment_teardown_resource_pod_termination,
    DROP CONSTRAINT IF EXISTS ck_deployment_teardown_resource_pod_termination_sha256;
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
    ),
    ADD CONSTRAINT ck_deployment_teardown_resource_pod_termination CHECK (
        ((pod_termination_evidence IS NULL) =
            (pod_termination_evidence_sha256 IS NULL))
        AND ((pod_termination_evidence IS NULL) =
            (pod_teardown_finalizer_removal_requested_at IS NULL))
        AND (kind = 'Pod' OR pod_termination_evidence IS NULL)
        AND (
            kind = 'Pod'
            OR (
                pod_teardown_finalizer_attached_at IS NULL
                AND pod_teardown_finalizer_removal_requested_at IS NULL
                AND pod_teardown_finalizer_removed_at IS NULL
            )
        )
        AND (
            pod_teardown_finalizer_removal_requested_at IS NULL
            OR pod_teardown_finalizer_attached_at IS NOT NULL
        )
        AND (
            pod_teardown_finalizer_removed_at IS NULL
            OR pod_teardown_finalizer_removal_requested_at IS NOT NULL
        )
        AND (
            kind <> 'Pod'
            OR state NOT IN ('absent', 'replaced')
            OR (
                pod_termination_evidence IS NOT NULL
                AND pod_teardown_finalizer_removed_at IS NOT NULL
            )
        )
    ),
    ADD CONSTRAINT ck_deployment_teardown_resource_pod_termination_sha256 CHECK (
        pod_termination_evidence_sha256 IS NULL
        OR pod_termination_evidence_sha256 ~ '^[0-9a-f]{64}$'
    );

ALTER TABLE deployment_teardown_operations
    ADD COLUMN IF NOT EXISTS validator_job_release_ack JSONB,
    ADD COLUMN IF NOT EXISTS validator_job_released_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS launch_operation_id TEXT,
    ADD COLUMN IF NOT EXISTS launch_phase_at_request TEXT,
    ADD COLUMN IF NOT EXISTS launch_kubernetes_mutation_possible BOOLEAN,
    ADD COLUMN IF NOT EXISTS launch_create_results_sha256 VARCHAR(64),
    ADD COLUMN IF NOT EXISTS resource_discovery JSONB,
    ADD COLUMN IF NOT EXISTS resource_discovery_sha256 VARCHAR(64),
    ADD COLUMN IF NOT EXISTS resource_discovered_at TIMESTAMPTZ;
ALTER TABLE deployment_teardown_operations
    DROP CONSTRAINT IF EXISTS ck_deployment_teardown_job_ack,
    DROP CONSTRAINT IF EXISTS ck_deployment_teardown_resource_discovery,
    DROP CONSTRAINT IF EXISTS ck_deployment_teardown_launch_snapshot,
    DROP CONSTRAINT IF EXISTS deployment_teardown_operations_launch_operation_id_fkey;
ALTER TABLE deployment_teardown_operations
    ADD CONSTRAINT ck_deployment_teardown_job_ack CHECK (
        (validator_job_release_ack IS NULL) =
        (validator_job_released_at IS NULL)
    ),
    ADD CONSTRAINT ck_deployment_teardown_resource_discovery CHECK (
        (
            resource_discovery IS NULL
            AND resource_discovery_sha256 IS NULL
            AND resource_discovered_at IS NULL
        ) OR (
            resource_discovery IS NOT NULL
            AND resource_discovery_sha256 ~ '^[0-9a-f]{64}$'
            AND resource_discovered_at IS NOT NULL
        )
    ),
    ADD CONSTRAINT ck_deployment_teardown_launch_snapshot CHECK (
        (
            launch_operation_id IS NULL
            AND launch_phase_at_request IS NULL
            AND launch_kubernetes_mutation_possible IS NULL
            AND launch_create_results_sha256 IS NULL
        ) OR (
            launch_operation_id IS NOT NULL
            AND launch_phase_at_request IN (
                'reserved', 'creating', 'created', 'failed'
            )
            AND launch_kubernetes_mutation_possible =
                (launch_phase_at_request <> 'reserved')
            AND launch_create_results_sha256 ~ '^[0-9a-f]{64}$'
        )
    );
ALTER TABLE deployment_teardown_operations
    ADD CONSTRAINT deployment_teardown_operations_launch_operation_id_fkey
    FOREIGN KEY (launch_operation_id)
    REFERENCES deployment_launch_operations(operation_id)
    ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION canonical_miner_teardown_jsonb(value JSONB)
RETURNS TEXT AS $$
DECLARE
    result TEXT;
BEGIN
    CASE jsonb_typeof(value)
        WHEN 'object' THEN
            SELECT '{' || COALESCE(
                string_agg(
                    to_jsonb(entry.key)::TEXT || ':' ||
                    canonical_miner_teardown_jsonb(entry.value),
                    ',' ORDER BY entry.key
                ),
                ''
            ) || '}'
            INTO result
            FROM jsonb_each(value) AS entry;
        WHEN 'array' THEN
            SELECT '[' || COALESCE(
                string_agg(
                    canonical_miner_teardown_jsonb(entry.value),
                    ',' ORDER BY entry.ordinality
                ),
                ''
            ) || ']'
            INTO result
            FROM jsonb_array_elements(value) WITH ORDINALITY
                AS entry(value, ordinality);
        ELSE
            result := value::TEXT;
    END CASE;
    RETURN result;
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION deployment_teardown_resource_chain_closed(
    start_resource_id TEXT,
    expected_operation_id TEXT
)
RETURNS BOOLEAN AS $$
    WITH RECURSIVE chain AS (
        SELECT
            resource.resource_id,
            resource.replaced_by_resource_id,
            resource.state,
            resource.cluster_context,
            resource.namespace,
            resource.api_version,
            resource.kind,
            resource.name,
            resource.labels_sha256,
            ARRAY[resource.resource_id]::TEXT[] AS path,
            FALSE AS cycle
        FROM deployment_teardown_k8s_resources resource
        WHERE resource.resource_id = start_resource_id
          AND resource.operation_id = expected_operation_id

        UNION ALL

        SELECT
            successor.resource_id,
            successor.replaced_by_resource_id,
            successor.state,
            successor.cluster_context,
            successor.namespace,
            successor.api_version,
            successor.kind,
            successor.name,
            successor.labels_sha256,
            chain.path || successor.resource_id,
            successor.resource_id = ANY(chain.path)
        FROM chain
        JOIN deployment_teardown_k8s_resources successor
          ON successor.resource_id = chain.replaced_by_resource_id
         AND successor.operation_id = expected_operation_id
         AND successor.cluster_context = chain.cluster_context
         AND successor.namespace = chain.namespace
         AND successor.api_version = chain.api_version
         AND successor.kind = chain.kind
         AND successor.name = chain.name
         AND successor.labels_sha256 = chain.labels_sha256
        WHERE chain.state = 'replaced'
          AND NOT chain.cycle
    )
    SELECT
        EXISTS (
            SELECT 1
            FROM chain
            WHERE state = 'absent'
              AND replaced_by_resource_id IS NULL
              AND NOT cycle
        )
        AND NOT EXISTS (SELECT 1 FROM chain WHERE cycle);
$$ LANGUAGE SQL STABLE;

CREATE OR REPLACE FUNCTION deployment_teardown_closure_complete(
    expected_deployment_id TEXT,
    expected_operation_id TEXT
)
RETURNS BOOLEAN AS $$
    SELECT EXISTS (
        SELECT 1
        FROM deployment_teardown_operations op
        WHERE op.deployment_id = expected_deployment_id
          AND op.operation_id = expected_operation_id
          AND op.phase IN ('finalizing', 'completed')
          AND op.lineage_conflict_at IS NULL
          AND (op.config_id IS NULL OR op.registry_revocation_ack IS NOT NULL)
          AND (op.instance_id IS NULL OR op.validator_instance_deletion_ack IS NOT NULL)
          AND (op.job_id IS NULL OR op.validator_job_release_ack IS NOT NULL)
          AND op.controllers_absent_at IS NOT NULL
          AND op.services_absent_at IS NOT NULL
          AND op.pods_absent_at IS NOT NULL
          AND (op.config_id IS NULL OR op.pull_secret_deletion_ack IS NOT NULL)
          AND op.resource_discovered_at IS NOT NULL
          AND jsonb_typeof(op.resource_discovery) = 'object'
          AND op.resource_discovery = jsonb_build_object(
              'schema', op.resource_discovery -> 'schema',
              'operation_id', op.resource_discovery -> 'operation_id',
              'deployment_id', op.resource_discovery -> 'deployment_id',
              'cluster_context', op.resource_discovery -> 'cluster_context',
              'cluster_context_sha256',
                  op.resource_discovery -> 'cluster_context_sha256',
              'namespace', op.resource_discovery -> 'namespace',
              'config_id', op.resource_discovery -> 'config_id',
              'immutable_labels_sha256',
                  op.resource_discovery -> 'immutable_labels_sha256',
              'launch_operation_id',
                  op.resource_discovery -> 'launch_operation_id',
              'launch_phase_at_request',
                  op.resource_discovery -> 'launch_phase_at_request',
              'launch_kubernetes_mutation_possible',
                  op.resource_discovery ->
                      'launch_kubernetes_mutation_possible',
              'launch_create_results_sha256',
                  op.resource_discovery -> 'launch_create_results_sha256',
              'resources', op.resource_discovery -> 'resources'
          )
          AND op.resource_discovery ->> 'schema' =
              'chutes.miner-k8s-resource-discovery.v1'
          AND op.resource_discovery ->> 'operation_id' = op.operation_id
          AND op.resource_discovery ->> 'deployment_id' = op.deployment_id
          AND op.resource_discovery ->> 'cluster_context' = op.cluster_context
          AND op.resource_discovery ->> 'cluster_context_sha256' =
              op.cluster_context_sha256
          AND op.resource_discovery ->> 'namespace' = op.namespace
          AND (op.resource_discovery ->> 'config_id') IS NOT DISTINCT FROM op.config_id
          AND op.resource_discovery ->> 'immutable_labels_sha256' = encode(
              sha256(
                  convert_to(
                      canonical_miner_teardown_jsonb(op.immutable_labels),
                      'UTF8'
                  )
              ),
              'hex'
          )
          AND (op.resource_discovery ->> 'launch_operation_id')
              IS NOT DISTINCT FROM op.launch_operation_id
          AND (op.resource_discovery ->> 'launch_phase_at_request')
              IS NOT DISTINCT FROM op.launch_phase_at_request
          AND (
              op.resource_discovery -> 'launch_kubernetes_mutation_possible'
          ) IS NOT DISTINCT FROM COALESCE(
              to_jsonb(op.launch_kubernetes_mutation_possible),
              'null'::JSONB
          )
          AND (op.resource_discovery ->> 'launch_create_results_sha256')
              IS NOT DISTINCT FROM op.launch_create_results_sha256
          AND jsonb_typeof(op.gpu_hardware_uuids) = 'array'
          AND (
              op.launch_operation_id IS NULL
              OR EXISTS (
                  SELECT 1
                  FROM deployment_launch_operations launch
                  WHERE launch.operation_id = op.launch_operation_id
                    AND launch.deployment_id = op.deployment_id
                    AND launch.phase = 'teardown_fenced'
                    AND op.launch_create_results_sha256 = encode(
                        sha256(
                            convert_to(
                                canonical_miner_teardown_jsonb(
                                    launch.create_results
                                ),
                                'UTF8'
                            )
                        ),
                        'hex'
                    )
              )
          )
          AND jsonb_typeof(op.resource_discovery -> 'resources') = 'array'
          AND op.resource_discovery_sha256 = encode(
              sha256(
                  convert_to(
                      canonical_miner_teardown_jsonb(op.resource_discovery),
                      'UTF8'
                  )
              ),
              'hex'
          )
          AND jsonb_array_length(op.resource_discovery -> 'resources') = (
              SELECT count(DISTINCT (
                  witness.value ->> 'kind',
                  witness.value ->> 'uid'
              ))
              FROM jsonb_array_elements(
                  CASE
                      WHEN jsonb_typeof(
                          op.resource_discovery -> 'resources'
                      ) = 'array'
                      THEN op.resource_discovery -> 'resources'
                      ELSE '[]'::JSONB
                  END
              ) AS witness(value)
          )
          AND (
              jsonb_array_length(op.resource_discovery -> 'resources') > 0
              OR jsonb_array_length(op.gpu_hardware_uuids) = 0
              OR (
                  op.launch_operation_id IS NOT NULL
                  AND op.launch_phase_at_request = 'reserved'
                  AND op.launch_kubernetes_mutation_possible = FALSE
                  AND op.launch_create_results_sha256 = encode(
                      sha256(convert_to('{}', 'UTF8')),
                      'hex'
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM deployment_launch_operations launch
                      WHERE launch.operation_id = op.launch_operation_id
                        AND launch.deployment_id = op.deployment_id
                        AND launch.phase = 'teardown_fenced'
                        AND launch.canonical_workload_spec IS NULL
                        AND launch.canonical_workload_spec_sha256 IS NULL
                        AND launch.service_name IS NULL
                        AND launch.service_uid IS NULL
                        AND launch.secret_name IS NULL
                        AND launch.secret_uid IS NULL
                        AND launch.job_name IS NULL
                        AND launch.job_uid IS NULL
                        AND launch.create_results = '{}'::JSONB
                  )
              )
          )
          AND (
              jsonb_array_length(op.gpu_hardware_uuids) = 0
              OR (
                  op.launch_operation_id IS NOT NULL
                  AND op.launch_phase_at_request = 'reserved'
                  AND op.launch_kubernetes_mutation_possible = FALSE
                  AND op.launch_create_results_sha256 = encode(
                      sha256(convert_to('{}', 'UTF8')),
                      'hex'
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM deployment_launch_operations launch
                      WHERE launch.operation_id = op.launch_operation_id
                        AND launch.deployment_id = op.deployment_id
                        AND launch.phase = 'teardown_fenced'
                        AND launch.canonical_workload_spec IS NULL
                        AND launch.canonical_workload_spec_sha256 IS NULL
                        AND launch.service_name IS NULL
                        AND launch.service_uid IS NULL
                        AND launch.secret_name IS NULL
                        AND launch.secret_uid IS NULL
                        AND launch.job_name IS NULL
                        AND launch.job_uid IS NULL
                        AND launch.create_results = '{}'::JSONB
                  )
              )
              OR EXISTS (
                  SELECT 1
                  FROM deployment_teardown_k8s_resources pod
                  WHERE pod.operation_id = op.operation_id
                    AND pod.kind = 'Pod'
              )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM jsonb_array_elements(
                  CASE
                      WHEN jsonb_typeof(
                          op.resource_discovery -> 'resources'
                      ) = 'array'
                      THEN op.resource_discovery -> 'resources'
                      ELSE '[]'::JSONB
                  END
              ) AS witness(value)
              WHERE (
                  jsonb_typeof(witness.value) = 'object'
                  AND witness.value = jsonb_build_object(
                      'api_version', witness.value -> 'api_version',
                      'kind', witness.value -> 'kind',
                      'name', witness.value -> 'name',
                      'namespace', witness.value -> 'namespace',
                      'uid', witness.value -> 'uid',
                      'owner_api_version', witness.value -> 'owner_api_version',
                      'owner_kind', witness.value -> 'owner_kind',
                      'owner_name', witness.value -> 'owner_name',
                      'owner_uid', witness.value -> 'owner_uid',
                      'node_name', witness.value -> 'node_name',
                      'labels_sha256', witness.value -> 'labels_sha256'
                  )
                  AND COALESCE(witness.value ->> 'api_version', '') <> ''
                  AND COALESCE(witness.value ->> 'kind', '') <> ''
                  AND COALESCE(witness.value ->> 'name', '') <> ''
                  AND witness.value ->> 'namespace' = op.namespace
                  AND COALESCE(witness.value ->> 'uid', '') <> ''
                  AND COALESCE(witness.value ->> 'labels_sha256', '') ~
                      '^[0-9a-f]{64}$'
                  AND EXISTS (
                      SELECT 1
                      FROM deployment_teardown_k8s_resources witnessed
                      WHERE witnessed.operation_id = op.operation_id
                        AND witnessed.cluster_context = op.cluster_context
                        AND witnessed.namespace = op.namespace
                        AND witnessed.api_version =
                            witness.value ->> 'api_version'
                        AND witnessed.kind = witness.value ->> 'kind'
                        AND witnessed.name = witness.value ->> 'name'
                        AND witnessed.namespace = witness.value ->> 'namespace'
                        AND witnessed.uid = witness.value ->> 'uid'
                        AND witnessed.owner_api_version IS NOT DISTINCT FROM
                            witness.value ->> 'owner_api_version'
                        AND witnessed.owner_kind IS NOT DISTINCT FROM
                            witness.value ->> 'owner_kind'
                        AND witnessed.owner_name IS NOT DISTINCT FROM
                            witness.value ->> 'owner_name'
                        AND witnessed.owner_uid IS NOT DISTINCT FROM
                            witness.value ->> 'owner_uid'
                        AND witnessed.node_name IS NOT DISTINCT FROM
                            witness.value ->> 'node_name'
                        AND witnessed.labels_sha256 =
                            witness.value ->> 'labels_sha256'
                        AND witnessed.labels_sha256 = encode(
                            sha256(
                                convert_to(
                                    canonical_miner_teardown_jsonb(
                                        witnessed.labels
                                    ),
                                    'UTF8'
                                )
                            ),
                            'hex'
                        )
                  )
              ) IS NOT TRUE
          )
          AND NOT EXISTS (
              SELECT 1
              FROM deployment_teardown_k8s_resources resource
              WHERE resource.operation_id = op.operation_id
                AND (
                    resource.cluster_context IS DISTINCT FROM op.cluster_context
                    OR resource.namespace IS DISTINCT FROM op.namespace
                    OR
                    (
                        (
                            resource.state = 'absent'
                            AND resource.absent_at IS NOT NULL
                            AND resource.replaced_by_resource_id IS NULL
                        ) OR (
                            resource.state = 'replaced'
                            AND resource.replaced_by_resource_id IS NOT NULL
                            AND deployment_teardown_resource_chain_closed(
                                resource.resource_id,
                                resource.operation_id
                            )
                        )
                    ) IS NOT TRUE
                    OR (
                        resource.kind = 'Pod'
                        AND (
                            resource.node_name IS NOT NULL
                            AND resource.pod_teardown_finalizer_attached_at IS NOT NULL
                            AND resource.pod_teardown_finalizer_removal_requested_at
                                >= resource.pod_teardown_finalizer_attached_at
                            AND resource.pod_teardown_finalizer_removed_at
                                >= resource.pod_teardown_finalizer_removal_requested_at
                            AND jsonb_typeof(resource.pod_termination_evidence) = 'object'
                            AND resource.pod_termination_evidence = jsonb_build_object(
                                'schema',
                                resource.pod_termination_evidence -> 'schema',
                                'pod_uid',
                                resource.pod_termination_evidence -> 'pod_uid',
                                'node_name',
                                resource.pod_termination_evidence -> 'node_name',
                                'teardown_finalizer',
                                resource.pod_termination_evidence -> 'teardown_finalizer',
                                'deletion_timestamp',
                                resource.pod_termination_evidence -> 'deletion_timestamp',
                                'containers',
                                resource.pod_termination_evidence -> 'containers'
                            )
                            AND resource.pod_termination_evidence ->> 'schema' =
                                'chutes.miner-pod-termination.v1'
                            AND resource.pod_termination_evidence ->> 'pod_uid' =
                                resource.uid
                            AND resource.pod_termination_evidence ->> 'node_name' =
                                resource.node_name
                            AND resource.pod_termination_evidence ->>
                                'teardown_finalizer' =
                                'chutes.ai/gpu-teardown-v1'
                            AND COALESCE(
                                resource.pod_termination_evidence ->>
                                    'deletion_timestamp',
                                ''
                            ) <> ''
                            AND jsonb_typeof(
                                resource.pod_termination_evidence -> 'containers'
                            ) = 'array'
                            AND jsonb_array_length(
                                resource.pod_termination_evidence -> 'containers'
                            ) > 0
                            AND NOT EXISTS (
                                SELECT 1
                                FROM jsonb_array_elements(
                                    CASE
                                        WHEN jsonb_typeof(
                                            resource.pod_termination_evidence ->
                                                'containers'
                                        ) = 'array'
                                        THEN resource.pod_termination_evidence ->
                                            'containers'
                                        ELSE '[]'::JSONB
                                    END
                                ) AS container(value)
                                WHERE (
                                    jsonb_typeof(container.value) = 'object'
                                    AND container.value = jsonb_build_object(
                                        'group', container.value -> 'group',
                                        'name', container.value -> 'name',
                                        'outcome', container.value -> 'outcome',
                                        'container_id',
                                            container.value -> 'container_id',
                                        'exit_code', container.value -> 'exit_code',
                                        'signal', container.value -> 'signal',
                                        'reason', container.value -> 'reason',
                                        'started_at', container.value -> 'started_at',
                                        'finished_at', container.value -> 'finished_at'
                                    )
                                    AND container.value ->> 'group' IN (
                                        'init', 'container', 'ephemeral'
                                    )
                                    AND COALESCE(container.value ->> 'name', '') <> ''
                                    AND container.value ->> 'outcome' = 'terminated'
                                    AND COALESCE(
                                        container.value ->> 'container_id',
                                        ''
                                    ) <> ''
                                    AND COALESCE(
                                        container.value ->> 'finished_at',
                                        ''
                                    ) <> ''
                                ) IS NOT TRUE
                            )
                            AND resource.pod_termination_evidence_sha256 = encode(
                                sha256(
                                    convert_to(
                                        canonical_miner_teardown_jsonb(
                                            resource.pod_termination_evidence
                                        ),
                                        'UTF8'
                                    )
                                ),
                                'hex'
                            )
                        ) IS NOT TRUE
                    )
                )
          )
    );
$$ LANGUAGE SQL STABLE;

CREATE OR REPLACE FUNCTION protect_deployment_teardown_discovery()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF (
            NEW.resource_discovery IS NOT NULL
            OR NEW.resource_discovery_sha256 IS NOT NULL
            OR NEW.resource_discovered_at IS NOT NULL
        ) AND NEW.phase <> 'discovering' THEN
            RAISE EXCEPTION
                'deployment teardown discovery may only be recorded while discovering'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(
        NEW.launch_operation_id,
        NEW.launch_phase_at_request,
        NEW.launch_kubernetes_mutation_possible,
        NEW.launch_create_results_sha256
    ) IS DISTINCT FROM ROW(
        OLD.launch_operation_id,
        OLD.launch_phase_at_request,
        OLD.launch_kubernetes_mutation_possible,
        OLD.launch_create_results_sha256
    ) THEN
        RAISE EXCEPTION 'deployment teardown launch snapshot is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.resource_discovery IS NOT NULL THEN
        IF ROW(
            NEW.resource_discovery,
            NEW.resource_discovery_sha256,
            NEW.resource_discovered_at
        ) IS DISTINCT FROM ROW(
            OLD.resource_discovery,
            OLD.resource_discovery_sha256,
            OLD.resource_discovered_at
        ) THEN
            RAISE EXCEPTION 'deployment teardown discovery witness is immutable'
                USING ERRCODE = '23514';
        END IF;
    ELSIF (
        NEW.resource_discovery IS NOT NULL
        OR NEW.resource_discovery_sha256 IS NOT NULL
        OR NEW.resource_discovered_at IS NOT NULL
    ) AND (OLD.phase <> 'discovering' OR NEW.phase <> 'discovering') THEN
        RAISE EXCEPTION
            'deployment teardown discovery may only be recorded while discovering'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS deployment_teardown_discovery_write_once
    ON deployment_teardown_operations;
CREATE TRIGGER deployment_teardown_discovery_write_once
    BEFORE INSERT OR UPDATE ON deployment_teardown_operations
    FOR EACH ROW EXECUTE FUNCTION protect_deployment_teardown_discovery();

CREATE OR REPLACE FUNCTION protect_deployment_teardown_resource_history()
RETURNS TRIGGER AS $$
DECLARE
    operation deployment_teardown_operations%ROWTYPE;
    witnessed BOOLEAN := FALSE;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'deployment teardown resource history cannot be deleted'
            USING ERRCODE = '23503';
    END IF;

    SELECT * INTO operation
    FROM deployment_teardown_operations
    WHERE operation_id = NEW.operation_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'deployment teardown resource has no operation'
            USING ERRCODE = '23503';
    END IF;
    IF NEW.cluster_context IS DISTINCT FROM operation.cluster_context
       OR NEW.namespace IS DISTINCT FROM operation.namespace THEN
        RAISE EXCEPTION
            'deployment teardown resource context differs from operation'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF ROW(
            NEW.resource_id,
            NEW.operation_id,
            NEW.cluster_context,
            NEW.namespace,
            NEW.api_version,
            NEW.kind,
            NEW.name,
            NEW.uid,
            NEW.owner_api_version,
            NEW.owner_kind,
            NEW.owner_name,
            NEW.owner_uid,
            NEW.node_name,
            NEW.labels,
            NEW.labels_sha256
        ) IS DISTINCT FROM ROW(
            OLD.resource_id,
            OLD.operation_id,
            OLD.cluster_context,
            OLD.namespace,
            OLD.api_version,
            OLD.kind,
            OLD.name,
            OLD.uid,
            OLD.owner_api_version,
            OLD.owner_kind,
            OLD.owner_name,
            OLD.owner_uid,
            OLD.node_name,
            OLD.labels,
            OLD.labels_sha256
        ) THEN
            RAISE EXCEPTION 'deployment teardown resource identity is immutable'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.replaced_by_resource_id IS NOT NULL
           AND NEW.replaced_by_resource_id IS DISTINCT FROM
               OLD.replaced_by_resource_id THEN
            RAISE EXCEPTION 'deployment teardown replacement binding is immutable'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.pod_termination_evidence IS NOT NULL
           AND ROW(
               NEW.pod_termination_evidence,
               NEW.pod_termination_evidence_sha256
           ) IS DISTINCT FROM ROW(
               OLD.pod_termination_evidence,
               OLD.pod_termination_evidence_sha256
           ) THEN
            RAISE EXCEPTION 'deployment teardown Pod evidence is immutable'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.pod_teardown_finalizer_attached_at IS NOT NULL
           AND NEW.pod_teardown_finalizer_attached_at IS DISTINCT FROM
               OLD.pod_teardown_finalizer_attached_at THEN
            RAISE EXCEPTION 'deployment teardown Pod finalizer audit is immutable'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.pod_teardown_finalizer_removal_requested_at IS NOT NULL
           AND NEW.pod_teardown_finalizer_removal_requested_at IS DISTINCT FROM
               OLD.pod_teardown_finalizer_removal_requested_at THEN
            RAISE EXCEPTION 'deployment teardown Pod removal audit is immutable'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.pod_teardown_finalizer_removed_at IS NOT NULL
           AND NEW.pod_teardown_finalizer_removed_at IS DISTINCT FROM
               OLD.pod_teardown_finalizer_removed_at THEN
            RAISE EXCEPTION 'deployment teardown Pod removal ACK is immutable'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.state IN ('absent', 'replaced') AND NEW.state <> OLD.state THEN
            RAISE EXCEPTION 'deployment teardown resource closure is terminal'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF operation.resource_discovery IS NULL THEN
        IF operation.phase NOT IN ('requested', 'discovering') THEN
            RAISE EXCEPTION
                'deployment teardown resource was inserted outside discovery'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM jsonb_array_elements(
            CASE
                WHEN jsonb_typeof(
                    operation.resource_discovery -> 'resources'
                ) = 'array'
                THEN operation.resource_discovery -> 'resources'
                ELSE '[]'::JSONB
            END
        ) AS witness(value)
        WHERE witness.value ->> 'api_version' = NEW.api_version
          AND witness.value ->> 'kind' = NEW.kind
          AND witness.value ->> 'name' = NEW.name
          AND witness.value ->> 'namespace' = NEW.namespace
          AND witness.value ->> 'uid' = NEW.uid
          AND (witness.value ->> 'owner_api_version') IS NOT DISTINCT FROM
              NEW.owner_api_version
          AND (witness.value ->> 'owner_kind') IS NOT DISTINCT FROM NEW.owner_kind
          AND (witness.value ->> 'owner_name') IS NOT DISTINCT FROM NEW.owner_name
          AND (witness.value ->> 'owner_uid') IS NOT DISTINCT FROM NEW.owner_uid
          AND (witness.value ->> 'node_name') IS NOT DISTINCT FROM NEW.node_name
          AND witness.value ->> 'labels_sha256' = NEW.labels_sha256
    ) INTO witnessed;
    IF NOT witnessed AND NOT (
        operation.phase IN ('discovering', 'deleting')
        AND operation.retry_lease_owner IS NOT NULL
        AND operation.retry_lease_expires_at > CURRENT_TIMESTAMP
    ) THEN
        RAISE EXCEPTION
            'post-discovery teardown resource insertion lacks a durable lease fence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS deployment_teardown_resource_history_guard
    ON deployment_teardown_k8s_resources;
CREATE CONSTRAINT TRIGGER deployment_teardown_resource_history_guard
    AFTER INSERT OR UPDATE OR DELETE ON deployment_teardown_k8s_resources
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION protect_deployment_teardown_resource_history();

CREATE OR REPLACE FUNCTION require_finished_deployment_teardown()
RETURNS TRIGGER AS $$
BEGIN
    IF NOT deployment_teardown_closure_complete(
        OLD.deployment_id,
        OLD.teardown_operation_id
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
        WHERE deployment.deployment_id = OLD.deployment_id
          AND deployment_teardown_closure_complete(
              deployment.deployment_id,
              deployment.teardown_operation_id
          )
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
    ADD COLUMN IF NOT EXISTS owner_api_version TEXT,
    ADD COLUMN IF NOT EXISTS pod_termination_evidence JSONB,
    ADD COLUMN IF NOT EXISTS pod_termination_evidence_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS pod_teardown_finalizer_attached_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS pod_teardown_finalizer_removal_requested_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS pod_teardown_finalizer_removed_at TIMESTAMPTZ;
UPDATE kubernetes_orphan_tombstone_resources
SET owner_api_version = CASE
    WHEN owner_kind = 'Job' THEN 'batch/v1'
    WHEN owner_kind IN ('Deployment', 'ReplicaSet') THEN 'apps/v1'
    ELSE owner_api_version
END
WHERE owner_kind IS NOT NULL
  AND owner_api_version IS NULL;
ALTER TABLE kubernetes_orphan_tombstone_resources
    DROP CONSTRAINT IF EXISTS ck_kubernetes_orphan_resource_owner,
    DROP CONSTRAINT IF EXISTS ck_kubernetes_orphan_resource_pod_termination,
    DROP CONSTRAINT IF EXISTS ck_kubernetes_orphan_resource_pod_termination_sha256;
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
    ),
    ADD CONSTRAINT ck_kubernetes_orphan_resource_pod_termination CHECK (
        ((pod_termination_evidence IS NULL) =
            (pod_termination_evidence_sha256 IS NULL))
        AND ((pod_termination_evidence IS NULL) =
            (pod_teardown_finalizer_removal_requested_at IS NULL))
        AND (kind = 'Pod' OR pod_termination_evidence IS NULL)
        AND (
            kind = 'Pod'
            OR (
                pod_teardown_finalizer_attached_at IS NULL
                AND pod_teardown_finalizer_removal_requested_at IS NULL
                AND pod_teardown_finalizer_removed_at IS NULL
            )
        )
        AND (
            pod_teardown_finalizer_removal_requested_at IS NULL
            OR pod_teardown_finalizer_attached_at IS NOT NULL
        )
        AND (
            pod_teardown_finalizer_removed_at IS NULL
            OR pod_teardown_finalizer_removal_requested_at IS NOT NULL
        )
        AND (
            kind <> 'Pod'
            OR state <> 'absent'
            OR (
                pod_termination_evidence IS NOT NULL
                AND pod_teardown_finalizer_removed_at IS NOT NULL
            )
        )
    ),
    ADD CONSTRAINT ck_kubernetes_orphan_resource_pod_termination_sha256 CHECK (
        pod_termination_evidence_sha256 IS NULL
        OR pod_termination_evidence_sha256 ~ '^[0-9a-f]{64}$'
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
    IF EXISTS (
        SELECT 1
        FROM deployment_teardown_operations
        WHERE resource_discovery IS NOT NULL
           OR resource_discovery_sha256 IS NOT NULL
           OR resource_discovered_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'cannot remove miner lifecycle follow-up schema while resource discovery history exists';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM deployment_teardown_operations
        WHERE launch_operation_id IS NOT NULL
           OR launch_phase_at_request IS NOT NULL
           OR launch_kubernetes_mutation_possible IS NOT NULL
           OR launch_create_results_sha256 IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'cannot remove miner lifecycle follow-up schema while teardown launch snapshots exist';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM deployment_teardown_k8s_resources
        WHERE pod_termination_evidence IS NOT NULL
           OR pod_termination_evidence_sha256 IS NOT NULL
           OR pod_teardown_finalizer_attached_at IS NOT NULL
           OR pod_teardown_finalizer_removal_requested_at IS NOT NULL
           OR pod_teardown_finalizer_removed_at IS NOT NULL
    ) OR EXISTS (
        SELECT 1
        FROM kubernetes_orphan_tombstone_resources
        WHERE pod_termination_evidence IS NOT NULL
           OR pod_termination_evidence_sha256 IS NOT NULL
           OR pod_teardown_finalizer_attached_at IS NOT NULL
           OR pod_teardown_finalizer_removal_requested_at IS NOT NULL
           OR pod_teardown_finalizer_removed_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'cannot remove miner lifecycle follow-up schema while pod termination evidence exists';
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

DROP TRIGGER IF EXISTS deployment_teardown_resource_history_guard
    ON deployment_teardown_k8s_resources;
DROP TRIGGER IF EXISTS deployment_teardown_discovery_write_once
    ON deployment_teardown_operations;
DROP FUNCTION IF EXISTS protect_deployment_teardown_resource_history();
DROP FUNCTION IF EXISTS protect_deployment_teardown_discovery();
DROP FUNCTION IF EXISTS deployment_teardown_closure_complete(TEXT, TEXT);
DROP FUNCTION IF EXISTS deployment_teardown_resource_chain_closed(TEXT, TEXT);
DROP FUNCTION IF EXISTS canonical_miner_teardown_jsonb(JSONB);

ALTER TABLE deployment_teardown_operations
    DROP CONSTRAINT IF EXISTS ck_deployment_teardown_job_ack,
    DROP CONSTRAINT IF EXISTS ck_deployment_teardown_resource_discovery,
    DROP CONSTRAINT IF EXISTS ck_deployment_teardown_launch_snapshot,
    DROP CONSTRAINT IF EXISTS deployment_teardown_operations_launch_operation_id_fkey,
    DROP COLUMN IF EXISTS validator_job_released_at,
    DROP COLUMN IF EXISTS validator_job_release_ack,
    DROP COLUMN IF EXISTS resource_discovered_at,
    DROP COLUMN IF EXISTS resource_discovery_sha256,
    DROP COLUMN IF EXISTS resource_discovery,
    DROP COLUMN IF EXISTS launch_create_results_sha256,
    DROP COLUMN IF EXISTS launch_kubernetes_mutation_possible,
    DROP COLUMN IF EXISTS launch_phase_at_request,
    DROP COLUMN IF EXISTS launch_operation_id;

ALTER TABLE kubernetes_orphan_tombstone_resources
    DROP CONSTRAINT IF EXISTS ck_kubernetes_orphan_resource_owner,
    DROP CONSTRAINT IF EXISTS ck_kubernetes_orphan_resource_pod_termination,
    DROP CONSTRAINT IF EXISTS ck_kubernetes_orphan_resource_pod_termination_sha256;
ALTER TABLE kubernetes_orphan_tombstone_resources
    ADD CONSTRAINT ck_kubernetes_orphan_resource_owner CHECK (
        (owner_kind IS NULL AND owner_name IS NULL AND owner_uid IS NULL) OR
        (owner_kind IS NOT NULL AND owner_name IS NOT NULL AND owner_uid IS NOT NULL)
    );
ALTER TABLE kubernetes_orphan_tombstone_resources
    DROP COLUMN IF EXISTS pod_teardown_finalizer_removed_at,
    DROP COLUMN IF EXISTS pod_teardown_finalizer_removal_requested_at,
    DROP COLUMN IF EXISTS pod_teardown_finalizer_attached_at,
    DROP COLUMN IF EXISTS pod_termination_evidence_sha256,
    DROP COLUMN IF EXISTS pod_termination_evidence,
    DROP COLUMN IF EXISTS owner_api_version;

ALTER TABLE deployment_teardown_k8s_resources
    DROP CONSTRAINT IF EXISTS ck_deployment_teardown_resource_owner,
    DROP CONSTRAINT IF EXISTS ck_deployment_teardown_resource_pod_termination,
    DROP CONSTRAINT IF EXISTS ck_deployment_teardown_resource_pod_termination_sha256;
ALTER TABLE deployment_teardown_k8s_resources
    ADD CONSTRAINT ck_deployment_teardown_resource_owner CHECK (
        (owner_kind IS NULL AND owner_name IS NULL AND owner_uid IS NULL) OR
        (owner_kind IS NOT NULL AND owner_name IS NOT NULL AND owner_uid IS NOT NULL)
    );
ALTER TABLE deployment_teardown_k8s_resources
    DROP COLUMN IF EXISTS pod_teardown_finalizer_removed_at,
    DROP COLUMN IF EXISTS pod_teardown_finalizer_removal_requested_at,
    DROP COLUMN IF EXISTS pod_teardown_finalizer_attached_at,
    DROP COLUMN IF EXISTS pod_termination_evidence_sha256,
    DROP COLUMN IF EXISTS pod_termination_evidence,
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

-- Metadata-created validation schemas can already contain this later migration's
-- table. Remove only its exact dependency; never cascade away registry history.
ALTER TABLE IF EXISTS registry_scope_intents
    DROP CONSTRAINT IF EXISTS registry_scope_intents_launch_intent_id_fkey;

DROP TABLE IF EXISTS miner_launch_intents;
