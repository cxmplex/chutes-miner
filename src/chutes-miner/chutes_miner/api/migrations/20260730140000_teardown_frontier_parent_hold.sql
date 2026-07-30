-- migrate:up

LOCK TABLE deployment_teardown_operations,
    deployment_teardown_k8s_resources,
    deployment_launch_operations,
    parent_deletion_operations,
    servers,
    gpus IN ACCESS EXCLUSIVE MODE;

ALTER TABLE deployment_teardown_operations
    ADD COLUMN launch_frontier JSONB,
    ADD COLUMN launch_frontier_sha256 VARCHAR(64),
    ADD COLUMN pod_lifecycle_evidence JSONB,
    ADD COLUMN pod_lifecycle_evidence_sha256 VARCHAR(64),
    ADD COLUMN pod_lifecycle_evidence_recorded_at TIMESTAMPTZ;

WITH frontiers AS (
    SELECT
        op.operation_id,
        jsonb_build_object(
            'schema', 'chutes.miner-launch-frontier.v1',
            'operation_id', launch.operation_id,
            'deployment_id', launch.deployment_id,
            'phase', op.launch_phase_at_request,
            'cluster_context', launch.cluster_context,
            'canonical_workload_spec_sha256', launch.canonical_workload_spec_sha256,
            'service', jsonb_build_object(
                'name', launch.service_name,
                'uid', launch.service_uid
            ),
            'secret', jsonb_build_object(
                'name', launch.secret_name,
                'uid', launch.secret_uid
            ),
            'job', jsonb_build_object(
                'name', launch.job_name,
                'uid', launch.job_uid
            ),
            'create_results', launch.create_results,
            'create_results_sha256', encode(
                sha256(
                    convert_to(
                        canonical_miner_teardown_jsonb(launch.create_results),
                        'UTF8'
                    )
                ),
                'hex'
            )
        ) AS frontier
    FROM deployment_teardown_operations op
    JOIN deployment_launch_operations launch
      ON launch.operation_id = op.launch_operation_id
     AND launch.deployment_id = op.deployment_id
)
UPDATE deployment_teardown_operations op
SET
    launch_frontier = frontiers.frontier,
    launch_frontier_sha256 = encode(
        sha256(
            convert_to(
                canonical_miner_teardown_jsonb(frontiers.frontier),
                'UTF8'
            )
        ),
        'hex'
    )
FROM frontiers
WHERE frontiers.operation_id = op.operation_id;

ALTER TABLE deployment_teardown_operations
    DROP CONSTRAINT ck_deployment_teardown_launch_snapshot,
    DROP CONSTRAINT ck_deployment_teardown_phase,
    ADD CONSTRAINT ck_deployment_teardown_phase CHECK (
        phase IN (
            'requested', 'discovering', 'revoking', 'deleting', 'verifying',
            'awaiting_registry', 'finalizing', 'completed'
        )
    ),
    ADD CONSTRAINT ck_deployment_teardown_launch_snapshot CHECK (
        (
            launch_operation_id IS NULL
            AND launch_phase_at_request IS NULL
            AND launch_kubernetes_mutation_possible IS NULL
            AND launch_create_results_sha256 IS NULL
            AND launch_frontier IS NULL
            AND launch_frontier_sha256 IS NULL
        ) OR (
            launch_operation_id IS NOT NULL
            AND launch_phase_at_request IN ('reserved', 'creating', 'created', 'failed')
            AND launch_kubernetes_mutation_possible =
                (launch_phase_at_request <> 'reserved')
            AND launch_create_results_sha256 ~ '^[0-9a-f]{64}$'
            AND launch_frontier IS NOT NULL
            AND launch_frontier_sha256 ~ '^[0-9a-f]{64}$'
        )
    ),
    ADD CONSTRAINT ck_deployment_teardown_pod_lifecycle_evidence CHECK (
        (
            pod_lifecycle_evidence IS NULL
            AND pod_lifecycle_evidence_sha256 IS NULL
            AND pod_lifecycle_evidence_recorded_at IS NULL
        ) OR (
            pod_lifecycle_evidence IS NOT NULL
            AND pod_lifecycle_evidence_sha256 ~ '^[0-9a-f]{64}$'
            AND pod_lifecycle_evidence_recorded_at IS NOT NULL
        )
    );

ALTER TABLE deployment_teardown_k8s_resources
    ADD COLUMN pod_uid_absence_evidence JSONB,
    ADD COLUMN pod_uid_absence_evidence_sha256 VARCHAR(64),
    ADD COLUMN pod_uid_absence_observed_at TIMESTAMPTZ,
    ADD COLUMN pod_already_terminating BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE deployment_teardown_k8s_resources
    DROP CONSTRAINT ck_deployment_teardown_resource_pod_termination,
    ADD CONSTRAINT ck_deployment_teardown_resource_pod_termination CHECK (
        ((pod_termination_evidence IS NULL) =
            (pod_termination_evidence_sha256 IS NULL))
        AND ((pod_termination_evidence IS NULL) =
            (pod_teardown_finalizer_removal_requested_at IS NULL))
        AND ((pod_uid_absence_evidence IS NULL) =
            (pod_uid_absence_evidence_sha256 IS NULL))
        AND ((pod_uid_absence_evidence IS NULL) =
            (pod_uid_absence_observed_at IS NULL))
        AND NOT (
            pod_termination_evidence IS NOT NULL
            AND pod_uid_absence_evidence IS NOT NULL
        )
        AND (kind = 'Pod' OR pod_termination_evidence IS NULL)
        AND (kind = 'Pod' OR pod_uid_absence_evidence IS NULL)
        AND (kind = 'Pod' OR pod_already_terminating IS FALSE)
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
            OR pod_uid_absence_evidence IS NOT NULL
        )
    ),
    ADD CONSTRAINT ck_deployment_teardown_resource_pod_uid_absence_sha256 CHECK (
        pod_uid_absence_evidence_sha256 IS NULL
        OR pod_uid_absence_evidence_sha256 ~ '^[0-9a-f]{64}$'
    );

ALTER TABLE parent_deletion_operations
    ADD COLUMN allocation_release_evidence JSONB,
    ADD COLUMN allocation_release_evidence_sha256 VARCHAR(64),
    ADD COLUMN allocation_release_verified_at TIMESTAMPTZ,
    ADD CONSTRAINT ck_parent_deletion_allocation_release CHECK (
        (
            allocation_release_evidence IS NULL
            AND allocation_release_evidence_sha256 IS NULL
            AND allocation_release_verified_at IS NULL
        ) OR (
            parent_type = 'server'
            AND allocation_release_evidence IS NOT NULL
            AND allocation_release_evidence_sha256 ~ '^[0-9a-f]{64}$'
            AND allocation_release_verified_at IS NOT NULL
        )
    );

UPDATE parent_deletion_operations op
SET snapshot = op.snapshot || jsonb_build_object(
    'allocation_group_id', server.gpu_allocation_group_id,
    'allocation_group_generation', server.gpu_allocation_group_generation
)
FROM servers server
WHERE op.parent_type = 'server'
  AND server.server_id = op.parent_id;

CREATE OR REPLACE FUNCTION deployment_teardown_launch_frontier_complete(
    expected_deployment_id TEXT,
    expected_operation_id TEXT
)
RETURNS BOOLEAN AS $$
    SELECT EXISTS (
        SELECT 1
        FROM deployment_teardown_operations op
        WHERE op.deployment_id = expected_deployment_id
          AND op.operation_id = expected_operation_id
          AND (
              (
                  op.launch_operation_id IS NULL
                  AND op.launch_frontier IS NULL
                  AND op.launch_frontier_sha256 IS NULL
              ) OR (
                  op.launch_operation_id IS NOT NULL
                  AND jsonb_typeof(op.launch_frontier) = 'object'
                  AND op.launch_frontier = jsonb_build_object(
                      'schema', op.launch_frontier -> 'schema',
                      'operation_id', op.launch_frontier -> 'operation_id',
                      'deployment_id', op.launch_frontier -> 'deployment_id',
                      'phase', op.launch_frontier -> 'phase',
                      'cluster_context', op.launch_frontier -> 'cluster_context',
                      'canonical_workload_spec_sha256',
                          op.launch_frontier -> 'canonical_workload_spec_sha256',
                      'service', op.launch_frontier -> 'service',
                      'secret', op.launch_frontier -> 'secret',
                      'job', op.launch_frontier -> 'job',
                      'create_results', op.launch_frontier -> 'create_results',
                      'create_results_sha256',
                          op.launch_frontier -> 'create_results_sha256'
                  )
                  AND op.launch_frontier ->> 'schema' =
                      'chutes.miner-launch-frontier.v1'
                  AND op.launch_frontier ->> 'operation_id' = op.launch_operation_id
                  AND op.launch_frontier ->> 'deployment_id' = op.deployment_id
                  AND op.launch_frontier ->> 'phase' = op.launch_phase_at_request
                  AND op.launch_frontier ->> 'cluster_context' = op.cluster_context
                  AND jsonb_typeof(op.launch_frontier -> 'create_results') = 'object'
                  AND jsonb_typeof(op.launch_frontier -> 'service') = 'object'
                  AND jsonb_typeof(op.launch_frontier -> 'secret') = 'object'
                  AND jsonb_typeof(op.launch_frontier -> 'job') = 'object'
                  AND (op.launch_frontier ->> 'create_results_sha256') =
                      op.launch_create_results_sha256
                  AND op.launch_frontier ->> 'create_results_sha256' = encode(
                      sha256(
                          convert_to(
                              canonical_miner_teardown_jsonb(
                                  op.launch_frontier -> 'create_results'
                              ),
                              'UTF8'
                          )
                      ),
                      'hex'
                  )
                  AND op.launch_frontier_sha256 = encode(
                      sha256(
                          convert_to(
                              canonical_miner_teardown_jsonb(op.launch_frontier),
                              'UTF8'
                          )
                      ),
                      'hex'
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM deployment_launch_operations launch
                      WHERE launch.operation_id = op.launch_operation_id
                        AND launch.deployment_id = op.deployment_id
                        AND launch.phase = 'teardown_fenced'
                        AND (
                            op.launch_frontier ->>
                                'canonical_workload_spec_sha256'
                        ) IS NOT DISTINCT FROM launch.canonical_workload_spec_sha256
                        AND op.launch_frontier -> 'create_results' =
                            launch.create_results
                        AND op.launch_frontier -> 'service' = jsonb_build_object(
                            'name', launch.service_name,
                            'uid', launch.service_uid
                        )
                        AND op.launch_frontier -> 'secret' = jsonb_build_object(
                            'name', launch.secret_name,
                            'uid', launch.secret_uid
                        )
                        AND op.launch_frontier -> 'job' = jsonb_build_object(
                            'name', launch.job_name,
                            'uid', launch.job_uid
                        )
                  )
              )
          )
    );
$$ LANGUAGE SQL STABLE;

CREATE OR REPLACE FUNCTION deployment_teardown_pod_any_closed(
    expected_resource_id TEXT,
    expected_operation_id TEXT,
    expected_discovery_sha256 TEXT
)
RETURNS BOOLEAN AS $$
    SELECT EXISTS (
        SELECT 1
        FROM deployment_teardown_k8s_resources resource
        WHERE resource.resource_id = expected_resource_id
          AND resource.operation_id = expected_operation_id
          AND resource.kind = 'Pod'
          AND (
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
          )
          AND (
              (
                  resource.pod_uid_absence_observed_at IS NOT NULL
                  AND jsonb_typeof(resource.pod_uid_absence_evidence) = 'object'
                  AND resource.pod_uid_absence_evidence = jsonb_build_object(
                      'schema', resource.pod_uid_absence_evidence -> 'schema',
                      'outcome', resource.pod_uid_absence_evidence -> 'outcome',
                      'operation_id',
                          resource.pod_uid_absence_evidence -> 'operation_id',
                      'pod_uid', resource.pod_uid_absence_evidence -> 'pod_uid',
                      'node_name', resource.pod_uid_absence_evidence -> 'node_name',
                      'resource_discovery_sha256',
                          resource.pod_uid_absence_evidence ->
                              'resource_discovery_sha256',
                      'read_status',
                          resource.pod_uid_absence_evidence -> 'read_status',
                      'selector_absent',
                          resource.pod_uid_absence_evidence -> 'selector_absent'
                  )
                  AND resource.pod_uid_absence_evidence ->> 'schema' =
                      'chutes.miner-pod-uid-absence.v1'
                  AND resource.pod_uid_absence_evidence ->> 'outcome' = 'uid_absent'
                  AND resource.pod_uid_absence_evidence ->> 'operation_id' =
                      resource.operation_id
                  AND resource.pod_uid_absence_evidence ->> 'pod_uid' = resource.uid
                  AND (resource.pod_uid_absence_evidence ->> 'node_name')
                      IS NOT DISTINCT FROM resource.node_name
                  AND resource.pod_uid_absence_evidence ->>
                      'resource_discovery_sha256' = expected_discovery_sha256
                  AND resource.pod_uid_absence_evidence -> 'read_status' = '404'::JSONB
                  AND resource.pod_uid_absence_evidence -> 'selector_absent' =
                      'true'::JSONB
                  AND resource.pod_uid_absence_evidence_sha256 = encode(
                      sha256(
                          convert_to(
                              canonical_miner_teardown_jsonb(
                                  resource.pod_uid_absence_evidence
                              ),
                              'UTF8'
                          )
                      ),
                      'hex'
                  )
              ) OR (
                  resource.pod_teardown_finalizer_attached_at IS NOT NULL
                  AND resource.pod_teardown_finalizer_removal_requested_at >=
                      resource.pod_teardown_finalizer_attached_at
                  AND resource.pod_teardown_finalizer_removed_at >=
                      resource.pod_teardown_finalizer_removal_requested_at
                  AND jsonb_typeof(resource.pod_termination_evidence) = 'object'
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
                  AND resource.pod_termination_evidence ->> 'pod_uid' = resource.uid
                  AND resource.pod_termination_evidence ->> 'node_name' =
                      resource.node_name
                  AND resource.pod_termination_evidence ->> 'teardown_finalizer' =
                      'chutes.ai/gpu-teardown-v1'
                  AND COALESCE(
                      resource.pod_termination_evidence ->> 'deletion_timestamp',
                      ''
                  ) <> ''
                  AND jsonb_typeof(
                      resource.pod_termination_evidence -> 'containers'
                  ) = 'array'
                  AND jsonb_array_length(
                      resource.pod_termination_evidence -> 'containers'
                  ) > 0
                  AND (
                      (
                          resource.pod_termination_evidence ->> 'schema' =
                              'chutes.miner-pod-termination.v1'
                          AND resource.pod_termination_evidence = jsonb_build_object(
                              'schema',
                                  resource.pod_termination_evidence -> 'schema',
                              'pod_uid',
                                  resource.pod_termination_evidence -> 'pod_uid',
                              'node_name',
                                  resource.pod_termination_evidence -> 'node_name',
                              'teardown_finalizer',
                                  resource.pod_termination_evidence ->
                                      'teardown_finalizer',
                              'deletion_timestamp',
                                  resource.pod_termination_evidence ->
                                      'deletion_timestamp',
                              'containers',
                                  resource.pod_termination_evidence -> 'containers'
                          )
                          AND NOT EXISTS (
                              SELECT 1
                              FROM jsonb_array_elements(
                                  resource.pod_termination_evidence -> 'containers'
                              ) container(value)
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
                                      container.value ->> 'container_id', ''
                                  ) <> ''
                                  AND COALESCE(
                                      container.value ->> 'finished_at', ''
                                  ) <> ''
                              ) IS NOT TRUE
                          )
                      ) OR (
                          resource.pod_termination_evidence ->> 'schema' =
                              'chutes.miner-pod-termination.v2'
                          AND resource.pod_termination_evidence = jsonb_build_object(
                              'schema',
                                  resource.pod_termination_evidence -> 'schema',
                              'outcome',
                                  resource.pod_termination_evidence -> 'outcome',
                              'pod_phase',
                                  resource.pod_termination_evidence -> 'pod_phase',
                              'pod_uid',
                                  resource.pod_termination_evidence -> 'pod_uid',
                              'node_name',
                                  resource.pod_termination_evidence -> 'node_name',
                              'teardown_finalizer',
                                  resource.pod_termination_evidence ->
                                      'teardown_finalizer',
                              'deletion_timestamp',
                                  resource.pod_termination_evidence ->
                                      'deletion_timestamp',
                              'termination_origin',
                                  resource.pod_termination_evidence ->
                                      'termination_origin',
                              'containers',
                                  resource.pod_termination_evidence -> 'containers'
                          )
                          AND resource.pod_termination_evidence ->> 'outcome' IN (
                              'never_started', 'mixed_terminal'
                          )
                          AND resource.pod_termination_evidence ->> 'pod_phase' =
                              'Pending'
                          AND resource.pod_termination_evidence ->>
                              'termination_origin' = CASE
                                  WHEN resource.pod_already_terminating
                                  THEN 'already_terminating'
                                  ELSE 'teardown'
                              END
                          AND NOT EXISTS (
                              SELECT 1
                              FROM jsonb_array_elements(
                                  resource.pod_termination_evidence -> 'containers'
                              ) container(value)
                              WHERE (
                                  jsonb_typeof(container.value) = 'object'
                                  AND (
                                      (
                                          container.value ->> 'outcome' = 'terminated'
                                          AND container.value = jsonb_build_object(
                                              'group', container.value -> 'group',
                                              'name', container.value -> 'name',
                                              'outcome', container.value -> 'outcome',
                                              'container_id',
                                                  container.value -> 'container_id',
                                              'exit_code',
                                                  container.value -> 'exit_code',
                                              'signal', container.value -> 'signal',
                                              'reason', container.value -> 'reason',
                                              'started_at',
                                                  container.value -> 'started_at',
                                              'finished_at',
                                                  container.value -> 'finished_at'
                                          )
                                          AND COALESCE(
                                              container.value ->> 'container_id', ''
                                          ) <> ''
                                          AND COALESCE(
                                              container.value ->> 'finished_at', ''
                                          ) <> ''
                                      ) OR (
                                          container.value ->> 'outcome' =
                                              'never_started'
                                          AND container.value = jsonb_build_object(
                                              'group', container.value -> 'group',
                                              'name', container.value -> 'name',
                                              'outcome', container.value -> 'outcome',
                                              'waiting_reason',
                                                  container.value -> 'waiting_reason',
                                              'restart_count',
                                                  container.value -> 'restart_count'
                                          )
                                          AND COALESCE(
                                              container.value ->> 'waiting_reason', ''
                                          ) <> ''
                                          AND container.value -> 'restart_count' =
                                              '0'::JSONB
                                      )
                                  )
                                  AND container.value ->> 'group' IN (
                                      'init', 'container', 'ephemeral'
                                  )
                                  AND COALESCE(container.value ->> 'name', '') <> ''
                              ) IS NOT TRUE
                          )
                          AND (
                              (
                                  resource.pod_termination_evidence ->> 'outcome' =
                                      'never_started'
                                  AND NOT EXISTS (
                                      SELECT 1
                                      FROM jsonb_array_elements(
                                          resource.pod_termination_evidence ->
                                              'containers'
                                      ) container(value)
                                      WHERE container.value ->> 'outcome' <>
                                          'never_started'
                                  )
                              ) OR (
                                  resource.pod_termination_evidence ->> 'outcome' =
                                      'mixed_terminal'
                                  AND EXISTS (
                                      SELECT 1
                                      FROM jsonb_array_elements(
                                          resource.pod_termination_evidence ->
                                              'containers'
                                      ) container(value)
                                      WHERE container.value ->> 'outcome' = 'terminated'
                                  )
                                  AND EXISTS (
                                      SELECT 1
                                      FROM jsonb_array_elements(
                                          resource.pod_termination_evidence ->
                                              'containers'
                                      ) container(value)
                                      WHERE container.value ->> 'outcome' =
                                          'never_started'
                                  )
                              )
                          )
                      )
                  )
              )
          )
    );
$$ LANGUAGE SQL STABLE;

CREATE OR REPLACE FUNCTION deployment_teardown_extended_closure_complete(
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
                  op.resource_discovery -> 'launch_kubernetes_mutation_possible',
              'launch_create_results_sha256',
                  op.resource_discovery -> 'launch_create_results_sha256',
              'resources', op.resource_discovery -> 'resources'
          )
          AND op.resource_discovery ->> 'schema' =
              'chutes.miner-k8s-resource-discovery.v1'
          AND op.resource_discovery_sha256 = encode(
              sha256(
                  convert_to(
                      canonical_miner_teardown_jsonb(op.resource_discovery),
                      'UTF8'
                  )
              ),
              'hex'
          )
          AND op.resource_discovery ->> 'operation_id' = op.operation_id
          AND op.resource_discovery ->> 'deployment_id' = op.deployment_id
          AND op.resource_discovery ->> 'cluster_context' = op.cluster_context
          AND op.resource_discovery ->> 'cluster_context_sha256' =
              op.cluster_context_sha256
          AND op.resource_discovery ->> 'namespace' = op.namespace
          AND (op.resource_discovery ->> 'config_id')
              IS NOT DISTINCT FROM op.config_id
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
          AND jsonb_typeof(op.resource_discovery -> 'resources') = 'array'
          AND jsonb_array_length(op.resource_discovery -> 'resources') = (
              SELECT count(*)
              FROM deployment_teardown_k8s_resources resource
              WHERE resource.operation_id = op.operation_id
          )
          AND jsonb_array_length(op.resource_discovery -> 'resources') = (
              SELECT count(DISTINCT (
                  witness.value ->> 'kind',
                  witness.value ->> 'uid'
              ))
              FROM jsonb_array_elements(
                  op.resource_discovery -> 'resources'
              ) witness(value)
          )
          AND NOT EXISTS (
              SELECT 1
              FROM jsonb_array_elements(
                  op.resource_discovery -> 'resources'
              ) witness(value)
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
                      FROM deployment_teardown_k8s_resources resource
                      WHERE resource.operation_id = op.operation_id
                        AND resource.api_version =
                            witness.value ->> 'api_version'
                        AND resource.kind = witness.value ->> 'kind'
                        AND resource.name = witness.value ->> 'name'
                        AND resource.namespace = witness.value ->> 'namespace'
                        AND resource.uid = witness.value ->> 'uid'
                        AND resource.owner_api_version IS NOT DISTINCT FROM
                            witness.value ->> 'owner_api_version'
                        AND resource.owner_kind IS NOT DISTINCT FROM
                            witness.value ->> 'owner_kind'
                        AND resource.owner_name IS NOT DISTINCT FROM
                            witness.value ->> 'owner_name'
                        AND resource.owner_uid IS NOT DISTINCT FROM
                            witness.value ->> 'owner_uid'
                        AND resource.node_name IS NOT DISTINCT FROM
                            witness.value ->> 'node_name'
                        AND resource.labels_sha256 =
                            witness.value ->> 'labels_sha256'
                        AND resource.labels_sha256 = encode(
                            sha256(
                                convert_to(
                                    canonical_miner_teardown_jsonb(resource.labels),
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
                    OR (
                        resource.kind = 'Pod'
                        AND NOT deployment_teardown_pod_any_closed(
                            resource.resource_id,
                            resource.operation_id,
                            op.resource_discovery_sha256
                        )
                    )
                    OR (
                        resource.kind <> 'Pod'
                        AND NOT (
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
                        )
                    )
                )
          )
          AND (
              jsonb_array_length(op.gpu_hardware_uuids) = 0
              OR EXISTS (
                  SELECT 1
                  FROM deployment_teardown_k8s_resources pod
                  WHERE pod.operation_id = op.operation_id
                    AND pod.kind = 'Pod'
              )
              OR (
                  jsonb_typeof(op.pod_lifecycle_evidence) = 'object'
                  AND op.pod_lifecycle_evidence = jsonb_build_object(
                      'schema', op.pod_lifecycle_evidence -> 'schema',
                      'outcome', op.pod_lifecycle_evidence -> 'outcome',
                      'operation_id',
                          op.pod_lifecycle_evidence -> 'operation_id',
                      'deployment_id',
                          op.pod_lifecycle_evidence -> 'deployment_id',
                      'launch_frontier_sha256',
                          op.pod_lifecycle_evidence -> 'launch_frontier_sha256',
                      'resource_discovery_sha256',
                          op.pod_lifecycle_evidence -> 'resource_discovery_sha256',
                      'job_uid', op.pod_lifecycle_evidence -> 'job_uid',
                      'controllers_absent',
                          op.pod_lifecycle_evidence -> 'controllers_absent',
                      'selector_absent',
                          op.pod_lifecycle_evidence -> 'selector_absent'
                  )
                  AND op.pod_lifecycle_evidence ->> 'schema' =
                      'chutes.miner-pod-lifecycle.v1'
                  AND op.pod_lifecycle_evidence ->> 'operation_id' = op.operation_id
                  AND op.pod_lifecycle_evidence ->> 'deployment_id' = op.deployment_id
                  AND op.pod_lifecycle_evidence ->> 'launch_frontier_sha256' =
                      op.launch_frontier_sha256
                  AND op.pod_lifecycle_evidence ->> 'resource_discovery_sha256' =
                      op.resource_discovery_sha256
                  AND op.pod_lifecycle_evidence -> 'controllers_absent' = 'true'::JSONB
                  AND op.pod_lifecycle_evidence -> 'selector_absent' = 'true'::JSONB
                  AND (
                      (
                          op.pod_lifecycle_evidence ->> 'outcome' = 'never_started'
                          AND op.launch_frontier -> 'job' -> 'uid' = 'null'::JSONB
                          AND op.pod_lifecycle_evidence -> 'job_uid' = 'null'::JSONB
                      ) OR (
                          op.pod_lifecycle_evidence ->> 'outcome' = 'no_pod_observed'
                          AND op.launch_frontier -> 'job' -> 'uid' <> 'null'::JSONB
                          AND op.pod_lifecycle_evidence -> 'job_uid' =
                              op.launch_frontier -> 'job' -> 'uid'
                      )
                  )
                  AND op.pod_lifecycle_evidence_sha256 = encode(
                      sha256(
                          convert_to(
                              canonical_miner_teardown_jsonb(
                                  op.pod_lifecycle_evidence
                              ),
                              'UTF8'
                          )
                      ),
                      'hex'
                  )
              )
          )
    );
$$ LANGUAGE SQL STABLE;

CREATE OR REPLACE FUNCTION require_finished_deployment_teardown()
RETURNS TRIGGER AS $$
BEGIN
    IF NOT deployment_teardown_launch_frontier_complete(
        OLD.deployment_id,
        OLD.teardown_operation_id
    ) OR NOT (
        deployment_teardown_closure_complete(
            OLD.deployment_id,
            OLD.teardown_operation_id
        ) OR deployment_teardown_extended_closure_complete(
            OLD.deployment_id,
            OLD.teardown_operation_id
        )
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
          AND deployment_teardown_launch_frontier_complete(
              deployment.deployment_id,
              deployment.teardown_operation_id
          )
          AND (
              deployment_teardown_closure_complete(
                  deployment.deployment_id,
                  deployment.teardown_operation_id
              ) OR deployment_teardown_extended_closure_complete(
                  deployment.deployment_id,
                  deployment.teardown_operation_id
              )
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

CREATE OR REPLACE FUNCTION require_finished_parent_deletion()
RETURNS TRIGGER AS $$
DECLARE
    expected_type TEXT := CASE TG_TABLE_NAME WHEN 'servers' THEN 'server' ELSE 'chute' END;
    expected_id TEXT := CASE TG_TABLE_NAME
        WHEN 'servers' THEN to_jsonb(OLD) ->> 'server_id'
        ELSE to_jsonb(OLD) ->> 'chute_id'
    END;
    old_allocation_group_id TEXT :=
        to_jsonb(OLD) ->> 'gpu_allocation_group_id';
    old_allocation_group_generation INTEGER :=
        (to_jsonb(OLD) ->> 'gpu_allocation_group_generation')::INTEGER;
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
                  AND old_allocation_group_id IS NULL
                  AND old_allocation_group_generation IS NULL
                  AND op.allocation_release_verified_at IS NOT NULL
                  AND op.allocation_release_evidence = jsonb_build_object(
                      'schema', 'chutes.miner-parent-allocation-release.v1',
                      'operation_id', op.operation_id,
                      'server_id', op.parent_id,
                      'snapshot_allocation_group_id',
                          op.snapshot -> 'allocation_group_id',
                      'snapshot_allocation_group_generation',
                          op.snapshot -> 'allocation_group_generation',
                      'server_allocation_released', TRUE,
                      'gpu_allocation_generations_owned', '[]'::JSONB
                  )
                  AND op.allocation_release_evidence_sha256 = encode(
                      sha256(
                          convert_to(
                              canonical_miner_teardown_jsonb(
                                  op.allocation_release_evidence
                              ),
                              'UTF8'
                          )
                      ),
                      'hex'
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM gpus gpu
                      WHERE gpu.server_id = expected_id
                        AND (
                            gpu.gpu_allocation_group_id IS NOT NULL
                            OR gpu.gpu_allocation_group_generation IS NOT NULL
                        )
                  )
              )
          )
    ) THEN
        RAISE EXCEPTION '% % has no durable parent deletion', expected_type, expected_id
            USING ERRCODE = '23503';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fence_parent_allocation_ownership()
RETURNS TRIGGER AS $$
DECLARE
    target_server_id TEXT := NEW.server_id;
BEGIN
    IF (
        NEW.gpu_allocation_group_id IS NOT NULL
        OR NEW.gpu_allocation_group_generation IS NOT NULL
    ) AND EXISTS (
        SELECT 1
        FROM parent_deletion_operations op
        WHERE op.parent_type = 'server'
          AND op.parent_id = target_server_id
          AND op.phase <> 'completed'
    ) THEN
        RAISE EXCEPTION 'allocation ownership is fenced by parent deletion'
            USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS servers_fence_parent_allocation ON servers;
CREATE TRIGGER servers_fence_parent_allocation
    BEFORE INSERT OR UPDATE OF gpu_allocation_group_id,
        gpu_allocation_group_generation ON servers
    FOR EACH ROW EXECUTE FUNCTION fence_parent_allocation_ownership();

DROP TRIGGER IF EXISTS gpus_fence_parent_allocation ON gpus;
CREATE TRIGGER gpus_fence_parent_allocation
    BEFORE INSERT OR UPDATE OF gpu_allocation_group_id,
        gpu_allocation_group_generation ON gpus
    FOR EACH ROW EXECUTE FUNCTION fence_parent_allocation_ownership();

CREATE OR REPLACE FUNCTION protect_teardown_frontier_evidence()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_TABLE_NAME = 'deployment_teardown_operations' THEN
        IF TG_OP = 'UPDATE' AND (
            ROW(NEW.launch_frontier, NEW.launch_frontier_sha256) IS DISTINCT FROM
                ROW(OLD.launch_frontier, OLD.launch_frontier_sha256)
            OR (
                OLD.pod_lifecycle_evidence IS NOT NULL
                AND ROW(
                    NEW.pod_lifecycle_evidence,
                    NEW.pod_lifecycle_evidence_sha256,
                    NEW.pod_lifecycle_evidence_recorded_at
                ) IS DISTINCT FROM ROW(
                    OLD.pod_lifecycle_evidence,
                    OLD.pod_lifecycle_evidence_sha256,
                    OLD.pod_lifecycle_evidence_recorded_at
                )
            )
        ) THEN
            RAISE EXCEPTION 'teardown frontier/evidence is immutable'
                USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'deployment_teardown_k8s_resources' THEN
        IF TG_OP = 'UPDATE' AND (
            NEW.pod_already_terminating IS DISTINCT FROM OLD.pod_already_terminating
            OR (
                OLD.pod_uid_absence_evidence IS NOT NULL
                AND ROW(
                    NEW.pod_uid_absence_evidence,
                    NEW.pod_uid_absence_evidence_sha256,
                    NEW.pod_uid_absence_observed_at
                ) IS DISTINCT FROM ROW(
                    OLD.pod_uid_absence_evidence,
                    OLD.pod_uid_absence_evidence_sha256,
                    OLD.pod_uid_absence_observed_at
                )
            )
        ) THEN
            RAISE EXCEPTION 'Pod lifecycle observation is immutable'
                USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'parent_deletion_operations' THEN
        IF TG_OP = 'UPDATE'
           AND OLD.allocation_release_evidence IS NOT NULL
           AND ROW(
               NEW.allocation_release_evidence,
               NEW.allocation_release_evidence_sha256,
               NEW.allocation_release_verified_at
           ) IS DISTINCT FROM ROW(
               OLD.allocation_release_evidence,
               OLD.allocation_release_evidence_sha256,
               OLD.allocation_release_verified_at
           ) THEN
            RAISE EXCEPTION 'parent allocation release evidence is immutable'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER deployment_teardown_frontier_evidence_guard
    BEFORE UPDATE ON deployment_teardown_operations
    FOR EACH ROW EXECUTE FUNCTION protect_teardown_frontier_evidence();
CREATE TRIGGER deployment_teardown_pod_absence_guard
    BEFORE UPDATE ON deployment_teardown_k8s_resources
    FOR EACH ROW EXECUTE FUNCTION protect_teardown_frontier_evidence();
CREATE TRIGGER parent_deletion_allocation_evidence_guard
    BEFORE UPDATE ON parent_deletion_operations
    FOR EACH ROW EXECUTE FUNCTION protect_teardown_frontier_evidence();

-- migrate:down

LOCK TABLE deployment_teardown_operations,
    deployment_teardown_k8s_resources,
    parent_deletion_operations,
    servers,
    gpus IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM deployment_teardown_operations)
       OR EXISTS (SELECT 1 FROM parent_deletion_operations) THEN
        RAISE EXCEPTION
            'cannot remove teardown frontier authority while lifecycle history exists';
    END IF;
END
$$;

DROP TRIGGER deployment_teardown_frontier_evidence_guard
    ON deployment_teardown_operations;
DROP TRIGGER deployment_teardown_pod_absence_guard
    ON deployment_teardown_k8s_resources;
DROP TRIGGER parent_deletion_allocation_evidence_guard
    ON parent_deletion_operations;
DROP TRIGGER servers_fence_parent_allocation ON servers;
DROP TRIGGER gpus_fence_parent_allocation ON gpus;
DROP FUNCTION protect_teardown_frontier_evidence();
DROP FUNCTION fence_parent_allocation_ownership();
DROP FUNCTION deployment_teardown_extended_closure_complete(TEXT, TEXT);
DROP FUNCTION deployment_teardown_pod_any_closed(TEXT, TEXT, TEXT);
DROP FUNCTION deployment_teardown_launch_frontier_complete(TEXT, TEXT);

ALTER TABLE parent_deletion_operations
    DROP CONSTRAINT ck_parent_deletion_allocation_release,
    DROP COLUMN allocation_release_verified_at,
    DROP COLUMN allocation_release_evidence_sha256,
    DROP COLUMN allocation_release_evidence;

ALTER TABLE deployment_teardown_k8s_resources
    DROP CONSTRAINT ck_deployment_teardown_resource_pod_uid_absence_sha256,
    DROP CONSTRAINT ck_deployment_teardown_resource_pod_termination,
    DROP COLUMN pod_already_terminating,
    DROP COLUMN pod_uid_absence_observed_at,
    DROP COLUMN pod_uid_absence_evidence_sha256,
    DROP COLUMN pod_uid_absence_evidence;

ALTER TABLE deployment_teardown_k8s_resources
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
    );

ALTER TABLE deployment_teardown_operations
    DROP CONSTRAINT ck_deployment_teardown_pod_lifecycle_evidence,
    DROP CONSTRAINT ck_deployment_teardown_launch_snapshot,
    DROP CONSTRAINT ck_deployment_teardown_phase,
    DROP COLUMN pod_lifecycle_evidence_recorded_at,
    DROP COLUMN pod_lifecycle_evidence_sha256,
    DROP COLUMN pod_lifecycle_evidence,
    DROP COLUMN launch_frontier_sha256,
    DROP COLUMN launch_frontier;

ALTER TABLE deployment_teardown_operations
    ADD CONSTRAINT ck_deployment_teardown_phase CHECK (
        phase IN (
            'requested', 'discovering', 'revoking', 'deleting',
            'verifying', 'finalizing', 'completed'
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
            AND launch_phase_at_request IN ('reserved', 'creating', 'created', 'failed')
            AND launch_kubernetes_mutation_possible =
                (launch_phase_at_request <> 'reserved')
            AND launch_create_results_sha256 ~ '^[0-9a-f]{64}$'
        )
    );

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

CREATE OR REPLACE FUNCTION require_finished_parent_deletion()
RETURNS TRIGGER AS $$
DECLARE
    expected_type TEXT := CASE TG_TABLE_NAME WHEN 'servers' THEN 'server' ELSE 'chute' END;
    expected_id TEXT := CASE TG_TABLE_NAME
        WHEN 'servers' THEN to_jsonb(OLD) ->> 'server_id'
        ELSE to_jsonb(OLD) ->> 'chute_id'
    END;
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
