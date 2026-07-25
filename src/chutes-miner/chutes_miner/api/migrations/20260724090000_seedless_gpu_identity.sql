-- migrate:up
ALTER TABLE servers ADD COLUMN IF NOT EXISTS kubernetes_node_uid TEXT;
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS kubernetes_node_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE deployments DROP CONSTRAINT IF EXISTS deployments_server_id_fkey;
ALTER TABLE deployments
    ADD CONSTRAINT deployments_server_id_fkey
    FOREIGN KEY (server_id) REFERENCES servers(server_id)
    ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE gpus DROP CONSTRAINT IF EXISTS gpus_server_id_fkey;
ALTER TABLE gpus
    ADD CONSTRAINT gpus_server_id_fkey
    FOREIGN KEY (server_id) REFERENCES servers(server_id)
    ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS registration_attestation_id TEXT;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS gpu_allocation_group_id TEXT;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS gpu_allocation_group_generation INTEGER;
CREATE UNIQUE INDEX IF NOT EXISTS servers_kubernetes_node_uid_idx
    ON servers (kubernetes_node_uid) WHERE kubernetes_node_uid IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS servers_registration_attestation_id_idx
    ON servers (registration_attestation_id) WHERE registration_attestation_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS servers_gpu_allocation_group_id_idx
    ON servers (gpu_allocation_group_id) WHERE gpu_allocation_group_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS server_node_identities (
    server_id TEXT NOT NULL REFERENCES servers(server_id) ON UPDATE CASCADE ON DELETE CASCADE,
    generation INTEGER NOT NULL,
    kubernetes_node_uid TEXT NOT NULL,
    registration_attestation_id TEXT,
    adopted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at TIMESTAMPTZ,
    PRIMARY KEY (server_id, generation),
    UNIQUE (kubernetes_node_uid),
    CONSTRAINT ck_server_node_identity_generation CHECK (generation > 0)
);
INSERT INTO server_node_identities (
    server_id,
    generation,
    kubernetes_node_uid,
    registration_attestation_id
)
SELECT
    server_id,
    1,
    kubernetes_node_uid,
    registration_attestation_id
FROM servers
WHERE
    kubernetes_node_uid IS NOT NULL
ON CONFLICT DO NOTHING;
UPDATE servers
SET kubernetes_node_generation = 1
WHERE kubernetes_node_uid IS NOT NULL
  AND kubernetes_node_generation = 0;
ALTER TABLE servers DROP CONSTRAINT IF EXISTS ck_servers_kubernetes_node_generation;
ALTER TABLE servers
    ADD CONSTRAINT ck_servers_kubernetes_node_generation CHECK (
        (kubernetes_node_uid IS NULL AND kubernetes_node_generation = 0)
        OR
        (kubernetes_node_uid IS NOT NULL AND kubernetes_node_generation > 0)
    );
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS registry_repository TEXT;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS registry_manifest_digest TEXT;
ALTER TABLE gpus ADD COLUMN IF NOT EXISTS hardware_uuid TEXT;
ALTER TABLE gpus ADD COLUMN IF NOT EXISTS gpu_allocation_group_id TEXT;
ALTER TABLE gpus ADD COLUMN IF NOT EXISTS gpu_allocation_group_generation INTEGER;
UPDATE gpus
SET hardware_uuid = gpu_id
WHERE hardware_uuid IS NULL AND gpu_id LIKE 'GPU-%';
UPDATE gpus
SET
    gpu_allocation_group_id = servers.gpu_allocation_group_id,
    gpu_allocation_group_generation = servers.gpu_allocation_group_generation
FROM servers
WHERE
    gpus.server_id = servers.server_id
    AND gpus.gpu_allocation_group_id IS NULL
    AND gpus.gpu_allocation_group_generation IS NULL
    AND servers.gpu_allocation_group_id IS NOT NULL
    AND servers.gpu_allocation_group_generation > 0;
ALTER TABLE gpus DROP CONSTRAINT IF EXISTS ck_gpus_allocation_group_lineage;
ALTER TABLE gpus
    ADD CONSTRAINT ck_gpus_allocation_group_lineage CHECK (
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
    );
CREATE UNIQUE INDEX IF NOT EXISTS gpus_hardware_uuid_idx
    ON gpus (hardware_uuid) WHERE hardware_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS gpus_allocation_group_idx
    ON gpus (gpu_allocation_group_id, gpu_allocation_group_generation)
    WHERE gpu_allocation_group_id IS NOT NULL;

-- migrate:down
DROP TABLE IF EXISTS server_node_identities;
ALTER TABLE servers DROP CONSTRAINT IF EXISTS ck_servers_kubernetes_node_generation;
DROP INDEX IF EXISTS servers_gpu_allocation_group_id_idx;
DROP INDEX IF EXISTS servers_registration_attestation_id_idx;
DROP INDEX IF EXISTS servers_kubernetes_node_uid_idx;
ALTER TABLE servers DROP COLUMN IF EXISTS gpu_allocation_group_generation;
ALTER TABLE servers DROP COLUMN IF EXISTS gpu_allocation_group_id;
ALTER TABLE servers DROP COLUMN IF EXISTS registration_attestation_id;
ALTER TABLE servers DROP COLUMN IF EXISTS kubernetes_node_uid;
ALTER TABLE servers DROP COLUMN IF EXISTS kubernetes_node_generation;
ALTER TABLE deployments DROP COLUMN IF EXISTS registry_manifest_digest;
ALTER TABLE deployments DROP COLUMN IF EXISTS registry_repository;
DROP INDEX IF EXISTS gpus_allocation_group_idx;
DROP INDEX IF EXISTS gpus_hardware_uuid_idx;
ALTER TABLE gpus DROP CONSTRAINT IF EXISTS ck_gpus_allocation_group_lineage;
ALTER TABLE gpus DROP COLUMN IF EXISTS gpu_allocation_group_generation;
ALTER TABLE gpus DROP COLUMN IF EXISTS gpu_allocation_group_id;
ALTER TABLE gpus DROP COLUMN IF EXISTS hardware_uuid;
ALTER TABLE deployments DROP CONSTRAINT IF EXISTS deployments_server_id_fkey;
ALTER TABLE deployments
    ADD CONSTRAINT deployments_server_id_fkey
    FOREIGN KEY (server_id) REFERENCES servers(server_id)
    ON DELETE CASCADE;
ALTER TABLE gpus DROP CONSTRAINT IF EXISTS gpus_server_id_fkey;
ALTER TABLE gpus
    ADD CONSTRAINT gpus_server_id_fkey
    FOREIGN KEY (server_id) REFERENCES servers(server_id)
    ON DELETE CASCADE;
