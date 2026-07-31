import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from chutes_common.auth import sign_request
from chutes_common.settings import (
    GPU_REGISTRATION_IDENTITY_FIELDS,
    MinerSettings,
    SeedlessGPUConfigurationError,
    miner_settings,
)
from chutes_miner.api.config import settings
from chutes_miner.api.exceptions import UnsupportedRuntime
from chutes_miner.api.server.util import bootstrap_server
from chutes_miner.gepetto import Gepetto


def test_validator_requests_use_rotating_attested_session(monkeypatch, tmp_path):
    session = tmp_path / "session.env"
    session.write_text("CHUTES_ATTESTED_SESSION=first\n")
    monkeypatch.setattr(miner_settings, "attested_session_file", str(session))
    headers, payload = sign_request(purpose="miner")
    assert headers == {
        "X-Chutes-Hotkey": miner_settings.miner_ss58,
        "X-Chutes-Attested-Session": "first",
    }
    assert payload is None
    session.write_text("CHUTES_ATTESTED_SESSION=second\n")
    assert sign_request(purpose="miner")[0]["X-Chutes-Attested-Session"] == "second"


def test_internal_management_request_contains_public_owner_only(monkeypatch, tmp_path):
    session = Path(tmp_path) / "session.env"
    session.write_text("CHUTES_ATTESTED_SESSION=scoped\n")
    monkeypatch.setattr(miner_settings, "attested_session_file", str(session))
    headers, _ = sign_request(purpose="registration", management=True)
    assert headers == {
        "X-Chutes-Attested-Session": "scoped",
        "X-Chutes-Miner": miner_settings.miner_ss58,
        "X-Chutes-Validator": miner_settings.miner_ss58,
    }
    assert all("seed" not in key.lower() for key in headers)


def test_seedless_chart_disables_every_legacy_graval_bootstrap_path():
    root = Path(__file__).resolve().parents[2]
    for template in (
        root / "charts/chutes-miner/templates/api-deployment.yaml",
        root / "charts/chutes-miner/templates/gepetto-deployment.yaml",
    ):
        source = template.read_text()
        assert "GPU_TEE_ONLY" in source
        assert 'value: "true"' in source
    registry_template = (root / "charts/chutes-miner-gpu/templates/registry-cm.yaml").read_text()
    assert "requires exactly one validator" in registry_template
    bootstrap = (root / "src/chutes-miner/chutes_miner/api/server/util.py").read_text()
    assert "settings.gpu_tee_only" in bootstrap
    assert "disables legacy server bootstrap" in bootstrap
    assert "X-Chutes-Attested-Session" in registry_template
    assert "X-Chutes-Registry-Session $chutes_registry_session" in registry_template
    assert 'proxy_set_header X-Chutes-Attested-Session "";' in registry_template
    assert "X-Chutes-Registry-Uri" in registry_template
    assert "proxy_ssl_certificate /run/chutes-tls/server.crt" in registry_template
    daemonset = (root / "charts/chutes-miner-gpu/templates/registry-daemonset.yaml").read_text()
    assert "path: /run/chutes-gpu/registry-tls" in daemonset
    assert "runAsUser: 0" not in daemonset
    socket_client = (root / "src/chutes-miner/chutes_miner/api/socket_client.py").read_text()
    assert "while True:" in socket_client
    assert "except asyncio.CancelledError:" in socket_client


@pytest.mark.asyncio
async def test_seedless_runtime_rejects_legacy_bootstrap_before_side_effects(
    monkeypatch,
):
    monkeypatch.setattr(settings, "gpu_tee_only", True)
    stream = bootstrap_server(None, SimpleNamespace(), None)
    with pytest.raises(UnsupportedRuntime, match="disables legacy server bootstrap") as caught:
        await stream.__anext__()
    assert caught.value.code == "unsupported_runtime"


@pytest.mark.asyncio
async def test_seedless_route_returns_typed_unsupported_error(monkeypatch):
    from chutes_miner.api.server.router import create_server

    monkeypatch.setattr(settings, "gpu_tee_only", True)
    with pytest.raises(HTTPException) as caught:
        await create_server(SimpleNamespace(), None, None)

    assert caught.value.status_code == 501
    assert caught.value.detail == {
        "code": "unsupported_runtime",
        "message": (
            "Legacy server creation is disabled; the seedless GPU server is adopted from "
            "authenticated registrar state."
        ),
    }


def test_gepetto_generic_gpu_deletion_rejects_reservation_owned_nodes():
    with pytest.raises(ValueError, match="exact teardown/reset"):
        Gepetto.require_generic_gpu_deletion("allocation-group-1")
    Gepetto.require_generic_gpu_deletion(None)


def test_seedless_session_accepts_exactly_one_runtime_validator(tmp_path):
    session = {
        "schema": "chutes.gpu-miner-session",
        "version": 1,
        "server_id": "gpu-server",
        "owner_hotkey": "5Owner",
        "gpu_uuids": ["GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"],
        "gpu_identifiers": ["h100_sxm"],
        "runtime_session": "scoped",
        "runtime_session_expires_at": "2026-07-24T00:15:00Z",
        "allowed_purposes": [
            "cache",
            "gpu-infra",
            "instances",
            "launch",
            "miner",
            "nodes",
            "registry",
            "sockets",
        ],
        "validator": {
            "hotkey": "5Validator",
            "registry": "registry.validator.example",
            "api": "https://validator.example",
            "socket": "wss://validator.example/socket",
        },
    }
    path = tmp_path / "session.json"
    path.write_text(json.dumps(session, sort_keys=True, separators=(",", ":")) + "\n")
    settings = MinerSettings(
        miner_ss58="5Owner",
        gpu_tee_only=True,
        validators_file=str(path),
    )
    assert [item.hotkey for item in settings.validators] == ["5Validator"]
    assert settings.attested_session == "scoped"

    session["validators"] = [session.pop("validator"), session["runtime_session"]]
    path.write_text(json.dumps(session, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(ValueError, match="validator/session"):
        settings.validators


def test_seedless_miner_adopts_exact_registrar_identity(tmp_path):
    runtime = {
        "schema": "chutes.gpu-miner-session",
        "version": 1,
        "server_id": "logical-gpu-server",
        "owner_hotkey": "5Owner",
        "gpu_uuids": ["GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"],
        "gpu_identifiers": ["h100_sxm"],
        "runtime_session": "attested-session",
        "runtime_session_expires_at": "2026-07-24T13:00:00Z",
        "allowed_purposes": [
            "cache",
            "gpu-infra",
            "instances",
            "launch",
            "miner",
            "nodes",
            "registry",
            "sockets",
        ],
        "validator": {
            "hotkey": "5Validator",
            "registry": "registry.validator.example",
            "api": "https://validator.example",
            "socket": "wss://validator.example/socket",
        },
    }
    registration = {
        "schema": "chutes.gpu-registration-response.v2",
        "version": 2,
        "attempt_id": "attempt-1",
        "state": "completed",
        "status_url": "/servers/gpu/registration/attempts/attempt-1",
        "server_id": "logical-gpu-server",
        "owner_hotkey": "5Owner",
        "reservation_id": "reservation-1",
        "claims_sha256": "c" * 64,
        "allocation_group_id": "allocation-group-1",
        "allocation_group_generation": 7,
        "process_incarnation": "gpu-process",
        "gpu_uuids": ["GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"],
        "gpu_identifiers": ["h100_sxm"],
        "management_mode": "miner",
        "measurement_version": "1.11.0",
        "measurement_name": "gpu-miner",
        "measurement_config_fingerprint": "a" * 64,
        "trust_set_fingerprint": "b" * 64,
        "registration_id": "registration-1",
        "attestation_id": "attestation-1",
        "verified_at": "2026-07-24T12:45:00Z",
        "runtime_session": "attested-session",
        "runtime_session_expires_at": "2026-07-24T13:00:00Z",
        "registration_replay_until": "2026-07-24T13:00:00Z",
        "status": "registered",
    }
    runtime_path = tmp_path / "miner-session.json"
    registration_path = tmp_path / "registration.json"
    runtime_path.write_text(json.dumps(runtime, sort_keys=True, separators=(",", ":")) + "\n")
    registration_path.write_text(
        json.dumps(registration, sort_keys=True, separators=(",", ":")) + "\n"
    )
    parsed = MinerSettings(
        miner_ss58="5Owner",
        gpu_tee_only=True,
        validators_file=str(runtime_path),
        gpu_registration_file=str(registration_path),
    ).seedless_gpu_identity
    assert set(parsed) == {*GPU_REGISTRATION_IDENTITY_FIELDS, "validator"}
    assert parsed["server_id"] == "logical-gpu-server"
    assert parsed["attestation_id"] == "attestation-1"
    assert parsed["validator"]["hotkey"] == "5Validator"
    assert "attempt_id" not in parsed
    assert "registration_replay_until" not in parsed

    registration["server_id"] = "duplicate-server"
    registration_path.write_text(
        json.dumps(registration, sort_keys=True, separators=(",", ":")) + "\n"
    )
    with pytest.raises(ValueError, match="identities do not match"):
        MinerSettings(
            miner_ss58="5Owner",
            gpu_tee_only=True,
            validators_file=str(runtime_path),
            gpu_registration_file=str(registration_path),
        ).seedless_gpu_identity

    registration["server_id"] = "logical-gpu-server"
    invalid_documents = (
        {**registration, "schema": "chutes.gpu-registration-response.v3"},
        {**registration, "version": 3},
        {**registration, "state": "processing"},
        {**registration, "status": "failed"},
        {**registration, "runtime_session": 123},
        {**registration, "allocation_group_generation": True},
        {**registration, "gpu_uuids": [1]},
    )
    for invalid in invalid_documents:
        registration_path.write_text(
            json.dumps(invalid, sort_keys=True, separators=(",", ":")) + "\n"
        )
        with pytest.raises(ValueError, match="Registration V2 document is invalid"):
            MinerSettings(
                miner_ss58="5Owner",
                gpu_tee_only=True,
                validators_file=str(runtime_path),
                gpu_registration_file=str(registration_path),
            ).seedless_gpu_identity

    missing = dict(registration)
    missing.pop("attestation_id")
    registration_path.write_text(json.dumps(missing, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(ValueError, match="Registration V2 document is invalid"):
        MinerSettings(
            miner_ss58="5Owner",
            gpu_tee_only=True,
            validators_file=str(runtime_path),
            gpu_registration_file=str(registration_path),
        ).seedless_gpu_identity


def test_seedless_hourly_cost_comes_from_verified_claim_environment(tmp_path):
    verified = tmp_path / "verified.env"
    verified.write_text(
        "CHUTES_MANAGEMENT_MODE=miner\nCHUTES_MINER_HOURLY_COST=12.5\n",
        encoding="ascii",
    )
    settings = MinerSettings(
        miner_ss58="5Owner",
        gpu_tee_only=True,
        gpu_verified_env_file=str(verified),
    )
    assert settings.miner_hourly_cost == 12.5
    verified.write_text("CHUTES_MINER_HOURLY_COST=0\n", encoding="ascii")
    with pytest.raises(ValueError, match="positive and finite"):
        _ = settings.miner_hourly_cost


def test_seedless_hourly_cost_reports_actionable_permission_error(monkeypatch, tmp_path):
    verified = tmp_path / "verified.env"
    verified.write_text("CHUTES_MINER_HOURLY_COST=12.5\n", encoding="ascii")
    settings = MinerSettings(
        miner_ss58="5Owner",
        gpu_tee_only=True,
        gpu_verified_env_file=str(verified),
    )
    read_text = Path.read_text

    def deny_verified_env(path, *args, **kwargs):
        if path == verified:
            raise PermissionError("permission denied")
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", deny_verified_env)
    with pytest.raises(
        SeedlessGPUConfigurationError,
        match=r"UID 65532.*directory traversal.*file read permission",
    ) as caught:
        _ = settings.miner_hourly_cost
    assert isinstance(caught.value.__cause__, PermissionError)


def test_seedless_api_leader_election_uses_postgres_not_stale_pidfile():
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[2] / "src/chutes-miner/chutes_miner/api/main.py"
    ).read_text()
    assert "pg_try_advisory_lock" in source
    assert "pg_advisory_unlock" in source
    assert "/tmp/api.pid" not in source


def test_seedless_chart_removes_unsupported_wallet_audit_exporter():
    root = Path(__file__).resolve().parents[2]
    values = (root / "charts/chutes-miner/values.yaml").read_text()
    assert "chutes-miner-cpu-0" not in values
    assert 'chutes/seedless-control-plane: "true"' in values
    assert "auditExporter:" not in values
    for retired_path in (
        root / "src/chutes-miner/chutes_miner/audit_exporter.py",
        root / "charts/chutes-miner/templates/audit-export-cronjob.yaml",
        root / "charts/chutes-miner/templates/audit-exporter.rbac.yaml",
    ):
        assert not retired_path.exists()


def test_dev_helpers_use_public_owner_without_wallet_material():
    root = Path(__file__).resolve().parents[2]
    for path in (
        root / "docker/chutes-miner/docker-compose.yaml",
        root / "docker/chutes-miner/docker-compose.override.yml",
        root / "scripts/seed.py",
    ):
        source = path.read_text()
        assert "MINER_OWNER_SS58" in source
        assert "MINER_" + "SEED" not in source
        assert "MINER_SS58" not in source

    verification = (root / "src/chutes-miner/chutes_miner/api/server/verification.py").read_text()
    assert "miner_" + "keypair" not in verification
    for source_root in (
        root / "src/chutes-miner",
        root / "src/chutes-common",
    ):
        for path in source_root.rglob("*.py"):
            assert "settings." + "miner_keypair" not in path.read_text()


def test_merged_dev_compose_contains_only_public_owner_identity():
    docker = shutil.which("docker")
    if (
        docker is None
        or subprocess.run(
            [docker, "compose", "version"],
            check=False,
            capture_output=True,
            text=True,
        ).returncode
    ):
        pytest.skip("Docker Compose is unavailable")

    root = Path(__file__).resolve().parents[2]
    compose_dir = root / "docker/chutes-miner"
    environment = {
        **os.environ,
        "PROJECT": "hardening-test",
        "BRANCH_NAME": "review",
        "BUILD_NUMBER": "1",
    }
    resolved = subprocess.run(
        [
            docker,
            "compose",
            "-f",
            "docker-compose.yaml",
            "-f",
            "docker-compose.override.yml",
            "config",
            "--format",
            "json",
        ],
        cwd=compose_dir,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    document = json.loads(resolved.stdout)
    api_environment = document["services"]["api"]["environment"]
    assert {key: value for key, value in api_environment.items() if key.startswith("MINER_")} == {
        "MINER_OWNER_SS58": "5Df8xCSkGWk9VWU2QeWXDLn2p7zebV58TsFWxfhs8VRbARFj"
    }
    serialized = json.dumps(document, sort_keys=True)
    assert "MINER_SS58" not in serialized
    assert "MINER_SEED" not in serialized


def test_seedless_workload_cache_redis_and_registry_scopes_are_ephemeral():
    root = Path(__file__).resolve().parents[2]
    k8s_util = (root / "src/chutes-miner/chutes_miner/api/k8s/util.py").read_text()
    redis = (root / "charts/chutes-miner/templates/redis-deployment.yaml").read_text()
    registry = (root / "charts/chutes-miner-gpu/templates/registry-daemonset.yaml").read_text()
    assert "V1HostPathVolumeSource" not in k8s_util
    assert 'name="cache"' in k8s_util
    assert "V1EmptyDirVolumeSource" in k8s_util
    assert "cache-cleaner" not in k8s_util
    assert "/var/snap/cache" not in k8s_util
    assert "/var/snap/redis-data" not in redis
    assert "emptyDir:" in redis
    assert "path: /var/lib/chutes-registry" not in registry
    assert "chutes-registry-scopes\n          emptyDir: {}" in registry


def test_seedless_adoption_keeps_logical_and_kubernetes_ids_separate():
    root = Path(__file__).resolve().parents[2]
    adoption = (root / "src/chutes-miner/chutes_miner/api/server/seedless_adoption.py").read_text()
    model = (root / "src/chutes-common/chutes_common/schemas/server.py").read_text()
    gpu_model = (root / "src/chutes-common/chutes_common/schemas/gpu.py").read_text()
    migration = (
        root / "src/chutes-miner/chutes_miner/api/migrations/"
        "20260724090000_seedless_gpu_identity.sql"
    ).read_text()
    router = (root / "src/chutes-miner/chutes_miner/api/server/router.py").read_text()
    assert "server_id=logical_server_id" in adoption
    assert "server.kubernetes_node_uid = node_uid" in adoption
    assert "registration_attestation_id" in model
    assert "hardware_uuid" in gpu_model
    assert "ADD COLUMN IF NOT EXISTS hardware_uuid" in migration
    assert "ADD COLUMN IF NOT EXISTS gpu_allocation_group_id" in migration
    assert "ADD COLUMN IF NOT EXISTS gpu_allocation_group_generation" in migration
    assert "ck_gpus_allocation_group_lineage" in migration
    assert "gpus_allocation_group_idx" in migration
    assert "Legacy server creation is disabled" in router


def test_gpu_orm_has_exact_allocation_group_schema_parity():
    from chutes_common.schemas.gpu import GPU

    assert {
        "hardware_uuid",
        "gpu_allocation_group_id",
        "gpu_allocation_group_generation",
    }.issubset(GPU.__table__.columns.keys())
    assert {constraint.name for constraint in GPU.__table__.constraints} >= {
        "ck_gpus_allocation_group_lineage"
    }
    assert {index.name for index in GPU.__table__.indexes} >= {
        "gpus_hardware_uuid_idx",
        "gpus_allocation_group_idx",
    }


@pytest.mark.asyncio
async def test_registrar_identity_is_adopted_without_duplicate_server(monkeypatch):
    from chutes_common.schemas.gpu import GPU
    from chutes_common.schemas.server import Server, ServerNodeIdentity
    from chutes_miner.api.server import seedless_adoption

    identity = {
        "server_id": "logical-server",
        "attestation_id": "attestation-1",
        "allocation_group_id": "group-1",
        "allocation_group_generation": 3,
        "gpu_uuids": ["GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"],
        "gpu_identifiers": ["h100_sxm"],
        "validator": {"hotkey": "5Validator"},
    }
    node = SimpleNamespace(
        metadata=SimpleNamespace(
            name="k3s-node",
            uid="kubernetes-node-uid",
            labels={
                "node-role.kubernetes.io/control-plane": "true",
                "chutes/seedless-control-plane": "true",
                "chutes/external-ip": "192.0.2.10",
            },
        ),
        status=SimpleNamespace(
            capacity={
                "nvidia.com/gpu": "1",
                "cpu": "16",
                "memory": "65536Mi",
            },
            allocatable={"nvidia.com/gpu": "1"},
            conditions=[SimpleNamespace(type="Ready", status="True")],
        ),
    )

    class CoreClient:
        def list_node(self):
            return SimpleNamespace(items=[node])

        def patch_node(self, _name, body):
            node.metadata.labels.update(body["metadata"]["labels"])
            return node

    class EmptyResult:
        def unique(self):
            return self

        def scalar_one_or_none(self):
            return None

    class EmptyScalars:
        def all(self):
            return []

    class EmptyRows:
        def unique(self):
            return self

        def scalars(self):
            return EmptyScalars()

    class Session:
        def __init__(self):
            self.added = []
            self.results = [
                EmptyRows(),
                EmptyResult(),
                EmptyResult(),
                EmptyRows(),
                EmptyResult(),
            ]

        async def get(self, model, _key):
            assert model in {Server, GPU}
            return None

        async def execute(self, _statement):
            return self.results.pop(0)

        def add(self, value):
            self.added.append(value)

        async def commit(self):
            return None

    session = Session()

    class SessionContext:
        async def __aenter__(self):
            return session

        async def __aexit__(self, *_args):
            return None

    monkeypatch.setattr(
        seedless_adoption,
        "settings",
        SimpleNamespace(seedless_gpu_identity=identity, miner_hourly_cost=12.5),
    )
    monkeypatch.setattr(seedless_adoption, "k8s_core_client", lambda: CoreClient())
    monkeypatch.setattr(seedless_adoption, "get_session", lambda: SessionContext())

    assert await seedless_adoption.adopt_seedless_gpu_server() == "logical-server"
    server = next(value for value in session.added if isinstance(value, Server))
    gpu = next(value for value in session.added if isinstance(value, GPU))
    node_identity = next(value for value in session.added if isinstance(value, ServerNodeIdentity))
    assert server.server_id == "logical-server"
    assert server.kubernetes_node_uid == "kubernetes-node-uid"
    assert server.kubernetes_node_generation == 1
    assert server.registration_attestation_id == "attestation-1"
    assert server.hourly_cost == 12.5
    assert node_identity.generation == 1
    assert node_identity.registration_attestation_id == "attestation-1"
    assert gpu.server_id == "logical-server"
    assert gpu.hardware_uuid == identity["gpu_uuids"][0]
    assert not gpu.gpu_id.startswith("GPU-")
    assert gpu.gpu_allocation_group_id == "group-1"


@pytest.mark.asyncio
async def test_new_attestation_rotates_node_uid_without_rotating_logical_server(
    monkeypatch,
):
    from chutes_common.schemas.gpu import GPU
    from chutes_common.schemas.server import Server, ServerNodeIdentity
    from chutes_miner.api.server import seedless_adoption

    identity = {
        "server_id": "logical-server",
        "attestation_id": "attestation-2",
        "allocation_group_id": "group-1",
        "allocation_group_generation": 4,
        "gpu_uuids": ["GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"],
        "gpu_identifiers": ["h100_sxm"],
        "validator": {"hotkey": "5Validator"},
    }
    node = SimpleNamespace(
        metadata=SimpleNamespace(
            name="k3s-node",
            uid="node-uid-2",
            labels={
                "node-role.kubernetes.io/control-plane": "true",
                "chutes/seedless-control-plane": "true",
                "chutes/external-ip": "192.0.2.11",
            },
        ),
        status=SimpleNamespace(
            capacity={
                "nvidia.com/gpu": "1",
                "cpu": "16",
                "memory": "65536Mi",
            },
            allocatable={"nvidia.com/gpu": "1"},
            conditions=[SimpleNamespace(type="Ready", status="True")],
        ),
    )
    server = Server(
        server_id="logical-server",
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=1,
        registration_attestation_id="attestation-1",
        validator="5Validator",
        name="k3s-node",
        labels={},
        gpu_count=1,
        cpu_per_gpu=4,
        memory_per_gpu=32,
        hourly_cost=0,
    )
    prior = ServerNodeIdentity(
        server_id=server.server_id,
        generation=1,
        kubernetes_node_uid="node-uid-1",
        registration_attestation_id="attestation-1",
    )

    class Result:
        def __init__(self, value):
            self.value = value

        def unique(self):
            return self

        def scalar_one_or_none(self):
            return self.value

        def scalars(self):
            return self

        def all(self):
            return self.value

    class Session:
        def __init__(self):
            self.added = []
            self.results = [
                Result([server]),
                Result(None),
                Result(prior),
                Result([]),
                Result(None),
            ]

        async def execute(self, _statement):
            return self.results.pop(0)

        async def get(self, model, _key):
            assert model is GPU
            return None

        def add(self, value):
            self.added.append(value)

        async def commit(self):
            return None

    session = Session()

    class Context:
        async def __aenter__(self):
            return session

        async def __aexit__(self, *_args):
            return None

    class Core:
        def list_node(self):
            return SimpleNamespace(items=[node])

        def patch_node(self, _name, body):
            node.metadata.labels.update(body["metadata"]["labels"])
            return node

    monkeypatch.setattr(
        seedless_adoption,
        "settings",
        SimpleNamespace(seedless_gpu_identity=identity, miner_hourly_cost=12.5),
    )
    monkeypatch.setattr(seedless_adoption, "k8s_core_client", lambda: Core())
    monkeypatch.setattr(seedless_adoption, "get_session", lambda: Context())

    assert await seedless_adoption.adopt_seedless_gpu_server() == "logical-server"
    assert server.server_id == "logical-server"
    assert server.kubernetes_node_uid == "node-uid-2"
    assert server.kubernetes_node_generation == 2
    assert server.hourly_cost == 12.5
    assert prior.retired_at is not None
    current = next(value for value in session.added if isinstance(value, ServerNodeIdentity))
    assert current.generation == 2
    assert current.kubernetes_node_uid == "node-uid-2"


@pytest.mark.asyncio
async def test_legacy_db_identity_rekeys_before_conflict_checks(monkeypatch):
    from chutes_common.schemas.gpu import GPU
    from chutes_common.schemas.server import Server
    from chutes_miner.api.server import seedless_adoption

    gpu_uuid = "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    logical_server_id = "logical-server"
    node_uid = "legacy-node-uid"
    identity = {
        "server_id": logical_server_id,
        "attestation_id": "attestation-2",
        "allocation_group_id": "group-2",
        "allocation_group_generation": 5,
        "gpu_uuids": [gpu_uuid],
        "gpu_identifiers": ["h100_sxm"],
        "validator": {"hotkey": "5Validator"},
    }
    node = SimpleNamespace(
        metadata=SimpleNamespace(
            name="legacy-node",
            uid=node_uid,
            labels={
                "node-role.kubernetes.io/control-plane": "true",
                "chutes/seedless-control-plane": "true",
            },
        ),
        status=SimpleNamespace(
            capacity={"nvidia.com/gpu": "1", "cpu": "16", "memory": "65536Mi"},
            allocatable={"nvidia.com/gpu": "1"},
            conditions=[SimpleNamespace(type="Ready", status="True")],
        ),
    )
    old_server = Server(
        server_id=node_uid,
        kubernetes_node_uid=node_uid,
        kubernetes_node_generation=1,
        registration_attestation_id="attestation-1",
        validator="5Validator",
        name="legacy-node",
        labels={},
        gpu_count=1,
        cpu_per_gpu=4,
        memory_per_gpu=32,
        hourly_cost=0,
    )
    logical_server = Server(
        server_id=logical_server_id,
        kubernetes_node_uid=node_uid,
        kubernetes_node_generation=1,
        registration_attestation_id="attestation-1",
        validator="5Validator",
        name="legacy-node",
        labels={},
        gpu_count=1,
        cpu_per_gpu=4,
        memory_per_gpu=32,
        hourly_cost=0,
    )
    legacy_gpu = GPU(
        gpu_id=gpu_uuid,
        hardware_uuid=gpu_uuid,
        server_id=logical_server_id,
        deployment_id="deployment-kept",
    )

    class Result:
        def __init__(self, value=None, rowcount=None):
            self.value = value
            self.rowcount = rowcount

        def unique(self):
            return self

        def scalars(self):
            return self

        def all(self):
            return self.value

        def scalar_one(self):
            return self.value

        def scalar_one_or_none(self):
            return self.value

    class Session:
        def __init__(self):
            self.results = [
                Result([old_server]),
                Result(rowcount=1),
                Result(logical_server),
                Result(None),
                Result(None),
                Result([legacy_gpu]),
                Result(legacy_gpu),
                Result(None),
            ]
            self.executed = []
            self.added = []
            self.expunged = []

        async def execute(self, statement, parameters=None):
            self.executed.append((statement, parameters))
            return self.results.pop(0)

        def expunge(self, value):
            self.expunged.append(value)

        def add(self, value):
            self.added.append(value)

        async def commit(self):
            return None

    session = Session()

    class Context:
        async def __aenter__(self):
            return session

        async def __aexit__(self, *_args):
            return None

    class Core:
        def list_node(self):
            return SimpleNamespace(items=[node])

        def patch_node(self, _name, body):
            node.metadata.labels.update(body["metadata"]["labels"])
            return node

    monkeypatch.setattr(
        seedless_adoption,
        "settings",
        SimpleNamespace(seedless_gpu_identity=identity, miner_hourly_cost=12.5),
    )
    monkeypatch.setattr(seedless_adoption, "k8s_core_client", lambda: Core())
    monkeypatch.setattr(seedless_adoption, "get_session", lambda: Context())

    assert await seedless_adoption.adopt_seedless_gpu_server() == logical_server_id
    assert session.expunged == [old_server]
    assert session.executed[1][1] == {
        "logical_server_id": logical_server_id,
        "old_server_id": node_uid,
    }
    canonical_gpu_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"chutes:nvidia:{logical_server_id}:{gpu_uuid}",
        )
    )
    assert legacy_gpu.gpu_id == canonical_gpu_id
    assert legacy_gpu.deployment_id == "deployment-kept"
