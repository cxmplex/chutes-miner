from contextlib import asynccontextmanager
import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

import pytest

from chutes_common.schemas.gpu import GPU
from chutes_common.schemas.chute import Chute
from chutes_miner.api.config import settings
from chutes_miner.api.exceptions import DeploymentFailure
from chutes_miner.api.k8s.operator import K8sOperator
from chutes_miner.api.k8s.util import canonical_miner_launch_sha256
import chutes_miner.gepetto as gepetto_module
from chutes_miner.gepetto import Gepetto


VALIDATOR = "test_validator"


def _gepetto() -> Gepetto:
    gepetto = object.__new__(Gepetto)
    gepetto.remote_server_versions = {VALIDATOR: {"server-1": "1.8.0"}}
    gepetto.remote_chutes = {VALIDATOR: {}}
    gepetto.global_active_instances = {VALIDATOR: []}
    gepetto._begin_launch_intent = AsyncMock(return_value="request-1")
    gepetto._record_launch_response = AsyncMock()
    gepetto._record_registry_ack = AsyncMock()
    gepetto._record_launch_intent_failure = AsyncMock()
    gepetto._begin_job_cleanup_intent = AsyncMock(return_value="job-cleanup-1")
    gepetto.abort_launch_intent = AsyncMock(return_value=True)
    return gepetto


def _chute(**overrides):
    values = {
        "chute_id": "chute-1",
        "validator": VALIDATOR,
        "version": "1.0.0",
        "chutes_version": "0.8.0",
        "supported_gpus": ["h100"],
        "gpu_count": 1,
        "tee": False,
        "ban_reason": None,
        "preemptible": True,
        "name": "test chute",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _server(**overrides):
    values = {
        "server_id": "server-1",
        "validator": VALIDATOR,
        "name": "gpu-1",
        "ip_address": "192.0.2.10",
        "kubeconfig": None,
        "is_tee": False,
        "hourly_cost": 1.0,
        "kubernetes_node_uid": "node-uid-1",
        "kubernetes_node_generation": 1,
        "gpu_allocation_group_id": "group-1",
        "gpu_allocation_group_generation": 1,
        "gpus": [SimpleNamespace(deployment_id=None, model_short_ref="h100")],
        "deployments": [],
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _remote_chute_payload(**overrides):
    values = {
        "chute_id": "chute-1",
        "name": "test chute",
        "image": "owner/image:latest",
        "ref_str": "chute:chute",
        "version": "1.0.0",
        "supported_gpus": ["h100"],
        "node_selector": {"gpu_count": 1},
        "chutes_version": "0.8.0",
        "preemptible": True,
        "tee": False,
    }
    values.update(overrides)
    return values


class _ScalarResult:
    def __init__(self, scalar=None, scalars=None):
        self._scalar = scalar
        self._scalars = list(scalars or [])

    def unique(self):
        return self

    def scalar_one_or_none(self):
        return self._scalar

    def scalars(self):
        return self

    def all(self):
        return self._scalars

    def __iter__(self):
        return iter(self._scalars)


class _Session:
    def __init__(self, results):
        self.results = results
        self.statements = []

    async def execute(self, statement):
        self.statements.append(statement)
        return self.results.pop(0)


def _session_factory(results):
    queued_results = list(results)

    @asynccontextmanager
    async def get_session():
        yield _Session(queued_results)

    return get_session


def test_parse_server_versions_uses_actual_miner_servers_schema():
    assert Gepetto._parse_server_versions(
        {
            "servers": [
                {"server_id": "old", "version": "1.3.0"},
                {"server_id": "new", "version": "1.8.0"},
                {"server_id": "unknown", "version": None},
            ]
        }
    ) == {"old": "1.3.0", "new": "1.8.0", "unknown": None}


def test_local_chute_schema_and_remote_parser_exclude_source():
    assert "code" not in Chute.__table__.columns
    assert "filename" not in Chute.__table__.columns
    values = Gepetto._remote_chute_values(
        _remote_chute_payload(),
        VALIDATOR,
        expected_chute_id="chute-1",
        expected_version="1.0.0",
    )
    assert "code" not in values
    assert "legacy placeholder" not in repr(values)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("code", "print('legacy placeholder')"),
        ("filename", "chute.py"),
    ],
)
def test_remote_chute_parser_rejects_obsolete_source_fields(field, value):
    payload = _remote_chute_payload(**{field: value})
    with pytest.raises(ValueError, match="obsolete source fields are forbidden"):
        Gepetto._remote_chute_values(
            payload,
            VALIDATOR,
            expected_chute_id="chute-1",
            expected_version="1.0.0",
        )


@pytest.mark.asyncio
async def test_get_launch_token_rejects_unsupported_runtime_before_request(
    mock_aiohttp_response,
):
    gepetto = _gepetto()
    with pytest.raises(DeploymentFailure, match="Unsupported chutes runtime version"):
        await gepetto.get_launch_token(
            _chute(chutes_version="0.3.60"),
            _server(),
        )
    mock_aiohttp_response.json.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_launch_token_requires_exact_response_schema(mock_aiohttp_response):
    gepetto = _gepetto()
    mock_aiohttp_response.status = 200
    mock_aiohttp_response.json.return_value = {
        "token": "launch-token",
        "config_id": "config-1",
    }

    assert await gepetto.get_launch_token(_chute(), _server()) == {
        "token": "launch-token",
        "config_id": "config-1",
        "_miner_launch_request_id": "request-1",
    }

    mock_aiohttp_response.json.return_value = {
        "token": "launch-token",
        "config_id": "config-1",
        "code": "print('legacy placeholder')",
    }
    with pytest.raises(DeploymentFailure, match="expected exactly"):
        await gepetto.get_launch_token(_chute(), _server())
    gepetto.abort_launch_intent.assert_awaited_once_with("request-1")

    mock_aiohttp_response.json.return_value = {
        "token": "launch-token",
        "config_id": "config-1",
        "storage_session": "must-arrive-only-after-verified-launch",
    }
    with pytest.raises(DeploymentFailure, match="expected exactly"):
        await gepetto.get_launch_token(_chute(), _server())


@pytest.mark.asyncio
async def test_seedless_launch_token_registers_exact_descriptor_scope(
    monkeypatch,
    mock_aiohttp_response,
):
    gepetto = _gepetto()
    gepetto._register_registry_scope = AsyncMock()
    monkeypatch.setattr(settings, "gpu_tee_only", True)
    root = f"sha256:{'a' * 64}"
    mock_aiohttp_response.status = 200
    mock_aiohttp_response.json.return_value = {
        "token": "launch-token",
        "config_id": "config-1",
        "registry": {
            "repository": "owner/image",
            "manifest_digest": root,
        },
    }
    server = _server()
    result = await gepetto.get_launch_token(_chute(), server)
    assert result["registry"]["manifest_digest"] == root
    gepetto._register_registry_scope.assert_awaited_once()
    assert gepetto._register_registry_scope.await_args.args[1] is server


@pytest.mark.asyncio
async def test_launch_token_replay_uses_persisted_request_id(
    mock_aiohttp_response,
    mock_aiohttp_client_session,
):
    gepetto = _gepetto()
    mock_aiohttp_response.status = 200
    mock_aiohttp_response.json.return_value = {
        "token": "fresh-token",
        "config_id": "config-1",
    }

    await gepetto.get_launch_token(_chute(), _server(), job_id="job-1")

    request = mock_aiohttp_client_session.return_value.get
    assert request.call_args.kwargs["params"] == {
        "chute_id": "chute-1",
        "server_id": "server-1",
        "job_id": "job-1",
        "miner_launch_request_id": "request-1",
    }
    gepetto._record_launch_response.assert_awaited_once()
    gepetto._record_registry_ack.assert_awaited_once()


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"servers": None},
        {"servers": [{}]},
        {"servers": [{"server_id": "server-1", "version": 3}]},
        {
            "servers": [
                {"server_id": "server-1", "version": "1.8.0"},
                {"server_id": "server-1", "version": "1.8.0"},
            ]
        },
    ],
)
def test_parse_server_versions_rejects_malformed_or_ambiguous_payload(payload):
    with pytest.raises(ValueError):
        Gepetto._parse_server_versions(payload)


@pytest.mark.asyncio
async def test_server_version_refresh_atomically_replaces_stale_entries(
    mock_aiohttp_response,
):
    gepetto = _gepetto()
    gepetto.remote_server_versions[VALIDATOR]["removed-server"] = "1.9.0"
    mock_aiohttp_response.json.return_value = {
        "servers": [{"server_id": "server-1", "version": "1.3.0"}]
    }

    await gepetto._refresh_server_versions(settings.validators[0])

    assert gepetto.remote_server_versions[VALIDATOR] == {"server-1": "1.3.0"}


@pytest.mark.asyncio
async def test_server_version_refresh_failure_clears_stale_entries(
    mock_aiohttp_response,
):
    gepetto = _gepetto()
    mock_aiohttp_response.json.side_effect = RuntimeError("validator unavailable")

    await gepetto._refresh_server_versions(settings.validators[0])

    assert gepetto.remote_server_versions[VALIDATOR] == {}
    assert gepetto._server_vm_version(VALIDATOR, "server-1") is None


@pytest.mark.asyncio
async def test_inventory_refresh_failure_cannot_bypass_version_invalidation(
    mock_aiohttp_response,
):
    gepetto = _gepetto()
    mock_aiohttp_response.json.side_effect = RuntimeError("version inventory unavailable")
    gepetto._remote_refresh_objects = AsyncMock(
        side_effect=RuntimeError("chute inventory unavailable")
    )

    with pytest.raises(RuntimeError, match="chute inventory unavailable"):
        await gepetto.remote_refresh_all()

    assert gepetto.remote_server_versions[VALIDATOR] == {}


@pytest.mark.asyncio
async def test_direct_deployment_rejects_validator_mismatch_before_allocation(
    mock_db_session,
    sample_chute,
    sample_server,
):
    sample_chute.validator = "different-validator"
    result = MagicMock()
    result.unique.return_value = result
    result.scalar_one_or_none.side_effect = [sample_chute, sample_server]
    mock_db_session.execute = AsyncMock(return_value=result)

    with pytest.raises(DeploymentFailure, match="does not match"):
        await K8sOperator().deploy_chute(
            sample_chute,
            sample_server,
            token="launch-token",
            config_id="config-1",
        )

    mock_db_session.add.assert_not_called()
    mock_db_session.flush.assert_not_awaited()


@pytest.mark.asyncio
async def test_direct_deployment_rejects_unknown_validator_before_allocation(
    mock_db_session,
    sample_chute,
    sample_server,
):
    sample_chute.validator = sample_server.validator = "unknown-validator"
    result = MagicMock()
    result.unique.return_value = result
    result.scalar_one_or_none.side_effect = [sample_chute, sample_server]
    mock_db_session.execute = AsyncMock(return_value=result)

    with pytest.raises(DeploymentFailure, match="No configured validator API"):
        await K8sOperator().deploy_chute(
            sample_chute,
            sample_server,
            token="launch-token",
            config_id="config-1",
        )

    mock_db_session.add.assert_not_called()
    mock_db_session.flush.assert_not_awaited()


@pytest.mark.asyncio
async def test_scale_up_candidate_selection_skips_validator_mismatch():
    chute = _chute()
    mismatched = _server(validator="different-validator")
    session_factory = _session_factory([_ScalarResult(scalars=[mismatched])])

    with (
        patch.object(gepetto_module, "get_session", session_factory),
        patch.object(
            gepetto_module.k8s,
            "check_node_has_disk_available",
            new=AsyncMock(return_value=True),
        ) as disk_check,
    ):
        selected = await Gepetto.optimal_scale_up_server(chute)

    assert selected is None
    disk_check.assert_not_awaited()


@pytest.mark.asyncio
async def test_scale_up_candidate_selection_rejects_unknown_validator():
    chute = _chute(validator="unknown-validator")

    with patch.object(gepetto_module, "get_session") as get_session:
        selected = await Gepetto.optimal_scale_up_server(chute)

    assert selected is None
    get_session.assert_not_called()


@pytest.mark.asyncio
async def test_normal_scale_up_skips_nonpositive_hourly_cost():
    chute = _chute()
    invalid = _server(hourly_cost=0.0)
    with (
        patch.object(
            gepetto_module,
            "get_session",
            _session_factory([_ScalarResult(scalars=[invalid])]),
        ),
        patch.object(
            gepetto_module.k8s,
            "check_node_has_disk_available",
            new=AsyncMock(return_value=True),
        ) as disk_check,
    ):
        assert await Gepetto.optimal_scale_up_server(chute) is None
    disk_check.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_job_propagates_version_and_launch_context():
    gepetto = _gepetto()
    chute = _chute()
    server = _server()
    gepetto.get_launch_token = AsyncMock(
        return_value={
            "token": "launch-jwt",
            "config_id": "config-1",
            "_miner_launch_request_id": "request-1",
        }
    )
    gepetto._get_job_extra_services = AsyncMock(return_value=[{"port": 9000}])
    deployment = SimpleNamespace(deployment_id="deployment-1")

    with patch.object(
        gepetto_module.k8s,
        "deploy_chute",
        new=AsyncMock(return_value=(deployment, object())),
    ) as deploy:
        await gepetto.run_job(
            chute,
            "job-1",
            server,
            settings.validators[0],
            disk_gb=20,
        )

    assert deploy.await_args.kwargs["vm_version"] == "1.8.0"
    assert deploy.await_args.kwargs["token"] == "launch-jwt"
    assert deploy.await_args.kwargs["config_id"] == "config-1"
    assert deploy.await_args.kwargs["job_id"] == "job-1"


@pytest.mark.asyncio
async def test_job_path_rejects_nonpositive_hourly_cost_before_token_fetch():
    gepetto = _gepetto()
    chute = _chute()
    server = _server(hourly_cost=0.0)
    gepetto.get_launch_token = AsyncMock()
    with patch.object(gepetto_module.k8s, "deploy_chute", new=AsyncMock()) as deploy:
        await gepetto.run_job(chute, "job-1", server, settings.validators[0])
    gepetto.get_launch_token.assert_not_awaited()
    deploy.assert_not_awaited()
    gepetto._begin_job_cleanup_intent.assert_awaited_once_with(chute, server, "job-1")
    gepetto.abort_launch_intent.assert_awaited_once_with("job-cleanup-1")


@pytest.mark.asyncio
async def test_run_job_rejects_cross_validator_server_before_token_fetch():
    gepetto = _gepetto()
    chute = _chute()
    server = _server(validator="different-validator")
    gepetto.get_launch_token = AsyncMock()
    gepetto._get_job_extra_services = AsyncMock()

    with patch.object(gepetto_module.k8s, "deploy_chute", new=AsyncMock()) as deploy:
        await gepetto.run_job(chute, "job-1", server, settings.validators[0])

    gepetto.get_launch_token.assert_not_awaited()
    deploy.assert_not_awaited()
    gepetto._begin_job_cleanup_intent.assert_awaited_once_with(chute, server, "job-1")
    gepetto.abort_launch_intent.assert_awaited_once_with("job-cleanup-1")


@pytest.mark.asyncio
async def test_normal_scale_up_propagates_server_version():
    gepetto = _gepetto()
    gepetto._scale_lock = __import__("asyncio").Lock()
    chute = _chute()
    server = _server()
    gepetto.count_non_job_deployments = AsyncMock(side_effect=[0, 1])
    gepetto.optimal_scale_up_server = AsyncMock(return_value=server)
    gepetto.get_launch_token = AsyncMock(
        return_value={
            "token": "launch-jwt",
            "config_id": "config-1",
            "_miner_launch_request_id": "request-1",
        }
    )
    deployment = SimpleNamespace(deployment_id="deployment-1")

    with patch.object(
        gepetto_module.k8s,
        "deploy_chute",
        new=AsyncMock(return_value=(deployment, object())),
    ) as deploy:
        assert await gepetto.scale_chute(chute, desired_count=1)

    assert deploy.await_args.kwargs["vm_version"] == "1.8.0"


@pytest.mark.asyncio
async def test_preemption_job_propagates_version_and_job_identity():
    gepetto = _gepetto()
    chute = _chute()
    gepetto.remote_chutes[VALIDATOR][chute.chute_id] = {"effective_compute_multiplier": 2.0}
    server = _server()
    results = [
        _ScalarResult(scalar=None),
        _ScalarResult(scalars=[server]),
    ]
    gepetto.get_launch_token = AsyncMock(
        return_value={
            "token": "launch-jwt",
            "config_id": "config-1",
            "_miner_launch_request_id": "request-1",
        }
    )
    gepetto._get_job_extra_services = AsyncMock(return_value=[])
    deployment = SimpleNamespace(deployment_id="deployment-1")

    with (
        patch.object(gepetto_module, "get_session", _session_factory(results)),
        patch.object(
            gepetto_module.k8s,
            "check_node_has_disk_available",
            new=AsyncMock(return_value=True),
        ),
        patch.object(
            gepetto_module.k8s,
            "deploy_chute",
            new=AsyncMock(return_value=(deployment, object())),
        ) as deploy,
    ):
        assert await gepetto.preempting_deploy(chute, job_id="job-1")

    assert deploy.await_args.kwargs["vm_version"] == "1.8.0"
    assert deploy.await_args.kwargs["job_id"] == "job-1"


@pytest.mark.asyncio
async def test_preemption_rejects_cross_validator_candidate_before_token_fetch():
    gepetto = _gepetto()
    chute = _chute()
    mismatched = _server(validator="different-validator")
    results = [
        _ScalarResult(scalar=None),
        _ScalarResult(scalars=[mismatched]),
    ]
    gepetto.get_launch_token = AsyncMock()

    with (
        patch.object(gepetto_module, "get_session", _session_factory(results)),
        patch.object(
            gepetto_module.k8s,
            "check_node_has_disk_available",
            new=AsyncMock(return_value=True),
        ) as disk_check,
        patch.object(
            gepetto_module.k8s,
            "deploy_chute",
            new=AsyncMock(),
        ) as deploy,
    ):
        assert not await gepetto.preempting_deploy(chute)

    disk_check.assert_not_awaited()
    gepetto.get_launch_token.assert_not_awaited()
    deploy.assert_not_awaited()


@pytest.mark.asyncio
async def test_preemption_skips_nonpositive_hourly_cost_candidate():
    gepetto = _gepetto()
    chute = _chute()
    gepetto.remote_chutes[VALIDATOR][chute.chute_id] = {
        "effective_compute_multiplier": 2.0
    }
    invalid = _server(hourly_cost=0.0)
    with (
        patch.object(
            gepetto_module,
            "get_session",
            _session_factory(
                [
                    _ScalarResult(scalar=None),
                    _ScalarResult(scalars=[invalid]),
                ]
            ),
        ),
        patch.object(
            gepetto_module.k8s,
            "check_node_has_disk_available",
            new=AsyncMock(return_value=True),
        ) as disk_check,
        patch.object(gepetto_module.k8s, "deploy_chute", new=AsyncMock()) as deploy,
    ):
        assert not await gepetto.preempting_deploy(chute)
    disk_check.assert_not_awaited()
    deploy.assert_not_awaited()


@pytest.mark.asyncio
async def test_rolling_update_propagates_version_on_matching_server():
    gepetto = _gepetto()
    gepetto._scale_lock = __import__("asyncio").Lock()
    chute = _chute(version="2.0.0")
    server = _server()
    deployment = SimpleNamespace(
        deployment_id="deployment-old",
        server=server,
    )
    gepetto.undeploy = AsyncMock()
    gepetto.load_chute = AsyncMock(return_value=chute)
    gepetto.get_launch_token = AsyncMock(
        return_value={
            "token": "launch-jwt",
            "config_id": "config-2",
            "_miner_launch_request_id": "request-2",
        }
    )
    created = SimpleNamespace(deployment_id="deployment-new")

    with (
        patch.object(
            gepetto_module,
            "get_session",
            _session_factory([_ScalarResult(scalar=deployment)]),
        ),
        patch.object(
            gepetto_module.k8s,
            "deploy_chute",
            new=AsyncMock(return_value=(created, object())),
        ) as deploy,
    ):
        await gepetto.rolling_update(
            {
                "chute_id": chute.chute_id,
                "new_version": chute.version,
                "validator": VALIDATOR,
                "instance_id": "instance-1",
            }
        )

    assert deploy.await_args.kwargs["vm_version"] == "1.8.0"
    gepetto.undeploy.assert_awaited_once_with(
        "deployment-old",
        reason="rolling_update",
    )


@pytest.mark.asyncio
async def test_rolling_update_preserves_existing_deployment_with_invalid_hourly_cost():
    gepetto = _gepetto()
    gepetto._scale_lock = __import__("asyncio").Lock()
    server = _server(hourly_cost=0.0)
    deployment = SimpleNamespace(deployment_id="deployment-old", server=server)
    gepetto.undeploy = AsyncMock()
    gepetto.load_chute = AsyncMock()
    gepetto.get_launch_token = AsyncMock()
    with (
        patch.object(
            gepetto_module,
            "get_session",
            _session_factory([_ScalarResult(scalar=deployment)]),
        ),
        patch.object(gepetto_module.k8s, "deploy_chute", new=AsyncMock()) as deploy,
    ):
        await gepetto.rolling_update(
            {
                "chute_id": "chute-1",
                "new_version": "2.0.0",
                "validator": VALIDATOR,
                "instance_id": "instance-1",
            }
        )
    gepetto.undeploy.assert_not_awaited()
    gepetto.get_launch_token.assert_not_awaited()
    deploy.assert_not_awaited()


@pytest.mark.asyncio
async def test_rolling_update_does_not_remove_cross_validator_server():
    gepetto = _gepetto()
    gepetto._scale_lock = __import__("asyncio").Lock()
    server = _server(validator="different-validator")
    deployment = SimpleNamespace(
        deployment_id="deployment-old",
        server=server,
    )
    gepetto.undeploy = AsyncMock()
    gepetto.load_chute = AsyncMock()
    gepetto.get_launch_token = AsyncMock()

    with (
        patch.object(
            gepetto_module,
            "get_session",
            _session_factory([_ScalarResult(scalar=deployment)]),
        ),
        patch.object(
            gepetto_module.k8s,
            "deploy_chute",
            new=AsyncMock(),
        ) as deploy,
    ):
        await gepetto.rolling_update(
            {
                "chute_id": "chute-1",
                "new_version": "2.0.0",
                "validator": VALIDATOR,
                "instance_id": "instance-1",
            }
        )

    gepetto.undeploy.assert_not_awaited()
    gepetto.get_launch_token.assert_not_awaited()
    deploy.assert_not_awaited()


class _ClaimSession:
    def __init__(self, claimed, *, chute, server, job_id=None):
        self.claimed = claimed
        self.added = []
        self.statement = None
        self.flushed = False
        self.committed = False
        lineage = {
            "schema": "chutes.miner-launch-lineage",
            "version": 1,
            "miner_hotkey": settings.miner_ss58,
            "validator": chute.validator,
            "chute_id": chute.chute_id,
            "chute_version": chute.version,
            "server_id": server.server_id,
            "kubernetes_node_uid": server.kubernetes_node_uid,
            "kubernetes_node_generation": server.kubernetes_node_generation,
            "gpu_allocation_group_id": server.gpu_allocation_group_id,
            "gpu_allocation_group_generation": server.gpu_allocation_group_generation,
            "job_id": job_id,
        }
        request = {
            "schema": "chutes.miner-launch-request.v1",
            "miner_launch_request_id": "launch-intent-1",
            "lineage": lineage,
        }
        self.intent = SimpleNamespace(
            intent_id="launch-intent-1",
            phase="registry_acked",
            validator=chute.validator,
            chute_id=chute.chute_id,
            chute_version=chute.version,
            server_id=server.server_id,
            job_id=job_id,
            job_cleanup_only=False,
            request_payload=request,
            request_sha256=canonical_miner_launch_sha256(request),
            lineage_sha256=canonical_miner_launch_sha256(lineage),
            response_payload={"config_id": None, "registry": None},
            authorized_token_sha256s=[hashlib.sha256(b"launch-token").hexdigest()],
            deployment_id=None,
            last_failure=None,
        )

    def add(self, value):
        self.added.append(value)

    async def flush(self):
        self.flushed = True

    async def execute(self, statement):
        self.statement = statement
        return SimpleNamespace(rowcount=self.claimed)

    async def scalar(self, _statement):
        return None

    async def get(self, _model, identity, **_kwargs):
        return self.intent if identity == "launch-intent-1" else None

    async def commit(self):
        self.committed = True


@pytest.mark.asyncio
async def test_atomic_gpu_claim_requires_unassigned_rows():
    operator = K8sOperator()
    chute = _chute(gpu_count=2)
    server = _server(
        gpus=[
            GPU(
                gpu_id=str(uuid.uuid4()),
                hardware_uuid=f"GPU-{uuid.uuid4()}",
                server_id="server-1",
                verified=True,
                deployment_id=None,
            )
            for _ in range(2)
        ]
    )
    available = {gpu.gpu_id for gpu in server.gpus}
    session = _ClaimSession(claimed=2, chute=chute, server=server)

    deployment_id, gpu_uuids = await operator._track_deployment(
        session,
        chute,
        server,
        available,
        launch_intent_id="launch-intent-1",
        launch_token_sha256=hashlib.sha256(b"launch-token").hexdigest(),
    )

    assert deployment_id
    assert len(gpu_uuids) == 2
    assert session.flushed
    assert session.committed
    assert len(session.added) == 2
    assert "gpus.deployment_id IS NULL" in str(session.statement)


@pytest.mark.asyncio
async def test_atomic_gpu_claim_fails_on_partial_contention():
    operator = K8sOperator()
    chute = _chute(gpu_count=2)
    server = _server(
        gpus=[
            GPU(
                gpu_id=str(uuid.uuid4()),
                hardware_uuid=f"GPU-{uuid.uuid4()}",
                server_id="server-1",
                verified=True,
                deployment_id=None,
            )
            for _ in range(2)
        ]
    )
    session = _ClaimSession(claimed=1, chute=chute, server=server)

    with pytest.raises(DeploymentFailure, match="Could only claim 1/2"):
        await operator._track_deployment(
            session,
            chute,
            server,
            {gpu.gpu_id for gpu in server.gpus},
            launch_intent_id="launch-intent-1",
            launch_token_sha256=hashlib.sha256(b"launch-token").hexdigest(),
        )

    assert not session.committed


@pytest.mark.asyncio
async def test_atomic_gpu_claim_rejects_token_not_returned_for_launch_intent():
    operator = K8sOperator()
    chute = _chute()
    server = _server(
        gpus=[
            GPU(
                gpu_id=str(uuid.uuid4()),
                hardware_uuid=f"GPU-{uuid.uuid4()}",
                server_id="server-1",
                verified=True,
                deployment_id=None,
            )
        ]
    )
    session = _ClaimSession(claimed=1, chute=chute, server=server)

    with pytest.raises(DeploymentFailure, match="launch intent lineage conflicts"):
        await operator._track_deployment(
            session,
            chute,
            server,
            {server.gpus[0].gpu_id},
            launch_intent_id="launch-intent-1",
            launch_token_sha256=hashlib.sha256(b"attacker-token").hexdigest(),
        )

    assert not session.added
    assert not session.committed


@pytest.mark.asyncio
async def test_atomic_gpu_claim_rejects_noncanonical_launch_intent_before_assignment():
    operator = K8sOperator()
    chute = _chute()
    server = _server(
        gpus=[
            GPU(
                gpu_id=str(uuid.uuid4()),
                hardware_uuid=f"GPU-{uuid.uuid4()}",
                server_id="server-1",
                verified=True,
                deployment_id=None,
            )
        ]
    )
    session = _ClaimSession(claimed=1, chute=chute, server=server)
    session.intent.request_sha256 = "0" * 64

    with pytest.raises(DeploymentFailure, match="launch intent lineage conflicts"):
        await operator._track_deployment(
            session,
            chute,
            server,
            {server.gpus[0].gpu_id},
            launch_intent_id="launch-intent-1",
            launch_token_sha256=hashlib.sha256(b"launch-token").hexdigest(),
        )

    assert session.statement is None
    assert not session.added
    assert not session.committed


def test_failed_pod_inventory_is_not_treated_as_empty(monkeypatch):
    class FailingK8s:
        def get_pods(self, **_kwargs):
            raise RuntimeError("cluster unavailable")

    monkeypatch.setattr(gepetto_module, "K8sOperator", FailingK8s)

    config_ids = Gepetto._k8s_config_ids()

    assert config_ids is None
    assert not Gepetto._config_id_is_orphaned("config-1", config_ids)
    assert Gepetto._config_id_is_orphaned("config-1", set())
