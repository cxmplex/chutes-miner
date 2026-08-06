"""Startup must not expose API workers or Gepetto before the exact schema exists."""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from chutes_miner.api import schema_barrier


@pytest.mark.asyncio
async def test_wait_blocks_until_exact_required_version(monkeypatch):
    observed = iter([False, False, True])
    checks: list[object] = []
    sleeps: list[float] = []

    async def fake_present(engine):
        checks.append(engine)
        return next(observed)

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(schema_barrier, "required_schema_is_present", fake_present)
    engine = object()
    await schema_barrier.wait_for_required_schema(
        engine,
        poll_seconds=0.125,
        sleep=fake_sleep,
    )

    assert checks == [engine, engine, engine]
    assert sleeps == [0.125, 0.125]


@pytest.mark.asyncio
async def test_every_worker_waits_for_exact_seedless_adoption(monkeypatch):
    observed = iter([False, True])
    sleeps: list[float] = []

    async def fake_present(_engine, identity):
        assert identity == {"server_id": "server-1"}
        return next(observed)

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(schema_barrier, "seedless_adoption_is_present", fake_present)
    blockers = AsyncMock(return_value=[])
    monkeypatch.setattr(schema_barrier, "seedless_adoption_blockers", blockers)
    engine = object()
    identity = {"server_id": "server-1"}
    await schema_barrier.wait_for_seedless_adoption(
        engine,
        identity,
        poll_seconds=0.125,
        sleep=fake_sleep,
    )
    assert sleeps == [0.125]
    blockers.assert_awaited_once_with(engine, identity)


@pytest.mark.asyncio
async def test_adoption_wait_allows_only_supplied_teardown_progress(monkeypatch):
    observed = iter([False, True])

    async def fake_present(_engine, _identity):
        return next(observed)

    monkeypatch.setattr(schema_barrier, "seedless_adoption_is_present", fake_present)
    monkeypatch.setattr(
        schema_barrier,
        "seedless_adoption_blockers",
        AsyncMock(return_value=[("stale-gpu", "deployment-live")]),
    )
    teardown = AsyncMock()
    sleep = AsyncMock()

    await schema_barrier.wait_for_seedless_adoption(
        object(),
        {"server_id": "server-1"},
        sleep=sleep,
        on_blocked=teardown,
    )

    teardown.assert_awaited_once()
    sleep.assert_not_awaited()


@pytest.mark.asyncio
async def test_adoption_wait_does_not_run_teardown_without_deployment_blockers(
    monkeypatch,
):
    observed = iter([False, True])

    async def fake_present(_engine, _identity):
        return next(observed)

    monkeypatch.setattr(schema_barrier, "seedless_adoption_is_present", fake_present)
    monkeypatch.setattr(
        schema_barrier,
        "seedless_adoption_blockers",
        AsyncMock(return_value=[]),
    )
    teardown = AsyncMock()
    sleep = AsyncMock()

    await schema_barrier.wait_for_seedless_adoption(
        object(),
        {"server_id": "server-1"},
        sleep=sleep,
        on_blocked=teardown,
    )

    teardown.assert_not_awaited()
    sleep.assert_awaited_once()


def test_barrier_uses_exact_version_not_maximum():
    sql = str(schema_barrier._REQUIRED_SCHEMA_VERSION_PRESENT)
    assert "WHERE version = :required_version" in sql
    assert "MAX(" not in sql.upper()
    assert schema_barrier.REQUIRED_SCHEMA_VERSION == "20260806120000"
    adoption_sql = str(schema_barrier._SEEDLESS_ADOPTION_PRESENT)
    assert "array_agg(gpu.hardware_uuid ORDER BY gpu.hardware_uuid)" in adoption_sql
    assert "server.registration_attestation_id = :attestation_id" in adoption_sql
    assert "server.gpu_allocation_group_generation" in adoption_sql
    assert "chutes/seedless-adopted" in adoption_sql
    blocker_sql = str(schema_barrier._SEEDLESS_ADOPTION_BLOCKERS)
    assert "gpu.deployment_id IS NOT NULL" in blocker_sql
    assert "canonical_gpu_ids" in blocker_sql


@pytest.mark.asyncio
async def test_active_stale_gpu_blockers_are_structured_for_readiness():
    captured = {}

    class Connection:
        async def execute(self, statement, parameters):
            captured["statement"] = statement
            captured["parameters"] = parameters
            return [
                SimpleNamespace(
                    gpu_id="stale-gpu",
                    deployment_id="deployment-live",
                )
            ]

    class Context:
        async def __aenter__(self):
            return Connection()

        async def __aexit__(self, *_args):
            return None

    class Engine:
        def connect(self):
            return Context()

    identity = {
        "server_id": "server-1",
        "validator": {"hotkey": "validator-1"},
        "attestation_id": "attestation-1",
        "allocation_group_id": "group-1",
        "allocation_group_generation": 3,
        "gpu_uuids": ["GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"],
    }
    assert await schema_barrier.seedless_adoption_blockers(Engine(), identity) == [
        ("stale-gpu", "deployment-live")
    ]
    assert captured["statement"] is schema_barrier._SEEDLESS_ADOPTION_BLOCKERS
    assert captured["parameters"]["server_id"] == "server-1"
    assert captured["parameters"]["gpu_uuids"] == identity["gpu_uuids"]
    assert len(captured["parameters"]["canonical_gpu_ids"]) == 1


@pytest.mark.asyncio
async def test_migration_leader_retries_only_deployment_owned_adoption_blockers(
    monkeypatch,
):
    from chutes_miner.api import main
    from chutes_miner.api.server.seedless_adoption import SeedlessAdoptionBlocked

    adoption = AsyncMock(
        side_effect=[
            SeedlessAdoptionBlocked("gpu=stale-gpu deployment=deployment-live"),
            "logical-server",
        ]
    )
    sleep = AsyncMock()
    monkeypatch.setattr(main, "adopt_seedless_gpu_server", adoption)
    monkeypatch.setattr(main.asyncio, "sleep", sleep)

    assert await main._adopt_seedless_gpu_server_with_retry() == "logical-server"
    assert adoption.await_count == 2
    sleep.assert_awaited_once_with(main.SEEDLESS_ADOPTION_RETRY_SECONDS)


@pytest.mark.asyncio
async def test_blocked_adoption_keeps_health_live_and_all_other_routes_unready():
    from chutes_miner.api import main

    state = SimpleNamespace(
        schema_ready=False,
        readiness_reason="seedless_adoption_blocked",
    )
    application = SimpleNamespace(state=state)
    blocked_request = SimpleNamespace(
        app=application,
        url=SimpleNamespace(path="/deployments"),
    )
    call_next = AsyncMock()

    response = await main.readiness_barrier(blocked_request, call_next)
    assert response.status_code == 503
    assert b"seedless_adoption_blocked" in response.body
    call_next.assert_not_awaited()

    health_request = SimpleNamespace(
        app=application,
        url=SimpleNamespace(path="/ready"),
    )
    health_response = await main.ready(health_request)
    assert health_response.status_code == 503
    assert b"seedless_adoption_blocked" in health_response.body

    ping_next = AsyncMock(return_value="pong")
    assert (
        await main.readiness_barrier(
            SimpleNamespace(app=application, url=SimpleNamespace(path="/ping")),
            ping_next,
        )
        == "pong"
    )
    ping_next.assert_awaited_once()


@pytest.mark.asyncio
async def test_background_adoption_opens_readiness_only_after_exact_barrier(
    monkeypatch,
):
    from chutes_miner.api import main

    application = SimpleNamespace(
        state=SimpleNamespace(
            schema_ready=False,
            readiness_reason="seedless_adoption_blocked",
            socket_tasks=[],
        )
    )
    identity = {"server_id": "logical-server"}
    adopt = AsyncMock(return_value="logical-server")
    barrier = AsyncMock()
    monkeypatch.setattr(main, "_adopt_seedless_gpu_server_with_retry", adopt)
    monkeypatch.setattr(main, "wait_for_seedless_adoption", barrier)
    monkeypatch.setattr(main, "_start_socket_clients", lambda: [])
    monkeypatch.setattr(
        main,
        "settings",
        SimpleNamespace(seedless_gpu_identity=identity),
    )

    await main._complete_blocked_leader_readiness(application)

    adopt.assert_awaited_once()
    barrier.assert_awaited_once_with(main.engine, identity)
    assert application.state.schema_ready is True
    assert application.state.readiness_reason is None


@pytest.mark.asyncio
async def test_background_nonblocker_failure_closes_liveness_for_restart(monkeypatch):
    from chutes_miner.api import main

    application = SimpleNamespace(
        state=SimpleNamespace(
            schema_ready=False,
            readiness_reason="seedless_adoption_blocked",
            socket_tasks=[],
        )
    )
    monkeypatch.setattr(
        main,
        "_adopt_seedless_gpu_server_with_retry",
        AsyncMock(side_effect=RuntimeError("database invariant failed")),
    )

    await main._complete_blocked_leader_readiness(application)

    assert application.state.schema_ready is False
    assert application.state.readiness_reason == "seedless_adoption_failed"
    response = await main.ping(SimpleNamespace(app=application))
    assert response.status_code == 500
    assert b"seedless_adoption_failed" in response.body


def test_all_api_workers_and_gepetto_wait_before_work():
    from chutes_miner import gepetto
    from chutes_miner.api import main

    lifespan_source = inspect.getsource(main.lifespan)
    nonleader = lifespan_source.index("if not is_migration_process:")
    nonleader_schema = lifespan_source.index(
        "await wait_for_required_schema(engine)", nonleader
    )
    nonleader_background = lifespan_source.index(
        "_complete_follower_readiness(application)", nonleader_schema
    )
    nonleader_yield = lifespan_source.index("yield", nonleader_background)
    assert nonleader_schema < nonleader_background < nonleader_yield

    leader_schema = lifespan_source.index(
        "await wait_for_required_schema(engine)", nonleader_schema + 1
    )
    direct_adoption = lifespan_source.index(
        "server_id = await adopt_seedless_gpu_server()", leader_schema
    )
    typed_blocker = lifespan_source.index(
        "except SeedlessAdoptionBlocked as exc:", direct_adoption
    )
    blocked_background = lifespan_source.index(
        "_complete_blocked_leader_readiness(application)", typed_blocker
    )
    leader_yield = lifespan_source.index("yield", blocked_background)
    assert (
        leader_schema
        < direct_adoption
        < typed_blocker
        < blocked_background
        < leader_yield
    )

    run_source = inspect.getsource(gepetto.Gepetto.run)
    assert "Base.metadata.create_all" not in run_source
    schema_wait = run_source.index("await wait_for_required_schema(engine)")
    adoption_wait = run_source.index("await wait_for_seedless_adoption(")
    teardown_only_progress = run_source.index(
        "on_blocked=self.teardown.resume_pending", adoption_wait
    )
    validator_migrations = run_source.index("await run_validator_migrations()")
    launch_resume = run_source.index("await self.resume_launch_intents()")
    normal_teardown_resume = run_source.index("await self.teardown.resume_pending()")
    scope_rebuild = run_source.index(
        "await self.reconcile_registry_scope_intents(reconstruct_active=True)"
    )
    assert (
        schema_wait
        < adoption_wait
        < teardown_only_progress
        < validator_migrations
        < launch_resume
        < normal_teardown_resume
        < scope_rebuild
    )


@pytest.mark.asyncio
async def test_gepetto_mutators_stay_blocked_until_seedless_adoption(monkeypatch):
    from chutes_miner import gepetto

    adoption_started = asyncio.Event()
    release_adoption = asyncio.Event()

    async def wait_for_adoption(_engine, identity, *, on_blocked=None):
        assert identity == {"server_id": "server-1"}
        assert on_blocked is not None
        adoption_started.set()
        await on_blocked()
        await release_adoption.wait()

    monkeypatch.setattr(gepetto, "wait_for_required_schema", AsyncMock())
    monkeypatch.setattr(gepetto, "wait_for_seedless_adoption", wait_for_adoption)
    monkeypatch.setattr(
        gepetto,
        "settings",
        SimpleNamespace(
            gpu_tee_only=True,
            seedless_gpu_identity={"server_id": "server-1"},
            validator_migrations_enabled=False,
            registry_workload_token="w" * 64,
        ),
    )
    monkeypatch.setattr(gepetto.k8s, "purge_legacy_source_config_maps", AsyncMock())
    coordinator = object.__new__(gepetto.Gepetto)
    coordinator.resume_launch_intents = AsyncMock()
    coordinator.teardown = SimpleNamespace(resume_pending=AsyncMock())
    coordinator.reconcile_registry_scope_intents = AsyncMock()
    coordinator.reconcile = AsyncMock()
    coordinator.autoscaler = AsyncMock()
    coordinator.reconciler = AsyncMock()
    coordinator.pubsub = SimpleNamespace(start=AsyncMock())

    task = asyncio.create_task(coordinator.run())
    await adoption_started.wait()
    coordinator.resume_launch_intents.assert_not_awaited()
    coordinator.teardown.resume_pending.assert_awaited_once()
    coordinator.reconcile.assert_not_awaited()

    release_adoption.set()
    coordinator.reconcile_registry_scope_intents.assert_not_awaited()
    await task
    coordinator.resume_launch_intents.assert_awaited_once()
    assert coordinator.teardown.resume_pending.await_count == 2
    coordinator.reconcile.assert_awaited_once()
    coordinator.reconcile_registry_scope_intents.assert_awaited_once_with(
        reconstruct_active=True
    )


def test_api_chart_keeps_liveness_open_and_readiness_schema_gated():
    chart = (
        Path(__file__).resolve().parents[2]
        / "charts/chutes-miner/templates/api-deployment.yaml"
    ).read_text(encoding="utf-8")
    assert "livenessProbe:" in chart
    assert "path: /ping" in chart
    assert "readinessProbe:" in chart
    assert "path: /ready" in chart
    assert "startupProbe:" in chart
    assert "failureThreshold: 180" in chart
