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
    await schema_barrier.wait_for_seedless_adoption(
        object(),
        {"server_id": "server-1"},
        poll_seconds=0.125,
        sleep=fake_sleep,
    )
    assert sleeps == [0.125]


def test_barrier_uses_exact_version_not_maximum():
    sql = str(schema_barrier._REQUIRED_SCHEMA_VERSION_PRESENT)
    assert "WHERE version = :required_version" in sql
    assert "MAX(" not in sql.upper()
    assert schema_barrier.REQUIRED_SCHEMA_VERSION == "20260727120000"
    adoption_sql = str(schema_barrier._SEEDLESS_ADOPTION_PRESENT)
    assert "array_agg(gpu.hardware_uuid ORDER BY gpu.hardware_uuid)" in adoption_sql
    assert "server.registration_attestation_id = :attestation_id" in adoption_sql
    assert "server.gpu_allocation_group_generation" in adoption_sql
    assert "chutes/seedless-adopted" in adoption_sql


def test_all_api_workers_and_gepetto_wait_before_work():
    from chutes_miner.api import main
    from chutes_miner import gepetto

    lifespan_source = inspect.getsource(main.lifespan)
    nonleader = lifespan_source.index("if not is_migration_process:")
    nonleader_wait = lifespan_source.index(
        "await wait_for_required_schema(engine)",
        nonleader,
    )
    nonleader_adoption = lifespan_source.index(
        "await wait_for_seedless_adoption(engine, settings.seedless_gpu_identity)",
        nonleader_wait,
    )
    nonleader_yield = lifespan_source.index("yield", nonleader)
    assert nonleader_wait < nonleader_adoption < nonleader_yield

    leader_wait = lifespan_source.index(
        "await wait_for_required_schema(engine)",
        nonleader_wait + 1,
    )
    adoption = lifespan_source.index("await adopt_seedless_gpu_server()")
    leader_adoption_barrier = lifespan_source.index(
        "await wait_for_seedless_adoption(engine, settings.seedless_gpu_identity)",
        nonleader_adoption + 1,
    )
    assert leader_wait < adoption < leader_adoption_barrier

    run_source = inspect.getsource(gepetto.Gepetto.run)
    assert "Base.metadata.create_all" not in run_source
    gepetto_wait = run_source.index("await wait_for_required_schema(engine)")
    gepetto_adoption = run_source.index(
        "await wait_for_seedless_adoption(engine, settings.seedless_gpu_identity)"
    )
    validator_migrations = run_source.index("await run_validator_migrations()")
    launch_resume = run_source.index("await self.resume_launch_intents()")
    resume = run_source.index("await self.teardown.resume_pending()")
    assert gepetto_wait < gepetto_adoption < validator_migrations < launch_resume < resume


@pytest.mark.asyncio
async def test_gepetto_mutators_stay_blocked_until_seedless_adoption(monkeypatch):
    from chutes_miner import gepetto

    adoption_started = asyncio.Event()
    release_adoption = asyncio.Event()

    async def wait_for_adoption(_engine, identity):
        assert identity == {"server_id": "server-1"}
        adoption_started.set()
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
        ),
    )
    monkeypatch.setattr(gepetto.k8s, "purge_legacy_source_config_maps", AsyncMock())
    coordinator = object.__new__(gepetto.Gepetto)
    coordinator.resume_launch_intents = AsyncMock()
    coordinator.teardown = SimpleNamespace(resume_pending=AsyncMock())
    coordinator.reconcile = AsyncMock()
    coordinator.autoscaler = AsyncMock()
    coordinator.reconciler = AsyncMock()
    coordinator.pubsub = SimpleNamespace(start=AsyncMock())

    task = asyncio.create_task(coordinator.run())
    await adoption_started.wait()
    coordinator.resume_launch_intents.assert_not_awaited()
    coordinator.teardown.resume_pending.assert_not_awaited()
    coordinator.reconcile.assert_not_awaited()

    release_adoption.set()
    await task
    coordinator.resume_launch_intents.assert_awaited_once()
    coordinator.teardown.resume_pending.assert_awaited_once()
    coordinator.reconcile.assert_awaited_once()


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
