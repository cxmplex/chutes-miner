"""Real PostgreSQL barriers for placement versus orphan terminalization."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock
import uuid

import chutes_common.schemas.orms  # noqa: F401
import pytest
import chutes_miner.api.deployment.teardown as deployment_teardown_module
import chutes_miner.gepetto as gepetto_module
from chutes_common.schemas import Base
from chutes_common.schemas.chute import Chute
from chutes_common.schemas.deployment import Deployment
from chutes_common.schemas.gpu import GPU
from chutes_common.schemas.server import Server, ServerNodeIdentity
from chutes_common.schemas.teardown import (
    DeploymentLaunchOperation,
    DeploymentTeardownOperation,
    KubernetesOrphanTombstone,
    MinerLaunchIntent,
    RegistryScopeIntent,
)
from chutes_miner.api.config import settings
from chutes_miner.api.deployment.teardown import (
    DeploymentTeardownCoordinator,
    LineageConflict,
    cluster_context_sha256,
)
from chutes_miner.api.exceptions import DeploymentFailure
from chutes_miner.api.k8s.operator import K8sOperator
from chutes_miner.api.k8s.util import canonical_miner_launch_sha256
from chutes_miner.api.registry_scopes import RegistryScopeWorkItem
from chutes_miner.gepetto import Gepetto
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for orphan placement fence barriers",
)

DEPLOYMENT_ID = "11111111-1111-4111-8111-111111111111"
LAUNCH_INTENT_ID = "launch-intent-1"
LAUNCH_LEASE_OWNER = "placement-worker-1"
LAUNCH_TOKEN_SHA256 = hashlib.sha256(b"placement-token").hexdigest()
PLACEMENT_CONFIG_ID = "config-1"


def _asyncpg_url() -> str:
    assert TEST_DATABASE_URL is not None
    if TEST_DATABASE_URL.startswith("postgresql+asyncpg://"):
        return TEST_DATABASE_URL
    return TEST_DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)


@asynccontextmanager
async def _isolated_database():
    schema = f"orphan_placement_fence_{uuid.uuid4().hex}"
    admin = create_async_engine(_asyncpg_url())
    engine = create_async_engine(
        _asyncpg_url(),
        pool_size=4,
        max_overflow=0,
        connect_args={"server_settings": {"search_path": schema}},
    )
    try:
        async with admin.begin() as connection:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await admin.dispose()


async def _seed_orphan(
    session_factory,
    worker_id: str,
    *,
    include_tombstone: bool = True,
) -> None:
    server = Server(
        server_id="server-1",
        validator="validator-1",
        name="node-a",
        ip_address="192.0.2.1",
        status="active",
        labels={},
        gpu_count=1,
        cpu_per_gpu=1,
        memory_per_gpu=1,
        hourly_cost=1.0,
        kubeconfig="exact-kubeconfig",
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
        gpu_allocation_group_id="group-1",
        gpu_allocation_group_generation=1,
    )
    chute = Chute(
        chute_id="chute-1",
        validator="validator-1",
        name="chute",
        image="owner/image:tag",
        ref_str="chute:chute",
        version="1.0.0",
        supported_gpus=["h100"],
        gpu_count=1,
        chutes_version="0.8.0",
    )
    tombstone = KubernetesOrphanTombstone(
        tombstone_id="tombstone-1",
        deployment_id=DEPLOYMENT_ID,
        cluster_context="node-a",
        cluster_context_sha256=cluster_context_sha256(server),
        namespace=settings.namespace,
        kubernetes_node_uid="node-uid-1",
        kubernetes_node_generation=3,
        phase="verifying",
        retry_lease_owner=worker_id,
        retry_lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        immutable_labels={
            "chutes/deployment-id": DEPLOYMENT_ID,
            "chutes/chute-id": "chute-1",
            "chutes/config-id": "config-1",
        },
    )
    gpu = GPU(
        gpu_id="gpu-1",
        hardware_uuid="GPU-11111111-1111-4111-8111-111111111111",
        validator="validator-1",
        server_id="server-1",
        deployment_id=None,
        device_info={},
        model_short_ref="h100",
        verified=True,
        gpu_allocation_group_id="group-1",
        gpu_allocation_group_generation=1,
    )
    lineage = {
        "schema": "chutes.miner-launch-lineage",
        "version": 1,
        "deployment_id": DEPLOYMENT_ID,
        "miner_hotkey": settings.miner_ss58,
        "validator": "validator-1",
        "chute_id": "chute-1",
        "chute_version": "1.0.0",
        "server_id": "server-1",
        "kubernetes_node_uid": "node-uid-1",
        "kubernetes_node_generation": 3,
        "gpu_allocation_group_id": "group-1",
        "gpu_allocation_group_generation": 1,
        "job_id": None,
    }
    request = {
        "schema": "chutes.miner-launch-request.v1",
        "miner_launch_request_id": LAUNCH_INTENT_ID,
        "lineage": lineage,
    }
    response = {"config_id": PLACEMENT_CONFIG_ID, "registry": None}
    intent = MinerLaunchIntent(
        intent_id=LAUNCH_INTENT_ID,
        phase="registry_acked",
        validator="validator-1",
        chute_id="chute-1",
        chute_version="1.0.0",
        server_id="server-1",
        job_id=None,
        job_cleanup_only=False,
        request_payload=request,
        request_sha256=canonical_miner_launch_sha256(request),
        lineage_sha256=canonical_miner_launch_sha256(lineage),
        response_payload=response,
        response_sha256=canonical_miner_launch_sha256(response),
        token_sha256=LAUNCH_TOKEN_SHA256,
        authorized_token_sha256s=[LAUNCH_TOKEN_SHA256],
        registry_ack={
            "registered": False,
            "launch_config_id": PLACEMENT_CONFIG_ID,
            "status": "not_required",
        },
        deployment_id=DEPLOYMENT_ID,
        retry_lease_owner=LAUNCH_LEASE_OWNER,
        retry_lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        attempt_count=1,
        next_retry_at=None,
        last_failure=None,
    )
    async with session_factory() as session:
        rows = [server, chute, gpu, intent]
        if include_tombstone:
            rows.append(tombstone)
        session.add_all(rows)
        await session.commit()


async def _locked_server(session):
    return (
        (
            await session.execute(
                select(Server)
                .where(Server.server_id == "server-1")
                .with_for_update(of=Server)
            )
        )
        .unique()
        .scalar_one()
    )


class _ObservedServerLockSession:
    def __init__(
        self,
        session,
        server_lock_attempted: asyncio.Event,
        registry_lock_attempted: asyncio.Event | None = None,
    ):
        self._session = session
        self._server_lock_attempted = server_lock_attempted
        self._registry_lock_attempted = registry_lock_attempted

    def __getattr__(self, name):
        return getattr(self._session, name)

    async def execute(self, statement):
        if "FROM servers" in str(statement) and "FOR UPDATE" in str(statement):
            self._server_lock_attempted.set()
        return await self._session.execute(statement)

    async def get(self, model, identity, **kwargs):
        if (
            model is RegistryScopeIntent
            and kwargs.get("with_for_update") is True
            and self._registry_lock_attempted is not None
        ):
            self._registry_lock_attempted.set()
        return await self._session.get(model, identity, **kwargs)


@pytest.mark.asyncio
async def test_finalizer_waits_for_placement_insert_then_refuses_terminalization(
    monkeypatch,
):
    """A placement committed ahead of the fence must keep the orphan open."""

    monkeypatch.setattr(settings, "gpu_tee_only", False)
    coordinator = DeploymentTeardownCoordinator()
    async with _isolated_database() as session_factory:
        await _seed_orphan(session_factory, coordinator.worker_id)
        finalizer_server_lock_attempted = asyncio.Event()

        async def finalize():
            async with session_factory() as session:
                tombstone = await session.get(
                    KubernetesOrphanTombstone,
                    "tombstone-1",
                )
                observed = _ObservedServerLockSession(
                    session,
                    finalizer_server_lock_attempted,
                )
                await coordinator._complete_orphan_in_session(observed, tombstone)
                await session.commit()

        async with session_factory() as placement_session:
            await _locked_server(placement_session)
            placement_session.add(
                Deployment(
                    deployment_id=DEPLOYMENT_ID,
                    validator="validator-1",
                    server_id="server-1",
                    chute_id="chute-1",
                    version="1.0.0",
                    active=False,
                    stub=True,
                    config_id="config-1",
                )
            )
            await placement_session.flush()
            finalizer = asyncio.create_task(finalize())
            await asyncio.wait_for(finalizer_server_lock_attempted.wait(), timeout=1)
            await asyncio.sleep(0.05)
            assert finalizer.done() is False
            await placement_session.commit()

        with pytest.raises(
            LineageConflict,
            match="Deployment appeared before orphan completion",
        ):
            await finalizer

        async with session_factory() as session:
            tombstone = await session.get(
                KubernetesOrphanTombstone,
                "tombstone-1",
            )
            assert tombstone.phase == "verifying"
            assert tombstone.completed_at is None
            assert (
                await session.scalar(select(func.count()).select_from(Deployment)) == 1
            )
            assert (
                await session.scalar(
                    select(func.count()).select_from(RegistryScopeIntent)
                )
                == 0
            )


@pytest.mark.asyncio
async def test_placement_waits_for_finalizer_then_rejects_completed_tombstone(
    monkeypatch,
):
    """Terminal deletion history remains a fence after finalization commits."""

    monkeypatch.setattr(settings, "gpu_tee_only", False)
    coordinator = DeploymentTeardownCoordinator()
    operator = K8sOperator()
    async with _isolated_database() as session_factory:
        await _seed_orphan(session_factory, coordinator.worker_id)
        placement_server_lock_attempted = asyncio.Event()
        placement_acquired = asyncio.Event()

        async def place():
            async with session_factory() as session:
                observed = _ObservedServerLockSession(
                    session,
                    placement_server_lock_attempted,
                )
                server = await operator._get_server(observed, "server-1")
                placement_acquired.set()
                chute = await session.get(Chute, "chute-1")
                assert chute is not None
                available_gpus = operator._verify_gpus(chute, server)
                await operator._track_deployment(
                    observed,
                    chute,
                    server,
                    available_gpus,
                    config_id=PLACEMENT_CONFIG_ID,
                    registry_repository=None,
                    registry_manifest_digest=None,
                    launch_intent_id=LAUNCH_INTENT_ID,
                    launch_intent_lease_owner=LAUNCH_LEASE_OWNER,
                    launch_token_sha256=LAUNCH_TOKEN_SHA256,
                )

        async with session_factory() as finalizer_session:
            await _locked_server(finalizer_session)
            tombstone = await finalizer_session.get(
                KubernetesOrphanTombstone,
                "tombstone-1",
            )
            placement = asyncio.create_task(place())
            await asyncio.wait_for(placement_server_lock_attempted.wait(), timeout=1)
            await asyncio.sleep(0.05)
            assert placement_acquired.is_set() is False
            await coordinator._complete_orphan_in_session(
                finalizer_session,
                tombstone,
            )
            await finalizer_session.commit()

        with pytest.raises(DeploymentFailure, match="fenced by orphan cleanup"):
            await placement

        async with session_factory() as session:
            tombstone = await session.get(
                KubernetesOrphanTombstone,
                "tombstone-1",
            )
            assert tombstone.phase == "completed"
            assert tombstone.completed_at is not None
            assert (
                await session.scalar(select(func.count()).select_from(Deployment)) == 0
            )
            assert (
                await session.scalar(
                    select(func.count()).select_from(DeploymentLaunchOperation)
                )
                == 0
            )
            assert (
                await session.scalar(
                    select(func.count()).select_from(RegistryScopeIntent)
                )
                == 0
            )
            gpu = await session.get(GPU, "gpu-1")
            assert gpu.deployment_id is None
            intent = await session.get(MinerLaunchIntent, LAUNCH_INTENT_ID)
            assert intent.phase == "registry_acked"
            assert intent.retry_lease_owner == LAUNCH_LEASE_OWNER


@pytest.mark.asyncio
async def test_orphan_recovery_waits_on_server_before_locking_tombstone(
    monkeypatch,
):
    """Recovery cannot recreate the tombstone -> Server deadlock cycle."""

    monkeypatch.setattr(settings, "gpu_tee_only", False)
    coordinator = DeploymentTeardownCoordinator()
    async with _isolated_database() as session_factory:
        await _seed_orphan(session_factory, coordinator.worker_id)
        server_lock_attempted = asyncio.Event()

        class ObservedSession:
            def __init__(self, session):
                self._session = session

            def __getattr__(self, name):
                return getattr(self._session, name)

            async def scalar(self, statement):
                if "FROM servers" in str(statement) and "FOR UPDATE" in str(statement):
                    server_lock_attempted.set()
                return await self._session.scalar(statement)

        async def recover():
            async with session_factory() as session:
                return await coordinator._lineage_recovery_row(
                    ObservedSession(session),
                    "orphan",
                    "tombstone-1",
                )

        async with session_factory() as placement_session:
            await _locked_server(placement_session)
            recovery = asyncio.create_task(recover())
            await asyncio.wait_for(server_lock_attempted.wait(), timeout=1)
            await asyncio.sleep(0.05)
            assert recovery.done() is False

            # Recovery is blocked on Server and therefore cannot already own
            # the tombstone. A third transaction can still lock it NOWAIT.
            async with session_factory() as probe_session:
                probe = (
                    await probe_session.execute(
                        select(KubernetesOrphanTombstone)
                        .where(KubernetesOrphanTombstone.tombstone_id == "tombstone-1")
                        .with_for_update(nowait=True)
                    )
                ).scalar_one()
                assert probe.tombstone_id == "tombstone-1"
                await probe_session.rollback()

            await placement_session.commit()

        recovered = await asyncio.wait_for(recovery, timeout=2)
        assert recovered.tombstone_id == "tombstone-1"


@pytest.mark.asyncio
async def test_orphan_recovery_rejects_deployment_before_registry_lock(
    monkeypatch,
):
    """Recovery breaks the normal teardown Registry -> Server wait cycle."""

    monkeypatch.setattr(settings, "gpu_tee_only", True)
    coordinator = DeploymentTeardownCoordinator()
    async with _isolated_database() as session_factory:
        await _seed_orphan(session_factory, coordinator.worker_id)
        async with session_factory() as seed_session:
            seed_session.add_all(
                [
                    Deployment(
                        deployment_id=DEPLOYMENT_ID,
                        validator="validator-1",
                        server_id="server-1",
                        chute_id="chute-1",
                        version="1.0.0",
                        active=False,
                        stub=True,
                        config_id="config-1",
                    ),
                    RegistryScopeIntent(
                        launch_config_id="config-1",
                        validator="validator-1",
                        desired_state="revoked",
                        phase="revoked",
                        revocation_ack={"revoked": True},
                        revoked_at=datetime.now(timezone.utc),
                    ),
                ]
            )
            await seed_session.commit()

        normal_rows_locked = asyncio.Event()
        recovery_server_locked = asyncio.Event()
        normal_server_attempted = asyncio.Event()
        normal_server_acquired = asyncio.Event()

        class ObservedRecoverySession:
            def __init__(self, session):
                self._session = session

            def __getattr__(self, name):
                return getattr(self._session, name)

            async def scalar(self, statement):
                result = await self._session.scalar(statement)
                if "FROM servers" in str(statement) and "FOR UPDATE" in str(statement):
                    recovery_server_locked.set()
                    await normal_server_attempted.wait()
                    await asyncio.sleep(0.05)
                    assert normal_server_acquired.is_set() is False
                return result

        async def normal_teardown():
            async with session_factory() as session:
                await session.execute(
                    select(Deployment)
                    .where(Deployment.deployment_id == DEPLOYMENT_ID)
                    .with_for_update(of=Deployment)
                )
                await session.get(
                    RegistryScopeIntent,
                    "config-1",
                    with_for_update=True,
                )
                normal_rows_locked.set()
                await recovery_server_locked.wait()
                normal_server_attempted.set()
                await _locked_server(session)
                normal_server_acquired.set()
                await session.rollback()

        async def recover():
            await normal_rows_locked.wait()
            async with session_factory() as session:
                with pytest.raises(
                    LineageConflict,
                    match="conflicts with a local Deployment",
                ):
                    await coordinator._lineage_recovery_row(
                        ObservedRecoverySession(session),
                        "orphan",
                        "tombstone-1",
                    )

        normal = asyncio.create_task(normal_teardown())
        recovery = asyncio.create_task(recover())
        await asyncio.wait_for(recovery, timeout=2)
        await asyncio.wait_for(normal, timeout=2)
        assert normal_server_acquired.is_set()


@pytest.mark.asyncio
async def test_duplicate_placement_rejects_before_teardown_owned_intent_lock(
    monkeypatch,
):
    """A duplicate cannot deadlock Server against teardown's intent lock."""

    monkeypatch.setattr(settings, "gpu_tee_only", True)
    coordinator = DeploymentTeardownCoordinator()
    operator = K8sOperator()
    digest = f"sha256:{'a' * 64}"
    repository = "owner/image"
    async with _isolated_database() as session_factory:
        await _seed_orphan(
            session_factory,
            coordinator.worker_id,
            include_tombstone=False,
        )
        async with session_factory() as seed_session:
            server = await seed_session.get(Server, "server-1")
            intent = await seed_session.get(MinerLaunchIntent, LAUNCH_INTENT_ID)
            gpu = await seed_session.get(GPU, "gpu-1")
            assert server is not None and intent is not None and gpu is not None
            server.registration_attestation_id = "attestation-1"
            gpu.deployment_id = DEPLOYMENT_ID
            response = {
                "config_id": PLACEMENT_CONFIG_ID,
                "registry": {
                    "repository": repository,
                    "manifest_digest": digest,
                },
            }
            ack = {
                "registered": True,
                "launch_config_id": PLACEMENT_CONFIG_ID,
                "expires_at": (
                    datetime.now(timezone.utc) + timedelta(hours=1)
                ).isoformat(),
            }
            intent.response_payload = response
            intent.response_sha256 = canonical_miner_launch_sha256(response)
            intent.registry_ack = ack
            # Exact state committed by successful production _track_deployment.
            # A duplicate must reject the Deployment without waiting to lock
            # this consumed intent behind teardown.
            intent.phase = "consumed"
            intent.retry_lease_owner = None
            intent.retry_lease_expires_at = None
            launch = DeploymentLaunchOperation(
                operation_id="launch-operation-1",
                deployment_id=DEPLOYMENT_ID,
                phase="created",
                immutable_labels={
                    "chutes/deployment-id": DEPLOYMENT_ID,
                    "chutes/chute-id": "chute-1",
                    "chutes/config-id": PLACEMENT_CONFIG_ID,
                },
                launch_intent_id=LAUNCH_INTENT_ID,
                cluster_context="node-a",
                cluster_context_sha256=cluster_context_sha256(server),
                namespace=settings.namespace,
                server_name="node-a",
                create_results={},
            )
            seed_session.add_all(
                [
                    ServerNodeIdentity(
                        server_id="server-1",
                        generation=3,
                        kubernetes_node_uid="node-uid-1",
                        registration_attestation_id="attestation-1",
                    ),
                    RegistryScopeIntent(
                        launch_config_id=PLACEMENT_CONFIG_ID,
                        launch_intent_id=LAUNCH_INTENT_ID,
                        deployment_id=DEPLOYMENT_ID,
                        validator="validator-1",
                        server_id="server-1",
                        repository=repository,
                        manifest_digest=digest,
                        desired_state="active",
                        phase="active",
                        registration_ack=ack,
                        registered_at=datetime.now(timezone.utc),
                    ),
                    launch,
                    Deployment(
                        deployment_id=DEPLOYMENT_ID,
                        validator="validator-1",
                        server_id="server-1",
                        chute_id="chute-1",
                        version="1.0.0",
                        active=False,
                        stub=True,
                        config_id=PLACEMENT_CONFIG_ID,
                        registry_repository=repository,
                        registry_manifest_digest=digest,
                        launch_operation_id=launch.operation_id,
                    ),
                ]
            )
            await seed_session.commit()

        teardown_server_lock_attempted = asyncio.Event()

        @asynccontextmanager
        async def observed_teardown_session():
            async with session_factory() as session:
                yield _ObservedServerLockSession(
                    session,
                    teardown_server_lock_attempted,
                )

        monkeypatch.setattr(
            deployment_teardown_module,
            "get_session",
            observed_teardown_session,
        )

        async with session_factory() as placement_session:
            server = await _locked_server(placement_session)
            chute = await placement_session.get(Chute, "chute-1")
            assert chute is not None
            teardown = asyncio.create_task(
                coordinator.request(DEPLOYMENT_ID, "duplicate-placement-barrier")
            )
            await asyncio.wait_for(teardown_server_lock_attempted.wait(), timeout=1)
            await asyncio.sleep(0.05)
            assert teardown.done() is False

            with pytest.raises(
                DeploymentFailure,
                match="deployment already exists",
            ):
                await asyncio.wait_for(
                    operator._track_deployment(
                        placement_session,
                        chute,
                        server,
                        {"gpu-1"},
                        config_id=PLACEMENT_CONFIG_ID,
                        registry_repository=repository,
                        registry_manifest_digest=digest,
                        launch_intent_id=LAUNCH_INTENT_ID,
                        launch_intent_lease_owner=LAUNCH_LEASE_OWNER,
                        launch_token_sha256=LAUNCH_TOKEN_SHA256,
                    ),
                    timeout=1,
                )
            assert teardown.done() is False

        operation_id = await asyncio.wait_for(teardown, timeout=2)
        assert operation_id is not None
        async with session_factory() as session:
            assert (
                await session.scalar(select(func.count()).select_from(Deployment)) == 1
            )
            assert (
                await session.scalar(
                    select(func.count()).select_from(DeploymentLaunchOperation)
                )
                == 1
            )
            assert (
                await session.scalar(
                    select(func.count()).select_from(DeploymentTeardownOperation)
                )
                == 1
            )
            gpu = await session.get(GPU, "gpu-1")
            assert gpu.deployment_id == DEPLOYMENT_ID


@pytest.mark.asyncio
async def test_failed_reconstruction_wakes_production_placement_to_pending(
    monkeypatch,
):
    """Pending commits before POST; a waiting real placement loses cleanly."""

    monkeypatch.setattr(settings, "gpu_tee_only", True)
    monkeypatch.setattr(gepetto_module.settings, "gpu_tee_only", True)
    operator = K8sOperator()
    reconciler = object.__new__(Gepetto)
    digest = f"sha256:{'a' * 64}"
    repository = "owner/image"
    ack = {
        "registered": True,
        "launch_config_id": PLACEMENT_CONFIG_ID,
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    }

    async with _isolated_database() as session_factory:
        await _seed_orphan(
            session_factory,
            "unused-worker",
            include_tombstone=False,
        )
        async with session_factory() as seed_session:
            intent = await seed_session.get(MinerLaunchIntent, LAUNCH_INTENT_ID)
            response = {
                "config_id": PLACEMENT_CONFIG_ID,
                "registry": {
                    "repository": repository,
                    "manifest_digest": digest,
                },
            }
            intent.response_payload = response
            intent.response_sha256 = canonical_miner_launch_sha256(response)
            intent.registry_ack = ack
            seed_session.add(
                RegistryScopeIntent(
                    launch_config_id=PLACEMENT_CONFIG_ID,
                    launch_intent_id=LAUNCH_INTENT_ID,
                    deployment_id=DEPLOYMENT_ID,
                    validator="validator-1",
                    server_id="server-1",
                    repository=repository,
                    manifest_digest=digest,
                    desired_state="active",
                    phase="active",
                    registration_ack=ack,
                    registered_at=datetime.now(timezone.utc),
                    attempt_count=0,
                    next_retry_at=None,
                    last_failure=None,
                )
            )
            await seed_session.commit()

        pending_commit_entered = asyncio.Event()
        allow_pending_commit = asyncio.Event()
        placement_finished = asyncio.Event()
        placement_server_lock_attempted = asyncio.Event()
        placement_registry_lock_attempted = asyncio.Event()
        post_started = asyncio.Event()
        reconciliation_session_count = 0

        class PendingCommitSession:
            def __init__(self, session):
                self._session = session

            def __getattr__(self, name):
                return getattr(self._session, name)

            async def commit(self):
                pending_commit_entered.set()
                await allow_pending_commit.wait()
                await self._session.commit()
                # Keep reconstruction before POST until the placement that was
                # queued on this row lock has observed durable pending.
                await placement_finished.wait()

        @asynccontextmanager
        async def reconciliation_session():
            nonlocal reconciliation_session_count
            async with session_factory() as session:
                reconciliation_session_count += 1
                if reconciliation_session_count == 1:
                    yield PendingCommitSession(session)
                else:
                    yield session

        async def fail_registration(_validator, _body):
            post_started.set()
            # Transaction 1 released its row lock before external I/O.
            async with session_factory() as probe_session:
                scope = (
                    await probe_session.execute(
                        select(RegistryScopeIntent)
                        .where(
                            RegistryScopeIntent.launch_config_id == PLACEMENT_CONFIG_ID
                        )
                        .with_for_update(nowait=True)
                    )
                ).scalar_one()
                assert scope.phase == "register_pending"
                assert scope.attempt_count == 1
                await probe_session.rollback()
            raise TimeoutError("ambiguous registry POST")

        monkeypatch.setattr(gepetto_module, "get_session", reconciliation_session)
        monkeypatch.setattr(
            gepetto_module,
            "validator_by_hotkey",
            lambda hotkey: SimpleNamespace(hotkey=hotkey),
        )
        reconciler._send_registry_scope_registration = fail_registration
        reconciler._send_registry_scope_revocation = AsyncMock()
        item = RegistryScopeWorkItem(
            launch_config_id=PLACEMENT_CONFIG_ID,
            launch_intent_id=LAUNCH_INTENT_ID,
            deployment_id=DEPLOYMENT_ID,
            validator="validator-1",
            server_id="server-1",
            repository=repository,
            manifest_digest=digest,
            desired_state="active",
            phase="active",
            attempt_count=0,
        )

        reconciliation = asyncio.create_task(
            reconciler._reconcile_registry_scope_intent(item)
        )
        await asyncio.wait_for(pending_commit_entered.wait(), timeout=1)

        async def place():
            try:
                async with session_factory() as session:
                    observed = _ObservedServerLockSession(
                        session,
                        placement_server_lock_attempted,
                        placement_registry_lock_attempted,
                    )
                    server = await operator._get_server(observed, "server-1")
                    chute = await session.get(Chute, "chute-1")
                    assert chute is not None
                    await operator._track_deployment(
                        observed,
                        chute,
                        server,
                        operator._verify_gpus(chute, server),
                        config_id=PLACEMENT_CONFIG_ID,
                        registry_repository=repository,
                        registry_manifest_digest=digest,
                        launch_intent_id=LAUNCH_INTENT_ID,
                        launch_intent_lease_owner=LAUNCH_LEASE_OWNER,
                        launch_token_sha256=LAUNCH_TOKEN_SHA256,
                    )
            finally:
                placement_finished.set()

        placement = asyncio.create_task(place())
        await asyncio.wait_for(placement_registry_lock_attempted.wait(), timeout=1)
        await asyncio.sleep(0.05)
        assert placement.done() is False
        allow_pending_commit.set()

        with pytest.raises(DeploymentFailure, match="not exactly active"):
            await asyncio.wait_for(placement, timeout=2)
        with pytest.raises(TimeoutError, match="ambiguous registry POST"):
            await asyncio.wait_for(reconciliation, timeout=2)

        assert post_started.is_set()
        reconciler._send_registry_scope_revocation.assert_not_awaited()
        async with session_factory() as session:
            scope = await session.get(RegistryScopeIntent, PLACEMENT_CONFIG_ID)
            assert scope.phase == "register_pending"
            assert scope.attempt_count == 1
            assert scope.last_failure == "TimeoutError: ambiguous registry POST"
            assert scope.next_retry_at is not None
            assert (
                await session.scalar(select(func.count()).select_from(Deployment)) == 0
            )
            assert (
                await session.scalar(
                    select(func.count()).select_from(DeploymentLaunchOperation)
                )
                == 0
            )
            gpu = await session.get(GPU, "gpu-1")
            assert gpu.deployment_id is None
            intent = await session.get(MinerLaunchIntent, LAUNCH_INTENT_ID)
            assert intent.phase == "registry_acked"
            assert intent.retry_lease_owner == LAUNCH_LEASE_OWNER
