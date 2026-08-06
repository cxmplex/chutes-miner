"""
Gepetto - coordinate all the things.
"""

import asyncio
import hashlib
import math
import random
import re
import traceback
import uuid
from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import aiohttp
import chutes_common.schemas.orms  # noqa: F401 - register validator_migrations table
import chutes_miner.api.k8s as k8s
import orjson as json
from chutes_common.auth import sign_request
from chutes_common.schemas.chute import Chute
from chutes_common.schemas.deployment import Deployment
from chutes_common.schemas.gpu import GPU
from chutes_common.schemas.server import Server
from chutes_common.schemas.teardown import MinerLaunchIntent, RegistryScopeIntent
from chutes_common.settings import Validator
from chutes_miner.api.config import settings, validator_by_hotkey
from chutes_miner.api.database import engine, get_session
from chutes_miner.api.deployment.teardown import (
    LEASE_SECONDS,
    RESUME_CONCURRENCY,
    RESUME_ITEM_TIMEOUT_SECONDS,
    DeploymentTeardownCoordinator,
    retry_at,
)
from chutes_miner.api.exceptions import DeploymentFailure
from chutes_miner.api.k8s.operator import K8sOperator
from chutes_miner.api.k8s.util import (
    canonical_miner_launch_sha256,
    deployment_disk_requirements,
    require_supported_chutes_version,
    resolve_deployment_validator,
    validated_miner_launch_lineage,
)
from chutes_miner.api.registry_scopes import (
    ensure_registry_scope_registration_in_session,
    record_registry_scope_failure,
    record_registry_scope_registered_in_session,
    record_registry_scope_revoked,
    registry_scope_work_items,
    request_registry_scope_revocation,
)
from chutes_miner.api.redis_pubsub import RedisListener
from chutes_miner.api.schema_barrier import (
    wait_for_required_schema,
    wait_for_seedless_adoption,
)
from chutes_miner.leader import run_gepetto_leader_loop
from chutes_miner.validator_migrations import run_validator_migrations
from loguru import logger
from sqlalchemy import and_, case, func, or_, select, text, update

# When scaling up, randomly pick from up to this many of the tightest-fitting servers
# (rather than always the single most-utilized one) to spread load and avoid repeatedly
# scheduling onto a server that has an issue the disk check doesn't catch.
SCALE_UP_CANDIDATE_POOL = 2
REGISTRY_SCOPE_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=30, connect=10)
LAUNCH_AUTHORITY_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=30, connect=10)
LAUNCH_INTENT_HEARTBEAT_SECONDS = max(1, LEASE_SECONDS // 3)


def _canonical_sha256(document: Any) -> str:
    return canonical_miner_launch_sha256(document)


class Gepetto:
    def __init__(self):
        """
        Constructor.
        """
        self.pubsub = RedisListener()
        self.remote_chutes = {validator.hotkey: {} for validator in settings.validators}
        self.remote_images = {validator.hotkey: {} for validator in settings.validators}
        self.remote_instances = {
            validator.hotkey: {} for validator in settings.validators
        }
        self.remote_nodes = {validator.hotkey: {} for validator in settings.validators}
        self.remote_metrics = {
            validator.hotkey: {} for validator in settings.validators
        }
        # Global active instances across all miners (for preemption decisions)
        self.global_active_instances = {
            validator.hotkey: [] for validator in settings.validators
        }
        # Tracks the TEE VM version per server_id, sourced live from the validator each reconcile
        # cycle. Passed through to build_chute_job so pod scheduling can tune the runtime to the
        # VM version (e.g. HF download env vars for VMs >= 1.3.1).
        self.remote_server_versions: Dict[str, Dict[str, Optional[str]]] = {
            validator.hotkey: {} for validator in settings.validators
        }
        self._scale_lock = asyncio.Lock()
        self._restart_lock = asyncio.Lock()
        self.teardown = DeploymentTeardownCoordinator()
        self.setup_handlers()

    def setup_handlers(self):
        """
        Configure the various event listeners/handlers.
        """
        self.pubsub.on_event("gpu_verified")(self.gpu_verified)
        self.pubsub.on_event("server_deleted")(self.server_deleted)
        self.pubsub.on_event("gpu_deleted")(self.gpu_deleted)
        self.pubsub.on_event("instance_created")(self.instance_created)
        self.pubsub.on_event("instance_verified")(self.instance_verified)
        self.pubsub.on_event("instance_deleted")(self.instance_deleted)
        self.pubsub.on_event("instance_activated")(self.instance_activated)
        self.pubsub.on_event("rolling_update")(self.rolling_update)
        self.pubsub.on_event("chute_deleted")(self.chute_deleted)
        self.pubsub.on_event("chute_created")(self.chute_created)
        self.pubsub.on_event("bounty_change")(self.bounty_changed)
        self.pubsub.on_event("image_deleted")(self.image_deleted)
        self.pubsub.on_event("image_created")(self.image_created)
        self.pubsub.on_event("image_updated")(self.image_updated)
        self.pubsub.on_event("job_created")(self.job_created)
        self.pubsub.on_event("job_deleted")(self.job_deleted)
        self.pubsub.on_event("chute_updated")(self.chute_updated)

    @staticmethod
    def _launch_intent_lease_owner(kind: str) -> str:
        """Return one opaque owner token for a producer or recovery attempt."""

        return f"miner-launch:{kind}:{uuid.uuid4()}"

    @staticmethod
    def _require_live_launch_intent_lease(
        intent: MinerLaunchIntent | None,
        lease_owner: str,
        *,
        now: datetime | None = None,
    ) -> MinerLaunchIntent:
        deadline = getattr(intent, "retry_lease_expires_at", None)
        if (
            intent is None
            or not isinstance(lease_owner, str)
            or not lease_owner
            or intent.retry_lease_owner != lease_owner
            or deadline is None
            or deadline <= (now or datetime.now(timezone.utc))
        ):
            raise DeploymentFailure("durable miner launch lease changed or expired")
        return intent

    async def _renew_launch_intent_lease(
        self,
        intent_id: str,
        lease_owner: str,
    ) -> None:
        """Renew only an unexpired lease still owned by this exact attempt."""

        async with get_session() as session:
            intent = await session.get(
                MinerLaunchIntent,
                intent_id,
                with_for_update=True,
            )
            self._validated_launch_intent(intent)
            if intent is None or intent.phase not in {
                "pending",
                "response_persisted",
                "registry_acked",
                "cleanup_required",
            }:
                raise DeploymentFailure("durable miner launch is no longer renewable")
            self._require_live_launch_intent_lease(intent, lease_owner)
            intent.retry_lease_expires_at = datetime.now(timezone.utc) + timedelta(
                seconds=LEASE_SECONDS
            )
            await session.commit()

    @asynccontextmanager
    async def _launch_intent_lease_guard(
        self,
        intent_id: str,
        lease_owner: str,
    ):
        """Keep DB ownership live through the producer-to-deployment handoff."""

        await self._renew_launch_intent_lease(intent_id, lease_owner)
        producer_task = asyncio.current_task()
        if producer_task is None:
            raise DeploymentFailure("miner launch producer task is unavailable")
        stop = asyncio.Event()
        lease_failure: BaseException | None = None

        async def heartbeat() -> None:
            nonlocal lease_failure
            try:
                while True:
                    try:
                        await asyncio.wait_for(
                            stop.wait(),
                            timeout=LAUNCH_INTENT_HEARTBEAT_SECONDS,
                        )
                    except TimeoutError:
                        pass
                    if stop.is_set():
                        return
                    await self._renew_launch_intent_lease(intent_id, lease_owner)
            except asyncio.CancelledError:
                raise
            except BaseException as exc:
                lease_failure = exc
                producer_task.cancel()

        heartbeat_task = asyncio.create_task(
            heartbeat(),
            name=f"miner-launch-lease-{intent_id}",
        )
        try:
            yield
        except asyncio.CancelledError as exc:
            if lease_failure is not None:
                raise DeploymentFailure(
                    "durable miner launch lease heartbeat failed"
                ) from lease_failure
            raise exc
        finally:
            stop.set()
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except BaseException:
                pass
        if lease_failure is not None:
            raise DeploymentFailure(
                "durable miner launch lease heartbeat failed"
            ) from lease_failure

    @staticmethod
    def _platform_managed(data: Any) -> bool:
        return isinstance(data, dict) and (
            data.get("management_mode") == "platform"
            or data.get("gpu_management_mode") == "platform"
        )

    async def run(self):
        """
        Main loop.
        """
        if settings.gpu_tee_only:
            _ = settings.registry_workload_token
        await wait_for_required_schema(engine)
        if settings.gpu_tee_only:
            await wait_for_seedless_adoption(
                engine,
                settings.seedless_gpu_identity,
                on_blocked=self.teardown.resume_pending,
            )
        if settings.validator_migrations_enabled:
            await run_validator_migrations()
        await self.resume_launch_intents()
        await self.teardown.resume_pending()
        await self.reconcile_registry_scope_intents(reconstruct_active=True)
        await k8s.purge_legacy_source_config_maps()
        await self.reconcile()
        async with asyncio.TaskGroup() as tasks:
            tasks.create_task(self.autoscaler())
            tasks.create_task(self.reconciler())
            tasks.create_task(self.pubsub.start())

    @staticmethod
    async def _remote_refresh_objects(
        pointer: Dict[str, Any],
        hotkey: str,
        url: str,
        id_key: str,
        forbidden_keys: frozenset[str] | None = None,
    ):
        """
        Refresh images/chutes from validator(s).
        """
        async with aiohttp.ClientSession(
            raise_for_status=True, read_bufsize=8 * 1024 * 1024
        ) as session:
            headers, _ = sign_request(purpose="miner")
            updated_items = {}
            explicit_null = False
            params = {}
            if "instances" in url:
                params["explicit_null"] = "True"
            async with session.get(url, headers=headers, params=params) as resp:
                async for content_enc in resp.content:
                    content = content_enc.decode()
                    if content.startswith("data: {"):
                        data = json.loads(content[6:])
                        if Gepetto._platform_managed(data):
                            continue
                        if forbidden := (forbidden_keys or frozenset()).intersection(
                            data
                        ):
                            raise ValueError(
                                f"Invalid response from {url}: forbidden fields {', '.join(sorted(forbidden))}"
                            )
                        updated_items[data[id_key]] = data
                    elif content.startswith("data: NO_ITEMS"):
                        explicit_null = True
            if updated_items or explicit_null:
                pointer[hotkey] = updated_items

    async def _refresh_global_active_instances(self, validator):
        """
        Refresh global active instances from the validator.
        This endpoint returns all active instances across all miners.
        """
        try:
            async with aiohttp.ClientSession(raise_for_status=True) as session:
                headers, _ = sign_request(purpose="miner")
                async with session.get(
                    f"{validator.api}/miner/active_instances/", headers=headers
                ) as resp:
                    self.global_active_instances[validator.hotkey] = await resp.json()
        except Exception as exc:
            logger.error(
                f"Failed to refresh global active instances from {validator.hotkey}: {exc}"
            )

    async def _refresh_server_versions(self, validator):
        """
        Refresh the in-memory vm version map from the validator's /miner/servers/ endpoint.

        The version is the TEE measurement version reconciled from the TDX quote by the
        validator — the miner has no independent way to know it, so it is never persisted
        locally and is re-fetched every reconcile cycle. It feeds build_chute_job so pod
        scheduling can tune the runtime to the VM version.
        """
        try:
            async with aiohttp.ClientSession(raise_for_status=True) as session:
                headers, _ = sign_request(purpose="miner")
                async with session.get(
                    f"{validator.api}/miner/servers/", headers=headers
                ) as resp:
                    data = await resp.json()
            self.remote_server_versions[validator.hotkey] = self._parse_server_versions(
                data
            )
        except Exception as exc:
            # A failed or malformed refresh must not keep a version from an older VM.
            # Unknown versions intentionally use the conservative legacy HF environment.
            self.remote_server_versions[validator.hotkey] = {}
            logger.error(
                f"Failed to refresh server versions from {validator.hotkey}: {exc}"
            )

    @staticmethod
    def _parse_server_versions(data: Any) -> Dict[str, Optional[str]]:
        """Parse the validator's MinerServersResponse without retaining partial data."""
        if not isinstance(data, dict) or not isinstance(data.get("servers"), list):
            raise ValueError("Invalid MinerServersResponse: expected a servers list.")
        versions: Dict[str, Optional[str]] = {}
        for remote_server in data["servers"]:
            if not isinstance(remote_server, dict):
                raise ValueError("Invalid MinerServer entry: expected an object.")
            server_id = remote_server.get("server_id")
            version = remote_server.get("version")
            if not isinstance(server_id, str) or not server_id:
                raise ValueError("Invalid MinerServer entry: missing server_id.")
            if server_id in versions:
                raise ValueError(
                    f"Invalid MinerServersResponse: duplicate server_id {server_id!r}."
                )
            if version is not None and not isinstance(version, str):
                raise ValueError(
                    f"Invalid MinerServer entry for {server_id!r}: version must be a string or null."
                )
            versions[server_id] = version
        return versions

    def _server_vm_version(
        self, validator_hotkey: str, server_id: str
    ) -> Optional[str]:
        return self.remote_server_versions.get(validator_hotkey, {}).get(server_id)

    @staticmethod
    def _require_validator_match(chute: Chute, server: Server) -> None:
        try:
            resolve_deployment_validator(chute, server)
        except ValueError as exc:
            raise DeploymentFailure(str(exc)) from exc
        Gepetto._server_hourly_cost(server)

    @staticmethod
    def _server_hourly_cost(server: Server) -> float:
        try:
            cost = float(server.hourly_cost)
        except (TypeError, ValueError) as exc:
            raise DeploymentFailure(
                "Server hourly cost is not a positive finite value"
            ) from exc
        if not math.isfinite(cost) or cost <= 0:
            raise DeploymentFailure("Server hourly cost is not a positive finite value")
        return cost

    @staticmethod
    def _remote_chute_values(
        chute_data: dict,
        validator_hotkey: str,
        *,
        expected_chute_id: str,
        expected_version: str,
    ) -> dict:
        if not isinstance(chute_data, dict):
            raise ValueError("Invalid miner chute response: expected an object.")
        if forbidden := {"code", "filename"}.intersection(chute_data):
            raise ValueError(
                f"Invalid miner chute response: obsolete source fields are forbidden "
                f"({', '.join(sorted(forbidden))})."
            )

        required = {
            "chute_id",
            "name",
            "image",
            "ref_str",
            "version",
            "supported_gpus",
            "node_selector",
            "chutes_version",
            "preemptible",
            "tee",
        }
        if missing := required.difference(chute_data):
            raise ValueError(
                f"Invalid miner chute response: missing {', '.join(sorted(missing))}."
            )
        if chute_data["chute_id"] != expected_chute_id:
            raise ValueError(
                f"Invalid miner chute response: expected chute_id {expected_chute_id!r}, "
                f"received {chute_data['chute_id']!r}."
            )
        if chute_data["version"] != expected_version:
            raise ValueError(
                f"Invalid miner chute response: expected version {expected_version!r}, "
                f"received {chute_data['version']!r}."
            )

        require_supported_chutes_version(
            chute_data["chutes_version"],
            expected_chute_id,
        )
        node_selector = chute_data["node_selector"]
        if not isinstance(node_selector, dict) or "gpu_count" not in node_selector:
            raise ValueError(
                "Invalid miner chute response: node_selector.gpu_count is required."
            )

        return {
            "validator": validator_hotkey,
            "name": chute_data["name"],
            "image": chute_data["image"],
            "ref_str": chute_data["ref_str"],
            "version": chute_data["version"],
            "supported_gpus": chute_data["supported_gpus"],
            "gpu_count": node_selector["gpu_count"],
            "chutes_version": chute_data["chutes_version"],
            "ban_reason": None,
            "preemptible": chute_data["preemptible"],
            "tee": chute_data["tee"],
        }

    async def remote_refresh_all(self):
        """
        Refresh chutes from the validators.
        """
        for validator in settings.validators:
            # Refresh all version maps first so a later inventory failure for one
            # validator cannot leave an older VM version active for another.
            await self._refresh_server_versions(validator)
        for validator in settings.validators:
            for clazz, id_field in (
                ("chutes", "chute_id"),
                ("images", "image_id"),
                ("nodes", "uuid"),
                ("instances", "instance_id"),
                ("metrics", "chute_id"),
            ):
                logger.debug(f"Refreshing {clazz} from {validator.hotkey}...")
                await self._remote_refresh_objects(
                    getattr(self, f"remote_{clazz}"),
                    validator.hotkey,
                    f"{validator.api}/miner/{clazz}/",
                    id_field,
                    forbidden_keys=(
                        frozenset({"code", "filename"})
                        if clazz == "chutes"
                        else frozenset()
                    ),
                )
            # Also refresh global active instances for preemption decisions
            await self._refresh_global_active_instances(validator)

    @staticmethod
    async def load_chute(chute_id: str, version: str, validator: str):
        """
        Helper to load a chute from the local database.
        """
        async with get_session() as session:
            return (
                await session.execute(
                    select(Chute)
                    .where(Chute.chute_id == chute_id)
                    .where(Chute.version == version)
                    .where(Chute.validator == validator)
                )
            ).scalar_one_or_none()

    @staticmethod
    async def count_deployments(chute_id: str, version: str, validator: str):
        """
        Helper to get the number of deployments for a chute.
        """
        async with get_session() as session:
            return (
                await session.execute(
                    select(func.count())
                    .select_from(Deployment)
                    .where(Deployment.chute_id == chute_id)
                    .where(Deployment.version == version)
                    .where(Deployment.validator == validator)
                )
            ).scalar()

    @staticmethod
    async def count_non_job_deployments(chute_id: str, version: str, validator: str):
        """
        Helper to get the number of non-job deployments for a chute.
        """
        async with get_session() as session:
            return (
                await session.execute(
                    select(func.count())
                    .select_from(Deployment)
                    .where(Deployment.chute_id == chute_id)
                    .where(Deployment.version == version)
                    .where(Deployment.validator == validator)
                    .where(Deployment.job_id.is_(None))
                )
            ).scalar()

    @staticmethod
    async def has_pending_deployment(
        chute_id: str, version: str, validator: str
    ) -> bool:
        """
        True if there is at least one non-job deployment for this chute that is not yet active
        (pending activation). Used to avoid deploying additional instances while one is already
        coming up.
        """
        async with get_session() as session:
            return (
                await session.execute(
                    select(func.count())
                    .select_from(Deployment)
                    .where(Deployment.chute_id == chute_id)
                    .where(Deployment.version == version)
                    .where(Deployment.validator == validator)
                    .where(Deployment.job_id.is_(None))
                    .where(Deployment.active.is_(False))
                )
            ).scalar() > 0

    @staticmethod
    async def get_chute(chute_id: str, validator: str) -> Optional[Chute]:
        """
        Load a chute by ID.
        """
        async with get_session() as session:
            return (
                (
                    await session.execute(
                        select(Chute).where(
                            Chute.chute_id == chute_id, Chute.validator == validator
                        )
                    )
                )
                .unique()
                .scalar_one_or_none()
            )

    async def _send_registry_scope_registration(
        self,
        validator: Validator,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        headers, serialized = sign_request(payload=body, purpose="registry")
        headers["X-Chutes-Registry-Workload-Token"] = settings.registry_workload_token
        service = f"registry-{validator.hotkey.lower()}.{settings.namespace}.svc.cluster.local:5000"
        async with aiohttp.ClientSession(
            raise_for_status=False,
            timeout=REGISTRY_SCOPE_HTTP_TIMEOUT,
        ) as session:
            async with session.post(
                f"http://{service}/registry/scopes",
                data=serialized,
                headers=headers,
            ) as response:
                result = await response.json()
                if (
                    response.status != 200
                    or not isinstance(result, dict)
                    or set(result) != {"registered", "launch_config_id", "expires_at"}
                    or result["registered"] is not True
                    or result["launch_config_id"] != body["launch_config_id"]
                ):
                    raise DeploymentFailure(
                        "Registry broker rejected the exact launch-config scope."
                    )
                return result

    async def _register_registry_scope(
        self,
        validator: Validator,
        server: Server,
        payload: dict,
    ) -> dict[str, Any]:
        if not settings.gpu_tee_only:
            return {
                "registered": False,
                "launch_config_id": payload["config_id"],
                "status": "not_required",
            }
        registry = payload["registry"]
        body = {
            "schema": "chutes.miner-registry-scope",
            "version": 1,
            "server_id": server.server_id,
            "launch_config_id": payload["config_id"],
            "repository": registry["repository"],
            "manifest_digest": registry["manifest_digest"],
        }
        return await self._send_registry_scope_registration(validator, body)

    @staticmethod
    def _launch_lineage(
        chute: Chute,
        server: Server,
        job_id: str | None,
        deployment_id: str | None,
    ) -> dict[str, Any]:
        return {
            "schema": "chutes.miner-launch-lineage",
            "version": 1,
            "deployment_id": deployment_id,
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

    @staticmethod
    def _validated_launch_intent(intent: MinerLaunchIntent | None) -> dict[str, Any]:
        if intent is None:
            raise DeploymentFailure("durable miner launch intent disappeared")
        return validated_miner_launch_lineage(
            intent,
            miner_hotkey=settings.miner_ss58,
            validator=intent.validator,
            chute_id=intent.chute_id,
            chute_version=intent.chute_version,
            server_id=intent.server_id,
            job_id=intent.job_id,
            require_gpu_lineage=settings.gpu_tee_only,
        )

    async def _begin_launch_intent(
        self,
        chute: Chute,
        server: Server,
        job_id: str | None,
        deployment_id: str,
        *,
        lease_owner: str,
    ) -> str:
        """Persist/reuse one request UUID before any validator or registry call."""
        if not isinstance(lease_owner, str) or not lease_owner:
            raise DeploymentFailure("durable launch lease owner is required")
        try:
            canonical_deployment_id = str(uuid.UUID(deployment_id))
        except (AttributeError, TypeError, ValueError) as exc:
            raise DeploymentFailure("miner deployment identity is not a UUID") from exc
        if canonical_deployment_id != deployment_id:
            raise DeploymentFailure("miner deployment identity is not canonical")
        lineage = self._launch_lineage(chute, server, job_id, deployment_id)
        lineage_sha256 = _canonical_sha256(lineage)
        async with get_session() as session:
            await session.execute(
                text(
                    "SELECT pg_advisory_xact_lock(hashtextextended(:lineage_sha256, 0))"
                ),
                {"lineage_sha256": lineage_sha256},
            )
            existing = (
                await session.execute(
                    select(MinerLaunchIntent)
                    .where(
                        MinerLaunchIntent.lineage_sha256 == lineage_sha256,
                        MinerLaunchIntent.phase.not_in({"completed", "failed"}),
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if existing is not None:
                if self._validated_launch_intent(existing) != lineage:
                    raise DeploymentFailure("durable launch request lineage conflicts")
                if existing.phase in {"consumed", "cleanup_required"}:
                    raise DeploymentFailure(
                        f"durable launch request is already {existing.phase}"
                    )
                now = datetime.now(timezone.utc)
                if existing.next_retry_at is not None and existing.next_retry_at > now:
                    raise DeploymentFailure("durable launch request is backed off")
                if (
                    existing.retry_lease_owner is not None
                    and existing.retry_lease_expires_at is not None
                    and existing.retry_lease_expires_at > now
                ):
                    raise DeploymentFailure(
                        "durable launch request is owned by another producer"
                    )
                existing.retry_lease_owner = lease_owner
                existing.retry_lease_expires_at = now + timedelta(
                    seconds=LEASE_SECONDS
                )
                existing.attempt_count += 1
                existing.next_retry_at = None
                existing.last_failure = None
                await session.commit()
                return existing.intent_id
            intent_id = str(uuid.uuid4())
            request_payload = {
                "schema": "chutes.miner-launch-request.v1",
                "miner_launch_request_id": intent_id,
                "lineage": lineage,
            }
            session.add(
                MinerLaunchIntent(
                    intent_id=intent_id,
                    phase="pending",
                    validator=chute.validator,
                    chute_id=chute.chute_id,
                    chute_version=chute.version,
                    server_id=server.server_id,
                    job_id=job_id,
                    deployment_id=deployment_id,
                    request_payload=request_payload,
                    request_sha256=_canonical_sha256(request_payload),
                    lineage_sha256=lineage_sha256,
                    retry_lease_owner=lease_owner,
                    retry_lease_expires_at=datetime.now(timezone.utc)
                    + timedelta(seconds=LEASE_SECONDS),
                    attempt_count=1,
                )
            )
            await session.commit()
            return intent_id

    async def _begin_job_cleanup_intent(
        self,
        chute: Chute,
        server: Server,
        job_id: str,
        *,
        lease_owner: str,
    ) -> str:
        """Persist validator job cleanup when launch validation fails pre-request."""
        if not isinstance(lease_owner, str) or not lease_owner:
            raise DeploymentFailure("durable job cleanup lease owner is required")
        lineage = self._launch_lineage(chute, server, job_id, None)
        lineage_sha256 = _canonical_sha256(lineage)
        async with get_session() as session:
            await session.execute(
                text(
                    "SELECT pg_advisory_xact_lock(hashtextextended(:lineage_sha256, 0))"
                ),
                {"lineage_sha256": lineage_sha256},
            )
            existing = (
                await session.execute(
                    select(MinerLaunchIntent)
                    .where(
                        MinerLaunchIntent.lineage_sha256 == lineage_sha256,
                        MinerLaunchIntent.phase.not_in({"completed", "failed"}),
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if existing is not None:
                if self._validated_launch_intent(existing) != lineage:
                    raise DeploymentFailure("durable job cleanup lineage conflicts")
                if existing.phase == "consumed":
                    raise DeploymentFailure(
                        f"durable job cleanup request is already {existing.phase}"
                    )
                now = datetime.now(timezone.utc)
                if existing.next_retry_at is not None and existing.next_retry_at > now:
                    raise DeploymentFailure("durable job cleanup is backed off")
                if (
                    existing.retry_lease_owner is not None
                    and existing.retry_lease_expires_at is not None
                    and existing.retry_lease_expires_at > now
                ):
                    raise DeploymentFailure(
                        "durable job cleanup is owned by another producer"
                    )
                existing.retry_lease_owner = lease_owner
                existing.retry_lease_expires_at = now + timedelta(
                    seconds=LEASE_SECONDS
                )
                existing.attempt_count += 1
                existing.next_retry_at = None
                existing.last_failure = None
                await session.commit()
                return existing.intent_id
            intent_id = str(uuid.uuid4())
            request_payload = {
                "schema": "chutes.miner-job-release.v1",
                "miner_launch_request_id": intent_id,
                "lineage": lineage,
            }
            session.add(
                MinerLaunchIntent(
                    intent_id=intent_id,
                    phase="cleanup_required",
                    validator=chute.validator,
                    chute_id=chute.chute_id,
                    chute_version=chute.version,
                    server_id=server.server_id,
                    job_id=job_id,
                    job_cleanup_only=True,
                    request_payload=request_payload,
                    request_sha256=_canonical_sha256(request_payload),
                    lineage_sha256=lineage_sha256,
                    retry_lease_owner=lease_owner,
                    retry_lease_expires_at=datetime.now(timezone.utc)
                    + timedelta(seconds=LEASE_SECONDS),
                    attempt_count=1,
                )
            )
            await session.commit()
            return intent_id

    async def _record_launch_response(
        self,
        intent_id: str,
        payload: dict[str, Any],
        *,
        lease_owner: str,
    ) -> None:
        stable = {
            "config_id": payload["config_id"],
            "registry": payload.get("registry"),
        }
        async with get_session() as session:
            intent = await session.get(
                MinerLaunchIntent, intent_id, with_for_update=True
            )
            self._validated_launch_intent(intent)
            if intent is None or intent.phase not in {
                "pending",
                "response_persisted",
                "registry_acked",
                "cleanup_required",
            }:
                raise DeploymentFailure(
                    "durable launch response arrived in an invalid phase"
                )
            self._require_live_launch_intent_lease(intent, lease_owner)
            if (
                intent.response_payload is not None
                and intent.response_payload != stable
            ):
                raise DeploymentFailure(
                    "validator replay changed stable launch response"
                )
            intent.response_payload = stable
            intent.response_sha256 = _canonical_sha256(stable)
            token_sha256 = hashlib.sha256(payload["token"].encode()).hexdigest()
            authorized = set(intent.authorized_token_sha256s or [])
            authorized.add(token_sha256)
            intent.token_sha256 = token_sha256
            intent.authorized_token_sha256s = sorted(authorized)
            if intent.phase not in {"registry_acked", "cleanup_required"}:
                intent.phase = "response_persisted"
            intent.last_failure = None
            intent.next_retry_at = None
            intent.retry_lease_expires_at = datetime.now(timezone.utc) + timedelta(
                seconds=LEASE_SECONDS
            )
            if settings.gpu_tee_only:
                await ensure_registry_scope_registration_in_session(
                    session, intent, payload
                )
            await session.commit()

    async def _record_registry_ack(
        self,
        intent_id: str,
        ack: dict[str, Any],
        *,
        lease_owner: str,
    ) -> None:
        async with get_session() as session:
            intent = await session.get(
                MinerLaunchIntent, intent_id, with_for_update=True
            )
            self._validated_launch_intent(intent)
            if intent is None or intent.phase not in {
                "response_persisted",
                "registry_acked",
            }:
                raise DeploymentFailure(
                    "registry ACK arrived in an invalid launch phase"
                )
            self._require_live_launch_intent_lease(intent, lease_owner)
            expected_config_id = (intent.response_payload or {}).get("config_id")
            if (
                not isinstance(ack, dict)
                or ack.get("launch_config_id") != expected_config_id
            ):
                raise DeploymentFailure(
                    "registry ACK changed the launch config authority"
                )
            if intent.registry_ack is not None and intent.registry_ack != ack:
                raise DeploymentFailure("registry replay changed the launch ACK")
            if settings.gpu_tee_only:
                await record_registry_scope_registered_in_session(
                    session,
                    expected_config_id,
                    ack,
                    launch_intent_id=intent_id,
                )
            intent.registry_ack = ack
            intent.phase = "registry_acked"
            intent.last_failure = None
            intent.next_retry_at = None
            intent.retry_lease_expires_at = datetime.now(timezone.utc) + timedelta(
                seconds=LEASE_SECONDS
            )
            await session.commit()

    async def _record_launch_intent_failure(
        self,
        intent_id: str,
        exc: BaseException,
        *,
        lease_owner: str,
    ) -> None:
        async with get_session() as session:
            intent = await session.get(
                MinerLaunchIntent, intent_id, with_for_update=True
            )
            try:
                self._validated_launch_intent(intent)
            except DeploymentFailure as validation_error:
                logger.error(
                    f"Refusing to mutate invalid durable launch intent {intent_id}: "
                    f"{validation_error}"
                )
                return
            if intent is not None and intent.phase not in {"completed", "failed"}:
                self._require_live_launch_intent_lease(intent, lease_owner)
                intent.last_failure = f"{type(exc).__name__}: {exc}"[:8000]
                intent.next_retry_at = retry_at(intent.attempt_count)
                intent.retry_lease_owner = None
                intent.retry_lease_expires_at = None
                await session.commit()

    async def _resume_launch_intent(
        self,
        intent_id: str,
        *,
        lease_owner: str,
    ) -> bool:
        """Replay and close one exact pre-deployment launch authority."""
        try:
            async with get_session() as session:
                intent = await session.get(
                    MinerLaunchIntent,
                    intent_id,
                    with_for_update=True,
                )
                if intent is None or intent.phase not in {
                    "pending",
                    "response_persisted",
                    "registry_acked",
                    "cleanup_required",
                }:
                    return False
                self._validated_launch_intent(intent)
                self._require_live_launch_intent_lease(intent, lease_owner)
                intent.retry_lease_expires_at = datetime.now(
                    timezone.utc
                ) + timedelta(seconds=LEASE_SECONDS)
                phase = intent.phase
                chute_id = intent.chute_id
                server_id = intent.server_id
                job_id = intent.job_id
                deployment_id = intent.deployment_id
                validator_hotkey = intent.validator
                job_cleanup_only = bool(getattr(intent, "job_cleanup_only", False))
                job_release_ack = intent.job_release_ack
                stable_response = dict(intent.response_payload or {})
                await session.commit()

            # An exact request replay closes the response-loss window. The
            # replayed JWT stays in memory and is intentionally discarded.
            if not job_cleanup_only and (phase == "pending" or not stable_response):
                validator = validator_by_hotkey(validator_hotkey)
                if validator is None:
                    raise DeploymentFailure("launch intent validator is unavailable")
                payload = await self._fetch_launch_config(
                    validator=validator,
                    chute_id=chute_id,
                    server_id=server_id,
                    job_id=job_id,
                    intent_id=intent_id,
                    deployment_id=deployment_id,
                )
                await self._record_launch_response(
                    intent_id,
                    payload,
                    lease_owner=lease_owner,
                )
                stable_response = {
                    "config_id": payload["config_id"],
                    "registry": payload.get("registry"),
                }
            config_id = stable_response.get("config_id")
            if config_id:
                await self._renew_launch_intent_lease(intent_id, lease_owner)
                await self._revoke_registry_scope(
                    validator_hotkey, config_id, server_id
                )
            if job_id and job_release_ack is None:
                await self._renew_launch_intent_lease(intent_id, lease_owner)
                job_release_ack = await self._release_job_exact(
                    validator_hotkey,
                    job_id,
                )
            async with get_session() as session:
                current = await session.get(
                    MinerLaunchIntent,
                    intent_id,
                    with_for_update=True,
                )
                self._validated_launch_intent(current)
                self._require_live_launch_intent_lease(current, lease_owner)
                if current.phase not in {
                    "response_persisted",
                    "registry_acked",
                    "cleanup_required",
                }:
                    return False
                if job_id:
                    if job_release_ack is None:
                        raise DeploymentFailure(
                            "launch intent cleanup lacks validator job release ACK"
                        )
                    current.job_release_ack = job_release_ack
                    current.job_released_at = datetime.now(timezone.utc)
                current.phase = "completed"
                current.completed_at = datetime.now(timezone.utc)
                current.last_failure = None
                current.next_retry_at = None
                current.retry_lease_owner = None
                current.retry_lease_expires_at = None
                await session.commit()
                return True
        except Exception as exc:
            try:
                await self._record_launch_intent_failure(
                    intent_id,
                    exc,
                    lease_owner=lease_owner,
                )
            except DeploymentFailure as fence_error:
                logger.error(
                    f"Refusing stale launch cleanup mutation for {intent_id}: "
                    f"{fence_error}"
                )
            logger.warning(
                f"Durable launch intent {intent_id} cleanup paused for retry: {exc}"
            )
            return False

    async def _claim_launch_intents(
        self,
        phases: set[str],
    ) -> list[tuple[str, str]]:
        """Claim only due, abandoned work with a durable skip-locked lease."""

        now = datetime.now(timezone.utc)
        async with get_session() as session:
            result = await session.execute(
                select(MinerLaunchIntent)
                .where(
                    MinerLaunchIntent.phase.in_(phases),
                    or_(
                        MinerLaunchIntent.next_retry_at.is_(None),
                        MinerLaunchIntent.next_retry_at <= now,
                    ),
                    or_(
                        and_(
                            MinerLaunchIntent.retry_lease_owner.is_(None),
                            MinerLaunchIntent.retry_lease_expires_at.is_(None),
                        ),
                        MinerLaunchIntent.retry_lease_expires_at <= now,
                    ),
                )
                .order_by(
                    MinerLaunchIntent.created_at,
                    MinerLaunchIntent.intent_id,
                )
                .with_for_update(skip_locked=True)
                .limit(RESUME_CONCURRENCY)
            )
            intents = list(result.scalars())
            claims: list[tuple[str, str]] = []
            for intent in intents:
                lease_owner = self._launch_intent_lease_owner("recovery")
                intent.retry_lease_owner = lease_owner
                intent.retry_lease_expires_at = now + timedelta(
                    seconds=LEASE_SECONDS
                )
                intent.attempt_count += 1
                intent.next_retry_at = None
                claims.append((intent.intent_id, lease_owner))
            await session.commit()
            return claims

    async def resume_launch_intents(self) -> None:
        """Close pre-deployment launch authority left by a crashed worker."""
        claims = await self._claim_launch_intents(
            {"pending", "response_persisted", "registry_acked", "cleanup_required"}
        )

        async def resume_one(intent_id: str, lease_owner: str) -> None:
            try:
                await asyncio.wait_for(
                    self._resume_launch_intent(
                        intent_id,
                        lease_owner=lease_owner,
                    ),
                    timeout=RESUME_ITEM_TIMEOUT_SECONDS,
                )
            except TimeoutError as exc:
                try:
                    await self._record_launch_intent_failure(
                        intent_id,
                        exc,
                        lease_owner=lease_owner,
                    )
                except DeploymentFailure as fence_error:
                    logger.error(
                        f"Refusing stale timed-out launch mutation for {intent_id}: "
                        f"{fence_error}"
                    )

        await asyncio.gather(
            *(resume_one(intent_id, lease_owner) for intent_id, lease_owner in claims)
        )

    async def resume_aborted_launch_intents(self) -> None:
        """Retry only explicitly aborted intents during live reconciliation."""
        await self.resume_launch_intents()

    async def abort_launch_intent(
        self,
        intent_id: str,
        *,
        lease_owner: str,
        failure: BaseException | None = None,
    ) -> bool:
        """Persist an exact abort before revoking registry and job authority."""
        async with get_session() as session:
            intent = await session.get(
                MinerLaunchIntent,
                intent_id,
                with_for_update=True,
            )
            if intent is None or intent.phase in {"consumed", "completed", "failed"}:
                return False
            self._validated_launch_intent(intent)
            self._require_live_launch_intent_lease(intent, lease_owner)
            intent.phase = "cleanup_required"
            intent.last_failure = (
                f"{type(failure).__name__}: {failure}"[:8000]
                if failure is not None
                else None
            )
            intent.next_retry_at = None
            intent.retry_lease_expires_at = datetime.now(timezone.utc) + timedelta(
                seconds=LEASE_SECONDS
            )
            await session.commit()
        return await self._resume_launch_intent(
            intent_id,
            lease_owner=lease_owner,
        )

    async def _revoke_registry_scope(
        self,
        validator_hotkey: str,
        launch_config_id: str,
        server_id: str,
    ) -> None:
        if not settings.gpu_tee_only:
            return
        await request_registry_scope_revocation(
            launch_config_id=launch_config_id,
            validator=validator_hotkey,
            server_id=server_id,
        )
        result = await self._send_registry_scope_revocation(
            validator_hotkey,
            launch_config_id,
            server_id,
        )
        await record_registry_scope_revoked(launch_config_id, result)

    async def _send_registry_scope_revocation(
        self,
        validator_hotkey: str,
        launch_config_id: str,
        server_id: str,
    ) -> dict[str, Any]:
        """Send the exact broker DELETE without changing database authority."""

        if not settings.gpu_tee_only:
            raise DeploymentFailure("Registry scope revocation is unavailable.")
        if not isinstance(server_id, str) or not server_id:
            raise DeploymentFailure("Registry scope server identity is unavailable.")
        validator = validator_by_hotkey(validator_hotkey)
        if validator is None:
            raise DeploymentFailure("Registry scope validator is unavailable.")
        headers, _ = sign_request(purpose="registry")
        headers["X-Chutes-Server-Id"] = server_id
        headers["X-Chutes-Registry-Workload-Token"] = settings.registry_workload_token
        service = f"registry-{validator.hotkey.lower()}.{settings.namespace}.svc.cluster.local:5000"
        async with aiohttp.ClientSession(
            raise_for_status=False,
            timeout=REGISTRY_SCOPE_HTTP_TIMEOUT,
        ) as session:
            async with session.delete(
                f"http://{service}/registry/scopes/{launch_config_id}",
                headers=headers,
            ) as response:
                result = await response.json()
                expected = {
                    "status": result.get("status")
                    if isinstance(result, dict)
                    else None,
                    "revoked": True,
                    "launch_config_id": launch_config_id,
                    "server_id": server_id,
                }
                if (
                    expected["status"] not in {"revoked", "already_absent"}
                    or response.status != 200
                    or result != expected
                ):
                    raise DeploymentFailure(
                        "Registry broker did not revoke exact launch lifecycle."
                    )
        return result

    async def _fetch_launch_config(
        self,
        *,
        validator: Validator,
        chute_id: str,
        server_id: str,
        job_id: str | None,
        intent_id: str,
        deployment_id: str,
    ) -> dict[str, Any]:
        """Replay one persisted validator request without recomputing its lineage."""
        async with aiohttp.ClientSession(
            raise_for_status=False,
            timeout=LAUNCH_AUTHORITY_HTTP_TIMEOUT,
        ) as session:
            headers, _ = sign_request(purpose="launch")
            params = {"chute_id": chute_id, "server_id": server_id}
            if job_id:
                params["job_id"] = job_id
            params["miner_launch_request_id"] = intent_id
            params["miner_deployment_id"] = deployment_id
            async with session.get(
                f"{validator.api}/instances/launch_config",
                headers=headers,
                params=params,
            ) as resp:
                if resp.status == 200:
                    payload = await resp.json()
                    required = (
                        {"token", "config_id", "registry"}
                        if settings.gpu_tee_only
                        else {"token", "config_id"}
                    )
                    if not isinstance(payload, dict) or set(payload) != required:
                        raise DeploymentFailure(
                            f"Invalid launch config response for {chute_id}: "
                            f"expected exactly {sorted(required)}."
                        )
                    if not all(
                        isinstance(payload[field], str) and payload[field]
                        for field in ("token", "config_id")
                    ):
                        raise DeploymentFailure(
                            f"Invalid launch config response for {chute_id}: "
                            "token and config_id must be non-empty strings."
                        )
                    if settings.gpu_tee_only:
                        registry = payload["registry"]
                        if (
                            not isinstance(registry, dict)
                            or set(registry) != {"repository", "manifest_digest"}
                            or not isinstance(registry["repository"], str)
                            or not re.fullmatch(
                                r"sha256:[0-9a-f]{64}",
                                registry.get("manifest_digest", ""),
                            )
                        ):
                            raise DeploymentFailure(
                                "Invalid descriptor-closed registry launch scope."
                            )
                    return payload

                error_body = await resp.text()
                if resp.status == 423:
                    message = (
                        f"Unable to scale up {chute_id} at this time. "
                        f"Validator reported capacity issue: {error_body}"
                    )
                    logger.warning(message)
                else:
                    message = (
                        f"Failed to fetch launch token for {chute_id}: "
                        f"status={resp.status}, body={error_body}"
                    )
                    logger.error(message)
                raise DeploymentFailure(message)

    async def get_launch_token(
        self,
        chute: Chute,
        server: Server,
        job_id: str = None,
        deployment_id: str | None = None,
    ):
        """
        Fetch the validator-issued launch config required to deliver source.
        """
        require_supported_chutes_version(chute.chutes_version, chute.chute_id)
        if (validator := validator_by_hotkey(chute.validator)) is None:
            raise DeploymentFailure(f"Validator not found: {chute.validator}")
        deployment_id = deployment_id or str(uuid.uuid4())
        lease_owner = self._launch_intent_lease_owner("producer")
        intent_id = await self._begin_launch_intent(
            chute,
            server,
            job_id,
            deployment_id,
            lease_owner=lease_owner,
        )
        try:
            payload = await self._fetch_launch_config(
                validator=validator,
                chute_id=chute.chute_id,
                server_id=server.server_id,
                job_id=job_id,
                intent_id=intent_id,
                deployment_id=deployment_id,
            )
            await self._record_launch_response(
                intent_id,
                payload,
                lease_owner=lease_owner,
            )
            registry_ack = await self._register_registry_scope(
                validator,
                server,
                payload,
            )
            await self._record_registry_ack(
                intent_id,
                registry_ack,
                lease_owner=lease_owner,
            )
            payload["_miner_launch_request_id"] = intent_id
            payload["_miner_deployment_id"] = deployment_id
            payload["_miner_launch_lease_owner"] = lease_owner
            return payload
        except DeploymentFailure as exc:
            try:
                await self.abort_launch_intent(
                    intent_id,
                    lease_owner=lease_owner,
                    failure=exc,
                )
            except DeploymentFailure as cleanup_exc:
                logger.error(
                    f"Launch cleanup lost its durable fence for {intent_id}: "
                    f"{cleanup_exc}"
                )
            raise
        except Exception as exc:
            try:
                await self.abort_launch_intent(
                    intent_id,
                    lease_owner=lease_owner,
                    failure=exc,
                )
            except DeploymentFailure as cleanup_exc:
                logger.error(
                    f"Launch cleanup lost its durable fence for {intent_id}: "
                    f"{cleanup_exc}"
                )
            logger.warning(f"Unable to fetch launch config token: {exc}")
            raise DeploymentFailure(f"Failed to fetch JWT for launch: {exc}") from exc

    async def _autoscale(self):
        """
        Autoscale chutes based on effective_compute_multiplier.

        The effective_compute_multiplier is the sole metric that matters for incentive.
        It includes all bonuses (bounty age, urgency, TEE, private) baked in at activation.
        """
        # Refresh remote data - chutes, instances, etc. change dynamically
        await self.remote_refresh_all()

        # Load chute utilization to see if it can scale.
        scalable = {}
        for validator in settings.validators:
            scalable[validator.hotkey] = {}
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        f"{validator.api}/chutes/utilization"
                    ) as resp:
                        for item in await resp.json():
                            if item.get("scalable") is False:
                                scalable[validator.hotkey][item["chute_id"]] = False
                            if item.get("update_in_progress") is True:
                                scalable[validator.hotkey][item["chute_id"]] = False
                except Exception as exc:
                    logger.error(
                        f"Failed to fetch chute utilization from {validator=}: {exc}"
                    )

        # Evaluate chutes by effective_compute_multiplier / cost ratio
        chute_values = []
        for validator, chutes in self.remote_chutes.items():
            for chute_id, chute_info in chutes.items():
                try:
                    chute = await self.load_chute(
                        chute_id, chute_info["version"], validator
                    )
                    if not chute:
                        continue
                    if not chute_info.get("cords"):
                        continue
                    if scalable.get(validator, {}).get(chute_id) not in (None, True):
                        continue

                    # Get effective compute multiplier - this is what determines incentive
                    effective_multiplier = chute_info.get(
                        "effective_compute_multiplier", 1.0
                    )
                    if effective_multiplier <= 0:
                        continue

                    # See if we have a server that could handle it.
                    potential_server = await self.optimal_scale_up_server(chute)
                    if not potential_server:
                        continue

                    # XXX Miners you can choose two options here:
                    # 1. use the effective multiplier directly, which
                    #    can increase your overall score, but leave your
                    #    theoretical max incentive lacking in the sense that
                    #    you may be using more powerful servers than necessary
                    #    for a given chute.
                    # 2. use the effective multiplier scaled by GPU costs, which
                    #    maximize the efficiency/value but may leave some incentive
                    #    on the table.
                    # Default strategy is to maximize value, i.e. highest multiplier per GPU/option 2.
                    hourly_cost = self._server_hourly_cost(potential_server)
                    chute_value = effective_multiplier / (hourly_cost * chute.gpu_count)
                    # alternative
                    # chute_value = effective_multiplier

                    chute_values.append(
                        (validator, chute_id, chute_value, effective_multiplier)
                    )

                except Exception as e:
                    logger.error(f"Error processing chute {chute_id}: {e}")
                    continue

        if not chute_values:
            logger.info("No chutes available to scale.")
            return

        # Sort by value and attempt to deploy the highest value chute
        chute_values.sort(key=lambda x: x[2], reverse=True)
        for validator, chute_id, value, multiplier in chute_values:
            chute_info = self.remote_chutes[validator].get(chute_id, {})
            chute = await self.load_chute(
                chute_id, chute_info.get("version"), validator
            )
            if chute is None:
                continue

            # Skip if we already have a deployment pending activation; don't deploy more until it's up.
            if await self.has_pending_deployment(chute_id, chute.version, validator):
                logger.debug(
                    f"Skipping scale of {chute.name} ({chute_id}): already have a deployment pending activation"
                )
                continue

            logger.info(
                f"Scaling {chute.name} ({chute_id}) effective_multiplier={multiplier:.2f} value={value:.4f}"
            )
            current_count = await self.count_non_job_deployments(
                chute_id, chute.version, validator
            )
            if await self.scale_chute(chute, current_count + 1, preempt=False):
                break

    async def autoscaler(self):
        """
        Main autoscaling loop.
        """
        while True:
            try:
                await self._autoscale()
            except Exception as exc:
                logger.error(
                    f"Unexpected error in autoscaling loop: {exc}\n{traceback.format_exc()}"
                )
            await asyncio.sleep(15)

    @staticmethod
    async def purge_validator_instance(
        vali: Validator, chute_id: str, instance_id: str
    ):
        try:
            async with aiohttp.ClientSession() as session:
                headers, _ = sign_request(purpose="instances")
                async with session.delete(
                    f"{vali.api}/instances/{chute_id}/{instance_id}", headers=headers
                ) as resp:
                    logger.debug(await resp.text())
                    if resp.status not in (200, 404):
                        raise Exception(
                            f"status_code={resp.status}, response text: {await resp.text()}"
                        )
                    elif resp.status == 200:
                        logger.info(f"Deleted instance from validator {vali.hotkey}")
                    else:
                        logger.info(f"{instance_id=} already purged from {vali.hotkey}")
        except Exception as exc:
            logger.warning(f"Error purging {instance_id=} from {vali.hotkey=}: {exc}")

    async def undeploy(
        self,
        deployment_id: str,
        instance_id: str = None,
        *,
        reason: str = "requested",
    ) -> bool:
        """Request and advance the restartable teardown for a Deployment."""
        del instance_id  # The durable operation snapshots the authoritative DB value.
        logger.info(f"Requesting durable teardown: {deployment_id=} {reason=}")
        completed = await self.teardown.request_and_run(deployment_id, reason)
        if completed:
            logger.success(f"Durable teardown completed for {deployment_id=}")
        else:
            logger.warning(
                f"Durable teardown for {deployment_id=} is retained for retry or review"
            )
        return completed

    async def cleanup_kubernetes_orphan(self, resource: dict[str, Any]) -> bool:
        """Persist a UID-scoped tombstone before deleting an untracked K8s workload."""
        deployment_id = resource.get("deployment_id")
        cluster_context = resource.get("node")
        labels = resource.get("labels") or {}
        if not deployment_id or not cluster_context:
            logger.error(
                "Refusing Kubernetes orphan cleanup without deployment and cluster lineage: "
                f"{resource}"
            )
            return False
        tombstone_id = await self.teardown.request_orphan(
            deployment_id=deployment_id,
            cluster_context=cluster_context,
            immutable_labels={
                key: str(value)
                for key, value in labels.items()
                if key
                in {
                    "chutes/deployment-id",
                    "chutes/chute-id",
                    "chutes/config-id",
                    "chutes/job-id",
                }
            },
        )
        return bool(tombstone_id and await self.teardown.run_orphan(tombstone_id))

    async def gpu_verified(self, event_data):
        """
        Validator has finished verifying a GPU, so it is ready for use.
        """
        if self._platform_managed(event_data):
            return
        logger.info(f"Received gpu_verified event: {event_data}")
        async with get_session() as session:
            await session.execute(
                update(GPU)
                .where(GPU.hardware_uuid == event_data.get("gpu_id"))
                .values({"verified": True})
            )
            await session.commit()
        # Nothing to do here really, the autoscaler should take care of it, but feel free to change...

    async def instance_created(self, event_data):
        """
        Instance has been created - only relevant when using new launch config system.
        """
        if self._platform_managed(event_data):
            return
        if event_data["miner_hotkey"] != settings.miner_ss58:
            return
        logger.info(f"Received instance_created event: {event_data}")
        action = await self.teardown.bind_instance_created(
            config_id=event_data["config_id"],
            instance_id=event_data["instance_id"],
        )
        if action:
            action_type, operation_id = action
            if action_type == "teardown":
                await self.teardown.run(operation_id)
            else:
                await self.teardown.run_delayed_instance_cleanup(operation_id)

    async def instance_verified(self, event_data):
        """
        Validator has finished verifying an instance/deployment, so it should start receiving requests.
        """
        if self._platform_managed(event_data):
            return
        logger.info(f"Received instance_verified event: {event_data}")
        if event_data["miner_hotkey"] != settings.miner_ss58:
            return
        async with get_session() as session:
            await session.execute(
                update(Deployment)
                .where(Deployment.instance_id == event_data.get("instance_id"))
                .values({"verified_at": func.now()})
            )
        # Nothing to do here really, it should just start receiving traffic.

    async def _release_job_exact(
        self,
        validator_hotkey: str,
        job_id: str,
    ) -> dict[str, Any]:
        """Return a stable ACK for an idempotent validator job-lock release."""
        validator = validator_by_hotkey(validator_hotkey)
        if validator is None:
            raise DeploymentFailure("Validator job owner is unavailable")
        async with aiohttp.ClientSession(
            raise_for_status=False,
            timeout=LAUNCH_AUTHORITY_HTTP_TIMEOUT,
        ) as session:
            headers, _ = sign_request(purpose="miner")
            async with session.delete(
                f"{validator.api}/miner/jobs/{job_id}",
                headers=headers,
            ) as response:
                body = await response.read()
                if response.status not in {200, 404}:
                    raise DeploymentFailure(
                        f"validator job release returned HTTP {response.status}"
                    )
        return {
            "status": "released" if response.status == 200 else "already_absent",
            "job_id": job_id,
            "response_sha256": hashlib.sha256(body).hexdigest(),
        }

    async def _get_job_extra_services(self, chute: Chute):
        """
        Get the list of extra services (i.e. extra ports that the chute requires) for a chute.
        """
        if (
            chute_obj := self.remote_chutes.get(chute.validator, {}).get(chute.chute_id)
        ) is None:
            if (validator := validator_by_hotkey(chute.validator)) is None:
                # Won't work anyways, but we'll avoid an exception here...
                logger.warning(f"No validator found? {chute.validator=}")
                return []
            await self._remote_refresh_objects(
                self.remote_chutes,
                chute.validator,
                f"{validator.api}/miner/chutes/",
                "chute_id",
            )
            chute_obj = self.remote_chutes.get(chute.validator, {}).get(chute.chute_id)
        if not chute_obj:
            logger.warning(
                f"Could not find {chute.chute_id=} in remote chutes when trying to determine job services!"
            )
            return []
        if not chute_obj.get("jobs"):
            return []
        extra_services = []
        observed = set([])
        for job in chute_obj["jobs"]:
            for port in job.get("ports") or []:
                skip_key = f"{port['proto']}:{port['port']}"
                if skip_key in observed:
                    continue
                observed.add(skip_key)
                extra_services.append(port)
                extra_services[-1]["proto"] = (
                    "TCP"
                    if extra_services[-1]["proto"].lower() in ("tcp", "http")
                    else "UDP"
                )
                logger.info(f"Adding {port=} to job for {chute.chute_id=}")
        return extra_services

    async def run_job(
        self,
        chute: Chute,
        job_id: str,
        server: Server,
        validator: Validator,
        disk_gb: int = 10,
    ):
        """
        Run a job on the specified server.
        """
        logger.info(
            f"Attempting to deploy {job_id=} for {chute.chute_id=} on {server.server_id=} with {disk_gb=}"
        )
        deployment = None
        launch_token = None
        token_requested = False
        try:
            self._require_validator_match(chute, server)
            if validator.hotkey != chute.validator:
                raise DeploymentFailure(
                    f"Job validator {validator.hotkey!r} does not match chute validator {chute.validator!r}."
                )
            token_requested = True
            launch_token = await self.get_launch_token(
                chute,
                server,
                job_id=job_id,
            )
            async with self._launch_intent_lease_guard(
                launch_token["_miner_launch_request_id"],
                launch_token["_miner_launch_lease_owner"],
            ):
                extra_ports = await self._get_job_extra_services(chute)
            await self._renew_launch_intent_lease(
                launch_token["_miner_launch_request_id"],
                launch_token["_miner_launch_lease_owner"],
            )
            deployment, k8s_dep = await k8s.deploy_chute(
                chute.chute_id,
                server.server_id,
                token=launch_token["token"],
                launch_intent_id=launch_token["_miner_launch_request_id"],
                launch_intent_lease_owner=launch_token[
                    "_miner_launch_lease_owner"
                ],
                config_id=launch_token["config_id"],
                registry_repository=(launch_token.get("registry") or {}).get(
                    "repository"
                ),
                registry_manifest_digest=(launch_token.get("registry") or {}).get(
                    "manifest_digest"
                ),
                job_id=job_id,
                extra_labels={"chutes/job": "true"},
                disk_gb=disk_gb,
                extra_service_ports=extra_ports,
                vm_version=self._server_vm_version(chute.validator, server.server_id),
            )
            logger.success(
                f"Successfully deployed {job_id=} {chute.chute_id=} on {server.server_id=}: {deployment.deployment_id=}"
            )
        except DeploymentFailure as exc:
            logger.error(
                f"Error attempting to deploy {chute.chute_id=} on {server.server_id=}: {exc}\n{traceback.format_exc()}"
            )
            if deployment:
                await self.undeploy(
                    deployment.deployment_id, reason="job_launch_failure"
                )
            elif launch_token:
                await self.abort_launch_intent(
                    launch_token["_miner_launch_request_id"],
                    lease_owner=launch_token["_miner_launch_lease_owner"],
                    failure=exc,
                )
            elif not token_requested:
                cleanup_lease_owner = self._launch_intent_lease_owner(
                    "job-cleanup"
                )
                cleanup_intent_id = await self._begin_job_cleanup_intent(
                    chute,
                    server,
                    job_id,
                    lease_owner=cleanup_lease_owner,
                )
                await self.abort_launch_intent(
                    cleanup_intent_id,
                    lease_owner=cleanup_lease_owner,
                    failure=exc,
                )

    async def chute_updated(self, event_data: Dict[str, Any]):
        """
        Chute has been updated.
        """
        if self._platform_managed(event_data):
            return
        chute_id = event_data["chute_id"]
        version = event_data["version"]
        validator_hotkey = event_data["validator"]
        logger.info(
            f"Received chute_updated event from {validator_hotkey=} for {chute_id=} {version=}"
        )

        if (validator := validator_by_hotkey(validator_hotkey)) is None:
            logger.warning(f"Validator not found: {validator_hotkey}")
            return

        # Reload the definition directly from the validator.
        chute_dict = None
        try:
            async with aiohttp.ClientSession(raise_for_status=True) as session:
                headers, _ = sign_request(purpose="miner")
                async with session.get(
                    f"{validator.api}/miner/chutes/{chute_id}/{version}",
                    headers=headers,
                ) as resp:
                    chute_dict = await resp.json()
            chute_values = self._remote_chute_values(
                chute_dict,
                validator_hotkey,
                expected_chute_id=chute_id,
                expected_version=version,
            )
        except Exception as exc:
            logger.error(
                f"Error loading remote chute data: {chute_id=} {version=}: {exc}"
            )
            return

        # Upsert the chute in the local DB.
        async with get_session() as db:
            chute = (
                (
                    await db.execute(
                        select(Chute).where(
                            Chute.chute_id == chute_id,
                            Chute.validator == validator_hotkey,
                        )
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            if chute:
                for key, value in chute_values.items():
                    if key != "validator":
                        setattr(chute, key, value)
            else:
                chute = Chute(
                    chute_id=chute_id,
                    **chute_values,
                )
                db.add(chute)
            await db.commit()
            await db.refresh(chute)

    async def job_created(self, event_data: Dict[str, Any]):
        """
        Job available for processing.

        MINERS: This is another crtically important method to optimize. You don't want to
                blindly accept jobs and preempt your existing deployments most likely, but
                there are benefits to accepting them (you get a bounty, compute multiplier
                is semi-dynamic and may provide more compute units than a chute, etc).
        """
        if self._platform_managed(event_data):
            return
        chute_id = event_data["chute_id"]
        job_id = event_data["job_id"]
        gpu_count = event_data["gpu_count"]
        compute_multiplier = event_data["compute_multiplier"]
        validator_hotkey = event_data["validator"]
        disk_gb = event_data["disk_gb"]

        logger.info(
            f"Received job_created event for {chute_id=} {job_id=} with {gpu_count=} and {compute_multiplier=} and {disk_gb=}"
        )
        if settings.miner_ss58 in event_data.get("excluded", []):
            logger.warning("Miner hotkey excluded from job!")
            return
        if (validator := validator_by_hotkey(validator_hotkey)) is None:
            logger.warning(f"Validator not found: {validator_hotkey}")
            return

        # Do we already have a node that can accept the job, without pre-emption?
        chute = await self.get_chute(chute_id, validator_hotkey)
        if not chute:
            logger.warning(f"Failed to load chute: {chute_id}")
            return
        server = await self.optimal_scale_up_server(chute, disk_gb=disk_gb)
        if server:
            await self.run_job(chute, job_id, server, validator, disk_gb)
            return

        # XXX This is where you as a miner definitely want to customize the strategy!
        logger.info(
            f"Attempting a pre-empting deploy of {job_id=} {chute_id=} with {chute.supported_gpus=} and {gpu_count=}"
        )
        await self.preempting_deploy(chute, job_id=job_id, disk_gb=disk_gb)

    async def job_deleted(self, event_data: Dict[str, Any]):
        """
        Job has been deleted.
        """
        if self._platform_managed(event_data):
            return
        async with get_session() as session:
            deployment = (
                (
                    await session.execute(
                        select(Deployment).where(
                            Deployment.job_id == event_data["job_id"]
                        )
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
        if deployment:
            logger.info(
                f"Received job_deleted event, undeploying {deployment.deployment_id=}!"
            )
            await self.undeploy(deployment.deployment_id, reason="job_deleted")

    async def bounty_changed(self, event_data):
        """
        Bounty has changed for a chute.
        """
        logger.info(f"Received bounty_change event: {event_data}")

        # Check if we have this thing deployed already (or in progress).
        chute = None
        async with get_session() as session:
            result = await session.execute(
                select(Deployment).where(Deployment.chute_id == event_data["chute_id"])
            )
            deployment = result.unique().scalars().first()
            if deployment:
                logger.info(
                    f"Ignoring bounty event, already have a deployment pending: {deployment.deployment_id}"
                )
                return
            chute = await self.get_chute(
                event_data["chute_id"], event_data["validator"]
            )
        if chute:
            logger.info(f"Attempting to claim the bounty: {event_data}")
            await self.scale_chute(chute, 1, preempt=True)

    @staticmethod
    def require_generic_gpu_deletion(gpu_allocation_group_id: Optional[str]) -> None:
        if gpu_allocation_group_id is not None:
            raise ValueError(
                "reservation-owned GPU requires exact teardown/reset, not generic deletion"
            )

    @staticmethod
    async def remove_gpu_from_validator(
        validator: Validator,
        gpu_id: str,
        gpu_allocation_group_id: Optional[str] = None,
    ):
        """
        Purge a GPU from validator inventory.
        """
        Gepetto.require_generic_gpu_deletion(gpu_allocation_group_id)
        try:
            async with aiohttp.ClientSession(raise_for_status=True) as http_session:
                headers, _ = sign_request(purpose="nodes")
                async with http_session.delete(
                    f"{validator.api}/nodes/{gpu_id}", headers=headers
                ) as resp:
                    logger.success(
                        f"Successfully purged {gpu_id=} from validator={validator.hotkey}: {await resp.json()}"
                    )
        except Exception as exc:
            logger.error(
                f"Error purging {gpu_id=} from validator={validator.hotkey}: {exc}"
            )

    async def gpu_deleted(self, event_data):
        """
        GPU no longer exists in validator inventory for some reason.

        MINERS: This shouldn't really happen, unless the validator purges it's database
                or some such other rare event.  You may want to configure alerts or something
                in this code block just in case.
        """
        if self._platform_managed(event_data):
            return
        gpu_id = event_data["gpu_id"]
        logger.info(f"Received gpu_deleted event for {gpu_id=}")
        deployment_id = None
        validator_hotkey = None
        allocation_group_id = None
        async with get_session() as session:
            gpu = (
                (await session.execute(select(GPU).where(GPU.hardware_uuid == gpu_id)))
                .unique()
                .scalar_one_or_none()
            )
            if gpu:
                try:
                    self.require_generic_gpu_deletion(gpu.gpu_allocation_group_id)
                except ValueError as exc:
                    logger.error(
                        f"Refusing gpu_deleted generic teardown for {gpu_id}: {exc}"
                    )
                    return
                deployment_id = gpu.deployment_id
                validator_hotkey = gpu.validator
                allocation_group_id = gpu.gpu_allocation_group_id
        if deployment_id and not await self.undeploy(
            deployment_id,
            reason="gpu_deleted",
        ):
            logger.warning(
                f"Retaining {gpu_id=} until its deployment teardown completes"
            )
            return
        if (validator := validator_by_hotkey(validator_hotkey)) is not None:
            await self.remove_gpu_from_validator(
                validator,
                gpu_id,
                allocation_group_id,
            )
        async with get_session() as session:
            gpu = (
                await session.execute(
                    select(GPU).where(GPU.hardware_uuid == gpu_id).with_for_update()
                )
            ).scalar_one_or_none()
            if gpu:
                if gpu.deployment_id is not None:
                    logger.warning(f"Retaining reassigned {gpu_id=}")
                    return
                await session.delete(gpu)
                await session.commit()
        logger.info(f"Finished processing gpu_deleted event for {gpu_id=}")

    async def instance_activated(self, event_data: dict[str, Any]):
        """
        An instance has been marked as active (new chutes lib flow).
        """
        if self._platform_managed(event_data):
            return
        config_id = event_data["config_id"]
        logger.info(f"Received instance_activated event for {config_id=}")
        async with get_session() as session:
            await session.execute(
                text(
                    "UPDATE deployments SET active = true, activated_at = now(), stub = false WHERE config_id = :config_id"
                ),
                {"config_id": config_id},
            )

    async def instance_deleted(self, event_data: Dict[str, Any]):
        """
        An instance was removed validator side, likely meaning there were too
        many consecutive failures in inference.
        """
        if self._platform_managed(event_data):
            return
        instance_id = event_data["instance_id"]
        logger.info(f"Received instance_deleted event for {instance_id=}")
        async with get_session() as session:
            deployment = (
                (
                    await session.execute(
                        select(Deployment).where(Deployment.instance_id == instance_id)
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
        if deployment:
            await self.undeploy(deployment.deployment_id, reason="instance_deleted")
        logger.info(f"Finished processing instance_deleted event for {instance_id=}")

    async def server_deleted(self, event_data: Dict[str, Any]):
        """
        An entire kubernetes node was removed from your inventory.

        MINERS: This will happen when you remove a node intentionally, but otherwise
                should not really happen.  Also want to monitor this situation I think.
        """
        if self._platform_managed(event_data):
            return
        server_id = event_data["server_id"]
        logger.info(f"Received server_deleted event {server_id=}")

        operation_id = await self.teardown.request_parent(
            "server",
            server_id,
            "server_deleted",
        )
        if operation_id:
            await self.teardown.run_parent(operation_id)

        logger.info(f"Finished processing server_deleted event for {server_id=}")

    async def image_deleted(self, event_data: Dict[str, Any]):
        """
        An image was deleted (should clean up maybe?)
        """
        logger.info(
            f"Image deleted, but I'm lazy and will let k8s clean up: {event_data}"
        )

    async def image_created(self, event_data: Dict[str, Any]):
        """
        An image was created, we could be extra eager and pull the image onto each GPU node so it's hot faster.
        """
        logger.info(
            f"Image created, but I'm going to lazy load the image when chutes are created: {event_data}"
        )

    async def image_updated(self, event_data: Dict[str, Any]):
        """
        Image was updated, i.e. the chutes version of an image was upgraded.
        """
        logger.info(f"Image updated: {event_data}")
        chute_ids = event_data.get("chute_ids", [])
        if chute_ids:
            async with get_session() as session:
                await session.execute(
                    text(
                        "UPDATE chutes SET chutes_version = :chutes_version, image = :image WHERE chute_id = ANY(:chute_ids)"
                    ),
                    {
                        "image": event_data.get("image"),
                        "chute_ids": chute_ids,
                        "chutes_version": event_data["chutes_version"],
                    },
                )
                await session.commit()

    async def chute_deleted(self, event_data: Dict[str, Any]):
        """
        A chute (or specific version of a chute) was removed from validator inventory.
        """
        if self._platform_managed(event_data):
            return
        chute_id = event_data["chute_id"]
        version = event_data["version"]
        validator = event_data["validator"]
        logger.info(f"Received chute_deleted event for {chute_id=} {version=}")
        async with get_session() as session:
            chute = await session.scalar(
                select(Chute).where(
                    Chute.chute_id == chute_id,
                    Chute.version == version,
                    Chute.validator == validator,
                )
            )
        if chute:
            operation_id = await self.teardown.request_parent(
                "chute",
                chute_id,
                "chute_deleted",
                expected_validator=validator,
                expected_chute_version=version,
            )
            if operation_id:
                await self.teardown.run_parent(operation_id)

    async def chute_created(self, event_data: Dict[str, Any], desired_count: int = 1):
        """
        A brand new chute was added to validator inventory.

        MINERS: This is a critical optimization path. A chute being created
                does not necessarily mean inference will be requested. The
                base mining code here *will* deploy the chute however, given
                sufficient resources are available.
        """
        if self._platform_managed(event_data):
            return
        chute_id = event_data["chute_id"]
        version = event_data["version"]
        validator_hotkey = event_data["validator"]
        logger.info(f"Received chute_created event for {chute_id=} {version=}")
        if (validator := validator_by_hotkey(validator_hotkey)) is None:
            logger.warning(f"Validator not found: {validator_hotkey}")
            return

        # Already in inventory?
        if (
            chute := await self.load_chute(chute_id, version, validator_hotkey)
        ) is not None:
            logger.info(
                f"Chute {chute_id=} {version=} is already tracked in inventory?"
            )
            return

        # Load the chute details, preferably from the local cache.
        chute_dict = None
        try:
            async with aiohttp.ClientSession(raise_for_status=True) as session:
                headers, _ = sign_request(purpose="miner")
                async with session.get(
                    f"{validator.api}/miner/chutes/{chute_id}/{version}",
                    headers=headers,
                ) as resp:
                    chute_dict = await resp.json()
            chute_values = self._remote_chute_values(
                chute_dict,
                validator_hotkey,
                expected_chute_id=chute_id,
                expected_version=version,
            )
        except Exception as exc:
            logger.error(
                f"Error loading remote chute data: {chute_id=} {version=}: {exc}"
            )
            return

        # Track in inventory.
        async with get_session() as session:
            chute = Chute(
                chute_id=chute_id,
                **chute_values,
            )
            session.add(chute)
            await session.commit()
            await session.refresh(chute)

        # Don't deploy if this is a job-only chute, i.e. it has no "cords" to serve
        # so there's nothing to deploy.
        if event_data.get("job_only"):
            return

        # This should never be anything other than 0, but just in case...
        current_count = await self.count_non_job_deployments(
            chute.chute_id, chute.version, chute.validator
        )
        if not current_count:
            await self.scale_chute(chute, desired_count=desired_count, preempt=False)

    async def rolling_update(self, event_data: Dict[str, Any]):
        """
        A rolling update event, meaning we need to re-create a single instance.
        """
        if self._platform_managed(event_data):
            return
        async with self._scale_lock:
            chute_id = event_data["chute_id"]
            version = event_data["new_version"]
            validator_hotkey = event_data["validator"]
            instance_id = event_data["instance_id"]
            image = event_data.get("image", None)
            reason = event_data.get("reason", "chute updated")
            logger.info(
                f"Received rolling update event for {chute_id=} {version=} {instance_id=}, {reason=}, {image=}"
            )

            if (validator := validator_by_hotkey(validator_hotkey)) is None:
                logger.warning(f"Validator not found: {validator_hotkey}")
                return

            # Remove the instance/deployment.
            server_id = None
            server = None
            server_gpu_type = None
            server_validator = None
            old_deployment_id = None
            async with get_session() as session:
                deployment = (
                    (
                        await session.execute(
                            select(Deployment).where(
                                Deployment.instance_id == instance_id,
                                Deployment.chute_id == chute_id,
                                Deployment.validator == validator_hotkey,
                                Deployment.job_id.is_(None),
                            )
                        )
                    )
                    .unique()
                    .scalar_one_or_none()
                )
                if deployment:
                    old_deployment_id = deployment.deployment_id
                    server = deployment.server
                    server_id = deployment.server.server_id
                    server_gpu_type = deployment.server.gpus[0].model_short_ref
                    server_is_tee = deployment.server.is_tee
                    server_validator = deployment.server.validator
                    if server_validator != validator_hotkey:
                        logger.error(
                            f"Refusing rolling update for {instance_id=}: deployment validator "
                            f"{validator_hotkey!r} does not match server validator "
                            f"{server_validator!r}"
                        )
                        return
                    try:
                        self._server_hourly_cost(server)
                    except DeploymentFailure as exc:
                        logger.error(
                            f"Refusing rolling update for {instance_id=}: {exc}"
                        )
                        return
            if old_deployment_id and not await self.undeploy(
                old_deployment_id,
                reason="rolling_update",
            ):
                logger.warning(
                    f"Rolling update retained old deployment {old_deployment_id}; retrying later"
                )
                return

            # Make sure the local chute is updated.
            if (
                chute := await self.load_chute(chute_id, version, validator_hotkey)
            ) is None:
                chute_dict = None
                try:
                    async with aiohttp.ClientSession(raise_for_status=True) as session:
                        headers, _ = sign_request(purpose="miner")
                        async with session.get(
                            f"{validator.api}/miner/chutes/{chute_id}/{version}",
                            headers=headers,
                        ) as resp:
                            chute_dict = await resp.json()
                    chute_values = self._remote_chute_values(
                        chute_dict,
                        validator_hotkey,
                        expected_chute_id=chute_id,
                        expected_version=version,
                    )
                except Exception as exc:
                    logger.error(
                        f"Error loading remote chute data: {chute_id=} {version=}: {exc}"
                    )
                    return

                async with get_session() as db:
                    chute = (
                        (
                            await db.execute(
                                select(Chute).where(
                                    Chute.chute_id == chute_id,
                                    Chute.validator == validator_hotkey,
                                )
                            )
                        )
                        .unique()
                        .scalar_one_or_none()
                    )
                    if chute:
                        for key, value in chute_values.items():
                            if key != "validator":
                                setattr(chute, key, value)
                    else:
                        chute = Chute(
                            chute_id=chute_id,
                            **chute_values,
                        )
                        db.add(chute)
                    await db.commit()
                    await db.refresh(chute)

            # Deploy the new version.
            logger.info(
                f"Determining if we can deploy {chute.chute_id=} on {server_id=} with {server_gpu_type=} and supported={chute.supported_gpus}"
            )
            if (
                server_id
                and server_validator == chute.validator
                and server_gpu_type in chute.supported_gpus
                and server_is_tee == chute.tee
            ):
                logger.info(f"Attempting to deploy {chute.chute_id=} on {server_id=}")
                deployment = None
                launch_token = None
                try:
                    launch_token = await self.get_launch_token(chute, server)
                    await self._renew_launch_intent_lease(
                        launch_token["_miner_launch_request_id"],
                        launch_token["_miner_launch_lease_owner"],
                    )
                    deployment, _ = await k8s.deploy_chute(
                        chute.chute_id,
                        server_id,
                        token=launch_token["token"],
                        launch_intent_id=launch_token["_miner_launch_request_id"],
                        launch_intent_lease_owner=launch_token[
                            "_miner_launch_lease_owner"
                        ],
                        config_id=launch_token["config_id"],
                        registry_repository=(launch_token.get("registry") or {}).get(
                            "repository"
                        ),
                        registry_manifest_digest=(
                            launch_token.get("registry") or {}
                        ).get("manifest_digest"),
                        vm_version=self._server_vm_version(chute.validator, server_id),
                    )
                    logger.success(
                        f"Successfully updated {chute_id=} to {version=} on {server_id=}: {deployment.deployment_id=}"
                    )
                except DeploymentFailure as exc:
                    logger.error(
                        f"Unhandled error attempting to deploy {chute.chute_id=} on {server_id=}: {exc}\n{traceback.format_exc()}"
                    )
                    if deployment:
                        await self.undeploy(
                            deployment.deployment_id,
                            reason="rolling_update_launch_failure",
                        )
                    elif launch_token:
                        await self.abort_launch_intent(
                            launch_token["_miner_launch_request_id"],
                            lease_owner=launch_token[
                                "_miner_launch_lease_owner"
                            ],
                            failure=exc,
                        )
                    return

    @staticmethod
    async def optimal_scale_down_deployment(chute: Chute) -> Optional[Deployment]:
        """
        Default strategy for scaling down chutes is to find a deployment based on
        server cost and what will be the server's GPU availability after removal.
        """
        gpu_counts = (
            select(
                Server.server_id,
                func.count(GPU.gpu_id).label("total_gpus"),
                func.sum(case((GPU.deployment_id.is_not(None), 1), else_=0)).label(
                    "used_gpus"
                ),  # noqa
            )
            .select_from(Server)
            .join(GPU)
            .group_by(Server.server_id)
            .subquery()
        )
        query = (
            select(
                Deployment,
                (
                    Server.hourly_cost
                    * (gpu_counts.c.used_gpus / gpu_counts.c.total_gpus)
                ).label("removal_score"),
            )
            .select_from(Deployment)
            .join(GPU)
            .join(Server)
            .join(gpu_counts, Server.server_id == gpu_counts.c.server_id)
            .where(Server.locked.is_(False))
            .where(Deployment.preemptible.is_(True))
            .where(Deployment.chute_id == chute.chute_id)
            .where(Deployment.validator == chute.validator)
            .where(Server.validator == chute.validator)
            .where(Deployment.job_id.is_(None))
            .where(Deployment.activated_at <= func.now() - timedelta(minutes=63))
            .order_by(text("removal_score DESC"))
            .limit(1)
        )
        async with get_session() as session:
            return (await session.execute(query)).unique().scalar_one_or_none()

    @staticmethod
    async def optimal_scale_up_server(
        chute: Chute, disk_gb: int = 10
    ) -> Optional[Server]:
        """
        Find the optimal server for scaling up a chute deployment.
        """
        if chute.ban_reason:
            logger.warning(
                f"Will not scale up banned chute {chute.chute_id=}: {chute.ban_reason=}"
            )
            return None
        if not chute.validator or validator_by_hotkey(chute.validator) is None:
            logger.error(
                f"Will not select a server for {chute.chute_id=}: validator {chute.validator!r} is not configured"
            )
            return None
        supported_gpus = list(chute.supported_gpus)
        total_gpus_per_server = (
            select(Server.server_id, func.count(GPU.gpu_id).label("total_gpus"))
            .select_from(Server)
            .join(GPU, Server.server_id == GPU.server_id)
            .where(GPU.model_short_ref.in_(supported_gpus), GPU.verified.is_(True))
            .group_by(Server.server_id)
            .subquery()
        )
        used_gpus_per_server = (
            select(Server.server_id, func.count(GPU.gpu_id).label("used_gpus"))
            .select_from(Server)
            .join(GPU, Server.server_id == GPU.server_id)
            .where(GPU.verified.is_(True), GPU.deployment_id.isnot(None))
            .group_by(Server.server_id)
            .subquery()
        )
        query = (
            select(
                Server,
                total_gpus_per_server.c.total_gpus,
                func.coalesce(used_gpus_per_server.c.used_gpus, 0).label("used_gpus"),
                (
                    total_gpus_per_server.c.total_gpus
                    - func.coalesce(used_gpus_per_server.c.used_gpus, 0)
                ).label("free_gpus"),
            )
            .select_from(Server)
            .join(
                total_gpus_per_server,
                Server.server_id == total_gpus_per_server.c.server_id,
            )
            .outerjoin(
                used_gpus_per_server,
                Server.server_id == used_gpus_per_server.c.server_id,
            )
            .join(GPU, Server.server_id == GPU.server_id)
            .where(
                GPU.model_short_ref.in_(supported_gpus),
                GPU.verified.is_(True),
                (
                    total_gpus_per_server.c.total_gpus
                    - func.coalesce(used_gpus_per_server.c.used_gpus, 0)
                    >= chute.gpu_count
                ),
                Server.locked.is_(False),
                Server.is_tee.is_(chute.tee),
                Server.validator == chute.validator,
            )
            # Cheapest first, then best-fit (fewest free GPUs that still satisfy the
            # chute) so we pack tightly and preserve emptier servers for larger models.
            .order_by(Server.hourly_cost.asc(), text("free_gpus ASC"))
        )
        async with get_session() as session:
            servers = (await session.execute(query)).unique().scalars().all()
        # Disk probes are external Kubernetes work and must not retain an ORM
        # transaction while a node is slow or unreachable.
        candidates = []
        for server in servers:
            try:
                Gepetto._require_validator_match(chute, server)
            except DeploymentFailure as exc:
                logger.error(f"Skipping invalid scale-up candidate: {exc}")
                continue
            required_disk_gb = deployment_disk_requirements(
                server, disk_gb
            ).ephemeral_storage_gb
            if await k8s.check_node_has_disk_available(server.name, required_disk_gb):
                candidates.append(server)
                if len(candidates) >= SCALE_UP_CANDIDATE_POOL:
                    break
        if candidates:
            return random.choice(candidates)
        return None

    def _get_global_instance_count(self, validator: str, chute_id: str) -> int:
        """
        Get the global instance count for a chute from the active_instances endpoint.
        """
        count = 0
        for instance in self.global_active_instances.get(validator, []):
            if instance.get("chute_id") == chute_id:
                count += 1
        return count

    def _get_instance_multiplier_from_global(
        self, validator: str, instance_id: str
    ) -> float:
        """
        Get compute_multiplier for an instance from global_active_instances.
        Returns 0.0 if not found.
        """
        for instance in self.global_active_instances.get(validator, []):
            if instance.get("instance_id") == instance_id:
                return float(instance.get("compute_multiplier", 0.0))
        return 0.0

    async def preempting_deploy(
        self, chute: Chute, job_id: str = None, disk_gb: int = 10
    ):
        """
        Force deploy a chute by preempting other deployments.

        Preemption rules:
        - Never preempt non-preemptible (private) deployments
        - Never preempt the only global instance of a chute
        - Never preempt if existing instance's multiplier >= new chute's effective_multiplier
        - Sort by instance compute_multiplier (lowest first) to preempt least valuable
        """
        if chute.ban_reason:
            logger.warning(
                f"Refusing to perform a preempting deploy of banned chute {chute.chute_id=}: {chute.ban_reason=}"
            )
            return False
        if not chute.validator or validator_by_hotkey(chute.validator) is None:
            logger.error(
                f"Refusing to preempt for {chute.chute_id=}: validator {chute.validator!r} is not configured"
            )
            return False

        supported_gpus = list(chute.supported_gpus)

        # Get the new chute's effective multiplier - this is what we'd gain
        new_chute_info = self.remote_chutes.get(chute.validator, {}).get(
            chute.chute_id, {}
        )
        new_effective_multiplier = new_chute_info.get(
            "effective_compute_multiplier", 1.0
        )

        # Check if we already have a deployment in progress (not yet activated) for this chute
        async with get_session() as session:
            pending_deployment = (
                await session.execute(
                    select(Deployment)
                    .where(Deployment.chute_id == chute.chute_id)
                    .where(Deployment.validator == chute.validator)
                    .where(Deployment.activated_at.is_(None))
                )
            ).scalar_one_or_none()
            if pending_deployment:
                logger.warning(
                    f"Already have a pending deployment for {chute.chute_id=}: {pending_deployment.deployment_id}"
                )
                return False

        # Find all servers that support this chute, sorted by cheapest & most already free GPUs.
        total_gpus_per_server = (
            select(Server.server_id, func.count(GPU.gpu_id).label("total_gpus"))
            .select_from(Server)
            .join(GPU, Server.server_id == GPU.server_id)
            .where(GPU.model_short_ref.in_(supported_gpus), GPU.verified.is_(True))
            .group_by(Server.server_id)
            .subquery()
        )
        used_gpus_per_server = (
            select(Server.server_id, func.count(GPU.gpu_id).label("used_gpus"))
            .select_from(Server)
            .join(GPU, Server.server_id == GPU.server_id)
            .where(GPU.verified.is_(True), GPU.deployment_id.isnot(None))
            .group_by(Server.server_id)
            .subquery()
        )
        query = (
            select(
                Server,
                total_gpus_per_server.c.total_gpus,
                func.coalesce(used_gpus_per_server.c.used_gpus, 0).label("used_gpus"),
                (
                    total_gpus_per_server.c.total_gpus
                    - func.coalesce(used_gpus_per_server.c.used_gpus, 0)
                ).label("free_gpus"),
            )
            .select_from(Server)
            .join(
                total_gpus_per_server,
                Server.server_id == total_gpus_per_server.c.server_id,
            )
            .outerjoin(
                used_gpus_per_server,
                Server.server_id == used_gpus_per_server.c.server_id,
            )
            .join(GPU, Server.server_id == GPU.server_id)
            .where(
                GPU.model_short_ref.in_(supported_gpus),
                GPU.verified.is_(True),
                total_gpus_per_server.c.total_gpus >= chute.gpu_count,
                Server.locked.is_(False),
                Server.is_tee.is_(chute.tee),
                Server.validator == chute.validator,
            )
            .order_by(Server.hourly_cost.asc(), text("free_gpus ASC"))
        )
        async with get_session() as session:
            servers = (await session.execute(query)).unique().scalars()
        if not servers:
            logger.warning(
                f"No servers in inventory are capable of running {chute.chute_id=}"
            )
            return False

        # Fetch disk space.
        eligible_servers = []
        for server in servers:
            try:
                self._require_validator_match(chute, server)
            except DeploymentFailure as exc:
                logger.error(f"Skipping invalid preemption candidate: {exc}")
                continue
            required_disk_gb = deployment_disk_requirements(
                server, disk_gb
            ).ephemeral_storage_gb
            if await k8s.check_node_has_disk_available(server.name, required_disk_gb):
                eligible_servers.append(server)
        servers = eligible_servers

        # Build global instance counts from global_active_instances
        global_counts = {}
        for instance in self.global_active_instances.get(chute.validator, []):
            cid = instance.get("chute_id")
            global_counts[cid] = global_counts.get(cid, 0) + 1

        to_preempt = None
        target_server = None
        for server in servers:
            available_gpus = sum([1 for gpu in server.gpus if not gpu.deployment_id])
            if available_gpus >= chute.gpu_count:
                logger.info(
                    f"Server {server.name} already has {available_gpus=}, no preemption necessary!"
                )
                target_server = server
                break

            proposed_counts = deepcopy(global_counts)
            to_delete = []

            # Sort deployments by their instance compute_multiplier (lowest first = best to preempt)
            def get_deployment_multiplier(d):
                return self._get_instance_multiplier_from_global(
                    chute.validator, d.instance_id
                )

            for deployment in sorted(server.deployments, key=get_deployment_multiplier):
                # Never preempt jobs.
                if deployment.job_id:
                    continue

                # A server is bound to one validator. Do not mutate legacy/corrupt
                # cross-validator deployments while making room for this chute.
                if deployment.validator != chute.validator:
                    continue

                # Never preempt non-preemptible (private) deployments.
                if not deployment.preemptible:
                    continue

                # Can't preempt deployments that aren't active (still booting).
                if not deployment.activated_at:
                    continue

                # Make sure we don't replace an instance of the target chute.
                if deployment.chute_id == chute.chute_id:
                    continue

                # Can't preempt deployments that are too new (< 62 minutes since activation).
                if deployment.activated_at:
                    age = datetime.now(timezone.utc).replace(
                        tzinfo=None
                    ) - deployment.activated_at.replace(tzinfo=None)
                    if age <= timedelta(minutes=62):
                        logger.warning(
                            f"Cannot preempt {deployment.deployment_id=}, time since active is only {age}"
                        )
                        continue
                else:
                    logger.warning(
                        f"Cannot preempt {deployment.deployment_id=}, time active unknown."
                    )
                    continue

                # Get the existing instance's compute multiplier
                existing_multiplier = self._get_instance_multiplier_from_global(
                    chute.validator, deployment.instance_id
                )

                # Never preempt if existing multiplier >= new chute's effective multiplier
                if existing_multiplier >= new_effective_multiplier:
                    logger.info(
                        f"Skipping {deployment.chute_id} - existing multiplier {existing_multiplier:.2f} "
                        f">= new multiplier {new_effective_multiplier:.2f}"
                    )
                    continue

                # Never remove the only global instance of a chute
                if proposed_counts.get(deployment.chute_id, 0) <= 1:
                    logger.warning(
                        f"Skipping {deployment.chute_id} - would remove only global instance"
                    )
                    continue

                # This deployment is eligible for preemption
                to_delete.append(deployment.deployment_id)
                available_gpus += len(deployment.gpus)
                proposed_counts[deployment.chute_id] -= 1

                logger.info(
                    f"Proposing preemption of {deployment.chute_id} "
                    f"(multiplier={existing_multiplier:.2f}) for {chute.chute_id} "
                    f"(multiplier={new_effective_multiplier:.2f})"
                )

                # Would we reach a sufficient number of free GPUs?
                if available_gpus >= chute.gpu_count:
                    logger.info(
                        f"Found a server to preempt deployments on: {server.name}"
                    )
                    to_preempt = to_delete
                    target_server = server
                    break
            if target_server:
                break
        if not target_server:
            logger.warning(
                f"Could not find a server with sufficient preemptable deployments for {chute.chute_id=}"
            )
            return False
        try:
            self._require_validator_match(chute, target_server)
        except DeploymentFailure as exc:
            logger.error(f"Refusing cross-validator preemption target: {exc}")
            return False

        # Before we actually delete any deployments, let's ensure we can actually obtain the launch token,
        # because only one miner can claim a single job for example, so we don't want to undeploy if we
        # don't actually get the lock.
        try:
            launch_token = await self.get_launch_token(
                chute,
                target_server,
                job_id=job_id,
            )
        except DeploymentFailure:
            logger.warning(
                f"Failed to obtain launch token, skipping pre-emption {chute.chute_id=} {job_id=}"
            )
            return False

        # Do the preemption.
        try:
            async with self._launch_intent_lease_guard(
                launch_token["_miner_launch_request_id"],
                launch_token["_miner_launch_lease_owner"],
            ):
                if to_preempt:
                    logger.info(
                        f"Preempting deployments to make room for {chute.chute_id=}: {to_preempt}"
                    )
                    for deployment_id in to_preempt:
                        if not await self.undeploy(
                            deployment_id,
                            reason="preemption",
                        ):
                            raise DeploymentFailure(
                                f"preempted deployment {deployment_id} remains in teardown"
                            )
                extra_ports = (
                    await self._get_job_extra_services(chute) if job_id else []
                )
        except Exception as exc:
            logger.error(f"Unexpected error preempting deployments: {exc}")
            await self.abort_launch_intent(
                launch_token["_miner_launch_request_id"],
                lease_owner=launch_token["_miner_launch_lease_owner"],
                failure=exc,
            )
            return False

        # Deploy on our target server.
        deployment = None
        try:
            await self._renew_launch_intent_lease(
                launch_token["_miner_launch_request_id"],
                launch_token["_miner_launch_lease_owner"],
            )
            deployment, k8s_dep = await k8s.deploy_chute(
                chute.chute_id,
                target_server.server_id,
                token=launch_token["token"],
                launch_intent_id=launch_token["_miner_launch_request_id"],
                launch_intent_lease_owner=launch_token[
                    "_miner_launch_lease_owner"
                ],
                config_id=launch_token["config_id"],
                registry_repository=(launch_token.get("registry") or {}).get(
                    "repository"
                ),
                registry_manifest_digest=(launch_token.get("registry") or {}).get(
                    "manifest_digest"
                ),
                job_id=job_id,
                disk_gb=disk_gb,
                extra_service_ports=extra_ports,
                vm_version=self._server_vm_version(
                    chute.validator, target_server.server_id
                ),
            )
            logger.success(
                f"Successfully deployed {chute.chute_id=} {job_id=} via preemption on {target_server.server_id=}: {deployment.deployment_id=}"
            )
            return True
        except DeploymentFailure as exc:
            logger.error(
                f"Error attempting to deploy {chute.chute_id=} {job_id=} on {target_server.server_id=} via preemption: {exc}\n{traceback.format_exc()}"
            )
            if deployment:
                await self.undeploy(
                    deployment.deployment_id,
                    reason="preemption_launch_failure",
                )
            else:
                await self.abort_launch_intent(
                    launch_token["_miner_launch_request_id"],
                    lease_owner=launch_token["_miner_launch_lease_owner"],
                    failure=exc,
                )
        return False

    async def scale_chute(
        self, chute: Chute, desired_count: int, preempt: bool = False
    ) -> bool:
        """
        Scale up or down a chute.

        MINERS: This is probably the most critical function to optimize.
        """
        async with self._scale_lock:
            scaled = False
            while (
                current_count := await self.count_non_job_deployments(
                    chute.chute_id, chute.version, chute.validator
                )
            ) != desired_count:
                # Scale down?
                if current_count > desired_count:
                    # MINERS: You'll want to figure out the best strategy for selecting deployments to purge.
                    # Examples:
                    # - undeploy on whichever server already has the most GPUs free so that the server
                    #   is more capable of allocating larger chutes when they are needed
                    # - undeploy on whichever server is the most expensive, e.g. if you have a chute
                    #   running on an h100 instance but the node selector only really needs a t4
                    # - consider both when counts are equal
                    # The default selects the deployment which when removed results in highest free GPU count on that server.
                    if (
                        deployment := await self.optimal_scale_down_deployment(chute)
                    ) is not None:
                        scaled = await self.undeploy(
                            deployment.deployment_id,
                            reason="scale_down",
                        )
                        if not scaled:
                            break
                    else:
                        logger.error(
                            f"Scale down impossible right now, sorry: {chute.chute_id}"
                        )
                        scaled = False
                        break

                # Scale up?
                else:
                    # MINERS: You'll also want to figure out the best strategy for selecting servers here.
                    # Examples:
                    # - select server with the fewest GPUs available which suite the chute, like bin-packing
                    # - select the cheapest server that is capable of running the chute
                    # - select the server which already has the image and/or model warm (would be custom)
                    if (server := await self.optimal_scale_up_server(chute)) is None:
                        logger.warning(
                            f"No servers available to accept additional chute deployment: {chute.chute_id}"
                        )
                        # If no server can accept the new capacity, and preempt is true, we need to
                        # figure out which deployment(s) to remove.
                        if preempt:
                            return await self.preempting_deploy(chute)
                        scaled = False
                        break
                    else:
                        logger.info(
                            f"Attempting to deploy {chute.chute_id=} on {server.server_id=}"
                        )
                        deployment = None
                        launch_token = None
                        try:
                            self._require_validator_match(chute, server)
                            launch_token = await self.get_launch_token(
                                chute,
                                server,
                            )
                            await self._renew_launch_intent_lease(
                                launch_token["_miner_launch_request_id"],
                                launch_token["_miner_launch_lease_owner"],
                            )
                            deployment, _ = await k8s.deploy_chute(
                                chute.chute_id,
                                server.server_id,
                                token=launch_token["token"],
                                launch_intent_id=launch_token[
                                    "_miner_launch_request_id"
                                ],
                                launch_intent_lease_owner=launch_token[
                                    "_miner_launch_lease_owner"
                                ],
                                config_id=launch_token["config_id"],
                                registry_repository=(
                                    launch_token.get("registry") or {}
                                ).get("repository"),
                                registry_manifest_digest=(
                                    launch_token.get("registry") or {}
                                ).get("manifest_digest"),
                                vm_version=self._server_vm_version(
                                    chute.validator, server.server_id
                                ),
                            )
                            logger.success(
                                f"Successfully deployed {chute.chute_id=} on {server.server_id=}: {deployment.deployment_id=}"
                            )
                            scaled = True
                        except DeploymentFailure as exc:
                            logger.error(
                                f"Error attempting to deploy {chute.chute_id=} on {server.server_id=}: {exc}\n{traceback.format_exc()}"
                            )
                            if deployment:
                                await self.undeploy(
                                    deployment.deployment_id,
                                    reason="scale_up_launch_failure",
                                )
                            elif launch_token:
                                await self.abort_launch_intent(
                                    launch_token["_miner_launch_request_id"],
                                    lease_owner=launch_token[
                                        "_miner_launch_lease_owner"
                                    ],
                                    failure=exc,
                                )
                            scaled = False
                            break

            return scaled

    @staticmethod
    def _k8s_config_ids() -> Optional[set[str]]:
        """Return observed config IDs, or None when the pod inventory is unavailable."""
        try:
            pods = K8sOperator().get_pods(label_selector="chutes/config-id")
            return {
                pod.metadata.labels["chutes/config-id"]
                for pod in pods.items
                if getattr(pod.metadata, "deletion_timestamp", None) is None
                and getattr(pod.status, "phase", None) in {"Pending", "Running"}
            }
        except Exception as exc:
            logger.error(f"Failed to get pods by config-id label: {exc}")
            return None

    @staticmethod
    def _config_id_is_orphaned(
        config_id: Optional[str], k8s_config_ids: Optional[set[str]]
    ) -> bool:
        return bool(
            k8s_config_ids is not None and config_id and config_id not in k8s_config_ids
        )

    async def reconcile_registry_scope_intents(
        self, *, reconstruct_active: bool
    ) -> None:
        if not settings.gpu_tee_only:
            return
        items = await registry_scope_work_items(reconstruct_active=reconstruct_active)
        semaphore = asyncio.Semaphore(RESUME_CONCURRENCY)

        async def reconcile_one(item: Any) -> None:
            async with semaphore:
                try:
                    await asyncio.wait_for(
                        self._reconcile_registry_scope_intent(item),
                        timeout=RESUME_ITEM_TIMEOUT_SECONDS,
                    )
                except Exception as exc:
                    await record_registry_scope_failure(item.launch_config_id, exc)
                    logger.warning(
                        "registry scope {} reconciliation paused for retry: {}",
                        item.launch_config_id,
                        exc,
                    )

        await asyncio.gather(*(reconcile_one(item) for item in items))

    async def _reconcile_registry_scope_intent(self, item: Any) -> None:
        validator = validator_by_hotkey(item.validator)
        if validator is None:
            raise DeploymentFailure("registry scope validator is unavailable")
        if item.desired_state == "revoked":
            await self._revoke_registry_scope(
                item.validator, item.launch_config_id, item.server_id
            )
            return
        compensate = False
        async with get_session() as session:
            current = await session.get(
                RegistryScopeIntent,
                item.launch_config_id,
                with_for_update=True,
            )
            if current is None:
                raise DeploymentFailure(
                    "registry scope reconstruction authority disappeared"
                )
            if current.desired_state != "active":
                # Teardown committed first. It owns the external DELETE, and this
                # stale active snapshot must never issue a POST.
                compensate = True
            else:
                expected = {
                    "validator": item.validator,
                    "server_id": item.server_id,
                    "repository": item.repository,
                    "manifest_digest": item.manifest_digest,
                }
                if (
                    current.phase not in {"register_pending", "active"}
                    or any(
                        getattr(current, key) != value
                        for key, value in expected.items()
                    )
                    or not all(
                        expected[key]
                        for key in ("server_id", "repository", "manifest_digest")
                    )
                ):
                    raise DeploymentFailure(
                        "active registry scope lacks exact reconstruction identity"
                    )
                body = {
                    "schema": "chutes.miner-registry-scope",
                    "version": 1,
                    "server_id": current.server_id,
                    "launch_config_id": current.launch_config_id,
                    "repository": current.repository,
                    "manifest_digest": current.manifest_digest,
                }
                registration_attempted = False
                try:
                    registration_attempted = True
                    ack = await self._send_registry_scope_registration(validator, body)
                    persisted = await record_registry_scope_registered_in_session(
                        session,
                        current.launch_config_id,
                        ack,
                        launch_intent_id=current.launch_intent_id,
                    )
                    if (
                        persisted.desired_state != "active"
                        or persisted.phase != "active"
                    ):
                        raise DeploymentFailure(
                            "registry scope revocation raced locked reconstruction"
                        )
                    await session.commit()
                except BaseException:
                    if registration_attempted:
                        # POST completion is ambiguous after timeout/cancellation.
                        # The broker serializes this DELETE behind any in-flight
                        # POST, so do not release the row lock with uncertain live
                        # authority. The durable row remains active and can remint.
                        try:
                            await asyncio.shield(
                                self._send_registry_scope_revocation(
                                    item.validator,
                                    item.launch_config_id,
                                    item.server_id,
                                )
                            )
                        except BaseException as cleanup_exc:
                            logger.error(
                                "Could not compensate ambiguous registry scope POST {}: {}",
                                item.launch_config_id,
                                cleanup_exc,
                            )
                    raise
        if compensate:
            await self._revoke_registry_scope(
                item.validator,
                item.launch_config_id,
                item.server_id,
            )

    async def reconcile(self):
        """
        Put our local system back in harmony with the validators.
        """
        await self.resume_launch_intents()
        await self.teardown.resume_pending()
        await self.reconcile_registry_scope_intents(reconstruct_active=True)
        try:
            await self.remote_refresh_all()
        except Exception as exc:
            logger.error(f"Failed to refresh remote resources: {exc}")
            return

        # First, let's make sure the chutes database locally is in sync...
        chute_hashes = {}
        async with get_session() as session:
            chutes = (await session.execute(select(Chute))).unique().scalars().all()
            for chute in chutes:
                if chute.validator not in chute_hashes:
                    chute_hashes[chute.validator] = {}
                chute_hash = hashlib.sha256(
                    "\n".join(
                        [
                            chute.name,
                            chute.image,
                            chute.ref_str,
                            f"{chute.preemptible}",
                            f"{chute.gpu_count}",
                            f"{chute.chutes_version}",
                            f"{set(sorted(chute.supported_gpus))}",
                        ]
                    ).encode()
                ).hexdigest()
                chute_hashes[chute.validator][chute.chute_id] = chute_hash

        for validator, chutes in self.remote_chutes.items():
            for chute_id, chute_data in chutes.items():
                chute_hash = hashlib.sha256(
                    "\n".join(
                        [
                            chute_data["name"],
                            chute_data["image"],
                            chute_data["ref_str"],
                            f"{chute_data['preemptible']}",
                            f"{chute_data['node_selector']['gpu_count']}",
                            f"{chute_data['chutes_version']}",
                            f"{set(sorted(chute_data['supported_gpus']))}",
                        ]
                    ).encode()
                ).hexdigest()

                # Ignore chutes that don't exist here since they'll be created later down this loop.
                if chute_id not in chute_hashes.get(validator, {}):
                    continue

                if chute_hash != chute_hashes.get(validator, {}).get(chute_id):
                    logger.warning(
                        f"Local chute is outdated: {chute_id=} {chute_data['name']}"
                    )
                    try:
                        await self.chute_updated(
                            {
                                "chute_id": chute_id,
                                "version": chute_data["version"],
                                "validator": validator,
                            }
                        )
                        logger.success(
                            f"Successfully synchronized {chute_id=} to {chute_hash=}"
                        )
                    except Exception:
                        logger.warning(
                            f"Failed to reconcile {chute_id=} with {chute_hash=}"
                        )

        # Get the chutes currently undergoing a rolling update.
        updating = {}
        for validator in settings.validators:
            updating[validator.hotkey] = {}
            async with aiohttp.ClientSession(raise_for_status=True) as session:
                async with session.get(
                    f"{validator.api}/chutes/rolling_updates"
                ) as resp:
                    for item in await resp.json():
                        updating[validator.hotkey][item["chute_id"]] = item

        # Compare local items to validators' inventory.
        tasks = []
        chutes_to_remove = set()
        all_chutes = set()
        all_deployments = set()
        all_instances = set()
        all_configs = set()

        # Get both new job-based and old deployment-based chutes
        k8s_chutes = await k8s.get_deployed_chutes()
        k8s_legacy_deployments = await k8s.get_deployed_chutes_legacy()

        # Combine both into a single set of deployment IDs
        k8s_chute_ids = {c["deployment_id"] for c in k8s_chutes}
        k8s_legacy_ids = {d["deployment_id"] for d in k8s_legacy_deployments}
        all_k8s_ids = k8s_chute_ids | k8s_legacy_ids

        # Log legacy deployments for visibility
        if k8s_legacy_ids:
            logger.info(
                f"Found {len(k8s_legacy_ids)} legacy deployment-based chutes: {k8s_legacy_ids}"
            )

        # A failed pod inventory is unknown, not an empty result: orphan cleanup
        # must not turn a transient cluster failure into mass deletion.
        k8s_config_ids = self._k8s_config_ids()

        # Build map of config_id -> instance from remote inventory.
        remote_by_config_id = {}
        for validator, instances in self.remote_instances.items():
            for instance_id, data in instances.items():
                config_id = data.get("config_id")
                if config_id:
                    remote_by_config_id[config_id] = {
                        **data,
                        "instance_id": instance_id,
                        "validator": validator,
                    }

        # Update chutes image field based on remote_images
        chute_map = {}
        async with get_session() as session:
            image_updates = {}
            for validator, images in self.remote_images.items():
                for image_id, image_data in images.items():
                    image_str = f"{image_data['username']}/{image_data['name']}:{image_data['tag']}"
                    if (
                        image_data.get("patch_version")
                        and image_data["patch_version"] != "initial"
                    ):
                        image_str += f"-{image_data['patch_version']}"
                    image_updates[image_id] = {
                        "image": image_str,
                        "chutes_version": image_data["chutes_version"],
                    }
            for validator, chutes in self.remote_chutes.items():
                for chute_id, chute_data in chutes.items():
                    image_id = chute_data.get("image_id")
                    if image_id:
                        if image_id not in chute_map:
                            chute_map[image_id] = []
                        chute_map[image_id].append(chute_id)
            if image_updates and chute_map:
                async for row in (await session.stream(select(Chute))).unique():
                    chute = row[0]
                    for image_id, chute_ids in chute_map.items():
                        if chute.chute_id in chute_ids and image_id in image_updates:
                            update_data = image_updates[image_id]
                            if chute.image != update_data["image"]:
                                logger.info(
                                    f"Updating chute {chute.chute_id} image from '{chute.image}' to '{update_data['image']}'"
                                )
                                chute.image = update_data["image"]
                            if update_data["chutes_version"] != chute.chutes_version:
                                logger.info(
                                    f"Updating chute {chute.chute_id} chutes_version from '{chute.chutes_version}' to '{update_data['chutes_version']}'"
                                )
                                chute.chutes_version = update_data["chutes_version"]
                            break
                await session.commit()

        # Snapshot the rows that need a direct runtime read, then close the
        # database transaction before any Kubernetes call. A newly eligible row
        # is conservatively picked up on the next reconciliation pass.
        async with get_session() as session:
            runtime_candidates = list(
                (
                    await session.execute(
                        select(
                            Deployment.deployment_id,
                            Deployment.active,
                            Deployment.verified_at,
                            Deployment.created_at,
                        )
                    )
                ).all()
            )
        runtime_observations: dict[str, tuple[str, Any]] = {}
        runtime_now = datetime.now(timezone.utc)
        for deployment_id, active, verified_at, created_at in runtime_candidates:
            if active and not (
                verified_at is None and runtime_now - created_at >= timedelta(minutes=5)
            ):
                continue
            try:
                runtime_observations[deployment_id] = (
                    "present",
                    await k8s.get_deployment(deployment_id),
                )
            except Exception as exc:
                status = (
                    "absent"
                    if "Not Found" in str(exc) or "(404)" in str(exc)
                    else "unknown"
                )
                runtime_observations[deployment_id] = (status, exc)

        nodes = await k8s.get_kubernetes_nodes()

        async with get_session() as session:
            # Clean up based on deployments/instances.
            async for row in (await session.stream(select(Deployment))).unique():
                deployment = row[0]

                try:
                    require_supported_chutes_version(
                        deployment.chute.chutes_version,
                        deployment.chute_id,
                    )
                except DeploymentFailure as exc:
                    logger.error(
                        f"Removing unsupported deployment {deployment.deployment_id}: {exc}"
                    )
                    all_deployments.add(deployment.deployment_id)
                    if deployment.instance_id:
                        all_instances.add(deployment.instance_id)
                    tasks.append(
                        self.undeploy(
                            deployment.deployment_id,
                            reason="unsupported_runtime",
                        )
                    )
                    continue

                # Make sure the instances created with launch configs have the instance ID tracked.
                if deployment.config_id and not deployment.instance_id:
                    remote_match = remote_by_config_id.get(deployment.config_id)
                    if (
                        remote_match
                        and remote_match.get("validator") == deployment.validator
                    ):
                        deployment.instance_id = remote_match["instance_id"]
                        logger.info(
                            f"Updated deployment {deployment.deployment_id} with instance_id={deployment.instance_id} "
                            f"based on matching config_id={deployment.config_id}"
                        )

                # Reconcile the verified/active state for instances.
                if deployment.instance_id:
                    remote_instance = (
                        self.remote_instances.get(deployment.validator) or {}
                    ).get(deployment.instance_id)
                    if remote_instance:
                        if (
                            remote_instance.get("last_verified_at")
                            and not deployment.verified_at
                        ):
                            deployment.verified_at = func.now()
                            logger.info(
                                f"Marking deployment {deployment.deployment_id} as verified based on remote status"
                            )
                        remote_active = remote_instance.get("active", True)
                        if deployment.active != remote_active:
                            deployment.active = remote_active
                            deployment.activated_at = func.now()
                            deployment.stub = False
                            logger.info(
                                f"Updating deployment {deployment.deployment_id} active status to {deployment.active}"
                            )

                # Early check for orphaned deployments with config_id.
                # Skip if k8s_config_ids is None (pod scan failed) to avoid mass deletion.
                if self._config_id_is_orphaned(deployment.config_id, k8s_config_ids):
                    logger.warning(
                        f"Deployment {deployment.deployment_id} has config_id={deployment.config_id} but no matching pod in k8s, cleaning up"
                    )
                    all_deployments.add(deployment.deployment_id)
                    tasks.append(
                        self.undeploy(
                            deployment.deployment_id,
                            reason="reconcile_missing_pod",
                        )
                    )
                    continue

                # Check if instance exists on validator
                if deployment.instance_id and deployment.instance_id not in (
                    self.remote_instances.get(deployment.validator) or {}
                ):
                    logger.warning(
                        f"Deployment: {deployment.deployment_id} (instance_id={deployment.instance_id}) on validator {deployment.validator} not found"
                    )
                    tasks.append(
                        self.instance_deleted({"instance_id": deployment.instance_id})
                    )
                    # Skip the rest of processing for this deployment since instance is gone
                    continue

                remote = (self.remote_chutes.get(deployment.validator) or {}).get(
                    deployment.chute_id
                )

                # Track deployments by their launch configs.
                if deployment.config_id:
                    all_configs.add(deployment.config_id)

                # Special handling for deployments with job_id
                if hasattr(deployment, "job_id") and deployment.job_id:
                    # Always track the instance_id for job deployments to prevent premature purging
                    if deployment.instance_id:
                        all_instances.add(deployment.instance_id)

                    if remote:
                        logger.info(
                            f"Keeping deployment with job_id={deployment.job_id} for chute {deployment.chute_id} (remote version={remote.get('version')}, local version={deployment.version})"
                        )
                        all_deployments.add(deployment.deployment_id)
                        continue
                    else:
                        # Chute associated with the job doesn't exist anymore.
                        logger.warning(
                            f"Job deployment {deployment.deployment_id} with job_id={deployment.job_id} not found in remote inventory"
                        )
                        identifier = f"{deployment.validator}:{deployment.chute_id}:{deployment.version}"
                        if identifier not in chutes_to_remove:
                            chutes_to_remove.add(identifier)
                            tasks.append(
                                self.chute_deleted(
                                    {
                                        "chute_id": deployment.chute_id,
                                        "version": deployment.version,
                                        "validator": deployment.validator,
                                    }
                                )
                            )
                        continue

                # Normal deployment handling (no job_id)
                if not remote or remote["version"] != deployment.version:
                    update = updating.get(deployment.validator, {}).get(
                        deployment.chute_id
                    )
                    if update:
                        logger.warning(
                            f"Skipping reconciliation for chute with rolling {update=}"
                        )
                        all_deployments.add(deployment.deployment_id)
                        if deployment.instance_id:
                            all_instances.add(deployment.instance_id)
                        continue

                    logger.warning(
                        f"Chute: {deployment.chute_id} version={deployment.version} on validator {deployment.validator} not found"
                    )
                    identifier = f"{deployment.validator}:{deployment.chute_id}:{deployment.version}"
                    if identifier not in chutes_to_remove:
                        chutes_to_remove.add(identifier)
                        tasks.append(
                            self.chute_deleted(
                                {
                                    "chute_id": deployment.chute_id,
                                    "version": deployment.version,
                                    "validator": deployment.validator,
                                }
                            )
                        )
                    # Don't continue here - we still need to check k8s state and cleanup

                # Check if deployment exists in k8s (either as job or legacy deployment)
                deployment_in_k8s = deployment.deployment_id in all_k8s_ids

                # Special handling for legacy deployments
                if deployment.deployment_id in k8s_legacy_ids:
                    logger.info(
                        f"Found legacy deployment {deployment.deployment_id}, preserving it"
                    )
                    all_deployments.add(deployment.deployment_id)
                    if deployment.instance_id:
                        all_instances.add(deployment.instance_id)
                    continue

                # Delete deployments that never made it past stub stage or disappeared from k8s
                if not deployment.stub and not deployment_in_k8s:
                    logger.warning(
                        f"Deployment has disappeared from kubernetes: {deployment.deployment_id}"
                    )
                    all_deployments.add(deployment.deployment_id)
                    tasks.append(
                        self.undeploy(
                            deployment.deployment_id,
                            reason="reconcile_kubernetes_absent",
                        )
                    )
                    continue

                # Clean up old stubs
                deployment_age = datetime.now(timezone.utc) - deployment.created_at
                if (
                    deployment.stub or not deployment.instance_id
                ) and deployment_age >= timedelta(minutes=30):
                    logger.warning(
                        f"Deployment is still a stub after 30 minutes, deleting! {deployment.deployment_id}"
                    )
                    all_deployments.add(deployment.deployment_id)
                    tasks.append(
                        self.undeploy(
                            deployment.deployment_id,
                            reason="reconcile_stale_stub",
                        )
                    )
                    continue

                # Check for terminated jobs or jobs that never started
                if (
                    not deployment.active
                    or deployment.verified_at is None
                    and deployment_age >= timedelta(minutes=5)
                ):
                    runtime_status, runtime_payload = runtime_observations.get(
                        deployment.deployment_id,
                        ("unknown", None),
                    )
                    if runtime_status != "present":
                        if runtime_status == "absent":
                            tasks.append(
                                self.undeploy(
                                    deployment.deployment_id,
                                    reason="reconcile_job_absent",
                                )
                            )
                        continue
                    kd = runtime_payload

                    destroyed = False
                    job_status = kd.get("status", {})

                    # Check job completion status
                    if job_status.get("succeeded", 0) > 0:
                        logger.info(
                            f"Job completed successfully: {deployment.deployment_id}"
                        )
                        tasks.append(
                            self.undeploy(
                                deployment.deployment_id,
                                reason="job_completed",
                            )
                        )
                        destroyed = True
                    elif job_status.get("failed", 0) > 0:
                        logger.warning(f"Job failed: {deployment.deployment_id}")
                        tasks.append(
                            self.undeploy(
                                deployment.deployment_id,
                                reason="job_failed",
                            )
                        )
                        destroyed = True

                    # Check for terminated pods (for Jobs that don't update status properly)
                    if not destroyed:
                        for pod in kd.get("pods", []):
                            pod_state = pod.get("state") or {}
                            if pod_state.get("terminated"):
                                terminated = pod_state["terminated"]
                                exit_code = terminated.get("exit_code", 0)
                                if exit_code == 0:
                                    logger.info(
                                        f"Job pod completed successfully: {deployment.deployment_id}"
                                    )
                                else:
                                    logger.warning(
                                        f"Job pod terminated with error: {deployment.deployment_id}, exit_code={exit_code}"
                                    )
                                tasks.append(
                                    self.undeploy(
                                        deployment.deployment_id,
                                        reason="job_pod_terminated",
                                    )
                                )
                                destroyed = True
                                break

                    if destroyed:
                        continue

                # Track valid deployments
                all_deployments.add(deployment.deployment_id)
                if deployment.instance_id:
                    all_instances.add(deployment.instance_id)

            await session.commit()

            # Purge validator instances not deployed locally
            for validator, instances in self.remote_instances.items():
                if (vali := validator_by_hotkey(validator)) is None:
                    continue
                for instance_id, data in instances.items():
                    config_id = data.get("config_id", None)
                    if instance_id not in all_instances and (
                        not config_id or config_id not in all_configs
                    ):
                        chute_id = data["chute_id"]
                        logger.warning(
                            f"Found validator {chute_id=} {instance_id=} {config_id=} not deployed locally!"
                        )
                        await self.purge_validator_instance(vali, chute_id, instance_id)

            # Purge k8s deployments that aren't tracked anymore
            # BUT exclude legacy deployments from deletion
            k8s_by_id = {
                item["deployment_id"]: item
                for item in k8s_chutes
                if item.get("deployment_id")
            }
            for deployment_id in all_k8s_ids - all_deployments:
                if deployment_id in k8s_legacy_ids:
                    logger.info(
                        f"Preserving legacy kubernetes deployment: {deployment_id}"
                    )
                    continue
                logger.warning(
                    f"Removing kubernetes deployment that is no longer tracked: {deployment_id}"
                )
                resource = k8s_by_id.get(deployment_id)
                if resource is None:
                    logger.error(
                        f"Cannot tombstone Kubernetes orphan {deployment_id}: exact live identity missing"
                    )
                    continue
                tasks.append(self.cleanup_kubernetes_orphan(resource))

            # GPUs that no longer exist in validator inventory.
            all_gpus = []
            for nodes in self.remote_nodes.values():
                all_gpus.extend(nodes)

            local_gpu_ids = set()
            async for row in (await session.stream(select(GPU))).unique():
                gpu = row[0]
                local_gpu_ids.add(gpu.hardware_uuid)
                if gpu.hardware_uuid not in all_gpus:
                    logger.warning(
                        f"GPU {gpu.hardware_uuid} is no longer in validator "
                        f"{gpu.validator} inventory"
                    )
                    # XXX we need this reconciliation somehow, but API downtime is really problematic here...
                    # tasks.append(
                    #     asyncio.create_task(
                    #         self.gpu_deleted({"gpu_id": gpu.gpu_id, "validator": gpu.validator})
                    #     )
                    # )

            # XXX this also seems problematic currently :thinking:
            ## GPUs in validator inventory that don't exist locally.
            # for validator_hotkey, nodes in self.remote_nodes.items():
            #    for gpu_id in nodes:
            #        if gpu_id not in local_gpu_ids:
            #            logger.warning(
            #                f"Found GPU in inventory of {validator_hotkey} that is not local: {gpu_id}"
            #            )
            #            if (validator := validator_by_hotkey(validator_hotkey)) is not None:
            #                await self.remove_gpu_from_validator(validator, gpu_id)

            # Process chutes
            async for row in await session.stream(select(Chute)):
                chute = row[0]
                identifier = f"{chute.validator}:{chute.chute_id}:{chute.version}"
                all_chutes.add(identifier)

                if identifier in chutes_to_remove:
                    continue

                remote = (self.remote_chutes.get(chute.validator) or {}).get(
                    chute.chute_id
                )
                if not remote or remote["version"] != chute.version:
                    update = updating.get(chute.validator, {}).get(chute.chute_id)
                    if update:
                        logger.warning(
                            f"Skipping reconciliation for chute with rolling {update=}"
                        )
                        continue

                    logger.warning(
                        f"Chute: {chute.chute_id} version={chute.version} on validator {chute.validator} not found: {remote=}"
                    )
                    tasks.append(
                        self.chute_deleted(
                            {
                                "chute_id": chute.chute_id,
                                "version": chute.version,
                                "validator": chute.validator,
                            }
                        )
                    )
                    chutes_to_remove.add(identifier)

            # Find new chutes
            for validator, chutes in self.remote_chutes.items():
                for chute_id, config in chutes.items():
                    identifier = f"{validator}:{chute_id}:{config['version']}"
                    if identifier not in all_chutes:
                        update = updating.get(validator, {}).get(chute_id)
                        if update:
                            logger.warning(
                                f"Skipping chute reconciliation for chute with rolling {update=}"
                            )
                            continue
                        logger.info(f"Found a new/untracked chute: {chute_id}")
                        tasks.append(
                            self.chute_created(
                                {
                                    "chute_id": chute_id,
                                    "version": config["version"],
                                    "validator": validator,
                                }
                            )
                        )

            # Check Kubernetes nodes
            node_ids = {node["server_id"] for node in nodes}
            all_server_ids = set()

            servers = (await session.execute(select(Server))).unique().scalars()
            for server in servers:
                if server.server_id not in node_ids:
                    logger.warning(
                        f"Server {server.server_id} no longer in kubernetes node list!"
                    )
                    tasks.append(self.server_deleted({"server_id": server.server_id}))
                all_server_ids.add(server.server_id)

            # XXX We won't do the opposite (remove k8s nodes that aren't tracked) because they could be in provisioning status.
            for node_id in node_ids - all_server_ids:
                logger.warning(
                    f"Server/node {node_id} not tracked in inventory, ignoring..."
                )

        await asyncio.gather(*tasks)

    async def reconciler(self):
        """
        Reconcile on a regular basis.
        """
        while True:
            await asyncio.sleep(60)
            try:
                await self.reconcile()
            except Exception as exc:
                logger.error(
                    f"Unexpected error in reconciliation loop: {exc}\n{traceback.format_exc()}"
                )


async def main():
    await run_gepetto_leader_loop(engine, lambda: Gepetto().run())


def run():
    asyncio.run(main())


if __name__ == "__main__":
    run()
