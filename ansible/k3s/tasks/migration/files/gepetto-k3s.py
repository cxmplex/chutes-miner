"""
Gepetto - coordinate all the things.
"""

import re
import aiohttp
import asyncio
import hashlib
from chutes_miner.api.server.util import stop_server_monitoring
import orjson as json
import traceback
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from loguru import logger
from typing import Dict, Any, Optional
from sqlalchemy import select, func, case, text, update
from sqlalchemy.orm import selectinload
from prometheus_api_client import PrometheusConnect
from chutes_miner.api.config import settings, validator_by_hotkey
from chutes_miner.api.redis_pubsub import RedisListener
from chutes_common.auth import sign_request
from chutes_common.settings import Validator
from chutes_miner.api.database import get_session, engine
import chutes_common.schemas.orms  # noqa: F401 - register validator_migrations table
from chutes_common.schemas import Base
from chutes_common.schemas.chute import Chute
from chutes_common.schemas.server import Server
from chutes_common.schemas.gpu import GPU
from chutes_common.schemas.deployment import Deployment
from chutes_miner.api.exceptions import DeploymentFailure
from chutes_miner.validator_migrations import run_validator_migrations
import chutes_miner.api.k8s as k8s


MIN_SUPPORTED_CHUTES_VERSION = "0.3.61"
LEGACY_SOURCE_FIELDS = frozenset({"code", "filename"})
_CHUTES_VERSION_RE = re.compile(
    r"^(?P<core>[0-9]+\.[0-9]+\.[0-9]+)(?:(?:[.+-])[0-9A-Za-z][0-9A-Za-z.+-]*)?$"
)


def require_supported_chutes_version(version: Optional[str], chute_id: str) -> None:
    match = _CHUTES_VERSION_RE.fullmatch(version) if isinstance(version, str) else None
    minimum = tuple(int(part) for part in MIN_SUPPORTED_CHUTES_VERSION.split("."))
    unsupported = (
        match is None or tuple(int(part) for part in match.group("core").split(".")) < minimum
    )
    if unsupported:
        raise DeploymentFailure(
            f"Unsupported chutes runtime version {version!r} for chute {chute_id}; "
            f"minimum supported version is {MIN_SUPPORTED_CHUTES_VERSION}. "
            "Legacy source ConfigMap delivery has been removed; rebuild the chute image."
        )


class Gepetto:
    def __init__(self):
        """
        Constructor.
        """
        self.pubsub = RedisListener()
        self.remote_chutes = {validator.hotkey: {} for validator in settings.validators}
        self.remote_images = {validator.hotkey: {} for validator in settings.validators}
        self.remote_instances = {validator.hotkey: {} for validator in settings.validators}
        self.remote_nodes = {validator.hotkey: {} for validator in settings.validators}
        self.remote_metrics = {validator.hotkey: {} for validator in settings.validators}
        self._scale_lock = asyncio.Lock()
        self._restart_lock = asyncio.Lock()
        self.setup_handlers()

    @staticmethod
    def _validator_matches(chute: Chute, server: Server) -> bool:
        if not chute.validator or validator_by_hotkey(chute.validator) is None:
            logger.error(
                f"Refusing deployment for {chute.chute_id=}: "
                f"validator {chute.validator!r} is not configured"
            )
            return False
        if server.validator != chute.validator:
            logger.error(
                f"Refusing deployment for {chute.chute_id=}: validator "
                f"{chute.validator!r} does not match server {server.server_id} "
                f"validator {server.validator!r}"
            )
            return False
        return True

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

    async def run(self):
        """
        Main loop.
        """
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        if settings.validator_migrations_enabled:
            await run_validator_migrations()
        await k8s.purge_legacy_source_config_maps()
        await self.reconcile()
        asyncio.create_task(self.autoscaler())
        asyncio.create_task(self.reconciler())
        await self.pubsub.start()

    @staticmethod
    async def _remote_refresh_objects(
        pointer: Dict[str, Any],
        hotkey: str,
        url: str,
        id_key: str,
        forbidden_keys: Optional[frozenset] = None,
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
                        if forbidden := (forbidden_keys or frozenset()).intersection(data):
                            raise ValueError(
                                f"Invalid response from {url}: forbidden fields "
                                f"{', '.join(sorted(forbidden))}"
                            )
                        updated_items[data[id_key]] = data
                    elif content.startswith("data: NO_ITEMS"):
                        explicit_null = True
            if updated_items or explicit_null:
                pointer[hotkey] = updated_items

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
        if forbidden := LEGACY_SOURCE_FIELDS.intersection(chute_data):
            raise ValueError(
                "Invalid miner chute response: obsolete source fields are forbidden "
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
        }
        if missing := required.difference(chute_data):
            raise ValueError(f"Invalid miner chute response: missing {', '.join(sorted(missing))}.")
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
        require_supported_chutes_version(chute_data["chutes_version"], expected_chute_id)

        node_selector = chute_data["node_selector"]
        if not isinstance(node_selector, dict) or "gpu_count" not in node_selector:
            raise ValueError("Invalid miner chute response: node_selector.gpu_count is required.")

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
        }

    async def remote_refresh_all(self):
        """
        Refresh chutes from the validators.
        """
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
                    forbidden_keys=LEGACY_SOURCE_FIELDS if clazz == "chutes" else frozenset(),
                )

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

    async def get_launch_token(self, chute: Chute, job_id: str = None):
        """
        Fetch the validator-issued launch config required to deliver source.
        """
        require_supported_chutes_version(chute.chutes_version, chute.chute_id)
        if (validator := validator_by_hotkey(chute.validator)) is None:
            raise DeploymentFailure(f"Validator not found: {chute.validator}")
        try:
            async with aiohttp.ClientSession(raise_for_status=False) as session:
                headers, _ = sign_request(purpose="launch")
                params = {"chute_id": chute.chute_id}
                if job_id:
                    params["job_id"] = job_id
                async with session.get(
                    f"{validator.api}/instances/launch_config",
                    headers=headers,
                    params=params,
                ) as resp:
                    if resp.status == 200:
                        payload = await resp.json()
                        if not isinstance(payload, dict) or set(payload) != {
                            "token",
                            "config_id",
                        }:
                            raise DeploymentFailure(
                                f"Invalid launch config response for {chute.chute_id}: "
                                "expected exactly token and config_id."
                            )
                        if not all(
                            isinstance(payload[field], str) and payload[field]
                            for field in ("token", "config_id")
                        ):
                            raise DeploymentFailure(
                                f"Invalid launch config response for {chute.chute_id}: "
                                "token and config_id must be non-empty strings."
                            )
                        return payload

                    error_body = await resp.text()
                    if resp.status == 423:
                        message = (
                            f"Unable to scale up {chute.chute_id} at this time. "
                            f"Validator reported capacity issue: {error_body}"
                        )
                        logger.warning(message)
                    else:
                        message = (
                            f"Failed to fetch launch token for {chute.chute_id}: "
                            f"status={resp.status}, body={error_body}"
                        )
                        logger.error(message)
                    raise DeploymentFailure(message)
        except DeploymentFailure:
            raise
        except Exception as exc:
            logger.warning(f"Unable to fetch launch config token: {exc}")
            raise DeploymentFailure(f"Failed to fetch JWT for launch: {exc}") from exc

    async def _autoscale(self):
        """
        Autoscale chutes, based on metrics and server availability.
        """
        for validator in settings.validators:
            await self._remote_refresh_objects(
                self.remote_metrics,
                validator.hotkey,
                f"{validator.api}/miner/metrics/",
                "chute_id",
            )

        # Load chute utilization to see if it can scale.
        scalable = {}
        for validator in settings.validators:
            scalable[validator.hotkey] = {}
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(f"{validator.api}/chutes/utilization") as resp:
                        for item in await resp.json():
                            if item.get("scalable") is False:
                                scalable[validator.hotkey][item["chute_id"]] = False
                                logger.warning(
                                    f"Chute {item['chute_id']} is capped due to utilization: {item}"
                                )
                            if item.get("update_in_progress") is True:
                                scalable[validator.hotkey][item["chute_id"]] = False
                                logger.warning(
                                    f"Chute {item['chute_id']} is updating, cannot scale now: {item}"
                                )
                except Exception as exc:
                    logger.error(f"Failed to fetch chute utilization from {validator=}: {exc}")

        # Count the number of deployments for each chute
        chute_values = []
        for validator, chutes in self.remote_chutes.items():
            for chute_id, chute_info in chutes.items():
                try:
                    chute_name = chute_info.get("name")
                    chute = await self.load_chute(chute_id, chute_info["version"], validator)
                    if not chute:
                        continue
                    if not chute_info.get("cords"):
                        continue
                    if scalable.get(validator, {}).get(chute_id) not in (None, True):
                        continue

                    # Count how many deployments we already have (excluding jobs).
                    local_count = await self.count_non_job_deployments(
                        chute_id, chute_info["version"], validator
                    )
                    if local_count >= 3:
                        logger.info(f"Already have max instances of {chute_id=} {chute_name}")
                        continue

                    # If there are no metrics, it means the chute is not being actively used, so don't scale.
                    metrics = self.remote_metrics.get(validator, {}).get(chute_id, {})
                    if not metrics:
                        logger.info(
                            f"No metrics for {chute_id=} {chute_name}, scaling would be unproductive..."
                        )
                        continue

                    # If we have all deployments already (no other miner has this) then no need to scale.
                    total_count = metrics.get("instance_count", 0)
                    if (
                        local_count
                        and local_count >= total_count
                        and not metrics.get("rate_limit_count")
                    ):
                        logger.info(
                            f"We have all deployments for {chute_id=} {chute_name}, scaling would be unproductive..."
                        )
                        continue

                    # First, we need to adjust the theoretical usage based on the rate limit counts.
                    rate_limited = metrics.get("rate_limit_count")
                    if metrics.get("instance_count") and metrics["instance_count"] >= 5:
                        # We try up to 5 miners so the rate limit count can be artificially high.
                        rate_limited /= 5

                    # Calculate approximate compute units.
                    compute_units = metrics.get("total_compute_time")
                    if metrics.get("compute_multiplier"):
                        compute_units *= metrics["compute_multiplier"]
                    per_invocation = compute_units / (metrics.get("total_invocations", 0) or 1.0)
                    theoretical = compute_units
                    if per_invocation and rate_limited:
                        theoretical += rate_limited * per_invocation

                    # Calculate potential gain from a new deployment.
                    potential_gain = theoretical
                    if total_count:
                        potential_gain /= total_count + 1

                    # See if we have a server that could even handle it.
                    potential_server = await self.optimal_scale_up_server(chute)
                    if not potential_server:
                        logger.info(f"No viable server to scale {chute_id=} {chute_name}")
                        continue

                    # Calculate value ratio
                    chute_value = potential_gain / (potential_server.hourly_cost * chute.gpu_count)
                    logger.info(
                        f"Estimated {potential_gain=} for name={chute_name} "
                        f"chute_id={chute_info['chute_id']} on {validator=}, "
                        f"optimal server hourly cost={potential_server.hourly_cost} "
                        f"on server {potential_server.name}, {chute_value=} "
                        f"{local_count=} {total_count=}"
                    )
                    chute_values.append((validator, chute_id, chute_value))

                except Exception as e:
                    logger.error(f"Error processing chute {chute_id}: {e}")
                    continue

        if not chute_values:
            logger.info("No benefit in scaling, or no ability to do so...")
            return

        # Sort by value and attempt to deploy the highest value chute
        chute_values.sort(key=lambda x: x[2], reverse=True)
        best_validator, best_chute_id, best_value = chute_values[0]
        if (
            chute := await self.load_chute(
                best_chute_id,
                self.remote_chutes[best_validator][best_chute_id]["version"],
                best_validator,
            )
        ) is not None:
            current_count = await self.count_non_job_deployments(
                best_chute_id, chute.version, best_validator
            )
            logger.info(f"Scaling up {best_chute_id} for validator {best_validator}")
            await self.scale_chute(chute, current_count + 1, preempt=False)

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
    async def purge_validator_instance(vali: Validator, chute_id: str, instance_id: str):
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

    async def undeploy(self, deployment_id: str, instance_id: str = None):
        """
        Delete a deployment.
        """
        logger.info(f"Removing all traces of deployment: {deployment_id}")

        # Clean up the database.
        chute_id = None
        validator_hotkey = None
        async with get_session() as session:
            deployment = (
                (
                    await session.execute(
                        select(Deployment).where(Deployment.deployment_id == deployment_id)
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            if deployment:
                if not instance_id:
                    instance_id = deployment.instance_id
                chute_id = deployment.chute_id
                validator_hotkey = deployment.validator
                await session.delete(deployment)
                await session.commit()

        # Clean up the validator's instance record.
        if instance_id:
            if (vali := validator_by_hotkey(validator_hotkey)) is not None:
                await self.purge_validator_instance(vali, chute_id, instance_id)

        # Purge in k8s if still there.
        await k8s.undeploy(deployment_id)
        logger.success(f"Removed {deployment_id=}")

    async def gpu_verified(self, event_data):
        """
        Validator has finished verifying a GPU, so it is ready for use.
        """
        logger.info(f"Received gpu_verified event: {event_data}")
        async with get_session() as session:
            await session.execute(
                update(GPU)
                .where(GPU.server_id == event_data.get("gpu_id"))
                .values({"verified": True})
            )
            await session.commit()
        # Nothing to do here really, the autoscaler should take care of it, but feel free to change...

    async def instance_created(self, event_data):
        """
        Instance has been created - only relevant when using new launch config system.
        """
        if event_data["miner_hotkey"] != settings.miner_ss58:
            return
        logger.info(f"Received instance_created event: {event_data}")
        async with get_session() as session:
            await session.execute(
                update(Deployment)
                .where(Deployment.config_id == event_data["config_id"])
                .values({"instance_id": event_data["instance_id"]})
            )

    async def instance_verified(self, event_data):
        """
        Validator has finished verifying an instance/deployment, so it should start receiving requests.
        """
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

    async def release_job(self, chute: Chute, job_id: str):
        """
        Release the lock/launch config on a job for another miner to pick up.
        """
        if (validator := validator_by_hotkey(chute.validator)) is None:
            return
        try:
            async with aiohttp.ClientSession(raise_for_status=True) as session:
                headers, _ = sign_request(purpose="miner")
                async with session.delete(
                    f"{validator.api}/miner/jobs/{job_id}",
                    headers=headers,
                ) as resp:
                    logger.success(f"Successfully released job {job_id=}: {await resp.json()}")
        except Exception as exc:
            logger.warning(f"Failed to release job: {exc=}")

    async def _get_job_extra_services(self, chute: Chute):
        """
        Get the list of extra services (i.e. extra ports that the chute requires) for a chute.
        """
        if (chute_obj := self.remote_chutes.get(chute.validator, {}).get(chute.chute_id)) is None:
            if (validator := validator_by_hotkey(chute.validator)) is None:
                # Won't work anyways, but we'll avoid an exception here...
                logger.warning(f"No validator found? {chute.validator=}")
                return []
            await self._remote_refresh_objects(
                self.remote_chutes, chute.validator, f"{validator.api}/miner/chutes/", "chute_id"
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
                    "TCP" if extra_services[-1]["proto"].lower() in ("tcp", "http") else "UDP"
                )
                logger.info(f"Adding {port=} to job for {chute.chute_id=}")
        return extra_services

    async def run_job(
        self, chute: Chute, job_id: str, server: Server, validator: Validator, disk_gb: int = 10
    ):
        """
        Run a job on the specified server.
        """
        logger.info(
            f"Attempting to deploy {job_id=} for {chute.chute_id=} on {server.server_id=} with {disk_gb=}"
        )
        deployment = None
        try:
            if not self._validator_matches(chute, server) or validator.hotkey != chute.validator:
                await self.release_job(chute, job_id)
                return
            launch_token = await self.get_launch_token(chute, job_id=job_id)
            extra_ports = await self._get_job_extra_services(chute)
            deployment, k8s_dep = await k8s.deploy_chute(
                chute.chute_id,
                server.server_id,
                token=launch_token["token"],
                config_id=launch_token["config_id"],
                job_id=job_id,
                extra_labels={"chutes/job": "true"},
                disk_gb=disk_gb,
                extra_service_ports=extra_ports,
            )
            logger.success(
                f"Successfully deployed {job_id=} {chute.chute_id=} on {server.server_id=}: {deployment.deployment_id=}"
            )
        except DeploymentFailure as exc:
            logger.error(
                f"Error attempting to deploy {chute.chute_id=} on {server.server_id=}: {exc}\n{traceback.format_exc()}"
            )
            if deployment:
                await self.undeploy(deployment.deployment_id)
            await self.release_job(chute, job_id)

    async def chute_updated(self, event_data: Dict[str, Any]):
        """
        Chute has been updated.
        """
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
            logger.error(f"Error loading remote chute data: {chute_id=} {version=}: {exc}")
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
        supported_gpus = set(chute.supported_gpus)
        if supported_gpus - set(["h200", "b200"]):
            # Generally speaking, non-h200/b200 GPUs typically have lower compute multipliers than
            # the job would provide because they regularly do not have even one request in flight
            # on average, although that is not always the case, so this should be updated to be smarter.
            logger.info(
                f"Attempting a pre-empting deploy of {job_id=} {chute_id=} with {supported_gpus=} and {gpu_count=}"
            )
            await self.preempting_deploy(chute, job_id=job_id, disk_gb=disk_gb)

    async def job_deleted(self, event_data: Dict[str, Any]):
        """
        Job has been deleted.
        """
        async with get_session() as session:
            deployment = (
                (
                    await session.execute(
                        select(Deployment).where(Deployment.job_id == event_data["job_id"])
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
        if deployment:
            logger.info(f"Received job_deleted event, undeploying {deployment.deployment_id=}!")
            await self.undeploy(deployment.deployment_id)

    async def bounty_changed(self, event_data):
        """
        Bounty has changed for a chute.
        """
        logger.info(f"Received bounty_change event: {event_data}")

        # Check if we have this thing deployed already (or in progress).
        chute = None
        async with get_session() as session:
            deployment = (
                (
                    await session.execute(
                        select(Deployment).where(Deployment.chute_id == event_data["chute_id"])
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            if deployment:
                logger.info(
                    f"Ignoring bounty event, already have a deployment pending: {deployment.deployment_id}"
                )
                return
            chute = await self.get_chute(event_data["chute_id"], event_data["validator"])
        if chute:
            logger.info(f"Attempting to claim the bounty: {event_data}")
            await self.scale_chute(chute, 1, preempt=True)

    @staticmethod
    async def remove_gpu_from_validator(validator: Validator, gpu_id: str):
        """
        Purge a GPU from validator inventory.
        """
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
            logger.error(f"Error purging {gpu_id=} from validator={validator.hotkey}: {exc}")

    async def gpu_deleted(self, event_data):
        """
        GPU no longer exists in validator inventory for some reason.

        MINERS: This shouldn't really happen, unless the validator purges it's database
                or some such other rare event.  You may want to configure alerts or something
                in this code block just in case.
        """
        gpu_id = event_data["gpu_id"]
        logger.info(f"Received gpu_deleted event for {gpu_id=}")
        async with get_session() as session:
            gpu = (
                (await session.execute(select(GPU).where(GPU.gpu_id == gpu_id)))
                .unique()
                .scalar_one_or_none()
            )
            if gpu:
                if gpu.deployment:
                    await self.undeploy(gpu.deployment_id)
                validator_hotkey = gpu.validator
                if (validator := validator_by_hotkey(validator_hotkey)) is not None:
                    await self.remove_gpu_from_validator(validator, gpu_id)
                await session.delete(gpu)
                await session.commit()
        logger.info(f"Finished processing gpu_deleted event for {gpu_id=}")

    async def instance_activated(self, event_data: dict[str, Any]):
        """
        An instance has been marked as active (new chutes lib flow).
        """
        config_id = event_data["config_id"]
        logger.info(f"Received instance_activated event for {config_id=}")
        async with get_session() as session:
            await session.execute(
                text(
                    "UPDATE deployments SET active = true, stub = false WHERE config_id = :config_id"
                ),
                {"config_id": config_id},
            )

    async def instance_deleted(self, event_data: Dict[str, Any]):
        """
        An instance was removed validator side, likely meaning there were too
        many consecutive failures in inference.
        """
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
            await self.undeploy(deployment.deployment_id)
        logger.info(f"Finished processing instance_deleted event for {instance_id=}")

    async def server_deleted(self, event_data: Dict[str, Any]):
        """
        An entire kubernetes node was removed from your inventory.

        MINERS: This will happen when you remove a node intentionally, but otherwise
                should not really happen.  Also want to monitor this situation I think.
        """
        server_id = event_data["server_id"]
        logger.info(f"Received server_deleted event {server_id=}")

        async with get_session() as session:
            server = (
                (await session.execute(select(Server).where(Server.server_id == server_id)))
                .unique()
                .scalar_one_or_none()
            )
            if server:
                # If this is a standalone server, we need to stop monitoring from the agent
                if server.agent_api:
                    await stop_server_monitoring(server.agent_api)

                await asyncio.gather(
                    *[self.gpu_deleted({"gpu_id": gpu.gpu_id}) for gpu in server.gpus]
                )
                await session.refresh(server)
                await session.delete(server)
                await session.commit()
        logger.info(f"Finished processing server_deleted event for {server_id=}")

    async def image_deleted(self, event_data: Dict[str, Any]):
        """
        An image was deleted (should clean up maybe?)
        """
        logger.info(f"Image deleted, but I'm lazy and will let k8s clean up: {event_data}")

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
        chute_id = event_data["chute_id"]
        version = event_data["version"]
        validator = event_data["validator"]
        logger.info(f"Received chute_deleted event for {chute_id=} {version=}")
        async with get_session() as session:
            chute = (
                await session.execute(
                    select(Chute)
                    .where(Chute.chute_id == chute_id)
                    .where(Chute.version == version)
                    .where(Chute.validator == validator)
                    .options(selectinload(Chute.deployments))
                )
            ).scalar_one_or_none()
            if chute:
                if chute.deployments:
                    await asyncio.gather(
                        *[
                            self.undeploy(deployment.deployment_id)
                            for deployment in chute.deployments
                        ]
                    )
                await session.delete(chute)
                await session.commit()

    async def chute_created(self, event_data: Dict[str, Any], desired_count: int = 1):
        """
        A brand new chute was added to validator inventory.

        MINERS: This is a critical optimization path. A chute being created
                does not necessarily mean inference will be requested. The
                base mining code here *will* deploy the chute however, given
                sufficient resources are available.
        """
        chute_id = event_data["chute_id"]
        version = event_data["version"]
        validator_hotkey = event_data["validator"]
        logger.info(f"Received chute_created event for {chute_id=} {version=}")
        if (validator := validator_by_hotkey(validator_hotkey)) is None:
            logger.warning(f"Validator not found: {validator_hotkey}")
            return

        # Already in inventory?
        if (chute := await self.load_chute(chute_id, version, validator_hotkey)) is not None:
            logger.info(f"Chute {chute_id=} {version=} is already tracked in inventory?")
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
            logger.error(f"Error loading remote chute data: {chute_id=} {version=}: {exc}")
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
            server_gpu_type = None
            server_validator = None
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
                    server_id = deployment.server.server_id
                    server_gpu_type = deployment.server.gpus[0].model_short_ref
                    server_validator = deployment.server.validator
                    if server_validator != validator_hotkey:
                        logger.error(
                            f"Refusing rolling update for {instance_id=}: deployment validator "
                            f"{validator_hotkey!r} does not match server validator "
                            f"{server_validator!r}"
                        )
                        return
                    await self.undeploy(deployment.deployment_id)

            # Make sure the local chute is updated.
            if (chute := await self.load_chute(chute_id, version, validator_hotkey)) is None:
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
                    logger.error(f"Error loading remote chute data: {chute_id=} {version=}: {exc}")
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
            ):
                logger.info(f"Attempting to deploy {chute.chute_id=} on {server_id=}")
                deployment = None
                try:
                    launch_token = await self.get_launch_token(chute)
                    deployment, _ = await k8s.deploy_chute(
                        chute.chute_id,
                        server_id,
                        token=launch_token["token"],
                        config_id=launch_token["config_id"],
                    )
                    logger.success(
                        f"Successfully updated {chute_id=} to {version=} on {server_id=}: {deployment.deployment_id=}"
                    )
                except DeploymentFailure as exc:
                    logger.error(
                        f"Unhandled error attempting to deploy {chute.chute_id=} on {server_id=}: {exc}\n{traceback.format_exc()}"
                    )
                    if deployment:
                        await self.undeploy(deployment.deployment_id)
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
                func.sum(case((GPU.deployment_id != None, 1), else_=0)).label("used_gpus"),  # noqa
            )
            .select_from(Server)
            .join(GPU)
            .group_by(Server.server_id)
            .subquery()
        )
        query = (
            select(
                Deployment,
                (Server.hourly_cost * (gpu_counts.c.used_gpus / gpu_counts.c.total_gpus)).label(
                    "removal_score"
                ),
            )
            .select_from(Deployment)
            .join(GPU)
            .join(Server)
            .join(gpu_counts, Server.server_id == gpu_counts.c.server_id)
            .where(Server.locked.is_(False))
            .where(Deployment.chute_id == chute.chute_id)
            .where(Deployment.validator == chute.validator)
            .where(Server.validator == chute.validator)
            .where(Deployment.job_id.is_(None))  # Don't scale down job deployments
            .where(Deployment.created_at <= func.now() - timedelta(minutes=5))
            .order_by(text("removal_score DESC"))
            .limit(1)
        )
        async with get_session() as session:
            return (await session.execute(query)).unique().scalar_one_or_none()

    @staticmethod
    async def optimal_scale_up_server(chute: Chute, disk_gb: int = 10) -> Optional[Server]:
        """
        Find the optimal server for scaling up a chute deployment.
        """
        if chute.ban_reason:
            logger.warning(f"Will not scale up banned chute {chute.chute_id=}: {chute.ban_reason=}")
            return None
        if not chute.validator or validator_by_hotkey(chute.validator) is None:
            logger.error(
                f"Will not select a server for {chute.chute_id=}: "
                f"validator {chute.validator!r} is not configured"
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
                Server.validator == chute.validator,
            )
            .order_by(Server.hourly_cost.asc(), text("free_gpus ASC"))
        )
        async with get_session() as session:
            servers = (await session.execute(query)).unique().scalars().all()
            for server in servers:
                if not Gepetto._validator_matches(chute, server):
                    continue
                if await k8s.check_node_has_disk_available(server.name, disk_gb):
                    return server
        return None

    async def preempting_deploy(self, chute: Chute, job_id: str = None, disk_gb: int = 10):
        """
        Force deploy a chute by preempting other deployments (assuming a server exists that can be used).
        """
        if chute.ban_reason:
            logger.warning(
                f"Refusing to perform a preempting deploy of banned chute {chute.chute_id=}: {chute.ban_reason=}"
            )
            return
        if not chute.validator or validator_by_hotkey(chute.validator) is None:
            logger.error(
                f"Refusing to preempt for {chute.chute_id=}: "
                f"validator {chute.validator!r} is not configured"
            )
            return

        supported_gpus = list(chute.supported_gpus)
        if "h200" in supported_gpus and set(supported_gpus) - set(["h200"]):
            supported_gpus = list(set(supported_gpus) - set(["h200"]))
        # Get the prometheus data for staleness check
        prom = PrometheusConnect(url=settings.prometheus_url)
        last_invocations = {}
        try:
            result = prom.custom_query("max by (chute_id) (invocation_last_timestamp)")
            for metric in result:
                chute_id = metric["metric"]["chute_id"]
                timestamp = datetime.fromtimestamp(float(metric["value"][1]))
                last_invocations[chute_id] = timestamp.replace(tzinfo=None)
        except Exception as e:
            logger.error(f"Failed to fetch prometheus metrics: {e}")
            pass

        # Calculate value metrics for each chute per validator
        chute_values = {}
        for chute_id, metric in self.remote_metrics.get(chute.validator, {}).items():
            instance_count = metric["instance_count"]
            rate_limited = metric.get("rate_limit_count", 0)
            if instance_count and instance_count >= 5:
                rate_limited = rate_limited / 5
            total_usage_usd = metric.get("total_usage_usd", 0)
            total_invocations = metric.get("total_invocations", 0)
            per_invocation_cost = total_usage_usd / (total_invocations or 1.0)
            theoretical_usage = total_usage_usd
            if per_invocation_cost and rate_limited:
                theoretical_usage += rate_limited * per_invocation_cost
            value_per_instance = 0 if not instance_count else theoretical_usage / instance_count
            chute_values[chute_id] = value_per_instance

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
                Server.validator == chute.validator,
            )
            .order_by(Server.hourly_cost.asc(), text("free_gpus ASC"))
        )
        async with get_session() as session:
            servers = (await session.execute(query)).unique().scalars()
        if not servers:
            logger.warning(f"No servers in inventory are capable of running {chute.chute_id=}")
            return

        # Fetch disk space.
        servers = [
            server
            for server in servers
            if self._validator_matches(chute, server)
            and await k8s.check_node_has_disk_available(server.name, disk_gb)
        ]

        # Iterate through servers to see if any *could* handle preemption.
        chute_counts = {}
        for chute_id, metrics in self.remote_metrics.get(chute.validator, {}).items():
            chute_counts[chute_id] = metrics.get("instance_count", 0)
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

            proposed_counts = deepcopy(chute_counts)
            to_delete = []
            for deployment in sorted(
                server.deployments, key=lambda d: chute_values.get(d.chute_id, 0.0)
            ):
                # Never preempt jobs.
                if deployment.job_id:
                    logger.warning(f"Cannot preempt job deployments: {deployment.job_id=}")
                    continue
                if deployment.validator != chute.validator:
                    continue

                # Make sure we aren't pointlessly preempting (already have a deployment in progress).
                if deployment.chute_id == chute.chute_id:
                    logger.warning(
                        f"Attempting to preempt for {chute.chute_id=}, but deployment already exists: {deployment.deployment_id=}"
                    )
                    return

                # Can't preempt deployments that haven't been verified yet.
                if not deployment.verified_at:
                    logger.warning(
                        f"Cannot preempt unverified deployment: {deployment.deployment_id}"
                    )
                    continue

                # Can't preempt deployments that are <= 5 minutes since verification.
                age = datetime.now(timezone.utc).replace(
                    tzinfo=None
                ) - deployment.verified_at.replace(tzinfo=None)
                if age <= timedelta(minutes=60):
                    logger.warning(
                        f"Cannot preempt {deployment.deployment_id=}, verification age is only {age}"
                    )
                    continue

                # If we'd be left with > 1 instance, we can preempt.
                if proposed_counts.get(deployment.chute_id, 0) > 1:
                    to_delete.append(deployment.deployment_id)
                    available_gpus += len(deployment.gpus)
                    proposed_counts[deployment.chute_id] -= 1
                elif deployment.chute_id in proposed_counts:
                    # Only allow 0 global replicas if we aren't getting invocations.
                    message = (
                        f"Preempting {deployment.deployment_id=} would leave no global instances!"
                    )
                    if (last_invoked := last_invocations.get(deployment.chute_id)) is not None:
                        time_since_invoked = (
                            datetime.now(timezone.utc).replace(tzinfo=None) - last_invoked
                        )
                        if time_since_invoked >= timedelta(minutes=10):
                            to_delete.append(deployment.deployment_id)
                            available_gpus += len(deployment.gpus)
                            proposed_counts[deployment.chute_id] -= 1
                        else:
                            logger.warning(message)
                    else:
                        logger.warning(message)

                # Would we reach a sufficient number of free GPUs?
                if available_gpus >= chute.gpu_count:
                    logger.info(f"Found a server to preempt deployments on: {server.name}")
                    to_preempt = to_delete
                    target_server = server
                    break
            if target_server:
                break
        if not target_server:
            logger.warning(
                f"Could not find a server with sufficient preemptable deployments for {chute.chute_id=}"
            )
            return
        if not self._validator_matches(chute, target_server):
            return

        # Before we actually delete any deployments, let's ensure we can actually obtain the launch token,
        # because only one miner can claim a single job for example, so we don't want to undeploy if we
        # don't actually get the lock.
        try:
            launch_token = await self.get_launch_token(chute, job_id=job_id)
        except DeploymentFailure:
            logger.warning(
                f"Failed to obtain launch token, skipping pre-emption {chute.chute_id=} {job_id=}"
            )
            return

        # Do the preemption.
        try:
            if to_preempt:
                logger.info(
                    f"Preempting deployments to make room for {chute.chute_id=}: {to_preempt}"
                )
                for deployment_id in to_preempt:
                    await self.undeploy(deployment_id)
        except Exception as exc:
            logger.error(f"Unexpected error preempting deployments: {exc}")
            if job_id:
                await self.release_job(chute, job_id)
            raise

        # Deploy on our target server.
        deployment = None
        try:
            extra_ports = await self._get_job_extra_services(chute) if job_id else []
            deployment, k8s_dep = await k8s.deploy_chute(
                chute.chute_id,
                target_server.server_id,
                token=launch_token["token"],
                config_id=launch_token["config_id"],
                job_id=job_id,
                disk_gb=disk_gb,
                extra_service_ports=extra_ports,
            )
            logger.success(
                f"Successfully deployed {chute.chute_id=} {job_id=} via preemption on {server.server_id=}: {deployment.deployment_id=}"
            )
        except DeploymentFailure as exc:
            logger.error(
                f"Error attempting to deploy {chute.chute_id=} {job_id=} on {server.server_id=} via preemption: {exc}\n{traceback.format_exc()}"
            )
            if deployment:
                await self.undeploy(deployment.deployment_id)
            if job_id:
                self.release_job(chute, job_id)

    async def scale_chute(self, chute: Chute, desired_count: int, preempt: bool = False):
        """
        Scale up or down a chute.

        MINERS: This is probably the most critical function to optimize.
        """
        async with self._scale_lock:
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
                    if (deployment := await self.optimal_scale_down_deployment(chute)) is not None:
                        await self.undeploy(deployment.deployment_id)
                    else:
                        logger.error(f"Scale down impossible right now, sorry: {chute.chute_id}")
                        return

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
                            await self.preempting_deploy(chute)
                        return

                    else:
                        logger.info(
                            f"Attempting to deploy {chute.chute_id=} on {server.server_id=}"
                        )
                        deployment = None
                        try:
                            if not self._validator_matches(chute, server):
                                return
                            launch_token = await self.get_launch_token(chute)
                            deployment, _ = await k8s.deploy_chute(
                                chute.chute_id,
                                server.server_id,
                                token=launch_token["token"],
                                config_id=launch_token["config_id"],
                            )
                            logger.success(
                                f"Successfully deployed {chute.chute_id=} on {server.server_id=}: {deployment.deployment_id=}"
                            )
                        except DeploymentFailure as exc:
                            logger.error(
                                f"Error attempting to deploy {chute.chute_id=} on {server.server_id=}: {exc}\n{traceback.format_exc()}"
                            )
                            if deployment:
                                await self.undeploy(deployment.deployment_id)
                            return

    async def reconcile(self):
        """
        Put our local system back in harmony with the validators.
        """
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
                    logger.warning(f"Local chute is outdated: {chute_id=} {chute_data['name']}")
                    try:
                        await self.chute_updated(
                            {
                                "chute_id": chute_id,
                                "version": chute_data["version"],
                                "validator": validator,
                            }
                        )
                        logger.success(f"Successfully synchronized {chute_id=} to {chute_hash=}")
                    except Exception:
                        logger.warning(f"Failed to reconcile {chute_id=} with {chute_hash=}")

        # Get the chutes currently undergoing a rolling update.
        updating = {}
        for validator in settings.validators:
            updating[validator.hotkey] = {}
            async with aiohttp.ClientSession(raise_for_status=True) as session:
                async with session.get(f"{validator.api}/chutes/rolling_updates") as resp:
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
                    if image_data.get("patch_version") and image_data["patch_version"] != "initial":
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
                    tasks.append(asyncio.create_task(self.undeploy(deployment.deployment_id)))
                    continue

                # Make sure the instances created with launch configs have the instance ID tracked.
                if deployment.config_id and not deployment.instance_id:
                    remote_match = remote_by_config_id.get(deployment.config_id)
                    if remote_match and remote_match.get("validator") == deployment.validator:
                        deployment.instance_id = remote_match["instance_id"]
                        logger.info(
                            f"Updated deployment {deployment.deployment_id} with instance_id={deployment.instance_id} "
                            f"based on matching config_id={deployment.config_id}"
                        )

                # Reconcile the verified/active state for instances.
                if deployment.instance_id:
                    remote_instance = (self.remote_instances.get(deployment.validator) or {}).get(
                        deployment.instance_id
                    )
                    if remote_instance:
                        if remote_instance.get("last_verified_at") and not deployment.verified_at:
                            deployment.verified_at = func.now()
                            logger.info(
                                f"Marking deployment {deployment.deployment_id} as verified based on remote status"
                            )
                        remote_active = remote_instance.get("active", True)
                        if deployment.active != remote_active:
                            deployment.active = remote_active
                            deployment.stub = False
                            logger.info(
                                f"Updating deployment {deployment.deployment_id} active status to {deployment.active}"
                            )

                # Check if instance exists on validator
                if deployment.instance_id and deployment.instance_id not in (
                    self.remote_instances.get(deployment.validator) or {}
                ):
                    logger.warning(
                        f"Deployment: {deployment.deployment_id} (instance_id={deployment.instance_id}) on validator {deployment.validator} not found"
                    )
                    tasks.append(
                        asyncio.create_task(
                            self.instance_deleted({"instance_id": deployment.instance_id})
                        )
                    )
                    # Skip the rest of processing for this deployment since instance is gone
                    continue

                remote = (self.remote_chutes.get(deployment.validator) or {}).get(
                    deployment.chute_id
                )

                # Track deployments by their launch configs.
                if deployment.config_id:
                    all_configs.add(deployment.config_id)

                # Special handling for deployments with job_idds
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
                        identifier = (
                            f"{deployment.validator}:{deployment.chute_id}:{deployment.version}"
                        )
                        if identifier not in chutes_to_remove:
                            chutes_to_remove.add(identifier)
                            tasks.append(
                                asyncio.create_task(
                                    self.chute_deleted(
                                        {
                                            "chute_id": deployment.chute_id,
                                            "version": deployment.version,
                                            "validator": deployment.validator,
                                        }
                                    )
                                )
                            )
                        continue

                # Normal deployment handling (no job_id)
                if not remote or remote["version"] != deployment.version:
                    update = updating.get(deployment.validator, {}).get(deployment.chute_id)
                    if update:
                        logger.warning(f"Skipping reconciliation for chute with rolling {update=}")
                        all_deployments.add(deployment.deployment_id)
                        if deployment.instance_id:
                            all_instances.add(deployment.instance_id)
                        continue

                    logger.warning(
                        f"Chute: {deployment.chute_id} version={deployment.version} on validator {deployment.validator} not found"
                    )
                    identifier = (
                        f"{deployment.validator}:{deployment.chute_id}:{deployment.version}"
                    )
                    if identifier not in chutes_to_remove:
                        chutes_to_remove.add(identifier)
                        tasks.append(
                            asyncio.create_task(
                                self.chute_deleted(
                                    {
                                        "chute_id": deployment.chute_id,
                                        "version": deployment.version,
                                        "validator": deployment.validator,
                                    }
                                )
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
                    if deployment.instance_id:
                        if (vali := validator_by_hotkey(deployment.validator)) is not None:
                            await self.purge_validator_instance(
                                vali, deployment.chute_id, deployment.instance_id
                            )
                    await session.delete(deployment)
                    continue

                # Clean up old stubs
                deployment_age = datetime.now(timezone.utc) - deployment.created_at
                if (deployment.stub or not deployment.instance_id) and deployment_age >= timedelta(
                    minutes=30
                ):
                    logger.warning(
                        f"Deployment is still a stub after 30 minutes, deleting! {deployment.deployment_id}"
                    )
                    await session.delete(deployment)
                    continue

                # Check for terminated jobs or jobs that never started
                if (
                    not deployment.active
                    or deployment.verified_at is None
                    and deployment_age >= timedelta(minutes=5)
                ):
                    try:
                        kd = await k8s.get_deployment(deployment.deployment_id)
                    except Exception as exc:
                        if "Not Found" in str(exc) or "(404)" in str(exc):
                            await self.undeploy(deployment.deployment_id)
                        continue

                    destroyed = False
                    job_status = kd.get("status", {})

                    # Check job completion status
                    if job_status.get("succeeded", 0) > 0:
                        logger.info(f"Job completed successfully: {deployment.deployment_id}")
                        await self.undeploy(deployment.deployment_id)
                        destroyed = True
                    elif job_status.get("failed", 0) > 0:
                        logger.warning(f"Job failed: {deployment.deployment_id}")
                        await self.undeploy(deployment.deployment_id)
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
                                await self.undeploy(deployment.deployment_id)
                                destroyed = True
                                break

                    if destroyed:
                        continue

                # Track valid deployments
                all_deployments.add(deployment.deployment_id)
                if deployment.instance_id:
                    all_instances.add(deployment.instance_id)

            await session.commit()

            # # Purge validator instances not deployed locally
            # for validator, instances in self.remote_instances.items():
            #     if (vali := validator_by_hotkey(validator)) is None:
            #         continue
            #     for instance_id, data in instances.items():
            #         config_id = data.get("config_id", None)
            #         if instance_id not in all_instances and (
            #             not config_id or config_id not in all_configs
            #         ):
            #             chute_id = data["chute_id"]
            #             logger.warning(
            #                 f"Found validator {chute_id=} {instance_id=} {config_id=} not deployed locally!"
            #             )
            #             await self.purge_validator_instance(vali, chute_id, instance_id)

            # Purge k8s deployments that aren't tracked anymore
            # BUT exclude legacy deployments from deletion
            for deployment_id in all_k8s_ids - all_deployments:
                if deployment_id in k8s_legacy_ids:
                    logger.info(f"Preserving legacy kubernetes deployment: {deployment_id}")
                    continue
                logger.warning(
                    f"Removing kubernetes deployment that is no longer tracked: {deployment_id}"
                )
                tasks.append(asyncio.create_task(self.undeploy(deployment_id)))

            # GPUs that no longer exist in validator inventory.
            all_gpus = []
            for nodes in self.remote_nodes.values():
                all_gpus.extend(nodes)

            local_gpu_ids = set()
            async for row in (await session.stream(select(GPU))).unique():
                gpu = row[0]
                local_gpu_ids.add(gpu.gpu_id)
                if gpu.gpu_id not in all_gpus:
                    logger.warning(
                        f"GPU {gpu.gpu_id} is no longer in validator {gpu.validator} inventory"
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

                remote = (self.remote_chutes.get(chute.validator) or {}).get(chute.chute_id)
                if not remote or remote["version"] != chute.version:
                    update = updating.get(chute.validator, {}).get(chute.chute_id)
                    if update:
                        logger.warning(f"Skipping reconciliation for chute with rolling {update=}")
                        continue

                    logger.warning(
                        f"Chute: {chute.chute_id} version={chute.version} on validator {chute.validator} not found: {remote=}"
                    )
                    tasks.append(
                        asyncio.create_task(
                            self.chute_deleted(
                                {
                                    "chute_id": chute.chute_id,
                                    "version": chute.version,
                                    "validator": chute.validator,
                                }
                            )
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
                            asyncio.create_task(
                                self.chute_created(
                                    {
                                        "chute_id": chute_id,
                                        "version": config["version"],
                                        "validator": validator,
                                    }
                                )
                            )
                        )

            # Check Kubernetes nodes
            nodes = await k8s.get_kubernetes_nodes()
            node_ids = {node["server_id"] for node in nodes}
            all_server_ids = set()

            servers = (await session.execute(select(Server))).unique().scalars()
            for server in servers:
                if server.server_id not in node_ids:
                    logger.warning(f"Server {server.server_id} no longer in kubernetes node list!")
                    tasks.append(
                        asyncio.create_task(self.server_deleted({"server_id": server.server_id}))
                    )
                all_server_ids.add(server.server_id)

            # XXX We won't do the opposite (remove k8s nodes that aren't tracked) because they could be in provisioning status.
            for node_id in node_ids - all_server_ids:
                logger.warning(f"Server/node {node_id} not tracked in inventory, ignoring...")

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
    gepetto = Gepetto()
    await gepetto.run()


def run():
    asyncio.run(main())


if __name__ == "__main__":
    run()
