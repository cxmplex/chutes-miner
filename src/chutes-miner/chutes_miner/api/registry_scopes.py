"""Durable database authority and replay outbox for registry launch scopes."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from chutes_common.schemas.teardown import MinerLaunchIntent, RegistryScopeIntent
from chutes_miner.api.database import get_session
from chutes_miner.api.exceptions import DeploymentFailure
from sqlalchemy import and_, or_, select


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True)
class RegistryScopeWorkItem:
    launch_config_id: str
    validator: str
    server_id: str | None
    repository: str | None
    manifest_digest: str | None
    desired_state: str
    phase: str


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _exact_registration(
    intent: MinerLaunchIntent,
    payload: dict[str, Any],
) -> dict[str, str]:
    registry = payload.get("registry")
    if (
        not isinstance(registry, dict)
        or set(registry) != {"repository", "manifest_digest"}
        or not isinstance(payload.get("config_id"), str)
        or not payload["config_id"]
        or not isinstance(registry["repository"], str)
        or not registry["repository"]
        or not isinstance(registry["manifest_digest"], str)
        or _DIGEST_RE.fullmatch(registry["manifest_digest"]) is None
        or not isinstance(intent.deployment_id, str)
        or not intent.deployment_id
    ):
        raise DeploymentFailure("registry scope intent lacks exact launch authority")
    return {
        "launch_config_id": payload["config_id"],
        "validator": intent.validator,
        "server_id": intent.server_id,
        "repository": registry["repository"],
        "manifest_digest": registry["manifest_digest"],
        "deployment_id": intent.deployment_id,
        "launch_intent_id": intent.intent_id,
    }


async def ensure_registry_scope_registration_in_session(
    session: Any,
    intent: MinerLaunchIntent,
    payload: dict[str, Any],
) -> RegistryScopeIntent:
    """Persist exact scope authority in the launch-response transaction."""
    expected = _exact_registration(intent, payload)
    row = await session.get(
        RegistryScopeIntent,
        expected["launch_config_id"],
        with_for_update=True,
    )
    if row is None:
        row = RegistryScopeIntent(
            **expected,
            desired_state="active",
            phase="register_pending",
        )
        session.add(row)
        return row
    observed = {
        field: getattr(row, field)
        for field in (
            "launch_config_id",
            "validator",
            "server_id",
            "repository",
            "manifest_digest",
            "deployment_id",
            "launch_intent_id",
        )
    }
    if observed != expected or row.desired_state != "active":
        raise DeploymentFailure(
            "registry scope authority conflicts with durable launch"
        )
    return row


def _validate_registration_ack(
    launch_config_id: str,
    ack: dict[str, Any],
) -> None:
    if (
        not isinstance(ack, dict)
        or set(ack) != {"registered", "launch_config_id", "expires_at"}
        or ack.get("registered") is not True
        or ack.get("launch_config_id") != launch_config_id
        or not isinstance(ack.get("expires_at"), str)
        or not ack["expires_at"]
    ):
        raise DeploymentFailure("registry broker returned a malformed registration ACK")


async def record_registry_scope_registered_in_session(
    session: Any,
    launch_config_id: str,
    ack: dict[str, Any],
    *,
    launch_intent_id: str | None = None,
) -> RegistryScopeIntent:
    """Persist the latest exact broker ACK in the caller's transaction."""
    _validate_registration_ack(launch_config_id, ack)
    row = await session.get(
        RegistryScopeIntent,
        launch_config_id,
        with_for_update=True,
    )
    if row is None:
        raise DeploymentFailure("registry scope registration authority disappeared")
    if launch_intent_id is not None and row.launch_intent_id != launch_intent_id:
        raise DeploymentFailure("registry scope registration launch authority changed")
    # Reconstructing an evicted broker cache legitimately renews expires_at. The
    # database therefore retains the latest exact ACK, not an obsolete expiry.
    row.registration_ack = ack
    row.registered_at = row.registered_at or _utc_now()
    if row.desired_state == "active":
        row.phase = "active"
    else:
        # A stale registration completion that races a revoke must make the
        # durable revocation outbox pending again.
        row.phase = "revoke_pending"
    row.last_failure = None
    return row


async def record_registry_scope_registered(
    launch_config_id: str,
    ack: dict[str, Any],
) -> None:
    _validate_registration_ack(launch_config_id, ack)
    async with get_session() as session:
        await record_registry_scope_registered_in_session(
            session,
            launch_config_id,
            ack,
        )
        await session.commit()


async def request_registry_scope_revocation_in_session(
    session: Any,
    *,
    launch_config_id: str,
    validator: str,
    server_id: str | None = None,
    deployment_id: str | None = None,
) -> RegistryScopeIntent:
    """Write the revocation outbox entry before any external revoke request."""
    if not launch_config_id or not validator:
        raise DeploymentFailure("registry scope revocation lacks exact authority")
    row = await session.get(
        RegistryScopeIntent,
        launch_config_id,
        with_for_update=True,
    )
    if row is None:
        row = RegistryScopeIntent(
            launch_config_id=launch_config_id,
            validator=validator,
            server_id=server_id,
            deployment_id=deployment_id,
            desired_state="revoked",
            phase="revoke_pending",
        )
        session.add(row)
        return row
    if row.validator != validator:
        raise DeploymentFailure("registry scope revocation validator changed")
    if server_id is not None and row.server_id not in {None, server_id}:
        raise DeploymentFailure("registry scope revocation server changed")
    if deployment_id is not None and row.deployment_id not in {None, deployment_id}:
        raise DeploymentFailure("registry scope revocation deployment changed")
    row.server_id = row.server_id or server_id
    row.deployment_id = row.deployment_id or deployment_id
    row.desired_state = "revoked"
    if row.phase != "revoked":
        row.phase = "revoke_pending"
    row.last_failure = None
    return row


async def request_registry_scope_revocation(
    *,
    launch_config_id: str,
    validator: str,
    server_id: str | None = None,
    deployment_id: str | None = None,
) -> None:
    async with get_session() as session:
        await request_registry_scope_revocation_in_session(
            session,
            launch_config_id=launch_config_id,
            validator=validator,
            server_id=server_id,
            deployment_id=deployment_id,
        )
        await session.commit()


async def record_registry_scope_revoked(
    launch_config_id: str,
    ack: dict[str, Any],
) -> dict[str, Any]:
    async with get_session() as session:
        row = await session.get(
            RegistryScopeIntent,
            launch_config_id,
            with_for_update=True,
        )
        if row is None or row.desired_state != "revoked":
            raise DeploymentFailure("registry scope revocation authority disappeared")
        expected = {
            "status": ack.get("status") if isinstance(ack, dict) else None,
            "revoked": True,
            "launch_config_id": launch_config_id,
            "server_id": row.server_id,
        }
        if (
            row.server_id is None
            or expected["status"] not in {"revoked", "already_absent"}
            or ack != expected
        ):
            raise DeploymentFailure("registry broker returned a malformed revocation ACK")
        durable_ack = {
            "status": "revoked",
            "revoked": True,
            "launch_config_id": launch_config_id,
            "server_id": row.server_id,
        }
        if row.revocation_ack is not None and row.revocation_ack != durable_ack:
            raise DeploymentFailure("registry scope revocation replay changed its ACK")
        row.revocation_ack = durable_ack
        row.revoked_at = row.revoked_at or _utc_now()
        row.phase = "revoked"
        row.last_failure = None
        await session.commit()
        return durable_ack


async def record_registry_scope_failure(
    launch_config_id: str,
    exc: Exception,
) -> None:
    async with get_session() as session:
        row = await session.get(
            RegistryScopeIntent,
            launch_config_id,
            with_for_update=True,
        )
        if row is not None and row.phase != "revoked":
            row.last_failure = f"{type(exc).__name__}: {exc}"[:8000]
            await session.commit()


async def registry_scope_work_items(
    *,
    reconstruct_active: bool,
) -> list[RegistryScopeWorkItem]:
    """Return pending outbox work, optionally reminting active broker caches."""
    active_phases = {"register_pending"}
    if reconstruct_active:
        active_phases.add("active")
    async with get_session() as session:
        rows = (
            await session.execute(
                select(RegistryScopeIntent)
                .where(
                    or_(
                        and_(
                            RegistryScopeIntent.desired_state == "active",
                            RegistryScopeIntent.phase.in_(active_phases),
                        ),
                        and_(
                            RegistryScopeIntent.desired_state == "revoked",
                            RegistryScopeIntent.phase != "revoked",
                        ),
                    )
                )
                .order_by(
                    RegistryScopeIntent.created_at, RegistryScopeIntent.launch_config_id
                )
            )
        ).scalars()
        return [
            RegistryScopeWorkItem(
                launch_config_id=row.launch_config_id,
                validator=row.validator,
                server_id=row.server_id,
                repository=row.repository,
                manifest_digest=row.manifest_digest,
                desired_state=row.desired_state,
                phase=row.phase,
            )
            for row in rows
        ]
