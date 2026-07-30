"""
Authentication helper for pulling images with miner credentials.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import ssl
import tempfile
import time
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import parse_qs, urlsplit

import aiohttp
from chutes_common.auth import sign_request
from chutes_common.settings import miner_settings as settings
from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger(__name__)
router = APIRouter()
_scopes: dict[str, dict] = {}
_scope_lock = asyncio.Lock()
_scopes_loaded = False


def _persist_scopes() -> None:
    path = Path(settings.registry_scopes_file)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for stale in path.parent.glob(f".{path.name}.*.tmp"):
        try:
            if stale.is_file() and not stale.is_symlink():
                stale.unlink()
        except FileNotFoundError:
            pass
    document = {
        config_id: {
            key: (
                value.isoformat()
                if key == "expires_at_value" and isinstance(value, datetime)
                else value
            )
            for key, value in scope.items()
        }
        for config_id, scope in sorted(_scopes.items())
    }
    payload = (
        _canonical(
            {
                "schema": "chutes.registry-scopes",
                "version": 1,
                "scopes": document,
            }
        )
        + b"\n"
    )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _load_scopes_unchecked() -> None:
    global _scopes_loaded
    if _scopes_loaded:
        return
    path = Path(settings.registry_scopes_file)
    try:
        document = json.loads(path.read_text(encoding="ascii"))
    except FileNotFoundError:
        _scopes_loaded = True
        return
    if (
        not isinstance(document, dict)
        or document.get("schema") != "chutes.registry-scopes"
        or document.get("version") != 1
        or not isinstance(document.get("scopes"), dict)
    ):
        raise RuntimeError("durable registry scope state is invalid")
    loaded: dict[str, dict] = {}
    for config_id, scope in document["scopes"].items():
        if not isinstance(config_id, str) or not isinstance(scope, dict):
            raise RuntimeError("durable registry scope entry is invalid")
        try:
            expires_at_value = datetime.fromisoformat(
                scope["expires_at_value"].replace("Z", "+00:00")
            )
        except (KeyError, AttributeError, ValueError) as exc:
            raise RuntimeError("durable registry scope expiry is invalid") from exc
        _scope_identity(scope)
        loaded[config_id] = {**scope, "expires_at_value": expires_at_value}
    now = datetime.now(timezone.utc)
    _scopes.clear()
    _scopes.update(
        {
            config_id: scope
            for config_id, scope in loaded.items()
            if scope["expires_at_value"] > now and scope.get("revoked") is not True
        }
    )
    _scopes_loaded = True
    if len(_scopes) != len(loaded):
        _persist_scopes()

def _quarantine_corrupt_scope_cache(path: Path, exc: Exception) -> None:
    quarantine = path.with_name(f"{path.name}.corrupt-{time.time_ns()}-{os.getpid()}")
    try:
        os.replace(path, quarantine)
    except FileNotFoundError:
        return
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    logger.error("quarantined corrupt registry scope cache %s as %s: %s", path, quarantine, exc)


def _load_scopes() -> None:
    global _scopes_loaded
    if _scopes_loaded:
        return
    path = Path(settings.registry_scopes_file)
    try:
        _load_scopes_unchecked()
    except (json.JSONDecodeError, UnicodeError, RuntimeError, TypeError, ValueError) as exc:
        _quarantine_corrupt_scope_cache(path, exc)
        _scopes.clear()
        _scopes_loaded = True

def _garbage_collect_scopes(now: datetime) -> bool:
    removed = [
        config_id
        for config_id, scope in _scopes.items()
        if scope["expires_at_value"] <= now or scope.get("revoked") is True
    ]
    for config_id in removed:
        _scopes.pop(config_id, None)
    return bool(removed)


class RegistryScopeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_name: Literal["chutes.miner-registry-scope"] = Field(alias="schema")
    version: Literal[1]
    server_id: str
    launch_config_id: str
    repository: str = Field(min_length=3, max_length=255)
    manifest_digest: str

    @field_validator("manifest_digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        value = value.lower()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("manifest_digest must be a canonical sha256")
        return value


def _private_request(request: Request) -> None:
    ip = ip_address(request.client.host)
    if not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="go away",
        )


def _canonical(value: dict) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _matches(scope: dict, method: str, uri: str) -> bool:
    if method.upper() not in {"GET", "HEAD"}:
        return False
    parsed = urlsplit(uri)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return False
    path = parsed.path
    if path == "/v2/":
        return not parsed.query
    if path == "/v2/_token":
        try:
            query = parse_qs(
                parsed.query,
                strict_parsing=True,
                keep_blank_values=True,
            )
        except ValueError:
            return False
        return (
            method.upper() == "GET"
            and not set(query).difference({"scope", "service"})
            and query.get("scope") == [f"repository:{scope['repository']}:pull"]
        )
    if parsed.query:
        return False
    prefix = f"/v2/{scope['repository']}/"
    if not path.startswith(prefix):
        return False
    suffix = path[len(prefix) :]
    if suffix.startswith("manifests/"):
        reference = suffix.removeprefix("manifests/")
        return reference in {
            *scope["allowed_manifests"],
            *scope["allowed_manifest_tags"],
        }
    if suffix.startswith("blobs/"):
        return suffix.removeprefix("blobs/") in scope["allowed_blobs"]
    return False


def _scope_identity(scope: dict) -> tuple[str, str, str]:
    try:
        values = (
            scope["server_id"],
            scope["attestation_id"],
            scope["attested_cert_sha256"],
        )
    except KeyError as exc:
        raise RuntimeError("durable registry scope identity is incomplete") from exc
    if any(not isinstance(value, str) or not value for value in values):
        raise RuntimeError("durable registry scope identity is invalid")
    return values


def _authorization_launch_config(authorization: str | None) -> str | None:
    if not authorization or not authorization.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(
            authorization.removeprefix("Basic "),
            validate=True,
        ).decode("ascii")
        launch_config_id, password = decoded.split(":", 1)
    except (ValueError, UnicodeDecodeError):
        return None
    if (
        not launch_config_id
        or password != "chutes-registry-scope"
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", launch_config_id)
    ):
        return None
    return launch_config_id


def _current_scope_identity() -> tuple[str, str, str]:
    identity = settings.seedless_gpu_identity
    return (
        identity["server_id"],
        identity["attestation_id"],
        hashlib.sha256(Path(settings.attested_cert_file).read_bytes()).hexdigest(),
    )


def _select_scope(
    scopes: list[dict],
    method: str,
    uri: str,
    now: datetime,
    *,
    launch_config_id: str | None = None,
) -> dict | None:
    if not scopes:
        return None
    current_identity = _current_scope_identity()
    active = [
        scope
        for scope in scopes
        if scope.get("expires_at_value") is not None
        and scope["expires_at_value"] > now
        and _scope_identity(scope) == current_identity
        and (launch_config_id is None or scope.get("launch_config_id") == launch_config_id)
    ]
    matches = [scope for scope in active if _matches(scope, method, uri)]
    if not matches:
        return None
    parsed = urlsplit(uri)
    if parsed.path.startswith("/v2/") and "/manifests/" in parsed.path:
        reference = parsed.path.rsplit("/manifests/", 1)[1]
        exact_roots = [scope for scope in matches if scope["manifest_digest"] == reference]
        if exact_roots:
            matches = exact_roots
            if len({scope["descriptor_closure_sha256"] for scope in matches}) != 1:
                return None
        canonical_references = {
            scope["manifest_tag_digests"].get(reference, reference) for scope in matches
        }
        if len(canonical_references) != 1:
            return None
    identities = {_scope_identity(scope) for scope in matches}
    if len(identities) != 1:
        return None
    return max(
        matches,
        key=lambda item: (
            item["expires_at_value"],
            item["launch_config_id"],
        ),
    )


async def _mint_registry_scope(
    body: RegistryScopeRequest,
    attested_session: str,
) -> dict:
    validator = settings.validators[0]
    context = ssl.create_default_context()
    context.load_cert_chain(
        settings.attested_cert_file,
        settings.attested_key_file,
    )
    payload = {
        "schema": "chutes.registry-session-request",
        "version": 1,
        "repository": body.repository,
        "action": "pull",
        "manifest_digest": body.manifest_digest,
        "launch_config_id": body.launch_config_id,
    }
    try:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=context),
        ) as client:
            async with client.post(
                f"{validator.api.rstrip('/')}/registry/sessions",
                data=_canonical(payload),
                headers={
                    "Content-Type": "application/json",
                    "X-Chutes-Attested-Session": attested_session,
                },
                allow_redirects=False,
            ) as response:
                result = await response.json()
                if response.status != 200:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Validator rejected the exact registry launch scope.",
                    )
    except aiohttp.ClientError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Validator registry session service is unavailable.",
        ) from exc
    required = {
        "schema",
        "version",
        "token",
        "expires_at",
        "launch_config_id",
        "repository",
        "manifest_digest",
        "descriptor_closure_sha256",
        "allowed_manifests",
        "allowed_blobs",
        "allowed_manifest_tags",
        "manifest_tag_digests",
    }
    if (
        not isinstance(result, dict)
        or set(result) != required
        or result["schema"] != "chutes.registry-session-result"
        or result["version"] != 1
        or result["launch_config_id"] != body.launch_config_id
        or result["repository"] != body.repository
        or result["manifest_digest"] != body.manifest_digest
        or not isinstance(result["token"], str)
        or not result["token"]
        or not re.fullmatch(
            r"[0-9a-f]{64}",
            result.get("descriptor_closure_sha256", ""),
        )
        or any(
            not isinstance(result.get(field), list) or result[field] != sorted(set(result[field]))
            for field in (
                "allowed_manifests",
                "allowed_blobs",
                "allowed_manifest_tags",
            )
        )
        or body.manifest_digest not in result["allowed_manifests"]
        or not isinstance(result["manifest_tag_digests"], dict)
        or set(result["manifest_tag_digests"]) != set(result["allowed_manifest_tags"])
        or any(
            digest not in result["allowed_manifests"]
            for digest in result["manifest_tag_digests"].values()
        )
        or any(
            not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            for field in ("allowed_manifests", "allowed_blobs")
            for digest in result[field]
        )
        or any(
            not re.fullmatch(r"sha256-[0-9a-f]{64}\.sig", tag)
            for tag in result["allowed_manifest_tags"]
        )
        or hashlib.sha256(
            _canonical(
                {
                    "schema": "chutes.oci-descriptor-closure",
                    "version": 1,
                    "root_manifest": result["manifest_digest"],
                    "manifests": result["allowed_manifests"],
                    "blobs": result["allowed_blobs"],
                    "manifest_tags": result["allowed_manifest_tags"],
                    "manifest_tag_digests": result["manifest_tag_digests"],
                }
            )
        ).hexdigest()
        != result["descriptor_closure_sha256"]
    ):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Validator returned a malformed registry session closure.",
        )
    try:
        expires_at = datetime.fromisoformat(result["expires_at"].replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Validator returned an invalid registry session expiry.",
        ) from exc
    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Validator returned an already expired registry session.",
        )
    scope_identity = _current_scope_identity()
    return {
        **result,
        "expires_at_value": expires_at,
        "server_id": scope_identity[0],
        "attestation_id": scope_identity[1],
        "attested_cert_sha256": scope_identity[2],
    }


@router.post("/scopes")
async def register_registry_scope(
    body: RegistryScopeRequest,
    request: Request,
    attested_session: str | None = Header(
        None,
        alias="X-Chutes-Attested-Session",
    ),
):
    _private_request(request)
    if (
        not settings.gpu_tee_only
        or not attested_session
        or not hmac.compare_digest(attested_session, settings.attested_session)
        or body.server_id != settings.seedless_gpu_identity["server_id"]
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Registry scope registration requires the current attested identity.",
        )
    scope = await _mint_registry_scope(body, attested_session)
    async with _scope_lock:
        _load_scopes()
        _garbage_collect_scopes(datetime.now(timezone.utc))
        _scopes[body.launch_config_id] = scope
        _persist_scopes()
    return {
        "registered": True,
        "launch_config_id": body.launch_config_id,
        "expires_at": scope["expires_at"],
    }


@router.delete("/scopes/{launch_config_id}")
async def revoke_registry_scope(
    launch_config_id: str,
    request: Request,
    attested_session: str | None = Header(
        None,
        alias="X-Chutes-Attested-Session",
    ),
):
    _private_request(request)
    if (
        not settings.gpu_tee_only
        or not attested_session
        or not hmac.compare_digest(attested_session, settings.attested_session)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Registry scope revocation requires current attested identity.",
        )
    validator = settings.validators[0]
    context = ssl.create_default_context()
    context.load_cert_chain(settings.attested_cert_file, settings.attested_key_file)
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=context),
    ) as client:
        async with client.delete(
            f"{validator.api.rstrip('/')}/registry/sessions/{launch_config_id}",
            headers={"X-Chutes-Attested-Session": attested_session},
            allow_redirects=False,
        ) as response:
            result = await response.json()
            if response.status != 200 or result != {
                "revoked": True,
                "launch_config_id": launch_config_id,
            }:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Validator rejected exact registry scope revocation.",
                )
    async with _scope_lock:
        _load_scopes()
        _scopes.pop(launch_config_id, None)
        _garbage_collect_scopes(datetime.now(timezone.utc))
        _persist_scopes()
    return result


@router.get("/auth")
async def registry_auth(
    request: Request,
    response: Response,
    original_method: str | None = Header(
        None,
        alias="X-Chutes-Registry-Method",
    ),
    original_uri: str | None = Header(
        None,
        alias="X-Chutes-Registry-Uri",
    ),
    launch_config_id: Annotated[
        str | None,
        Header(alias="X-Chutes-Launch-Config-ID"),
    ] = None,
    authorization: Annotated[
        str | None,
        Header(alias="Authorization"),
    ] = None,
):
    _private_request(request)
    if settings.gpu_tee_only:
        if not original_method or not original_uri:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Registry request context is missing.",
            )
        now = datetime.now(timezone.utc)
        credential_config_id = _authorization_launch_config(authorization)
        if credential_config_id is None or launch_config_id not in {
            None,
            credential_config_id,
        }:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Registry request lacks its exact launch-config credential.",
            )
        launch_config_id = credential_config_id
        async with _scope_lock:
            _load_scopes()
            changed = _garbage_collect_scopes(now)
            scope = _select_scope(
                list(_scopes.values()),
                original_method,
                original_uri,
                now,
                launch_config_id=launch_config_id,
            )
            if changed:
                _persist_scopes()
        if scope is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No exact registry launch scope authorizes this request.",
            )
        if scope["expires_at_value"] <= now + timedelta(seconds=60):
            body = RegistryScopeRequest(
                schema_name="chutes.miner-registry-scope",
                version=1,
                server_id=scope["server_id"],
                launch_config_id=scope["launch_config_id"],
                repository=scope["repository"],
                manifest_digest=scope["manifest_digest"],
            )
            try:
                refreshed = await _mint_registry_scope(
                    body,
                    settings.attested_session,
                )
            except HTTPException:
                async with _scope_lock:
                    _scopes.pop(body.launch_config_id, None)
                    _persist_scopes()
                raise
            async with _scope_lock:
                current = _scopes.get(body.launch_config_id)
                if (
                    current is None
                    or current["repository"] != body.repository
                    or current["manifest_digest"] != body.manifest_digest
                ):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Registry launch scope changed during refresh.",
                    )
                _scopes[body.launch_config_id] = refreshed
                _persist_scopes()
            scope = refreshed
        parsed = urlsplit(original_uri)
        prefix = f"/v2/{scope['repository']}/manifests/"
        upstream_uri = original_uri
        if parsed.path.startswith(prefix):
            reference = parsed.path.removeprefix(prefix)
            digest = scope["manifest_tag_digests"].get(reference)
            if digest:
                upstream_uri = f"{prefix}{digest}"
        response.headers["X-Chutes-Registry-Upstream-Uri"] = upstream_uri
        response.headers["X-Chutes-Registry-Session"] = scope["token"]
        response.headers["X-Chutes-Launch-Config-ID"] = scope["launch_config_id"]
        return {"authenticated": True, "auth_type": "registry_session"}
    if request.headers.get("X-Chutes-Attested-Session"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Attested registry requests cannot fall back to hotkey auth.",
        )
    headers, _ = sign_request(payload=None, purpose="registry")
    response.headers.update(headers)
    return {"authenticated": True, "auth_type": "legacy_miner"}
