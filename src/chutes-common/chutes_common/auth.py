"""
Authentication helpers.
"""

import time
import hashlib
import hmac
import re
import secrets
import orjson as json
from loguru import logger
from typing import Dict, Any, Callable
from functools import lru_cache
from substrateinterface import Keypair, KeypairType
from fastapi import Request, status, HTTPException, Header
from chutes_common.constants import (
    HOTKEY_HEADER,
    MINER_HEADER,
    VALIDATOR_HEADER,
    SIGNATURE_HEADER,
    NONCE_HEADER,
    SIG_VERSION_HEADER,
    SIG_VERSION_V2,
)
from chutes_common.settings import miner_settings


V2_NONCE_ACCEPTANCE_SECONDS = 30
_V2_NONCE_PATTERN = re.compile(r"(0|[1-9][0-9]*)[.][0-9a-f]{16}")


@lru_cache(maxsize=32)
def get_keypair(ss58):
    """
    Helper to load keypairs efficiently.
    """
    return Keypair(ss58_address=ss58, crypto_type=KeypairType.SR25519)


def generate_v2_nonce() -> str:
    """A v2 nonce: unix seconds (freshness window) + random suffix (per-request uniqueness)."""
    return f"{int(time.time())}.{secrets.token_hex(8)}"


def _nonce_timestamp(nonce: str) -> int:
    """Leading unix-seconds timestamp of a v1 (bare int) or v2 (``ts.rand``) nonce."""
    return int(nonce.split(".", 1)[0])


def _v2_nonce_timestamp(nonce: str | None) -> int | None:
    """Return the timestamp only for a canonical ``unix-seconds.16-lower-hex`` nonce."""
    if not isinstance(nonce, str):
        return None
    match = _V2_NONCE_PATTERN.fullmatch(nonce)
    return int(match.group(1)) if match else None


def build_v2_message_mgmt(
    miner: str,
    validator: str,
    method: str,
    target: str,
    nonce: str,
    body_sha256: str | None,
) -> str:
    """4-part v2 signed message binding method + path (see the sek8s backend fix plan, Phase 2)."""
    return f"v2:{miner}:{validator}:{method.upper()}:{target}:{nonce}:{body_sha256 or ''}"


def _request_target(request: Request) -> str:
    query = request.url.query
    return f"{request.url.path}?{query}" if query else request.url.path


def _consume_v2_nonce(signer: str, nonce: str, ttl_seconds: int) -> bool:
    """Single-use guard for a v2 nonce via Redis SET NX EX (fail-closed).

    Returns False if the (signer, nonce) was already consumed or Redis is unavailable, so a replayed
    v2 signature is rejected within the acceptance window. Uses the miner control-plane Redis (the
    server context that runs these verifiers); imported lazily to avoid the monitoring import chain in
    contexts that never verify requests.
    """
    try:
        from chutes_common.redis import MonitoringRedisClient

        client = MonitoringRedisClient().redis
        return bool(client.set(f"sig:{signer}:{nonce}", "1", nx=True, ex=ttl_seconds))
    except Exception as exc:  # noqa: BLE001 - fail closed: if we cannot dedupe, reject the replay-risky request
        logger.warning(f"sig-nonce cache unavailable, rejecting v2 request: {exc}")
        return False


def authorize(
    allow_miner=False,
    allow_validator=False,
    purpose: str = None,
    require_v2: bool | Callable[[], bool] = False,
    allow_attested_session: bool = True,
    observe_v1: bool = False,
):
    def _authorize(
        request: Request,
        validator: str | None = Header(None, alias=VALIDATOR_HEADER),
        miner: str | None = Header(None, alias=MINER_HEADER),
        nonce: str | None = Header(None, alias=NONCE_HEADER),
        signature: str | None = Header(None, alias=SIGNATURE_HEADER),
        sig_version: str | None = Header(None, alias=SIG_VERSION_HEADER),
        attested_session: str | None = Header(None, alias="X-Chutes-Attested-Session"),
    ):
        """
        Verify the authenticity of a request.

        A request carrying ``X-Chutes-Sig-Version: 2`` is verified against the v2 message binding the
        HTTP method + path (so a captured read signature cannot be replayed to a same-purpose
        destructive endpoint); legacy v1 is still accepted unless ``require_v2``.
        """
        v2_required = require_v2() if callable(require_v2) else require_v2
        if isinstance(attested_session, str) and attested_session:
            if v2_required or not allow_attested_session:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="V2 management signature required",
                )
            expected_session = miner_settings.attested_session
            if (
                not allow_miner
                or miner != miner_settings.miner_ss58
                or validator != miner_settings.miner_ss58
                or not hmac.compare_digest(attested_session, expected_session)
                or nonce
                or signature
            ):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="invalid attested miner session",
                )
            return
        allowed_signers = []
        if allow_miner:
            allowed_signers.append(miner_settings.miner_ss58)
        if allow_validator:
            allowed_signers += [validator.hotkey for validator in miner_settings.validators]
        is_v2 = sig_version == SIG_VERSION_V2
        if is_v2:
            nonce_ts = _v2_nonce_timestamp(nonce)
        else:
            try:
                nonce_ts = _nonce_timestamp(nonce) if nonce else None
            except (ValueError, TypeError):
                nonce_ts = None
        nonce_age = int(time.time()) - nonce_ts if nonce_ts is not None else None
        if (
            any(not v for v in [miner, validator, nonce, signature])
            or miner != miner_settings.miner_ss58
            or validator not in allowed_signers
            or nonce_ts is None
            or nonce_age < 0
            or nonce_age >= V2_NONCE_ACCEPTANCE_SECONDS
            or (v2_required and not is_v2)
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="go away (missing)"
            )
        if is_v2:
            signature_string = build_v2_message_mgmt(
                miner,
                validator,
                request.method,
                _request_target(request),
                nonce,
                request.state.body_sha256 if request.state.body_sha256 else None,
            )
        else:
            signature_string = ":".join(
                [
                    miner,
                    validator,
                    nonce,
                    request.state.body_sha256 if request.state.body_sha256 else purpose,
                ]
            )
        if not get_keypair(validator).verify(signature_string, bytes.fromhex(signature)):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"go away: (sig): {request.state.body_sha256=} {signature_string=}",
            )
        if observe_v1 and not is_v2:
            logger.warning(
                "legacy_v1_management_signature_accepted signer={} method={} target={}",
                validator,
                request.method,
                _request_target(request),
            )
        # v2 nonces are single-use: consume only AFTER the signature verifies, so an unauthenticated
        # caller cannot burn a legitimate signer's nonce.
        if is_v2 and not _consume_v2_nonce(
            validator,
            nonce,
            ttl_seconds=max(1, V2_NONCE_ACCEPTANCE_SECONDS - nonce_age),
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Nonce already used (replay); request a fresh signature.",
            )

    return _authorize


def get_signing_message(
    hotkey: str,
    nonce: str,
    payload_str: str | bytes | None,
    purpose: str | None = None,
    payload_hash: str | None = None,
) -> str:
    """
    Get the signing message for a given hotkey, nonce, and payload.
    """
    if payload_str:
        if isinstance(payload_str, str):
            payload_str = payload_str.encode()
        return f"{hotkey}:{nonce}:{hashlib.sha256(payload_str).hexdigest()}"
    elif purpose:
        return f"{hotkey}:{nonce}:{purpose}"
    elif payload_hash:
        return f"{hotkey}:{nonce}:{payload_hash}"
    else:
        raise ValueError("Either payload_str or purpose must be provided")


def sign_request(
    payload: Dict[str, Any] | str | None = None,
    purpose: str = None,
    management: bool = False,
    method: str = None,
    path: str = None,
):
    """Build a request using the short-lived attested GPU runtime session."""
    headers = {
        HOTKEY_HEADER: miner_settings.miner_ss58,
        "X-Chutes-Attested-Session": miner_settings.attested_session,
    }
    payload_string = None
    if payload is not None:
        if isinstance(payload, (list, dict)):
            headers["Content-Type"] = "application/json"
            payload_string = json.dumps(payload)
        else:
            payload_string = payload
    if management:
        headers[MINER_HEADER] = headers.pop(HOTKEY_HEADER)
        headers[VALIDATOR_HEADER] = headers[MINER_HEADER]

    return headers, payload_string
