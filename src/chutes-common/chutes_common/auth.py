"""
Authentication helpers.
"""

import time
import hashlib
import secrets
import orjson as json
from loguru import logger
from typing import Dict, Any
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


def build_v2_message_mgmt(
    miner: str, validator: str, method: str, target: str, nonce: str, body_sha256: str | None
) -> str:
    """4-part v2 signed message binding method + path (see the sek8s backend fix plan, Phase 2)."""
    return f"v2:{miner}:{validator}:{method.upper()}:{target}:{nonce}:{body_sha256 or ''}"


def _request_target(request: Request) -> str:
    query = request.url.query
    return f"{request.url.path}?{query}" if query else request.url.path


def _consume_v2_nonce(signer: str, nonce: str, ttl_seconds: int = 30) -> bool:
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


def authorize(allow_miner=False, allow_validator=False, purpose: str = None, require_v2=False):
    def _authorize(
        request: Request,
        validator: str | None = Header(None, alias=VALIDATOR_HEADER),
        miner: str | None = Header(None, alias=MINER_HEADER),
        nonce: str | None = Header(None, alias=NONCE_HEADER),
        signature: str | None = Header(None, alias=SIGNATURE_HEADER),
        sig_version: str | None = Header(None, alias=SIG_VERSION_HEADER),
    ):
        """
        Verify the authenticity of a request.

        A request carrying ``X-Chutes-Sig-Version: 2`` is verified against the v2 message binding the
        HTTP method + path (so a captured read signature cannot be replayed to a same-purpose
        destructive endpoint); legacy v1 is still accepted unless ``require_v2``.
        """
        allowed_signers = []
        if allow_miner:
            allowed_signers.append(miner_settings.miner_ss58)
        if allow_validator:
            allowed_signers += [validator.hotkey for validator in miner_settings.validators]
        is_v2 = sig_version == SIG_VERSION_V2
        try:
            nonce_ts = _nonce_timestamp(nonce) if nonce else None
        except (ValueError, TypeError):
            nonce_ts = None
        if (
            any(not v for v in [miner, validator, nonce, signature])
            or miner != miner_settings.miner_ss58
            or validator not in allowed_signers
            or nonce_ts is None
            or int(time.time()) - nonce_ts >= 30
            or (require_v2 and not is_v2)
            # A v2 nonce must carry the random suffix (`{ts}.{rand}`) for single-use uniqueness.
            or (is_v2 and "." not in nonce)
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
        # v2 nonces are single-use: consume only AFTER the signature verifies, so an unauthenticated
        # caller cannot burn a legitimate signer's nonce.
        if is_v2 and not _consume_v2_nonce(validator, nonce):
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
    """
    Generate a signed request (for miner requests to validators).

    When ``method`` and ``path`` are supplied, emit a v2 signature binding the HTTP method + path
    (dropping ``purpose``) with a single-use nonce and the ``X-Chutes-Sig-Version: 2`` header;
    otherwise emit the legacy v1 signature.
    """
    use_v2 = path is not None
    nonce = generate_v2_nonce() if use_v2 else str(int(time.time()))
    headers = {
        HOTKEY_HEADER: miner_settings.miner_ss58,
        NONCE_HEADER: nonce,
    }
    payload_string = None
    if payload is not None:
        if isinstance(payload, (list, dict)):
            headers["Content-Type"] = "application/json"
            payload_string = json.dumps(payload)
        else:
            payload_string = payload

    if use_v2:
        body_sha256 = (
            hashlib.sha256(
                payload_string.encode() if isinstance(payload_string, str) else payload_string
            ).hexdigest()
            if payload_string
            else None
        )
        resolved_method = (method or ("POST" if payload_string else "GET")).upper()
        # management => 4-part (miner acting toward a validator); else 3-part (single signer).
        if management:
            signature_string = build_v2_message_mgmt(
                miner_settings.miner_ss58,
                miner_settings.miner_ss58,
                resolved_method,
                path,
                nonce,
                body_sha256,
            )
        else:
            signature_string = f"v2:{miner_settings.miner_ss58}:{resolved_method}:{path}:{nonce}:{body_sha256 or ''}"
        headers[SIG_VERSION_HEADER] = SIG_VERSION_V2
    else:
        if payload is not None:
            signature_string = get_signing_message(
                miner_settings.miner_ss58, nonce, payload_str=payload_string, purpose=None
            )
        else:
            signature_string = get_signing_message(
                miner_settings.miner_ss58, nonce, payload_str=None, purpose=purpose
            )
        if management:
            signature_string = miner_settings.miner_ss58 + ":" + signature_string

    if management:
        headers[MINER_HEADER] = headers.pop(HOTKEY_HEADER)
        headers[VALIDATOR_HEADER] = headers[MINER_HEADER]
    logger.debug(f"Signing message: {signature_string}")
    headers[SIGNATURE_HEADER] = miner_settings.miner_keypair.sign(signature_string.encode()).hex()
    return headers, payload_string
