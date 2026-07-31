#!/usr/bin/env python

import json
import hashlib
import secrets
import time
from substrateinterface import Keypair
from typing import Dict, Any
from chutes_miner_cli.constants import (
    VALIDATOR_HEADER,
    HOTKEY_HEADER,
    MINER_HEADER,
    NONCE_HEADER,
    SIGNATURE_HEADER,
    SIG_VERSION_HEADER,
    SIG_VERSION_V2,
)


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
    hotkey: str,
    payload: Dict[str, Any] | str | None = None,
    purpose: str = None,
    remote: bool = False,
    management: bool = False,
    method: str | None = None,
    path: str | None = None,
):
    """
    Generate a signed request (for miner requests to validators).
    """
    if (method is None) != (path is None):
        raise ValueError("method and path must be supplied together")
    use_management_v2 = method is not None
    if use_management_v2 and (remote or not management):
        raise ValueError("V2 method/path signing is only supported for management requests")

    hotkey_data = json.loads(open(hotkey).read())
    nonce = (
        f"{int(time.time())}.{secrets.token_hex(8)}" if use_management_v2 else str(int(time.time()))
    )
    headers = {
        MINER_HEADER: hotkey_data["ss58Address"],
        NONCE_HEADER: nonce,
    }
    if remote:
        headers[HOTKEY_HEADER] = headers.pop(MINER_HEADER)
    elif management:
        headers[VALIDATOR_HEADER] = headers[MINER_HEADER]
    payload_string = None
    if payload is not None:
        if isinstance(payload, (list, dict)):
            headers["Content-Type"] = "application/json"
            payload_string = json.dumps(payload)
        else:
            payload_string = payload

    if use_management_v2:
        payload_bytes = (
            payload_string.encode() if isinstance(payload_string, str) else payload_string
        )
        body_sha256 = hashlib.sha256(payload_bytes).hexdigest() if payload_bytes is not None else ""
        signature_string = (
            f"v2:{hotkey_data['ss58Address']}:{hotkey_data['ss58Address']}:"
            f"{method.upper()}:{path}:{nonce}:{body_sha256}"
        )
        headers[SIG_VERSION_HEADER] = SIG_VERSION_V2
    elif payload is not None:
        signature_string = get_signing_message(
            hotkey_data["ss58Address"],
            nonce,
            payload_str=payload_string,
            purpose=None,
        )
    else:
        signature_string = get_signing_message(
            hotkey_data["ss58Address"], nonce, payload_str=None, purpose=purpose
        )

    if not remote and not use_management_v2:
        signature_string = hotkey_data["ss58Address"] + ":" + signature_string
    if not remote:
        headers[MINER_HEADER] = hotkey_data["ss58Address"]
        headers[VALIDATOR_HEADER] = headers[MINER_HEADER]
    keypair = Keypair.create_from_seed(hotkey_data["secretSeed"])
    headers[SIGNATURE_HEADER] = keypair.sign(signature_string.encode()).hex()
    return headers, payload_string


def sign_management_request(
    hotkey: str,
    *,
    method: str,
    path: str,
    payload: Dict[str, Any] | str | None = None,
):
    """Sign one miner-management request with the replay-resistant V2 contract."""
    return sign_request(
        hotkey,
        payload=payload,
        management=True,
        method=method,
        path=path,
    )
