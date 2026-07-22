import asyncio
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from chutes_miner_cli import l0


def _signed_manifest(private_key, now):
    def artifact(name, digit):
        return {
            "url": f"https://objects.example.com/l0/1/{name}",
            "size": 123,
            "sha256": digit * 64,
        }

    manifest = {
        "schema": "chutes.l0-bootstrap",
        "version": 1,
        "tee_type": "tdx",
        "channel": "stable",
        "generation": 1,
        "key_id": "release-1",
        "key_epoch": 1,
        "l0_version": "1.10.0",
        "kernel": artifact("vmlinuz", "1"),
        "initrd": artifact("initrd.img", "2"),
        "cmdline": artifact("cc-cmdline", "3"),
        "squashfs": artifact("filesystem.squashfs", "4"),
        "validator_ca_sha256": "5" * 64,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
    }
    return {
        "manifest": manifest,
        "signature": base64.b64encode(
            private_key.sign(l0.canonical_json_bytes(manifest))
        ).decode(),
    }


def _registry(private_key, now):
    return {
        "schema": "chutes.l0-publisher-keys",
        "version": 1,
        "keys": [
            {
                "key_id": "release-1",
                "epoch": 1,
                "public_key": base64.b64encode(
                    private_key.public_key().public_bytes(
                        serialization.Encoding.Raw,
                        serialization.PublicFormat.Raw,
                    )
                ).decode(),
                "not_before": (now - timedelta(days=1))
                .isoformat()
                .replace("+00:00", "Z"),
                "not_after": (now + timedelta(days=30))
                .isoformat()
                .replace("+00:00", "Z"),
                "enabled": True,
            }
        ],
    }


def test_manifest_signature_tamper_and_expiry(monkeypatch):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(l0, "_publisher_registry", lambda: _registry(private_key, now))
    signed = _signed_manifest(private_key, now)

    assert (
        l0.verify_bootstrap(signed, tee_type="tdx", channel="stable", now=now)[
            "generation"
        ]
        == 1
    )

    tampered = json.loads(json.dumps(signed))
    tampered["manifest"]["generation"] = 2
    with pytest.raises(l0.L0CliError, match="signature"):
        l0.verify_bootstrap(tampered, tee_type="tdx", channel="stable", now=now)
    with pytest.raises(l0.L0CliError, match="currently valid"):
        l0.verify_bootstrap(
            signed,
            tee_type="tdx",
            channel="stable",
            now=now + timedelta(hours=2),
        )


def test_manifest_rejects_explicit_null_release_id(monkeypatch):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(l0, "_publisher_registry", lambda: _registry(private_key, now))
    signed = _signed_manifest(private_key, now)
    signed["manifest"]["release_id"] = None
    signed["signature"] = base64.b64encode(
        private_key.sign(l0.canonical_json_bytes(signed["manifest"]))
    ).decode()

    with pytest.raises(l0.L0CliError, match="absent or canonical"):
        l0.verify_bootstrap(signed, tee_type="tdx", channel="stable", now=now)


def test_missing_packaged_publisher_registry_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(l0.importlib.resources, "files", lambda _package: tmp_path)
    with pytest.raises(l0.L0CliError, match="release packaging is incomplete"):
        l0._publisher_registry()


def test_rendered_scripts_are_seedless_and_private(tmp_path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    manifest = _signed_manifest(private_key, now)["manifest"]
    script = l0.render_ipxe(
        manifest,
        manifest_signature=base64.b64encode(b"s" * 64).decode(),
        validator_api="https://api.example.com",
        socket_url="wss://ws.example.com",
        validator_ca_url="https://objects.example.com/validator-ca.crt",
        host_id="host-1",
        tee_type="tdx",
        channel="stable",
        data_device="/dev/nvme0n1",
        data_device_id="nvme-test",
        bootif="",
        voucher="voucher.secret",
        enrollment_generation=1,
        rotate_identity=False,
        cmdline="kvm_intel.tdx=1 nohibernate",
    )
    assert "MINER_SEED" not in script
    assert "PCCS_API_KEY" not in script
    assert "PCCS_PASSWORD" not in script
    assert "chutes_data_initialize=true" in script
    assert manifest["squashfs"]["sha256"] in script
    assert "data:application/octet-stream" not in script
    assert "chutes_l0_enrollment_b64=" in script
    assert "chutes_l0_manifest_url=" in script
    encoded = re.search(r"chutes_l0_enrollment_b64=([A-Za-z0-9_-]+)", script).group(1)
    boot_config = json.loads(
        base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    )
    assert boot_config["voucher"] == "voucher.secret"
    assert boot_config["enrollment_generation"] == 1
    assert boot_config["rotate_identity"] is False

    output = tmp_path / "boot.ipxe"
    l0.write_private(output, script.encode())
    assert os.stat(output).st_mode & 0o777 == 0o600


def test_prepare_boot_always_writes_enrollment_and_steady_scripts(
    tmp_path, monkeypatch
):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    signed = _signed_manifest(private_key, now)
    voucher = {
        "schema": "chutes.host-enrollment-voucher",
        "version": 1,
        "voucher": "voucher.secret",
        "claims": {
            "host_id": "host-1",
            "enrollment_generation": 7,
        },
    }

    class FakeSession:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    fetch = AsyncMock(
        return_value=(
            signed["manifest"],
            "kvm_intel.tdx=1 nohibernate",
            signed["signature"],
        )
    )
    request = AsyncMock(return_value=(200, voucher))
    monkeypatch.setattr(l0.aiohttp, "ClientSession", FakeSession)
    monkeypatch.setattr(l0, "_fetch_verified_bootstrap", fetch)
    monkeypatch.setattr(l0, "_api_request", request)

    enrollment = tmp_path / "enrollment.ipxe"
    steady = tmp_path / "steady.ipxe"
    l0.prepare_boot(
        host_id="host-1",
        tee_type="tdx",
        data_device="/dev/nvme0n1",
        data_device_id="nvme-test",
        output=enrollment,
        validator_ca_url="https://objects.example.com/validator-ca.crt",
        socket_url="wss://ws.example.com",
        channel="stable",
        provider=None,
        source=None,
        bootif="",
        rotate_identity=False,
        wait=False,
        wait_timeout_seconds=None,
        steady_output=steady,
        hotkey="/unused",
        validator_api="https://api.example.com",
    )

    assert enrollment.is_file()
    assert steady.is_file()
    assert "voucher.secret" not in steady.read_text()
    assert "chutes_data_initialize=true" in enrollment.read_text()
    assert "chutes_data_initialize=false" in steady.read_text()
    encoded = re.search(
        r"chutes_l0_enrollment_b64=([A-Za-z0-9_-]+)",
        enrollment.read_text(),
    ).group(1)
    enrollment_config = json.loads(
        base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    )
    assert enrollment_config["voucher"] == "voucher.secret"
    mint_document = request.await_args.args[-1]
    assert "provider" not in mint_document
    assert "source" not in mint_document


@pytest.mark.parametrize(
    "status_payload, message",
    [
        (
            {
                "enrollment_generation": 4,
                "provisioning_state": "revoked",
            },
            "revoked",
        ),
        (
            {
                "enrollment_generation": 5,
                "provisioning_state": "ready",
            },
            "stale",
        ),
    ],
)
def test_wait_fails_immediately_for_revoked_or_newer_generation(
    status_payload, message, monkeypatch
):
    monkeypatch.setattr(l0, "_status", AsyncMock(return_value=status_payload))
    with pytest.raises(l0.L0CliError, match=message):
        asyncio.run(
            l0._wait_for_ready(
                object(),
                "https://api.example.com",
                "/unused",
                "host-1",
                expected_generation=4,
                timeout_seconds=30,
            )
        )


def test_wait_uses_finite_monotonic_deadline(monkeypatch):
    monkeypatch.setattr(l0, "_status", AsyncMock(return_value=None))
    monotonic = iter((100.0, 100.0, 101.0))
    monkeypatch.setattr(l0, "monotonic", lambda: next(monotonic))
    sleep = AsyncMock()
    monkeypatch.setattr(l0.asyncio, "sleep", sleep)

    with pytest.raises(l0.L0CliError, match="timed out"):
        asyncio.run(
            l0._wait_for_ready(
                object(),
                "https://api.example.com",
                "/unused",
                "host-1",
                expected_generation=1,
                timeout_seconds=1,
            )
        )
    sleep.assert_not_awaited()


def test_wait_cancels_a_stalled_status_request(monkeypatch):
    async def stalled_status(*_args):
        await asyncio.Event().wait()

    monkeypatch.setattr(l0, "_status", stalled_status)
    with pytest.raises(l0.L0CliError, match="timed out"):
        asyncio.run(
            l0._wait_for_ready(
                object(),
                "https://api.example.com",
                "/unused",
                "host-1",
                expected_generation=1,
                timeout_seconds=0.01,
            )
        )


def test_cli_exception_boundaries_never_render_secret_locals():
    script = r"""
from pathlib import Path
from typer.testing import CliRunner
from chutes_miner_cli import l0
from chutes_miner_cli.cli import app

runner = CliRunner()

def bootstrap_failure(_value):
    secretSeed = "SECRET_SEED_CANARY"
    raise RuntimeError("bootstrap failure")

l0._validate_artifact_url = bootstrap_failure
first = runner.invoke(app, [
    "l0", "prepare-boot",
    "--host-id", "host-1",
    "--tee-type", "tdx",
    "--data-device", "/dev/nvme0n1",
    "--data-device-id", "nvme-test",
    "--output", "/tmp/enrollment.ipxe",
    "--steady-output", "/tmp/steady.ipxe",
    "--validator-ca-url", "https://objects.example.com/validator-ca.crt",
    "--hotkey", "/unused",
])
print(first.output)

def pcs_failure(_self):
    pcs_plaintext = "PCS_PLAINTEXT_CANARY"
    raise RuntimeError("pcs failure")

Path.lstat = pcs_failure
second = runner.invoke(app, [
    "l0", "complete-enrollment",
    "--host-id", "host-1",
    "--pcs-key-file", "/tmp/pcs-key",
    "--hotkey", "/unused",
])
print(second.output)
raise SystemExit(0 if first.exit_code == 1 and second.exit_code == 1 else 1)
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
    )
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert "SECRET_SEED_CANARY" not in combined
    assert "PCS_PLAINTEXT_CANARY" not in combined
    assert "Traceback" not in combined


def test_pcs_envelope_interoperability(monkeypatch):
    recipient_private = X25519PrivateKey.generate()
    recipient_public = recipient_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    status = {
        "owner_hotkey": "owner",
        "host_id": "host-1",
        "x25519_public_key": base64.b64encode(recipient_public).decode(),
        "x25519_fingerprint": hashlib.sha256(recipient_public).hexdigest(),
        "enrollment_generation": 2,
        "key_generation": 3,
    }

    class SigningKey:
        @staticmethod
        def sign(_payload):
            return b"s" * 64

    monkeypatch.setattr(
        l0, "_load_hotkey", lambda _path: ({"ss58Address": "owner"}, SigningKey())
    )
    plaintext = b"pcs-subscription-key"
    envelope = l0._pcs_envelope("/unused", status, plaintext)
    aad = l0.canonical_json_bytes(envelope["aad"])
    peer = X25519PublicKey.from_public_bytes(
        base64.b64decode(envelope["sender_ephemeral_public_key"])
    )
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(aad).digest(),
        info=b"chutes/model-b/pcs-mailbox/v1",
    ).derive(recipient_private.exchange(peer))
    assert (
        ChaCha20Poly1305(key).decrypt(
            base64.b64decode(envelope["nonce"]),
            base64.b64decode(envelope["ciphertext"]),
            aad,
        )
        == plaintext
    )
