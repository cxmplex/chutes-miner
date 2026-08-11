import asyncio
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import ANY, AsyncMock

import pytest
from chutes_miner_cli import l0
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cross_repo_tests import repository_root


def _storage_closure():
    return {
        "schema": "chutes.gpu-l0-storage-closure",
        "version": 1,
        "source_release_id": "cpu-storage-release",
        "image_version": "1.10.0",
        "image_sha256": "6" * 64,
        "kernel_sha256": "7" * 64,
        "initrd_sha256": "8" * 64,
        "cmdline_sha256": "9" * 64,
        "measurement_names": ["storage-baremetal-tdx-1.10.0-2vcpu-8g"],
        "launch_contract": {
            "role": "storage",
            "qemu_binary": "qemu-system-x86_64",
            "qemu_package": "qemu-system-x86",
            "qemu_package_version": "1:10.1.0+ds-5ubuntu2.7",
            "qemu_binary_sha256": "a" * 64,
            "machine_type": "pc-q35-10.1",
            "firmware_filename": "OVMF.inteltdx.fd",
            "firmware_sha256": "b" * 64,
        },
    }


def _signed_manifest(private_key, now, *, compute_type="cpu"):
    def artifact(name, digit):
        return {
            "url": f"https://objects.example.com/l0/1/{name}",
            "size": 123,
            "sha256": digit * 64,
        }

    manifest = {
        "schema": "chutes.l0-bootstrap",
        "version": 2 if compute_type == "gpu" else 1,
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
    if compute_type == "gpu":
        manifest["compute_type"] = "gpu"
        manifest["storage_closure"] = _storage_closure()
        manifest["gpu_profile_id"] = "b200-8gpu"
        manifest["gpu_qemu_sha256s"] = ["6" * 64]
        manifest["gpu_tdvf_sha256s"] = ["7" * 64]
        manifest["gpu_launch_public_key_id"] = "8" * 64
        manifest["gpu_launch_public_key_epoch"] = 1
        manifest["gpu_build_inputs_sha256"] = "9" * 64
    return {
        "manifest": manifest,
        "signature": base64.b64encode(private_key.sign(l0.canonical_json_bytes(manifest))).decode(),
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
                "not_before": (now - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
                "not_after": (now + timedelta(days=30)).isoformat().replace("+00:00", "Z"),
                "enabled": True,
            }
        ],
    }


def test_manifest_signature_tamper_and_expiry(monkeypatch):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(l0, "_publisher_registry", lambda: _registry(private_key, now))
    signed = _signed_manifest(private_key, now)

    assert l0.verify_bootstrap(signed, tee_type="tdx", channel="stable", now=now)["generation"] == 1

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


def test_gpu_v2_manifest_is_strictly_compute_bound(monkeypatch):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(l0, "_publisher_registry", lambda: _registry(private_key, now))
    gpu = _signed_manifest(private_key, now, compute_type="gpu")
    cpu = _signed_manifest(private_key, now)

    verified = l0.verify_bootstrap(
        gpu,
        tee_type="tdx",
        channel="stable",
        compute_type="gpu",
        now=now,
    )
    assert verified["version"] == 2
    assert verified["compute_type"] == "gpu"
    assert verified["gpu_profile_id"] == "b200-8gpu"
    with pytest.raises(l0.L0CliError):
        l0.verify_bootstrap(
            gpu,
            tee_type="tdx",
            channel="stable",
            compute_type="cpu",
            now=now,
        )
    missing_closure = _signed_manifest(private_key, now, compute_type="gpu")
    del missing_closure["manifest"]["storage_closure"]
    missing_closure["signature"] = base64.b64encode(
        private_key.sign(l0.canonical_json_bytes(missing_closure["manifest"]))
    ).decode()
    with pytest.raises(l0.L0CliError, match="fields are not canonical"):
        l0.verify_bootstrap(
            missing_closure,
            tee_type="tdx",
            channel="stable",
            compute_type="gpu",
            now=now,
        )
    with pytest.raises(l0.L0CliError):
        l0.verify_bootstrap(
            cpu,
            tee_type="tdx",
            channel="stable",
            compute_type="gpu",
            now=now,
        )
    gpu["manifest"]["tee_type"] = "sev-snp"
    gpu["signature"] = base64.b64encode(
        private_key.sign(l0.canonical_json_bytes(gpu["manifest"]))
    ).decode()
    with pytest.raises(l0.L0CliError):
        l0.verify_bootstrap(
            gpu,
            tee_type="sev-snp",
            channel="stable",
            compute_type="gpu",
            now=now,
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
        data_device_serial=None,
        gpu_l0_profile=None,
        storage_data_size_gb=None,
        gpu_infra_size_gb=None,
        socket_url="wss://ws.example.com",
        validator_ca_url="https://objects.example.com/validator-ca.crt",
        host_id="host-1",
        tee_type="tdx",
        channel="stable",
        data_device="/dev/nvme0n1",
        data_device_id="nvme-test",
        data_expected_uuid="11111111-2222-3333-4444-555555555555",
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
    assert (
        "chutes_data_expected_uuid=11111111-2222-3333-4444-555555555555"
        in script
    )
    assert manifest["squashfs"]["sha256"] in script
    assert "data:application/octet-stream" not in script
    assert "chutes_l0_enrollment_b64=" in script
    assert "chutes_l0_manifest_url=" in script
    encoded = re.search(r"chutes_l0_enrollment_b64=([A-Za-z0-9_-]+)", script).group(1)
    boot_config = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert boot_config["voucher"] == "voucher.secret"
    assert boot_config["data_expected_uuid"] == "11111111-2222-3333-4444-555555555555"
    assert boot_config["enrollment_generation"] == 1
    assert boot_config["rotate_identity"] is False
    assert boot_config["version"] == 1
    assert "compute_type" not in boot_config

    output = tmp_path / "boot.ipxe"
    l0.write_private(output, script.encode())
    assert os.stat(output).st_mode & 0o777 == 0o600

    gpu_manifest = _signed_manifest(
        private_key,
        now,
        compute_type="gpu",
    )["manifest"]
    gpu_script = l0.render_ipxe(
        gpu_manifest,
        manifest_signature=base64.b64encode(b"s" * 64).decode(),
        validator_api="https://api.example.com",
        socket_url="wss://ws.example.com",
        validator_ca_url="https://objects.example.com/validator-ca.crt",
        host_id="gpu-host-1",
        tee_type="tdx",
        channel="stable",
        data_device="/dev/nvme0n1",
        data_device_id="nvme-gpu",
        data_expected_uuid="11111111-2222-3333-4444-555555555555",
        bootif="",
        voucher="voucher.secret",
        enrollment_generation=1,
        rotate_identity=False,
        cmdline="kvm_intel.tdx=1 nohibernate",
        compute_type="gpu",
        data_device_serial="GPU-SERIAL",
        gpu_l0_profile="b200-8gpu",
        storage_data_size_gb=500,
        gpu_infra_size_gb=100,
    )
    encoded = re.search(
        r"chutes_l0_enrollment_b64=([A-Za-z0-9_-]+)",
        gpu_script,
    ).group(1)
    gpu_config = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert gpu_config["version"] == 2
    assert gpu_config["compute_type"] == "gpu"
    assert gpu_config["storage_enabled"] is True
    assert gpu_config["data_device_serial"] == "GPU-SERIAL"
    assert gpu_config["gpu_l0_profile"] == "b200-8gpu"
    assert gpu_config["storage_data_size_gb"] == 500
    assert gpu_config["gpu_infra_size_gb"] == 100
    assert "chutes_compute_type=gpu" in gpu_script
    assert "chutes_data_device_serial=GPU-SERIAL" in gpu_script
    with pytest.raises(l0.L0CliError, match="publisher-signed GPU L0 profile"):
        l0.render_ipxe(
            gpu_manifest,
            manifest_signature=base64.b64encode(b"s" * 64).decode(),
            validator_api="https://api.example.com",
            socket_url="wss://ws.example.com",
            validator_ca_url="https://objects.example.com/validator-ca.crt",
            host_id="gpu-host-1",
            tee_type="tdx",
            channel="stable",
            data_device="/dev/nvme0n1",
            data_device_id="nvme-gpu",
            data_expected_uuid="11111111-2222-3333-4444-555555555555",
            bootif="",
            voucher="voucher.secret",
            enrollment_generation=1,
            rotate_identity=False,
            cmdline="kvm_intel.tdx=1 nohibernate",
            compute_type="gpu",
            data_device_serial="GPU-SERIAL",
            gpu_l0_profile="b200-xeon6-8gpu-qemu10-2-numa",
            storage_data_size_gb=500,
            gpu_infra_size_gb=100,
        )


def test_rotation_voucher_never_authorizes_data_initialization():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    manifest = _signed_manifest(Ed25519PrivateKey.generate(), now)["manifest"]
    expected_uuid = "9c3bb112-648e-4111-a24c-046bb5d0a78f"

    script = l0.render_ipxe(
        manifest,
        manifest_signature=base64.b64encode(b"s" * 64).decode(),
        validator_api="https://api.example.com",
        socket_url="wss://ws.example.com",
        validator_ca_url="https://objects.example.com/validator-ca.crt",
        host_id="l0-intel-tdx-ovh-vin1",
        tee_type="tdx",
        channel="canary",
        data_device="/dev/nvme0n1",
        data_device_id="nvme-eui.000000000000000100a07524492f9248",
        data_expected_uuid=expected_uuid,
        bootif="",
        voucher="one-use-voucher",
        enrollment_generation=3,
        rotate_identity=True,
        cmdline="kvm_intel.tdx=1 nohibernate",
    )

    assert "chutes_data_initialize=false" in script
    assert f"chutes_data_expected_uuid={expected_uuid}" in script
    encoded = re.search(r"chutes_l0_enrollment_b64=([A-Za-z0-9_-]+)", script).group(1)
    config = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert config["voucher"] == "one-use-voucher"
    assert config["rotate_identity"] is True
    assert config["initialize"] is False
    assert config["data_expected_uuid"] == expected_uuid


def test_rotation_boot_bytes_are_accepted_exactly_by_sek8s_consumer(tmp_path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    manifest = _signed_manifest(Ed25519PrivateKey.generate(), now)["manifest"]
    expected_uuid = "9c3bb112-648e-4111-a24c-046bb5d0a78f"
    script = l0.render_ipxe(
        manifest,
        manifest_signature=base64.b64encode(b"s" * 64).decode(),
        validator_api="https://api.example.com",
        socket_url="wss://ws.example.com",
        validator_ca_url="https://objects.example.com/validator-ca.crt",
        host_id="l0-intel-tdx-ovh-vin1",
        tee_type="tdx",
        channel="canary",
        data_device="/dev/nvme0n1",
        data_device_id="nvme-eui.000000000000000100a07524492f9248",
        data_expected_uuid=expected_uuid,
        bootif="",
        voucher="one-use-voucher",
        enrollment_generation=3,
        rotate_identity=True,
        cmdline="kvm_intel.tdx=1 nohibernate",
    )
    encoded = re.search(r"chutes_l0_enrollment_b64=([A-Za-z0-9_-]+)", script).group(1)
    sek8s_root = repository_root("sek8s", start=Path(__file__))
    firstboot = (
        sek8s_root / "host-tools/scripts/l0/chutes-l0-firstboot.sh"
    ).read_text(encoding="utf-8")
    marker = 'BOOT_SECRET_ID_STAGING="$BOOT_SECRET_ID_STAGING" python3 - <<\'PY\'\n'
    consumer = firstboot.split(marker, 1)[1].split("\nPY\n", 1)[0]

    def consume(value):
        config_path = tmp_path / "l0.conf.boot-secret"
        boot_id_path = tmp_path / "l0.conf.boot-secret.id"
        config_path.unlink(missing_ok=True)
        boot_id_path.unlink(missing_ok=True)
        environment = os.environ.copy()
        environment.update(
            {
                "BOOT_CONFIG_B64": value,
                "BOOT_SECRET_STAGING": str(config_path),
                "BOOT_SECRET_ID_STAGING": str(boot_id_path),
            }
        )
        return subprocess.run(
            [sys.executable, "-c", consumer],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        ), config_path

    accepted, config_path = consume(encoded)
    assert accepted.returncode == 0, accepted.stderr
    assert f"CHUTES_DATA_EXPECTED_UUID={expected_uuid}\n" in config_path.read_text()
    assert "CHUTES_DATA_INITIALIZE=false\n" in config_path.read_text()

    document = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    document["initialize"] = True
    altered = base64.urlsafe_b64encode(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).decode("ascii").rstrip("=")
    rejected, _config_path = consume(altered)
    assert rejected.returncode != 0
    assert "schema or enrollment mode is invalid" in rejected.stderr


@pytest.mark.parametrize(
    "value",
    ["", "NOT-A-UUID", "9C3BB112-648E-4111-A24C-046BB5D0A78F"],
)
def test_renderer_rejects_missing_or_noncanonical_data_uuid(value):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    manifest = _signed_manifest(Ed25519PrivateKey.generate(), now)["manifest"]
    with pytest.raises(l0.L0CliError, match="UUID"):
        l0.render_ipxe(
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
            data_expected_uuid=value,
            bootif="",
            voucher="voucher.secret",
            enrollment_generation=1,
            rotate_identity=False,
            cmdline="kvm_intel.tdx=1 nohibernate",
        )


def test_prepare_boot_always_writes_enrollment_and_steady_scripts(tmp_path, monkeypatch):
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
        compute_type="cpu",
        data_device="/dev/nvme0n1",
        data_device_id="nvme-test",
        data_expected_uuid="11111111-2222-3333-4444-555555555555",
        data_device_serial=None,
        gpu_l0_profile=None,
        storage_data_size_gb=None,
        gpu_infra_size_gb=None,
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
    assert (
        "chutes_data_expected_uuid=11111111-2222-3333-4444-555555555555"
        in enrollment.read_text()
    )
    assert (
        "chutes_data_expected_uuid=11111111-2222-3333-4444-555555555555"
        in steady.read_text()
    )
    encoded = re.search(
        r"chutes_l0_enrollment_b64=([A-Za-z0-9_-]+)",
        enrollment.read_text(),
    ).group(1)
    enrollment_config = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert enrollment_config["voucher"] == "voucher.secret"
    mint_document = request.await_args.args[-1]
    assert "provider" not in mint_document
    assert "source" not in mint_document
    assert mint_document["version"] == 1
    assert "compute_type" not in mint_document


def test_prepare_boot_uses_gpu_v2_manifest_and_enrollment(tmp_path, monkeypatch):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    signed = _signed_manifest(private_key, now, compute_type="gpu")
    voucher = {
        "schema": "chutes.host-enrollment-voucher",
        "version": 2,
        "voucher": "voucher.secret",
        "claims": {
            "host_id": "gpu-host-1",
            "tee_type": "tdx",
            "compute_type": "gpu",
            "storage_enabled": True,
            "enrollment_generation": 3,
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
    enrollment = tmp_path / "gpu-enrollment.ipxe"
    steady = tmp_path / "gpu-steady.ipxe"

    l0.prepare_boot(
        host_id="gpu-host-1",
        tee_type="tdx",
        compute_type="gpu",
        data_device="/dev/nvme0n1",
        data_device_id="nvme-gpu",
        data_expected_uuid="11111111-2222-3333-4444-555555555555",
        data_device_serial="GPU-SERIAL",
        gpu_l0_profile="b200-8gpu",
        storage_data_size_gb=500,
        gpu_infra_size_gb=100,
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

    fetch.assert_awaited_once_with(
        ANY,
        "https://api.example.com",
        "/unused",
        "tdx",
        "stable",
        "gpu",
        "https://objects.example.com/validator-ca.crt",
    )
    mint_document = request.await_args.args[-1]
    assert mint_document["version"] == 2
    assert mint_document["compute_type"] == "gpu"
    assert mint_document["storage_enabled"] is True
    encoded = re.search(
        r"chutes_l0_enrollment_b64=([A-Za-z0-9_-]+)",
        enrollment.read_text(),
    ).group(1)
    boot_config = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert boot_config["version"] == 2
    assert boot_config["compute_type"] == "gpu"
    assert boot_config["storage_enabled"] is True


def test_gpu_boot_renderer_rejects_missing_public_disk_contract():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    manifest = _signed_manifest(private_key, now, compute_type="gpu")["manifest"]
    with pytest.raises(l0.L0CliError, match="requires serial"):
        l0.render_ipxe(
            manifest,
            manifest_signature=base64.b64encode(b"s" * 64).decode(),
            validator_api="https://api.example.com",
            socket_url="wss://ws.example.com",
            validator_ca_url="https://objects.example.com/validator-ca.crt",
            host_id="gpu-host",
            tee_type="tdx",
            channel="stable",
            data_device="/dev/nvme0n1",
            data_device_id="nvme-gpu",
            data_expected_uuid="11111111-2222-3333-4444-555555555555",
            bootif="",
            voucher="voucher.secret",
            enrollment_generation=1,
            rotate_identity=False,
            cmdline="kvm_intel.tdx=1 nohibernate",
            compute_type="gpu",
        )


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
    "--data-expected-uuid", "11111111-2222-3333-4444-555555555555",
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

    monkeypatch.setattr(l0, "_load_hotkey", lambda _path: ({"ss58Address": "owner"}, SigningKey()))
    plaintext = b"pcs-subscription-key"
    envelope = l0._pcs_envelope("/unused", status, plaintext)
    assert envelope["version"] == 1
    assert "compute_type" not in envelope["aad"]
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

    gpu_status = {
        **status,
        "version": 2,
        "tee_type": "tdx",
        "compute_type": "gpu",
        "storage_enabled": True,
    }
    gpu_envelope = l0._pcs_envelope("/unused", gpu_status, plaintext)
    assert gpu_envelope["version"] == 2
    assert gpu_envelope["aad"]["compute_type"] == "gpu"
    gpu_aad = l0.canonical_json_bytes(gpu_envelope["aad"])
    gpu_peer = X25519PublicKey.from_public_bytes(
        base64.b64decode(gpu_envelope["sender_ephemeral_public_key"])
    )
    gpu_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(gpu_aad).digest(),
        info=b"chutes/model-b/pcs-mailbox/v2",
    ).derive(recipient_private.exchange(gpu_peer))
    assert (
        ChaCha20Poly1305(gpu_key).decrypt(
            base64.b64decode(gpu_envelope["nonce"]),
            base64.b64decode(gpu_envelope["ciphertext"]),
            gpu_aad,
        )
        == plaintext
    )


def test_gpu_start_uses_validator_owned_server_and_process_identity(monkeypatch, capsys):
    claims = {
        "schema": "chutes.gpu-launch-reservation",
        "version": 1,
        "management_mode": "miner",
        "host_id": "gpu-host",
        "server_id": "gpu-miner-validator-owned",
        "reservation_id": "reservation-1",
        "process_incarnation": "process-validator-owned",
        "allocation_group_id": "group-1",
        "allocation_group_generation": 3,
    }
    request = AsyncMock(
        return_value=(
            200,
            {
                "schema": "chutes.gpu-launch-reservation-result",
                "version": 1,
                "token": "redacted-launch-capability",
                "claims": claims,
                "claims_sha256": "a" * 64,
            },
        )
    )
    monkeypatch.setattr(l0, "_api_request", request)

    l0.gpu_start(
        host_id="gpu-host",
        gpu_identifier="b200",
        gpu_count=8,
        minimum_vram_mib=196608,
        miner_hourly_cost=12.5,
        legacy_vm_name=None,
        hotkey="/hotkey",
        validator_api="https://validator.example",
    )

    body = request.await_args.args[5]
    assert set(body) == {
        "schema",
        "version",
        "gpu_identifier",
        "gpu_count",
        "minimum_vram_mib",
        "miner_hourly_cost",
    }
    assert body["miner_hourly_cost"] == 12.5
    assert "server_id" not in body
    assert "process_incarnation" not in body
    output = json.loads(capsys.readouterr().out)
    assert output["server_id"] == "gpu-miner-validator-owned"
    assert "redacted-launch-capability" not in output.values()


def test_gpu_stop_requests_whole_fabric_teardown_without_seed(monkeypatch, capsys):
    request = AsyncMock(
        return_value=(
            200,
            {
                "schema": "chutes.gpu-miner-stop-result",
                "version": 1,
                "server_id": "gpu-miner-validator-owned",
                "reservation_id": "reservation-1",
                "status": "teardown_requested",
            },
        )
    )
    monkeypatch.setattr(l0, "_api_request", request)

    l0.gpu_stop(
        server_id="gpu-miner-validator-owned",
        reason="operator stop",
        hotkey="/hotkey",
        validator_api="https://validator.example",
    )

    body = request.await_args.args[5]
    assert body == {
        "schema": "chutes.gpu-miner-stop-request",
        "version": 1,
        "reason": "operator stop",
    }
    assert "seed" not in json.dumps(body).lower()
    assert json.loads(capsys.readouterr().out)["status"] == "teardown_requested"
