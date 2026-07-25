"""Seedless Model-B L0 enrollment and PCS provisioning commands."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.resources
import json
import math
import os
import re
import secrets
import stat
import subprocess  # nosec B404
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import monotonic
from typing import TYPE_CHECKING, Any, Dict, Optional
from urllib.parse import quote, urlencode, urlsplit

import aiohttp
import typer
from chutes_miner_cli.constants import (
    HOTKEY_ENVVAR,
    HOTKEY_HEADER,
    NONCE_HEADER,
    SIGNATURE_HEADER,
    VALIDATOR_API_ENVVAR,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from chutes_miner_cli.legacy_cutover import (
    BUNDLE_PATH as LEGACY_CUTOVER_BUNDLE_PATH,
    K3S_ADMIN_KUBECONFIG,
    LegacyCutoverError,
    recover_legacy_cutover,
    rebind_closure_authorization,
    run as run_legacy_cutover,
)

if TYPE_CHECKING:
    from substrateinterface import Keypair

l0_app = typer.Typer(
    name="l0",
    help="Prepare and enroll seedless confidential-compute L0 hosts.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)

SIG_VERSION_HEADER = "X-Chutes-Sig-Version"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 16 * 1024**3
DEFAULT_WAIT_TIMEOUT_SECONDS = 1800
POLL_INTERVAL_SECONDS = 5
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CHANNEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_GPU_PROFILE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_SHELL_META = frozenset("$`'\";\\|&<>(){}")
_REJECTED_SUFFIXES = (
    ".home.arpa",
    ".internal",
    ".invalid",
    ".lan",
    ".local",
    ".localhost",
    ".test",
)


class L0CliError(RuntimeError):
    pass


def canonical_json_bytes(value: Dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _load_hotkey(path: str) -> tuple[Dict[str, Any], Keypair]:
    from substrateinterface import Keypair

    try:
        metadata = os.lstat(path)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_mode & 0o077
        ):
            raise L0CliError("hotkey file must be one private non-symlink regular file")
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        address = document["ss58Address"]
        seed = document["secretSeed"]
        keypair = Keypair.create_from_seed(seed)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, L0CliError):
            raise
        raise L0CliError("could not load the local hotkey JSON") from exc
    if keypair.ss58_address != address:
        raise L0CliError("hotkey seed does not match ss58Address")
    return {"ss58Address": address}, keypair


def _signed_headers(
    hotkey_path: str,
    method: str,
    target: str,
    body: bytes,
) -> Dict[str, str]:
    public, keypair = _load_hotkey(hotkey_path)
    nonce = f"{int(time.time())}.{secrets.token_hex(16)}"
    message = (
        f"v2:{public['ss58Address']}:{method.upper()}:{target}:{nonce}:"
        f"{hashlib.sha256(body).hexdigest() if body else ''}"
    )
    return {
        HOTKEY_HEADER: public["ss58Address"],
        NONCE_HEADER: nonce,
        SIGNATURE_HEADER: keypair.sign(message.encode("ascii")).hex(),
        SIG_VERSION_HEADER: "2",
    }


async def _api_request(
    session: aiohttp.ClientSession,
    validator_api: str,
    hotkey_path: str,
    method: str,
    target: str,
    document: Optional[Dict[str, Any]] = None,
) -> tuple[int, Any]:
    body = b"" if document is None else canonical_json_bytes(document)
    headers = _signed_headers(hotkey_path, method, target, body)
    if document is not None:
        headers["Content-Type"] = "application/json"
    async with session.request(
        method,
        f"{validator_api.rstrip('/')}{target}",
        data=body,
        headers=headers,
        allow_redirects=False,
    ) as response:
        payload = await response.read()
        if not payload:
            return response.status, None
        try:
            return response.status, json.loads(payload)
        except json.JSONDecodeError:
            return response.status, payload.decode("utf-8", "replace")


def _require_success(status_code: int, payload: Any, operation: str) -> Any:
    if 200 <= status_code < 300:
        return payload
    raise L0CliError(f"{operation} failed with HTTP status {status_code}")


def _validate_artifact_url(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise L0CliError("artifact URL must be a non-empty string")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
        raise L0CliError("artifact URL must contain visible ASCII only")
    if any(character in _SHELL_META for character in value):
        raise L0CliError("artifact URL contains a forbidden metacharacter")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise L0CliError("artifact URL has an invalid host or port") from exc
    if parsed.scheme not in {"http", "https"} or not value.startswith(f"{parsed.scheme}://"):
        raise L0CliError("artifact URL must use canonical HTTP(S)")
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
        or parsed.query
        or parsed.fragment
    ):
        raise L0CliError("artifact URL has forbidden authority/query/fragment data")
    host = parsed.hostname
    if host.endswith("."):
        raise L0CliError("artifact URL host has a trailing dot")
    import ipaddress

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if (
            ":" in host
            or len(host) > 253
            or len(labels) < 2
            or any(not _DNS_LABEL.fullmatch(label) for label in labels)
            or labels[-1].isdigit()
            or host.lower() == "localhost"
            or host.lower().endswith(_REJECTED_SUFFIXES)
        ):
            raise L0CliError("artifact URL host is not a public canonical DNS name")
        authority = host
    else:
        if not address.is_global:
            raise L0CliError("artifact URL IP must be globally routable")
        authority = f"[{host}]" if address.version == 6 else host
    allowed_port = 80 if parsed.scheme == "http" else 443
    if port is not None and port != allowed_port:
        raise L0CliError("artifact URL uses a non-standard port")
    expected_authority = authority if port is None else f"{authority}:{port}"
    if parsed.netloc.lower() != expected_authority.lower():
        raise L0CliError("artifact URL authority is non-canonical")
    if (
        not parsed.path.startswith("/")
        or not re.fullmatch(r"/[A-Za-z0-9._~/-]+", parsed.path)
        or any(not segment or segment in {".", ".."} for segment in parsed.path.split("/")[1:])
    ):
        raise L0CliError("artifact URL path is invalid")
    if parsed.scheme == "http" and host.lower() != "storage.googleapis.com":
        raise L0CliError("plain HTTP is allowed only for storage.googleapis.com")
    return value


def _publisher_registry() -> Dict[str, Any]:
    resource = importlib.resources.files("chutes_miner_cli") / "data" / "l0-publisher-keys.json"
    try:
        payload = resource.read_bytes()
    except FileNotFoundError as exc:
        raise L0CliError(
            "this CLI package has no L0 publisher trust registry; release packaging is incomplete"
        ) from exc
    if not payload or len(payload) > MAX_MANIFEST_BYTES:
        raise L0CliError("packaged L0 publisher registry has an invalid size")
    try:
        registry = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise L0CliError("packaged L0 publisher registry is invalid") from exc
    if (
        not isinstance(registry, dict)
        or set(registry) != {"schema", "version", "keys"}
        or registry["schema"] != "chutes.l0-publisher-keys"
        or registry["version"] != 1
        or not isinstance(registry["keys"], list)
        or not registry["keys"]
    ):
        raise L0CliError("packaged L0 publisher registry has the wrong schema")
    return registry


def _validate_gpu_storage_closure(value: Any) -> Dict[str, Any]:
    closure_keys = {
        "schema",
        "version",
        "source_release_id",
        "image_version",
        "image_sha256",
        "kernel_sha256",
        "initrd_sha256",
        "cmdline_sha256",
        "measurement_names",
        "launch_contract",
    }
    launch_keys = {
        "role",
        "qemu_binary",
        "qemu_package",
        "qemu_package_version",
        "qemu_binary_sha256",
        "machine_type",
        "firmware_filename",
        "firmware_sha256",
    }
    if (
        not isinstance(value, dict)
        or set(value) != closure_keys
        or value.get("schema") != "chutes.gpu-l0-storage-closure"
        or value.get("version") != 1
        or not isinstance(value.get("source_release_id"), str)
        or not _ID.fullmatch(value["source_release_id"])
        or not isinstance(value.get("image_version"), str)
        or not value["image_version"]
        or not isinstance(value.get("measurement_names"), list)
        or not value["measurement_names"]
        or len(value["measurement_names"]) != len(set(value["measurement_names"]))
        or any(
            not isinstance(name, str) or not _ID.fullmatch(name)
            for name in value["measurement_names"]
        )
        or not isinstance(value.get("launch_contract"), dict)
        or set(value["launch_contract"]) != launch_keys
        or value["launch_contract"].get("role") != "storage"
        or value["launch_contract"].get("qemu_binary") != "qemu-system-x86_64"
        or value["launch_contract"].get("qemu_package") != "qemu-system-x86"
        or value["launch_contract"].get("firmware_filename") != "OVMF.inteltdx.fd"
        or not re.fullmatch(
            r"pc-q35-[0-9]+\.[0-9]+",
            str(value["launch_contract"].get("machine_type") or ""),
        )
    ):
        raise L0CliError("GPU L0 storage closure fields are not canonical")
    for field in ("image_sha256", "kernel_sha256", "initrd_sha256", "cmdline_sha256"):
        if not isinstance(value.get(field), str) or not _HEX64.fullmatch(value[field]):
            raise L0CliError("GPU L0 storage closure has an invalid digest")
    for field in ("qemu_binary_sha256", "firmware_sha256"):
        digest = value["launch_contract"].get(field)
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            raise L0CliError("GPU L0 storage launch contract has an invalid digest")
    return value


def verify_bootstrap(
    signed: Any,
    *,
    tee_type: str,
    channel: str,
    compute_type: str = "cpu",
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    if (
        not isinstance(signed, dict)
        or set(signed) != {"manifest", "signature"}
        or not isinstance(signed["manifest"], dict)
        or not isinstance(signed["signature"], str)
    ):
        raise L0CliError("validator returned an invalid signed bootstrap envelope")
    manifest = signed["manifest"]
    required = {
        "schema",
        "version",
        "tee_type",
        "channel",
        "generation",
        "key_id",
        "key_epoch",
        "l0_version",
        "kernel",
        "initrd",
        "cmdline",
        "squashfs",
        "validator_ca_sha256",
        "issued_at",
        "expires_at",
    }
    if compute_type == "gpu":
        required.update(
            {
                "compute_type",
                "storage_closure",
                "gpu_profile_id",
                "gpu_qemu_sha256s",
                "gpu_tdvf_sha256s",
                "gpu_launch_public_key_id",
                "gpu_launch_public_key_epoch",
                "gpu_build_inputs_sha256",
            }
        )
    manifest_fields = set(manifest)
    if manifest_fields != required and manifest_fields != required | {"release_id"}:
        raise L0CliError("L0 bootstrap manifest fields are not canonical")
    if "release_id" in manifest and (
        not isinstance(manifest["release_id"], str) or not _ID.fullmatch(manifest["release_id"])
    ):
        raise L0CliError("L0 bootstrap release_id must be absent or canonical")
    if (
        manifest.get("schema") != "chutes.l0-bootstrap"
        or (compute_type == "cpu" and (manifest.get("version") != 1 or "compute_type" in manifest))
        or (
            compute_type == "gpu"
            and (
                manifest.get("version") != 2
                or manifest.get("compute_type") != "gpu"
                or manifest.get("tee_type") != "tdx"
            )
        )
        or compute_type not in {"cpu", "gpu"}
        or manifest.get("tee_type") != tee_type
        or manifest.get("channel") != channel
        or not isinstance(manifest.get("generation"), int)
        or isinstance(manifest.get("generation"), bool)
        or manifest["generation"] < 1
        or not isinstance(manifest.get("key_epoch"), int)
        or isinstance(manifest.get("key_epoch"), bool)
        or manifest["key_epoch"] < 1
        or not isinstance(manifest.get("key_id"), str)
        or not _ID.fullmatch(manifest["key_id"])
        or not isinstance(manifest.get("l0_version"), str)
    ):
        raise L0CliError("L0 bootstrap manifest targeting/version fields are invalid")
    if compute_type == "gpu":
        _validate_gpu_storage_closure(manifest["storage_closure"])
        if (
            not isinstance(manifest.get("gpu_profile_id"), str)
            or not _GPU_PROFILE.fullmatch(manifest["gpu_profile_id"])
            or not isinstance(manifest.get("gpu_qemu_sha256s"), list)
            or not manifest["gpu_qemu_sha256s"]
            or manifest["gpu_qemu_sha256s"] != sorted(set(manifest["gpu_qemu_sha256s"]))
            or any(
                not isinstance(value, str) or not _HEX64.fullmatch(value)
                for value in manifest["gpu_qemu_sha256s"]
            )
            or not isinstance(manifest.get("gpu_tdvf_sha256s"), list)
            or not manifest["gpu_tdvf_sha256s"]
            or manifest["gpu_tdvf_sha256s"] != sorted(set(manifest["gpu_tdvf_sha256s"]))
            or any(
                not isinstance(value, str) or not _HEX64.fullmatch(value)
                for value in manifest["gpu_tdvf_sha256s"]
            )
            or not isinstance(manifest.get("gpu_launch_public_key_id"), str)
            or not _HEX64.fullmatch(manifest["gpu_launch_public_key_id"])
            or not isinstance(manifest.get("gpu_launch_public_key_epoch"), int)
            or isinstance(manifest["gpu_launch_public_key_epoch"], bool)
            or manifest["gpu_launch_public_key_epoch"] < 1
            or not isinstance(manifest.get("gpu_build_inputs_sha256"), str)
            or not _HEX64.fullmatch(manifest["gpu_build_inputs_sha256"])
        ):
            raise L0CliError("GPU L0 launch closure fields are not canonical")
    for name in ("kernel", "initrd", "cmdline", "squashfs"):
        artifact = manifest[name]
        if not isinstance(artifact, dict) or set(artifact) != {
            "url",
            "size",
            "sha256",
        }:
            raise L0CliError(f"{name} artifact fields are invalid")
        artifact["url"] = _validate_artifact_url(artifact["url"])
        if (
            not isinstance(artifact["size"], int)
            or isinstance(artifact["size"], bool)
            or not 1 <= artifact["size"] <= MAX_ARTIFACT_BYTES
            or not isinstance(artifact["sha256"], str)
            or not _HEX64.fullmatch(artifact["sha256"])
        ):
            raise L0CliError(f"{name} artifact size or digest is invalid")
    if len({manifest[name]["url"] for name in ("kernel", "initrd", "cmdline", "squashfs")}) != 4:
        raise L0CliError("L0 artifact URLs must be distinct")
    if (
        len(
            {
                manifest[name]["url"].rsplit("/", 1)[0]
                for name in ("kernel", "initrd", "cmdline", "squashfs")
            }
        )
        != 1
    ):
        raise L0CliError("L0 artifacts must share one immutable versioned origin")
    if not isinstance(manifest["validator_ca_sha256"], str) or not _HEX64.fullmatch(
        manifest["validator_ca_sha256"]
    ):
        raise L0CliError("validator CA digest is invalid")
    try:
        issued_at = datetime.fromisoformat(manifest["issued_at"].replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(manifest["expires_at"].replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise L0CliError("L0 manifest timestamps are invalid") from exc
    current = now or datetime.now(timezone.utc)
    if (
        issued_at > current + timedelta(minutes=5)
        or expires_at <= current
        or expires_at <= issued_at
        or expires_at - issued_at > timedelta(days=7)
    ):
        raise L0CliError("L0 manifest is not currently valid")

    registry = _publisher_registry()
    keys = [
        key
        for key in registry["keys"]
        if isinstance(key, dict)
        and key.get("key_id") == manifest["key_id"]
        and key.get("epoch") == manifest["key_epoch"]
    ]
    if len(keys) != 1:
        raise L0CliError("L0 manifest references an unknown publisher key")
    key = keys[0]
    if set(key) != {
        "key_id",
        "epoch",
        "public_key",
        "not_before",
        "not_after",
        "enabled",
    }:
        raise L0CliError("packaged publisher key fields are invalid")
    try:
        not_before = datetime.fromisoformat(key["not_before"].replace("Z", "+00:00"))
        not_after = datetime.fromisoformat(key["not_after"].replace("Z", "+00:00"))
        public = base64.b64decode(key["public_key"], validate=True)
        signature = base64.b64decode(signed["signature"], validate=True)
        if (
            key["enabled"] is not True
            or len(public) != 32
            or len(signature) != 64
            or not (not_before <= issued_at < not_after)
        ):
            raise ValueError("inactive or malformed publisher key")
        Ed25519PublicKey.from_public_bytes(public).verify(signature, canonical_json_bytes(manifest))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise L0CliError("L0 bootstrap publisher signature is invalid") from exc
    return manifest


async def verify_remote_artifact(
    session: aiohttp.ClientSession,
    artifact: Dict[str, Any],
    *,
    capture: bool = False,
) -> bytes:
    digest = hashlib.sha256()
    total = 0
    captured = bytearray()
    async with session.get(artifact["url"], allow_redirects=False) as response:
        if response.status != 200:
            raise L0CliError(f"artifact fetch failed ({response.status}): {artifact['url']}")
        content_length = response.headers.get("Content-Length")
        if content_length is not None and int(content_length) != artifact["size"]:
            raise L0CliError("artifact Content-Length does not match signed size")
        async for chunk in response.content.iter_chunked(1024 * 1024):
            total += len(chunk)
            if total > artifact["size"]:
                raise L0CliError("artifact exceeds its signed size")
            digest.update(chunk)
            if capture:
                if total > 64 * 1024:
                    raise L0CliError("captured text artifact exceeds 64KiB")
                captured.extend(chunk)
    if total != artifact["size"] or digest.hexdigest() != artifact["sha256"]:
        raise L0CliError("artifact bytes do not match signed size and digest")
    return bytes(captured)


def render_ipxe(
    manifest: Dict[str, Any],
    *,
    manifest_signature: str,
    validator_api: str,
    socket_url: str,
    validator_ca_url: str,
    host_id: str,
    tee_type: str,
    channel: str,
    data_device: str,
    data_device_id: str,
    bootif: str,
    voucher: Optional[str],
    enrollment_generation: int,
    rotate_identity: bool,
    cmdline: str,
    compute_type: str = "cpu",
    data_device_serial: Optional[str] = None,
    gpu_l0_profile: Optional[str] = None,
    storage_data_size_gb: Optional[int] = None,
    gpu_infra_size_gb: Optional[int] = None,
) -> str:
    if any(character in cmdline for character in "\r\n\x00"):
        raise L0CliError("signed L0 command line contains forbidden characters")
    if not isinstance(manifest_signature, str) or len(manifest_signature) != 88:
        raise L0CliError("manifest signature is invalid")
    config_document = {
        "schema": "chutes.l0-boot-config",
        "version": 1,
        "boot_id": secrets.token_hex(32),
        "validator_api": validator_api.rstrip("/"),
        "socket_url": socket_url.rstrip("/"),
        "host_id": host_id,
        "tee_type": tee_type,
        "channel": channel,
        "data_device": data_device,
        "data_device_id": data_device_id,
        "initialize": bool(voucher),
        "voucher": voucher,
        "enrollment_generation": enrollment_generation,
        "rotate_identity": rotate_identity,
    }
    if compute_type == "gpu":
        if tee_type != "tdx" or manifest.get("version") != 2:
            raise L0CliError("GPU boot rendering requires a verified GPU TDX V2 manifest")
        if (
            not isinstance(data_device_serial, str)
            or not re.fullmatch(r"[A-Za-z0-9._:+-]{1,255}", data_device_serial)
            or not isinstance(gpu_l0_profile, str)
            or not _GPU_PROFILE.fullmatch(gpu_l0_profile)
            or not isinstance(storage_data_size_gb, int)
            or isinstance(storage_data_size_gb, bool)
            or storage_data_size_gb < 1
            or not isinstance(gpu_infra_size_gb, int)
            or isinstance(gpu_infra_size_gb, bool)
            or gpu_infra_size_gb < 1
        ):
            raise L0CliError(
                "GPU boot rendering requires serial, profile, storage size, and gpu-infra size"
            )
        if gpu_l0_profile != manifest.get("gpu_profile_id"):
            raise L0CliError(
                "--gpu-l0-profile must exactly match the publisher-signed GPU L0 profile"
            )
        config_document["version"] = 2
        config_document["compute_type"] = "gpu"
        config_document["storage_enabled"] = True
        config_document["data_device_serial"] = data_device_serial
        config_document["gpu_l0_profile"] = gpu_l0_profile
        config_document["storage_data_size_gb"] = storage_data_size_gb
        config_document["gpu_infra_size_gb"] = gpu_infra_size_gb
    elif any(
        value is not None
        for value in (
            data_device_serial,
            gpu_l0_profile,
            storage_data_size_gb,
            gpu_infra_size_gb,
        )
    ):
        raise L0CliError("GPU disk-contract fields are invalid for a CPU V1 boot")
    config_b64 = (
        base64.urlsafe_b64encode(canonical_json_bytes(config_document)).decode("ascii").rstrip("=")
    )
    artifact_parent = manifest["kernel"]["url"].rsplit("/", 1)[0]
    manifest_url = f"{artifact_parent}/l0-bootstrap.json"
    signature_url = f"{artifact_parent}/l0-bootstrap.json.sig"
    bootif_arg = f" BOOTIF={bootif}" if bootif else ""
    kernel_line = (
        f"kernel {manifest['kernel']['url']} initrd=initrd.img "
        f"boot=live fetch={manifest['squashfs']['url']} ip=dhcp{bootif_arg} "
        "modprobe.blacklist=rndis_host,cdc_ether,cdc_ncm,cdc_subset "
        "console=tty0 console=ttyS0,115200 "
        f"{cmdline} chutes_data_device={data_device} "
        f"chutes_data_device_id={data_device_id} "
        f"chutes_data_initialize={'true' if voucher else 'false'} "
        f"chutes_l0ca_url={validator_ca_url} "
        f"chutes_l0_squashfs_sha256={manifest['squashfs']['sha256']} "
        f"chutes_l0_manifest_generation={manifest['generation']} "
        f"chutes_l0_manifest_key_id={manifest['key_id']} "
        f"chutes_l0_manifest_url={manifest_url} "
        f"chutes_l0_signature_url={signature_url} "
        f"chutes_l0_enrollment_b64={config_b64}"
    )
    if compute_type == "gpu":
        kernel_line += (
            f" chutes_compute_type=gpu"
            f" chutes_data_device_serial={data_device_serial}"
            f" chutes_gpu_l0_profile={gpu_l0_profile}"
            f" chutes_storage_data_size_gb={storage_data_size_gb}"
            f" chutes_gpu_infra_size_gb={gpu_infra_size_gb}"
        )
    if len(kernel_line.encode("ascii")) > 2048:
        raise L0CliError("generated iPXE kernel command exceeds the 2048-byte bound")
    return "\n".join(
        [
            "#!ipxe",
            "dhcp",
            kernel_line,
            f"initrd --name initrd.img {manifest['initrd']['url']}",
            "boot",
            "",
        ]
    )


def write_private(path: Path, payload: bytes) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise L0CliError("refusing to replace a symlink output")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def check_and_record_manifest_state(manifest: Dict[str, Any]) -> None:
    path = Path(
        os.environ.get(
            "CHUTES_L0_MANIFEST_STATE",
            "~/.config/chutes/l0-manifests.json",
        )
    ).expanduser()
    state: Dict[str, Any] = {
        "schema": "chutes.l0-manifest-state",
        "version": 1,
        "targets": {},
    }
    if path.is_file():
        try:
            state = json.loads(path.read_text(encoding="ascii"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise L0CliError("local L0 manifest state is corrupt") from exc
        if (
            not isinstance(state, dict)
            or set(state) != {"schema", "version", "targets"}
            or state["schema"] != "chutes.l0-manifest-state"
            or state["version"] != 1
            or not isinstance(state["targets"], dict)
        ):
            raise L0CliError("local L0 manifest state has an invalid schema")
    target = (
        f"{manifest['tee_type']}:{manifest['channel']}"
        if manifest.get("version") == 1
        else f"{manifest['tee_type']}:{manifest['channel']}:{manifest['compute_type']}"
    )
    digest = hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()
    previous = state["targets"].get(target)
    if previous is not None:
        if (
            not isinstance(previous, dict)
            or previous.get("generation", 0) > manifest["generation"]
            or previous.get("key_epoch", 0) > manifest["key_epoch"]
            or (
                previous.get("generation") == manifest["generation"]
                and previous.get("manifest_sha256") != digest
            )
        ):
            raise L0CliError("publisher-signed L0 manifest is stale or equivocated")
    state["targets"][target] = {
        "generation": manifest["generation"],
        "key_id": manifest["key_id"],
        "key_epoch": manifest["key_epoch"],
        "manifest_sha256": digest,
    }
    write_private(path, canonical_json_bytes(state) + b"\n")


async def _fetch_verified_bootstrap(
    session: aiohttp.ClientSession,
    validator_api: str,
    hotkey: str,
    tee_type: str,
    channel: str,
    compute_type: str,
    validator_ca_url: str,
) -> tuple[Dict[str, Any], str, str]:
    query = {"tee_type": tee_type, "channel": channel}
    if compute_type == "gpu":
        query["compute_type"] = "gpu"
    target = "/releases/l0-bootstrap?" + urlencode(query)
    status_code, signed = await _api_request(session, validator_api, hotkey, "GET", target)
    _require_success(status_code, signed, "fetch L0 bootstrap")
    manifest = verify_bootstrap(
        signed,
        tee_type=tee_type,
        channel=channel,
        compute_type=compute_type,
    )
    cmdline_bytes = b""
    for name in ("kernel", "initrd", "cmdline", "squashfs"):
        captured = await verify_remote_artifact(
            session, manifest[name], capture=(name == "cmdline")
        )
        if name == "cmdline":
            cmdline_bytes = captured
    ca_spec = {
        "url": _validate_artifact_url(validator_ca_url),
        "size": None,
        "sha256": manifest["validator_ca_sha256"],
    }
    digest = hashlib.sha256()
    total = 0
    async with session.get(ca_spec["url"], allow_redirects=False) as response:
        if response.status != 200:
            raise L0CliError("validator CA fetch failed")
        async for chunk in response.content.iter_chunked(64 * 1024):
            total += len(chunk)
            if total > 1024 * 1024:
                raise L0CliError("validator CA exceeds 1MiB")
            digest.update(chunk)
    if total == 0 or digest.hexdigest() != ca_spec["sha256"]:
        raise L0CliError("validator CA does not match the publisher-signed digest")
    try:
        cmdline = cmdline_bytes.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise L0CliError("signed L0 command line is not ASCII") from exc
    check_and_record_manifest_state(manifest)
    return manifest, cmdline, signed["signature"]


async def _status(
    session: aiohttp.ClientSession,
    validator_api: str,
    hotkey: str,
    host_id: str,
) -> Optional[Dict[str, Any]]:
    target = "/hosts/enrollment-status?" + urlencode({"host_id": host_id})
    status_code, payload = await _api_request(session, validator_api, hotkey, "GET", target)
    if status_code == 404:
        return None
    return _require_success(status_code, payload, "fetch enrollment status")


async def _wait_for_ready(
    session: aiohttp.ClientSession,
    validator_api: str,
    hotkey: str,
    host_id: str,
    *,
    expected_generation: int,
    expected_compute_type: str = "cpu",
    timeout_seconds: int,
) -> Dict[str, Any]:
    deadline = monotonic() + timeout_seconds
    while True:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise L0CliError("timed out waiting for enrollment readiness")
        try:
            status_payload = await asyncio.wait_for(
                _status(session, validator_api, hotkey, host_id),
                timeout=remaining,
            )
        except TimeoutError as exc:
            raise L0CliError("timed out waiting for enrollment readiness") from exc
        if status_payload is not None:
            if not isinstance(status_payload, dict):
                raise L0CliError("validator returned an invalid enrollment status")
            generation = status_payload.get("enrollment_generation")
            state = status_payload.get("provisioning_state")
            if (
                not isinstance(generation, int)
                or isinstance(generation, bool)
                or state
                not in {
                    "persisting_identity",
                    "awaiting_pcs",
                    "ready",
                    "revoked",
                }
            ):
                raise L0CliError("validator returned an invalid enrollment status")
            if expected_compute_type == "gpu" and (
                status_payload.get("version") != 2
                or status_payload.get("compute_type") != "gpu"
                or status_payload.get("tee_type") != "tdx"
                or status_payload.get("storage_enabled") is not True
            ):
                raise L0CliError("validator returned a non-GPU enrollment status")
            if state == "revoked":
                raise L0CliError("host enrollment was revoked")
            if generation > expected_generation:
                raise L0CliError(
                    "enrollment voucher generation is stale; a newer generation is active"
                )
            if generation == expected_generation and state == "ready":
                return status_payload
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise L0CliError("timed out waiting for enrollment readiness")
        await asyncio.sleep(min(POLL_INTERVAL_SECONDS, remaining))


def _print_cli_error(message: str) -> None:
    typer.echo(f"Error: {message}", err=True)


@l0_app.command("prepare-boot")
def prepare_boot(
    host_id: str = typer.Option(..., "--host-id"),
    tee_type: str = typer.Option(..., "--tee-type"),
    compute_type: str = typer.Option("cpu", "--compute-type"),
    data_device: str = typer.Option(..., "--data-device"),
    data_device_id: str = typer.Option(..., "--data-device-id"),
    data_device_serial: Optional[str] = typer.Option(None, "--data-device-serial"),
    gpu_l0_profile: Optional[str] = typer.Option(None, "--gpu-l0-profile"),
    storage_data_size_gb: Optional[int] = typer.Option(None, "--storage-data-size-gb", min=1),
    gpu_infra_size_gb: Optional[int] = typer.Option(None, "--gpu-infra-size-gb", min=1),
    output: Path = typer.Option(..., "--output"),
    validator_ca_url: str = typer.Option(..., "--validator-ca-url"),
    socket_url: str = typer.Option("wss://ws.chutes.ai", "--socket-url"),
    channel: str = typer.Option("stable", "--channel"),
    provider: Optional[str] = typer.Option(None, "--provider"),
    source: Optional[str] = typer.Option(None, "--source"),
    bootif: str = typer.Option("", "--bootif"),
    rotate_identity: bool = typer.Option(False, "--rotate-identity"),
    wait: bool = typer.Option(False, "--wait"),
    wait_timeout_seconds: Optional[int] = typer.Option(
        None,
        "--wait-timeout-seconds",
        min=1,
        max=86400,
        help="Finite readiness polling deadline; valid only with --wait.",
    ),
    steady_output: Path = typer.Option(..., "--steady-output"),
    hotkey: str = typer.Option(..., "--hotkey", envvar=HOTKEY_ENVVAR),
    validator_api: str = typer.Option(
        "https://api.chutes.ai", "--validator-api", envvar=VALIDATOR_API_ENVVAR
    ),
) -> None:
    """Verify signed L0 bytes, mint one voucher, and write raw mode-0600 iPXE."""

    async def execute() -> None:
        normalized_tee = tee_type.strip().lower()
        normalized_compute = (
            compute_type.strip().lower() if isinstance(compute_type, str) else "cpu"
        )
        if normalized_tee not in {"tdx", "sev-snp"}:
            raise L0CliError("--tee-type must be tdx or sev-snp")
        if normalized_compute not in {"cpu", "gpu"} or (
            normalized_compute == "gpu" and normalized_tee != "tdx"
        ):
            raise L0CliError("--compute-type must be cpu, or gpu with TDX")
        if not _ID.fullmatch(host_id) or not _CHANNEL.fullmatch(channel):
            raise L0CliError("host id or channel has an invalid format")
        if output.expanduser().absolute() == steady_output.expanduser().absolute():
            raise L0CliError("--output and --steady-output must be different files")
        if wait_timeout_seconds is not None and not wait:
            raise L0CliError("--wait-timeout-seconds requires --wait")
        for option_name, value, maximum in (
            ("--provider", provider, 64),
            ("--source", source, 128),
        ):
            if value is not None and (
                not 1 <= len(value) <= maximum
                or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
            ):
                raise L0CliError(f"{option_name} has an invalid format")
        if not re.fullmatch(r"/dev/[A-Za-z0-9._:+-]{1,128}", data_device) or not re.fullmatch(
            r"[A-Za-z0-9._:+-]{1,255}", data_device_id
        ):
            raise L0CliError("data device or /dev/disk/by-id basename is invalid")
        gpu_disk_fields = (
            data_device_serial,
            gpu_l0_profile,
            storage_data_size_gb,
            gpu_infra_size_gb,
        )
        if normalized_compute == "gpu":
            if (
                not isinstance(data_device_serial, str)
                or not re.fullmatch(r"[A-Za-z0-9._:+-]{1,255}", data_device_serial)
                or not isinstance(gpu_l0_profile, str)
                or not _GPU_PROFILE.fullmatch(gpu_l0_profile)
                or storage_data_size_gb is None
                or gpu_infra_size_gb is None
            ):
                raise L0CliError(
                    "GPU prepare-boot requires --data-device-serial, --gpu-l0-profile, "
                    "--storage-data-size-gb, and --gpu-infra-size-gb"
                )
        elif any(value is not None for value in gpu_disk_fields):
            raise L0CliError("GPU disk-contract options require --compute-type gpu")
        normalized_bootif = bootif
        if normalized_bootif:
            if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bootif):
                normalized_bootif = "01-" + bootif.replace(":", "-").lower()
            elif re.fullmatch(
                r"01-(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}",
                bootif,
            ):
                normalized_bootif = bootif.lower()
            else:
                raise L0CliError("--bootif must be a canonical MAC or 01-prefixed BOOTIF")
        normalized_ca_url = _validate_artifact_url(validator_ca_url)
        timeout = aiohttp.ClientTimeout(total=None, connect=30, sock_read=900)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            (
                manifest,
                signed_cmdline,
                manifest_signature,
            ) = await _fetch_verified_bootstrap(
                session,
                validator_api,
                hotkey,
                normalized_tee,
                channel,
                normalized_compute,
                normalized_ca_url,
            )
            if normalized_compute == "gpu" and gpu_l0_profile != manifest.get("gpu_profile_id"):
                raise L0CliError(
                    "--gpu-l0-profile must exactly match the publisher-signed GPU L0 profile"
                )
            request = {
                "schema": "chutes.host-enrollment-mint",
                "version": 2 if normalized_compute == "gpu" else 1,
                "host_id": host_id,
                "tee_type": normalized_tee,
                "channel": channel,
                "expires_in_seconds": 900,
                "source_metadata": {},
            }
            if normalized_compute == "gpu":
                request["compute_type"] = "gpu"
                request["storage_enabled"] = True
            if provider is not None:
                request["provider"] = provider
            if source is not None:
                request["source"] = source
            target = "/hosts/enrollment-vouchers"
            status_code, voucher_result = await _api_request(
                session, validator_api, hotkey, "POST", target, request
            )
            voucher_result = _require_success(
                status_code, voucher_result, "mint enrollment voucher"
            )
            if (
                not isinstance(voucher_result, dict)
                or set(voucher_result) != {"schema", "version", "voucher", "claims"}
                or voucher_result.get("schema") != "chutes.host-enrollment-voucher"
                or voucher_result.get("version") != (2 if normalized_compute == "gpu" else 1)
                or (voucher_result.get("claims") or {}).get("host_id") != host_id
                or (
                    normalized_compute == "gpu"
                    and (
                        (voucher_result.get("claims") or {}).get("compute_type") != "gpu"
                        or (voucher_result.get("claims") or {}).get("tee_type") != "tdx"
                        or (voucher_result.get("claims") or {}).get("storage_enabled") is not True
                    )
                )
            ):
                raise L0CliError("validator returned an invalid enrollment voucher")
            enrollment_script = render_ipxe(
                manifest,
                manifest_signature=manifest_signature,
                validator_api=validator_api,
                socket_url=socket_url,
                validator_ca_url=normalized_ca_url,
                host_id=host_id,
                tee_type=normalized_tee,
                channel=channel,
                data_device=data_device,
                data_device_id=data_device_id,
                bootif=normalized_bootif,
                voucher=voucher_result["voucher"],
                enrollment_generation=int(voucher_result["claims"]["enrollment_generation"]),
                rotate_identity=rotate_identity,
                cmdline=signed_cmdline,
                compute_type=normalized_compute,
                data_device_serial=data_device_serial,
                gpu_l0_profile=gpu_l0_profile,
                storage_data_size_gb=storage_data_size_gb,
                gpu_infra_size_gb=gpu_infra_size_gb,
            )
            write_private(output, enrollment_script.encode("ascii"))
            expected_generation = int(voucher_result["claims"]["enrollment_generation"])
            steady_script = render_ipxe(
                manifest,
                manifest_signature=manifest_signature,
                validator_api=validator_api,
                socket_url=socket_url,
                validator_ca_url=normalized_ca_url,
                host_id=host_id,
                tee_type=normalized_tee,
                channel=channel,
                data_device=data_device,
                data_device_id=data_device_id,
                bootif=normalized_bootif,
                voucher=None,
                enrollment_generation=int(voucher_result["claims"]["enrollment_generation"]),
                rotate_identity=False,
                cmdline=signed_cmdline,
                compute_type=normalized_compute,
                data_device_serial=data_device_serial,
                gpu_l0_profile=gpu_l0_profile,
                storage_data_size_gb=storage_data_size_gb,
                gpu_infra_size_gb=gpu_infra_size_gb,
            )
            write_private(steady_output, steady_script.encode("ascii"))
            typer.echo(str(output))
            typer.echo(str(steady_output))
            if wait:
                await _wait_for_ready(
                    session,
                    validator_api,
                    hotkey,
                    host_id,
                    expected_generation=expected_generation,
                    expected_compute_type=normalized_compute,
                    timeout_seconds=(
                        wait_timeout_seconds
                        if wait_timeout_seconds is not None
                        else DEFAULT_WAIT_TIMEOUT_SECONDS
                    ),
                )
                typer.echo(f"Enrollment ready for {host_id}")

    try:
        asyncio.run(execute())
    except L0CliError as exc:
        _print_cli_error(str(exc))
        raise typer.Exit(1) from None
    except (aiohttp.ClientError, OSError):
        _print_cli_error("local file or network operation failed")
        raise typer.Exit(1) from None
    except Exception:
        _print_cli_error("prepare-boot failed unexpectedly")
        raise typer.Exit(1) from None


@l0_app.command("enrollment-status")
def enrollment_status(
    host_id: str = typer.Option(..., "--host-id"),
    hotkey: str = typer.Option(..., "--hotkey", envvar=HOTKEY_ENVVAR),
    validator_api: str = typer.Option(
        "https://api.chutes.ai", "--validator-api", envvar=VALIDATOR_API_ENVVAR
    ),
) -> None:
    async def execute() -> None:
        async with aiohttp.ClientSession() as session:
            payload = await _status(session, validator_api, hotkey, host_id)
        if payload is None:
            raise L0CliError("host is not enrolled")
        typer.echo(json.dumps(payload, sort_keys=True, indent=2))

    try:
        asyncio.run(execute())
    except L0CliError as exc:
        _print_cli_error(str(exc))
        raise typer.Exit(1) from None
    except (aiohttp.ClientError, OSError):
        _print_cli_error("local file or network operation failed")
        raise typer.Exit(1) from None
    except Exception:
        _print_cli_error("enrollment-status failed unexpectedly")
        raise typer.Exit(1) from None


@l0_app.command("gpu-legacy-cutover")
def gpu_legacy_cutover(
    host_id: str = typer.Option(..., "--host-id"),
    legacy_server_id: str = typer.Option(..., "--legacy-server-id"),
    hotkey: str = typer.Option(..., "--hotkey", envvar=HOTKEY_ENVVAR),
    validator_api: str = typer.Option(
        "https://api.chutes.ai",
        "--validator-api",
        envvar=VALIDATOR_API_ENVVAR,
    ),
    bundle_path: str = typer.Option(
        LEGACY_CUTOVER_BUNDLE_PATH,
        "--bundle-path",
    ),
    cert_path: str = typer.Option(
        "/etc/attestation-service/certs/server.crt",
        "--cert-path",
    ),
    key_path: str = typer.Option(
        "/etc/attestation-service/certs/server.key",
        "--key-path",
    ),
    ca_path: str = typer.Option("", "--ca-path"),
    kubeconfig_path: str = typer.Option(
        K3S_ADMIN_KUBECONFIG,
        "--kubeconfig",
    ),
) -> None:
    """Authorize and start one legacy guest custody cutover."""

    async def execute() -> None:
        if os.geteuid() != 0:
            raise L0CliError("legacy GPU cutover initiation must run as root")
        if bundle_path != LEGACY_CUTOVER_BUNDLE_PATH:
            raise L0CliError("operator cutover bundle path must match the installed service")
        if not _ID.fullmatch(host_id) or not _ID.fullmatch(legacy_server_id):
            raise L0CliError("legacy cutover host/server identity is invalid")
        target = f"/hosts/{quote(host_id, safe='')}/gpu/migrations/legacy/authorize"
        async with aiohttp.ClientSession() as session:
            status_code, payload = await _api_request(
                session,
                validator_api,
                hotkey,
                "POST",
                target,
                {
                    "schema": "chutes.gpu-legacy-cutover-authorize",
                    "version": 1,
                    "legacy_server_id": legacy_server_id,
                },
            )
        if kubeconfig_path != K3S_ADMIN_KUBECONFIG:
            raise L0CliError("legacy cutover kubeconfig must use the persisted K3s admin contract")
        payload = _require_success(
            status_code,
            payload,
            "authorize legacy GPU cutover",
        )
        required = {
            "schema",
            "version",
            "authorization_id",
            "cutover_authorization",
            "legacy_server_id",
            "legacy_vm_name",
            "target_server_id",
            "target_host_id",
            "expires_at",
        }
        if (
            not isinstance(payload, dict)
            or set(payload) != required
            or payload["schema"] != "chutes.gpu-legacy-cutover-authorization"
            or payload["version"] != 1
            or payload["legacy_server_id"] != legacy_server_id
            or payload["target_host_id"] != host_id
            or not isinstance(payload["cutover_authorization"], str)
            or not payload["cutover_authorization"]
        ):
            raise L0CliError("validator returned invalid legacy cutover authorization")
        bundle = {
            "schema": "chutes.legacy-gpu-cutover-bundle",
            "version": 1,
            "validator_api": validator_api.rstrip("/"),
            "cutover_authorization": payload["cutover_authorization"],
            "legacy_server_id": legacy_server_id,
            "target_host_id": host_id,
            "cert_path": cert_path,
            "key_path": key_path,
            "ca_path": ca_path,
            "kubeconfig_path": kubeconfig_path,
        }
        write_private(
            Path(bundle_path),
            canonical_json_bytes(bundle) + b"\n",
        )
        rebind_closure_authorization(payload["cutover_authorization"])
        result = subprocess.run(  # nosec B603
            ["systemctl", "start", "chutes-legacy-gpu-cutover.service"],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise L0CliError("legacy GPU cutover service failed to start")
        typer.echo(
            json.dumps(
                {
                    "authorization_id": payload["authorization_id"],
                    "target_server_id": payload["target_server_id"],
                    "status": "cutover_started",
                },
                sort_keys=True,
            )
        )

    try:
        asyncio.run(execute())
    except L0CliError as exc:
        _print_cli_error(str(exc))
        raise typer.Exit(1) from None
    except (aiohttp.ClientError, OSError):
        _print_cli_error("legacy GPU cutover initiation failed")
        raise typer.Exit(1) from None


@l0_app.command("gpu-legacy-cutover-run", hidden=True)
def gpu_legacy_cutover_run(
    bundle_path: str = typer.Option(
        LEGACY_CUTOVER_BUNDLE_PATH,
        "--bundle-path",
    ),
) -> None:
    """Run the root-only cutover service payload."""

    try:
        result = run_legacy_cutover(bundle_path)
        typer.echo(json.dumps(result, sort_keys=True))
    except LegacyCutoverError as exc:
        _print_cli_error(str(exc))
        raise typer.Exit(1) from None


@l0_app.command("gpu-legacy-cutover-retry")
def gpu_legacy_cutover_retry() -> None:
    """Retry the fenced API transfer using persisted closure evidence."""

    if os.geteuid() != 0:
        _print_cli_error("legacy GPU cutover retry must run as root")
        raise typer.Exit(1)
    if not Path(LEGACY_CUTOVER_BUNDLE_PATH).is_file():
        _print_cli_error("legacy GPU cutover bundle is unavailable")
        raise typer.Exit(1)
    result = subprocess.run(  # nosec B603
        ["systemctl", "start", "chutes-legacy-gpu-cutover.service"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        _print_cli_error("legacy GPU cutover retry failed")
        raise typer.Exit(1)


@l0_app.command("gpu-legacy-recover")
def gpu_legacy_recover() -> None:
    """Reboot through legacy key release after a failed API transfer."""

    try:
        recover_legacy_cutover()
    except LegacyCutoverError as exc:
        _print_cli_error(str(exc))
        raise typer.Exit(1) from None


@l0_app.command("gpu-start")
def gpu_start(
    host_id: str = typer.Option(..., "--host-id"),
    gpu_identifier: str = typer.Option(..., "--gpu-identifier"),
    gpu_count: int = typer.Option(..., "--gpu-count", min=1, max=64),
    minimum_vram_mib: int = typer.Option(..., "--minimum-vram-mib", min=1),
    miner_hourly_cost: float = typer.Option(..., "--miner-hourly-cost"),
    legacy_vm_name: Optional[str] = typer.Option(None, "--legacy-vm-name"),
    hotkey: str = typer.Option(..., "--hotkey", envvar=HOTKEY_ENVVAR),
    validator_api: str = typer.Option(
        "https://api.chutes.ai", "--validator-api", envvar=VALIDATOR_API_ENVVAR
    ),
) -> None:
    """Reserve and dispatch one validator-owned miner GPU fabric."""

    async def execute() -> None:
        if not _ID.fullmatch(host_id):
            raise L0CliError("--host-id has an invalid format")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", gpu_identifier):
            raise L0CliError("--gpu-identifier has an invalid format")
        if not math.isfinite(miner_hourly_cost) or miner_hourly_cost <= 0:
            raise L0CliError("--miner-hourly-cost must be a positive finite value")
        if legacy_vm_name is not None and not _ID.fullmatch(legacy_vm_name):
            raise L0CliError("--legacy-vm-name has an invalid format")
        body: Dict[str, Any] = {
            "schema": "chutes.gpu-miner-reservation-request",
            "version": 1,
            "gpu_identifier": gpu_identifier,
            "gpu_count": gpu_count,
            "minimum_vram_mib": minimum_vram_mib,
            "miner_hourly_cost": miner_hourly_cost,
        }
        if legacy_vm_name is not None:
            body["legacy_vm_name"] = legacy_vm_name
        target = f"/hosts/{quote(host_id, safe='')}/gpu/reservations/miner"
        async with aiohttp.ClientSession() as session:
            status_code, payload = await _api_request(
                session,
                validator_api,
                hotkey,
                "POST",
                target,
                body,
            )
        payload = _require_success(status_code, payload, "reserve miner GPU fabric")
        claims = payload.get("claims") if isinstance(payload, dict) else None
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema", "version", "token", "claims", "claims_sha256"}
            or payload.get("schema") != "chutes.gpu-launch-reservation-result"
            or payload.get("version") != 1
            or not isinstance(payload.get("token"), str)
            or not isinstance(payload.get("claims_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", payload["claims_sha256"])
            or not isinstance(claims, dict)
            or claims.get("schema") != "chutes.gpu-launch-reservation"
            or claims.get("version") != 1
            or claims.get("management_mode") != "miner"
            or claims.get("host_id") != host_id
            or not isinstance(claims.get("server_id"), str)
            or not isinstance(claims.get("reservation_id"), str)
            or not isinstance(claims.get("process_incarnation"), str)
        ):
            raise L0CliError("validator returned an invalid miner GPU reservation")
        typer.echo(
            json.dumps(
                {
                    "server_id": claims["server_id"],
                    "reservation_id": claims["reservation_id"],
                    "process_incarnation": claims["process_incarnation"],
                    "allocation_group_id": claims["allocation_group_id"],
                    "allocation_group_generation": claims["allocation_group_generation"],
                    "status": "dispatched",
                },
                sort_keys=True,
            )
        )

    try:
        asyncio.run(execute())
    except L0CliError as exc:
        _print_cli_error(str(exc))
        raise typer.Exit(1) from None
    except (aiohttp.ClientError, OSError):
        _print_cli_error("GPU reservation request failed")
        raise typer.Exit(1) from None


@l0_app.command("gpu-stop")
def gpu_stop(
    server_id: str = typer.Option(..., "--server-id"),
    reason: str = typer.Option("operator requested miner TD stop", "--reason"),
    hotkey: str = typer.Option(..., "--hotkey", envvar=HOTKEY_ENVVAR),
    validator_api: str = typer.Option(
        "https://api.chutes.ai", "--validator-api", envvar=VALIDATOR_API_ENVVAR
    ),
) -> None:
    """Request sealed gpu-infra shutdown, exact QEMU stop, and GPU reset."""

    async def execute() -> None:
        if not _ID.fullmatch(server_id):
            raise L0CliError("--server-id has an invalid format")
        if not 1 <= len(reason) <= 2000:
            raise L0CliError("--reason must contain 1..2000 characters")
        target = f"/hosts/gpu/miner/{quote(server_id, safe='')}/stop"
        async with aiohttp.ClientSession() as session:
            status_code, payload = await _api_request(
                session,
                validator_api,
                hotkey,
                "POST",
                target,
                {
                    "schema": "chutes.gpu-miner-stop-request",
                    "version": 1,
                    "reason": reason,
                },
            )
        payload = _require_success(status_code, payload, "stop miner GPU fabric")
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema", "version", "server_id", "reservation_id", "status"}
            or payload.get("schema") != "chutes.gpu-miner-stop-result"
            or payload.get("version") != 1
            or payload.get("server_id") != server_id
            or payload.get("status") not in {"teardown_requested", "released"}
        ):
            raise L0CliError("validator returned an invalid miner GPU stop result")
        typer.echo(json.dumps(payload, sort_keys=True))

    try:
        asyncio.run(execute())
    except L0CliError as exc:
        _print_cli_error(str(exc))
        raise typer.Exit(1) from None
    except (aiohttp.ClientError, OSError):
        _print_cli_error("GPU stop request failed")
        raise typer.Exit(1) from None


def _pcs_envelope(
    hotkey_path: str,
    status_payload: Dict[str, Any],
    pcs_key: bytes,
) -> Dict[str, Any]:
    if not 1 <= len(pcs_key) <= 1024 or b"\x00" in pcs_key:
        raise L0CliError("PCS key file has an invalid size or contains NUL")
    pcs_key.decode("utf-8")
    now = datetime.now(timezone.utc)
    compute_type = status_payload.get("compute_type", "cpu")
    if compute_type not in {"cpu", "gpu"}:
        raise L0CliError("enrollment status has an invalid compute_type")
    version = 2 if compute_type == "gpu" else 1
    aad = {
        "schema": "chutes.pcs-mailbox-aad",
        "version": version,
        "owner_hotkey": status_payload["owner_hotkey"],
        "host_id": status_payload["host_id"],
        "recipient_fingerprint": status_payload["x25519_fingerprint"],
        "enrollment_generation": status_payload["enrollment_generation"],
        "key_generation": status_payload["key_generation"],
        "message_id": secrets.token_hex(32),
        "purpose": "intel-pcs-provisioning",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
    }
    if compute_type == "gpu":
        if (
            status_payload.get("version") != 2
            or status_payload.get("tee_type") != "tdx"
            or status_payload.get("storage_enabled") is not True
        ):
            raise L0CliError("GPU PCS status is not compute-scoped and storage-enabled")
        aad["compute_type"] = "gpu"
    recipient = X25519PublicKey.from_public_bytes(
        base64.b64decode(status_payload["x25519_public_key"], validate=True)
    )
    ephemeral = X25519PrivateKey.generate()
    aad_bytes = canonical_json_bytes(aad)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(aad_bytes).digest(),
        info=f"chutes/model-b/pcs-mailbox/v{version}".encode("ascii"),
    ).derive(ephemeral.exchange(recipient))
    nonce = secrets.token_bytes(12)
    envelope = {
        "schema": "chutes.pcs-mailbox",
        "version": version,
        "algorithm": "X25519-HKDF-SHA256-CHACHA20POLY1305",
        "kdf_label": f"chutes/model-b/pcs-mailbox/v{version}",
        "sender_ephemeral_public_key": base64.b64encode(
            ephemeral.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(
            ChaCha20Poly1305(key).encrypt(nonce, pcs_key, aad_bytes)
        ).decode("ascii"),
        "aad": aad,
    }
    _, keypair = _load_hotkey(hotkey_path)
    envelope["miner_signature"] = base64.b64encode(
        keypair.sign(canonical_json_bytes(envelope))
    ).decode("ascii")
    return envelope


@l0_app.command("complete-enrollment")
def complete_enrollment(
    host_id: str = typer.Option(..., "--host-id"),
    pcs_key_file: Path = typer.Option(..., "--pcs-key-file"),
    hotkey: str = typer.Option(..., "--hotkey", envvar=HOTKEY_ENVVAR),
    validator_api: str = typer.Option(
        "https://api.chutes.ai", "--validator-api", envvar=VALIDATOR_API_ENVVAR
    ),
) -> None:
    """Encrypt a miner-owned PCS key to the enrolled host and upload ciphertext only."""

    async def execute() -> None:
        metadata = pcs_key_file.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_mode & 0o077
        ):
            raise L0CliError("PCS key file must be one mode-0600 regular file")
        pcs_key = pcs_key_file.read_bytes().rstrip(b"\r\n")
        async with aiohttp.ClientSession() as session:
            status_payload = await _status(session, validator_api, hotkey, host_id)
            if status_payload is None:
                raise L0CliError("host is not enrolled")
            if status_payload.get("tee_type") != "tdx":
                raise L0CliError("PCS provisioning applies only to TDX hosts")
            if status_payload.get("provisioning_state") != "awaiting_pcs":
                raise L0CliError("host is not awaiting PCS provisioning")
            envelope = _pcs_envelope(hotkey, status_payload, pcs_key)
            status_code, payload = await _api_request(
                session,
                validator_api,
                hotkey,
                "POST",
                "/hosts/pcs-mailbox",
                envelope,
            )
            _require_success(status_code, payload, "provision PCS mailbox")
        typer.echo(f"PCS ciphertext provisioned for {host_id}")

    try:
        asyncio.run(execute())
    except L0CliError as exc:
        _print_cli_error(str(exc))
        raise typer.Exit(1) from None
    except (aiohttp.ClientError, OSError, UnicodeDecodeError):
        _print_cli_error("local file, network, or PCS input operation failed")
        raise typer.Exit(1) from None
    except Exception:
        _print_cli_error("complete-enrollment failed unexpectedly")
        raise typer.Exit(1) from None


def register(app: typer.Typer) -> None:
    app.add_typer(l0_app, name="l0")
