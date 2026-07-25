"""Standalone legacy GPU guest cutover using its existing attested identity."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import ssl
import stat
import subprocess  # nosec B404
import tempfile
from pathlib import Path
from typing import Any

import aiohttp

BUNDLE_PATH = "/run/chutes/legacy-gpu-cutover.json"
RECOVERY_MARKER = "/run/chutes/legacy-gpu-cutover-recovery-required"
CLOSURE_PATH = "/run/chutes/legacy-gpu-cutover-closure.json"
K3S_ADMIN_KUBECONFIG = "/run/chutes/legacy-k3s-admin.yaml"


class LegacyCutoverError(RuntimeError):
    """Legacy volume closure or custody transfer failed."""


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(  # nosec B603
        argv,
        check=False,
        capture_output=True,
        text=True,
    )


def _output(argv: list[str], label: str, *, lower: bool = True) -> str:
    result = _run(argv)
    value = result.stdout.strip()
    if result.returncode != 0 or not value:
        raise LegacyCutoverError(f"{label} is unavailable")
    return value.lower() if lower else value


def _load_bundle(path: str = BUNDLE_PATH) -> dict[str, Any]:
    metadata = os.stat(path, follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o077
    ):
        raise LegacyCutoverError("cutover bundle must be one root-only regular file")
    payload = Path(path).read_bytes()
    try:
        document = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LegacyCutoverError("cutover bundle is malformed") from exc
    required = {
        "schema",
        "version",
        "validator_api",
        "cutover_authorization",
        "legacy_server_id",
        "target_host_id",
        "cert_path",
        "key_path",
        "ca_path",
        "kubeconfig_path",
    }
    if (
        not isinstance(document, dict)
        or set(document) != required
        or document["schema"] != "chutes.legacy-gpu-cutover-bundle"
        or document["version"] != 1
        or any(
            not isinstance(document[key], str) or not document[key]
            for key in required.difference({"schema", "version", "ca_path"})
        )
        or not isinstance(document["ca_path"], str)
    ):
        raise LegacyCutoverError("cutover bundle has the wrong schema")
    return document


def _write_private_json(path: str, document: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(
                json.dumps(
                    document,
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
                + b"\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _load_closure(path: str) -> dict[str, Any]:
    metadata = os.stat(path, follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o077
    ):
        raise LegacyCutoverError("persisted closure evidence is unsafe")
    try:
        document = json.loads(Path(path).read_text(encoding="ascii"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LegacyCutoverError("persisted closure evidence is malformed") from exc
    if (
        not isinstance(document, dict)
        or document.get("schema") != "chutes.gpu-legacy-close-request"
        or document.get("version") != 1
    ):
        raise LegacyCutoverError("persisted closure evidence has the wrong schema")
    return document


def rebind_closure_authorization(token: str) -> None:
    if not Path(CLOSURE_PATH).exists():
        return
    if not token:
        raise LegacyCutoverError("replacement cutover authorization is empty")
    closure = _load_closure(CLOSURE_PATH)
    closure["cutover_authorization"] = token
    _write_private_json(CLOSURE_PATH, closure)


def _generation(root: str) -> int:
    try:
        value = int((Path(root) / ".chutefs-epoch").read_text(encoding="ascii").strip())
    except (OSError, ValueError) as exc:
        raise LegacyCutoverError(f"{root} has no valid generation marker") from exc
    if value < 0:
        raise LegacyCutoverError("legacy generation cannot be negative")
    return value


def _unmount(path: str) -> None:
    if _run(["mountpoint", "-q", path]).returncode == 0:
        if _run(["umount", path]).returncode != 0:
            raise LegacyCutoverError(f"legacy mount could not be closed: {path}")


def _close_mapper(name: str) -> None:
    mapper = f"/dev/mapper/{name}"
    if os.path.exists(mapper) and _run(["cryptsetup", "luksClose", name]).returncode != 0:
        raise LegacyCutoverError(f"legacy mapper could not be closed: {name}")
    if os.path.exists(mapper) or _run(["cryptsetup", "status", name]).returncode == 0:
        raise LegacyCutoverError(f"legacy mapper remains open: {name}")


def _verified_postgres_password(kubeconfig: str) -> str:
    try:
        metadata = os.stat(kubeconfig, follow_symlinks=False)
    except OSError as exc:
        raise LegacyCutoverError("legacy K3s admin kubeconfig is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o077
    ):
        raise LegacyCutoverError("legacy K3s admin kubeconfig is absent or not root-only")
    ready = _run(["kubectl", "--kubeconfig", kubeconfig, "get", "--raw=/readyz"])
    if ready.returncode != 0 or ready.stdout.strip() != "ok":
        raise LegacyCutoverError("legacy K3s admin kubeconfig is not ready")
    namespace_raw = _output(
        [
            "kubectl",
            "--kubeconfig",
            kubeconfig,
            "get",
            "namespace",
            "kube-system",
            "-o",
            "json",
        ],
        "legacy K3s cluster identity",
        lower=False,
    )
    secret_raw = _output(
        [
            "kubectl",
            "--kubeconfig",
            kubeconfig,
            "get",
            "secret",
            "postgres-secret",
            "-n",
            "chutes",
            "-o",
            "json",
        ],
        "legacy PostgreSQL credential",
        lower=False,
    )
    try:
        namespace = json.loads(namespace_raw)
        secret = json.loads(secret_raw)
        if (
            namespace.get("metadata", {}).get("name") != "kube-system"
            or not namespace.get("metadata", {}).get("uid")
            or secret.get("metadata", {}).get("name") != "postgres-secret"
            or secret.get("metadata", {}).get("namespace") != "chutes"
            or not secret.get("metadata", {}).get("uid")
            or set(secret.get("data", {})) != {"postgres-password"}
        ):
            raise LegacyCutoverError("legacy cluster or PostgreSQL secret identity is invalid")
        encoded = secret["data"]["postgres-password"]
        password = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LegacyCutoverError("legacy PostgreSQL credential is invalid") from exc
    if not 16 <= len(password) <= 256 or "\x00" in password:
        raise LegacyCutoverError("legacy PostgreSQL credential has an invalid size")
    return password


def _closure_document(bundle: dict[str, Any]) -> dict[str, Any]:
    postgres_password = _verified_postgres_password(bundle["kubeconfig_path"])
    storage_device = "/dev/disk/by-label/storage"
    cache_device = "/dev/disk/by-label/tdx-cache"
    storage_mapper = "/dev/mapper/storage"
    cache_mapper = "/dev/mapper/tdx-cache"
    if (
        _output(
            ["blkid", "-o", "value", "-s", "TYPE", storage_mapper],
            "legacy storage filesystem type",
        )
        != "xfs"
    ):
        raise LegacyCutoverError("legacy storage filesystem must be XFS")
    cache_type = _output(
        ["blkid", "-o", "value", "-s", "TYPE", cache_mapper],
        "legacy tdx-cache filesystem type",
    )
    if cache_type not in {"xfs", "ext4"}:
        raise LegacyCutoverError("legacy tdx-cache filesystem is unsupported")
    return {
        "schema": "chutes.gpu-legacy-close-request",
        "version": 1,
        "cutover_authorization": bundle["cutover_authorization"],
        "target_host_id": bundle["target_host_id"],
        "storage_luks_uuid": _output(
            ["cryptsetup", "luksUUID", storage_device],
            "legacy storage LUKS UUID",
        ),
        "storage_filesystem_uuid": _output(
            ["blkid", "-o", "value", "-s", "UUID", storage_mapper],
            "legacy storage filesystem UUID",
        ),
        "storage_generation": _generation("/cache/storage"),
        "cache_luks_uuid": _output(
            ["cryptsetup", "luksUUID", cache_device],
            "legacy tdx-cache LUKS UUID",
        ),
        "cache_filesystem_uuid": _output(
            ["blkid", "-o", "value", "-s", "UUID", cache_mapper],
            "legacy tdx-cache filesystem UUID",
        ),
        "cache_filesystem_type": cache_type,
        "cache_generation": _generation("/var/snap"),
        "postgres_password": postgres_password,
        "workloads_stopped": True,
        "postgres_stopped": True,
        "filesystems_synced": True,
        "filesystems_unmounted": True,
        "storage_mapper_closed": True,
        "cache_mapper_closed": True,
    }


async def run_cutover(bundle_path: str = BUNDLE_PATH) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise LegacyCutoverError("legacy GPU cutover must run as root")
    bundle = _load_bundle(bundle_path)
    closure = (
        _load_closure(CLOSURE_PATH) if Path(CLOSURE_PATH).exists() else _closure_document(bundle)
    )
    if not Path(CLOSURE_PATH).exists():
        _write_private_json(CLOSURE_PATH, closure)
    if _run(["systemctl", "stop", "k3s.service"]).returncode != 0:
        raise LegacyCutoverError("K3s and legacy PostgreSQL did not quiesce")
    os.sync()
    for path in (
        "/var/lib/chutes/agent",
        "/etc/admission-controller/certs",
        "/etc/rancher/k3s",
        "/var/lib/kubelet",
        "/var/lib/rancher/k3s",
        "/cache/storage",
        "/var/snap",
    ):
        _unmount(path)
    _close_mapper("storage")
    _close_mapper("tdx-cache")
    os.sync()
    Path(RECOVERY_MARKER).write_text("reboot reopens validator custody\n", encoding="ascii")
    os.chmod(RECOVERY_MARKER, 0o600)
    context = ssl.create_default_context(cafile=bundle["ca_path"] or None)
    context.load_cert_chain(bundle["cert_path"], bundle["key_path"])
    connector = aiohttp.TCPConnector(ssl=context)
    target = f"/servers/gpu/{bundle['legacy_server_id']}/legacy-migration/close"
    try:
        async with aiohttp.ClientSession(
            base_url=bundle["validator_api"].rstrip("/"),
            connector=connector,
        ) as session:
            async with session.post(target, json=closure, allow_redirects=False) as response:
                result = await response.json()
                if response.status != 200:
                    raise LegacyCutoverError(
                        f"validator custody transfer failed with HTTP {response.status}"
                    )
    except Exception:
        # Mappings remain closed. The operator can run recovery, which reboots
        # through the unchanged legacy initramfs key-release flow.
        raise
    if (
        not isinstance(result, dict)
        or result.get("schema") != "chutes.gpu-legacy-closed"
        or result.get("legacy_server_id") != bundle["legacy_server_id"]
        or result.get("status") != "guest_closed"
    ):
        raise LegacyCutoverError("validator returned invalid transfer evidence")
    Path(RECOVERY_MARKER).unlink(missing_ok=True)
    Path(CLOSURE_PATH).unlink(missing_ok=True)
    Path(bundle_path).unlink(missing_ok=True)
    os.sync()
    if _run(["systemctl", "poweroff", "--no-block"]).returncode != 0:
        raise LegacyCutoverError("legacy guest could not begin final poweroff")
    return result


def recover_legacy_cutover() -> None:
    if os.geteuid() != 0:
        raise LegacyCutoverError("legacy GPU recovery must run as root")
    if not Path(RECOVERY_MARKER).is_file():
        raise LegacyCutoverError("no failed legacy cutover requires recovery")
    if _run(["systemctl", "reboot", "--no-block"]).returncode != 0:
        raise LegacyCutoverError("legacy recovery reboot failed")


def run(bundle_path: str = BUNDLE_PATH) -> dict[str, Any]:
    kubeconfig: str | None = None
    try:
        kubeconfig = _load_bundle(bundle_path)["kubeconfig_path"]
        return asyncio.run(run_cutover(bundle_path))
    finally:
        if kubeconfig:
            Path(kubeconfig).unlink(missing_ok=True)
