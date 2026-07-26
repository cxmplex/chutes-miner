"""Standalone legacy GPU guest cutover using its existing attested identity."""

from __future__ import annotations

import asyncio
import base64
import hashlib
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
CUTOVER_STATE_PATH = "/var/lib/chutes/legacy-gpu-cutover/state.json"
CLOSURE_PATH = "/var/lib/chutes/legacy-gpu-cutover/closure.json"
AUTHORIZATION_PATH = "/var/lib/chutes/legacy-gpu-cutover/authorization.json"
K3S_ADMIN_KUBECONFIG = "/run/chutes/legacy-k3s-admin.yaml"
K3S_SHUTDOWN_HELPER = "/usr/local/libexec/chutes/k3s-killall-v1.33.1+k3s1.sh"
K3S_SHUTDOWN_HELPER_SHA256 = (
    "bff738a1797f26645a75258ec9ab5c575e8689ddab0803dcd7b8d091a987347d"
)
CUTOVER_STATE_SCHEMA = "chutes.legacy-gpu-cutover-state"
CUTOVER_STATE_VERSION = 1
CUTOVER_STATE_PHASES = (
    "prepared",
    "k3s_quiesced",
    "filesystems_unmounted",
    "mappers_closed",
    "transfer_acknowledged",
)
CUTOVER_STATE_COMMON_FIELDS = frozenset(
    {
        "schema",
        "version",
        "phase",
        "boot_id",
        "last_boot_id",
        "legacy_server_id",
        "target_host_id",
    }
)
CUTOVER_STATE_SOURCE_FIELDS = CUTOVER_STATE_COMMON_FIELDS | {
    "connection",
    "storage_luks_uuid",
    "storage_filesystem_uuid",
    "storage_generation",
    "cache_luks_uuid",
    "cache_filesystem_uuid",
    "cache_filesystem_type",
    "cache_generation",
    "postgres_password",
}
CUTOVER_STATE_ACKNOWLEDGED_FIELDS = CUTOVER_STATE_COMMON_FIELDS | {
    "closure_sha256",
    "api_result",
}
_LEGACY_MOUNTS = (
    "/var/lib/chutes/agent",
    "/etc/admission-controller/certs",
    "/etc/rancher/k3s",
    "/var/lib/kubelet",
    "/var/lib/rancher/k3s",
    "/cache/storage",
    "/var/snap",
)


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
        directory_descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def _unlink_private(path: str) -> None:
    destination = Path(path)
    if not destination.exists():
        return
    destination.unlink()
    directory_descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _path_present(path: str) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def _load_private_json(path: str, label: str) -> dict[str, Any]:
    metadata = os.stat(path, follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise LegacyCutoverError(f"persisted {label} is unsafe")
    try:
        document = json.loads(Path(path).read_text(encoding="ascii"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LegacyCutoverError(f"persisted {label} is malformed") from exc
    if not isinstance(document, dict):
        raise LegacyCutoverError(f"persisted {label} is malformed")
    return document


def _load_closure(path: str) -> dict[str, Any]:
    document = _load_private_json(path, "closure evidence")
    if (
        document.get("schema") != "chutes.gpu-legacy-close-request"
        or document.get("version") != 1
    ):
        raise LegacyCutoverError("persisted closure evidence has the wrong schema")
    return document


def _load_cutover_state(path: str | None = None) -> dict[str, Any]:
    path = path or CUTOVER_STATE_PATH
    document = _load_private_json(path, "cutover recovery state")
    phase = document.get("phase")
    expected = (
        CUTOVER_STATE_ACKNOWLEDGED_FIELDS
        if phase == "transfer_acknowledged"
        else CUTOVER_STATE_SOURCE_FIELDS
    )
    if (
        set(document) != expected
        or document.get("schema") != CUTOVER_STATE_SCHEMA
        or document.get("version") != CUTOVER_STATE_VERSION
        or phase not in CUTOVER_STATE_PHASES
        or any(
            not isinstance(document.get(key), str) or not document[key]
            for key in ("boot_id", "last_boot_id", "legacy_server_id", "target_host_id")
        )
    ):
        raise LegacyCutoverError(
            "persisted cutover recovery state has the wrong schema"
        )
    if phase == "transfer_acknowledged":
        result = document["api_result"]
        if (
            not isinstance(result, dict)
            or set(result)
            != {"schema", "version", "migration_id", "legacy_server_id", "status"}
            or not isinstance(document["closure_sha256"], str)
            or len(document["closure_sha256"]) != 64
            or any(
                character not in "0123456789abcdef"
                for character in document["closure_sha256"]
            )
            or result.get("schema") != "chutes.gpu-legacy-closed"
            or result.get("version") != 1
            or not isinstance(result.get("migration_id"), str)
            or not result["migration_id"]
            or result.get("legacy_server_id") != document["legacy_server_id"]
            or result.get("status") != "guest_closed"
        ):
            raise LegacyCutoverError("persisted transfer acknowledgement is malformed")
        return document
    if (
        any(
            not isinstance(document.get(key), str) or not document[key]
            for key in CUTOVER_STATE_SOURCE_FIELDS
            - CUTOVER_STATE_COMMON_FIELDS
            - {"storage_generation", "cache_generation", "connection"}
        )
        or not isinstance(document["storage_generation"], int)
        or document["storage_generation"] < 0
        or not isinstance(document["cache_generation"], int)
        or document["cache_generation"] < 0
    ):
        raise LegacyCutoverError("persisted cutover source evidence is malformed")
    connection = document["connection"]
    if (
        not isinstance(connection, dict)
        or set(connection) != {"validator_api", "cert_path", "key_path", "ca_path"}
        or any(
            not isinstance(connection.get(key), str) or not connection[key]
            for key in ("validator_api", "cert_path", "key_path")
        )
        or not isinstance(connection.get("ca_path"), str)
    ):
        raise LegacyCutoverError("persisted validator connection descriptor is malformed")
    return document


def _persist_authorization(
    *, legacy_server_id: str, target_host_id: str, token: str
) -> None:
    _write_private_json(
        AUTHORIZATION_PATH,
        {
            "schema": "chutes.legacy-gpu-cutover-authorization-envelope",
            "version": 1,
            "legacy_server_id": legacy_server_id,
            "target_host_id": target_host_id,
            "cutover_authorization": token,
        },
    )


def rebind_closure_authorization(token: str) -> None:
    if not token:
        raise LegacyCutoverError("replacement cutover authorization is empty")
    if _path_present(CUTOVER_STATE_PATH):
        state = _load_cutover_state()
        if state["phase"] == "transfer_acknowledged":
            raise LegacyCutoverError("acknowledged cutover authorization is immutable")
        legacy_server_id = state["legacy_server_id"]
        target_host_id = state["target_host_id"]
    elif Path(BUNDLE_PATH).exists():
        bundle = _load_bundle(BUNDLE_PATH)
        legacy_server_id = bundle["legacy_server_id"]
        target_host_id = bundle["target_host_id"]
    else:
        return
    _persist_authorization(
        legacy_server_id=legacy_server_id,
        target_host_id=target_host_id,
        token=token,
    )


def _load_authorization(state: dict[str, Any]) -> str:
    envelope = _load_private_json(AUTHORIZATION_PATH, "authorization envelope")
    if (
        set(envelope)
        != {
            "schema",
            "version",
            "legacy_server_id",
            "target_host_id",
            "cutover_authorization",
        }
        or envelope.get("schema")
        != "chutes.legacy-gpu-cutover-authorization-envelope"
        or envelope.get("version") != 1
        or envelope.get("legacy_server_id") != state["legacy_server_id"]
        or envelope.get("target_host_id") != state["target_host_id"]
        or not isinstance(envelope.get("cutover_authorization"), str)
        or not envelope["cutover_authorization"]
    ):
        raise LegacyCutoverError("persisted authorization envelope is malformed")
    return envelope["cutover_authorization"]


def _generation(root: str) -> int:
    try:
        value = int((Path(root) / ".chutefs-epoch").read_text(encoding="ascii").strip())
    except (OSError, ValueError) as exc:
        raise LegacyCutoverError(f"{root} has no valid generation marker") from exc
    if value < 0:
        raise LegacyCutoverError("legacy generation cannot be negative")
    return value


def _boot_id() -> str:
    try:
        value = (
            Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        )
    except OSError as exc:
        raise LegacyCutoverError("host boot identity is unavailable") from exc
    if len(value) != 36:
        raise LegacyCutoverError("host boot identity is malformed")
    return value


def _verify_host_mount_namespace() -> None:
    try:
        current = os.stat("/proc/self/ns/mnt")
        host = os.stat("/proc/1/ns/mnt")
    except OSError as exc:
        raise LegacyCutoverError("mount namespace identity is unavailable") from exc
    if (current.st_dev, current.st_ino) != (host.st_dev, host.st_ino):
        raise LegacyCutoverError(
            "legacy cutover is not running in PID 1's mount namespace"
        )


def _verify_shutdown_helper() -> None:
    try:
        metadata = os.stat(K3S_SHUTDOWN_HELPER, follow_symlinks=False)
        payload = Path(K3S_SHUTDOWN_HELPER).read_bytes()
    except OSError as exc:
        raise LegacyCutoverError("pinned K3s shutdown helper is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or not metadata.st_mode & stat.S_IXUSR
        or hashlib.sha256(payload).hexdigest() != K3S_SHUTDOWN_HELPER_SHA256
    ):
        raise LegacyCutoverError("pinned K3s shutdown helper failed validation")


def _mountpoint(path: str) -> bool:
    result = _run(["/usr/bin/mountpoint", "-q", "--", path])
    if result.returncode not in {0, 1}:
        raise LegacyCutoverError(f"legacy mount status is unavailable: {path}")
    return result.returncode == 0


def _require_no_mount_holders(path: str) -> None:
    if not _mountpoint(path):
        return
    result = _run(["/usr/bin/fuser", "-m", "--", path])
    if result.returncode == 0:
        raise LegacyCutoverError(f"legacy mount still has open holders: {path}")
    if result.returncode != 1:
        raise LegacyCutoverError(f"legacy mount holders are unavailable: {path}")


def _unmount(path: str) -> None:
    if not _mountpoint(path):
        return
    _require_no_mount_holders(path)
    if _run(["/usr/bin/umount", "--", path]).returncode != 0 or _mountpoint(path):
        raise LegacyCutoverError(f"legacy mount could not be closed: {path}")


def _require_mapper_unmounted(name: str) -> None:
    mapper = f"/dev/mapper/{name}"
    result = _run(["/usr/bin/findmnt", "-rn", "--source", mapper])
    if result.returncode == 0:
        raise LegacyCutoverError(f"legacy mapper remains mounted: {name}")
    if result.returncode != 1:
        raise LegacyCutoverError(f"legacy mapper mount status is unavailable: {name}")


def _require_no_mapper_holders(name: str) -> None:
    mapper = f"/dev/mapper/{name}"
    if not os.path.exists(mapper):
        return
    result = _run(["/usr/bin/fuser", "--", mapper])
    if result.returncode == 0:
        raise LegacyCutoverError(f"legacy mapper still has open holders: {name}")
    if result.returncode != 1:
        raise LegacyCutoverError(f"legacy mapper holders are unavailable: {name}")


def _close_mapper(name: str) -> None:
    mapper = f"/dev/mapper/{name}"
    _require_mapper_unmounted(name)
    _require_no_mapper_holders(name)
    if (
        os.path.exists(mapper)
        and _run(["cryptsetup", "luksClose", name]).returncode != 0
    ):
        raise LegacyCutoverError(f"legacy mapper could not be closed: {name}")
    if os.path.exists(mapper) or _run(["cryptsetup", "status", name]).returncode == 0:
        raise LegacyCutoverError(f"legacy mapper remains open: {name}")


def _require_k3s_quiesced() -> None:
    service = _run(["systemctl", "is-active", "--quiet", "k3s.service"])
    if service.returncode == 0:
        raise LegacyCutoverError("K3s remains active after the shutdown helper")
    if service.returncode != 3:
        raise LegacyCutoverError(
            "K3s service state is unavailable after the shutdown helper"
        )
    shims = _run(
        [
            "pgrep",
            "-f",
            r"/var/lib/rancher/k3s/data/[^/]+/bin/containerd-shim",
        ]
    )
    if shims.returncode == 0:
        raise LegacyCutoverError("K3s container shims remain active")
    if shims.returncode != 1:
        raise LegacyCutoverError("K3s container-shim state is unavailable")


def _require_filesystems_unmounted() -> None:
    for path in _LEGACY_MOUNTS:
        if _mountpoint(path):
            raise LegacyCutoverError(f"legacy mount remains open: {path}")
    _require_mapper_unmounted("storage")
    _require_mapper_unmounted("tdx-cache")


def _require_mappers_closed() -> None:
    _require_filesystems_unmounted()
    for name in ("storage", "tdx-cache"):
        mapper = f"/dev/mapper/{name}"
        if (
            os.path.exists(mapper)
            or _run(["cryptsetup", "status", name]).returncode == 0
        ):
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
        raise LegacyCutoverError(
            "legacy K3s admin kubeconfig is absent or not root-only"
        )
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
            raise LegacyCutoverError(
                "legacy cluster or PostgreSQL secret identity is invalid"
            )
        encoded = secret["data"]["postgres-password"]
        password = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LegacyCutoverError("legacy PostgreSQL credential is invalid") from exc
    if not 16 <= len(password) <= 256 or "\x00" in password:
        raise LegacyCutoverError("legacy PostgreSQL credential has an invalid size")
    return password


def _canonical_json(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _capture_source_state(bundle: dict[str, Any], boot_id: str) -> dict[str, Any]:
    postgres_password = _verified_postgres_password(bundle["kubeconfig_path"])
    storage_device = "/dev/disk/by-label/storage"
    cache_device = "/dev/disk/by-label/tdx-cache"
    storage_mapper = "/dev/mapper/storage"
    cache_mapper = "/dev/mapper/tdx-cache"
    if (
        not os.path.exists(storage_mapper)
        or not os.path.exists(cache_mapper)
        or not _mountpoint("/cache/storage")
        or not _mountpoint("/var/snap")
    ):
        raise LegacyCutoverError(
            "legacy storage and tdx-cache layouts must both be mounted"
        )
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
        "schema": CUTOVER_STATE_SCHEMA,
        "version": CUTOVER_STATE_VERSION,
        "phase": "prepared",
        "boot_id": boot_id,
        "last_boot_id": boot_id,
        "legacy_server_id": bundle["legacy_server_id"],
        "target_host_id": bundle["target_host_id"],
        "connection": {
            "validator_api": bundle["validator_api"].rstrip("/"),
            "cert_path": bundle["cert_path"],
            "key_path": bundle["key_path"],
            "ca_path": bundle["ca_path"],
        },
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
    }


def _closure_document(state: dict[str, Any]) -> dict[str, Any]:
    if state["phase"] != "mappers_closed":
        raise LegacyCutoverError(
            "closure cannot be generated before both mappers are closed"
        )
    _require_mappers_closed()
    return {
        "schema": "chutes.gpu-legacy-close-request",
        "version": 1,
        "cutover_authorization": _load_authorization(state),
        "target_host_id": state["target_host_id"],
        "storage_luks_uuid": state["storage_luks_uuid"],
        "storage_filesystem_uuid": state["storage_filesystem_uuid"],
        "storage_generation": state["storage_generation"],
        "cache_luks_uuid": state["cache_luks_uuid"],
        "cache_filesystem_uuid": state["cache_filesystem_uuid"],
        "cache_filesystem_type": state["cache_filesystem_type"],
        "cache_generation": state["cache_generation"],
        "postgres_password": state["postgres_password"],
        "workloads_stopped": True,
        "postgres_stopped": True,
        "filesystems_synced": True,
        "filesystems_unmounted": True,
        "storage_mapper_closed": True,
        "cache_mapper_closed": True,
    }


def _advance_phase(
    state: dict[str, Any],
    expected: str,
    successor: str,
) -> dict[str, Any]:
    if (
        state.get("phase") != expected
        or CUTOVER_STATE_PHASES.index(successor)
        != CUTOVER_STATE_PHASES.index(expected) + 1
    ):
        raise LegacyCutoverError("cutover phase transition is invalid")
    updated = dict(state)
    updated["phase"] = successor
    _write_private_json(CUTOVER_STATE_PATH, updated)
    return updated


def _require_state_bundle_identity(
    state: dict[str, Any],
    bundle: dict[str, Any],
) -> None:
    if (
        state["legacy_server_id"] != bundle["legacy_server_id"]
        or state["target_host_id"] != bundle["target_host_id"]
        or state["connection"]
        != {
            "validator_api": bundle["validator_api"].rstrip("/"),
            "cert_path": bundle["cert_path"],
            "key_path": bundle["key_path"],
            "ca_path": bundle["ca_path"],
        }
    ):
        raise LegacyCutoverError("persisted cutover state belongs to different custody")


async def run_cutover(bundle_path: str = BUNDLE_PATH) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise LegacyCutoverError("legacy GPU cutover must run as root")
    _verify_host_mount_namespace()
    current_boot_id = _boot_id()
    state = (
        _load_cutover_state(CUTOVER_STATE_PATH)
        if _path_present(CUTOVER_STATE_PATH)
        else None
    )
    if state is not None and state["phase"] == "transfer_acknowledged":
        _unlink_private(CLOSURE_PATH)
        _unlink_private(AUTHORIZATION_PATH)
        _unlink_private(bundle_path)
        if _run(["systemctl", "poweroff", "--no-block"]).returncode != 0:
            raise LegacyCutoverError("legacy guest could not resume final poweroff")
        return state["api_result"]

    _verify_shutdown_helper()
    bundle = _load_bundle(bundle_path) if Path(bundle_path).exists() else None
    if state is None:
        if bundle is None:
            raise LegacyCutoverError("cutover has neither prepared state nor an input bundle")
        _persist_authorization(
            legacy_server_id=bundle["legacy_server_id"],
            target_host_id=bundle["target_host_id"],
            token=bundle["cutover_authorization"],
        )
        try:
            state = _capture_source_state(bundle, current_boot_id)
            _write_private_json(CUTOVER_STATE_PATH, state)
        except Exception:
            if not _path_present(CUTOVER_STATE_PATH):
                _unlink_private(AUTHORIZATION_PATH)
            raise
        _unlink_private(CLOSURE_PATH)
    else:
        if bundle is not None:
            _require_state_bundle_identity(state, bundle)
            _persist_authorization(
                legacy_server_id=state["legacy_server_id"],
                target_host_id=state["target_host_id"],
                token=bundle["cutover_authorization"],
            )
        if state["last_boot_id"] != current_boot_id:
            state = dict(state)
            state["last_boot_id"] = current_boot_id
            _write_private_json(CUTOVER_STATE_PATH, state)

    if state["phase"] == "prepared":
        if _run([K3S_SHUTDOWN_HELPER]).returncode != 0:
            raise LegacyCutoverError("pinned K3s shutdown helper failed")
        _require_k3s_quiesced()
        state = _advance_phase(state, "prepared", "k3s_quiesced")

    if state["phase"] == "k3s_quiesced":
        _require_k3s_quiesced()
        os.sync()
        for path in _LEGACY_MOUNTS:
            _unmount(path)
        os.sync()
        _require_filesystems_unmounted()
        state = _advance_phase(
            state,
            "k3s_quiesced",
            "filesystems_unmounted",
        )

    if state["phase"] == "filesystems_unmounted":
        _require_filesystems_unmounted()
        _close_mapper("storage")
        _close_mapper("tdx-cache")
        os.sync()
        _require_mappers_closed()
        state = _advance_phase(
            state,
            "filesystems_unmounted",
            "mappers_closed",
        )

    if state["phase"] == "mappers_closed":
        _require_mappers_closed()
        expected_closure = _closure_document(state)
        if Path(CLOSURE_PATH).exists():
            closure = _load_closure(CLOSURE_PATH)
            if closure != expected_closure:
                without_authorization = dict(closure)
                without_authorization.pop("cutover_authorization", None)
                expected_without_authorization = dict(expected_closure)
                expected_without_authorization.pop("cutover_authorization", None)
                if without_authorization != expected_without_authorization:
                    raise LegacyCutoverError(
                        "persisted closure differs from closed source evidence"
                    )
                closure = expected_closure
                _write_private_json(CLOSURE_PATH, closure)
        else:
            closure = expected_closure
            _write_private_json(CLOSURE_PATH, closure)

        connection = state["connection"]
        context = ssl.create_default_context(cafile=connection["ca_path"] or None)
        context.load_cert_chain(connection["cert_path"], connection["key_path"])
        connector = aiohttp.TCPConnector(ssl=context)
        target = f"/servers/gpu/{state['legacy_server_id']}/legacy-migration/close"
        async with aiohttp.ClientSession(
            base_url=connection["validator_api"],
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30, connect=10),
        ) as session:
            async with session.post(
                target, json=closure, allow_redirects=False
            ) as response:
                result = await response.json()
                if response.status != 200:
                    raise LegacyCutoverError(
                        f"validator custody transfer failed with HTTP {response.status}"
                    )
        if (
            not isinstance(result, dict)
            or set(result)
            != {"schema", "version", "migration_id", "legacy_server_id", "status"}
            or result.get("schema") != "chutes.gpu-legacy-closed"
            or result.get("version") != 1
            or not isinstance(result.get("migration_id"), str)
            or not result["migration_id"]
            or result.get("legacy_server_id") != state["legacy_server_id"]
            or result.get("status") != "guest_closed"
        ):
            raise LegacyCutoverError("validator returned invalid transfer evidence")
        acknowledged = {
            "schema": CUTOVER_STATE_SCHEMA,
            "version": CUTOVER_STATE_VERSION,
            "phase": "transfer_acknowledged",
            "boot_id": state["boot_id"],
            "last_boot_id": state["last_boot_id"],
            "legacy_server_id": state["legacy_server_id"],
            "target_host_id": state["target_host_id"],
            "closure_sha256": hashlib.sha256(_canonical_json(closure)).hexdigest(),
            "api_result": result,
        }
        _write_private_json(CUTOVER_STATE_PATH, acknowledged)
        _unlink_private(CLOSURE_PATH)
        _unlink_private(AUTHORIZATION_PATH)
        _unlink_private(bundle_path)
        state = acknowledged

    if state["phase"] != "transfer_acknowledged":
        raise LegacyCutoverError("cutover stopped in an unknown phase")
    if _run(["systemctl", "poweroff", "--no-block"]).returncode != 0:
        raise LegacyCutoverError("legacy guest could not begin final poweroff")
    return state["api_result"]


def recover_legacy_cutover() -> None:
    if os.geteuid() != 0:
        raise LegacyCutoverError("legacy GPU recovery must run as root")
    if not Path(CUTOVER_STATE_PATH).is_file():
        raise LegacyCutoverError("no failed legacy cutover requires recovery")
    state = _load_cutover_state(CUTOVER_STATE_PATH)
    if state["phase"] == "mappers_closed":
        raise LegacyCutoverError(
            "exact validator closure must be resumed; reboot is forbidden after mapper closure"
        )
    action = "poweroff" if state["phase"] == "transfer_acknowledged" else "reboot"
    if _run(["systemctl", action, "--no-block"]).returncode != 0:
        raise LegacyCutoverError(f"legacy recovery {action} failed")


def enforce_reboot_fence() -> None:
    """Fail a RequiredBy probe while any transferred-source state remains."""
    if not _path_present(CUTOVER_STATE_PATH):
        return
    state = _load_cutover_state(CUTOVER_STATE_PATH)
    raise LegacyCutoverError(
        "legacy GPU cutover state fences K3s and legacy storage unlock "
        f"through irreversible guest retirement: {state['phase']}"
    )


def run(bundle_path: str = BUNDLE_PATH) -> dict[str, Any]:
    kubeconfig: str | None = None
    try:
        if Path(bundle_path).exists():
            kubeconfig = _load_bundle(bundle_path)["kubeconfig_path"]
        return asyncio.run(run_cutover(bundle_path))
    finally:
        if kubeconfig:
            Path(kubeconfig).unlink(missing_ok=True)
