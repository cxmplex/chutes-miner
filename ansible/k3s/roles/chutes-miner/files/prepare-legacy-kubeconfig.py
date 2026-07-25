#!/usr/bin/env python3
"""Copy verified live K3s admin access into root-only tmpfs."""

import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path

SOURCE = Path("/etc/rancher/k3s/k3s.yaml")
DESTINATION = Path("/run/chutes/legacy-k3s-admin.yaml")


class PreparationError(RuntimeError):
    """The live admin kubeconfig could not be safely copied."""


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
    )


def _metadata(path: Path) -> os.stat_result:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise PreparationError(f"missing kubeconfig: {path}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise PreparationError(f"kubeconfig is not root-only: {path}")
    return metadata


def _cluster_uid(path: Path) -> str:
    ready = _run(
        [
            "kubectl",
            "--kubeconfig",
            str(path),
            "get",
            "--raw=/readyz",
        ]
    )
    if ready.returncode != 0 or ready.stdout.strip() != "ok":
        raise PreparationError(f"kubeconfig is not ready: {path}")
    result = _run(
        [
            "kubectl",
            "--kubeconfig",
            str(path),
            "get",
            "namespace",
            "kube-system",
            "-o",
            "json",
        ]
    )
    try:
        document = json.loads(result.stdout)
        uid = document["metadata"]["uid"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise PreparationError(f"cluster identity is invalid: {path}") from exc
    if (
        result.returncode != 0
        or document["metadata"].get("name") != "kube-system"
        or not isinstance(uid, str)
        or not uid
    ):
        raise PreparationError(f"cluster identity is invalid: {path}")
    return uid


def prepare(source: Path = SOURCE, destination: Path = DESTINATION) -> None:
    _metadata(source)
    source_uid = _cluster_uid(source)
    payload = source.read_bytes()
    if not payload:
        raise PreparationError("live K3s admin kubeconfig is empty")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
    _metadata(destination)
    if _cluster_uid(destination) != source_uid:
        destination.unlink(missing_ok=True)
        raise PreparationError("runtime kubeconfig resolves to another cluster")


if __name__ == "__main__":
    prepare()
