#!/usr/bin/env python3
"""Build the deterministic, unpublished seedless miner-stack OCI archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess  # nosec B404
import tarfile
from pathlib import Path

SOURCE_DATE_EPOCH = 1735689600
IMAGE_NAME = "chutes.local/seedless-stack:1.11.0"


def canonical_bytes(value: dict) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def image_digest(archive: Path) -> str:
    with tarfile.open(archive, "r:") as layout:
        member = layout.getmember("index.json")
        payload = layout.extractfile(member)
        if payload is None:
            raise ValueError("OCI archive has no index payload")
        index = json.loads(payload.read())
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != 1:
        raise ValueError("OCI archive must contain exactly one amd64 image")
    digest = manifests[0].get("digest")
    if (
        not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or len(digest) != 71
    ):
        raise ValueError("OCI archive image digest is invalid")
    return digest


def build(root: Path, archive: Path) -> dict:
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.unlink(missing_ok=True)
    subprocess.run(  # nosec B603 B607 - fixed buildx executable and arguments.
        [
            "docker",
            "buildx",
            "build",
            "--file",
            str(root / "docker/seedless/Dockerfile"),
            "--platform",
            "linux/amd64",
            "--tag",
            IMAGE_NAME,
            "--build-arg",
            f"SOURCE_DATE_EPOCH={SOURCE_DATE_EPOCH}",
            "--provenance=false",
            "--sbom=false",
            "--output",
            f"type=oci,dest={archive},rewrite-timestamp=true",
            str(root),
        ],
        check=True,
        env={**os.environ, "SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH)},
    )
    return {
        "schema": "chutes.seedless-stack-image",
        "version": 1,
        "source_identity": "1.11.0",
        "reference": IMAGE_NAME.split(":", 1)[0] + "@" + image_digest(archive),
        "image_digest": image_digest(archive),
        "archive_sha256": sha256_file(archive),
        "requirements_sha256": sha256_file(root / "docker/seedless/requirements.lock"),
        "dependency_project_sha256": sha256_file(
            root / "docker/seedless/pyproject.toml"
        ),
        "poetry_lock_sha256": sha256_file(root / "docker/seedless/poetry.lock"),
        "dockerfile_sha256": sha256_file(root / "docker/seedless/Dockerfile"),
        "builder_sha256": sha256_file(root / "docker/seedless/build.py"),
        "dockerignore_sha256": sha256_file(root / ".dockerignore"),
        "source_date_epoch": SOURCE_DATE_EPOCH,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--identity-output", required=True, type=Path)
    parser.add_argument("--verify-rebuild", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    first = build(root, args.output.resolve())
    if args.verify_rebuild:
        second_archive = args.output.with_name(f".{args.output.name}.rebuild")
        try:
            second = build(root, second_archive.resolve())
            if first != second:
                raise ValueError("seedless stack rebuild was not byte-identical")
        finally:
            second_archive.unlink(missing_ok=True)
    args.identity_output.parent.mkdir(parents=True, exist_ok=True)
    args.identity_output.write_bytes(canonical_bytes(first))
    print(first["reference"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
