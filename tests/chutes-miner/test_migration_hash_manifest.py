"""Freeze the exact miner migration file set and bytes at first remediation ship."""

import re
from hashlib import sha256
from pathlib import Path


MIGRATIONS = (
    Path(__file__).resolve().parents[2] / "src/chutes-miner/chutes_miner/api/migrations"
)
MANIFEST = MIGRATIONS / "SHA256SUMS"
MANIFEST_LINE = re.compile(
    r"^(?P<digest>[0-9a-f]{64})  (?P<filename>[0-9]{14}_[a-z0-9_]+\.sql)$"
)


def _frozen_hashes() -> dict[str, str]:
    lines = MANIFEST.read_text(encoding="ascii").splitlines()
    assert lines
    frozen: dict[str, str] = {}
    for line in lines:
        match = MANIFEST_LINE.fullmatch(line)
        assert match is not None, f"invalid migration hash manifest line: {line!r}"
        filename = match.group("filename")
        assert filename not in frozen, f"duplicate migration manifest entry: {filename}"
        frozen[filename] = match.group("digest")
    return frozen


def test_miner_migration_file_set_and_bytes_are_frozen():
    frozen = _frozen_hashes()
    migration_files = {path.name: path for path in sorted(MIGRATIONS.glob("*.sql"))}

    assert set(frozen) == set(migration_files), (
        "miner migration file set changed; add new migrations or approve an explicit "
        "first-release manifest update without rewriting shipped migration history"
    )
    actual = {
        filename: sha256(path.read_bytes()).hexdigest()
        for filename, path in migration_files.items()
    }
    mismatches = {
        filename: (frozen[filename], actual[filename])
        for filename in frozen
        if actual[filename] != frozen[filename]
    }
    assert mismatches == {}, f"miner migration bytes changed: {mismatches!r}"
