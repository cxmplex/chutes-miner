import base64
import hashlib
import json
import stat
import threading
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from chutes_miner_cli import legacy_cutover


BOOT_ID = "11111111-2222-3333-4444-555555555555"
ROOT = Path(__file__).resolve().parents[2]


def test_cutover_state_contract_fixture_matches_implementation():
    contract = json.loads(
        (ROOT / "tests/fixtures/legacy_gpu_cutover_state_v1.json").read_text(encoding="ascii")
    )
    assert contract == {
        "acknowledged_fields": sorted(legacy_cutover.CUTOVER_STATE_ACKNOWLEDGED_FIELDS),
        "file_requirements": {
            "mode": "0600",
            "owner_uid": 0,
            "regular_file": True,
            "symlinks": False,
        },
        "path": legacy_cutover.CUTOVER_STATE_PATH,
        "phases": list(legacy_cutover.CUTOVER_STATE_PHASES),
        "schema": legacy_cutover.CUTOVER_STATE_SCHEMA,
        "source_fields": sorted(legacy_cutover.CUTOVER_STATE_SOURCE_FIELDS),
        "version": legacy_cutover.CUTOVER_STATE_VERSION,
    }


def test_cutover_fence_contract_fixture_matches_producer():
    contract = json.loads(
        (ROOT / "tests/fixtures/legacy_gpu_cutover_fence_v1.json").read_text(
            encoding="ascii"
        )
    )
    state = _source_state()
    marker = legacy_cutover._fence_marker_document(state)
    assert contract == {
        "fields": sorted(marker),
        "file_requirements": {
            "mode": "0600",
            "owner_uid": 0,
            "regular_file": True,
            "symlinks": False,
        },
        "path": legacy_cutover.CUTOVER_FENCE_MARKER_PATH,
        "pending_state_path": legacy_cutover.CUTOVER_FENCE_PENDING_STATE_PATH,
        "schema": legacy_cutover.CUTOVER_FENCE_MARKER_SCHEMA,
        "state_identity_fields": sorted(marker["state_identity"]),
        "state_identity_schema": legacy_cutover.CUTOVER_STATE_SCHEMA,
        "state_identity_version": legacy_cutover.CUTOVER_STATE_VERSION,
        "state_path": legacy_cutover.CUTOVER_FENCE_STATE_PATH,
        "version": legacy_cutover.CUTOVER_FENCE_MARKER_VERSION,
    }


def _bundle() -> dict:
    return {
        "validator_api": "https://validator.example",
        "cutover_authorization": "authorization",
        "legacy_server_id": "legacy-server",
        "target_host_id": "host-1",
        "cert_path": "/cert",
        "key_path": "/key",
        "ca_path": "",
        "kubeconfig_path": "/run/chutes/legacy-k3s-admin.yaml",
    }


def _source_state(phase: str = "prepared") -> dict:
    return {
        "schema": "chutes.legacy-gpu-cutover-state",
        "version": 1,
        "phase": phase,
        "boot_id": BOOT_ID,
        "last_boot_id": BOOT_ID,
        "legacy_server_id": "legacy-server",
        "target_host_id": "host-1",
        "connection": {
            "validator_api": "https://validator.example",
            "cert_path": "/cert",
            "key_path": "/key",
            "ca_path": "",
        },
        "storage_luks_uuid": "storage-luks",
        "storage_filesystem_uuid": "storage-fs",
        "storage_generation": 4,
        "cache_luks_uuid": "cache-luks",
        "cache_filesystem_uuid": "cache-fs",
        "cache_filesystem_type": "xfs",
        "cache_generation": 9,
        "postgres_password": "stable-postgres-password",
    }


def _acknowledged_state() -> dict:
    return {
        "schema": "chutes.legacy-gpu-cutover-state",
        "version": 1,
        "phase": "transfer_acknowledged",
        "boot_id": BOOT_ID,
        "last_boot_id": BOOT_ID,
        "legacy_server_id": "legacy-server",
        "target_host_id": "host-1",
        "closure_sha256": "a" * 64,
        "api_result": {
            "schema": "chutes.gpu-legacy-closed",
            "version": 1,
            "migration_id": "migration-1",
            "legacy_server_id": "legacy-server",
            "status": "guest_closed",
        },
    }


def _patch_fence(monkeypatch, tmp_path, state: dict | None = None):
    marker_path = tmp_path / "root-fence" / "fence.json"
    monkeypatch.setattr(
        legacy_cutover,
        "CUTOVER_FENCE_MARKER_PATH",
        str(marker_path),
    )
    if state is not None:
        legacy_cutover._write_private_json(
            str(marker_path),
            legacy_cutover._fence_marker_document(state),
        )

    def load_marker(path=None):
        return json.loads(
            Path(path or marker_path).read_text(encoding="ascii")
        )

    # The production loader requires uid 0. Pytest's private temporary files
    # are owned by the unprivileged test runner, so flow tests use the same
    # bytes while the loader's schema and file-safety checks are tested alone.
    monkeypatch.setattr(
        legacy_cutover,
        "_load_cutover_fence_marker",
        load_marker,
    )
    return marker_path


def _patch_runtime(monkeypatch, tmp_path, state: dict | None = None):
    durable_dir = tmp_path / "separate-var" / "legacy-gpu-cutover"
    state_path = durable_dir / "state.json"
    pending_state_path = durable_dir / "state.pending.json"
    closure_path = durable_dir / "closure.json"
    authorization_path = durable_dir / "authorization.json"
    source_absence_path = durable_dir / "source-absence.json"
    lock_path = durable_dir / "operation.lock"
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text("bundle", encoding="ascii")
    monkeypatch.setattr(legacy_cutover, "BUNDLE_PATH", str(bundle_path))
    monkeypatch.setattr(legacy_cutover, "CUTOVER_STATE_PATH", str(state_path))
    monkeypatch.setattr(
        legacy_cutover,
        "CUTOVER_PENDING_STATE_PATH",
        str(pending_state_path),
    )
    monkeypatch.setattr(legacy_cutover, "CUTOVER_LOCK_PATH", str(lock_path))
    monkeypatch.setattr(legacy_cutover, "CLOSURE_PATH", str(closure_path))
    monkeypatch.setattr(legacy_cutover, "AUTHORIZATION_PATH", str(authorization_path))
    monkeypatch.setattr(
        legacy_cutover,
        "K3S_ADMIN_KUBECONFIG",
        str(durable_dir / "admin.yaml"),
    )
    monkeypatch.setattr(
        legacy_cutover,
        "CUTOVER_SOURCE_ABSENCE_PATH",
        str(source_absence_path),
    )
    _patch_fence(monkeypatch, tmp_path, state)
    legacy_cutover._persist_authorization(
        legacy_server_id="legacy-server",
        target_host_id="host-1",
        token="authorization",
    )
    monkeypatch.setattr(
        legacy_cutover, "_load_authorization", lambda _state: "authorization"
    )
    monkeypatch.setattr(legacy_cutover.os, "geteuid", lambda: 0)
    monkeypatch.setattr(legacy_cutover.os, "sync", lambda: None)
    monkeypatch.setattr(legacy_cutover, "_verify_host_mount_namespace", lambda: None)
    monkeypatch.setattr(legacy_cutover, "_verify_shutdown_helper", lambda: None)
    monkeypatch.setattr(legacy_cutover, "_boot_id", lambda: BOOT_ID)
    monkeypatch.setattr(legacy_cutover, "_load_bundle", lambda _path: _bundle())
    monkeypatch.setattr(
        legacy_cutover,
        "_capture_source_state",
        lambda _bundle_value, _boot: _source_state(),
    )
    monkeypatch.setattr(legacy_cutover, "_require_k3s_quiesced", lambda: None)
    monkeypatch.setattr(legacy_cutover, "_require_filesystems_unmounted", lambda: None)
    monkeypatch.setattr(
        legacy_cutover,
        "_generation",
        lambda root: 4 if root == "/cache/storage" else 9,
    )
    monkeypatch.setattr(legacy_cutover, "_require_mappers_closed", lambda: None)
    if state is not None:
        legacy_cutover._write_private_json(str(state_path), state)

    def load_state(path=None):
        return json.loads(
            Path(path or state_path).read_text(encoding="ascii")
        )

    monkeypatch.setattr(legacy_cutover, "_load_cutover_state", load_state)
    return state_path, closure_path, bundle_path


def test_root_fence_marker_authenticates_exact_full_state_bytes():
    state = _source_state("filesystems_unmounted")
    marker = legacy_cutover._fence_marker_document(state)
    identity = {
        "schema": "chutes.legacy-gpu-cutover-state",
        "version": 1,
        "boot_id": BOOT_ID,
        "legacy_server_id": "legacy-server",
        "target_host_id": "host-1",
    }
    expected_hash = hashlib.sha256(
        legacy_cutover._canonical_private_json(state)
    ).hexdigest()

    assert marker == {
        "schema": "chutes.legacy-gpu-cutover-fence",
        "version": 1,
        "state_path": "/var/lib/chutes/legacy-gpu-cutover/state.json",
        "pending_state_path": (
            "/var/lib/chutes/legacy-gpu-cutover/state.pending.json"
        ),
        "state_identity": identity,
        "current_state_sha256": expected_hash,
        "pending_state_sha256": None,
    }
    changed = deepcopy(state)
    changed["storage_generation"] += 1
    assert legacy_cutover._fence_marker_document(changed) != marker


def test_missing_root_fence_is_repaired_only_for_prepared_state(
    monkeypatch,
    tmp_path,
):
    state_path, _closure_path, _bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("prepared"),
    )
    marker_path = Path(legacy_cutover.CUTOVER_FENCE_MARKER_PATH)
    marker_path.unlink()
    state, marker = legacy_cutover._reconcile_cutover_fence(
        json.loads(state_path.read_text(encoding="ascii")),
        repair_prepared=True,
    )
    assert marker_path.exists()
    assert marker == legacy_cutover._fence_marker_document(state)

    marker_path.unlink()
    later = _source_state("k3s_quiesced")
    legacy_cutover._write_private_json(str(state_path), later)
    with pytest.raises(
        legacy_cutover.LegacyCutoverError,
        match="missing after destructive action",
    ):
        legacy_cutover._reconcile_cutover_fence(
            later,
            repair_prepared=True,
        )
    assert not marker_path.exists()


def test_root_fence_rejects_different_durable_state_identity(monkeypatch, tmp_path):
    state_path, _closure_path, _bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state(),
    )
    changed = _source_state()
    changed["target_host_id"] = "host-2"
    legacy_cutover._write_private_json(str(state_path), changed)
    with pytest.raises(
        legacy_cutover.LegacyCutoverError,
        match="not authenticated|different recovery state",
    ):
        legacy_cutover._reconcile_cutover_fence(changed)


def test_root_fence_loader_rejects_changed_state_hash(monkeypatch):
    marker = legacy_cutover._fence_marker_document(_source_state())
    marker["current_state_sha256"] = "not-a-sha256"
    monkeypatch.setattr(
        legacy_cutover,
        "_load_private_json",
        lambda _path, _label: marker,
    )
    with pytest.raises(
        legacy_cutover.LegacyCutoverError,
        match="identity is invalid",
    ):
        legacy_cutover._load_cutover_fence_marker("unused")


def test_state_loader_rejects_semantically_equal_noncanonical_bytes(
    monkeypatch,
    tmp_path,
):
    state = _source_state()
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps(state, indent=2), encoding="ascii")
    monkeypatch.setattr(
        legacy_cutover,
        "_load_private_json",
        lambda _path, _label: deepcopy(state),
    )
    with pytest.raises(legacy_cutover.LegacyCutoverError, match="not canonical"):
        legacy_cutover._load_cutover_state(str(state_path))


@pytest.mark.parametrize(
    ("operation", "side"),
    [
        ("pending_state_write", "before"),
        ("pending_state_write", "after"),
        ("transition_marker_write", "before"),
        ("transition_marker_write", "after"),
        ("state_promotion", "before"),
        ("state_promotion", "after"),
        ("stable_marker_write", "before"),
        ("stable_marker_write", "after"),
    ],
)
def test_state_transition_recovers_every_cross_filesystem_crash_boundary(
    monkeypatch,
    tmp_path,
    operation,
    side,
):
    state_path, _closure_path, _bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("prepared"),
    )
    current = json.loads(state_path.read_text(encoding="ascii"))
    successor = deepcopy(current)
    successor["phase"] = "k3s_quiesced"
    real_write = legacy_cutover._write_private_json
    real_promote = legacy_cutover._promote_private_file
    crashed = False

    def maybe_crash(label, action):
        nonlocal crashed
        if label != operation or crashed:
            return action()
        crashed = True
        if side == "before":
            raise RuntimeError(f"crash before {label}")
        action()
        raise RuntimeError(f"crash after {label}")

    def crash_write(path, document):
        if path == legacy_cutover.CUTOVER_PENDING_STATE_PATH:
            label = "pending_state_write"
        elif (
            path == legacy_cutover.CUTOVER_FENCE_MARKER_PATH
            and document.get("pending_state_sha256") is not None
        ):
            label = "transition_marker_write"
        elif path == legacy_cutover.CUTOVER_FENCE_MARKER_PATH:
            label = "stable_marker_write"
        else:
            return real_write(path, document)
        return maybe_crash(label, lambda: real_write(path, document))

    def crash_promote(source, destination):
        return maybe_crash(
            "state_promotion",
            lambda: real_promote(source, destination),
        )

    monkeypatch.setattr(legacy_cutover, "_write_private_json", crash_write)
    monkeypatch.setattr(legacy_cutover, "_promote_private_file", crash_promote)
    with pytest.raises(RuntimeError, match=f"crash .* {operation}"):
        legacy_cutover._persist_state_transition(current, successor)
    assert crashed

    monkeypatch.setattr(legacy_cutover, "_write_private_json", real_write)
    monkeypatch.setattr(legacy_cutover, "_promote_private_file", real_promote)
    recovered = json.loads(state_path.read_text(encoding="ascii"))
    recovered, marker = legacy_cutover._reconcile_cutover_fence(recovered)
    if recovered != successor:
        recovered = legacy_cutover._persist_state_transition(recovered, successor)
        marker = legacy_cutover._load_cutover_fence_marker()

    assert recovered == successor
    assert marker == legacy_cutover._fence_marker_document(successor)
    assert not Path(legacy_cutover.CUTOVER_PENDING_STATE_PATH).exists()
    assert state_path.read_bytes() == legacy_cutover._canonical_private_json(successor)


@pytest.mark.parametrize("side", ["before", "after"])
def test_initial_prepared_state_write_is_crash_safe_before_fencing(
    monkeypatch,
    tmp_path,
    side,
):
    state_path, _closure_path, _bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
    )
    state = _source_state("prepared")
    real_write = legacy_cutover._write_private_json
    crashed = False

    def crash_state(path, document):
        nonlocal crashed
        if path != legacy_cutover.CUTOVER_STATE_PATH or crashed:
            return real_write(path, document)
        crashed = True
        if side == "before":
            raise RuntimeError("crash before initial state")
        real_write(path, document)
        raise RuntimeError("crash after initial state")

    monkeypatch.setattr(legacy_cutover, "_write_private_json", crash_state)
    with pytest.raises(RuntimeError, match="crash .* initial state"):
        legacy_cutover._write_private_json(
            legacy_cutover.CUTOVER_STATE_PATH,
            state,
        )
    assert not Path(legacy_cutover.CUTOVER_FENCE_MARKER_PATH).exists()

    monkeypatch.setattr(legacy_cutover, "_write_private_json", real_write)
    if not state_path.exists():
        legacy_cutover._write_private_json(legacy_cutover.CUTOVER_STATE_PATH, state)
    recovered, marker = legacy_cutover._reconcile_cutover_fence(
        state,
        repair_prepared=True,
    )
    assert recovered == state
    assert marker == legacy_cutover._fence_marker_document(state)


@pytest.mark.parametrize("side", ["before", "after"])
def test_initial_prepared_marker_write_is_crash_repairable(
    monkeypatch,
    tmp_path,
    side,
):
    state_path, _closure_path, _bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("prepared"),
    )
    marker_path = Path(legacy_cutover.CUTOVER_FENCE_MARKER_PATH)
    marker_path.unlink()
    state = json.loads(state_path.read_text(encoding="ascii"))
    real_write = legacy_cutover._write_private_json
    crashed = False

    def crash_marker(path, document):
        nonlocal crashed
        if path != legacy_cutover.CUTOVER_FENCE_MARKER_PATH or crashed:
            return real_write(path, document)
        crashed = True
        if side == "before":
            raise RuntimeError("crash before initial marker")
        real_write(path, document)
        raise RuntimeError("crash after initial marker")

    monkeypatch.setattr(legacy_cutover, "_write_private_json", crash_marker)
    with pytest.raises(RuntimeError, match="crash .* initial marker"):
        legacy_cutover._reconcile_cutover_fence(state, repair_prepared=True)
    monkeypatch.setattr(legacy_cutover, "_write_private_json", real_write)

    recovered, marker = legacy_cutover._reconcile_cutover_fence(
        state,
        repair_prepared=True,
    )
    assert recovered == state
    assert marker == legacy_cutover._fence_marker_document(state)


def test_authenticated_marker_rejects_canonical_nonidentity_state_tamper(
    monkeypatch,
    tmp_path,
):
    state_path, _closure_path, _bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("prepared"),
    )
    tampered = _source_state("prepared")
    tampered["storage_generation"] += 1
    legacy_cutover._write_private_json(str(state_path), tampered)
    with pytest.raises(
        legacy_cutover.LegacyCutoverError,
        match="not authenticated",
    ):
        legacy_cutover._reconcile_cutover_fence(tampered)


def test_source_absence_is_durable_before_root_fence_is_cleared(
    monkeypatch,
    tmp_path,
):
    state_path, _closure_path, _bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _acknowledged_state(),
    )
    events = []
    real_write = legacy_cutover._write_private_json
    real_unlink = legacy_cutover._unlink_private

    def record_write(path, document):
        if path == legacy_cutover.CUTOVER_SOURCE_ABSENCE_PATH:
            events.append("absence-durable")
        return real_write(path, document)

    def record_unlink(path):
        if path == legacy_cutover.CUTOVER_FENCE_MARKER_PATH:
            events.append("fence-cleared")
        return real_unlink(path)

    monkeypatch.setattr(legacy_cutover, "_write_private_json", record_write)
    monkeypatch.setattr(legacy_cutover, "_unlink_private", record_unlink)
    state = json.loads(state_path.read_text(encoding="ascii"))
    assert legacy_cutover._finalize_acknowledged_source(state) is True

    absence = json.loads(
        Path(legacy_cutover.CUTOVER_SOURCE_ABSENCE_PATH).read_text(encoding="ascii")
    )
    assert events == ["absence-durable", "fence-cleared"]
    assert absence["state_sha256"] == legacy_cutover._state_sha256(state)
    assert absence["closure_sha256"] == state["closure_sha256"]
    assert not Path(legacy_cutover.CUTOVER_FENCE_MARKER_PATH).exists()


def test_attached_source_keeps_root_fence_after_transfer_ack(monkeypatch, tmp_path):
    state_path, _closure_path, _bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _acknowledged_state(),
    )
    real_present = legacy_cutover._path_present
    monkeypatch.setattr(
        legacy_cutover,
        "_path_present",
        lambda path: True
        if path in legacy_cutover._LEGACY_SOURCE_DEVICES
        else real_present(path),
    )
    state = json.loads(state_path.read_text(encoding="ascii"))
    assert legacy_cutover._finalize_acknowledged_source(state) is False
    assert Path(legacy_cutover.CUTOVER_FENCE_MARKER_PATH).exists()
    assert not Path(legacy_cutover.CUTOVER_SOURCE_ABSENCE_PATH).exists()


@pytest.mark.parametrize(
    ("operation", "side"),
    [
        ("absence_write", "before"),
        ("absence_write", "after"),
        ("fence_clear", "before"),
        ("fence_clear", "after"),
    ],
)
def test_source_fence_release_recovers_every_crash_boundary(
    monkeypatch,
    tmp_path,
    operation,
    side,
):
    state_path, _closure_path, _bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _acknowledged_state(),
    )
    state = json.loads(state_path.read_text(encoding="ascii"))
    real_write = legacy_cutover._write_private_json
    real_unlink = legacy_cutover._unlink_private
    crashed = False

    def maybe_crash(label, action):
        nonlocal crashed
        if label != operation or crashed:
            return action()
        crashed = True
        if side == "before":
            raise RuntimeError(f"crash before {label}")
        action()
        raise RuntimeError(f"crash after {label}")

    def crash_write(path, document):
        if path == legacy_cutover.CUTOVER_SOURCE_ABSENCE_PATH:
            return maybe_crash(
                "absence_write",
                lambda: real_write(path, document),
            )
        return real_write(path, document)

    def crash_unlink(path):
        if path == legacy_cutover.CUTOVER_FENCE_MARKER_PATH:
            return maybe_crash("fence_clear", lambda: real_unlink(path))
        return real_unlink(path)

    monkeypatch.setattr(legacy_cutover, "_write_private_json", crash_write)
    monkeypatch.setattr(legacy_cutover, "_unlink_private", crash_unlink)
    with pytest.raises(RuntimeError, match=f"crash .* {operation}"):
        legacy_cutover._finalize_acknowledged_source(state)
    assert crashed

    monkeypatch.setattr(legacy_cutover, "_write_private_json", real_write)
    monkeypatch.setattr(legacy_cutover, "_unlink_private", real_unlink)

    def load_absence(reloaded):
        document = json.loads(
            Path(legacy_cutover.CUTOVER_SOURCE_ABSENCE_PATH).read_text(
                encoding="ascii"
            )
        )
        assert document == legacy_cutover._source_absence_document(reloaded)
        return document

    monkeypatch.setattr(legacy_cutover, "_load_source_absence", load_absence)
    assert legacy_cutover._finalize_acknowledged_source(state) is True
    assert not Path(legacy_cutover.CUTOVER_FENCE_MARKER_PATH).exists()
    assert Path(legacy_cutover.CUTOVER_SOURCE_ABSENCE_PATH).exists()


def _patch_tls(monkeypatch):
    class Context:
        def load_cert_chain(self, _cert, _key):
            return None

    monkeypatch.setattr(
        legacy_cutover.ssl,
        "create_default_context",
        lambda **_kwargs: Context(),
    )
    monkeypatch.setattr(
        legacy_cutover.aiohttp,
        "TCPConnector",
        lambda **_kwargs: object(),
    )


def _patch_successful_api(monkeypatch, events, posted):
    class Response:
        status = 200

        async def __aenter__(self):
            events.append("api")
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {
                "schema": "chutes.gpu-legacy-closed",
                "version": 1,
                "migration_id": "migration-1",
                "legacy_server_id": "legacy-server",
                "status": "guest_closed",
            }

    class Session:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def post(self, _target, *, json, **_kwargs):
            posted.append(deepcopy(json))
            return Response()

    monkeypatch.setattr(legacy_cutover.aiohttp, "ClientSession", Session)


@pytest.mark.asyncio
async def test_cutover_journals_before_quiesce_and_closes_before_api(
    monkeypatch, tmp_path
):
    state_path, closure_path, bundle_path = _patch_runtime(monkeypatch, tmp_path)
    events = []
    posted = []
    _patch_tls(monkeypatch)
    _patch_successful_api(monkeypatch, events, posted)

    def run(argv):
        if argv == [legacy_cutover.K3S_SHUTDOWN_HELPER]:
            prepared = json.loads(state_path.read_text(encoding="ascii"))
            assert prepared["phase"] == "prepared"
            marker = legacy_cutover._load_cutover_fence_marker()
            assert marker == legacy_cutover._fence_marker_document(prepared)
            events.append("k3s-helper")
        elif argv == ["systemctl", "poweroff", "--no-block"]:
            events.append("poweroff")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(legacy_cutover, "_run", run)
    monkeypatch.setattr(
        legacy_cutover,
        "_unmount",
        lambda path: events.append(f"unmount:{path}"),
    )
    monkeypatch.setattr(
        legacy_cutover,
        "_close_mapper",
        lambda name: events.append(f"close:{name}"),
    )
    original_closure = legacy_cutover._closure_document

    def closure_after_postconditions(state):
        assert "close:storage" in events
        assert "close:tdx-cache" in events
        return original_closure(state)

    monkeypatch.setattr(
        legacy_cutover, "_closure_document", closure_after_postconditions
    )
    result = await legacy_cutover.run_cutover(str(bundle_path))

    assert result["status"] == "guest_closed"
    assert events.index("k3s-helper") < events.index("unmount:/cache/storage")
    assert events.index("close:storage") < events.index("api")
    assert events.index("close:tdx-cache") < events.index("api")
    assert events[-1] == "poweroff"
    assert len(posted) == 1
    assert posted[0]["filesystems_unmounted"] is True
    assert json.loads(state_path.read_text(encoding="ascii"))["phase"] == (
        "transfer_acknowledged"
    )
    assert "postgres_password" not in state_path.read_text(encoding="ascii")
    assert not closure_path.exists()
    assert not bundle_path.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("phase", "expected"),
    [
        ("k3s_quiesced", ["unmount", "close", "api"]),
        ("filesystems_unmounted", ["close", "api"]),
        ("mappers_closed", ["api"]),
    ],
)
async def test_restart_resumes_each_phase_without_repeating_prior_work(
    monkeypatch,
    tmp_path,
    phase,
    expected,
):
    _state_path, _closure_path, bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state(phase),
    )
    events = []
    posted = []
    _patch_tls(monkeypatch)
    _patch_successful_api(monkeypatch, events, posted)
    monkeypatch.setattr(
        legacy_cutover,
        "_run",
        lambda argv: SimpleNamespace(
            returncode=0,
            stdout="",
            stderr="",
        ),
    )
    monkeypatch.setattr(
        legacy_cutover, "_unmount", lambda _path: events.append("unmount")
    )
    monkeypatch.setattr(
        legacy_cutover, "_close_mapper", lambda _name: events.append("close")
    )

    await legacy_cutover.run_cutover(str(bundle_path))
    condensed = []
    for event in events:
        if event not in condensed:
            condensed.append(event)
    assert condensed == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "phase",
    ["prepared", "k3s_quiesced", "filesystems_unmounted", "mappers_closed"],
)
async def test_reboot_resumes_every_phase_without_ephemeral_bundle(
    monkeypatch,
    tmp_path,
    phase,
):
    state_path, _closure_path, bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state(phase),
    )
    bundle_path.unlink()
    new_boot_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    monkeypatch.setattr(legacy_cutover, "_boot_id", lambda: new_boot_id)
    monkeypatch.setattr(
        legacy_cutover,
        "_capture_source_state",
        lambda *_args: pytest.fail("cross-boot recovery recaptured mutable source state"),
    )
    monkeypatch.setattr(
        legacy_cutover,
        "_run",
        lambda _argv: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(legacy_cutover, "_unmount", lambda _path: None)
    monkeypatch.setattr(legacy_cutover, "_close_mapper", lambda _name: None)
    _patch_tls(monkeypatch)
    _patch_successful_api(monkeypatch, [], [])

    await legacy_cutover.run_cutover(str(bundle_path))
    persisted = json.loads(state_path.read_text(encoding="ascii"))
    assert persisted["phase"] == "transfer_acknowledged"
    assert persisted["boot_id"] == BOOT_ID
    assert persisted["last_boot_id"] == new_boot_id


@pytest.mark.asyncio
async def test_authorization_rebind_rewrites_only_token_in_persisted_closure(
    monkeypatch,
    tmp_path,
):
    state_path, closure_path, bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("mappers_closed"),
    )
    bundle_path.unlink()
    old_closure = {
        **legacy_cutover._closure_document(_source_state("mappers_closed")),
        "cutover_authorization": "old-authorization",
    }
    closure_path.write_text(json.dumps(old_closure), encoding="ascii")
    monkeypatch.setattr(
        legacy_cutover,
        "_load_closure",
        lambda path: json.loads(Path(path).read_text(encoding="ascii")),
    )
    monkeypatch.setattr(
        legacy_cutover, "_load_authorization", lambda _state: "new-authorization"
    )
    monkeypatch.setattr(
        legacy_cutover,
        "_run",
        lambda _argv: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    posted = []
    _patch_tls(monkeypatch)
    _patch_successful_api(monkeypatch, [], posted)

    await legacy_cutover.run_cutover(str(bundle_path))
    assert posted[0]["cutover_authorization"] == "new-authorization"
    for key, value in old_closure.items():
        if key != "cutover_authorization":
            assert posted[0][key] == value
    assert json.loads(state_path.read_text(encoding="ascii"))["phase"] == (
        "transfer_acknowledged"
    )


def test_rebind_persists_one_canonical_authorization_envelope(monkeypatch, tmp_path):
    _state_path, _closure_path, _bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("mappers_closed"),
    )

    legacy_cutover.rebind_closure_authorization("replacement-token")
    envelope = json.loads(
        Path(legacy_cutover.AUTHORIZATION_PATH).read_text(encoding="ascii")
    )
    assert envelope == {
        "schema": "chutes.legacy-gpu-cutover-authorization-envelope",
        "version": 1,
        "legacy_server_id": "legacy-server",
        "target_host_id": "host-1",
        "cutover_authorization": "replacement-token",
    }


def test_persist_cutover_bundle_rebinds_under_one_operation_lock(
    monkeypatch,
    tmp_path,
):
    _state_path, _closure_path, bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("prepared"),
    )
    bundle = _bundle() | {"cutover_authorization": "replacement-token"}
    monkeypatch.setattr(
        legacy_cutover,
        "_load_bundle",
        lambda path: json.loads(Path(path).read_text(encoding="ascii")),
    )

    legacy_cutover.persist_cutover_bundle(bundle)

    assert json.loads(bundle_path.read_text(encoding="ascii")) == bundle
    envelope = json.loads(
        Path(legacy_cutover.AUTHORIZATION_PATH).read_text(encoding="ascii")
    )
    assert envelope["cutover_authorization"] == "replacement-token"


def test_authorization_rebind_waits_for_state_transition_barrier(
    monkeypatch,
    tmp_path,
):
    state = _source_state("prepared")
    state_path, _closure_path, _bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        state,
    )
    pending_written = threading.Event()
    allow_transition = threading.Event()
    rebind_finished = threading.Event()
    errors = []
    real_write = legacy_cutover._write_private_json

    def barrier_write(path, document):
        real_write(path, document)
        if (
            path == legacy_cutover.CUTOVER_PENDING_STATE_PATH
            and document.get("phase") == "k3s_quiesced"
        ):
            pending_written.set()
            if not allow_transition.wait(5):
                raise AssertionError("state transition barrier timed out")

    monkeypatch.setattr(legacy_cutover, "_write_private_json", barrier_write)

    def transition_worker():
        try:
            with legacy_cutover._cutover_lock():
                updated = dict(state)
                updated["phase"] = "k3s_quiesced"
                legacy_cutover._persist_state_transition(state, updated)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    def rebind_worker():
        try:
            legacy_cutover.rebind_closure_authorization("replacement-token")
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
        finally:
            rebind_finished.set()

    transition_thread = threading.Thread(target=transition_worker)
    rebind_thread = threading.Thread(target=rebind_worker)
    transition_thread.start()
    assert pending_written.wait(5)
    rebind_thread.start()
    assert not rebind_finished.wait(0.2)
    assert Path(legacy_cutover.CUTOVER_PENDING_STATE_PATH).exists()

    allow_transition.set()
    transition_thread.join(5)
    rebind_thread.join(5)
    assert not transition_thread.is_alive()
    assert not rebind_thread.is_alive()
    assert errors == []
    assert json.loads(state_path.read_text(encoding="ascii"))["phase"] == (
        "k3s_quiesced"
    )
    marker = json.loads(
        Path(legacy_cutover.CUTOVER_FENCE_MARKER_PATH).read_text(encoding="ascii")
    )
    assert marker["pending_state_sha256"] is None
    assert not Path(legacy_cutover.CUTOVER_PENDING_STATE_PATH).exists()
    envelope = json.loads(
        Path(legacy_cutover.AUTHORIZATION_PATH).read_text(encoding="ascii")
    )
    assert envelope["cutover_authorization"] == "replacement-token"


def test_durable_cutover_reauthorization_does_not_require_live_kubeconfig(
    monkeypatch,
    tmp_path,
):
    _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("mappers_closed"),
    )
    monkeypatch.setattr(
        legacy_cutover,
        "_verified_postgres_password",
        lambda _path: pytest.fail("durable reauthorization touched kubeconfig"),
    )

    legacy_cutover.require_cutover_initiation_access()


def test_new_cutover_after_terminal_abort_requires_reboot_for_runtime_kubeconfig(
    monkeypatch,
    tmp_path,
):
    state_path, _closure_path, _bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("prepared"),
    )
    state_path.unlink()
    Path(legacy_cutover.CUTOVER_FENCE_MARKER_PATH).unlink()

    def unavailable(_path):
        raise legacy_cutover.LegacyCutoverError("runtime copy is absent")

    monkeypatch.setattr(
        legacy_cutover,
        "_verified_postgres_password",
        unavailable,
    )

    with pytest.raises(
        legacy_cutover.LegacyCutoverError,
        match="reboot the live source",
    ):
        legacy_cutover.require_cutover_initiation_access()


def test_acknowledged_state_rejects_noncontract_api_receipt_fields(monkeypatch):
    state = _acknowledged_state()
    state["api_result"]["unexpected"] = "must-not-persist"
    monkeypatch.setattr(
        legacy_cutover,
        "_load_private_json",
        lambda _path, _label: state,
    )
    with pytest.raises(
        legacy_cutover.LegacyCutoverError,
        match="transfer acknowledgement is malformed",
    ):
        legacy_cutover._load_cutover_state("unused")


@pytest.mark.asyncio
async def test_lost_api_response_replays_exact_persisted_closure(monkeypatch, tmp_path):
    state_path, closure_path, bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("mappers_closed"),
    )
    monkeypatch.setattr(
        legacy_cutover,
        "_load_closure",
        lambda path: json.loads(Path(path).read_text(encoding="ascii")),
    )
    _patch_tls(monkeypatch)
    posts = []
    attempts = 0

    class Response:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {
                "schema": "chutes.gpu-legacy-closed",
                "version": 1,
                "migration_id": "migration-1",
                "legacy_server_id": "legacy-server",
                "status": "guest_closed",
            }

    class Session:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def post(self, _target, *, json, **_kwargs):
            nonlocal attempts
            attempts += 1
            posts.append(deepcopy(json))
            if attempts == 1:
                raise ConnectionError("response lost")
            return Response()

    monkeypatch.setattr(legacy_cutover.aiohttp, "ClientSession", Session)
    monkeypatch.setattr(
        legacy_cutover,
        "_run",
        lambda _argv: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    with pytest.raises(ConnectionError, match="response lost"):
        await legacy_cutover.run_cutover(str(bundle_path))
    assert closure_path.exists()
    assert (
        json.loads(state_path.read_text(encoding="ascii"))["phase"] == "mappers_closed"
    )

    await legacy_cutover.run_cutover(str(bundle_path))
    assert posts[0] == posts[1]
    assert json.loads(state_path.read_text(encoding="ascii"))["phase"] == (
        "transfer_acknowledged"
    )


@pytest.mark.parametrize(
    ("state", "action"),
    [(_source_state("prepared"), "reboot"), (_acknowledged_state(), "poweroff")],
)
def test_recovery_action_depends_on_api_ack(monkeypatch, tmp_path, state, action):
    _state_path, _closure_path, _bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        state,
    )
    monkeypatch.setattr(legacy_cutover.os, "geteuid", lambda: 0)
    calls = []
    monkeypatch.setattr(
        legacy_cutover,
        "_run",
        lambda argv: calls.append(argv)
        or SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    legacy_cutover.recover_legacy_cutover()
    assert calls == [["systemctl", action, "--no-block"]]


def test_recovery_cannot_reopen_source_after_closure_may_have_reached_api(
    monkeypatch,
    tmp_path,
):
    _state_path, _closure_path, _bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("mappers_closed"),
    )
    monkeypatch.setattr(legacy_cutover.os, "geteuid", lambda: 0)
    calls = []
    monkeypatch.setattr(legacy_cutover, "_run", lambda argv: calls.append(argv))

    with pytest.raises(legacy_cutover.LegacyCutoverError, match="reboot is forbidden"):
        legacy_cutover.recover_legacy_cutover()
    assert calls == []


@pytest.mark.parametrize(
    "state",
    [
        _source_state("prepared"),
        _source_state("k3s_quiesced"),
        _source_state("filesystems_unmounted"),
        _source_state("mappers_closed"),
        _acknowledged_state(),
    ],
)
def test_reboot_fence_blocks_storage_and_k3s_until_guest_retirement(
    monkeypatch,
    tmp_path,
    state,
):
    _patch_fence(monkeypatch, tmp_path, state)
    with pytest.raises(legacy_cutover.LegacyCutoverError, match="fences K3s"):
        legacy_cutover.enforce_reboot_fence()


def test_early_reboot_fence_never_reads_separate_var_state(monkeypatch, tmp_path):
    _patch_fence(monkeypatch, tmp_path, _source_state("mappers_closed"))
    monkeypatch.setattr(
        legacy_cutover,
        "_load_cutover_state",
        lambda *_args: pytest.fail("early fence tried to read unmounted /var"),
    )
    with pytest.raises(legacy_cutover.LegacyCutoverError, match="fences K3s"):
        legacy_cutover.enforce_reboot_fence()


def test_pending_transition_fences_while_separate_var_is_offline_then_recovers(
    monkeypatch,
    tmp_path,
):
    state_path, _closure_path, _bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("prepared"),
    )
    state = json.loads(state_path.read_text(encoding="ascii"))
    successor = deepcopy(state)
    successor["phase"] = "k3s_quiesced"
    legacy_cutover._write_private_json(
        legacy_cutover.CUTOVER_PENDING_STATE_PATH,
        successor,
    )
    legacy_cutover._write_private_json(
        legacy_cutover.CUTOVER_FENCE_MARKER_PATH,
        legacy_cutover._fence_marker_document(state, successor),
    )
    durable_dir = state_path.parent
    offline_dir = durable_dir.with_name("separate-var-offline")
    durable_dir.rename(offline_dir)

    with pytest.raises(legacy_cutover.LegacyCutoverError, match="fences K3s"):
        legacy_cutover.enforce_reboot_fence()

    offline_dir.rename(durable_dir)
    recovered, marker = legacy_cutover._reconcile_cutover_fence(state)
    assert recovered == successor
    assert marker == legacy_cutover._fence_marker_document(successor)


def test_private_json_fsyncs_file_and_directory(monkeypatch, tmp_path):
    calls = []
    modes = []
    monkeypatch.setattr(
        legacy_cutover.os, "fsync", lambda descriptor: calls.append(descriptor)
    )
    monkeypatch.setattr(
        legacy_cutover.os,
        "fchmod",
        lambda _descriptor, mode: modes.append(mode),
    )
    path = tmp_path / "state" / "journal.json"
    legacy_cutover._write_private_json(str(path), {"phase": "prepared"})

    assert len(calls) == 2
    assert modes == [0o600]
    assert json.loads(path.read_text(encoding="ascii")) == {"phase": "prepared"}


@pytest.mark.parametrize("mode", [0o400, 0o640, 0o700])
def test_private_json_requires_exact_mode_0600(monkeypatch, tmp_path, mode):
    path = tmp_path / "state.json"
    path.write_text('{"phase":"prepared"}\n', encoding="ascii")
    monkeypatch.setattr(
        legacy_cutover.os,
        "stat",
        lambda *_args, **_kwargs: SimpleNamespace(
            st_mode=stat.S_IFREG | mode,
            st_uid=0,
        ),
    )
    with pytest.raises(legacy_cutover.LegacyCutoverError, match="unsafe"):
        legacy_cutover._load_private_json(str(path), "cutover recovery state")


def test_dangling_cutover_marker_symlink_fails_closed(monkeypatch, tmp_path):
    marker_path = tmp_path / "fence.json"
    marker_path.symlink_to(tmp_path / "missing.json")
    monkeypatch.setattr(
        legacy_cutover,
        "CUTOVER_FENCE_MARKER_PATH",
        str(marker_path),
    )
    with pytest.raises(legacy_cutover.LegacyCutoverError, match="unsafe"):
        legacy_cutover.enforce_reboot_fence()


def test_cutover_rejects_service_private_mount_namespace(monkeypatch):
    def namespace_stat(path, **_kwargs):
        inode = 10 if path == "/proc/self/ns/mnt" else 11
        return SimpleNamespace(st_dev=1, st_ino=inode)

    monkeypatch.setattr(legacy_cutover.os, "stat", namespace_stat)
    with pytest.raises(legacy_cutover.LegacyCutoverError, match="PID 1"):
        legacy_cutover._verify_host_mount_namespace()

    monkeypatch.setattr(
        legacy_cutover.os,
        "stat",
        lambda _path, **_kwargs: SimpleNamespace(st_dev=1, st_ino=10),
    )
    legacy_cutover._verify_host_mount_namespace()


def test_cutover_holder_probes_use_supported_silent_fuser_argv(monkeypatch):
    calls = []

    def run(argv):
        calls.append(argv)
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    monkeypatch.setattr(legacy_cutover, "_run", run)
    monkeypatch.setattr(legacy_cutover, "_mountpoint", lambda _path: True)
    monkeypatch.setattr(legacy_cutover.os.path, "exists", lambda _path: True)

    legacy_cutover._require_no_mount_holders("/cache/storage")
    legacy_cutover._require_no_mapper_holders("tdx-cache")

    assert calls == [
        ["/usr/bin/fuser", "-s", "-m", "/cache/storage"],
        ["/usr/bin/fuser", "-s", "/dev/mapper/tdx-cache"],
    ]


@pytest.mark.parametrize("returncode", [0, 2])
def test_cutover_holder_probes_fail_closed(monkeypatch, returncode):
    monkeypatch.setattr(legacy_cutover, "_mountpoint", lambda _path: True)
    monkeypatch.setattr(legacy_cutover.os.path, "exists", lambda _path: True)
    monkeypatch.setattr(
        legacy_cutover,
        "_run",
        lambda _argv: SimpleNamespace(returncode=returncode, stdout="", stderr=""),
    )

    mount_message = "open holders" if returncode == 0 else "holders are unavailable"
    mapper_message = "open holders" if returncode == 0 else "holders are unavailable"
    with pytest.raises(legacy_cutover.LegacyCutoverError, match=mount_message):
        legacy_cutover._require_no_mount_holders("/cache/storage")
    with pytest.raises(legacy_cutover.LegacyCutoverError, match=mapper_message):
        legacy_cutover._require_no_mapper_holders("tdx-cache")


def test_cutover_service_and_dependencies_are_exactly_pinned():
    root = Path(__file__).resolve().parents[2]
    source = (
        root / "src/chutes-miner-cli/chutes_miner_cli/legacy_cutover.py"
    ).read_text(encoding="utf-8")
    role = root / "ansible/k3s/roles/chutes-miner"
    service = (role / "files/chutes-legacy-gpu-cutover.service").read_text(
        encoding="utf-8"
    )
    fence_service = (
        role / "files/chutes-legacy-gpu-cutover-fence.service"
    ).read_text(encoding="utf-8")
    fence_dropin = (role / "files/legacy-cutover-fence.conf").read_text(
        encoding="utf-8"
    )
    tasks = (role / "tasks/main.yml").read_text(encoding="utf-8")
    defaults = (role / "defaults/main.yml").read_text(encoding="utf-8")
    helper = role / "files/k3s-killall-v1.33.1+k3s1.sh"
    helper_sha256 = hashlib.sha256(helper.read_bytes()).hexdigest()

    assert "AgentConfig" not in source
    assert (
        "ExecStart=/usr/bin/nsenter --target 1 --mount -- /usr/local/bin/chutes-miner"
        in service
    )
    assert "PrivateTmp=yes" in service
    assert "ProtectSystem=strict" in service
    assert "RequiresMountsFor=/var/lib/chutes/legacy-gpu-cutover" in service
    assert "ExecStopPost=" not in service
    assert "_has_durable_cutover_progress()" in source
    assert "ConditionPathExists=|/var/lib/chutes/legacy-gpu-cutover/state.json" in service
    assert "ConditionPathExists=|/etc/chutes/legacy-gpu-cutover/fence.json" in service
    assert "/etc/chutes/legacy-gpu-cutover" in service
    assert "DefaultDependencies=no" in fence_service
    assert "gpu-legacy-cutover-fence" in fence_service
    assert "ConditionPathExists=/etc/chutes/legacy-gpu-cutover/fence.json" in (
        fence_service
    )
    assert "/var/lib/chutes/legacy-gpu-cutover" not in fence_service
    assert "systemd-cryptsetup@storage.service" in fence_service
    assert "systemd-cryptsetup@tdx\\x2dcache.service" in fence_service
    assert "cache-storage.mount" in fence_service
    assert "var-snap.mount" in fence_service
    assert "Requires=chutes-legacy-gpu-cutover-fence.service" in fence_dropin
    assert "systemd-cryptsetup@tdx\\x2dcache.service" in tasks
    assert "cache-storage.mount" in tasks
    assert "var-snap.mount" in tasks
    assert '"util-linux={{ legacy_cutover_util_linux_version }}"' in tasks
    assert '"psmisc={{ legacy_cutover_psmisc_version }}"' in tasks
    assert "path: /etc/chutes/legacy-gpu-cutover" in tasks
    assert "checksum_algorithm: sha256" in tasks
    assert "legacy_cutover_util_linux_version: 2.37.2-4ubuntu3.4" in defaults
    assert "legacy_cutover_psmisc_version: 23.4-2build3" in defaults
    assert helper_sha256 == legacy_cutover.K3S_SHUTDOWN_HELPER_SHA256
    assert helper_sha256 in defaults
    assert '"/usr/bin/fuser"' in source
    assert "_verify_host_mount_namespace()" in source


def test_cutover_reads_secret_through_verified_explicit_kubeconfig(monkeypatch):
    calls = []
    monkeypatch.setattr(
        legacy_cutover.os,
        "stat",
        lambda *_args, **_kwargs: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_uid=0,
        ),
    )

    def run(argv):
        calls.append(argv)
        if "--raw=/readyz" in argv:
            return SimpleNamespace(returncode=0, stdout="ok\n", stderr="")
        if "namespace" in argv:
            payload = {"metadata": {"name": "kube-system", "uid": "cluster-uid"}}
        else:
            payload = {
                "metadata": {
                    "name": "postgres-secret",
                    "namespace": "chutes",
                    "uid": "secret-uid",
                },
                "data": {
                    "postgres-password": base64.b64encode(
                        b"stable-postgres-password"
                    ).decode("ascii")
                },
            }
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(legacy_cutover, "_run", run)
    assert (
        legacy_cutover._verified_postgres_password("/run/chutes/legacy-k3s-admin.yaml")
        == "stable-postgres-password"
    )
    assert calls
    assert all(
        command[:3] == ["kubectl", "--kubeconfig", "/run/chutes/legacy-k3s-admin.yaml"]
        for command in calls
    )


@pytest.mark.asyncio
async def test_missing_admin_kubeconfig_fails_before_quiesce(monkeypatch, tmp_path):
    state_path = tmp_path / "state.json"
    closure_path = tmp_path / "closure.json"
    bundle = _bundle() | {"kubeconfig_path": str(tmp_path / "missing-kubeconfig")}
    calls = []
    bundle_path = tmp_path / "bundle"
    bundle_path.write_text("bundle", encoding="ascii")
    monkeypatch.setattr(legacy_cutover, "CUTOVER_STATE_PATH", str(state_path))
    monkeypatch.setattr(
        legacy_cutover,
        "CUTOVER_LOCK_PATH",
        str(tmp_path / "operation.lock"),
    )
    _patch_fence(monkeypatch, tmp_path)
    monkeypatch.setattr(legacy_cutover, "CLOSURE_PATH", str(closure_path))
    monkeypatch.setattr(
        legacy_cutover, "AUTHORIZATION_PATH", str(tmp_path / "authorization.json")
    )
    monkeypatch.setattr(legacy_cutover.os, "geteuid", lambda: 0)
    monkeypatch.setattr(legacy_cutover, "_verify_host_mount_namespace", lambda: None)
    monkeypatch.setattr(legacy_cutover, "_verify_shutdown_helper", lambda: None)
    monkeypatch.setattr(legacy_cutover, "_boot_id", lambda: BOOT_ID)
    monkeypatch.setattr(legacy_cutover, "_load_bundle", lambda _path: bundle)
    monkeypatch.setattr(
        legacy_cutover,
        "_run",
        lambda argv: calls.append(argv)
        or SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    with pytest.raises(
        legacy_cutover.LegacyCutoverError,
        match="kubeconfig is unavailable",
    ):
        await legacy_cutover.run_cutover(str(bundle_path))
    assert not state_path.exists()
    assert not Path(legacy_cutover.AUTHORIZATION_PATH).exists()
    assert [legacy_cutover.K3S_SHUTDOWN_HELPER] not in calls


@pytest.mark.asyncio
async def test_volume_generations_are_rechecked_before_any_unmount(
    monkeypatch,
    tmp_path,
):
    state_path, _closure_path, bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("k3s_quiesced"),
    )
    monkeypatch.setattr(
        legacy_cutover,
        "_generation",
        lambda root: 5 if root == "/cache/storage" else 9,
    )
    monkeypatch.setattr(
        legacy_cutover,
        "_unmount",
        lambda _path: pytest.fail("stale generation reached unmount"),
    )

    with pytest.raises(
        legacy_cutover.LegacyCutoverError,
        match="volume generation changed before unmount",
    ):
        await legacy_cutover.run_cutover(str(bundle_path))

    persisted = json.loads(state_path.read_text(encoding="ascii"))
    assert persisted["phase"] == "k3s_quiesced"


def _patch_live_prequiescence_source(monkeypatch, state, *, identity_change=None):
    commands = []
    identities = {
        ("cryptsetup", "luksUUID", "/dev/disk/by-label/storage"): state[
            "storage_luks_uuid"
        ],
        ("blkid", "-o", "value", "-s", "UUID", "/dev/mapper/storage"): state[
            "storage_filesystem_uuid"
        ],
        ("cryptsetup", "luksUUID", "/dev/disk/by-label/tdx-cache"): state[
            "cache_luks_uuid"
        ],
        ("blkid", "-o", "value", "-s", "UUID", "/dev/mapper/tdx-cache"): state[
            "cache_filesystem_uuid"
        ],
        ("blkid", "-o", "value", "-s", "TYPE", "/dev/mapper/tdx-cache"): state[
            "cache_filesystem_type"
        ],
    }
    if identity_change is not None:
        identities[identity_change] = "changed"

    def run(argv):
        commands.append(tuple(argv))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def output(argv, _label, *, lower=True):
        value = identities[tuple(argv)]
        return value.lower() if lower else value

    monkeypatch.setattr(legacy_cutover, "_run", run)
    monkeypatch.setattr(legacy_cutover, "_mountpoint", lambda _path: True)
    monkeypatch.setattr(legacy_cutover.os.path, "exists", lambda _path: True)
    monkeypatch.setattr(legacy_cutover, "_output", output)
    monkeypatch.setattr(
        legacy_cutover,
        "_generation",
        lambda root: (
            state["storage_generation"]
            if root == "/cache/storage"
            else state["cache_generation"]
        ),
    )
    return commands


def test_prequiescence_abort_revalidates_exact_live_source(monkeypatch):
    state = _source_state("prepared")
    commands = _patch_live_prequiescence_source(monkeypatch, state)

    legacy_cutover._require_prequiescence_source(state)

    assert commands == [
        ("systemctl", "is-active", "--quiet", "k3s.service"),
        ("cryptsetup", "status", "storage"),
        ("cryptsetup", "status", "tdx-cache"),
    ]


def test_prequiescence_abort_rejects_inactive_k3s(monkeypatch):
    monkeypatch.setattr(
        legacy_cutover,
        "_run",
        lambda _argv: SimpleNamespace(returncode=3, stdout="", stderr=""),
    )
    monkeypatch.setattr(
        legacy_cutover,
        "_mountpoint",
        lambda _path: pytest.fail("inactive K3s reached mount checks"),
    )

    with pytest.raises(
        legacy_cutover.LegacyCutoverError,
        match="cannot abort after K3s quiescence",
    ):
        legacy_cutover._require_prequiescence_source(_source_state("prepared"))


def test_prequiescence_abort_rejects_source_identity_drift(monkeypatch):
    state = _source_state("prepared")
    _patch_live_prequiescence_source(
        monkeypatch,
        state,
        identity_change=(
            "blkid",
            "-o",
            "value",
            "-s",
            "UUID",
            "/dev/mapper/tdx-cache",
        ),
    )

    with pytest.raises(
        legacy_cutover.LegacyCutoverError,
        match="legacy source identity changed: cache_filesystem_uuid",
    ):
        legacy_cutover._require_prequiescence_source(state)


def test_prequiescence_abort_clears_fence_and_sensitive_state(
    monkeypatch,
    tmp_path,
):
    state_path, closure_path, bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("prepared"),
    )
    monkeypatch.setattr(
        legacy_cutover,
        "_require_prequiescence_source",
        lambda _state: None,
    )
    kubeconfig = Path(legacy_cutover.K3S_ADMIN_KUBECONFIG)
    kubeconfig.write_text("credential", encoding="ascii")

    result = legacy_cutover.abort_legacy_cutover(str(bundle_path))

    assert result == {
        "schema": "chutes.legacy-gpu-cutover-aborted",
        "version": 1,
        "status": "aborted",
    }
    assert not state_path.exists()
    assert not closure_path.exists()
    assert not Path(legacy_cutover.AUTHORIZATION_PATH).exists()
    assert not Path(legacy_cutover.CUTOVER_FENCE_MARKER_PATH).exists()
    assert not bundle_path.exists()
    assert not kubeconfig.exists()


def test_prequiescence_abort_repairs_missing_initial_fence(
    monkeypatch,
    tmp_path,
):
    state_path, _closure_path, bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("prepared"),
    )
    Path(legacy_cutover.CUTOVER_FENCE_MARKER_PATH).unlink()
    monkeypatch.setattr(
        legacy_cutover,
        "_require_prequiescence_source",
        lambda _state: None,
    )

    result = legacy_cutover.abort_legacy_cutover(str(bundle_path))

    assert result["status"] == "aborted"
    assert not state_path.exists()
    assert not Path(legacy_cutover.CUTOVER_FENCE_MARKER_PATH).exists()


@pytest.mark.parametrize(
    "phase",
    ["k3s_quiesced", "filesystems_unmounted", "mappers_closed", "transfer_acknowledged"],
)
def test_abort_is_rejected_after_quiescence(
    monkeypatch,
    tmp_path,
    phase,
):
    state_path, _closure_path, bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state(phase) if phase != "transfer_acknowledged" else _acknowledged_state(),
    )

    with pytest.raises(
        legacy_cutover.LegacyCutoverError,
        match="cannot abort after quiescence",
    ):
        legacy_cutover.abort_legacy_cutover(str(bundle_path))

    assert state_path.exists()
    assert Path(legacy_cutover.CUTOVER_FENCE_MARKER_PATH).exists()


def test_prepared_phase_cannot_abort_after_physical_quiescence(
    monkeypatch,
    tmp_path,
):
    state_path, _closure_path, bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("prepared"),
    )
    monkeypatch.setattr(
        legacy_cutover,
        "_require_prequiescence_source",
        lambda _state: (_ for _ in ()).throw(
            legacy_cutover.LegacyCutoverError(
                "legacy cutover cannot abort after K3s quiescence has begun"
            )
        ),
    )

    with pytest.raises(
        legacy_cutover.LegacyCutoverError,
        match="cannot abort after K3s quiescence",
    ):
        legacy_cutover.abort_legacy_cutover(str(bundle_path))

    assert json.loads(state_path.read_text(encoding="ascii"))["phase"] == "prepared"
    assert Path(legacy_cutover.CUTOVER_FENCE_MARKER_PATH).exists()


@pytest.mark.parametrize("side", ["before", "after"])
def test_abort_recovers_crash_at_root_fence_clear(
    monkeypatch,
    tmp_path,
    side,
):
    state_path, _closure_path, bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("prepared"),
    )
    monkeypatch.setattr(
        legacy_cutover,
        "_require_prequiescence_source",
        lambda _state: None,
    )
    real_unlink = legacy_cutover._unlink_private
    crashed = False

    def crash_fence(path):
        nonlocal crashed
        if path != legacy_cutover.CUTOVER_FENCE_MARKER_PATH or crashed:
            return real_unlink(path)
        crashed = True
        if side == "before":
            raise RuntimeError("crash before abort fence clear")
        real_unlink(path)
        raise RuntimeError("crash after abort fence clear")

    monkeypatch.setattr(legacy_cutover, "_unlink_private", crash_fence)
    with pytest.raises(RuntimeError, match="crash .* abort fence clear"):
        legacy_cutover.abort_legacy_cutover(str(bundle_path))
    assert crashed
    assert json.loads(state_path.read_text(encoding="ascii"))["phase"] == (
        "abort_requested"
    )

    monkeypatch.setattr(legacy_cutover, "_unlink_private", real_unlink)
    result = legacy_cutover.abort_legacy_cutover(str(bundle_path))
    assert result["status"] == "aborted"
    assert not state_path.exists()
    assert not Path(legacy_cutover.CUTOVER_FENCE_MARKER_PATH).exists()


def test_runtime_kubeconfig_survives_failure_before_durable_progress(
    monkeypatch,
    tmp_path,
):
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text("bundle", encoding="ascii")
    kubeconfig = tmp_path / "admin.yaml"
    kubeconfig.write_text("credential", encoding="ascii")
    monkeypatch.setattr(
        legacy_cutover,
        "_load_bundle",
        lambda _path: {"kubeconfig_path": str(kubeconfig)},
    )
    monkeypatch.setattr(
        legacy_cutover,
        "CUTOVER_STATE_PATH",
        str(tmp_path / "missing-state.json"),
    )
    monkeypatch.setattr(legacy_cutover, "run_cutover", lambda _path: object())

    def fail_before_progress(_value):
        raise legacy_cutover.LegacyCutoverError("capture failed")

    monkeypatch.setattr(legacy_cutover.asyncio, "run", fail_before_progress)

    with pytest.raises(legacy_cutover.LegacyCutoverError, match="capture failed"):
        legacy_cutover.run(str(bundle_path))
    assert kubeconfig.exists()


def test_runtime_kubeconfig_is_removed_after_durable_prepared_state(
    monkeypatch,
    tmp_path,
):
    _state_path, _closure_path, bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("prepared"),
    )
    kubeconfig = tmp_path / "admin.yaml"
    kubeconfig.write_text("credential", encoding="ascii")
    monkeypatch.setattr(
        legacy_cutover,
        "_load_bundle",
        lambda _path: {"kubeconfig_path": str(kubeconfig)},
    )
    monkeypatch.setattr(legacy_cutover, "run_cutover", lambda _path: object())
    monkeypatch.setattr(
        legacy_cutover.asyncio,
        "run",
        lambda _value: {"status": "still_prepared"},
    )

    assert legacy_cutover.run(str(bundle_path))["status"] == "still_prepared"
    assert not kubeconfig.exists()
