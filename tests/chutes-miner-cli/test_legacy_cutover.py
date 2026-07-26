import base64
import hashlib
import json
import stat
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from chutes_miner_cli import legacy_cutover


BOOT_ID = "11111111-2222-3333-4444-555555555555"


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
        "legacy_server_id": "legacy-server",
        "target_host_id": "host-1",
        "cutover_authorization": "authorization",
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
        "legacy_server_id": "legacy-server",
        "target_host_id": "host-1",
        "closure_sha256": "a" * 64,
        "api_result": {
            "schema": "chutes.gpu-legacy-closed",
            "legacy_server_id": "legacy-server",
            "status": "guest_closed",
        },
    }


def _patch_runtime(monkeypatch, tmp_path, state: dict | None = None):
    state_path = tmp_path / "state.json"
    closure_path = tmp_path / "closure.json"
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text("bundle", encoding="ascii")
    monkeypatch.setattr(legacy_cutover, "CUTOVER_STATE_PATH", str(state_path))
    monkeypatch.setattr(legacy_cutover, "CLOSURE_PATH", str(closure_path))
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
    monkeypatch.setattr(legacy_cutover, "_require_mappers_closed", lambda: None)
    if state is not None:
        state_path.write_text("state", encoding="ascii")
        monkeypatch.setattr(
            legacy_cutover,
            "_load_cutover_state",
            lambda _path=None: deepcopy(state),
        )
    return state_path, closure_path, bundle_path


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
async def test_lost_api_response_replays_exact_persisted_closure(monkeypatch, tmp_path):
    state_path, closure_path, bundle_path = _patch_runtime(
        monkeypatch,
        tmp_path,
        _source_state("mappers_closed"),
    )
    state_path.write_text(json.dumps(_source_state("mappers_closed")), encoding="ascii")
    monkeypatch.setattr(
        legacy_cutover,
        "_load_cutover_state",
        lambda _path=None: json.loads(state_path.read_text(encoding="ascii")),
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
    state_path = tmp_path / "state.json"
    state_path.write_text("state", encoding="ascii")
    monkeypatch.setattr(legacy_cutover, "CUTOVER_STATE_PATH", str(state_path))
    monkeypatch.setattr(legacy_cutover.os, "geteuid", lambda: 0)
    monkeypatch.setattr(legacy_cutover, "_load_cutover_state", lambda _path=None: state)
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
    state_path = tmp_path / "state.json"
    state_path.write_text("state", encoding="ascii")
    monkeypatch.setattr(legacy_cutover, "CUTOVER_STATE_PATH", str(state_path))
    monkeypatch.setattr(legacy_cutover.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        legacy_cutover,
        "_load_cutover_state",
        lambda _path=None: _source_state("mappers_closed"),
    )
    calls = []
    monkeypatch.setattr(legacy_cutover, "_run", lambda argv: calls.append(argv))

    with pytest.raises(legacy_cutover.LegacyCutoverError, match="reboot is forbidden"):
        legacy_cutover.recover_legacy_cutover()
    assert calls == []


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


def test_cutover_service_and_dependencies_are_exactly_pinned():
    root = Path(__file__).resolve().parents[2]
    source = (
        root / "src/chutes-miner-cli/chutes_miner_cli/legacy_cutover.py"
    ).read_text(encoding="utf-8")
    role = root / "ansible/k3s/roles/chutes-miner"
    service = (role / "files/chutes-legacy-gpu-cutover.service").read_text(
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
    assert '"util-linux={{ legacy_cutover_util_linux_version }}"' in tasks
    assert '"psmisc={{ legacy_cutover_psmisc_version }}"' in tasks
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
    monkeypatch.setattr(legacy_cutover, "CUTOVER_STATE_PATH", str(state_path))
    monkeypatch.setattr(legacy_cutover, "CLOSURE_PATH", str(closure_path))
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
        await legacy_cutover.run_cutover(str(tmp_path / "bundle"))
    assert not state_path.exists()
    assert [legacy_cutover.K3S_SHUTDOWN_HELPER] not in calls
