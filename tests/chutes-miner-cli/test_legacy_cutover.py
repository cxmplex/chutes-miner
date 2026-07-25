from types import SimpleNamespace
from pathlib import Path
import base64
import json
import stat

import pytest
from chutes_miner_cli import legacy_cutover


@pytest.mark.asyncio
async def test_legacy_cutover_closes_both_mappers_before_api(monkeypatch, tmp_path):
    events = []
    bundle = {
        "validator_api": "https://validator.example",
        "legacy_server_id": "legacy-server",
        "target_host_id": "host-1",
        "cert_path": "/cert",
        "key_path": "/key",
        "ca_path": "",
    }
    monkeypatch.setattr(legacy_cutover.os, "geteuid", lambda: 0)
    monkeypatch.setattr(legacy_cutover.os, "sync", lambda: events.append("sync"))
    monkeypatch.setattr(legacy_cutover, "_load_bundle", lambda _path: bundle)
    monkeypatch.setattr(
        legacy_cutover,
        "_closure_document",
        lambda _bundle: {"closure": True},
    )
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
    monkeypatch.setattr(
        legacy_cutover,
        "RECOVERY_MARKER",
        str(tmp_path / "recovery"),
    )
    monkeypatch.setattr(
        legacy_cutover,
        "CLOSURE_PATH",
        str(tmp_path / "closure.json"),
    )

    def run(argv):
        events.append(":".join(argv))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(legacy_cutover, "_run", run)

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

        def post(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(legacy_cutover.aiohttp, "ClientSession", Session)
    bundle_path = tmp_path / "bundle"
    bundle_path.write_text("bundle", encoding="ascii")
    result = await legacy_cutover.run_cutover(str(bundle_path))
    assert result["status"] == "guest_closed"
    assert events.index("close:storage") < events.index("api")
    assert events.index("close:tdx-cache") < events.index("api")
    assert "systemctl:poweroff:--no-block" in events


def test_failed_transfer_recovery_reboots_legacy_key_release(monkeypatch, tmp_path):
    marker = tmp_path / "recovery"
    marker.write_text("required\n", encoding="ascii")
    monkeypatch.setattr(legacy_cutover, "RECOVERY_MARKER", str(marker))
    monkeypatch.setattr(legacy_cutover.os, "geteuid", lambda: 0)
    calls = []

    def run(argv):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(legacy_cutover, "_run", run)
    legacy_cutover.recover_legacy_cutover()
    assert calls == [["systemctl", "reboot", "--no-block"]]


def test_cutover_service_is_packaged_without_agent_config_dependency():
    root = Path(__file__).resolve().parents[2]
    source = (root / "src/chutes-miner-cli/chutes_miner_cli/legacy_cutover.py").read_text(
        encoding="utf-8"
    )
    service = (
        root / "ansible/k3s/roles/chutes-miner/files/chutes-legacy-gpu-cutover.service"
    ).read_text(encoding="utf-8")
    tasks = (root / "ansible/k3s/roles/chutes-miner/tasks/main.yml").read_text(encoding="utf-8")
    assert "AgentConfig" not in source
    assert "gpu-legacy-cutover-run" in service
    assert "KUBECONFIG=/run/chutes/legacy-k3s-admin.yaml" in service
    assert '"kubectl", "--kubeconfig",' in source
    assert "chutes-legacy-gpu-cutover.service" in tasks


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
                    "postgres-password": base64.b64encode(b"stable-postgres-password").decode(
                        "ascii"
                    )
                },
            }
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

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
    bundle = {
        "validator_api": "https://validator.example",
        "legacy_server_id": "legacy-server",
        "target_host_id": "host-1",
        "cert_path": "/cert",
        "key_path": "/key",
        "ca_path": "",
        "kubeconfig_path": str(tmp_path / "missing-kubeconfig"),
    }
    calls = []
    monkeypatch.setattr(legacy_cutover.os, "geteuid", lambda: 0)
    monkeypatch.setattr(legacy_cutover, "_load_bundle", lambda _path: bundle)
    monkeypatch.setattr(
        legacy_cutover,
        "CLOSURE_PATH",
        str(tmp_path / "closure.json"),
    )

    def run(argv):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(legacy_cutover, "_run", run)
    with pytest.raises(
        legacy_cutover.LegacyCutoverError,
        match="kubeconfig is unavailable",
    ):
        await legacy_cutover.run_cutover(str(tmp_path / "bundle"))
    assert not any(command[:2] == ["systemctl", "stop"] for command in calls)
