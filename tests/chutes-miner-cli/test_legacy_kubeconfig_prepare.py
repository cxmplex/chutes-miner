import importlib.util
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ansible/k3s/roles/chutes-miner/files/prepare-legacy-kubeconfig.py"
SPEC = importlib.util.spec_from_file_location("legacy_kubeconfig_prepare", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def test_normal_boot_copies_before_source_purge(monkeypatch, tmp_path):
    source = tmp_path / "k3s.yaml"
    runtime = tmp_path / "run/chutes/legacy-k3s-admin.yaml"
    source.write_text("apiVersion: v1\nclusters: []\n", encoding="ascii")
    source.chmod(0o600)
    monkeypatch.setattr(MODULE, "_cluster_uid", lambda _path: "cluster-uid")
    MODULE.prepare(source, runtime)
    source.unlink()  # normal 99-purge-kubeconfig posture
    assert not source.exists()
    assert runtime.read_text(encoding="ascii") == "apiVersion: v1\nclusters: []\n"
    assert stat.S_IMODE(runtime.stat().st_mode) == 0o600

    service = (
        ROOT / "ansible/k3s/roles/chutes-miner/files/chutes-legacy-gpu-cutover.service"
    ).read_text(encoding="utf-8")
    prepare_service = (
        ROOT / "ansible/k3s/roles/chutes-miner/files/chutes-legacy-kubeconfig-prepare.service"
    ).read_text(encoding="utf-8")
    drop_in = (
        ROOT / "ansible/k3s/roles/chutes-miner/files/legacy-cutover-kubeconfig.conf"
    ).read_text(encoding="utf-8")
    assert "Requires=chutes-legacy-kubeconfig-prepare.service" not in service
    assert "ConditionPathExists=|/run/chutes/legacy-gpu-cutover.json" in service
    assert "ConditionPathExists=|/var/lib/chutes/legacy-gpu-cutover/state.json" in service
    assert "ConditionPathExists=|/etc/chutes/legacy-gpu-cutover/fence.json" in service
    assert "RequiresMountsFor=/var/lib/chutes/legacy-gpu-cutover" in service
    assert "Before=k3s-post-start.service" in prepare_service
    assert "Requires=chutes-legacy-kubeconfig-prepare.service" in drop_in
    assert "KUBECONFIG=/run/chutes/legacy-k3s-admin.yaml" in service
    assert "ExecStopPost=/usr/bin/rm -f /run/chutes/legacy-k3s-admin.yaml" in service


def test_prepare_rejects_missing_source(tmp_path):
    with pytest.raises(MODULE.PreparationError, match="missing kubeconfig"):
        MODULE.prepare(
            tmp_path / "missing",
            tmp_path / "runtime",
        )


def test_prepare_rejects_non_root_only_source(tmp_path):
    source = tmp_path / "k3s.yaml"
    source.write_text("unsafe\n", encoding="ascii")
    source.chmod(0o644)
    with pytest.raises(MODULE.PreparationError, match="not root-only"):
        MODULE.prepare(source, tmp_path / "runtime")


def test_prepare_rejects_cluster_identity_change(monkeypatch, tmp_path):
    source = tmp_path / "k3s.yaml"
    runtime = tmp_path / "runtime"
    source.write_text("apiVersion: v1\n", encoding="ascii")
    source.chmod(0o600)
    identities = iter(["cluster-a", "cluster-b"])
    monkeypatch.setattr(MODULE, "_cluster_uid", lambda _path: next(identities))
    with pytest.raises(MODULE.PreparationError, match="another cluster"):
        MODULE.prepare(source, runtime)
    assert not runtime.exists()
