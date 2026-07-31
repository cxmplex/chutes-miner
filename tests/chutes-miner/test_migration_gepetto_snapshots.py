"""Migrated k3s and MicroK8s use the same image-built Gepetto implementation."""

from pathlib import Path

import pytest
from chutes_miner.api.exceptions import DeploymentFailure
from chutes_miner.api.k8s.util import require_supported_chutes_version

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_migration_removes_both_retired_gepetto_source_overrides():
    migrate_playbook = (REPO_ROOT / "ansible/k3s/playbooks/migrate.yml").read_text(encoding="utf-8")
    verification_tasks = (REPO_ROOT / "ansible/k3s/tasks/migration/verify-chutes.yml").read_text(
        encoding="utf-8"
    )
    deployment = (REPO_ROOT / "charts/chutes-miner/templates/gepetto-deployment.yaml").read_text(
        encoding="utf-8"
    )

    assert "Remove retired gepetto source override" in migrate_playbook
    assert "state: absent" in migrate_playbook
    assert "MicroK8s" in verification_tasks
    assert "k3s" in verification_tasks
    assert verification_tasks.count("Remove retired gepetto source override") == 2
    assert verification_tasks.count("name: gepetto-code") == 2
    assert "gepetto-code" not in deployment
    assert "subPath: gepetto.py" not in deployment


@pytest.mark.parametrize(
    "version",
    [None, "", "garbage", "0.3.60", "0.3.60.rc1"],
)
def test_migrated_clusters_share_exact_runtime_version_floor(version):
    with pytest.raises(
        DeploymentFailure,
        match="minimum supported version is 0.3.61",
    ):
        require_supported_chutes_version(version, "chute-1")


@pytest.mark.parametrize(
    "version",
    [
        "0.3.61",
        "0.3.61.dev1",
        "0.3.61rc1",
        "0.3.61garbage",
        "0.3.62",
        "1.0.0",
    ],
)
def test_migrated_clusters_accept_supported_runtime(version):
    require_supported_chutes_version(version, "chute-1")


def test_canonical_gepetto_keeps_k3s_and_microk8s_migration_paths():
    source = (REPO_ROOT / "src/chutes-miner/chutes_miner/gepetto.py").read_text(encoding="utf-8")
    assert "get_deployed_chutes_legacy" in source
    assert "purge_legacy_source_config_maps" in source
    assert "migration" in source.lower()
