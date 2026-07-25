import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from chutes_common.settings import GPU_MINER_RUNTIME_PURPOSES
from cross_repo_tests import repository_root

ROOT = Path(__file__).resolve().parents[2]
CONTROL_LABEL = {"chutes/seedless-control-plane": "true"}
STACK_IMAGE = f"chutes.local/seedless-stack@sha256:{'a' * 64}"


def test_runtime_purposes_use_the_cross_repo_contract():
    fixture = (
        repository_root("api", start=Path(__file__))
        / "tests/fixtures/gpu_runtime_purposes_v1.json"
    )
    document = json.loads(fixture.read_text(encoding="ascii"))
    assert document["miner"] == GPU_MINER_RUNTIME_PURPOSES
    assert document["platform"] == ["registry"]


def test_fresh_and_migrated_gepetto_cannot_mount_stale_source_configmap():
    deployment = (
        ROOT / "charts/chutes-miner/templates/gepetto-deployment.yaml"
    ).read_text(encoding="utf-8")
    assert "gepetto-code" not in deployment
    assert "subPath: gepetto.py" not in deployment
    assert 'image: "{{ .Values.seedlessStack.image }}"' in deployment
    assert 'command: ["python", "-m", "chutes_miner.gepetto"]' in deployment


def _render(chart: str) -> list[dict]:
    if shutil.which("helm") is not None:
        command = [
            "helm",
            "template",
            chart,
            str(ROOT / f"charts/{chart}"),
            "-f",
            str(ROOT / f"charts/{chart}/values.yaml"),
            "--set-string",
            f"seedlessStack.image={STACK_IMAGE}",
        ]
    elif shutil.which("docker") is not None and (
        subprocess.run(
            ["docker", "image", "inspect", "alpine/helm:latest"],
            check=False,
            capture_output=True,
        ).returncode
        == 0
    ):
        command = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{ROOT}:/workspace:ro",
            "-w",
            "/workspace",
            "alpine/helm:latest",
            "template",
            chart,
            f"charts/{chart}",
            "-f",
            f"charts/{chart}/values.yaml",
            "--set-string",
            f"seedlessStack.image={STACK_IMAGE}",
        ]
    else:
        pytest.skip("neither Helm nor the local alpine/helm image is available")
    rendered = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [item for item in yaml.safe_load_all(rendered) if isinstance(item, dict)]


@pytest.mark.parametrize("chart", ["chutes-miner", "chutes-miner-gpu"])
def test_fresh_install_render_uses_exact_single_node_placement(chart):
    documents = _render(chart)
    assert documents
    pod_controllers = [
        item
        for item in documents
        if item.get("kind") in {"Deployment", "DaemonSet", "StatefulSet", "CronJob"}
    ]
    assert pod_controllers
    for document in pod_controllers:
        if document["kind"] == "CronJob":
            spec = document["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        else:
            spec = document["spec"]["template"]["spec"]
        assert spec.get("nodeSelector") == CONTROL_LABEL
    assert not any(
        item.get("metadata", {}).get("name") == "monitor" for item in documents
    )
    rendered = json.dumps(documents, sort_keys=True)
    assert "REPLACE_WITH" not in rendered
    images = []
    for document in documents:
        if document.get("kind") not in {
            "Deployment",
            "DaemonSet",
            "StatefulSet",
            "CronJob",
        }:
            continue
        if document["kind"] == "CronJob":
            spec = document["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        else:
            spec = document["spec"]["template"]["spec"]
        images.extend(
            container["image"]
            for container in [
                *spec.get("initContainers", []),
                *spec.get("containers", []),
            ]
        )
    assert images
    assert all("@sha256:" in image for image in images)
    assert STACK_IMAGE in images


def test_migrated_install_reconstructs_measured_releases():
    reconciler = (
        repository_root("sek8s", start=Path(__file__))
        / "ansible/guest/roles/k3s/files/cluster-init/04-helm-chart-upgrade.sh"
    ).read_text(encoding="utf-8")
    assert "upgrade --install" in reconciler
    assert "--create-namespace" in reconciler
    assert "release '$RELEASE' not installed" not in reconciler
    assert '[ "$status" = "deployed" ]' in reconciler
    assert "--reuse-values" not in reconciler
    assert "seedlessStack.image=$STACK_REFERENCE" in reconciler
