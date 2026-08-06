import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from chutes_common.settings import (
    GPU_MINER_RUNTIME_PURPOSES_V1,
    GPU_MINER_RUNTIME_PURPOSES_V2,
)
from cross_repo_tests import repository_root

ROOT = Path(__file__).resolve().parents[2]
CONTROL_LABEL = {"chutes/seedless-control-plane": "true"}
STACK_IMAGE = f"chutes.local/seedless-stack@sha256:{'a' * 64}"
OWNER_SS58 = "5PublicOwnerIdentity"


def test_legacy_cutover_state_contract_is_byte_exact_across_guest_and_miner():
    miner_fixture = ROOT / "tests/fixtures/legacy_gpu_cutover_state_v1.json"
    sek8s_root = repository_root("sek8s", start=Path(__file__))
    sek8s_fixture = sek8s_root / "tests/fixtures/legacy_gpu_cutover_state_v1.json"
    assert miner_fixture.read_bytes() == sek8s_fixture.read_bytes()
    setup_storage = (
        sek8s_root / "ansible/guest/roles/luks/files/initramfs/setup_storage"
    ).read_text(encoding="utf-8")
    fence_call = '"$CUTOVER_FENCE_HELPER" "$cutover_fence" 0'
    assert 'CUTOVER_FENCE_RELATIVE="/etc/chutes/legacy-gpu-cutover/fence.json"' in (setup_storage)
    assert setup_storage.index(fence_call) < setup_storage.index("if ! load_vm_data")
    for operation in (
        "detect_storage_device",
        "detect_cache_device",
        "post_sync_keys",
        "setup_storage",
        "setup_cache",
        "stage_volume_generation",
    ):
        assert setup_storage.index(fence_call) < setup_storage.index(f"if ! {operation}")


def test_legacy_cutover_fence_contract_is_byte_exact_across_guest_and_miner():
    miner_fixture = ROOT / "tests/fixtures/legacy_gpu_cutover_fence_v1.json"
    sek8s_root = repository_root("sek8s", start=Path(__file__))
    sek8s_fixture = sek8s_root / "tests/fixtures/legacy_gpu_cutover_fence_v1.json"
    assert miner_fixture.read_bytes() == sek8s_fixture.read_bytes()


def test_runtime_purposes_use_the_cross_repo_contract():
    api_root = repository_root("api", start=Path(__file__))
    version_one = json.loads(
        (api_root / "tests/fixtures/gpu_runtime_purposes_v1.json").read_text(
            encoding="ascii"
        )
    )
    version_two = json.loads(
        (api_root / "tests/fixtures/gpu_runtime_purposes_v2.json").read_text(
            encoding="ascii"
        )
    )
    assert version_one["miner"] == GPU_MINER_RUNTIME_PURPOSES_V1
    assert version_two["miner"] == GPU_MINER_RUNTIME_PURPOSES_V2
    assert version_one["platform"] == version_two["platform"] == ["registry"]


def test_fresh_and_migrated_gepetto_cannot_mount_stale_source_configmap():
    deployment = (ROOT / "charts/chutes-miner/templates/gepetto-deployment.yaml").read_text(
        encoding="utf-8"
    )
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
            "--set-string",
            f"minerCredentials.ownerSs58={OWNER_SS58}",
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
            "--set-string",
            f"minerCredentials.ownerSs58={OWNER_SS58}",
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
    assert not any(item.get("metadata", {}).get("name") == "monitor" for item in documents)
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


def test_rendered_registry_has_one_attested_certificate_binding():
    documents = _render("chutes-miner-gpu")
    registry = next(
        item
        for item in documents
        if item.get("kind") == "DaemonSet" and item.get("metadata", {}).get("name") == "registry"
    )
    auth = next(
        container
        for container in registry["spec"]["template"]["spec"]["initContainers"]
        if container["name"] == "auth"
    )
    cert_entries = [entry for entry in auth["env"] if entry["name"] == "CHUTES_ATTESTED_CERT_FILE"]
    assert cert_entries == [
        {"name": "CHUTES_ATTESTED_CERT_FILE", "value": "/run/chutes-tls/server.crt"}
    ]


@pytest.mark.parametrize("chart", ["chutes-miner", "chutes-miner-gpu"])
def test_rendered_charts_use_only_public_owner_identity(chart):
    documents = _render(chart)
    rendered = json.dumps(documents, sort_keys=True)
    for forbidden in (
        "MINER_SS58",
        "MINER_SEED",
        "minerCredentials.ss58Address",
        "minerCredentials.secretSeed",
        "secretSeed",
    ):
        assert forbidden not in rendered
    assert not any(item.get("metadata", {}).get("name") == "audit-exporter" for item in documents)

    owner_bindings = []
    for document in documents:
        if document.get("kind") not in {
            "Deployment",
            "DaemonSet",
            "StatefulSet",
            "CronJob",
        }:
            continue
        if document["kind"] == "CronJob":
            pod_spec = document["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        else:
            pod_spec = document["spec"]["template"]["spec"]
        for container in [
            *pod_spec.get("initContainers", []),
            *pod_spec.get("containers", []),
        ]:
            owner_bindings.extend(
                entry
                for entry in container.get("env", [])
                if entry.get("name") == "MINER_OWNER_SS58"
            )

    assert owner_bindings
    assert all(
        entry.get("valueFrom", {}).get("secretKeyRef")
        == {"name": "miner-credentials", "key": "owner"}
        for entry in owner_bindings
    )

    if chart == "chutes-miner":
        credentials = next(
            item
            for item in documents
            if item.get("kind") == "Secret"
            and item.get("metadata", {}).get("name") == "miner-credentials"
        )
        assert set(credentials["data"]) == {"owner"}
        assert base64.b64decode(credentials["data"]["owner"]).decode("ascii") == OWNER_SS58


def test_fleet_uses_public_owner_chart_value_without_seed_material():
    parse_credentials = (ROOT / "ansible/k3s/tasks/charts/parse_credentials.yml").read_text(
        encoding="utf-8"
    )
    assert "owner_ss58" in parse_credentials
    assert "secretSeed" not in parse_credentials
    assert "miner_secret_seed" not in parse_credentials
    assert "miner_ss58_address" not in parse_credentials
    assert "miner_owner_ss58" in parse_credentials
    for name in ("deploy_miner.yml", "deploy_miner_gpu.yml"):
        deployment = (ROOT / "ansible/k3s/tasks/charts" / name).read_text(encoding="utf-8")
        assert "minerCredentials.ownerSs58" in deployment
        assert "minerCredentials.ss58Address" not in deployment
        assert "minerCredentials.secretSeed" not in deployment
        assert "miner_owner_ss58" in deployment
        assert "miner_ss58_address" not in deployment

    migration = yaml.safe_load(
        (ROOT / "ansible/k3s/tasks/migration/verify-chutes.yml").read_text(encoding="utf-8")
    )
    cleanup_by_name = {task["name"]: task for task in migration}
    microk8s_cleanup = cleanup_by_name["Remove unsupported legacy audit exporter from MicroK8s"]
    assert microk8s_cleanup["when"] == "inventory_hostname in groups['microk8s']"
    assert microk8s_cleanup["kubernetes.core.k8s"] == {
        "context": "default",
        "state": "absent",
        "kind": "CronJob",
        "name": "audit-exporter",
        "namespace": "{{ chutes_namespace | default('chutes') }}",
    }
    k3s_cleanup = cleanup_by_name["Remove unsupported legacy audit exporter from k3s"]
    assert k3s_cleanup["when"] == "inventory_hostname in groups['control']"
    assert k3s_cleanup["kubernetes.core.k8s"] == {
        "kubeconfig": "/etc/rancher/k3s/k3s.yaml",
        "state": "absent",
        "kind": "CronJob",
        "name": "audit-exporter",
        "namespace": "{{ chutes_namespace | default('chutes') }}",
    }


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
