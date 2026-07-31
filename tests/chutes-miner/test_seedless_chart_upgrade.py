import base64
import gzip
import json
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
STACK_IMAGE = f"chutes.local/seedless-stack@sha256:{'a' * 64}"
CONFIGURED_OWNER = "5PublicOwnerIdentity"
EXISTING_OWNER = "5ExistingPublicOwner"
SECRET_PATH = "/api/v1/namespaces/chutes/secrets/miner-credentials"
RELEASE_LIST_PATH = "/api/v1/namespaces/chutes/secrets"

API_RESOURCES = {
    "/api/v1": (
        ("serviceaccounts", "ServiceAccount", True),
        ("configmaps", "ConfigMap", True),
        ("secrets", "Secret", True),
        ("services", "Service", True),
    ),
    "/apis/apps/v1": (("deployments", "Deployment", True),),
    "/apis/networking.k8s.io/v1": (("networkpolicies", "NetworkPolicy", True),),
    "/apis/rbac.authorization.k8s.io/v1": (
        ("clusterroles", "ClusterRole", False),
        ("clusterrolebindings", "ClusterRoleBinding", False),
    ),
}


def _api_resource_list(path: str) -> dict:
    group_version = "v1" if path == "/api/v1" else path.removeprefix("/apis/")
    return {
        "apiVersion": "v1",
        "kind": "APIResourceList",
        "groupVersion": group_version,
        "resources": [
            {
                "name": name,
                "singularName": "",
                "namespaced": namespaced,
                "kind": kind,
                "verbs": ["get", "list"],
            }
            for name, kind, namespaced in API_RESOURCES[path]
        ],
    }


def _lookup_responses(existing_data: dict[str, str]) -> dict[str, dict]:
    groups = []
    for name in ("apps", "networking.k8s.io", "rbac.authorization.k8s.io"):
        version = {"groupVersion": f"{name}/v1", "version": "v1"}
        groups.append(
            {
                "name": name,
                "versions": [version],
                "preferredVersion": version,
            }
        )
    return {
        "/version": {
            "major": "1",
            "minor": "31",
            "gitVersion": "v1.31.0",
            "gitCommit": "test",
            "gitTreeState": "clean",
            "buildDate": "2026-01-01T00:00:00Z",
            "goVersion": "go1.23",
            "compiler": "gc",
            "platform": "linux/amd64",
        },
        "/api": {
            "apiVersion": "v1",
            "kind": "APIVersions",
            "versions": ["v1"],
            "serverAddressByClientCIDRs": [],
        },
        "/apis": {
            "apiVersion": "v1",
            "kind": "APIGroupList",
            "groups": groups,
        },
        SECRET_PATH: {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "miner-credentials",
                "namespace": "chutes",
                "resourceVersion": "1",
            },
            "type": "Opaque",
            "data": existing_data,
        },
        **{path: _api_resource_list(path) for path in API_RESOURCES},
    }


def _stored_release_secret(existing_data: dict[str, str]) -> dict:
    legacy_manifest = "---\n" + yaml.safe_dump(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "miner-credentials",
                "namespace": "chutes",
            },
            "type": "Opaque",
            "data": existing_data,
        },
        sort_keys=False,
    )
    release = {
        "name": "chutes",
        "info": {
            "first_deployed": "2026-01-01T00:00:00Z",
            "last_deployed": "2026-01-01T00:00:00Z",
            "deleted": "",
            "description": "Install complete",
            "status": "deployed",
            "notes": "",
        },
        "chart": {
            "metadata": {
                "name": "chutes-miner",
                "version": "0.1.0",
                "apiVersion": "v2",
                "type": "application",
            },
            "templates": [],
            "values": {},
            "schema": None,
            "files": [],
        },
        "config": {},
        "manifest": legacy_manifest,
        "version": 1,
        "namespace": "chutes",
    }
    # Helm base64-encodes gzip JSON; the Kubernetes Secret API base64-encodes
    # those stored bytes once more.
    helm_payload = base64.b64encode(
        gzip.compress(
            json.dumps(release, separators=(",", ":")).encode("utf-8"),
            mtime=0,
        )
    )
    api_payload = base64.b64encode(helm_payload).decode("ascii")
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "sh.helm.release.v1.chutes.v1",
            "namespace": "chutes",
            "resourceVersion": "2",
            "labels": {
                "name": "chutes",
                "owner": "helm",
                "status": "deployed",
                "version": "1",
            },
        },
        "type": "helm.sh/release.v1",
        "data": {"release": api_payload},
    }


def _server_upgrade_render(
    tmp_path: Path,
    existing_data: dict[str, str],
    configured_owner: str | None,
) -> tuple[list[dict], list[str]]:
    requested_paths: list[str] = []
    responses = _lookup_responses(existing_data)
    stored_release = _stored_release_secret(existing_data)

    class LookupApiHandler(BaseHTTPRequestHandler):
        def log_message(self, _format, *args):
            return

        def _respond(self, status: int, body: dict) -> None:
            payload = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            requested_paths.append(path)
            if path == RELEASE_LIST_PATH:
                self._respond(
                    200,
                    {
                        "apiVersion": "v1",
                        "kind": "SecretList",
                        "metadata": {"resourceVersion": "2"},
                        "items": [stored_release],
                    },
                )
                return
            if path in responses:
                self._respond(200, responses[path])
                return
            self._respond(
                404,
                {
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "reason": "NotFound",
                    "code": 404,
                },
            )

    server = ThreadingHTTPServer(("127.0.0.1", 0), LookupApiHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        kubeconfig = tmp_path / "kubeconfig"
        kubeconfig.write_text(
            yaml.safe_dump(
                {
                    "apiVersion": "v1",
                    "kind": "Config",
                    "clusters": [
                        {
                            "name": "lookup-test",
                            "cluster": {"server": f"http://127.0.0.1:{server.server_port}"},
                        }
                    ],
                    "contexts": [
                        {
                            "name": "lookup-test",
                            "context": {
                                "cluster": "lookup-test",
                                "user": "lookup-test",
                                "namespace": "chutes",
                            },
                        }
                    ],
                    "current-context": "lookup-test",
                    "users": [{"name": "lookup-test", "user": {}}],
                }
            ),
            encoding="utf-8",
        )
        kubeconfig.chmod(0o600)

        if shutil.which("helm") is not None:
            command = ["helm"]
            chart = str(ROOT / "charts/chutes-miner")
            kubeconfig_arg = str(kubeconfig)
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
                "--network",
                "host",
                "-v",
                f"{ROOT}:/workspace:ro",
                "-v",
                f"{tmp_path}:/lookup-test:ro",
                "-w",
                "/workspace",
                "alpine/helm:latest",
            ]
            chart = "charts/chutes-miner"
            kubeconfig_arg = "/lookup-test/kubeconfig"
        else:
            pytest.skip("neither Helm nor the local alpine/helm image is available")

        command.extend(
            [
                "upgrade",
                "chutes",
                chart,
                "--namespace",
                "chutes",
                "--dry-run=server",
                "--disable-openapi-validation",
                "--kubeconfig",
                kubeconfig_arg,
                "--output",
                "json",
                "--set-string",
                f"seedlessStack.image={STACK_IMAGE}",
            ]
        )
        if configured_owner is not None:
            command.extend(["--set-string", f"minerCredentials.ownerSs58={configured_owner}"])
        upgrade_output = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        release = json.loads(upgrade_output)
        documents = [
            item for item in yaml.safe_load_all(release["manifest"]) if isinstance(item, dict)
        ]
        return documents, requested_paths
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join()


@pytest.mark.parametrize(
    ("existing_owner", "configured_owner", "expected_owner"),
    [
        pytest.param(None, CONFIGURED_OWNER, CONFIGURED_OWNER, id="production-legacy"),
        pytest.param("", CONFIGURED_OWNER, CONFIGURED_OWNER, id="empty-owner"),
        pytest.param(EXISTING_OWNER, None, EXISTING_OWNER, id="existing-owner"),
    ],
)
def test_server_side_upgrade_removes_legacy_keys_and_keeps_nonempty_owner(
    tmp_path,
    existing_owner,
    configured_owner,
    expected_owner,
):
    existing_data = {
        "ss58": base64.b64encode(b"legacy-public-address").decode("ascii"),
        "seed": base64.b64encode(b"legacy-secret-seed").decode("ascii"),
    }
    if existing_owner is not None:
        existing_data["owner"] = base64.b64encode(existing_owner.encode("ascii")).decode("ascii")

    documents, requested_paths = _server_upgrade_render(
        tmp_path,
        existing_data,
        configured_owner,
    )

    assert RELEASE_LIST_PATH in requested_paths
    assert SECRET_PATH in requested_paths
    credentials = next(
        item
        for item in documents
        if item.get("kind") == "Secret"
        and item.get("metadata", {}).get("name") == "miner-credentials"
    )
    assert set(credentials["data"]) == {"owner"}
    rendered_owner = base64.b64decode(credentials["data"]["owner"]).decode("ascii")
    assert rendered_owner == expected_owner
    assert rendered_owner


def test_server_side_legacy_upgrade_requires_public_owner_fallback(tmp_path):
    production_data = {
        "ss58": base64.b64encode(b"legacy-public-address").decode("ascii"),
        "seed": base64.b64encode(b"legacy-secret-seed").decode("ascii"),
    }
    with pytest.raises(subprocess.CalledProcessError) as error:
        _server_upgrade_render(tmp_path, production_data, configured_owner=None)
    assert "minerCredentials.ownerSs58 is required" in error.value.stderr
