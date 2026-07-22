import base64
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import typer

from chutes_miner_cli import l0_providers


def _private_ipxe(tmp_path):
    path = tmp_path / "boot.ipxe"
    path.write_text("#!ipxe\ndhcp\nboot\n", encoding="ascii")
    path.chmod(0o600)
    return path


class FakeSession:
    def __init__(self, **_kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


def test_latitude_reinstall_request_matches_documented_json_api_shape():
    script = "#!ipxe\ndhcp\nboot\n"
    document = l0_providers._latitude_reinstall_document("l0-chi", script)

    assert document == {
        "data": {
            "type": "reinstalls",
            "attributes": {
                "operating_system": "ipxe",
                "hostname": "l0-chi",
                "ipxe": base64.b64encode(script.encode("ascii")).decode("ascii"),
            },
        }
    }


def test_latitude_adapter_applies_private_ipxe_and_reports_only_state(
    tmp_path, monkeypatch, capsys
):
    ipxe = _private_ipxe(tmp_path)
    token = "LATITUDE_TOKEN_CANARY"
    monkeypatch.setenv("LATITUDESH_BEARER", token)
    monkeypatch.delenv("LATITUDESH_BEARER_FILE", raising=False)
    monkeypatch.setattr(l0_providers.aiohttp, "ClientSession", FakeSession)
    request = AsyncMock(
        side_effect=[
            {},
            {
                "data": {
                    "id": "sv_ABCDEF123456",
                    "type": "servers",
                    "attributes": {"status": "disk_erasing"},
                }
            },
        ]
    )
    monkeypatch.setattr(l0_providers, "_request_json", request)

    l0_providers.latitude_reinstall(
        server_id="sv_ABCDEF123456",
        hostname="l0-chi",
        ipxe_file=ipxe,
        wait=False,
        timeout_seconds=30,
    )

    first = request.await_args_list[0]
    assert first.args[1:] == (
        "POST",
        "https://api.latitude.sh/servers/sv_ABCDEF123456/reinstall",
    )
    assert first.kwargs["content_type"] == "application/vnd.api+json"
    assert first.kwargs["document"] == l0_providers._latitude_reinstall_document(
        "l0-chi",
        ipxe.read_text(encoding="ascii"),
    )
    result = json.loads(capsys.readouterr().out)
    assert result["server_status"] == "disk_erasing"
    assert token not in json.dumps(result)
    assert ipxe.read_text(encoding="ascii") not in json.dumps(result)


def test_ovh_adapter_verifies_exact_script_before_hard_reboot(
    tmp_path, monkeypatch, capsys
):
    ipxe = _private_ipxe(tmp_path)
    script = ipxe.read_text(encoding="ascii")
    token = "OVH_TOKEN_CANARY"
    monkeypatch.setenv("OVH_BEARER_TOKEN", token)
    monkeypatch.delenv("OVH_BEARER_TOKEN_FILE", raising=False)
    monkeypatch.setattr(l0_providers.aiohttp, "ClientSession", FakeSession)
    task = {
        "taskId": 29639479,
        "status": "init",
        "function": "hardReboot",
        "comment": "Reboot asked",
    }
    request = AsyncMock(side_effect=[None, {"bootScript": script}, task])
    monkeypatch.setattr(l0_providers, "_request_json", request)

    l0_providers.ovh_boot(
        service_name="ns1030904.ip-40-160-16.us",
        ipxe_file=ipxe,
        reboot=True,
        wait=False,
        timeout_seconds=30,
    )

    server_url = (
        "https://api.us.ovhcloud.com/v1/dedicated/server/ns1030904.ip-40-160-16.us"
    )
    assert [(call.args[1], call.args[2]) for call in request.await_args_list] == [
        ("PUT", server_url),
        ("GET", server_url),
        ("POST", f"{server_url}/reboot"),
    ]
    assert request.await_args_list[0].kwargs["document"] == {"bootScript": script}
    result = json.loads(capsys.readouterr().out)
    assert result == {
        "provider": "ovh-us",
        "service_name": "ns1030904.ip-40-160-16.us",
        "task_function": "hardReboot",
        "task_id": 29639479,
        "task_status": "init",
    }
    assert token not in json.dumps(result)
    assert script not in json.dumps(result)


def test_provider_secret_files_and_ipxe_must_be_private(tmp_path, monkeypatch):
    credential = tmp_path / "token"
    credential.write_text("secret\n")
    credential.chmod(0o644)
    monkeypatch.delenv("OVH_BEARER_TOKEN", raising=False)
    monkeypatch.setenv("OVH_BEARER_TOKEN_FILE", str(credential))
    with pytest.raises(l0_providers.L0CliError, match="mode-0600"):
        l0_providers._read_private_value("OVH_BEARER_TOKEN")

    ipxe = _private_ipxe(tmp_path)
    ipxe.chmod(0o644)
    with pytest.raises(l0_providers.L0CliError, match="mode-0600"):
        l0_providers._read_private_ipxe(ipxe)


def test_ovh_requires_explicit_reboot_before_reading_credentials_or_ipxe(
    tmp_path, monkeypatch, capsys
):
    ipxe = tmp_path / "does-not-exist.ipxe"
    monkeypatch.delenv("OVH_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("OVH_BEARER_TOKEN_FILE", raising=False)

    with pytest.raises(typer.Exit) as raised:
        l0_providers.ovh_boot(
            service_name="ns1030904.ip-40-160-16.us",
            ipxe_file=ipxe,
            reboot=False,
            wait=False,
            timeout_seconds=30,
        )
    assert raised.value.exit_code == 1
    output = capsys.readouterr().err
    assert "--reboot is required" in output
    assert "OVH_BEARER_TOKEN" not in output


def test_provider_module_contains_no_seed_or_pcs_inputs():
    source = Path(l0_providers.__file__).read_text(encoding="utf-8")
    assert "MINER_SEED" not in source
    assert "PCCS_API_KEY" not in source
    assert "PCCS_PASSWORD" not in source
