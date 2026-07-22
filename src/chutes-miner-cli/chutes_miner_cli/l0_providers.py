"""Seedless provider adapters for verified private L0 iPXE files."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import stat
from pathlib import Path
from time import monotonic
from typing import Any, Dict, Optional
from urllib.parse import quote

import aiohttp
import typer

from chutes_miner_cli.l0 import L0CliError, _print_cli_error

LATITUDE_API_BASE = "https://api.latitude.sh"
OVH_US_API_BASE = "https://api.us.ovhcloud.com/v1"
MAX_IPXE_BYTES = 64 * 1024
PROVIDER_POLL_SECONDS = 5
DEFAULT_PROVIDER_WAIT_SECONDS = 1800
_LATITUDE_SERVER_ID = re.compile(r"^sv_[A-Za-z0-9]{8,64}$")
_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_OVH_SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$")
_LATITUDE_STATUSES = {
    "on",
    "off",
    "unknown",
    "disk_erasing",
    "deploying",
    "failed_deployment",
    "rescue_mode",
}
_OVH_TASK_STATUSES = {
    "cancelled",
    "customerError",
    "doing",
    "done",
    "init",
    "ovhError",
    "todo",
}


def _read_private_value(name: str) -> str:
    direct = os.environ.get(name)
    file_name = os.environ.get(f"{name}_FILE")
    if bool(direct) == bool(file_name):
        raise L0CliError(f"set exactly one of {name} or {name}_FILE")
    if direct is not None:
        value = direct
    else:
        path = Path(file_name).expanduser()
        try:
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_mode & 0o077
            ):
                raise L0CliError(f"{name}_FILE must be one mode-0600 regular file")
            payload = path.read_bytes()
        except OSError as exc:
            raise L0CliError(f"could not read {name}_FILE") from exc
        if not 1 <= len(payload) <= 4096 or b"\x00" in payload:
            raise L0CliError(f"{name}_FILE has an invalid size or content")
        try:
            value = payload.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError as exc:
            raise L0CliError(f"{name}_FILE is not UTF-8") from exc
    if not value or "\r" in value or "\n" in value or "\x00" in value:
        raise L0CliError(f"{name} must contain one non-empty line")
    return value


def _read_private_ipxe(path: Path) -> str:
    path = path.expanduser()
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_mode & 0o077
        ):
            raise L0CliError("iPXE input must be one mode-0600 regular file")
        payload = path.read_bytes()
    except OSError as exc:
        raise L0CliError("could not read the private iPXE input") from exc
    if not 1 <= len(payload) <= MAX_IPXE_BYTES or b"\x00" in payload:
        raise L0CliError("private iPXE input has an invalid size or content")
    try:
        script = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise L0CliError("private iPXE input must be ASCII") from exc
    if not script.startswith("#!ipxe\n") or not script.endswith("\n"):
        raise L0CliError("private iPXE input is not a complete raw iPXE script")
    return script


async def _request_json(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    *,
    token: str,
    expected_status: int,
    document: Optional[Dict[str, Any]] = None,
    content_type: str = "application/json",
) -> Any:
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
    body = None
    if document is not None:
        headers["Content-Type"] = content_type
        body = json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    async with session.request(
        method,
        url,
        data=body,
        headers=headers,
        allow_redirects=False,
    ) as response:
        payload = await response.read()
        if response.status != expected_status:
            raise L0CliError(
                f"provider {method.upper()} request failed with HTTP status {response.status}"
            )
    if not payload:
        return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise L0CliError("provider returned a non-JSON response") from exc


def _latitude_reinstall_document(hostname: str, ipxe_script: str) -> Dict[str, Any]:
    return {
        "data": {
            "type": "reinstalls",
            "attributes": {
                "operating_system": "ipxe",
                "hostname": hostname,
                "ipxe": base64.b64encode(ipxe_script.encode("ascii")).decode("ascii"),
            },
        }
    }


def _latitude_status(payload: Any, server_id: str) -> str:
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("data"), dict)
        or payload["data"].get("id") != server_id
        or payload["data"].get("type") != "servers"
        or not isinstance(payload["data"].get("attributes"), dict)
        or payload["data"]["attributes"].get("status") not in _LATITUDE_STATUSES
    ):
        raise L0CliError("Latitude returned an invalid server status response")
    return payload["data"]["attributes"]["status"]


async def _latitude_server_status(
    session: aiohttp.ClientSession,
    token: str,
    server_id: str,
) -> str:
    payload = await _request_json(
        session,
        "GET",
        f"{LATITUDE_API_BASE}/servers/{quote(server_id, safe='')}",
        token=token,
        expected_status=200,
    )
    return _latitude_status(payload, server_id)


async def _wait_latitude(
    session: aiohttp.ClientSession,
    token: str,
    server_id: str,
    timeout_seconds: int,
    initial_status: str,
) -> str:
    deadline = monotonic() + timeout_seconds
    observed_transitional = initial_status in {"disk_erasing", "deploying"}
    stable_observations = 1 if initial_status in {"on", "off"} else 0
    while True:
        provider_status = await _latitude_server_status(session, token, server_id)
        if provider_status == "failed_deployment":
            raise L0CliError("Latitude reported failed_deployment")
        if provider_status in {"disk_erasing", "deploying"}:
            observed_transitional = True
            stable_observations = 0
        if observed_transitional and provider_status in {"on", "off"}:
            return provider_status
        if provider_status in {"on", "off"}:
            stable_observations += 1
            if stable_observations >= 2:
                return provider_status
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise L0CliError("timed out waiting for Latitude reinstall state")
        await asyncio.sleep(min(PROVIDER_POLL_SECONDS, remaining))


def _validate_ovh_task(payload: Any) -> Dict[str, Any]:
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("taskId"), int)
        or isinstance(payload.get("taskId"), bool)
        or payload["taskId"] < 1
        or payload.get("status") not in _OVH_TASK_STATUSES
        or payload.get("function") != "hardReboot"
    ):
        raise L0CliError("OVHcloud returned an invalid hard-reboot task")
    return payload


async def _ovh_task(
    session: aiohttp.ClientSession,
    token: str,
    service_name: str,
    task_id: int,
) -> Dict[str, Any]:
    payload = await _request_json(
        session,
        "GET",
        (
            f"{OVH_US_API_BASE}/dedicated/server/{quote(service_name, safe='')}"
            f"/task/{task_id}"
        ),
        token=token,
        expected_status=200,
    )
    return _validate_ovh_task(payload)


async def _wait_ovh(
    session: aiohttp.ClientSession,
    token: str,
    service_name: str,
    task_id: int,
    timeout_seconds: int,
) -> Dict[str, Any]:
    deadline = monotonic() + timeout_seconds
    while True:
        task = await _ovh_task(session, token, service_name, task_id)
        if task["status"] == "done":
            return task
        if task["status"] in {"cancelled", "customerError", "ovhError"}:
            raise L0CliError(f"OVHcloud hard-reboot task entered {task['status']}")
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise L0CliError("timed out waiting for OVHcloud hard-reboot task")
        await asyncio.sleep(min(PROVIDER_POLL_SECONDS, remaining))


def _run_provider_command(operation: str, execute) -> None:
    try:
        asyncio.run(execute())
    except L0CliError as exc:
        _print_cli_error(str(exc))
        raise typer.Exit(1) from None
    except (aiohttp.ClientError, OSError):
        _print_cli_error("provider network or local file operation failed")
        raise typer.Exit(1) from None
    except Exception:
        _print_cli_error(f"{operation} failed unexpectedly")
        raise typer.Exit(1) from None


def latitude_reinstall(
    server_id: str = typer.Option(..., "--server-id"),
    hostname: str = typer.Option(..., "--hostname"),
    ipxe_file: Path = typer.Option(..., "--ipxe-file"),
    wait: bool = typer.Option(False, "--wait"),
    timeout_seconds: int = typer.Option(
        DEFAULT_PROVIDER_WAIT_SECONDS,
        "--timeout-seconds",
        min=1,
        max=86400,
    ),
) -> None:
    """Apply a verified seedless iPXE file through Latitude's reinstall API."""

    async def execute() -> None:
        if not _LATITUDE_SERVER_ID.fullmatch(server_id):
            raise L0CliError("--server-id is not a canonical Latitude server ID")
        if not _HOSTNAME.fullmatch(hostname) or ".." in hostname or len(hostname) > 253:
            raise L0CliError("--hostname has an invalid format")
        ipxe_script = _read_private_ipxe(ipxe_file)
        token = _read_private_value("LATITUDESH_BEARER")
        timeout = aiohttp.ClientTimeout(total=60, connect=30, sock_read=60)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            response = await _request_json(
                session,
                "POST",
                (f"{LATITUDE_API_BASE}/servers/{quote(server_id, safe='')}/reinstall"),
                token=token,
                expected_status=201,
                document=_latitude_reinstall_document(hostname, ipxe_script),
                content_type="application/vnd.api+json",
            )
            if response not in (None, {}):
                raise L0CliError("Latitude returned an unexpected reinstall response")
            provider_status = await _latitude_server_status(session, token, server_id)
            if provider_status == "failed_deployment":
                raise L0CliError("Latitude reported failed_deployment")
            if wait:
                provider_status = await _wait_latitude(
                    session,
                    token,
                    server_id,
                    timeout_seconds,
                    provider_status,
                )
        typer.echo(
            json.dumps(
                {
                    "provider": "latitude",
                    "server_id": server_id,
                    "request_status": "accepted",
                    "server_status": provider_status,
                },
                sort_keys=True,
            )
        )

    _run_provider_command("Latitude reinstall", execute)


def ovh_boot(
    service_name: str = typer.Option(..., "--service-name"),
    ipxe_file: Path = typer.Option(..., "--ipxe-file"),
    reboot: bool = typer.Option(
        False,
        "--reboot",
        help="Required acknowledgement that this command performs a hard reboot.",
    ),
    wait: bool = typer.Option(False, "--wait"),
    timeout_seconds: int = typer.Option(
        DEFAULT_PROVIDER_WAIT_SECONDS,
        "--timeout-seconds",
        min=1,
        max=86400,
    ),
) -> None:
    """Install inline OVH iPXE, verify it, and start a hard-reboot task."""

    async def execute() -> None:
        if not _OVH_SERVICE_NAME.fullmatch(service_name) or ".." in service_name:
            raise L0CliError("--service-name has an invalid format")
        if not reboot:
            raise L0CliError("--reboot is required before any provider side effect")
        ipxe_script = _read_private_ipxe(ipxe_file)
        token = _read_private_value("OVH_BEARER_TOKEN")
        server_url = (
            f"{OVH_US_API_BASE}/dedicated/server/{quote(service_name, safe='')}"
        )
        timeout = aiohttp.ClientTimeout(total=60, connect=30, sock_read=60)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            response = await _request_json(
                session,
                "PUT",
                server_url,
                token=token,
                expected_status=200,
                document={"bootScript": ipxe_script},
            )
            if response not in (None, {}):
                raise L0CliError("OVHcloud returned an unexpected boot update response")
            server = await _request_json(
                session,
                "GET",
                server_url,
                token=token,
                expected_status=200,
            )
            if not isinstance(server, dict) or server.get("bootScript") != ipxe_script:
                raise L0CliError("OVHcloud did not retain the exact inline bootScript")
            task = _validate_ovh_task(
                await _request_json(
                    session,
                    "POST",
                    f"{server_url}/reboot",
                    token=token,
                    expected_status=200,
                )
            )
            if wait:
                task = await _wait_ovh(
                    session,
                    token,
                    service_name,
                    task["taskId"],
                    timeout_seconds,
                )
        typer.echo(
            json.dumps(
                {
                    "provider": "ovh-us",
                    "service_name": service_name,
                    "task_id": task["taskId"],
                    "task_function": task["function"],
                    "task_status": task["status"],
                },
                sort_keys=True,
            )
        )

    _run_provider_command("OVHcloud boot", execute)


def register(app: typer.Typer) -> None:
    app.command("latitude-reinstall")(latitude_reinstall)
    app.command("ovh-boot")(ovh_boot)
