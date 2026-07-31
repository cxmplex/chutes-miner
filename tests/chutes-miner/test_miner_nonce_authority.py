"""Per-deployment launch authority regressions for MIN-NONCE-01."""

from __future__ import annotations

from contextlib import asynccontextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import chutes_miner.gepetto as gepetto_module
from chutes_miner.api.exceptions import DeploymentFailure
from chutes_miner.api.k8s.util import canonical_miner_launch_sha256
from chutes_miner.gepetto import Gepetto


DEPLOYMENT_ONE = "11111111-1111-4111-8111-111111111111"
DEPLOYMENT_TWO = "22222222-2222-4222-8222-222222222222"


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


def _chute_and_server():
    return (
        SimpleNamespace(
            validator="validator-1",
            chute_id="chute-1",
            version="1.0.0",
        ),
        SimpleNamespace(
            server_id="server-1",
            kubernetes_node_uid="node-uid-1",
            kubernetes_node_generation=1,
            gpu_allocation_group_id="group-1",
            gpu_allocation_group_generation=1,
        ),
    )


@pytest.mark.asyncio
async def test_two_legitimate_deployments_get_distinct_authority_and_exact_replay(
    monkeypatch,
):
    added = []
    session_count = 0

    @asynccontextmanager
    async def fake_session():
        nonlocal session_count
        existing = added[0] if session_count == 2 else None
        session_count += 1
        session = SimpleNamespace(
            execute=AsyncMock(side_effect=[None, _Result(existing)]),
            add=added.append,
            commit=AsyncMock(),
        )
        yield session

    monkeypatch.setattr(gepetto_module, "get_session", fake_session)
    coordinator = object.__new__(Gepetto)
    chute, server = _chute_and_server()

    first_intent = await coordinator._begin_launch_intent(chute, server, None, DEPLOYMENT_ONE)
    second_intent = await coordinator._begin_launch_intent(chute, server, None, DEPLOYMENT_TWO)
    replayed_intent = await coordinator._begin_launch_intent(chute, server, None, DEPLOYMENT_ONE)

    assert first_intent != second_intent
    assert replayed_intent == first_intent
    assert len(added) == 2
    assert added[0].deployment_id == DEPLOYMENT_ONE
    assert added[1].deployment_id == DEPLOYMENT_TWO
    assert added[0].lineage_sha256 != added[1].lineage_sha256
    assert added[0].request_payload["lineage"]["deployment_id"] == DEPLOYMENT_ONE
    assert added[1].request_payload["lineage"]["deployment_id"] == DEPLOYMENT_TWO


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "deployment_id",
    ["not-a-uuid", "11111111-1111-4111-8111-11111111111A", None],
)
async def test_launch_authority_rejects_noncanonical_deployment_ids(deployment_id):
    coordinator = object.__new__(Gepetto)
    chute, server = _chute_and_server()

    with pytest.raises(DeploymentFailure, match="deployment identity"):
        await coordinator._begin_launch_intent(chute, server, None, deployment_id)


def test_replay_swapping_only_the_deployment_uuid_fails_closed():
    coordinator = object.__new__(Gepetto)
    chute, server = _chute_and_server()
    lineage = coordinator._launch_lineage(chute, server, None, DEPLOYMENT_ONE)
    request = {
        "schema": "chutes.miner-launch-request.v1",
        "miner_launch_request_id": "intent-1",
        "lineage": lineage,
    }
    intent = SimpleNamespace(
        intent_id="intent-1",
        deployment_id=DEPLOYMENT_ONE,
        validator=chute.validator,
        chute_id=chute.chute_id,
        chute_version=chute.version,
        server_id=server.server_id,
        job_id=None,
        job_cleanup_only=False,
        request_payload=request,
        request_sha256=canonical_miner_launch_sha256(request),
        lineage_sha256=canonical_miner_launch_sha256(lineage),
    )
    assert coordinator._validated_launch_intent(intent) == lineage

    swapped = deepcopy(intent)
    swapped.request_payload["lineage"]["deployment_id"] = DEPLOYMENT_TWO
    swapped.request_sha256 = canonical_miner_launch_sha256(swapped.request_payload)
    swapped.lineage_sha256 = canonical_miner_launch_sha256(swapped.request_payload["lineage"])
    with pytest.raises(DeploymentFailure, match="deployment identity changed"):
        coordinator._validated_launch_intent(swapped)


@pytest.mark.asyncio
async def test_validator_request_carries_exact_miner_deployment_id(monkeypatch):
    captured = {}

    class Response:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {"token": "token-1", "config_id": "config-1"}

    class Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def get(self, url, *, headers, params):
            captured.update(url=url, headers=headers, params=params)
            return Response()

    monkeypatch.setattr(gepetto_module.settings, "gpu_tee_only", False)
    monkeypatch.setattr(gepetto_module.aiohttp, "ClientSession", Client)
    monkeypatch.setattr(
        gepetto_module,
        "sign_request",
        lambda **_kwargs: ({"Authorization": "signed"}, b""),
    )
    coordinator = object.__new__(Gepetto)
    payload = await coordinator._fetch_launch_config(
        validator=SimpleNamespace(api="https://validator.example"),
        chute_id="chute-1",
        server_id="server-1",
        job_id=None,
        intent_id="intent-1",
        deployment_id=DEPLOYMENT_ONE,
    )

    assert payload == {"token": "token-1", "config_id": "config-1"}
    assert captured["params"] == {
        "chute_id": "chute-1",
        "server_id": "server-1",
        "miner_launch_request_id": "intent-1",
        "miner_deployment_id": DEPLOYMENT_ONE,
    }
