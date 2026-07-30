"""Fail-closed regressions for seedless GPU assignment shrink."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

import chutes_common.schemas.orms  # noqa: F401
from chutes_common.schemas.gpu import GPU
from chutes_common.schemas.gpu_adoption import GPUAdoptionRetirement
from chutes_miner.api.server.seedless_adoption import (
    SeedlessAdoptionBlocked,
    _canonical_gpu_id,
    _retire_unassigned_tracked_gpus,
    adopt_seedless_gpu_server,
)


GPU_A = "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
GPU_B = "GPU-bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
GPU_C = "GPU-cccccccc-dddd-eeee-ffff-000000000000"


def _identity() -> dict:
    return {
        "server_id": "logical-server",
        "attestation_id": "attestation-2",
        "allocation_group_id": "group-2",
        "allocation_group_generation": 8,
        "gpu_uuids": [GPU_A, GPU_B],
        "gpu_identifiers": ["h100_sxm", "h100_sxm"],
        "validator": {"hotkey": "5Validator"},
    }


def _gpu(
    gpu_id: str,
    *,
    hardware_uuid: str | None,
    deployment_id: str | None = None,
) -> GPU:
    return GPU(
        gpu_id=gpu_id,
        hardware_uuid=hardware_uuid,
        validator="5Validator",
        server_id="logical-server",
        deployment_id=deployment_id,
        device_info={} if hardware_uuid is None else {"uuid": hardware_uuid},
        model_short_ref="h100_sxm",
        verified=True,
        gpu_allocation_group_id="group-1",
        gpu_allocation_group_generation=7,
    )


class _Session:
    def __init__(self) -> None:
        self.added: list[object] = []
        self.deleted: list[object] = []

    def add(self, value) -> None:
        self.added.append(value)

    async def delete(self, value) -> None:
        self.deleted.append(value)


@pytest.mark.asyncio
async def test_assignment_shrink_three_to_two_audits_and_retires_only_unused_row():
    identity = _identity()
    canonical_b = _canonical_gpu_id(identity["server_id"], GPU_B)
    assigned_a = _gpu("local-a", hardware_uuid=GPU_A)
    assigned_b_legacy = _gpu(canonical_b, hardware_uuid=None)
    stale = _gpu("local-c", hardware_uuid=GPU_C)
    session = _Session()

    retired = await _retire_unassigned_tracked_gpus(
        session,
        tracked=[assigned_a, assigned_b_legacy, stale],
        identity=identity,
        logical_server_id=identity["server_id"],
    )

    assert retired == ["local-c"]
    assert session.deleted == [stale]
    assert assigned_a.hardware_uuid == GPU_A
    assert assigned_b_legacy.hardware_uuid == GPU_B
    [audit] = session.added
    assert isinstance(audit, GPUAdoptionRetirement)
    assert audit.server_id == identity["server_id"]
    assert audit.gpu_id == stale.gpu_id
    assert audit.hardware_uuid == GPU_C
    assert audit.deployment_id is None
    assert audit.prior_gpu_allocation_group_id == "group-1"
    assert audit.prior_gpu_allocation_group_generation == 7
    assert audit.replacement_registration_attestation_id == "attestation-2"
    assert audit.replacement_gpu_allocation_group_id == "group-2"
    assert audit.replacement_gpu_allocation_group_generation == 8


@pytest.mark.asyncio
async def test_uuid_null_unused_legacy_row_is_audited_instead_of_wedging_adoption():
    identity = _identity()
    stale = _gpu("legacy-local-id", hardware_uuid=None)
    session = _Session()

    retired = await _retire_unassigned_tracked_gpus(
        session,
        tracked=[stale],
        identity=identity,
        logical_server_id=identity["server_id"],
    )

    assert retired == ["legacy-local-id"]
    assert session.deleted == [stale]
    [audit] = session.added
    assert audit.hardware_uuid is None
    assert audit.device_info == {}


@pytest.mark.asyncio
async def test_active_stale_gpu_blocks_before_any_retirement_side_effect():
    identity = _identity()
    unused = _gpu("unused-stale", hardware_uuid=GPU_C)
    active = _gpu(
        "active-stale",
        hardware_uuid="GPU-dddddddd-eeee-ffff-0000-111111111111",
        deployment_id="deployment-live",
    )
    session = _Session()

    with pytest.raises(
        SeedlessAdoptionBlocked,
        match=r"active/nonterminal deployment .*gpu=active-stale deployment=deployment-live",
    ):
        await _retire_unassigned_tracked_gpus(
            session,
            tracked=[unused, active],
            identity=identity,
            logical_server_id=identity["server_id"],
        )

    assert session.added == []
    assert session.deleted == []


def test_external_node_labels_are_after_locked_adoption_preconditions():
    source = inspect.getsource(adopt_seedless_gpu_server)
    blocker_scan = source.index("await _retire_unassigned_tracked_gpus(")
    node_commit_marker = source.index("k8s_core_client().patch_node(")
    database_commit = source.index("await session.commit()")
    assert blocker_scan < node_commit_marker < database_commit


def test_retirement_history_has_no_foreign_keys_and_database_immutability_guard():
    assert not GPUAdoptionRetirement.__table__.foreign_keys
    migration = (
        Path(__file__).resolve().parents[2]
        / "src/chutes-miner/chutes_miner/api/migrations/"
        "20260730160000_gpu_adoption_retirement.sql"
    ).read_text(encoding="utf-8")
    up_sql = migration.split("-- migrate:down", 1)[0]
    assert "REFERENCES" not in up_sql.upper()
    assert "BEFORE UPDATE OR DELETE ON gpu_adoption_retirements" in up_sql
    assert "BEFORE TRUNCATE ON gpu_adoption_retirements" in up_sql
    assert "gpu adoption retirement audit rows are immutable" in up_sql
    assert "cannot roll back GPU adoption retirement audit while history exists" in migration
