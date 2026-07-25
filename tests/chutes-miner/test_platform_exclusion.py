import inspect

import pytest

from chutes_miner.gepetto import Gepetto


def test_platform_marker_is_fail_closed_and_remote_refresh_filters_it():
    assert Gepetto._platform_managed({"management_mode": "platform"})
    assert Gepetto._platform_managed({"gpu_management_mode": "platform"})
    assert not Gepetto._platform_managed({"management_mode": "miner"})

    source = inspect.getsource(Gepetto._remote_refresh_objects)
    assert "Gepetto._platform_managed(data)" in source


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "handler",
    [
        "gpu_verified",
        "instance_created",
        "instance_verified",
        "job_created",
        "job_deleted",
        "gpu_deleted",
        "instance_activated",
        "instance_deleted",
        "server_deleted",
        "chute_created",
        "chute_updated",
        "chute_deleted",
        "rolling_update",
    ],
)
async def test_every_gepetto_resource_event_ignores_platform_managed(handler):
    gepetto = Gepetto.__new__(Gepetto)
    await getattr(gepetto, handler)(
        {
            "management_mode": "platform",
            "gpu_management_mode": "platform",
        }
    )
