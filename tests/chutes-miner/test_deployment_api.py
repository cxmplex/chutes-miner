import asyncio
from types import SimpleNamespace

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.sql.selectable import Select
from fastapi.testclient import TestClient
from fastapi import FastAPI, HTTPException

from chutes_miner.api.deployment.router import router, purge, purge_deployment
from chutes_common.schemas.deployment import Deployment
from chutes_miner.api.server.router import purge_server

# Create test app
app = FastAPI()
app.include_router(router, prefix="/deployments")
client = TestClient(app)


def _durable_gepetto(operation_id="operation-1"):
    teardown = SimpleNamespace(
        request=AsyncMock(return_value=operation_id),
        run=AsyncMock(return_value=True),
    )
    return SimpleNamespace(teardown=teardown)


def _close_scheduled(coroutine):
    coroutine.close()
    return MagicMock()


@pytest.fixture
def mock_deployment():
    """Create a mock deployment object."""
    deployment = MagicMock(spec=Deployment)
    deployment.deployment_id = "test-deployment-id"
    deployment.chute_id = "test-chute-id"
    deployment.server_id = "test-server-id"

    # Set up related objects
    deployment.chute = MagicMock()
    deployment.chute.name = "test-chute-name"
    deployment.server = MagicMock()
    deployment.server.name = "test-server-name"
    deployment.gpus = [MagicMock(), MagicMock()]  # Two mock GPUs

    return deployment


@pytest.mark.asyncio
async def test_purge_endpoint(mock_db_session, mock_deployment):
    """Test the purge endpoint."""
    # Set up mock query result
    mock_result = MagicMock()
    mock_result.unique.return_value = mock_result
    mock_result.scalars.return_value = mock_result
    mock_result.all.return_value = [mock_deployment]
    mock_db_session.execute = AsyncMock(return_value=mock_result)

    # Mock Gepetto
    mock_gepetto = _durable_gepetto()

    with (
        patch("chutes_miner.api.deployment.router.Gepetto", return_value=mock_gepetto),
        patch(
            "chutes_miner.api.deployment.router.asyncio.create_task",
            side_effect=_close_scheduled,
        ),
    ):
        with patch("chutes_miner.api.deployment.router.logger") as mock_logger:
            # Call the function
            response = await purge(db=mock_db_session)

            # Assertions
            assert response["status"] == "initiated"
            assert len(response["deployments_purged"]) == 1
            assert response["deployments_purged"][0]["chute_id"] == "test-chute-id"
            assert response["deployments_purged"][0]["chute_name"] == "test-chute-name"
            assert response["deployments_purged"][0]["server_id"] == "test-server-id"
            assert response["deployments_purged"][0]["server_name"] == "test-server-name"
            assert response["deployments_purged"][0]["gpu_count"] == 2

            # Verify logger was called
            mock_logger.warning.assert_called_once()

            # Verify create_task was called to undeploy
            mock_db_session.execute.assert_called_once()
            mock_gepetto.teardown.request.assert_awaited_once_with(
                "test-deployment-id", "management_purge_all"
            )


@pytest.mark.asyncio
async def test_purge_deployment_endpoint(mock_db_session, mock_deployment):
    """Test the purge_deployment endpoint."""
    # Set up mock query result for a single deployment
    mock_result = MagicMock()
    mock_result.unique.return_value = mock_result
    mock_result.scalar_one_or_none.return_value = mock_deployment
    mock_db_session.execute = AsyncMock(return_value=mock_result)

    # Mock Gepetto
    mock_gepetto = _durable_gepetto()

    with (
        patch("chutes_miner.api.deployment.router.Gepetto", return_value=mock_gepetto),
        patch(
            "chutes_miner.api.deployment.router.asyncio.create_task",
            side_effect=_close_scheduled,
        ),
    ):
        with patch("chutes_miner.api.deployment.router.logger") as mock_logger:
            # Call the function
            response = await purge_deployment(
                deployment_id="test-deployment-id", db=mock_db_session
            )

            # Assertions
            assert response["status"] == "initiated"
            assert response["deployment_purged"] == mock_deployment

            # Verify logger was called
            mock_logger.warning.assert_called_once()

            # Verify db.execute was called with the right query
            mock_db_session.execute.assert_called_once()
            # Get the first positional argument of the first call
            call_args = mock_db_session.execute.call_args[0][0]
            # Check that it's a select query
            assert isinstance(call_args, Select)
            mock_gepetto.teardown.request.assert_awaited_once_with(
                "test-deployment-id", "management_purge_single"
            )


@pytest.mark.asyncio
async def test_purge_server_endpoint(mock_db_session, mock_deployment):
    """Test the purge_server endpoint."""
    # Set up mock query result for a single deployment
    mock_result = MagicMock()
    mock_result.unique.return_value = mock_result
    mock_result.scalars.return_value = mock_result
    mock_result.all.return_value = [mock_deployment]
    mock_db_session.execute = AsyncMock(return_value=mock_result)

    # Mock Gepetto
    mock_gepetto = _durable_gepetto()

    with (
        patch("chutes_miner.api.server.router.Gepetto", return_value=mock_gepetto),
        patch(
            "chutes_miner.api.server.router.asyncio.create_task",
            side_effect=_close_scheduled,
        ),
    ):
        with patch("chutes_miner.api.server.router.logger") as mock_logger:
            # Call the function
            response = await purge_server(id_or_name="test-deployment-id", db=mock_db_session)

            # Assertions
            assert response["status"] == "initiated"
            assert len(response["deployments_purged"]) == 1
            assert response["deployments_purged"][0]["chute_id"] == "test-chute-id"
            assert response["deployments_purged"][0]["chute_name"] == "test-chute-name"
            assert response["deployments_purged"][0]["server_id"] == "test-server-id"
            assert response["deployments_purged"][0]["server_name"] == "test-server-name"
            assert response["deployments_purged"][0]["gpu_count"] == 2

            # Verify logger was called
            mock_logger.warning.assert_called_once()

            # Verify db.execute was called with the right query
            mock_db_session.execute.assert_called_once()
            # Get the first positional argument of the first call
            call_args = mock_db_session.execute.call_args[0][0]
            # Check that it's a select query
            assert isinstance(call_args, Select)
            mock_gepetto.teardown.request.assert_awaited_once_with(
                "test-deployment-id", "management_purge_server"
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("route", "router_module", "reason"),
    [
        ("all", "chutes_miner.api.deployment.router", "management_purge_all"),
        ("single", "chutes_miner.api.deployment.router", "management_purge_single"),
        ("server", "chutes_miner.api.server.router", "management_purge_server"),
    ],
)
async def test_purge_cancellation_happens_only_after_durable_request(
    mock_db_session,
    mock_deployment,
    route,
    router_module,
    reason,
):
    result = MagicMock()
    result.unique.return_value = result
    result.scalars.return_value = result
    result.all.return_value = [mock_deployment]
    result.scalar_one_or_none.return_value = mock_deployment
    mock_db_session.execute = AsyncMock(return_value=result)
    gepetto = _durable_gepetto("persisted-operation")

    def cancel_after_persist(coroutine):
        coroutine.close()
        gepetto.teardown.request.assert_awaited_once_with(
            "test-deployment-id", reason
        )
        raise asyncio.CancelledError

    with (
        patch(f"{router_module}.Gepetto", return_value=gepetto),
        patch(f"{router_module}.asyncio.create_task", side_effect=cancel_after_persist),
        pytest.raises(asyncio.CancelledError),
    ):
        if route == "all":
            await purge(db=mock_db_session)
        elif route == "single":
            await purge_deployment("test-deployment-id", db=mock_db_session)
        else:
            await purge_server("test-server-id", db=mock_db_session)


@pytest.mark.asyncio
async def test_purge_invalid_deployment_id(mock_db_session):
    """Test purge_deployment with an invalid deployment ID."""
    # Set up mock query result for no deployments
    mock_result = MagicMock()
    mock_result.unique.return_value = mock_result
    mock_result.scalar_one_or_none.return_value = None
    mock_db_session.execute = AsyncMock(return_value=mock_result)

    # Mock Gepetto
    mock_gepetto = MagicMock()

    with patch("chutes_miner.api.deployment.router.Gepetto", return_value=mock_gepetto):
        # This should raise an HTTPException because the deployment is None
        with pytest.raises(HTTPException):
            await purge_deployment(deployment_id="nonexistent-id", db=mock_db_session)


@pytest.mark.asyncio
async def test_purge_empty_deployments(mock_db_session):
    """Test purge with no deployments."""
    # Set up mock query result for no deployments
    mock_result = MagicMock()
    mock_result.unique.return_value = mock_result
    mock_result.scalars.return_value = mock_result
    mock_result.all.return_value = []
    mock_db_session.execute = AsyncMock(return_value=mock_result)

    # Mock Gepetto
    mock_gepetto = MagicMock()

    with patch("chutes_miner.api.deployment.router.Gepetto", return_value=mock_gepetto):
        # Call the function
        response = await purge(db=mock_db_session)

        # Assertions
        assert response["status"] == "initiated"
        assert len(response["deployments_purged"]) == 0
