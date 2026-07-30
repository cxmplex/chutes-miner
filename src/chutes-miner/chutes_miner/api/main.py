"""
Miner API entrypoint.
"""

import asyncio
import hashlib
from contextlib import asynccontextmanager
from loguru import logger
from fastapi import FastAPI, Request
from fastapi.responses import ORJSONResponse
from sqlalchemy import text
import chutes_common.schemas.orms  # noqa: F401
from chutes_miner.api.server.router import router as servers_router
from chutes_miner.api.deployment.router import router as deployments_router
from chutes_miner.api.database import engine
from chutes_common.schemas import Base
from chutes_miner.api.config import settings
from chutes_miner.api.socket_client import SocketClient
from chutes_miner.api.server.seedless_adoption import (
    SeedlessAdoptionBlocked,
    adopt_seedless_gpu_server,
)
from chutes_miner.api.schema_barrier import (
    wait_for_required_schema,
    wait_for_seedless_adoption,
)


SEEDLESS_ADOPTION_RETRY_SECONDS = 5.0


async def _adopt_seedless_gpu_server_with_retry() -> str:
    """Retry only deployment-owned adoption barriers; fail fast on every other defect."""

    while True:
        try:
            return await adopt_seedless_gpu_server()
        except SeedlessAdoptionBlocked as exc:
            logger.warning("{}; adoption remains unready and will be retried", exc)
            await asyncio.sleep(SEEDLESS_ADOPTION_RETRY_SECONDS)


def _start_socket_clients() -> list[asyncio.Task]:
    tasks = []
    for validator in settings.validators:
        socket_client = SocketClient(
            url=validator.socket,
            validator=validator.hotkey,
        )
        tasks.append(asyncio.create_task(socket_client.connect_and_run()))
    return tasks


async def _cancel_tasks(tasks: list[asyncio.Task]) -> None:
    for task in tasks:
        if not task.done():
            task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def _complete_blocked_leader_readiness(application: FastAPI) -> None:
    """Reconcile a typed adoption blocker while serving only health endpoints."""

    try:
        server_id = await _adopt_seedless_gpu_server_with_retry()
        logger.success(f"adopted registrar-created logical GPU server {server_id}")
        await wait_for_seedless_adoption(engine, settings.seedless_gpu_identity)
        application.state.socket_tasks = _start_socket_clients()
        application.state.readiness_reason = None
        application.state.schema_ready = True
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - remain fail-closed and operator-visible
        application.state.readiness_reason = "seedless_adoption_failed"
        logger.exception(f"seedless GPU adoption reconciliation failed: {exc}")


async def _complete_follower_readiness(application: FastAPI) -> None:
    try:
        await wait_for_seedless_adoption(engine, settings.seedless_gpu_identity)
        application.state.readiness_reason = None
        application.state.schema_ready = True
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - remain fail-closed and operator-visible
        application.state.readiness_reason = "seedless_adoption_failed"
        logger.exception(f"seedless GPU adoption wait failed: {exc}")


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Apply schema/adoption gates while keeping health endpoints observable."""

    application.state.schema_ready = False
    application.state.readiness_reason = "required_schema_unavailable"
    application.state.socket_tasks = []
    readiness_task = None
    leader_connection = await engine.connect()
    is_migration_process = bool(
        await leader_connection.scalar(
            text(
                "SELECT pg_try_advisory_lock(hashtextextended('chutes:seedless-api-leader:v1', 0))"
            )
        )
    )
    if not is_migration_process:
        await leader_connection.close()
        await wait_for_required_schema(engine)
        if settings.gpu_tee_only:
            application.state.readiness_reason = "seedless_adoption_pending"
            readiness_task = asyncio.create_task(
                _complete_follower_readiness(application)
            )
        else:
            application.state.readiness_reason = None
            application.state.schema_ready = True
        try:
            yield
        finally:
            application.state.schema_ready = False
            if readiness_task is not None:
                await _cancel_tasks([readiness_task])
        return
    try:
        # The elected API worker is the only metadata/migration owner.
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        # Manual DB migrations.
        process = await asyncio.create_subprocess_exec(
            "dbmate",
            "--url",
            settings.sqlalchemy.replace("+asyncpg", "") + "?sslmode=disable",
            "--migrations-dir",
            settings.migrations_dir,
            "migrate",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def log_migrations(stream, name):
            log_method = logger.info if name == "stdout" else logger.warning
            while True:
                line = await stream.readline()
                if line:
                    decoded_line = line.decode().strip()
                    log_method(decoded_line)
                else:
                    break

        await asyncio.gather(
            log_migrations(process.stdout, "stdout"),
            log_migrations(process.stderr, "stderr"),
            process.wait(),
        )
        if process.returncode == 0:
            logger.success("successfully applied all DB migrations")
        else:
            logger.error(f"failed to run db migrations returncode={process.returncode}")
            raise RuntimeError("miner database migration failed")

        await wait_for_required_schema(engine)
        if settings.gpu_tee_only:
            try:
                server_id = await adopt_seedless_gpu_server()
            except SeedlessAdoptionBlocked as exc:
                application.state.readiness_reason = "seedless_adoption_blocked"
                logger.warning("{}; serving health endpoints while adoption retries", exc)
                readiness_task = asyncio.create_task(
                    _complete_blocked_leader_readiness(application)
                )
            else:
                logger.success(
                    f"adopted registrar-created logical GPU server {server_id}"
                )
                await wait_for_seedless_adoption(
                    engine, settings.seedless_gpu_identity
                )
                application.state.socket_tasks = _start_socket_clients()
                application.state.readiness_reason = None
                application.state.schema_ready = True
        else:
            application.state.socket_tasks = _start_socket_clients()
            application.state.readiness_reason = None
            application.state.schema_ready = True
        yield
    finally:
        application.state.schema_ready = False
        if readiness_task is not None:
            await _cancel_tasks([readiness_task])
        await _cancel_tasks(application.state.socket_tasks)
        unlocked = await leader_connection.scalar(
            text("SELECT pg_advisory_unlock(hashtextextended('chutes:seedless-api-leader:v1', 0))")
        )
        if not unlocked:
            logger.error("seedless API leader advisory lock was not held at shutdown")
        await leader_connection.close()


app = FastAPI(default_response_class=ORJSONResponse, lifespan=lifespan)
app.include_router(servers_router, prefix="/servers", tags=["Servers"])
app.include_router(deployments_router, prefix="/deployments", tags=["Deployments"])


@app.get("/ping")
async def ping(request: Request):
    if getattr(request.app.state, "readiness_reason", None) == "seedless_adoption_failed":
        return ORJSONResponse(
            status_code=500,
            content={
                "message": "seedless adoption reconciliation failed",
                "reason": "seedless_adoption_failed",
            },
        )
    return {"message": "pong"}


@app.get("/ready")
async def ready(request: Request):
    if not getattr(request.app.state, "schema_ready", False):
        return ORJSONResponse(
            status_code=503,
            content={
                "ready": False,
                "reason": getattr(
                    request.app.state,
                    "readiness_reason",
                    "required_schema_unavailable",
                ),
            },
        )
    return {"ready": True}


@app.middleware("http")
async def request_body_checksum(request: Request, call_next):
    if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
        body = await request.body()
        request.state.body_sha256 = hashlib.sha256(body).hexdigest() if body else None
    else:
        request.state.body_sha256 = None
    return await call_next(request)


@app.middleware("http")
async def readiness_barrier(request: Request, call_next):
    if request.url.path not in {"/ping", "/ready"} and not getattr(
        request.app.state, "schema_ready", False
    ):
        return ORJSONResponse(
            status_code=503,
            content={
                "detail": "miner_not_ready",
                "reason": getattr(
                    request.app.state,
                    "readiness_reason",
                    "required_schema_unavailable",
                ),
            },
        )
    return await call_next(request)
