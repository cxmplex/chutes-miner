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
from chutes_miner.api.server.seedless_adoption import adopt_seedless_gpu_server


@asynccontextmanager
async def lifespan(_: FastAPI):
    """
    Execute all initialization/startup code, e.g. ensuring tables exist and such.
    """
    # SQLAlchemy init.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

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
        yield
        return
    try:
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
            if settings.gpu_tee_only:
                raise RuntimeError("seedless GPU database migration failed")

        if settings.gpu_tee_only:
            server_id = await adopt_seedless_gpu_server()
            logger.success(f"adopted registrar-created logical GPU server {server_id}")

        for validator in settings.validators:
            socket_client = SocketClient(
                url=validator.socket,
                validator=validator.hotkey,
            )
            asyncio.create_task(socket_client.connect_and_run())

        yield
    finally:
        await leader_connection.scalar(
            text("SELECT pg_advisory_unlock(hashtextextended('chutes:seedless-api-leader:v1', 0))")
        )
        await leader_connection.close()


app = FastAPI(default_response_class=ORJSONResponse, lifespan=lifespan)
app.include_router(servers_router, prefix="/servers", tags=["Servers"])
app.include_router(deployments_router, prefix="/deployments", tags=["Deployments"])
app.get("/ping")(lambda: {"message": "pong"})


@app.middleware("http")
async def request_body_checksum(request: Request, call_next):
    if request.method in ["POST", "PUT", "PATCH"]:
        body = await request.body()
        sha256_hash = hashlib.sha256(body).hexdigest()
        request.state.body_sha256 = sha256_hash
    else:
        request.state.body_sha256 = None
    return await call_next(request)
