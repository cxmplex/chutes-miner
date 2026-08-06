"""
Miner API entrypoint.
"""

import hashlib
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import ORJSONResponse
from chutes_common.settings import miner_settings as settings
from chutes_registry.api.registry.router import router as registry_router


@asynccontextmanager
async def lifespan(_application: FastAPI):
    if settings.gpu_tee_only:
        # Fail startup when the narrow Gepetto workload channel is not mounted.
        _ = settings.registry_workload_token
    yield


app = FastAPI(default_response_class=ORJSONResponse, lifespan=lifespan)
app.include_router(registry_router, prefix="/registry", tags=["Registry"])
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
