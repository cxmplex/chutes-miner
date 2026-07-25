FROM amacneil/dbmate@sha256:3786f8400f02a9c759394a2eb609ed4bd7c81d92bb3495982c9406aaf59e7315 AS dbmate

FROM python:3.12.10-slim-bookworm@sha256:97983fa8cc88343512862c62307159a82261c3528dc025f79e5a3f7af43e50b4

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    HOME=/tmp \
    PYTHONPATH=/app/chutes-common:/app/chutes-miner:/app/chutes-agent:/app/chutes-monitor:/app/chutes-registry

RUN mkdir -p /app && chown 65532:65532 /app

COPY --from=dbmate /usr/local/bin/dbmate /usr/local/bin/dbmate
COPY docker/seedless/requirements.lock /tmp/requirements.lock
RUN python -m pip install \
      --disable-pip-version-check \
      --no-cache-dir \
      --require-hashes \
      --requirement /tmp/requirements.lock \
    && rm /tmp/requirements.lock

COPY --chown=65532:65532 src/chutes-common /app/chutes-common
COPY --chown=65532:65532 src/chutes-miner /app/chutes-miner
COPY --chown=65532:65532 src/chutes-agent /app/chutes-agent
COPY --chown=65532:65532 src/chutes-monitor /app/chutes-monitor
COPY --chown=65532:65532 src/chutes-registry /app/chutes-registry

USER 65532:65532
WORKDIR /app
CMD ["python", "-m", "uvicorn", "--host", "0.0.0.0", "--port", "8000", "chutes_miner.api.main:app"]
