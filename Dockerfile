FROM docker:29-cli@sha256:34507eb5069d8be82c95dd3b6987d4250fd5fee49b82e2509b7d7a7030740d6d AS docker
FROM ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 AS uv
FROM python:3.15-slim-bookworm@sha256:96599df822d0e1c6bb700014a05c7f3c8cabc6e0f7ff3c4f9f69cee033b4b5d9
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
# Compose and Buildx, for the dashboard's self-update helper (localci/updater.py).
COPY --from=docker /usr/local/libexec/docker/cli-plugins /usr/local/libexec/docker/cli-plugins
COPY --from=uv /uv /usr/local/bin/uv
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY localci ./localci
COPY smoke.py smoke_parallel.py smoke_artifacts.py ./
COPY backup.py ./backup.py
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
# The commit this image was built from, shown on the dashboard; the self-update helper sets it.
ARG LOCALCI_VERSION=""
ENV LOCALCI_VERSION=$LOCALCI_VERSION
CMD ["uvicorn", "localci.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8787", "--no-access-log"]
