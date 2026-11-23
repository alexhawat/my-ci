FROM docker:29-cli@sha256:34507eb5069d8be82c95dd3b6987d4250fd5fee49b82e2509b7d7a7030740d6d AS docker
FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv
FROM python:3.14-slim-bookworm@sha256:3fe1a0b6c2d6b2ebb572906cdabeca75aeb558c0c17db5ffefbcf8094871c32b
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
# Compose and Buildx, for the dashboard's self-update helper (localci/updater.py).
COPY --from=docker /usr/local/libexec/docker/cli-plugins /usr/local/libexec/docker/cli-plugins
COPY --from=uv /uv /usr/local/bin/uv
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY localci ./localci
COPY smoke.py smoke_parallel.py smoke_artifacts.py smoke_sysbox.py ./
COPY backup.py ./backup.py
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
# The commit this image was built from, shown on the dashboard; the self-update helper sets it.
ARG LOCALCI_VERSION=""
ENV LOCALCI_VERSION=$LOCALCI_VERSION
CMD ["uvicorn", "localci.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8787", "--no-access-log"]
