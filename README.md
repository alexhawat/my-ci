# My CI

Self-hosted pull-request CI, optional mergeCraft reviews, and a private web dashboard. Jobs run in disposable Docker containers on your infrastructure; GitHub supplies source and receives results but provides no runners or compute.

## Features

- Polls open, non-draft, same-repository pull requests.
- Runs selected Linux GitHub Actions workflows with pinned `act` compatibility fixes.
- Supports matrices, parallel jobs, PostgreSQL services, browser tests, and artifacts.
- Runs CI and mergeCraft review independently and in parallel.
- Publishes commit statuses, bounded CI comments, and native review summaries.
- Encrypts locally configured credentials and redacts known values from logs and PR comments; CI artifacts are not redacted.
- Provides cancellation, bounded retries, history, logs, artifacts, analytics, and backups.
- Separates the dashboard from the execution service and its Docker socket.

This is not universal GitHub Actions compatibility. Windows and macOS jobs, reusable workflows, custom checkout/submodules/LFS, OIDC, deployment environments, and enabled CodeQL jobs require additional adapters and are rejected explicitly. Fork pull requests are visible but do not execute.

## Architecture

The FastAPI dashboard and execution worker share a versioned SQLite database and durable queue. Each run receives fresh outer containers. CI jobs use a disposable inner Docker daemon; optional review runs in a separate container with separate credentials and artifact namespaces.

The dashboard has no Docker socket, but the execution worker has host Docker access and starts privileged Docker-in-Docker workers. **PR code is effectively root on the host.** It can access the host data volume and every stored credential, regardless of which values a job references. Enable only repositories and contributors you would trust with host-root access. Do not run dependency-bot or other upstream-authored changes without reviewing them first.

## Prerequisites

- A dedicated, single-user Linux x86-64 host with Docker and Docker Compose; local users and containers must be trusted.
- Python 3.12 or newer for local development.
- GitHub CLI for authentication.
- Tailscale Serve, or an equivalently strict authenticated local ingress.
- Internet access for source, packages, images, and configured model providers.

## Quick start

Clone the repository and choose an installation directory such as `/opt/my-ci`:

```sh
git clone https://github.com/alexhawat/my-ci.git
cd my-ci
cp .env.example .env
```

Edit `.env` and set the exact externally visible dashboard URL and permitted Tailscale login. Then build the images and prepare the local runner:

```sh
bash login.sh
docker compose --profile build build app worker worker-image jobs-image
bash scripts/build_review.sh
docker image save -o runtime/runner-image.tar localci-jobs:1
docker compose up -d app worker
```

Bind only the local backend with your authenticated ingress. For Tailscale Serve:

```sh
tailscale serve --bg --https=9443 http://127.0.0.1:8787
```

Set `LOCALCI_URL` to the complete external origin, including `:9443`; write requests reject a mismatched `Origin`. An alternative ingress must strip every client-supplied `Tailscale-User-Login` header and insert the authenticated identity itself. The application cannot distinguish a forged header from a trusted proxy on a multi-user host.

Open the configured dashboard URL, select **Repositories → Configure**, choose CI workflows and/or review, add any required variables and credentials, and explicitly enable the repository. Repositories start disabled. The dashboard URL is included in public commit statuses and PR comments, so do not use a hostname you need to keep private.

## Configuration

- `LOCALCI_URL`: exact external dashboard origin, without a trailing slash.
- `LOCALCI_HOST_LABEL`: generic display name for the worker.
- `LOCALCI_TAILSCALE_LOGIN`: exact identity allowed by the dashboard.
- `LOCALCI_DATA`: data directory, defaulting to `/data` in containers.
- `LOCALCI_TOKEN_FILE`: GitHub token file, defaulting to `/run/secrets/github-token`.
- `LOCALCI_WORKER_IMAGE`: disposable CI worker image, defaulting to `localci-worker:1`.
- `LOCALCI_REVIEW_IMAGE`: review image; Compose sets `localci-review:1`.
- `LOCALCI_SMOKE_GH_AUTH`: opt-in real-token requirement for Docker smoke tests.

Do not place credentials in `.env.example`, Compose, workflow YAML, or documentation. `login.sh` copies the current GitHub CLI token into the ignored, mode-0600 `runtime/github-token` file without printing it or placing it in command arguments.

### Repository credentials

The dashboard separates two credential scopes:

- **CI workflows** supply `secrets.NAME` to selected jobs.
- **Review only** supplies model-provider settings to mergeCraft.

Values are encrypted, write-only, and never imported automatically from GitHub Actions. Use narrow test credentials. The optional host GitHub login grants CI jobs all permissions of that login; workflow YAML `permissions` does not narrow it under `act`. Leave it disabled unless needed and trusted.

For repository-scoped Check Runs, connect a GitHub App with Checks read/write permission and an RSA private key. App credentials remain in the trusted service and do not enter CI or review containers.

### Execution limits

Repository settings control per-workflow job parallelism and time limits; selected workflow files run sequentially. Execution settings control simultaneous runs, CPU/memory reservations, and retry budgets. Defaults adapt to detected capacity, and queued runs report when they cannot fit. Failed runs are not retried automatically; cancelled and worker-interrupted runs recover automatically, while manual retries share the configured per-revision budget.

## Review behavior

Review configuration comes from the trusted base revision. PR-authored mergeCraft/OpenCode configuration and nested `AGENTS.md`/`CLAUDE.md` instructions are removed from the review workspace. Shell execution, pushes, approvals, and auto-merge are disabled. Missing credentials, incomplete reviews, timeouts, provider failures, and invalid terminal evidence cannot produce a clean review.

Model calls use your configured provider and its charges/limits. CI and review use separate containers and credential namespaces, but host-root-equivalent PR code can defeat that separation. Findings below the configured severity threshold remain visible without failing an otherwise completed review; execution failures and blocking findings still fail closed.

`scripts/build_review.sh` builds the pinned upstream runtime from the public mergeCraft source revision and then applies the local compatibility patches. It requires no private container registry or provider credential.

## Logs, artifacts, and retention

The dashboard provides structured output, raw output, redacted log export, failure excerpts, run metadata, resource usage, and retained artifacts. Raw log writing stops after 8 MB. Published run rows, events, resource samples, logs, and artifacts are deleted after 14 days; compact usage totals retain 90 days. PR comments contain bounded excerpts rather than complete logs. CI artifacts are copied without redaction.

## Backup and recovery

Create a consistent archive containing the SQLite database and encryption key:

```sh
docker compose exec -T app python /app/backup.py
```

Archives are written below `/data/backups` with mode 0600. Logs and artifacts are omitted. Copy archives out of the container for safekeeping. Keep the database and encryption key together; stored credentials cannot be decrypted without the matching key.

To restore, stop both services, extract only a trusted archive created by this tool into the data volume, remove obsolete SQLite WAL/SHM sidecars, and restart. Keep `runtime/github-token` separately or rerun `login.sh`.

## Development

```sh
uv sync --frozen
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run pyright
node --check localci/static/app.js
node --test tests/test_history.mjs tests/test_selection.mjs
```

Tests use temporary databases, synthetic workflow fixtures, and mocked GitHub endpoints. They do not require real repository credentials or paid model calls. Docker smoke scripts create local fixture repositories and should be run only in a suitable disposable Docker environment.

See [TESTING.md](TESTING.md) for validation guidance and [SECURITY.md](SECURITY.md) before deployment.

## License

MIT. See [LICENSE](LICENSE).
