# My CI

The `my-ci` repository contains **Local CI**, the name the service, dashboard, and GitHub statuses use.

Self-hosted pull-request CI, optional mergeCraft reviews, and a private web dashboard. Jobs run in disposable Docker containers on your infrastructure; GitHub supplies source and receives results but provides no runners or compute.

## Features

- Polls open, non-draft, same-repository pull requests.
- Runs selected Linux GitHub Actions workflows with pinned `act` compatibility fixes.
- Supports matrices, parallel jobs, PostgreSQL services, browser tests, and artifacts.
- Runs CI and mergeCraft review independently and in parallel.
- Publishes commit statuses, bounded CI comments, and native review summaries.
- Encrypts locally configured credentials and redacts known values from logs and PR comments; CI artifacts are not redacted.
- Provides cancellation, bounded retries, history, logs, artifacts, analytics, and backups.
- Lets the operator replace a repository's workflow file with a versioned local override.
- Separates the dashboard from the execution service and its Docker socket.

This is not universal GitHub Actions compatibility. Windows and macOS jobs, reusable workflows, custom checkout/submodules/LFS, OIDC, deployment environments, and enabled CodeQL jobs require additional adapters and are rejected explicitly. Fork pull requests are visible but do not execute.

## Architecture

The FastAPI dashboard and execution worker share a versioned SQLite database and durable queue. Each run receives fresh outer containers on its own Docker bridge network, so concurrent runs cannot reach each other over the network; the CI worker and review container of the same run share that network. CI jobs use a disposable inner Docker daemon; optional review runs in a separate container with separate credentials and artifact namespaces.

The dashboard has no Docker socket, but the execution worker has host Docker access and starts `--privileged` Docker-in-Docker workers. Per-run networks do not change this: **PR code is effectively root on the host.** It can access the host data volume and every stored credential, regardless of which values a job references. Enable only repositories and contributors you would trust with host-root access.

Bot-authored PRs (GitHub user type `Bot` or a login ending in `[bot]`, such as Dependabot) do not run automatically. Local CI records a blocked run, "awaiting operator approval"; after reviewing the change, start it from the dashboard with **Retry latest PR** or **Run selected as new runs**. The approval applies to the exact revision of that held run: if the bot has pushed since, the retry is refused and the new revision's own held run must be reviewed and started. An approval counts as one attempt in the retry budget. The per-repository setting `run_bot_prs` (off by default) restores automatic runs for that repository and starts PRs that are currently held.

## Prerequisites

- A dedicated, single-user Linux x86-64 host with Docker and Docker Compose; local users and containers must be trusted.
- Python 3.12 or newer for local development.
- GitHub CLI for authentication.
- Tailscale Serve, or an equivalently strict authenticated local ingress.
- Internet access for source, packages, images, and configured model providers.

## Quick start

Clone the repository into the directory you will run it from. The commands below run from the checkout root; Compose reads `.env` and `runtime/` there.

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
- `LOCALCI_NESTED_DNS` (optional): comma-separated DNS server IP addresses for containers that CI jobs start with Docker (`docker build`, `docker run`, service containers). Each run's worker sits on its own Docker network, where the nested Docker daemon cannot use the host's resolver and falls back to public DNS. Set this if those containers must resolve internal names or cannot reach public DNS; job steps themselves are not affected.
These are read from `.env`. The following are internal container paths and image names. `compose.yaml` sets only `LOCALCI_REVIEW_IMAGE`; the others use the defaults built into the code, so they matter only when running the services outside Compose:

- `LOCALCI_DATA`: data directory, default `/data`.
- `LOCALCI_TOKEN_FILE`: GitHub token file, default `/run/secrets/github-token`.
- `LOCALCI_WORKER_IMAGE`: disposable CI worker image, default `localci-worker:1`.
- `LOCALCI_REVIEW_IMAGE`: review image. Compose sets `localci-review:1`; outside Compose it is required when review is enabled.

`LOCALCI_SMOKE_GH_AUTH=1` is required to run `smoke.py` and `smoke_artifacts.py`; see [TESTING.md](TESTING.md).

Do not place credentials in `.env.example`, Compose, workflow YAML, or documentation. `login.sh` copies the current GitHub CLI token into the ignored, mode-0600 `runtime/github-token` file without printing it or placing it in command arguments.

### Repository credentials

The dashboard separates two credential scopes:

- **CI workflows** supply `secrets.NAME` to workflows that reference it.
- **Review only** supplies model-provider settings to mergeCraft.

Values are encrypted, write-only, and never imported automatically from GitHub Actions. Each workflow's secrets file contains only the secrets that workflow references (plus the host GitHub token for every selected workflow when host GitHub login is enabled) and is present in the worker only while that workflow runs. A workflow that reads secrets dynamically (`toJSON(secrets)`, `secrets.*`, or `secrets[<expression>]`) receives every CI secret. This limits exposure; it is not a sandbox boundary. Jobs of the same workflow share those secrets, and host-root-equivalent PR code can still reach every stored credential. Use narrow test credentials.

The optional host GitHub login grants CI jobs all permissions of that login; workflow YAML `permissions` does not narrow it under `act`. Leaving it disabled keeps the token out of CI jobs, but once `login.sh` has run the token file exists on the host, where PR code can read it regardless of the setting. Use a dedicated low-privilege GitHub account and token.

For repository-scoped Check Runs, connect a GitHub App with Checks read/write permission and an RSA private key. App credentials are not passed to CI or review containers, but they are stored in the data volume, which host-root-equivalent PR code can read.

### Execution limits

Repository settings control per-workflow job parallelism and time limits; selected workflow files run sequentially. Execution settings control simultaneous runs, CPU/memory reservations, and retry budgets. Defaults adapt to detected capacity, and queued runs report when they cannot fit.

Failed runs are not retried automatically, and manual retries share the configured per-revision budget. An operator's **Cancel** is final for that PR revision until the operator retries it. Runs cancelled by the system are re-queued automatically without consuming the retry budget, at most 3 times per PR revision: the PR became a draft or was closed and later returns, the repository was disabled and re-enabled, or the execution worker stopped, restarted, or crashed mid-run.

A workflow in which no job ran is reported as skipped and named in the run summary rather than counted as passed. If no selected workflow ran any job and no review ran, the run ends blocked with "No checks executed".

### Workflow overrides

**Repositories → Configure** includes a workflow editor. Saving creates a new local version that replaces the base-revision workflow file for that repository in later runs; the file must keep its `pull_request` trigger. Earlier versions stay viewable, each run records which version it used, and reverting returns to the file from the PR's base revision.

### Images

Base images are pinned by digest. The job image installs Chrome from Google's signed apt repository, authenticated by a pinned signing-key fingerprint; the Chrome version is not pinned by default (set the `CHROME_VERSION` build argument to pin one; such a pin builds only while Google's repository still serves that version). Alpine packages in the Docker-in-Docker worker image are not version-pinned. Runner images for the `ubuntu-22.04` and `ubuntu-20.04` labels are pulled by tag at run time; `ubuntu-latest` and `ubuntu-24.04` use the locally built job image.

## Review behavior

Review configuration comes from the trusted base revision. PR-authored mergeCraft/OpenCode configuration and nested `AGENTS.md`/`CLAUDE.md` instructions are removed from the review workspace. Shell execution, pushes, approvals, and auto-merge are disabled. Missing credentials, incomplete reviews, timeouts, provider failures, and invalid terminal evidence cannot produce a clean review.

Each review has a fixed USD 5 provider budget and a per-repository timeout of at most 50 minutes (the default). Model calls use your configured provider and its charges/limits. CI and review use separate containers and credential namespaces, but host-root-equivalent PR code can defeat that separation. Findings below the configured severity threshold remain visible without failing an otherwise completed review; execution failures and blocking findings still fail closed.

`scripts/build_review.sh` builds the pinned upstream runtime from the public mergeCraft source revision and then applies the local compatibility patches. It requires no private container registry or provider credential.

## Logs, artifacts, and retention

The dashboard provides structured output, raw output, redacted log export, failure excerpts, run metadata, resource usage, and retained artifacts. The closed-PR view shows only the 200 most recently updated closed PRs per repository. Raw log writing stops after 8 MB. Published run rows, events, resource samples, logs, and artifacts are deleted after 14 days; compact usage totals retain 90 days. PR comments contain bounded excerpts rather than complete logs. CI artifacts are copied without redaction.

## Backup and recovery

Create a consistent archive containing the SQLite database and encryption key:

```sh
docker compose exec -T app python /app/backup.py
```

Archives are written below `/data/backups` with mode 0600 and appear under their final name only once complete. The tool fails without creating anything if the database or encryption key is missing. Logs and artifacts are omitted. Copy archives out of the container for safekeeping. Keep the database and encryption key together; stored credentials cannot be decrypted without the matching key.

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
