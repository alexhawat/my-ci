# My CI

The service, its dashboard and the results it posts to GitHub are all named **my-ci**. It used to be called Local CI; the Python package (`localci`), `LOCALCI_*` environment variables, image tags and container names keep that name.

Self-hosted pull-request CI, optional mergeCraft reviews, and a private web dashboard. Jobs run in disposable Docker containers on your infrastructure; GitHub supplies source and receives results but provides no runners or compute.

## Features

- Polls open, non-draft, same-repository pull requests.
- Shows the checks and statuses GitHub itself reports for every open PR (GitHub Actions and other integrations) next to the local result, including draft and fork PRs that do not run locally.
- Watches a repository without running anything: **Just watch this repo** lists its PRs and their GitHub CI on the dashboard only.
- Merges a PR from the dashboard through GitHub, bound to the commit you reviewed.
- Runs selected Linux GitHub Actions workflows with pinned `act` compatibility fixes, from `.github/workflows/`, any other YAML file in the repository, or a file you upload or paste.
- Supports matrices, parallel jobs, PostgreSQL services, browser tests, and artifacts.
- Optionally adds mergeCraft AI review, run independently of CI and in parallel with it.
- Publishes commit statuses, bounded CI comments, and native review summaries.
- Encrypts locally configured credentials and redacts known values (and, on a best-effort basis, their common encodings) from logs and PR comments; CI artifacts are not redacted.
- Provides cancellation, bounded retries, history, logs, artifacts, analytics, and backups.
- Lets the operator replace a repository's workflow file with a versioned local override.
- Separates the dashboard from the execution service and its Docker socket.

This is not universal GitHub Actions compatibility. Windows and macOS jobs, reusable workflows, custom checkout/submodules/LFS, OIDC, deployment environments, and enabled CodeQL jobs require additional adapters and are rejected explicitly. Fork pull requests are visible but do not execute.

## Architecture

The FastAPI dashboard and execution worker share a versioned SQLite database and durable queue. Each run receives fresh outer containers. The run's privileged CI worker is on its own Docker bridge network, so the CI workers of concurrent runs cannot reach each other over the network. The run's review container is not attached to that network: it uses Docker's default bridge and needs only outbound access to the model provider, so PR code in the CI worker has no direct network path to it. CI jobs use a disposable inner Docker daemon; optional review runs in a separate container with separate credentials and artifact namespaces.

The dashboard has no Docker socket, but the execution worker has host Docker access and starts `--privileged` Docker-in-Docker workers (or, with `LOCALCI_WORKER_RUNTIME=sysbox-runc`, Sysbox system containers). Per-run networks are not a host boundary and do not change this: **PR code is effectively root on the host.** It can access the host data volume and every stored credential, regardless of which values a job references. Enable only repositories and contributors you would trust with host-root access.

Bot-authored PRs (GitHub user type `Bot` or a login ending in `[bot]`, such as Dependabot) do not run automatically. my-ci records a blocked run, "awaiting operator approval"; after reviewing the change, start it from the dashboard with **Retry latest PR** or **Run selected as new runs**. The approval applies to the exact revision of that held run: if the PR's head or base commit has changed since (the bot pushed, or the base branch moved), the retry is refused and the new revision's own held run must be reviewed and started. An approval counts as one attempt in the retry budget. A system-ended run of a bot-authored PR is re-queued automatically only if an operator had started that revision or the repository allows automatic bot runs; otherwise a new held run awaits approval (see [Execution limits](#execution-limits)). The per-repository setting `run_bot_prs` (off by default) restores automatic runs for that repository and starts PRs that are currently held.

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

Open the configured dashboard URL, select **Repositories → Configure**, choose CI workflows, add any required variables and credentials, and explicitly enable the repository. Repositories start disabled. To see a repository's PRs and GitHub CI without running anything, tick **Just watch this repo** instead (see [Watching a repository](#watching-a-repository)). mergeCraft review appears in **Configure** once it is added under **Settings → Integrations**. The dashboard URL is included in public commit statuses and PR comments, so do not use a hostname you need to keep private.

## Configuration

- `LOCALCI_URL`: exact external dashboard origin, without a trailing slash.
- `LOCALCI_HOST_LABEL`: generic display name for the worker.
- `LOCALCI_TAILSCALE_LOGIN`: exact identity allowed by the dashboard.
- `LOCALCI_NESTED_DNS` (optional): comma-separated DNS server IP addresses, passed as the nested Docker daemon's `--dns`, so they apply to every container that daemon starts, including all CI job steps. When it is unset, steps of jobs without `services:` use the worker's own resolver; containers on the nested daemon's user-defined networks (jobs that declare `services:`, `docker compose`, `docker network create`) resolve through its embedded resolver, which forwards to the worker's resolver; only containers on its default bridge (plain `docker run`, `docker build`) fall back to public DNS. Set it if such containers must resolve internal names or public DNS is unreachable.

- `LOCALCI_NESTED_BIP` and `LOCALCI_NESTED_ADDRESS_POOL` (optional): the nested Docker daemon's `--bip` (an IPv4 address with prefix) and `--default-address-pool` base (an IPv4 network of /24 or larger, split into /24 networks). When unset, the nested daemon uses Docker's default bridge range. Set both to ranges unused on the host and its networks when the host's Docker daemon sends container DNS to a resolver on the host's own `docker0` (its `daemon.json` `"dns"` set to the `docker0` address): the nested `docker0` otherwise takes that same address, the worker's lookups reach its own bridge, and every image pull inside CI fails with `lookup … on 127.0.0.11:53: server misbehaving`.
- `LOCALCI_WORKER_RUNTIME` (optional): `privileged` (default) runs CI workers as `--privileged` Docker-in-Docker; `sysbox-runc` runs them as [Sysbox](https://github.com/nestybox/sysbox) system containers, which the host must have installed and registered as a Docker runtime. Sysbox workers run in a user namespace without `--privileged`. `docker cp` cannot write into them, so the controller streams files with tar instead. [SECURITY.md](SECURITY.md) says what this does and does not change.

These are read from `.env`. The following are internal container paths and image names. `compose.yaml` sets only `LOCALCI_REVIEW_IMAGE`; the others use the defaults built into the code, so they matter only when running the services outside Compose:

- `LOCALCI_DATA`: data directory, default `/data`.
- `LOCALCI_TOKEN_FILE`: GitHub token file, default `/run/secrets/github-token`.
- `LOCALCI_WORKER_IMAGE`: disposable CI worker image, default `localci-worker:1`. Set this alongside `LOCALCI_WORKER_RUNTIME` to select a custom Sysbox-compatible image and runtime pair.
- `LOCALCI_REVIEW_IMAGE`: review image. Compose sets `localci-review:1`; outside Compose it is required when review is enabled.

`LOCALCI_SMOKE_GH_AUTH=1` is required to run `smoke.py` and `smoke_artifacts.py`; see [TESTING.md](TESTING.md).

Do not place credentials in `.env.example`, Compose, workflow YAML, or documentation. `login.sh` copies the current GitHub CLI token into the ignored, mode-0600 `runtime/github-token` file without printing it or placing it in command arguments.

### Review token ceiling

Repository settings expose an optional **Review token ceiling** (1–100,000,000). This is an operator-controlled override: the worker writes it into its trusted review config with zero tolerance and a flat round multiplier, and pins the same value in the review process environment. Other base settings and all review gates remain intact. Blank preserves the trusted base budget. PR-head config cannot change its own review policy. Settings are snapshotted per run; save and Retry to apply a new ceiling. The startup log identifies the operator override. Usage arrives after each response, so the final in-flight response may exceed the limit.

### Skip review for matching diffs

Set `review.skipWhenOnly` in the base branch's `.mergecraft/config.yaml` to skip
mergeCraft when every changed path in a nonempty PR diff matches one of the
listed case-sensitive globs. Patterns match full paths relative to the
repository root. For example, `review: {skipWhenOnly: ["execution_files/**"]}`
covers an input-only PR. A cross-directory rename counts as a change at both
paths, and an unreadable diff keeps the normal review path.

my-ci records the skip and runs the configured CI workflows. CI failures
still fail the run. The worker reads the rule before scheduling review and
uses the base commit from the run snapshot.

### Optional lightweight job image

A repository with a lightweight workflow for the paths covered by
`review.skipWhenOnly` can set the my-ci repository variable
`LOCALCI_LIGHTWEIGHT_JOBS` to `true`. Configure this only for workflows whose
`ubuntu-latest` and `ubuntu-24.04` jobs on that path need the lightweight image's
Bash, Git, Python 3, Node.js 24 and Docker CLI. my-ci uses the normal per-run
Docker worker and swaps only the job image archive. A mixed diff, a Dependabot
exemption, or an unavailable archive uses the standard image.

Build and archive the image on the Docker host that runs my-ci:

```sh
docker compose --profile build build lightweight-jobs-image
docker image save -o runtime/lightweight-runner-image.tar localci-jobs-lightweight:1
docker compose -f compose.yaml -f compose.lightweight.yaml up -d app worker
```

For a custom deployment, mount that archive read-only at
`/opt/localci/lightweight-runner-image.tar` in the execution worker. You can
include any pinned Docker images the lightweight jobs use in the same
`docker image save` command to seed their layers before the workflow runs.

### Repository credentials

The dashboard separates two credential scopes:

- **CI workflows** supply `secrets.NAME` to workflows that reference it.
- **Review only** supplies model-provider settings to mergeCraft.

Values are encrypted, write-only, and never imported automatically from GitHub Actions. Each workflow's secrets file contains only the secrets that workflow references (plus the host GitHub token for every selected workflow when host GitHub login is enabled) and is present in the worker only while that workflow runs; between workflows of one run, every container of the nested Docker daemon is removed before the next workflow's secrets file is copied in. A workflow that reads secrets dynamically (`toJSON(secrets)`, `secrets.*`, or `secrets[<expression>]`) receives every CI secret. This limits exposure; it is not a sandbox boundary. Jobs of the same workflow share those secrets, and host-root-equivalent PR code can still reach every stored credential. Use narrow test credentials.

The optional host GitHub login grants CI jobs all permissions of that login; workflow YAML `permissions` does not narrow it under `act`. Leaving it disabled keeps the token out of CI jobs, but once `login.sh` has run the token file exists on the host, where PR code can read it regardless of the setting. Use a dedicated low-privilege GitHub account and token.

Results reach GitHub as a `my-ci` commit status posted with the worker's GitHub login; no GitHub App is needed. To publish a `my-ci` Check Run instead, connect a GitHub App under **Settings → Reporting results to GitHub**. Any App you own works (it need not be a mergeCraft App, although one you already use for mergeCraft can be reused) if it has Checks read/write permission and is installed on the repository; repositories it is not installed on keep getting commit statuses. Provide its App ID and an RSA private key. **Disconnect App** deletes the stored credentials and goes back to commit statuses. App credentials are not passed to CI or review containers, but they are stored in the data volume, which host-root-equivalent PR code can read.

The status context and Check Run were called `local-ci` before they were renamed to `my-ci`. A PR whose head commit already has a `local-ci` result gets `my-ci` from its next run, and the old result is retired so it does not stay beside the new one:

- Check Run: a run that started under `local-ci` is renamed to `my-ci` in place when it is next updated, so no second run appears. Any other `local-ci` Check Run from the same App on that commit is completed as **neutral**, titled "Renamed to my-ci".
- Commit status: a status cannot be deleted or made neutral, so the `local-ci` context on that commit is set once to success with the description "Renamed to my-ci; see the my-ci result for this commit." The `my-ci` status beside it carries the real result.

Nothing is changed until my-ci next publishes for that commit, so a PR that is not re-run keeps its `local-ci` result. Branch protection, rulesets or tools that require `local-ci` need to require `my-ci` instead, because the retired context reports success whatever the new result is. Disconnecting the App before an old Check Run has been retired leaves it in place, since only that App can change it.

Enable **Settings → Integrations → mergeCraft AI review** to reveal **mergeCraft** at the bottom of a repository’s **Configure** dialog. CI workflow credentials have their own section. An empty reviewer pipeline uses the trusted base roster and its existing review credentials.

Use **Add reviewer** for each required review, then **Add backup** on the relevant row. Each model needs a label, a provider/model slug, and a saved or new API key. For example, a security reviewer can have two backups while a second reviewer checks correctness with its own key. Two slots may use the same model with different credentials. Select a node to edit its label, model, key or position. The arrows beside each reviewer change row order. **Save repository settings** applies the graph and any new private values together.

Rows run in sequence under the review’s shared budget and timeout. Each row supports one primary and up to two ordered backups, within the image’s existing attempt limits. Eligible provider failures can advance a chain. Blocking findings and exhausted budgets remain blocking. Retries use the latest saved graph. Queued runs retain their graph and read the current credential values at execution. After upgrading an existing worker, rebuild its review image with `scripts/build_review.sh` before using a dashboard pipeline.

Each provider in a trusted review roster needs its own review-scoped credential binding, using the provider's configured environment index or documented credential name. Credential changes apply to the next execution. A confirmed free-tier HTTP 429 rejection is recorded against its single pending request with zero charged tokens and can proceed to the next configured model with the same shared budget. Completed requests retain their usage; incomplete or ambiguous accounting still stops the review.

Which failures move on to the next model:

- A rate limit (HTTP 429) falls back only on the free model `opencode/deepseek-v4.1-flash-free`, and only when the rejected request is that session's only outstanding request. It is then recorded with zero charged tokens.
- The typed `provider.free-limit` and `provider.no-route` errors also fall back when the failing model is that free model.
- Any other error ends the review without trying the next model. That includes a 429 from any other model, paid or free, and a 429 that arrives while several requests are outstanding: both are incomplete accounting and stop the review.

When accounting stops a review, its run record names the cause after "Complete model usage unavailable", for example "Provider request failed; complete usage unavailable (HTTP 429)". Only fixed texts and the HTTP status code are recorded, never the provider's response.

A roster that starts with a free model sends the review content to that provider's free endpoint first: the diff, the source ranges the reviewer reads, and CI excerpts, for every enabled repository, private ones included. Free tiers often have different data-retention and training terms from paid API access. Check the provider's terms before putting a free model first for private repositories.

### Execution limits

Repository settings control per-workflow job parallelism and time limits; selected workflow files run sequentially. Execution settings control simultaneous runs, CPU/memory reservations, and retry budgets. Defaults adapt to detected capacity, and queued runs report when they cannot fit.

Failed runs are not retried automatically, and manual retries share the configured per-revision budget. An operator's **Cancel** is final for that PR revision until the operator retries it. Runs ended by the system are re-queued automatically as new runs without consuming the retry budget, at most 3 times per PR revision; the original run stays in history. This covers a PR that became a draft or was closed and later returns and a repository that was disabled and re-enabled (both shown as cancelled), and an execution worker that stopped, restarted, or crashed mid-run (shown as an error, or as a failure if a check had already failed). These normally need no manual retry. Automatic re-queueing never bypasses the bot-PR approval gate: a system-ended run of a bot-authored PR is re-queued automatically only if an operator had started that revision or the repository allows automatic bot runs (`run_bot_prs`); otherwise a new held run awaits approval. This also applies after upgrading from a release that ran bot PRs automatically.

A workflow in which no job ran is reported as skipped and named in the run summary rather than counted as passed. If CI workflows are selected and none of them runs any job, the run ends blocked, even when the review passes. A run with neither a CI workflow nor a review to run also ends blocked.

### Updating from the dashboard

**Execution settings → my-ci version** shows the commit the running images were built from and the latest commit on `alexhawat/my-ci@main`. **Update to latest** does what you would otherwise do by hand. New runs pause, and active runs finish first; an update that has not started yet can be cancelled. Then the execution worker starts a short-lived helper container from its own image. The helper:

1. fast-forwards the deployment's git checkout to the upstream branch;
2. rebuilds the `app` and `worker` images with `LOCALCI_VERSION` set to the new commit;
3. recreates both services.

The dashboard is unavailable for about a minute. The new worker records the result and the helper's log, which the panel shows. Runs resume after the update, and also after a failed one.

The update needs:

- a Compose deployment from a git checkout, with every Compose file inside the project directory;
- an `origin` remote the host can fetch without a prompt;
- no uncommitted changes to tracked files. Untracked files such as `.env` and `runtime/` are left alone.

Git runs as the checkout's owner. The update fast-forwards only; a checkout with local commits is refused rather than merged. It rebuilds only the dashboard and execution worker images. When a release changes `Dockerfile.worker`, `Dockerfile.jobs` or the review build, rebuild those by hand as in the quick start; the release notes say when. Images built by hand show an unrecorded version until the first dashboard update, unless built with `--build-arg LOCALCI_VERSION=$(git rev-parse HEAD)`.

- `LOCALCI_UPDATE_REPO` and `LOCALCI_UPDATE_BRANCH` (optional): the repository whose latest commit is shown, default `alexhawat/my-ci`, and the branch to fetch from `origin`, default `main`.
- `LOCALCI_SELF_UPDATE=0` turns the button off.

### Agent access (API + MCP)

Optional **Settings → Integrations → Agent access** exposes a versioned HTTP API at `/api/agent/v1` and an MCP server at `/agent/mcp` on the same tailnet origin as the dashboard. Access is **tailnet-only** (use `tailscale serve`, not Funnel) plus a **Bearer token** you create in the dashboard. Scopes are least-privilege (`read`, `write-config`, `write-runs`); tokens are hashed, audited, and revocable. Setup, threat model, and client JSON examples are in [docs/agent-access.md](docs/agent-access.md).

### Settings and the mergeCraft add-on

The **Settings** page holds the GitHub App described above and the optional integrations. mergeCraft review is an add-on: until it is added under **Settings → Integrations**, **Configure** shows no review options and the API refuses to turn review on. Installations that already review a repository with it keep it added. Removing it turns review off in every repository (queued runs keep their snapshot) and is refused while an enabled repository has nothing but review to run.

The worker asks GitHub for open PRs every 60 seconds and for new repositories every 10 minutes. **Check GitHub now**, in the header, asks right away, for example after creating a repository. Runs never depend on it.

### Workflow sources

A selected workflow can come from:

- `.github/workflows/` on the default branch, listed automatically;
- any other YAML file in the repository, added by its path (such as `ci/pipeline.yml`) under **Configure → Add a workflow from any YAML file**. Like files in `.github/workflows/`, it is read from each PR's base commit;
- a file you upload or YAML you paste there. It is stored on this worker as a local-only workflow named `local:<name>.yml`, never committed, and edited or deleted with **Edit local copy**. Deleting one also unselects it.

Every source must be a GitHub Actions workflow with an `on: pull_request` trigger. A file that is missing from a PR's base commit, or a local workflow deleted after it was selected, blocks that workflow's check with a message instead of running something else. Each workflow runs under its file name; when two selected workflows share a name, later ones get `-2`, `-3` and so on.

### Workflow overrides

**Repositories → Configure** includes a workflow editor. Saving creates a new local version that replaces the base-revision workflow file for that repository in later runs; the file must keep its `pull_request` trigger. Earlier versions stay viewable, each run records which version it used, and reverting returns to the file from the PR's base revision.

### Images

Base images are pinned by digest. The job image installs Chrome from Google's signed apt repository, authenticated by a pinned signing-key fingerprint; the Chrome version is not pinned by default (set the `CHROME_VERSION` build argument to pin one; such a pin builds only while Google's repository still serves that version). Alpine packages in the Docker-in-Docker worker image are not version-pinned. Runner images for the `ubuntu-22.04` and `ubuntu-20.04` labels are pulled by tag at run time; `ubuntu-latest` and `ubuntu-24.04` use the locally built job image.

## GitHub CI and merging

The **PRs** view shows two results for each open pull request. **my-ci** is the run on your worker. **GitHub CI** is what GitHub reports for the PR's head commit: GitHub Actions check runs and commit statuses from other integrations, with a link to each. The `my-ci` result this service publishes, and the `local-ci` result it published before the rename, are left out of that column. GitHub CI is display only: it never starts, cancels or changes a local run. It is read with the worker's GitHub login (one GraphQL request per enabled or watched repository, cached for 20 seconds) and covers the 200 most recently updated open PRs of a repository and the first 100 checks of each.

**Merge** asks GitHub to merge the pull request as the worker's GitHub login, using the merge method you choose from those the repository allows. The request names the head commit shown in the dashboard, so GitHub refuses it if the PR has changed since. my-ci does not gate the button: the confirmation lists a local or GitHub result that is not green, and GitHub's branch protection, required checks and required reviews decide whether the merge is accepted. Draft PRs and PRs with merge conflicts cannot be merged from the dashboard. The login needs write access to the repository; anyone who can reach the dashboard can merge with it.

### Watching a repository

**Repositories → Configure → Just watch this repo** shows a repository's open and closed PRs and their GitHub CI on the **PRs** page without running anything locally: no runs are queued, nothing new is posted to GitHub, and it needs no workflow or credential. The repository stays disabled, so **Retry** and bulk reruns refuse it; **Merge** still works. Watching a repository that ran checks here cancels its active runs, as disabling does. Untick the box to run checks again; the earlier settings are kept.

## Review behavior

Review configuration comes from the trusted base revision. PR-authored mergeCraft/OpenCode configuration and nested `AGENTS.md`/`CLAUDE.md` instructions are removed from the review workspace. The patch given to the reviewer is the exact bytes `git diff` produced between the PR's merge base and head. Shell execution, pushes, approvals, and auto-merge are disabled. Missing credentials, incomplete reviews, timeouts, provider failures, and invalid terminal evidence cannot produce a clean review.

Each review has a fixed USD 5 provider budget and a per-repository timeout of at most 50 minutes (the default). Model calls use your configured provider and its charges/limits. CI and review use separate containers and credential namespaces, but host-root-equivalent PR code can defeat that separation. Findings below the configured severity threshold remain visible without failing an otherwise completed review; execution failures and blocking findings still fail closed.

`scripts/build_review.sh` builds the review image for `linux/amd64` or `linux/arm64` from mergeCraft source `6dc67ab3ce873a4b313553d5e1ac9e469295eb03` and applies and tests the local compatibility patches. For `linux/amd64` it starts from the published mergeCraft image, pinned by digest. Before building, the script runs a digest-pinned Cosign verifier and requires a signature from the upstream main-branch release workflow at the pinned commit. That image is published for `linux/amd64` only, so for `linux/arm64` the script first builds the same revision from the public mergeCraft repository and uses the result as the base. No private registry authentication or provider credential is required.

The script uses the Docker server's platform by default, honors `DOCKER_DEFAULT_PLATFORM`, and lets `REVIEW_PLATFORM` take precedence for an explicit cross-build. A build for the Docker server's own architecture is tagged `localci-review:1`, the tag `compose.yaml` runs. A cross-build is tagged `localci-review:1-<arch>` instead, so it cannot replace the image the worker uses. Set `REVIEW_IMAGE` to choose the tag yourself.

TruffleHog and OSV-Scanner are checksum-verified for the target architecture when they are downloaded. Semgrep is pinned by package version only, without a hash. Each image bakes its own analyzer cache; do not share that cache between architectures. The build verifies the warmed analyzers offline as the review user. The jobs image and the deployment prerequisites above still require x86-64.

Native per-step budget enforcement charges streamed usage once while numeric telemetry retains the final in-flight response. A run-scoped plugin journals numeric cumulative usage for primary and compaction requests; monotonic deltas use upstream enforcement, and normal CLI primary events are reconciled rather than charged twice. Missing, incomplete, decreasing, or mismatched accounting stops the review. Journal request IDs include a process-unique prefix for safe session resumption, and no prompt, response, source, or credential content is journaled. Evidence schemas 1.13.0, 1.19.0, and 1.21.0 remain bound to the recorded reviewer revision and digest.

The confined `read_batch` tool returns up to eight related source or authoritative-diff ranges per model turn. Batches contain at most 24,000 UTF-8 source bytes and 1,000 source lines, and final metadata plus source is validated below 40,000 bytes and 1,100 physical lines before coverage is credited. `@diff` reads the authoritative complete diff; repository paths use the existing Git guards for tracked HEAD files, and absolute paths are limited to guarded Git exports. Native file reads are disabled in the local reviewer. Only complete returned lines count as read, truncation includes a continuation, and budget notices precede source. Shell, approval, coverage, and completion policies remain unchanged.

A reviewer that repeats itself is told, then stopped. From the third identical tool call, or the third time findings are sent for verification with no verdict recorded, the result ends with a note to finish. At the sixth the review stops as inconclusive and the run record names the tool. Counts restart after a context compaction. Agent configuration files stay out of the review working tree, but the verifier now says that such a file is in the reviewed commit instead of telling the judge to drop every finding about it.

Automatic foreground compaction retains recent context and all unresolved findings, evidence, unread ranges, and verification requirements. Summary calls and cached input count toward the same operator ceiling. Full source remains available for targeted rereads.

Metadata SELECTs reopen their SQLite connection and retry only transient `SQLITE_PROTOCOL` WAL-lock races up to four times with bounded backoff. Other database failures and exhausted retries still fail; mutations are never replayed.

## Logs, artifacts, and retention

The dashboard provides structured output, raw output, redacted log export, failure excerpts, run metadata, resource usage, and retained artifacts. The closed-PR view shows only the 200 most recently updated closed PRs per repository. Raw log writing stops after 8 MB. Published run rows, events, resource samples, logs, and artifacts are deleted after 14 days; compact usage totals retain 90 days. PR comments contain bounded excerpts rather than complete logs. Known credential values are redacted from logs and PR comments, together with their base64, JSON-escaped, and URL-encoded forms on a best-effort basis: base64 that a tool wraps across lines is redacted line by line, but a few characters at the very edge of an encoding can remain when the block is interrupted by another job's output or a log flush. CI artifacts are copied without redaction.

## Backup and recovery

Create a consistent archive containing the SQLite database and encryption key:

```sh
docker compose exec -T app python /app/backup.py
```

Archives are written below `/data/backups` with mode 0600 and appear under their final name only once complete. The tool reads the database read-only and never migrates it, so it is safe to run a newer release's tool before upgrading. It fails without creating anything if the database or encryption key is missing. The data volume must support hard links (ordinary Docker named volumes do). Logs and artifacts are omitted. Copy archives out of the container for safekeeping, for example `docker compose cp app:/data/backups/<archive> .`. Keep the database and encryption key together; stored credentials cannot be decrypted without the matching key.

To restore, stop both services (`docker compose stop`) and copy a trusted archive created by this tool into the checkout root. Run the following from the checkout root, since Compose needs `compose.yaml` and `.env` there; it extracts the archive into the data volume and removes obsolete SQLite WAL/SHM sidecars:

```sh
docker compose run --rm --no-deps -T -v "$PWD:/restore:ro" app sh -c \
  'tar -xzf /restore/<archive> -C /data && rm -f /data/localci.db-wal /data/localci.db-shm'
docker compose up -d
```

The archive contains `localci.db` and `encryption.key` at its top level; delete the copy in the checkout root afterwards. Keep `runtime/github-token` separately or rerun `login.sh`.

## Development

```sh
uv sync --frozen
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run pyright
node --check localci/static/app.js
node --test tests/test_history.mjs tests/test_selection.mjs tests/test_render.mjs
```

Tests use temporary databases, synthetic workflow fixtures, and mocked GitHub endpoints. They do not require real repository credentials or paid model calls. Docker smoke scripts create local fixture repositories and should be run only in a suitable disposable Docker environment.

See [TESTING.md](TESTING.md) for validation guidance and [SECURITY.md](SECURITY.md) before deployment.

## CI and review of this repository

Every pull request runs `CI` and `CodeQL`, and pull requests from branches in this repository are reviewed by [mergeCraft](https://github.com/alexhawat/mergeCraft) with Claude Sonnet 5.5. Who can push, merge and trigger reviews, and the one-time settings that back it up, are in [docs/repository-security.md](docs/repository-security.md).

## License

MIT. See [LICENSE](LICENSE).
