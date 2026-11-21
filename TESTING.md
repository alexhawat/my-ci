# Testing

## Automated checks

The Python suite covers queue persistence, retries, cancellation, workflow policy, reporting, redaction, credential isolation, artifact handling, dashboard authentication, execution limits, backup archive creation (read-only, non-migrating snapshots) and failure handling, and database restore from backups. JavaScript tests cover run history, filtering, sorting, selection, and bounded reruns.

```sh
uv sync --frozen
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run pyright
node --check localci/static/app.js
node --test tests/test_history.mjs tests/test_selection.mjs
```

Privacy release tests reject personal paths, non-public commit identities, common credential formats, concrete private IPv4/IPv6 and Tailscale addresses and hostnames (documented IPv6 ranges with an empty host part, such as `fd00::/8`, are allowed), the former private registry namespace, non-placeholder email addresses, and non-synthetic workflow fixtures without embedding a denylist of private names. Files and commit message bodies are both checked for personal paths, private network names and email addresses; the only allowed addresses are at example.com, example.org or example.net (and their subdomains), `users.noreply.github.com` addresses, `git@github.com`, and the `noreply@anthropic.com` co-author trailer. They also verify generic deployment defaults and configurable host labels.

## Docker validation

`smoke.py`, `smoke_parallel.py`, and `smoke_artifacts.py` use local fixture repositories to exercise execution, parallelism, intentional failures, and artifacts. Run them inside the execution worker service, which has the Docker socket, on a disposable CI host. `smoke.py` and `smoke_artifacts.py` require `LOCALCI_SMOKE_GH_AUTH=1` and the host token file (`LOCALCI_TOKEN_FILE`, default `/run/secrets/github-token`). They pass that real token to jobs that run third-party actions, so use a dedicated low-privilege account. `smoke_parallel.py` uses a fixture token. No paid model credentials are required. The authenticated smoke tests size their run using the Docker daemon's available CPUs and memory, just as the worker scheduler does.

On a host with Sysbox registered, run `docker compose run --rm --no-deps worker python smoke_sysbox.py` after building the images and saving the jobs image as described in the README. This fixture selects Sysbox, uses synthetic credentials, checks the outer container's runtime and privilege flag, and runs two workflows as the jobs image's unprivileged user. It checks the PR checkout, the per-workflow secret file, artifact contents, and worker and network cleanup.

The parallel smoke test also checks that repository variables with shell metacharacters reach jobs unchanged. To pass a value literally, bind it with step-level `env:` and expand the quoted shell variable. GitHub Actions substitutes expressions in `run:` before the shell executes the script.

```yaml
- env:
    VALUE: ${{ vars.NAME }}
  run: printf '%s\n' "$VALUE"
```

Build the review runtime from its pinned public source with `scripts/build_review.sh`. The script needs network access for source and dependencies, but no private registry login or model-provider credential.

On a Linux Docker host with native ARM64 support or ARM64 emulation enabled, verify the ARM64 review image and its warmed analyzers with:

```sh
REVIEW_PLATFORM=linux/arm64 REVIEW_IMAGE=localci-review:arm64-check bash scripts/build_review.sh
docker image inspect --format '{{.Os}}/{{.Architecture}}' localci-review:arm64-check
docker run --rm --platform linux/arm64 --network none --user mergecraft --entrypoint python \
  localci-review:arm64-check /opt/localci/test_review_analyzers.py linux-arm64
```

The architecture output should be `linux/arm64`. The offline check refuses to run as root, validates the binary architecture of TruffleHog, OSV-Scanner and `semgrep-core`, checks the TruffleHog and OSV-Scanner versions, runs Semgrep against a local fixture, and exercises platform selection, catalog provenance, and checksum rejection. Managed analyzers outside the warm-up list retain on-demand provisioning. This check covers the review image. Full deployment and the jobs image require an x86-64 host.

Live GitHub reporting and paid provider reviews are optional acceptance checks, not prerequisites for the unit suite. Use dedicated test repositories and narrow credentials if you choose to run them.

## Compatibility limits

The workflow adapter rejects unsupported features explicitly. A skipped or unsupported check is not evidence of a successful scan. Browser, PostgreSQL, artifact, and nested Docker behavior require the relevant Docker smoke coverage in addition to mocked unit tests.
