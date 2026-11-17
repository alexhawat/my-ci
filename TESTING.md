# Testing

## Automated checks

The Python suite covers queue persistence, retries, cancellation, workflow policy, reporting, redaction, credential isolation, artifact handling, dashboard authentication, execution limits, backup archive creation and failure handling, and database restore from backups. JavaScript tests cover run history, filtering, sorting, selection, and bounded reruns.

```sh
uv sync --frozen
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run pyright
node --check localci/static/app.js
node --test tests/test_history.mjs tests/test_selection.mjs
```

Privacy release tests reject personal paths, non-public commit identities, common credential formats, private-network addresses and hostnames, private registry namespaces, non-placeholder email addresses, and non-synthetic workflow fixtures without embedding a denylist of private names. They also verify generic deployment defaults and configurable host labels.

## Docker validation

`smoke.py`, `smoke_parallel.py`, and `smoke_artifacts.py` use local fixture repositories to exercise execution, parallelism, intentional failures, and artifacts. Run them inside the execution worker service, which has the Docker socket, on a disposable CI host. `smoke.py` and `smoke_artifacts.py` require `LOCALCI_SMOKE_GH_AUTH=1` and the host token file (`LOCALCI_TOKEN_FILE`, default `/run/secrets/github-token`). They pass that real token to jobs that run third-party actions, so use a dedicated low-privilege account. `smoke_parallel.py` uses a fixture token. No paid model credentials are required.

Build the review runtime from its pinned public source with `scripts/build_review.sh`. The script needs network access for source and dependencies, but no private registry login or model-provider credential.

Live GitHub reporting and paid provider reviews are optional acceptance checks, not prerequisites for the unit suite. Use dedicated test repositories and narrow credentials if you choose to run them.

## Compatibility limits

The workflow adapter rejects unsupported features explicitly. A skipped or unsupported check is not evidence of a successful scan. Browser, PostgreSQL, artifact, and nested Docker behavior require the relevant Docker smoke coverage in addition to mocked unit tests.
