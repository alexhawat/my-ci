# Contributing

Use a feature branch and keep changes focused. Do not commit real infrastructure names, private repository references, deployment paths, credentials, operational logs, customer information, or private project details. Use synthetic fixtures; where documentation or tests need a hostname or email address, use `example.com`. The workflow fixture `tests/fixtures/example-ci.yml` must not reference any external endpoint, including `example.com`.

Before submitting a pull request, run:

```sh
uv sync --frozen
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run pyright
node --check localci/static/app.js
node --test tests/test_history.mjs tests/test_selection.mjs
```

For execution changes, also run the relevant local Docker smoke tests in a disposable environment. Do not run paid model reviews or publish results to real repositories merely to validate a change.

The privacy release tests must pass for every change. If a test fixture needs a password or token, use an unmistakable fixture-only value.
