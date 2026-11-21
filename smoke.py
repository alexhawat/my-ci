"""Exercise the real runner against local fixture commits, without GitHub writes.

Run inside the execution worker service, which has the Docker socket, with
LOCALCI_SMOKE_GH_AUTH=1 and the host token file (LOCALCI_TOKEN_FILE, default
/run/secrets/github-token). The real token reaches jobs that run third-party actions.
"""

import asyncio
import json
import os
import subprocess
import tempfile
import zipfile
from pathlib import Path

from localci.github import GitHub
from localci.runner import Runner
from localci.store import Store

WORKFLOW = """name: Docker integration
on: pull_request
jobs:
  database:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:17-bookworm
        env:
          POSTGRES_PASSWORD: smoke-test-only
        ports: ['5432:5432']
        options: --health-cmd pg_isready --health-interval 2s --health-retries 30
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      - uses: astral-sh/setup-uv@d0d8abe699bfb85fec6de9f7adb5ae17292296ff
        with: {version: '0.13.1'}
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
        with: {node-version: '22'}
      - name: Python and Node toolchains
        run: |
          uv sync --frozen --python 3.13
          uv run python -c 'import sys; assert sys.version_info[:2] == (3, 13)'
          npm ci
          npm run check
      - name: Database, browser binary, and nested Docker
        run: |
          test "$(cat /proc/1/comm)" = docker-init
          test -f source.txt
          test "$(id -u)" != 0
          google-chrome --version
          google-chrome --headless --disable-gpu --dump-dom about:blank 2>/dev/null | grep '<html>'
          docker ps --format '{{.Image}}' | grep postgres
          node -e 'const s=require("net").connect(5432,"127.0.0.1",()=>{console.log("PostgreSQL reachable");s.end()});s.on("error",()=>process.exit(1))'
          mkdir -p output
          echo local-artifact > output/proof.txt
      - uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25
        with:
          scan-type: fs
          scan-ref: .
          scanners: secret
          skip-db-update: true
          skip-java-db-update: true
          exit-code: '1'
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9
        with:
          name: local-proof
          path: output/proof.txt
  matrix:
    needs: database
    runs-on: ubuntu-latest
    strategy:
      matrix:
        value: [one, two]
    steps:
      - run: echo 'matrix ${{ matrix.value }}'
"""


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.DEVNULL).decode().strip()


async def main():
    if os.environ.get("LOCALCI_SMOKE_GH_AUTH") != "1":
        raise SystemExit(
            "Set LOCALCI_SMOKE_GH_AUTH=1 to test authenticated Trivy checkout with the mounted gh login"
        )
    with tempfile.TemporaryDirectory(prefix="localci-smoke-") as directory:
        root = Path(directory)
        source = root / "source"
        source.mkdir()
        git(source, "init", "-b", "main")
        git(source, "config", "user.name", "Local CI test")
        git(source, "config", "user.email", "localci@localhost")
        (source / ".github/workflows").mkdir(parents=True)
        (source / ".github/workflows/ci.yml").write_text(WORKFLOW)
        (source / "source.txt").write_text("base")
        (source / "pyproject.toml").write_text(
            '[project]\nname="fixture"\nversion="0.1.0"\nrequires-python=">=3.13"\n'
        )
        await asyncio.to_thread(subprocess.check_call, ["uv", "lock", "--directory", str(source)])
        (source / "index.js").write_text("console.log('local CI');\n")
        (source / "package.json").write_text(
            json.dumps({"name": "fixture", "version": "1.0.0", "scripts": {"check": "node --check index.js"}})
        )
        (source / "package-lock.json").write_text(
            json.dumps(
                {
                    "name": "fixture",
                    "version": "1.0.0",
                    "lockfileVersion": 3,
                    "requires": True,
                    "packages": {"": {"name": "fixture", "version": "1.0.0"}},
                }
            )
        )
        git(source, "add", ".")
        git(source, "commit", "-m", "Fixture base")
        base = git(source, "rev-parse", "HEAD")
        (source / "source.txt").write_text("PR head")
        git(source, "commit", "-am", "Fixture PR")
        head = git(source, "rev-parse", "HEAD")
        token = root / "token"
        token.write_text(Path(os.environ.get("LOCALCI_TOKEN_FILE", "/run/secrets/github-token")).read_text())
        token.chmod(0o600)
        store = Store(root / "data" / "db")
        info = json.loads(
            await asyncio.to_thread(
                subprocess.check_output, ["docker", "info", "--format", "{{json .}}"], text=True
            )
        )
        execution = store.settings({"cpus": info["NCPU"], "memory_gb": info["MemTotal"] // 2**30})
        runner = Runner(store, GitHub(token), root / "data", lambda *_: {})
        original = runner.command

        async def fixture_command(*args, **kwargs):
            args = tuple(str(source) if a == "https://github.com/fixture/localci.git" else a for a in args)
            return await original(*args, **kwargs)

        runner.command = fixture_command
        repo = {
            "full_name": "fixture/localci",
            "name": "localci",
            "default_branch": "main",
            "owner": {"login": "fixture"},
        }
        pr = {
            "number": 1,
            "title": "Smoke PR",
            "state": "open",
            "draft": False,
            "user": {"login": "fixture"},
            "head": {"sha": head, "ref": "feature", "repo": repo},
            "base": {"sha": base, "ref": "main", "repo": repo},
        }
        rid = store.enqueue(
            "fixture/localci",
            pr,
            {"workflows": [".github/workflows/ci.yml"], "github_auth": "gh", "timeout": 1800},
        )
        await runner.execute(store.claim(execution))
        row = store.rows("SELECT state,message,steps FROM runs WHERE id=?", (rid,))[0]
        print(json.dumps(row))
        print((root / "data/logs" / f"{rid}.log").read_text()[-18000:])
        artifacts = list((root / "data/artifacts" / rid).rglob("*"))
        print("Artifact paths:", [str(p.relative_to(root / "data/artifacts" / rid)) for p in artifacts])
        if row["state"] != "success" or not any(p.is_file() for p in artifacts):
            raise SystemExit(1)
        archives = [p for p in artifacts if p.is_file() and zipfile.is_zipfile(p)]
        assert archives, "No readable artifact ZIP"
        with zipfile.ZipFile(archives[0]) as archive:
            assert archive.read("proof.txt").strip() == b"local-artifact"
        assert token.read_text().strip() not in (root / "data/logs" / f"{rid}.log").read_text()
        print(
            "PASS: configured Docker workflow, latest upload-artifact ZIP content, token redaction, and cleanup"
        )
        # A separate PR with a deliberate failure must never be reported green.
        (source / ".github/workflows/ci.yml").write_text(
            "on: pull_request\njobs:\n  failing:\n    runs-on: ubuntu-latest\n    steps:\n      - run: exit 7\n"
        )
        git(source, "commit", "-am", "Failure fixture base")
        pr["base"]["sha"] = git(source, "rev-parse", "HEAD")
        (source / "source.txt").write_text("failure PR")
        git(source, "commit", "-am", "Failure PR")
        pr["head"]["sha"] = git(source, "rev-parse", "HEAD")
        rid = store.enqueue(
            "fixture/localci",
            pr,
            {"workflows": [".github/workflows/ci.yml"], "github_auth": "gh", "timeout": 1800},
        )
        await runner.execute(store.claim(execution))
        row = store.rows("SELECT state,message FROM runs WHERE id=?", (rid,))[0]
        print(json.dumps(row))
        if row["state"] != "failure":
            print((root / "data/logs" / f"{rid}.log").read_text()[-10000:])
            raise SystemExit(1)
        print("PASS: failing workflow is reported as failure")


if __name__ == "__main__":
    asyncio.run(main())
