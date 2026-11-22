"""Run a local two-workflow fixture through the real Sysbox worker and nested act."""

import asyncio
import os
import subprocess
import tempfile
import zipfile
from pathlib import Path

from localci.github import GitHub
from localci.runner import Runner
from localci.store import Store
from smoke import git

FIRST = """on: pull_request
jobs:
  proof:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      - env:
          INPUT: ${{ secrets.FIXTURE_KEY }}
        run: |
          test "$(id -u)" != 0
          test "$INPUT" = fixture-only-value
          test "$(cat revision.txt)" = head
          echo verified > proof.txt
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9
        with:
          name: sysbox-proof
          path: proof.txt
"""
SECOND = """on: pull_request
jobs:
  next:
    runs-on: ubuntu-latest
    steps:
      - run: test "$(id -u)" != 0
"""


async def main():
    os.environ["LOCALCI_WORKER_RUNTIME"] = "sysbox-runc"
    with tempfile.TemporaryDirectory(prefix="localci-sysbox-") as directory:
        root = Path(directory)
        source = root / "source"
        workflows = source / ".github/workflows"
        workflows.mkdir(parents=True)
        git(source, "init", "-b", "main")
        git(source, "config", "user.name", "Local CI fixture")
        git(source, "config", "user.email", "fixture@example.com")
        (workflows / "first.yml").write_text(FIRST)
        (workflows / "second.yml").write_text(SECOND)
        revision = source / "revision.txt"
        revision.write_text("base")
        git(source, "add", ".")
        git(source, "commit", "-m", "Fixture base")
        base = git(source, "rev-parse", "HEAD")
        revision.write_text("head")
        git(source, "commit", "-am", "Fixture PR")
        repo = {"full_name": "fixture/localci", "name": "localci", "owner": {"login": "fixture"}}
        pr = {
            "number": 1,
            "title": "Sysbox fixture",
            "state": "open",
            "draft": False,
            "user": {"login": "fixture"},
            "head": {"sha": git(source, "rev-parse", "HEAD"), "ref": "feature", "repo": repo},
            "base": {"sha": base, "ref": "main", "repo": repo},
        }
        token = root / "token"
        token.write_text("fixture-only-token")
        data = root / "data"
        store = Store(data / "db")
        runner = Runner(
            store,
            GitHub(token),
            data,
            lambda _, scope: {"FIXTURE_KEY": "fixture-only-value"} if scope == "ci" else {},
        )
        rid = store.enqueue(
            repo["full_name"],
            pr,
            {"workflows": [".github/workflows/first.yml", ".github/workflows/second.yml"]},
        )
        worker = f"localci-run-{rid}"
        original = runner.command
        observed = []

        async def fixture_command(*args, **kwargs):
            args = tuple(
                str(source) if arg == "https://github.com/fixture/localci.git" else arg for arg in args
            )
            if "act" in args and "-W" in args:
                filename = Path(args[args.index("-W") + 1]).name
                _, config = await original(
                    "docker",
                    "inspect",
                    "--format",
                    "{{.HostConfig.Runtime}} {{.HostConfig.Privileged}}",
                    worker,
                    capture=True,
                )
                assert config.strip() == "sysbox-runc false", config
                if filename == "second.yml":
                    await original(
                        "docker",
                        "exec",
                        worker,
                        "sh",
                        "-ec",
                        "test ! -e /control/first.yml.secrets && ! grep -q '^FIXTURE_KEY=' /control/second.yml.secrets",
                    )
                observed.append(filename)
            return await original(*args, **kwargs)

        runner.command = fixture_command
        await runner.execute(store.claim())
        row = store.rows("SELECT state,message FROM runs WHERE id=?", (rid,))[0]
        if row["state"] != "success":
            raise RuntimeError(f"{row}\n{(data / 'logs' / f'{rid}.log').read_text()[-8000:]}")
        assert observed == ["first.yml", "second.yml"]
        archives = [
            p for p in (data / "artifacts" / rid / "ci").rglob("*") if p.is_file() and zipfile.is_zipfile(p)
        ]
        assert len(archives) == 1
        with zipfile.ZipFile(archives[0]) as archive:
            assert archive.read("proof.txt").strip() == b"verified"
        for query in (["ps", "-a"], ["network", "ls"]):
            names = await asyncio.to_thread(
                subprocess.check_output,
                ["docker", *query, "--format", "{{.Names}}" if query[0] == "ps" else "{{.Name}}"],
                text=True,
            )
            assert worker not in names.splitlines()
        print(
            "PASS: Sysbox runtime, Privileged=false, checkout, scoped secrets, nested jobs, artifact and cleanup"
        )


if __name__ == "__main__":
    asyncio.run(main())
