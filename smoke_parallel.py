"""Real, isolated two-PR/two-job smoke; no GitHub or provider credentials/writes."""

import asyncio
import json
import re
import subprocess
import tempfile
from pathlib import Path

from localci.app import Controller
from localci.github import GitHub
from localci.runner import Runner

WORKFLOW = """name: Local parallel fixture
on: pull_request
jobs:
  first:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "PARALLEL_START=first:$(date +%s)"
          sleep 20
          echo "PARALLEL_END=first:$(date +%s)"
  second:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "PARALLEL_START=second:$(date +%s)"
          sleep 20
          echo "PARALLEL_END=second:$(date +%s)"
"""


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.DEVNULL).decode().strip()


async def main():
    with tempfile.TemporaryDirectory(prefix="localci-parallel-") as tmp:
        root = Path(tmp)
        source = root / "source"
        source.mkdir()
        git(source, "init", "-b", "main")
        git(source, "config", "user.name", "Local CI fixture")
        git(source, "config", "user.email", "localci@localhost")
        (source / ".github/workflows").mkdir(parents=True)
        # A successful run proves the local revision was used instead of this failing upstream.
        (source / ".github/workflows/ci.yml").write_text(WORKFLOW.replace("sleep 20", "exit 9"))
        (source / "file.txt").write_text("base")
        git(source, "add", ".")
        git(source, "commit", "-m", "base")
        base = git(source, "rev-parse", "HEAD")
        (source / "file.txt").write_text("head")
        git(source, "commit", "-am", "head")
        head = git(source, "rev-parse", "HEAD")
        token = root / "token"
        token.write_text("fixture-not-a-credential")
        c = Controller(root / "data")
        c.github = GitHub(token)
        c.capacity = {"cpus": 32, "memory_gb": 125}
        c.store.save_settings(
            {"max_parallel_runs": 2, "cpus_per_run": 4, "memory_gb_per_run": 8, "paused": False}
        )
        c.store.save_workflow("fixture/localci", ".github/workflows/ci.yml", WORKFLOW, base)
        repo = {
            "full_name": "fixture/localci",
            "name": "localci",
            "owner": {"login": "fixture"},
            "default_branch": "main",
        }
        ids = []
        for number in (1, 2):
            pr = {
                "number": number,
                "title": "Parallel fixture",
                "state": "open",
                "draft": False,
                "user": {"login": "fixture"},
                "head": {"sha": head, "ref": "feature", "repo": repo},
                "base": {"sha": base, "ref": "main", "repo": repo},
            }
            ids.append(
                c.store.enqueue(
                    "fixture/localci",
                    pr,
                    {"workflows": [".github/workflows/ci.yml"], "job_parallelism": 2, "timeout": 1800},
                )
            )
        # Saving another revision must not mutate the two queued snapshots.
        c.store.save_workflow(
            "fixture/localci", ".github/workflows/ci.yml", WORKFLOW.replace("sleep 20", "exit 8"), base
        )

        completed = asyncio.Event()

        async def execute(run):
            runner = Runner(c.store, c.github, c.root, lambda *_: {})
            original = runner.command

            async def command(*args, **kwargs):
                args = tuple(
                    str(source) if a == "https://github.com/fixture/localci.git" else a for a in args
                )
                return await original(*args, **kwargs)

            runner.command = command
            await runner.execute(run)
            if not c.store.rows("SELECT id FROM runs WHERE state IN ('queued','running')"):
                completed.set()

        c.execute_run = execute
        scheduler = asyncio.create_task(c.schedule())
        try:
            async with asyncio.timeout(1800):
                await completed.wait()
        finally:
            scheduler.cancel()
            await asyncio.gather(scheduler, return_exceptions=True)
        runs = c.store.rows("SELECT * FROM runs ORDER BY started")
        for run in runs:
            log = (c.root / "logs" / f"{run['id']}.log").read_text()
            if run["state"] != "success":
                print(log[-16000:])
                raise AssertionError(run["message"])
            starts = [int(v) for v in re.findall(r"\| PARALLEL_START=(?:first|second):(\d+)", log)]
            ends = [int(v) for v in re.findall(r"\| PARALLEL_END=(?:first|second):(\d+)", log)]
            assert len(starts) == len(ends) == 2 and max(starts) < min(ends), (starts, ends)
            usage = c.store.rows("SELECT * FROM run_usage WHERE run_id=?", (run["id"],))[0]
            assert usage["samples"] > 0 and usage["peak_memory_bytes"] > 0 and usage["cpu_seconds"] > 0
            assert c.store.rows("SELECT id FROM run_events WHERE run_id=? AND job!=''", (run["id"],))
            print(
                json.dumps(
                    {
                        "run": run["id"],
                        "state": run["state"],
                        "parallel_job_starts": starts,
                        "parallel_job_ends": ends,
                        "usage": usage,
                    }
                ),
                flush=True,
            )
        assert max(r["started"] for r in runs) < min(r["finished"] for r in runs)
        proc = await asyncio.create_subprocess_exec(
            "docker", "ps", "-aq", "--filter", "name=localci-run-", stdout=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        # The actual fixture names must be absent; other live runs are allowed.
        for rid in ids:
            check = await asyncio.create_subprocess_exec(
                "docker",
                "inspect",
                f"localci-run-{rid}",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            assert await check.wait() != 0
        print(
            "PASS: two concurrent PR containers; two overlapping jobs each; immutable local workflow v1; timestamps; CPU/memory samples; cleanup",
            flush=True,
        )


if __name__ == "__main__":
    asyncio.run(main())
