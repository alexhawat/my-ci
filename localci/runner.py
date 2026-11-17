import asyncio
import base64
import contextlib
import hashlib
import json
import os
import re
import shutil
import threading
import time
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path

import yaml

from localci.github import GitHub
from localci.policy import Blocked, dependabot_pr, plan
from localci.review_evidence import (
    classify_review,
    configuration_diagnostic,
    primary_findings,
    terminal_event,
)
from localci.store import Store
from localci.telemetry import sample_resources


class Cancelled(RuntimeError):
    pass


def redact(text: str, secrets: list[str]) -> str:
    for secret in sorted(filter(None, secrets), key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
        text = text.replace(base64.b64encode(secret.encode()).decode(), "[redacted]")
    return re.sub(r"(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)", "[redacted]", text)


def offline_review_prompt(head: str, base: str) -> str:
    return (
        "Local CI execution context (authoritative for source/scope acquisition): "
        "this is an offline diff review. This context supersedes repository guidance "
        "about GitHub PR API calls, checkout_pr or GitHub Actions scope acquisition. "
        "Retain all domain-specific review criteria and verification requirements. "
        "Scope is already established from /control/review.patch; there is no GitHub "
        "PR API in this container. "
        f"HEAD is {head}; base is {base}. "
        "Do not rediscover the PR, branch or merge-base. Use the supplied full "
        "diff and read every changed file before the terminal verdict. "
        "Plan related reads together and issue independent reads in the same model turn. "
        "Read every changed hunk with its surrounding functions, types and relevant callers; "
        "expand context whenever necessary to verify a finding. Reuse already-read ranges "
        "instead of repeatedly loading entire large files. The full source remains available. "
        "Do not skip scope, analyzers, verification or unresolved coverage to save tokens. "
        "For git grep put all options "
        "before the pattern, revision and -- paths. Unsupported commands must "
        "not be retried unchanged. Reuse precomputed analyzer results. "
        "Retain all required verification and report coverage gaps honestly. "
        "Finish with a concise written review explaining scope, evidence, "
        "findings and remaining uncertainty."
    )


class Runner:
    def __init__(self, store: Store, github: GitHub, root: Path, secret_reader):
        self.store, self.github, self.root, self.secret_reader = store, github, root, secret_reader
        self.log_path = root / "unused"
        self.run: dict = {}
        self.sensitive: list[str] = []
        self.deadline = 0.0
        self.completed_jobs = 0
        self._lane = ContextVar("runner_lane", default="setup")
        self._phases: dict[str, str] = {}
        self._write_lock = threading.RLock()
        self.phase = "Setup"
        self.event_count = 0
        self.review_events: dict[str, dict] = {}

    @property
    def phase(self):
        return self._phases.get(self._lane.get(), "Setup")

    @phase.setter
    def phase(self, value):
        self._phases[self._lane.get()] = value

    def log(self, text: str):
        with self._write_lock:
            self._log(text)

    def _log(self, text: str):
        # Capture only bounded terminal protocol fields, even after log retention caps.
        if self._lane.get() == "review":
            for line in text.splitlines():
                event = terminal_event(line)
                if event:
                    if event["event"] == "verdict":
                        self.review_events.pop("run_finished", None)
                    self.review_events[event["event"]] = event
        if self._lane.get() != "review":
            self.completed_jobs += len(re.findall(r"^\[[^\n]+\] 🏁  Job succeeded", text, re.MULTILINE))
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if self.log_path.exists() and self.log_path.stat().st_size > 8_000_000:
            return
        text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
        text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", text)
        clean = redact(text, self.sensitive)
        events = []
        with self.log_path.open("a") as f:
            for line in clean.splitlines():
                timestamp = time.time()
                stamp = datetime.fromtimestamp(timestamp, UTC).isoformat(timespec="milliseconds")
                f.write(f"{stamp} {line}\n")
                if self.run.get("id") and self.event_count < 50000:
                    parsed = re.match(r"^\[([^]]+)\]\s*(.*)", line)
                    job = parsed[1] if parsed else ""
                    message = parsed[2] if parsed else line
                    level = (
                        "error"
                        if re.search(
                            r"error|failed|failure|❌|command not found|permission denied", message, re.I
                        )
                        else "info"
                    )
                    events.append((self.run["id"], timestamp, self.phase, job, level, message))
                    self.event_count += 1
        self.store.append_events(events)

    def cancelled(self):
        rows = self.store.rows("SELECT cancel FROM runs WHERE id=?", (self.run["id"],))
        if rows and rows[0]["cancel"]:
            raise Cancelled("Cancelled by operator or superseded PR revision")
        if time.monotonic() > self.deadline:
            raise TimeoutError("Run exceeded its wall-clock limit")

    async def command(
        self,
        *args: str,
        cwd: Path | None = None,
        env: dict | None = None,
        capture: bool = False,
        check: bool = True,
        max_seconds: int = 3600,
    ) -> tuple[int, str]:
        await asyncio.to_thread(self.cancelled)
        proc = await asyncio.create_subprocess_exec(
            *args,
            cwd=cwd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        output: list[str] = []
        output_size = 0

        async def consume():
            nonlocal output_size
            assert proc.stdout
            pending = b""
            discarding_line = False
            lines: list[str] = []
            buffered = 0
            last_flush = time.monotonic()

            async def flush():
                nonlocal buffered, last_flush
                if lines:
                    # Bound commit frequency during verbose scanners without delaying
                    # sparse live output. The raw log and structured index stay aligned.
                    await asyncio.to_thread(self.log, "".join(lines))
                    lines.clear()
                    buffered = 0
                last_flush = time.monotonic()

            while True:
                try:
                    chunk = await asyncio.wait_for(proc.stdout.read(65536), timeout=0.25)
                except TimeoutError:
                    await flush()
                    continue
                if not chunk:
                    break
                if discarding_line:
                    if b"\n" not in chunk:
                        continue
                    chunk = chunk.split(b"\n", 1)[1]
                    discarding_line = False
                pending += chunk
                while len(pending) <= 100_000 and b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    decoded = line.decode(errors="replace") + "\n"
                    if capture:
                        output.append(decoded)
                        output_size += len(decoded)
                        if output_size > 2_000_000:
                            raise RuntimeError("Command output exceeded limit")
                    else:
                        lines.append(decoded)
                        buffered += len(decoded)
                if buffered >= 65536 or time.monotonic() - last_flush >= 0.25:
                    await flush()
                if len(pending) > 100_000:
                    # Drop the entire line, including its tail, so no secret fragment survives.
                    pending = b""
                    discarding_line = True
                    lines.append("[oversized output line omitted]\n")
                    buffered += 33
            if pending:
                text = pending.decode(errors="replace")
                if capture:
                    output.append(text)
                else:
                    lines.append(text)
            await flush()

        reader = asyncio.create_task(consume())
        start = time.monotonic()
        try:
            while proc.returncode is None:
                await asyncio.to_thread(self.cancelled)
                if time.monotonic() - start > max_seconds:
                    raise TimeoutError(f"{args[0]} exceeded timeout")
                if reader.done() and reader.exception():
                    raise reader.exception()  # type: ignore[misc]
                await asyncio.sleep(0.4)
            await reader
        finally:
            if proc.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, 9)
                await proc.wait()
            reader.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reader
        code = proc.returncode or 0
        if code and check:
            raise RuntimeError(f"{args[0]} exited {code}; see run log")
        return code, "".join(output)

    async def cleanup(self, name: str):
        proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-fv", name, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(proc.wait(), 30)

    def step(self, name: str, state: str, message: str = "", **details):
        with self._write_lock:
            self._step(name, state, message, **details)

    def _step(self, name: str, state: str, message: str = "", **details):
        steps = json.loads(
            self.store.rows("SELECT steps FROM runs WHERE id=?", (self.run["id"],))[0]["steps"]
        )
        entry = next((s for s in steps if s["name"] == name), None)
        now = time.time()
        if entry:
            entry.update(state=state, message=message)
        else:
            entry = {"name": name, "state": state, "message": message, "started": now}
            steps.append(entry)
        entry.update(details)
        if state == "running":
            self.phase = name
            entry["started"] = now
            entry.pop("finished", None)
        elif state != "queued":
            entry["finished"] = now
        self.store.execute(
            "UPDATE runs SET steps=?,published=0 WHERE id=?", (json.dumps(steps), self.run["id"])
        )

    async def execute(self, run: dict):
        self.run = run
        config = json.loads(run["config"])
        pr = json.loads(run["snapshot"])
        skip_review = bool(config.get("review") and dependabot_pr(pr))
        run_review = bool(config.get("review") and not skip_review)
        self.deadline = time.monotonic() + config.get("timeout", 7200)
        work = self.root / "work" / run["id"]
        checkout, control = work / "repo", work / "control"
        self.log_path = self.root / "logs" / f"{run['id']}.log"
        name = f"localci-run-{run['id']}"
        review_name = name + "-review"
        metrics = None
        resources = config.get("execution", {})
        final_state, message = "success", "All configured checks passed"
        executed = 0
        try:
            work.mkdir(parents=True, mode=0o700)
            control.mkdir()
            token = self.github.token()
            secrets = self.secret_reader(run["repo"], "ci")
            review_secrets = self.secret_reader(run["repo"], "review") if run_review else {}
            if config.get("github_auth") == "gh":
                secrets = {**secrets, "GITHUB_TOKEN": token, "GH_TOKEN": token}
            self.sensitive = [token, *secrets.values(), *review_secrets.values()]
            metrics = asyncio.create_task(sample_resources(self.store, run["id"], {name, review_name}))
            if skip_review:
                await asyncio.to_thread(
                    self.step,
                    "mergeCraft",
                    "skipped",
                    "Dependabot PR: mergeCraft review is disabled; CI still runs",
                )
            await asyncio.to_thread(self.step, "Checkout", "running")
            basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
            self.sensitive.append(basic)
            git_env = {
                **os.environ,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
            }
            await self.command(
                "git",
                "clone",
                "--no-checkout",
                "--",
                f"https://github.com/{run['repo']}.git",
                str(checkout),
                env=git_env,
                max_seconds=600,
            )
            for sha in (run["head"], run["base"]):
                if not re.fullmatch(r"[0-9a-f]{40}", sha):
                    raise Blocked("Invalid GitHub commit SHA")
                await self.command("git", "fetch", "origin", sha, cwd=checkout, env=git_env, max_seconds=300)
            await self.command("git", "checkout", "--detach", run["base"], cwd=checkout)
            # Pin workflows to the trusted base. The tested tree is a real merge, like PR CI on GitHub.
            prepared = []
            workflow_secrets: dict[str, set[str]] = {}
            blockers = []
            for path in config.get("workflows", []):
                override = config.get("workflow_overrides", {}).get(path)
                if override:
                    text = override["content"]
                    await asyncio.to_thread(
                        self.log,
                        f"Using local workflow v{override['version']}: {path} (imported from {override['source_ref']})\n",
                    )
                else:
                    _, text = await self.command(
                        "git", "show", f"{run['base']}:{path}", cwd=checkout, capture=True
                    )
                    await asyncio.to_thread(
                        self.log,
                        f"Using GitHub base {run['base'][:12]}: {path}; "
                        f"executing on {os.environ.get('LOCALCI_HOST_LABEL', 'local worker')}\n",
                    )
                try:
                    data, notes = plan(text, set(secrets), config.get("variables", {}))
                    destination = control / Path(path).name
                    destination.write_text(yaml.safe_dump(data, sort_keys=False))
                    workflow_secrets[destination.name] = set(
                        re.findall(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)", yaml.safe_dump(data))
                    )
                    prepared.append(destination.name)
                    await asyncio.to_thread(self.log, "\n".join(notes) + "\n")
                except Blocked as exc:
                    blockers.append(str(exc))
                    await asyncio.to_thread(self.step, Path(path).name, "blocked", str(exc))
            code, _ = await self.command(
                "git",
                "-c",
                "user.name=Local CI",
                "-c",
                "user.email=localci@localhost",
                "merge",
                "--no-ff",
                "--no-edit",
                run["head"],
                cwd=checkout,
                check=False,
            )
            if code:
                raise Blocked("PR does not merge cleanly into its base; resolve conflicts first")
            _, tested_sha = await self.command("git", "rev-parse", "HEAD", cwd=checkout, capture=True)
            await asyncio.to_thread(
                self.step,
                "Checkout",
                "success",
                f"Testing merge {tested_sha.strip()[:12]} of {run['head'][:12]} into {run['base'][:12]}",
            )
            event = {
                "action": "synchronize",
                "number": pr["number"],
                "pull_request": pr,
                "repository": pr["base"]["repo"],
                "sender": pr["user"],
            }
            (control / "event.json").write_text(json.dumps(event))
            (control / "vars").write_text(
                "\n".join(f"{k}={v}" for k, v in config.get("variables", {}).items())
            )
            # Transfer only values referenced by each selected workflow, never via argv/logs.
            # Privileged CI remains host-root-equivalent; this is least exposure, not a sandbox boundary.
            for filename in prepared:
                names = workflow_secrets[filename]
                values = {
                    k: v
                    for k, v in secrets.items()
                    if k in names or (config.get("github_auth") == "gh" and k in {"GITHUB_TOKEN", "GH_TOKEN"})
                }
                secret_file = control / f"{filename}.secrets"
                secret_file.write_text(
                    "\n".join(f"{k}={json.dumps(v)}" for k, v in {"GITHUB_TOKEN": "", **values}.items())
                )
                secret_file.chmod(0o600)
            if not prepared and (not run_review or not review_secrets):
                if run_review and not review_secrets:
                    await asyncio.to_thread(
                        self.step, "mergeCraft", "blocked", "Configure a local review provider credential"
                    )
                    blockers.append("mergeCraft requires a locally configured provider credential")
                raise Blocked("; ".join(blockers) or "No CI workflows selected")
            artifact_dir = self.root / "artifacts" / run["id"]
            artifact_dir.mkdir(parents=True, exist_ok=True)
            # Separate outer containers, repository exports and credential paths allow
            # review and CI to overlap without exposing review credentials to CI.
            # Both container limits together stay within the configured run budget.
            total_cpus = resources.get("cpus_per_run", 8)
            total_memory = resources.get("memory_gb_per_run", 24)
            parallel = bool(prepared and run_review and review_secrets)
            review_cpus = min(2, total_cpus / 4) if parallel else min(4, total_cpus)
            review_memory = min(4, total_memory / 4) if parallel else min(8, total_memory)
            ci_cpus = total_cpus - review_cpus if parallel else total_cpus
            ci_memory = total_memory - review_memory if parallel else total_memory
            for filename in prepared:
                await asyncio.to_thread(self.step, filename, "queued")
            if run_review:
                await asyncio.to_thread(self.step, "mergeCraft", "queued")

            async def ci_phase():
                nonlocal executed, final_state, message
                if prepared:
                    await self.command(
                        "docker",
                        "run",
                        "-d",
                        "--name",
                        name,
                        "--label",
                        "localci.worker=true",
                        "--privileged",
                        f"--memory={ci_memory}g",
                        f"--cpus={ci_cpus}",
                        "--pids-limit=8192",
                        "-e",
                        "DOCKER_TLS_CERTDIR=",
                        os.environ.get("LOCALCI_WORKER_IMAGE", "localci-worker:1"),
                        "--host=unix:///var/run/docker.sock",
                    )
                    for _ in range(60):
                        code, _ = await self.command(
                            "docker", "exec", name, "docker", "info", capture=True, check=False
                        )
                        if code == 0:
                            break
                        await asyncio.sleep(1)
                    else:
                        raise RuntimeError("Docker worker failed to start")
                    await asyncio.to_thread(
                        self.log,
                        "Privileged nested Docker ready. PR code has host-root-equivalent access; trusted repositories only.\n",
                    )
                    await self.command("docker", "cp", str(checkout), f"{name}:/workspace")
                    await self.command("docker", "cp", str(control), f"{name}:/control")
                    # Seed the local runner image, avoiding a full image download on every run.
                    await self.command(
                        "docker",
                        "cp",
                        "/opt/localci/runner-image.tar",
                        f"{name}:/runner-image.tar",
                        max_seconds=600,
                    )
                    await self.command(
                        "docker",
                        "exec",
                        name,
                        "sh",
                        "-c",
                        "docker load -i /runner-image.tar && rm /runner-image.tar",
                        max_seconds=600,
                    )
                    for filename in prepared:
                        self.completed_jobs = 0
                        await asyncio.to_thread(self.step, filename, "running")
                        await asyncio.to_thread(self.log, f"\n--- {filename} ---\n")
                        args = [
                            "docker",
                            "exec",
                            "-w",
                            "/control",
                            name,
                            "act",
                            "pull_request",
                            "-C",
                            "/workspace",
                            "-W",
                            f"/control/{filename}",
                            "-e",
                            "/control/event.json",
                            "--actor",
                            pr["user"]["login"],
                            "--secret-file",
                            f"/control/{filename}.secrets",
                            "--var-file",
                            "/control/vars",
                            "--env-file",
                            "/dev/null",
                            "--input-file",
                            "/dev/null",
                            "--artifact-server-path",
                            "/artifacts",
                            "--artifact-server-addr",
                            "0.0.0.0",
                            "--artifact-server-port",
                            "34567",
                            "--network",
                            "host",
                            "--container-options",
                            "--init --security-opt seccomp=unconfined --shm-size=2g "
                            "--tmpfs /tmp:rw,exec,nosuid,size=4g,mode=1777",
                            "--pull=false",
                            "--concurrent-jobs",
                            str(config.get("job_parallelism", 1)),
                            "--rm",
                        ]
                        for label in ("ubuntu-latest", "ubuntu-24.04"):
                            args += ["-P", f"{label}=localci-jobs:1"]
                        for version in ("22.04", "20.04"):
                            args += ["-P", f"ubuntu-{version}=ghcr.io/catthehacker/ubuntu:act-{version}"]
                        code, _ = await self.command(*args, check=False)
                        executed += self.completed_jobs
                        state = "failure" if code else ("success" if self.completed_jobs else "skipped")
                        await asyncio.to_thread(
                            self.step,
                            filename,
                            state,
                            f"act exited {code}; {self.completed_jobs} jobs passed",
                        )
                        if code:
                            final_state, message = "failure", "One or more CI workflows failed"
                    # CI-controlled artifacts cannot overwrite review evidence.
                    ci_artifacts = artifact_dir / "ci"
                    ci_artifacts.mkdir(exist_ok=True)
                    await self.command("docker", "cp", f"{name}:/artifacts/.", str(ci_artifacts), check=False)

            async def review_phase():
                nonlocal executed, final_state, message
                if run_review:
                    await asyncio.to_thread(self.step, "mergeCraft", "running")
                    if not review_secrets:
                        blockers.append("mergeCraft requires a locally configured provider credential")
                        await asyncio.to_thread(self.step, "mergeCraft", "blocked", blockers[-1])
                    else:
                        # Build an independent repository for review; linked worktree pointers cannot cross containers.
                        review_dir = work / "review-export"
                        await self.command("git", "clone", "--no-local", str(checkout), str(review_dir))
                        await self.command("git", "checkout", "--detach", run["head"], cwd=review_dir)
                        # Remove PR-authored agent configuration and nested prompt instructions.
                        for relative in (
                            ".mergecraft",
                            ".opencode",
                            "opencode.json",
                            "opencode.jsonc",
                            ".mcp.json",
                        ):
                            target = review_dir / relative
                            if target.is_dir() and not target.is_symlink():
                                shutil.rmtree(target)
                            elif target.exists() or target.is_symlink():
                                target.unlink()
                        for filename in ("AGENTS.md", "CLAUDE.md"):
                            for target in review_dir.rglob(filename):
                                if target.is_symlink() or target.is_file():
                                    target.unlink()
                        code, base_config = await self.command(
                            "git",
                            "show",
                            f"{run['base']}:.mergecraft/config.yaml",
                            cwd=checkout,
                            capture=True,
                            check=False,
                        )
                        review_config = yaml.safe_load(base_config) if code == 0 else {}
                        review_config = review_config or {}
                        review_config.update(
                            push="disabled",
                            shell="disabled",
                            prApproveEnabled=False,
                            autoMergeEnabled=False,
                            trust={"selfReview": "off", "agentSandbox": "never"},
                        )
                        instructions = dict(review_config.get("modeInstructions") or {})
                        instructions["Review"] = (
                            str(instructions.get("Review", ""))
                            + "\n\n"
                            + offline_review_prompt(run["head"], run["base"])
                        )
                        review_config["modeInstructions"] = instructions
                        review_control = work / "review-control"
                        review_control.mkdir()
                        shutil.copyfile(
                            Path(__file__).with_name("review_bootstrap.py"),
                            review_control / "review-bootstrap.py",
                        )
                        (review_control / "review-config.yaml").write_text(yaml.safe_dump(review_config))
                        _, patch = await self.command(
                            "git", "diff", f"{run['base']}...{run['head']}", cwd=checkout, capture=True
                        )
                        (review_control / "review.patch").write_text(patch)
                        review_timeout = config.get("review_timeout", 3000)
                        (work / "review-env").write_text(
                            "\n".join(f"{k}={v}" for k, v in review_secrets.items())
                            + f"\nLOCALCI_PROFILE_PATH=/tmp/mergecraft-profile.jsonl\nMERGECRAFT_NONINTERACTIVE=1\nMERGECRAFT_ENV=/dev/null\nMERGECRAFT_CONFIG=/control/review-config.yaml\nMERGECRAFT_RUN_TIMEOUT_S={review_timeout}\nMERGECRAFT_COST_BUDGET_USD=5\n"
                        )
                        (work / "review-env").chmod(0o600)
                        await asyncio.to_thread(
                            self.log,
                            f"Independent mergeCraft review: {review_timeout // 60} minute limit, $5 budget; CI does not wait for review.\n",
                        )
                        await self.command(
                            "docker",
                            "create",
                            "--init",
                            "--name",
                            review_name,
                            "--label",
                            "localci.worker=true",
                            f"--memory={review_memory}g",
                            f"--cpus={review_cpus}",
                            "--pids-limit=1024",
                            "--env-file",
                            str(work / "review-env"),
                            "-w",
                            "/review",
                            "--entrypoint",
                            "python",
                            os.environ["LOCALCI_REVIEW_IMAGE"],
                            "/control/review-bootstrap.py",
                            "review",
                            "--diff",
                            "/control/review.patch",
                            "--agent",
                            "--prompt",
                            offline_review_prompt(run["head"], run["base"]),
                            "--json",
                            "/tmp/review.json",
                        )
                        await self.command("docker", "cp", str(review_dir) + "/.", f"{review_name}:/review")
                        await self.command("docker", "cp", str(review_control), f"{review_name}:/control")
                        _, review_image_id = await self.command(
                            "docker",
                            "inspect",
                            "--format",
                            "{{.Image}}",
                            review_name,
                            check=False,
                            capture=True,
                        )
                        review_started = time.monotonic()
                        code, _ = await self.command(
                            "docker", "start", "-a", review_name, check=False, max_seconds=review_timeout + 60
                        )
                        (artifact_dir / "mergecraft-runtime.json").write_text(
                            json.dumps(
                                {
                                    "image": review_image_id.strip(),
                                    "run_id": run["id"],
                                    "repo": run["repo"],
                                    "head": run["head"],
                                    "base": run["base"],
                                    "exit_code": code,
                                    "terminal": self.review_events,
                                    "container_seconds": round(time.monotonic() - review_started, 2),
                                    "timeout_seconds": review_timeout,
                                    "model_attempt_limit": 3,
                                }
                            )
                        )
                        artifact_code, _ = await self.command(
                            "docker",
                            "cp",
                            f"{review_name}:/tmp/review.json",
                            str(artifact_dir / "mergecraft.json"),
                            check=False,
                            capture=True,
                        )
                        if artifact_code:
                            await asyncio.to_thread(
                                self.log,
                                f"mergeCraft exited {code} without a JSON report; see its diagnostic output above.\n",
                            )
                        result_file = artifact_dir / "mergecraft.json"
                        if result_file.is_file() and not result_file.is_symlink():
                            result_file.write_text(
                                redact(result_file.read_text(errors="replace"), self.sensitive)
                            )
                        evidence_file = artifact_dir / "mergecraft-evidence.json"
                        await self.command(
                            "docker",
                            "cp",
                            f"{review_name}:/tmp/mergecraft-evidence.json",
                            str(evidence_file),
                            check=False,
                            capture=True,
                        )
                        if evidence_file.is_file() and not evidence_file.is_symlink():
                            evidence_file.write_text(
                                redact(evidence_file.read_text(errors="replace"), self.sensitive)
                            )
                        for filename in (
                            "mergecraft-review.md",
                            "mergecraft-metrics.json",
                            "mergecraft-profile.jsonl",
                            "mergecraft-usage.json",
                        ):
                            exported = artifact_dir / filename
                            await self.command(
                                "docker",
                                "cp",
                                f"{review_name}:/tmp/{filename}",
                                str(exported),
                                check=False,
                                capture=True,
                            )
                            if exported.is_file() and not exported.is_symlink():
                                exported.write_text(
                                    redact(exported.read_text(errors="replace"), self.sensitive)
                                )
                        runtime_path = artifact_dir / "mergecraft-runtime.json"
                        runtime = json.loads(runtime_path.read_text())
                        if (
                            evidence_file.is_file()
                            and not evidence_file.is_symlink()
                            and evidence_file.stat().st_size <= 10_000_000
                        ):
                            runtime["evidence_sha256"] = hashlib.sha256(
                                evidence_file.read_bytes()
                            ).hexdigest()
                        runtime_path.write_text(json.dumps(runtime))
                        findings = None
                        try:
                            findings = primary_findings(artifact_dir)
                            primary_available = True
                        except (ValueError, TypeError, OSError):
                            primary_available = False
                        state, detail = classify_review(
                            code,
                            self.review_events,
                            primary_available=primary_available,
                            findings=findings,
                            failure_threshold=config.get("review_failure_threshold", "major"),
                            configuration_error=redact(
                                await asyncio.to_thread(configuration_diagnostic, self.store, run["id"]),
                                self.sensitive,
                            ),
                        )
                        if result_file.exists():
                            try:
                                findings = json.loads(result_file.read_text()).get("findings", [])
                                if isinstance(findings, list):
                                    for finding in findings[:100]:
                                        if isinstance(finding, dict):
                                            await asyncio.to_thread(
                                                self.log,
                                                f"mergeCraft {finding.get('severity', '')}: "
                                                f"{finding.get('path', '')}:{finding.get('start_line', '')} — "
                                                f"{str(finding.get('message', ''))[:3000]}\n"
                                                f"Suggested fix: {str(finding.get('remediation', ''))[:3000]}\n",
                                            )
                                    if findings:
                                        detail += f"; {len(findings)} findings — see review details"
                            except (ValueError, AttributeError, OSError):
                                await asyncio.to_thread(
                                    self.log,
                                    "mergeCraft JSON report could not be parsed; see diagnostic output.\n",
                                )
                        executed += 1
                        await asyncio.to_thread(
                            self.step,
                            "mergeCraft",
                            state,
                            detail,
                            review_failure_threshold=config.get("review_failure_threshold", "major"),
                            non_blocking_findings=len(findings or []) if state == "success" else 0,
                        )
                        if state != "success":
                            final_state, message = state, detail

            async def guarded(lane, names, action):
                nonlocal final_state, message
                self._lane.set(lane)
                if names:
                    self.phase = names[0]
                try:
                    await action()
                except Cancelled:
                    raise
                except Exception as exc:
                    final_state, message = "error", redact(str(exc), self.sensitive)
                    await asyncio.to_thread(self.log, f"ERROR: {message}\n")
                    steps = json.loads(
                        self.store.rows("SELECT steps FROM runs WHERE id=?", (run["id"],))[0]["steps"]
                    )
                    for step in steps:
                        if step["name"] in names and step["state"] in ("queued", "running"):
                            await asyncio.to_thread(self.step, step["name"], "error", message)
                finally:
                    await self.cleanup(name if lane == "ci" else review_name)

            tasks = [
                asyncio.create_task(guarded("ci", prepared, ci_phase)),
                asyncio.create_task(guarded("review", ["mergeCraft"] if run_review else [], review_phase)),
            ]
            try:
                await asyncio.gather(*tasks)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            if blockers and final_state == "success":
                final_state, message = "blocked", "; ".join(blockers)
            if not prepared and not run_review:
                final_state, message = "blocked", "; ".join(blockers) or "No CI workflows selected"
            if final_state == "success" and not executed:
                final_state, message = (
                    "blocked",
                    "No checks executed; check workflow conditions and variables",
                )
            await asyncio.to_thread(self.cancelled)
        except asyncio.CancelledError:
            final_state, message = "error", "Controller stopped during execution; retry this run"
        except Cancelled as exc:
            final_state, message = "cancelled", str(exc)
        except Blocked as exc:
            final_state, message = "blocked", str(exc)
        except Exception as exc:
            final_state, message = "error", redact(str(exc), self.sensitive)
        finally:
            await asyncio.to_thread(self.log, f"\n{final_state.upper()}: {message}\n")
            await self.cleanup(name)
            await self.cleanup(review_name)
            if metrics is not None:
                metrics.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await metrics
            await asyncio.to_thread(shutil.rmtree, work, ignore_errors=True)
            await asyncio.to_thread(self.store.finish, run["id"], final_state, message)
