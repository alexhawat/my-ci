import asyncio
import base64
import contextlib
import functools
import hashlib
import json
import os
import re
import shutil
import stat
import threading
import time
import urllib.parse
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path

import yaml

from localci.github import GitHub
from localci.policy import Blocked, dependabot_pr, github_token_referenced, plan, secret_references
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


_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
# Fragments derived from a secret (its stripped form, individual lines) are redacted
# only when reasonably long, so short pieces cannot wreck unrelated log text.
MIN_SECRET_FRAGMENT = 8
OUTPUT_LINE_LIMIT = 100_000
OVERSIZED_LINE = "[oversized output line omitted]\n"


def strip_controls(text: str) -> str:
    return _CONTROL.sub("", _ANSI.sub("", text))


@functools.lru_cache(maxsize=16)
def _secret_forms(secrets: tuple[str, ...]) -> tuple[str, ...]:
    forms: set[str] = set()
    for secret in filter(None, secrets):
        # Encodings are never shorter than the value itself.
        forms |= {
            secret,
            base64.b64encode(secret.encode()).decode(),
            json.dumps(secret)[1:-1],
            json.dumps(secret, ensure_ascii=False)[1:-1],
            urllib.parse.quote(secret, safe=""),
        }
        # Logs are line-oriented and stripped of control characters: also cover
        # the normalised value and each line of a multi-line secret.
        fragments = {strip_controls(secret)}
        for line in re.split(r"\r\n|\r|\n", secret):
            fragments |= {line, strip_controls(line)}
        forms |= {f for f in fragments if len(f) >= MIN_SECRET_FRAGMENT}
    forms.discard("")
    return tuple(sorted(forms, key=len, reverse=True))


def redact(text: str, secrets: list[str]) -> str:
    for form in _secret_forms(tuple(secrets)):
        text = text.replace(form, "[redacted]")
    return re.sub(r"(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)", "[redacted]", text)


def sanitize(text: str, secrets: list[str]) -> str:
    """Redact, strip escapes/control characters, then redact again.

    The first pass catches secrets that themselves contain stripped characters;
    the second catches secrets split by escapes that stripping rejoined.
    """
    return redact(strip_controls(redact(text, secrets)), secrets)


AGENT_FILES = {
    "agents.md",
    "claude.md",
    "claude.local.md",
    "gemini.md",
    ".cursorrules",
    "opencode.json",
    "opencode.jsonc",
    ".mcp.json",
}
AGENT_DIRS = {".cursor", ".claude", ".opencode", ".mergecraft"}
GITHUB_AGENT_ENTRIES = {"copilot-instructions.md", "instructions"}


def remove_agent_configuration(root: Path) -> list[str]:
    """Delete PR-authored agent instructions/configuration at any depth, case-insensitively.

    Never follows symlinks: a matching link is unlinked itself, and linked
    directories are not descended into. ``.git`` is skipped.
    """
    removed = []
    for directory, dirs, files in os.walk(root, topdown=True, followlinks=False):
        parent = Path(directory)
        kept = []
        for name in [*dirs, *files]:
            lowered = name.casefold()
            if name == ".git" and parent == root:
                continue
            match = (
                lowered in AGENT_FILES
                or lowered in AGENT_DIRS
                or (parent.name.casefold() == ".github" and lowered in GITHUB_AGENT_ENTRIES)
            )
            target = parent / name
            if not match:
                if name in dirs:
                    kept.append(name)
                continue
            if target.is_symlink() or not target.is_dir():
                target.unlink()
            else:
                shutil.rmtree(target)
            removed.append(str(target.relative_to(root)))
        dirs[:] = [d for d in dirs if d in kept]
    return removed


def read_export(path: Path, limit: int) -> bytes | None:
    """Read a file copied out of a container: regular file only, no links, bounded.

    Anything else at the path (symlink, FIFO, device, directory, oversized file)
    is removed so later readers cannot block on it or follow it.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError:
        fd = None
    data = None
    if fd is not None:
        try:
            info = os.fstat(fd)
            if stat.S_ISREG(info.st_mode) and info.st_size <= limit:
                with os.fdopen(fd, "rb", closefd=False) as handle:
                    data = handle.read(limit + 1)
                if len(data) > limit:
                    data = None
        finally:
            os.close(fd)
    if data is None:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)
        else:
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
    return data


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
        clean = sanitize(text, self.sensitive)
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
        honor_cancel: bool = True,
    ) -> tuple[int, str]:
        """Run a command; ``honor_cancel=False`` is for bounded cleanup that must run anyway."""
        if honor_cancel:
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
            # True while skipping the rest of a line already known to exceed the limit.
            oversized = False
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

            def emit(text: str):
                nonlocal output_size, buffered
                if capture:
                    output.append(text)
                    output_size += len(text)
                    if output_size > 2_000_000:
                        raise RuntimeError("Command output exceeded limit")
                else:
                    lines.append(text)
                    buffered += len(text)

            def omit():
                # Drop the entire line, including its tail, so no secret fragment survives.
                emit(OVERSIZED_LINE)

            while True:
                try:
                    chunk = await asyncio.wait_for(proc.stdout.read(65536), timeout=0.25)
                except TimeoutError:
                    await flush()
                    continue
                if not chunk:
                    break
                start = 0
                while True:
                    end = chunk.find(b"\n", start)
                    piece = chunk[start:] if end < 0 else chunk[start:end]
                    if capture:
                        # Captured output (workflow files, review.patch) is never logged and must
                        # stay byte-exact, so long lines are kept; only the total size is bounded.
                        if len(pending) + len(piece) > 2_000_000:
                            raise RuntimeError("Command output exceeded limit")
                    elif not oversized and len(pending) + len(piece) > OUTPUT_LINE_LIMIT:
                        oversized, pending = True, b""
                        omit()
                    if end < 0:
                        if not oversized:
                            pending += piece  # bounded by the line limit, or the capture limit
                        break
                    if oversized:
                        oversized = False
                    else:
                        emit((pending + piece).decode(errors="replace") + "\n")
                    pending = b""
                    start = end + 1
                if buffered >= 65536 or time.monotonic() - last_flush >= 0.25:
                    await flush()
            if pending and not oversized:
                emit(pending.decode(errors="replace"))
            await flush()

        reader = asyncio.create_task(consume())
        start = time.monotonic()
        try:
            while proc.returncode is None:
                if honor_cancel:
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

    async def _quiet_docker(self, *args: str) -> str:
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )
        except OSError:
            return ""
        try:
            output, _ = await asyncio.wait_for(proc.communicate(), 30)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            return ""
        return output.decode(errors="replace")

    async def cleanup(self, name: str):
        """Remove a run container and the run network of the same name (idempotent).

        The per-run network is named after the run's CI worker container, so the
        controller's startup sweep of labelled containers also removes leftover
        networks. Removing a network that is missing or still in use is a no-op.
        """
        await self._quiet_docker("rm", "-fv", name)
        await self._quiet_docker("network", "rm", name)

    async def cleanup_networks(self):
        """Remove every leftover per-run network (for startup sweeps); in-use ones are kept."""
        listing = await self._quiet_docker("network", "ls", "-q", "--filter", "label=localci.worker=true")
        for network in listing.split():
            await self._quiet_docker("network", "rm", network)

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
        network = name
        metrics = None
        resources = config.get("execution", {})
        final_state, message = "success", "All configured checks passed"
        end_reason = None
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
                    names, dynamic = secret_references(data)
                    # Enabling host GitHub login is the operator's opt-in for every selected
                    # workflow: actions default their token input to github.token without
                    # naming it, so withholding it from "non-referencing" workflows breaks them.
                    if "GITHUB_TOKEN" in secrets or github_token_referenced(data):
                        names.add("GITHUB_TOKEN")
                    workflow_secrets[destination.name] = (
                        set(secrets) if dynamic else {n.upper() for n in names}
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
            # Values referenced by each workflow; written and copied into the worker only
            # for the duration of that workflow's act invocation (see ci_phase), never
            # via argv/logs. The GitHub token is included only where referenced.
            # Privileged CI remains host-root-equivalent and jobs of the SAME workflow
            # share its secrets and worker: this is least exposure, not a sandbox boundary.
            workflow_values = {
                filename: {
                    k: v
                    for k, v in secrets.items()
                    if k in workflow_secrets[filename] or k.upper() in workflow_secrets[filename]
                }
                for filename in prepared
            }
            ci_secret_dir = work / "ci-secrets"
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
            # A user-defined bridge per run: concurrent runs cannot reach each other's
            # artifact server or job service ports over Docker's shared default bridge.
            # Named after the worker container so cleanup(name) also removes it.
            await self.command("docker", "network", "rm", network, check=False, capture=True)
            await self.command(
                "docker",
                "network",
                "create",
                "--driver",
                "bridge",
                "--label",
                "localci.worker=true",
                network,
            )

            async def remove_worker_secrets(filename: str) -> bool:
                (ci_secret_dir / f"{filename}.secrets").unlink(missing_ok=True)
                try:
                    code, _ = await self.command(
                        "docker",
                        "exec",
                        name,
                        "rm",
                        "-f",
                        f"/control/{filename}.secrets",
                        check=False,
                        capture=True,
                        max_seconds=60,
                        honor_cancel=False,
                    )
                except Exception:
                    return False
                return code == 0

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
                        "--network",
                        network,
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
                        # Only this workflow's secrets are present in the worker, and only
                        # while its act invocation runs; removed before the next starts.
                        ci_secret_dir.mkdir(mode=0o700, exist_ok=True)
                        secret_file = ci_secret_dir / f"{filename}.secrets"
                        secret_file.touch(mode=0o600)
                        secret_file.write_text(
                            "\n".join(
                                f"{k}={json.dumps(v)}"
                                for k, v in {"GITHUB_TOKEN": "", **workflow_values[filename]}.items()
                            )
                        )
                        removed = False
                        try:
                            await self.command(
                                "docker", "cp", str(secret_file), f"{name}:/control/{filename}.secrets"
                            )
                            code, _ = await self.command(*args, check=False)
                        finally:
                            removed = await remove_worker_secrets(filename)
                        if not removed:
                            raise RuntimeError(
                                f"Could not remove {filename} secrets from the CI worker; stopping CI"
                            )
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
                        # Remove PR-authored agent configuration and prompt instructions at any depth.
                        removed = await asyncio.to_thread(remove_agent_configuration, review_dir)
                        if removed:
                            await asyncio.to_thread(
                                self.log,
                                f"Removed {len(removed)} PR-authored agent configuration entries from the review tree.\n",
                            )
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
                            "--network",
                            network,
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

                        def export(path: Path, limit: int) -> bytes | None:
                            # Container-controlled output: regular file only, no links/FIFOs, bounded.
                            data = read_export(path, limit)
                            if data is None:
                                return None
                            data = redact(data.decode(errors="replace"), self.sensitive).encode()
                            path.write_bytes(data)
                            return data

                        result_file = artifact_dir / "mergecraft.json"
                        result_data = await asyncio.to_thread(export, result_file, 2_000_000)
                        evidence_file = artifact_dir / "mergecraft-evidence.json"
                        await self.command(
                            "docker",
                            "cp",
                            f"{review_name}:/tmp/mergecraft-evidence.json",
                            str(evidence_file),
                            check=False,
                            capture=True,
                        )
                        evidence_data = await asyncio.to_thread(export, evidence_file, 10_000_000)
                        for filename, limit in (
                            ("mergecraft-review.md", 1_000_000),
                            ("mergecraft-metrics.json", 100_000),
                            ("mergecraft-profile.jsonl", 6_000_000),
                            ("mergecraft-usage.json", 100_000),
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
                            await asyncio.to_thread(export, exported, limit)
                        runtime_path = artifact_dir / "mergecraft-runtime.json"
                        runtime = json.loads(runtime_path.read_text())
                        if evidence_data is not None:
                            runtime["evidence_sha256"] = hashlib.sha256(evidence_data).hexdigest()
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
                        if result_data is not None:
                            try:
                                findings = json.loads(result_data).get("findings", [])
                                if isinstance(findings, list):
                                    for finding in findings[:100]:
                                        if isinstance(finding, dict):
                                            await asyncio.to_thread(
                                                self.log,
                                                f"mergeCraft {finding.get('severity', '')}: "
                                                f"{finding.get('path', '')}:{finding.get('start_line', '')} — "
                                                # Redact before truncating: a cut must not
                                                # leave an unredactable secret prefix.
                                                f"{sanitize(str(finding.get('message', '')), self.sensitive)[:3000]}\n"
                                                f"Suggested fix: "
                                                f"{sanitize(str(finding.get('remediation', '')), self.sensitive)[:3000]}\n",
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
            # Graceful worker stop: the store may automatically re-queue this run.
            final_state, message = "error", "Controller stopped during execution; retry this run"
            end_reason = "worker_interrupted"
        except Cancelled as exc:
            # Operator/superseded cancellation: the store recorded its reason at request time.
            final_state, message = "cancelled", str(exc)
        except Blocked as exc:
            final_state, message = "blocked", str(exc)
        except Exception as exc:
            final_state, message = "error", redact(str(exc), self.sensitive)
        finally:
            await self._finalize(
                run["id"], work, (review_name, name), metrics, final_state, message, end_reason
            )

    async def _finalize(self, rid, work, containers, metrics, state, message, reason):
        """Each step runs even if an earlier one fails; credential removal and
        run finalisation always complete, and a cancellation arriving meanwhile is
        re-raised afterwards instead of being swallowed."""
        interrupted: asyncio.CancelledError | None = None

        async def attempt(action, *args):
            nonlocal interrupted
            try:
                await action(*args)
            except asyncio.CancelledError as exc:
                interrupted = interrupted or exc
            except Exception:  # noqa: BLE001 - best effort; must not skip later steps
                pass

        async def complete(function, *args, **kwargs):
            # Shielded: a cancellation cannot abandon this step midway.
            nonlocal interrupted
            task = asyncio.ensure_future(asyncio.to_thread(function, *args, **kwargs))
            while True:
                try:
                    return await asyncio.shield(task)
                except asyncio.CancelledError as exc:
                    interrupted = interrupted or exc

        async def stop_metrics():
            if metrics is not None:
                metrics.cancel()
                await asyncio.gather(metrics, return_exceptions=True)

        await attempt(asyncio.to_thread, self.log, f"\n{state.upper()}: {message}\n")
        # Review container first: the run network is removable once both are gone.
        for container in containers:
            await attempt(self.cleanup, container)
        await attempt(stop_metrics)
        await complete(shutil.rmtree, work, ignore_errors=True)
        try:
            await complete(self.store.finish, rid, state, message, reason=reason)
        finally:
            if interrupted is not None:
                raise interrupted
