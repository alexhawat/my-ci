import asyncio
import contextlib
import json
import os
import shutil
import time
from functools import partial
from pathlib import Path

from cryptography.fernet import Fernet

from localci import updater
from localci.github import GitHub
from localci.policy import BOT_HOLD, bot_pr, eligible
from localci.reporting import comment_body, reports
from localci.review_reconcile import reconcile_legacy_reviews
from localci.runner import Runner
from localci.store import Store

PUBLISH_ATTEMPTS = 3  # Only permanent failures of a final publication count toward abandonment.
NETWORK_SWEEP_SECONDS = 600


class Controller:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.store = Store(root / "localci.db")
        self.github = GitHub(Path(os.environ.get("LOCALCI_TOKEN_FILE", "/run/secrets/github-token")))
        key = root / "encryption.key"
        with self.store.writer():
            if not key.exists():
                fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(Fernet.generate_key())
        self.cipher = Fernet(key.read_bytes())
        self.github.app_credentials = lambda: self.secrets("__github_app__", "app")
        self.capacity: dict = {}
        self.login = ""
        # Separate sources so one cannot overwrite or prematurely clear another.
        self.poll_error = self.capacity_error = ""
        # Finalization failures by run id, with the time they happened.
        self.run_errors: dict[str, tuple[str, float]] = {}
        self.last_poll = 0.0
        self.last_discovery = 0.0
        self.lock = asyncio.Lock()
        self.publish_lock = asyncio.Lock()
        # Permanent final failures and transient/pending backoff have separate budgets.
        self.publish_retries: dict[str, tuple[int, float]] = {}
        self.publish_backoff: dict[str, tuple[int, float]] = {}
        self.wake = asyncio.Event()
        self.base_url = os.environ.get("LOCALCI_URL", "http://localhost:8787").rstrip("/")
        self.host_label = os.environ.get("LOCALCI_HOST_LABEL", "local worker")
        # Set by the execution worker once it has inspected its own container.
        self.deployment: dict | None = None
        self.update_unavailable = "The execution worker has not started yet."

    @property
    def error(self) -> str:
        # A copy: expire_run_errors() removes entries from a worker thread.
        failures = [message for message, _ in list(self.run_errors.values())]
        return "; ".join(e for e in (self.poll_error, self.capacity_error, *failures) if e)

    def expire_run_errors(self):
        """Keep a finalization failure visible while its run is still marked active
        (stuck until the worker restarts), and for a few minutes after it is not."""
        for rid, (_, since) in list(self.run_errors.items()):
            stuck = self.store.rows("SELECT 1 FROM runs WHERE id=? AND state IN ('queued','running')", (rid,))
            if not stuck and time.time() - since > 300:
                self.run_errors.pop(rid, None)

    def status(self):
        rows = self.store.rows("SELECT value FROM settings WHERE key='worker_status'")
        status = (
            json.loads(rows[0]["value"])
            if rows
            else {
                "login": self.login,
                "error": self.error,
                "last_poll": self.last_poll,
                "capacity": self.capacity,
                "heartbeat": 0,
            }
        )
        status["online"] = bool(status.get("heartbeat") and time.time() - status["heartbeat"] < 30)
        return status

    def notify(self, *, discover=False):
        # Durable requests cross the dashboard/worker process boundary.
        import uuid

        with self.store.connect() as db:
            for key in ["worker_wake", "worker_sync"] if discover else ["worker_wake"]:
                db.execute(
                    "INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, uuid.uuid4().hex),
                )
        self.wake.set()

    async def heartbeat(self):
        seen = {}
        while True:
            rows = await asyncio.to_thread(
                self.store.rows, "SELECT key,value FROM settings WHERE key IN ('worker_wake','worker_sync')"
            )
            for row in rows:
                if seen.get(row["key"]) != row["value"]:
                    seen[row["key"]] = row["value"]
                    if row["key"] == "worker_sync":
                        self.last_discovery = 0
                    self.wake.set()
            await asyncio.to_thread(
                self.store.execute,
                "INSERT INTO settings VALUES('worker_status',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (
                    json.dumps(
                        {
                            "login": self.login,
                            "error": self.error,
                            "last_poll": self.last_poll,
                            "capacity": self.capacity,
                            "version": updater.version(),
                            "update_unavailable": self.update_unavailable,
                            "heartbeat": time.time(),
                        }
                    ),
                ),
            )
            await asyncio.sleep(2)

    def secrets(self, repo: str, scope: str) -> dict[str, str]:
        return {
            row["name"].split(":", 1)[1]: self.cipher.decrypt(row["ciphertext"].encode()).decode()
            for row in self.store.rows(
                "SELECT * FROM secrets WHERE repo=? AND name LIKE ?", (repo, scope + ":%")
            )
        }

    async def discover(self):
        self.login, repos = await self.github.discover()
        await asyncio.to_thread(self.store.discover, repos)
        self.last_discovery = time.time()

    async def poll(self):
        async with self.lock:
            if time.time() - self.last_discovery > 600:
                await self.discover()
            for repo in await asyncio.to_thread(self.store.rows, "SELECT * FROM repos WHERE enabled=1"):
                try:
                    # Oldest first: a PR closing between page requests then shifts later
                    # pages toward newer PRs less often than the default newest-first order.
                    prs = await self.github.pages(
                        f"repos/{repo['name']}/pulls?state=open&sort=created&direction=asc"
                    )
                    await asyncio.to_thread(self.store.cancel_stale, repo["name"], prs)
                    await asyncio.to_thread(self.store.replace_prs, repo["name"], prs)
                    config = json.loads(repo["config"])
                    for pr in prs:
                        if eligible(pr, repo["name"]):
                            # Bot PRs run privileged CI only after an operator starts them,
                            # unless the repository allows it when the run is enqueued.
                            await asyncio.to_thread(
                                partial(
                                    self.store.enqueue,
                                    repo["name"],
                                    pr,
                                    config,
                                    bot_hold=BOT_HOLD if bot_pr(pr) else None,
                                    require_enabled=True,
                                )
                            )
                    await asyncio.to_thread(
                        self.store.execute, "UPDATE repos SET error='' WHERE name=?", (repo["name"],)
                    )
                except Exception as exc:
                    await asyncio.to_thread(
                        self.store.execute, "UPDATE repos SET error=? WHERE name=?", (str(exc), repo["name"])
                    )
            self.last_poll = time.time()
            self.poll_error = ""
            await self.publish()

    def reports(self, run):
        if run["end_reason"] == "awaiting_approval":
            return {}  # Nothing ran; the commit status alone explains the hold.
        values = [*self.secrets(run["repo"], "ci").values(), *self.secrets(run["repo"], "review").values()]
        if self.github.token_path.is_file():
            values.append(self.github.token())
        return reports(run, self.root, self.store, values)

    async def publish(self):
        async with self.publish_lock:
            await self._publish()

    async def _publish(self):
        await asyncio.to_thread(
            self.store.execute,
            """UPDATE runs SET published=1 WHERE state NOT IN ('queued','running') AND EXISTS (
            SELECT 1 FROM runs newer WHERE newer.repo=runs.repo AND newer.pr=runs.pr AND newer.created>runs.created)""",
        )
        # Only the newest attempt for a PR may update its aggregate status. Old completions never overwrite it.
        for run in await asyncio.to_thread(
            self.store.rows,
            """SELECT r.* FROM runs r WHERE r.published=0 AND NOT EXISTS (
                SELECT 1 FROM runs newer WHERE newer.repo=r.repo AND newer.pr=r.pr AND newer.created>r.created)
                ORDER BY r.created DESC LIMIT 50""",
        ):
            retry_at = max(
                self.publish_retries.get(run["id"], (0, 0))[1],
                self.publish_backoff.get(run["id"], (0, 0))[1],
            )
            if time.time() < retry_at:
                continue
            state = {
                "queued": "pending",
                "running": "pending",
                "success": "success",
                "failure": "failure",
            }.get(run["state"], "error")
            description = run["message"] or f"Local CI {run['state']} on {self.host_label}"
            try:
                evidence = await asyncio.to_thread(self.reports, run)
                # Recheck before final phase comments as well as aggregate results.
                if state != "pending" or evidence:
                    current = await self.github.request("GET", f"repos/{run['repo']}/pulls/{run['pr']}")
                    if (current["head"]["sha"], current["base"]["sha"]) != (run["head"], run["base"]):
                        await asyncio.to_thread(
                            self.store.execute,
                            "UPDATE runs SET published=1,publish_error='Superseded revision; not published' WHERE id=?",
                            (run["id"],),
                        )
                        self.publish_retries.pop(run["id"], None)
                        self.publish_backoff.pop(run["id"], None)
                        continue
                reporting = await self.github.status(
                    run, state, description, f"{self.base_url}/?run={run['id']}"
                )
                for kind, report in evidence.items():
                    await self.github.comment(
                        run, kind, comment_body(run, kind, report, f"{self.base_url}/?run={run['id']}")
                    )
                if reporting:
                    await asyncio.to_thread(
                        self.store.execute,
                        "INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (f"reporting:{run['repo']}", json.dumps(reporting)),
                    )
                await asyncio.to_thread(
                    self.store.execute,
                    "UPDATE runs SET published=1,publish_error='' WHERE id=? AND state=? AND steps=?",
                    (run["id"], run["state"], run["steps"]),
                )
                self.publish_retries.pop(run["id"], None)
                self.publish_backoff.pop(run["id"], None)
            except Exception as exc:
                final = state != "pending"
                permanent = final and getattr(exc, "status", None) in (404, 410, 422)
                failures = self.publish_retries.get(run["id"], (0, 0))[0] + int(permanent)
                if permanent:
                    self.publish_retries[run["id"]] = (failures, 0.0)
                if failures >= PUBLISH_ATTEMPTS:
                    # Only a final target that is missing or invalid is unrecoverable.
                    # Network, authentication, server and rate-limit failures keep retrying.
                    self.publish_retries.pop(run["id"], None)
                    self.publish_backoff.pop(run["id"], None)
                    await asyncio.to_thread(
                        self.store.execute,
                        "UPDATE runs SET published=1,publish_error=? WHERE id=? AND state=? AND steps=?",
                        (
                            f"{exc}; not published after {failures} permanent failures",
                            run["id"],
                            run["state"],
                            run["steps"],
                        ),
                    )
                    continue
                # Honour GitHub's requested wait (rate limits) when it is longer than ours.
                transient = self.publish_backoff.get(run["id"], (0, 0))[0] + 1
                delay = max(min(300, 5 * 2 ** (transient - 1)), getattr(exc, "retry_after", None) or 0)
                self.publish_backoff[run["id"]] = (transient, time.time() + delay)
                await asyncio.to_thread(
                    self.store.execute,
                    "UPDATE runs SET publish_error=? WHERE id=?",
                    (f"{exc}; retrying with backoff", run["id"]),
                )

    async def monitor(self):
        while True:
            self.wake.clear()
            try:
                await self.poll()
                await asyncio.to_thread(self.prune)
            except Exception as exc:
                self.poll_error = str(exc)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.wake.wait(), 60)

    def prune(self):
        self.store.execute("DELETE FROM run_usage WHERE created<?", (time.time() - 90 * 86400,))
        cutoff = time.time() - 14 * 86400
        # Transient publication failures are retried for the full retention period,
        # then abandoned explicitly so an unpublished run cannot be retained forever.
        self.store.execute(
            """UPDATE runs SET published=1,publish_error=CASE WHEN publish_error=''
            THEN 'Publication abandoned at retention age'
            ELSE publish_error||'; publication abandoned at retention age' END
            WHERE finished<? AND published=0 AND state NOT IN ('queued','running')""",
            (cutoff,),
        )
        for run in self.store.rows("SELECT id FROM runs WHERE finished<? AND published=1", (cutoff,)):
            (self.root / "logs" / f"{run['id']}.log").unlink(missing_ok=True)
            shutil.rmtree(self.root / "artifacts" / run["id"], ignore_errors=True)
            self.store.execute("DELETE FROM run_events WHERE run_id=?", (run["id"],))
            self.store.execute("DELETE FROM resource_samples WHERE run_id=?", (run["id"],))
            self.store.execute("DELETE FROM runs WHERE id=?", (run["id"],))
            self.publish_retries.pop(run["id"], None)
            self.publish_backoff.pop(run["id"], None)

    async def worker(self):
        # Only the exclusive worker service may recover runs and manage containers.
        await asyncio.to_thread(self.store.reconcile_results)
        await asyncio.to_thread(reconcile_legacy_reviews, self.store, self.root)
        runner = Runner(self.store, self.github, self.root, self.secrets)
        proc = await asyncio.create_subprocess_exec(
            "docker", "info", "--format", "{{json .}}", stdout=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        info = json.loads(output)
        self.capacity = {"cpus": info["NCPU"], "memory_gb": int(info["MemTotal"] / 2**30)}
        proc = await asyncio.create_subprocess_exec(
            "docker", "ps", "-aq", "--filter", "label=localci.worker=true", stdout=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        for name in output.decode().split():
            await runner.cleanup(name)
        await runner.cleanup_networks()  # Per-run networks whose containers are already gone.
        self.deployment, self.update_unavailable = await updater.detect()
        await updater.reconcile(self.store)  # The helper that replaced the previous worker.
        # A crash cannot leave decrypted CI/provider credentials in the data volume.
        await asyncio.to_thread(shutil.rmtree, self.root / "work", ignore_errors=True)
        for row in await asyncio.to_thread(self.store.rows, "SELECT id FROM runs WHERE state='running'"):
            await asyncio.to_thread(
                partial(
                    self.store.finish,
                    row["id"],
                    "error",
                    "Execution worker restarted before this run completed",
                    reason="worker_interrupted",
                )
            )
        await self.schedule()

    async def execute_run(self, run):
        runner = Runner(self.store, self.github, self.root, self.secrets)
        try:
            await runner.execute(run)
        except Exception:
            await asyncio.to_thread(
                self.store.finish, run["id"], "error", "Worker setup failed; inspect execution worker logs"
            )
        await self.publish()

    async def schedule(self):
        active = {}
        swept = checked = time.monotonic()
        sweep: asyncio.Future = asyncio.get_running_loop().create_future()
        sweep.set_result(None)
        try:
            while True:
                done = {t for t in active if t.done()}
                for task in done:
                    try:
                        task.result()
                    except Exception as exc:
                        rid = active[task]["run_id"]
                        self.run_errors[rid] = (f"Run {rid[:8]} finalization failed: {exc}", time.time())
                    del active[task]
                await asyncio.to_thread(self.expire_run_errors)
                if not active and time.monotonic() - swept > NETWORK_SWEEP_SECONDS and sweep.done():
                    # Networks whose removal lost a race with a slow container teardown. In the
                    # background: a slow Docker daemon must not delay claiming the next run.
                    # Removal only succeeds for networks no container is attached to.
                    swept = time.monotonic()
                    sweep = asyncio.create_task(
                        Runner(self.store, self.github, self.root, self.secrets).cleanup_networks()
                    )
                settings = await asyncio.to_thread(self.store.settings, self.capacity)
                update = await asyncio.to_thread(updater.load, self.store)
                if update.get("state") == "requested" and not active:
                    await updater.start(self.store, self.deployment, self.update_unavailable)
                elif update.get("state") == "running" and time.monotonic() - checked > 5:
                    checked = time.monotonic()
                    await updater.reconcile(self.store)
                unfit = False
                # Lowering the limit drains existing runs; it never kills them. A requested
                # update drains them the same way before it restarts the services.
                while updater.admits_runs(settings, update) and len(active) < settings["max_parallel_runs"]:
                    # In-flight runs retain their old limits after a settings change.
                    if sum(v["cpus_per_run"] for v in active.values()) + settings["cpus_per_run"] > max(
                        1, self.capacity["cpus"] - 2
                    ) or sum(v["memory_gb_per_run"] for v in active.values()) + settings[
                        "memory_gb_per_run"
                    ] > max(2, self.capacity["memory_gb"] - 4):
                        unfit = bool(
                            await asyncio.to_thread(
                                self.store.rows,
                                "SELECT id FROM runs WHERE state='queued' AND cancel=0 LIMIT 1",
                            )
                        )
                        break
                    run = await asyncio.to_thread(self.store.claim, settings)
                    if not run:
                        break
                    active[asyncio.create_task(self.execute_run(run))] = {**settings, "run_id": run["id"]}
                # Recomputed every pass, so it clears as soon as the queued run fits or leaves.
                self.capacity_error = (
                    "Queued run does not fit configured host capacity; reduce CPU/memory limits "
                    "or free an active run"
                    if unfit
                    else ""
                )
                await asyncio.sleep(1)
        finally:
            sweep.cancel()
            for task in active:
                task.cancel()
            await asyncio.gather(*active, return_exceptions=True)
