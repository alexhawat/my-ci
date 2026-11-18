import asyncio
import fcntl
import json
import os
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any

from localci.results import aggregate

ACTIVE = ("queued", "running")
# Why a run ended, when the system rather than its checks decided. Only these
# system-caused endings are re-queued automatically; an operator's cancel is final.
RECOVERABLE = ("pr_inactive", "repo_disabled", "worker_interrupted")
MAX_RECOVERIES = 3  # Unbilled automatic re-runs per PR revision; bounds crash loops.
SCHEMA_VERSION = 4
_SELECT = re.compile(r"\s*SELECT\b", re.IGNORECASE)


def _on_event_loop() -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


class RetryLimitReached(RuntimeError):
    pass


class RevisionChanged(RuntimeError):
    """An operator's approval named a revision that is no longer the PR's current one."""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise RuntimeError("Database is newer than this Local CI release")
            if 0 < version < SCHEMA_VERSION:
                backup = path.with_suffix(f".pre-v{version + 1}.sqlite")
                if not backup.exists():
                    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    os.close(fd)
                    with sqlite3.connect(backup) as target:
                        db.backup(target)
            db.executescript("""
                CREATE TABLE IF NOT EXISTS repos (
                    name TEXT PRIMARY KEY, data TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,
                    config TEXT NOT NULL DEFAULT '{}', error TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS prs (
                    repo TEXT NOT NULL, number INTEGER NOT NULL, data TEXT NOT NULL,
                    PRIMARY KEY(repo, number)
                );
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, repo TEXT NOT NULL, pr INTEGER NOT NULL,
                    head TEXT NOT NULL, base TEXT NOT NULL, attempt INTEGER NOT NULL,
                    state TEXT NOT NULL, created REAL NOT NULL, started REAL, finished REAL,
                    snapshot TEXT NOT NULL, config TEXT NOT NULL, steps TEXT NOT NULL DEFAULT '[]',
                    message TEXT NOT NULL DEFAULT '', cancel INTEGER NOT NULL DEFAULT 0,
                    publish_error TEXT NOT NULL DEFAULT '', published INTEGER NOT NULL DEFAULT 0,
                    end_reason TEXT NOT NULL DEFAULT '',
                    UNIQUE(repo, pr, head, base, attempt)
                );
                CREATE TABLE IF NOT EXISTS revision_attempts (
                    repo TEXT NOT NULL, pr INTEGER NOT NULL, head TEXT NOT NULL, base TEXT NOT NULL,
                    attempts INTEGER NOT NULL, recoveries INTEGER NOT NULL DEFAULT 0,
                    approved INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(repo,pr,head,base)
                );
                CREATE TABLE IF NOT EXISTS secrets (
                    repo TEXT NOT NULL, name TEXT NOT NULL, ciphertext TEXT NOT NULL,
                    PRIMARY KEY(repo, name)
                );
                CREATE INDEX IF NOT EXISTS run_queue ON runs(state, created);
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS workflow_versions (
                    repo TEXT NOT NULL, path TEXT NOT NULL, version INTEGER NOT NULL,
                    content TEXT NOT NULL, source_ref TEXT NOT NULL, created REAL NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(repo,path,version)
                );
                CREATE TABLE IF NOT EXISTS run_events (
                    id INTEGER PRIMARY KEY, run_id TEXT NOT NULL, timestamp REAL NOT NULL,
                    phase TEXT NOT NULL, job TEXT NOT NULL, level TEXT NOT NULL, message TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS events_run ON run_events(run_id,id);
                CREATE TABLE IF NOT EXISTS run_usage (
                    run_id TEXT PRIMARY KEY, repo TEXT NOT NULL, created REAL NOT NULL,
                    cpu_seconds REAL NOT NULL DEFAULT 0, peak_memory_bytes INTEGER NOT NULL DEFAULT 0,
                    samples INTEGER NOT NULL DEFAULT 0, last_sample REAL,
                    duration_seconds REAL NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'running'
                );
                CREATE TABLE IF NOT EXISTS resource_samples (
                    run_id TEXT NOT NULL, timestamp REAL NOT NULL, cpu_percent REAL NOT NULL,
                    memory_bytes INTEGER NOT NULL, PRIMARY KEY(run_id,timestamp)
                );
                INSERT OR IGNORE INTO run_usage(run_id,repo,created,duration_seconds,state)
                    SELECT id,repo,created,MAX(0,COALESCE(finished-started,0)),state FROM runs WHERE started IS NOT NULL;
            """)
            if "end_reason" not in {r[1] for r in db.execute("PRAGMA table_info(runs)")}:
                db.execute("ALTER TABLE runs ADD COLUMN end_reason TEXT NOT NULL DEFAULT ''")
            budget_columns = {r[1] for r in db.execute("PRAGMA table_info(revision_attempts)")}
            if "recoveries" not in budget_columns:
                db.execute("ALTER TABLE revision_attempts ADD COLUMN recoveries INTEGER NOT NULL DEFAULT 0")
            if "approved" not in budget_columns:
                # Whether an operator started this revision; nothing earlier recorded that.
                db.execute("ALTER TABLE revision_attempts ADD COLUMN approved INTEGER NOT NULL DEFAULT 0")
            if version == 3:
                # The previous release re-ran these system-ended runs by matching their
                # message; keep them recoverable now that the reason is a column.
                for message, reason in (
                    ("PR changed, closed, or became a draft", "pr_inactive"),
                    ("Repository disabled", "repo_disabled"),
                ):
                    db.execute(
                        "UPDATE runs SET end_reason=? WHERE state='cancelled' AND message=? AND end_reason=''",
                        (reason, message),
                    )
                # Crash recovery, and the graceful stop that an upgrade itself performs.
                db.execute(
                    "UPDATE runs SET end_reason='worker_interrupted' WHERE state IN ('error','failure') "
                    "AND end_reason='' AND (message LIKE '%Execution worker restarted; retry this run%' "
                    "OR message LIKE '%Controller stopped during execution; retry this run%')"
                )
            if version in (1, 2):
                # One-time backfill for databases that predate the budget table. Running it on
                # every start would bill unbilled automatic recoveries against the retry budget.
                db.execute(
                    """INSERT INTO revision_attempts(repo,pr,head,base,attempts)
                    SELECT repo,pr,head,base,MAX(attempt) FROM runs GROUP BY repo,pr,head,base
                    ON CONFLICT(repo,pr,head,base) DO UPDATE SET
                        attempts=MAX(revision_attempts.attempts,excluded.attempts)"""
                )
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        # Keep the WAL open between short-lived request connections. Otherwise SQLite
        # checkpoints and removes it after every log batch, amplifying writes on CoW disks.
        # This connection holds no transaction and is never used for application queries.
        self._journal_connection = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self._journal_connection.execute("PRAGMA journal_mode=WAL")
        # A single incomplete paginated result is not proof that a PR disappeared.
        self._missing_pr_observations: set[str] = set()

    def close(self):
        self._journal_connection.close()

    @contextmanager
    def writer(self):
        # All controller/worker processes share one admission lock. SQLite busy
        # retries alone can starve a writer behind continuous scan-log commits.
        fd = os.open(self.path.with_suffix(self.path.suffix + ".writer.lock"), os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(fd, "a") as lock:
            deadline = time.monotonic() + 120
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Local CI database writer did not become available") from None
                    time.sleep(0.02)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    @contextmanager
    def connect(self, *, write: bool = True):
        with self.writer() if write else nullcontext():
            db = sqlite3.connect(self.path, timeout=30)
            db.row_factory = sqlite3.Row
            try:
                with db:
                    yield db
            finally:
                db.close()

    def rows(self, sql: str, args: tuple = (), *, readonly: bool | None = None) -> list[dict[str, Any]]:
        # WAL reader lock races can return SQLITE_PROTOCOL despite busy_timeout.
        # Retry only reads on a fresh connection, never ambiguous mutations or
        # unrelated database failures. A metadata poll must survive a brief race.
        # A statement whose first keyword is SELECT cannot write. Anything else
        # (WITH can front a mutation) is retried only when the caller passes
        # readonly=True.
        if readonly is None:
            readonly = _SELECT.match(sql) is not None
        attempt = 0
        while True:
            try:
                with self.connect(write=False) as db:
                    return [dict(r) for r in db.execute(sql, args)]
            except sqlite3.OperationalError as exc:
                if (
                    getattr(exc, "sqlite_errorcode", None) != sqlite3.SQLITE_PROTOCOL
                    or not readonly
                    or attempt >= 4
                ):
                    raise
                # Some callers run on the event loop. Never block it: retry at
                # once there, and back off only in worker threads.
                if not _on_event_loop():
                    time.sleep(0.02 * 2**attempt)
                attempt += 1

    def execute(self, sql: str, args: tuple = ()):
        with self.connect() as db:
            db.execute(sql, args)

    def append_events(self, rows: list[tuple]):
        if not rows:
            return
        with self.connect() as db:
            db.executemany(
                "INSERT INTO run_events(run_id,timestamp,phase,job,level,message) VALUES(?,?,?,?,?,?)",
                rows,
            )

    def discover(self, repos: list[dict]):
        with self.connect() as db:
            for repo in repos:
                db.execute(
                    "INSERT INTO repos(name,data) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET data=excluded.data",
                    (repo["full_name"], json.dumps(repo)),
                )

    def replace_prs(self, repo: str, prs: list[dict]):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM prs WHERE repo=?", (repo,))
            db.executemany(
                "INSERT INTO prs(repo,number,data) VALUES(?,?,?)",
                [(repo, pr["number"], json.dumps(pr)) for pr in prs],
            )

    def repo(self, name: str) -> dict:
        rows = self.rows("SELECT * FROM repos WHERE name=?", (name,))
        if not rows:
            raise KeyError(name)
        return rows[0]

    def enqueue(
        self,
        repo: str,
        pr: dict,
        config: dict,
        *,
        retry: bool = False,
        hold: str | None = None,
        bot_hold: str | None = None,
        reviewed: tuple[str, str] | None = None,
        require_enabled: bool = False,
    ) -> str | None:
        """Queue a run for the PR's current head/base revision.

        Without ``retry`` this is the automatic path: it creates the first run of a
        revision, or re-queues one that the system itself ended (RECOVERABLE) without
        charging the retry budget, at most MAX_RECOVERIES times. ``retry`` is the
        operator path and is charged against the budget. ``hold`` records the first
        run as blocked with that message instead of queueing it (operator approval gate).
        ``bot_hold`` is such a message for a bot-authored PR. Unless the repository's
        stored configuration allows automatic bot runs at this moment, such a PR runs
        only on a revision an operator started: its first run is held, an automatic
        recovery of a never-approved revision becomes a held run, and a retry must name
        the revision the operator ``reviewed`` (head, base) or RevisionChanged is raised.
        ``require_enabled`` makes the repository's enabled flag part of the transaction.
        """
        head, base = pr["head"]["sha"], pr["base"]["sha"]
        key = (repo, pr["number"], head, base)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT state,end_reason FROM runs WHERE repo=? AND pr=? AND head=? AND base=? "
                "ORDER BY created DESC,rowid DESC LIMIT 1",
                key,
            ).fetchone()
            if previous and previous["state"] in ACTIVE:
                return None
            # Checked inside the transaction: a poll that listed the repository before it
            # was disabled must not re-queue the run that disabling just cancelled.
            watched = db.execute("SELECT enabled,config FROM repos WHERE name=?", (repo,)).fetchone()
            if require_enabled and (not watched or not watched["enabled"]):
                return None
            budget = db.execute(
                "SELECT attempts,recoveries,approved FROM revision_attempts "
                "WHERE repo=? AND pr=? AND head=? AND base=?",
                key,
            ).fetchone()
            attempts, recoveries, approved = tuple(budget) if budget else (0, 0, 0)
            # Read here, not by the caller before its slow GitHub request: an operator who
            # just switched automatic bot runs off must not be overtaken by a poll or retry.
            gated = bool(bot_hold) and not (watched and json.loads(watched["config"]).get("run_bot_prs"))
            if gated and retry and reviewed is not None and reviewed != (head, base):
                raise RevisionChanged(
                    "This bot-authored PR changed after this run; review the new revision and retry its own run"
                )
            # The automatic path may start a gated bot PR only on a revision an operator started.
            gated = gated and not retry and not approved
            if gated:
                hold = bot_hold
            recovery = bool(
                not retry
                and previous
                and previous["end_reason"] in RECOVERABLE
                and recoveries < MAX_RECOVERIES
            )
            # An interrupted bot run nobody approved (auto-run before the option was switched
            # off, or by a release that had no gate) is held for approval, not re-run.
            hold_recovery = recovery and gated
            recovery = recovery and not gated
            # ``attempts`` outlives pruned run rows, so a completed revision is never re-run
            # automatically just because its history aged out.
            # A held bot PR starts on its own once the repository opts into automatic bot runs.
            release = bool(
                not retry and hold is None and previous and previous["end_reason"] == "awaiting_approval"
            )
            if (previous or attempts) and not retry and not recovery and not release and not hold_recovery:
                return None
            hold = None if (previous and not hold_recovery) or retry else hold
            if retry:
                setting = db.execute("SELECT value FROM settings WHERE key='execution'").fetchone()
                max_retries = (json.loads(setting[0]) if setting else {}).get("max_retries", 2)
                if attempts >= max_retries + 1:
                    raise RetryLimitReached(
                        f"Retry limit reached: {max_retries + 1} attempts per PR head/base revision. "
                        "Change Maximum retries in Execution settings to allow more."
                    )
            config = {
                **config,
                "review_failure_threshold": config.get("review_failure_threshold", "major"),
                "review_policy_version": 1,
                "workflow_overrides": {
                    r["path"]: dict(r)
                    for r in db.execute(
                        "SELECT path,version,content,source_ref FROM workflow_versions WHERE repo=? AND active=1",
                        (repo,),
                    )
                    if r["path"] in config.get("workflows", [])
                },
            }
            # Run numbers are independent of the billed budget: recoveries and held runs
            # take a number without being charged.
            highest = db.execute(
                "SELECT COALESCE(MAX(attempt),0) FROM runs WHERE repo=? AND pr=? AND head=? AND base=?", key
            ).fetchone()[0]
            attempt = max(highest, attempts + recoveries) + 1  # Stays monotonic after pruning.
            rid, now = uuid.uuid4().hex, time.time()
            db.execute(
                "INSERT INTO runs(id,repo,pr,head,base,attempt,state,created,snapshot,config) VALUES(?,?,?,?,?,?,'queued',?,?,?)",
                (rid, *key, attempt, now, json.dumps(pr), json.dumps(config)),
            )
            if hold:
                db.execute(
                    "UPDATE runs SET state='blocked',message=?,finished=?,end_reason='awaiting_approval' WHERE id=?",
                    (hold, now, rid),
                )
            billed = 0 if recovery or hold else 1
            db.execute(
                "INSERT INTO revision_attempts(repo,pr,head,base,attempts,recoveries,approved) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(repo,pr,head,base) DO UPDATE SET "
                "attempts=attempts+excluded.attempts,recoveries=recoveries+excluded.recoveries,"
                "approved=MAX(approved,excluded.approved)",
                # A retry is an operator starting this exact revision.
                (*key, billed, int(recovery), int(retry)),
            )
            return rid

    def request_cancel(self, rid: str, reason: str, message: str) -> None:
        """Ask an active run to stop and remember why. A queued run is finalized here;
        a running one is finalized by its worker, which keeps the recorded reason."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # An operator's cancel is final: a later system cancel of the same still-running
            # run (repository disabled, PR drafted) must not make it recoverable again.
            db.execute(
                "UPDATE runs SET cancel=1,"
                "end_reason=CASE WHEN end_reason='operator' THEN 'operator' ELSE ? END "
                "WHERE id=? AND state IN ('queued','running')",
                (reason, rid),
            )
            # Same transaction, so a crash cannot leave a queued row that nothing claims
            # or finalizes. A run a worker already claimed is left for that worker to end.
            self._finish(db, rid, "cancelled", message, expected_state="queued")

    def claim(self, execution: dict | None = None) -> dict | None:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM runs WHERE state='queued' AND cancel=0 ORDER BY created LIMIT 1"
            ).fetchone()
            if not row:
                return None
            result = dict(row)
            config = json.loads(result["config"])
            config.setdefault("review_failure_threshold", "major")
            config.setdefault("review_policy_version", 1)
            if execution is not None:
                config["execution"] = execution
            result.update(state="running", started=time.time(), config=json.dumps(config))
            db.execute(
                "UPDATE runs SET state='running',started=?,config=?,published=0 WHERE id=?",
                (result["started"], result["config"], row["id"]),
            )
            db.execute(
                "INSERT OR IGNORE INTO run_usage(run_id,repo,created) VALUES(?,?,?)",
                (row["id"], row["repo"], row["created"]),
            )
            return result

    def finish(
        self,
        rid: str,
        state: str,
        message: str,
        *,
        expected_state: str | None = None,
        reason: str | None = None,
    ):
        """Finalize an active run. ``reason`` records why it ended (see RECOVERABLE);
        None keeps a reason already stored with a cancellation request."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._finish(db, rid, state, message, expected_state=expected_state, reason=reason)

    @staticmethod
    def _finish(db, rid, state, message, *, expected_state=None, reason=None):
        row = db.execute("SELECT steps,state,end_reason FROM runs WHERE id=?", (rid,)).fetchone()
        if (
            not row
            or row["state"] not in ACTIVE
            or (expected_state is not None and row["state"] != expected_state)
        ):
            return
        steps = json.loads(row["steps"])
        now = time.time()
        for step in steps:
            if step["state"] in ("queued", "running"):
                # Reports distinguish a check that was cut short from one that never began.
                if step["state"] == "queued":
                    step["never_started"] = True
                step.update(state=state, message=message, finished=now)
        state, message = aggregate(steps, state, message)
        requested = row["end_reason"]
        if requested == "operator" and (state == "cancelled" or reason):
            end_reason = "operator"  # A worker stop must not resurrect an operator's cancel.
        elif reason is not None:
            end_reason = reason
        else:
            # A requested cancel only explains a run that actually ended cancelled;
            # one that completed first keeps its real outcome and is not re-queued.
            end_reason = requested if state == "cancelled" else ""
        db.execute(
            "UPDATE runs SET state=?,message=?,steps=?,finished=?,published=0,end_reason=? WHERE id=?",
            (state, message, json.dumps(steps), now, end_reason, rid),
        )
        db.execute(
            """UPDATE run_usage SET state=?,duration_seconds=COALESCE(
            (SELECT MAX(0,finished-started) FROM runs WHERE id=?),0) WHERE run_id=?""",
            (state, rid, rid),
        )

    def reconcile_results(self):
        # Derived result repair; individual historical check outcomes remain intact.
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for row in db.execute(
                "SELECT id,state,message,steps,finished FROM runs WHERE state IN ('failure','error','blocked','cancelled')"
            ).fetchall():
                steps = json.loads(row["steps"])
                interrupted = False
                for step in steps:
                    if step["state"] == "running":
                        interrupted = True
                        step.update(
                            state="cancelled" if row["state"] == "cancelled" else "error",
                            message=row["message"] or "Run ended before this check completed",
                            finished=row["finished"],
                        )
                state, message = aggregate(steps, row["state"], row["message"])
                if state != row["state"] or interrupted:
                    db.execute(
                        "UPDATE runs SET state=?,message=?,steps=?,published=0 WHERE id=?",
                        (state, message, json.dumps(steps), row["id"]),
                    )
                    db.execute("UPDATE run_usage SET state=? WHERE run_id=?", (state, row["id"]))

    def settings(self, capacity: dict | None = None) -> dict:
        capacity = capacity or {}
        available_cpus = max(1, int(capacity.get("cpus", 10)) - 2)
        available_memory = max(2, int(capacity.get("memory_gb", 28)) - 4)
        defaults = {
            "max_parallel_runs": 1,
            "cpus_per_run": min(8, available_cpus),
            "memory_gb_per_run": min(24, available_memory),
            "paused": False,
            "max_retries": 2,
        }
        rows = self.rows("SELECT value FROM settings WHERE key='execution'")
        return {**defaults, **(json.loads(rows[0]["value"]) if rows else {})}

    def save_settings(self, value: dict):
        self.execute(
            "INSERT INTO settings VALUES('execution',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (json.dumps(value),),
        )

    def save_workflow(self, repo: str, path: str, content: str, source_ref: str) -> int:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            version = db.execute(
                "SELECT COALESCE(MAX(version),0)+1 FROM workflow_versions WHERE repo=? AND path=?",
                (repo, path),
            ).fetchone()[0]
            db.execute("UPDATE workflow_versions SET active=0 WHERE repo=? AND path=?", (repo, path))
            db.execute(
                "INSERT INTO workflow_versions VALUES(?,?,?,?,?,?,1)",
                (repo, path, version, content, source_ref, time.time()),
            )
            return version

    def usage_sample(self, rid: str, timestamp: float, cpu_percent: float, memory: int, interval: float):
        with self.connect() as db:
            db.execute("INSERT INTO resource_samples VALUES(?,?,?,?)", (rid, timestamp, cpu_percent, memory))
            db.execute(
                """UPDATE run_usage SET cpu_seconds=cpu_seconds+?,peak_memory_bytes=MAX(peak_memory_bytes,?),
                samples=samples+1,last_sample=? WHERE run_id=?""",
                (max(0, cpu_percent) * max(0, interval) / 100, memory, timestamp, rid),
            )

    def cancel_stale(self, repo: str, prs: list[dict]):
        current = {p["number"]: p for p in prs}
        active = self.rows("SELECT * FROM runs WHERE repo=? AND state IN ('queued','running')", (repo,))
        active_ids = {run["id"] for run in active}
        self._missing_pr_observations.intersection_update(active_ids)
        for run in active:
            pr = current.get(run["pr"])
            if not pr:
                # Pagination can omit an open PR when another PR closes between pages.
                # Cancel only after a second complete poll also fails to observe it.
                if run["id"] not in self._missing_pr_observations:
                    self._missing_pr_observations.add(run["id"])
                    continue
            else:
                self._missing_pr_observations.discard(run["id"])
            if not pr or pr["draft"] or (pr["head"]["sha"], pr["base"]["sha"]) != (run["head"], run["base"]):
                self.request_cancel(run["id"], "pr_inactive", "PR changed, closed, or became a draft")

    def backup(self, destination: Path):
        with self.connect(write=False) as source, sqlite3.connect(destination) as target:
            source.backup(target)
