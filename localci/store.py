import fcntl
import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any

from localci.results import aggregate

ACTIVE = ("queued", "running")


class RetryLimitReached(RuntimeError):
    pass


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > 3:
                raise RuntimeError("Database is newer than this Local CI release")
            if version in (1, 2):
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
                    UNIQUE(repo, pr, head, base, attempt)
                );
                CREATE TABLE IF NOT EXISTS revision_attempts (
                    repo TEXT NOT NULL, pr INTEGER NOT NULL, head TEXT NOT NULL, base TEXT NOT NULL,
                    attempts INTEGER NOT NULL, PRIMARY KEY(repo,pr,head,base)
                );
                INSERT INTO revision_attempts(repo,pr,head,base,attempts)
                    SELECT repo,pr,head,base,MAX(attempt) FROM runs GROUP BY repo,pr,head,base
                    ON CONFLICT(repo,pr,head,base) DO UPDATE SET
                        attempts=MAX(revision_attempts.attempts,excluded.attempts);
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
                PRAGMA user_version=3;
            """)
        # Keep the WAL open between short-lived request connections. Otherwise SQLite
        # checkpoints and removes it after every log batch, amplifying writes on CoW disks.
        # This connection holds no transaction and is never used for application queries.
        self._journal_connection = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self._journal_connection.execute("PRAGMA journal_mode=WAL")

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

    def rows(self, sql: str, args: tuple = ()) -> list[dict[str, Any]]:
        with self.connect(write=False) as db:
            return [dict(r) for r in db.execute(sql, args)]

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

    def enqueue(self, repo: str, pr: dict, config: dict, *, retry: bool = False) -> str | None:
        head, base = pr["head"]["sha"], pr["base"]["sha"]
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT attempt,state,message FROM runs WHERE repo=? AND pr=? AND head=? AND base=? ORDER BY created DESC LIMIT 1",
                (repo, pr["number"], head, base),
            ).fetchone()
            budget = db.execute(
                "SELECT attempts FROM revision_attempts WHERE repo=? AND pr=? AND head=? AND base=?",
                (repo, pr["number"], head, base),
            ).fetchone()
            attempts = budget["attempts"] if budget else 0
            automatic_recovery = bool(
                previous
                and (
                    previous["state"] == "cancelled"
                    or previous["message"] == "Execution worker restarted; retry this run"
                )
            )
            if (attempts and not retry and not automatic_recovery) or (
                previous and previous["state"] in ACTIVE
            ):
                return None
            setting = db.execute("SELECT value FROM settings WHERE key='execution'").fetchone()
            max_retries = (json.loads(setting[0]) if setting else {}).get("max_retries", 2)
            if not automatic_recovery and attempts >= max_retries + 1:
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
            attempt = previous["attempt"] + 1 if automatic_recovery and previous else attempts + 1
            billed_attempts = attempts if automatic_recovery else attempt
            rid = uuid.uuid4().hex
            db.execute(
                "INSERT INTO runs(id,repo,pr,head,base,attempt,state,created,snapshot,config) VALUES(?,?,?,?,?,?,'queued',?,?,?)",
                (
                    rid,
                    repo,
                    pr["number"],
                    head,
                    base,
                    attempt,
                    time.time(),
                    json.dumps(pr),
                    json.dumps(config),
                ),
            )
            db.execute(
                "INSERT INTO revision_attempts VALUES(?,?,?,?,?) "
                "ON CONFLICT(repo,pr,head,base) DO UPDATE SET attempts=excluded.attempts",
                (repo, pr["number"], head, base, billed_attempts),
            )
            return rid

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

    def finish(self, rid: str, state: str, message: str, *, expected_state: str | None = None):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT steps,state FROM runs WHERE id=?", (rid,)).fetchone()
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
                    step.update(state=state, message=message, finished=now)
            state, message = aggregate(steps, state, message)
            db.execute(
                "UPDATE runs SET state=?,message=?,steps=?,finished=?,published=0 WHERE id=?",
                (state, message, json.dumps(steps), now, rid),
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
        for run in self.rows("SELECT * FROM runs WHERE repo=? AND state IN ('queued','running')", (repo,)):
            pr = current.get(run["pr"])
            if not pr or pr["draft"] or (pr["head"]["sha"], pr["base"]["sha"]) != (run["head"], run["base"]):
                self.execute("UPDATE runs SET cancel=1 WHERE id=?", (run["id"],))
                if run["state"] == "queued":
                    self.finish(run["id"], "cancelled", "PR changed, closed, or became a draft")

    def backup(self, destination: Path):
        with self.connect(write=False) as source, sqlite3.connect(destination) as target:
            source.backup(target)
