import asyncio
import sqlite3
import sys
import threading
import time

import httpx
from test_service import pr

from localci.app import create_app
from localci.runner import Runner
from localci.store import Store


def test_log_transactions_reuse_wal_and_checkpoint_on_close(tmp_path):
    store = Store(tmp_path / "ci.db")
    wal = tmp_path / "ci.db-wal"
    for index in range(3):
        store.append_events([("fixture", float(index), "ci", "job", "info", str(index))])
        assert wal.exists() and wal.stat().st_size > 0
    store.close()
    assert not wal.exists()
    # All events survive reopening after the final checkpoint.
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT message FROM run_events ORDER BY id").fetchall() == [("0",), ("1",), ("2",)]


async def test_slow_log_storage_does_not_block_health(tmp_path, monkeypatch):
    app = create_app(tmp_path, background=False)
    c = app.state.controller
    rid = c.store.enqueue("o/r", pr(), {})
    runner = Runner(c.store, c.github, tmp_path, lambda *_: {})
    runner.run = c.store.claim()
    runner.deadline = time.monotonic() + 10
    runner.log_path = tmp_path / "logs" / f"{rid}.log"
    writing = threading.Event()
    release = threading.Event()
    original = runner.log

    def slow_log(text):
        writing.set()
        assert release.wait(5), "test did not release simulated disk stall"
        original(text)

    monkeypatch.setattr(runner, "log", slow_log)
    task = asyncio.create_task(runner.command(sys.executable, "-c", 'print("[test/job] hello",flush=True)'))
    try:
        assert await asyncio.to_thread(writing.wait, 3)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://local"
        ) as client:
            response = await asyncio.wait_for(client.get("/healthz"), 2)
            assert response.status_code == 200
    finally:
        release.set()
        # Command has already exited, so its output must still flush before completion.
        await task
    assert "hello" in runner.log_path.read_text()


def test_log_batch_preserves_all_job_results_redaction_and_events(tmp_path):
    c = create_app(tmp_path, background=False).state.controller
    rid = c.store.enqueue("o/r", pr(), {})
    runner = Runner(c.store, c.github, tmp_path, lambda *_: {})
    runner.run = c.store.claim()
    runner.log_path = tmp_path / "logs" / f"{rid}.log"
    runner.sensitive = ["private-fixture-token"]
    runner.log(
        "[test/one] 🏁  Job succeeded\n[test/two] private-fixture-token\n[test/two] 🏁  Job succeeded\n"
    )
    assert runner.completed_jobs == 2
    rows = c.store.rows("SELECT message FROM run_events WHERE run_id=?", (rid,))
    assert len(rows) == 3
    assert "private-fixture-token" not in runner.log_path.read_text()
    assert rows[1]["message"] == "[redacted]"


def test_independent_process_writers_serialize_without_sqlite_busy(tmp_path):
    import os
    import subprocess
    from pathlib import Path

    path = tmp_path / "ci.db"
    store = Store(path)
    gate = tmp_path / "go"
    script = """
import sqlite3, sys, time
from pathlib import Path
from localci.store import Store
store = Store(Path(sys.argv[1]))
original = sqlite3.connect
def short_timeout(*args, **kwargs):
    kwargs['timeout'] = 0.001
    return original(*args, **kwargs)
sqlite3.connect = short_timeout
print('ready', flush=True)
while not Path(sys.argv[2]).exists():
    time.sleep(0.01)
for batch in range(20):
    with store.connect() as db:
        db.executemany('INSERT INTO run_events(run_id,timestamp,phase,job,level,message) VALUES(?,?,?,?,?,?)',
            [(sys.argv[3], batch, 'ci', 'scan', 'info', str(i)) for i in range(20)])
        time.sleep(0.02)
store.close()
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(path), str(gate), str(index)],
            env={"PYTHONPATH": str(Path(__file__).resolve().parents[1])},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(4)
    ]
    try:
        for process in processes:
            assert process.stdout.readline().strip() == "ready"
        gate.touch()
        for process in processes:
            _, error = process.communicate(timeout=20)
            assert process.returncode == 0, error
        assert store.rows("SELECT count(*) AS n FROM run_events")[0]["n"] == 1600
        assert os.stat(path.with_suffix(".db.writer.lock")).st_mode & 0o777 == 0o600
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        store.close()


async def test_sparse_live_output_flushes_before_command_finishes(tmp_path, monkeypatch):
    c = create_app(tmp_path, background=False).state.controller
    rid = c.store.enqueue("o/r", pr(), {})
    runner = Runner(c.store, c.github, tmp_path, lambda *_: {})
    runner.run = c.store.claim()
    runner.deadline = time.monotonic() + 10
    runner.log_path = tmp_path / "logs" / f"{rid}.log"
    flushed = asyncio.Event()
    loop = asyncio.get_running_loop()
    original = runner.log

    def recorded(text):
        original(text)
        loop.call_soon_threadsafe(flushed.set)

    monkeypatch.setattr(runner, "log", recorded)
    task = asyncio.create_task(
        runner.command(
            sys.executable,
            "-c",
            'import time; print("[ci/job] first", flush=True); time.sleep(2); print("last")',
        )
    )
    try:
        await asyncio.wait_for(flushed.wait(), 1.5)
        assert c.store.rows("SELECT id FROM run_events WHERE run_id=?", (rid,))
        assert not task.done()
    finally:
        await task
    rows = c.store.rows("SELECT message FROM run_events WHERE run_id=? ORDER BY id", (rid,))
    assert [row["message"] for row in rows] == ["first", "last"]
    c.store.close()


async def test_metric_write_contention_is_a_gap_not_a_failed_run(monkeypatch):
    from types import SimpleNamespace

    from localci import telemetry

    class Process:
        returncode = 0

        async def communicate(self):
            return b'{"Name":"ci-fixture","CPUPerc":"10%","MemUsage":"1MiB / 2GiB"}\n', b""

    async def spawn(*args, **kwargs):
        return Process()

    intervals = []
    recorded = asyncio.Event()
    loop = asyncio.get_running_loop()

    def sample(*args):
        intervals.append(args[-1])
        if len(intervals) == 1:
            raise sqlite3.OperationalError("database is locked")
        loop.call_soon_threadsafe(recorded.set)

    monkeypatch.setattr(telemetry.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(telemetry, "SAMPLE_INTERVAL", 0.01)
    task = asyncio.create_task(
        telemetry.sample_resources(SimpleNamespace(usage_sample=sample), "run", {"ci-fixture"})
    )
    try:
        await asyncio.wait_for(recorded.wait(), 2)
        assert intervals[:2] == [0, 0]  # No extrapolation across the failed sample.
        assert not task.done()
    finally:
        task.cancel()
        import contextlib

        with contextlib.suppress(asyncio.CancelledError):
            await task
