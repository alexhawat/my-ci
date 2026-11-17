"""Independent execution service; the dashboard owns no run lifecycle."""

import argparse
import asyncio
import fcntl
import json
import os
import signal
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from localci.controller import Controller

ROOT = Path(os.environ.get("LOCALCI_DATA", "/data"))


@contextmanager
def worker_lock(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    fd = os.open(root / "execution-worker.lock", os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(fd, "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("An execution worker already owns this data directory") from None
        yield


def healthy(root: Path) -> bool:
    try:
        with sqlite3.connect(f"file:{root / 'localci.db'}?mode=ro", uri=True, timeout=5) as db:
            row = db.execute("SELECT value FROM settings WHERE key='worker_status'").fetchone()
        status = json.loads(row[0]) if row else {}
        return bool(status.get("heartbeat") and time.time() - status["heartbeat"] < 30)
    except (OSError, sqlite3.Error, ValueError, TypeError):
        return False


async def serve(root: Path, stop: asyncio.Event | None = None):
    with worker_lock(root):
        controller = Controller(root)
        stopped = stop or asyncio.Event()
        loop = asyncio.get_running_loop()
        if stop is None:
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, stopped.set)
        tasks = [
            asyncio.create_task(controller.monitor()),
            asyncio.create_task(controller.worker()),
            asyncio.create_task(controller.heartbeat()),
        ]
        shutdown = asyncio.create_task(stopped.wait())
        try:
            done, _ = await asyncio.wait([*tasks, shutdown], return_when=asyncio.FIRST_COMPLETED)
            if shutdown not in done:
                for task in done:
                    task.result()
                raise RuntimeError("Execution service task stopped unexpectedly")
        finally:
            for task in [*tasks, shutdown]:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.gather(shutdown, return_exceptions=True)
            await asyncio.to_thread(
                controller.store.execute,
                "INSERT INTO settings VALUES('worker_status',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (json.dumps({**controller.status(), "heartbeat": 0}),),
            )
            await asyncio.to_thread(controller.store.close)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--healthcheck", action="store_true")
    args = parser.parse_args()
    if args.healthcheck:
        raise SystemExit(0 if healthy(ROOT) else 1)
    asyncio.run(serve(ROOT))


if __name__ == "__main__":
    main()
