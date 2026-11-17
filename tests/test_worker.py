"""Lifecycle boundaries: dashboard restarts must never touch active execution."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from localci.app import Controller, create_app
from localci.worker import healthy, serve, worker_lock
from tests.test_service import pr, repo


def test_dashboard_restart_preserves_active_run_and_durable_requests(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TAILSCALE_LOGIN", "owner")
    monkeypatch.setenv("LOCALCI_URL", "https://localci.test")
    observer = Controller(tmp_path)
    observer.store.discover([repo()])
    rid = observer.store.enqueue("owner/repo", pr(), {"review": True})
    observer.store.claim()
    monitor, worker = AsyncMock(), AsyncMock()
    monkeypatch.setattr(Controller, "monitor", monitor)
    monkeypatch.setattr(Controller, "worker", worker)
    for _ in range(2):
        with TestClient(create_app(tmp_path)) as client:
            response = client.post(
                "/api/sync", headers={"Tailscale-User-Login": "owner", "Origin": "https://localci.test"}
            )
            assert response.status_code == 200
            assert client.get("/healthz").status_code == 200
        assert observer.store.rows("SELECT state,cancel FROM runs WHERE id=?", (rid,)) == [
            {"state": "running", "cancel": 0}
        ]
    monitor.assert_not_called()
    worker.assert_not_called()
    assert {r["key"] for r in observer.store.rows("SELECT key FROM settings WHERE key LIKE 'worker_%'")} == {
        "worker_sync",
        "worker_wake",
    }
    observer.store.close()


def test_worker_exclusive_lock_released_after_owner_exits(tmp_path):
    with worker_lock(tmp_path):
        with pytest.raises(RuntimeError, match="already owns"):
            with worker_lock(tmp_path):
                pytest.fail("Second worker acquired ownership")
    with worker_lock(tmp_path):
        pass


async def test_worker_receives_dashboard_sync_and_publishes_status(tmp_path):
    worker = Controller(tmp_path)
    dashboard = Controller(tmp_path)
    worker.login = "owner"
    worker.capacity = {"cpus": 32, "memory_gb": 125}
    worker.last_discovery = 123
    dashboard.notify(discover=True)
    task = asyncio.create_task(worker.heartbeat())
    try:
        for _ in range(100):
            if dashboard.status()["online"]:
                break
            await asyncio.sleep(0.01)
        status = dashboard.status()
        assert status["online"] and status["login"] == "owner"
        assert status["capacity"] == worker.capacity
        assert worker.last_discovery == 0 and worker.wake.is_set()
        assert healthy(tmp_path)
        worker.store.execute(
            "UPDATE settings SET value=? WHERE key='worker_status'", (json.dumps({**status, "heartbeat": 1}),)
        )
        assert not dashboard.status()["online"] and not healthy(tmp_path)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        dashboard.store.close()
        worker.store.close()


async def test_worker_supervision_stops_and_releases_ownership(tmp_path, monkeypatch):
    running = asyncio.Event()
    stopped = asyncio.Event()

    async def execution(self):
        running.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(Controller, "worker", execution)
    monkeypatch.setattr(Controller, "monitor", execution)
    task = asyncio.create_task(serve(tmp_path, stopped))
    await asyncio.wait_for(running.wait(), 2)
    stopped.set()
    await asyncio.wait_for(task, 2)
    assert not healthy(tmp_path)
    with worker_lock(tmp_path):
        pass


def test_web_cannot_enable_legacy_execution(tmp_path):
    with pytest.raises(ValueError, match="separate service"):
        create_app(tmp_path, background=True)


def test_dashboard_compose_has_no_docker_access():
    import yaml

    services = yaml.safe_load(Path("compose.yaml").read_text())["services"]
    assert all(
        "docker.sock" not in value and "runner-image.tar" not in value for value in services["app"]["volumes"]
    )
    assert any("docker.sock" in value for value in services["worker"]["volumes"])
    assert "ports" not in services["worker"] and "depends_on" not in services["worker"]
    assert services["worker"]["image"] != services["app"]["image"]


async def test_execution_finishes_across_dashboard_restarts(tmp_path, monkeypatch):
    """Real scheduler/shared queue, bounded fake work; no Docker or provider request."""
    started, release, finished, shutdown = (asyncio.Event() for _ in range(4))

    async def scheduler(self):
        self.capacity = {"cpus": 32, "memory_gb": 125}
        await self.schedule()

    async def execute(self, run):
        started.set()
        await release.wait()
        self.store.finish(run["id"], "success", "Completed independently of dashboard")
        finished.set()

    async def monitor(self):
        await asyncio.Event().wait()

    monkeypatch.setattr(Controller, "worker", scheduler)
    monkeypatch.setattr(Controller, "execute_run", execute)
    monkeypatch.setattr(Controller, "monitor", monitor)
    owner = Controller(tmp_path)
    rid = owner.store.enqueue("owner/repo", pr(), {"review": False})
    task = asyncio.create_task(serve(tmp_path, shutdown))
    try:
        await asyncio.wait_for(started.wait(), 3)
        for _ in range(2):
            with TestClient(create_app(tmp_path)) as client:
                assert client.get("/healthz").status_code == 200
            assert not task.done()
            assert owner.store.rows("SELECT state FROM runs WHERE id=?", (rid,))[0]["state"] == "running"
        # No dashboard is running when execution completes.
        release.set()
        await asyncio.wait_for(finished.wait(), 3)
        assert owner.store.rows("SELECT state FROM runs WHERE id=?", (rid,))[0]["state"] == "success"
    finally:
        shutdown.set()
        await asyncio.wait_for(task, 3)
        owner.store.close()
