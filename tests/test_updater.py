"""Dashboard self-update: request lifecycle, drain gate, helper container and its outcome."""

import json
import os
import shutil
import subprocess
import time
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from localci import updater
from localci.app import create_app
from localci.store import Store

DIRECTORY = "/srv/my-ci"


def inspect(**labels):
    base = {
        "com.docker.compose.project": "myci",
        "com.docker.compose.project.working_dir": DIRECTORY,
        "com.docker.compose.project.config_files": f"{DIRECTORY}/compose.yaml",
    }
    return {
        "Image": "sha256:" + "1" * 64,
        "Config": {"Labels": {**base, **labels}},
        "Mounts": [{"Source": "/run/docker.sock", "Destination": "/var/run/docker.sock"}],
    }


def test_deployment_comes_from_the_worker_compose_labels(monkeypatch):
    monkeypatch.delenv("LOCALCI_SELF_UPDATE", raising=False)
    target, reason = updater.deployment(inspect())
    assert reason == ""
    assert target == {
        "project": "myci",
        "directory": DIRECTORY,
        "files": [f"{DIRECTORY}/compose.yaml"],
        "image": "sha256:" + "1" * 64,
        "socket": "/run/docker.sock",
    }
    assert updater.deployment({"Config": {"Labels": {}}})[0] is None
    outside = inspect(**{"com.docker.compose.project.config_files": "/etc/compose.yaml"})
    assert "inside the project directory" in updater.deployment(outside)[1]
    assert "socket" in updater.deployment({**inspect(), "Mounts": []})[1]
    monkeypatch.setenv("LOCALCI_SELF_UPDATE", "0")
    assert "turned off" in updater.deployment(inspect())[1]


def test_helper_runs_outside_the_compose_project_with_the_checkout_at_its_host_path():
    target, _ = updater.deployment(inspect())
    args = updater.helper_command(target, "myci-update-1", "main", "a" * 40)
    assert args[:6] == ["docker", "run", "-d", "--name", "myci-update-1", "--label"]
    assert not any(a.startswith("com.docker.compose") for a in args)
    assert f"{DIRECTORY}:{DIRECTORY}" in args and "/run/docker.sock:/var/run/docker.sock" in args
    env = dict(a.split("=", 1) for a, flag in zip(args[1:], args[:-1], strict=True) if flag == "-e")
    assert env["LOCALCI_COMPOSE"] == (
        f"docker compose --project-name myci --project-directory {DIRECTORY} -f {DIRECTORY}/compose.yaml"
    )
    assert env["LOCALCI_RUNNING_VERSION"] == "a" * 40 and env["LOCALCI_SERVICES"] == "app worker"
    assert args[-5:] == ["--entrypoint", "sh", target["image"], "-c", updater.SCRIPT]


def test_a_pending_or_running_update_stops_new_runs():
    settings = {"paused": False}
    assert updater.admits_runs(settings, {})
    assert updater.admits_runs(settings, {"state": "failed"})
    assert not updater.admits_runs(settings, {"state": "requested"})
    assert not updater.admits_runs(settings, {"state": "running"})
    assert not updater.admits_runs({"paused": True}, {})


def test_transition_only_from_allowed_states(tmp_path):
    store = Store(tmp_path / "localci.db")
    assert updater.transition(store, (None,), {"state": "requested"})
    assert not updater.transition(store, (None, "failed"), {"state": "requested"})
    assert updater.transition(store, ("requested",), {"state": "cancelled"})
    assert updater.load(store) == {"state": "cancelled"}


async def test_start_records_the_helper_or_why_it_could_not_start(tmp_path, monkeypatch):
    store = Store(tmp_path / "localci.db")
    calls = []

    async def docker(*args):
        calls.append(args)
        return 0, "container-id\n"

    monkeypatch.setattr(updater, "docker", docker)
    await updater.start(store, None, "not compose")
    assert updater.load(store) == {}  # Nothing was requested.
    updater.save(store, {"state": "requested", "requested": 1.0})
    await updater.start(store, None, "Self-update needs Compose.")
    assert updater.load(store)["state"] == "failed"
    assert updater.load(store)["error"] == "Self-update needs Compose."
    assert not calls
    updater.save(store, {"state": "requested", "requested": 1.0})
    monkeypatch.setenv("LOCALCI_VERSION", "b" * 40)
    await updater.start(store, updater.deployment(inspect())[0], "")
    state = updater.load(store)
    assert state["state"] == "running" and state["from"] == "b" * 40
    assert calls[0][:4] == ("run", "-d", "--name", state["helper"])


async def test_reconcile_records_the_helper_outcome_and_removes_it(tmp_path, monkeypatch):
    store = Store(tmp_path / "localci.db")
    results = {}
    removed = []

    async def docker(*args):
        if args[0] == "inspect":
            return results["inspect"]
        if args[0] == "logs":
            return 0, results["log"]
        removed.append(args)
        return 0, ""

    monkeypatch.setattr(updater, "docker", docker)
    running = {"state": "running", "helper": "myci-update-1", "started": time.time()}
    updater.save(store, running)
    results["inspect"] = (0, json.dumps({"Running": True}))
    await updater.reconcile(store)
    assert updater.load(store) == running and not removed

    results.update(
        inspect=(0, json.dumps({"Running": False, "ExitCode": 0})),
        log=f"localci-update: {'a' * 40} {'c' * 40}\nUpdated to {'c' * 40}.\n",
    )
    await updater.reconcile(store)
    state = updater.load(store)
    assert state["state"] == "succeeded" and state["to"] == "c" * 40 and "Updated to" in state["log"]
    assert removed == [("rm", "-f", "myci-update-1")]

    updater.save(store, running)
    results.update(
        inspect=(0, json.dumps({"Running": False, "ExitCode": 3})),
        log="The deployment checkout has uncommitted changes to tracked files.\n",
    )
    await updater.reconcile(store)
    assert updater.load(store)["state"] == "failed"
    assert updater.load(store)["error"].startswith("The deployment checkout has uncommitted")

    updater.save(store, running)
    results["inspect"] = (1, "No such object")
    await updater.reconcile(store)
    assert updater.load(store)["error"] == "The update helper disappeared."


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TAILSCALE_LOGIN", "owner@example.com")
    monkeypatch.setenv("LOCALCI_VERSION", "a" * 40)
    app = create_app(tmp_path, background=False)
    controller = app.state.controller
    controller.github.request = AsyncMock(
        return_value={
            "sha": "c" * 40,
            "html_url": "https://github.com/alexhawat/my-ci/commit/" + "c" * 40,
            "commit": {"message": "Latest change\n\nBody", "committer": {"date": "2026-11-20T10:00:00Z"}},
        }
    )
    with TestClient(
        app, headers={"Tailscale-User-Login": "owner@example.com", "Origin": controller.base_url}
    ) as http:
        yield http, controller


def worker_online(controller, unavailable=""):
    controller.store.execute(
        "INSERT INTO settings VALUES('worker_status',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (json.dumps({"heartbeat": time.time(), "version": "a" * 40, "update_unavailable": unavailable}),),
    )


def test_update_api_reports_versions_and_guards_the_request(client):
    http, controller = client
    data = http.get("/api/update").json()
    assert data["current"] == "a" * 40
    assert data["latest"]["sha"] == "c" * 40 and data["latest"]["message"] == "Latest change"
    assert data["latest"]["repo"] == "alexhawat/my-ci" and data["latest"]["branch"] == "main"
    assert data["unavailable"] == "The execution worker is offline."
    assert http.post("/api/update").status_code == 400

    worker_online(controller, "Self-update needs my-ci to run under Docker Compose from a git checkout.")
    assert "Docker Compose" in http.post("/api/update").json()["detail"]

    worker_online(controller)
    response = http.post("/api/update")
    assert response.status_code == 200
    state = response.json()["update"]
    assert state["state"] == "requested" and state["requested_by"] == "owner@example.com"
    assert state["from"] == "a" * 40
    assert http.post("/api/update").status_code == 409
    assert http.delete("/api/update").json()["update"]["state"] == "cancelled"
    assert http.delete("/api/update").status_code == 409
    assert http.post("/api/update", headers={"Origin": "https://evil.test"}).status_code == 403
    # The latest commit is cached instead of fetched on every poll.
    http.get("/api/update")
    assert controller.github.request.await_count == 1


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0 or not shutil.which("setpriv"),
    reason="the helper script needs root and setpriv, as in its container",
)
def test_helper_script_fast_forwards_and_rebuilds(tmp_path):
    def git(*args, cwd):
        subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)

    upstream, checkout = tmp_path / "upstream", tmp_path / "checkout"
    upstream.mkdir()
    git("init", "-q", "-b", "main", cwd=upstream)
    for args in (("config", "user.email", "ci@example.com"), ("config", "user.name", "CI")):
        git(*args, cwd=upstream)
    (upstream / "file").write_text("one\n")
    git("add", "file", cwd=upstream)
    git("commit", "-qm", "one", cwd=upstream)
    git("clone", "-q", str(upstream), str(checkout), cwd=tmp_path)
    (upstream / "file").write_text("two\n")
    git("commit", "-qam", "two", cwd=upstream)
    env = {
        **os.environ,
        "LOCALCI_CHECKOUT": str(checkout),
        "LOCALCI_UPDATE_BRANCH": "main",
        "LOCALCI_RUNNING_VERSION": "",
        "LOCALCI_COMPOSE": "echo compose",
        "LOCALCI_SERVICES": "app worker",
    }
    result = subprocess.run(["sh", "-c", updater.SCRIPT], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (checkout / "file").read_text() == "two\n"
    assert "compose build --build-arg LOCALCI_VERSION=" in result.stdout
    assert "compose up -d --no-build app worker" in result.stdout
    (checkout / "file").write_text("local edit\n")
    result = subprocess.run(["sh", "-c", updater.SCRIPT], env=env, capture_output=True, text=True)
    assert result.returncode == 3 and "uncommitted changes" in result.stderr
