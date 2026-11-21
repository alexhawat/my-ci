"""Update a Docker Compose deployment of my-ci to the latest upstream commit, from the dashboard.

The dashboard only records the request. The execution worker, which owns the Docker socket,
stops admitting runs, waits until no run is active, then starts a detached helper container from
its own image. The helper fast-forwards the deployment's git checkout to the upstream branch,
rebuilds the app and worker images with the new commit as ``LOCALCI_VERSION`` and recreates
both services. The helper is not part of the Compose project, so it outlives the worker it
replaces; the new worker records its outcome and removes it.

Only the ``app`` and ``worker`` services are rebuilt. The CI worker, jobs and review images
(``Dockerfile.worker``, ``Dockerfile.jobs``, ``scripts/build_review.sh``) are left as they are.
"""

import asyncio
import json
import os
import posixpath
import shlex
import time

KEY = "update"
ACTIVE = ("requested", "running")
HELPER_LABEL = "localci.updater"
HELPER_TIMEOUT = 3600
LOG_LIMIT = 8000
SOCKET = "/var/run/docker.sock"
SERVICES = ("app", "worker")

# Runs in the helper container as root, for the Docker socket. Git runs as the checkout's
# owner so that no file in the checkout becomes root-owned.
SCRIPT = r"""set -eu
owner=$(stat -c %u:%g "$LOCALCI_CHECKOUT")
checkout() {
  setpriv --reuid="${owner%:*}" --regid="${owner#*:}" --clear-groups env HOME=/tmp \
    git -c safe.directory="$LOCALCI_CHECKOUT" -C "$LOCALCI_CHECKOUT" "$@"
}
if [ -n "$(checkout status --porcelain --untracked-files=no)" ]; then
  echo "The deployment checkout has uncommitted changes to tracked files. Commit or discard them, then update again." >&2
  exit 3
fi
before=$(checkout rev-parse HEAD)
checkout fetch --quiet origin "$LOCALCI_UPDATE_BRANCH"
checkout merge --quiet --ff-only FETCH_HEAD
after=$(checkout rev-parse HEAD)
echo "localci-update: $before $after"
if [ "$after" = "$LOCALCI_RUNNING_VERSION" ]; then
  echo "Already running $after; nothing to rebuild."
  exit 0
fi
eval "$LOCALCI_COMPOSE build --build-arg LOCALCI_VERSION=$after $LOCALCI_SERVICES"
eval "$LOCALCI_COMPOSE up -d --no-build $LOCALCI_SERVICES"
echo "Updated to $after."
"""


def version() -> str:
    """The commit this image was built from, or "" for a build that did not record it."""
    return os.environ.get("LOCALCI_VERSION", "").strip()


def upstream() -> tuple[str, str]:
    return (
        os.environ.get("LOCALCI_UPDATE_REPO", "").strip() or "alexhawat/my-ci",
        os.environ.get("LOCALCI_UPDATE_BRANCH", "").strip() or "main",
    )


def load(store) -> dict:
    rows = store.rows("SELECT value FROM settings WHERE key=?", (KEY,))
    return json.loads(rows[0]["value"]) if rows else {}


def save(store, value: dict):
    store.execute(
        "INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (KEY, json.dumps(value)),
    )


def transition(store, allowed: tuple[str | None, ...], value: dict) -> bool:
    """Replace the update state only if its current state is one of ``allowed``, atomically."""
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT value FROM settings WHERE key=?", (KEY,)).fetchone()
        current = json.loads(row[0]).get("state") if row else None
        if current not in allowed:
            return False
        db.execute(
            "INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (KEY, json.dumps(value)),
        )
        return True


def admits_runs(settings: dict, update: dict) -> bool:
    """New runs start only while the queue is not paused and no update is pending or running."""
    return not settings["paused"] and update.get("state") not in ACTIVE


def deployment(inspect: dict) -> tuple[dict | None, str]:
    """The Compose deployment a worker container belongs to, from its ``docker inspect`` record.

    Returns the deployment, or None and the reason self-update is not available.
    """
    if os.environ.get("LOCALCI_SELF_UPDATE", "").strip().lower() in {"0", "false", "no", "off"}:
        return None, "Self-update is turned off by LOCALCI_SELF_UPDATE."
    labels = inspect.get("Config", {}).get("Labels") or {}
    project = labels.get("com.docker.compose.project", "")
    directory = labels.get("com.docker.compose.project.working_dir", "")
    files = [f for f in labels.get("com.docker.compose.project.config_files", "").split(",") if f]
    if not (project and directory and files):
        return None, "Self-update needs my-ci to run under Docker Compose from a git checkout."
    if not posixpath.isabs(directory) or any(
        not posixpath.isabs(f) or posixpath.commonpath([directory, f]) != directory for f in files
    ):
        return None, "Self-update needs every Compose file inside the project directory."
    socket = next(
        (m["Source"] for m in inspect.get("Mounts", []) if m.get("Destination") == SOCKET),
        "",
    )
    if not socket:
        return None, "The execution worker has no Docker socket mount."
    return {
        "project": project,
        "directory": directory,
        "files": files,
        "image": inspect.get("Image", ""),
        "socket": socket,
    }, ""


def helper_command(target: dict, name: str, branch: str, running: str) -> list[str]:
    compose = shlex.join(
        [
            "docker",
            "compose",
            "--project-name",
            target["project"],
            "--project-directory",
            target["directory"],
            *[arg for f in target["files"] for arg in ("-f", f)],
        ]
    )
    return [
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "--label",
        f"{HELPER_LABEL}=true",
        "--network",
        "host",
        "-v",
        f"{target['socket']}:{SOCKET}",
        "-v",
        f"{target['directory']}:{target['directory']}",
        "-w",
        target["directory"],
        "-e",
        f"LOCALCI_CHECKOUT={target['directory']}",
        "-e",
        f"LOCALCI_UPDATE_BRANCH={branch}",
        "-e",
        f"LOCALCI_RUNNING_VERSION={running}",
        "-e",
        f"LOCALCI_COMPOSE={compose}",
        "-e",
        f"LOCALCI_SERVICES={' '.join(SERVICES)}",
        "--entrypoint",
        "sh",
        target["image"],
        "-c",
        SCRIPT,
    ]


async def docker(*args: str) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        "docker", *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    output, _ = await proc.communicate()
    return proc.returncode or 0, output.decode(errors="replace")


async def detect() -> tuple[dict | None, str]:
    """This worker's own Compose deployment; the container's hostname is its short ID."""
    code, output = await docker("inspect", os.environ.get("HOSTNAME", ""))
    if code:
        return None, "The execution worker could not inspect its own container."
    try:
        return deployment(json.loads(output)[0])
    except (ValueError, IndexError, KeyError, TypeError):
        return None, "The execution worker could not read its own container record."


async def start(store, target: dict | None, reason: str):
    """Start the helper for a requested update; record why when it cannot start."""
    state = load(store)
    if state.get("state") != "requested":
        return
    if target is None:
        save(store, {**state, "state": "failed", "finished": time.time(), "error": reason})
        return
    _, branch = upstream()
    name = f"{target['project']}-update-{int(time.time())}"
    code, output = await docker(*helper_command(target, name, branch, version())[1:])
    if code:
        save(
            store, {**state, "state": "failed", "finished": time.time(), "error": output.strip()[-LOG_LIMIT:]}
        )
        return
    save(store, {**state, "state": "running", "started": time.time(), "helper": name, "from": version()})


async def reconcile(store):
    """Record the outcome of a helper that has exited, and remove it."""
    state = load(store)
    if state.get("state") != "running":
        return
    name = state.get("helper", "")
    code, output = await docker("inspect", "--format", "{{json .State}}", name)
    if code:
        save(
            store,
            {**state, "state": "failed", "finished": time.time(), "error": "The update helper disappeared."},
        )
        return
    status = json.loads(output)
    if status.get("Running"):
        if time.time() - state.get("started", time.time()) < HELPER_TIMEOUT:
            return
        await docker("kill", name)
        exit_code, timed_out = None, True
    else:
        exit_code, timed_out = status.get("ExitCode"), False
    _, log = await docker("logs", "--tail", "200", name)
    await docker("rm", "-f", name)
    log = log[-LOG_LIMIT:]
    result = {**state, "finished": time.time(), "log": log}
    for line in log.splitlines():
        if line.startswith("localci-update: "):
            parts = line.split()
            if len(parts) == 3:
                result["checkout_from"], result["to"] = parts[1], parts[2]
    if exit_code == 0:
        result["state"] = "succeeded"
    else:
        lines = [line for line in log.splitlines() if line.strip()]
        result["state"] = "failed"
        result["error"] = (
            "The update helper ran for more than an hour and was stopped."
            if timed_out
            else (lines[-1] if lines else f"The update helper exited with status {exit_code}.")
        )
    save(store, result)
