"""Dashboard settings, local workflow revisions, run evidence, and usage APIs."""

import asyncio
import json
import re
import time
from datetime import datetime
from typing import Literal

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field

from localci import updater
from localci.github import GitHubError
from localci.policy import is_pr_workflow, workflow
from localci.results import check_summary

WORKFLOW_PATH = r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$"


class ExecutionSettings(BaseModel):
    max_parallel_runs: int = Field(default=1, ge=1, le=8)
    cpus_per_run: int = Field(default=8, ge=1, le=24)
    memory_gb_per_run: int = Field(default=24, ge=2, le=96)
    paused: bool = False
    max_retries: int = Field(default=2, ge=0, le=5)


class WorkflowEdit(BaseModel):
    path: str = Field(pattern=WORKFLOW_PATH)
    content: str = Field(min_length=1, max_length=200000)
    source_ref: str = Field(max_length=200)
    expected_version: int = Field(default=0, ge=0)


class MergeRequest(BaseModel):
    # The head commit the operator was shown; GitHub refuses the merge if it has changed.
    sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    method: Literal["merge", "squash", "rebase"]


CHECK_CONCLUSIONS = {
    "SUCCESS": "success",
    "FAILURE": "failure",
    "TIMED_OUT": "failure",
    "STARTUP_FAILURE": "failure",
    "CANCELLED": "cancelled",
    "ACTION_REQUIRED": "blocked",
}
STATUS_STATES = {"SUCCESS": "success", "FAILURE": "failure", "ERROR": "failure"}
CHECK_ORDER = ["failure", "running", "queued", "blocked", "cancelled", "success", "skipped"]
CHECK_LABELS = {"success": "passed", "failure": "failed"}


def github_checks(node: dict) -> dict:
    """Summarize GitHub's checks for one PR head, leaving out the ``local-ci`` result
    this service publishes itself (the Local CI column already shows it)."""
    commits = (node.get("commits") or {}).get("nodes") or []
    rollup = ((commits[0] or {}).get("commit") or {}).get("statusCheckRollup") if commits else None
    contexts = (rollup or {}).get("contexts") or {}
    checks = []
    for item in contexts.get("nodes") or []:
        if not item:
            continue
        if item.get("__typename") == "CheckRun":
            name, url = item.get("name") or "", item.get("detailsUrl") or ""
            workflow_run = (item.get("checkSuite") or {}).get("workflowRun") or {}
            workflow_name = (workflow_run.get("workflow") or {}).get("name")
            if item.get("status") == "COMPLETED":
                state = CHECK_CONCLUSIONS.get(item.get("conclusion") or "", "skipped")
            else:
                state = "running" if item.get("status") == "IN_PROGRESS" else "queued"
            label = f"{workflow_name} / {name}" if workflow_name else name
        else:
            name, url = item.get("context") or "", item.get("targetUrl") or ""
            state, label = STATUS_STATES.get(item.get("state") or "", "running"), name
        if name == "local-ci":
            continue
        checks.append({"name": label, "state": state, "url": url if url.startswith("https://") else ""})
    counts = {state: sum(c["state"] == state for c in checks) for state in CHECK_ORDER}
    checks.sort(key=lambda c: (CHECK_ORDER.index(c["state"]), c["name"].casefold()))
    return {
        "head": node.get("headRefOid", ""),
        "state": next((s for s in CHECK_ORDER if counts[s]), "none"),
        "summary": " · ".join(f"{counts[s]} {CHECK_LABELS.get(s, s)}" for s in CHECK_ORDER if counts[s]),
        "checks": checks,
        # More than one page of checks: the counts cover only the first 100.
        "truncated": (contexts.get("totalCount") or 0) > len(contexts.get("nodes") or []),
        "mergeable": node.get("mergeable") or "UNKNOWN",
        "merge_state": node.get("mergeStateStatus") or "UNKNOWN",
        "review_decision": node.get("reviewDecision") or "",
    }


def enrich_run(run: dict, store) -> dict:
    result = {**run}
    snapshot = json.loads(result.pop("snapshot", "{}"))
    config = json.loads(result.pop("config", "{}"))
    result["steps"] = json.loads(result["steps"]) if isinstance(result["steps"], str) else result["steps"]
    result.update(
        checks_summary=check_summary(result["steps"]),
        github_auth=config.get("github_auth", "none"),
        title=snapshot.get("title", ""),
        branch=snapshot.get("head", {}).get("ref", ""),
        actor=snapshot.get("user", {}).get("login", ""),
        event="pull_request",
        workflow_sources=[
            {
                "path": p,
                "version": config.get("workflow_overrides", {}).get(p, {}).get("version"),
                "source_ref": config.get("workflow_overrides", {})
                .get(p, {})
                .get("source_ref", result["base"]),
            }
            for p in config.get("workflows", [])
        ],
        job_parallelism=config.get("job_parallelism", 1),
        review_timeout=config.get("review_timeout", 3000),
        review_failure_threshold=config.get("review_failure_threshold"),
        execution=config.get("execution", {}),
    )
    rows = store.rows("SELECT * FROM run_usage WHERE run_id=?", (run["id"],))
    result["usage"] = rows[0] if rows else None
    attempts = store.rows(
        "SELECT attempts AS total FROM revision_attempts WHERE repo=? AND pr=? AND head=? AND base=?",
        (run["repo"], run["pr"], run["head"], run["base"]),
    )[0]["total"]
    result["max_attempts"] = store.settings()["max_retries"] + 1
    result["retries_remaining"] = max(0, result["max_attempts"] - attempts)
    result["retry_limit_reached"] = result["retries_remaining"] == 0
    reporting = store.rows("SELECT value FROM settings WHERE key=?", (f"reporting:{run['repo']}",))
    result["reporting"] = json.loads(reporting[0]["value"]) if reporting else "Not published yet"
    return result


def register_dashboard(app, controller, repo_name, get_run):
    store = controller.store

    @app.get("/api/runs/{rid}/reports")
    def run_reports(rid: str):
        return controller.reports(get_run(rid))

    # Per repository: time of the last attempt, PRs, error of that attempt, time of the
    # last successful fetch.
    closed_cache: dict[str, tuple[float, list, str, float]] = {}
    closed_fetches: dict[str, asyncio.Task] = {}

    async def fetch_closed(name: str):
        previous = closed_cache.get(name)
        try:
            prs = await controller.github.pages(
                f"repos/{name}/pulls?state=closed&sort=updated&direction=desc",
                max_pages=2,
                truncate=True,  # Display only: the 200 most recently updated.
            )
        except (RuntimeError, httpx.HTTPError) as exc:
            # Keep what was shown before, and the time it was actually fetched.
            closed_cache[name] = (
                time.time(),
                previous[1] if previous else [],
                str(exc),
                previous[3] if previous else 0.0,
            )
        else:
            closed_cache[name] = (time.time(), prs, "", time.time())
        return closed_cache[name]

    async def closed_prs(name: str):
        cached = closed_cache.get(name)
        if cached and time.time() - cached[0] < 60:
            return cached
        # One request per repository at a time: simultaneous dashboard requests that find
        # the cache stale share it instead of each calling GitHub.
        task = closed_fetches.get(name)
        if task is None or task.done():
            task = closed_fetches[name] = asyncio.create_task(fetch_closed(name))
        return await asyncio.shield(task)

    # GitHub's own checks and mergeability per repository: time fetched, data, error.
    # Display only, like closed PRs; the executor never reads it.
    remote_cache: dict[str, tuple[float, dict, str]] = {}
    remote_fetches: dict[str, asyncio.Task] = {}

    async def fetch_remote(name: str):
        try:
            data = await controller.github.pull_request_checks(name)
        except (RuntimeError, httpx.HTTPError, OSError) as exc:
            previous = remote_cache.get(name)
            # A failed refresh must not leave stale checks looking current, or a merge
            # button enabled on them.
            remote_cache[name] = (
                time.time(),
                {"merge_methods": previous[1]["merge_methods"] if previous else [], "prs": {}},
                str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__,
            )
        else:
            remote_cache[name] = (time.time(), data, "")
        return remote_cache[name]

    async def remote_prs(name: str):
        cached = remote_cache.get(name)
        if cached and time.time() - cached[0] < 20:
            return cached
        task = remote_fetches.get(name)
        if task is None or task.done():
            task = remote_fetches[name] = asyncio.create_task(fetch_remote(name))
        return await asyncio.shield(task)

    @app.get("/api/prs")
    async def pull_requests(state: Literal["open", "closed"] = "open"):
        errors = []
        synced = controller.status()["last_poll"]
        if state == "open":
            rows = await asyncio.to_thread(
                store.rows,
                """SELECT p.repo,p.number,p.data,r.error FROM prs p
                JOIN repos r ON r.name=p.repo WHERE r.enabled=1""",
            )
            errors = await asyncio.to_thread(
                store.rows, "SELECT name,error FROM repos WHERE enabled=1 AND error!=''"
            )
        else:
            rows = []
            synced = time.time()
            # Display-only cache: never replace the executor's open-PR snapshot
            # or enqueue work while browsing closed/merged pull requests.
            names = [
                repo["name"]
                for repo in await asyncio.to_thread(store.rows, "SELECT name FROM repos WHERE enabled=1")
            ]
            for name, cached in zip(names, await asyncio.gather(*map(closed_prs, names)), strict=True):
                # The oldest successful fetch, so a failed refresh does not look current.
                synced = min(synced, cached[3])
                if cached[2]:
                    errors.append({"name": name, "error": cached[2]})
                rows.extend(
                    {"repo": name, "number": pr["number"], "data": json.dumps(pr), "error": ""}
                    for pr in cached[1]
                )
        remote, github_errors = {}, []
        if state == "open":
            names = sorted({row["repo"] for row in rows})
            for name, cached in zip(names, await asyncio.gather(*map(remote_prs, names)), strict=True):
                remote[name] = cached[1]
                if cached[2]:
                    github_errors.append({"name": name, "error": cached[2]})
        latest_rows = await asyncio.to_thread(
            store.rows,
            """SELECT r.repo,r.pr,r.id,r.state,r.head,r.base,r.steps,r.created
            FROM runs r JOIN (SELECT id, ROW_NUMBER() OVER (
                PARTITION BY repo,pr ORDER BY created DESC,rowid DESC) AS position FROM runs
            ) ranked ON ranked.id=r.id WHERE ranked.position=1""",
        )
        latest_by_pr = {(r["repo"], r["pr"]): r for r in latest_rows}
        items = []
        for row in rows:
            pr = json.loads(row["data"])
            if pr.get("state") != state:
                continue
            latest = latest_by_pr.get((row["repo"], row["number"]))
            latest = dict(latest) if latest else None
            if latest:
                latest["current"] = (latest["head"], latest["base"]) == (pr["head"]["sha"], pr["base"]["sha"])
                latest["checks_summary"] = check_summary(json.loads(latest.pop("steps")))
            draft = bool(pr.get("draft"))
            node = remote.get(row["repo"], {}).get("prs", {}).get(row["number"])
            github = github_checks(node) if node else None
            if github:
                # The local snapshot can trail GitHub by one poll.
                github["current"] = github["head"] == pr["head"]["sha"]
            fork = (pr["head"].get("repo") or {}).get("full_name") != row["repo"]
            items.append(
                {
                    "repo": row["repo"],
                    "number": row["number"],
                    "title": pr.get("title", ""),
                    "url": f"https://github.com/{row['repo']}/pull/{row['number']}",
                    "author": (pr.get("user") or {}).get("login", ""),
                    "branch": pr["head"].get("ref", ""),
                    "base_branch": pr["base"].get("ref", ""),
                    "head": pr["head"]["sha"],
                    "state": state,
                    "merged": bool(pr.get("merged_at")),
                    "closed": pr.get("closed_at"),
                    "draft": draft,
                    "fork": fork,
                    "created": pr.get("created_at"),
                    "updated": pr.get("updated_at"),
                    "ci_eligibility": "Closed — not scheduled"
                    if state == "closed"
                    else "Draft — not scheduled"
                    if draft
                    else "Fork — not scheduled"
                    if fork
                    else "Automatic CI",
                    "latest_run": latest,
                    "github": github,
                    "merge_methods": remote.get(row["repo"], {}).get("merge_methods", []),
                    "sync_error": row["error"],
                }
            )
        items.sort(key=lambda p: (p["updated"] or "", p["repo"], p["number"]), reverse=True)
        return {
            "prs": items,
            "last_poll": synced,
            "state": state,
            "errors": errors,
            "github_errors": github_errors,
        }

    @app.post("/api/repos/{owner}/{repo}/prs/{number}/merge")
    async def merge_pr(owner: str, repo: str, number: int, body: MergeRequest):
        name = repo_name(owner, repo)
        if not store.repo(name)["enabled"]:
            raise HTTPException(400, "Enable the repository before merging its pull requests")
        try:
            result = await controller.github.merge(name, number, body.sha, body.method)
        except GitHubError as exc:
            # GitHub decides: branch protection, required checks and reviews all apply.
            detail = {
                403: "GitHub refused: the worker's GitHub login may not merge this pull request",
                404: "GitHub could not find this pull request, or the login cannot access it",
                405: "GitHub refused: the pull request is not mergeable (conflicts, required "
                "checks or reviews, a draft, or a merge method the repository does not allow)",
                409: "The pull request head changed since this page loaded; review it and try again",
                422: "GitHub rejected the merge request for this pull request",
            }.get(exc.status, str(exc))
            raise HTTPException(409 if exc.status in (405, 409, 422) else 502, detail) from None
        except (RuntimeError, httpx.HTTPError, OSError) as exc:
            # The outcome is unknown; the operator must check before trying again.
            raise HTTPException(
                502, f"GitHub did not confirm the merge ({type(exc).__name__}); check the pull request"
            ) from None
        if not (result or {}).get("merged"):
            raise HTTPException(502, "GitHub did not confirm the merge; check the pull request")
        # Show the result now; the executor's next poll replaces the snapshot and cancels
        # any run still active for the merged PR.
        await asyncio.to_thread(store.execute, "DELETE FROM prs WHERE repo=? AND number=?", (name, number))
        remote_cache.pop(name, None)
        closed_cache.pop(name, None)
        controller.notify()
        return {"merged": True, "sha": result.get("sha", "")}

    @app.get("/api/execution")
    def execution():
        capacity = controller.status()["capacity"]
        return {"settings": store.settings(capacity), "capacity": capacity}

    @app.put("/api/execution")
    def save_execution(value: ExecutionSettings):
        capacity = controller.status()["capacity"]
        if not capacity:
            raise HTTPException(503, "Host capacity is not available yet")
        if value.max_parallel_runs * value.cpus_per_run > max(1, capacity["cpus"] - 2):
            raise HTTPException(
                400, "Combined CPU limits must leave 2 host CPUs free. Reduce runs or CPUs per run."
            )
        if value.max_parallel_runs * value.memory_gb_per_run > max(2, capacity["memory_gb"] - 4):
            raise HTTPException(400, "Combined memory limits must leave host memory free where possible.")
        store.save_settings(value.model_dump())
        return execution()

    latest: dict = {}

    async def latest_commit() -> dict:
        """The upstream branch head, cached for five minutes; errors are cached for one."""
        if latest and time.time() - latest["fetched"] < (300 if latest.get("sha") else 60):
            return latest
        repo, branch = updater.upstream()
        try:
            data = await controller.github.request("GET", f"repos/{repo}/commits/{branch}")
            commit = data["commit"]
            when = datetime.fromisoformat(commit["committer"]["date"].replace("Z", "+00:00"))
            value = {
                "sha": data["sha"],
                "message": commit["message"].splitlines()[0][:200] if commit["message"] else "",
                "date": when.timestamp(),
                "url": data.get("html_url", f"https://github.com/{repo}/commit/{data['sha']}"),
            }
        except (RuntimeError, httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            value = {"error": f"Could not read {repo}@{branch} from GitHub: {exc}"}
        latest.clear()
        latest.update(value, repo=repo, branch=branch, fetched=time.time())
        return latest

    def update_status() -> dict:
        worker = controller.status()
        running = store.rows("SELECT COUNT(*) AS n FROM runs WHERE state='running'")[0]["n"]
        unavailable = worker.get("update_unavailable", "The execution worker does not support updates yet.")
        if not worker["online"]:
            unavailable = "The execution worker is offline."
        return {
            "current": worker.get("version") or updater.version(),
            "update": updater.load(store),
            "unavailable": unavailable,
            "active_runs": running,
        }

    @app.get("/api/update")
    async def get_update():
        status = await asyncio.to_thread(update_status)
        return {**status, "latest": {k: v for k, v in (await latest_commit()).items() if k != "fetched"}}

    @app.post("/api/update")
    def request_update(request: Request):
        status = update_status()
        if status["unavailable"]:
            raise HTTPException(400, status["unavailable"])
        value = {
            "state": "requested",
            "requested": time.time(),
            "requested_by": request.headers.get("tailscale-user-login", ""),
            "from": status["current"],
        }
        if not updater.transition(store, (None, "succeeded", "failed", "cancelled"), value):
            raise HTTPException(409, "An update is already pending or running")
        controller.notify()
        return update_status()

    @app.delete("/api/update")
    def cancel_update():
        state = updater.load(store)
        if not updater.transition(
            store, ("requested",), {**state, "state": "cancelled", "finished": time.time()}
        ):
            raise HTTPException(409, "Only an update that has not started can be cancelled")
        controller.notify()
        return update_status()

    @app.get("/api/repos/{owner}/{repo}/workflow")
    async def get_workflow(owner: str, repo: str, path: str, version: int | None = None):
        name = repo_name(owner, repo)
        if not re.fullmatch(WORKFLOW_PATH, path):
            raise HTTPException(400, "Expected .github/workflows/name.yml")
        versions = store.rows(
            "SELECT version,source_ref,created,active FROM workflow_versions WHERE repo=? AND path=? ORDER BY version DESC",
            (name, path),
        )
        if version is not None:
            rows = store.rows(
                "SELECT * FROM workflow_versions WHERE repo=? AND path=? AND version=?", (name, path, version)
            )
            if not rows:
                raise HTTPException(404, "Unknown local workflow version")
            return {**rows[0], "versions": versions}
        active = store.rows(
            "SELECT * FROM workflow_versions WHERE repo=? AND path=? AND active=1", (name, path)
        )
        if active:
            return {**active[0], "versions": versions}
        data = json.loads(store.repo(name)["data"])
        commit = await controller.github.request("GET", f"repos/{name}/commits/{data['default_branch']}")
        content = await controller.github.content(name, path, commit["sha"])
        return {
            "path": path,
            "content": content,
            "source_ref": commit["sha"],
            "version": 0,
            "versions": versions,
        }

    @app.put("/api/repos/{owner}/{repo}/workflow")
    def save_workflow(owner: str, repo: str, value: WorkflowEdit):
        name = repo_name(owner, repo)
        try:
            data = workflow(value.content)
            if not is_pr_workflow(data):
                raise ValueError("Keep the pull_request trigger for local CI")
        except Exception as exc:
            raise HTTPException(400, f"Invalid workflow: {exc}") from None
        # Serialize optimistic version check and write in the same DB transaction.
        with store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute(
                "SELECT version FROM workflow_versions WHERE repo=? AND path=? AND active=1",
                (name, value.path),
            ).fetchone()
            if (current[0] if current else 0) != value.expected_version:
                raise HTTPException(409, "This workflow changed in another window. Reopen it before saving.")
            version = db.execute(
                "SELECT COALESCE(MAX(version),0)+1 FROM workflow_versions WHERE repo=? AND path=?",
                (name, value.path),
            ).fetchone()[0]
            db.execute("UPDATE workflow_versions SET active=0 WHERE repo=? AND path=?", (name, value.path))
            db.execute(
                "INSERT INTO workflow_versions VALUES(?,?,?,?,?,?,1)",
                (name, value.path, version, value.content, value.source_ref, time.time()),
            )
        return {"version": version}

    @app.delete("/api/repos/{owner}/{repo}/workflow")
    def upstream_workflow(owner: str, repo: str, path: str):
        name = repo_name(owner, repo)
        store.execute("UPDATE workflow_versions SET active=0 WHERE repo=? AND path=?", (name, path))
        return {"ok": True}

    @app.get("/api/runs/{rid}")
    def run_detail(rid: str):
        return enrich_run(get_run(rid), store)

    @app.get("/api/runs/{rid}/events")
    def events(rid: str, level: Literal["all", "error"] = "all"):
        get_run(rid)
        rows = store.rows(
            "SELECT * FROM (SELECT id,timestamp,phase,job,level,message FROM run_events WHERE run_id=? AND (?='all' OR level=?) ORDER BY id DESC LIMIT 500) ORDER BY id",
            (rid, level, level),
        )
        return rows

    @app.get("/api/runs/{rid}/download-log")
    def download_log(rid: str):
        get_run(rid)
        path = controller.root / "logs" / f"{rid}.log"
        if not path.exists():
            return PlainTextResponse(
                "Waiting for worker…",
                headers={"Content-Disposition": f'attachment; filename="local-ci-{rid}.log"'},
            )
        return FileResponse(path, filename=f"local-ci-{rid}.log", media_type="text/plain")

    @app.get("/api/runs/{rid}/resources")
    def resources(rid: str):
        get_run(rid)
        return store.rows("SELECT * FROM resource_samples WHERE run_id=? ORDER BY timestamp", (rid,))

    @app.get("/api/analytics")
    def analytics(days: int = 30):
        if days not in {1, 7, 14, 30, 90}:
            raise HTTPException(400, "Choose 1, 7, 14, 30, or 90 days")
        cutoff = time.time() - days * 86400
        rows = store.rows(
            """SELECT u.*,r.started,r.finished,r.state AS current_state FROM run_usage u
                             LEFT JOIN runs r ON r.id=u.run_id WHERE u.created>=?""",
            (cutoff,),
        )
        by_repo = {}
        daily = {}
        totals = {
            "runs": 0,
            "minutes": 0.0,
            "cpu_minutes": 0.0,
            "peak_memory_bytes": 0,
            "measured_runs": 0,
            "success": 0,
            "failure": 0,
        }
        for row in rows:
            seconds = row["duration_seconds"]
            if row["current_state"] == "running" and row["started"]:
                seconds = time.time() - row["started"]
            values = {
                "runs": 1,
                "minutes": seconds / 60,
                "cpu_minutes": row["cpu_seconds"] / 60,
                "peak_memory_bytes": row["peak_memory_bytes"],
                "measured_runs": int(row["samples"] > 0),
                "success": int((row["current_state"] or row["state"]) == "success"),
                "failure": int((row["current_state"] or row["state"]) in {"failure", "error", "blocked"}),
            }
            day = time.strftime("%Y-%m-%d", time.gmtime(row["created"]))
            for target in (
                totals,
                by_repo.setdefault(row["repo"], dict.fromkeys(totals, 0)),
                daily.setdefault(day, dict.fromkeys(totals, 0)),
            ):
                for key, value in values.items():
                    target[key] = (
                        max(target[key], value) if key == "peak_memory_bytes" else target[key] + value
                    )
        return {
            "days": days,
            "totals": totals,
            "repositories": [{"repo": k, **v} for k, v in sorted(by_repo.items())],
            "daily": [{"day": k, **v} for k, v in sorted(daily.items())],
            "measurement": "CPU time is estimated from Docker samples about every 5 seconds. Peak memory is sampled outer-container usage, including nested CI jobs. Short spikes and controller work are not included. Historical runs before this update have no resource measurements. Daily buckets use UTC.",
        }
