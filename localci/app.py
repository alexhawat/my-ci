import asyncio
import json
import os
import re
import shutil
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from localci.controller import Controller
from localci.dashboard import enrich_run, register_dashboard
from localci.github import app_jwt
from localci.policy import eligible, is_pr_workflow, workflow
from localci.store import RetryLimitReached

ROOT = Path(os.environ.get("LOCALCI_DATA", "/data"))


class RepoConfig(BaseModel):
    enabled: bool = False
    workflows: list[str] = Field(default_factory=list, max_length=30)
    review: bool = False
    review_failure_threshold: Literal["major", "minor", "trivial"] = "major"
    github_auth: Literal["none", "gh"] = "none"
    job_parallelism: int = Field(default=1, ge=1, le=8)
    variables: dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(default=7200, ge=60, le=14400)
    review_timeout: int = Field(default=3000, ge=60, le=3000)
    # Bot-authored PRs carry third-party content; they wait for an operator unless enabled.
    run_bot_prs: bool = False

    @field_validator("workflows")
    @classmethod
    def paths(cls, values):
        if any(not re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", v) for v in values):
            raise ValueError("Expected .github/workflows/name.yml")
        if len(set(values)) != len(values):
            raise ValueError("Duplicate workflow path")
        return values

    @field_validator("variables")
    @classmethod
    def vars(cls, values):
        if any(
            not re.fullmatch(r"[A-Z][A-Z0-9_]{0,100}", k) or "\n" in v or "\r" in v for k, v in values.items()
        ):
            raise ValueError("Variables require uppercase identifiers and single-line values")
        return values


class SecretInput(BaseModel):
    name: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,100}$")
    value: str = Field(min_length=1, max_length=20000)
    scope: Literal["ci", "review"] = "review"

    @field_validator("value")
    @classmethod
    def single_line(cls, value):
        if "\n" in value or "\r" in value:
            raise ValueError("Use a single-line value; JSON credentials must be compact JSON")
        return value


class AppInput(BaseModel):
    app_id: str = Field(pattern=r"^[0-9]{1,20}$")
    private_key: str = Field(min_length=100, max_length=20000)


def create_app(root: Path = ROOT, *, background: bool = False) -> FastAPI:
    if background:
        raise ValueError("Execution is a separate service; run python -m localci.worker")
    controller = Controller(root)

    @asynccontextmanager
    async def lifespan(app):
        # The web process never starts, recovers, cancels, or publishes execution tasks.
        yield
        await asyncio.to_thread(controller.store.close)

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.controller = controller

    @app.middleware("http")
    async def access(request: Request, call_next):
        expected = os.environ.get("LOCALCI_TAILSCALE_LOGIN", "")
        if request.url.path != "/healthz":
            if (
                not expected
                or request.headers.get("tailscale-user-login", "").casefold() != expected.casefold()
            ):
                return JSONResponse(
                    {"detail": "Open this dashboard through its private Tailscale HTTPS URL"}, status_code=403
                )
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                if request.headers.get("origin", "").rstrip("/") != controller.base_url:
                    return JSONResponse({"detail": "Invalid request origin"}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    @app.get("/healthz")
    async def health():
        return {"ok": True}

    @app.get("/api/state")
    def state():
        # Fetch shared dashboard metadata once instead of reopening SQLite for every repo.
        secret_labels = {}
        for row in controller.store.rows("SELECT repo,name FROM secrets"):
            secret_labels.setdefault(row["repo"], []).append(row["name"])
        pr_data = {}
        for row in controller.store.rows("SELECT repo,data FROM prs"):
            pr_data.setdefault(row["repo"], []).append(json.loads(row["data"]))
        repos = []
        for repo in controller.store.rows("SELECT * FROM repos ORDER BY enabled DESC,name COLLATE NOCASE"):
            data = json.loads(repo.pop("data"))
            repo.update(
                private=data["private"],
                description=data.get("description"),
                url=data["html_url"],
                config=json.loads(repo["config"]),
                default_branch=data["default_branch"],
            )
            repo["secrets"] = secret_labels.get(repo["name"], [])
            repo["prs"] = [
                {
                    "number": p["number"],
                    "title": p["title"],
                    "head": p["head"]["sha"],
                    "draft": p["draft"],
                    "eligible": eligible(p, repo["name"]),
                }
                for p in pr_data.get(repo["name"], [])
            ]
            repos.append(repo)
        runs = controller.store.rows("SELECT * FROM runs ORDER BY created DESC LIMIT 100")
        runs = [enrich_run(run, controller.store) for run in runs]
        # Deduplicate before limiting so a busy PR cannot hide other PRs' latest runs.
        latest = controller.store.rows("""SELECT r.* FROM runs r JOIN (
            SELECT id, ROW_NUMBER() OVER (
                PARTITION BY repo,pr ORDER BY created DESC,rowid DESC
            ) AS position FROM runs
        ) ranked ON ranked.id=r.id WHERE ranked.position=1
        ORDER BY r.created DESC,r.rowid DESC LIMIT 100""")
        recent = {run["id"]: run for run in runs}
        latest = [
            recent[run["id"]] if run["id"] in recent else enrich_run(run, controller.store) for run in latest
        ]
        disk = shutil.disk_usage(controller.root)
        worker = controller.status()
        return {
            "login": worker["login"],
            "repos": repos,
            "runs": runs,
            "latest_runs": latest,
            "error": worker["error"],
            "last_poll": worker["last_poll"],
            "disk_free": disk.free,
            "poll_seconds": 60,
            "github_app": bool(controller.secrets("__github_app__", "app")),
            "host": controller.host_label,
            "retention_days": 14,
            "execution": controller.store.settings(),
            "capacity": worker["capacity"],
            "worker": worker,
        }

    def repo_name(owner: str, repo: str):
        name = f"{owner}/{repo}"
        try:
            controller.store.repo(name)
        except KeyError:
            raise HTTPException(404, "Unknown repository") from None
        return name

    @app.get("/api/repos/{owner}/{repo}/workflows")
    async def workflows(owner: str, repo: str):
        name = repo_name(owner, repo)
        data = json.loads(controller.store.repo(name)["data"])
        try:
            entries = await controller.github.request(
                "GET", f"repos/{name}/contents/.github/workflows", params={"ref": data["default_branch"]}
            )
        except RuntimeError as exc:
            if "HTTP 404" in str(exc):
                return []
            raise HTTPException(502, str(exc)) from None
        result = []
        for entry in entries:
            if entry["type"] != "file" or not entry["name"].endswith((".yml", ".yaml")):
                continue
            upstream = await controller.github.content(name, entry["path"], data["default_branch"])
            overrides = controller.store.rows(
                "SELECT version,content FROM workflow_versions WHERE repo=? AND path=? AND active=1",
                (name, entry["path"]),
            )
            text = overrides[0]["content"] if overrides else upstream
            try:
                parsed = workflow(text)
                review = "mergecraft" in text.lower()
                result.append(
                    {
                        "path": entry["path"],
                        "name": parsed.get("name", entry["name"]),
                        "pr": is_pr_workflow(parsed),
                        "review": review,
                        "local_version": overrides[0]["version"] if overrides else None,
                        "variables": sorted(set(re.findall(r"vars\.([A-Za-z_][A-Za-z0-9_]*)", text))),
                        "secrets": sorted(
                            set(re.findall(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)", text))
                            - {"GITHUB_TOKEN", "GH_TOKEN"}
                        ),
                        "jobs": list(parsed.get("jobs", {})),
                    }
                )
            except RuntimeError:
                result.append({"path": entry["path"], "name": entry["name"], "pr": False, "review": False})
        return result

    @app.put("/api/repos/{owner}/{repo}")
    def configure(owner: str, repo: str, config: RepoConfig):
        name = repo_name(owner, repo)
        if config.enabled and not config.workflows and not config.review:
            raise HTTPException(400, "Select at least one CI workflow or mergeCraft review")
        controller.store.execute(
            "UPDATE repos SET enabled=?,config=? WHERE name=?",
            (int(config.enabled), config.model_dump_json(), name),
        )
        if not config.enabled:
            for row in controller.store.rows(
                "SELECT id FROM runs WHERE repo=? AND state IN ('queued','running')", (name,)
            ):
                controller.store.request_cancel(row["id"], "repo_disabled", "Repository disabled")
        controller.notify()
        return {"ok": True}

    @app.put("/api/repos/{owner}/{repo}/secrets")
    def secret(owner: str, repo: str, value: SecretInput):
        name = repo_name(owner, repo)
        if value.name in {"GITHUB_TOKEN", "GH_TOKEN"}:
            raise HTTPException(
                400, "Use the repository GitHub authentication selector to reuse the host gh login"
            )
        ciphertext = controller.cipher.encrypt(value.value.encode()).decode()
        controller.store.execute(
            "INSERT INTO secrets VALUES(?,?,?) ON CONFLICT(repo,name) DO UPDATE SET ciphertext=excluded.ciphertext",
            (name, f"{value.scope}:{value.name}", ciphertext),
        )
        return {"ok": True}

    @app.delete("/api/repos/{owner}/{repo}/secrets/{scope}/{name}")
    def delete_secret(owner: str, repo: str, scope: str, name: str):
        controller.store.execute(
            "DELETE FROM secrets WHERE repo=? AND name=?", (repo_name(owner, repo), f"{scope}:{name}")
        )
        return {"ok": True}

    @app.post("/api/sync")
    async def sync():
        controller.notify(discover=True)
        return {"ok": True}

    @app.put("/api/github-app")
    async def github_app(value: AppInput):
        try:
            credential = app_jwt(value.app_id, value.private_key)
            info = await controller.github.request("GET", "app", credential=credential)
            if str(info["id"]) != value.app_id:
                raise ValueError("App ID does not match this private key")
        except (ValueError, RuntimeError):
            raise HTTPException(400, "GitHub could not validate that App ID and private key") from None
        with controller.store.connect() as db:
            for name, text in value.model_dump().items():
                db.execute(
                    "INSERT INTO secrets VALUES(?,?,?) ON CONFLICT(repo,name) DO UPDATE SET ciphertext=excluded.ciphertext",
                    ("__github_app__", f"app:{name}", controller.cipher.encrypt(text.encode()).decode()),
                )
        return {"ok": True, "name": info["name"]}

    def get_run(rid: str):
        if not re.fullmatch("[0-9a-f]{32}", rid):
            raise HTTPException(404)
        rows = controller.store.rows("SELECT * FROM runs WHERE id=?", (rid,))
        if not rows:
            raise HTTPException(404)
        return rows[0]

    @app.get("/api/runs/{rid}/log")
    def log(rid: str):
        get_run(rid)
        path = root / "logs" / f"{rid}.log"
        return PlainTextResponse(
            path.read_text(errors="replace")[-200_000:] if path.exists() else "Waiting for worker…"
        )

    @app.get("/api/runs/{rid}/artifacts")
    def artifacts(rid: str):
        get_run(rid)
        directory = root / "artifacts" / rid
        return [
            {"path": str(p.relative_to(directory)), "bytes": p.stat().st_size}
            for p in directory.rglob("*")
            if p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(directory.resolve())
        ][:500]

    @app.get("/api/runs/{rid}/artifact")
    def artifact(rid: str, path: str):
        get_run(rid)
        directory = (root / "artifacts" / rid).resolve()
        target = (directory / path).resolve()
        if not target.is_relative_to(directory) or not target.is_file():
            raise HTTPException(404)
        return FileResponse(target, filename=target.name, media_type="application/octet-stream")

    @app.post("/api/runs/{rid}/cancel")
    def cancel(rid: str):
        get_run(rid)
        # An operator's cancel is final for this revision until the operator retries it.
        controller.store.request_cancel(rid, "operator", "Cancelled by operator")
        controller.notify()
        return {"ok": True}

    @app.post("/api/runs/{rid}/retry")
    async def retry(rid: str):
        run = get_run(rid)
        repo = controller.store.repo(run["repo"])
        if not repo["enabled"]:
            raise HTTPException(400, "Enable the repository before retrying")
        pr = await controller.github.request("GET", f"repos/{run['repo']}/pulls/{run['pr']}")
        if not eligible(pr, run["repo"]):
            raise HTTPException(400, "Only open, non-draft, same-repository PRs can run")
        try:
            new_id = await asyncio.to_thread(
                controller.store.enqueue, run["repo"], pr, json.loads(repo["config"]), retry=True
            )
        except RetryLimitReached as exc:
            raise HTTPException(409, str(exc)) from None
        controller.notify()
        return {"id": new_id}

    register_dashboard(app, controller, repo_name, get_run)

    static = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/")
    def index():
        return FileResponse(static / "index.html")

    return app
