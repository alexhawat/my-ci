"""Shared read/write operations for the agent HTTP API and MCP tools."""

from __future__ import annotations

import json
import re
from typing import Any

from fastapi import HTTPException

from localci.dashboard import enrich_run
from localci.policy import eligible

FORBIDDEN_KEYS = frozenset(
    {
        "ciphertext",
        "private_key",
        "value",
        "token",
        "api_key",
        "secret",
        "password",
    }
)
FORBIDDEN_SUBSTRINGS = ("-----BEGIN", "app:private_key", "app:app_id")


class AgentService:
    def __init__(self, controller, scopes: frozenset[str]):
        self.controller = controller
        self.scopes = scopes

    def _need(self, scope: str) -> None:
        if scope not in self.scopes:
            raise HTTPException(403, f"Scope {scope!r} required")

    @staticmethod
    def public_view(data: Any) -> Any:
        """Return a JSON-safe structure with no secret material."""
        text = json.dumps(data, default=str)
        lowered = text.casefold()
        for bad in FORBIDDEN_SUBSTRINGS:
            if bad.casefold() in lowered:
                raise HTTPException(500, "Internal serialization guard")
        if re.search(r'"ciphertext"\s*:', text):
            raise HTTPException(500, "Internal serialization guard")
        return json.loads(text)

    def list_repos(self) -> list[dict]:
        self._need("read")
        result = []
        for repo in self.controller.store.rows("SELECT * FROM repos ORDER BY name"):
            config = json.loads(repo["config"])
            data = json.loads(repo["data"])
            result.append(
                {
                    "name": repo["name"],
                    "enabled": bool(repo["enabled"]),
                    "error": repo["error"],
                    "watch_only": bool(config.get("watch_only")),
                    "review": bool(config.get("review")),
                    "workflows": list(config.get("workflows", [])),
                    "private": data.get("private"),
                    "default_branch": data.get("default_branch"),
                    "url": data.get("html_url"),
                }
            )
        return self.public_view(result)

    def list_runs(
        self,
        *,
        repo: str | None = None,
        state: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        self._need("read")
        limit = max(1, min(limit, 200))
        sql = "SELECT * FROM runs"
        args: list = []
        clauses = []
        if repo:
            clauses.append("repo=?")
            args.append(repo)
        if state:
            clauses.append("state=?")
            args.append(state)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created DESC LIMIT ?"
        args.append(limit)
        runs = self.controller.store.rows(sql, tuple(args))
        return self.public_view([self._run_summary(enrich_run(r, self.controller.store)) for r in runs])

    def get_run(self, run_id: str) -> dict:
        self._need("read")
        rows = self.controller.store.rows("SELECT * FROM runs WHERE id=?", (run_id,))
        if not rows:
            raise HTTPException(404, "Unknown run")
        run = enrich_run(rows[0], self.controller.store)
        return self.public_view(self._run_detail(run))

    def get_review(self, run_id: str) -> dict:
        self._need("read")
        rows = self.controller.store.rows("SELECT * FROM runs WHERE id=?", (run_id,))
        if not rows:
            raise HTTPException(404, "Unknown run")
        reports = self.controller.reports(rows[0])
        review = reports.get("review", {"state": "unavailable"})
        return self.public_view({"run_id": run_id, "review": review})

    def logs_metadata(self, run_id: str) -> dict:
        self._need("read")
        rows = self.controller.store.rows("SELECT * FROM runs WHERE id=?", (run_id,))
        if not rows:
            raise HTTPException(404, "Unknown run")
        log_path = self.controller.root / "logs" / f"{run_id}.log"
        artifacts = self.controller.root / "artifacts" / run_id
        artifact_files = (
            [
                {"path": str(p.relative_to(artifacts)), "bytes": p.stat().st_size}
                for p in artifacts.rglob("*")
                if p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(artifacts.resolve())
            ]
            if artifacts.is_dir()
            else []
        )
        return self.public_view(
            {
                "run_id": run_id,
                "log_bytes": log_path.stat().st_size if log_path.is_file() else 0,
                "events_count": len(
                    self.controller.store.rows("SELECT 1 FROM run_events WHERE run_id=?", (run_id,))
                ),
                "artifacts": artifact_files[:100],
            }
        )

    def queue_status(self) -> dict:
        self._need("read")
        worker = self.controller.status()
        queued = self.controller.store.rows("SELECT COUNT(*) AS n FROM runs WHERE state='queued'")[0]["n"]
        running = self.controller.store.rows("SELECT COUNT(*) AS n FROM runs WHERE state='running'")[0]["n"]
        execution = self.controller.store.settings()
        return self.public_view(
            {
                "queued": queued,
                "running": running,
                "worker_online": worker.get("online", False),
                "paused": execution.get("paused", False),
                "capacity": worker.get("capacity"),
                "error": worker.get("error", ""),
            }
        )

    async def rerun(self, run_id: str) -> dict:
        self._need("write-runs")
        rows = self.controller.store.rows("SELECT * FROM runs WHERE id=?", (run_id,))
        if not rows:
            raise HTTPException(404, "Unknown run")
        run = rows[0]
        repo = self.controller.store.repo(run["repo"])
        if not repo["enabled"]:
            raise HTTPException(400, "Enable the repository before retrying")
        pr = await self.controller.github.request("GET", f"repos/{run['repo']}/pulls/{run['pr']}")
        if not eligible(pr, run["repo"]):
            raise HTTPException(400, "Only open, non-draft, same-repository PRs can run")
        import asyncio
        from functools import partial

        from localci.app import BOT_HOLD
        from localci.policy import bot_pr
        from localci.store import RetryLimitReached, RevisionChanged

        config = json.loads(self.controller.store.repo(run["repo"])["config"])
        try:
            new_id = await asyncio.to_thread(
                partial(
                    self.controller.store.enqueue,
                    run["repo"],
                    pr,
                    config,
                    retry=True,
                    require_enabled=True,
                    bot_hold=BOT_HOLD if bot_pr(pr) else None,
                    reviewed=(run["head"], run["base"]),
                )
            )
        except (RetryLimitReached, RevisionChanged) as exc:
            raise HTTPException(409, str(exc)) from None
        if new_id is None and not self.controller.store.repo(run["repo"])["enabled"]:
            raise HTTPException(400, "Enable the repository before retrying")
        self.controller.notify()
        return self.public_view({"id": new_id})

    def set_repo_review(
        self,
        name: str,
        *,
        enabled: bool | None = None,
        review: bool | None = None,
    ) -> dict:
        self._need("write-config")
        try:
            record = self.controller.store.repo(name)
        except KeyError:
            raise HTTPException(404, "Unknown repository") from None
        config = json.loads(record["config"])
        mergecraft = self.controller.store.integrations().get("mergecraft")
        if review is True and not mergecraft:
            raise HTTPException(400, "Add mergeCraft review in Settings before turning it on")
        if enabled is not None:
            config["enabled"] = enabled
        if review is not None:
            config["review"] = review
        if config.get("watch_only") and config.get("enabled"):
            raise HTTPException(400, "Cannot enable execution while watch-only is set")
        if config.get("enabled") and not config.get("workflows") and not config.get("review"):
            raise HTTPException(400, "Select at least one CI workflow or mergeCraft review")
        from localci.app import RepoConfig

        parsed = RepoConfig(**config)
        self.controller.store.execute(
            "UPDATE repos SET enabled=?,config=? WHERE name=?",
            (int(parsed.enabled), parsed.model_dump_json(), name),
        )
        if not parsed.enabled:
            for row in self.controller.store.rows(
                "SELECT id FROM runs WHERE repo=? AND state IN ('queued','running')", (name,)
            ):
                self.controller.store.request_cancel(row["id"], "repo_disabled", "Repository disabled")
        self.controller.notify()
        return self.public_view({"name": name, "enabled": parsed.enabled, "review": parsed.review})

    def _run_summary(self, run: dict) -> dict:
        return {
            "id": run["id"],
            "repo": run["repo"],
            "pr": run["pr"],
            "state": run["state"],
            "created": run["created"],
            "started": run.get("started"),
            "finished": run.get("finished"),
            "message": run.get("message"),
            "title": run.get("title"),
            "branch": run.get("branch"),
            "checks_summary": run.get("checks_summary"),
        }

    def _run_detail(self, run: dict) -> dict:
        detail = self._run_summary(run)
        detail.update(
            {
                "head": run["head"],
                "base": run["base"],
                "steps": run.get("steps", []),
                "workflow_sources": run.get("workflow_sources", []),
                "retries_remaining": run.get("retries_remaining"),
                "usage": run.get("usage"),
            }
        )
        return detail