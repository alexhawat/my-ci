"""Shared enqueue/retry and repository config updates for dashboard and agent APIs."""

from __future__ import annotations

import asyncio
import json
from functools import partial

from fastapi import HTTPException

from localci.policy import BOT_HOLD, bot_pr, eligible
from localci.store import RetryLimitReached, RevisionChanged


async def retry_pull_request_run(controller, run_id: str) -> str:
    rows = controller.store.rows("SELECT * FROM runs WHERE id=?", (run_id,))
    if not rows:
        raise HTTPException(404, "Unknown run")
    run = rows[0]
    if not controller.store.repo(run["repo"])["enabled"]:
        raise HTTPException(400, "Enable the repository before retrying")
    pr = await controller.github.request("GET", f"repos/{run['repo']}/pulls/{run['pr']}")
    if not eligible(pr, run["repo"]):
        raise HTTPException(400, "Only open, non-draft, same-repository PRs can run")
    config = json.loads(controller.store.repo(run["repo"])["config"])
    try:
        new_id = await asyncio.to_thread(
            partial(
                controller.store.enqueue,
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
    if new_id is None:
        if not controller.store.repo(run["repo"])["enabled"]:
            raise HTTPException(400, "Enable the repository before retrying")
        raise HTTPException(409, "Could not queue retry")
    controller.notify()
    return new_id


def persist_repo_config(controller, name: str, config) -> None:
    from localci.app import RepoConfig

    if not isinstance(config, RepoConfig):
        config = RepoConfig(**config)
    controller.store.keep_integrations()
    with controller.store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        active = json.loads(db.execute("SELECT value FROM settings WHERE key='integrations'").fetchone()[0])
        if config.review and not active["mergecraft"]:
            raise HTTPException(
                400, "Add mergeCraft review in Settings before turning it on for a repository"
            )
        if config.enabled and not config.workflows and not config.review:
            raise HTTPException(
                400,
                "Select at least one CI workflow" + (" or mergeCraft review" if active["mergecraft"] else ""),
            )
        current = json.loads(db.execute("SELECT config FROM repos WHERE name=?", (name,)).fetchone()[0])
        saved = config.model_dump()
        if "review_pipeline" not in config.model_fields_set:
            saved["review_pipeline"] = current.get("review_pipeline", [])
        if not active["mergecraft"] and (
            config.review_key_updates or saved["review_pipeline"] != current.get("review_pipeline", [])
        ):
            raise HTTPException(400, "Enable the mergeCraft integration to edit its pipeline")
        keys = {slot["credential"] for chain in saved["review_pipeline"] for slot in chain}
        for key, secret_value in config.review_key_updates.items():
            raw = secret_value.get_secret_value()
            if key not in keys or not raw.strip() or len(raw) > 20000 or any(c in raw for c in "\0\n\r"):
                raise HTTPException(400, "Enter a single-line API key for a credential used in the pipeline")
            db.execute(
                "INSERT INTO secrets VALUES(?,?,?) ON CONFLICT(repo,name) DO UPDATE SET ciphertext=excluded.ciphertext",
                (name, f"review:{key}", controller.cipher.encrypt(raw.encode()).decode()),
            )
        if "review_pipeline" in config.model_fields_set:
            existing = {row[0] for row in db.execute("SELECT name FROM secrets WHERE repo=?", (name,))}
            for key in sorted(keys):
                if f"review:{key}" not in existing:
                    raise HTTPException(400, f"Enter a private value for {key}")
        db.execute(
            "UPDATE repos SET enabled=?,config=? WHERE name=?",
            (int(config.enabled), json.dumps(saved), name),
        )
    if not config.enabled:
        for row in controller.store.rows(
            "SELECT id FROM runs WHERE repo=? AND state IN ('queued','running')", (name,)
        ):
            controller.store.request_cancel(row["id"], "repo_disabled", "Repository disabled")
    controller.notify()
