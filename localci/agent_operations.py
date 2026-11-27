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
    mergecraft = controller.store.keep_integrations()["mergecraft"]
    if config.review and not mergecraft:
        raise HTTPException(400, "Add mergeCraft review in Settings before turning it on for a repository")
    if config.enabled and not config.workflows and not config.review:
        raise HTTPException(
            400, "Select at least one CI workflow" + (" or mergeCraft review" if mergecraft else "")
        )
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
