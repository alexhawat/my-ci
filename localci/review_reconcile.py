"""One-time, evidence-backed upgrade of legacy non-blocking review results."""

import json
import time
from pathlib import Path

from localci.results import aggregate
from localci.review_evidence import bound_packet, classify_review, primary_findings, read_json


def reconcile_legacy_reviews(store, root: Path, *, apply: bool = True) -> list[str]:
    changed = []
    for run in store.rows("SELECT * FROM runs WHERE state='failure'"):
        config = json.loads(run["config"])
        if "review_failure_threshold" in config or "review_policy_version" in config:
            continue
        steps = json.loads(run["steps"])
        review = next((s for s in steps if s["name"] == "mergeCraft"), None)
        if (
            not review
            or review["state"] != "failure"
            or any(s["state"] in ("queued", "running", "cancelled") for s in steps)
        ):
            continue
        # Do not erase a failure outside the recorded checks (for example a
        # late runner exception). Only repair the derived legacy summary.
        if aggregate(steps, "success", "All configured checks passed") != (run["state"], run["message"]):
            continue
        directory = root / "artifacts" / run["id"]
        try:
            # Require run/revision provenance and the retained evidence digest,
            # plus the complete primary report and matching terminal events.
            bound_packet(run, directory)
            runtime = read_json(directory / "mergecraft-runtime.json", 100_000)
            if (
                not isinstance(runtime, dict)
                or type(runtime.get("exit_code")) is not int
                or runtime["exit_code"] != 10
            ):
                continue
            events = runtime.get("terminal")
            if not isinstance(events, dict):
                continue
            findings = primary_findings(directory)
            state, detail = classify_review(10, events, findings=findings, failure_threshold="major")
        except (ValueError, TypeError, OSError, KeyError):
            continue
        if state != "success":
            continue
        config.update(
            review_failure_threshold="major",
            review_policy_version=1,
            review_policy_adjustment={
                "at": time.time(),
                "reason": "Legacy exit-10 result re-evaluated from retained evidence; no execution rerun",
                "previous_review_state": review["state"],
                "previous_review_message": review.get("message", ""),
                "previous_run_state": run["state"],
                "previous_run_message": run["message"],
            },
        )
        review.update(
            state=state, message=detail, review_failure_threshold="major", non_blocking_findings=len(findings)
        )
        outcome, message = aggregate(steps, "success", "All configured checks passed")
        if not apply:
            changed.append(run["id"])
            continue
        with store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            updated = db.execute(
                """UPDATE runs SET state=?,message=?,steps=?,config=?,published=0
                WHERE id=? AND state='failure' AND steps=? AND config=?""",
                (
                    outcome,
                    message,
                    json.dumps(steps),
                    json.dumps(config),
                    run["id"],
                    run["steps"],
                    run["config"],
                ),
            ).rowcount
            if updated:
                db.execute("UPDATE run_usage SET state=? WHERE run_id=?", (outcome, run["id"]))
                changed.append(run["id"])
    return changed
