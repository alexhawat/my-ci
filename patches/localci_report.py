"""Export only the terminal summary and allowlisted numeric accounting."""

import json


def export(tmpdir, tracker, usages, timing, state, markdown):
    from mergecraft.utils.run_bounds import format_token_budget_summary

    complete = bool(usages) and all(u is not None for u in usages)
    costs_complete = complete and all(getattr(u, "cost_usd", None) is not None for u in usages)
    metrics = {
        "tokens": format_token_budget_summary(tracker) if complete else "Unavailable: provider usage missing",
        "cost": f"${tracker.cost_used:.6f} reported/estimated usage; subscription charges may differ"
        if costs_complete
        else "Unavailable: provider cost missing for one or more attempts",
        "timing": (timing or {}).get("line") or "Unavailable",
        "attempts": len(usages),
    }
    summary = getattr(state.terminal_submission, "summary", "") or markdown or ""
    try:
        # mergeCraft removes everything in its review directory at exit except
        # `evidence/`; the bootstrap copies these files only after that exit.
        folder = tmpdir / "evidence"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "localci-review.md").write_text(summary)
        (folder / "localci-metrics.json").write_text(json.dumps(metrics))
    except OSError:
        from loguru import logger

        logger.warning("Local CI accounting export unavailable")
