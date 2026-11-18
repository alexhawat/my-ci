"""Export allowlisted offline-review accounting and bound model fallback attempts."""

from pathlib import Path


def apply(root: Path):
    path = root / "review/offline_agent.py"
    source = path.read_text()
    anchor = "        async def run_once(slug: str) -> AgentResult:\n"
    if source.count(anchor) != 1:
        raise RuntimeError("Pinned offline dispatch changed")
    source = source.replace(anchor, "        _localci_usages = []\n\n" + anchor, 1)
    anchor = '            record_agent_usage(budget_tracker, result.usage, phase="reviewer_dispatch")\n'
    if source.count(anchor) != 1:
        raise RuntimeError("Pinned offline accounting changed")
    source = source.replace(anchor, "            _localci_usages.append(result.usage)\n" + anchor, 1)
    anchor = "        tool_state.llm_review_timing = timing_payload\n"
    if source.count(anchor) != 1:
        raise RuntimeError("Pinned offline timing export changed; review the patch")
    source = source.replace(
        anchor,
        anchor
        + """        # Local CI preserves only accounting, never harness auth/config/session data.
        import json as _localci_json
        from mergecraft.utils.run_bounds import format_token_budget_summary
        _costs_complete = bool(_localci_usages) and all(getattr(u, "cost_usd", None) is not None for u in _localci_usages)
        _metrics = {
            "tokens": format_token_budget_summary(budget_tracker) if all(u is not None for u in _localci_usages) and _localci_usages else "Unavailable: provider usage missing",
            "cost": (
                f"${budget_tracker.cost_used:.6f} provider-reported; subscription charges may differ"
                if _costs_complete else "Unavailable: provider cost missing for one or more attempts"
            ),
            "timing": (timing_payload or {}).get("line") or "Unavailable",
            "attempts": len(_localci_usages),
        }
        try:
            # --agent exits before the CLI's --output renderer. Preserve the
            # same authoritative terminal summary used by native PR reviews.
            _summary = getattr(tool_state.terminal_submission, "summary", "") or markdown_output or ""
            (tmpdir / "localci-review.md").write_text(_summary)
            (tmpdir / "localci-metrics.json").write_text(_localci_json.dumps(_metrics))
        except OSError:
            logger.warning("Local CI accounting export unavailable")
        # End local CI accounting export
""",
        1,
    )
    anchor = "                pin=settings.model_pin,\n                tool_state=tool_state,\n"
    if source.count(anchor) != 1:
        raise RuntimeError("Pinned model fallback call changed; review the patch")
    source = source.replace(anchor, "                max_attempts=3,\n" + anchor, 1)
    compile(source, str(path), "exec")
    path.write_text(source)


if __name__ == "__main__":
    apply(Path("/opt/mergecraft/src/mergecraft"))
