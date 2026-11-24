"""Observe native per-step enforcement without charging stream usage twice."""

from pathlib import Path


def apply(root):
    def replace(name, old, new):
        path = root / name
        text = path.read_text()
        if text.count(old) != 1:
            raise RuntimeError(f"Pinned live-budget anchor changed: {name}: {old[:80]}")
        text = text.replace(old, new, 1)
        compile(text, str(path), "exec")
        path.write_text(text)

    replace(
        "review/offline_agent.py",
        "                result = await attempt_agent.run(attempt_ctx)",
        "                from mergecraft.localci_live_budget import bind\n"
        "                budget_tracker.stream_tokens_charged = 0\n"
        "                budget_tracker.stream_cost_charged = 0.0\n"
        "                with bind(budget_tracker) as live_budget:\n"
        "                    result = await attempt_agent.run(attempt_ctx)",
    )
    # Enforce the existing cost ceiling on estimates before exporting billed usage.
    charge = '        record_agent_usage(budget_tracker, result.usage, phase="reviewer_dispatch")'
    replace(
        "review/offline_agent.py",
        "        _localci_usages.append(result.usage)\n" + charge,
        charge + "\n        result.usage = live_budget.reported_usage(result.usage)\n"
        "        _localci_usages.append(result.usage)",
    )
    replace(
        "agents/opencode.py",
        '    cache = tokens.get("cache")\n    cache = cache if isinstance(cache, dict) else {}',
        "    from mergecraft.localci_live_budget import current\n"
        "    live_budget = current()\n"
        "    try:\n"
        "        if live_budget is not None and not live_budget.accept(event):\n"
        "            # A duplicate is skipped; invalid counters or cost stop the review.\n"
        "            if live_budget.error:\n"
        "                accumulator.halt_reason = str(live_budget.error)\n"
        "            return\n"
        "    except Exception:\n"
        '        accumulator.halt_reason = "Live usage evidence failed; review stopped"\n'
        "        return\n"
        '    cache = tokens.get("cache")\n    cache = cache if isinstance(cache, dict) else {}',
    )
    replace(
        "agents/opencode.py",
        "    if stop:\n        accumulator.halt_reason = stop\n        return\n    accumulator.absorb_usage(payload)",
        "    if live_budget is not None:\n"
        "        try:\n"
        "            live_budget.observe(event, stop)\n"
        "        except Exception:\n"
        '            accumulator.halt_reason = "Live usage evidence failed; review stopped"\n'
        "            return\n"
        "    if stop:\n        accumulator.halt_reason = stop\n        return\n    accumulator.absorb_usage(payload)\n"
        "    if live_budget is not None and live_budget.loops.reason:\n"
        "        accumulator.halt_reason = live_budget.loops.reason",
    )
    replace(
        "review/offline_agent.py",
        """    except BudgetExhausted as exc:
        return _offline_failure(
            error=str(exc),
            outcome=budget_exhaustion_outcome(exc),
            diff_path=str(materialization.path),
        )""",
        """    except BudgetExhausted as exc:
        outcome = budget_exhaustion_outcome(exc)
        packet_path = None
        try:
            packet_path = await asyncio.to_thread(
                _emit_offline_packet, prepared.tool_context, cwd=cwd,
                materialization=materialization, run_succeeded=False,
                structured_output=prepared.tool_context.tool_state.output, output_path=evidence_packet_path,
            )
        except Exception:
            logger.warning("Budget-stop evidence export unavailable")
        return OfflineReviewResult(
            success=False, error=str(exc), outcome=outcome,
            diff_path=str(materialization.path), evidence_packet_path=packet_path,
        )""",
    )


if __name__ == "__main__":
    apply(Path("/opt/mergecraft/src/mergecraft"))
