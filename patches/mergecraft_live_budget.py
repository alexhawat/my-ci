"""Fail closed on the pinned OpenCode stream without losing usage evidence."""

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
        "                try:\n                    result = await attempt_agent.run(attempt_ctx)\n                finally:",
        "                from mergecraft.localci_live_budget import bind\n"
        "                try:\n                    with bind(budget_tracker) as live_budget:\n"
        "                        result = await attempt_agent.run(attempt_ctx)\n                finally:",
    )
    replace(
        "review/offline_agent.py",
        '            record_agent_usage(budget_tracker, result.usage, phase="reviewer_dispatch")',
        "            if not live_budget.steps:\n"
        '                record_agent_usage(budget_tracker, result.usage, phase="reviewer_dispatch")',
    )
    replace(
        "agents/opencode.py",
        "    def _watched_handler(acc: StreamSpanAccumulator, event: dict[str, Any]) -> None:",
        "    from mergecraft.localci_live_budget import current\n"
        "    from mergecraft.utils.process_group import kill_process_group\n"
        "    live_budget = current()\n\n"
        "    def _watched_handler(acc: StreamSpanAccumulator, event: dict[str, Any]) -> None:",
    )
    replace(
        "agents/opencode.py",
        "        base_handler(acc, event)\n",
        """        if live_budget is not None:
            if live_budget.error:
                return
            try:
                accepted = live_budget.accept(event)
            except Exception as exc:
                # The generic stream handler would swallow this and leave the agent
                # running with metering already stopped.
                from mergecraft.utils.run_bounds import BudgetExhausted
                live_budget.error = live_budget.error or BudgetExhausted(
                    "token", "Live usage meter failed; review stopped: " + type(exc).__name__
                )
                live_budget.tracker.last_exhausted = live_budget.error
                accepted = False
            if not accepted:
                # A rejected event (invalid counters, failed meter) stops the agent.
                if live_budget.error:
                    kill_process_group(getattr(process, "pid", None))
                return
        before = acc.to_usage()
        previous = (before.input_tokens + before.output_tokens, before.cost_usd or 0) if before else (0, 0)
        base_handler(acc, event)
        if live_budget is not None:
            usage = acc.to_usage()
            if usage is not None:
                try:
                    live_budget.charge(event, usage, previous)
                except Exception as exc:
                    # Do not let the generic stream handler swallow a failed meter.
                    from mergecraft.utils.run_bounds import BudgetExhausted
                    live_budget.error = BudgetExhausted("token", "Live usage meter failed; review stopped: " + type(exc).__name__)
                    live_budget.tracker.last_exhausted = live_budget.error
                    kill_process_group(getattr(process, "pid", None))
                if live_budget.error:
                    kill_process_group(getattr(process, "pid", None))
""",
    )
    replace(
        "agents/opencode.py",
        "    if watchdog.stalled:\n",
        "    if live_budget is not None and live_budget.error:\n        raise live_budget.error\n\n"
        "    if watchdog.stalled:\n",
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
                _emit_offline_packet, tool_context, cwd=cwd,
                materialization=materialization, run_succeeded=False,
                structured_output=tool_state.output, output_path=evidence_packet_path,
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
