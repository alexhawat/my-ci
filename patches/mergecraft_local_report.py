"""Export offline review summaries and accounting from the pinned upstream runtime."""

from pathlib import Path


def apply(root):
    def replace(name, old, new):
        path = root / name
        source = path.read_text()
        if source.count(old) != 1:
            raise RuntimeError(f"Pinned report anchor changed: {name}: {old[:60]}")
        source = source.replace(old, new, 1)
        compile(source, str(path), "exec")
        path.write_text(source)

    name = "review/offline_agent.py"
    replace(
        name,
        "    async def run_once(slug: str) -> AgentResult:",
        "    _localci_usages = []\n\n    async def run_once(slug: str) -> AgentResult:",
    )
    replace(
        name,
        '        record_agent_usage(budget_tracker, result.usage, phase="reviewer_dispatch")',
        '        _localci_usages.append(result.usage)\n        record_agent_usage(budget_tracker, result.usage, phase="reviewer_dispatch")',
    )
    replace(
        name,
        "        result = dispatched.agent_result",
        "        result = dispatched.agent_result\n        result.metadata['localci_usages'] = _localci_usages",
    )
    replace(
        name,
        "    tool_state.llm_review_timing = timing_payload\n",
        "    tool_state.llm_review_timing = timing_payload\n"
        "    from mergecraft.localci_report import export\n"
        "    export(Path(prepared.tool_context.tmpdir), prepared.budget_tracker, "
        "result.metadata.get('localci_usages', []), timing_payload, tool_state, markdown_output)\n",
    )
    replace(
        "review/pipeline/dispatch.py",
        "        pin=model_pin,\n        tool_state=tool_state,",
        "        max_attempts=3,\n        pin=model_pin,\n        tool_state=tool_state,",
    )


if __name__ == "__main__":
    apply(Path("/opt/mergecraft/src/mergecraft"))
