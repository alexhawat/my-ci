"""Route the installed CLI's complete native usage through upstream accounting."""

from pathlib import Path


def replace(path, old, new):
    value = path.read_text()
    if value.count(old) != 1:
        raise RuntimeError(f"Pinned compaction anchor changed: {path.name}: {old[:60]}")
    value = value.replace(old, new, 1)
    compile(value, str(path), "exec")
    path.write_text(value)


def reconcile_final_call(path):
    anchor = "    def classify(returncode: int, stderr_text: str) -> AgentResult:\n"
    replace(
        path,
        anchor,
        anchor
        + """        from mergecraft.localci_compaction import consume
        consume(
            accumulator, {},
            lambda row: _absorb_step_usage(accumulator, row, model=ctx.resolved_model, budget_tracker=ctx.budget_tracker),
            final=True,
            unrouted=returncode != 0 and (session or {}).get("error_type") == "provider.no-route",
        )
""",
    )


def apply(root):
    path = root / "agents/opencode_config.py"
    replace(
        path,
        "    return json.dumps(config)",
        "    from mergecraft.localci_compaction import configure\n    configure(ctx, model, config)\n    return json.dumps(config)",
    )
    path = root / "agents/opencode.py"
    anchor = '    if event.get("type") != "step_finish":\n        return\n    part = event.get("part")'
    replace(
        path,
        anchor,
        """    from mergecraft.localci_compaction import consume
    if consume(accumulator, event, lambda row: _absorb_step_usage(accumulator, row, model=model, budget_tracker=budget_tracker)):
        return
"""
        + anchor,
    )
    reconcile_final_call(path)


if __name__ == "__main__":
    apply(Path("/opt/mergecraft/src/mergecraft"))
