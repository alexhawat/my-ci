"""Support metered free-first OpenCode fallback in the Local CI review image."""

from pathlib import Path

from mergecraft import _build_metadata

ROOT = Path(_build_metadata.__file__).parent
FREE_MODEL = "opencode/deepseek-v4.1-flash-free"


def replace_once(relative_path: str, before: str, after: str) -> None:
    path = ROOT / relative_path
    source = path.read_text()
    if source.count(before) != 1:
        raise RuntimeError(f"Pinned mergeCraft source changed in {relative_path}")
    source = source.replace(before, after, 1)
    compile(source, str(path), "exec")
    path.write_text(source)


if __name__ == "__main__":
    # Register the native Console model for mergeCraft's roster validator.
    catalog = '                "mimo-v2-pro-free": ModelDef(\n'
    replace_once(
        "models.py",
        catalog,
        '                "deepseek-v4.1-flash-free": ModelDef(\n'
        '                    display_name="DeepSeek V4.1 Flash Free",\n'
        f'                    resolve="{FREE_MODEL}",\n'
        "                    is_free=True,\n"
        "                ),\n" + catalog,
    )

    # OpenCode enables the active native provider for each attempt. Only
    # subagents whose chain includes that model should switch with the reviewer.
    roster = "        if dispatch_instructions and binding.role is AgentRole.reviewer:\n"
    replace_once(
        "agents/harness_render.py",
        roster,
        "        if (\n"
        "            isinstance(ctx, AgentRunContext)\n"
        "            and ctx.tool_state.fallback_index > 0\n"
        "            and ctx.resolved_model in binding.model_chain\n"
        "        ):\n"
        '            entry["model"] = ctx.resolved_model\n' + roster,
    )

    # OpenCode reports free-tier limits and missing routes with typed errors.
    # Let those failures reach Go once the usage journal has been reconciled.
    # This adds to upstream's retryable path, which already moves a rate limit
    # (typed or not) on to the next model; it does not replace or narrow it.
    stream = '            detail = event.get("error")\n'
    replace_once(
        "agents/opencode.py",
        stream,
        stream
        + '            session["error_type"] = str(detail.get("type", "")) if isinstance(detail, dict) else ""\n',
    )
    replace_once(
        "agents/opencode.py",
        '                metadata={"retryable": True} if retryable else {},\n',
        "                metadata={\n"
        '                    **({"retryable": True} if retryable else {}),\n'
        '                    "failover_eligible": (\n'
        f'                        ctx.resolved_model == "{FREE_MODEL}"\n'
        '                        and (session or {}).get("error_type") in {"provider.no-route", "provider.free-limit"}\n'
        "                    ),\n"
        "                },\n",
    )
