"""Pinned-image read transport fixes and metadata-only profiling."""

from pathlib import Path


def replace(path, old, new):
    text = path.read_text()
    if text.count(old) != 1:
        raise RuntimeError(f"Pinned source changed: {path.name}: {old[:60]}")
    text = text.replace(old, new, 1)
    compile(text, str(path), "exec")
    path.write_text(text)


def apply(root):
    path = root / "mcp/server.py"
    replace(
        path,
        "from mergecraft.mcp.git import (",
        "from mergecraft.localci_git_batch import git_batch_tool\nfrom mergecraft.localci_read_batch import read_batch_tool\nfrom mergecraft.mcp.git import (",
    )
    replace(
        path,
        "        git_tool(ctx),",
        "        git_tool(ctx),\n        git_batch_tool(ctx),\n        read_batch_tool(ctx),",
    )
    path = root / "mcp/rpc.py"
    replace(
        path,
        "                result = await tool.execute(arguments)",
        "                from mergecraft.localci_profile import invoke\n                result = await invoke(tool, arguments)",
    )
    path = root / "agents/opencode_config.py"
    replace(path, "    read = _build_review_mode_read_allowlist(checkout, evidence, exports)\n", "")
    replace(
        path,
        '        "read": read,',
        '        "read": "deny",  # Local CI uses guarded read_batch for all source reads.',
    )
    replace(
        path,
        '                "timeout": 300_000,',
        '                "timeout": 300_000,\n                "codemode": False,  # Deliver credited text directly to the model.',
    )
    replace(path, '        "skill": "allow",', '        "skill": "allow",\n        "execute": "deny",')
    path = root / "agents/opencode.py"
    replace(
        path,
        '        session["last_event"] = summary',
        '        from mergecraft.localci_profile import event as profile_event\n        profile_event("provider_event", event_type=str(event.get("type", "unknown"))[:60], tool=str(detail.get("tool", ""))[:100] if isinstance(detail, dict) else "")\n        session["last_event"] = summary',
    )
    path = root / "review/offline_agent.py"
    replace(
        path,
        "        tool_context = prepared.tool_context\n        mcp_url, stop_mcp =",
        "        from mergecraft.localci_profile import prepare_read_transport\n"
        "        prompt += prepare_read_transport(materialization.path, tmpdir)\n"
        "        tool_context = prepared.tool_context\n        mcp_url, stop_mcp =",
    )
    replace(
        path,
        "            result = await attempt_agent.run(attempt_ctx)",
        "            from mergecraft.localci_profile import event as profile_event\n"
        '            profile_event("agent_start")\n'
        "            try:\n"
        "                result = await attempt_agent.run(attempt_ctx)\n"
        "            finally:\n"
        '                profile_event("agent_end")',
    )


if __name__ == "__main__":
    apply(Path("/opt/mergecraft/src/mergecraft"))
