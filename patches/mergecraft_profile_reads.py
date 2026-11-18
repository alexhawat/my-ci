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
    path = root / "mcp/git.py"
    replace(
        path,
        '    return str(Path(temp) / f"git-show-{digest}.txt")',
        '    export = Path(temp) / "evidence" / "git-read"\n    export.mkdir(parents=True, exist_ok=True)\n    return str(export / f"git-show-{digest}.txt")',
    )
    replace(path, "_GIT_SHOW_PREVIEW_LINES = 5", "_GIT_SHOW_PREVIEW_LINES = 120")
    replace(
        path,
        '    preview = "\\n".join(lines[:_GIT_SHOW_PREVIEW_LINES])',
        '    preview = "\\n".join(lines[:_GIT_SHOW_PREVIEW_LINES])[:12000]',
    )
    replace(
        path,
        "    if len(lines) > _GIT_SHOW_PREVIEW_LINES:",
        "    if len(lines) > _GIT_SHOW_PREVIEW_LINES or len(text) > 12000:",
    )
    replace(
        path,
        '            temp = os.environ.get("MERGECRAFT_TEMP_DIR") or ctx.tmpdir\n            path = str(Path(temp) / f"git-{command}-{uuid.uuid4().hex[:8]}.txt")',
        '            temp = os.environ.get("MERGECRAFT_TEMP_DIR") or ctx.tmpdir\n            export = Path(temp) / "evidence" / "git-read"\n            export.mkdir(parents=True, exist_ok=True)\n            path = str(export / f"git-{command}-{uuid.uuid4().hex[:8]}.txt")',
    )
    path = root / "mcp/server.py"
    replace(
        path,
        "from mergecraft.mcp.git import (",
        "from mergecraft.localci_git_batch import git_batch_tool\nfrom mergecraft.mcp.git import (",
    )
    replace(path, "        git_tool(ctx),", "        git_tool(ctx),\n        git_batch_tool(ctx),")
    path = root / "mcp/rpc.py"
    replace(
        path,
        "                result = await tool.execute(arguments)",
        "                from mergecraft.localci_profile import invoke\n                result = await invoke(tool, arguments)",
    )
    path = root / "agents/opencode.py"
    replace(
        path,
        '        session["last_event"] = summary',
        '        from mergecraft.localci_profile import event as profile_event\n        profile_event("provider_event", event_type=str(event.get("type", "unknown"))[:60], tool=str(detail.get("tool", ""))[:100] if isinstance(detail, dict) else "")\n        session["last_event"] = summary',
    )
    path = root / "review/offline_agent.py"
    replace(
        path,
        "        establish_offline_review_scope(tool_state, diff_path=str(materialization.path))",
        """        establish_offline_review_scope(tool_state, diff_path=str(materialization.path))
        # Copy only the already-materialized diff into the existing read boundary.
        from mergecraft.evidence.run_packet import resolve_packet_path
        from mergecraft.localci_profile import event as profile_event
        _read_dir = resolve_packet_path(tmpdir=str(tmpdir), change_slug="local-review").parent / "git-read"
        _read_dir.mkdir(parents=True, exist_ok=True)
        _safe_diff = _read_dir / "full-review.patch"
        _safe_diff.write_bytes(materialization.path.read_bytes())
        prompt += (f"\\nLocal CI read transport: the complete authoritative diff is {_safe_diff}. "
                   "Read it with native read; it is inside the allowed evidence directory. "
                   "For current files use native read on the checkout. For prior revisions use git show "
                   "then native read of its outputPath; its preview is not the full file. "
                   "Use git_batch for up to eight independent related diff/search operations per turn. "
                   "Do not reconstruct whole files with many single-pattern grep calls. "
                   "Inspect all changed files and retain every verification requirement.")""",
    )
    replace(
        path,
        "                result = await attempt_agent.run(attempt_ctx)",
        """                profile_event("agent_start")
                try:
                    result = await attempt_agent.run(attempt_ctx)
                finally:
                    profile_event("agent_end")""",
    )


if __name__ == "__main__":
    apply(Path("/opt/mergecraft/src/mergecraft"))
