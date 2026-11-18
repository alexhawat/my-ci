"""Keep the exit status when OpenCode terminates without a diagnostic event."""

from pathlib import Path


def apply(root: Path):
    path = root / "agents/opencode.py"
    source = path.read_text()
    old = '            error=failure_error or f"opencode failed (exit {returncode})",'
    new = '            error=f"opencode exited {returncode}: " + (\n                failure_error or (\n                    "no diagnostic event or stderr output; last event="\n                    + (session or {}).get("last_event", "none")\n                )\n            ),'
    if source.count(old) != 1:
        raise RuntimeError("Pinned OpenCode adapter changed; review the diagnostic patch")
    source = source.replace(old, new, 1)
    command = 'base = [cli, "run", "--standalone", "--format", "json", "--title", "mergecraft"]'
    if source.count(command) != 1:
        raise RuntimeError("Pinned OpenCode v2 command changed")
    source = source.replace(
        command,
        'base = [cli, "run", "--standalone", "--print-logs", "--log-level", "error", '
        '"--format", "json", "--title", "mergecraft"]',
        1,
    )
    anchor = '        session_id = event.get("sessionID")\n'
    if source.count(anchor) != 1:
        raise RuntimeError("Pinned OpenCode event handler changed")
    source = source.replace(
        anchor,
        """        summary = str(event.get("type", "unknown"))[:80]
        detail = event.get("part")
        if isinstance(detail, dict) and summary == "tool_use":
            summary += "/" + str(detail.get("tool", "unknown"))[:80]
            state = detail.get("state")
            if isinstance(state, dict):
                summary += "/" + str(state.get("status", "unknown"))[:80]
        session["last_event"] = summary
"""
        + anchor,
        1,
    )
    path.write_text(source)
    path = root / "agents/opencode_config.py"
    source = path.read_text()
    permission = '        "webfetch": "deny",\n'
    if source.count(permission) != 1:
        raise RuntimeError("Pinned OpenCode review permission policy changed")
    # OpenCode 2's websearch opens a provider-selection form. Noninteractive
    # cancellation poisons the CLI exit status even if the review then completes.
    # Local diff reviews are offline; deny the tool before it can open that form.
    source = source.replace(permission, permission + '        "websearch": "deny",\n', 1)
    path.write_text(source)


if __name__ == "__main__":
    apply(Path("/opt/mergecraft/src/mergecraft"))
