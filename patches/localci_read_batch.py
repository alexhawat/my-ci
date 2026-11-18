"""Bounded text batches using upstream Git guards and honest read-span evidence."""

import json
from pathlib import Path, PurePosixPath


def read_batch_tool(ctx):
    from mergecraft.evidence.trajectory import record_driver_read
    from mergecraft.mcp.git import git_tool
    from mergecraft.mcp.shared import ToolClass, execute, tool
    from mergecraft.mcp.tool_call import charge_tool_call_budget
    from mergecraft.mcp.tool_state import primary_repo_state
    from mergecraft.mcp.verdict import confine_diff_path
    from mergecraft.utils.git_setup import run_export_directory

    git = git_tool(ctx)

    async def run(params):
        requests = params.get("requests")
        if not isinstance(requests, list) or not 1 <= len(requests) <= 8:
            raise ValueError("Provide 1 to 8 line-range read requests")
        results, remaining, reads = [], 24_000, []
        remaining_lines = 1000
        repo = primary_repo_state(ctx.tool_state)
        for request in requests:
            if not isinstance(request, dict) or set(request) - {"path", "start", "limit"}:
                raise ValueError("Use path, start and limit only")
            name = request.get("path")
            start, limit = request.get("start", 1), request.get("limit", 1000)
            if type(start) is not int or start < 1 or type(limit) is not int or not 1 <= limit <= 2000:
                raise ValueError("Use a positive line start and a limit of 1–2000")
            if not isinstance(name, str) or not name or len(name) > 1000:
                raise ValueError("A bounded repository-relative path or @diff is required")
            charge_tool_call_budget(ctx)
            if name == "@diff":
                if not repo.diff_path:
                    raise ValueError("Authoritative review scope is not established")
                source = confine_diff_path(ctx, repo.diff_path)
                evidence_path = str(source)
            elif Path(name).is_absolute():
                # Only outputs already produced by guarded Git calls are readable.
                # Config/auth/session directories remain outside this boundary.
                source = Path(name).resolve()
                if not source.is_relative_to(run_export_directory(ctx.tmpdir).resolve()):
                    raise ValueError("Only guarded Git export paths may be absolute")
                evidence_path = str(source)
            else:
                path = PurePosixPath(name)
                if path.is_absolute() or ".." in path.parts or any(c in name for c in "\n\r\x00\\:"):
                    raise ValueError("Read paths must stay inside the checkout")
                result = await git.execute({"command": "show", "args": [f"HEAD:{name}"]})
                if result.is_error:
                    results.append({"path": name, "error": "Upstream Git read refused or file unavailable"})
                    continue
                payload = json.loads(result.content[0]["text"])
                source = Path(payload["outputPath"]).resolve()
                if not source.is_relative_to(run_export_directory(ctx.tmpdir).resolve()):
                    raise ValueError("Git export escaped the authorized output directory")
                evidence_path = str(Path(repo.dir) / name)
            if not source.is_file() or source.stat().st_size > 2_000_000:
                results.append(
                    {"path": name, "error": "File exceeds 2MB batch limit; use guarded Git searches"}
                )
                continue
            # Lines are what Git and the diff count: separated by "\n" only. splitlines()
            # also breaks on form feed, U+2028 and similar, and text-mode reading turns a
            # bare "\r" into "\n"; either would shift every later line number and credit
            # read coverage to the wrong ranges. Decode the bytes without translation.
            lines = source.read_bytes().decode("utf-8").split("\n")
            if lines and lines[-1] == "":
                lines.pop()
            lines = [line.removesuffix("\r") for line in lines]
            shown, used = [], 0
            for number, line in enumerate(lines[start - 1 : start - 1 + limit], start):
                rendered = f"{number}: {line}"
                size = len(rendered.encode("utf-8")) + 1
                if size > 2000 or used + size > remaining or len(shown) >= remaining_lines:
                    break
                shown.append(rendered)
                used += size
            remaining -= used
            remaining_lines -= len(shown)
            end = start + len(shown) - 1
            if shown:
                reads.append((evidence_path, (start, end)))
            results.append(
                {
                    "path": name,
                    "start": start,
                    "end": end if shown else None,
                    "total_lines": len(lines),
                    "text": "\n".join(shown),
                    "next_line": end + 1 if end < len(lines) else None,
                }
            )
        tracker = ctx.budget_tracker
        checkpoint = ""
        if tracker and tracker.tokens_used >= tracker.bounds.token_ceiling // 2:
            checkpoint = (
                "Budget checkpoint: at least half the token ceiling is spent. "
                "Prioritize mandatory verification and the terminal verdict now; "
                "limit further exploration to unresolved changed-code questions. "
                "Never drop an unresolved finding or approve incomplete coverage. "
            )
        budget = (
            f"Token budget: used={tracker.tokens_used}; ceiling={tracker.bounds.token_ceiling}; "
            f"remaining={max(0, tracker.bounds.token_ceiling - tracker.tokens_used)}"
            if tracker
            else "Token budget unavailable"
        )
        sections = [
            budget,
            checkpoint
            + "Only returned complete lines count as read. Continue next_line ranges; preserve coverage, verification and the terminal verdict.",
        ]
        for result in results:
            body = result.pop("text", "")
            sections.append("Range: " + json.dumps(result, ensure_ascii=False))
            if body:
                sections.append(body)
        output = "\n".join(sections)
        # OpenCode 2.2.5 can drop a whole oversized JSON text line. Send physical
        # source lines below its byte/line limits, directly (Code Mode disabled).
        # Validate the final wire text BEFORE crediting any returned ranges.
        if len(output.encode("utf-8")) > 40_000 or len(output.splitlines()) > 1100:
            raise ValueError("Batch metadata exceeds safe transport bounds; request fewer paths")
        for path, span in reads:
            record_driver_read(ctx.tool_state, path=path, span=span)
        return output

    return tool(
        name="read_batch",
        tool_class=ToolClass.REPOSITORY_READ,
        description="Read 1–8 related ranges in one turn. @diff reads the authoritative full diff; relative paths read tracked HEAD files through the original Git security checks; absolute outputPath values read only guarded Git exports. Native file reads are disabled in this local review; batch independent ranges together. Returns numbered source text, exact read coverage and token budget. Up to 2000 lines/request and 24000 UTF-8 source bytes and 1000 source lines/batch; truncated ranges must be continued. Lines over 2000 bytes are not credited; use guarded Git searches to inspect them.",
        input_schema={
            "type": "object",
            "properties": {
                "requests": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 8,
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "start": {"type": "integer", "minimum": 1},
                            "limit": {"type": "integer", "minimum": 1, "maximum": 2000},
                        },
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["requests"],
            "additionalProperties": False,
        },
        execute=execute(run, "read_batch"),
    )
