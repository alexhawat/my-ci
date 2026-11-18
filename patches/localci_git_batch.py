"""Batch existing read-only Git calls, preserving every original guard and gate."""


def git_batch_tool(ctx):
    from mergecraft.mcp.git import git_tool
    from mergecraft.mcp.shared import ToolClass, execute, tool
    from mergecraft.mcp.tool_call import charge_tool_call_budget, record_trajectory

    git = git_tool(ctx)

    async def run(params):
        requests = params.get("requests")
        if not isinstance(requests, list) or not 1 <= len(requests) <= 8:
            raise ValueError("Provide 1 to 8 independent read-only Git requests")
        results = []
        for request in requests:
            # Runtime checks also protect direct callers outside JSON-RPC validation.
            if not isinstance(request, dict) or set(request) - {"command", "args"}:
                raise ValueError("Expected command and args only")
            if not isinstance(request.get("command"), str) or not isinstance(request.get("args", []), list):
                raise ValueError("Invalid Git request")
            if len(request.get("args", [])) > 64 or not all(
                isinstance(a, str) and len(a) <= 2000 for a in request.get("args", [])
            ):
                raise ValueError("Git arguments exceed batch bounds")
            charge_tool_call_budget(ctx)
            result = await git.execute(request)
            record_trajectory(ctx, "git", request, ok=not result.is_error, result=result)
            results.append(
                {"command": request["command"], "content": result.content, "isError": result.is_error}
            )
        return {
            "results": results,
            "note": "Independent read-only operations; errors are retained per operation.",
        }

    return tool(
        name="git_batch",
        tool_class=ToolClass.REPOSITORY_READ,
        description="Run 1–8 independent read-only Git commands in one model turn. Same guards as git. Use for grouped diffs/searches across related files; use native read on returned outputPath for full contents.",
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
                            "command": {"type": "string"},
                            "args": {
                                "type": "array",
                                "maxItems": 64,
                                "items": {"type": "string", "maxLength": 2000},
                            },
                        },
                        "required": ["command"],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["requests"],
            "additionalProperties": False,
        },
        execute=execute(run, "git_batch"),
    )
