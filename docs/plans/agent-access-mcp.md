# Agent access (HTTP API + MCP) — implementation plan

## Goal

Expose my-ci to external agents over the tailnet via a versioned Bearer-token HTTP API and an MCP (streamable HTTP) server, both toggled from **Settings → Integrations**, sharing one service layer with the dashboard.

## Non-goals

- Public internet exposure (no Funnel); no Tailscale login automation or stored TS auth keys.
- New execution paths; agents mirror existing dashboard capabilities only.
- Shipping plaintext tokens after creation or any secret material in API/MCP payloads.

## Architecture

```
Dashboard (Tailscale user login) ──► token CRUD, integration toggle
Agent client (tailnet + Bearer)  ──► /api/agent/v1/*  ──┐
Agent MCP client                 ──► /agent/mcp       ──├── AgentService(controller)
```

- **AgentService**: single module for list repos/runs, run detail, review summary, queue status, retry, repo review toggle. Responses pass through `public_view()` (no secrets, no ciphertext).
- **AgentTokenStore** (SQLite): salted PBKDF2 hashes, scopes, optional expiry, `last_used_at`, append-only audit rows.
- **MCP**: official `mcp` SDK v2 (`MCPServer`), streamable HTTP, stateless, custom `TokenVerifier` delegating to `AgentTokenStore`.

## Data model (schema v5)

- `agent_tokens(id, name, scopes, salt, token_hash, created, expires_at, last_used_at, revoked_at)`
- `agent_token_audit(id, token_id, timestamp, action, path, detail)`
- `settings.integrations.agent_access` (bool, default false)

## Scopes

| Scope | Capability |
|-------|------------|
| `read` | List repos/runs, get run, review/findings metadata, queue status, log/artifact metadata |
| `write-config` | Enable/disable repo, toggle `review` (respect mergeCraft add-on) |
| `write-runs` | Retry (re-run) a run |

## HTTP surface (`/api/agent/v1`)

| Method | Path | Scope |
|--------|------|-------|
| GET | `/openapi.json`, `/docs` | (addon on; Bearer) |
| GET | `/repos` | read |
| GET | `/runs` | read (+ filters: repo, state, limit) |
| GET | `/runs/{id}` | read |
| GET | `/runs/{id}/review` | read |
| GET | `/runs/{id}/logs/meta` | read |
| GET | `/queue` | read |
| POST | `/runs/{id}/retry` | write-runs |
| PATCH | `/repos/{owner}/{repo}` | write-config |

Addon disabled → **404**. Missing/invalid token → **401**. Insufficient scope → **403**.

## MCP tools

Same operations as above: `list_repos`, `list_runs`, `get_run`, `get_review`, `get_queue`, `rerun`, `set_repo_review`.

## Dashboard UI

- Integrations: **Agent access (API + MCP)** toggle (with mergeCraft).
- **Agent access** panel: Tailscale serve steps, MCP/HTTP base URLs from `LOCALCI_URL`, copy-paste Cursor / Claude Code JSON (placeholders), token management table, optional `tailscale status` hint when CLI available.
- Token create: name, scope checkboxes, optional expiry days; show secret once.

## Auth middleware (app)

- `/healthz`: unchanged.
- `/api/agent/*`, `/agent/mcp`: skip Tailscale login header; require addon + Bearer (validated in agent layer).
- Other routes: existing Tailscale + Origin checks.

## Security tests

- Assert no `ciphertext`, `private_key`, `app:`, decrypted secret values in serialized agent responses (parametrize endpoints).

## Docs

- `docs/agent-access.md`: threat model, setup, client config.
- README: short section linking to doc and tailnet requirement.

## Test plan (automated)

- `tests/test_agent_access.py`: tokens, scopes, disabled addon, API, MCP tool handlers (via service), no-secret-leak.
- Full suite: `uv run pytest -q`, `ruff`, `pyright` (as in README).

## Risks / open questions

- MCP SDK v2 API surface (MCPServer rename); pinned `mcp>=2,<3`.
- Whether `write-runs` should also allow cancel (deferred; not in scope).
- DNS rebinding protection in MCP transport may need `allowed_hosts` aligned with Tailscale hostname (configure via env if needed).