# Agent access (HTTP API + MCP)

Programmatic access lets automation and LLM clients read my-ci state and perform a small set of operator actions. Both surfaces are **off by default** until you enable **Settings → Integrations → Agent access (API + MCP)**.

## Threat model

| Layer | Control |
|-------|---------|
| Network | **Tailnet only.** Expose the dashboard with `tailscale serve` (or equivalent private ingress). Do not use Tailscale Funnel or a public reverse proxy without the same identity guarantees. |
| Authentication | **Bearer tokens** you create in the dashboard. Tokens are stored as salted PBKDF2 hashes; the plaintext is shown once at creation. |
| Authorization | **Scopes:** `read`, `write-config` (repo enable/review), `write-runs` (retry). Each request is audit-logged with token id, path, and action. |
| Secrets | Tokens never gate access to workflow credentials, GitHub App keys, or review provider secrets. Agent responses are filtered to exclude secret material. |
| Revocation | Revoke a token in the dashboard; agents receive **401** on the next call. |

Assume anyone who can reach the dashboard origin on your tailnet can attempt authentication; keep ACLs tight and use least-privilege scopes.

## Setup

1. Deploy my-ci with `LOCALCI_URL` set to your **tailnet HTTPS origin** (including port), e.g. `https://YOUR_TAILNET_HOST:9443`.
2. On the worker: `tailscale serve --bg --https=9443 http://127.0.0.1:8787` (match your compose port).
3. Enable **Agent access** under Settings → Integrations.
4. Open **Connect an agent**, create a token with required scopes, copy it once.
5. On the agent machine: join the same tailnet, then call the API or configure MCP.

## HTTP API

- Base: `{LOCALCI_URL}/api/agent/v1`
- OpenAPI: `{LOCALCI_URL}/api/agent/v1/docs`
- Header: `Authorization: Bearer mci_…`

Example:

```sh
curl -sS -H "Authorization: Bearer YOUR_TOKEN" \
  "$LOCALCI_URL/api/agent/v1/queue"
```

When the add-on is disabled, agent routes return **404**. Invalid tokens return **401**; missing scope returns **403**.

## MCP

- URL: `{LOCALCI_URL}/agent/mcp`
- Transport: streamable HTTP (stateless)
- Same Bearer header as the HTTP API

Tools: `list_repos`, `list_runs`, `get_run`, `get_review`, `get_queue`, `rerun`, `set_repo_review`.

### Cursor (example)

```json
{
  "mcpServers": {
    "my-ci": {
      "url": "https://YOUR_TAILNET_HOST:9443/agent/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_MY_CI_TOKEN"
      }
    }
  }
}
```

### Claude Code (example)

```json
{
  "mcpServers": {
    "my-ci": {
      "type": "http",
      "url": "https://YOUR_TAILNET_HOST:9443/agent/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_MY_CI_TOKEN"
      }
    }
  }
}
```

Replace the URL and token placeholder; never commit real tokens.

## Operations

- **Rotate:** create a new token, update clients, revoke the old token.
- **Audit:** `agent_token_audit` in the SQLite database (token id, timestamp, action, path).
- **Disable add-on:** turns off API and MCP immediately (404 for agents); existing dashboard access unchanged.