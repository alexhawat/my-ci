"""Bearer tokens for agent HTTP and MCP access."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from mcp.server.auth.provider import AccessToken

VALID_SCOPES = frozenset({"read", "write-config", "write-runs"})
AuditAction = Literal["auth", "read", "write", "denied"]
TOKEN_RE = re.compile(r"^mci_([0-9a-f]{32})\.([A-Za-z0-9_-]+)$")
DEFAULT_AUDIT_RETENTION_DAYS = 30
DEFAULT_AUDIT_MAX_ROWS = 10_000


@dataclass(frozen=True)
class VerifiedToken:
    id: str
    name: str
    scopes: frozenset[str]


def parse_agent_token(raw: str) -> tuple[str, str] | None:
    """Split ``mci_<id>.<secret>``. Legacy ``mci_<secret>`` tokens are rejected."""
    match = TOKEN_RE.match(raw)
    if not match:
        return None
    return match.group(1), match.group(2)


def hash_agent_secret(secret: str, pepper: bytes) -> str:
    return hmac.new(pepper, secret.encode(), hashlib.sha256).hexdigest()


class AgentTokenStore:
    def __init__(self, store, pepper: bytes):
        self.store = store
        self.pepper = pepper

    def create(self, name: str, scopes: list[str], *, expires_days: int | None = None) -> tuple[str, dict]:
        unknown = set(scopes) - VALID_SCOPES
        if unknown:
            raise ValueError(f"Unknown scopes: {', '.join(sorted(unknown))}")
        if not scopes:
            raise ValueError("Select at least one scope")
        if not name.strip():
            raise ValueError("Name is required")
        token_id = uuid.uuid4().hex
        secret = secrets.token_urlsafe(32)
        raw = f"mci_{token_id}.{secret}"
        token_hash = hash_agent_secret(secret, self.pepper)
        created = time.time()
        expires_at = created + expires_days * 86400 if expires_days else None
        self.store.execute(
            "INSERT INTO agent_tokens VALUES(?,?,?,?,?,?,?,?,NULL)",
            (
                token_id,
                name.strip(),
                json.dumps(sorted(set(scopes))),
                "",
                token_hash,
                created,
                expires_at,
                None,
            ),
        )
        return raw, self._public_row(token_id)

    def list_tokens(self) -> list[dict]:
        rows = self.store.rows(
            "SELECT id,name,scopes,created,expires_at,last_used_at,revoked_at FROM agent_tokens ORDER BY created DESC"
        )
        return [
            {
                **row,
                "scopes": json.loads(row["scopes"]),
                "revoked": row["revoked_at"] is not None,
                "expired": row["expires_at"] is not None and row["expires_at"] < time.time(),
            }
            for row in rows
        ]

    def revoke(self, token_id: str) -> bool:
        rows = self.store.rows("SELECT revoked_at FROM agent_tokens WHERE id=?", (token_id,))
        if not rows or rows[0]["revoked_at"]:
            return False
        self.store.execute("UPDATE agent_tokens SET revoked_at=? WHERE id=?", (time.time(), token_id))
        return True

    def verify(self, raw: str) -> VerifiedToken | None:
        parsed = parse_agent_token(raw)
        if not parsed:
            return None
        token_id, secret = parsed
        rows = self.store.rows("SELECT * FROM agent_tokens WHERE id=? AND revoked_at IS NULL", (token_id,))
        if not rows:
            return None
        row = rows[0]
        if row["expires_at"] and row["expires_at"] < time.time():
            return None
        if not hmac.compare_digest(hash_agent_secret(secret, self.pepper), row["token_hash"]):
            return None
        self.store.execute("UPDATE agent_tokens SET last_used_at=? WHERE id=?", (time.time(), token_id))
        return VerifiedToken(row["id"], row["name"], frozenset(json.loads(row["scopes"])))

    async def verify_async(self, raw: str) -> VerifiedToken | None:
        return await asyncio.to_thread(self.verify, raw)

    def audit(self, token_id: str, action: AuditAction, path: str, detail: str = "") -> None:
        self.store.execute(
            "INSERT INTO agent_token_audit(token_id,timestamp,action,path,detail) VALUES(?,?,?,?,?)",
            (token_id, time.time(), action, path[:200], detail[:500]),
        )
        self._prune_audit()

    def _prune_audit(self) -> None:
        days = int(os.environ.get("LOCALCI_AGENT_AUDIT_RETENTION_DAYS", DEFAULT_AUDIT_RETENTION_DAYS))
        max_rows = int(os.environ.get("LOCALCI_AGENT_AUDIT_MAX_ROWS", DEFAULT_AUDIT_MAX_ROWS))
        if days > 0:
            self.store.execute(
                "DELETE FROM agent_token_audit WHERE timestamp < ?",
                (time.time() - days * 86400,),
            )
        if max_rows <= 0:
            return
        (row,) = self.store.rows("SELECT COUNT(*) AS n FROM agent_token_audit")
        excess = row["n"] - max_rows
        if excess > 0:
            self.store.execute(
                "DELETE FROM agent_token_audit WHERE id IN "
                "(SELECT id FROM agent_token_audit ORDER BY id ASC LIMIT ?)",
                (excess,),
            )

    def _public_row(self, token_id: str) -> dict:
        (row,) = self.store.rows(
            "SELECT id,name,scopes,created,expires_at,last_used_at,revoked_at FROM agent_tokens WHERE id=?",
            (token_id,),
        )
        return {
            **row,
            "scopes": json.loads(row["scopes"]),
            "revoked": row["revoked_at"] is not None,
        }


class AgentTokenVerifier:
    """MCP SDK TokenVerifier backed by AgentTokenStore."""

    def __init__(self, token_store: AgentTokenStore):
        self.token_store = token_store

    async def verify_token(self, token: str) -> AccessToken | None:
        verified = await self.token_store.verify_async(token)
        if not verified:
            return None
        return AccessToken(
            token=token,
            client_id=verified.id,
            scopes=sorted(verified.scopes),
            subject=verified.name,
        )


def token_store_from_controller(controller) -> AgentTokenStore:
    pepper = Path(controller.root / "encryption.key").read_bytes()[:32]
    return AgentTokenStore(controller.store, pepper)
