"""Bearer tokens for agent HTTP and MCP access."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from mcp.server.auth.provider import AccessToken

VALID_SCOPES = frozenset({"read", "write-config", "write-runs"})
AuditAction = Literal["auth", "read", "write", "denied"]


@dataclass(frozen=True)
class VerifiedToken:
    id: str
    name: str
    scopes: frozenset[str]


def _hash_token(raw: str, salt: str, pepper: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", raw.encode(), salt.encode() + pepper, 200_000).hex()


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
        raw = f"mci_{secrets.token_urlsafe(32)}"
        salt = secrets.token_hex(16)
        token_hash = _hash_token(raw, salt, self.pepper)
        created = time.time()
        expires_at = created + expires_days * 86400 if expires_days else None
        self.store.execute(
            "INSERT INTO agent_tokens VALUES(?,?,?,?,?,?,?,?,NULL)",
            (
                token_id,
                name.strip(),
                json.dumps(sorted(set(scopes))),
                salt,
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
        if not raw.startswith("mci_"):
            return None
        rows = self.store.rows("SELECT * FROM agent_tokens WHERE revoked_at IS NULL")
        for row in rows:
            if secrets.compare_digest(_hash_token(raw, row["salt"], self.pepper), row["token_hash"]):
                if row["expires_at"] and row["expires_at"] < time.time():
                    return None
                self.store.execute(
                    "UPDATE agent_tokens SET last_used_at=? WHERE id=?", (time.time(), row["id"])
                )
                return VerifiedToken(row["id"], row["name"], frozenset(json.loads(row["scopes"])))
        return None

    def audit(self, token_id: str, action: AuditAction, path: str, detail: str = "") -> None:
        self.store.execute(
            "INSERT INTO agent_token_audit(token_id,timestamp,action,path,detail) VALUES(?,?,?,?,?)",
            (token_id, time.time(), action, path[:200], detail[:500]),
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
        verified = self.token_store.verify(token)
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
