"""Versioned HTTP API for autonomous agents."""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel

from localci.agent_service import AgentService
from localci.agent_tokens import AgentTokenStore, AuditAction, VerifiedToken


class AgentRepoPatch(BaseModel):
    enabled: bool | None = None
    review: bool | None = None


def _bearer(authorization: Annotated[str | None, Header()] = None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Bearer token required")
    return authorization[7:].strip()


def register_agent_api(main_app, controller, token_store: AgentTokenStore, *, addon_enabled) -> None:
    router = APIRouter()

    async def require_token(raw: str = Depends(_bearer)) -> VerifiedToken:
        if not addon_enabled():
            raise HTTPException(404, "Agent access is disabled")
        verified = await token_store.verify_async(raw)
        if not verified:
            token_store.audit("anonymous", "denied", "api", "invalid token")
            raise HTTPException(401, "Invalid or expired token")
        return verified

    def service(token: VerifiedToken = Depends(require_token)) -> AgentService:
        return AgentService(controller, token.scopes)

    def audit(token: VerifiedToken, request: Request, action: AuditAction, detail: str = "") -> None:
        token_store.audit(token.id, action, request.url.path, detail)

    @router.get("/repos")
    def list_repos(
        request: Request, svc: AgentService = Depends(service), token: VerifiedToken = Depends(require_token)
    ):
        audit(token, request, "read")
        return svc.list_repos()

    @router.get("/runs")
    def list_runs(
        request: Request,
        repo: str | None = None,
        state: str | None = None,
        limit: int = Query(50, ge=1, le=200),
        svc: AgentService = Depends(service),
        token: VerifiedToken = Depends(require_token),
    ):
        audit(token, request, "read")
        return svc.list_runs(repo=repo, state=state, limit=limit)

    @router.get("/runs/{run_id}")
    def get_run(
        run_id: str,
        request: Request,
        svc: AgentService = Depends(service),
        token: VerifiedToken = Depends(require_token),
    ):
        if not re.fullmatch(r"[0-9a-f]{32}", run_id):
            raise HTTPException(404)
        audit(token, request, "read")
        return svc.get_run(run_id)

    @router.get("/runs/{run_id}/review")
    def get_review(
        run_id: str,
        request: Request,
        svc: AgentService = Depends(service),
        token: VerifiedToken = Depends(require_token),
    ):
        audit(token, request, "read")
        return svc.get_review(run_id)

    @router.get("/runs/{run_id}/logs/meta")
    def logs_meta(
        run_id: str,
        request: Request,
        svc: AgentService = Depends(service),
        token: VerifiedToken = Depends(require_token),
    ):
        audit(token, request, "read")
        return svc.logs_metadata(run_id)

    @router.get("/queue")
    def queue(
        request: Request, svc: AgentService = Depends(service), token: VerifiedToken = Depends(require_token)
    ):
        audit(token, request, "read")
        return svc.queue_status()

    @router.post("/runs/{run_id}/retry")
    async def retry(
        run_id: str,
        request: Request,
        svc: AgentService = Depends(service),
        token: VerifiedToken = Depends(require_token),
    ):
        audit(token, request, "write", "retry")
        return await svc.rerun(run_id)

    @router.patch("/repos/{owner}/{repo}")
    def patch_repo(
        owner: str,
        repo: str,
        body: AgentRepoPatch,
        request: Request,
        svc: AgentService = Depends(service),
        token: VerifiedToken = Depends(require_token),
    ):
        audit(token, request, "write", "repo patch")
        return svc.set_repo_review(f"{owner}/{repo}", enabled=body.enabled, review=body.review)

    agent_app = FastAPI(
        title="my-ci Agent API",
        version="1.0.0",
        description="Tailnet-only programmatic access to my-ci. Authenticate with `Authorization: Bearer <token>`.",
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url=None,
    )
    agent_app.include_router(router)
    main_app.mount("/api/agent/v1", agent_app)
