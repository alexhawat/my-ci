import asyncio
import base64
import json
import time
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class GitHubError(RuntimeError):
    def __init__(self, status: int, method: str, path: str):
        self.status, self.method, self.path = status, method, path.split("?")[0]
        super().__init__(f"GitHub returned HTTP {status} for {method} {self.path}")


def app_jwt(app_id: str, private_key: str) -> str:
    key = serialization.load_pem_private_key(private_key.encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("GitHub App requires an RSA private key")

    def encode(value: bytes):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

    now = int(time.time())
    header = encode(b'{"alg":"RS256","typ":"JWT"}')
    payload = encode(json.dumps({"iat": now - 60, "exp": now + 540, "iss": app_id}).encode())
    signing = f"{header}.{payload}"
    return signing + "." + encode(key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256()))


class GitHub:
    def __init__(self, token_path: Path, app_credentials=None):
        self.token_path = token_path
        self.app_credentials = app_credentials

    def token(self) -> str:
        token = self.token_path.read_text().strip()
        if not token:
            raise RuntimeError("GitHub login required: run the host login script")
        return token

    async def request(self, method: str, path: str, *, credential: str | None = None, **kwargs) -> Any:
        async with httpx.AsyncClient(
            base_url="https://api.github.com/",
            headers={
                "Authorization": f"Bearer {credential or self.token()}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=40,
        ) as client:
            response = await client.request(method, path, **kwargs)
            if response.status_code >= 400:
                # Do not include request headers, repository payloads, or arbitrary server text.
                raise GitHubError(response.status_code, method, path)
            return response.json() if response.content else None

    async def pages(self, path: str, *, max_pages: int = 100, truncate: bool = False) -> list:
        """Fetch every page. A caller that acts on the complete list (stale-run
        cancellation, comment lookup) must never get a silently shortened one, so
        hitting the cap is an error unless the caller opts into truncation."""
        result = []
        separator = "&" if "?" in path else "?"
        for page in range(1, max_pages + 1):
            values = await self.request("GET", f"{path}{separator}per_page=100&page={page}")
            result.extend(values)
            if len(values) < 100:
                return result
        if truncate:
            return result
        raise RuntimeError(f"GitHub pagination exceeded {max_pages} pages; refusing a partial result")

    async def discover(self):
        user, repos = await asyncio.gather(
            self.request("GET", "user"),
            self.pages("user/repos?affiliation=owner,collaborator,organization_member"),
        )
        return user["login"], [r for r in repos if not r["archived"] and r.get("permissions", {}).get("push")]

    async def content(self, repo: str, path: str, ref: str) -> str:
        result = await self.request("GET", f"repos/{repo}/contents/{path}", params={"ref": ref})
        return base64.b64decode(result["content"]).decode()

    async def status(self, run: dict, state: str, description: str, url: str):
        credentials = self.app_credentials() if self.app_credentials else {}
        if credentials:
            try:
                await self.check_run(run, state, description, url, credentials)
                return "GitHub App Check Run"
            except GitHubError as exc:
                if (
                    exc.status != 404
                    or exc.method != "GET"
                    or exc.path != f"repos/{run['repo']}/installation"
                ):
                    raise
                # No installation access: the existing gh login can publish a
                # normal commit status without changing App permissions.

        await self.request(
            "POST",
            f"repos/{run['repo']}/statuses/{run['head']}",
            json={
                "state": state,
                "context": "local-ci",
                "description": description[:140],
                "target_url": url,
            },
        )
        return "GitHub commit status via gh login" + (
            " (App has no repository installation access)" if credentials else ""
        )

    async def comment(self, run: dict, kind: str, body: str):
        if kind == "review":
            return await self.review(run, body)
        # One CI comment per run, owned by the authenticated reporting user.
        # A retry after an ambiguous POST finds the marker rather than duplicating it.
        user = await self.request("GET", "user")
        endpoint = f"repos/{run['repo']}/issues/{run['pr']}/comments"
        marker = f"<!-- localci:ci:v2:{run['id']} -->"
        comments = await self.pages(endpoint)
        existing = next(
            (
                c
                for c in comments
                if c.get("body", "").startswith(marker) and c.get("user", {}).get("id") == user["id"]
            ),
            None,
        )
        if existing:
            if existing["body"] != body:
                await self.request(
                    "PATCH", f"repos/{run['repo']}/issues/comments/{existing['id']}", json={"body": body}
                )
        else:
            await self.request("POST", endpoint, json={"body": body})

    async def review(self, run: dict, body: str):
        """One native COMMENT review per run, including ambiguous-POST recovery.

        Never approve or request changes on behalf of the authenticated user.
        Bind both the marker and GitHub review to the reviewed commit.
        """
        user = await self.request("GET", "user")
        endpoint = f"repos/{run['repo']}/pulls/{run['pr']}/reviews"
        marker = f"<!-- localci:review:v2:{run['id']} -->"
        body = marker + "\n" + body
        existing = next(
            (
                item
                for item in await self.pages(endpoint)
                if item.get("body", "").startswith(marker)
                and item.get("user", {}).get("id") == user["id"]
                and item.get("commit_id") == run["head"]
                and item.get("state") == "COMMENTED"
            ),
            None,
        )
        if existing:
            if existing["body"] != body:
                await self.request("PUT", f"{endpoint}/{existing['id']}", json={"body": body})
            review = existing
        else:
            review = await self.request(
                "POST", endpoint, json={"event": "COMMENT", "commit_id": run["head"], "body": body}
            )
        # Migrate an existing v1 discussion comment without creating a third
        # notification. New PRs receive only the CI comment and native review.
        if review.get("html_url"):
            marker = "<!-- localci:review:v1 -->"
            legacy_body = (
                f"{marker}\nmergeCraft now publishes native PR reviews.\n\n"
                f"[Full review for `{run['head']}`]({review['html_url']}) · run `{run['id']}`"
            )
            for item in await self.pages(f"repos/{run['repo']}/issues/{run['pr']}/comments"):
                if (
                    item.get("body", "").startswith(marker)
                    and item.get("user", {}).get("id") == user["id"]
                    and item["body"] != legacy_body
                ):
                    await self.request(
                        "PATCH",
                        f"repos/{run['repo']}/issues/comments/{item['id']}",
                        json={"body": legacy_body},
                    )
        return review

    async def check_run(self, run: dict, state: str, description: str, url: str, credentials: dict):
        jwt = app_jwt(credentials["app_id"], credentials["private_key"])
        installation = await self.request("GET", f"repos/{run['repo']}/installation", credential=jwt)
        issued = await self.request(
            "POST",
            f"app/installations/{installation['id']}/access_tokens",
            credential=jwt,
            json={"repositories": [run["repo"].split("/")[1]], "permissions": {"checks": "write"}},
        )
        token = issued["token"]
        try:
            existing = await self.request(
                "GET",
                f"repos/{run['repo']}/commits/{run['head']}/check-runs",
                credential=token,
                params={"check_name": "local-ci", "filter": "latest", "per_page": 100},
            )
            match = next(
                (
                    c
                    for c in existing["check_runs"]
                    if c.get("external_id") == run["id"] and str(c["app"]["id"]) == str(credentials["app_id"])
                ),
                None,
            )
            steps = json.loads(run.get("steps", "[]"))
            payload = {
                "name": "local-ci",
                "head_sha": run["head"],
                "external_id": run["id"],
                "details_url": url,
                "status": "in_progress" if state == "pending" else "completed",
                "output": {
                    "title": description[:250],
                    "summary": "\n".join(f"- **{s['name']}**: {s['state']} — {s['message']}" for s in steps)[
                        :60000
                    ]
                    or description,
                },
            }
            if state != "pending":
                payload["conclusion"] = {"success": "success", "failure": "failure"}.get(
                    state, "action_required"
                )
                if run["state"] == "cancelled":
                    payload["conclusion"] = "cancelled"
            endpoint = f"repos/{run['repo']}/check-runs"
            if match:
                payload.pop("head_sha")
                await self.request("PATCH", f"{endpoint}/{match['id']}", credential=token, json=payload)
            else:
                await self.request("POST", endpoint, credential=token, json=payload)
        finally:
            # Short-lived and repository-scoped, and never shared with a worker.
            try:
                await self.request("DELETE", "installation/token", credential=token)
            except RuntimeError:
                pass
