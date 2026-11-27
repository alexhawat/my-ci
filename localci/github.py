import asyncio
import base64
import json
import time
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PR_CHECKS_QUERY = """
query($owner: String!, $name: String!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    mergeCommitAllowed
    squashMergeAllowed
    rebaseMergeAllowed
    viewerDefaultMergeMethod
    pullRequests(states: OPEN, first: 50, after: $cursor, orderBy: {field: UPDATED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number
        headRefOid
        mergeable
        mergeStateStatus
        reviewDecision
        commits(last: 1) {
          nodes {
            commit {
              statusCheckRollup {
                contexts(first: 100) {
                  totalCount
                  nodes {
                    __typename
                    ... on CheckRun {
                      name
                      status
                      conclusion
                      detailsUrl
                      checkSuite { workflowRun { workflow { name } } }
                    }
                    ... on StatusContext { context state targetUrl }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
"""


# The name of the commit status context and Check Run this service publishes.
CHECK_NAME = "my-ci"
# The name it published under before the rename. Still read, so that a result posted
# under it before the rename is renamed in place or retired instead of left beside the
# new one. Remove once no open PR's head commit carries a local-ci result: every PR
# opened before the rename has been pushed to, re-run or closed.
LEGACY_CHECK_NAME = "local-ci"
RETIRED_SUMMARY = f"Renamed to {CHECK_NAME}; see the {CHECK_NAME} result for this commit."


class GitHubError(RuntimeError):
    def __init__(self, status: int, method: str, path: str, retry_after: float | None = None):
        self.status, self.method, self.path = status, method, path.split("?")[0]
        # Seconds GitHub asked the client to wait (rate limits), when it said so.
        self.retry_after = retry_after
        super().__init__(f"GitHub returned HTTP {status} for {method} {self.path}")


def retry_after(headers) -> float | None:
    """GitHub's requested wait: ``Retry-After`` (secondary limits) or the reset time of
    an exhausted primary limit. Bounded, so a bad header cannot park work for days."""
    try:
        if headers.get("retry-after"):
            wait = float(headers["retry-after"])
        elif headers.get("x-ratelimit-remaining") == "0" and headers.get("x-ratelimit-reset"):
            wait = float(headers["x-ratelimit-reset"]) - time.time()
        else:
            return None
    except ValueError:
        return None
    return min(max(wait, 0.0), 3600.0)


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
                raise GitHubError(response.status_code, method, path, retry_after(response.headers))
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
        # Exactly max_pages full pages is a complete list; only a further item is an overflow.
        if not await self.request("GET", f"{path}{separator}per_page=1&page={max_pages * 100 + 1}"):
            return result
        raise RuntimeError(f"GitHub pagination exceeded {max_pages} pages; refusing a partial result")

    async def graphql(self, query: str, variables: dict) -> dict:
        result = await self.request("POST", "graphql", json={"query": query, "variables": variables})
        if not isinstance(result, dict) or result.get("errors") or not result.get("data"):
            # GraphQL reports failures with HTTP 200; never echo arbitrary server text.
            raise RuntimeError("GitHub GraphQL query failed")
        return result["data"]

    async def pull_request_checks(self, repo: str, *, max_pages: int = 4) -> dict:
        """GitHub's own view of a repository's open PRs: checks and statuses on each
        head commit, mergeability, and the merge methods the repository allows."""
        owner, name = repo.split("/", 1)
        prs, cursor, repository = [], None, {}
        for _ in range(max_pages):
            data = await self.graphql(PR_CHECKS_QUERY, {"owner": owner, "name": name, "cursor": cursor})
            repository = data.get("repository") or {}
            page = repository.get("pullRequests") or {}
            prs.extend(page.get("nodes") or [])
            info = page.get("pageInfo") or {}
            if not info.get("hasNextPage"):
                break
            cursor = info.get("endCursor")
        methods = [
            method
            for method, key in (
                ("merge", "mergeCommitAllowed"),
                ("squash", "squashMergeAllowed"),
                ("rebase", "rebaseMergeAllowed"),
            )
            if repository.get(key)
        ]
        default = str(repository.get("viewerDefaultMergeMethod") or "").lower()
        if default in methods:
            methods.insert(0, methods.pop(methods.index(default)))
        return {"merge_methods": methods, "prs": {pr["number"]: pr for pr in prs if pr}}

    async def merge(self, repo: str, number: int, sha: str, method: str):
        """Merge as the authenticated user. ``sha`` binds the merge to the head commit the
        operator saw: GitHub refuses with HTTP 409 when the PR has moved on."""
        return await self.request(
            "PUT", f"repos/{repo}/pulls/{number}/merge", json={"sha": sha, "merge_method": method}
        )

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
                await self.retire_legacy_status(run, url)
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
                "context": CHECK_NAME,
                "description": description[:140],
                "target_url": url,
            },
        )
        await self.retire_legacy_status(run, url)
        return "GitHub commit status via gh login" + (
            " (App has no repository installation access)" if credentials else ""
        )

    async def retire_legacy_status(self, run: dict, url: str):
        """Overwrite a ``local-ci`` commit status left on this head before the rename.

        A commit status cannot be removed or made neutral, and GitHub shows the latest
        status of every context, so an old failure would otherwise stay next to the new
        result. It is replaced once with a success that says where the result went;
        nothing in GitHub requires the retired context.
        """
        combined = await self.request(
            "GET", f"repos/{run['repo']}/commits/{run['head']}/status", params={"per_page": 100}
        )
        legacy = next(
            (s for s in (combined or {}).get("statuses") or [] if s.get("context") == LEGACY_CHECK_NAME),
            None,
        )
        if legacy and (legacy.get("state"), legacy.get("description")) != ("success", RETIRED_SUMMARY):
            await self.request(
                "POST",
                f"repos/{run['repo']}/statuses/{run['head']}",
                json={
                    "state": "success",
                    "context": LEGACY_CHECK_NAME,
                    "description": RETIRED_SUMMARY,
                    "target_url": url,
                },
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
            # This App's latest runs on the head under the current and the retired name.
            existing = []
            for name in (CHECK_NAME, LEGACY_CHECK_NAME):
                listed = await self.request(
                    "GET",
                    f"repos/{run['repo']}/commits/{run['head']}/check-runs",
                    credential=token,
                    params={"check_name": name, "filter": "latest", "per_page": 100},
                )
                existing += [
                    (name, c)
                    for c in listed["check_runs"]
                    if str(c["app"]["id"]) == str(credentials["app_id"])
                ]
            # A run that started before the rename is found by its external ID under the
            # old name, and the PATCH below renames it in place rather than adding a second.
            match = next((c for _, c in existing if c.get("external_id") == run["id"]), None)
            steps = json.loads(run.get("steps", "[]"))
            payload = {
                "name": CHECK_NAME,
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
            # Another run's result under the old name would otherwise stay next to this
            # one. Neutral is GitHub's "does not count" conclusion; it is set only once.
            retired = {match["id"]} if match else set()
            for name, legacy in existing:
                if (
                    name != LEGACY_CHECK_NAME
                    or legacy["id"] in retired
                    or legacy.get("conclusion") == "neutral"
                ):
                    continue
                retired.add(legacy["id"])
                await self.request(
                    "PATCH",
                    f"{endpoint}/{legacy['id']}",
                    credential=token,
                    json={
                        "status": "completed",
                        "conclusion": "neutral",
                        "output": {"title": f"Renamed to {CHECK_NAME}", "summary": RETIRED_SUMMARY},
                    },
                )
        finally:
            # Short-lived and repository-scoped, and never shared with a worker.
            try:
                await self.request("DELETE", "installation/token", credential=token)
            except RuntimeError:
                pass
