import copy
import re

import yaml


class Blocked(RuntimeError):
    pass


class WorkflowLoader(yaml.SafeLoader):
    pass


WorkflowLoader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in values if tag != "tag:yaml.org,2002:bool"]
    for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$", re.I), list("tTfF")
)


def workflow(text: str) -> dict:
    # YAML 1.2 booleans: preserve 'on' while keeping true/false typed correctly.
    data = yaml.load(text, Loader=WorkflowLoader)
    if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict):
        raise Blocked("Invalid workflow: expected a jobs mapping")
    return data


def is_pr_workflow(data: dict) -> bool:
    events = data.get("on") or {}
    return events == "pull_request" if isinstance(events, str) else "pull_request" in events


def plan(text: str, available_secrets: set[str], variables: dict[str, str]) -> tuple[dict, list[str]]:
    """Reject unsupported execution instead of silently dropping mandatory checks."""
    data = workflow(text)
    if not is_pr_workflow(data):
        raise Blocked("Only pull_request CI workflows are supported; deployment workflows are excluded")
    result = copy.deepcopy(data)
    notes = []
    for jid, job in result["jobs"].items():
        condition = str(job.get("if", ""))
        var_condition = re.fullmatch(r"\s*(?:\$\{\{\s*)?vars\.(\w+)\s*==\s*'true'\s*(?:\}\})?\s*", condition)
        if var_condition and variables.get(var_condition[1]) != "true":
            notes.append(f"{jid}: disabled by local vars.{var_condition[1]}")
            continue
        if "uses" in job:
            raise Blocked(f"{jid}: reusable workflow requires a local adapter")
        if job.get("environment"):
            raise Blocked(f"{jid}: deployment environments require GitHub approval semantics")
        runners = str(job.get("runs-on", ""))
        if "matrix." in runners:
            matrix = job.get("strategy", {}).get("matrix", {})
            if any("macos" in str(v).lower() or "windows" in str(v).lower() for v in matrix.values()):
                raise Blocked(f"{jid}: macOS/Windows matrix cannot execute in Linux Docker")
        elif "ubuntu" not in runners:
            raise Blocked(f"{jid}: unsupported runner {runners}")
        permissions = job.get("permissions", data.get("permissions", {}))
        if isinstance(permissions, dict) and permissions.get("id-token") == "write":
            raise Blocked(f"{jid}: GitHub OIDC is unavailable locally")
        for step in job.get("steps", []):
            uses = step.get("uses", "")
            if "mergecraft" in uses.lower():
                raise Blocked(
                    "Use the separate mergeCraft review toggle instead of its GitHub Action workflow"
                )
            if uses.startswith("github/codeql-action/"):
                raise Blocked("CodeQL requires a separately configured local adapter and applicable license")
            if uses.startswith("actions/checkout@"):
                checkout = step.get("with", {})
                if any(
                    checkout.get(k)
                    for k in ("repository", "ref", "path", "submodules", "lfs", "sparse-checkout")
                ):
                    raise Blocked(f"{jid}: custom checkout settings need a local adapter")
            if uses.startswith("gitleaks/gitleaks-action@"):
                # Its wrapper fetches GitHub metadata and may require an org license.
                # Run the same pinned open-source scanner against local full history.
                version = step.get("env", {}).get("GITLEAKS_VERSION", "8.30.1")
                if not re.fullmatch(r"\d+\.\d+\.\d+", version):
                    raise Blocked("Gitleaks requires an explicit numeric version")
                step.clear()
                step.update(
                    {
                        "name": "Gitleaks (local full-history adapter)",
                        "run": f'docker run --rm -v "$PWD:/repo:ro" zricethezav/gitleaks:v{version} git /repo --redact --no-banner',
                    }
                )
                notes.append(f"{jid}: Gitleaks v{version} scans full history locally; no GitHub API token")
        required = set(
            re.findall(
                r"secrets\.([A-Za-z_][A-Za-z0-9_]*)",
                yaml.safe_dump({"workflow_env": data.get("env"), "job": job}),
            )
        )
        missing = required - available_secrets
        if missing:
            raise Blocked(f"{jid}: local secrets required: {', '.join(sorted(missing))}")
        if re.search(r"github\.token", yaml.safe_dump(job)) and "GITHUB_TOKEN" not in available_secrets:
            raise Blocked(f"{jid}: enable GitHub authentication in repository settings for github.token")
        if job.get("runs-on") in {"ubuntu-latest", "ubuntu-24.04"} and not job.get("container"):
            setup = {
                "name": "Prepare local runner workspace",
                "run": 'sudo chown -R "$(id -u):$(id -g)" "$GITHUB_WORKSPACE" /var/run/act\nsudo chgrp "$(id -g)" /var/run/docker.sock\nsudo chmod g+rw /var/run/docker.sock',
            }
            steps = job.get("steps", [])
            # act's local checkout copies tracked files; fix their ownership immediately afterwards.
            index = next(
                (i + 1 for i, s in enumerate(steps) if s.get("uses", "").startswith("actions/checkout@")), 0
            )
            steps.insert(index, setup)
    return result, notes


def eligible(pr: dict, repo: str) -> bool:
    return (
        not pr["draft"] and pr["state"] == "open" and (pr["head"].get("repo") or {}).get("full_name") == repo
    )


def review_state(code: int) -> tuple[str, str]:
    return {
        0: ("success", "Review passed"),
        10: ("success", "Review completed with non-blocking findings"),
        11: ("failure", "Blocking review findings"),
        12: ("failure", "Review failed"),
        20: ("blocked", "Review inconclusive"),
        30: ("blocked", "Review configuration required"),
        40: ("error", "Review provider/infrastructure failure"),
        50: ("error", "Review timed out"),
    }.get(code, ("error", f"Review exited {code}"))


def dependabot_pr(pr: dict) -> bool:
    """Branch names are collaborator-controlled; only the PR author proves origin."""
    return (pr.get("user") or {}).get("login", "").casefold() == "dependabot[bot]"
