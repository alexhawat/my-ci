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


# The secrets context, not a property such as needs.scan.outputs.secrets-found or
# inputs.secrets.TOKEN: never preceded by ".", a word character or "-".
_CONTEXT = r"(?<![.\w-])secrets"
_SECRET_NAME = re.compile(_CONTEXT + r"\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)(?![\w-])", re.I)
_SECRET_INDEX = re.compile(_CONTEXT + r"\s*\[\s*(?:'([^'\]]+)'|\"([^\"\]]+)\")\s*\]", re.I)
# Access that cannot be resolved statically: toJSON(secrets), secrets.*, secrets[<expr>].
_SECRET_DYNAMIC = re.compile(
    r"toJSON\s*\(\s*secrets\s*\)|"
    + _CONTEXT
    + r"\s*\.\s*\*|"
    + _CONTEXT
    + r"\s*\[(?!\s*(?:'[^'\]]+'|\"[^\"\]]+\")\s*\])",
    re.I,
)
_STRING_LITERAL = re.compile(r"'(?:[^']|'')*'")
# A context indexed by a string literal that must survive _code: secrets['NAME'] names
# a secret and github['token'] is github.token.
_INDEXED_CONTEXT = re.compile(r"(?<![.\w-])(?:secrets|github)\s*\[\s*\Z", re.I)
_INDEX_AFTER = re.compile(r"\s*\]")
# Longest text before a literal that _INDEXED_CONTEXT needs to see, blanks included.
_INDEX_CONTEXT_WINDOW = 256


def _embedded_expressions(text: str) -> list[str]:
    """The inside of every ``${{ }}`` in ``text``.

    The closing braces are searched outside single-quoted string literals:
    ``format('{{ {0} }}', secrets.X)`` contains ``}}`` without ending there.
    An unterminated expression extends to the end of the text.
    """
    found, position = [], 0
    while (start := text.find("${{", position)) >= 0:
        index = start + 3
        while index < len(text):
            if text[index] == "'":
                literal = _STRING_LITERAL.match(text, index)
                index = literal.end() if literal else len(text)
            elif text.startswith("}}", index):
                break
            else:
                index += 1
        found.append(text[start + 3 : index])
        position = index + 2
    return found


def _code(expression: str) -> str:
    """The expression with string literals emptied, so words inside text such as
    ``'rotate secrets'`` are not read as references. A literal used as the index
    of ``secrets[...]`` or ``github[...]`` is kept: it names the secret or property.

    Linear: only a bounded stretch before each literal is inspected (an index
    padded with more blanks than that is emptied, which reads as dynamic access,
    the safe direction for secrets).
    """

    def replace(match: re.Match) -> str:
        start = match.start()
        before = expression[max(0, start - _INDEX_CONTEXT_WINDOW) : start]
        if _INDEXED_CONTEXT.search(before) and _INDEX_AFTER.match(expression, match.end()):
            return match.group()
        return "''"

    return _STRING_LITERAL.sub(replace, expression)


_BARE_SECRETS = re.compile(_CONTEXT + r"(?![\w-])(?!\s*[.\[])", re.I)
_GITHUB_TOKEN = re.compile(r"(?<![.\w-])github\s*(?:\.\s*token(?![\w-])|\[\s*['\"]token['\"]\s*\])", re.I)


def _expressions(document, conditional: bool = False):
    """Text GitHub Actions evaluates as an expression: the inside of every ``${{ }}``,
    plus whole ``if:`` values, which are expressions without the braces.

    Shell and program text in ``run:`` is not an expression; ``app.secrets['x']``
    in a script is the program's own variable, not a workflow secret.
    """
    if isinstance(document, str):
        yield from map(_code, _embedded_expressions(document))
        if conditional and "${{" not in document:
            yield _code(document)
    elif isinstance(document, dict):
        for key, value in document.items():
            yield from _expressions(key)
            yield from _expressions(value, conditional=key == "if")
    elif isinstance(document, (list, tuple)):
        for value in document:
            yield from _expressions(value)


def secret_references(document) -> tuple[set[str], bool]:
    """Secret names a workflow fragment references, and whether any access is dynamic.

    Supports ``secrets.NAME`` and ``secrets['NAME']``/``secrets["NAME"]``. Dynamic
    access (``toJSON(secrets)``, ``secrets.*``, ``secrets[<expression>]`` or a bare
    ``secrets`` inside ``${{ }}``) means "may read every configured secret".
    """
    names: set[str] = set()
    dynamic = False
    for expression in _expressions(document):
        names.update(_SECRET_NAME.findall(expression))
        names.update(a or b for a, b in _SECRET_INDEX.findall(expression))
        if _SECRET_DYNAMIC.search(expression) or _BARE_SECRETS.search(expression):
            dynamic = True
    return names, dynamic


def github_token_referenced(document) -> bool:
    """``github.token`` (act derives it from the GITHUB_TOKEN secret) or the secret itself."""
    names, dynamic = secret_references(document)
    return (
        dynamic
        or bool({n.upper() for n in names} & {"GITHUB_TOKEN", "GH_TOKEN"})
        or any(_GITHUB_TOKEN.search(expression) for expression in _expressions(document))
    )


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
        scope = {"workflow_env": data.get("env"), "job": job}
        # Dynamic access (toJSON(secrets), secrets[expr]) adds no statically known
        # requirement; explicitly named secrets are still required.
        required, _ = secret_references(scope)
        configured = {name.upper() for name in available_secrets}
        missing = {name for name in required if name.upper() not in configured}
        if missing:
            raise Blocked(f"{jid}: local secrets required: {', '.join(sorted(missing))}")
        if (
            any(_GITHUB_TOKEN.search(expression) for expression in _expressions(scope))
            and "GITHUB_TOKEN" not in configured
        ):
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


def bot_pr(pr: dict) -> bool:
    """Bot-authored PRs (dependency updaters and similar) carry third-party content."""
    user = pr.get("user") or {}
    return user.get("type") == "Bot" or user.get("login", "").casefold().endswith("[bot]")


BOT_HOLD = "Bot-authored PR awaiting operator approval; review the change, then run it from the dashboard"


def dependabot_pr(pr: dict) -> bool:
    """Branch names are collaborator-controlled; only the PR author proves origin."""
    return (pr.get("user") or {}).get("login", "").casefold() == "dependabot[bot]"
