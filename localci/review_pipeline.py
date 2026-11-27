"""Translate an operator's ordered reviewer chains to the offline mergeCraft roster."""

from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints


# The pinned local review image caps a dispatch at three attempts.
class ReviewSlot(BaseModel):
    label: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=80)]
    model: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*/[A-Za-z0-9][A-Za-z0-9._:/-]*$", max_length=180)
    credential: str = Field(pattern=r"^(?:[A-Z][A-Z0-9_]*_)?API_KEY$", max_length=101)


ReviewChain = Annotated[list[ReviewSlot], Field(min_length=1, max_length=3)]
BUILTIN_KEYS = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GEMINI_API_KEY",
    "cursor": "CURSOR_API_KEY",
    "opencode": "OPENCODE_API_KEY",
    "opencode-go": "OPENCODE_GO_API_KEY",
}


def validate_pipeline(chains: list[ReviewChain]) -> list[ReviewChain]:
    for chain in chains:
        if len({(slot.model, slot.credential) for slot in chain}) != len(chain):
            raise ValueError("Choose a different model or API key for each position in a reviewer chain")
    return chains


def configure_pipeline(config: dict, chains: list, secrets: dict[str, str]) -> tuple[dict, dict]:
    """Keep trusted policies and auxiliary agents. An empty pipeline uses the base roster verbatim."""
    if not chains:
        return secrets, {}
    providers = {p["label"]: p for p in config.get("providers", [])}
    agents = config.get("agents") or {}
    # A local pipeline owns the lens-less reviewers. Keep verifiers, lenses and their policies.
    roster = {k: v for k, v in agents.items() if v.get("lens") or (v.get("role") or k).lower() != "reviewer"}
    env = {}
    routes = {}
    previous = None
    for index, chain in enumerate(chains):
        models = [slot["model"] for slot in chain]
        name = "reviewer" if index == 0 else f"reviewer-{index + 1}"
        if name in roster:
            raise ValueError(f"Trusted auxiliary agent {name} conflicts with the local reviewer pipeline")
        binding = {**agents.get(name, {}), "role": "reviewer", "modelChain": models, "required": True}
        binding.pop("model", None)
        binding.pop("after", None)
        if previous:
            binding["after"] = previous
        roster[name] = binding
        previous = name
        routes[name] = []
        for position, slot in enumerate(chain):
            provider = slot["model"].split("/", 1)[0]
            entry = providers.get(provider)
            if entry:
                if entry.get("authKind", "api_key") != "api_key":
                    raise ValueError(
                        f"{provider} requires a non-API-key credential in the trusted base configuration"
                    )
                target = f"LLM_PROVIDER_{entry['envIndex']}_API_KEY"
            elif provider in BUILTIN_KEYS:
                target = BUILTIN_KEYS[provider]
            else:
                raise ValueError(f"Register provider {provider} in the trusted base mergeCraft configuration")
            source = slot["credential"]
            if source not in secrets:
                raise ValueError(f"Missing review credential {source}")
            private_name = f"LOCALCI_REVIEW_KEY_{index}_{position}"
            env[private_name] = secrets[source]
            env.setdefault(target, secrets[source])  # Native provider availability checks precede dispatch.
            routes[name].append({"model": slot["model"], "target": target, "source": private_name})
    first = [slot["model"] for slot in chains[0]]
    config.update(
        agents=roster,
        models=first,
        modelPin=len(first) == 1,
        allowFallback=any(len(chain) > 1 for chain in chains),
        modelFallbacks={first[0]: []},
    )
    return env, routes
