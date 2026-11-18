"""Fail image builds if the consumer configuration/packet contract regresses."""

from mergecraft.config.settings import RepoSettings
from mergecraft.evidence.packet import PACKET_SCHEMA_VERSION

settings = RepoSettings.model_validate(
    {
        "models": ["opencode-go/deepseek-v4.1-flash"],
        "modelPin": True,
        "allowFallback": False,
        "providers": [{"label": "opencode-go", "harness": "opencode", "envIndex": 1, "authKind": "api_key"}],
        "review": {"ignorePaths": ["**/.env", "**/*.pem", "reports/**"]},
        "push": "disabled",
        "shell": "disabled",
        "prApproveEnabled": False,
        "autoMergeEnabled": False,
        "trust": {"selfReview": "off", "agentSandbox": "never"},
    }
)
assert settings.review.ignore_paths == ["**/.env", "**/*.pem", "reports/**"]
assert PACKET_SCHEMA_VERSION == "1.21.0"
print("PASS: consumer ignorePaths configuration and evidence schema supported")
