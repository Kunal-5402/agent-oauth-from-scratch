"""Explicit configuration for the small authorization-server deployment."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Values that define this authorization server's security boundary."""

    issuer: str
    key_directory: Path
    resource_audience: str
    access_token_ttl_seconds: int = 600

    def __post_init__(self) -> None:
        if not self.issuer or self.issuer.endswith("/"):
            raise ValueError("issuer must be a non-empty URL without a trailing slash")
        if not self.resource_audience:
            raise ValueError("resource_audience must not be empty")
        if not 1 <= self.access_token_ttl_seconds <= 3600:
            raise ValueError("access_token_ttl_seconds must be between 1 and 3600")

    def url_for(self, path: str) -> str:
        return f"{self.issuer}{path}"


def settings_from_environment() -> Settings:
    """Load deployment configuration; client credentials are loaded separately."""
    return Settings(
        issuer=os.environ.get("OAUTH_ISSUER", "http://127.0.0.1:8000"),
        key_directory=Path(os.environ.get("OAUTH_KEY_DIRECTORY", "keys")),
        resource_audience=os.environ.get("OAUTH_RESOURCE_AUDIENCE", "agent-resource"),
        access_token_ttl_seconds=int(os.environ.get("OAUTH_ACCESS_TOKEN_TTL_SECONDS", "600")),
    )
