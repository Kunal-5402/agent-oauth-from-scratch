"""Explicit configuration for the small authorization-server deployment."""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

# Metadata keys a deployment may never set. Imported lazily by the metadata
# module to avoid a circular import; kept here so the refusal happens at
# startup rather than on the first discovery request.
_DERIVED_METADATA_KEYS = frozenset(
    {
        "issuer",
        "token_endpoint",
        "jwks_uri",
        "grant_types_supported",
        "response_types_supported",
        "token_endpoint_auth_methods_supported",
        "code_challenge_methods_supported",
        "dpop_signing_alg_values_supported",
        "introspection_endpoint",
        "revocation_endpoint",
        "scopes_supported",
    }
)


@dataclass(frozen=True)
class Settings:
    """Values that define this authorization server's security boundary."""

    issuer: str
    key_directory: Path
    resource_audience: str
    access_token_ttl_seconds: int = 600
    database_url: str = "postgresql://oauth:oauth@127.0.0.1:5433/oauth"
    metadata_overlay: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.issuer or self.issuer.endswith("/"):
            raise ValueError("issuer must be a non-empty URL without a trailing slash")
        if not self.resource_audience:
            raise ValueError("resource_audience must not be empty")
        if not self.database_url:
            raise ValueError("database_url must not be empty")
        if not 1 <= self.access_token_ttl_seconds <= 3600:
            raise ValueError("access_token_ttl_seconds must be between 1 and 3600")

        declared = _DERIVED_METADATA_KEYS & set(self.metadata_overlay)
        if declared:
            raise ValueError(
                "the metadata overlay may not declare a capability: " + ", ".join(sorted(declared))
            )

    def url_for(self, path: str) -> str:
        return f"{self.issuer}{path}"


def load_metadata_overlay(path: str | Path | None) -> Mapping[str, object]:
    """Read descriptive, deployment-specific metadata values from TOML.

    These are values no registry can derive, such as a documentation URL. A
    missing file is not an error; the overlay is simply empty.
    """
    if not path:
        return {}
    overlay_path = Path(path)
    if not overlay_path.is_file():
        return {}
    with overlay_path.open("rb") as overlay_file:
        return tomllib.load(overlay_file)


def settings_from_environment() -> Settings:
    """Load deployment configuration; client credentials are loaded separately."""
    return Settings(
        issuer=os.environ.get("OAUTH_ISSUER", "http://127.0.0.1:8000"),
        key_directory=Path(os.environ.get("OAUTH_KEY_DIRECTORY", "keys")),
        resource_audience=os.environ.get("OAUTH_RESOURCE_AUDIENCE", "agent-resource"),
        access_token_ttl_seconds=int(os.environ.get("OAUTH_ACCESS_TOKEN_TTL_SECONDS", "600")),
        metadata_overlay=load_metadata_overlay(os.environ.get("OAUTH_METADATA_OVERLAY_PATH")),
    )
