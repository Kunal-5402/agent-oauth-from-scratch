"""Domain records shared by the storage layer and the services above it.

This module imports nothing from the rest of the package. Both the repository
that reads a client and the registry that authenticates one need this type, and
a leaf module is what keeps that from becoming a circular import.
"""

from __future__ import annotations

from dataclasses import dataclass

ACTIVE = "active"
SUSPENDED = "suspended"


@dataclass(frozen=True)
class RegisteredClient:
    """A stored client. The secret is never held in plain text."""

    client_id: str
    subject: str
    allowed_scopes: frozenset[str] = frozenset()
    allowed_audiences: frozenset[str] = frozenset()
    status: str = ACTIVE
    secret_hash: str | None = None
    auth_method: str = "client_secret_post"

    def __post_init__(self) -> None:
        if not self.client_id or not self.subject:
            raise ValueError("client_id and subject must not be empty")
        if self.status not in (ACTIVE, SUSPENDED):
            raise ValueError(f"unknown client status: {self.status}")


@dataclass(frozen=True)
class ClientKey:
    """One public key a client may sign a client assertion with."""

    client_id: str
    kid: str
    public_jwk: dict[str, object]
