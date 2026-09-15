"""The client authentication contract.

Client authentication answers "which registered client is calling". It is
deliberately separate from the grant type, which answers "where does the
authority in the new token come from". The 2 are orthogonal: every method here
applies to every grant that needs a client.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from src.api.forms import TokenForm


@dataclass(frozen=True)
class ClientCredentials:
    """Credentials as presented, before they are verified against the registry."""

    client_id: str
    client_secret: str
    method: str


@runtime_checkable
class ClientAuthMethod(Protocol):
    """One way for a client to present its credentials."""

    name: str

    def extract(self, headers: Mapping[str, str], form: TokenForm) -> ClientCredentials | None:
        """Return credentials when this method was used, else None.

        Raise OAuthError only when this method was clearly attempted and is
        malformed. Returning None means "not my method", which lets the
        registry detect a caller using 2 methods at once.
        """
