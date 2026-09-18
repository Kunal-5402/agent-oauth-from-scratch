"""The registry of installed grants.

Adding a grant is adding one module and one registration. A grant cannot reach
the signing code except through the shared pipeline, so it cannot skip a check
by forgetting one.
"""

from __future__ import annotations

from collections.abc import Iterable

from src.crypto.tokens import TokenVerifier
from src.errors import OAuthError
from src.grants.base import Grant, GrantResult
from src.grants.client_credentials import ClientCredentialsGrant
from src.grants.token_exchange import TokenExchangeGrant
from src.storage.repositories import ClientRepository

__all__ = [
    "ClientCredentialsGrant",
    "Grant",
    "GrantRegistry",
    "GrantResult",
    "TokenExchangeGrant",
    "default_grant_registry",
]


class GrantRegistry:
    def __init__(self, grants: Iterable[Grant]) -> None:
        installed = tuple(grants)
        self._grants = {grant.grant_type: grant for grant in installed}
        if len(self._grants) != len(installed):
            raise ValueError("grant types must be unique")

    def get(self, grant_type: str) -> Grant:
        grant = self._grants.get(grant_type)
        if grant is None:
            raise OAuthError("unsupported_grant_type", "grant type is not supported", 400)
        return grant

    def grant_types(self) -> frozenset[str]:
        """The value advertised as grant_types_supported."""
        return frozenset(self._grants)

    def response_types(self) -> frozenset[str]:
        """The value advertised as response_types_supported."""
        return frozenset().union(*(g.response_types for g in self._grants.values()))

    def all(self) -> tuple[Grant, ...]:
        return tuple(self._grants.values())


def default_grant_registry(
    *, verifier: TokenVerifier, clients: ClientRepository, maximum_depth: int
) -> GrantRegistry:
    """Every grant this server supports today.

    Adding a grant is adding one module and one entry here. It cannot reach the
    signer except through the shared pipeline, so it cannot skip a check.
    """
    return GrantRegistry(
        [
            ClientCredentialsGrant(),
            TokenExchangeGrant(verifier=verifier, clients=clients, maximum_depth=maximum_depth),
        ]
    )
