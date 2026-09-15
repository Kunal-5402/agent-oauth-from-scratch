"""The shared issuance path. Steps 2 to 5, and the only call to the signer.

Every grant runs the same 5 steps. Only step 1 differs, and step 1 lives in the
grant module. Keeping steps 2 to 5 here means a grant added later inherits every
check instead of having to remember it.

    1. Authenticate the caller      <- the grant, plus src/auth/
    2. Resolve the identity         <- here
    3. Check the identity is usable <- here
    4. Resolve the policy ceiling   <- here
    5. Attenuate the scopes         <- here
"""

from __future__ import annotations

from dataclasses import dataclass

from src.config import Settings
from src.crypto.keys import SigningKey
from src.crypto.tokens import TokenMinter
from src.grants.base import GrantResult
from src.services.scopes import attenuate


@dataclass(frozen=True)
class IssuedToken:
    access_token: str
    expires_in: int
    scope: str


class IssuancePipeline:
    """The single token-issuance chokepoint for every supported grant."""

    def __init__(self, settings: Settings, signing_key: SigningKey) -> None:
        self._settings = settings
        self._minter = TokenMinter(
            issuer=settings.issuer,
            signing_key=signing_key,
            default_ttl_seconds=settings.access_token_ttl_seconds,
        )

    def issue(self, result: GrantResult) -> IssuedToken:
        subject = self._resolve_identity(result)
        self._check_identity_is_usable(subject)
        ceilings = self._resolve_policy(result)
        granted_scopes = attenuate(result.requested_scopes, *ceilings)
        scope = " ".join(granted_scopes)

        claims: dict[str, object] = {
            "sub": subject,
            "aud": self._settings.resource_audience,
            "client_id": result.client_id,
        }
        if scope:
            claims["scope"] = scope
        if result.act is not None:
            claims["act"] = result.act
        if result.task_id is not None:
            claims["task_id"] = result.task_id
        claims.update(result.extra_claims)

        # The minter owns iss, iat, exp and jti, and applies the not_after
        # ceiling. A grant cannot set its own lifetime, which is shrink rule 4
        # held structurally rather than by a check somebody has to remember.
        minted = self._minter.mint(claims, not_after=result.max_expires_at)
        return IssuedToken(
            access_token=minted.token,
            expires_in=minted.expires_in,
            scope=scope,
        )

    @staticmethod
    def _resolve_identity(result: GrantResult) -> str:
        """Step 2. Trivial today; it becomes a repository lookup with storage."""
        return result.subject

    @staticmethod
    def _check_identity_is_usable(subject: str) -> None:
        """Step 3. A deliberate no-op until clients carry lifecycle state.

        This step exists as its own method so the suspended-client refusal
        lands here rather than being folded into authentication. The 2 are
        different questions and must fail independently.
        """

    @staticmethod
    def _resolve_policy(result: GrantResult) -> tuple[frozenset[str], ...]:
        """Step 4. The authority ceilings, in the order the grant supplied them."""
        return result.ceilings
