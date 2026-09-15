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
from src.errors import OAuthError
from src.grants.base import GrantResult
from src.models import ACTIVE
from src.services.scopes import attenuate
from src.storage.repositories import IssuanceRecord, IssuedCredentialRepository


@dataclass(frozen=True)
class IssuedToken:
    access_token: str
    expires_in: int
    scope: str


class IssuancePipeline:
    """The single token-issuance chokepoint for every supported grant."""

    def __init__(
        self,
        settings: Settings,
        signing_key: SigningKey,
        credentials: IssuedCredentialRepository,
    ) -> None:
        self._settings = settings
        self._credentials = credentials
        self._minter = TokenMinter(
            issuer=settings.issuer,
            signing_key=signing_key,
            default_ttl_seconds=settings.access_token_ttl_seconds,
        )

    async def issue(self, result: GrantResult) -> IssuedToken:
        subject = self._resolve_identity(result)
        self._check_identity_is_usable(result)
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

        # Record BEFORE the token can reach anybody. Crashing here wastes a row.
        # Crashing after responding leaves a live credential nobody can revoke,
        # because phase 6 cannot revoke what it cannot find.
        await self._credentials.record(
            IssuanceRecord(
                jti=minted.claims["jti"],
                client_id=result.client_id,
                subject=subject,
                audience=str(claims["aud"]),
                scope=scope,
                issued_at=minted.claims["iat"],
                expires_at=minted.claims["exp"],
                # For client_credentials the client is its own root. From token
                # exchange onward it is the innermost entry of the act chain.
                root_subject=result.act_root or subject,
                task_id=result.task_id,
                delegation_depth=result.delegation_depth,
            )
        )
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
    def _check_identity_is_usable(result: GrantResult) -> None:
        """Step 3. Authenticating is not the same question as being allowed to act.

        A suspended client can still prove who it is. It is refused here, after
        authentication succeeded, so the 2 failures stay independent and a
        future grant cannot satisfy one by satisfying the other.
        """
        if result.principal_status != ACTIVE:
            raise OAuthError("invalid_client", "client authentication failed", 401)

    @staticmethod
    def _resolve_policy(result: GrantResult) -> tuple[frozenset[str], ...]:
        """Step 4. The authority ceilings, in the order the grant supplied them."""
        return result.ceilings
