"""RFC 8693 token exchange. The phase this repository exists for.

An agent should not wear the user's identity. It should **carry** it, in a claim
that names both of them and cannot be edited by anybody downstream.

The sentence to memorise:

    The SUBJECT token carries the authority.
    The ACTOR token carries the identity of whoever is about to hold it.

The actor token grants nothing at all. It is proof of who is asking. Every scope
in the result comes from the subject token, and the actor's own policy can only
reduce what passes through.
"""

from __future__ import annotations

from datetime import UTC, datetime

from src.api.forms import TokenForm
from src.crypto.tokens import TokenError, TokenVerifier
from src.errors import OAuthError
from src.grants.base import GrantResult
from src.models import RegisteredClient
from src.services.delegation import chain, may_act_permits, nest, task_of
from src.services.scopes import parse_scope
from src.storage.repositories import ClientRepository

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105 - an RFC 8693 type URN

SUPPORTED_TOKEN_TYPES = frozenset({ACCESS_TOKEN_TYPE})


class TokenExchangeGrant:
    grant_type = GRANT_TYPE
    requires_client_auth = True
    response_types = frozenset()

    def __init__(self, *, verifier: TokenVerifier, clients: ClientRepository) -> None:
        self._verifier = verifier
        self._clients = clients

    async def resolve(self, form: TokenForm, client: RegisteredClient | None) -> GrantResult:
        assert client is not None  # noqa: S101 - requires_client_auth guarantees it

        audience = self._required_audience(form, client)
        subject_token = form.require("subject_token")
        actor_token = form.require("actor_token")
        self._check_token_types(form)

        # Both tokens get the FULL verification path, and both finish before any
        # policy runs. It is tempting to treat the actor token as a hint, because
        # it grants nothing. It decides who the new token NAMES, and an
        # unverified actor token means anybody can be named.
        subject_claims = self._verify(subject_token, audience)
        actor_claims = self._verify(actor_token, audience)

        actor_client = await self._actor_client(actor_claims)
        self._check_may_act(subject_claims, actor_claims)

        subject_scopes = frozenset(parse_scope(subject_claims.get("scope")))
        requested = parse_scope(form.get("scope")) or tuple(sorted(subject_scopes))

        return GrantResult(
            # The new token names the ACTOR. The previous holder moves into act.
            subject=actor_claims["sub"],
            client_id=client.client_id,
            requested_scopes=requested,
            # Three ceilings: what the subject token holds, what the actor's
            # client may hold, and what was asked for. Intersection cannot grow.
            ceilings=(subject_scopes, actor_client.allowed_scopes),
            act=nest(subject_claims),
            act_root=chain(subject_claims)[-1],
            # Copied, never generated. A new task_id here would detach this
            # branch from the tree it belongs to, and phase 6 revokes by tree.
            task_id=task_of(subject_claims),
            audience=audience,
            # A derived token must never outlive the token it came from.
            max_expires_at=datetime.fromtimestamp(subject_claims["exp"], tz=UTC),
            issued_token_type=ACCESS_TOKEN_TYPE,
        )

    # ------------------------------------------------------------------ helpers

    def _verify(self, token: str, audience: str) -> dict:
        try:
            # Verified against THIS server's audience for the presented token,
            # not the requested one: the token being exchanged was issued for
            # where it is now, not for where it is going.
            return self._verifier.verify_any_audience(token)
        except TokenError as exc:
            # One message whichever token failed. Naming it would tell a caller
            # probing with 2 forgeries which one it got closest on.
            raise OAuthError("invalid_grant", "token exchange was refused", 400) from exc

    def _required_audience(self, form: TokenForm, client: RegisteredClient) -> str:
        """Refuse to issue a token that works everywhere.

        RFC 8693 makes audience optional. The specification permits a server to
        demand it, and demanding it prevents a category of incident for the cost
        of one conditional: a token that works everywhere is a token whose theft
        costs you everything.
        """
        # A repeated audience is already refused by the form reader, which
        # rejects any field appearing twice. One hop, one destination.
        audience = form.require("audience")
        if audience not in client.allowed_audiences:
            # invalid_target is the RFC 8693 error for an audience this caller
            # may not reach.
            raise OAuthError("invalid_target", "audience is not permitted", 400)
        return audience

    @staticmethod
    def _check_token_types(form: TokenForm) -> None:
        for name in ("subject_token_type", "actor_token_type"):
            value = form.require(name)
            if value not in SUPPORTED_TOKEN_TYPES:
                raise OAuthError("invalid_request", f"unsupported {name}", 400)

        requested = form.get("requested_token_type")
        if requested is not None and requested not in SUPPORTED_TOKEN_TYPES:
            raise OAuthError("invalid_request", "unsupported requested_token_type", 400)

    async def _actor_client(self, actor_claims: dict) -> RegisteredClient:
        """The actor's own registration is the second ceiling."""
        client_id = actor_claims.get("client_id")
        actor_client = await self._clients.get(client_id) if isinstance(client_id, str) else None
        if actor_client is None:
            raise OAuthError("invalid_grant", "token exchange was refused", 400)
        return actor_client

    @staticmethod
    def _check_may_act(subject_claims: dict, actor_claims: dict) -> None:
        """``may_act`` names, in advance, who is permitted to act for a subject.

        It is read from the VERIFIED subject token only. A request parameter
        saying the same thing would let any holder name itself, which is bearer
        semantics wearing a delegation costume.
        """
        if not may_act_permits(subject_claims, actor_claims["sub"]):
            # Do not name who WAS expected. That would leak the delegation
            # topology to a caller who merely guessed a subject token.
            raise OAuthError("invalid_grant", "token exchange was refused", 400)

    # ------------------------------------------------------------------ registry

    def metadata(self, settings: object) -> dict[str, object]:
        return {}

    def openapi_schema(self) -> dict[str, object]:
        return {
            "title": "token-exchange",
            "type": "object",
            "required": [
                "grant_type",
                "subject_token",
                "subject_token_type",
                "actor_token",
                "actor_token_type",
                "audience",
            ],
            "properties": {
                "grant_type": {"type": "string", "enum": [GRANT_TYPE]},
                "subject_token": {"type": "string"},
                "subject_token_type": {
                    "type": "string",
                    "enum": sorted(SUPPORTED_TOKEN_TYPES),
                },
                "actor_token": {"type": "string"},
                "actor_token_type": {
                    "type": "string",
                    "enum": sorted(SUPPORTED_TOKEN_TYPES),
                },
                "audience": {
                    "type": "string",
                    "description": "Required. Exactly one downstream service.",
                },
                "scope": {"type": "string"},
            },
        }
