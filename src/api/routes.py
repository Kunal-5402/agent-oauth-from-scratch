"""FastAPI routes. Parse, dispatch, serialise. No grant logic lives here."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.api.forms import read_token_form
from src.api.metadata import authorization_server_metadata, token_request_openapi
from src.api.schemas import OAuthErrorResponse, TokenResponse
from src.auth import ClientAuthRegistry, default_client_auth_registry
from src.config import Settings
from src.crypto.keys import SigningKey
from src.crypto.tokens import TokenVerifier
from src.errors import OAuthError
from src.grants import GrantRegistry, default_grant_registry
from src.services.clients import ClientRegistry
from src.services.pipeline import IssuancePipeline
from src.storage.repositories import (
    AssertionReplayRepository,
    ClientKeyRepository,
    ClientRepository,
    IssuedCredentialRepository,
)

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def create_app(
    *,
    settings: Settings,
    signing_key: SigningKey,
    clients: ClientRegistry,
    client_records: ClientRepository,
    credentials: IssuedCredentialRepository,
    client_keys: ClientKeyRepository,
    replays: AssertionReplayRepository,
    grants: GrantRegistry | None = None,
    auth_methods: ClientAuthRegistry | None = None,
    lifespan: object | None = None,
) -> FastAPI:
    """Create an isolated application instance with explicit dependencies."""
    verifier = TokenVerifier(issuer=settings.issuer, signing_key=signing_key)
    grants = grants or default_grant_registry(verifier=verifier, clients=client_records)
    auth_methods = auth_methods or default_client_auth_registry(
        issuer=settings.issuer,
        token_endpoint=settings.url_for("/oauth/token"),
        keys=client_keys,
        replays=replays,
        server_key=signing_key,
    )
    pipeline = IssuancePipeline(settings=settings, signing_key=signing_key, credentials=credentials)
    app = FastAPI(
        title="Agent OAuth Authorization Server",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.exception_handler(OAuthError)
    async def oauth_error_handler(_: Request, exc: OAuthError) -> JSONResponse:
        headers = dict(NO_STORE)
        if exc.error == "invalid_client":
            headers["WWW-Authenticate"] = 'Basic realm="oauth/token"'
        return JSONResponse(
            status_code=exc.status_code,
            content=OAuthErrorResponse(
                error=exc.error,
                error_description=exc.description,
            ).model_dump(),
            headers=headers,
        )

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"service": "agent-oauth-authorization-server"}

    @app.get("/.well-known/jwks.json")
    async def get_jwks() -> dict[str, list[dict[str, str]]]:
        return {"keys": [signing_key.public_jwk()]}

    @app.get("/.well-known/oauth-authorization-server")
    async def get_oauth_authorization_server() -> dict[str, object]:
        return await authorization_server_metadata(
            settings=settings,
            grants=grants,
            auth_methods=auth_methods,
            clients=clients,
        )

    @app.post(
        "/oauth/token",
        response_model=TokenResponse,
        openapi_extra=token_request_openapi(grants),
    )
    async def get_oauth_token(request: Request) -> JSONResponse:
        form = await read_token_form(request)
        grant = grants.get(form.grant_type)

        client = None
        if grant.requires_client_auth:
            presented, method = auth_methods.extract(request.headers, form)
            client = await clients.authenticate(presented, method)

        token = await pipeline.issue(await grant.resolve(form, client))
        body = TokenResponse(
            access_token=token.access_token,
            expires_in=token.expires_in,
            scope=token.scope or None,
        ).model_dump(exclude_none=True)
        return JSONResponse(status_code=200, content=body, headers=dict(NO_STORE))

    return app
