"""FastAPI routes for the Phase 1 authorization server."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.api.schemas import OAuthErrorResponse, TokenResponse
from src.config import Settings
from src.crypto.keys import SigningKey
from src.services.token_issuer import ClientRegistry, OAuthError, TokenIssuer


def create_app(
    *,
    settings: Settings,
    signing_key: SigningKey,
    clients: ClientRegistry,
) -> FastAPI:
    """Create an isolated application instance with explicit dependencies."""
    issuer = TokenIssuer(settings=settings, signing_key=signing_key, clients=clients)
    app = FastAPI(title="Agent OAuth Authorization Server", version="0.1.0")

    @app.exception_handler(OAuthError)
    async def oauth_error_handler(_: Request, exc: OAuthError) -> JSONResponse:
        headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
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
        return {
            "issuer": settings.issuer,
            "token_endpoint": settings.url_for("/oauth/token"),
            "jwks_uri": settings.url_for("/.well-known/jwks.json"),
            "grant_types_supported": ["client_credentials"],
            # RFC 8414 requires this member. This server has no endpoint that
            # returns an authorization response, so the supported set is empty.
            "response_types_supported": [],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "scopes_supported": sorted(
                {scope for client in clients.all() for scope in client.allowed_scopes}
            ),
        }

    @app.post("/oauth/token", response_model=TokenResponse)
    async def get_oauth_token(request: Request) -> JSONResponse:
        form = await _read_token_form(request)
        if form["grant_type"] != "client_credentials":
            raise OAuthError("unsupported_grant_type", "grant type is not supported", 400)

        token = issuer.issue_client_credentials(
            client_id=form["client_id"],
            client_secret=form["client_secret"],
            requested_scope=form.get("scope"),
        )
        body = TokenResponse(
            access_token=token.access_token,
            expires_in=token.expires_in,
            scope=token.scope or None,
        ).model_dump(exclude_none=True)
        return JSONResponse(
            status_code=200,
            content=body,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    return app


async def _read_token_form(request: Request) -> dict[str, str]:
    """Read one form body only; query parameters never affect token issuance."""
    content_type = request.headers.get("content-type", "")
    if not content_type.lower().startswith("application/x-www-form-urlencoded"):
        raise OAuthError(
            "invalid_request",
            "content type must be application/x-www-form-urlencoded",
            400,
        )

    form = await request.form()
    fields: dict[str, str] = {}
    for name in ("grant_type", "client_id", "client_secret", "scope"):
        values = form.getlist(name)
        if len(values) > 1:
            raise OAuthError("invalid_request", f"{name} must appear at most once", 400)
        if values:
            value = values[0]
            if not isinstance(value, str):
                raise OAuthError("invalid_request", f"{name} must be text", 400)
            fields[name] = value

    required = ("grant_type", "client_id", "client_secret")
    missing = [name for name in required if not fields.get(name)]
    if missing:
        raise OAuthError("invalid_request", f"missing required parameter: {missing[0]}", 400)
    return fields
