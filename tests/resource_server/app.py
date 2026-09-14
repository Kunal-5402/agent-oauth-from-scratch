"""A separate FastAPI resource server protected by the test verifier."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, status

from tests.resource_server.verifier import (
    AuthorizationServerVerifier,
    TokenValidationError,
)


def create_resource_server(*, authorization_server_issuer: str, audience: str) -> FastAPI:
    """Create a resource server that validates tokens from one trusted issuer."""
    verifier = AuthorizationServerVerifier(authorization_server_issuer, audience=audience)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        verifier.close()

    app = FastAPI(title="Integration Test Resource Server", lifespan=lifespan)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/reports")
    async def read_reports(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        claims = _validated_claims(authorization, verifier)
        _require_scope(claims, "reports:read")
        return {"subject": claims["sub"], "report": "access granted"}

    return app


def _validated_claims(
    authorization: str | None,
    verifier: AuthorizationServerVerifier,
) -> dict[str, Any]:
    if authorization is None:
        raise _unauthorized("missing bearer token")

    scheme, _, token = authorization.partition(" ")
    if scheme != "Bearer" or not token:
        raise _unauthorized("authorization header must use the Bearer scheme")

    try:
        return verifier.validate(token)
    except TokenValidationError as exc:
        raise _unauthorized("invalid access token") from exc


def _require_scope(claims: dict[str, Any], required_scope: str) -> None:
    granted_scopes = set(str(claims.get("scope", "")).split())
    if required_scope not in granted_scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="insufficient scope",
            headers={
                "WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{required_scope}"'
            },
        )


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
    )
