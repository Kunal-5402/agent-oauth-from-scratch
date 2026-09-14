"""Minimal OAuth client that discovers endpoints before requesting a token."""

from __future__ import annotations

from typing import Any

import httpx


class OAuthClient:
    """Client-credentials client that communicates over ordinary HTTP."""

    def __init__(self, issuer: str, *, timeout_seconds: float = 5.0) -> None:
        self.issuer = issuer.rstrip("/")
        self._http = httpx.Client(timeout=timeout_seconds)

    def close(self) -> None:
        self._http.close()

    def discover(self) -> dict[str, Any]:
        response = self._http.get(f"{self.issuer}/.well-known/oauth-authorization-server")
        response.raise_for_status()
        metadata = response.json()
        if metadata.get("issuer") != self.issuer:
            raise ValueError(
                "authorization-server metadata issuer does not match the configured issuer"
            )
        return metadata

    def client_credentials(
        self,
        *,
        client_id: str,
        client_secret: str,
        scope: str,
    ) -> httpx.Response:
        """Request a token through the discovered token endpoint."""
        metadata = self.discover()
        return self._http.post(
            metadata["token_endpoint"],
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": scope,
            },
        )
