"""JWT validation through OAuth discovery and a remotely fetched JWKS."""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx
import jwt


class TokenValidationError(Exception):
    """A token was absent, malformed, unverifiable, or did not meet policy."""


class AuthorizationServerVerifier:
    """Discover an AS, cache its JWKS, and validate ES256 access tokens."""

    def __init__(
        self,
        issuer: str,
        *,
        audience: str,
        cache_ttl_seconds: int = 60,
        forced_refresh_interval_seconds: float = 5.0,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._audience = audience
        self._cache_ttl_seconds = cache_ttl_seconds
        self._forced_refresh_interval_seconds = forced_refresh_interval_seconds
        self._http = httpx.Client(timeout=timeout_seconds)
        self._lock = threading.Lock()
        self._keys_by_kid: dict[str, dict[str, Any]] = {}
        self._cache_expires_at = 0.0
        self._earliest_next_refresh_at = 0.0

    def close(self) -> None:
        self._http.close()

    def validate(self, access_token: str) -> dict[str, Any]:
        """Verify all security-relevant JWT properties before returning claims."""
        try:
            header = jwt.get_unverified_header(access_token)
        except jwt.InvalidTokenError as exc:
            raise TokenValidationError("token header is malformed") from exc

        if header.get("alg") != "ES256":
            raise TokenValidationError("only ES256 access tokens are accepted")
        if header.get("typ") != "at+jwt":
            raise TokenValidationError("token is not an access token")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenValidationError("token does not name a signing key")

        jwk = self._key_for(kid)
        try:
            public_key = jwt.PyJWK.from_dict(jwk).key
            return jwt.decode(
                access_token,
                public_key,
                algorithms=["ES256"],
                issuer=self._issuer,
                audience=self._audience,
                options={"require": ["iss", "sub", "aud", "iat", "exp", "jti"]},
            )
        except jwt.InvalidTokenError as exc:
            raise TokenValidationError("token validation failed") from exc

    def _key_for(self, kid: str) -> dict[str, Any]:
        self._refresh_if_needed()
        key = self._keys_by_kid.get(kid)
        if key is not None:
            return key

        # A missing kid can mean key rotation; force one fresh fetch before
        # rejecting it, then fail closed if the server still does not publish it.
        # The forced fetch is rate limited, so a caller that sends random kid
        # values cannot drive one JWKS request per token at the AS.
        self._refresh(force=True)
        key = self._keys_by_kid.get(kid)
        if key is None:
            raise TokenValidationError("token key ID is not published by the authorization server")
        return key

    def _refresh_if_needed(self) -> None:
        if time.monotonic() >= self._cache_expires_at:
            self._refresh()

    def _refresh(self, *, force: bool = False) -> None:
        with self._lock:
            now = time.monotonic()
            if not force and now < self._cache_expires_at:
                return
            if force and now < self._earliest_next_refresh_at:
                return
            try:
                metadata_response = self._http.get(
                    f"{self._issuer}/.well-known/oauth-authorization-server"
                )
                metadata_response.raise_for_status()
                metadata = metadata_response.json()
                if metadata.get("issuer") != self._issuer:
                    raise TokenValidationError("discovered issuer does not match the configured issuer")

                jwks_uri = metadata.get("jwks_uri")
                if not isinstance(jwks_uri, str):
                    raise TokenValidationError("authorization-server metadata has no JWKS URI")
                jwks_response = self._http.get(jwks_uri)
                jwks_response.raise_for_status()
                keys = jwks_response.json().get("keys")
            except (httpx.HTTPError, ValueError) as exc:
                raise TokenValidationError("could not retrieve authorization-server keys") from exc

            if not isinstance(keys, list):
                raise TokenValidationError("JWKS response has no keys array")

            parsed_keys: dict[str, dict[str, Any]] = {}
            for key in keys:
                if not isinstance(key, dict):
                    continue
                kid = key.get("kid")
                if (
                    isinstance(kid, str)
                    and key.get("kty") == "EC"
                    and key.get("crv") == "P-256"
                    and key.get("alg") == "ES256"
                ):
                    parsed_keys[kid] = key

            if not parsed_keys:
                raise TokenValidationError("JWKS contains no usable ES256 keys")
            fetched_at = time.monotonic()
            self._keys_by_kid = parsed_keys
            self._cache_expires_at = fetched_at + self._cache_ttl_seconds
            self._earliest_next_refresh_at = (
                fetched_at + self._forced_refresh_interval_seconds
            )
