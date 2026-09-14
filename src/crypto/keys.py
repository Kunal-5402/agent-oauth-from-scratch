"""Persistent ES256 signing-key management for the authorization server.

The authorization server owns the private key. Resource servers receive only
the corresponding public JWK through the JWKS endpoint.

This module intentionally manages one active key. Key rotation will later
become a collection of ``SigningKey`` values, but a single persistent key is
the smallest correct shape for the first token endpoint.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


class KeyStoreError(RuntimeError):
    """Raised when the configured signing key is missing or unsuitable."""


def _base64url(value: bytes) -> str:
    """Encode bytes as unpadded base64url, as required by JWK and JWT."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class SigningKey:
    """The active private key and the public metadata needed to publish it."""

    private_key: ec.EllipticCurvePrivateKey
    kid: str

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self.private_key.public_key()

    def public_jwk(self) -> dict[str, str]:
        """Return a public-only RFC 7517 JWK suitable for a JWKS response."""
        numbers = self.public_key.public_numbers()
        coordinate_size = 32  # P-256 coordinates are always 256 bits.

        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _base64url(numbers.x.to_bytes(coordinate_size, "big")),
            "y": _base64url(numbers.y.to_bytes(coordinate_size, "big")),
            "kid": self.kid,
            "use": "sig",
            "alg": "ES256",
        }


class KeyStore:
    """Load the server's P-256 signing key, creating it once when absent."""

    def __init__(
        self,
        directory: str | Path = "keys",
        filename: str = "es256-private.pem",
    ) -> None:
        self.directory = Path(directory)
        self.private_key_path = self.directory / filename

    def load_or_create(self) -> SigningKey:
        """Return the persistent active key, creating it only on first run.

        The first-start write is published atomically, so a simultaneous
        starter either wins with a complete PEM file or loads the winner's
        complete PEM file; it can never observe a half-written key.
        """
        self.directory.mkdir(parents=True, exist_ok=True)
        self._restrict_directory_permissions()

        try:
            private_key = self._load_private_key()
        except FileNotFoundError:
            private_key = self._create_private_key_once()

        return SigningKey(private_key=private_key, kid=self._kid_for(private_key))

    def load(self) -> SigningKey:
        """Load an existing key without creating one."""
        private_key = self._load_private_key()
        return SigningKey(private_key=private_key, kid=self._kid_for(private_key))

    def _load_private_key(self) -> ec.EllipticCurvePrivateKey:
        try:
            pem = self.private_key_path.read_bytes()
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise KeyStoreError(f"could not read signing key: {self.private_key_path}") from exc

        try:
            key = serialization.load_pem_private_key(pem, password=None)
        except (TypeError, ValueError) as exc:
            raise KeyStoreError(
                "configured signing key is not a valid unencrypted PEM key"
            ) from exc

        self._validate_private_key(key)
        return key

    def _create_private_key_once(self) -> ec.EllipticCurvePrivateKey:
        private_key = ec.generate_private_key(ec.SECP256R1())
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        descriptor, temporary_path_string = tempfile.mkstemp(
            dir=self.directory,
            prefix=f".{self.private_key_path.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_path_string)
        try:
            with os.fdopen(descriptor, "wb") as key_file:
                key_file.write(pem)
                key_file.flush()
                os.fsync(key_file.fileno())

            # os.link is an atomic "publish if absent" operation. Unlike
            # os.replace, it never overwrites a live signing key.
            try:
                os.link(temporary_path, self.private_key_path)
            except FileExistsError:
                return self._load_private_key()
        except OSError as exc:
            raise KeyStoreError(f"could not persist signing key: {self.private_key_path}") from exc
        finally:
            temporary_path.unlink(missing_ok=True)

        return private_key

    @staticmethod
    def _validate_private_key(key: object) -> None:
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise KeyStoreError("configured signing key must be an EC private key")
        if not isinstance(key.curve, ec.SECP256R1):
            raise KeyStoreError("configured signing key must use the P-256 curve for ES256")

    @staticmethod
    def _kid_for(private_key: ec.EllipticCurvePrivateKey) -> str:
        """Calculate the RFC 7638 JWK thumbprint used as this key's ``kid``."""
        numbers = private_key.public_key().public_numbers()
        coordinate_size = 32
        thumbprint_members = {
            "crv": "P-256",
            "kty": "EC",
            "x": _base64url(numbers.x.to_bytes(coordinate_size, "big")),
            "y": _base64url(numbers.y.to_bytes(coordinate_size, "big")),
        }
        canonical_jwk = json.dumps(
            thumbprint_members,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return _base64url(hashlib.sha256(canonical_jwk).digest())

    def _restrict_directory_permissions(self) -> None:
        """Keep locally generated private keys owner-accessible on POSIX hosts."""
        if os.name == "posix":
            self.directory.chmod(0o700)
