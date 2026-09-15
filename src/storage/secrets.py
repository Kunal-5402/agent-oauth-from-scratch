"""Client secret hashing.

A client secret is a password, and the database is the thing that leaks. A
plaintext column turns one database read into every client's credential.

argon2id is memory-hard. A fast hash over a high-entropy random secret is
defensible, but nobody controls whether a future operator registers a weak one,
so the assumption is not built in.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError

_hasher = PasswordHasher()

# Verified against when a client is unknown or holds no secret, so every failure
# path costs the same work. Computed once at import, never per request.
_ABSENT_SECRET_HASH = _hasher.hash("absent-client-placeholder-secret")


def hash_secret(secret: str) -> str:
    return _hasher.hash(secret)


def verify_secret(secret: str, secret_hash: str | None) -> bool:
    """Check a secret in constant-ish time, even when there is nothing to check.

    Passing ``None`` still runs a full verification against a placeholder. An
    early return there would let the response time enumerate valid client IDs,
    which is the exact hole the plaintext comparison was fixed for.
    """
    try:
        _hasher.verify(secret_hash if secret_hash is not None else _ABSENT_SECRET_HASH, secret)
    except (VerifyMismatchError, VerificationError):
        return False
    return secret_hash is not None
