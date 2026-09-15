"""Unit tests for the server's JWT boundary.

These need no HTTP and no fixtures beyond a key on disk, because minting and
verifying are pure functions of a key, a clock, and the claims.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from src.crypto.keys import KeyStore
from src.crypto.tokens import (
    ACCESS_TOKEN_TYPE,
    MINTER_OWNED_CLAIMS,
    REQUIRED_CLAIMS,
    TokenError,
    TokenMinter,
    TokenVerifier,
)

ISSUER = "https://as.test"
AUDIENCE = "test-resource"


@pytest.fixture
def signing_key(tmp_path):
    return KeyStore(tmp_path / "keys").load_or_create()


@pytest.fixture
def minter(signing_key):
    return TokenMinter(issuer=ISSUER, signing_key=signing_key, default_ttl_seconds=600)


@pytest.fixture
def verifier(signing_key):
    return TokenVerifier(issuer=ISSUER, signing_key=signing_key)


def _forge(signing_key, claims, *, headers=None, key=None, algorithm="ES256"):
    """Sign a token directly, bypassing the minter, to test the verifier."""
    return jwt.encode(
        claims,
        key if key is not None else signing_key.private_key,
        algorithm=algorithm,
        headers={"kid": signing_key.kid, "typ": ACCESS_TOKEN_TYPE, **(headers or {})},
    )


def _valid_claims():
    now = datetime.now(UTC)
    return {
        "iss": ISSUER,
        "sub": "agent:reporting",
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "jti": "test-jti",
    }


# ---------------------------------------------------------------- minting


def test_the_minter_owns_the_claims_the_caller_must_not_choose(minter):
    minted = minter.mint({"sub": "agent:reporting", "aud": AUDIENCE})

    assert set(MINTER_OWNED_CLAIMS).issubset(minted.claims)
    assert minted.claims["iss"] == ISSUER
    assert minted.claims["exp"] > minted.claims["iat"]


@pytest.mark.parametrize("claim", sorted(MINTER_OWNED_CLAIMS))
def test_a_caller_cannot_set_an_owned_claim(minter, claim):
    """Silently overwriting would hide a grant trying to pick its own lifetime."""
    with pytest.raises(TokenError, match=claim):
        minter.mint({"sub": "x", "aud": AUDIENCE, claim: "anything"})


def test_the_header_names_the_active_key_and_the_token_type(minter, signing_key):
    header = jwt.get_unverified_header(minter.mint({"sub": "x", "aud": AUDIENCE}).token)

    assert header["alg"] == "ES256"
    assert header["typ"] == ACCESS_TOKEN_TYPE
    assert header["kid"] == signing_key.kid


def test_every_token_gets_its_own_jti(minter):
    identifiers = {minter.mint({"sub": "x", "aud": AUDIENCE}).claims["jti"] for _ in range(200)}

    assert len(identifiers) == 200


def test_not_after_shortens_a_lifetime_but_never_extends_one(minter):
    now = datetime.now(UTC)

    short = minter.mint({"sub": "x", "aud": AUDIENCE}, not_after=now + timedelta(seconds=30))
    long = minter.mint({"sub": "x", "aud": AUDIENCE}, not_after=now + timedelta(hours=9))

    assert short.expires_in <= 30
    assert long.expires_in <= 600  # the configured ttl still wins


def test_a_lifetime_that_has_already_elapsed_is_refused(minter):
    past = datetime.now(UTC) - timedelta(seconds=1)

    with pytest.raises(TokenError, match="already elapsed"):
        minter.mint({"sub": "x", "aud": AUDIENCE}, not_after=past)


def test_a_lifetime_never_grows_however_many_times_it_is_derived(minter):
    """Shrink rule 4, proved by repetition rather than by one hop.

    A single-hop test passes under an implementation that merely uses a short
    default. Only repeated derivation shows the min() is doing the work.
    """
    original = minter.mint(
        {"sub": "x", "aud": AUDIENCE}, not_after=datetime.now(UTC) + timedelta(seconds=45)
    )
    ceiling = original.claims["exp"]

    token = original
    for _ in range(5):
        token = minter.mint({"sub": "x", "aud": AUDIENCE}, not_after=token.claims["exp"])
        assert token.claims["exp"] <= ceiling

    assert token.claims["exp"] <= ceiling


# ------------------------------------------------------------- verifying


def test_a_freshly_minted_token_verifies(minter, verifier):
    minted = minter.mint({"sub": "agent:reporting", "aud": AUDIENCE, "scope": "a:b"})

    claims = verifier.verify(minted.token, audience=AUDIENCE)

    assert claims["sub"] == "agent:reporting"
    assert claims["scope"] == "a:b"
    assert all(name in claims for name in REQUIRED_CLAIMS)


def test_a_tampered_signature_is_refused(minter, verifier):
    minted = minter.mint({"sub": "x", "aud": AUDIENCE})

    with pytest.raises(TokenError):
        verifier.verify(minted.token + "x", audience=AUDIENCE)


def test_a_token_for_another_audience_is_refused(minter, verifier):
    minted = minter.mint({"sub": "x", "aud": "some-other-api"})

    with pytest.raises(TokenError):
        verifier.verify(minted.token, audience=AUDIENCE)


def test_a_token_from_another_issuer_is_refused(signing_key, verifier):
    other = TokenMinter(
        issuer="https://evil.test", signing_key=signing_key, default_ttl_seconds=600
    )

    with pytest.raises(TokenError):
        verifier.verify(other.mint({"sub": "x", "aud": AUDIENCE}).token, audience=AUDIENCE)


def test_an_hmac_token_forged_from_the_published_key_is_refused(signing_key, verifier):
    """Algorithm confusion. The attacker uses public key material as an HMAC secret."""
    forged = _forge(
        signing_key,
        _valid_claims(),
        key=signing_key.public_jwk()["x"],
        algorithm="HS256",
        headers={"alg": "HS256"},
    )

    with pytest.raises(TokenError, match="unsupported token algorithm"):
        verifier.verify(forged, audience=AUDIENCE)


def test_a_token_that_is_not_an_access_token_is_refused(signing_key, verifier):
    forged = _forge(signing_key, _valid_claims(), headers={"typ": "JWT"})

    with pytest.raises(TokenError, match="not an access token"):
        verifier.verify(forged, audience=AUDIENCE)


def test_a_token_signed_by_an_unknown_key_is_refused(signing_key, verifier, tmp_path):
    other_key = KeyStore(tmp_path / "other").load_or_create()
    forged = _forge(other_key, _valid_claims())

    with pytest.raises(TokenError, match="not signed by the active key"):
        verifier.verify(forged, audience=AUDIENCE)


def test_an_expired_token_is_refused(signing_key, verifier):
    expired = _valid_claims()
    expired["exp"] = datetime.now(UTC) - timedelta(seconds=1)

    with pytest.raises(TokenError):
        verifier.verify(_forge(signing_key, expired), audience=AUDIENCE)


@pytest.mark.parametrize("missing", REQUIRED_CLAIMS)
def test_a_token_missing_a_required_claim_is_refused(signing_key, verifier, missing):
    claims = _valid_claims()
    del claims[missing]

    with pytest.raises(TokenError):
        verifier.verify(_forge(signing_key, claims), audience=AUDIENCE)


def test_garbage_is_refused_without_raising_something_other_than_tokenerror(verifier):
    for rubbish in ("", "not-a-jwt", "a.b.c", "..."):
        with pytest.raises(TokenError):
            verifier.verify(rubbish, audience=AUDIENCE)
