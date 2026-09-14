from __future__ import annotations

from src.crypto.keys import KeyStore


def test_key_store_persists_the_same_key_and_kid(tmp_path):
    first = KeyStore(tmp_path / "keys").load_or_create()
    second = KeyStore(tmp_path / "keys").load_or_create()

    assert first.kid == second.kid
    assert first.public_jwk() == second.public_jwk()


def test_public_jwk_never_contains_private_key_material(tmp_path):
    public_jwk = KeyStore(tmp_path / "keys").load_or_create().public_jwk()

    assert set(public_jwk) == {"kty", "crv", "x", "y", "kid", "use", "alg"}
    assert "d" not in public_jwk
