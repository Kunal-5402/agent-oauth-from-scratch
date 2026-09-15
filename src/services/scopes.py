"""Scope parsing and the one attenuation function every grant must use."""

from __future__ import annotations

from src.errors import OAuthError


def parse_scope(value: str | None) -> tuple[str, ...]:
    """Parse OAuth's space-delimited scope string, retaining stable order."""
    if value is None or not value.strip():
        return ()

    scopes: list[str] = []
    for scope in value.split():
        if scope not in scopes:
            scopes.append(scope)
    return tuple(scopes)


def attenuate(requested: tuple[str, ...], *ceilings: frozenset[str]) -> tuple[str, ...]:
    """Intersect the request with every ceiling. The result can never grow.

    An empty ceiling means *deliberately powerless*, never *no opinion*. That
    distinction is the phase 1 landmine: the same empty value in a database can
    be read either way, and reading it as "no restriction configured" is a
    complete authorization bypass. Refuse before the intersection runs, so no
    later code has to remember the rule.
    """
    if not requested:
        return ()

    if any(not ceiling for ceiling in ceilings):
        raise OAuthError("invalid_scope", "none of the requested scopes are allowed", 400)

    granted = tuple(scope for scope in requested if all(scope in ceiling for ceiling in ceilings))

    # Unknown scopes are dropped when at least one requested scope is valid, as
    # documented in the roadmap. A wholly unauthorized request is refused.
    if not granted:
        raise OAuthError("invalid_scope", "none of the requested scopes are allowed", 400)
    return granted
