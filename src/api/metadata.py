"""The authorization-server metadata document, assembled from what is installed.

The document is derived, never stored. A static file would be a second source
of truth, and the 2 drift in both directions: you advertise a grant you removed,
or you add one and forget the file. Deriving it from the registries keeps the
project invariant true by construction:

    the server advertises only capabilities it implements.

A file still has one honest job. Descriptive, deployment-specific values such
as a documentation URL are not derivable from code, so they are merged last and
may never declare a capability.
"""

from __future__ import annotations

from src.auth import ClientAuthRegistry
from src.config import Settings
from src.grants import GrantRegistry
from src.services.clients import ClientRegistry

# Keys a deployment may never set. Each one is a claim about what the code can
# do, so only the code may assert it.
DERIVED_KEYS = frozenset(
    {
        "issuer",
        "token_endpoint",
        "jwks_uri",
        "grant_types_supported",
        "response_types_supported",
        "token_endpoint_auth_methods_supported",
        "code_challenge_methods_supported",
        "dpop_signing_alg_values_supported",
        "introspection_endpoint",
        "revocation_endpoint",
        "scopes_supported",
    }
)


async def authorization_server_metadata(
    *,
    settings: Settings,
    grants: GrantRegistry,
    auth_methods: ClientAuthRegistry,
    clients: ClientRegistry,
) -> dict[str, object]:
    """Build the RFC 8414 document from the installed capabilities."""
    document: dict[str, object] = {
        "issuer": settings.issuer,
        "token_endpoint": settings.url_for("/oauth/token"),
        "jwks_uri": settings.url_for("/.well-known/jwks.json"),
        "grant_types_supported": sorted(grants.grant_types()),
        # RFC 8414 requires this member. A grant that returns an authorization
        # response contributes to it; client_credentials contributes nothing.
        "response_types_supported": sorted(grants.response_types()),
        "token_endpoint_auth_methods_supported": sorted(auth_methods.names()),
        "scopes_supported": sorted(
            {scope for client in await clients.all() for scope in client.allowed_scopes}
        ),
    }

    # Each installed capability adds its own keys. Uninstall the module and the
    # key disappears, which is the property a static file cannot give you.
    for grant in grants.all():
        document.update(grant.metadata(settings))

    document.update(settings.metadata_overlay)
    return document


def token_request_openapi(grants: GrantRegistry) -> dict[str, object]:
    """Describe the token endpoint body so the generated API document works.

    The route still parses the body itself, because FastAPI's Form handling
    keeps only the first value of a repeated field and would silently remove
    the duplicate-parameter refusal.
    """
    return {
        "requestBody": {
            "required": True,
            "content": {
                "application/x-www-form-urlencoded": {
                    "schema": {"oneOf": [g.openapi_schema() for g in grants.all()]}
                }
            },
        }
    }
