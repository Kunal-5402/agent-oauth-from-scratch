"""The grant contract.

A grant answers exactly one question: *where does the authority in the new
token come from?* It resolves the principal and the ceilings, and then stops.
It never signs, never records, and never decides a lifetime. Those belong to
the shared pipeline, which is the single place an issued token can come from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable

from src.api.forms import TokenForm
from src.services.clients import RegisteredClient


@dataclass(frozen=True)
class GrantResult:
    """Everything step 1 of the pipeline learned, and nothing more."""

    subject: str
    client_id: str
    requested_scopes: tuple[str, ...]
    ceilings: tuple[frozenset[str], ...]

    # Filled in by later phases. They are declared now because the pipeline has
    # to apply them uniformly, and a grant added later must not be able to
    # introduce a field the shared path does not already honour.
    max_expires_at: datetime | None = None
    act: dict[str, object] | None = None
    task_id: str | None = None
    delegation_depth: int = 0
    extra_claims: dict[str, object] = field(default_factory=dict)


@runtime_checkable
class Grant(Protocol):
    """One door into the shared issuance room."""

    grant_type: str
    requires_client_auth: bool
    response_types: frozenset[str]

    def resolve(self, form: TokenForm, client: RegisteredClient | None) -> GrantResult:
        """Step 1 of the pipeline. The only step that differs per grant."""

    def metadata(self, settings: object) -> dict[str, object]:
        """Discovery keys this grant contributes when it is installed."""

    def openapi_schema(self) -> dict[str, object]:
        """The request body this grant accepts, for the generated API document."""
