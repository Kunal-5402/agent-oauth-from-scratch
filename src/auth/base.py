"""The client authentication contract.

Client authentication answers "which registered client is calling". It is
deliberately separate from the grant type, which answers "where does the
authority in the new token come from". The 2 are orthogonal: every method here
applies to every grant that needs a client.

A method does 2 things and no more:

* ``extract`` says "this request used my method", and pulls out what was sent.
* ``verify`` says "the proof is valid for this client".

Looking the client up, and returning one indistinguishable failure whatever went
wrong, stay in the registry. A method that could choose its own error message
would be a method that could leak which half was wrong.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from src.api.forms import TokenForm
from src.models import RegisteredClient


@dataclass(frozen=True)
class PresentedCredential:
    """What a caller sent, before anything has been checked."""

    client_id: str
    method: str
    secret: str | None = None
    assertion: str | None = None


@runtime_checkable
class ClientAuthMethod(Protocol):
    """One way for a client to prove who it is."""

    name: str

    def extract(self, headers: Mapping[str, str], form: TokenForm) -> PresentedCredential | None:
        """Return what was presented when this method was used, else None.

        Returning None means "not my method", which is what lets the registry
        detect a caller using 2 methods at once. Raise OAuthError only when this
        method was clearly attempted and the request is malformed.
        """

    async def verify(self, presented: PresentedCredential, client: RegisteredClient | None) -> bool:
        """Is the proof valid for this client?

        ``client`` is None when no such client exists. An implementation must
        still do comparable work in that case, or the response time tells an
        attacker which client IDs are real.
        """
