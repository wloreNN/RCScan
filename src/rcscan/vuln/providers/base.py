"""Provider contract for replaceable vulnerability intelligence sources."""

from __future__ import annotations

from typing import Protocol

from rcscan.vuln.models import NormalizedIdentity, ProviderQueryResult


class VulnerabilityProvider(Protocol):
    @property
    def name(self) -> str: ...

    async def search_product(
        self,
        identity: NormalizedIdentity,
    ) -> ProviderQueryResult: ...

    async def lookup_cve(self, cve_id: str) -> ProviderQueryResult: ...
