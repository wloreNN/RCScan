"""Rate-limited client for the official NVD CVE API 2.0."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from time import monotonic
from typing import Any

import httpx

from rcscan import __version__
from rcscan.vuln.errors import (
    ProviderRateLimitError,
    ProviderResponseError,
    ProviderUnavailableError,
)
from rcscan.vuln.models import (
    LookupProvenance,
    NormalizedIdentity,
    ProviderQueryResult,
)
from rcscan.vuln.providers.nvd_parser import parse_nvd_response

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDProvider:
    def __init__(
        self,
        *,
        api_key: str | None,
        timeout_seconds: float,
        max_response_bytes: int,
        max_references: int,
        max_records: int,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._api_key = api_key
        self._timeout = httpx.Timeout(timeout_seconds)
        self._max_response_bytes = max_response_bytes
        self._max_references = max_references
        self._max_records = max_records
        self._client = client
        self._request_lock = asyncio.Lock()
        self._last_request = 0.0
        self._minimum_interval = 0.6 if api_key else 6.0

    @property
    def name(self) -> str:
        return "nvd"

    async def search_product(
        self,
        identity: NormalizedIdentity,
    ) -> ProviderQueryResult:
        document = await self._request(
            {
                "cpeName": identity.cpe23,
                "resultsPerPage": str(min(self._max_records, 100)),
            }
        )
        return self._result(document, identity.cache_key)

    async def lookup_cve(self, cve_id: str) -> ProviderQueryResult:
        document = await self._request({"cveId": cve_id})
        return self._result(document, cve_id)

    def _result(self, document: Any, identity_key: str) -> ProviderQueryResult:
        return ProviderQueryResult(
            provider=self.name,
            identity_key=identity_key,
            records=parse_nvd_response(
                document,
                max_references=self._max_references,
                max_records=self._max_records,
            ),
            lookup_at=datetime.now(UTC),
            provenance=LookupProvenance.LIVE,
        )

    async def _request(self, params: dict[str, str]) -> Any:
        headers = {
            "User-Agent": f"RCScan/{__version__} vulnerability-intelligence"
        }
        if self._api_key:
            headers["apiKey"] = self._api_key
        if self._client is not None:
            return await self._request_with_client(self._client, params, headers)
        async with httpx.AsyncClient(
            verify=True,
            follow_redirects=False,
            timeout=self._timeout,
        ) as client:
            return await self._request_with_client(client, params, headers)

    async def _request_with_client(
        self,
        client: httpx.AsyncClient,
        params: dict[str, str],
        headers: dict[str, str],
    ) -> Any:
        for attempt in range(2):
            await self._pace()
            try:
                async with client.stream(
                    "GET",
                    NVD_API_URL,
                    params=params,
                    headers=headers,
                    timeout=self._timeout,
                ) as response:
                    if response.status_code == 429:
                        if attempt == 0:
                            await asyncio.sleep(
                                _retry_after_seconds(response.headers.get("Retry-After"))
                            )
                            continue
                        raise ProviderRateLimitError(
                            "NVD rate limit prevented the vulnerability lookup."
                        )
                    if response.status_code >= 500:
                        if attempt == 0:
                            await asyncio.sleep(1.0)
                            continue
                        raise ProviderUnavailableError(
                            "NVD is temporarily unavailable."
                        )
                    if response.status_code in {401, 403}:
                        raise ProviderUnavailableError(
                            "NVD rejected the request credentials."
                        )
                    if response.status_code != 200:
                        raise ProviderUnavailableError(
                            f"NVD returned HTTP {response.status_code}."
                        )
                    payload = await _read_bounded(response, self._max_response_bytes)
            except asyncio.CancelledError:
                raise
            except httpx.TimeoutException as exc:
                raise ProviderUnavailableError("NVD request timed out.") from exc
            except httpx.RequestError as exc:
                raise ProviderUnavailableError("NVD network request failed.") from exc
            try:
                return json.loads(payload)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProviderResponseError("NVD returned malformed JSON.") from exc
        raise ProviderUnavailableError("NVD request did not complete.")

    async def _pace(self) -> None:
        async with self._request_lock:
            delay = self._minimum_interval - (monotonic() - self._last_request)
            if delay > 0:
                await asyncio.sleep(delay)
            self._last_request = monotonic()


async def _read_bounded(response: httpx.Response, limit: int) -> bytes:
    payload = bytearray()
    async for chunk in response.aiter_bytes():
        if len(payload) + len(chunk) > limit:
            raise ProviderResponseError("NVD response exceeded the configured size limit.")
        payload.extend(chunk)
    return bytes(payload)


def _retry_after_seconds(value: str | None) -> float:
    if value is None:
        return 1.0
    try:
        return min(30.0, max(0.0, float(value)))
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return 1.0
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)
        return min(30.0, max(0.0, (retry_at - datetime.now(UTC)).total_seconds()))
