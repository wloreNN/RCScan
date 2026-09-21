"""Bounded same-origin web discovery with no form submission or payload testing."""

from __future__ import annotations

import asyncio
import re
from collections import deque
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import (
    SplitResult,
    parse_qsl,
    quote,
    unquote,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)
from xml.etree import ElementTree

from rcscan.fingerprint.models import Service
from rcscan.network.models import HostScanResult, PortState
from rcscan.web.http import WebHttpClient, WebResponse
from rcscan.web.models import (
    ParameterSource,
    WebDiscoveryResult,
    WebEndpoint,
    WebForm,
    WebParameter,
)
from rcscan.web.request_context import WebRequestContext
from rcscan.web.throttle import OriginThrottleCoordinator

_IGNORED_SCHEMES = ("mailto:", "javascript:", "data:", "tel:")
_BINARY_SUFFIXES = {
    ".7z",
    ".avi",
    ".bmp",
    ".css.map",
    ".doc",
    ".docx",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".jpeg",
    ".jpg",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".svg",
    ".tar",
    ".webp",
    ".woff",
    ".woff2",
    ".zip",
}
_API_REFERENCE = re.compile(
    r"""(?P<quote>["'])(?P<url>/api/[A-Za-z0-9_./?&=%+-]{1,500})(?P=quote)"""
)
_SECURITY_EVIDENCE_HEADERS = {
    "access-control-allow-credentials",
    "access-control-allow-origin",
    "content-security-policy",
    "content-type",
    "referrer-policy",
    "server",
    "strict-transport-security",
    "vary",
    "x-content-type-options",
    "x-frame-options",
}


class WebCrawler:
    def __init__(
        self,
        *,
        max_pages: int,
        max_depth: int,
        concurrency: int,
        timeout_seconds: float,
        max_response_bytes: int,
        max_links_per_page: int,
        request_context: WebRequestContext | None = None,
        throttle: OriginThrottleCoordinator | None = None,
        client: WebHttpClient | None = None,
    ) -> None:
        self._max_pages = max_pages
        self._max_depth = max_depth
        self._concurrency = concurrency
        self._max_links_per_page = max_links_per_page
        self._semaphore = asyncio.Semaphore(concurrency)
        self._request_context = request_context or WebRequestContext()
        self._client = client or WebHttpClient(
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            request_context=self._request_context,
            throttle=throttle,
        )

    async def discover(
        self,
        hosts: tuple[HostScanResult, ...],
    ) -> tuple[WebDiscoveryResult, ...]:
        targets = _confirmed_web_origins(hosts)
        if not targets:
            return ()
        results: list[WebDiscoveryResult] = []
        remaining_pages = self._max_pages
        for origin, connect_host in targets:
            if remaining_pages <= 0:
                break
            result = await self._crawl_origin(
                origin,
                connect_host,
                page_limit=remaining_pages,
            )
            results.append(result)
            remaining_pages -= result.pages_crawled
        return tuple(results)

    async def _crawl_origin(
        self,
        origin: str,
        connect_host: str,
        *,
        page_limit: int,
    ) -> WebDiscoveryResult:
        started_at = datetime.now(UTC)
        self._request_context.register_origin(origin)
        if isinstance(self._client, WebHttpClient):
            self._client.register_origin(origin)
        queue: deque[tuple[str, int]] = deque()
        seen_shapes: set[str] = set()
        for candidate in ("/", "/robots.txt", "/sitemap.xml"):
            normalized = _normalize_url(origin, candidate, origin)
            if normalized is not None:
                queue.append((normalized, 0))
                seen_shapes.add(_url_shape(normalized))

        fetched_endpoints: list[WebEndpoint] = []
        discovered_urls: dict[str, int] = {
            url: depth for url, depth in queue
        }
        resource_reference_urls: set[str] = set()
        forms: list[WebForm] = []
        scripts: set[str] = set()
        resources: set[str] = set()
        robots_entries: set[str] = set()
        sitemap_urls: set[str] = set()
        errors: list[str] = []

        while queue and len(fetched_endpoints) < page_limit:
            batch: list[tuple[str, int]] = []
            while (
                queue
                and len(batch) < self._concurrency
                and len(fetched_endpoints) + len(batch) < page_limit
            ):
                batch.append(queue.popleft())
            responses = await asyncio.gather(
                *(
                    self._get(url, connect_host=connect_host)
                    for url, _depth in batch
                )
            )
            for (url, depth), response in zip(batch, responses, strict=True):
                endpoint = _endpoint(url, depth, response)
                fetched_endpoints.append(endpoint)
                if response.error:
                    errors.append(f"{url}: {response.error}")
                    continue
                links: list[tuple[str, bool]] = []
                if 300 <= (response.status_code or 0) < 400:
                    location = response.headers.get("location")
                    if location:
                        links.append((location, False))
                elif response.body:
                    content_type = response.headers.get("content-type", "").casefold()
                    path = urlsplit(url).path
                    if path == "/robots.txt":
                        entries, robot_links = _parse_robots(response.body)
                        robots_entries.update(entries)
                        links.extend((link, False) for link in robot_links)
                    elif path == "/sitemap.xml" or "xml" in content_type:
                        urls, xml_error = _parse_sitemap(response.body)
                        for discovered in urls:
                            normalized = _normalize_url(url, discovered, origin)
                            if normalized is not None:
                                sitemap_urls.add(normalized)
                                links.append((normalized, False))
                        if xml_error:
                            errors.append(f"{url}: {xml_error}")
                    elif "html" in content_type or not content_type:
                        page = _parse_html(response.body, page_url=url, origin=origin)
                        forms.extend(page.forms)
                        scripts.update(page.scripts)
                        resources.update(page.resources)
                        links.extend((link, False) for link in page.links)
                        resource_references = sorted(
                            {
                                *page.scripts,
                                *page.resources,
                            }
                        )
                        links.extend(
                            (reference, True)
                            for reference in resource_references
                            if urlsplit(reference).query
                        )
                for candidate, resource_only in links[: self._max_links_per_page]:
                    normalized = _normalize_url(url, candidate, origin)
                    if normalized is None:
                        continue
                    shape = _url_shape(normalized)
                    if shape in seen_shapes:
                        continue
                    seen_shapes.add(shape)
                    discovered_urls.setdefault(normalized, depth + 1)
                    if resource_only:
                        resource_reference_urls.add(normalized)
                        continue
                    if depth >= self._max_depth or _looks_binary(normalized):
                        continue
                    queue.append((normalized, depth + 1))

        fetched_urls = {endpoint.url for endpoint in fetched_endpoints}
        endpoints = [
            *fetched_endpoints,
            *(
                _endpoint(
                    url,
                    depth,
                    WebResponse(),
                    discovered_via_resource=url in resource_reference_urls,
                )
                for url, depth in discovered_urls.items()
                if url not in fetched_urls
            ),
        ]
        return WebDiscoveryResult(
            origin=origin,
            connect_host=connect_host,
            pages_crawled=len(fetched_endpoints),
            endpoints=tuple(endpoints),
            forms=tuple(_dedupe_forms(forms)),
            scripts=tuple(sorted(scripts)),
            resources=tuple(sorted(resources)),
            robots_entries=tuple(sorted(robots_entries)),
            sitemap_urls=tuple(sorted(sitemap_urls)),
            errors=tuple(errors[:20]),
            started_at=started_at,
            completed_at=datetime.now(UTC),
        )

    async def _get(self, url: str, *, connect_host: str) -> WebResponse:
        async with self._semaphore:
            return await self._client.get(url, connect_host=connect_host)


def _confirmed_web_origins(
    hosts: tuple[HostScanResult, ...],
) -> tuple[tuple[str, str], ...]:
    targets: dict[str, str] = {}
    for host in hosts:
        connect_host = host.resolved_address or host.target
        request_host = host.target
        for port in host.ports:
            if (
                port.state is not PortState.OPEN
                or port.fingerprint is None
                or port.fingerprint.service not in {Service.HTTP, Service.HTTPS}
            ):
                continue
            scheme = "https" if port.fingerprint.service is Service.HTTPS else "http"
            default_port = 443 if scheme == "https" else 80
            authority = request_host if port.port == default_port else f"{request_host}:{port.port}"
            targets.setdefault(f"{scheme}://{authority}", connect_host)
    return tuple(targets.items())


def _endpoint(
    url: str,
    depth: int,
    response: WebResponse,
    *,
    discovered_via_resource: bool = False,
) -> WebEndpoint:
    parsed = urlsplit(url)
    parameters = tuple(
        WebParameter(name=name, source=ParameterSource.QUERY)
        for name in dict.fromkeys(
            name
            for name, _value in parse_qsl(parsed.query, keep_blank_values=True)
        )
        if name
    )
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    return WebEndpoint(
        url=url,
        path=path,
        depth=depth,
        status_code=response.status_code,
        content_type=response.headers.get("content-type"),
        response_headers={
            name: value
            for name, value in response.headers.items()
            if name in _SECURITY_EVIDENCE_HEADERS
        },
        cookies=response.cookies,
        body_preview=response.body.decode("utf-8", errors="replace")[:16_384],
        query_parameters=parameters,
        error=response.error,
        truncated=response.truncated,
        discovered_via_resource=discovered_via_resource,
    )


class _PageParser(HTMLParser):
    def __init__(self, page_url: str, origin: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.origin = origin
        self.links: list[str] = []
        self.forms: list[WebForm] = []
        self.scripts: set[str] = set()
        self.resources: set[str] = set()
        self._form_method: str | None = None
        self._form_action: str | None = None
        self._form_inputs: list[WebParameter] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        values = {name.casefold(): value or "" for name, value in attrs}
        normalized_tag = tag.casefold()
        if normalized_tag in {"a", "area"} and values.get("href"):
            self.links.append(values["href"])
        elif normalized_tag == "script" and values.get("src"):
            normalized = _normalize_url(self.page_url, values["src"], self.origin)
            if normalized is not None:
                self.scripts.add(normalized)
        elif normalized_tag in {"link", "img", "source"}:
            reference = values.get("href") or values.get("src")
            if reference:
                normalized = _normalize_url(self.page_url, reference, self.origin)
                if normalized is not None:
                    self.resources.add(normalized)
        elif normalized_tag == "form":
            self._finish_form()
            method = values.get("method", "GET").upper()
            self._form_method = method if method in {"GET", "POST"} else "GET"
            action = values.get("action") or self.page_url
            self._form_action = _normalize_url(self.page_url, action, self.origin)
            self._form_inputs = []
        elif normalized_tag in {"input", "select", "textarea", "button"}:
            name = values.get("name")
            if (
                self._form_method is not None
                and name
                and "disabled" not in values
            ):
                input_type = values.get("type") or normalized_tag
                self._form_inputs.append(
                    WebParameter(
                        name=name[:200],
                        source=ParameterSource.FORM,
                        input_type=input_type[:50],
                    )
                )

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "form":
            self._finish_form()

    def _finish_form(self) -> None:
        if self._form_method is not None and self._form_action is not None:
            self.forms.append(
                WebForm(
                    page_url=self.page_url,
                    method=self._form_method,
                    action_url=self._form_action,
                    inputs=tuple(self._form_inputs),
                )
            )
        self._form_method = None
        self._form_action = None
        self._form_inputs = []

    def close(self) -> None:
        super().close()
        self._finish_form()


def _parse_html(body: bytes, *, page_url: str, origin: str) -> _PageParser:
    text = body.decode("utf-8", errors="replace")
    parser = _PageParser(page_url, origin)
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        pass
    for match in _API_REFERENCE.finditer(text):
        parser.links.append(match.group("url"))
    return parser


def _parse_robots(body: bytes) -> tuple[set[str], list[str]]:
    entries: set[str] = set()
    links: list[str] = []
    for line in body.decode("utf-8", errors="replace").splitlines():
        key, separator, value = line.partition(":")
        value = value.strip()
        if separator and key.strip().casefold() in {"allow", "disallow"} and value:
            entries.add(f"{key.strip().title()}: {value[:500]}")
        elif separator and key.strip().casefold() == "sitemap" and value:
            links.append(value[:2_048])
    return entries, links


def _parse_sitemap(body: bytes) -> tuple[set[str], str | None]:
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError as exc:
        return set(), f"Malformed sitemap XML: {exc}"
    urls = {
        (element.text or "").strip()[:2_048]
        for element in root.iter()
        if element.tag.rsplit("}", 1)[-1].casefold() == "loc" and (element.text or "").strip()
    }
    return urls, None


def _normalize_url(base: str, candidate: str, origin: str) -> str | None:
    candidate = candidate.strip()
    if not candidate or candidate.casefold().startswith(_IGNORED_SCHEMES):
        return None
    if len(candidate) > 2_048 or any(ord(character) < 0x20 for character in candidate):
        return None
    try:
        joined = urlsplit(urljoin(base, candidate))
        expected = urlsplit(origin)
        if (
            joined.scheme not in {"http", "https"}
            or joined.username is not None
            or joined.password is not None
            or _origin_key(joined) != _origin_key(expected)
        ):
            return None
        path = quote(unquote(joined.path or "/"), safe="/:@-._~!$&'()*+,;=")
        segments = [segment for segment in path.split("/") if segment]
        if any(segments.count(segment) > 3 for segment in set(segments)):
            return None
        query_pairs = parse_qsl(joined.query, keep_blank_values=True)[:20]
        query = urlencode(sorted(query_pairs), doseq=True)
        return urlunsplit((joined.scheme, joined.netloc, path, query, ""))
    except (UnicodeError, ValueError):
        return None


def _origin_key(parsed: SplitResult) -> tuple[str, str, int]:
    scheme = parsed.scheme.casefold()
    host = (parsed.hostname or "").casefold()
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, host, port


def _url_shape(url: str) -> str:
    parsed = urlsplit(url)
    names = sorted(
        {name for name, _value in parse_qsl(parsed.query, keep_blank_values=True)}
    )
    return urlunsplit(
        (
            parsed.scheme.casefold(),
            parsed.netloc.casefold(),
            parsed.path or "/",
            "&".join(names),
            "",
        )
    )


def _looks_binary(url: str) -> bool:
    return any(urlsplit(url).path.casefold().endswith(suffix) for suffix in _BINARY_SUFFIXES)


def _dedupe_forms(forms: list[WebForm]) -> list[WebForm]:
    unique: dict[tuple[str, str, tuple[str, ...]], WebForm] = {}
    for form in forms:
        key = (
            form.method,
            form.action_url,
            tuple(parameter.name for parameter in form.inputs),
        )
        unique.setdefault(key, form)
    return list(unique.values())
