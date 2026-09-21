"""Structured, bounded web-discovery records."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ParameterSource(StrEnum):
    QUERY = "QUERY"
    FORM = "FORM"


class WebParameter(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1, max_length=200)
    source: ParameterSource
    input_type: str | None = Field(default=None, max_length=50)


class WebForm(BaseModel):
    model_config = ConfigDict(frozen=True)

    page_url: str = Field(min_length=1, max_length=2_048)
    method: str = Field(pattern=r"^(?:GET|POST)$")
    action_url: str = Field(min_length=1, max_length=2_048)
    inputs: tuple[WebParameter, ...] = ()


class WebCookie(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1, max_length=100)
    secure: bool = False
    http_only: bool = False
    same_site: str | None = Field(default=None, max_length=20)


class WebEndpoint(BaseModel):
    model_config = ConfigDict(frozen=True)

    url: str = Field(min_length=1, max_length=2_048)
    path: str = Field(min_length=1, max_length=2_048)
    depth: int = Field(ge=0, le=11)
    status_code: int | None = Field(default=None, ge=100, le=599)
    content_type: str | None = Field(default=None, max_length=200)
    response_headers: dict[str, str] = Field(default_factory=dict)
    cookies: tuple[WebCookie, ...] = ()
    body_preview: str = Field(default="", max_length=16_384)
    query_parameters: tuple[WebParameter, ...] = ()
    error: str | None = Field(default=None, max_length=300)
    truncated: bool = False
    discovered_via_resource: bool = False


class WebDiscoveryResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    origin: str = Field(min_length=1, max_length=2_048)
    connect_host: str | None = Field(default=None, min_length=1, max_length=253)
    pages_crawled: int = Field(default=0, ge=0, le=500)
    endpoints: tuple[WebEndpoint, ...] = ()
    forms: tuple[WebForm, ...] = ()
    scripts: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    robots_entries: tuple[str, ...] = ()
    sitemap_urls: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    started_at: datetime
    completed_at: datetime

    @property
    def query_parameter_count(self) -> int:
        return len(
            {
                parameter.name
                for endpoint in self.endpoints
                for parameter in endpoint.query_parameters
            }
        )
