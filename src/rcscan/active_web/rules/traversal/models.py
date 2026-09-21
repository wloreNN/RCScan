"""Models for reviewed traversal rule families."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class TraversalPlatform(StrEnum):
    UNIX = "UNIX"
    WINDOWS = "WINDOWS"
    UNKNOWN = "UNKNOWN"


class TraversalFamily(StrEnum):
    CANONICAL_RELATIVE = "CANONICAL_RELATIVE"
    DEPTH_VARIANT = "DEPTH_VARIANT"
    URL_ENCODED = "URL_ENCODED"
    DOUBLE_ENCODED = "DOUBLE_ENCODED"
    SEPARATOR_VARIANT = "SEPARATOR_VARIANT"
    PATH_NORMALIZATION = "PATH_NORMALIZATION"


class TraversalVariant(BaseModel):
    model_config = ConfigDict(frozen=True)

    variant_id: str = Field(pattern=r"^traversal-[a-z0-9-]{3,100}$")
    family: TraversalFamily
    platform: TraversalPlatform
    value: str = Field(min_length=1, max_length=300)
    raw_encoded: bool = False
    initial: bool = False


class TraversalEligibility(BaseModel):
    model_config = ConfigDict(frozen=True)

    eligible: bool
    score: int = Field(ge=0, le=10)
    reasons: tuple[str, ...] = ()


class TraversalSignatureMatch(BaseModel):
    model_config = ConfigDict(frozen=True)

    marker_id: str = Field(min_length=1, max_length=100)
    platform: TraversalPlatform
    reason: str = Field(min_length=1, max_length=500)
