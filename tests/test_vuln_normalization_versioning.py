import pytest

from rcscan.fingerprint.models import Confidence, Service, ServiceFingerprint
from rcscan.vuln.models import AffectedRange, Applicability, NormalizedIdentity
from rcscan.vuln.normalization import normalize_fingerprint
from rcscan.vuln.versioning import compare_versions, match_affected_range, parse_version


def fingerprint(
    product: str | None,
    version: str | None,
    *,
    service: Service = Service.HTTP,
    confidence: Confidence = Confidence.HIGH,
) -> ServiceFingerprint:
    return ServiceFingerprint(
        service=service,
        product=product,
        version=version,
        confidence=confidence,
        evidence=(),
        probe_used="synthetic",
    )


@pytest.mark.parametrize(
    ("alias", "vendor", "product"),
    [
        ("nginx", "nginx", "nginx"),
        (" NGINX ", "nginx", "nginx"),
        ("OpenSSH", "openbsd", "openssh"),
        ("apache", "apache", "http_server"),
        ("Apache HTTP Server", "apache", "http_server"),
        ("  APACHE   HTTP SERVER ", "apache", "http_server"),
        ("Microsoft-IIS", "microsoft", "internet_information_services"),
    ],
)
def test_normalization_accepts_only_exact_conservative_aliases(
    alias: str, vendor: str, product: str
) -> None:
    result = normalize_fingerprint(fingerprint(alias, "1.10", confidence=Confidence.MEDIUM))

    assert result is not None
    assert (result.vendor, result.product, result.version) == (vendor, product, "1.10")
    assert result.cpe23 == f"cpe:2.3:a:{vendor}:{product}:1.10:*:*:*:*:*:*:*"
    assert result.confidence is Confidence.MEDIUM
    assert result.cache_key == f"{vendor}|{product}|1.10"
    assert "dotted numeric" in result.reason


@pytest.mark.parametrize(
    ("product", "version", "service"),
    [
        ("custom nginx", "1.2", Service.HTTP),
        ("nginx proxy", "1.2", Service.HTTP),
        ("Apache Tomcat", "9.0", Service.HTTP),
        ("Apache-Coyote", "1.1", Service.HTTP),
        ("Dropbear", "2024.85", Service.SSH),
        ("unknown ssh", "2.0", Service.SSH),
        ("OpenSSL", "3.0", Service.TLS),
        ("TLS", "1.3", Service.TLS),
        ("nginx", "1.2.3-rc1", Service.HTTP),
        ("OpenSSH", "9.8p1", Service.SSH),
        ("nginx", "", Service.HTTP),
        ("nginx", None, Service.HTTP),
        (None, "1.2", Service.UNKNOWN),
    ],
)
def test_normalization_refuses_guesses(
    product: str | None, version: str | None, service: Service
) -> None:
    assert normalize_fingerprint(fingerprint(product, version, service=service)) is None


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.10", "1.9", 1),
        ("1.9", "1.10", -1),
        ("1", "1.0.0", 0),
        ("1.0.0", "1", 0),
        ("01.002", "1.2.0", 0),
        ("0", "0.0", 0),
        ("2.0", "1.999", 1),
    ],
)
def test_dotted_numeric_comparison(
    left: str, right: str, expected: int
) -> None:
    assert compare_versions(left, right) == expected


@pytest.mark.parametrize(
    "value",
    ["", "1.", ".1", "1..2", "v1.2", "1.2rc1", "1.2-rc1", "1.2+build", "*", "-"],
)
def test_malformed_or_prerelease_versions_are_unknown(value: str) -> None:
    assert parse_version(value) is None
    assert compare_versions(value, "1.2") is None
    assert compare_versions("1.2", value) is None


def identity(version: str = "2.0") -> NormalizedIdentity:
    return NormalizedIdentity(
        original_product="nginx",
        vendor="nginx",
        product="nginx",
        version=version,
        cpe23=f"cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*",
        confidence=Confidence.HIGH,
        reason="synthetic",
    )


@pytest.mark.parametrize(
    ("affected", "expected"),
    [
        (AffectedRange(vendor="nginx", product="nginx", version="2.0"), Applicability.MATCH),
        (AffectedRange(vendor="nginx", product="nginx", version="2.1"), Applicability.NO_MATCH),
        (AffectedRange(vendor="nginx", product="nginx", version="*"), Applicability.MATCH),
        (AffectedRange(vendor="nginx", product="nginx", version="-"), Applicability.MATCH),
        (AffectedRange(vendor="nginx", product="nginx", version=None), Applicability.MATCH),
        (
            AffectedRange(vendor="nginx", product="nginx", version_start_including="2.0"),
            Applicability.MATCH,
        ),
        (
            AffectedRange(vendor="nginx", product="nginx", version_start_excluding="2.0"),
            Applicability.NO_MATCH,
        ),
        (
            AffectedRange(vendor="nginx", product="nginx", version_end_including="2.0"),
            Applicability.MATCH,
        ),
        (
            AffectedRange(vendor="nginx", product="nginx", version_end_excluding="2.0"),
            Applicability.NO_MATCH,
        ),
        (
            AffectedRange(
                vendor="nginx",
                product="nginx",
                version_start_including="1.5",
                version_end_excluding="2.1",
            ),
            Applicability.MATCH,
        ),
        (
            AffectedRange(vendor="nginx", product="nginx", version_start_including="2.1"),
            Applicability.NO_MATCH,
        ),
        (
            AffectedRange(vendor="nginx", product="nginx", version_end_including="1.9"),
            Applicability.NO_MATCH,
        ),
        (
            AffectedRange(vendor="nginx", product="nginx", version_start_including="bad"),
            Applicability.INDETERMINATE,
        ),
        (AffectedRange(vendor="apache", product="nginx"), Applicability.NO_MATCH),
        (AffectedRange(vendor="nginx", product="other"), Applicability.NO_MATCH),
        (
            AffectedRange(vendor="nginx", product="nginx", vulnerable=False),
            Applicability.NO_MATCH,
        ),
    ],
)
def test_exact_and_range_matching(
    affected: AffectedRange, expected: Applicability
) -> None:
    assert match_affected_range(identity(), affected) is expected


def test_malformed_observed_version_is_indeterminate_for_matching_product() -> None:
    assert (
        match_affected_range(
            identity("2.0-rc1"),
            AffectedRange(vendor="nginx", product="nginx", version="2.0"),
        )
        is Applicability.INDETERMINATE
    )
