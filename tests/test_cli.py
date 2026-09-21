import socket
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest
from typer.testing import CliRunner

from rcscan import __version__
from rcscan.cli.main import app
from rcscan.core.config import AppConfig
from rcscan.models.scan import ScanStatus
from rcscan.network.models import (
    DiscoveryMethod,
    DiscoveryStatus,
    HostScanResult,
    PortResult,
    PortState,
    ScanRunResult,
)
from rcscan.services.scan_service import ScanService
from rcscan.web.models import (
    ParameterSource,
    WebDiscoveryResult,
    WebEndpoint,
    WebForm,
    WebParameter,
)
from rcscan.web_security.engine import WebSecurityEngine

runner = CliRunner()


def invoke_scan(*arguments: str):
    return runner.invoke(app, ["scan", *arguments])


def test_cli_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert f"RCScan {__version__}" in result.output


def test_cli_requires_authorization_confirmation() -> None:
    result = invoke_scan("--target", "10.0.0.1", "--scope", "10.0.0.0/8")

    assert result.exit_code == 2
    assert "Authorization confirmation is required" in result.output


@pytest.mark.parametrize(
    "source_arguments",
    [
        (),
        ("--target", "10.0.0.1", "--targets", "targets.txt"),
    ],
)
def test_cli_requires_exactly_one_target_source(source_arguments: tuple[str, ...]) -> None:
    result = invoke_scan(
        *source_arguments,
        "--scope",
        "10.0.0.0/8",
        "--confirm-authorized",
    )

    assert result.exit_code == 2
    assert "Provide exactly one of --target or --targets" in result.output


def completed_result(
    address: str,
    ports: tuple[PortResult, ...] = (),
) -> ScanRunResult:
    now = datetime.now(UTC)
    host = HostScanResult(
        target=address,
        resolved_address=address,
        discovery_status=DiscoveryStatus.REACHABLE,
        discovery_method=DiscoveryMethod.TCP_CONNECT,
        discovery_latency_ms=1,
        ports=ports,
        started_at=now,
        completed_at=now,
    )
    return ScanRunResult(
        scan_id=UUID(int=1),
        status=ScanStatus.COMPLETED,
        targets_requested=1,
        hosts_expanded=1,
        hosts=(host,),
        started_at=now,
        completed_at=now,
    )


def port(address: str, number: int, state: PortState) -> PortResult:
    return PortResult(
        host=address,
        port=number,
        state=state,
        latency_ms=1,
        timestamp=datetime.now(UTC),
    )


def test_cli_completes_private_scan_and_renders_summary() -> None:
    with patch(
        "rcscan.cli.main._run_with_progress",
        return_value=completed_result("10.1.2.3"),
    ):
        result = invoke_scan(
            "--target",
            "10.1.2.3",
            "--scope",
            "10.0.0.0/8",
            "--ports",
            "443,80",
            "--confirm-authorized",
        )

    assert result.exit_code == 0
    assert "COMPLETED" in result.output
    assert "Scope validation successful" in result.output
    assert "Scan completed" in result.output
    assert "Hosts expanded" in result.output


def test_cli_web_discovery_flag_and_bounded_summary() -> None:
    now = datetime.now(UTC)
    web = WebDiscoveryResult(
        origin="http://10.1.2.3",
        pages_crawled=1,
        endpoints=(
            WebEndpoint(
                url="http://10.1.2.3/search?q=test",
                path="/search?q=test",
                depth=1,
                status_code=200,
                content_type="text/html",
                query_parameters=(
                    WebParameter(name="q", source=ParameterSource.QUERY),
                ),
            ),
        ),
        forms=(
            WebForm(
                page_url="http://10.1.2.3/",
                method="POST",
                action_url="http://10.1.2.3/login",
                inputs=(
                    WebParameter(
                        name="user",
                        source=ParameterSource.FORM,
                        input_type="text",
                    ),
                ),
            ),
        ),
        scripts=("http://10.1.2.3/app.js",),
        started_at=now,
        completed_at=now,
    )
    run = completed_result("10.1.2.3").model_copy(
        update={"web_discovery_results": (web,)}
    )
    with patch("rcscan.cli.main._run_with_progress", return_value=run) as execute:
        result = invoke_scan(
            "--target",
            "10.1.2.3",
            "--scope",
            "10.0.0.0/8",
            "--confirm-authorized",
            "--web-discovery",
        )
    assert result.exit_code == 0
    assert execute.call_args.kwargs["web_discovery"] is True
    assert "Web discovery: ENABLED" in result.output
    assert "Pages crawled: 1" in result.output
    assert "Forms: 1" in result.output
    assert "Query parameters: 1" in result.output
    assert "Scripts: 1" in result.output


def test_cli_web_checks_auto_enable_discovery_and_render_summary() -> None:
    now = datetime.now(UTC)
    web = WebDiscoveryResult(
        origin="https://10.1.2.3",
        pages_crawled=1,
        endpoints=(
            WebEndpoint(
                url="https://10.1.2.3/",
                path="/",
                depth=0,
                status_code=200,
                content_type="text/html",
                response_headers={"server": "DemoServer/1.2.3"},
            ),
        ),
        started_at=now,
        completed_at=now,
    )
    web_findings = WebSecurityEngine().analyze((web,))
    run = completed_result("10.1.2.3").model_copy(
        update={
            "web_discovery_results": (web,),
            "web_findings": web_findings,
        }
    )
    with patch("rcscan.cli.main._run_with_progress", return_value=run) as execute:
        result = invoke_scan(
            "--target",
            "10.1.2.3",
            "--scope",
            "10.0.0.0/8",
            "--confirm-authorized",
            "--web-checks",
        )
    assert result.exit_code == 0
    assert execute.call_args.kwargs["web_checks"] is True
    assert "Web discovery: ENABLED" in result.output
    assert "Web security checks: ENABLED" in result.output
    assert "Information disclosure:" in result.output
    assert "HTTP server product and version disclosed" in result.output


def test_cli_active_web_checks_auto_enable_discovery_and_render_summary() -> None:
    now = datetime.now(UTC)
    web = WebDiscoveryResult(
        origin="http://10.1.2.3",
        pages_crawled=1,
        endpoints=(
            WebEndpoint(
                url="http://10.1.2.3/search?q=test",
                path="/search?q=test",
                depth=1,
                status_code=200,
                content_type="text/html",
            ),
        ),
        started_at=now,
        completed_at=now,
    )
    passive = WebSecurityEngine().analyze((web,))[0]
    active = passive.model_copy(
        update={
            "title": "Potential reflected XSS indicator",
            "source": "active-web-potential-reflected-xss",
            "metadata": {
                "category": "POTENTIAL_REFLECTED_XSS",
                "affected_url": "http://10.1.2.3/search?q=test",
                "parameter": "q",
            },
        }
    )
    traversal = passive.model_copy(
        update={
            "title": "Potential Path Traversal / Local File Disclosure",
            "source": "active-web-potential-path-traversal",
            "metadata": {
                "category": "POTENTIAL_PATH_TRAVERSAL",
                "affected_url": "http://10.1.2.3/download?filename=manual.pdf",
                "parameter": "filename",
                "rule_family": "traversal-windows-canonical",
                "platform": "WINDOWS",
                "confirmation_status": "CONFIRMED_BY_REPEAT",
            },
        }
    )
    run = completed_result("10.1.2.3").model_copy(
        update={
            "web_discovery_results": (web,),
            "active_web_findings": (active, traversal),
        }
    )
    with patch("rcscan.cli.main._run_with_progress", return_value=run) as execute:
        result = invoke_scan(
            "--target",
            "10.1.2.3",
            "--scope",
            "10.0.0.0/8",
            "--confirm-authorized",
            "--active-web-checks",
        )
    assert result.exit_code == 0
    assert execute.call_args.kwargs["active_web_checks"] is True
    assert "Web discovery: ENABLED" in result.output
    assert "Active web checks: ENABLED" in result.output
    assert "Active web security findings" in result.output
    assert "Potential reflected XSS: 1" in result.output
    assert "Potential path traversal: 1" in result.output
    assert "Potential Path Traversal / Local File Disclosure" in result.output
    assert "Parameter: filename" in result.output
    assert "Rule family: traversal-windows-canonical" in result.output
    assert "Platform: Windows" in result.output
    assert "Confirmation: CONFIRMED_BY_REPEAT" in result.output


@pytest.mark.parametrize(
    ("option", "filename"),
    [
        ("--report-json", "scan.json"),
        ("--report-html", "scan.html"),
        ("--report-sarif", "scan.sarif"),
    ],
)
def test_cli_writes_each_requested_report(
    tmp_path: Path,
    option: str,
    filename: str,
) -> None:
    destination = tmp_path / filename
    with patch(
        "rcscan.cli.main._run_with_progress",
        return_value=completed_result("10.1.2.3"),
    ) as execute:
        result = invoke_scan(
            "--target",
            "10.1.2.3",
            "--scope",
            "10.0.0.0/8",
            "--confirm-authorized",
            option,
            str(destination),
        )
    assert result.exit_code == 0
    assert destination.exists()
    assert execute.call_count == 1
    assert "report written" in result.output


def test_cli_writes_all_reports_without_rerunning_scan(tmp_path: Path) -> None:
    json_path = tmp_path / "scan.json"
    html_path = tmp_path / "scan.html"
    sarif_path = tmp_path / "scan.sarif"
    with patch(
        "rcscan.cli.main._run_with_progress",
        return_value=completed_result("10.1.2.3"),
    ) as execute:
        result = invoke_scan(
            "--target",
            "10.1.2.3",
            "--scope",
            "10.0.0.0/8",
            "--confirm-authorized",
            "--report-json",
            str(json_path),
            "--report-html",
            str(html_path),
            "--report-sarif",
            str(sarif_path),
        )
    assert result.exit_code == 0
    assert execute.call_count == 1
    assert all(path.exists() for path in (json_path, html_path, sarif_path))


def test_cli_report_write_failure_is_explicit_and_nonzero(tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("block", encoding="utf-8")
    with patch(
        "rcscan.cli.main._run_with_progress",
        return_value=completed_result("10.1.2.3"),
    ) as execute:
        result = invoke_scan(
            "--target",
            "10.1.2.3",
            "--scope",
            "10.0.0.0/8",
            "--confirm-authorized",
            "--report-json",
            str(blocker / "scan.json"),
        )
    assert result.exit_code == 1
    assert execute.call_count == 1
    assert "Reporting error:" in result.output
    assert not (blocker / "scan.json").exists()


def test_cli_static_auth_secrets_never_reach_output_or_reports(
    tmp_path: Path,
) -> None:
    header_secret = "CLI_HEADER_SENTINEL_f3249"
    cookie_secret = "CLI_COOKIE_SENTINEL_a881c"
    json_path = tmp_path / "auth.json"
    html_path = tmp_path / "auth.html"
    sarif_path = tmp_path / "auth.sarif"
    with patch(
        "rcscan.cli.main._run_with_progress",
        return_value=completed_result("10.1.2.3"),
    ):
        result = invoke_scan(
            "--target",
            "10.1.2.3",
            "--scope",
            "10.0.0.0/8",
            "--confirm-authorized",
            "--verbose",
            "--header",
            f"Authorization: Bearer {header_secret}",
            "--cookie",
            f"session={cookie_secret}",
            "--report-json",
            str(json_path),
            "--report-html",
            str(html_path),
            "--report-sarif",
            str(sarif_path),
        )
    assert result.exit_code == 0
    assert "Authentication context: configured" in result.output
    for payload in (
        result.output,
        json_path.read_text(encoding="utf-8"),
        html_path.read_text(encoding="utf-8"),
        sarif_path.read_text(encoding="utf-8"),
    ):
        assert header_secret not in payload
        assert cookie_secret not in payload


def test_cli_malformed_auth_input_does_not_echo_secret() -> None:
    secret = "MALFORMED_AUTH_SENTINEL_19bd"
    result = invoke_scan(
        "--target",
        "10.1.2.3",
        "--scope",
        "10.0.0.0/8",
        "--confirm-authorized",
        "--header",
        f"malformed-{secret}",
    )
    assert result.exit_code == 2
    assert "Invalid --header input" in result.output
    assert secret not in result.output


def test_cli_blocks_loopback_by_default() -> None:
    result = invoke_scan(
        "--target",
        "127.0.0.1",
        "--scope",
        "127.0.0.0/8",
        "--confirm-authorized",
    )

    assert result.exit_code == 2
    assert "Loopback target '127.0.0.1' is blocked" in result.output


def test_cli_allows_loopback_with_explicit_flag() -> None:
    with patch(
        "rcscan.cli.main._run_with_progress",
        return_value=completed_result("127.0.0.1"),
    ):
        result = invoke_scan(
            "--target",
            "127.0.0.1",
            "--scope",
            "127.0.0.0/8",
            "--allow-loopback",
            "--confirm-authorized",
        )

    assert result.exit_code == 0
    assert "COMPLETED" in result.output
    assert "Scope validation successful" in result.output


def test_cli_blocks_public_hostname_without_runtime_opt_in() -> None:
    with patch("rcscan.cli.main._run_with_progress") as execute:
        result = invoke_scan(
            "--target",
            "authorized-public.com",
            "--scope",
            "authorized-public.com",
            "--confirm-authorized",
        )

    assert result.exit_code == 2
    assert "Public target 'authorized-public.com' is blocked" in result.output
    execute.assert_not_called()


def test_cli_allows_exactly_scoped_public_hostname_with_runtime_opt_in() -> None:
    with patch(
        "rcscan.cli.main._run_with_progress",
        return_value=completed_result("authorized-public.com"),
    ) as execute:
        result = invoke_scan(
            "--target",
            "authorized-public.com",
            "--scope",
            "authorized-public.com",
            "--allow-public-targets",
            "--confirm-authorized",
        )

    assert result.exit_code == 0
    assert "Scope validation successful" in result.output
    execute.assert_called_once()


def test_cli_allows_explicitly_scoped_public_ipv4_with_runtime_opt_in() -> None:
    with patch(
        "rcscan.cli.main._run_with_progress",
        return_value=completed_result("203.0.113.9"),
    ):
        result = invoke_scan(
            "--target",
            "203.0.113.9",
            "--scope",
            "203.0.113.9",
            "--allow-public-targets",
            "--confirm-authorized",
        )

    assert result.exit_code == 0
    assert "Scope validation successful" in result.output


def test_public_runtime_opt_in_does_not_bypass_scope_identity() -> None:
    with patch("rcscan.cli.main._run_with_progress") as execute:
        result = invoke_scan(
            "--target",
            "public-a.com",
            "--scope",
            "public-b.com",
            "--allow-public-targets",
            "--confirm-authorized",
        )

    assert result.exit_code == 2
    assert "outside the explicitly authorized scope" in result.output
    execute.assert_not_called()


def test_public_runtime_opt_in_does_not_bypass_authorization_or_loopback_policy() -> None:
    missing_authorization = invoke_scan(
        "--target",
        "authorized-public.com",
        "--scope",
        "authorized-public.com",
        "--allow-public-targets",
    )
    blocked_loopback = invoke_scan(
        "--target",
        "127.0.0.1",
        "--scope",
        "127.0.0.1",
        "--allow-public-targets",
        "--confirm-authorized",
    )

    assert missing_authorization.exit_code == 2
    assert "Authorization confirmation is required" in missing_authorization.output
    assert blocked_loopback.exit_code == 2
    assert "Loopback target '127.0.0.1' is blocked" in blocked_loopback.output


def test_public_runtime_opt_in_does_not_mutate_configuration() -> None:
    settings = AppConfig()

    created = ScanService(settings).create_scan(
        target_value="authorized-public.com",
        targets_file=None,
        scope_value="authorized-public.com",
        ports_value="443",
        authorization_confirmed=True,
        allow_loopback=False,
        allow_public_targets=True,
    )

    assert created.targets[0].value == "authorized-public.com"
    assert settings.scope.allow_public_targets is False


def test_scan_service_validation_only_makes_zero_socket_calls() -> None:
    socket_apis = (
        "socket",
        "create_connection",
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
        "gethostbyaddr",
    )
    mocks: dict[str, MagicMock] = {}

    with ExitStack() as stack:
        for api_name in socket_apis:
            mocked = stack.enter_context(
                patch.object(
                    socket,
                    api_name,
                    autospec=True,
                    side_effect=AssertionError(f"network API called: socket.{api_name}"),
                )
            )
            mocks[api_name] = mocked

        scan = ScanService(AppConfig()).create_scan(
            target_value="192.168.50.10",
            targets_file=None,
            scope_value="192.168.50.0/24",
            ports_value="22,80,443",
            authorization_confirmed=True,
            allow_loopback=False,
        )

    assert scan.status is ScanStatus.PENDING
    for mocked in mocks.values():
        mocked.assert_not_called()


def test_cli_default_output_hides_non_open_ports() -> None:
    address = "10.0.0.1"
    run = completed_result(
        address,
        (
            port(address, 22, PortState.OPEN),
            port(address, 23, PortState.CLOSED),
        ),
    )
    with patch("rcscan.cli.main._run_with_progress", return_value=run):
        result = invoke_scan(
            "--target",
            address,
            "--scope",
            "10.0.0.0/8",
            "--ports",
            "22,23",
            "--confirm-authorized",
        )

    assert result.exit_code == 0
    assert "22/tcp" in result.output
    assert "23/tcp" not in result.output
    assert "Open ports" in result.output
    assert "Closed" in result.output


def test_cli_verbose_renders_all_port_states_and_forwards_options() -> None:
    address = "10.0.0.1"
    run = completed_result(address, (port(address, 23, PortState.CLOSED),))
    with patch(
        "rcscan.cli.main._run_with_progress", return_value=run
    ) as execute:
        result = invoke_scan(
            "--target",
            address,
            "--scope",
            "10.0.0.0/8",
            "--ports",
            "23",
            "--confirm-authorized",
            "--skip-discovery",
            "--verbose",
        )

    assert result.exit_code == 0
    assert "23/tcp" in result.output
    assert "CLOSED" in result.output
    assert execute.call_args.kwargs == {
        "skip_discovery": True,
        "assume_up": False,
        "no_fingerprint": False,
        "vulnerability_lookup": None,
        "active_verification": False,
        "web_discovery": False,
        "web_checks": False,
        "active_web_checks": False,
    }


def test_cli_keyboard_interrupt_returns_cancellation_exit_code() -> None:
    with patch(
        "rcscan.cli.main._run_with_progress", side_effect=KeyboardInterrupt
    ):
        result = invoke_scan(
            "--target",
            "10.0.0.1",
            "--scope",
            "10.0.0.0/8",
            "--confirm-authorized",
        )

    assert result.exit_code == 130
    assert "Scan cancelled" in result.output
