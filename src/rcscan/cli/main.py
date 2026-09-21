"""Typer and Rich command-line interface."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from rcscan import __version__
from rcscan.core.config import load_config
from rcscan.core.exceptions import RCScanError
from rcscan.core.logging import configure_logging
from rcscan.findings.models import Finding
from rcscan.fingerprint.models import Service
from rcscan.models.scan import Scan
from rcscan.network.errors import ScanExecutionError
from rcscan.network.models import (
    DiscoveryStatus,
    HostScanResult,
    PortState,
    ScanRunResult,
)
from rcscan.reporting import (
    ReportFeatures,
    build_report,
    write_html_report,
    write_json_report,
    write_sarif_report,
)
from rcscan.reporting.errors import ReportingError
from rcscan.scope.parser import parse_target
from rcscan.services.scan_runner import ScanRunner
from rcscan.services.scan_service import ScanService
from rcscan.verification.models import VerificationResult
from rcscan.web.models import WebDiscoveryResult
from rcscan.web.request_context import (
    WebRequestContext,
    parse_static_authentication,
)

console = Console()
error_console = Console(stderr=True)
app = typer.Typer(
    name="rcscan",
    help="Scope-first vulnerability assessment platform.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"RCScan {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the RCScan version and exit.",
        ),
    ] = None,
) -> None:
    """RCScan enforces explicit authorization scope before scan creation."""


@app.command("validate-target")
def validate_target_command(
    target: Annotated[str, typer.Argument(help="Target to validate.")],
) -> None:
    """Parse and normalize a target without network access."""
    try:
        parsed = parse_target(target)
    except RCScanError as exc:
        _fail(exc)
    console.print(f"[green]Valid target[/green]: {parsed.value} ({parsed.type.value})")


@app.command("validate-scope")
def validate_scope_command(
    scope: Annotated[str, typer.Argument(help="Scope entry to validate.")],
) -> None:
    """Parse and normalize one authorization scope entry."""
    try:
        parsed = parse_target(scope)
    except RCScanError as exc:
        _fail(exc)
    console.print(f"[green]Valid scope[/green]: {parsed.value} ({parsed.type.value})")


@app.command()
def scan(
    target: Annotated[
        str | None, typer.Option("--target", help="Single target IP, CIDR, or hostname.")
    ] = None,
    targets: Annotated[
        Path | None, typer.Option("--targets", help="UTF-8 file containing one target per line.")
    ] = None,
    scope: Annotated[
        str | None, typer.Option("--scope", help="Explicitly authorized scope entry.")
    ] = None,
    config: Annotated[
        Path | None, typer.Option("--config", help="Path to a YAML configuration file.")
    ] = None,
    ports: Annotated[
        str | None, typer.Option("--ports", help="Port preset, list, or range.")
    ] = None,
    confirm_authorized: Annotated[
        bool,
        typer.Option(
            "--confirm-authorized",
            help="Confirm explicit permission for every target in scope.",
        ),
    ] = False,
    allow_loopback: Annotated[
        bool,
        typer.Option(
            "--allow-loopback",
            help="Permit loopback targets for authorized local development.",
        ),
    ] = False,
    allow_public_targets: Annotated[
        bool,
        typer.Option(
            "--allow-public-targets",
            help="Permit explicitly scoped authorized public targets for this scan.",
        ),
    ] = False,
    skip_discovery: Annotated[
        bool,
        typer.Option(
            "--skip-discovery",
            help="Skip discovery probes and scan requested ports directly.",
        ),
    ] = False,
    assume_up: Annotated[
        bool,
        typer.Option(
            "--assume-up",
            help="Scan after inconclusive discovery; clearly unreachable hosts remain skipped.",
        ),
    ] = False,
    no_fingerprint: Annotated[
        bool,
        typer.Option(
            "--no-fingerprint",
            help="Run TCP scanning without application-layer fingerprint probes.",
        ),
    ] = False,
    vuln_lookup: Annotated[
        bool,
        typer.Option(
            "--vuln-lookup",
            help="Opt in to external vulnerability intelligence correlation.",
        ),
    ] = False,
    no_vuln_lookup: Annotated[
        bool,
        typer.Option(
            "--no-vuln-lookup",
            help="Disable lookup even when enabled by the active configuration.",
        ),
    ] = False,
    active_verification: Annotated[
        bool,
        typer.Option(
            "--active-verification",
            help="Opt in to bounded active verification for explicitly supported findings.",
        ),
    ] = False,
    web_discovery: Annotated[
        bool,
        typer.Option(
            "--web-discovery",
            help="Opt in to bounded same-origin web attack-surface discovery.",
        ),
    ] = False,
    web_checks: Annotated[
        bool,
        typer.Option(
            "--web-checks",
            help="Opt in to passive web security checks; enables web discovery.",
        ),
    ] = False,
    active_web_checks: Annotated[
        bool,
        typer.Option(
            "--active-web-checks",
            help="Opt in to controlled active GET checks; enables web discovery.",
        ),
    ] = False,
    header: Annotated[
        list[str] | None,
        typer.Option(
            "--header",
            help="Repeatable static HTTP header, formatted as 'Name: Value'.",
        ),
    ] = None,
    cookie: Annotated[
        list[str] | None,
        typer.Option(
            "--cookie",
            help="Repeatable origin-bound static cookie, formatted as 'name=value'.",
        ),
    ] = None,
    report_json: Annotated[
        Path | None,
        typer.Option("--report-json", help="Write a sanitized JSON report."),
    ] = None,
    report_html: Annotated[
        Path | None,
        typer.Option("--report-html", help="Write a standalone sanitized HTML report."),
    ] = None,
    report_sarif: Annotated[
        Path | None,
        typer.Option("--report-sarif", help="Write a sanitized SARIF 2.1.0 report."),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", help="Enable verbose application logging.")
    ] = False,
) -> None:
    """Run an authorized, bounded asynchronous TCP connect scan."""
    configure_logging(verbose)
    logger = logging.getLogger(__name__)
    if confirm_authorized:
        _show_authorization_panel()
    try:
        settings = load_config(config)
        service = ScanService(settings)
        created_scan = service.create_scan(
            target_value=target,
            targets_file=targets,
            scope_value=scope,
            ports_value=ports,
            authorization_confirmed=confirm_authorized,
            allow_loopback=allow_loopback,
            allow_public_targets=allow_public_targets,
        )
        request_context = WebRequestContext(
            parse_static_authentication(header, cookie)
        )
    except RCScanError as exc:
        _fail(exc)
    except Exception:
        logger.debug("Unexpected failure while creating a scan", exc_info=True)
        error_console.print("[red]Error:[/red] Unable to create scan due to an unexpected failure.")
        raise typer.Exit(code=1) from None

    if vuln_lookup and no_vuln_lookup:
        _fail(ScanExecutionError("--vuln-lookup and --no-vuln-lookup cannot be combined."))
    lookup_override = True if vuln_lookup else False if no_vuln_lookup else None
    verification_enabled = settings.verification.enabled or active_verification
    console.print("[green]Scope validation successful.[/green]")
    if verification_enabled:
        console.print("[yellow]Active verification: ENABLED[/yellow]")
    if (
        settings.web_discovery.enabled
        or web_discovery
        or web_checks
        or active_web_checks
        or settings.active_web_checks.enabled
    ):
        console.print("[yellow]Web discovery: ENABLED[/yellow]")
    if settings.web_checks.enabled or web_checks:
        console.print("[yellow]Web security checks: ENABLED[/yellow]")
    if settings.active_web_checks.enabled or active_web_checks:
        console.print("[yellow]Active web checks: ENABLED[/yellow]")
    console.print(
        f"[bold]Scan started[/bold]\n"
        f"Targets: {len(created_scan.targets)}\n"
        f"Ports: {len(created_scan.ports)}"
    )
    if request_context.authentication_configured:
        console.print("[yellow]Authentication context: configured[/yellow]")
    runner = ScanRunner(settings, request_context=request_context)
    try:
        result = _run_with_progress(
            runner,
            created_scan,
            skip_discovery=skip_discovery,
            assume_up=assume_up,
            no_fingerprint=no_fingerprint,
            vulnerability_lookup=lookup_override,
            active_verification=active_verification,
            web_discovery=web_discovery,
            web_checks=web_checks,
            active_web_checks=active_web_checks,
        )
    except (KeyboardInterrupt, asyncio.CancelledError):
        error_console.print("[yellow]Scan cancelled. Status: CANCELLED.[/yellow]")
        raise typer.Exit(code=130) from None
    except RCScanError as exc:
        _fail(exc)
    except Exception:
        logger.debug("Unexpected scan execution failure", exc_info=True)
        error_console.print(
            "[red]Error:[/red] Scan failed due to an unexpected error. Status: FAILED."
        )
        raise typer.Exit(code=1) from None
    _render_results(
        result,
        verbose=verbose,
        max_displayed_candidates=settings.vulnerability.max_displayed_candidates,
        max_displayed_findings=settings.findings.max_displayed,
        max_displayed_web=settings.web_discovery.max_displayed,
        max_displayed_web_findings=settings.web_checks.max_displayed,
        max_displayed_active_web_findings=(
            settings.active_web_checks.max_displayed
        ),
    )
    requested_reports = tuple(
        path for path in (report_json, report_html, report_sarif) if path is not None
    )
    if requested_reports:
        features = ReportFeatures(
            fingerprinting=not no_fingerprint,
            vulnerability_lookup=(
                (
                    settings.vulnerability.enabled
                    if lookup_override is None
                    else lookup_override
                )
                and not no_fingerprint
            ),
            active_verification=verification_enabled,
            web_discovery=(
                settings.web_discovery.enabled
                or web_discovery
                or settings.web_checks.enabled
                or web_checks
                or active_web_checks
                or settings.active_web_checks.enabled
            ),
            web_checks=settings.web_checks.enabled or web_checks,
            active_web_checks=(
                settings.active_web_checks.enabled or active_web_checks
            ),
        )
        try:
            report = build_report(created_scan, result, features=features)
            if report_json is not None:
                write_json_report(report, report_json)
                console.print(f"[green]JSON report written:[/green] {report_json}")
            if report_html is not None:
                write_html_report(report, report_html)
                console.print(f"[green]HTML report written:[/green] {report_html}")
            if report_sarif is not None:
                write_sarif_report(report, report_sarif)
                console.print(f"[green]SARIF report written:[/green] {report_sarif}")
        except ReportingError as exc:
            error_console.print(f"[red]Reporting error:[/red] {exc}")
            raise typer.Exit(code=1) from None
        except Exception:
            logger.debug("Unexpected report generation failure", exc_info=True)
            error_console.print(
                "[red]Reporting error:[/red] Requested reports could not be generated."
            )
            raise typer.Exit(code=1) from None


def _run_with_progress(
    runner: ScanRunner,
    scan: Scan,
    *,
    skip_discovery: bool,
    assume_up: bool,
    no_fingerprint: bool,
    vulnerability_lookup: bool | None,
    active_verification: bool,
    web_discovery: bool,
    web_checks: bool,
    active_web_checks: bool,
) -> ScanRunResult:
    ports_attempted = 0
    progress = Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        disable=not console.is_terminal,
    )
    with progress:
        task_id = progress.add_task("Preparing scan", total=1)

        def on_plan(host_count: int, _maximum_ports: int) -> None:
            progress.update(task_id, total=max(host_count, 1))

        def on_port(_result: object) -> None:
            nonlocal ports_attempted
            ports_attempted += 1
            progress.update(
                task_id,
                description=f"Scanning — ports attempted: {ports_attempted}",
            )

        def on_host(_result: HostScanResult) -> None:
            progress.advance(task_id)

        return asyncio.run(
            runner.run(
                scan,
                skip_discovery=skip_discovery,
                assume_up=assume_up,
                no_fingerprint=no_fingerprint,
                vulnerability_lookup=vulnerability_lookup,
                active_verification=active_verification,
                web_discovery=web_discovery,
                web_checks=web_checks,
                active_web_checks=active_web_checks,
                on_plan=on_plan,
                on_port=on_port,
                on_host=on_host,
            )
        )


def _render_results(
    result: ScanRunResult,
    *,
    verbose: bool,
    max_displayed_candidates: int,
    max_displayed_findings: int,
    max_displayed_web: int,
    max_displayed_web_findings: int,
    max_displayed_active_web_findings: int,
) -> None:
    remaining_candidates = max_displayed_candidates
    for host in result.hosts:
        address = host.resolved_address or host.target
        console.print(
            f"\n[bold]{address}[/bold] "
            f"(discovery: {host.discovery_status.value})"
        )
        if host.scan_skipped_reason:
            console.print(f"  [yellow]{host.scan_skipped_reason}[/yellow]")
        if host.error:
            console.print(f"  [red]{host.error}[/red]")
        if host.discovery_error and (
            verbose or host.discovery_status is DiscoveryStatus.UNREACHABLE
        ):
            console.print(f"  [yellow]{host.discovery_error}[/yellow]")
        shown_ports = (
            host.ports
            if verbose
            else tuple(port for port in host.ports if port.state is PortState.OPEN)
        )
        for port in shown_ports:
            style = "green" if port.state is PortState.OPEN else "default"
            console.print(f"  [{style}]{port.port}/tcp   {port.state.value}[/{style}]")
            if port.fingerprint is not None:
                fingerprint = port.fingerprint
                console.print(f"    Service     {fingerprint.service.value}")
                if fingerprint.product:
                    console.print(f"    Product     {fingerprint.product}")
                if fingerprint.version:
                    console.print(f"    Version     {fingerprint.version}")
                if fingerprint.service is not Service.UNKNOWN:
                    console.print(f"    Confidence  {fingerprint.confidence.value}")
                if verbose:
                    console.print(f"    Probe        {fingerprint.probe_used}")
                    console.print(
                        f"    Encrypted    {'yes' if fingerprint.encrypted else 'no'}"
                    )
                    for item in fingerprint.evidence:
                        console.print(f"    Evidence     {item.summary}")
                        if item.raw_preview:
                            console.print(f"                 {item.raw_preview}")
                    for key, value in sorted(fingerprint.metadata.items()):
                        console.print(f"    {key:<12} {value}")
            if port.vulnerability_lookup_error:
                console.print(
                    "    [yellow]Vulnerability intelligence unavailable:[/yellow] "
                    f"{port.vulnerability_lookup_error}"
                )
            if port.vulnerability_candidates:
                console.print("    [bold]Potential vulnerability matches:[/bold]")
                displayed = port.vulnerability_candidates[:remaining_candidates]
                for candidate in displayed:
                    console.print(
                        f"      {candidate.cve_id}  {candidate.status.value}"
                    )
                    if candidate.cvss is not None:
                        severity = candidate.cvss.base_severity or "UNSPECIFIED"
                        console.print(
                            f"        Published CVSS {candidate.cvss.version}: "
                            f"{candidate.cvss.base_score:.1f} {severity}"
                        )
                    console.print(
                        f"        Version match: {candidate.affected_match.value}"
                    )
                    console.print(
                        f"        Match confidence: {candidate.match_confidence.value}"
                    )
                    if verbose:
                        console.print(f"        Reason: {candidate.match_reason}")
                        console.print(
                            f"        Source: {candidate.source} "
                            f"({candidate.provenance.value})"
                        )
                remaining_candidates -= len(displayed)
                hidden = len(port.vulnerability_candidates) - len(displayed)
                if hidden:
                    console.print(f"      … {hidden} additional candidates not displayed")

    _render_findings(
        result.findings,
        verification_results=result.verification_results,
        verbose=verbose,
        max_displayed=max_displayed_findings,
    )
    _render_web_discovery(
        result.web_discovery_results,
        max_displayed=max_displayed_web,
    )
    _render_web_findings(
        result.web_findings,
        max_displayed=max_displayed_web_findings,
        heading="Web security findings",
    )
    _render_web_findings(
        result.active_web_findings,
        max_displayed=max_displayed_active_web_findings,
        heading="Active web security findings",
    )

    table = Table(title="Scan completed")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("Scan ID", str(result.scan_id))
    table.add_row("Status", result.status.value)
    table.add_row("Targets requested", str(result.targets_requested))
    table.add_row("Hosts expanded", str(result.hosts_expanded))
    table.add_row("Hosts discovered reachable", str(result.hosts_reachable))
    table.add_row("Hosts discovery inconclusive", str(result.hosts_inconclusive))
    table.add_row("Hosts scanned", str(result.hosts_scanned))
    table.add_row("Ports attempted", str(result.ports_attempted))
    table.add_row("Open ports", str(result.open_ports))
    table.add_row("Closed", str(result.closed_ports))
    table.add_row("Filtered/timeouts", str(result.filtered_ports))
    table.add_row("Errors", str(result.errors))
    table.add_row("Duration", f"{result.duration_seconds:.2f}s")
    console.print()
    console.print(table)


def _render_web_discovery(
    results: tuple[WebDiscoveryResult, ...],
    *,
    max_displayed: int,
) -> None:
    if not results:
        return
    pages = sum(result.pages_crawled for result in results)
    endpoints = sum(len(result.endpoints) for result in results)
    forms = sum(len(result.forms) for result in results)
    parameters = len(
        {
            parameter.name
            for result in results
            for endpoint in result.endpoints
            for parameter in endpoint.query_parameters
        }
    )
    scripts = sum(len(result.scripts) for result in results)
    console.print("\n[bold]Web discovery[/bold]")
    console.print(f"  Pages crawled: {pages}")
    console.print(f"  Endpoints: {endpoints}")
    console.print(f"  Forms: {forms}")
    console.print(f"  Query parameters: {parameters}")
    console.print(f"  Scripts: {scripts}")
    shown = 0
    for result in results:
        for endpoint in result.endpoints:
            if shown >= max_displayed:
                break
            console.print(f"  Path: {endpoint.path}")
            shown += 1
        for form in result.forms:
            if shown >= max_displayed:
                break
            names = ", ".join(parameter.name for parameter in form.inputs) or "none"
            console.print(
                f"  Form: {form.method} {form.action_url} (inputs: {names})"
            )
            shown += 1
        if shown >= max_displayed:
            break


def _render_web_findings(
    findings: tuple[Finding, ...],
    *,
    max_displayed: int,
    heading: str,
) -> None:
    if not findings:
        return
    labels = {
        "INFORMATION_DISCLOSURE": "Information disclosure",
        "SECURITY_MISCONFIGURATION": "Security misconfiguration",
        "COOKIE_SECURITY": "Cookie security",
        "CORS_CONFIGURATION": "CORS",
        "POTENTIAL_SQL_INJECTION": "Potential SQL injection",
        "POTENTIAL_REFLECTED_XSS": "Potential reflected XSS",
        "POTENTIAL_PATH_TRAVERSAL": "Potential path traversal",
    }
    counts = {
        category: sum(
            finding.metadata.get("category") == category for finding in findings
        )
        for category in labels
    }
    console.print(f"\n[bold]{heading}[/bold]")
    for category, label in labels.items():
        console.print(f"  {label}: {counts[category]}")
    for finding in findings[:max_displayed]:
        console.print(f"\n[bold]{finding.title}[/bold]")
        console.print(f"  URL: {finding.metadata.get('affected_url', finding.host)}")
        confirmation = None
        if finding.metadata.get("category") == "POTENTIAL_PATH_TRAVERSAL":
            parameter = finding.metadata.get("parameter")
            rule_family = finding.metadata.get("rule_family")
            platform = finding.metadata.get("platform")
            confirmation = finding.metadata.get("confirmation_status")
            if parameter:
                console.print(f"  Parameter: {parameter}")
            if rule_family:
                console.print(f"  Rule family: {rule_family}")
            if platform in {"UNIX", "WINDOWS"}:
                console.print(f"  Platform: {platform.title()}")
        console.print(
            f"  Severity/Priority: {finding.severity.value}/{finding.priority.value}"
        )
        console.print(f"  Confidence: {finding.confidence.value}")
        if (
            finding.metadata.get("category") == "POTENTIAL_PATH_TRAVERSAL"
            and confirmation
        ):
            console.print(f"  Confirmation: {confirmation}")
        for evidence in finding.evidence[:1]:
            console.print(f"  Evidence: {evidence.summary}")
        console.print(f"  Remediation: {finding.remediation.text}")
    hidden = len(findings) - min(len(findings), max_displayed)
    if hidden:
        console.print(f"\n  … {hidden} additional web findings not displayed")


def _render_findings(
    findings: tuple[Finding, ...],
    *,
    verification_results: tuple[VerificationResult, ...],
    verbose: bool,
    max_displayed: int,
) -> None:
    if not findings:
        return
    verification_by_finding = {
        result.finding_id: result for result in verification_results
    }
    console.print("\n[bold]Findings[/bold]")
    for finding in findings[:max_displayed]:
        console.print(
            f"\n[bold]\\[{finding.priority.value}][/bold] "
            f"[bold]Potential known vulnerability[/bold]"
        )
        if finding.cve_id:
            console.print(f"CVE: {finding.cve_id}")
        console.print(f"Asset: {finding.host}:{finding.port}")
        service = finding.service.value
        if finding.product:
            service += f" / {finding.product}"
        if finding.version:
            service += f" {finding.version}"
        console.print(f"Service: {service}")
        if finding.cvss is None:
            console.print("Published CVSS: unavailable")
        else:
            published = finding.cvss.base_severity or finding.severity.value
            console.print(
                f"Published CVSS: {finding.cvss.base_score:.1f} {published} "
                f"(v{finding.cvss.version})"
            )
        console.print(f"Severity: {finding.severity.value}")
        console.print(f"Applicability: {finding.applicability.value}")
        console.print(f"Confidence: {finding.confidence.value}")
        console.print(f"Priority: {finding.priority.value}")
        console.print(f"Reason: {finding.confidence_reason}")
        console.print(f"Remediation: {finding.remediation.text}")
        console.print(
            f"Remediation source: {finding.remediation.source} "
            f"({finding.remediation.provenance.value})"
        )
        verification = verification_by_finding.get(finding.finding_id)
        if verification is not None:
            console.print("Verification:")
            console.print(f"  Status: {verification.status.value}")
            console.print(f"  Verifier: {verification.verifier_name}")
            console.print(f"  Requests: {verification.requests_attempted}")
            console.print(f"  Reason: {verification.reason}")
            for evidence in verification.evidence:
                console.print(f"  Evidence: {evidence.summary}")
        if verbose:
            console.print(
                f"Finding ID: {finding.finding_id}\n"
                f"Provider: {finding.source} ({finding.provider_provenance.value})"
            )
            for reference in finding.references[:3]:
                console.print(f"Reference: {reference}")
            if len(finding.references) > 3:
                console.print(
                    f"… {len(finding.references) - 3} additional references not displayed"
                )
    hidden = len(findings) - min(len(findings), max_displayed)
    if hidden:
        console.print(f"\n… {hidden} additional findings not displayed")


def _show_authorization_panel() -> None:
    console.print(
        Panel(
            "RCScan is for authorized security testing only.\n"
            "The operator confirms they have explicit permission\n"
            "to assess every target included in the scan scope.\n\n"
            "Authorization confirmation does NOT disable scope validation.",
            title="Authorization Required",
            border_style="yellow",
        )
    )


def _fail(exc: RCScanError) -> NoReturn:
    error_console.print(f"[red]Error:[/red] {exc}")
    raise typer.Exit(code=2)
