"""JSON, standalone HTML, and SARIF exporters for canonical reports."""

from __future__ import annotations

import html
import json
import os
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from rcscan.reporting.errors import ReportingError
from rcscan.reporting.models import RCScanReport, ReportFinding


def write_json_report(
    report: RCScanReport,
    path: Path,
    *,
    pretty: bool = True,
) -> None:
    payload = json.dumps(
        report.model_dump(mode="json", by_alias=True),
        ensure_ascii=False,
        indent=2 if pretty else None,
        sort_keys=True,
    )
    _atomic_write(path, payload + "\n")


def write_html_report(report: RCScanReport, path: Path) -> None:
    _atomic_write(path, _html_document(report))


def write_sarif_report(report: RCScanReport, path: Path) -> None:
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for finding in report.findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.category,
                "shortDescription": {"text": finding.title},
                "help": {
                    "text": finding.remediation,
                },
                "properties": {
                    "category": finding.category,
                    "source": finding.source,
                },
            },
        )
        properties: dict[str, object] = {
            "findingId": finding.finding_id,
            "severity": finding.severity,
            "priority": finding.priority,
            "confidence": finding.confidence,
            "applicability": finding.applicability,
            "target": finding.target,
            "port": finding.port,
            "service": finding.service,
            "parameter": finding.parameter,
            "ruleFamily": finding.rule_family,
            "platform": finding.platform,
            "confirmation": finding.confirmation,
            "advisoryId": finding.advisory_id,
            "evidence": list(finding.evidence),
        }
        properties = {
            key: value for key, value in properties.items() if value is not None
        }
        result: dict[str, object] = {
            "ruleId": finding.rule_id,
            "level": _sarif_level(finding.severity),
            "message": {"text": _finding_message(finding)},
            "properties": properties,
        }
        if finding.url:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.url},
                    }
                }
            ]
        results.append(result)
    payload = {
        "$schema": (
            "https://json.schemastore.org/sarif-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RCScan",
                        "version": report.rcscan_version,
                        "informationUri": "https://github.com/wloreNN/RCScan",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": report.scan.status == "COMPLETED",
                        "properties": {
                            "scanId": report.scan.scan_id,
                            "schemaVersion": report.schema_version,
                        },
                    }
                ],
                "results": results,
            }
        ],
    }
    _atomic_write(
        path,
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def _atomic_write(path: Path, payload: str) -> None:
    temporary: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except (OSError, UnicodeError) as exc:
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
        raise ReportingError(f"Unable to write report '{path}': {exc}") from exc


def _finding_message(finding: ReportFinding) -> str:
    evidence = finding.evidence[0] if finding.evidence else "No evidence summary."
    return f"{finding.title}: {evidence}"


def _sarif_level(severity: str) -> str:
    if severity in {"CRITICAL", "HIGH"}:
        return "error"
    if severity == "MEDIUM":
        return "warning"
    if severity in {"LOW", "INFORMATIONAL"}:
        return "note"
    return "none"


def _html_document(report: RCScanReport) -> str:
    escape = html.escape
    severity_order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
    metadata_rows = (
        ("Started", report.scan.started_at.isoformat()),
        ("Completed", report.scan.completed_at.isoformat()),
        ("Duration", f"{report.scan.duration_seconds:.3f} seconds"),
        ("Targets", ", ".join(report.scan.targets) or "None"),
        ("Authorized scope", ", ".join(report.scan.authorized_scope) or "None"),
        ("Ports", ", ".join(str(port) for port in report.scan.selected_ports)),
        ("Profile", report.scan.profile_name),
    )
    host_rows = "".join(
        (
            "<tr>"
            f"<td>{escape(host.target)}</td>"
            f"<td>{escape(host.resolved_address or '—')}</td>"
            f"<td>{escape(host.discovery_status)}</td>"
            f"<td>{len(host.ports)}</td>"
            f"<td>{sum(port.state == 'OPEN' for port in host.ports)}</td>"
            "</tr>"
        )
        for host in report.hosts
    ) or '<tr><td colspan="5">No host results.</td></tr>'
    service_rows = "".join(
        (
            "<tr>"
            f"<td>{escape(host.target)}</td>"
            f"<td>{port.port}/{escape(port.protocol)}</td>"
            f"<td>{escape(port.state)}</td>"
            f"<td>{escape(port.service or '—')}</td>"
            f"<td>{escape(port.product or '—')}</td>"
            f"<td>{escape(port.version or '—')}</td>"
            f"<td>{escape(port.fingerprint_confidence or '—')}</td>"
            "</tr>"
        )
        for host in report.hosts
        for port in host.ports
    ) or '<tr><td colspan="7">No service results.</td></tr>'
    web_rows = "".join(
        (
            "<tr>"
            f"<td>{escape(item.origin)}</td>"
            f"<td>{item.pages_crawled}</td>"
            f"<td>{len(item.endpoints)}</td>"
            f"<td>{item.query_parameter_count}</td>"
            f"<td>{len(item.forms)}</td>"
            "</tr>"
        )
        for item in report.web_discovery
    ) or '<tr><td colspan="5">Web discovery was not run or returned no results.</td></tr>'
    finding_cards = "".join(_finding_html(finding) for finding in report.findings)
    if not finding_cards:
        finding_cards = '<p class="empty">No findings were generated.</p>'
    overview_rows = "".join(
        (
            "<tr>"
            f'<td><span class="badge severity-{finding.severity.casefold()}">'
            f"{escape(finding.severity)}</span></td>"
            f'<td class="title-cell">{escape(finding.title)}</td>'
            f"<td>{escape(finding.target)}:{finding.port}</td>"
            f"<td>{escape(finding.confidence)}</td>"
            f'<td class="wrap">{escape(finding.category)}</td>'
            "</tr>"
        )
        for finding in report.findings
    ) or '<tr><td colspan="5">No findings were generated.</td></tr>'
    severity_summary = "".join(
        _severity_item(
            name,
            report.summary.findings_by_severity.get(name, 0),
            report.summary.findings,
        )
        for name in severity_order
    )
    feature_list = "".join(
        f'<span class="feature {"enabled" if enabled else "disabled"}">'
        f"{escape(name.replace('_', ' ').title())}: "
        f"<strong>{'Enabled' if enabled else 'Disabled'}</strong></span>"
        for name, enabled in report.scan.features.model_dump().items()
    )
    metadata_table = "".join(
        f"<tr><th>{escape(label)}</th><td>{escape(str(value))}</td></tr>"
        for label, value in metadata_rows
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RCScan Report {escape(report.scan.scan_id)}</title>
<style>
:root {{ color-scheme:light; --ink:#172033; --muted:#667085; --line:#d7deea;
--panel:#fff; --bg:#f2f5f9; --navy:#12213f; --blue:#2459d3; --soft:#f8fafc; }}
* {{ box-sizing:border-box; }}
html {{ background:var(--bg); }}
body {{ margin:0; color:var(--ink); background:var(--bg);
font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; }}
main {{ max-width:1180px; margin:auto; padding:34px 22px 70px; }}
.report-header {{ color:#fff; padding:30px 32px; border-radius:16px;
background:linear-gradient(125deg,#0e1c38 0%,#17336d 62%,#2459d3 100%);
box-shadow:0 16px 38px #12213f26; }}
.header-row {{ display:flex; align-items:flex-start; justify-content:space-between; gap:24px; }}
.brand {{ display:flex; align-items:center; gap:16px; }}
.monogram {{ display:grid; place-items:center; width:52px; height:52px; border-radius:12px;
border:1px solid #ffffff55; background:#ffffff14; font-size:20px; font-weight:800;
letter-spacing:.08em; }}
h1 {{ margin:0; font-size:32px; line-height:1.2; letter-spacing:-.025em; }}
h2 {{ margin:0 0 16px; font-size:20px; letter-spacing:-.01em; }}
h3 {{ margin:0; }} h4 {{ margin:0 0 9px; font-size:13px; text-transform:uppercase;
letter-spacing:.055em; color:#46546b; }}
.subtitle {{ margin-top:5px; color:#dbe7ff; }}
.header-meta {{ min-width:260px; text-align:right; color:#e7edfa; }}
.header-meta div {{ margin-top:7px; }}
.scan-id {{ font:12px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace;
overflow-wrap:anywhere; }}
.status {{ display:inline-block; padding:5px 11px; border:1px solid #9be2b3;
border-radius:999px; background:#176b36; color:#fff; font-size:12px; font-weight:750; }}
.grid {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px;
margin:20px 0; }}
.metric,.panel,.finding {{ background:var(--panel); border:1px solid var(--line);
border-radius:12px; }}
.metric {{ padding:17px 18px; border-top:3px solid var(--blue); }}
.metric span {{ color:var(--muted); font-size:12px; font-weight:700; letter-spacing:.04em;
text-transform:uppercase; }}
.metric strong {{ display:block; margin-top:3px; font-size:28px; line-height:1.2; }}
.panel {{ margin:18px 0; padding:22px; box-shadow:0 3px 12px #12213f0a; }}
.section-intro {{ margin:-8px 0 16px; color:var(--muted); }}
.table-wrap {{ width:100%; overflow-x:auto; }}
table {{ width:100%; border-collapse:collapse; min-width:620px; }}
th,td {{ padding:11px 12px; text-align:left; border-bottom:1px solid #e5eaf1;
vertical-align:top; }}
thead th {{ color:#46546b; background:#f6f8fb; font-size:11px; text-transform:uppercase;
letter-spacing:.045em; white-space:nowrap; }}
tbody tr:last-child td,tbody tr:last-child th {{ border-bottom:0; }}
.title-cell {{ font-weight:700; color:#23324d; }}
.wrap,code,.url {{ overflow-wrap:anywhere; word-break:break-word; }}
.badge,.chip {{ display:inline-block; border-radius:999px; padding:4px 9px; font-size:11px;
font-weight:750; letter-spacing:.025em; background:#e9eef8; color:#344054; }}
.severity-critical {{ background:#fce4e4; color:#9e1c1c; }}
.severity-high {{ background:#ffe8df; color:#a33a13; }}
.severity-medium {{ background:#fff0c7; color:#815000; }}
.severity-low {{ background:#e3f0ff; color:#1855a0; }}
.severity-informational {{ background:#e7f4ec; color:#176b36; }}
.severity-grid {{ display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:10px;
margin-top:17px; }}
.severity-item {{ padding:11px; border:1px solid var(--line); border-radius:9px;
background:var(--soft); }}
.severity-head {{ display:flex; justify-content:space-between; gap:8px; align-items:center; }}
.severity-track {{ height:5px; margin-top:9px; border-radius:5px; background:#e2e8f0;
overflow:hidden; }}
.severity-fill {{ height:100%; min-width:0; background:var(--blue); }}
.feature-list {{ display:flex; flex-wrap:wrap; gap:7px; margin-top:12px; }}
.feature {{ padding:5px 9px; border:1px solid var(--line); border-radius:7px;
font-size:12px; }} .feature.enabled {{ color:#176b36; background:#edf8f1; }}
.feature.disabled {{ color:var(--muted); background:#f5f6f8; }}
.finding {{ margin:16px 0; border-left:5px solid #718096; overflow:hidden; }}
.finding.sev-critical {{ border-left-color:#b42318; }}
.finding.sev-high {{ border-left-color:#d64b1a; }}
.finding.sev-medium {{ border-left-color:#d18a00; }}
.finding.sev-low {{ border-left-color:#2878c7; }}
.finding.sev-informational {{ border-left-color:#2d8653; }}
.finding-head {{ display:flex; justify-content:space-between; gap:18px; align-items:flex-start;
padding:18px 20px; border-bottom:1px solid #e5eaf1; background:#fbfcfe; }}
.finding-head h3 {{ font-size:18px; line-height:1.35; }}
.finding-kicker {{ color:var(--muted); font:11px/1.4 ui-monospace,SFMono-Regular,monospace;
margin-top:4px; overflow-wrap:anywhere; }}
.finding-badges {{ display:flex; flex-wrap:wrap; justify-content:flex-end; gap:6px; }}
.finding-body {{ padding:19px 20px 21px; }}
.facts {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:8px; }}
.fact {{ min-width:0; padding:9px 10px; border-radius:7px; background:#f6f8fb; }}
.fact-label {{ display:block; margin-bottom:2px; color:var(--muted); font-size:10px;
font-weight:750; letter-spacing:.055em; text-transform:uppercase; }}
.report-blocks {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:16px; }}
.report-block {{ min-width:0; padding:14px 15px; border:1px solid var(--line);
border-radius:9px; background:#fff; }}
.report-block.evidence {{ border-top:3px solid #516f9f; }}
.report-block.reproduction {{ border-top:3px solid #7756b3; }}
.report-block.remediation {{ border-top:3px solid #2d8653; }}
.report-block.references {{ border-top:3px solid #7b8799; }}
.report-block p,.report-block ul {{ margin:0; }}
.report-block ul {{ padding-left:18px; }}
.repro-grid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:6px 12px;
margin-bottom:9px; }}
.repro-grid div {{ min-width:0; overflow-wrap:anywhere; }}
.empty,.note {{ color:var(--muted); }}
.appendix {{ background:#f8fafc; border-style:dashed; box-shadow:none; }}
@media (max-width:760px) {{
main {{ padding:18px 12px 44px; }} .report-header {{ padding:23px 20px; }}
.header-row {{ display:block; }} .header-meta {{ min-width:0; margin-top:20px; text-align:left; }}
.grid {{ grid-template-columns:repeat(2,minmax(0,1fr)); }}
.severity-grid {{ grid-template-columns:repeat(2,minmax(0,1fr)); }}
.facts,.report-blocks {{ grid-template-columns:1fr; }}
.finding-head {{ display:block; }}
.finding-badges {{ justify-content:flex-start; margin-top:12px; }}
}}
@media print {{
@page {{ margin:14mm; }} * {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
html,body {{ background:#fff; }} main {{ max-width:none; padding:0; }}
.report-header {{ box-shadow:none; }} .panel,.finding,.metric {{ box-shadow:none; }}
.finding,.metric,.severity-item,.report-block {{ break-inside:avoid; page-break-inside:avoid; }}
.panel {{ overflow:visible; }} .table-wrap {{ overflow:visible; }}
a {{ color:inherit; text-decoration:none; }} .finding {{ border-color:#cbd3df; }}
}}
</style>
</head>
<body><main>
<header class="report-header"><div class="header-row">
<div class="brand"><div class="monogram" aria-hidden="true">RC</div><div>
<h1>RCScan Security Assessment</h1>
<div class="subtitle">Evidence-driven security assessment report</div>
</div></div>
<div class="header-meta">
<span class="status">Status: {escape(report.scan.status)}</span>
<div>RCScan {escape(report.rcscan_version)} · Schema {escape(report.schema_version)}</div>
<div>{escape(report.scan.completed_at.isoformat())}</div>
<div class="scan-id">Scan ID · {escape(report.scan.scan_id)}</div>
</div></div></header>
<section class="grid">
<div class="metric"><span>Hosts</span><strong>{report.summary.hosts}</strong></div>
<div class="metric"><span>Open ports</span><strong>{report.summary.open_ports}</strong></div>
<div class="metric"><span>Web origins</span><strong>{report.summary.web_origins}</strong></div>
<div class="metric"><span>Findings</span><strong>{report.summary.findings}</strong></div>
</section>
<section class="panel"><h2>Executive Summary</h2>
<p>Findings are evidence-based assessment results and preserve RCScan's conservative
“Potential” semantics.</p>
<div class="severity-grid" aria-label="Finding severity distribution">
{severity_summary}</div></section>
<section class="panel"><h2>Scan Metadata</h2>
<div class="table-wrap"><table>{metadata_table}</table></div>
<h3>Enabled Features</h3><div class="feature-list">{feature_list}</div></section>
<section class="panel"><h2>Scope / Authorization Summary</h2>
<p>Authorization confirmed: <strong>{report.scan.authorization_confirmed!s}</strong>.
Targets and scope are listed exactly as supplied to the validated scan model.</p></section>
<section class="panel"><h2>Host Summary</h2><div class="table-wrap"><table><thead><tr>
<th>Target</th><th>Address</th><th>Discovery</th><th>Ports</th><th>Open</th></tr></thead>
<tbody>{host_rows}</tbody></table></div></section>
<section class="panel"><h2>Service Summary</h2><div class="table-wrap"><table><thead><tr>
<th>Target</th><th>Port</th>
<th>State</th><th>Service</th><th>Product</th><th>Version</th><th>Confidence</th></tr></thead>
<tbody>{service_rows}</tbody></table></div></section>
<section class="panel"><h2>Vulnerability Intelligence Summary</h2>
<p>{report.summary.vulnerability_candidates} correlated advisory candidate(s). Correlation
does not establish exploitability or confirmation.</p></section>
<section class="panel"><h2>Web Discovery Summary</h2><div class="table-wrap"><table>
<thead><tr><th>Origin</th>
<th>Pages</th><th>Endpoints</th><th>Parameters</th><th>Forms</th></tr></thead>
<tbody>{web_rows}</tbody></table></div></section>
<section class="panel"><h2>Findings Overview</h2>
<p class="section-intro">Compact triage view of all assessment results.</p>
<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Title</th>
<th>Affected asset</th><th>Confidence</th><th>Category</th></tr></thead>
<tbody>{overview_rows}</tbody></table></div></section>
<section class="panel"><h2>Detailed Findings</h2>{finding_cards}</section>
<section class="panel appendix"><h2>Methodology / Confidence</h2>
<p>Confidence reflects the strength
and repeatability of bounded observations. Severity and priority remain separate from
confidence. Advisory matches remain potential unless explicitly verified.</p></section>
<section class="panel appendix"><h2>Limitations / Safety Note</h2>
<p class="note">This report contains
sanitized summaries rather than raw traffic or response bodies. Secrets and sensitive
parameter values are redacted. Testing remained subject to configured authorization,
scope, timeout, concurrency, request, and response-size limits.</p></section>
</main></body></html>
"""


def _finding_html(finding: ReportFinding) -> str:
    escape = html.escape
    evidence = "".join(f"<li>{escape(item)}</li>" for item in finding.evidence)
    references = "".join(
        (
            f'<li><a href="{escape(reference, quote=True)}">{escape(reference)}</a></li>'
            if urlsplit(reference).scheme in {"http", "https"}
            else f"<li><code>{escape(reference)}</code></li>"
        )
        for reference in finding.references
    ) or "<li>None supplied</li>"
    platform = _fact("Platform", finding.platform) if finding.platform else ""
    reproduction = finding.reproduction
    reproduction_items = "".join(
        _reproduction_item(label, value)
        for label, value in (
            ("Method", reproduction.method),
            ("Parameter", reproduction.parameter),
            ("Baseline status", reproduction.baseline_status),
            ("Probe status", reproduction.probe_status),
            ("Content type", reproduction.response_content_type),
            ("Response length", reproduction.response_length),
            ("Rule ID", reproduction.rule_id),
            ("Confirmation", reproduction.confirmation),
        )
        if value is not None
    )
    return f"""<article class="finding sev-{finding.severity.casefold()}">
<div class="finding-head"><div><h3>{escape(finding.title)}</h3>
<div class="finding-kicker">{escape(finding.finding_id)}</div></div>
<div class="finding-badges">
<span class="badge severity-{finding.severity.casefold()}">{escape(finding.severity)}</span>
<span class="chip">Priority: {escape(finding.priority)}</span>
<span class="chip">Confidence: {escape(finding.confidence)}</span>
</div></div>
<div class="finding-body">
<div class="facts">
{_fact("Affected asset", f"{finding.target}:{finding.port}")}
{_fact("URL", finding.url or "—", css_class="url")}
{_fact("Parameter", finding.parameter or "—")}
{_fact("Rule family", finding.rule_family or finding.rule_id)}
{platform}
{_fact("Confirmation", finding.confirmation or "Not available")}
{_fact("Category", finding.category)}
</div>
<div class="report-blocks">
<section class="report-block evidence"><h4>Evidence</h4>
<ul>{evidence or '<li>No evidence summary.</li>'}</ul></section>
<section class="report-block reproduction"><h4>Reproduction Evidence</h4>
<div class="repro-grid">{reproduction_items or '<div>Not available</div>'}</div>
<p>{escape(reproduction.summary)}</p></section>
<section class="report-block remediation"><h4>Remediation</h4>
<p>{escape(finding.remediation)}</p></section>
<section class="report-block references"><h4>References</h4>
<ul>{references}</ul></section>
</div></div></article>"""


def _severity_item(name: str, count: int, total: int) -> str:
    percentage = (count / total * 100) if total else 0
    return (
        '<div class="severity-item">'
        '<div class="severity-head">'
        f'<span class="badge severity-{name.casefold()}">{html.escape(name)}</span>'
        f"<strong>{count}</strong></div>"
        '<div class="severity-track" aria-hidden="true">'
        f'<div class="severity-fill" style="width:{percentage:.1f}%"></div>'
        "</div></div>"
    )


def _fact(label: str, value: str, *, css_class: str = "") -> str:
    class_name = f"fact {css_class}".strip()
    return (
        f'<div class="{class_name}"><span class="fact-label">{html.escape(label)}</span>'
        f"{html.escape(value)}</div>"
    )


def _reproduction_item(label: str, value: str | int) -> str:
    return (
        f'<div><span class="fact-label">{html.escape(label)}</span>'
        f"{html.escape(str(value))}</div>"
    )
