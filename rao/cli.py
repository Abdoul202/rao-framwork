"""
RAO-Framework CLI - Command-line interface.

Usage:
    rao scan <target> [options]       Full mission pipeline
    rao recon <target>                Scout-only (nmap + web scan)
    rao webscan <target>              Web-only scan (headers, paths, CORS)
    rao subdomains <domain>           Subdomain enumeration
    rao ssl <target>                  SSL/TLS analysis
    rao osint <domain>                Passive OSINT collection
    rao nuclei-scan <target>          Nuclei template-based vulnerability scan
    rao jwt-scan <token>              JWT security analysis (v0.5)
    rao sessions list                 List saved sessions
    rao sessions resume <name>        Resume a saved session
"""

from __future__ import annotations

import logging
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# BUG #28 fix: single source of truth for the version string
try:
    from importlib.metadata import version as _pkg_version
    _VERSION = _pkg_version("rao-framework")
except Exception:
    _VERSION = "0.0.0-dev"

console = Console()

BANNER = f"""[bold red]
  ██████╗  █████╗  ██████╗
  ██╔══██╗██╔══██╗██╔═══██╗
  ██████╔╝███████║██║   ██║
  ██╔══██╗██╔══██║██║   ██║
  ██║  ██║██║  ██║╚██████╔╝
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝[/bold red]
[dim]  Multi-Agent Red Team Framework v{_VERSION}[/dim]
"""


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


# ── Shared authorization guard ─────────────────────────────────────────────────

def _require_confirm(target: str, confirm: bool) -> None:
    """BUG #27 fix: centralized authorization gate used by all active-scan commands."""
    if not confirm:
        console.print(
            "[bold red]ERROR:[/bold red] You must pass [bold]--confirm[/bold] to confirm "
            "you have explicit written authorization to scan this target.\n"
            f"  Example: rao scan {target} --confirm"
        )
        sys.exit(1)
    _log_authorization(target)


@click.group()
@click.version_option(version=_VERSION, prog_name="rao")  # BUG #28 fix: uses _VERSION
def cli():
    """RAO-Framework - Multi-Agent Autonomous Red Teaming System."""


@cli.command()
@click.argument("target")
@click.option("--scope", "-s", multiple=True, help="Additional scope entries (IPs, CIDRs, domains)")
@click.option("--no-web", is_flag=True, help="Skip web scanning")
@click.option("--no-subdomains", is_flag=True, help="Skip subdomain enumeration")
@click.option("--no-ssl", is_flag=True, help="Skip SSL/TLS analysis")
@click.option("--no-osint", is_flag=True, help="Skip OSINT collection")
@click.option("--nuclei", is_flag=True, help="Run Nuclei template-based scanner (requires nuclei installed)")
@click.option("--nuclei-severity", default="medium,high,critical", show_default=True,
              help="Nuclei severity filter")
@click.option("--profile", "-p",
              type=click.Choice(["quick", "full", "stealth", "udp", "vuln", "smb", "web"]),
              default="quick", show_default=True,
              help="Nmap scan profile")
@click.option("--inject", is_flag=True, help="Enable active SQLi/XSS injection tests in web scan")
@click.option("--save", is_flag=True, help="Save session for later resume")
@click.option("--html", is_flag=True, help="Generate HTML report")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option(
    "--confirm",
    is_flag=True,
    default=False,
    help="REQUIRED: Confirm you have written authorization to scan this target.",
)
def scan(target, scope, no_web, no_subdomains, no_ssl, no_osint, nuclei,
         nuclei_severity, profile, inject, save, html, verbose, confirm):
    """Run a full red team mission against TARGET."""
    _setup_logging(verbose)
    console.print(BANNER)

    # Legal gate
    _require_confirm(target, confirm)

    # BUG #26 fix: use a set to deduplicate — target was being appended even
    # when it was already in scope, causing the Scout to scan it twice.
    scope_set = set(scope) | {target}
    scope_list = sorted(scope_set)

    # Scope validation
    from rao.tools.scope_validator import ScopeValidator

    validator = ScopeValidator(allowed_targets=scope_list, allow_private=True)
    try:
        validator.validate(target)
    except Exception as e:
        console.print(f"[red]Scope error: {e}[/red]")
        sys.exit(1)

    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Scope:[/bold] {', '.join(scope_list)}\n"
        f"[bold]Nmap profile:[/bold] {profile}\n"
        f"[bold]Web scan:[/bold] {'No' if no_web else 'Yes'}{'  [inject]' if inject and not no_web else ''}\n"
        f"[bold]SSL/TLS:[/bold] {'No' if no_ssl else 'Yes'}\n"
        f"[bold]Subdomains:[/bold] {'No' if no_subdomains else 'Yes'}\n"
        f"[bold]OSINT:[/bold] {'No' if no_osint else 'Yes'}\n"
        f"[bold]Nuclei:[/bold] {'Yes (' + nuclei_severity + ')' if nuclei else 'No'}",
        title="[red]Mission Config[/red]",
        border_style="red",
    ))

    console.print("\n[yellow]DISCLAIMER: Authorized testing only. Ensure you have written permission.[/yellow]\n")

    # Run main pipeline
    from rao.core.orchestrator import OCC

    with console.status("[bold blue]Running mission pipeline...[/bold blue]"):
        occ = OCC()
        mission = occ.execute(target=target, scope=scope_list)

    # Web scanning
    web_results = []
    if not no_web:
        from rao.core.state import WebScanInfo
        from rao.tools.web_scanner import WebScanner

        scanner = WebScanner(test_injections=inject)
        with console.status("[bold blue]Web scanning...[/bold blue]"):
            for host in mission.hosts:
                for port in host.ports:
                    if port.service in ("http", "https", "http-proxy", "http-alt"):
                        scheme = "https" if port.port == 443 or "ssl" in port.service else "http"
                        url = f"{scheme}://{host.ip}:{port.port}"
                        result = scanner.scan(url)
                        if result:
                            web_results.append(result)
                            _web_to_findings(result, mission)
                            # BUG #3 fix: actually populate mission.web_scans
                            mission.web_scans.append(WebScanInfo(
                                url=result.url,
                                status_code=result.status_code,
                                server=result.server,
                                technologies=result.technologies,
                                missing_headers_count=len(result.missing_headers),
                                exposed_paths_count=len(result.exposed_paths),
                                cors_issues_count=len(result.cors_issues),
                            ))
                            # Surface WAF / SQLi / XSS findings
                            if result.waf_detected:
                                console.print(f"  [yellow]WAF detected:[/yellow] {', '.join(result.waf_detected)}")
                            if result.sqli_indicators:
                                console.print(f"  [red]SQLi indicators:[/red] {len(result.sqli_indicators)} param(s)")
                            if result.xss_indicators:
                                console.print(f"  [red]XSS indicators:[/red] {len(result.xss_indicators)} param(s)")

    # SSL/TLS analysis
    if not no_ssl:
        from rao.core.state import SSLFinding
        from rao.tools.ssl_analyzer import SSLAnalyzer

        ssl_analyzer = SSLAnalyzer()
        with console.status("[bold blue]SSL/TLS analysis...[/bold blue]"):
            for host in mission.hosts:
                for port in host.ports:
                    if port.port in (443, 8443) or "ssl" in port.service.lower() or "https" in port.service.lower():
                        ssl_result = ssl_analyzer.analyze(host.ip, port.port)
                        for f in ssl_result.findings:
                            mission.ssl_findings.append(SSLFinding(
                                host=host.ip,
                                port=port.port,
                                severity=f["severity"],
                                title=f["title"],
                                detail=f["detail"],
                            ))
                            # Also inject into mission findings for Critic consideration
                            from rao.core.state import Finding, Severity
                            sev = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                                   "medium": Severity.MEDIUM, "low": Severity.LOW}.get(
                                f["severity"], Severity.INFO)
                            mission.findings.append(Finding(
                                title=f["title"], severity=sev,
                                description=f["detail"],
                                evidence=f"SSL analysis: {host.ip}:{port.port}",
                                host=host.ip, port=port.port,
                            ))

    # OSINT collection
    if not no_osint and not _is_ip(target):
        from rao.core.state import OSINTSummary
        from rao.tools.osint import OSINTCollector

        collector = OSINTCollector()
        with console.status("[bold blue]OSINT collection...[/bold blue]"):
            osint_result = collector.collect(target)
            mission.osint = OSINTSummary(
                target=target,
                registrar=osint_result.whois.get("registrar", ""),
                shodan_ports=osint_result.shodan_info.get("open_ports", []),
                shodan_vulns=osint_result.shodan_info.get("vulns", []),
                otx_pulse_count=len(osint_result.otx_pulses),
                emails_found=len(osint_result.emails),
                github_leaks=len(osint_result.github_results),
                google_dorks=osint_result.google_dorks,
                findings=osint_result.findings,
            )
            if osint_result.findings:
                console.print(f"  [yellow]OSINT:[/yellow] {len(osint_result.findings)} findings")
            # Feed OSINT findings into mission.findings so Critic can validate them
            _osint_to_findings(osint_result.findings, target, mission)

    # Nuclei scan
    if nuclei:
        from rao.tools.nuclei_plugin import nuclei_plugin

        if not nuclei_plugin.is_available():
            console.print("[yellow]Nuclei not installed — skipping. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest[/yellow]")
        else:
            scan_targets = [target]
            # Also scan discovered web services
            for ws in mission.web_scans:
                if ws.url not in scan_targets:
                    scan_targets.append(ws.url)

            with console.status(f"[bold blue]Nuclei scanning ({nuclei_severity})...[/bold blue]"):
                for scan_target in scan_targets[:5]:  # cap to avoid runaway
                    tool_result = nuclei_plugin.run(scan_target, severity=nuclei_severity)
                    if tool_result.success:
                        nf = tool_result.data.get("rao_findings", [])
                        mission.nuclei_findings.extend(nf)
                        mission.validated_findings.extend(nf)
                        if nf:
                            console.print(f"  [red]Nuclei:[/red] {len(nf)} findings on {scan_target}")

    # Subdomain enumeration
    subdomains = []
    if not no_subdomains and not _is_ip(target):
        from rao.core.state import SubdomainInfo
        from rao.tools.subdomain_enum import SubdomainEnumerator

        enumerator = SubdomainEnumerator()
        with console.status("[bold blue]Enumerating subdomains...[/bold blue]"):
            subdomains = enumerator.enumerate(target)
            # BUG #3 fix: store subdomains in mission state (persisted in sessions)
            for s in subdomains:
                mission.subdomains.append(SubdomainInfo(
                    subdomain=s["subdomain"],
                    ip=s["ip"],
                    source=s.get("source", ""),
                ))

    # Post-pipeline Critic pass — validate web/SSL/OSINT findings that were added
    # after the main OCC pipeline (Scout → Librarian → Critic) already ran.
    _run_post_scan_critic(mission, console)

    # Report generation (single location — BUG #6 fix already in orchestrator)
    from rao.reporting.report_generator import generate_report

    generate_report(mission)

    if html:
        from rao.reporting.html_report import generate_html_report

        path = generate_html_report(mission, web_results, subdomains)
        console.print(f"\n[green]HTML report: {path}[/green]")

    # Session save
    if save:
        from rao.core.session import save_session

        path = save_session(mission)
        console.print(f"[green]Session saved: {path}[/green]")

    # Final summary
    _print_summary(mission, web_results, subdomains)


@cli.command()
@click.argument("target")
@click.option("--verbose", "-v", is_flag=True)
@click.option(
    "--confirm",
    is_flag=True,
    default=False,
    help="REQUIRED: Confirm you have written authorization to scan this target.",
)
def recon(target, verbose, confirm):
    """Scout-only reconnaissance (nmap + web scan)."""
    _setup_logging(verbose)
    console.print(BANNER)

    # BUG #27 fix: recon also requires --confirm (was missing the authorization gate)
    _require_confirm(target, confirm)

    console.print(f"[bold]Recon-only mode for {target}[/bold]\n")

    from rao.agents.scout import ScoutAgent
    from rao.core.state import MissionState
    from rao.tools.web_scanner import WebScanner

    mission = MissionState(target=target, scope=[target])

    with console.status("[bold blue]Nmap scanning...[/bold blue]"):
        scout = ScoutAgent()
        mission = scout.run(mission)

    web_results = []
    scanner = WebScanner()
    with console.status("[bold blue]Web scanning...[/bold blue]"):
        for host in mission.hosts:
            for port in host.ports:
                if port.service in ("http", "https", "http-proxy", "http-alt"):
                    scheme = "https" if port.port == 443 else "http"
                    result = scanner.scan(f"{scheme}://{host.ip}:{port.port}")
                    if result:
                        web_results.append(result)

    from rao.reporting.report_generator import generate_report

    generate_report(mission)

    if web_results:
        console.print("\n[bold]Web scan results:[/bold]")
        for wr in web_results:
            console.print(
                f"  {wr.url} - "
                f"{len(wr.missing_headers)} missing headers, "
                f"{len(wr.exposed_paths)} exposed paths"
            )


@cli.command()
@click.argument("target")
@click.option("--verbose", "-v", is_flag=True)
@click.option(
    "--confirm",
    is_flag=True,
    default=False,
    help="REQUIRED: Confirm you have written authorization to scan this target.",
)
def webscan(target, verbose, confirm):
    """Web-only security scan (headers, paths, CORS, cookies)."""
    _setup_logging(verbose)
    console.print(BANNER)

    # BUG #27 fix: webscan also requires --confirm (was missing the authorization gate)
    _require_confirm(target, confirm)

    from rao.tools.web_scanner import WebScanner

    scanner = WebScanner()
    with console.status(f"[bold blue]Scanning {target}...[/bold blue]"):
        result = scanner.scan(target)

    if not result:
        console.print(f"[red]Cannot reach {target}[/red]")
        sys.exit(1)

    console.print(f"\n[bold]Results for {result.url}[/bold] (HTTP {result.status_code})")

    if result.server:
        console.print(f"  Server: {result.server}")
    if result.technologies:
        console.print(f"  Technologies: {', '.join(result.technologies)}")

    if result.missing_headers:
        table = Table(title="Missing Security Headers")
        table.add_column("Header", style="cyan")
        table.add_column("Severity", style="yellow")
        table.add_column("Impact")
        for mh in result.missing_headers:
            table.add_row(mh["header"], mh["severity"].upper(), mh["description"])
        console.print(table)

    if result.exposed_paths:
        table = Table(title="Exposed Paths")
        table.add_column("Path", style="cyan")
        table.add_column("Status")
        table.add_column("Size")
        for ep in result.exposed_paths:
            table.add_row(ep["path"], str(ep["status"]), f"{ep['size']} bytes")
        console.print(table)

    if result.cors_issues:
        console.print("\n[bold red]CORS Issues:[/bold red]")
        for ci in result.cors_issues:
            console.print(f"  [red]! {ci}[/red]")

    if result.cookies_issues:
        console.print("\n[bold yellow]Cookie Issues:[/bold yellow]")
        for ci in result.cookies_issues:
            console.print(f"  {ci['name']}: {', '.join(ci['issues'])}")

    if result.info_leaks:
        console.print("\n[bold yellow]Information Leakage:[/bold yellow]")
        for il in result.info_leaks:
            console.print(f"  [yellow]! {il}[/yellow]")


@cli.command()
@click.argument("domain")
@click.option("--verbose", "-v", is_flag=True)
def subdomains(domain, verbose):
    """Enumerate subdomains for a domain (passive — no --confirm required)."""
    _setup_logging(verbose)
    console.print(BANNER)

    from rao.tools.subdomain_enum import SubdomainEnumerator

    enumerator = SubdomainEnumerator()
    with console.status(f"[bold blue]Enumerating {domain}...[/bold blue]"):
        results = enumerator.enumerate(domain)

    if not results:
        console.print(f"[yellow]No subdomains found for {domain}[/yellow]")
        return

    table = Table(title=f"Subdomains for {domain} ({len(results)} found)")
    table.add_column("Subdomain", style="cyan")
    table.add_column("IP", style="green")
    table.add_column("Source", style="dim")

    for r in sorted(results, key=lambda x: x["subdomain"]):
        table.add_row(r["subdomain"], r["ip"], r["source"])

    console.print(table)


@cli.command()
@click.argument("target")
@click.option("--port", default=443, show_default=True, help="Port to analyze")
@click.option("--verbose", "-v", is_flag=True)
@click.option(
    "--confirm", is_flag=True, default=False,
    help="REQUIRED: Confirm you have written authorization to scan this target.",
)
def ssl(target, port, verbose, confirm):
    """SSL/TLS security analysis (certificate, protocols, ciphers, HSTS)."""
    _setup_logging(verbose)
    console.print(BANNER)
    _require_confirm(target, confirm)

    from rao.tools.ssl_analyzer import SSLAnalyzer

    analyzer = SSLAnalyzer()
    with console.status(f"[bold blue]Analyzing SSL/TLS on {target}:{port}...[/bold blue]"):
        result = analyzer.analyze(target, port)

    if result.error:
        console.print(f"[red]Error: {result.error}[/red]")
        return

    console.print(f"\n[bold]SSL/TLS Analysis — {target}:{port}[/bold]")
    console.print(f"  Supported protocols: {', '.join(result.supported_protocols) or 'Unknown'}")
    if result.weak_protocols:
        console.print(f"  [red]Weak protocols:[/red] {', '.join(result.weak_protocols)}")
    console.print(f"  Cipher suite: {result.cipher_suite or 'Unknown'}")
    if result.weak_ciphers_detected:
        console.print(f"  [red]Weak ciphers:[/red] {', '.join(result.weak_ciphers_detected)}")

    if result.cert.subject:
        console.print(f"\n  Certificate: {result.cert.subject}")
        console.print(f"  Issuer: {result.cert.issuer}")
        console.print(f"  Expires: {result.cert.not_after} ({result.cert.days_until_expiry} days)")
        if result.cert.is_expired:
            console.print("  [red]EXPIRED![/red]")
        if result.cert.is_self_signed:
            console.print("  [red]Self-signed certificate[/red]")
        if result.cert.hostname_mismatch:
            console.print("  [red]Hostname mismatch![/red]")

    console.print(f"\n  HSTS: {'✓ present' if result.hsts_present else '[red]✗ missing[/red]'}")

    if result.findings:
        table = Table(title="SSL/TLS Findings")
        table.add_column("Severity", style="yellow")
        table.add_column("Finding", style="cyan")
        table.add_column("Detail")
        for f in result.findings:
            sev_color = {"critical": "bold red", "high": "red", "medium": "yellow",
                         "low": "dim", "info": "dim"}.get(f["severity"], "white")
            table.add_row(
                f"[{sev_color}]{f['severity'].upper()}[/{sev_color}]",
                f["title"], f["detail"][:80]
            )
        console.print(table)
    else:
        console.print("\n[green]No SSL/TLS issues detected.[/green]")


@cli.command()
@click.argument("domain")
@click.option("--verbose", "-v", is_flag=True)
def osint(domain, verbose):
    """Passive OSINT collection (WHOIS, Shodan, OTX, Hunter.io, GitHub — no --confirm required)."""
    _setup_logging(verbose)
    console.print(BANNER)

    from rao.tools.osint import OSINTCollector

    collector = OSINTCollector()
    with console.status(f"[bold blue]Collecting OSINT for {domain}...[/bold blue]"):
        result = collector.collect(domain)

    console.print(f"\n[bold]OSINT Report — {domain}[/bold]")

    if result.whois:
        console.print("\n[bold]WHOIS[/bold]")
        for k, v in result.whois.items():
            if v:
                console.print(f"  {k}: {v}")

    if result.shodan_info:
        console.print("\n[bold]Shodan[/bold]")
        console.print(f"  Open ports: {result.shodan_info.get('open_ports', [])}")
        if result.shodan_info.get("vulns"):
            console.print(f"  [red]Known CVEs: {', '.join(result.shodan_info['vulns'])}[/red]")

    if result.otx_pulses:
        console.print(f"\n[bold yellow]AlienVault OTX — {len(result.otx_pulses)} threat reports[/bold yellow]")
        for p in result.otx_pulses[:3]:
            console.print(f"  • {p['name']}")

    if result.emails:
        console.print(f"\n[bold]Hunter.io — {len(result.emails)} emails found[/bold]")
        for e in result.emails[:5]:
            console.print(f"  {e['email']} ({e.get('position', '')})")

    if result.github_results:
        console.print(f"\n[bold red]GitHub — {len(result.github_results)} potential leaks[/bold red]")
        for g in result.github_results[:5]:
            console.print(f"  {g['url']}")

    if result.google_dorks:
        console.print("\n[bold]Google Dorks (run manually in browser)[/bold]")
        for d in result.google_dorks[:5]:
            console.print(f"  [dim]{d}[/dim]")

    if result.findings:
        console.print()
        table = Table(title="OSINT Findings")
        table.add_column("Severity", style="yellow")
        table.add_column("Finding")
        for f in result.findings:
            sev_color = {"critical": "bold red", "high": "red", "medium": "yellow",
                         "low": "dim", "info": "dim"}.get(f["severity"], "white")
            table.add_row(
                f"[{sev_color}]{f['severity'].upper()}[/{sev_color}]",
                f["title"]
            )
        console.print(table)


@cli.command("nuclei-scan")
@click.argument("target")
@click.option("--severity", default="medium,high,critical", show_default=True,
              help="Severity filter")
@click.option("--tags", default="cve,misconfig,oast,exposure,default-logins", show_default=True,
              help="Template tags to run")
@click.option("--templates", "-t", default=None, help="Specific template path or glob")
@click.option("--verbose", "-v", is_flag=True)
@click.option(
    "--confirm", is_flag=True, default=False,
    help="REQUIRED: Confirm you have written authorization to scan this target.",
)
def nuclei_scan(target, severity, tags, templates, verbose, confirm):
    """Nuclei template-based vulnerability scanner (requires nuclei installed)."""
    _setup_logging(verbose)
    console.print(BANNER)
    _require_confirm(target, confirm)

    from rao.tools.nuclei_plugin import nuclei_plugin

    if not nuclei_plugin.is_available():
        console.print(
            "[red]nuclei binary not found.[/red]\n"
            "Install with: [bold]go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest[/bold]\n"
            "Or: [bold]sudo apt install nuclei[/bold]"
        )
        sys.exit(1)

    console.print(f"Nuclei version: [dim]{nuclei_plugin.get_version()}[/dim]")
    console.print(f"Target: [bold]{target}[/bold] | Severity: {severity} | Tags: {tags}\n")

    with console.status("[bold blue]Running Nuclei scan...[/bold blue]"):
        result = nuclei_plugin.run(target, severity=severity, tags=tags, templates=templates)

    if not result.success:
        console.print(f"[red]Scan failed: {result.error}[/red]")
        sys.exit(1)

    findings = result.data.get("rao_findings", [])
    if not findings:
        console.print("[green]No findings.[/green]")
        return

    table = Table(title=f"Nuclei Findings — {target} ({len(findings)} total)")
    table.add_column("Severity", style="yellow")
    table.add_column("Title", style="cyan")
    table.add_column("CVEs", style="dim")
    for f in sorted(findings, key=lambda x: x.severity.value):
        sev_color = {"critical": "bold red", "high": "red", "medium": "yellow",
                     "low": "dim", "info": "dim"}.get(f.severity.value, "white")
        table.add_row(
            f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
            f.title.replace("[Nuclei] ", ""),
            ", ".join(f.cve_ids[:3]) or "—",
        )
    console.print(table)


@cli.command("jwt-scan")
@click.argument("token")
@click.option("--target", "-t", default="", help="Target URL for live alg:none test (optional)")
@click.option("--verbose", "-v", is_flag=True)
def jwt_scan(token: str, target: str, verbose: bool) -> None:
    """Analyze a JWT token for security vulnerabilities.

    Checks: alg:none, weak secret (offline brute-force), expiry, sensitive
    payload data, and optionally a live alg:none injection test.

    TOKEN can be a raw JWT (eyJ...) or prefixed with 'Bearer '.
    """
    _setup_logging(verbose)
    console.print(BANNER)

    from rao.tools.jwt_analyzer import JWTAnalyzer

    analyzer = JWTAnalyzer(target_url=target)
    with console.status("[bold blue]Analyzing JWT...[/bold blue]"):
        result = analyzer.analyze(token)

    if result.error:
        console.print(f"[red]Error: {result.error}[/red]")
        return

    # Header / payload summary
    console.print("\n[bold]JWT Header[/bold]")
    for k, v in result.header.items():
        console.print(f"  {k}: [cyan]{v}[/cyan]")

    console.print("\n[bold]JWT Payload[/bold]")
    for k, v in result.payload.items():
        color = "red" if k in {"password", "secret", "api_key"} else "white"
        console.print(f"  [{color}]{k}[/{color}]: {v}")

    if result.expires_at:
        status = "[red]EXPIRED[/red]" if result.is_expired else f"[green]{result.days_until_expiry}d remaining[/green]"
        console.print(f"\n  Expires: {result.expires_at} ({status})")

    if result.weak_secret_found:
        console.print(f"\n[bold red]⚠ CRACKED SECRET: '{result.weak_secret_found}'[/bold red]")

    if result.alg_none_vulnerable:
        console.print("\n[bold red]⚠ ALG:NONE ATTACK CONFIRMED — server accepts unsigned tokens![/bold red]")

    if not result.findings:
        console.print("\n[green]No issues found.[/green]")
        return

    table = Table(title=f"JWT Findings ({len(result.findings)} total)")
    table.add_column("Severity", style="yellow")
    table.add_column("Finding", style="cyan")
    table.add_column("Detail")

    sev_color_map = {
        "critical": "bold red", "high": "red",
        "medium": "yellow", "low": "dim", "info": "dim",
    }
    for f in result.findings:
        sev = f["severity"]
        col = sev_color_map.get(sev, "white")
        table.add_row(
            f"[{col}]{sev.upper()}[/{col}]",
            f["title"],
            f["detail"][:90],
        )
    console.print(table)


@cli.group()
def sessions():
    """Manage saved mission sessions."""


@sessions.command("list")
def sessions_list():
    """List all saved sessions."""
    from rao.core.session import list_sessions

    saved = list_sessions()
    if not saved:
        console.print("[dim]No saved sessions.[/dim]")
        return

    table = Table(title="Saved Sessions")
    table.add_column("Name", style="cyan")
    table.add_column("Target")
    table.add_column("Phase")
    table.add_column("Hosts")
    table.add_column("Findings")
    table.add_column("Saved At", style="dim")

    for s in saved:
        table.add_row(
            s["name"], s["target"], s["phase"],
            str(s["hosts"]), str(s["findings"]), s["saved_at"][:19],
        )
    console.print(table)


@sessions.command("resume")
@click.argument("name")
@click.option("--html", is_flag=True, help="Generate HTML report")
@click.option("--verbose", "-v", is_flag=True)
def sessions_resume(name, html, verbose):
    """Resume a saved session from where it left off."""
    _setup_logging(verbose)
    console.print(BANNER)

    from rao.core.session import load_session

    try:
        mission = load_session(name)
    except FileNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    console.print(f"[green]Resumed session: target={mission.target}, phase={mission.current_phase}[/green]")
    console.print(f"  Hosts: {len(mission.hosts)}, Findings: {len(mission.findings)}")

    # Continue from where we left off
    from rao.agents.critic import CriticAgent
    from rao.agents.librarian import LibrarianAgent

    if mission.current_phase in ("reconnaissance", "analysis"):
        if mission.findings and not mission.validated_findings:
            console.print("\n[yellow]Resuming at Critic phase...[/yellow]")
            critic = CriticAgent()
            with console.status("[bold blue]Validating findings...[/bold blue]"):
                mission = critic.run(mission)
        elif mission.hosts and not mission.findings:
            console.print("\n[yellow]Resuming at Librarian phase...[/yellow]")
            librarian = LibrarianAgent()
            with console.status("[bold blue]Analyzing services...[/bold blue]"):
                mission = librarian.run(mission)
            critic = CriticAgent()
            with console.status("[bold blue]Validating findings...[/bold blue]"):
                mission = critic.run(mission)

    from rao.reporting.report_generator import generate_report

    generate_report(mission)

    if html:
        from rao.reporting.html_report import generate_html_report

        path = generate_html_report(mission)
        console.print(f"\n[green]HTML report: {path}[/green]")


# ── Internal helpers ───────────────────────────────────────────────────────────

def _log_authorization(target: str) -> None:
    """Append a timestamped authorization record to the audit log."""
    import datetime
    import os
    from pathlib import Path

    from rao.config import settings

    log_path = Path(settings.report_output_dir) / "audit.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    entry = (
        f"{datetime.datetime.utcnow().isoformat()}Z"
        f" | AUTHORIZED_SCAN"
        f" | target={target}"
        f" | pid={os.getpid()}\n"
    )
    with open(log_path, "a") as fh:
        fh.write(entry)


def _osint_to_findings(osint_findings: list[dict], target: str, mission) -> None:
    """Convert OSINT finding dicts into Finding objects and append to mission.findings.

    OSINT findings (severity/title/detail dicts from OSINTCollector) were
    previously only stored in mission.osint.findings — invisible to the Critic.
    This function makes them first-class pipeline findings.
    """
    from rao.core.state import Finding, Severity

    _sev_map = {
        "critical": Severity.CRITICAL,
        "high":     Severity.HIGH,
        "medium":   Severity.MEDIUM,
        "low":      Severity.LOW,
        "info":     Severity.INFO,
    }
    for f_dict in osint_findings:
        sev = _sev_map.get(f_dict.get("severity", "info"), Severity.INFO)
        detail = f_dict.get("detail") or f_dict.get("description", "")
        mission.findings.append(Finding(
            title=f_dict["title"],
            severity=sev,
            description=detail,
            evidence=f"OSINT passive finding for {target}",
            host=target,
        ))


def _run_post_scan_critic(mission, console) -> None:
    """Second Critic pass for findings discovered after the main OCC pipeline.

    The main pipeline runs Scout → Librarian → Critic early. Web/SSL/OSINT
    scans then append to mission.findings, but those findings never go through
    Critic. This function validates only the unvalidated remainder.
    """
    already_validated = {id(f) for f in mission.validated_findings}
    unvalidated = [
        f for f in mission.findings
        if id(f) not in already_validated
    ]
    if not unvalidated:
        return

    from rao.agents.critic import CriticAgent
    from rao.core.state import MissionState

    critic = CriticAgent()
    # Create a lightweight proxy mission with only the unvalidated findings
    proxy = MissionState(target=mission.target, scope=mission.scope, findings=unvalidated)
    with console.status(
        f"[bold blue]Validating {len(unvalidated)} supplementary findings...[/bold blue]"
    ):
        proxy = critic.run(proxy)

    mission.validated_findings.extend(proxy.validated_findings)
    if proxy.validated_findings:
        console.print(
            f"  [green]Post-scan Critic:[/green] "
            f"{len(proxy.validated_findings)}/{len(unvalidated)} findings validated"
        )


def _web_to_findings(web_result, mission) -> None:
    """Convert web scan results into mission findings."""
    from rao.core.state import Finding, Severity

    for ci in web_result.cors_issues:
        mission.findings.append(Finding(
            title=f"CORS Misconfiguration - {web_result.url}",
            severity=Severity.HIGH,
            description=ci,
            evidence=f"Detected on {web_result.url}",
            host=web_result.url,
        ))

    for ep in web_result.exposed_paths:
        if ep["path"] in ("/.env", "/.git/HEAD", "/backup.sql", "/phpinfo.php"):
            mission.findings.append(Finding(
                title=f"Sensitive path exposed: {ep['path']}",
                severity=Severity.HIGH if ep["path"] in ("/.env", "/.git/HEAD") else Severity.MEDIUM,
                description=f"Sensitive file accessible at {ep['path']} (HTTP {ep['status']})",
                evidence=f"{ep['size']} bytes returned",
                host=web_result.url,
                port=None,
            ))

    for mh in web_result.missing_headers:
        mission.findings.append(Finding(
            title=f"Missing header: {mh['header']}",
            severity=Severity(mh["severity"]),
            description=mh["description"],
            evidence=f"Header not present in response from {web_result.url}",
            host=web_result.url,
        ))


def _print_summary(mission, web_results, subdomains) -> None:

    console.print("\n")
    console.print(Panel(
        f"[bold]Hosts:[/bold] {len(mission.hosts)}  |  "
        f"[bold]Findings:[/bold] {len(mission.findings)}  |  "
        f"[bold]Validated:[/bold] {len(mission.validated_findings)}  |  "
        f"[bold]Web scans:[/bold] {len(web_results)}  |  "
        f"[bold]Subdomains:[/bold] {len(subdomains)}  |  "
        f"[bold]Errors:[/bold] {len(mission.errors)}",
        title="[bold green]Mission Complete[/bold green]",
        border_style="green",
    ))


def _is_ip(target: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def main():
    cli()


if __name__ == "__main__":
    main()
