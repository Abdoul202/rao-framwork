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
    # Also normalize: ScopeValidator expects hostname/IP, not a full URL.
    _host = target
    for _scheme in ("https://", "http://"):
        if _host.startswith(_scheme):
            _host = _host[len(_scheme):]
    _host = _host.split("/")[0].rstrip(":")

    scope_set = set(scope) | {_host}
    scope_list = sorted(scope_set)

    # Scope validation
    from rao.tools.scope_validator import ScopeValidator

    validator = ScopeValidator(allowed_targets=scope_list, allow_private=True)
    try:
        validator.validate(_host)
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


# ── rao audit ─────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option(
    "--confirm", is_flag=True, default=False,
    help="REQUIRED: Confirm written authorization to scan this target.",
)
@click.option("--scope", "-s", multiple=True, help="Additional scope entries (IPs, CIDRs, domains).")
@click.option("--jwt", "jwt_token", default="", help="JWT token to analyze (optional).")
@click.option("--jwt-target", default="", help="URL for live alg:none JWT test (optional).")
@click.option("--no-web",        is_flag=True, help="Skip web vulnerability scan.")
@click.option("--no-inject",     is_flag=True, help="Skip active injection tests (SQLi, XSS, SSTI, SSRF…).")
@click.option("--no-auth",       is_flag=True, help="Skip authentication tests (default creds, rate limiting).")
@click.option("--no-ssl",        is_flag=True, help="Skip SSL/TLS analysis.")
@click.option("--no-osint",      is_flag=True, help="Skip OSINT collection.")
@click.option("--no-nuclei",     is_flag=True, help="Skip Nuclei scan.")
@click.option("--no-subdomains", is_flag=True, help="Skip subdomain enumeration.")
@click.option("--no-cve",        is_flag=True, help="Skip nmap + CVE + LLM pipeline.")
@click.option(
    "--nuclei-severity", default="medium,high,critical", show_default=True,
    help="Nuclei severity filter.",
)
@click.option("--html",    is_flag=True, default=True,  help="Generate HTML report (default: on).")
@click.option("--no-html", is_flag=True, default=False, help="Disable HTML report generation.")
@click.option("--save",    is_flag=True, help="Save session for later resume.")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output.")
def audit(
    target, confirm, scope, jwt_token, jwt_target,
    no_web, no_inject, no_auth, no_ssl, no_osint, no_nuclei, no_subdomains, no_cve,
    nuclei_severity, html, no_html, save, verbose,
):
    """Full security audit — ALL tests enabled by default.

    Runs every available module in one command:\n
      • Nmap port scan + CVE lookup + LLM analytics\n
      • Web scan: headers, cookies, CORS, paths (500+)\n
      • Active injection tests: SQLi, XSS, SSTI, XXE, CMDi, CRLF, NoSQL, GraphQL\n
      • SSRF, IDOR, forceful browsing, PII, token-in-URL\n
      • Auth tests: default credentials (12 pairs), rate limiting\n
      • SSL/TLS deep analysis\n
      • OSINT (WHOIS, Shodan, Censys, LeakIX, GreyNoise, URLScan, HaveIBeenPwned)\n
      • Nuclei (9000+ templates — if installed)\n
      • Subdomain enumeration (crt.sh + DNS brute-force)\n
      • JWT analysis (--jwt TOKEN)\n
      • HTML report auto-generated\n

    Example:\n
      rao audit https://target.com --confirm\n
      rao audit https://target.com --confirm --jwt eyJhbGc... --no-nuclei
    """
    _setup_logging(verbose)
    console.print(BANNER)
    _require_confirm(target, confirm)

    do_html = html and not no_html

    # Normalize: ScopeValidator expects hostname/IP, not a full URL.
    # Strip scheme (https://, http://) and trailing path/slash.
    _host = target
    for _scheme in ("https://", "http://"):
        if _host.startswith(_scheme):
            _host = _host[len(_scheme):]
    _host = _host.split("/")[0].rstrip(":")   # remove port-less trailing colon too

    scope_set = set(scope) | {_host}
    scope_list = sorted(scope_set)

    from rao.tools.scope_validator import ScopeValidator
    validator = ScopeValidator(allowed_targets=scope_list, allow_private=True)
    try:
        validator.validate(_host)
    except Exception as e:
        console.print(f"[red]Scope error: {e}[/red]")
        sys.exit(1)

    # ── Mission banner ──────────────────────────────────────────────────────
    modules = []
    if not no_cve:
        modules.append("[green]CVE + LLM[/green]")
    if not no_web:
        modules.append("[green]WebScan (OWASP x10)[/green]")
    if not no_inject:
        modules.append("[yellow]Injections[/yellow]")
    if not no_auth:
        modules.append("[yellow]Auth tests[/yellow]")
    if not no_ssl:
        modules.append("[green]SSL/TLS[/green]")
    if not no_osint:
        modules.append("[green]OSINT[/green]")
    if not no_nuclei:
        modules.append("[green]Nuclei[/green]")
    if not no_subdomains:
        modules.append("[green]Subdomains[/green]")
    if jwt_token:
        modules.append("[cyan]JWT[/cyan]")

    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Scope:[/bold]  {', '.join(scope_list)}\n"
        f"[bold]Modules:[/bold] {' | '.join(modules)}\n"
        f"[bold]HTML report:[/bold] {'Yes' if do_html else 'No'}",
        title="[bold red]⚔  RAO AUDIT — Full Security Assessment[/bold red]",
        border_style="red",
    ))
    console.print("\n[yellow]DISCLAIMER: Authorized testing only. Ensure you have explicit written permission.[/yellow]\n")

    # ── Phase 1: Nmap + CVE + LLM ──────────────────────────────────────────
    from rao.core.orchestrator import OCC
    from rao.core.state import MissionState

    if not no_cve:
        console.rule("[bold blue]Phase 1/8 — Nmap · CVE · LLM[/bold blue]")
        with console.status("[bold blue]Running recon + CVE analysis...[/bold blue]"):
            occ = OCC()
            mission = occ.execute(target=target, scope=scope_list)
        console.print(f"  Hosts: {len(mission.hosts)} | Findings: {len(mission.findings)}")
    else:
        console.rule("[dim]Phase 1/8 — Nmap · CVE · LLM (skipped)[/dim]")
        mission = MissionState(target=target, scope=scope_list)

    web_results = []
    subdomains = []

    # ── Phase 2: Web scan ──────────────────────────────────────────────────
    if not no_web:
        console.rule("[bold blue]Phase 2/8 — Web Scanner (OWASP Top 10)[/bold blue]")
        from rao.core.state import WebScanInfo
        from rao.tools.web_scanner import WebScanner

        scanner = WebScanner(
            test_injections=not no_inject,
            test_auth=not no_auth,
        )
        # Build URL list: from nmap results + target itself
        urls_to_scan: list[str] = []
        for host in mission.hosts:
            for port in host.ports:
                if port.service in ("http", "https", "http-proxy", "http-alt"):
                    scheme = "https" if port.port in (443, 8443) or "ssl" in port.service else "http"
                    urls_to_scan.append(f"{scheme}://{host.ip}:{port.port}")
        if not urls_to_scan:
            # Fallback: scan the target directly
            t = target if target.startswith(("http://", "https://")) else f"https://{target}"
            urls_to_scan.append(t)

        for url in urls_to_scan:
            with console.status(f"[bold blue]Scanning {url}...[/bold blue]"):
                result = scanner.scan(url)
            if result:
                web_results.append(result)
                _web_to_findings(result, mission)
                mission.web_scans.append(WebScanInfo(
                    url=result.url,
                    status_code=result.status_code,
                    server=result.server,
                    technologies=result.technologies,
                    missing_headers_count=len(result.missing_headers),
                    exposed_paths_count=len(result.exposed_paths),
                    cors_issues_count=len(result.cors_issues),
                ))
                # Surface critical OWASP findings
                _audit_print_web_findings(result, console)
    else:
        console.rule("[dim]Phase 2/8 — Web Scanner (skipped)[/dim]")

    # ── Phase 3: SSL/TLS ───────────────────────────────────────────────────
    if not no_ssl:
        console.rule("[bold blue]Phase 3/8 — SSL/TLS Analysis[/bold blue]")
        from rao.core.state import SSLFinding
        from rao.tools.ssl_analyzer import SSLAnalyzer

        ssl_analyzer = SSLAnalyzer()
        # Try target directly if no nmap hosts
        ssl_targets = [
            (host.ip, port.port)
            for host in mission.hosts
            for port in host.ports
            if port.port in (443, 8443) or "ssl" in port.service.lower()
        ]
        if not ssl_targets and not _is_ip(target):
            ssl_targets = [(target.replace("https://", "").replace("http://", "").split("/")[0], 443)]

        for ssl_host, ssl_port in ssl_targets:
            with console.status(f"[bold blue]SSL analysis {ssl_host}:{ssl_port}...[/bold blue]"):
                ssl_result = ssl_analyzer.analyze(ssl_host, ssl_port)
            for f in ssl_result.findings:
                from rao.core.state import Finding, Severity
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW}
                mission.ssl_findings.append(SSLFinding(
                    host=ssl_host, port=ssl_port,
                    severity=f["severity"], title=f["title"], detail=f["detail"],
                ))
                mission.findings.append(Finding(
                    title=f["title"], severity=sev_map.get(f["severity"], Severity.INFO),
                    description=f["detail"],
                    evidence=f"SSL: {ssl_host}:{ssl_port}",
                    host=ssl_host, port=ssl_port,
                ))
            if ssl_result.findings:
                console.print(f"  [yellow]SSL:[/yellow] {len(ssl_result.findings)} findings on {ssl_host}:{ssl_port}")
    else:
        console.rule("[dim]Phase 3/8 — SSL/TLS (skipped)[/dim]")

    # ── Phase 4: OSINT ─────────────────────────────────────────────────────
    if not no_osint and not _is_ip(target):
        console.rule("[bold blue]Phase 4/8 — OSINT Collection[/bold blue]")
        from rao.core.state import OSINTSummary
        from rao.tools.osint import OSINTCollector

        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        collector = OSINTCollector()
        with console.status(f"[bold blue]OSINT: {domain}...[/bold blue]"):
            osint_result = collector.collect(domain)
        mission.osint = OSINTSummary(
            target=domain,
            registrar=osint_result.whois.get("registrar", ""),
            shodan_ports=osint_result.shodan_info.get("open_ports", []),
            shodan_vulns=osint_result.shodan_info.get("vulns", []),
            otx_pulse_count=len(osint_result.otx_pulses),
            emails_found=len(osint_result.emails),
            github_leaks=len(osint_result.github_results),
            google_dorks=osint_result.google_dorks,
            findings=osint_result.findings,
        )
        _osint_to_findings(osint_result.findings, domain, mission)
        console.print(f"  [green]OSINT:[/green] {len(osint_result.findings)} findings")
    elif no_osint or _is_ip(target):
        tag = "skipped" if no_osint else "IP target — skipped"
        console.rule(f"[dim]Phase 4/8 — OSINT ({tag})[/dim]")

    # ── Phase 5: Nuclei ────────────────────────────────────────────────────
    if not no_nuclei:
        console.rule("[bold blue]Phase 5/8 — Nuclei Scan[/bold blue]")
        from rao.tools.nuclei_plugin import nuclei_plugin

        if not nuclei_plugin.is_available():
            console.print("  [yellow]Nuclei not installed — skipping.[/yellow]")
            console.print("  Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        else:
            nuclei_targets = [target] + [ws.url for ws in mission.web_scans][:4]
            for nt in nuclei_targets:
                with console.status(f"[bold blue]Nuclei: {nt}...[/bold blue]"):
                    tool_result = nuclei_plugin.run(nt, severity=nuclei_severity)
                if tool_result.success:
                    nf = tool_result.data.get("rao_findings", [])
                    mission.nuclei_findings.extend(nf)
                    mission.validated_findings.extend(nf)
                    if nf:
                        console.print(f"  [red]Nuclei:[/red] {len(nf)} findings on {nt}")
    else:
        console.rule("[dim]Phase 5/8 — Nuclei (skipped)[/dim]")

    # ── Phase 6: Subdomains ────────────────────────────────────────────────
    if not no_subdomains and not _is_ip(target):
        console.rule("[bold blue]Phase 6/8 — Subdomain Enumeration[/bold blue]")
        from rao.core.state import SubdomainInfo
        from rao.tools.subdomain_enum import SubdomainEnumerator

        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        enumerator = SubdomainEnumerator()
        with console.status(f"[bold blue]Enumerating subdomains of {domain}...[/bold blue]"):
            subdomains = enumerator.enumerate(domain)
        for s in subdomains:
            mission.subdomains.append(SubdomainInfo(
                subdomain=s["subdomain"], ip=s["ip"], source=s.get("source", ""),
            ))
        console.print(f"  [green]Subdomains:[/green] {len(subdomains)} found")
    else:
        console.rule("[dim]Phase 6/8 — Subdomains (skipped)[/dim]")

    # ── Phase 7: JWT Analysis ──────────────────────────────────────────────
    if jwt_token:
        console.rule("[bold blue]Phase 7/8 — JWT Analysis[/bold blue]")
        try:
            from rao.tools.jwt_analyzer import JWTAnalyzer
            analyzer = JWTAnalyzer()
            jwt_result = analyzer.analyze(jwt_token)

            # Display findings inline
            jwt_table = Table(title="JWT Security Analysis", border_style="cyan")
            jwt_table.add_column("Check", style="bold")
            jwt_table.add_column("Result")
            jwt_table.add_row("Algorithm", jwt_result.algorithm or "unknown")
            jwt_table.add_row("alg:none", "[red]YES — CRITICAL[/red]" if jwt_result.alg_none_detected else "[green]No[/green]")
            jwt_table.add_row("Expired", "[red]YES[/red]" if jwt_result.is_expired else "[green]No[/green]")
            jwt_table.add_row("Weak secret", f"[red]{jwt_result.weak_secret}[/red]" if jwt_result.weak_secret else "[green]Not found[/green]")
            jwt_table.add_row("PII in payload", "[red]" + ", ".join(jwt_result.sensitive_payload_keys) + "[/red]" if jwt_result.sensitive_payload_keys else "[green]None[/green]")
            console.print(jwt_table)

            # Feed JWT findings into mission
            from rao.core.state import Finding, Severity
            if jwt_result.alg_none_detected:
                mission.findings.append(Finding(
                    title="JWT alg:none — Signature bypass possible",
                    severity=Severity.CRITICAL,
                    description="The JWT token uses alg:none, allowing forged tokens without a valid signature.",
                    evidence="Token header declares alg:none",
                    host=target,
                ))
            if jwt_result.weak_secret:
                mission.findings.append(Finding(
                    title=f"JWT weak secret found: '{jwt_result.weak_secret}'",
                    severity=Severity.HIGH,
                    description="The JWT HMAC secret was found via offline brute-force.",
                    evidence=f"Secret: {jwt_result.weak_secret}",
                    host=target,
                ))
            if jwt_result.sensitive_payload_keys:
                mission.findings.append(Finding(
                    title=f"Sensitive data in JWT payload: {', '.join(jwt_result.sensitive_payload_keys)}",
                    severity=Severity.MEDIUM,
                    description="The JWT payload contains sensitive field names (PII/credentials).",
                    evidence="JWT payload analysis",
                    host=target,
                ))

            # Optional live test
            if jwt_target:
                with console.status(f"[bold blue]Testing alg:none live on {jwt_target}...[/bold blue]"):
                    bypassed = analyzer.test_alg_none_live(jwt_token, jwt_target)
                if bypassed:
                    console.print(f"  [bold red]⚠  Live alg:none bypass SUCCEEDED on {jwt_target}[/bold red]")
                else:
                    console.print("  [green]Live alg:none: server rejected forged token[/green]")
        except Exception as e:
            console.print(f"  [yellow]JWT analysis error: {e}[/yellow]")
    else:
        console.rule("[dim]Phase 7/8 — JWT (no token provided — use --jwt TOKEN)[/dim]")

    # ── Phase 8: Post-scan LLM Critic validation ───────────────────────
    console.rule("[bold blue]Phase 8/8 — LLM Critic Validation[/bold blue]")
    _run_post_scan_critic(mission, console)

    # ── Phase 8b: Operator — LLM Attack Plan ────────────────────────
    _run_operator_and_display(mission, console)

    # ── Report ─────────────────────────────────────────────────────────────
    console.rule("[bold green]Generating Reports[/bold green]")
    from rao.reporting.report_generator import generate_report
    try:
        json_path = generate_report(mission)
        console.print(f"[green]JSON report: {json_path}[/green]")
    except Exception as _exc:
        console.print(f"[yellow]⚠ JSON report failed: {_exc}[/yellow]")

    if do_html:
        from rao.reporting.html_report import generate_html_report
        try:
            path = generate_html_report(mission, web_results, subdomains)
            console.print(f"[bold green]HTML report: {path}[/bold green]")
        except Exception as _exc:
            console.print(f"[red]✗ HTML report failed: {_exc}[/red]")

    if save:
        from rao.core.session import save_session
        path = save_session(mission)
        console.print(f"[green]Session saved: {path}[/green]")

    # ── Final summary ──────────────────────────────────────────────────────
    ssl_count = len(getattr(mission, "ssl_findings", []))
    nuclei_count = len(getattr(mission, "nuclei_findings", []))
    osint_count = len(getattr(mission.osint, "findings", []) if mission.osint else [])
    attack_steps_count = len(getattr(mission, "attack_steps", []))

    console.print("\n")
    console.print(Panel(
        f"[bold]Hosts:[/bold]          {len(mission.hosts)}\n"
        f"[bold]CVE findings:[/bold]   {len(mission.findings)}\n"
        f"[bold]Validated:[/bold]      {len(mission.validated_findings)}\n"
        f"[bold]Web scans:[/bold]      {len(web_results)}\n"
        f"[bold]SSL findings:[/bold]   {ssl_count}\n"
        f"[bold]Nuclei findings:[/bold]{nuclei_count}\n"
        f"[bold]OSINT findings:[/bold] {osint_count}\n"
        f"[bold]Subdomains:[/bold]     {len(subdomains)}\n"
        f"[bold]JWT analysis:[/bold]   {'Yes' if jwt_token else 'No'}\n"
        f"[bold]Attack steps:[/bold]   {attack_steps_count} (LLM-generated)\n"
        f"[bold]Errors:[/bold]         {len(mission.errors)}",
        title="[bold green]⚔  AUDIT COMPLETE[/bold green]",
        border_style="green",
    ))


def _audit_print_web_findings(result, console) -> None:
    """Print important OWASP findings from a WebScanResult inline during audit."""
    pairs = [
        (result.sqli_indicators,         "SQLi",         "red"),
        (result.xss_indicators,          "XSS",          "red"),
        (result.ssti_indicators,         "SSTI",         "red"),
        (result.ssrf_indicators,         "SSRF",         "red"),
        (result.idor_indicators,         "IDOR",         "red"),
        (result.nosql_indicators,        "NoSQL-inject", "red"),
        (result.xxe_indicators,          "XXE",          "red"),
        (result.cmdi_indicators,         "CMDi",         "red"),
        (result.crlf_indicators,         "CRLF",         "yellow"),
        (result.open_redirect_indicators,"Open Redirect", "yellow"),
        (result.cleartext_pii,           "Cleartext PII", "yellow"),
        (result.token_in_url,            "Token-in-URL", "yellow"),
        (result.sri_missing,             "SRI missing",  "yellow"),
        (result.default_creds_found,     "Default creds","red"),
        (result.cors_issues,             "CORS issue",   "yellow"),
        (result.forceful_browsing,       "Forced browse","yellow"),
        (result.exposed_paths,           "Exposed path", "yellow"),
        (result.waf_detected,            "WAF detected", "dim"),
    ]
    for items, label, color in pairs:
        if items:
            console.print(f"  [{color}]{label}:[/{color}] {len(items)} finding(s)")
    if result.rate_limiting_absent:
        console.print("  [red]Rate limiting:[/red] ABSENT on login endpoint")
    if not result.security_txt_present:
        console.print("  [dim]security.txt:[/dim] not present")


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
    Critic. This function validates only the unvalidated remainder and prints
    live LLM feedback for each finding.
    """
    from rao.core.llm import get_llm_or_none
    from rao.core.state import Severity

    already_validated = {id(f) for f in mission.validated_findings}
    unvalidated = [
        f for f in mission.findings
        if id(f) not in already_validated
    ]
    if not unvalidated:
        console.print("  [dim]No new findings to validate.[/dim]")
        return

    # Check LLM availability upfront and display status
    llm = get_llm_or_none()
    if llm is None:
        console.print("  [yellow]⚠ LLM non disponible — mode offline (CRITICAL/HIGH conservés sans validation).[/yellow]")
    else:
        console.print(f"  [bold cyan]🧠 LLM actif: {type(llm).__name__}[/bold cyan]")
        console.print(f"  [dim]Analyse de {len(unvalidated)} finding(s) en cours...[/dim]\n")

    from rao.agents.critic import CriticAgent

    critic = CriticAgent()
    validated_count = 0
    fp_count = 0

    sev_color = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH:     "red",
        Severity.MEDIUM:   "yellow",
        Severity.LOW:      "cyan",
        Severity.INFO:     "dim",
    }

    for finding in unvalidated:
        color = sev_color.get(finding.severity, "white")
        with console.status(
            f"  [bold blue]Critic LLM → [{color}]{finding.severity.value.upper()}[/{color}] {finding.title[:60]}...[/bold blue]"
        ):
            is_valid = critic._validate_finding(finding)

        verdict_icon = "✅" if is_valid else "❌"
        verdict_label = "VALIDÉ" if is_valid else "FAUX POSITIF"
        verdict_color = "green" if is_valid else "dim"
        console.print(
            f"  {verdict_icon} [{verdict_color}]{verdict_label}[/{verdict_color}] "
            f"[{color}][{finding.severity.value.upper()}][/{color}] "
            f"{finding.title[:65]}"
        )

        if is_valid:
            mission.validated_findings.append(finding)
            validated_count += 1
        else:
            fp_count += 1

    console.print()
    console.print(Panel(
        f"[green]Validés:[/green]      {validated_count}/{len(unvalidated)}\n"
        f"[dim]Faux positifs:[/dim] {fp_count}/{len(unvalidated)}\n"
        f"[bold]Total validés:[/bold] {len(mission.validated_findings)}",
        title="[bold cyan]🧠 Critic LLM — Résultat[/bold cyan]",
        border_style="cyan",
    ))


def _run_operator_and_display(mission, console) -> None:
    """Run OperatorAgent and display the LLM attack plan in the console."""
    from rao.core.state import Severity

    critical_findings = [
        f for f in mission.validated_findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]

    if not critical_findings:
        console.print("  [dim]Operator: aucun finding HIGH/CRITICAL validé — plan d'attaque ignoré.[/dim]")
        return

    console.rule("[bold red]⚔ Operator — Plan d'attaque LLM[/bold red]")
    console.print(
        f"  [bold cyan]🧠 Génération du plan d'attaque pour "
        f"{len(critical_findings)} finding(s) HIGH/CRITICAL...[/bold cyan]\n"
    )

    from rao.agents.operator import OperatorAgent
    operator = OperatorAgent()

    with console.status("[bold red]Operator LLM — planification en cours...[/bold red]"):
        mission = operator.run(mission)

    if mission.attack_steps:
        # Display structured steps
        from rich.table import Table
        table = Table(
            title=f"⚔ Plan d'attaque — {len(mission.attack_steps)} étape(s)",
            border_style="red",
            show_lines=True,
        )
        table.add_column("#",       width=3,  style="dim")
        table.add_column("Severity", width=10)
        table.add_column("Finding",  width=35)
        table.add_column("Tool",     width=12, style="cyan")
        table.add_column("Approach", width=40)
        table.add_column("Risk",     width=8)

        risk_color = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "green"}
        for i, step in enumerate(mission.attack_steps, 1):
            risk_val = getattr(step.risk, 'value', str(step.risk)).upper()
            rc = risk_color.get(risk_val, "white")
            table.add_row(
                str(i),
                f"[red]{step.finding[:10]}[/red]" if step.finding else "—",
                step.finding[:35] if step.finding else step.approach[:35],
                step.tool[:12] if step.tool else "—",
                step.approach[:40] if step.approach else "—",
                f"[{rc}]{risk_val}[/{rc}]",
            )
        console.print(table)

    elif mission.attack_plan:
        # Fallback: raw plan
        console.print(Panel(
            mission.attack_plan[:2000] + ("..." if len(mission.attack_plan) > 2000 else ""),
            title="[bold red]⚔ Plan d'attaque LLM (brut)[/bold red]",
            border_style="red",
        ))
    else:
        console.print("  [yellow]Operator: plan non généré (LLM indisponible ou erreur).[/yellow]")


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


# ── rao llm-redteam ─────────────────────────────────────────────────────────────

@cli.command("llm-redteam")
@click.option("--profile", "-p", type=click.Path(exists=True), help="Target profile YAML (see rao/tools/llm_redteam/data/targets/)")
@click.option("--openai", "openai_base", default="", help="Quick mode: OpenAI-compatible api_base, e.g. http://localhost:8000/v1")
@click.option("--model", default="", help="Model name (used with --openai)")
@click.option("--api-key-env", default="OPENAI_API_KEY", help="Env var holding the API key (used with --openai)")
@click.option("--system", default="", help="System prompt to place the target under test (used with --openai)")
@click.option("--categories", default="", help="Comma-separated OWASP LLM ids to run, e.g. LLM01,LLM07")
@click.option("--known-secret", "known_secret", multiple=True, help="A secret known to be in the target's context; makes LLM02 exfil deterministic. Repeatable.")
@click.option("--system-marker", "system_marker", multiple=True, help="A known marker from the target's system prompt; makes LLM07 leak deterministic. Repeatable.")
@click.option("--judge/--no-judge", "use_judge", default=None, help="Use the conservative LLM judge for ambiguous cases")
@click.option("--baseline", is_flag=True, help="Compare against and update the per-target baseline")
@click.option("--ci", is_flag=True, help="Exit non-zero if a NEW vulnerability appears vs baseline (implies --baseline)")
@click.option("--json", "json_out", is_flag=True, help="Write a JSON report")
@click.option("--confirm", is_flag=True, help="Confirm you are authorized to test this target")
@click.option("--verbose", "-v", is_flag=True)
def llm_redteam(profile, openai_base, model, api_key_env, system, categories,
                known_secret, system_marker, use_judge, baseline, ci, json_out, confirm, verbose):
    """Red-team an LLM endpoint (OWASP LLM Top 10 + MITRE ATLAS).

    Provide a target either via --profile <yaml> or quick OpenAI mode:

        rao llm-redteam --openai http://localhost:8000/v1 --model gpt-test --confirm
        rao llm-redteam --profile my_target.yaml --baseline --ci --confirm
    """
    import yaml

    from rao.config import settings
    from rao.tools.llm_redteam.baseline import (
        diff_baseline,
        load_baseline,
        probe_status,
        save_baseline,
    )
    from rao.tools.llm_redteam.judge import LLMJudge
    from rao.tools.llm_redteam.probes import filter_probes, load_probes
    from rao.tools.llm_redteam.report import print_console_report, save_json_report
    from rao.tools.llm_redteam.scanner import LLMRedTeamScanner
    from rao.tools.llm_redteam.target import build_target

    _setup_logging(verbose)
    console.print(BANNER)

    # Build the target.
    try:
        if profile:
            prof = yaml.safe_load(open(profile, encoding="utf-8")) or {}
            target = build_target(prof)
        elif openai_base and model:
            target = build_target({
                "type": "openai", "api_base": openai_base, "model": model,
                "api_key_env": api_key_env, "system": system,
            })
        else:
            console.print("[red]ERROR:[/red] provide --profile <yaml> or --openai <api_base> --model <name>.")
            sys.exit(1)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Could not build target: {e}[/red]")
        sys.exit(1)

    _require_confirm(target.label, confirm)

    # Judge selection (default from config).
    judge_enabled = settings.llm_redteam.judge_enabled if use_judge is None else use_judge
    judge = None
    if judge_enabled:
        judge = LLMJudge()
        status = "available" if judge.available else "[yellow]offline — ambiguous probes stay BLOCKED[/yellow]"
        console.print(f"[dim]Judge LLM: {status}[/dim]")
    else:
        console.print("[dim]Judge disabled — only deterministic detectors used.[/dim]")

    cats = [c for c in categories.split(",") if c.strip()] if categories else None
    probes = filter_probes(load_probes(), cats)
    console.print(f"[dim]Running {len(probes)} probe group(s) against {target.label}...[/dim]\n")

    scanner = LLMRedTeamScanner(
        concurrency=settings.llm_redteam.concurrency,
        request_timeout=settings.llm_redteam.request_timeout,
        judge=judge,
    )
    with console.status("[bold blue]Probing LLM target...[/bold blue]"):
        result = scanner.scan(
            target, probes,
            sentinels=list(system_marker) or None,
            known_secrets=list(known_secret) or None,
        )

    print_console_report(result, console)

    # Continuous: baseline diff / CI gate.
    if baseline or ci:
        prior = load_baseline(result.target_id)
        statuses = probe_status(result)
        diff = diff_baseline(prior, statuses)
        save_baseline(result.target_id, statuses)
        console.print(f"\n[bold]Baseline diff:[/bold] {diff.summary()}")
        for entry in diff.new:
            console.print(f"  [red]NEW[/red] {entry['probe_id']} ({entry['owasp_id']})")
        for entry in diff.fixed:
            console.print(f"  [green]FIXED[/green] {entry['probe_id']} ({entry['owasp_id']})")
        if ci and diff.has_regressions:
            console.print("\n[bold red]CI gate: NEW vulnerabilities detected — failing.[/bold red]")
            sys.exit(1)

    if json_out:
        path = save_json_report(result)
        console.print(f"\n[green]JSON report: {path}[/green]")


# ── rao llm-eval ──────────────────────────────────────────────────────────────

@cli.command("llm-eval")
@click.option("--judge/--no-judge", "use_judge", default=False, help="Use the LLM judge during evaluation")
@click.option("--verbose", "-v", is_flag=True)
def llm_eval(use_judge, verbose):
    """Measure the scanner's false-positive / false-negative rate against
    ground-truth mock targets. Fails if any false positive occurs (FP must be 0)."""
    from rao.tools.llm_redteam.eval import run_eval
    from rao.tools.llm_redteam.judge import LLMJudge
    from rao.tools.llm_redteam.scanner import LLMRedTeamScanner, new_canary

    _setup_logging(verbose)
    console.print(BANNER)

    judge = LLMJudge() if use_judge else None
    if use_judge:
        console.print(f"[dim]Judge LLM: {'available' if judge.available else 'offline'}[/dim]")

    scanner = LLMRedTeamScanner(judge=judge)
    with console.status("[bold blue]Running evaluation suite...[/bold blue]"):
        report = run_eval(scanner, canary=new_canary())

    console.print("\n[bold]Confusion matrix[/bold]")
    console.print(report.confusion_str())

    if report.fp:
        console.print(f"\n[bold red]FAIL: {report.fp} false positive(s)[/bold red]")
        for d in report.fp_details:
            console.print(f"  [red]FP[/red] {d['probe_id']} on {d['target']}")
        sys.exit(1)
    console.print("\n[bold green]PASS: 0 false positives[/bold green] "
                  f"(recall={report.recall:.2f})")


def main():
    cli()


if __name__ == "__main__":
    main()
