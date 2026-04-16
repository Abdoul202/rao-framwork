"""
RAO-Framework CLI - Command-line interface.

Usage:
    rao scan <target> [options]       Full mission pipeline
    rao recon <target>                Scout-only (nmap + web scan)
    rao webscan <target>              Web-only scan (headers, paths, CORS)
    rao subdomains <domain>           Subdomain enumeration
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

console = Console()

BANNER = """[bold red]
  ██████╗  █████╗  ██████╗
  ██╔══██╗██╔══██╗██╔═══██╗
  ██████╔╝███████║██║   ██║
  ██╔══██╗██╔══██║██║   ██║
  ██║  ██║██║  ██║╚██████╔╝
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝[/bold red]
[dim]  Multi-Agent Red Team Framework v0.1.0[/dim]
"""


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group()
@click.version_option(version="0.1.0", prog_name="rao")
def cli():
    """RAO-Framework - Multi-Agent Autonomous Red Teaming System."""
    pass


@cli.command()
@click.argument("target")
@click.option("--scope", "-s", multiple=True, help="Additional scope entries (IPs, CIDRs, domains)")
@click.option("--no-web", is_flag=True, help="Skip web scanning")
@click.option("--no-subdomains", is_flag=True, help="Skip subdomain enumeration")
@click.option("--save", is_flag=True, help="Save session for later resume")
@click.option("--html", is_flag=True, help="Generate HTML report")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def scan(target, scope, no_web, no_subdomains, save, html, verbose):
    """Run a full red team mission against TARGET."""
    _setup_logging(verbose)
    console.print(BANNER)

    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Scope:[/bold] {', '.join(scope) if scope else target}\n"
        f"[bold]Web scan:[/bold] {'No' if no_web else 'Yes'}\n"
        f"[bold]Subdomains:[/bold] {'No' if no_subdomains else 'Yes'}",
        title="[red]Mission Config[/red]",
        border_style="red",
    ))

    console.print("\n[yellow]DISCLAIMER: Authorized testing only. Ensure you have written permission.[/yellow]\n")

    # Scope validation
    from rao.tools.scope_validator import ScopeValidator

    scope_list = list(scope) + [target] if scope else [target]
    validator = ScopeValidator(allowed_targets=scope_list, allow_private=True)

    try:
        validator.validate(target)
    except Exception as e:
        console.print(f"[red]Scope error: {e}[/red]")
        sys.exit(1)

    # Run main pipeline
    from rao.core.orchestrator import OCC

    with console.status("[bold blue]Running mission pipeline...[/bold blue]"):
        occ = OCC()
        mission = occ.execute(target=target, scope=scope_list)

    # Web scanning
    web_results = []
    if not no_web:
        from rao.tools.web_scanner import WebScanner

        scanner = WebScanner()
        with console.status("[bold blue]Web scanning...[/bold blue]"):
            for host in mission.hosts:
                for port in host.ports:
                    if port.service in ("http", "https", "http-proxy", "http-alt"):
                        scheme = "https" if port.port == 443 or "ssl" in port.service else "http"
                        url = f"{scheme}://{host.ip}:{port.port}"
                        result = scanner.scan(url)
                        if result:
                            web_results.append(result)
                            # Convert web findings to mission findings
                            _web_to_findings(result, mission)

    # Subdomain enumeration
    subdomains = []
    if not no_subdomains and not _is_ip(target):
        from rao.tools.subdomain_enum import SubdomainEnumerator

        enumerator = SubdomainEnumerator()
        with console.status("[bold blue]Enumerating subdomains...[/bold blue]"):
            subdomains = enumerator.enumerate(target)

    # Reports
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
def recon(target, verbose):
    """Scout-only reconnaissance (nmap + web scan)."""
    _setup_logging(verbose)
    console.print(BANNER)
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
        console.print(f"\n[bold]Web scan results:[/bold]")
        for wr in web_results:
            console.print(f"  {wr.url} - {len(wr.missing_headers)} missing headers, {len(wr.exposed_paths)} exposed paths")


@cli.command()
@click.argument("target")
@click.option("--verbose", "-v", is_flag=True)
def webscan(target, verbose):
    """Web-only security scan (headers, paths, CORS, cookies)."""
    _setup_logging(verbose)
    console.print(BANNER)

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
    """Enumerate subdomains for a domain."""
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


@cli.group()
def sessions():
    """Manage saved mission sessions."""
    pass


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
    from rao.core.state import Severity

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
