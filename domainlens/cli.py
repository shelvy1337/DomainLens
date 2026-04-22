import argparse
from pathlib import Path

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from . import __version__
from .dns_recon import dns_recon
from .findings import build_findings
from .http_recon import headers_audit, http_recon
from .report import write_json, write_md
from .score import compute_security_score
from .subdomains import crtsh_subdomains
from .tls_recon import tls_recon
from .util import normalize_domain, now_iso, safe_filename

console = Console()

BANNER = r"""

$$$$$$$\                                    $$\           $$\                                    
$$  __$$\                                   \__|          $$ |                                   
$$ |  $$ | $$$$$$\  $$$$$$\$$$$\   $$$$$$\  $$\ $$$$$$$\  $$ |      $$$$$$\  $$$$$$$\   $$$$$$$\ 
$$ |  $$ |$$  __$$\ $$  _$$  _$$\  \____$$\ $$ |$$  __$$\ $$ |     $$  __$$\ $$  __$$\ $$  _____|
$$ |  $$ |$$ /  $$ |$$ / $$ / $$ | $$$$$$$ |$$ |$$ |  $$ |$$ |     $$$$$$$$ |$$ |  $$ |\$$$$$$\  
$$ |  $$ |$$ |  $$ |$$ | $$ | $$ |$$  __$$ |$$ |$$ |  $$ |$$ |     $$   ____|$$ |  $$ | \____$$\ 
$$$$$$$  |\$$$$$$  |$$ | $$ | $$ |\$$$$$$$ |$$ |$$ |  $$ |$$$$$$$$\\$$$$$$$\ $$ |  $$ |$$$$$$$  |
\_______/  \______/ \__| \__| \__| \_______|\__|\__|  \__|\________|\_______|\__|  \__|\_______/

""".strip("\n")


def build_parser():
    p = argparse.ArgumentParser(
        prog="domainlens",
        description="DomainLens - Passive Recon Tool (DNS, HTTP, TLS, headers, subdomains)",
    )
    p.add_argument("target", nargs="?", help="Domain or URL (example.com or https://example.com)")
    p.add_argument("--timeout", type=int, default=8, help="HTTP timeout in seconds (default: 8)")
    p.add_argument("--out", default="reports", help="Output directory (default: reports)")
    p.add_argument("--json", action="store_true", help="Generate JSON report")
    p.add_argument("--md", action="store_true", help="Generate Markdown report")
    p.add_argument("--subdomains", action="store_true", help="Enable passive subdomain discovery (crt.sh)")
    p.add_argument("--all", action="store_true", help="Generate everything (md+json+subdomains)")
    p.add_argument("--version", action="store_true", help="Show version and exit")
    return p


def print_banner():
    title = Text(f"DomainLens v{__version__}", style="bold cyan")
    subtitle = Text("Passive Recon Tool • DNS • HTTP • TLS • Headers • crt.sh", style="dim")
    body = Text(BANNER, style="bold")
    console.print(Panel.fit(Text.assemble(body, "\n\n", title, "\n", subtitle), border_style="cyan"))


def score_style(score: int) -> str:
    if score >= 85:
        return "green"
    if score >= 70:
        return "yellow"
    if score >= 50:
        return "bright_yellow"
    return "red"


def severity_style(severity: str) -> str:
    return {
        "high": "bold red",
        "medium": "bold yellow",
        "low": "bold cyan",
        "info": "dim",
    }.get(severity, "white")


def main():
    args = build_parser().parse_args()

    if args.version:
        console.print(f"DomainLens v{__version__}")
        console.print("Coded with ❤️ by shelvy")
        raise SystemExit(0)

    if not args.target:
        console.print(">> [red]Error:[/red] missing target. Example: domainlens example.com")
        raise SystemExit(2)

    print_banner()

    try:
        domain = normalize_domain(args.target)
    except ValueError as e:
        console.print(f">> [red]Error:[/red] {e}")
        raise SystemExit(2)

    if args.all:
        args.md = True
        args.json = True
        args.subdomains = True

    if not args.md and not args.json:
        args.md = True
        args.json = True

    out_dir = Path(args.out) / safe_filename(domain)
    out_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold cyan]🎯 Target:[/bold cyan] [bold]{domain}[/bold]")
    console.print(f"[bold yellow]⭐[/bold yellow] [dim]Output:[/dim] {out_dir}\n")

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold]{task.description}[/bold]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        t_dns = progress.add_task("DNS recon", start=True)
        dns_data = dns_recon(domain)
        progress.update(t_dns, completed=1)

        t_http = progress.add_task("HTTP/HTTPS recon", start=True)
        http_data = http_recon(domain, timeout=args.timeout)
        progress.update(t_http, completed=1)

        chosen = None
        if http_data.get("https", {}).get("ok"):
            chosen = http_data["https"]["security_headers"]
        elif http_data.get("http", {}).get("ok"):
            chosen = http_data["http"]["security_headers"]

        headers_data = headers_audit(chosen) if chosen else None

        t_tls = progress.add_task("TLS certificate", start=True)
        tls_data = tls_recon(domain)
        progress.update(t_tls, completed=1)

        subs_data = None
        if args.subdomains:
            t_sub = progress.add_task("Passive subdomains (crt.sh)", start=True)
            subs_data = crtsh_subdomains(domain)
            progress.update(t_sub, completed=1)

    security = compute_security_score(http_data, tls_data, headers_data)

    report = {
        "tool": "DomainLens",
        "version": __version__,
        "generated_at": now_iso(),
        "domain": domain,
        "security": security,
        "dns": dns_data,
        "http": http_data,
        "headers_audit": headers_data,
        "tls": tls_data,
        "subdomains": subs_data,
    }

    findings = build_findings(report)
    report["findings"] = findings

    if args.json:
        json_path = out_dir / "report.json"
        write_json(json_path, report)
        console.print(f"[green]✔[/green] [dim]|[/dim] JSON saved: [yellow]{json_path}[/yellow]")

    if args.md:
        md_path = out_dir / "report.md"
        write_md(md_path, report)
        console.print(f"[green]✔[/green] [dim]|[/dim] Markdown saved: [yellow]{md_path}[/yellow]")

    console.print()

    score_panel = Panel.fit(
        f"[bold {score_style(security['score'])}]{security['score']}/100[/bold {score_style(security['score'])}]"
        f"\n[bold]{security['posture']}[/bold]",
        title="Security Score",
        border_style="cyan",
    )
    console.print(score_panel)
    console.print()

    summary = Table(show_lines=True, expand=True)
    summary.add_column("Item", style="bold cyan", no_wrap=True)
    summary.add_column("Value", style="white")

    summary.add_row("HTTPS", "Yes" if http_data["https"]["ok"] else "No")
    summary.add_row("HTTP", "Yes" if http_data["http"]["ok"] else "No")
    summary.add_row("TLS", "OK" if tls_data["ok"] else "Unavailable")
    summary.add_row("robots.txt", "Found" if http_data.get("robots_txt", {}).get("exists") else "Missing")
    summary.add_row("sitemap.xml", "Found" if http_data.get("sitemap_xml", {}).get("exists") else "Missing")
    if subs_data is not None:
        summary.add_row("Subdomains", str(subs_data.get("count", 0)))

    top_findings = findings[:5]
    findings_table = Table(show_lines=True, expand=True)
    findings_table.add_column("Severity", style="bold", no_wrap=True)
    findings_table.add_column("Finding", style="bold", overflow="fold")
    findings_table.add_column("Recommendation", overflow="fold")

    for item in top_findings:
        sev = item["severity"].upper()
        findings_table.add_row(
            f"[{severity_style(item['severity'])}]{sev}[/{severity_style(item['severity'])}]",
            item["title"],
            item["recommendation"],
        )

    panels = [
        Panel(summary, title="DomainLens Summary", border_style="cyan"),
    ]

    if top_findings:
        panels.append(
            Panel(findings_table, title="Top Findings", border_style="yellow")
        )

    console.print(Columns(panels, equal=True, expand=True))

    console.print("\n>> [bold green]✔ Task done[/bold green]")