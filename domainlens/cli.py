import argparse
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .util import normalize_domain, safe_filename, now_iso
from .dns_recon import dns_recon
from .http_recon import http_recon, headers_audit
from .tls_recon import tls_recon
from .subdomains import crtsh_subdomains
from .report import write_json, write_md

console = Console()


def build_parser():
    p = argparse.ArgumentParser(
        prog="domainlens",
        description="DomainLens - Passive Recon Tool (DNS, HTTP, TLS, headers, subdomains)",
    )
    p.add_argument("target", help="Domain or URL (example.com or https://example.com)")
    p.add_argument("--timeout", type=int, default=8, help="HTTP timeout in seconds (default: 8)")
    p.add_argument("--out", default="reports", help="Output directory (default: reports)")
    p.add_argument("--json", action="store_true", help="Generate JSON report")
    p.add_argument("--md", action="store_true", help="Generate Markdown report")
    p.add_argument("--subdomains", action="store_true", help="Enable passive subdomain discovery (crt.sh)")
    p.add_argument("--all", action="store_true", help="Generate everything (md+json+subdomains)")
    return p


def main():
    args = build_parser().parse_args()

    try:
        domain = normalize_domain(args.target)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(2)

    if args.all:
        args.md = True
        args.json = True
        args.subdomains = True

    if not args.md and not args.json:
        # default behavior
        args.md = True
        args.json = True

    out_dir = Path(args.out) / safe_filename(domain)
    out_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold cyan]DomainLens[/bold cyan] scanning: [bold]{domain}[/bold]")
    console.print(f"Output directory: {out_dir}")

    # Collect
    console.print("\n[bold]DNS Recon[/bold]")
    dns_data = dns_recon(domain)

    console.print("[bold]HTTP Recon[/bold]")
    http_data = http_recon(domain, timeout=args.timeout)

    # Headers audit (prefer HTTPS if ok, else HTTP)
    chosen = None
    if http_data.get("https", {}).get("ok"):
        chosen = http_data["https"]["security_headers"]
    elif http_data.get("http", {}).get("ok"):
        chosen = http_data["http"]["security_headers"]

    headers_data = headers_audit(chosen) if chosen else None

    console.print("[bold]TLS Recon[/bold]")
    tls_data = tls_recon(domain)

    subs_data = None
    if args.subdomains:
        console.print("[bold]Passive Subdomains (crt.sh)[/bold]")
        subs_data = crtsh_subdomains(domain)

    # Build final report dict
    report = {
        "tool": "DomainLens",
        "version": "0.1.0",
        "generated_at": now_iso(),
        "domain": domain,
        "dns": dns_data,
        "http": http_data,
        "headers_audit": headers_data,
        "tls": tls_data,
        "subdomains": subs_data,
    }

    # Save
    if args.json:
        json_path = out_dir / "report.json"
        write_json(json_path, report)
        console.print(f"[green]✔[/green] JSON saved: {json_path}")

    if args.md:
        md_path = out_dir / "report.md"
        write_md(md_path, report)
        console.print(f"[green]✔[/green] Markdown saved: {md_path}")

    # Pretty summary
    table = Table(title="DomainLens Summary", show_lines=True)
    table.add_column("Item", style="bold")
    table.add_column("Value")

    table.add_row("HTTPS", "Yes" if http_data["https"]["ok"] else "No")
    table.add_row("HTTP", "Yes" if http_data["http"]["ok"] else "No")
    table.add_row("TLS", "OK" if tls_data["ok"] else "Unavailable")
    if subs_data:
        table.add_row("Subdomains", str(subs_data.get("count", 0)))

    console.print()
    console.print(table)
    console.print("\n[bold green]Done.[/bold green]")