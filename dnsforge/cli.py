"""DNS zone file CLI — validate, analyze, convert, and inspect DNS zone files."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .analyzer import analyze_zone
from .models import RecordType, Severity
from .parser import ParseError, parse_zone_file
from .reporter import format_json, format_markdown, format_text, format_zone
from .validator import validate_zone

console = Console()


@click.group()
@click.version_option(package_name="dnsforge")
def main() -> None:
    """DNS zone file parser, validator, analyzer, and converter."""
    pass


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", type=click.Choice(["text", "json", "markdown"]), default="text")
def validate(file: str, output_format: str) -> None:
    """Validate a DNS zone file for RFC compliance and best practices."""
    try:
        zone = parse_zone_file(file)
    except ParseError as e:
        console.print(f"[red]Parse error:[/red] {e}")
        sys.exit(1)

    issues = validate_zone(zone)

    if output_format == "json":
        data = {
            "zone": zone.to_dict(),
            "issues": [i.to_dict() for i in issues],
        }
        click.echo(json.dumps(data, indent=2))
    elif output_format == "markdown":
        report = analyze_zone(zone, issues)
        click.echo(format_markdown(report, zone))
    else:
        if not issues:
            console.print("[green]✓ Zone file is valid![/green]")
        else:
            errors = [i for i in issues if i.severity == Severity.ERROR]
            warnings = [i for i in issues if i.severity == Severity.WARNING]
            infos = [i for i in issues if i.severity == Severity.INFO]

            if errors:
                console.print(f"\n[red]✗ {len(errors)} error(s):[/red]")
                for issue in errors:
                    loc = f"L{issue.line_number}" if issue.line_number else ""
                    console.print(f"  [red]✗[/red] [{issue.rule}] {issue.message} {loc}")

            if warnings:
                console.print(f"\n[yellow]⚠ {len(warnings)} warning(s):[/yellow]")
                for issue in warnings:
                    loc = f"L{issue.line_number}" if issue.line_number else ""
                    console.print(f"  [yellow]⚠[/yellow] [{issue.rule}] {issue.message} {loc}")

            if infos:
                console.print(f"\n[blue]ℹ {len(infos)} info(s):[/blue]")
                for issue in infos:
                    loc = f"L{issue.line_number}" if issue.line_number else ""
                    console.print(f"  [blue]ℹ[/blue] [{issue.rule}] {issue.message} {loc}")

            console.print()

        if any(i.severity == Severity.ERROR for i in issues):
            sys.exit(1)


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", type=click.Choice(["text", "json", "markdown"]), default="text")
def analyze(file: str, output_format: str) -> None:
    """Analyze a DNS zone file and generate a health report."""
    try:
        zone = parse_zone_file(file)
    except ParseError as e:
        console.print(f"[red]Parse error:[/red] {e}")
        sys.exit(1)

    issues = validate_zone(zone)
    report = analyze_zone(zone, issues)

    if output_format == "json":
        click.echo(format_json(report, zone))
    elif output_format == "markdown":
        click.echo(format_markdown(report, zone))
    else:
        click.echo(format_text(report, zone))


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", type=click.Choice(["text", "json"]), default="text")
def info(file: str, output_format: str) -> None:
    """Display detailed information about a DNS zone file."""
    try:
        zone = parse_zone_file(file)
    except ParseError as e:
        console.print(f"[red]Parse error:[/red] {e}")
        sys.exit(1)

    if output_format == "json":
        click.echo(zone.to_json())
        return

    console.print(f"\n[bold]Zone: {zone.origin or '(unnamed)'}[/bold]")
    console.print(f"Total records: {zone.record_count}")
    console.print()

    # Directives
    if zone.directives:
        console.print("[bold]Directives:[/bold]")
        for key, value in zone.directives.items():
            console.print(f"  {key} {value}")
        console.print()

    # SOA
    if zone.soa:
        soa = zone.soa
        console.print("[bold]SOA Record:[/bold]")
        console.print(f"  Primary NS:  {soa.mname}")
        console.print(f"  Admin email: {soa.rname}")
        console.print(f"  Serial:      {soa.serial}")
        console.print(f"  Refresh:     {soa.refresh}s")
        console.print(f"  Retry:       {soa.retry}s")
        console.print(f"  Expire:      {soa.expire}s")
        console.print(f"  Minimum:     {soa.minimum}s")
        console.print()

    # Record table
    table = Table(title="Records")
    table.add_column("Name", style="cyan")
    table.add_column("TTL", style="dim")
    table.add_column("Type", style="green")
    table.add_column("Rdata", style="white")

    for record in zone.records:
        ttl_str = str(record.ttl) if record.ttl is not None else "-"
        name_display = record.name
        if name_display == zone.origin:
            name_display = "@"
        elif name_display.startswith(zone.origin + "."):
            name_display = name_display[: -len(zone.origin) - 1] + "@"

        table.add_row(name_display, ttl_str, record.record_type.value, record.rdata)

    console.print(table)


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", type=click.Choice(["text", "json", "zone"]), default="text")
def stats(file: str, output_format: str) -> None:
    """Show statistics about a DNS zone file."""
    try:
        zone = parse_zone_file(file)
    except ParseError as e:
        console.print(f"[red]Parse error:[/red] {e}")
        sys.exit(1)

    report = analyze_zone(zone)
    stats_data = report.stats

    if output_format == "json":
        click.echo(json.dumps(stats_data.to_dict(), indent=2))
        return

    console.print(f"\n[bold]Zone Statistics: {zone.origin or '(unnamed)'}[/bold]")
    console.print(f"  Total records:    {stats_data.total_records}")
    console.print(f"  Unique names:     {stats_data.unique_names}")
    console.print(f"  Has SOA:          {'✓' if stats_data.has_soa else '✗'}")
    console.print(f"  Has NS:           {'✓' if stats_data.has_ns else '✗'}")

    if stats_data.min_ttl > 0 or stats_data.max_ttl > 0:
        console.print(f"  TTL range:        {stats_data.min_ttl}s — {stats_data.max_ttl}s")
        console.print(f"  Average TTL:      {stats_data.avg_ttl:.0f}s")

    console.print()

    # Record types table
    if stats_data.records_by_type:
        table = Table(title="Record Types")
        table.add_column("Type", style="green")
        table.add_column("Count", justify="right")

        for type_name, count in sorted(stats_data.records_by_type.items()):
            table.add_row(type_name, str(count))

        console.print(table)

    if stats_data.cname_targets:
        console.print(f"\n[bold]CNAME Targets ({len(stats_data.cname_targets)}):[/bold]")
        for name, target in sorted(stats_data.cname_targets.items()):
            console.print(f"  {name} → {target}")

    if stats_data.mx_exchanges:
        console.print(f"\n[bold]MX Exchanges ({len(stats_data.mx_exchanges)}):[/bold]")
        for exchange in stats_data.mx_exchanges:
            console.print(f"  {exchange}")


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--origin", "-o", default="", help="Default $ORIGIN value")
def parse(file: str, origin: str) -> None:
    """Parse a DNS zone file and display the AST (JSON)."""
    try:
        zone = parse_zone_file(file, origin)
    except ParseError as e:
        console.print(f"[red]Parse error:[/red] {e}")
        sys.exit(1)

    click.echo(zone.to_json())


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--format", "-f", "output_format", type=click.Choice(["json", "markdown"]), default="json")
def convert(file: str, output: str | None, output_format: str) -> None:
    """Convert a DNS zone file to JSON or Markdown format."""
    try:
        zone = parse_zone_file(file)
    except ParseError as e:
        console.print(f"[red]Parse error:[/red] {e}")
        sys.exit(1)

    issues = validate_zone(zone)
    report = analyze_zone(zone, issues)

    result = format_json(report, zone) if output_format == "json" else format_markdown(report, zone)

    if output:
        Path(output).write_text(result, encoding="utf-8")
        console.print(f"[green]Written to {output}[/green]")
    else:
        click.echo(result)


@main.command("format")
@click.argument("file", type=click.Path(exists=True))
def format_cmd(file: str) -> None:
    """Re-format a DNS zone file with consistent styling."""
    try:
        zone = parse_zone_file(file)
    except ParseError as e:
        console.print(f"[red]Parse error:[/red] {e}")
        sys.exit(1)

    click.echo(format_zone(None, zone))  # type: ignore


@main.command()
def types() -> None:
    """List all supported DNS record types."""
    table = Table(title="Supported DNS Record Types")
    table.add_column("Type", style="green")
    table.add_column("Description")

    descriptions = {
        "A": "IPv4 address",
        "AAAA": "IPv6 address",
        "CNAME": "Canonical name (alias)",
        "MX": "Mail exchange",
        "NS": "Name server",
        "TXT": "Text record",
        "SOA": "Start of authority",
        "SRV": "Service locator",
        "PTR": "Pointer (reverse DNS)",
        "CAA": "Certification Authority Authorization",
        "TLSA": "DANE TLS association",
        "SSHFP": "SSH fingerprint",
        "DS": "Delegation Signer",
        "DNSKEY": "DNSSEC key",
        "HTTPS": "HTTPS binding",
        "SVCB": "Service binding",
        "CDS": "Child DS",
        "CDNSKEY": "Child DNSKEY",
        "NSEC": "Next SECURE (DNSSEC)",
        "NSEC3": "Next SECURE v3 (DNSSEC)",
        "RRSIG": "Resource Record Signature (DNSSEC)",
        "OPENPGPKEY": "OpenPGP key",
        "LOC": "Location",
        "HINFO": "Host information",
    }

    for rt in RecordType:
        if rt == RecordType.Unknown:
            continue
        desc = descriptions.get(rt.value, "")
        table.add_row(rt.value, desc)

    console.print(table)


@main.command()
def sample() -> None:
    """Print a sample zone file to stdout."""
    sample_zone = """$ORIGIN example.com.
$TTL 3600

@   IN  SOA  ns1.example.com. admin.example.com. (
    2024070601  ; Serial
    3600        ; Refresh
    900         ; Retry
    604800      ; Expire
    86400       ; Minimum
)

@       IN  NS      ns1.example.com.
@       IN  NS      ns2.example.com.

ns1     IN  A       192.0.2.1
ns2     IN  A       192.0.2.2

@       IN  A       192.0.2.10
@       IN  AAAA    2001:db8::10

www     IN  CNAME   @
mail    IN  A       192.0.2.20
@       IN  MX      10 mail.example.com.
@       IN  MX      20 mail2.example.com.

ftp     IN  CNAME   www.example.com.
"""
    click.echo(sample_zone)


if __name__ == "__main__":
    main()
