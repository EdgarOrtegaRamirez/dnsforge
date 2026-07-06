"""DNS zone file reporter — output formatters for analysis results."""

from __future__ import annotations

import json

from .analyzer import HealthReport
from .models import RecordType, ZoneFile


def format_text(report: HealthReport, zone: ZoneFile) -> str:
    """Format report as human-readable text."""
    lines = []
    lines.append(f"═══ DNS Zone Analysis: {zone.origin or '(unnamed)'} ═══")
    lines.append("")

    # Health score
    score = report.score
    grade = report.grade
    bar_len = 30
    filled = int(score / 100 * bar_len)
    bar = "█" * filled + "░" * (bar_len - filled)
    lines.append(f"  Health: [{bar}] {score}/100 ({grade})")
    lines.append("")

    # Stats
    stats = report.stats
    lines.append(f"  Total records:  {stats.total_records}")
    lines.append(f"  Unique names:   {stats.unique_names}")
    lines.append(f"  SOA present:    {'✓' if stats.has_soa else '✗'}")
    lines.append(f"  NS records:     {len(stats.ns_records)}")

    if stats.min_ttl > 0 or stats.max_ttl > 0:
        lines.append(f"  TTL range:      {stats.min_ttl}s — {stats.max_ttl}s (avg {stats.avg_ttl:.0f}s)")

    lines.append("")

    # Record types
    if stats.records_by_type:
        lines.append("  Record Types:")
        for type_name, count in sorted(stats.records_by_type.items()):
            lines.append(f"    {type_name:8s}  {count}")
        lines.append("")

    # Issues
    if report.issues:
        lines.append("  Issues:")
        for issue in report.issues:
            icon = {"error": "✗", "warning": "⚠", "info": "ℹ"}[issue.severity.value]
            loc = f"L{issue.line_number}" if issue.line_number else ""
            name = f" ({issue.record_name})" if issue.record_name else ""
            lines.append(f"    {icon} [{issue.rule}] {issue.message}{name} {loc}")
        lines.append("")

    # Recommendations
    if report.recommendations:
        lines.append("  Recommendations:")
        for i, rec in enumerate(report.recommendations, 1):
            lines.append(f"    {i}. {rec}")
        lines.append("")

    return "\n".join(lines)


def format_json(report: HealthReport, zone: ZoneFile) -> str:
    """Format report as JSON."""
    data = report.to_dict()
    data["zone"] = zone.to_dict()
    return json.dumps(data, indent=2)


def format_markdown(report: HealthReport, zone: ZoneFile) -> str:
    """Format report as Markdown."""
    lines = []
    lines.append(f"# DNS Zone Analysis: {zone.origin or '(unnamed)'}")
    lines.append("")

    # Health score
    lines.append(f"## Health: {report.score}/100 ({report.grade})")
    lines.append("")

    # Stats
    stats = report.stats
    lines.append("## Statistics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total records | {stats.total_records} |")
    lines.append(f"| Unique names | {stats.unique_names} |")
    lines.append(f"| SOA present | {'✓' if stats.has_soa else '✗'} |")
    lines.append(f"| NS records | {len(stats.ns_records)} |")
    if stats.min_ttl > 0 or stats.max_ttl > 0:
        lines.append(f"| TTL range | {stats.min_ttl}s — {stats.max_ttl}s |")
    lines.append("")

    # Record types
    if stats.records_by_type:
        lines.append("## Record Types")
        lines.append("")
        lines.append("| Type | Count |")
        lines.append("|------|-------|")
        for type_name, count in sorted(stats.records_by_type.items()):
            lines.append(f"| {type_name} | {count} |")
        lines.append("")

    # Issues
    if report.issues:
        lines.append("## Issues")
        lines.append("")
        lines.append("| Severity | Rule | Message |")
        lines.append("|----------|------|---------|")
        for issue in report.issues:
            lines.append(f"| {issue.severity.value} | {issue.rule} | {issue.message} |")
        lines.append("")

    # Recommendations
    if report.recommendations:
        lines.append("## Recommendations")
        lines.append("")
        for i, rec in enumerate(report.recommendations, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

    return "\n".join(lines)


def format_zone(report: HealthReport, zone: ZoneFile) -> str:
    """Format as a clean zone file (re-serialized)."""
    lines = []

    if zone.origin_directive:
        lines.append(f"$ORIGIN {zone.origin_directive}")

    # Find TTL directive
    if "$TTL" in zone.directives:
        lines.append(f"$TTL {zone.directives['$TTL']}")
    lines.append("")

    # SOA first
    if zone.soa:
        soa = zone.soa
        name = "@"
        lines.append(f"{name}  IN  SOA  {soa.mname} {soa.rname} (")
        lines.append(f"    {soa.serial}  ; Serial")
        lines.append(f"    {soa.refresh}  ; Refresh")
        lines.append(f"    {soa.retry}    ; Retry")
        lines.append(f"    {soa.expire}   ; Expire")
        lines.append(f"    {soa.minimum}  ; Minimum")
        lines.append(")")
        lines.append("")

    # Group records by name
    by_name: dict[str, list] = {}
    for record in zone.records:
        if record.record_type == RecordType.SOA:
            continue
        rname = record.name
        if rname not in by_name:
            by_name[rname] = []
        by_name[rname].append(record)

    for rname, records in by_name.items():
        display_name = rname.replace(zone.origin + ".", "@.").rstrip(".")
        if display_name == "@" or display_name == zone.origin:
            display_name = "@"

        for record in records:
            ttl_str = f" {record.ttl}" if record.ttl is not None else ""
            rdata = record.rdata
            lines.append(f"{display_name}{ttl_str}  IN  {record.record_type.value:8s}  {rdata}")
        lines.append("")

    return "\n".join(lines)
