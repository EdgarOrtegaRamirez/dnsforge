"""Tests for DNS zone file reporter."""

import json

from dnsforge.analyzer import analyze_zone
from dnsforge.parser import parse_zone
from dnsforge.reporter import format_json, format_markdown, format_text
from dnsforge.validator import validate_zone


def _make_report():
    zone = parse_zone(
        """$ORIGIN example.com.
$TTL 3600

@   IN  SOA  ns1.example.com. admin.example.com. (
    2024070601 3600 900 604800 86400
)

@       IN  NS      ns1.example.com.
@       IN  NS      ns2.example.com.
ns1     IN  A       192.0.2.1
ns2     IN  A       192.0.2.2
@       IN  A       192.0.2.10
www     IN  CNAME   @
@       IN  MX      10 mail.example.com.
""",
        origin="example.com",
    )
    issues = validate_zone(zone)
    report = analyze_zone(zone, issues)
    return report, zone


class TestFormatText:
    def test_contains_origin(self):
        report, zone = _make_report()
        text = format_text(report, zone)
        assert "example.com" in text

    def test_contains_score(self):
        report, zone = _make_report()
        text = format_text(report, zone)
        assert "/100" in text

    def test_contains_record_types(self):
        report, zone = _make_report()
        text = format_text(report, zone)
        assert "A" in text
        assert "MX" in text

    def test_contains_bar(self):
        report, zone = _make_report()
        text = format_text(report, zone)
        assert "█" in text or "░" in text


class TestFormatJSON:
    def test_valid_json(self):
        report, zone = _make_report()
        result = format_json(report, zone)
        data = json.loads(result)
        assert "score" in data
        assert "zone" in data

    def test_contains_records(self):
        report, zone = _make_report()
        result = format_json(report, zone)
        data = json.loads(result)
        assert len(data["zone"]["records"]) > 0


class TestFormatMarkdown:
    def test_contains_heading(self):
        report, zone = _make_report()
        md = format_markdown(report, zone)
        assert "# DNS Zone Analysis" in md

    def test_contains_table(self):
        report, zone = _make_report()
        md = format_markdown(report, zone)
        assert "| Metric |" in md
        assert "| Type |" in md

    def test_contains_recommendations(self):
        report, zone = _make_report()
        md = format_markdown(report, zone)
        assert "## Recommendations" in md or "## Issues" in md
