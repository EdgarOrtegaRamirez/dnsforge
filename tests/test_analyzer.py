"""Tests for DNS zone file analyzer."""

from dnsforge.analyzer import analyze_zone
from dnsforge.parser import parse_zone
from dnsforge.validator import validate_zone


def _make_full_zone():
    return parse_zone(
        """$ORIGIN example.com.
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
@       IN  TXT     "v=spf1 include:_spf.google.com ~all"
""",
        origin="example.com",
    )


class TestStats:
    def test_total_records(self):
        zone = _make_full_zone()
        report = analyze_zone(zone)
        assert report.stats.total_records > 0

    def test_has_soa(self):
        zone = _make_full_zone()
        report = analyze_zone(zone)
        assert report.stats.has_soa is True

    def test_has_ns(self):
        zone = _make_full_zone()
        report = analyze_zone(zone)
        assert report.stats.has_ns is True

    def test_cname_targets(self):
        zone = _make_full_zone()
        report = analyze_zone(zone)
        assert "www.example.com" in report.stats.cname_targets

    def test_mx_exchanges(self):
        zone = _make_full_zone()
        report = analyze_zone(zone)
        assert len(report.stats.mx_exchanges) == 2

    def test_records_by_type(self):
        zone = _make_full_zone()
        report = analyze_zone(zone)
        assert "A" in report.stats.records_by_type
        assert "MX" in report.stats.records_by_type
        assert "CNAME" in report.stats.records_by_type

    def test_ttl_stats(self):
        zone = _make_full_zone()
        report = analyze_zone(zone)
        assert report.stats.max_ttl >= report.stats.min_ttl
        # avg_ttl may be 0 if no TTL is set on records


class TestScoring:
    def test_perfect_zone_high_score(self):
        zone = _make_full_zone()
        report = analyze_zone(zone)
        assert report.score >= 80
        assert report.grade in ("A+", "A", "A-", "B+", "B")

    def test_broken_zone_low_score(self):
        zone = parse_zone("@ IN A not-an-ip", origin="example.com")
        issues = validate_zone(zone)
        report = analyze_zone(zone, issues)
        assert report.score < 100

    def test_grade_mapping(self):
        zone = _make_full_zone()
        report = analyze_zone(zone)
        # Grade should be a valid letter grade
        assert report.grade[0] in "ABCDF"

    def test_score_range(self):
        zone = _make_full_zone()
        report = analyze_zone(zone)
        assert 0 <= report.score <= 100


class TestRecommendations:
    def test_recommendations_generated(self):
        zone = _make_full_zone()
        report = analyze_zone(zone)
        assert isinstance(report.recommendations, list)

    def test_ipv6_recommendation(self):
        # Zone with A but no AAAA
        zone = parse_zone(
            """@ IN SOA ns1.example.com. admin.example.com. (1 3600 900 604800 86400)
@ IN NS ns1.example.com.
@ IN A 192.0.2.1
ns1 IN A 192.0.2.1""",
            origin="example.com",
        )
        issues = validate_zone(zone)
        report = analyze_zone(zone, issues)
        ipv6_recs = [r for r in report.recommendations if "AAAA" in r or "IPv6" in r]
        assert len(ipv6_recs) > 0

    def test_spf_recommendation(self):
        # Zone with MX but no SPF
        zone = parse_zone(
            """@ IN SOA ns1.example.com. admin.example.com. (1 3600 900 604800 86400)
@ IN NS ns1.example.com.
@ IN MX 10 mail.example.com.""",
            origin="example.com",
        )
        issues = validate_zone(zone)
        report = analyze_zone(zone, issues)
        spf_recs = [r for r in report.recommendations if "SPF" in r]
        assert len(spf_recs) > 0


class TestSummary:
    def test_summary_contains_origin(self):
        zone = _make_full_zone()
        report = analyze_zone(zone)
        assert "example.com" in report.summary

    def test_summary_contains_score(self):
        zone = _make_full_zone()
        report = analyze_zone(zone)
        assert str(report.score) in report.summary


class TestToDict:
    def test_to_dict(self):
        zone = _make_full_zone()
        report = analyze_zone(zone)
        d = report.to_dict()
        assert "score" in d
        assert "grade" in d
        assert "stats" in d
        assert "issues" in d
        assert "recommendations" in d
