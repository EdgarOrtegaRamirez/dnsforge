"""DNS zone file analyzer — statistics, health scoring, and recommendations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import (
    Issue,
    RecordType,
    Severity,
    ZoneFile,
    ZoneStats,
)


@dataclass
class HealthReport:
    """Comprehensive health report for a zone file."""

    score: int  # 0-100
    grade: str  # A+ to F
    stats: ZoneStats
    issues: list[Issue]
    recommendations: list[str]
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "stats": self.stats.to_dict(),
            "issues": [i.to_dict() for i in self.issues],
            "recommendations": self.recommendations,
            "summary": self.summary,
        }


class ZoneAnalyzer:
    """Analyze a parsed DNS zone file for health, statistics, and recommendations."""

    def __init__(self, zone: ZoneFile, issues: list[Issue] | None = None):
        self.zone = zone
        self.issues = issues or []

    def analyze(self) -> HealthReport:
        """Perform full analysis and return a health report."""
        stats = self._compute_stats()
        score, grade = self._compute_score(stats)
        recommendations = self._generate_recommendations(stats)
        summary = self._generate_summary(stats, score, grade)

        return HealthReport(
            score=score,
            grade=grade,
            stats=stats,
            issues=self.issues,
            recommendations=recommendations,
            summary=summary,
        )

    def _compute_stats(self) -> ZoneStats:
        """Compute zone statistics."""
        stats = ZoneStats()
        stats.total_records = len(self.zone.records)

        # Records by type
        for record in self.zone.records:
            type_name = record.record_type.value
            stats.records_by_type[type_name] = stats.records_by_type.get(type_name, 0) + 1

        # Unique names
        names = set()
        for record in self.zone.records:
            names.add(record.name)
        stats.unique_names = len(names)

        # TTL stats
        ttls = [record.ttl for record in self.zone.records if record.ttl is not None]
        if ttls:
            stats.max_ttl = max(ttls)
            stats.min_ttl = min(ttls)
            stats.avg_ttl = sum(ttls) / len(ttls)

        # SOA/NS presence
        stats.has_soa = self.zone.soa is not None
        stats.has_ns = "NS" in stats.records_by_type

        # CNAME targets
        stats.cname_targets = self.zone.get_cname_targets()

        # MX exchanges
        mx_records = self.zone.get_mx_records()
        stats.mx_exchanges = [mx[2] for mx in mx_records]

        # NS records
        ns_records = self.zone.get_records(RecordType.NS)
        stats.ns_records = [r.rdata_parts.get("target", r.rdata) for r in ns_records]

        # Delegation points
        delegation_ns: dict[str, list[str]] = {}
        for record in ns_records:
            if record.name != self.zone.origin:
                if record.name not in delegation_ns:
                    delegation_ns[record.name] = []
                delegation_ns[record.name].append(record.rdata_parts.get("target", record.rdata))
        stats.delegation_points = list(delegation_ns.keys())

        return stats

    def _compute_score(self, stats: ZoneStats) -> tuple[int, str]:
        """Compute health score (0-100) and letter grade."""
        score = 100

        # Deductions for issues
        for issue in self.issues:
            if issue.severity == Severity.ERROR:
                score -= 10
            elif issue.severity == Severity.WARNING:
                score -= 5
            elif issue.severity == Severity.INFO:
                score -= 1

        # Bonus for good practices
        if stats.has_soa:
            score += 2
        if stats.has_ns:
            score += 2
        if len(stats.ns_records) >= 2:
            score += 3
        if stats.avg_ttl > 300:  # Reasonable TTLs
            score += 2
        if stats.cname_targets:  # Has CNAMEs (common)
            score += 0
        if stats.mx_exchanges:
            score += 2

        # Penalty for missing essentials
        if not stats.has_soa:
            score -= 15
        if not stats.has_ns:
            score -= 15

        # Clamp
        score = max(0, min(100, score))

        # Grade
        if score >= 97:
            grade = "A+"
        elif score >= 93:
            grade = "A"
        elif score >= 90:
            grade = "A-"
        elif score >= 87:
            grade = "B+"
        elif score >= 83:
            grade = "B"
        elif score >= 80:
            grade = "B-"
        elif score >= 77:
            grade = "C+"
        elif score >= 73:
            grade = "C"
        elif score >= 70:
            grade = "C-"
        elif score >= 67:
            grade = "D+"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return score, grade

    def _generate_recommendations(self, stats: ZoneStats) -> list[str]:
        """Generate actionable recommendations based on analysis."""
        recs = []

        if not stats.has_soa:
            recs.append("Add a SOA record — it's required for any DNS zone")

        if not stats.has_ns:
            recs.append("Add NS records — they're required to delegate your zone")

        if len(stats.ns_records) < 2:
            recs.append("Add at least 2 NS records for redundancy and reliability")

        if stats.avg_ttl < 300:
            recs.append("Consider increasing TTL values — very low TTLs increase DNS query load")

        if stats.max_ttl > 86400:
            recs.append("Very high TTLs (>24h) may delay propagation of changes")

        # Check for CNAME at zone apex
        if self.zone.origin in stats.cname_targets:
            recs.append("Avoid CNAME at zone apex (@) — use ALIAS/ANAME or A/AAAA records instead")

        # Check for missing AAAA records where A exists
        a_names = set()
        aaaa_names = set()
        for record in self.zone.records:
            if record.record_type == RecordType.A:
                a_names.add(record.name)
            elif record.record_type == RecordType.AAAA:
                aaaa_names.add(record.name)
        missing_aaaa = a_names - aaaa_names
        if missing_aaaa and len(missing_aaaa) <= 5:
            for name in sorted(missing_aaaa):
                recs.append(f"Consider adding AAAA record for '{name}' (IPv6 support)")
        elif missing_aaaa:
            recs.append(f"{len(missing_aaaa)} A records have no corresponding AAAA records (IPv6 readiness)")

        # Check for low-priority MX records
        for name, priority, _exchange in self.zone.get_mx_records():
            if priority == 0:
                recs.append(f"MX record at '{name}' has priority 0 — ensure this is intentional")

        # Check for SRV with port 0
        for record in self.zone.get_records(RecordType.SRV):
            port = record.rdata_parts.get("port", 0)
            if port == 0:
                recs.append(f"SRV record at '{record.name}' has port 0 (service unavailable)")

        # Check for empty TXT records (SPF, DKIM, etc.)
        has_spf = False
        has_dmarc = False
        for record in self.zone.get_records(RecordType.TXT):
            txtdata = record.rdata_parts.get("txtdata", record.rdata)
            if "v=spf1" in txtdata:
                has_spf = True
            if "v=DMARC1" in txtdata:
                has_dmarc = True

        if not has_spf and self.zone.get_records(RecordType.MX):
            recs.append("Consider adding SPF record (TXT with v=spf1) for email deliverability")

        if not has_dmarc and self.zone.get_records(RecordType.MX):
            recs.append("Consider adding DMARC record (TXT with v=DMARC1) for email authentication")

        return recs

    def _generate_summary(self, stats: ZoneStats, score: int, grade: str) -> str:
        """Generate a human-readable summary."""
        parts = []
        parts.append(f"Zone: {self.zone.origin or '(unnamed)'}")
        parts.append(f"Records: {stats.total_records} ({stats.unique_names} unique names)")
        parts.append(f"Health: {score}/100 ({grade})")

        # Record type breakdown
        type_parts = []
        for type_name, count in sorted(stats.records_by_type.items()):
            type_parts.append(f"{count} {type_name}")
        parts.append(f"Types: {', '.join(type_parts)}")

        # Issue summary
        errors = sum(1 for i in self.issues if i.severity == Severity.ERROR)
        warnings = sum(1 for i in self.issues if i.severity == Severity.WARNING)
        infos = sum(1 for i in self.issues if i.severity == Severity.INFO)
        if errors or warnings or infos:
            parts.append(f"Issues: {errors} errors, {warnings} warnings, {infos} info")
        else:
            parts.append("Issues: none")

        return " | ".join(parts)


def analyze_zone(zone: ZoneFile, issues: list[Issue] | None = None) -> HealthReport:
    """Analyze a zone file and return a health report."""
    analyzer = ZoneAnalyzer(zone, issues)
    return analyzer.analyze()
