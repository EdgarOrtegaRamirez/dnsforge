"""DNS zone file validator — RFC-compliant validation rules."""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING

from .models import DNSRecord, Issue, RecordType, Severity, ZoneFile

if TYPE_CHECKING:
    pass


class ZoneValidator:
    """Validate a parsed DNS zone file against RFC standards and best practices."""

    def __init__(self, zone: ZoneFile):
        self.zone = zone
        self.issues: list[Issue] = []

    def validate(self) -> list[Issue]:
        """Run all validation rules and return list of issues."""
        self.issues = []
        self._check_soa()
        self._check_ns_records()
        self._check_duplicate_records()
        self._check_record_names()
        self._check_a_records()
        self._check_aaaa_records()
        self._check_cname_records()
        self._check_mx_records()
        self._check_srv_records()
        self._check_txt_records()
        self._check_caa_records()
        self._check_sshfp_records()
        self._check_tlsa_records()
        self._check_ttl_values()
        self._check_cname_coexistence()
        self._check_wildcard_records()
        self._check_delegations()
        return self.issues

    def _add(self, severity: Severity, rule: str, message: str, line: int = 0, name: str = "") -> None:
        self.issues.append(Issue(severity=severity, rule=rule, message=message, line_number=line, record_name=name))

    def _check_soa(self) -> None:
        """Validate SOA record."""
        soa_records = self.zone.get_records(RecordType.SOA)

        if not soa_records:
            self._add(Severity.ERROR, "MISSING_SOA", "Zone has no SOA record")
            return

        if len(soa_records) > 1:
            self._add(Severity.ERROR, "MULTIPLE_SOA", f"Zone has {len(soa_records)} SOA records (expected 1)")

        soa = self.zone.soa
        if not soa:
            return

        # Serial number must be between 0 and 2^32 - 1
        if soa.serial < 0 or soa.serial > 0xFFFFFFFF:
            self._add(
                Severity.ERROR,
                "SOA_SERIAL_RANGE",
                f"SOA serial {soa.serial} is out of valid range (0-4294967295)",
                line=soa_records[0].line_number if soa_records else 0,
            )

        # Refresh should be reasonable (60s to 86400s)
        if soa.refresh < 60 or soa.refresh > 86400:
            self._add(
                Severity.WARNING,
                "SOA_REFRESH_RANGE",
                f"SOA refresh {soa.refresh}s is outside recommended range (60-86400)",
                line=soa_records[0].line_number if soa_records else 0,
            )

        # Retry should be less than refresh
        if soa.retry >= soa.refresh and soa.refresh > 0:
            self._add(
                Severity.WARNING,
                "SOA_RETRY_GTE_REFRESH",
                f"SOA retry ({soa.retry}s) should be less than refresh ({soa.refresh}s)",
                line=soa_records[0].line_number if soa_records else 0,
            )

        # Expire should be larger than refresh
        if soa.expire <= soa.refresh and soa.refresh > 0:
            self._add(
                Severity.WARNING,
                "SOA_EXPIRE_LTE_REFRESH",
                f"SOA expire ({soa.expire}s) should be larger than refresh ({soa.refresh}s)",
                line=soa_records[0].line_number if soa_records else 0,
            )

        # Minimum (negative caching TTL) should be reasonable
        if soa.minimum < 60 or soa.minimum > 86400:
            self._add(
                Severity.WARNING,
                "SOA_MINIMUM_RANGE",
                f"SOA minimum {soa.minimum}s is outside recommended range (60-86400)",
                line=soa_records[0].line_number if soa_records else 0,
            )

    def _check_ns_records(self) -> None:
        """Validate NS records."""
        ns_records = self.zone.get_records(RecordType.NS)

        if not ns_records:
            self._add(Severity.ERROR, "MISSING_NS", "Zone has no NS records")
            return

        # Should have at least 2 NS records for redundancy
        if len(ns_records) < 2:
            self._add(Severity.WARNING, "NS_REDUNDANCY", "Zone has only 1 NS record (recommend at least 2)")

        # Check for NS pointing to CNAME (forbidden)
        cname_targets = self.zone.get_cname_targets()
        for ns in ns_records:
            target = ns.rdata_parts.get("target", ns.rdata).rstrip(".")
            if target in cname_targets:
                self._add(
                    Severity.ERROR,
                    "NS_CNAME",
                    f"NS record {ns.rdata} points to a CNAME (forbidden by RFC 1034)",
                    line=ns.line_number,
                    name=ns.name,
                )

    def _check_duplicate_records(self) -> None:
        """Check for duplicate records (same name, type, and rdata)."""
        seen: dict[tuple, DNSRecord] = {}
        for record in self.zone.records:
            key = (record.name, record.record_type, record.rdata)
            if key in seen:
                # Allow multiple MX/SRV (different priorities) and NS (different targets)
                if record.record_type in (RecordType.MX, RecordType.SRV, RecordType.NS, RecordType.TXT):
                    continue
                self._add(
                    Severity.WARNING,
                    "DUPLICATE_RECORD",
                    f"Duplicate {record.record_type.value} record: {record.rdata}",
                    line=record.line_number,
                    name=record.name,
                )
            else:
                seen[key] = record

    def _check_record_names(self) -> None:
        """Validate record names."""
        for record in self.zone.records:
            name = record.name
            if not name:
                continue

            # Check for invalid characters
            if not re.match(r"^[a-zA-Z0-9._@*-]+$", name.replace(".", "")):
                self._add(
                    Severity.WARNING,
                    "INVALID_NAME_CHARS",
                    f"Record name '{name}' contains unusual characters",
                    line=record.line_number,
                    name=name,
                )

            # Check label length (max 63 chars)
            labels = name.split(".")
            for label in labels:
                if len(label) > 63:
                    self._add(
                        Severity.ERROR,
                        "LABEL_TOO_LONG",
                        f"DNS label '{label}' exceeds 63 character limit ({len(label)} chars)",
                        line=record.line_number,
                        name=name,
                    )
                    break

            # Total name length (max 253 chars)
            if len(name) > 253:
                self._add(
                    Severity.ERROR,
                    "NAME_TOO_LONG",
                    f"Record name exceeds 253 character limit ({len(name)} chars)",
                    line=record.line_number,
                    name=name,
                )

    def _check_a_records(self) -> None:
        """Validate A records."""
        for record in self.zone.get_records(RecordType.A):
            address = record.rdata_parts.get("address", record.rdata)
            try:
                addr = ipaddress.IPv4Address(address)
                # Check for special addresses (most specific first)
                if addr.is_loopback:
                    self._add(
                        Severity.WARNING,
                        "A_LOOPBACK",
                        f"A record points to loopback: {address}",
                        line=record.line_number,
                        name=record.name,
                    )
                elif addr.is_multicast:
                    self._add(
                        Severity.ERROR,
                        "A_MULTICAST",
                        f"A record points to multicast address: {address}",
                        line=record.line_number,
                        name=record.name,
                    )
                elif addr.is_private:
                    self._add(
                        Severity.INFO,
                        "A_PRIVATE_ADDRESS",
                        f"A record points to private IP: {address}",
                        line=record.line_number,
                        name=record.name,
                    )
            except ValueError:
                self._add(
                    Severity.ERROR,
                    "A_INVALID_ADDRESS",
                    f"Invalid IPv4 address: {address}",
                    line=record.line_number,
                    name=record.name,
                )

    def _check_aaaa_records(self) -> None:
        """Validate AAAA records."""
        for record in self.zone.get_records(RecordType.AAAA):
            address = record.rdata_parts.get("address", record.rdata)
            try:
                addr = ipaddress.IPv6Address(address)
                if addr.is_loopback:
                    self._add(
                        Severity.WARNING,
                        "AAAA_LOOPBACK",
                        f"AAAA record points to loopback: {address}",
                        line=record.line_number,
                        name=record.name,
                    )
                elif addr.is_multicast:
                    self._add(
                        Severity.ERROR,
                        "AAAA_MULTICAST",
                        f"AAAA record points to multicast address: {address}",
                        line=record.line_number,
                        name=record.name,
                    )
            except ValueError:
                self._add(
                    Severity.ERROR,
                    "AAAA_INVALID_ADDRESS",
                    f"Invalid IPv6 address: {address}",
                    line=record.line_number,
                    name=record.name,
                )

    def _check_cname_records(self) -> None:
        """Validate CNAME records."""
        for record in self.zone.get_records(RecordType.CNAME):
            target = record.rdata_parts.get("target", record.rdata)

            # CNAME target should not be empty
            if not target or target == ".":
                self._add(
                    Severity.ERROR,
                    "CNAME_EMPTY_TARGET",
                    "CNAME record has empty target",
                    line=record.line_number,
                    name=record.name,
                )
                continue

            # CNAME target should not point to self
            if target.rstrip(".") == record.name.rstrip("."):
                self._add(
                    Severity.ERROR,
                    "CNAME_SELF_LOOP",
                    "CNAME record points to itself",
                    line=record.line_number,
                    name=record.name,
                )

    def _check_mx_records(self) -> None:
        """Validate MX records."""
        for record in self.zone.get_records(RecordType.MX):
            priority = record.rdata_parts.get("priority", 0)
            exchange = record.rdata_parts.get("exchange", record.rdata)

            # Priority should be 0-65535
            if priority < 0 or priority > 65535:
                self._add(
                    Severity.ERROR,
                    "MX_PRIORITY_RANGE",
                    f"MX priority {priority} is out of range (0-65535)",
                    line=record.line_number,
                    name=record.name,
                )

            # Exchange should not be empty
            if not exchange or exchange == ".":
                self._add(
                    Severity.ERROR,
                    "MX_EMPTY_EXCHANGE",
                    "MX record has empty exchange",
                    line=record.line_number,
                    name=record.name,
                )

            # Exchange should not point to CNAME (RFC 2181)
            cname_targets = self.zone.get_cname_targets()
            exchange_base = exchange.rstrip(".")
            if exchange_base in cname_targets:
                self._add(
                    Severity.WARNING,
                    "MX_CNAME",
                    f"MX exchange '{exchange}' points to a CNAME (RFC 2181 recommends against this)",
                    line=record.line_number,
                    name=record.name,
                )

    def _check_srv_records(self) -> None:
        """Validate SRV records."""
        for record in self.zone.get_records(RecordType.SRV):
            priority = record.rdata_parts.get("priority", 0)
            weight = record.rdata_parts.get("weight", 0)
            port = record.rdata_parts.get("port", 0)
            target = record.rdata_parts.get("target", "")

            if priority < 0 or priority > 65535:
                self._add(
                    Severity.ERROR,
                    "SRV_PRIORITY_RANGE",
                    f"SRV priority {priority} is out of range",
                    line=record.line_number,
                    name=record.name,
                )

            if weight < 0 or weight > 65535:
                self._add(
                    Severity.ERROR,
                    "SRV_WEIGHT_RANGE",
                    f"SRV weight {weight} is out of range",
                    line=record.line_number,
                    name=record.name,
                )

            if port < 0 or port > 65535:
                self._add(
                    Severity.ERROR,
                    "SRV_PORT_RANGE",
                    f"SRV port {port} is out of range",
                    line=record.line_number,
                    name=record.name,
                )

            if not target or target == ".":
                self._add(
                    Severity.WARNING,
                    "SRV_EMPTY_TARGET",
                    "SRV record has empty target (service is unavailable)",
                    line=record.line_number,
                    name=record.name,
                )

    def _check_txt_records(self) -> None:
        """Validate TXT records."""
        for record in self.zone.get_records(RecordType.TXT):
            txtdata = record.rdata_parts.get("txtdata", record.rdata)

            # TXT records should not exceed 255 bytes per string
            if len(txtdata) > 255:
                self._add(
                    Severity.INFO,
                    "TXT_LONG_STRING",
                    f"TXT record data is {len(txtdata)} chars (may need multi-string format)",
                    line=record.line_number,
                    name=record.name,
                )

    def _check_caa_records(self) -> None:
        """Validate CAA records."""
        valid_tags = {"issue", "issuewild", "iodef"}
        for record in self.zone.get_records(RecordType.CAA):
            tag = record.rdata_parts.get("tag", "")
            flags = record.rdata_parts.get("flags", 0)

            if tag not in valid_tags:
                self._add(
                    Severity.WARNING,
                    "CAA_UNKNOWN_TAG",
                    f"CAA record has unknown tag '{tag}' (known: issue, issuewild, iodef)",
                    line=record.line_number,
                    name=record.name,
                )

            if flags not in (0, 128):
                self._add(
                    Severity.INFO,
                    "CAA_UNUSUAL_FLAGS",
                    f"CAA record has unusual flags value {flags} (typically 0 or 128)",
                    line=record.line_number,
                    name=record.name,
                )

    def _check_sshfp_records(self) -> None:
        """Validate SSHFP records."""
        valid_algorithms = {1, 2, 3, 4, 6, 8}
        valid_fingerprint_types = {1, 2}
        for record in self.zone.get_records(RecordType.SSHFP):
            algo = record.rdata_parts.get("algorithm", 0)
            ftype = record.rdata_parts.get("fingerprint_type", 0)
            fp = record.rdata_parts.get("fingerprint", "")

            if algo not in valid_algorithms:
                self._add(
                    Severity.WARNING,
                    "SSHFP_UNKNOWN_ALGO",
                    f"SSHFP has unknown algorithm {algo}",
                    line=record.line_number,
                    name=record.name,
                )

            if ftype not in valid_fingerprint_types:
                self._add(
                    Severity.WARNING,
                    "SSHFP_UNKNOWN_FPTYPE",
                    f"SSHFP has unknown fingerprint type {ftype}",
                    line=record.line_number,
                    name=record.name,
                )

            if not fp:
                self._add(
                    Severity.ERROR,
                    "SSHFP_EMPTY_FINGERPRINT",
                    "SSHFP has empty fingerprint",
                    line=record.line_number,
                    name=record.name,
                )

    def _check_tlsa_records(self) -> None:
        """Validate TLSA records."""
        for record in self.zone.get_records(RecordType.TLSA):
            cert_usage = record.rdata_parts.get("cert_usage", 0)
            selector = record.rdata_parts.get("selector", 0)
            matching_type = record.rdata_parts.get("matching_type", 0)

            if cert_usage not in (0, 1, 2, 3):
                self._add(
                    Severity.WARNING,
                    "TLSA_INVALID_CERT_USAGE",
                    f"TLSA has invalid cert usage {cert_usage} (valid: 0-3)",
                    line=record.line_number,
                    name=record.name,
                )

            if selector not in (0, 1):
                self._add(
                    Severity.WARNING,
                    "TLSA_INVALID_SELECTOR",
                    f"TLSA has invalid selector {selector} (valid: 0-1)",
                    line=record.line_number,
                    name=record.name,
                )

            if matching_type not in (0, 1, 2):
                self._add(
                    Severity.WARNING,
                    "TLSA_INVALID_MATCHING_TYPE",
                    f"TLSA has invalid matching type {matching_type} (valid: 0-2)",
                    line=record.line_number,
                    name=record.name,
                )

    def _check_ttl_values(self) -> None:
        """Check TTL values are reasonable."""
        for record in self.zone.records:
            if record.ttl is not None:
                if record.ttl < 0:
                    self._add(
                        Severity.ERROR,
                        "TTL_NEGATIVE",
                        f"Negative TTL value: {record.ttl}",
                        line=record.line_number,
                        name=record.name,
                    )
                elif record.ttl > 604800:  # 1 week
                    self._add(
                        Severity.INFO,
                        "TTL_VERY_HIGH",
                        f"Very high TTL: {record.ttl}s ({record.ttl // 86400} days)",
                        line=record.line_number,
                        name=record.name,
                    )

    def _check_cname_coexistence(self) -> None:
        """Check that CNAME records don't coexist with other types (RFC 1034)."""
        cname_names = set()
        for record in self.zone.records:
            if record.record_type == RecordType.CNAME:
                cname_names.add(record.name)

        for record in self.zone.records:
            if record.record_type != RecordType.CNAME and record.name in cname_names:
                self._add(
                    Severity.ERROR,
                    "CNAME_COEXIST",
                    f"CNAME record cannot coexist with {record.record_type.value} at '{record.name}'",
                    line=record.line_number,
                    name=record.name,
                )

    def _check_wildcard_records(self) -> None:
        """Check wildcard record usage."""
        for record in self.zone.records:
            if record.name.startswith("*."):
                if record.record_type == RecordType.CNAME:
                    self._add(
                        Severity.WARNING,
                        "WILDCARD_CNAME",
                        "Wildcard CNAME records are unusual and may cause issues",
                        line=record.line_number,
                        name=record.name,
                    )
                elif record.record_type == RecordType.NS:
                    self._add(
                        Severity.WARNING,
                        "WILDCARD_NS",
                        "Wildcard NS records are not recommended",
                        line=record.line_number,
                        name=record.name,
                    )

    def _check_delegations(self) -> None:
        """Check for delegation points (subdomain NS without SOA)."""
        subdomain_ns: dict[str, list[DNSRecord]] = {}
        for record in self.zone.records:
            if record.record_type == RecordType.NS and record.name != self.zone.origin:
                if record.name not in subdomain_ns:
                    subdomain_ns[record.name] = []
                subdomain_ns[record.name].append(record)

        for name, ns_records in subdomain_ns.items():
            # Check if there's a SOA for this subdomain
            soa_records = [r for r in self.zone.records if r.record_type == RecordType.SOA and r.name == name]
            if not soa_records:
                self._add(
                    Severity.INFO,
                    "DELEGATION_NO_SOA",
                    f"Subdomain '{name}' has NS records but no SOA (delegation)",
                    line=ns_records[0].line_number,
                    name=name,
                )


def validate_zone(zone: ZoneFile) -> list[Issue]:
    """Validate a zone file and return list of issues."""
    validator = ZoneValidator(zone)
    return validator.validate()
