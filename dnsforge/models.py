"""DNS data models — record types, zone structure, validation results."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RecordType(Enum):
    """DNS record types."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"
    SRV = "SRV"
    PTR = "PTR"
    CAA = "CAA"
    TLSA = "TLSA"
    CDS = "CDS"
    CDNSKEY = "CDNSKEY"
    DNSKEY = "DNSKEY"
    DS = "DS"
    NSEC = "NSEC"
    NSEC3 = "NSEC3"
    RRSIG = "RRSIG"
    HTTPS = "HTTPS"
    SVCB = "SVCB"
    OPENPGPKEY = "OPENPGPKEY"
    SSHFP = "SSHFP"
    LOC = "LOC"
    HINFO = "HINFO"
    RP = "RP"
    AFSDB = "AFSDB"
    X25 = "X25"
    ISDN = "ISDN"
    RT = "RT"
    NSAP = "NSAP"
    PX = "PX"
    EUI48 = "EUI48"
    EUI64 = "EUI64"
    Unknown = "Unknown"


class Severity(Enum):
    """Issue severity levels."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class DNSRecord:
    """A single DNS resource record."""

    name: str
    ttl: int | None
    record_class: str
    record_type: RecordType
    rdata: str
    line_number: int = 0
    # Parsed rdata fields
    rdata_parts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ttl": self.ttl,
            "class": self.record_class,
            "type": self.record_type.value,
            "rdata": self.rdata,
            "rdata_parts": self.rdata_parts,
        }


@dataclass
class SOARecord:
    """Parsed SOA record data."""

    mname: str  # primary nameserver
    rname: str  # responsible person email (with dot notation)
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "mname": self.mname,
            "rname": self.rname,
            "serial": self.serial,
            "refresh": self.refresh,
            "retry": self.retry,
            "expire": self.expire,
            "minimum": self.minimum,
        }


@dataclass
class MXRecord:
    """Parsed MX record data."""

    priority: int
    exchange: str

    def to_dict(self) -> dict[str, Any]:
        return {"priority": self.priority, "exchange": self.exchange}


@dataclass
class SRVRecord:
    """Parsed SRV record data."""

    priority: int
    weight: int
    port: int
    target: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "priority": self.priority,
            "weight": self.weight,
            "port": self.port,
            "target": self.target,
        }


@dataclass
class CAARecord:
    """Parsed CAA record data."""

    flags: int
    tag: str
    value: str

    def to_dict(self) -> dict[str, Any]:
        return {"flags": self.flags, "tag": self.tag, "value": self.value}


@dataclass
class SSHFPRecord:
    """Parsed SSHFP record data."""

    algorithm: int
    fingerprint_type: int
    fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "fingerprint_type": self.fingerprint_type,
            "fingerprint": self.fingerprint,
        }


@dataclass
class TLSARecord:
    """Parsed TLSA record data."""

    cert_usage: int
    selector: int
    matching_type: int
    cert_data: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cert_usage": self.cert_usage,
            "selector": self.selector,
            "matching_type": self.matching_type,
            "cert_data": self.cert_data,
        }


@dataclass
class Issue:
    """A validation issue found in the zone file."""

    severity: Severity
    rule: str
    message: str
    line_number: int = 0
    record_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "rule": self.rule,
            "message": self.message,
            "line_number": self.line_number,
            "record_name": self.record_name,
        }


@dataclass
class ZoneStats:
    """Statistics about a parsed zone."""

    total_records: int = 0
    records_by_type: dict[str, int] = field(default_factory=dict)
    unique_names: int = 0
    max_ttl: int = 0
    min_ttl: int = 0
    avg_ttl: float = 0.0
    has_soa: bool = False
    has_ns: bool = False
    cname_targets: dict[str, str] = field(default_factory=dict)
    mx_exchanges: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    delegation_points: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_records": self.total_records,
            "records_by_type": self.records_by_type,
            "unique_names": self.unique_names,
            "max_ttl": self.max_ttl,
            "min_ttl": self.min_ttl,
            "avg_ttl": round(self.avg_ttl, 2),
            "has_soa": self.has_soa,
            "has_ns": self.has_ns,
            "cname_targets": self.cname_targets,
            "mx_exchanges": self.mx_exchanges,
            "ns_records": self.ns_records,
            "delegation_points": self.delegation_points,
        }


@dataclass
class ZoneFile:
    """A parsed DNS zone file."""

    origin: str = ""
    records: list[DNSRecord] = field(default_factory=list)
    soa: SOARecord | None = None
    origin_directive: str = ""
    include_directives: list[str] = field(default_factory=list)
    directives: dict[str, str] = field(default_factory=dict)

    @property
    def record_count(self) -> int:
        return len(self.records)

    def get_records(self, record_type: RecordType) -> list[DNSRecord]:
        return [r for r in self.records if r.record_type == record_type]

    def get_records_by_name(self, name: str) -> list[DNSRecord]:
        normalized = self._normalize_name(name)
        return [r for r in self.records if self._normalize_name(r.name) == normalized]

    def get_cname_targets(self) -> dict[str, str]:
        """Get CNAME -> target mapping."""
        result = {}
        for r in self.records:
            if r.record_type == RecordType.CNAME:
                target = r.rdata_parts.get("target", r.rdata).rstrip(".")
                key = r.name.rstrip(".")
                result[key] = target
        return result

    def get_mx_records(self) -> list[tuple[str, int, str]]:
        """Get (name, priority, exchange) tuples for MX records."""
        result = []
        for r in self.records:
            if r.record_type == RecordType.MX:
                priority = r.rdata_parts.get("priority", 10)
                exchange = r.rdata_parts.get("exchange", r.rdata).rstrip(".")
                result.append((r.name, priority, exchange))
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "origin": self.origin,
            "origin_directive": self.origin_directive,
            "soa": self.soa.to_dict() if self.soa else None,
            "records": [r.to_dict() for r in self.records],
            "include_directives": self.include_directives,
            "directives": self.directives,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @staticmethod
    def _normalize_name(name: str) -> str:
        """Normalize a domain name for comparison."""
        name = name.rstrip(".").lower()
        if not name:
            return name
        return name
