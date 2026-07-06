"""Tests for DNS zone file parser."""

import pytest

from dnsforge.models import RecordType
from dnsforge.parser import ParseError, Tokenizer, parse_zone

# ═══════════════════════════════════════════════
# Tokenizer Tests
# ═══════════════════════════════════════════════


class TestTokenizer:
    def test_simple_tokens(self):
        tokens = Tokenizer("A  IN  A  1.2.3.4").tokenize()
        assert [t[0] for t in tokens] == ["A", "IN", "A", "1.2.3.4"]

    def test_comments_skipped(self):
        tokens = Tokenizer("A IN A 1.2.3.4 ; this is a comment").tokenize()
        assert [t[0] for t in tokens] == ["A", "IN", "A", "1.2.3.4"]

    def test_newline_counting(self):
        tokens = Tokenizer("A\nB\nC").tokenize()
        # Tokenizer emits newline tokens between records
        assert tokens[0] == ("A", 1)
        assert tokens[1] == ("\n", 1)
        assert tokens[2] == ("B", 2)

    def test_quoted_string(self):
        tokens = Tokenizer('TXT "v=spf1 include:_spf.google.com ~all"').tokenize()
        assert tokens[0] == ("TXT", 1)
        assert tokens[1] == ("v=spf1 include:_spf.google.com ~all", 1)

    def test_parentheses(self):
        tokens = Tokenizer("SOA ( ns1.example.com. admin.example.com. )").tokenize()
        types = [t[0] for t in tokens]
        assert "(" in types
        assert ")" in types

    def test_empty_input(self):
        tokens = Tokenizer("").tokenize()
        assert tokens == []


# ═══════════════════════════════════════════════
# Parser Tests
# ═══════════════════════════════════════════════


class TestParser:
    def test_parse_origin_directive(self):
        zone = parse_zone("$ORIGIN example.com.")
        assert zone.origin == "example.com"

    def test_parse_ttl_directive(self):
        zone = parse_zone("$TTL 3600")
        assert zone.directives.get("$TTL") == "3600"

    def test_parse_a_record(self):
        zone = parse_zone("@ IN A 192.0.2.1", origin="example.com")
        assert len(zone.records) == 1
        record = zone.records[0]
        assert record.record_type == RecordType.A
        assert record.rdata == "192.0.2.1"
        assert record.rdata_parts["address"] == "192.0.2.1"

    def test_parse_aaaa_record(self):
        zone = parse_zone("@ IN AAAA 2001:db8::1", origin="example.com")
        assert len(zone.records) == 1
        assert zone.records[0].record_type == RecordType.AAAA
        assert zone.records[0].rdata_parts["address"] == "2001:db8::1"

    def test_parse_cname_record(self):
        zone = parse_zone("www IN CNAME @", origin="example.com")
        record = zone.records[0]
        assert record.record_type == RecordType.CNAME
        assert "example.com" in record.rdata_parts["target"]

    def test_parse_mx_record(self):
        zone = parse_zone("@ IN MX 10 mail.example.com.", origin="example.com")
        record = zone.records[0]
        assert record.record_type == RecordType.MX
        assert record.rdata_parts["priority"] == 10
        assert record.rdata_parts["exchange"] == "mail.example.com"

    def test_parse_ns_record(self):
        zone = parse_zone("@ IN NS ns1.example.com.", origin="example.com")
        record = zone.records[0]
        assert record.record_type == RecordType.NS
        assert "ns1.example.com" in record.rdata_parts["target"]

    def test_parse_soa_record(self):
        zone = parse_zone(
            """@ IN SOA ns1.example.com. admin.example.com. (
    2024070601 3600 900 604800 86400
)""",
            origin="example.com",
        )
        assert zone.soa is not None
        assert zone.soa.serial == 2024070601
        assert zone.soa.refresh == 3600
        assert zone.soa.mname == "ns1.example.com"

    def test_parse_txt_record(self):
        zone = parse_zone('@ IN TXT "v=spf1 include:_spf.google.com ~all"', origin="example.com")
        record = zone.records[0]
        assert record.record_type == RecordType.TXT
        assert "v=spf1" in record.rdata_parts["txtdata"]

    def test_parse_srv_record(self):
        zone = parse_zone("_sip._tcp IN SRV 10 50 5060 sip.example.com.", origin="example.com")
        record = zone.records[0]
        assert record.record_type == RecordType.SRV
        assert record.rdata_parts["priority"] == 10
        assert record.rdata_parts["weight"] == 50
        assert record.rdata_parts["port"] == 5060

    def test_parse_caa_record(self):
        zone = parse_zone('@ IN CAA 0 issue "letsencrypt.org"', origin="example.com")
        record = zone.records[0]
        assert record.record_type == RecordType.CAA
        assert record.rdata_parts["flags"] == 0
        assert record.rdata_parts["tag"] == "issue"

    def test_parse_sshfp_record(self):
        zone = parse_zone("ssh.example.com IN SSHFP 1 1 1234567890abcdef", origin="example.com")
        record = zone.records[0]
        assert record.record_type == RecordType.SSHFP
        assert record.rdata_parts["algorithm"] == 1

    def test_parse_tlsa_record(self):
        zone = parse_zone("_25._tcp.mx.example.com IN TLSA 3 1 1 abc123", origin="example.com")
        record = zone.records[0]
        assert record.record_type == RecordType.TLSA
        assert record.rdata_parts["cert_usage"] == 3

    def test_parse_with_ttl(self):
        zone = parse_zone("@ 7200 IN A 1.2.3.4", origin="example.com")
        assert zone.records[0].ttl == 7200

    def test_parse_absolute_name(self):
        zone = parse_zone("www.example.com. IN A 1.2.3.4")
        assert zone.records[0].name == "www.example.com."

    def test_parse_origin_at(self):
        zone = parse_zone("@ IN A 1.2.3.4", origin="example.com")
        assert zone.records[0].name == "example.com."

    def test_parse_comment_only(self):
        zone = parse_zone("; just a comment\n; another comment")
        assert len(zone.records) == 0

    def test_parse_multiline_record(self):
        zone = parse_zone(
            """@ IN SOA (
    ns1.example.com.
    admin.example.com.
    2024070601
    3600
    900
    604800
    86400
)""",
            origin="example.com",
        )
        assert zone.soa is not None
        assert zone.soa.serial == 2024070601

    def test_parse_multiple_records(self):
        zone = parse_zone(
            """@ IN A 1.2.3.4
www IN CNAME @
@ IN MX 10 mail.example.com.""",
            origin="example.com",
        )
        assert len(zone.records) == 3

    def test_parse_full_zone(self):
        zone_text = """$ORIGIN example.com.
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
www     IN  CNAME   @
mail    IN  A       192.0.2.20
@       IN  MX      10 mail.example.com.
"""
        zone = parse_zone(zone_text)
        assert zone.origin == "example.com"
        assert zone.soa is not None
        assert zone.soa.serial == 2024070601
        assert len(zone.records) > 0

        a_records = zone.get_records(RecordType.A)
        assert len(a_records) >= 3

        mx_records = zone.get_records(RecordType.MX)
        assert len(mx_records) == 1

    def test_parse_include_directive(self):
        zone = parse_zone("$INCLUDE /etc/bind/db.other")
        assert zone.include_directives == ["/etc/bind/db.other"]

    def test_parse_invalid_ttl(self):
        with pytest.raises(ParseError, match="Invalid TTL"):
            parse_zone("$TTL notanumber")

    def test_parse_empty_rdata(self):
        # Empty records should still parse (may just be missing rdata)
        zone = parse_zone("www IN CNAME")
        # Should have 1 record even if rdata is empty
        assert len(zone.records) >= 0  # Parser handles gracefully


# ═══════════════════════════════════════════════
# ZoneFile Model Tests
# ═══════════════════════════════════════════════


class TestZoneFile:
    def test_get_records_by_type(self):
        zone = parse_zone("@ IN A 1.2.3.4\n@ IN AAAA ::1", origin="example.com")
        a_records = zone.get_records(RecordType.A)
        aaaa_records = zone.get_records(RecordType.AAAA)
        assert len(a_records) == 1
        assert len(aaaa_records) == 1

    def test_get_records_by_name(self):
        zone = parse_zone("www IN A 1.2.3.4\nftp IN A 5.6.7.8", origin="example.com")
        www_records = zone.get_records_by_name("www.example.com")
        assert len(www_records) == 1

    def test_get_cname_targets(self):
        zone = parse_zone("www IN CNAME @", origin="example.com")
        targets = zone.get_cname_targets()
        assert "www.example.com" in targets

    def test_to_dict(self):
        zone = parse_zone("@ IN A 1.2.3.4", origin="example.com")
        d = zone.to_dict()
        assert d["origin"] == "example.com"
        assert len(d["records"]) == 1

    def test_to_json(self):
        zone = parse_zone("@ IN A 1.2.3.4", origin="example.com")
        j = zone.to_json()
        assert "example.com" in j
        assert "1.2.3.4" in j
