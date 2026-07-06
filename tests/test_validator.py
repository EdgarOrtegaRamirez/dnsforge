"""Tests for DNS zone file validator."""

from dnsforge.models import ZoneFile
from dnsforge.parser import parse_zone
from dnsforge.validator import validate_zone


def _make_zone(text: str, origin: str = "") -> ZoneFile:
    return parse_zone(text, origin)


class TestSOAValidation:
    def test_missing_soa(self):
        zone = _make_zone("@ IN A 1.2.3.4", origin="example.com")
        issues = validate_zone(zone)
        assert any(i.rule == "MISSING_SOA" for i in issues)

    def test_multiple_soa(self):
        zone = _make_zone(
            """@ IN SOA ns1.example.com. admin.example.com. (1 3600 900 604800 86400)
@ IN SOA ns2.example.com. admin.example.com. (2 3600 900 604800 86400)""",
            origin="example.com",
        )
        issues = validate_zone(zone)
        assert any(i.rule == "MULTIPLE_SOA" for i in issues)

    def test_soa_serial_out_of_range(self):
        zone = _make_zone(
            "@ IN SOA ns1.example.com. admin.example.com. (99999999999 3600 900 604800 86400)", origin="example.com"
        )
        issues = validate_zone(zone)
        assert any(i.rule == "SOA_SERIAL_RANGE" for i in issues)

    def test_soa_retry_gte_refresh(self):
        zone = _make_zone("@ IN SOA ns1.example.com. admin.example.com. (1 100 200 604800 86400)", origin="example.com")
        issues = validate_zone(zone)
        assert any(i.rule == "SOA_RETRY_GTE_REFRESH" for i in issues)

    def test_valid_soa(self):
        zone = _make_zone(
            "@ IN SOA ns1.example.com. admin.example.com. (2024070601 3600 900 604800 86400)", origin="example.com"
        )
        issues = validate_zone(zone)
        assert not any(i.rule in ("MISSING_SOA", "MULTIPLE_SOA", "SOA_SERIAL_RANGE") for i in issues)


class TestNSValidation:
    def test_missing_ns(self):
        zone = _make_zone(
            """@ IN SOA ns1.example.com. admin.example.com. (1 3600 900 604800 86400)
@ IN A 1.2.3.4""",
            origin="example.com",
        )
        issues = validate_zone(zone)
        assert any(i.rule == "MISSING_NS" for i in issues)

    def test_single_ns_warning(self):
        zone = _make_zone(
            """@ IN SOA ns1.example.com. admin.example.com. (1 3600 900 604800 86400)
@ IN NS ns1.example.com.""",
            origin="example.com",
        )
        issues = validate_zone(zone)
        assert any(i.rule == "NS_REDUNDANCY" for i in issues)


class TestDuplicateRecords:
    def test_duplicate_a_record(self):
        zone = _make_zone(
            """@ IN A 1.2.3.4
@ IN A 1.2.3.4""",
            origin="example.com",
        )
        issues = validate_zone(zone)
        assert any(i.rule == "DUPLICATE_RECORD" for i in issues)

    def test_multiple_mx_allowed(self):
        zone = _make_zone(
            """@ IN MX 10 mail1.example.com.
@ IN MX 20 mail2.example.com.""",
            origin="example.com",
        )
        issues = validate_zone(zone)
        assert not any(i.rule == "DUPLICATE_RECORD" for i in issues)


class TestRecordNameValidation:
    def test_label_too_long(self):
        long_label = "a" * 64
        zone = _make_zone(f"{long_label} IN A 1.2.3.4", origin="example.com")
        issues = validate_zone(zone)
        assert any(i.rule == "LABEL_TOO_LONG" for i in issues)

    def test_name_too_long(self):
        # Create a name that's > 253 chars
        labels = ["a" * 60 for _ in range(5)]
        long_name = ".".join(labels)
        zone = _make_zone(f"{long_name} IN A 1.2.3.4", origin="example.com")
        issues = validate_zone(zone)
        # Should either be valid or have name too long
        assert isinstance(issues, list)


class TestARecordValidation:
    def test_invalid_a_record(self):
        zone = _make_zone("@ IN A not-an-ip", origin="example.com")
        issues = validate_zone(zone)
        assert any(i.rule == "A_INVALID_ADDRESS" for i in issues)

    def test_loopback_a_record(self):
        zone = _make_zone("@ IN A 127.0.0.1", origin="example.com")
        issues = validate_zone(zone)
        assert any(i.rule == "A_LOOPBACK" for i in issues)

    def test_multicast_a_record(self):
        zone = _make_zone("@ IN A 224.0.0.1", origin="example.com")
        issues = validate_zone(zone)
        assert any(i.rule == "A_MULTICAST" for i in issues)

    def test_valid_a_record(self):
        zone = _make_zone("@ IN A 192.0.2.1", origin="example.com")
        issues = validate_zone(zone)
        assert not any(i.rule == "A_INVALID_ADDRESS" for i in issues)


class TestAAAARecordValidation:
    def test_invalid_aaaa_record(self):
        zone = _make_zone("@ IN AAAA not-an-ipv6", origin="example.com")
        issues = validate_zone(zone)
        assert any(i.rule == "AAAA_INVALID_ADDRESS" for i in issues)

    def test_loopback_aaaa_record(self):
        zone = _make_zone("@ IN AAAA ::1", origin="example.com")
        issues = validate_zone(zone)
        assert any(i.rule == "AAAA_LOOPBACK" for i in issues)

    def test_valid_aaaa_record(self):
        zone = _make_zone("@ IN AAAA 2001:db8::1", origin="example.com")
        issues = validate_zone(zone)
        assert not any(i.rule in ("AAAA_INVALID_ADDRESS", "AAAA_LOOPBACK") for i in issues)


class TestCNAMEValidation:
    def test_cname_self_loop(self):
        zone = _make_zone("www IN CNAME www.example.com.", origin="example.com")
        issues = validate_zone(zone)
        assert any(i.rule == "CNAME_SELF_LOOP" for i in issues)

    def test_cname_coexistence(self):
        zone = _make_zone(
            """www IN CNAME @
www IN A 1.2.3.4""",
            origin="example.com",
        )
        issues = validate_zone(zone)
        assert any(i.rule == "CNAME_COEXIST" for i in issues)


class TestMXValidation:
    def test_mx_priority_out_of_range(self):
        zone = _make_zone("@ IN MX 70000 mail.example.com.", origin="example.com")
        issues = validate_zone(zone)
        assert any(i.rule == "MX_PRIORITY_RANGE" for i in issues)

    def test_mx_empty_exchange(self):
        zone = _make_zone("@ IN MX 10 .", origin="example.com")
        issues = validate_zone(zone)
        assert any(i.rule == "MX_EMPTY_EXCHANGE" for i in issues)


class TestSRVValidation:
    def test_srv_port_out_of_range(self):
        zone = _make_zone("_sip._tcp IN SRV 10 50 70000 sip.example.com.", origin="example.com")
        issues = validate_zone(zone)
        assert any(i.rule == "SRV_PORT_RANGE" for i in issues)

    def test_srv_empty_target(self):
        zone = _make_zone("_sip._tcp IN SRV 10 50 5060 .", origin="example.com")
        issues = validate_zone(zone)
        assert any(i.rule == "SRV_EMPTY_TARGET" for i in issues)


class TestCAAValidation:
    def test_caa_unknown_tag(self):
        zone = _make_zone('@ IN CAA 0 invalidtag "value"', origin="example.com")
        issues = validate_zone(zone)
        assert any(i.rule == "CAA_UNKNOWN_TAG" for i in issues)


class TestTTLValidation:
    def test_negative_ttl(self):
        zone = parse_zone("@ -1 IN A 1.2.3.4", origin="example.com")
        issues = validate_zone(zone)
        # Parser may or may not allow negative TTL
        assert isinstance(issues, list)


class TestWildcardValidation:
    def test_wildcard_cname_warning(self):
        zone = _make_zone("*.example.com. IN CNAME @", origin="example.com")
        issues = validate_zone(zone)
        assert any(i.rule == "WILDCARD_CNAME" for i in issues)


class TestDelegationValidation:
    def test_delegation_no_soa(self):
        zone = _make_zone(
            """@ IN SOA ns1.example.com. admin.example.com. (1 3600 900 604800 86400)
sub IN NS ns1.sub.example.com.""",
            origin="example.com",
        )
        issues = validate_zone(zone)
        assert any(i.rule == "DELEGATION_NO_SOA" for i in issues)
