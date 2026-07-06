package lookup

import (
	"fmt"
	"net"
	"strings"
)

// ParseRecordType parses a string into a RecordType
func ParseRecordType(s string) (RecordType, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "A", "IPV4":
		return TypeA, nil
	case "AAAA", "IPV6":
		return TypeAAAA, nil
	case "MX", "MAIL":
		return TypeMX, nil
	case "TXT", "TEXT":
		return TypeTXT, nil
	case "CNAME", "CANONICAL":
		return TypeCNAME, nil
	case "NS", "NAMESERVER":
		return TypeNS, nil
	case "SOA", "AUTHORITY":
		return TypeSOA, nil
	case "SRV", "SERVICE":
		return TypeSRV, nil
	case "CAA", "AUTH":
		return TypeCAA, nil
	case "PTR", "REVERSE":
		return TypePTR, nil
	case "ANY", "ALL", "*":
		return TypeANY, nil
	default:
		return "", fmt.Errorf("unsupported record type: %s (supported: %s)", s, strings.Join(getTypeNames(), ", "))
	}
}

func getTypeNames() []string {
	types := SupportedTypes()
	names := make([]string, len(types))
	for i, t := range types {
		names[i] = string(t)
	}
	return names
}

// NormalizeDomain normalizes a domain name
func NormalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

// IsIPAddress checks if a string is an IP address
func IsIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}
