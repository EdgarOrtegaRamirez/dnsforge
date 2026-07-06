package lookup

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// RecordType represents a DNS record type
type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeMX    RecordType = "MX"
	TypeTXT   RecordType = "TXT"
	TypeCNAME RecordType = "CNAME"
	TypeNS    RecordType = "NS"
	TypeSOA   RecordType = "SOA"
	TypeSRV   RecordType = "SRV"
	TypeCAA   RecordType = "CAA"
	TypePTR   RecordType = "PTR"
	TypeANY   RecordType = "ANY"
)

// Record represents a single DNS record
type Record struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Class   string `json:"class"`
	TTL     uint32 `json:"ttl"`
	RData   string `json:"rdata"`
	Section string `json:"section"`
}

// LookupResult contains the results of a DNS lookup
type LookupResult struct {
	Domain      string        `json:"domain"`
	RecordType  string        `json:"record_type"`
	Server      string        `json:"server"`
	Records     []Record      `json:"records"`
	Duration    time.Duration `json:"duration"`
	Success     bool          `json:"success"`
	Error       string        `json:"error,omitempty"`
	Cached      bool          `json:"cached"`
	Authoritative bool        `json:"authoritative"`
	RecursionAvailable bool   `json:"recursion_available"`
	Truncated   bool          `json:"truncated"`
}

// Resolver performs DNS lookups
type Resolver struct {
	client   *dns.Client
	server   string
	timeout  time.Duration
	tries    int
}

// NewResolver creates a new DNS resolver
func NewResolver(server string, timeout time.Duration, tries int) *Resolver {
	if server == "" {
		server = "8.8.8.8:53"
	}
	if !strings.Contains(server, ":") {
		server = server + ":53"
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if tries == 0 {
		tries = 2
	}

	return &Resolver{
		client: &dns.Client{
			Timeout: timeout,
		},
		server:  server,
		timeout: timeout,
		tries:   tries,
	}
}

// Lookup performs a DNS lookup for the given domain and record type
func (r *Resolver) Lookup(domain string, recordType RecordType) *LookupResult {
	result := &LookupResult{
		Domain:     domain,
		RecordType: string(recordType),
		Server:     r.server,
	}

	qType := dns.StringToType[string(recordType)]
	if qType == 0 {
		result.Error = fmt.Sprintf("unknown record type: %s", recordType)
		return result
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qType)
	msg.RecursionDesired = true

	start := time.Now()
	resp, _, err := r.client.Exchange(msg, r.server)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Success = true
	result.Authoritative = resp.Authoritative
	result.RecursionAvailable = resp.RecursionAvailable
	result.Truncated = resp.Truncated
	result.Cached = resp.AuthenticatedData

	result.Records = extractRecords(resp)

	return result
}

// LookupAll performs lookups for all common record types
func (r *Resolver) LookupAll(domain string) map[RecordType]*LookupResult {
	types := []RecordType{TypeA, TypeAAAA, TypeMX, TypeTXT, TypeCNAME, TypeNS, TypeSOA, TypeSRV, TypeCAA}
	results := make(map[RecordType]*LookupResult)

	for _, rt := range types {
		results[rt] = r.Lookup(domain, rt)
	}

	return results
}

// ReverseLookup performs a reverse DNS lookup for an IP address
func (r *Resolver) ReverseLookup(ip string) *LookupResult {
	rev, err := dns.ReverseAddr(ip)
	if err != nil {
		return &LookupResult{
			Domain:     ip,
			RecordType: "PTR",
			Server:     r.server,
			Error:      err.Error(),
		}
	}

	// Remove trailing dot
	fqdn := rev
	if len(fqdn) > 0 && fqdn[len(fqdn)-1] == '.' {
		fqdn = fqdn[:len(fqdn)-1]
	}

	return r.Lookup(fqdn, TypePTR)
}

// extractRecords extracts DNS records from a response
func extractRecords(resp *dns.Msg) []Record {
	var records []Record

	for _, rr := range resp.Answer {
		records = append(records, rrToRecord(rr, "answer"))
	}
	for _, rr := range resp.Ns {
		records = append(records, rrToRecord(rr, "authority"))
	}
	for _, rr := range resp.Extra {
		records = append(records, rrToRecord(rr, "additional"))
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Type != records[j].Type {
			return records[i].Type < records[j].Type
		}
		return records[i].Name < records[j].Name
	})

	return records
}

// rrToRecord converts a DNS RR to our Record type
func rrToRecord(rr dns.RR, section string) Record {
	header := rr.Header()
	return Record{
		Name:    strings.TrimSuffix(header.Name, "."),
		Type:    dns.TypeToString[header.Rrtype],
		Class:   dns.ClassToString[header.Class],
		TTL:     header.Ttl,
		RData:   formatRData(rr),
		Section: section,
	}
}

// formatRData formats the RData of a DNS record
func formatRData(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, "."))
	case *dns.TXT:
		return strings.Join(v.Txt, " ")
	case *dns.CNAME:
		return strings.TrimSuffix(v.Target, ".")
	case *dns.NS:
		return strings.TrimSuffix(v.Ns, ".")
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			strings.TrimSuffix(v.Ns, "."),
			strings.TrimSuffix(v.Mbox, "."),
			v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, strings.TrimSuffix(v.Target, "."))
	case *dns.CAA:
		return fmt.Sprintf("%d %s \"%s\"", v.Flag, v.Tag, v.Value)
	case *dns.PTR:
		return strings.TrimSuffix(v.Ptr, ".")
	default:
		return rr.String()
	}
}

// SupportedTypes returns all supported record types
func SupportedTypes() []RecordType {
	return []RecordType{TypeA, TypeAAAA, TypeMX, TypeTXT, TypeCNAME, TypeNS, TypeSOA, TypeSRV, TypeCAA, TypePTR, TypeANY}
}
