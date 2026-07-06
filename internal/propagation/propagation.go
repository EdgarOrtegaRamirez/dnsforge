package propagation

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/EdgarOrtegaRamirez/dnsforge/internal/lookup"
)

// PublicDNS resolvers for propagation checking
var PublicDNS = []struct {
	Name    string
	Address string
	Region  string
}{
	{"Google", "8.8.8.8", "Global"},
	{"Google-2", "8.8.4.4", "Global"},
	{"Cloudflare", "1.1.1.1", "Global"},
	{"Cloudflare-2", "1.0.0.1", "Global"},
	{"Quad9", "9.9.9.9", "Global"},
	{"Quad9-2", "149.112.112.112", "Global"},
	{"OpenDNS", "208.67.222.222", "Global"},
	{"OpenDNS-2", "208.67.220.220", "Global"},
	{"AdGuard", "94.140.14.14", "EU"},
	{"AdGuard-2", "94.140.15.15", "EU"},
	{"NextDNS", "45.90.28.0", "EU"},
	{"NextDNS-2", "45.90.30.0", "EU"},
	{"Level3", "4.2.2.1", "US"},
	{"Level3-2", "4.2.2.2", "US"},
	{"Verisign", "64.6.64.6", "US"},
}

// PropagationResult shows the result from a single resolver
type PropagationResult struct {
	Resolver  string        `json:"resolver"`
	Address   string        `json:"address"`
	Region    string        `json:"region"`
	Records   []lookup.Record `json:"records"`
	Duration  time.Duration `json:"duration"`
	Success   bool          `json:"success"`
	Error     string        `json:"error,omitempty"`
	Matched   bool          `json:"matched"`
}

// PropagationReport contains the full propagation check results
type PropagationReport struct {
	Domain      string              `json:"domain"`
	RecordType  string              `json:"record_type"`
	Results     []PropagationResult `json:"results"`
	Total       int                 `json:"total"`
	Successful  int                 `json:"successful"`
	Failed      int                 `json:"failed"`
	Consistent  bool                `json:"consistent"`
	Duration    time.Duration       `json:"duration"`
	UniqueValues []string           `json:"unique_values"`
}

// CheckPropagation checks DNS propagation across multiple public resolvers
func CheckPropagation(domain string, recordType lookup.RecordType, customResolvers []struct{ Name, Address, Region string }) *PropagationReport {
	resolvers := customResolvers
	if len(resolvers) == 0 {
		resolvers = PublicDNS
	}

	report := &PropagationReport{
		Domain:     lookup.NormalizeDomain(domain),
		RecordType: string(recordType),
		Total:      len(resolvers),
	}

	start := time.Now()

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, resolver := range resolvers {
		wg.Add(1)
		go func(name, address, region string) {
			defer wg.Done()

			r := lookup.NewResolver(address, 3*time.Second, 1)
			result := r.Lookup(report.Domain, recordType)

			pr := PropagationResult{
				Resolver: name,
				Address:  address,
				Region:   region,
				Duration: result.Duration,
				Success:  result.Success,
				Records:  result.Records,
			}
			if !result.Success {
				pr.Error = result.Error
			}

			mu.Lock()
			if pr.Success {
				report.Successful++
			} else {
				report.Failed++
			}
			report.Results = append(report.Results, pr)
			mu.Unlock()
		}(resolver.Name, resolver.Address, resolver.Region)
	}

	wg.Wait()
	report.Duration = time.Since(start)

	// Analyze consistency
	report.AnalyzeConsistency()

	return report
}

// AnalyzeConsistency checks if all successful results are consistent
func (pr *PropagationReport) AnalyzeConsistency() {
	uniqueValues := make(map[string]bool)

	for _, r := range pr.Results {
		if !r.Success || len(r.Records) == 0 {
			continue
		}
		for _, rec := range pr.Records {
			val := normalizeRecordValue(rec.RData)
			uniqueValues[val] = true
		}
	}

	for val := range uniqueValues {
		pr.UniqueValues = append(pr.UniqueValues, val)
	}

	pr.Consistent = len(pr.UniqueValues) <= 1
}

// normalizeRecordValue normalizes a record value for comparison
func normalizeRecordValue(val string) string {
	val = strings.ToLower(strings.TrimSpace(val))
	// Remove trailing dot for comparison
	val = strings.TrimSuffix(val, ".")
	return val
}

// GetResolverCount returns how many resolvers to use
func GetResolverCount() int {
	return len(PublicDNS)
}

// FormatDuration formats a duration for display
func FormatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.1fµs", float64(d.Microseconds()))
	}
	if d < time.Second {
		return fmt.Sprintf("%.1fms", float64(d.Nanoseconds())/1e6)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}
