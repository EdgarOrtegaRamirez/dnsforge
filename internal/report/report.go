package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/EdgarOrtegaRamirez/dnsforge/internal/benchmark"
	"github.com/EdgarOrtegaRamirez/dnsforge/internal/lookup"
	"github.com/EdgarOrtegaRamirez/dnsforge/internal/propagation"
	"github.com/EdgarOrtegaRamirez/dnsforge/internal/security"
)

// Format represents the output format
type Format string

const (
	FormatText   Format = "text"
	FormatJSON   Format = "json"
	FormatCompact Format = "compact"
)

// PrintLookup prints DNS lookup results
func PrintLookup(result *lookup.LookupResult, w io.Writer, format Format) {
	if format == FormatJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(result)
		return
	}

	if format == FormatCompact {
		if !result.Success {
			fmt.Fprintf(w, "%s (%s): %s\n", result.Domain, result.RecordType, result.Error)
			return
		}
		for _, rec := range result.Records {
			fmt.Fprintf(w, "%s %s %s\n", rec.Type, rec.Name, rec.RData)
		}
		return
	}

	fmt.Fprintf(w, "DNS Lookup: %s (%s)\n", result.Domain, result.RecordType)
	fmt.Fprintf(w, "Server: %s\n", result.Server)

	if !result.Success {
		fmt.Fprintf(w, "Error: %s\n", result.Error)
		return
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  Section\tType\tTTL\tData\n")
	fmt.Fprintf(tw, "  -------\t----\t---\t----\n")

	for _, rec := range result.Records {
		fmt.Fprintf(tw, "  %s\t%s\t%ds\t%s\n", rec.Section, rec.Type, rec.TTL, rec.RData)
	}
	tw.Flush()

	fmt.Fprintf(w, "\nAuthoritative: %v | Truncated: %v | Time: %s\n",
		result.Authoritative, result.Truncated, result.Duration.Round(100_000))
}

// PrintAllLookup prints results for all record types
func PrintAllLookup(results map[lookup.RecordType]*lookup.LookupResult, w io.Writer, format Format) {
	if format == FormatJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(results)
		return
	}

	types := []lookup.RecordType{
		lookup.TypeA, lookup.TypeAAAA, lookup.TypeMX, lookup.TypeTXT,
		lookup.TypeCNAME, lookup.TypeNS, lookup.TypeSOA, lookup.TypeSRV, lookup.TypeCAA,
	}

	for _, rt := range types {
		r, ok := results[rt]
		if !ok || !r.Success || len(r.Records) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n--- %s Records ---\n", rt)
		for _, rec := range r.Records {
			fmt.Fprintf(w, "  %s (TTL: %ds)\n", rec.RData, rec.TTL)
		}
	}
}

// PrintPropagation prints propagation check results
func PrintPropagation(report *propagation.PropagationReport, w io.Writer, format Format) {
	if format == FormatJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(report)
		return
	}

	fmt.Fprintf(w, "DNS Propagation: %s (%s)\n", report.Domain, report.RecordType)
	fmt.Fprintf(w, "Resolvers: %d | Consistent: %v | Duration: %s\n\n",
		report.Total, report.Consistent, report.Duration.Round(100_000))

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  Resolver\tRegion\tStatus\tValue\tTime\n")
	fmt.Fprintf(tw, "  --------\t------\t------\t-----\t----\n")

	for _, r := range report.Results {
		status := "✓"
		value := ""
		if !r.Success {
			status = "✗"
			value = r.Error
		} else if len(r.Records) > 0 {
			value = r.Records[0].RData
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
			r.Resolver, r.Region, status, truncate(value, 40), r.Duration.Round(100_000))
	}
	tw.Flush()

	if !report.Consistent {
		fmt.Fprintf(w, "\n⚠ Inconsistent! Found %d unique values:\n", len(report.UniqueValues))
		for _, v := range report.UniqueValues {
			fmt.Fprintf(w, "  - %s\n", v)
		}
	} else {
		fmt.Fprintf(w, "\n✓ All resolvers returned consistent results\n")
	}
}

// PrintSecurity prints security analysis results
func PrintSecurity(report *security.SecurityReport, w io.Writer, format Format) {
	if format == FormatJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(report)
		return
	}

	fmt.Fprintf(w, "Email Security Analysis: %s\n", report.Domain)
	fmt.Fprintf(w, "Security Score: %d/%d\n\n", report.Score, report.MaxScore)

	// Score bar
	barLen := 30
	filled := (report.Score * barLen) / report.MaxScore
	fmt.Fprintf(w, "  [")
	for i := 0; i < barLen; i++ {
		if i < filled {
			fmt.Fprintf(w, "█")
		} else {
			fmt.Fprintf(w, "░")
		}
	}
	fmt.Fprintf(w, "] %d%%\n\n", report.Score)

	// SPF
	fmt.Fprintf(w, "SPF:\n")
	if report.SPF != nil && report.SPF.Valid {
		fmt.Fprintf(w, "  ✓ Record found: %s\n", truncate(report.SPF.Record, 60))
		fmt.Fprintf(w, "    Mechanisms: %s\n", strings.Join(report.SPF.Mechanisms, ", "))
		if len(report.SPF.Includes) > 0 {
			fmt.Fprintf(w, "    Includes: %s\n", strings.Join(report.SPF.Includes, ", "))
		}
		for _, w_msg := range report.SPF.Warnings {
			fmt.Fprintf(w, "    ⚠ %s\n", w_msg)
		}
	} else {
		fmt.Fprintf(w, "  ✗ Not found\n")
		for _, e := range report.SPF.Errors {
			fmt.Fprintf(w, "    %s\n", e)
		}
	}

	// DMARC
	fmt.Fprintf(w, "\nDMARC:\n")
	if report.DMARC != nil && report.DMARC.Valid {
		fmt.Fprintf(w, "  ✓ Record found: %s\n", truncate(report.DMARC.Record, 60))
		fmt.Fprintf(w, "    Policy: %s | Sub-policy: %s\n", report.DMARC.Policy, report.DMARC.SubPolicy)
		fmt.Fprintf(w, "    Percentage: %d%%\n", report.DMARC.Percentage)
		for _, w_msg := range report.DMARC.Warnings {
			fmt.Fprintf(w, "    ⚠ %s\n", w_msg)
		}
	} else {
		fmt.Fprintf(w, "  ✗ Not found\n")
		for _, e := range report.DMARC.Errors {
			fmt.Fprintf(w, "    %s\n", e)
		}
	}

	// DKIM
	fmt.Fprintf(w, "\nDKIM:\n")
	found := 0
	for _, dkim := range report.DKIM {
		if dkim.Found {
			found++
			status := "✓"
			if !dkim.Valid {
				status = "⚠"
			}
			fmt.Fprintf(w, "  %s %s._domainkey.%s\n", status, dkim.selector, report.Domain)
		}
	}
	if found == 0 {
		fmt.Fprintf(w, "  No common DKIM selectors found\n")
	} else {
		fmt.Fprintf(w, "  Found %d selector(s)\n", found)
	}
}

// PrintBenchmark prints benchmark results
func PrintBenchmark(report *benchmark.BenchmarkReport, w io.Writer, format Format) {
	if format == FormatJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(report)
		return
	}

	fmt.Fprintf(w, "DNS Benchmark: %s (%d queries per resolver)\n", report.Domain, report.Queries)
	fmt.Fprintf(w, "Duration: %s | Best: %s | Worst: %s\n\n",
		report.Duration.Round(100_000), report.Best, report.Worst)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  Resolver\tAvg\tMin\tP50\tP95\tP99\tMax\tOK/Fail\n")
	fmt.Fprintf(tw, "  --------\t---\t---\t---\t---\t---\t---\t-------\n")

	for _, r := range report.Results {
		fmt.Fprintf(tw, "  %s\t%.1fms\t%.1fms\t%.1fms\t%.1fms\t%.1fms\t%.1fms\t%d/%d\n",
			r.Name, r.AverageMs, r.MinMs, r.P50Ms, r.P95Ms, r.P99Ms, r.MaxMs,
			r.Successes, r.Failures)
	}
	tw.Flush()
}

// truncate truncates a string to maxLen
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
