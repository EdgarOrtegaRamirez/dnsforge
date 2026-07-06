package benchmark

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/EdgarOrtegaRamirez/dnsforge/internal/lookup"
)

// BenchmarkResult stores results for a single resolver
type BenchmarkResult struct {
	Name       string        `json:"name"`
	Address    string        `json:"address"`
	AverageMs  float64       `json:"average_ms"`
	MinMs      float64       `json:"min_ms"`
	MaxMs      float64       `json:"max_ms"`
	P50Ms      float64       `json:"p50_ms"`
	P95Ms      float64       `json:"p95_ms"`
	P99Ms      float64       `json:"p99_ms"`
	Successes  int           `json:"successes"`
	Failures   int           `json:"failures"`
	TotalTime  time.Duration `json:"total_time"`
	Latencies  []time.Duration `json:"-"`
}

// BenchmarkReport contains the full benchmark results
type BenchmarkReport struct {
	Domain     string              `json:"domain"`
	Queries    int                 `json:"queries"`
	Results    []BenchmarkResult   `json:"results"`
	Duration   time.Duration       `json:"duration"`
	Best       string              `json:"best"`
	Worst      string              `json:"worst"`
}

// RunBenchmark benchmarks DNS resolution across multiple resolvers
func RunBenchmark(domain string, recordType lookup.RecordType, resolvers []struct{ Name, Address string }, queries int) *BenchmarkReport {
	if queries <= 0 {
		queries = 10
	}
	if len(resolvers) == 0 {
		resolvers = defaultResolvers()
	}

	report := &BenchmarkReport{
		Domain:  domain,
		Queries: queries,
	}

	start := time.Now()

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, resolver := range resolvers {
		wg.Add(1)
		go func(name, address string) {
			defer wg.Done()

			br := BenchmarkResult{
				Name:    name,
				Address: address,
				Latencies: make([]time.Duration, 0, queries),
			}

			r := lookup.NewResolver(address, 5*time.Second, 1)

			for i := 0; i < queries; i++ {
				result := r.Lookup(domain, recordType)
				mu.Lock()
				br.Latencies = append(br.Latencies, result.Duration)
				if result.Success {
					br.Successes++
				} else {
					br.Failures++
				}
				mu.Unlock()
			}

			// Calculate statistics
			if len(br.Latencies) > 0 {
				br.TotalTime = 0
				for _, l := range br.Latencies {
					br.TotalTime += l
				}
				br.AverageMs = float64(br.TotalTime.Microseconds()) / float64(len(br.Latencies)) / 1000.0

				sorted := make([]time.Duration, len(br.Latencies))
				copy(sorted, br.Latencies)
				sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

				br.MinMs = float64(sorted[0].Microseconds()) / 1000.0
				br.MaxMs = float64(sorted[len(sorted)-1].Microseconds()) / 1000.0
				br.P50Ms = percentile(sorted, 50)
				br.P95Ms = percentile(sorted, 95)
				br.P99Ms = percentile(sorted, 99)
			}

			mu.Lock()
			report.Results = append(report.Results, br)
			mu.Unlock()
		}(resolver.Name, resolver.Address)
	}

	wg.Wait()
	report.Duration = time.Since(start)

	// Find best and worst
	if len(report.Results) > 0 {
		sort.Slice(report.Results, func(i, j int) bool {
			return report.Results[i].AverageMs < report.Results[j].AverageMs
		})
		report.Best = report.Results[0].Name
		report.Worst = report.Results[len(report.Results)-1].Name
	}

	return report
}

// percentile calculates the p-th percentile from sorted data
func percentile(sorted []time.Duration, p int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := (p * (len(sorted) - 1)) / 100
	return float64(sorted[idx].Microseconds()) / 1000.0
}

// defaultResolvers returns a set of common DNS resolvers for benchmarking
func defaultResolvers() []struct{ Name, Address string } {
	return []struct{ Name, Address string }{
		{"Google", "8.8.8.8"},
		{"Cloudflare", "1.1.1.1"},
		{"Quad9", "9.9.9.9"},
		{"OpenDNS", "208.67.222.222"},
		{"AdGuard", "94.140.14.14"},
		{"Level3", "4.2.2.1"},
	}
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
