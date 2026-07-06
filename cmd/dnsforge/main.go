package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/EdgarOrtegaRamirez/dnsforge/internal/benchmark"
	"github.com/EdgarOrtegaRamirez/dnsforge/internal/lookup"
	"github.com/EdgarOrtegaRamirez/dnsforge/internal/propagation"
	"github.com/EdgarOrtegaRamirez/dnsforge/internal/report"
	"github.com/EdgarOrtegaRamirez/dnsforge/internal/security"
	"github.com/spf13/cobra"
)

var version = "0.1.0"

var rootCmd = &cobra.Command{
	Use:   "dnsforge",
	Short: "A comprehensive DNS toolkit for lookups, propagation checks, and security analysis",
	Long: `DNSForge is a fast, comprehensive DNS toolkit that provides:
  - DNS record lookups (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, CAA, PTR)
  - DNS propagation checking across multiple public resolvers
  - Email security analysis (SPF, DMARC, DKIM)
  - DNS resolver benchmarking
  - Multiple output formats (text, JSON, compact)`,
}

func main() {

	var server string
	var outputFormat string
	var timeout int

	rootCmd.PersistentFlags().StringVar(&server, "server", "8.8.8.8", "DNS resolver to use")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "text", "Output format (text, json, compact)")
	rootCmd.PersistentFlags().IntVar(&timeout, "timeout", 5, "Timeout in seconds")

	getFormat := func() report.Format {
		switch strings.ToLower(outputFormat) {
		case "json":
			return report.FormatJSON
		case "compact":
			return report.FormatCompact
		default:
			return report.FormatText
		}
	}

	// Lookup command
	lookupCmd := &cobra.Command{
		Use:   "lookup <domain> [type]",
		Short: "Look up DNS records for a domain",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			recordType := lookup.TypeA

			if len(args) > 1 {
				var err error
				recordType, err = lookup.ParseRecordType(args[1])
				if err != nil {
					return err
				}
			}

			r := lookup.NewResolver(server, parseTimeout(timeout), 2)

			if recordType == lookup.TypeANY {
				results := r.LookupAll(domain)
				report.PrintAllLookup(results, os.Stdout, getFormat())
			} else {
				result := r.Lookup(domain, recordType)
				report.PrintLookup(result, os.Stdout, getFormat())
			}
			return nil
		},
	}

	// Reverse lookup command
	reverseCmd := &cobra.Command{
		Use:   "reverse <ip>",
		Short: "Perform a reverse DNS lookup (PTR record)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := lookup.NewResolver(server, parseTimeout(timeout), 2)
			result := r.ReverseLookup(args[0])
			report.PrintLookup(result, os.Stdout, getFormat())
			return nil
		},
	}

	// Propagation command
	propCmd := &cobra.Command{
		Use:   "propagation <domain> [type]",
		Short: "Check DNS propagation across multiple resolvers",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			recordType := lookup.TypeA

			if len(args) > 1 {
				var err error
				recordType, err = lookup.ParseRecordType(args[1])
				if err != nil {
					return err
				}
			}

			result := propagation.CheckPropagation(domain, recordType, nil)
			report.PrintPropagation(result, os.Stdout, getFormat())
			return nil
		},
	}

	// Security command
	securityCmd := &cobra.Command{
		Use:   "security <domain>",
		Short: "Analyze email security (SPF, DMARC, DKIM)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := lookup.NewResolver(server, parseTimeout(timeout), 2)
			result := security.AnalyzeEmailSecurity(args[0], r)
			report.PrintSecurity(result, os.Stdout, getFormat())
			return nil
		},
	}

	// Benchmark command
	benchCmd := &cobra.Command{
		Use:   "benchmark <domain> [type]",
		Short: "Benchmark DNS resolver performance",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			recordType := lookup.TypeA

			if len(args) > 1 {
				var err error
				recordType, err = lookup.ParseRecordType(args[1])
				if err != nil {
					return err
				}
			}

			queries, _ := cmd.Flags().GetInt("queries")
			result := benchmark.RunBenchmark(domain, recordType, nil, queries)
			report.PrintBenchmark(result, os.Stdout, getFormat())
			return nil
		},
	}
	benchCmd.Flags().IntP("queries", "q", 10, "Number of queries per resolver")

	// Version command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("dnsforge %s\n", version)
		},
	}

	rootCmd.AddCommand(lookupCmd, reverseCmd, propCmd, securityCmd, benchCmd, versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func parseTimeout(seconds int) time.Duration {
	return time.Duration(seconds) * time.Second
}
