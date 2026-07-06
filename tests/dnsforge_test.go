package main

import (
	"bytes"
	"testing"

	"github.com/EdgarOrtegaRamirez/dnsforge/internal/lookup"
	"github.com/EdgarOrtegaRamirez/dnsforge/internal/report"
)

func TestParseRecordType(t *testing.T) {
	tests := []struct {
		input    string
		expected lookup.RecordType
		wantErr  bool
	}{
		{"A", lookup.TypeA, false},
		{"aaaa", lookup.TypeAAAA, false},
		{"MX", lookup.TypeMX, false},
		{"txt", lookup.TypeTXT, false},
		{"cname", lookup.TypeCNAME, false},
		{"NS", lookup.TypeNS, false},
		{"SOA", lookup.TypeSOA, false},
		{"SRV", lookup.TypeSRV, false},
		{"CAA", lookup.TypeCAA, false},
		{"PTR", lookup.TypePTR, false},
		{"ANY", lookup.TypeANY, false},
		{"*", lookup.TypeANY, false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := lookup.ParseRecordType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordType(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("ParseRecordType(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"Example.COM", "example.com"},
		{"example.com.", "example.com"},
		{"  example.com  ", "example.com"},
		{"Example.Com.", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := lookup.NormalizeDomain(tt.input)
			if got != tt.expected {
				t.Errorf("NormalizeDomain(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"8.8.8.8", true},
		{"2001:4860:4860::8888", true},
		{"example.com", false},
		{"not-an-ip", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := lookup.IsIPAddress(tt.input)
			if got != tt.expected {
				t.Errorf("IsIPAddress(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestLookupResolver(t *testing.T) {
	r := lookup.NewResolver("8.8.8.8", 5e9, 2)

	// Test A record lookup (known domain)
	result := r.Lookup("google.com", lookup.TypeA)
	if !result.Success {
		t.Errorf("Lookup(google.com, A) failed: %s", result.Error)
	}
	if len(result.Records) == 0 {
		t.Error("Lookup(google.com, A) returned no records")
	}

	// Verify the record type is A
	for _, rec := range result.Records {
		if rec.Type != "A" && rec.Section == "answer" {
			t.Errorf("Expected A record, got %s", rec.Type)
		}
	}

	// Test TXT record lookup
	txtResult := r.Lookup("google.com", lookup.TypeTXT)
	if !txtResult.Success {
		t.Errorf("Lookup(google.com, TXT) failed: %s", txtResult.Error)
	}
}

func TestLookupAll(t *testing.T) {
	r := lookup.NewResolver("8.8.8.8", 5e9, 1)

	results := r.LookupAll("google.com")
	if len(results) == 0 {
		t.Error("LookupAll returned no results")
	}

	// google.com should have A records
	if aResult, ok := results[lookup.TypeA]; ok {
		if !aResult.Success {
			t.Error("A record lookup failed")
		}
	}
}

func TestReverseLookup(t *testing.T) {
	r := lookup.NewResolver("8.8.8.8", 5e9, 2)

	result := r.ReverseLookup("8.8.8.8")
	if !result.Success {
		t.Logf("Reverse lookup of 8.8.8.8 failed (may be expected): %s", result.Error)
	}
}

func TestPrintLookup(t *testing.T) {
	result := &lookup.LookupResult{
		Domain:     "example.com",
		RecordType: "A",
		Server:     "8.8.8.8:53",
		Success:    true,
		Records: []lookup.Record{
			{Name: "example.com", Type: "A", TTL: 3600, RData: "93.184.216.34", Section: "answer"},
		},
	}

	var buf bytes.Buffer
	report.PrintLookup(result, &buf, report.FormatText)
	output := buf.String()

	if !contains(output, "example.com") {
		t.Error("Text output missing domain")
	}
	if !contains(output, "93.184.216.34") {
		t.Error("Text output missing record data")
	}

	// JSON format
	buf.Reset()
	report.PrintLookup(result, &buf, report.FormatJSON)
	jsonOutput := buf.String()
	if !contains(jsonOutput, "example.com") {
		t.Error("JSON output missing domain")
	}

	// Compact format
	buf.Reset()
	report.PrintLookup(result, &buf, report.FormatCompact)
	compactOutput := buf.String()
	if !contains(compactOutput, "93.184.216.34") {
		t.Error("Compact output missing record data")
	}
}

func TestPrintLookupError(t *testing.T) {
	result := &lookup.LookupResult{
		Domain:     "nonexistent.invalid",
		RecordType: "A",
		Server:     "8.8.8.8:53",
		Success:    false,
		Error:      "lookup failed",
	}

	var buf bytes.Buffer
	report.PrintLookup(result, &buf, report.FormatText)
	output := buf.String()

	if !contains(output, "Error") {
		t.Error("Error output missing error message")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestVersion(t *testing.T) {
	// Test that version command works
	cmd := rootCmd
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Errorf("version command failed: %v", err)
	}

	output := buf.String()
	if !contains(output, "dnsforge") {
		t.Error("version output missing 'dnsforge'")
	}
}

func TestLookupInvalidType(t *testing.T) {
	cmd := rootCmd
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"lookup", "example.com", "INVALID"})

	err := cmd.Execute()
	if err == nil {
		t.Error("Expected error for invalid record type")
	}
}

func TestSupportedTypes(t *testing.T) {
	types := lookup.SupportedTypes()
	if len(types) < 10 {
		t.Errorf("Expected at least 10 supported types, got %d", len(types))
	}
}
