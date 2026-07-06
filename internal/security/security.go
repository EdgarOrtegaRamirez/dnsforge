package security

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/EdgarOrtegaRamirez/dnsforge/internal/lookup"
)

// SPFResult represents the analysis of an SPF record
type SPFResult struct {
	Record    string   `json:"record"`
	Valid     bool     `json:"valid"`
	Mechanisms []string `json:"mechanisms"`
	Warnings  []string `json:"warnings"`
	Errors    []string `json:"errors"`
	Includes  []string `json:"includes"`
	IPCount   int      `json:"ip_count"`
}

// DMARCResult represents the analysis of a DMARC record
type DMARCResult struct {
	Record     string `json:"record"`
	Valid      bool   `json:"valid"`
	Policy     string `json:"policy"`
	SubPolicy  string `json:"sub_policy"`
	Percentage int    `json:"percentage"`
	 rua       string `json:"rua"`
	ruf       string `json:"ruf"`
	Adkim      string `json:"adkim"`
	Aspf       string `json:"aspf"`
	Warnings   []string `json:"warnings"`
	Errors     []string `json:"errors"`
}

// DKIMResult represents a DKIM lookup attempt
type DKIMResult struct {
	Selector string `json:"selector"`
	Record   string `json:"record"`
	Found    bool   `json:"found"`
	Valid    bool   `json:"valid"`
	Error    string `json:"error,omitempty"`
}

// SecurityReport contains all email security analysis
type SecurityReport struct {
	Domain    string        `json:"domain"`
	SPF       *SPFResult    `json:"spf"`
	DMARC     *DMARCResult  `json:"dmarc"`
	DKIM      []DKIMResult  `json:"dkim"`
	Score     int           `json:"score"`
	MaxScore  int           `json:"max_score"`
}

// AnalyzeEmailSecurity performs comprehensive email security analysis
func AnalyzeEmailSecurity(domain string, resolver *lookup.Resolver) *SecurityReport {
	domain = lookup.NormalizeDomain(domain)

	report := &SecurityReport{
		Domain:   domain,
		MaxScore: 100,
	}

	// Check SPF
	report.SPF = analyzeSPF(domain, resolver)

	// Check DMARC
	report.DMARC = analyzeDMARC(domain, resolver)

	// Check common DKIM selectors
	report.DKIM = analyzeDKIM(domain, resolver)

	// Calculate score
	report.Score = calculateSecurityScore(report)

	return report
}

// analyzeSPF analyzes the SPF record for a domain
func analyzeSPF(domain string, resolver *lookup.Resolver) *SPFResult {
	result := &SPFResult{}

	spfRecords := resolver.Lookup(domain, lookup.TypeTXT)
	if !spfRecords.Success {
		result.Errors = append(result.Errors, "failed to query TXT records")
		return result
	}

	for _, rec := range spfRecords.Records {
		if strings.HasPrefix(rec.RData, "v=spf1") {
			result.Record = rec.RData
			break
		}
	}

	if result.Record == "" {
		result.Errors = append(result.Errors, "no SPF record found")
		return result
	}

	result.Valid = true
	result.Mechanisms = extractSPFMechanisms(result.Record)
	result.Includes = extractSPFIncludes(result.Record)
	result.Warnings = checkSPFWarnings(result)
	result.IPCount = countSPFIPs(result.Record)

	return result
}

// analyzeDMARC analyzes the DMARC record for a domain
func analyzeDMARC(domain string, resolver *lookup.Resolver) *DMARCResult {
	result := &DMARCResult{}

	dmarcQuery := fmt.Sprintf("_dmarc.%s", domain)
	dmarcRecords := resolver.Lookup(dmarcQuery, lookup.TypeTXT)
	if !dmarcRecords.Success {
		result.Errors = append(result.Errors, "failed to query DMARC record")
		return result
	}

	for _, rec := range dmarcRecords.Records {
		if strings.HasPrefix(rec.RData, "v=DMARC1") {
			result.Record = rec.RData
			break
		}
	}

	if result.Record == "" {
		result.Errors = append(result.Errors, "no DMARC record found")
		return result
	}

	result.Valid = true
	result.Policy = extractDMARCTag(result.Record, "p")
	result.SubPolicy = extractDMARCTag(result.Record, "sp")
	result.Percentage = extractDMARCPercentage(result.Record)
	result rua = extractDMARCTag(result.Record, "rua")
	result.ruf = extractDMARCTag(result.Record, "ruf")
	result.Adkim = extractDMARCTag(result.Record, "adkim")
	result.Aspf = extractDMARCTag(result.Record, "aspf")

	result.Warnings = checkDMARCWarnings(result)

	return result
}

// analyzeDKIM checks common DKIM selectors
func analyzeDKIM(domain string, resolver *lookup.Resolver) []DKIMResult {
	commonSelectors := []string{"default", "google", "selector1", "selector2", "k1", "mandrill", "everlytickey1", "dkim", "mail", "s1", "s2"}

	var results []DKIMResult

	for _, selector := range commonSelectors {
		dkimQuery := fmt.Sprintf("%s._domainkey.%s", selector, domain)
		dkimRecords := resolver.Lookup(dkimQuery, lookup.TypeTXT)

		dr := DKIMResult{
			Selector: selector,
			Found:    false,
			Valid:    false,
		}

		if dkimRecords.Success && len(dkimRecords.Records) > 0 {
			for _, rec := range dkimRecords.Records {
				if strings.Contains(rec.RData, "v=DKIM1") || strings.Contains(rec.RData, "p=") {
					dr.Found = true
					dr.Record = rec.RData
					dr.Valid = !strings.Contains(rec.RData, "p=") || !strings.Contains(rec.RData, "p=\"\"")
					break
				}
			}
		}

		results = append(results, dr)
	}

	return results
}

// extractSPFMechanisms extracts SPF mechanisms
func extractSPFMechanisms(record string) []string {
	mechanismRegex := regexp.MustCompile(`[+\-~?]?(all|include|a|mx|ip4|ip6|exists|redirect|exp)`)
	matches := mechanismRegex.FindAllString(record, -1)
	return matches
}

// extractSPFIncludes extracts include domains
func extractSPFIncludes(record string) []string {
	includeRegex := regexp.MustCompile(`include:([^\s]+)`)
	matches := includeRegex.FindAllStringSubmatch(record, -1)
	var includes []string
	for _, m := range matches {
		if len(m) > 1 {
			includes = append(includes, m[1])
		}
	}
	return includes
}

// countSPFIPs counts IP mechanisms in SPF record
func countSPFIPs(record string) int {
	ipRegex := regexp.MustCompile(`(ip4|ip6):[^\s]+`)
	return len(ipRegex.FindAllString(record, -1))
}

// checkSPFWarnings checks for SPF warnings
func checkSPFWarnings(spf *SPFResult) []string {
	var warnings []string

	if len(spf.Includes) > 3 {
		warnings = append(warnings, fmt.Sprintf("SPF has %d includes (may affect lookup depth)", len(spf.Includes)))
	}

	if spf.IPCount > 10 {
		warnings = append(warnings, fmt.Sprintf("SPF has %d IP mechanisms (DNS lookup limit is 10)", spf.IPCount))
	}

	hasAll := false
	for _, m := range spf.Mechanisms {
		if m == "all" || strings.HasSuffix(m, "all") {
			hasAll = true
			break
		}
	}
	if !hasAll {
		warnings = append(warnings, "SPF record missing 'all' mechanism")
	}

	return warnings
}

// checkDMARCWarnings checks for DMARC warnings
func checkDMARCWarnings(dmarc *DMARCResult) []string {
	var warnings []string

	if dmarc.Policy == "none" {
		warnings = append(warnings, "DMARC policy is 'none' (monitoring only, no enforcement)")
	}

	if dmarc.Percentage < 100 {
		warnings = append(warnings, fmt.Sprintf("DMARC only applies to %d%% of messages", dmarc.Percentage))
	}

	if dmarc.rua == "" {
		warnings = append(warnings, "DMARC missing aggregate reporting (rua)")
	}

	if dmarc.ruf == "" {
		warnings = append(warnings, "DMARC missing forensic reporting (ruf)")
	}

	if dmarc.Adkim == "" || dmarc.Adkim == "r" {
		warnings = append(warnings, "DMARC DKIM alignment is relaxed (consider strict)")
	}

	if dmarc.Aspf == "" || dmarc.Aspf == "r" {
		warnings = append(warnings, "DMARC SPF alignment is relaxed (consider strict)")
	}

	return warnings
}

// extractDMARCTag extracts a specific tag from a DMARC record
func extractDMARCTag(record, tag string) string {
	tagRegex := regexp.MustCompile(fmt.Sprintf(`%s=([^;\s]+)`, tag))
	matches := tagRegex.FindStringSubmatch(record)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractDMARCPercentage extracts the pct tag from DMARC
func extractDMARCPercentage(record string) int {
	pctStr := extractDMARCTag(record, "pct")
	if pctStr == "" {
		return 100 // default
	}
	pct := 0
	fmt.Sscanf(pctStr, "%d", &pct)
	return pct
}

// calculateSecurityScore calculates a 0-100 security score
func calculateSecurityScore(report *SecurityReport) int {
	score := 0

	// SPF (40 points max)
	if report.SPF != nil && report.SPF.Valid {
		score += 20
		if len(report.SPF.Warnings) == 0 {
			score += 20
		} else if len(report.SPF.Warnings) <= 2 {
			score += 10
		}
	}

	// DMARC (40 points max)
	if report.DMARC != nil && report.DMARC.Valid {
		score += 15
		if report.DMARC.Policy == "reject" || report.DMARC.Policy == "quarantine" {
			score += 15
		}
		if len(report.DMARC.Warnings) == 0 {
			score += 10
		} else if len(report.DMARC.Warnings) <= 2 {
			score += 5
		}
	}

	// DKIM (20 points max)
	dkimFound := 0
	for _, dkim := range report.DKIM {
		if dkim.Found && dkim.Valid {
			dkimFound++
		}
	}
	if dkimFound > 0 {
		score += 10
		if dkimFound >= 2 {
			score += 10
		} else {
			score += 5
		}
	}

	if score > 100 {
		score = 100
	}

	return score
}
