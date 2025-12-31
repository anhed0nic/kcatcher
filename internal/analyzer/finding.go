// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package analyzer

import "fmt"

// Severity represents the severity level of a security finding.
type Severity int

const (
	// SeverityInfo represents informational findings.
	SeverityInfo Severity = iota
	// SeverityLow represents low severity findings.
	SeverityLow
	// SeverityMedium represents medium severity findings.
	SeverityMedium
	// SeverityHigh represents high severity findings.
	SeverityHigh
	// SeverityCritical represents critical severity findings.
	SeverityCritical
)

// String returns the string representation of the severity.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Category represents the category of a security finding.
type Category string

const (
	CategoryAuthentication Category = "AUTHENTICATION"
	CategoryAuthorization  Category = "AUTHORIZATION"
	CategoryEncryption     Category = "ENCRYPTION"
	CategoryACL            Category = "ACCESS_CONTROL"
	CategoryDataProtection Category = "DATA_PROTECTION"
	CategoryNetwork        Category = "NETWORK"
	CategoryConfiguration  Category = "CONFIGURATION"
)

// Finding represents a security finding from the analysis.
type Finding struct {
	// RuleID is a unique identifier for the rule that generated this finding.
	RuleID string `json:"rule_id"`

	// Title is a short description of the finding.
	Title string `json:"title"`

	// Description provides detailed information about the finding.
	Description string `json:"description"`

	// Severity indicates how critical the finding is.
	Severity Severity `json:"severity"`

	// Category groups findings by security domain.
	Category Category `json:"category"`

	// Resource identifies what resource is affected (e.g., broker ID, topic name).
	Resource string `json:"resource"`

	// ResourceType indicates the type of resource (broker, topic, acl).
	ResourceType string `json:"resource_type"`

	// CurrentValue shows the current configuration value.
	CurrentValue string `json:"current_value,omitempty"`

	// ExpectedValue shows the recommended configuration value.
	ExpectedValue string `json:"expected_value,omitempty"`

	// Remediation provides guidance on how to fix the issue.
	Remediation string `json:"remediation"`

	// References provides links to relevant documentation.
	References []string `json:"references,omitempty"`
}

// NewFinding creates a new Finding with the given parameters.
func NewFinding(ruleID, title string, severity Severity, category Category) *Finding {
	return &Finding{
		RuleID:   ruleID,
		Title:    title,
		Severity: severity,
		Category: category,
	}
}

// WithDescription sets the description for the finding.
func (f *Finding) WithDescription(desc string, args ...interface{}) *Finding {
	f.Description = fmt.Sprintf(desc, args...)
	return f
}

// WithResource sets the resource information for the finding.
func (f *Finding) WithResource(resourceType, resource string) *Finding {
	f.ResourceType = resourceType
	f.Resource = resource
	return f
}

// WithValues sets the current and expected values for the finding.
func (f *Finding) WithValues(current, expected string) *Finding {
	f.CurrentValue = current
	f.ExpectedValue = expected
	return f
}

// WithRemediation sets the remediation guidance for the finding.
func (f *Finding) WithRemediation(remediation string) *Finding {
	f.Remediation = remediation
	return f
}

// WithReferences adds reference URLs to the finding.
func (f *Finding) WithReferences(refs ...string) *Finding {
	f.References = refs
	return f
}

// AnalysisResult holds the complete results of a security analysis.
type AnalysisResult struct {
	// Findings is the list of all security findings.
	Findings []*Finding `json:"findings"`

	// Summary provides aggregate statistics.
	Summary *AnalysisSummary `json:"summary"`
}

// AnalysisSummary provides aggregate statistics about the analysis.
type AnalysisSummary struct {
	TotalFindings    int            `json:"total_findings"`
	BySeverity       map[string]int `json:"by_severity"`
	ByCategory       map[string]int `json:"by_category"`
	CriticalCount    int            `json:"critical_count"`
	HighCount        int            `json:"high_count"`
	MediumCount      int            `json:"medium_count"`
	LowCount         int            `json:"low_count"`
	InfoCount        int            `json:"info_count"`
	SecurityScore    float64        `json:"security_score"`
	SecurityGrade    string         `json:"security_grade"`
}

// NewAnalysisResult creates a new AnalysisResult from a list of findings.
func NewAnalysisResult(findings []*Finding) *AnalysisResult {
	result := &AnalysisResult{
		Findings: findings,
		Summary:  &AnalysisSummary{},
	}
	result.calculateSummary()
	return result
}

// calculateSummary computes the summary statistics from the findings.
func (r *AnalysisResult) calculateSummary() {
	r.Summary.BySeverity = make(map[string]int)
	r.Summary.ByCategory = make(map[string]int)
	r.Summary.TotalFindings = len(r.Findings)

	for _, f := range r.Findings {
		// Count by severity
		r.Summary.BySeverity[f.Severity.String()]++
		switch f.Severity {
		case SeverityCritical:
			r.Summary.CriticalCount++
		case SeverityHigh:
			r.Summary.HighCount++
		case SeverityMedium:
			r.Summary.MediumCount++
		case SeverityLow:
			r.Summary.LowCount++
		case SeverityInfo:
			r.Summary.InfoCount++
		}

		// Count by category
		r.Summary.ByCategory[string(f.Category)]++
	}

	// Calculate security score (0-100, higher is better)
	r.Summary.SecurityScore = r.calculateSecurityScore()
	r.Summary.SecurityGrade = r.calculateGrade(r.Summary.SecurityScore)
}

// calculateSecurityScore computes a security score based on findings.
// Score starts at 100 and deducts points based on severity.
func (r *AnalysisResult) calculateSecurityScore() float64 {
	if len(r.Findings) == 0 {
		return 100.0
	}

	score := 100.0
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityCritical:
			score -= 25.0
		case SeverityHigh:
			score -= 15.0
		case SeverityMedium:
			score -= 8.0
		case SeverityLow:
			score -= 3.0
		case SeverityInfo:
			score -= 1.0
		}
	}

	if score < 0 {
		score = 0
	}
	return score
}

// calculateGrade converts a score to a letter grade.
func (r *AnalysisResult) calculateGrade(score float64) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}
