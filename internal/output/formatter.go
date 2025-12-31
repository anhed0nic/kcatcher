// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Formatter interface for different output formats.
type Formatter interface {
	Format(data *OutputData) error
}

// NewFormatter creates a formatter based on format type.
func NewFormatter(w io.Writer, format string) (Formatter, error) {
	switch format {
	case "text", "":
		return &TextFormatter{writer: w}, nil
	case "json":
		return &JSONFormatter{writer: w}, nil
	default:
		return nil, fmt.Errorf("unsupported output format: %s", format)
	}
}

// TextFormatter outputs in kcat-compatible text format.
type TextFormatter struct {
	writer io.Writer
}

// Format outputs the data in kcat-compatible text format.
func (f *TextFormatter) Format(data *OutputData) error {
	// Format analysis first if present (security report)
	if data.Analysis != nil {
		f.formatAnalysis(data.Analysis)
	}

	// Format metadata
	if data.Metadata != nil {
		f.formatMetadata(data.Metadata)
	}

	// Format configs
	if data.Configs != nil {
		f.formatConfigs(data.Configs)
	}

	// Format ACLs
	if len(data.ACLs) > 0 {
		f.formatACLs(data.ACLs)
	}

	// Format samples
	if len(data.Samples) > 0 {
		f.formatSamples(data.Samples)
	}

	return nil
}

func (f *TextFormatter) formatMetadata(meta *MetadataOutput) {
	// Print header
	fmt.Fprintf(f.writer, "Metadata for all topics:\n")

	// Print brokers
	fmt.Fprintf(f.writer, " %d brokers:\n", len(meta.Brokers))
	for _, broker := range meta.Brokers {
		fmt.Fprintf(f.writer, "  broker %d at %s:%d\n",
			broker.NodeID, broker.Host, broker.Port)
	}

	// Print topics
	fmt.Fprintf(f.writer, "\n %d topics:\n", len(meta.Topics))

	for _, topic := range meta.Topics {
		fmt.Fprintf(f.writer, "  topic \"%s\" with %d partitions:\n",
			topic.Name, len(topic.Partitions))

		for _, partition := range topic.Partitions {
			replicas := formatInt32Slice(partition.Replicas)
			isrs := formatInt32Slice(partition.ISRs)
			fmt.Fprintf(f.writer, "    partition %d, leader %d, replicas: %s, isrs: %s\n",
				partition.ID, partition.Leader, replicas, isrs)
		}
	}
}

func (f *TextFormatter) formatConfigs(configs *ConfigsOutput) {
	// Print broker configs
	fmt.Fprintf(f.writer, "\nBroker Configurations:\n")
	for _, broker := range configs.Brokers {
		fmt.Fprintf(f.writer, " broker %d:\n", broker.BrokerID)
		for _, cfg := range broker.Configs {
			value := cfg.Value
			if cfg.Sensitive {
				value = "********"
			}
			fmt.Fprintf(f.writer, "  %s = %s [%s]\n", cfg.Name, value, cfg.Source)
		}
	}

	// Print topic configs
	if len(configs.Topics) > 0 {
		fmt.Fprintf(f.writer, "\nTopic Configurations:\n")
		for _, topic := range configs.Topics {
			fmt.Fprintf(f.writer, " topic \"%s\":\n", topic.TopicName)
			for _, cfg := range topic.Configs {
				value := cfg.Value
				if cfg.Sensitive {
					value = "********"
				}
				fmt.Fprintf(f.writer, "  %s = %s [%s]\n", cfg.Name, value, cfg.Source)
			}
		}
	}
}

func (f *TextFormatter) formatACLs(acls []ACLOutput) {
	fmt.Fprintf(f.writer, "\n %d ACLs:\n", len(acls))
	for _, acl := range acls {
		fmt.Fprintf(f.writer, "  %s %s/%s: %s@%s %s %s\n",
			acl.ResourceType,
			acl.ResourceName,
			acl.PatternType,
			acl.Principal,
			acl.Host,
			acl.Operation,
			acl.PermissionType,
		)
	}
}

func (f *TextFormatter) formatSamples(samples []SampleOutput) {
	fmt.Fprintf(f.writer, "\n %d sampled messages:\n", len(samples))
	for _, s := range samples {
		fmt.Fprintf(f.writer, "  [%s] partition:%d offset:%d timestamp:%s\n",
			s.Topic, s.Partition, s.Offset, s.Timestamp.Format(time.RFC3339))

		if s.IsBinary {
			fmt.Fprintf(f.writer, "    key (base64): %s\n", s.KeyBase64)
			fmt.Fprintf(f.writer, "    value (base64): %s\n", s.ValueBase64)
		} else {
			keyDisplay := s.Key
			if keyDisplay == "" {
				keyDisplay = "<null>"
			}
			fmt.Fprintf(f.writer, "    key: %s\n", keyDisplay)
			fmt.Fprintf(f.writer, "    value: %s\n", s.Value)
		}
	}
}

func (f *TextFormatter) formatAnalysis(analysis *AnalysisOutput) {
	// Print header with security grade
	fmt.Fprintf(f.writer, "\n")
	fmt.Fprintf(f.writer, "╔══════════════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(f.writer, "║                    SECURITY ANALYSIS REPORT                      ║\n")
	fmt.Fprintf(f.writer, "╚══════════════════════════════════════════════════════════════════╝\n\n")

	// Print summary
	if analysis.Summary != nil {
		f.formatSummary(analysis.Summary)
	}

	// Print findings grouped by severity
	if len(analysis.Findings) > 0 {
		f.formatFindings(analysis.Findings)
	} else {
		fmt.Fprintf(f.writer, "No security findings detected.\n\n")
	}
}

func (f *TextFormatter) formatSummary(summary *AnalysisSummaryOutput) {
	fmt.Fprintf(f.writer, "Security Score: %.0f/100 (Grade: %s)\n\n",
		summary.SecurityScore, summary.SecurityGrade)

	fmt.Fprintf(f.writer, "Findings Summary:\n")
	fmt.Fprintf(f.writer, "  CRITICAL: %d\n", summary.CriticalCount)
	fmt.Fprintf(f.writer, "  HIGH:     %d\n", summary.HighCount)
	fmt.Fprintf(f.writer, "  MEDIUM:   %d\n", summary.MediumCount)
	fmt.Fprintf(f.writer, "  LOW:      %d\n", summary.LowCount)
	fmt.Fprintf(f.writer, "  INFO:     %d\n", summary.InfoCount)
	fmt.Fprintf(f.writer, "  ─────────────\n")
	fmt.Fprintf(f.writer, "  TOTAL:    %d\n\n", summary.TotalFindings)
}

func (f *TextFormatter) formatFindings(findings []FindingOutput) {
	// Group findings by severity for display
	severityOrder := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	grouped := make(map[string][]FindingOutput)

	for _, finding := range findings {
		grouped[finding.Severity] = append(grouped[finding.Severity], finding)
	}

	fmt.Fprintf(f.writer, "Detailed Findings:\n")
	fmt.Fprintf(f.writer, "══════════════════════════════════════════════════════════════════\n\n")

	for _, severity := range severityOrder {
		if len(grouped[severity]) == 0 {
			continue
		}

		fmt.Fprintf(f.writer, "── %s ──\n\n", severity)

		for _, finding := range grouped[severity] {
			fmt.Fprintf(f.writer, "  [%s] %s\n", finding.RuleID, finding.Title)
			fmt.Fprintf(f.writer, "  Category: %s | Resource: %s (%s)\n",
				finding.Category, finding.Resource, finding.ResourceType)
			fmt.Fprintf(f.writer, "\n")
			fmt.Fprintf(f.writer, "  Description:\n")
			// Word wrap the description
			wrapped := wordWrap(finding.Description, 64)
			for _, line := range wrapped {
				fmt.Fprintf(f.writer, "    %s\n", line)
			}

			if finding.CurrentValue != "" || finding.ExpectedValue != "" {
				fmt.Fprintf(f.writer, "\n")
				fmt.Fprintf(f.writer, "  Current:  %s\n", finding.CurrentValue)
				fmt.Fprintf(f.writer, "  Expected: %s\n", finding.ExpectedValue)
			}

			fmt.Fprintf(f.writer, "\n")
			fmt.Fprintf(f.writer, "  Remediation:\n")
			wrapped = wordWrap(finding.Remediation, 64)
			for _, line := range wrapped {
				fmt.Fprintf(f.writer, "    %s\n", line)
			}

			if len(finding.References) > 0 {
				fmt.Fprintf(f.writer, "\n")
				fmt.Fprintf(f.writer, "  References:\n")
				for _, ref := range finding.References {
					fmt.Fprintf(f.writer, "    - %s\n", ref)
				}
			}

			fmt.Fprintf(f.writer, "\n  ──────────────────────────────────────────────────────────────\n\n")
		}
	}
}

// wordWrap wraps text to the specified width.
func wordWrap(text string, width int) []string {
	var lines []string
	words := strings.Fields(text)
	if len(words) == 0 {
		return lines
	}

	currentLine := words[0]
	for _, word := range words[1:] {
		if len(currentLine)+1+len(word) <= width {
			currentLine += " " + word
		} else {
			lines = append(lines, currentLine)
			currentLine = word
		}
	}
	lines = append(lines, currentLine)
	return lines
}

// JSONFormatter outputs in JSON format.
type JSONFormatter struct {
	writer io.Writer
}

// Format outputs the data in JSON format.
func (f *JSONFormatter) Format(data *OutputData) error {
	encoder := json.NewEncoder(f.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// formatInt32Slice converts a slice of int32 to a comma-separated string.
func formatInt32Slice(nums []int32) string {
	if len(nums) == 0 {
		return "-"
	}
	strs := make([]string, len(nums))
	for i, n := range nums {
		strs[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(strs, ",")
}
