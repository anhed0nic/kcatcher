// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestCSVFormatter_Format(t *testing.T) {
	// Create test data
	analysis := &AnalysisOutput{
		Findings: []*FindingOutput{
			{
				RuleID:         "TEST001",
				Title:          "Test Finding",
				Severity:       "HIGH",
				Category:       "Security",
				Resource:       "broker:1",
				ResourceType:   "broker",
				CurrentValue:   "false",
				ExpectedValue:  "true",
				Description:    "This is a test finding with, commas and \"quotes\"",
				Remediation:    "Fix this issue by setting the value to true",
			},
		},
	}

	data := &OutputData{
		Analysis: analysis,
	}

	// Test CSV formatting
	var buf bytes.Buffer
	formatter := &CSVFormatter{writer: &buf}

	err := formatter.Format(data)
	if err != nil {
		t.Fatalf("CSVFormatter.Format() error = %v", err)
	}

	output := buf.String()

	// Check header
	if !strings.Contains(output, "Rule ID,Title,Severity,Category") {
		t.Errorf("CSV output missing header: %s", output)
	}

	// Check data row (CSV should properly escape commas and quotes)
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 2 {
		t.Errorf("Expected 2 lines (header + data), got %d", len(lines))
	}

	dataLine := lines[1]
	// Should contain properly escaped fields
	expectedParts := []string{"TEST001", "Test Finding", "HIGH", "Security", "broker:1", "broker", "false", "true"}
	for _, part := range expectedParts {
		if !strings.Contains(dataLine, part) {
			t.Errorf("CSV data line missing expected part '%s': %s", part, dataLine)
		}
	}

	// Check that commas in description are handled (should be quoted)
	if !strings.Contains(dataLine, "\"This is a test finding with, commas and \"\"quotes\"\"\"") {
		t.Errorf("CSV escaping not working properly: %s", dataLine)
	}
}

func TestCSVFormatter_NoAnalysisData(t *testing.T) {
	data := &OutputData{
		Analysis: nil,
	}

	var buf bytes.Buffer
	formatter := &CSVFormatter{writer: &buf}

	err := formatter.Format(data)
	if err != nil {
		t.Fatalf("CSVFormatter.Format() error = %v", err)
	}

	output := buf.String()
	expected := "No analysis data available\n"
	if output != expected {
		t.Errorf("Expected %q, got %q", expected, output)
	}
}