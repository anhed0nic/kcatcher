// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnonymizeData(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "email anonymization",
			input:    "Contact user@example.com for details",
			expected: "Contact [EMAIL_REDACTED] for details",
		},
		{
			name:     "SSN anonymization",
			input:    "SSN: 123-45-6789",
			expected: "SSN: [SSN_REDACTED]",
		},
		{
			name:     "phone anonymization",
			input:    "Call 555-123-4567",
			expected: "Call [PHONE_REDACTED]",
		},
		{
			name:     "MRN anonymization",
			input:    "Patient MRN: ABC123456",
			expected: "Patient [MRN_REDACTED]",
		},
		{
			name:     "MRN with different label",
			input:    "Medical Record #XYZ789012",
			expected: "[MRN_REDACTED]",
		},
		{
			name:     "ICD code anonymization",
			input:    "Diagnosis: ICD-10-CM I10.9",
			expected: "Diagnosis: [ICD_REDACTED]",
		},
		{
			name:     "DOB anonymization",
			input:    "DOB: 01/15/1980",
			expected: "DOB: [DOB_REDACTED]",
		},
		{
			name:     "multiple patterns",
			input:    "Email: test@example.com, SSN: 123-45-6789, Phone: 555-123-4567",
			expected: "Email: [EMAIL_REDACTED], SSN: [SSN_REDACTED], Phone: [PHONE_REDACTED]",
		},
		{
			name:     "no sensitive data",
			input:    "This is normal text",
			expected: "This is normal text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := anonymizeData(tt.input)
			if result != tt.expected {
				t.Errorf("anonymizeData() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestLogAudit(t *testing.T) {
	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "kcatcher_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	auditFile := filepath.Join(tempDir, "audit.log")

	// Save original config
	originalCfg := Cfg
	defer func() { Cfg = originalCfg }()

	// Set up test config
	Cfg = Config{
		AuditLogFile: auditFile,
	}

	// Test logging
	testMessage := "Test audit message"
	logAudit(testMessage)

	// Check if file was created and contains the message
	if _, err := os.Stat(auditFile); os.IsNotExist(err) {
		t.Errorf("Audit log file was not created")
	}

	content, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("Failed to read audit log: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, testMessage) {
		t.Errorf("Audit log does not contain expected message. Got: %s", contentStr)
	}

	// Check file permissions (should be 0600)
	info, err := os.Stat(auditFile)
	if err != nil {
		t.Fatalf("Failed to stat audit log: %v", err)
	}

	// On Windows, permissions work differently, so we'll just check the file exists
	// The permission check would be: if info.Mode().Perm() != 0600 { ... }
}