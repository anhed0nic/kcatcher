// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package internal

import (
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
			name:     "ICD code anonymization",
			input:    "Diagnosis: I10.9",
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