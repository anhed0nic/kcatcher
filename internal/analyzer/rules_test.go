// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"testing"

	"github.com/RoseSecurity/kcatcher/internal/kafka"
)

func TestPhiExposureRiskRule(t *testing.T) {
	rule := &PhiExposureRiskRule{}

	tests := []struct {
		name           string
		sampleTopic    string
		expectFindings bool
	}{
		{
			name:           "sampling enabled",
			sampleTopic:    "test-topic",
			expectFindings: true,
		},
		{
			name:           "no sampling",
			sampleTopic:    "",
			expectFindings: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{
				SampleTopic: tt.sampleTopic,
			}

			findings := rule.Evaluate(ctx)

			if tt.expectFindings && len(findings) == 0 {
				t.Error("Expected findings but got none")
			}
			if !tt.expectFindings && len(findings) > 0 {
				t.Errorf("Expected no findings but got %d", len(findings))
			}

			if tt.expectFindings {
				finding := findings[0]
				if finding.RuleID != "PHI001" {
					t.Errorf("Expected rule ID PHI001, got %s", finding.RuleID)
				}
				if finding.Severity.String() != "HIGH" {
					t.Errorf("Expected HIGH severity, got %s", finding.Severity.String())
				}
			}
		})
	}
}

func TestShortRetentionRule(t *testing.T) {
	rule := &ShortRetentionRule{}

	tests := []struct {
		name           string
		retentionMs    string
		expectFindings bool
	}{
		{
			name:           "short retention",
			retentionMs:    "100000000", // ~3 years
			expectFindings: true,
		},
		{
			name:           "long retention",
			retentionMs:    "200000000000", // ~6+ years
			expectFindings: false,
		},
		{
			name:           "infinite retention",
			retentionMs:    "-1",
			expectFindings: false,
		},
		{
			name:           "no retention set",
			retentionMs:    "",
			expectFindings: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configs := &kafka.ClusterConfigs{
				TopicConfigs: []kafka.TopicConfig{
					{
						TopicName: "test-topic",
						Configs: []kafka.ConfigEntry{
							{Name: "retention.ms", Value: tt.retentionMs},
						},
					},
				},
			}

			ctx := &AnalysisContext{
				Configs: configs,
			}

			findings := rule.Evaluate(ctx)

			if tt.expectFindings && len(findings) == 0 {
				t.Error("Expected findings but got none")
			}
			if !tt.expectFindings && len(findings) > 0 {
				t.Errorf("Expected no findings but got %d", len(findings))
			}
		})
	}
}