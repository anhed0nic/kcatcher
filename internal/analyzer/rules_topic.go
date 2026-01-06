// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"fmt"
	"strconv"

	"github.com/RoseSecurity/kcatcher/internal/kafka"
)

// AutoCreateTopicsRule checks if auto.create.topics.enable is true.
type AutoCreateTopicsRule struct {
	BaseRule
}

func (r *AutoCreateTopicsRule) ID() string         { return "TOPIC001" }
func (r *AutoCreateTopicsRule) Name() string       { return "Auto Topic Creation Enabled" }
func (r *AutoCreateTopicsRule) Severity() Severity { return SeverityHigh }
func (r *AutoCreateTopicsRule) Category() Category { return CategoryConfiguration }

func (r *AutoCreateTopicsRule) Description() string {
	return "Checks if automatic topic creation is enabled"
}

func (r *AutoCreateTopicsRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding

	for _, broker := range ctx.Configs.BrokerConfigs {
		autoCreate := getConfigValue(broker.Configs, "auto.create.topics.enable")

		if autoCreate == "true" {
			finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
				WithDescription("Broker %d has auto.create.topics.enable set to true. "+
					"Any client can create topics by producing or consuming from non-existent topics. "+
					"This can lead to resource exhaustion and makes auditing difficult.", broker.BrokerID).
				WithResource("broker", fmt.Sprintf("%d", broker.BrokerID)).
				WithValues("true", "false").
				WithRemediation("Set 'auto.create.topics.enable=false' and create topics explicitly "+
					"through controlled administrative processes.").
				WithReferences(
					"https://kafka.apache.org/documentation/#brokerconfigs_auto.create.topics.enable",
				)
			findings = append(findings, finding)
		}
	}

	return findings
}

// UncleanLeaderElectionRule checks if unclean leader election is enabled.
type UncleanLeaderElectionRule struct {
	BaseRule
}

func (r *UncleanLeaderElectionRule) ID() string         { return "TOPIC002" }
func (r *UncleanLeaderElectionRule) Name() string       { return "Unclean Leader Election Enabled" }
func (r *UncleanLeaderElectionRule) Severity() Severity { return SeverityHigh }
func (r *UncleanLeaderElectionRule) Category() Category { return CategoryDataProtection }

func (r *UncleanLeaderElectionRule) Description() string {
	return "Checks if unclean leader election is enabled on topics"
}

func (r *UncleanLeaderElectionRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding

	// Check topic-level configuration
	for _, topic := range ctx.Configs.TopicConfigs {
		uncleanElection := getTopicConfigValue(topic.Configs, "unclean.leader.election.enable")

		if uncleanElection == "true" {
			finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
				WithDescription("Topic '%s' has unclean.leader.election.enable set to true. "+
					"This can result in data loss when an out-of-sync replica becomes leader.", topic.TopicName).
				WithResource("topic", topic.TopicName).
				WithValues("true", "false").
				WithRemediation("Set 'unclean.leader.election.enable=false' for topics where data "+
					"integrity is important. Accept potential unavailability over data loss.").
				WithReferences(
					"https://kafka.apache.org/documentation/#topicconfigs_unclean.leader.election.enable",
				)
			findings = append(findings, finding)
		}
	}

	return findings
}

// LowMinISRRule checks if min.insync.replicas is too low.
type LowMinISRRule struct {
	BaseRule
}

func (r *LowMinISRRule) ID() string         { return "TOPIC003" }
func (r *LowMinISRRule) Name() string       { return "Low Minimum In-Sync Replicas" }
func (r *LowMinISRRule) Severity() Severity { return SeverityMedium }
func (r *LowMinISRRule) Category() Category { return CategoryDataProtection }

func (r *LowMinISRRule) Description() string {
	return "Checks if min.insync.replicas is set too low for data durability"
}

func (r *LowMinISRRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding

	// Check topic-level configuration
	for _, topic := range ctx.Configs.TopicConfigs {
		minISR := getTopicConfigValue(topic.Configs, "min.insync.replicas")

		if minISR != "" && minISR != "<null>" {
			minISRVal, err := strconv.Atoi(minISR)
			if err == nil && minISRVal < 2 {
				finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
					WithDescription("Topic '%s' has min.insync.replicas set to %d. "+
						"With fewer than 2 in-sync replicas required, data could be lost if "+
						"the single replica fails before replication completes.", topic.TopicName, minISRVal).
					WithResource("topic", topic.TopicName).
					WithValues(minISR, "2 or higher").
					WithRemediation("Set 'min.insync.replicas=2' (or higher) for topics requiring "+
						"high durability. Ensure replication factor is at least min.insync.replicas + 1.").
					WithReferences(
						"https://kafka.apache.org/documentation/#topicconfigs_min.insync.replicas",
					)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// ShortRetentionRule checks if retention is suspiciously short.
type ShortRetentionRule struct {
	BaseRule
}

func (r *ShortRetentionRule) ID() string         { return "TOPIC004" }
func (r *ShortRetentionRule) Name() string       { return "Short Message Retention" }
func (r *ShortRetentionRule) Severity() Severity { return SeverityLow }
func (r *ShortRetentionRule) Category() Category { return CategoryDataProtection }

func (r *ShortRetentionRule) Description() string {
	return "Reports topics with retention less than 24 hours for awareness"
}

func (r *ShortRetentionRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding
	const oneDayMs = 24 * 60 * 60 * 1000 // 86400000 ms

	for _, topic := range ctx.Configs.TopicConfigs {
		retentionMs := getTopicConfigValue(topic.Configs, "retention.ms")

		if retentionMs != "" && retentionMs != "<null>" && retentionMs != "-1" {
			retentionVal, err := strconv.ParseInt(retentionMs, 10, 64)
			if err == nil && retentionVal > 0 && retentionVal < oneDayMs {
				hours := retentionVal / (60 * 60 * 1000)
				finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
					WithDescription("Topic '%s' has retention.ms set to %d (%d hours). "+
						"Short retention may impact audit trails and disaster recovery.",
						topic.TopicName, retentionVal, hours).
					WithResource("topic", topic.TopicName).
					WithValues(retentionMs, "86400000 (1 day) or longer").
					WithRemediation("Consider if short retention meets compliance and "+
						"operational requirements. Ensure critical data is archived if needed.").
					WithReferences(
						"https://kafka.apache.org/documentation/#topicconfigs_retention.ms",
					)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// DeleteTopicEnabledRule checks if topic deletion is enabled.
type DeleteTopicEnabledRule struct {
	BaseRule
}

func (r *DeleteTopicEnabledRule) ID() string         { return "TOPIC005" }
func (r *DeleteTopicEnabledRule) Name() string       { return "Topic Deletion Enabled" }
func (r *DeleteTopicEnabledRule) Severity() Severity { return SeverityInfo }
func (r *DeleteTopicEnabledRule) Category() Category { return CategoryConfiguration }

func (r *DeleteTopicEnabledRule) Description() string {
	return "Reports if topic deletion is enabled for awareness"
}

func (r *DeleteTopicEnabledRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding

	for _, broker := range ctx.Configs.BrokerConfigs {
		deleteEnabled := getConfigValue(broker.Configs, "delete.topic.enable")

		if deleteEnabled == "true" {
			finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
				WithDescription("Broker %d has delete.topic.enable set to true. "+
					"Topics can be permanently deleted. Ensure proper ACLs protect against "+
					"unauthorized deletion.", broker.BrokerID).
				WithResource("broker", fmt.Sprintf("%d", broker.BrokerID)).
				WithValues("true", "Depends on requirements").
				WithRemediation("Ensure Delete ACLs are restricted to authorized administrators. "+
					"Consider setting to false in production if topic deletion is not needed.").
				WithReferences(
					"https://kafka.apache.org/documentation/#brokerconfigs_delete.topic.enable",
				)
			findings = append(findings, finding)
			break // Only report once
		}
	}

	return findings
}

// ShortRetentionRule checks if topic retention period is too short for compliance.
type ShortRetentionRule struct {
	BaseRule
}

func (r *ShortRetentionRule) ID() string         { return "TOPIC006" }
func (r *ShortRetentionRule) Name() string       { return "Short Message Retention Period" }
func (r *ShortRetentionRule) Severity() Severity { return SeverityMedium }
func (r *ShortRetentionRule) Category() Category { return CategoryConfiguration }

func (r *ShortRetentionRule) Description() string {
	return "Checks if topic message retention periods are set to short durations that may violate compliance requirements"
}

func (r *ShortRetentionRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding

	// Minimum retention for compliance (6 years in milliseconds)
	minRetentionMs := int64(6 * 365 * 24 * 60 * 60 * 1000) // approx 189216000000

	for _, topic := range ctx.Configs.TopicConfigs {
		retentionMsStr := getTopicConfigValue(topic.Configs, "retention.ms")
		if retentionMsStr == "" || retentionMsStr == "<null>" {
			// No retention set, infinite retention is fine
			continue
		}

		retentionMs, err := strconv.ParseInt(retentionMsStr, 10, 64)
		if err != nil {
			continue
		}

		if retentionMs > 0 && retentionMs < minRetentionMs {
			finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
				WithDescription("Topic %s has retention.ms set to %d ms (~%.1f years), which may be too short for compliance requirements. "+
					"Ensure retention policies meet legal and regulatory standards.", topic.TopicName, retentionMs, float64(retentionMs)/(365*24*60*60*1000)).
				WithResource("topic", topic.TopicName).
				WithValues(retentionMsStr, fmt.Sprintf(">=%d", minRetentionMs)).
				WithRemediation("Review and adjust retention.ms to comply with data retention regulations. "+
					"Consider setting to -1 for infinite retention if appropriate.").
				WithReferences(
					"https://kafka.apache.org/documentation/#topicconfigs_retention.ms",
				)
			findings = append(findings, finding)
		}
	}

	return findings
}

// EncryptionAtRestRule checks if log segment encryption is enabled.
type EncryptionAtRestRule struct {
	BaseRule
}

func (r *EncryptionAtRestRule) ID() string         { return "ENC005" }
func (r *EncryptionAtRestRule) Name() string       { return "No Encryption at Rest" }
func (r *EncryptionAtRestRule) Severity() Severity { return SeverityHigh }
func (r *EncryptionAtRestRule) Category() Category { return CategoryEncryption }

func (r *EncryptionAtRestRule) Description() string {
	return "Checks if log segment encryption is configured for data at rest protection"
}

func (r *EncryptionAtRestRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding

	for _, broker := range ctx.Configs.BrokerConfigs {
		encryptionEnabled := getConfigValue(broker.Configs, "log.segment.encryption")

		if encryptionEnabled == "" || encryptionEnabled == "<null>" || encryptionEnabled == "false" {
			finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
				WithDescription("Broker %d does not have log segment encryption enabled. "+
					"Data at rest is not encrypted, which may violate compliance requirements for sensitive data.", broker.BrokerID).
				WithResource("broker", fmt.Sprintf("%d", broker.BrokerID)).
				WithValues(encryptionEnabled, "true").
				WithRemediation("Enable log segment encryption by setting 'log.segment.encryption=true' and configuring encryption keys. "+
					"Note: This requires Confluent Platform or custom encryption implementation.").
				WithReferences(
					"https://docs.confluent.io/platform/current/security/encrypt-data-at-rest.html",
				)
			findings = append(findings, finding)
		}
	}

	return findings
}

// getTopicConfigValue is a helper to retrieve a config value by name from topic configs.
func getTopicConfigValue(configs []kafka.ConfigEntry, name string) string {
	for _, cfg := range configs {
		if cfg.Name == name {
			return cfg.Value
		}
	}
	return ""
}
