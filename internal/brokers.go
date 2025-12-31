// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/RoseSecurity/kcatcher/internal/analyzer"
	"github.com/RoseSecurity/kcatcher/internal/kafka"
	"github.com/RoseSecurity/kcatcher/internal/output"
	"github.com/RoseSecurity/kcatcher/pkg/utils"
	"github.com/spf13/cobra"
)

// EnumerateBrokers connects to Kafka brokers and lists cluster metadata.
func EnumerateBrokers(cmd *cobra.Command, args []string) error {
	if len(Cfg.Brokers) == 0 {
		fmt.Println()
		if err := utils.PrintStyledText("kcatcher"); err != nil {
			return fmt.Errorf("failed to print banner: %w", err)
		}
		if err := cmd.Help(); err != nil {
			return fmt.Errorf("failed to print help: %w", err)
		}
		return nil
	}

	// Validate brokers
	if err := utils.ValidateBrokers(Cfg.Brokers); err != nil {
		return err
	}

	// Format broker addresses with port
	brokerAddrs := make([]string, len(Cfg.Brokers))
	for i, broker := range Cfg.Brokers {
		brokerAddrs[i] = fmt.Sprintf("%s:%d", broker, Cfg.Port)
	}

	// Create Kafka client
	client, err := kafka.NewClient(brokerAddrs, Cfg.Timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to brokers: %w", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), Cfg.Timeout)
	defer cancel()

	// Collect all data
	data := &output.OutputData{}

	// Determine if we should show metadata
	// Auto-enable metadata display unless --analyze is used (can override with --metadata)
	showMetadata := Cfg.ShowMetadata || !Cfg.RunAnalysis

	// Always get metadata (needed internally even if not displayed)
	metadata, err := client.GetMetadata(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve metadata: %w", err)
	}

	// Only include in output if showing metadata
	if showMetadata {
		data.Metadata = convertMetadata(metadata)
	}

	// Track raw data for analysis
	var clusterConfigs *kafka.ClusterConfigs
	var aclEntries []kafka.ACLEntry

	// Get configs if requested or needed for analysis
	if Cfg.EnumerateConfigs || Cfg.RunAnalysis {
		clusterConfigs, err = client.GetClusterConfigs(ctx)
		if err != nil {
			return fmt.Errorf("failed to enumerate configs: %w", err)
		}
		if Cfg.EnumerateConfigs {
			data.Configs = convertConfigs(clusterConfigs)
		}
	}

	// Get ACLs if requested or needed for analysis
	if Cfg.EnumerateACLs || Cfg.RunAnalysis {
		aclEntries, err = client.GetACLs(ctx)
		if err != nil {
			// ACL enumeration may fail if no authorizer is configured
			// For analysis, we continue without ACLs
			if !Cfg.RunAnalysis {
				return fmt.Errorf("failed to enumerate ACLs: %w", err)
			}
		}
		if Cfg.EnumerateACLs && err == nil {
			data.ACLs = convertACLs(aclEntries)
		}
	}

	// Sample messages if requested
	if Cfg.SampleTopic != "" {
		samples, err := client.SampleMessages(ctx, Cfg.SampleTopic, Cfg.SampleCount)
		if err != nil {
			return fmt.Errorf("failed to sample messages: %w", err)
		}
		data.Samples = convertSamples(samples)
	}

	// Run security analysis if requested
	if Cfg.RunAnalysis {
		analysisCtx := &analyzer.AnalysisContext{
			Metadata: data.Metadata,
			Configs:  clusterConfigs,
			ACLs:     aclEntries,
		}

		engine := analyzer.DefaultEngine()
		result := engine.Analyze(analysisCtx)
		data.Analysis = convertAnalysisResult(result)
	}

	// Format and output
	formatter, err := output.NewFormatter(os.Stdout, Cfg.OutputFormat)
	if err != nil {
		return err
	}

	return formatter.Format(data)
}

// convertMetadata converts kafka.ClusterMetadata to output.MetadataOutput.
func convertMetadata(meta *kafka.ClusterMetadata) *output.MetadataOutput {
	out := &output.MetadataOutput{
		Brokers: make([]output.BrokerOutput, 0, len(meta.Brokers)),
		Topics:  make([]output.TopicOutput, 0, len(meta.Topics)),
	}

	// Convert brokers
	for _, broker := range meta.Brokers {
		out.Brokers = append(out.Brokers, output.BrokerOutput{
			NodeID: broker.NodeID,
			Host:   broker.Host,
			Port:   broker.Port,
		})
	}

	// Sort topics by name for consistent output
	topicNames := make([]string, 0, len(meta.Topics))
	for name := range meta.Topics {
		topicNames = append(topicNames, name)
	}
	sort.Strings(topicNames)

	// Convert topics
	for _, topicName := range topicNames {
		topic := meta.Topics[topicName]
		topicOut := output.TopicOutput{
			Name:       topic.Topic,
			Partitions: make([]output.PartitionOutput, 0, len(topic.Partitions)),
		}

		// Sort partitions by ID
		partitions := topic.Partitions.Sorted()
		for _, partition := range partitions {
			topicOut.Partitions = append(topicOut.Partitions, output.PartitionOutput{
				ID:       partition.Partition,
				Leader:   partition.Leader,
				Replicas: partition.Replicas,
				ISRs:     partition.ISR,
			})
		}

		out.Topics = append(out.Topics, topicOut)
	}

	return out
}

// convertACLs converts kafka.ACLEntry slice to output.ACLOutput slice.
func convertACLs(acls []kafka.ACLEntry) []output.ACLOutput {
	out := make([]output.ACLOutput, 0, len(acls))
	for _, acl := range acls {
		out = append(out, output.ACLOutput{
			ResourceType:   acl.ResourceType,
			ResourceName:   acl.ResourceName,
			PatternType:    acl.PatternType,
			Principal:      acl.Principal,
			Host:           acl.Host,
			Operation:      acl.Operation,
			PermissionType: acl.PermissionType,
		})
	}
	return out
}

// convertSamples converts kafka.SampledMessage slice to output.SampleOutput slice.
func convertSamples(samples []kafka.SampledMessage) []output.SampleOutput {
	out := make([]output.SampleOutput, 0, len(samples))
	for _, s := range samples {
		sample := output.SampleOutput{
			Topic:     s.Topic,
			Partition: s.Partition,
			Offset:    s.Offset,
			Timestamp: s.Timestamp,
			IsBinary:  kafka.IsBinaryData(s.Key) || kafka.IsBinaryData(s.Value),
		}

		if sample.IsBinary {
			sample.KeyBase64 = kafka.EncodeBase64(s.Key)
			sample.ValueBase64 = kafka.EncodeBase64(s.Value)
			sample.Key = ""
			sample.Value = ""
		} else {
			sample.Key = string(s.Key)
			sample.Value = string(s.Value)
		}

		out = append(out, sample)
	}
	return out
}

// convertConfigs converts kafka.ClusterConfigs to output.ConfigsOutput.
func convertConfigs(configs *kafka.ClusterConfigs) *output.ConfigsOutput {
	out := &output.ConfigsOutput{
		Brokers: make([]output.BrokerConfigOutput, 0, len(configs.BrokerConfigs)),
		Topics:  make([]output.TopicConfigOutput, 0, len(configs.TopicConfigs)),
	}

	// Convert broker configs
	for _, broker := range configs.BrokerConfigs {
		brokerOut := output.BrokerConfigOutput{
			BrokerID: broker.BrokerID,
			Configs:  make([]output.ConfigEntryOutput, 0, len(broker.Configs)),
		}
		for _, cfg := range broker.Configs {
			brokerOut.Configs = append(brokerOut.Configs, output.ConfigEntryOutput{
				Name:      cfg.Name,
				Value:     cfg.Value,
				Source:    cfg.Source,
				Sensitive: cfg.Sensitive,
				ReadOnly:  cfg.ReadOnly,
			})
		}
		out.Brokers = append(out.Brokers, brokerOut)
	}

	// Convert topic configs
	for _, topic := range configs.TopicConfigs {
		topicOut := output.TopicConfigOutput{
			TopicName: topic.TopicName,
			Configs:   make([]output.ConfigEntryOutput, 0, len(topic.Configs)),
		}
		for _, cfg := range topic.Configs {
			topicOut.Configs = append(topicOut.Configs, output.ConfigEntryOutput{
				Name:      cfg.Name,
				Value:     cfg.Value,
				Source:    cfg.Source,
				Sensitive: cfg.Sensitive,
				ReadOnly:  cfg.ReadOnly,
			})
		}
		out.Topics = append(out.Topics, topicOut)
	}

	return out
}

// convertAnalysisResult converts analyzer.AnalysisResult to output.AnalysisOutput.
func convertAnalysisResult(result *analyzer.AnalysisResult) *output.AnalysisOutput {
	out := &output.AnalysisOutput{
		Summary: &output.AnalysisSummaryOutput{
			TotalFindings: result.Summary.TotalFindings,
			BySeverity:    result.Summary.BySeverity,
			ByCategory:    result.Summary.ByCategory,
			CriticalCount: result.Summary.CriticalCount,
			HighCount:     result.Summary.HighCount,
			MediumCount:   result.Summary.MediumCount,
			LowCount:      result.Summary.LowCount,
			InfoCount:     result.Summary.InfoCount,
			SecurityScore: result.Summary.SecurityScore,
			SecurityGrade: result.Summary.SecurityGrade,
		},
		Findings: make([]output.FindingOutput, 0, len(result.Findings)),
	}

	for _, f := range result.Findings {
		out.Findings = append(out.Findings, output.FindingOutput{
			RuleID:        f.RuleID,
			Title:         f.Title,
			Description:   f.Description,
			Severity:      f.Severity.String(),
			Category:      string(f.Category),
			Resource:      f.Resource,
			ResourceType:  f.ResourceType,
			CurrentValue:  f.CurrentValue,
			ExpectedValue: f.ExpectedValue,
			Remediation:   f.Remediation,
			References:    f.References,
		})
	}

	return out
}
