// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/RoseSecurity/kcatcher/internal/analyzer"
	"github.com/RoseSecurity/kcatcher/internal/kafka"
	"github.com/RoseSecurity/kcatcher/internal/output"
	"github.com/RoseSecurity/kcatcher/pkg/utils"
	"github.com/spf13/cobra"
)

// Pre-compiled regex patterns for PHI anonymization
var (
	emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	ssnRegex   = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	phoneRegex = regexp.MustCompile(`\b\d{3}-\d{3}-\d{4}\b`)
	ccRegex    = regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`)
	// Improved MRN pattern to catch common variations
	mrnRegex = regexp.MustCompile(`(?i)\b(?:MRN|Medical\s*Record|Med(?:ical)?\s*Rec(?:ord)?|Record\s*#?)[:\s-]*[A-Z0-9]{6,12}\b`)
	// More specific ICD pattern requiring explicit ICD prefix
	icdRegex = regexp.MustCompile(`\b(?:ICD-10-CM|ICD-10|ICD10|ICD-9-CM|ICD-9|ICD9)\s+[A-TV-Z]\d{2}(?:\.[0-9A-TV-Z]{1,4})?\b`)
	// Contextual DOB pattern - matches DOB/date of birth followed by date
	dobRegex = regexp.MustCompile(`(?i)\b(?:DOB|Date\s*of\s*Birth)[:\s-]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b`)
)

// anonymizeData masks potential PHI in the given text.
func anonymizeData(text string) string {
	// Mask email addresses
	text = emailRegex.ReplaceAllString(text, "[EMAIL_REDACTED]")

	// Mask potential SSN (XXX-XX-XXXX) - note: phone numbers use different format
	text = ssnRegex.ReplaceAllString(text, "[SSN_REDACTED]")

	// Mask phone numbers (XXX-XXX-XXXX) - different from SSN format
	text = phoneRegex.ReplaceAllString(text, "[PHONE_REDACTED]")

	// Mask credit card numbers (simple 16-digit)
	text = ccRegex.ReplaceAllString(text, "[CC_REDACTED]")

	// Mask medical record numbers (MRN) - improved pattern
	text = mrnRegex.ReplaceAllString(text, "[MRN_REDACTED]")

	// Mask ICD codes - more specific pattern
	text = icdRegex.ReplaceAllString(text, "[ICD_REDACTED]")

	// Mask dates of birth (DOB) - contextual pattern
	text = dobRegex.ReplaceAllString(text, "[DOB_REDACTED]")

	return text
}

// logAudit logs an audit event to the specified file if configured.
func logAudit(message string) {
	if Cfg.AuditLogFile == "" {
		return
	}
	file, err := os.OpenFile(Cfg.AuditLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open audit log: %v\n", err)
		return
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to close audit log: %v\n", err)
		}
	}()
	timestamp := time.Now().Format(time.RFC3339)
	logEntry := fmt.Sprintf("[%s] %s\n", timestamp, message)
	if _, err := file.WriteString(logEntry); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write to audit log: %v\n", err)
	}
}

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

	// HIPAA compliance warning
	if Cfg.HipaaMode {
		fmt.Println("WARNING: HIPAA compliance mode enabled. Message sampling is disabled by default to protect potential PHI. Use --sample-topic only if data is properly anonymized and compliant.")
	}

	logAudit(fmt.Sprintf("Connected to brokers: %s", strings.Join(Cfg.Brokers, ",")))

	totalStartTime := time.Now()
	startTime := time.Now()
	var connectionTime, metadataTime, configTime, aclTime, sampleTime, analysisTime time.Duration

	// Format broker addresses with port
	brokerAddrs := make([]string, len(Cfg.Brokers))
	for i, broker := range Cfg.Brokers {
		brokerAddrs[i] = fmt.Sprintf("%s:%d", broker, Cfg.Port)
	}

	// Create auth config - only if authentication is actually configured
	var auth *kafka.AuthConfig
	if Cfg.SASLMechanism != "" || Cfg.SSLEnabled || Cfg.SSLCertFile != "" || Cfg.SSLKeyFile != "" || Cfg.SSLCAFile != "" || Cfg.MutualTLS {
		auth = &kafka.AuthConfig{
			SASLMechanism: Cfg.SASLMechanism,
			SASLUsername:  Cfg.SASLUsername,
			SASLPassword:  Cfg.SASLPassword,
			SSLEnabled:    Cfg.SSLEnabled,
			SSLCertFile:   Cfg.SSLCertFile,
			SSLKeyFile:    Cfg.SSLKeyFile,
			SSLCAFile:     Cfg.SSLCAFile,
			MutualTLS:     Cfg.MutualTLS,
		}
	}

	// Create Kafka client
	client, err := kafka.NewClient(brokerAddrs, Cfg.Timeout, auth)
	if err != nil {
		return fmt.Errorf("failed to connect to brokers: %w", err)
	}
	defer client.Close()

	connectionTime = time.Since(startTime)
	startTime = time.Now()

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

	metadataTime = time.Since(startTime)
	startTime = time.Now()

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

	configTime = time.Since(startTime)
	startTime = time.Now()

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

	aclTime = time.Since(startTime)
	startTime = time.Now()

	// Sample messages if requested
	if Cfg.SampleTopic != "" {
		samples, err := client.SampleMessages(ctx, Cfg.SampleTopic, Cfg.SampleCount)
		if err != nil {
			return fmt.Errorf("failed to sample messages: %w", err)
		}
		data.Samples = convertSamples(samples, Cfg.HipaaMode)
		logAudit(fmt.Sprintf("Sampled %d messages from topic: %s (redacted: %t)", len(samples), Cfg.SampleTopic, Cfg.HipaaMode))
		if Cfg.HipaaMode {
			fmt.Println("WARNING: Message sampling performed with data redaction in HIPAA mode.")
		}
	}

	sampleTime = time.Since(startTime)
	startTime = time.Now()

	// Run security analysis if requested
	if Cfg.RunAnalysis {
		analysisCtx := &analyzer.AnalysisContext{
			Metadata:   data.Metadata,
			Configs:    clusterConfigs,
			ACLs:       aclEntries,
			SampleTopic: Cfg.SampleTopic,
		}

		engine := analyzer.DefaultEngine()
		result := engine.Analyze(analysisCtx)
		data.Analysis = convertAnalysisResult(result)
		logAudit(fmt.Sprintf("Performed security analysis: %d findings", len(result.Findings)))
	}

	analysisTime = time.Since(startTime)

	// Print benchmark results if enabled
	if Cfg.Benchmark {
		totalTime := time.Since(totalStartTime)
		fmt.Printf("\nPerformance Benchmark:\n")
		fmt.Printf("  Connection Time: %v\n", connectionTime)
		fmt.Printf("  Metadata Retrieval: %v\n", metadataTime)
		fmt.Printf("  Config Retrieval: %v\n", configTime)
		fmt.Printf("  ACL Retrieval: %v\n", aclTime)
		fmt.Printf("  Message Sampling: %v\n", sampleTime)
		fmt.Printf("  Security Analysis: %v\n", analysisTime)
		fmt.Printf("  Total Time: %v\n", totalTime)
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
func convertSamples(samples []kafka.SampledMessage, redact bool) []output.SampleOutput {
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
			if redact {
				sample.Key = anonymizeData(string(s.Key))
				sample.Value = anonymizeData(string(s.Value))
			} else {
				sample.Key = string(s.Key)
				sample.Value = string(s.Value)
			}
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
