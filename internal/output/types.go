// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package output

import "time"

// OutputData represents all data that can be formatted for output.
type OutputData struct {
	Metadata *MetadataOutput  `json:"metadata,omitempty"`
	Configs  *ConfigsOutput   `json:"configs,omitempty"`
	ACLs     []ACLOutput      `json:"acls,omitempty"`
	Samples  []SampleOutput   `json:"samples,omitempty"`
	Analysis *AnalysisOutput  `json:"analysis,omitempty"`
}

// MetadataOutput represents cluster metadata in a serializable format.
type MetadataOutput struct {
	Brokers []BrokerOutput `json:"brokers"`
	Topics  []TopicOutput  `json:"topics"`
}

// BrokerOutput represents a broker.
type BrokerOutput struct {
	NodeID int32  `json:"node_id"`
	Host   string `json:"host"`
	Port   int32  `json:"port"`
}

// TopicOutput represents a topic.
type TopicOutput struct {
	Name       string            `json:"name"`
	Partitions []PartitionOutput `json:"partitions"`
}

// PartitionOutput represents a partition.
type PartitionOutput struct {
	ID       int32   `json:"id"`
	Leader   int32   `json:"leader"`
	Replicas []int32 `json:"replicas"`
	ISRs     []int32 `json:"isrs"`
}

// ACLOutput represents an ACL entry.
type ACLOutput struct {
	ResourceType   string `json:"resource_type"`
	ResourceName   string `json:"resource_name"`
	PatternType    string `json:"pattern_type"`
	Principal      string `json:"principal"`
	Host           string `json:"host"`
	Operation      string `json:"operation"`
	PermissionType string `json:"permission_type"`
}

// SampleOutput represents a sampled message.
type SampleOutput struct {
	Topic       string    `json:"topic"`
	Partition   int32     `json:"partition"`
	Offset      int64     `json:"offset"`
	Timestamp   time.Time `json:"timestamp"`
	Key         string    `json:"key"`
	KeyBase64   string    `json:"key_base64,omitempty"`
	Value       string    `json:"value"`
	ValueBase64 string    `json:"value_base64,omitempty"`
	IsBinary    bool      `json:"is_binary"`
}

// ConfigsOutput represents cluster configurations.
type ConfigsOutput struct {
	Brokers []BrokerConfigOutput `json:"brokers"`
	Topics  []TopicConfigOutput  `json:"topics"`
}

// BrokerConfigOutput represents a broker's configuration.
type BrokerConfigOutput struct {
	BrokerID int32                `json:"broker_id"`
	Configs  []ConfigEntryOutput  `json:"configs"`
}

// TopicConfigOutput represents a topic's configuration.
type TopicConfigOutput struct {
	TopicName string              `json:"topic_name"`
	Configs   []ConfigEntryOutput `json:"configs"`
}

// ConfigEntryOutput represents a single configuration entry.
type ConfigEntryOutput struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Source    string `json:"source"`
	Sensitive bool   `json:"sensitive"`
	ReadOnly  bool   `json:"read_only"`
}

// AnalysisOutput represents the security analysis results.
type AnalysisOutput struct {
	Summary  *AnalysisSummaryOutput `json:"summary"`
	Findings []FindingOutput        `json:"findings"`
}

// AnalysisSummaryOutput provides aggregate statistics about the analysis.
type AnalysisSummaryOutput struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByCategory    map[string]int `json:"by_category"`
	CriticalCount int            `json:"critical_count"`
	HighCount     int            `json:"high_count"`
	MediumCount   int            `json:"medium_count"`
	LowCount      int            `json:"low_count"`
	InfoCount     int            `json:"info_count"`
	SecurityScore float64        `json:"security_score"`
	SecurityGrade string         `json:"security_grade"`
}

// FindingOutput represents a security finding.
type FindingOutput struct {
	RuleID        string   `json:"rule_id"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	Severity      string   `json:"severity"`
	Category      string   `json:"category"`
	Resource      string   `json:"resource"`
	ResourceType  string   `json:"resource_type"`
	CurrentValue  string   `json:"current_value,omitempty"`
	ExpectedValue string   `json:"expected_value,omitempty"`
	Remediation   string   `json:"remediation"`
	References    []string `json:"references,omitempty"`
}
