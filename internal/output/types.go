// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package output

import "time"

// OutputData represents all data that can be formatted for output.
type OutputData struct {
	Metadata *MetadataOutput `json:"metadata,omitempty"`
	ACLs     []ACLOutput     `json:"acls,omitempty"`
	Samples  []SampleOutput  `json:"samples,omitempty"`
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
