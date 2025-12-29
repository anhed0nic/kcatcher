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
	// Format metadata
	if data.Metadata != nil {
		f.formatMetadata(data.Metadata)
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
