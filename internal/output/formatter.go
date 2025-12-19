// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/RoseSecurity/kcatcher/internal/kafka"
)

// Formatter formats cluster metadata for output.
type Formatter struct {
	writer io.Writer
}

// NewFormatter creates a new formatter that writes to the given writer.
func NewFormatter(w io.Writer) *Formatter {
	return &Formatter{writer: w}
}

// Format outputs the cluster metadata in kcat-compatible style.
func (f *Formatter) Format(meta *kafka.ClusterMetadata) error {
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

	// Sort topics by name for consistent output
	topicNames := make([]string, 0, len(meta.Topics))
	for name := range meta.Topics {
		topicNames = append(topicNames, name)
	}
	sort.Strings(topicNames)

	for _, topicName := range topicNames {
		topic := meta.Topics[topicName]
		fmt.Fprintf(f.writer, "  topic \"%s\" with %d partitions:\n",
			topic.Topic, len(topic.Partitions))

		// Sort partitions by ID
		partitions := topic.Partitions.Sorted()
		for _, partition := range partitions {
			replicas := formatInt32Slice(partition.Replicas)
			isrs := formatInt32Slice(partition.ISR)
			fmt.Fprintf(f.writer, "    partition %d, leader %d, replicas: %s, isrs: %s\n",
				partition.Partition, partition.Leader, replicas, isrs)
		}
	}

	return nil
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
