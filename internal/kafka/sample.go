// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/twmb/franz-go/pkg/kgo"
)

// SampledMessage represents a consumed message.
type SampledMessage struct {
	Topic     string
	Partition int32
	Offset    int64
	Timestamp time.Time
	Key       []byte
	Value     []byte
}

// SampleMessages consumes the latest N messages from a topic.
func (c *Client) SampleMessages(ctx context.Context, topic string, count int) ([]SampledMessage, error) {
	// First, get partition info for the topic
	topicDetails, err := c.admin.ListTopics(ctx, topic)
	if err != nil {
		return nil, fmt.Errorf("failed to list topic %s: %w", topic, err)
	}

	topicDetail, ok := topicDetails[topic]
	if !ok {
		return nil, fmt.Errorf("topic %s not found", topic)
	}

	// Get end offsets for all partitions
	endOffsets, err := c.admin.ListEndOffsets(ctx, topic)
	if err != nil {
		return nil, fmt.Errorf("failed to get end offsets: %w", err)
	}

	// Calculate starting offsets (end - count/partitions per partition)
	partitionOffsets := make(map[string]map[int32]kgo.Offset)
	partitionOffsets[topic] = make(map[int32]kgo.Offset)

	numPartitions := len(topicDetail.Partitions)
	msgsPerPartition := count / numPartitions
	if msgsPerPartition < 1 {
		msgsPerPartition = 1
	}

	// Get start offsets to avoid going below 0
	startOffsets, err := c.admin.ListStartOffsets(ctx, topic)
	if err != nil {
		return nil, fmt.Errorf("failed to get start offsets: %w", err)
	}

	for _, p := range topicDetail.Partitions.Sorted() {
		endOffset := endOffsets[topic][p.Partition].Offset
		startOffset := startOffsets[topic][p.Partition].Offset
		calculatedStart := endOffset - int64(msgsPerPartition)
		if calculatedStart < startOffset {
			calculatedStart = startOffset
		}
		partitionOffsets[topic][p.Partition] = kgo.NewOffset().At(calculatedStart)
	}

	// Create a new consumer client for sampling
	opts := buildClientOpts(c.brokers, 0, c.auth)
	opts = append(opts, kgo.ConsumePartitions(partitionOffsets))
	consumer, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create consumer: %w", err)
	}
	defer consumer.Close()

	// Collect messages with a timeout
	var messages []SampledMessage
	deadline := time.Now().Add(10 * time.Second)

	for len(messages) < count && time.Now().Before(deadline) {
		fetchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		fetches := consumer.PollFetches(fetchCtx)
		cancel()

		if fetches.IsClientClosed() {
			break
		}
		if ctx.Err() != nil {
			break
		}

		// Check if we got any records
		if fetches.NumRecords() == 0 {
			break
		}

		iter := fetches.RecordIter()
		for !iter.Done() && len(messages) < count {
			record := iter.Next()
			messages = append(messages, SampledMessage{
				Topic:     record.Topic,
				Partition: record.Partition,
				Offset:    record.Offset,
				Timestamp: record.Timestamp,
				Key:       record.Key,
				Value:     record.Value,
			})
		}
	}

	return messages, nil
}

// IsBinaryData checks if data contains non-UTF8 bytes.
func IsBinaryData(data []byte) bool {
	return !utf8.Valid(data)
}

// EncodeBase64 encodes data as base64.
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
