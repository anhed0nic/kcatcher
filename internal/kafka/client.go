// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"context"
	"fmt"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

// Client wraps the franz-go Kafka client for metadata operations.
type Client struct {
	client  *kgo.Client
	admin   *kadm.Client
	brokers []string
}

// NewClient creates a new Kafka client with the given broker addresses.
func NewClient(brokers []string, timeout time.Duration) (*Client, error) {
	client, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.DialTimeout(timeout),
		kgo.RequestTimeoutOverhead(timeout),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create kafka client: %w", err)
	}

	return &Client{
		client:  client,
		admin:   kadm.NewClient(client),
		brokers: brokers,
	}, nil
}

// Close closes the Kafka client connection.
func (c *Client) Close() {
	c.client.Close()
}

// ClusterMetadata holds the complete cluster metadata.
type ClusterMetadata struct {
	Brokers kadm.BrokerDetails
	Topics  kadm.TopicDetails
}

// GetMetadata retrieves cluster metadata including brokers and topics.
func (c *Client) GetMetadata(ctx context.Context) (*ClusterMetadata, error) {
	// Get broker metadata
	brokers, err := c.admin.ListBrokers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list brokers: %w", err)
	}

	// Get topic metadata (all topics)
	topics, err := c.admin.ListTopics(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list topics: %w", err)
	}

	return &ClusterMetadata{
		Brokers: brokers,
		Topics:  topics,
	}, nil
}
