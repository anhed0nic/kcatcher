// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"context"
	"fmt"
	"strconv"

	"github.com/twmb/franz-go/pkg/kmsg"
)

// ConfigEntry represents a single configuration entry.
type ConfigEntry struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Source    string `json:"source"`
	Sensitive bool   `json:"sensitive"`
	ReadOnly  bool   `json:"read_only"`
}

// BrokerConfig holds configuration for a single broker.
type BrokerConfig struct {
	BrokerID int32         `json:"broker_id"`
	Configs  []ConfigEntry `json:"configs"`
}

// TopicConfig holds configuration for a single topic.
type TopicConfig struct {
	TopicName string        `json:"topic_name"`
	Configs   []ConfigEntry `json:"configs"`
}

// ClusterConfigs holds all retrieved configurations.
type ClusterConfigs struct {
	BrokerConfigs []BrokerConfig `json:"broker_configs"`
	TopicConfigs  []TopicConfig  `json:"topic_configs"`
}

// securityRelevantBrokerConfigs lists broker configs important for security analysis.
var securityRelevantBrokerConfigs = []string{
	// Authentication
	"security.inter.broker.protocol",
	"sasl.enabled.mechanisms",
	"sasl.mechanism.inter.broker.protocol",
	"listener.security.protocol.map",
	"listeners",
	"advertised.listeners",
	"inter.broker.listener.name",

	// Authorization
	"authorizer.class.name",
	"super.users",
	"allow.everyone.if.no.acl.found",

	// SSL/TLS
	"ssl.client.auth",
	"ssl.protocol",
	"ssl.enabled.protocols",
	"ssl.keystore.type",
	"ssl.truststore.type",
	"ssl.endpoint.identification.algorithm",

	// Topic management
	"auto.create.topics.enable",
	"delete.topic.enable",
	"default.replication.factor",
	"min.insync.replicas",

	// Network
	"max.connections",
	"max.connections.per.ip",
	"connections.max.idle.ms",

	// Logging and audit
	"log.message.timestamp.type",

	// Zookeeper (if applicable)
	"zookeeper.set.acl",
}

// securityRelevantTopicConfigs lists topic configs important for security analysis.
var securityRelevantTopicConfigs = []string{
	"min.insync.replicas",
	"unclean.leader.election.enable",
	"retention.ms",
	"retention.bytes",
	"max.message.bytes",
	"message.timestamp.type",
	"compression.type",
	"cleanup.policy",
}

// GetBrokerConfigs retrieves configuration for all brokers in the cluster.
func (c *Client) GetBrokerConfigs(ctx context.Context) ([]BrokerConfig, error) {
	// First, get the list of brokers
	brokers, err := c.admin.ListBrokers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list brokers: %w", err)
	}

	var brokerConfigs []BrokerConfig

	for _, broker := range brokers {
		configs, err := c.describeBrokerConfig(ctx, broker.NodeID)
		if err != nil {
			// Log warning but continue with other brokers
			continue
		}

		brokerConfigs = append(brokerConfigs, BrokerConfig{
			BrokerID: broker.NodeID,
			Configs:  configs,
		})
	}

	return brokerConfigs, nil
}

// describeBrokerConfig retrieves configuration for a specific broker.
func (c *Client) describeBrokerConfig(ctx context.Context, brokerID int32) ([]ConfigEntry, error) {
	req := kmsg.NewDescribeConfigsRequest()
	resource := kmsg.NewDescribeConfigsRequestResource()
	resource.ResourceType = kmsg.ConfigResourceTypeBroker
	resource.ResourceName = strconv.Itoa(int(brokerID))
	resource.ConfigNames = securityRelevantBrokerConfigs
	req.Resources = append(req.Resources, resource)

	resp, err := req.RequestWith(ctx, c.client)
	if err != nil {
		return nil, fmt.Errorf("failed to describe broker config: %w", err)
	}

	var configs []ConfigEntry
	for _, res := range resp.Resources {
		if res.ErrorCode != 0 {
			continue
		}
		for _, cfg := range res.Configs {
			configs = append(configs, ConfigEntry{
				Name:      cfg.Name,
				Value:     valueOrDefault(cfg.Value),
				Source:    configSourceString(cfg.Source),
				Sensitive: cfg.IsSensitive,
				ReadOnly:  cfg.ReadOnly,
			})
		}
	}

	return configs, nil
}

// GetTopicConfigs retrieves configuration for all topics in the cluster.
func (c *Client) GetTopicConfigs(ctx context.Context) ([]TopicConfig, error) {
	// First, get the list of topics
	topics, err := c.admin.ListTopics(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list topics: %w", err)
	}

	var topicConfigs []TopicConfig

	// Build request for all topics
	req := kmsg.NewDescribeConfigsRequest()
	for topicName := range topics {
		resource := kmsg.NewDescribeConfigsRequestResource()
		resource.ResourceType = kmsg.ConfigResourceTypeTopic
		resource.ResourceName = topicName
		resource.ConfigNames = securityRelevantTopicConfigs
		req.Resources = append(req.Resources, resource)
	}

	if len(req.Resources) == 0 {
		return topicConfigs, nil
	}

	resp, err := req.RequestWith(ctx, c.client)
	if err != nil {
		return nil, fmt.Errorf("failed to describe topic configs: %w", err)
	}

	for _, res := range resp.Resources {
		if res.ErrorCode != 0 {
			continue
		}

		var configs []ConfigEntry
		for _, cfg := range res.Configs {
			configs = append(configs, ConfigEntry{
				Name:      cfg.Name,
				Value:     valueOrDefault(cfg.Value),
				Source:    configSourceString(cfg.Source),
				Sensitive: cfg.IsSensitive,
				ReadOnly:  cfg.ReadOnly,
			})
		}

		topicConfigs = append(topicConfigs, TopicConfig{
			TopicName: res.ResourceName,
			Configs:   configs,
		})
	}

	return topicConfigs, nil
}

// GetClusterConfigs retrieves both broker and topic configurations.
func (c *Client) GetClusterConfigs(ctx context.Context) (*ClusterConfigs, error) {
	brokerConfigs, err := c.GetBrokerConfigs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get broker configs: %w", err)
	}

	topicConfigs, err := c.GetTopicConfigs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get topic configs: %w", err)
	}

	return &ClusterConfigs{
		BrokerConfigs: brokerConfigs,
		TopicConfigs:  topicConfigs,
	}, nil
}

// valueOrDefault returns the config value or a placeholder for nil values.
func valueOrDefault(v *string) string {
	if v == nil {
		return "<null>"
	}
	return *v
}

// configSourceString converts a config source to a human-readable string.
func configSourceString(source kmsg.ConfigSource) string {
	switch source {
	case kmsg.ConfigSourceUnknown:
		return "UNKNOWN"
	case kmsg.ConfigSourceDynamicTopicConfig:
		return "DYNAMIC_TOPIC"
	case kmsg.ConfigSourceDynamicBrokerConfig:
		return "DYNAMIC_BROKER"
	case kmsg.ConfigSourceDynamicDefaultBrokerConfig:
		return "DYNAMIC_DEFAULT_BROKER"
	case kmsg.ConfigSourceStaticBrokerConfig:
		return "STATIC_BROKER"
	case kmsg.ConfigSourceDefaultConfig:
		return "DEFAULT"
	case kmsg.ConfigSourceDynamicBrokerLoggerConfig:
		return "DYNAMIC_BROKER_LOGGER"
	default:
		return "UNKNOWN"
	}
}
