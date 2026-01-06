// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

// Client wraps the franz-go Kafka client for metadata operations.
type Client struct {
	client  *kgo.Client
	admin   *kadm.Client
	brokers []string
	auth    *AuthConfig
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	SASLMechanism string
	SASLUsername  string
	SASLPassword  string
	SSLEnabled    bool
	SSLCertFile   string
	SSLKeyFile    string
	SSLCAFile     string
	MutualTLS     bool
}

// NewClient creates a new Kafka client with the given broker addresses.
func NewClient(brokers []string, timeout time.Duration, auth *AuthConfig) (*Client, error) {
	opts := buildClientOpts(brokers, timeout, auth)

	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create kafka client: %w", err)
	}

	return &Client{
		client:  client,
		admin:   kadm.NewClient(client),
		brokers: brokers,
		auth:    auth,
	}, nil
}

// buildClientOpts builds kgo client options from config.
func buildClientOpts(brokers []string, timeout time.Duration, auth *AuthConfig) []kgo.Opt {
	opts := []kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.DialTimeout(timeout),
		kgo.RequestTimeoutOverhead(timeout),
	}

	// Add SASL authentication if configured
	if auth != nil && auth.SASLMechanism != "" {
		// For now, assume SCRAM or PLAIN
		// This is simplified; in real implementation, handle different mechanisms
		opts = append(opts, kgo.SASL(kgo.SASLType(auth.SASLMechanism), auth.SASLUsername, auth.SASLPassword))
	}

	// Add SSL/TLS if enabled
	if auth != nil && auth.SSLEnabled {
		tlsConfig := &tls.Config{}
		if auth.SSLCertFile != "" && auth.SSLKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(auth.SSLCertFile, auth.SSLKeyFile)
			if err != nil {
				// Handle error? For now, ignore or log
			} else {
				tlsConfig.Certificates = []tls.Certificate{cert}
			}
		}
		if auth.SSLCAFile != "" {
			caCert, err := os.ReadFile(auth.SSLCAFile)
			if err != nil {
				// Handle error
			} else {
				caCertPool := x509.NewCertPool()
				caCertPool.AppendCertsFromPEM(caCert)
				tlsConfig.RootCAs = caCertPool
			}
		}
		if auth.MutualTLS {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
		opts = append(opts, kgo.DialTLSConfig(tlsConfig))
	}

	return opts
}
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
