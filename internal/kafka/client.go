// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
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
	opts, err := buildClientOpts(brokers, timeout, auth)
	if err != nil {
		return nil, fmt.Errorf("failed to build client options: %w", err)
	}

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
func buildClientOpts(brokers []string, timeout time.Duration, auth *AuthConfig) ([]kgo.Opt, error) {
	opts := []kgo.Opt{
		kgo.SeedBrokers(brokers...),
	}

	// Only override timeouts when a positive timeout is provided.
	// When timeout is 0, we omit these options to inherit franz-go defaults.
	if timeout > 0 {
		opts = append(opts,
			kgo.DialTimeout(timeout),
			kgo.RequestTimeoutOverhead(timeout),
		)
	}

	// Add SASL authentication if configured
	if auth != nil && auth.SASLMechanism != "" {
		// Validate SASL credentials
		if auth.SASLUsername == "" || auth.SASLPassword == "" {
			return nil, fmt.Errorf("SASL authentication requires both username and password")
		}

		var saslMechanism kgo.Opt
		switch strings.ToUpper(auth.SASLMechanism) {
		case "PLAIN":
			saslMechanism = kgo.SASL(plain.Auth{
				User: auth.SASLUsername,
				Pass: auth.SASLPassword,
			}.AsMechanism())
		case "SCRAM-SHA-256":
			saslMechanism = kgo.SASL(scram.Auth{
				User: auth.SASLUsername,
				Pass: auth.SASLPassword,
			}.AsSha256Mechanism())
		case "SCRAM-SHA-512":
			saslMechanism = kgo.SASL(scram.Auth{
				User: auth.SASLUsername,
				Pass: auth.SASLPassword,
			}.AsSha512Mechanism())
		default:
			return nil, fmt.Errorf("unsupported SASL mechanism: %s", auth.SASLMechanism)
		}
		opts = append(opts, saslMechanism)
	}

	// Add SSL/TLS if enabled
	if auth != nil && auth.SSLEnabled {
		tlsConfig := &tls.Config{}
		if auth.SSLCertFile != "" && auth.SSLKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(auth.SSLCertFile, auth.SSLKeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load SSL certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
		if auth.SSLCAFile != "" {
			caCert, err := os.ReadFile(auth.SSLCAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read SSL CA file: %w", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse SSL CA certificate")
			}
			tlsConfig.RootCAs = caCertPool
		}
		// Note: ClientAuth is a server-side setting, not client-side
		// Mutual TLS is enabled by providing client certificates above
		opts = append(opts, kgo.DialTLSConfig(tlsConfig))
	}

	return opts, nil
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
