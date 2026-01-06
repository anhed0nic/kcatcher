// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package internal

import "time"

// Config holds the runtime configuration for kcatcher.
type Config struct {
	// Brokers is a list of Kafka broker addresses (IP, hostname, or FQDN).
	Brokers []string
	// Port is the Kafka broker port (default: 9092).
	Port int
	// Timeout is the connection/operation timeout.
	Timeout time.Duration

	// OutputFormat specifies the output format: "text" or "json".
	OutputFormat string

	// SampleTopic is the topic to sample messages from.
	SampleTopic string
	// SampleCount is the number of messages to sample.
	SampleCount int

	// EnumerateACLs enables ACL enumeration.
	EnumerateACLs bool

	// EnumerateConfigs enables broker and topic configuration retrieval.
	EnumerateConfigs bool

	// RunAnalysis enables security analysis of the cluster configuration.
	RunAnalysis bool

	// ShowMetadata explicitly shows metadata output (auto-enabled unless --analyze is used).
	ShowMetadata bool

	// HipaaMode enables HIPAA compliance mode, disabling message sampling by default and adding warnings.
	HipaaMode bool

	// AuditLogFile specifies a file to log audit events.
	AuditLogFile string

	// Benchmark enables performance benchmarking.
	Benchmark bool

	// SASL authentication
	SASLMechanism string
	SASLUsername  string
	SASLPassword  string

	// SSL/TLS
	SSLEnabled    bool
	SSLCertFile   string
	SSLKeyFile    string
	SSLCAFile     string
	MutualTLS     bool
}

// Cfg is the global configuration instance.
var Cfg Config

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Brokers:          []string{},
		Port:             9092,
		Timeout:          10 * time.Second,
		OutputFormat:     "text",
		SampleTopic:      "",
		SampleCount:      10,
		EnumerateACLs:    false,
		EnumerateConfigs: false,
		RunAnalysis:      false,
		ShowMetadata:     false,
		HipaaMode:        false,
		AuditLogFile:     "",
		Benchmark:        false,
		SASLMechanism:    "",
		SASLUsername:     "",
		SASLPassword:     "",
		SSLEnabled:       false,
		SSLCertFile:      "",
		SSLKeyFile:       "",
		SSLCAFile:        "",
		MutualTLS:        false,
	}
}
