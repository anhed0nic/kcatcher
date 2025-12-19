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
}

// Cfg is the global configuration instance.
var Cfg Config

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Brokers: []string{},
		Port:    9092,
		Timeout: 10 * time.Second,
	}
}
