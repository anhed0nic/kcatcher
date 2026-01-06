// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

// Package cmd provides the CLI commands, arguments, and flags.
package cmd

import (
	"time"

	i "github.com/RoseSecurity/kcatcher/internal"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:          "kcatcher",
	Short:        "A utility for enumerating and evaluating secure Kafka configurations.",
	Long:         `A utility for enumerating and evaluating secure Kafka configurations.`,
	RunE:         i.EnumerateBrokers,
	SilenceUsage: true,
}

func init() {
	// Initialize with defaults
	i.Cfg = i.DefaultConfig()

	// Connection flags
	rootCmd.PersistentFlags().StringSliceVarP(&i.Cfg.Brokers, "brokers", "b", []string{}, "A list of Kafka brokers to enumerate.")
	rootCmd.PersistentFlags().IntVarP(&i.Cfg.Port, "port", "p", 9092, "The port to use when connecting to Kafka brokers.")
	rootCmd.PersistentFlags().DurationVarP(&i.Cfg.Timeout, "timeout", "t", 10*time.Second, "Connection timeout duration.")

	// Output format flag
	rootCmd.PersistentFlags().StringVarP(&i.Cfg.OutputFormat, "output", "o", "text", "Output format: text, json (default: text)")

	// Message sampling flags
	rootCmd.PersistentFlags().StringVar(&i.Cfg.SampleTopic, "sample-topic", "", "Topic to sample messages from")
	rootCmd.PersistentFlags().IntVar(&i.Cfg.SampleCount, "sample-count", 10, "Number of messages to sample (default: 10)")

	// ACL enumeration flag
	rootCmd.PersistentFlags().BoolVar(&i.Cfg.EnumerateACLs, "acls", false, "Enumerate all ACLs")

	// Configuration enumeration flag
	rootCmd.PersistentFlags().BoolVar(&i.Cfg.EnumerateConfigs, "configs", false, "Enumerate broker and topic configurations")

	// Security analysis flag
	rootCmd.PersistentFlags().BoolVar(&i.Cfg.RunAnalysis, "analyze", false, "Run security analysis on cluster configuration")

	// Metadata display flag
	rootCmd.PersistentFlags().BoolVar(&i.Cfg.ShowMetadata, "metadata", false, "Show cluster metadata (auto-enabled unless --analyze is used)")

	// HIPAA compliance mode flag
	rootCmd.PersistentFlags().BoolVar(&i.Cfg.HipaaMode, "hipaa-mode", false, "Enable HIPAA compliance mode: disables message sampling by default and adds PHI warnings")

	// Audit log flag
	rootCmd.PersistentFlags().StringVar(&i.Cfg.AuditLogFile, "audit-log", "", "Path to audit log file for logging security events")

	// Benchmark flag
	rootCmd.PersistentFlags().BoolVar(&i.Cfg.Benchmark, "benchmark", false, "Enable performance benchmarking")

	// SASL authentication flags
	rootCmd.PersistentFlags().StringVar(&i.Cfg.SASLMechanism, "sasl-mechanism", "", "SASL mechanism (SCRAM-SHA-256, SCRAM-SHA-512, PLAIN, etc.)")
	rootCmd.PersistentFlags().StringVar(&i.Cfg.SASLUsername, "sasl-username", "", "SASL username")
	rootCmd.PersistentFlags().StringVar(&i.Cfg.SASLPassword, "sasl-password", "", "SASL password")

	// SSL/TLS flags
	rootCmd.PersistentFlags().BoolVar(&i.Cfg.SSLEnabled, "ssl", false, "Enable SSL/TLS encryption")
	rootCmd.PersistentFlags().StringVar(&i.Cfg.SSLCertFile, "ssl-cert", "", "Path to SSL client certificate file")
	rootCmd.PersistentFlags().StringVar(&i.Cfg.SSLKeyFile, "ssl-key", "", "Path to SSL client key file")
	rootCmd.PersistentFlags().StringVar(&i.Cfg.SSLCAFile, "ssl-ca", "", "Path to SSL CA certificate file")
	rootCmd.PersistentFlags().BoolVar(&i.Cfg.MutualTLS, "mutual-tls", false, "Enable mutual TLS authentication (requires client cert)")

	// Keep generated docs clean.
	rootCmd.DisableAutoGenTag = true
}

// Execute the root command and return the error to main to surface to the user.
func Execute() error {
	return rootCmd.Execute()
}
