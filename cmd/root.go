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

	rootCmd.PersistentFlags().StringSliceVarP(&i.Cfg.Brokers, "brokers", "b", []string{}, "A list of Kafka brokers to enumerate.")
	rootCmd.PersistentFlags().IntVarP(&i.Cfg.Port, "port", "p", 9092, "The port to use when connecting to Kafka brokers.")
	rootCmd.PersistentFlags().DurationVarP(&i.Cfg.Timeout, "timeout", "t", 10*time.Second, "Connection timeout duration.")

	// Keep generated docs clean.
	rootCmd.DisableAutoGenTag = true
}

// Execute the root command and return the error to main to surface to the user.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		return err
	}

	return nil
}
