// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"fmt"
	"os"

	"github.com/RoseSecurity/kcatcher/internal/kafka"
	"github.com/RoseSecurity/kcatcher/internal/output"
	"github.com/RoseSecurity/kcatcher/pkg/utils"
	"github.com/spf13/cobra"
)

// EnumerateBrokers connects to Kafka brokers and lists cluster metadata.
func EnumerateBrokers(cmd *cobra.Command, args []string) error {
	if len(Cfg.Brokers) == 0 {
		fmt.Println()
		utils.PrintStyledText("kcatcher")
		cmd.Help() // Print help to explain the required flags
		return nil
	}

	// Validate brokers
	if err := utils.ValidateBrokers(Cfg.Brokers); err != nil {
		return err
	}

	// Format broker addresses with port
	brokerAddrs := make([]string, len(Cfg.Brokers))
	for i, broker := range Cfg.Brokers {
		brokerAddrs[i] = fmt.Sprintf("%s:%d", broker, Cfg.Port)
	}

	// Create Kafka client
	client, err := kafka.NewClient(brokerAddrs, Cfg.Timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to brokers: %w", err)
	}
	defer client.Close()

	// Get metadata
	ctx, cancel := context.WithTimeout(context.Background(), Cfg.Timeout)
	defer cancel()

	metadata, err := client.GetMetadata(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve metadata: %w", err)
	}

	// Format and output
	formatter := output.NewFormatter(os.Stdout)
	return formatter.Format(metadata)
}
