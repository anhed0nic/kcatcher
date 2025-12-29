// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

// package main acts as the entrypoint for kcatcher.
package main

import (
	"fmt"
	"os"

	"github.com/RoseSecurity/kcatcher/cmd"
)

// main is the entrypoint for kcatcher.
// The Execute function runs the root command and returns the error to main to surface to the user.
func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
