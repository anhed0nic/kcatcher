// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"net"
	"regexp"
	"strings"

	e "github.com/RoseSecurity/kcatcher/pkg/errors"
)

// hostnameRegex matches valid hostnames and FQDNs.
var hostnameRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)

// ValidateBrokers validates that all provided broker addresses are valid.
func ValidateBrokers(brokers []string) error {
	if len(brokers) == 0 {
		return e.ErrNoBrokers
	}

	for _, broker := range brokers {
		if !isValidBroker(broker) {
			return e.ErrInvalidBroker
		}
	}

	return nil
}

// isValidBroker checks if a broker string is a valid IP, hostname, or FQDN.
func isValidBroker(broker string) bool {
	broker = strings.TrimSpace(broker)
	if broker == "" {
		return false
	}

	// Check if it's a valid IP address
	if ip := net.ParseIP(broker); ip != nil {
		return true
	}

	// Check if it's a valid hostname/FQDN
	if len(broker) > 253 {
		return false
	}

	return hostnameRegex.MatchString(broker)
}
