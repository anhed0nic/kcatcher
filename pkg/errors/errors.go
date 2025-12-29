// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"errors"
	"fmt"
)

var ErrNoBrokers = errors.New("no brokers provided; use --brokers/-b to specify")

// NewErrInvalidBroker creates an error indicating which broker address is invalid.
func NewErrInvalidBroker(broker string) error {
	return fmt.Errorf("invalid broker address %q; must be IP, hostname, or FQDN", broker)
}
