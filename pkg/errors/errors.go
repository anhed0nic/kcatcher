// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package errors

import "errors"

var (
	ErrNoBrokers     = errors.New("no brokers provided; use --brokers/-b to specify")
	ErrInvalidBroker = errors.New("invalid broker address; must be IP, hostname, or FQDN")
)
