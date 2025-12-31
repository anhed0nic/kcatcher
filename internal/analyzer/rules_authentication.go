// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"fmt"
	"strings"

	"github.com/RoseSecurity/kcatcher/internal/kafka"
)

// NoAuthenticationRule checks if no SASL mechanism is configured.
type NoAuthenticationRule struct {
	BaseRule
}

func (r *NoAuthenticationRule) ID() string      { return "AUTH001" }
func (r *NoAuthenticationRule) Name() string    { return "No Authentication Configured" }
func (r *NoAuthenticationRule) Severity() Severity { return SeverityCritical }
func (r *NoAuthenticationRule) Category() Category { return CategoryAuthentication }

func (r *NoAuthenticationRule) Description() string {
	return "Checks if SASL authentication mechanisms are configured for the cluster"
}

func (r *NoAuthenticationRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding

	for _, broker := range ctx.Configs.BrokerConfigs {
		saslMechanisms := getConfigValue(broker.Configs, "sasl.enabled.mechanisms")
		securityProtocol := getConfigValue(broker.Configs, "security.inter.broker.protocol")

		// Check if SASL is not configured
		if saslMechanisms == "" || saslMechanisms == "<null>" {
			// Also check if security protocol indicates no auth
			if securityProtocol == "" || securityProtocol == "<null>" ||
				securityProtocol == "PLAINTEXT" {
				finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
					WithDescription("Broker %d has no SASL authentication mechanisms configured. "+
						"This allows unauthenticated access to the Kafka cluster.", broker.BrokerID).
					WithResource("broker", fmt.Sprintf("%d", broker.BrokerID)).
					WithValues(saslMechanisms, "SCRAM-SHA-512, OAUTHBEARER, or GSSAPI").
					WithRemediation("Configure SASL authentication by setting 'sasl.enabled.mechanisms' "+
						"and updating 'security.inter.broker.protocol' to SASL_SSL or SASL_PLAINTEXT.").
					WithReferences(
						"https://kafka.apache.org/documentation/#security_sasl",
						"https://kafka.apache.org/documentation/#brokerconfigs_sasl.enabled.mechanisms",
					)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// PlaintextListenerRule checks for listeners using PLAINTEXT protocol.
type PlaintextListenerRule struct {
	BaseRule
}

func (r *PlaintextListenerRule) ID() string      { return "AUTH002" }
func (r *PlaintextListenerRule) Name() string    { return "Plaintext Listener Detected" }
func (r *PlaintextListenerRule) Severity() Severity { return SeverityCritical }
func (r *PlaintextListenerRule) Category() Category { return CategoryAuthentication }

func (r *PlaintextListenerRule) Description() string {
	return "Checks if any listeners are configured to use the PLAINTEXT protocol"
}

func (r *PlaintextListenerRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding

	for _, broker := range ctx.Configs.BrokerConfigs {
		listeners := getConfigValue(broker.Configs, "listeners")
		listenerSecurityMap := getConfigValue(broker.Configs, "listener.security.protocol.map")

		// Check listeners config directly
		if listeners != "" && listeners != "<null>" {
			if strings.Contains(strings.ToUpper(listeners), "PLAINTEXT://") {
				finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
					WithDescription("Broker %d has listeners configured with PLAINTEXT protocol. "+
						"Traffic is unencrypted and credentials (if any) are sent in clear text.", broker.BrokerID).
					WithResource("broker", fmt.Sprintf("%d", broker.BrokerID)).
					WithValues(listeners, "SSL:// or SASL_SSL://").
					WithRemediation("Update listener configuration to use SSL or SASL_SSL protocol. "+
						"Configure SSL certificates and update 'listeners' to use secure protocols.").
					WithReferences(
						"https://kafka.apache.org/documentation/#brokerconfigs_listeners",
						"https://kafka.apache.org/documentation/#security_ssl",
					)
				findings = append(findings, finding)
			}
		}

		// Also check the security protocol map
		if listenerSecurityMap != "" && listenerSecurityMap != "<null>" {
			if strings.Contains(strings.ToUpper(listenerSecurityMap), "PLAINTEXT") {
				// Only add if we haven't already flagged the listeners
				if len(findings) == 0 || findings[len(findings)-1].Resource != fmt.Sprintf("%d", broker.BrokerID) {
					finding := NewFinding(r.ID(), "Plaintext Protocol in Listener Map", r.Severity(), r.Category()).
						WithDescription("Broker %d has listener security protocol map containing PLAINTEXT. "+
							"Some listeners may be accepting unencrypted traffic.", broker.BrokerID).
						WithResource("broker", fmt.Sprintf("%d", broker.BrokerID)).
						WithValues(listenerSecurityMap, "All listeners should use SSL or SASL_SSL").
						WithRemediation("Update 'listener.security.protocol.map' to use secure protocols for all listeners.").
						WithReferences(
							"https://kafka.apache.org/documentation/#brokerconfigs_listener.security.protocol.map",
						)
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

// WeakSASLRule checks for weak SASL mechanisms like PLAIN without SSL.
type WeakSASLRule struct {
	BaseRule
}

func (r *WeakSASLRule) ID() string      { return "AUTH003" }
func (r *WeakSASLRule) Name() string    { return "Weak SASL Mechanism" }
func (r *WeakSASLRule) Severity() Severity { return SeverityHigh }
func (r *WeakSASLRule) Category() Category { return CategoryAuthentication }

func (r *WeakSASLRule) Description() string {
	return "Checks if weak SASL mechanisms are used without SSL encryption"
}

func (r *WeakSASLRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding

	for _, broker := range ctx.Configs.BrokerConfigs {
		saslMechanisms := getConfigValue(broker.Configs, "sasl.enabled.mechanisms")
		securityProtocol := getConfigValue(broker.Configs, "security.inter.broker.protocol")

		// Check if PLAIN mechanism is used
		if strings.Contains(strings.ToUpper(saslMechanisms), "PLAIN") {
			// Check if not using SSL
			if securityProtocol != "" && !strings.Contains(strings.ToUpper(securityProtocol), "SSL") {
				finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
					WithDescription("Broker %d uses SASL/PLAIN mechanism without SSL encryption. "+
						"Credentials are transmitted in clear text over the network.", broker.BrokerID).
					WithResource("broker", fmt.Sprintf("%d", broker.BrokerID)).
					WithValues(fmt.Sprintf("SASL: %s, Protocol: %s", saslMechanisms, securityProtocol),
						"SASL_SSL with SCRAM-SHA-512 or OAUTHBEARER").
					WithRemediation("Either upgrade to SASL_SSL protocol or use a stronger mechanism "+
						"like SCRAM-SHA-512. Never use SASL/PLAIN without SSL.").
					WithReferences(
						"https://kafka.apache.org/documentation/#security_sasl_plain",
					)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// getConfigValue is a helper to retrieve a config value by name from broker configs.
func getConfigValue(configs []kafka.ConfigEntry, name string) string {
	for _, cfg := range configs {
		if cfg.Name == name {
			return cfg.Value
		}
	}
	return ""
}
