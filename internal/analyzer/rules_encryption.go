// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"fmt"
	"strings"
)

// NoInterBrokerEncryptionRule checks if inter-broker communication is unencrypted.
type NoInterBrokerEncryptionRule struct {
	BaseRule
}

func (r *NoInterBrokerEncryptionRule) ID() string         { return "ENC001" }
func (r *NoInterBrokerEncryptionRule) Name() string       { return "No Inter-Broker Encryption" }
func (r *NoInterBrokerEncryptionRule) Severity() Severity { return SeverityHigh }
func (r *NoInterBrokerEncryptionRule) Category() Category { return CategoryEncryption }

func (r *NoInterBrokerEncryptionRule) Description() string {
	return "Checks if inter-broker communication uses encryption"
}

func (r *NoInterBrokerEncryptionRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding

	for _, broker := range ctx.Configs.BrokerConfigs {
		interBrokerProtocol := getConfigValue(broker.Configs, "security.inter.broker.protocol")

		if interBrokerProtocol != "" && interBrokerProtocol != "<null>" {
			if !strings.Contains(strings.ToUpper(interBrokerProtocol), "SSL") {
				finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
					WithDescription("Broker %d uses '%s' for inter-broker communication. "+
						"Data replicated between brokers is transmitted in clear text, "+
						"exposing sensitive data to network-level attacks.", broker.BrokerID, interBrokerProtocol).
					WithResource("broker", fmt.Sprintf("%d", broker.BrokerID)).
					WithValues(interBrokerProtocol, "SSL or SASL_SSL").
					WithRemediation("Configure 'security.inter.broker.protocol' to use SSL or SASL_SSL. "+
						"Ensure SSL certificates are properly configured for all brokers.").
					WithReferences(
						"https://kafka.apache.org/documentation/#brokerconfigs_security.inter.broker.protocol",
						"https://kafka.apache.org/documentation/#security_ssl",
					)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// WeakSSLProtocolRule checks for weak or deprecated SSL/TLS protocols.
type WeakSSLProtocolRule struct {
	BaseRule
}

func (r *WeakSSLProtocolRule) ID() string         { return "ENC002" }
func (r *WeakSSLProtocolRule) Name() string       { return "Weak SSL/TLS Protocol" }
func (r *WeakSSLProtocolRule) Severity() Severity { return SeverityHigh }
func (r *WeakSSLProtocolRule) Category() Category { return CategoryEncryption }

func (r *WeakSSLProtocolRule) Description() string {
	return "Checks if deprecated or weak SSL/TLS protocols are enabled"
}

var weakProtocols = []string{"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}

func (r *WeakSSLProtocolRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding

	for _, broker := range ctx.Configs.BrokerConfigs {
		sslProtocol := getConfigValue(broker.Configs, "ssl.protocol")
		sslEnabledProtocols := getConfigValue(broker.Configs, "ssl.enabled.protocols")

		// Check ssl.protocol
		for _, weak := range weakProtocols {
			if strings.EqualFold(sslProtocol, weak) {
				finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
					WithDescription("Broker %d has ssl.protocol set to '%s' which is deprecated and vulnerable. "+
						"This protocol has known security vulnerabilities.", broker.BrokerID, sslProtocol).
					WithResource("broker", fmt.Sprintf("%d", broker.BrokerID)).
					WithValues(sslProtocol, "TLSv1.2 or TLSv1.3").
					WithRemediation("Update 'ssl.protocol' to TLSv1.2 or TLSv1.3. "+
						"Disable all deprecated protocols in 'ssl.enabled.protocols'.").
					WithReferences(
						"https://kafka.apache.org/documentation/#brokerconfigs_ssl.protocol",
					)
				findings = append(findings, finding)
				break
			}
		}

		// Check ssl.enabled.protocols for weak protocols
		if sslEnabledProtocols != "" && sslEnabledProtocols != "<null>" {
			for _, weak := range weakProtocols {
				if strings.Contains(strings.ToUpper(sslEnabledProtocols), strings.ToUpper(weak)) {
					finding := NewFinding(r.ID(), "Weak Protocol in Enabled List", r.Severity(), r.Category()).
						WithDescription("Broker %d has '%s' in ssl.enabled.protocols which is deprecated. "+
							"Clients may negotiate a weak protocol.", broker.BrokerID, weak).
						WithResource("broker", fmt.Sprintf("%d", broker.BrokerID)).
						WithValues(sslEnabledProtocols, "TLSv1.2,TLSv1.3").
						WithRemediation("Remove deprecated protocols from 'ssl.enabled.protocols'. "+
							"Only enable TLSv1.2 and TLSv1.3.").
						WithReferences(
							"https://kafka.apache.org/documentation/#brokerconfigs_ssl.enabled.protocols",
						)
					findings = append(findings, finding)
					break
				}
			}
		}
	}

	return findings
}

// NoSSLClientAuthRule checks if SSL client authentication is disabled.
type NoSSLClientAuthRule struct {
	BaseRule
}

func (r *NoSSLClientAuthRule) ID() string         { return "ENC003" }
func (r *NoSSLClientAuthRule) Name() string       { return "SSL Client Authentication Disabled" }
func (r *NoSSLClientAuthRule) Severity() Severity { return SeverityMedium }
func (r *NoSSLClientAuthRule) Category() Category { return CategoryEncryption }

func (r *NoSSLClientAuthRule) Description() string {
	return "Checks if SSL client authentication (mTLS) is enabled"
}

func (r *NoSSLClientAuthRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding

	for _, broker := range ctx.Configs.BrokerConfigs {
		sslClientAuth := getConfigValue(broker.Configs, "ssl.client.auth")

		// Check if mTLS is not required
		if sslClientAuth == "none" {
			finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
				WithDescription("Broker %d has ssl.client.auth set to 'none'. "+
					"Clients are not required to present certificates, reducing the security posture.",
					broker.BrokerID).
				WithResource("broker", fmt.Sprintf("%d", broker.BrokerID)).
				WithValues(sslClientAuth, "required").
				WithRemediation("Set 'ssl.client.auth=required' to enforce mutual TLS (mTLS). "+
					"Ensure all clients have valid certificates.").
				WithReferences(
					"https://kafka.apache.org/documentation/#brokerconfigs_ssl.client.auth",
				)
			findings = append(findings, finding)
		}
	}

	return findings
}

// NoEndpointIdentificationRule checks if SSL endpoint identification is disabled.
type NoEndpointIdentificationRule struct {
	BaseRule
}

func (r *NoEndpointIdentificationRule) ID() string         { return "ENC004" }
func (r *NoEndpointIdentificationRule) Name() string       { return "SSL Endpoint Identification Disabled" }
func (r *NoEndpointIdentificationRule) Severity() Severity { return SeverityMedium }
func (r *NoEndpointIdentificationRule) Category() Category { return CategoryEncryption }

func (r *NoEndpointIdentificationRule) Description() string {
	return "Checks if SSL endpoint identification algorithm is configured"
}

func (r *NoEndpointIdentificationRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding

	for _, broker := range ctx.Configs.BrokerConfigs {
		endpointIdent := getConfigValue(broker.Configs, "ssl.endpoint.identification.algorithm")

		if endpointIdent == "" || endpointIdent == "<null>" {
			finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
				WithDescription("Broker %d has no SSL endpoint identification algorithm configured. "+
					"This makes the cluster vulnerable to man-in-the-middle attacks as server identity is not verified.",
					broker.BrokerID).
				WithResource("broker", fmt.Sprintf("%d", broker.BrokerID)).
				WithValues(endpointIdent, "https").
				WithRemediation("Set 'ssl.endpoint.identification.algorithm=https' to enable "+
					"hostname verification during SSL handshake.").
				WithReferences(
					"https://kafka.apache.org/documentation/#brokerconfigs_ssl.endpoint.identification.algorithm",
				)
			findings = append(findings, finding)
		}
	}

	return findings
}
