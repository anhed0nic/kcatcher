// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"fmt"
)

// NoAuthorizerRule checks if no authorizer is configured.
type NoAuthorizerRule struct {
	BaseRule
}

func (r *NoAuthorizerRule) ID() string         { return "AUTHZ001" }
func (r *NoAuthorizerRule) Name() string       { return "No Authorizer Configured" }
func (r *NoAuthorizerRule) Severity() Severity { return SeverityCritical }
func (r *NoAuthorizerRule) Category() Category { return CategoryAuthorization }

func (r *NoAuthorizerRule) Description() string {
	return "Checks if an authorizer class is configured for access control"
}

func (r *NoAuthorizerRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding

	for _, broker := range ctx.Configs.BrokerConfigs {
		authorizerClass := getConfigValue(broker.Configs, "authorizer.class.name")

		if authorizerClass == "" || authorizerClass == "<null>" {
			finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
				WithDescription("Broker %d has no authorizer configured. "+
					"Without an authorizer, ACLs cannot be enforced and all authenticated users "+
					"have full access to all resources.", broker.BrokerID).
				WithResource("broker", fmt.Sprintf("%d", broker.BrokerID)).
				WithValues(authorizerClass, "kafka.security.authorizer.AclAuthorizer").
				WithRemediation("Configure an authorizer by setting 'authorizer.class.name' to "+
					"'kafka.security.authorizer.AclAuthorizer' (or a custom authorizer class).").
				WithReferences(
					"https://kafka.apache.org/documentation/#brokerconfigs_authorizer.class.name",
					"https://kafka.apache.org/documentation/#security_authz",
				)
			findings = append(findings, finding)
		}
	}

	return findings
}

// AllowEveryoneRule checks if allow.everyone.if.no.acl.found is enabled.
type AllowEveryoneRule struct {
	BaseRule
}

func (r *AllowEveryoneRule) ID() string         { return "AUTHZ002" }
func (r *AllowEveryoneRule) Name() string       { return "Allow Everyone If No ACL Found" }
func (r *AllowEveryoneRule) Severity() Severity { return SeverityCritical }
func (r *AllowEveryoneRule) Category() Category { return CategoryAuthorization }

func (r *AllowEveryoneRule) Description() string {
	return "Checks if 'allow.everyone.if.no.acl.found' is set to true"
}

func (r *AllowEveryoneRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding

	for _, broker := range ctx.Configs.BrokerConfigs {
		allowEveryone := getConfigValue(broker.Configs, "allow.everyone.if.no.acl.found")

		if allowEveryone == "true" {
			finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
				WithDescription("Broker %d has 'allow.everyone.if.no.acl.found' set to true. "+
					"This grants all authenticated users full access to any resource without an explicit ACL, "+
					"effectively bypassing authorization for unprotected resources.", broker.BrokerID).
				WithResource("broker", fmt.Sprintf("%d", broker.BrokerID)).
				WithValues("true", "false").
				WithRemediation("Set 'allow.everyone.if.no.acl.found=false' and create explicit ACLs "+
					"for all resources that need to be accessed. Use a deny-by-default approach.").
				WithReferences(
					"https://kafka.apache.org/documentation/#brokerconfigs_allow.everyone.if.no.acl.found",
				)
			findings = append(findings, finding)
		}
	}

	return findings
}

// SuperUsersExposedRule checks if super.users configuration is overly permissive.
type SuperUsersExposedRule struct {
	BaseRule
}

func (r *SuperUsersExposedRule) ID() string         { return "AUTHZ003" }
func (r *SuperUsersExposedRule) Name() string       { return "Super Users Configured" }
func (r *SuperUsersExposedRule) Severity() Severity { return SeverityMedium }
func (r *SuperUsersExposedRule) Category() Category { return CategoryAuthorization }

func (r *SuperUsersExposedRule) Description() string {
	return "Reports configured super users for awareness"
}

func (r *SuperUsersExposedRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.Configs == nil {
		return nil
	}

	var findings []*Finding

	for _, broker := range ctx.Configs.BrokerConfigs {
		superUsers := getConfigValue(broker.Configs, "super.users")

		if superUsers != "" && superUsers != "<null>" {
			finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
				WithDescription("Broker %d has super users configured: %s. "+
					"Super users bypass all ACL checks. Ensure this list is minimal and reviewed regularly.",
					broker.BrokerID, superUsers).
				WithResource("broker", fmt.Sprintf("%d", broker.BrokerID)).
				WithValues(superUsers, "Minimal list of required admin users").
				WithRemediation("Review the super.users list and ensure only essential administrative "+
					"principals are included. Consider using standard ACLs where possible.").
				WithReferences(
					"https://kafka.apache.org/documentation/#brokerconfigs_super.users",
				)
			findings = append(findings, finding)
		}
	}

	return findings
}
