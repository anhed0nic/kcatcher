// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"fmt"
)

// WildcardPrincipalRule checks for ACLs with wildcard principals.
type WildcardPrincipalRule struct {
	BaseRule
}

func (r *WildcardPrincipalRule) ID() string         { return "ACL001" }
func (r *WildcardPrincipalRule) Name() string       { return "Wildcard Principal in ACL" }
func (r *WildcardPrincipalRule) Severity() Severity { return SeverityCritical }
func (r *WildcardPrincipalRule) Category() Category { return CategoryACL }

func (r *WildcardPrincipalRule) Description() string {
	return "Checks for ACLs that grant access to all principals using wildcards"
}

func (r *WildcardPrincipalRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.ACLs == nil {
		return nil
	}

	var findings []*Finding

	for _, acl := range ctx.ACLs {
		// Check for wildcard principal
		if acl.Principal == "User:*" || acl.Principal == "*" {
			if acl.PermissionType == "Allow" {
				finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
					WithDescription("ACL grants %s permission to ALL users (User:*) on %s '%s'. "+
						"This effectively bypasses authentication for this resource.",
						acl.Operation, acl.ResourceType, acl.ResourceName).
					WithResource(acl.ResourceType, acl.ResourceName).
					WithValues(acl.Principal, "Specific user principals").
					WithRemediation("Replace wildcard principal with specific user principals. "+
						"Create individual ACLs for each user or group that needs access.").
					WithReferences(
						"https://kafka.apache.org/documentation/#security_authz",
					)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// WildcardHostRule checks for ACLs with wildcard hosts.
type WildcardHostRule struct {
	BaseRule
}

func (r *WildcardHostRule) ID() string         { return "ACL002" }
func (r *WildcardHostRule) Name() string       { return "Wildcard Host in ACL" }
func (r *WildcardHostRule) Severity() Severity { return SeverityMedium }
func (r *WildcardHostRule) Category() Category { return CategoryACL }

func (r *WildcardHostRule) Description() string {
	return "Checks for ACLs that allow access from any host"
}

func (r *WildcardHostRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.ACLs == nil {
		return nil
	}

	var findings []*Finding

	for _, acl := range ctx.ACLs {
		// Check for wildcard host
		if acl.Host == "*" && acl.PermissionType == "Allow" {
			finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
				WithDescription("ACL for %s on %s '%s' allows access from any host (*). "+
					"Consider restricting to specific IP addresses or hostnames for defense in depth.",
					acl.Principal, acl.ResourceType, acl.ResourceName).
				WithResource(acl.ResourceType, acl.ResourceName).
				WithValues(acl.Host, "Specific IP addresses or hostnames").
				WithRemediation("Specify allowed hosts in ACLs to restrict network access. "+
					"Use IP addresses or hostnames of authorized clients.").
				WithReferences(
					"https://kafka.apache.org/documentation/#security_authz",
				)
			findings = append(findings, finding)
		}
	}

	return findings
}

// PermissiveOperationRule checks for ACLs granting ALL operations.
type PermissiveOperationRule struct {
	BaseRule
}

func (r *PermissiveOperationRule) ID() string         { return "ACL003" }
func (r *PermissiveOperationRule) Name() string       { return "Overly Permissive ACL" }
func (r *PermissiveOperationRule) Severity() Severity { return SeverityHigh }
func (r *PermissiveOperationRule) Category() Category { return CategoryACL }

func (r *PermissiveOperationRule) Description() string {
	return "Checks for ACLs that grant ALL operations on a resource"
}

func (r *PermissiveOperationRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.ACLs == nil {
		return nil
	}

	var findings []*Finding

	for _, acl := range ctx.ACLs {
		// Check for ALL operations permission
		if acl.Operation == "All" && acl.PermissionType == "Allow" {
			finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
				WithDescription("ACL grants ALL operations to %s on %s '%s'. "+
					"This violates the principle of least privilege.",
					acl.Principal, acl.ResourceType, acl.ResourceName).
				WithResource(acl.ResourceType, acl.ResourceName).
				WithValues("All", "Specific operations (Read, Write, etc.)").
				WithRemediation("Grant only the specific operations needed. "+
					"For example, producers need Write, consumers need Read and Describe.").
				WithReferences(
					"https://kafka.apache.org/documentation/#operations_resources_and_protocols",
				)
			findings = append(findings, finding)
		}
	}

	return findings
}

// ClusterWideACLRule checks for ACLs on the Cluster resource.
type ClusterWideACLRule struct {
	BaseRule
}

func (r *ClusterWideACLRule) ID() string         { return "ACL004" }
func (r *ClusterWideACLRule) Name() string       { return "Cluster-Wide ACL" }
func (r *ClusterWideACLRule) Severity() Severity { return SeverityMedium }
func (r *ClusterWideACLRule) Category() Category { return CategoryACL }

func (r *ClusterWideACLRule) Description() string {
	return "Reports ACLs on the Cluster resource for awareness"
}

func (r *ClusterWideACLRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.ACLs == nil {
		return nil
	}

	var findings []*Finding

	for _, acl := range ctx.ACLs {
		if acl.ResourceType == "Cluster" && acl.PermissionType == "Allow" {
			finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
				WithDescription("Cluster-level ACL grants %s %s permission to %s. "+
					"Cluster ACLs provide broad administrative access.",
					acl.Operation, acl.PermissionType, acl.Principal).
				WithResource("Cluster", "kafka-cluster").
				WithValues(fmt.Sprintf("%s: %s", acl.Principal, acl.Operation), "Limited cluster operations").
				WithRemediation("Review cluster-level ACLs and ensure only administrative users "+
					"have access. Consider more granular resource-level ACLs.").
				WithReferences(
					"https://kafka.apache.org/documentation/#operations_resources_and_protocols",
				)
			findings = append(findings, finding)
		}
	}

	return findings
}

// WildcardResourceRule checks for ACLs on wildcard resources.
type WildcardResourceRule struct {
	BaseRule
}

func (r *WildcardResourceRule) ID() string         { return "ACL005" }
func (r *WildcardResourceRule) Name() string       { return "Wildcard Resource in ACL" }
func (r *WildcardResourceRule) Severity() Severity { return SeverityHigh }
func (r *WildcardResourceRule) Category() Category { return CategoryACL }

func (r *WildcardResourceRule) Description() string {
	return "Checks for ACLs that apply to all resources of a type"
}

func (r *WildcardResourceRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.ACLs == nil {
		return nil
	}

	var findings []*Finding

	for _, acl := range ctx.ACLs {
		// Check for wildcard or prefixed resources granting broad access
		if acl.ResourceName == "*" && acl.PermissionType == "Allow" {
			finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
				WithDescription("ACL grants %s permission on ALL %s resources to %s. "+
					"This provides overly broad access.",
					acl.Operation, acl.ResourceType, acl.Principal).
				WithResource(acl.ResourceType, "*").
				WithValues("*", "Specific resource names").
				WithRemediation("Replace wildcard resource names with specific resource names. "+
					"Use prefixed patterns only when necessary.").
				WithReferences(
					"https://kafka.apache.org/documentation/#security_authz",
				)
			findings = append(findings, finding)
		}
	}

	return findings
}
