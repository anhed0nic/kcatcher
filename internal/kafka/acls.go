// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"context"
	"fmt"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kmsg"
)

// ACLEntry represents a single ACL.
type ACLEntry struct {
	ResourceType   string
	ResourceName   string
	PatternType    string
	Principal      string
	Host           string
	Operation      string
	PermissionType string
}

// GetACLs retrieves all ACLs from the cluster.
func (c *Client) GetACLs(ctx context.Context) ([]ACLEntry, error) {
	// Build a filter that matches all ACLs
	builder := kadm.NewACLs().
		AnyResource().
		ResourcePatternType(kadm.ACLPatternAny).
		Operations(kadm.OpAny).
		Allow().
		Deny()

	results, err := c.admin.DescribeACLs(ctx, builder)
	if err != nil {
		return nil, fmt.Errorf("failed to describe ACLs: %w", err)
	}

	var entries []ACLEntry
	for _, result := range results {
		if result.Err != nil {
			return nil, fmt.Errorf("ACL describe error: %w", result.Err)
		}

		for _, acl := range result.Described {
			entries = append(entries, ACLEntry{
				ResourceType:   aclResourceTypeString(acl.Type),
				ResourceName:   acl.Name,
				PatternType:    aclPatternString(acl.Pattern),
				Principal:      acl.Principal,
				Host:           acl.Host,
				Operation:      aclOperationString(acl.Operation),
				PermissionType: aclPermissionString(acl.Permission),
			})
		}
	}

	return entries, nil
}

// aclResourceTypeString converts ACL resource type to string.
func aclResourceTypeString(t kmsg.ACLResourceType) string {
	switch t {
	case kmsg.ACLResourceTypeTopic:
		return "Topic"
	case kmsg.ACLResourceTypeGroup:
		return "Group"
	case kmsg.ACLResourceTypeCluster:
		return "Cluster"
	case kmsg.ACLResourceTypeTransactionalId:
		return "TransactionalID"
	case kmsg.ACLResourceTypeDelegationToken:
		return "DelegationToken"
	default:
		return "Unknown"
	}
}

// aclPatternString converts ACL pattern type to string.
func aclPatternString(p kadm.ACLPattern) string {
	switch p {
	case kadm.ACLPatternLiteral:
		return "Literal"
	case kadm.ACLPatternPrefixed:
		return "Prefixed"
	case kadm.ACLPatternAny:
		return "Any"
	case kadm.ACLPatternMatch:
		return "Match"
	default:
		return "Unknown"
	}
}

// aclOperationString converts ACL operation to string.
func aclOperationString(o kadm.ACLOperation) string {
	switch o {
	case kadm.OpRead:
		return "Read"
	case kadm.OpWrite:
		return "Write"
	case kadm.OpCreate:
		return "Create"
	case kadm.OpDelete:
		return "Delete"
	case kadm.OpAlter:
		return "Alter"
	case kadm.OpDescribe:
		return "Describe"
	case kadm.OpClusterAction:
		return "ClusterAction"
	case kadm.OpDescribeConfigs:
		return "DescribeConfigs"
	case kadm.OpAlterConfigs:
		return "AlterConfigs"
	case kadm.OpIdempotentWrite:
		return "IdempotentWrite"
	case kadm.OpAll:
		return "All"
	case kadm.OpAny:
		return "Any"
	default:
		return "Unknown"
	}
}

// aclPermissionString converts ACL permission type to string.
func aclPermissionString(p kmsg.ACLPermissionType) string {
	switch p {
	case kmsg.ACLPermissionTypeAllow:
		return "Allow"
	case kmsg.ACLPermissionTypeDeny:
		return "Deny"
	default:
		return "Unknown"
	}
}
