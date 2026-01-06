// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"github.com/RoseSecurity/kcatcher/internal/kafka"
	"github.com/RoseSecurity/kcatcher/internal/output"
)

// AnalysisContext holds all data available for security analysis.
type AnalysisContext struct {
	// Metadata contains broker and topic metadata.
	Metadata *output.MetadataOutput

	// Configs contains broker and topic configurations.
	Configs *kafka.ClusterConfigs

	// ACLs contains the access control list entries.
	ACLs []kafka.ACLEntry

	// SampleTopic indicates if message sampling is enabled.
	SampleTopic string
}

// Rule defines the interface for security rules.
type Rule interface {
	// ID returns the unique identifier for the rule.
	ID() string

	// Name returns a human-readable name for the rule.
	Name() string

	// Description returns a description of what the rule checks.
	Description() string

	// Severity returns the default severity for findings from this rule.
	Severity() Severity

	// Category returns the category this rule belongs to.
	Category() Category

	// Evaluate runs the rule against the context and returns any findings.
	Evaluate(ctx *AnalysisContext) []*Finding
}

// Engine is the security rules engine that runs all registered rules.
type Engine struct {
	rules []Rule
}

// NewEngine creates a new security analysis engine.
func NewEngine() *Engine {
	return &Engine{
		rules: make([]Rule, 0),
	}
}

// RegisterRule adds a rule to the engine.
func (e *Engine) RegisterRule(rule Rule) {
	e.rules = append(e.rules, rule)
}

// RegisterRules adds multiple rules to the engine.
func (e *Engine) RegisterRules(rules ...Rule) {
	e.rules = append(e.rules, rules...)
}

// Analyze runs all registered rules against the provided context.
func (e *Engine) Analyze(ctx *AnalysisContext) *AnalysisResult {
	var findings []*Finding

	for _, rule := range e.rules {
		ruleFindings := rule.Evaluate(ctx)
		findings = append(findings, ruleFindings...)
	}

	return NewAnalysisResult(findings)
}

// RuleCount returns the number of registered rules.
func (e *Engine) RuleCount() int {
	return len(e.rules)
}

// GetRules returns all registered rules.
func (e *Engine) GetRules() []Rule {
	return e.rules
}

// BaseRule provides a base implementation for rules.
type BaseRule struct {
	id          string
	name        string
	description string
	severity    Severity
	category    Category
}

// NewBaseRule creates a new BaseRule with the given parameters.
func NewBaseRule(id, name, description string, severity Severity, category Category) BaseRule {
	return BaseRule{
		id:          id,
		name:        name,
		description: description,
		severity:    severity,
		category:    category,
	}
}

// ID returns the rule ID.
func (r BaseRule) ID() string {
	return r.id
}

// Name returns the rule name.
func (r BaseRule) Name() string {
	return r.name
}

// Description returns the rule description.
func (r BaseRule) Description() string {
	return r.description
}

// Severity returns the rule severity.
func (r BaseRule) Severity() Severity {
	return r.severity
}

// Category returns the rule category.
func (r BaseRule) Category() Category {
	return r.category
}

// DefaultEngine creates an engine with all default security rules registered.
func DefaultEngine() *Engine {
	engine := NewEngine()

	// Register all default rules
	// Authentication rules
	engine.RegisterRules(
		&NoAuthenticationRule{},
		&PlaintextListenerRule{},
		&WeakSASLRule{},
	)

	// Authorization rules
	engine.RegisterRules(
		&NoAuthorizerRule{},
		&AllowEveryoneRule{},
		&SuperUsersExposedRule{},
	)

	// Encryption rules
	engine.RegisterRules(
		&NoInterBrokerEncryptionRule{},
		&WeakSSLProtocolRule{},
		&NoSSLClientAuthRule{},
		&NoEndpointIdentificationRule{},
		&EncryptionAtRestRule{},
	)

	// ACL rules
	engine.RegisterRules(
		&WildcardPrincipalRule{},
		&WildcardHostRule{},
		&PermissiveOperationRule{},
		&ClusterWideACLRule{},
		&WildcardResourceRule{},
	)

	// Topic configuration rules
	engine.RegisterRules(
		&AutoCreateTopicsRule{},
		&UncleanLeaderElectionRule{},
		&LowMinISRRule{},
		&ShortRetentionRule{},
		&DeleteTopicEnabledRule{},
	)

	// Data protection rules
	engine.RegisterRules(
		&PhiExposureRiskRule{},
	)

	return engine
}
