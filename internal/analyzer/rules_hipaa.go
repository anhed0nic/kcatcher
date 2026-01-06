// Copyright (c) RoseSecurity
// SPDX-License-Identifier: Apache-2.0

package analyzer

// PhiExposureRiskRule checks if message sampling is enabled, which could expose PHI.
type PhiExposureRiskRule struct {
	BaseRule
}

func (r *PhiExposureRiskRule) ID() string         { return "PHI001" }
func (r *PhiExposureRiskRule) Name() string       { return "PHI Data Exposure Risk" }
func (r *PhiExposureRiskRule) Severity() Severity { return SeverityHigh }
func (r *PhiExposureRiskRule) Category() Category { return CategoryDataProtection }

func (r *PhiExposureRiskRule) Description() string {
	return "Checks if message sampling is enabled, which may expose protected health information"
}

func (r *PhiExposureRiskRule) Evaluate(ctx *AnalysisContext) []*Finding {
	if ctx.SampleTopic == "" {
		return nil
	}

	finding := NewFinding(r.ID(), r.Name(), r.Severity(), r.Category()).
		WithDescription("Message sampling is enabled for topic '%s'. This could expose protected health information (PHI) if the topic contains sensitive healthcare data. Ensure data is anonymized and access is compliant with HIPAA.", ctx.SampleTopic).
		WithResource("topic", ctx.SampleTopic).
		WithValues(ctx.SampleTopic, "disabled or anonymized").
		WithRemediation("Disable message sampling (--sample-topic) unless necessary, and ensure any sampled data is de-identified. Use --hipaa-mode for compliance warnings.").
		WithReferences(
			"https://www.hhs.gov/hipaa/for-professionals/privacy/guidance/protecting-patient-privacy/index.html",
		)

	return []*Finding{finding}
}