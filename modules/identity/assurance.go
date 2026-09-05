package identity

import (
	"bytes"
	"errors"
	"slices"
	"time"
)

var ErrInvalidAssurancePolicy = errors.New("invalid assurance policy")

// AssuranceLevel is the closed, ordered assurance vocabulary used after a
// primary proof has been validated. Its numeric ordering is part of the pure
// policy combiner, not a wire or database representation.
type AssuranceLevel uint8

const (
	AssurancePrimary AssuranceLevel = iota + 1
	AssuranceMFA
	AssurancePhishingResistant
)

// AssuranceEvidenceKind distinguishes ordinary factors from recovery. A
// recovery proof can repair access but can never become phishing-resistant.
type AssuranceEvidenceKind uint8

const (
	AssuranceEvidenceFactor AssuranceEvidenceKind = iota + 1
	AssuranceEvidenceRecovery
)

// AssuranceSource is closed to one of three mutually exclusive authorities:
// a local proof, one exact tenant provider binding, or one direct platform
// provider proof. DirectPlatform is explicit because a zero BindingID is not
// sufficient provenance by itself and must remain invalid for tenant proofs.
// ProviderID and BindingID are opaque typed identities at this package
// boundary; their UUIDv7 shape is checked before constructing a snapshot.
type AssuranceSource struct {
	Local          bool
	DirectPlatform bool
	ProviderID     EntityID
	BindingID      EntityID
}

// AssurancePolicy is one already-authorized immutable policy projection.
// Zero freshness means no additional age limit. EnrollmentDeadline applies
// only to the restricted enrollment continuation, never ordinary access.
type AssurancePolicy struct {
	ID                 EntityID
	Revision           int64
	Level              AssuranceLevel
	LocalRequired      bool
	Freshness          time.Duration
	EnrollmentDeadline *time.Time
}

type AssurancePolicyRevision struct {
	PolicyID EntityID
	Revision int64
}

// EffectiveAssuranceRequirement is the deterministic monotonic fold of the
// platform floor, tenant baseline, all live role/group policies, and action.
type EffectiveAssuranceRequirement struct {
	Level              AssuranceLevel
	LocalRequired      bool
	Freshness          time.Duration
	EnrollmentDeadline *time.Time
	PolicyRevisions    []AssurancePolicyRevision
}

// AssuranceEvidence contains only normalized, revision-pinned proof facts.
// Raw amr/acr/AuthnContext values and factor payloads never enter this type.
type AssuranceEvidence struct {
	Level             AssuranceLevel
	Kind              AssuranceEvidenceKind
	Source            AssuranceSource
	AuthenticatedAt   time.Time
	ExpiresAt         *time.Time
	FactorRevision    *int64
	TrustRuleRevision *int64
}

type AssuranceDecision string

const (
	AssuranceSatisfied       AssuranceDecision = "satisfied"
	AssuranceStepUpRequired  AssuranceDecision = "step_up_required"
	AssuranceEnrollmentOnly  AssuranceDecision = "enrollment_only"
	AssuranceEnrollmentEnded AssuranceDecision = "enrollment_expired"
	AssuranceDenied          AssuranceDecision = "denied"
)

// CombineAssurancePolicies rejects an empty or malformed policy set and folds
// every input without relying on caller ordering.
func CombineAssurancePolicies(policies []AssurancePolicy) (EffectiveAssuranceRequirement, error) {
	if len(policies) == 0 || len(policies) > 1_024 {
		return EffectiveAssuranceRequirement{}, ErrInvalidAssurancePolicy
	}
	result := EffectiveAssuranceRequirement{Level: AssurancePrimary}
	seen := make(map[EntityID]struct{}, len(policies))
	zeroID := EntityID{}
	for _, policy := range policies {
		if policy.ID == zeroID || !validAssuranceLevel(policy.Level) || policy.Revision < 1 ||
			policy.Freshness < 0 || policy.Freshness > 365*24*time.Hour {
			return EffectiveAssuranceRequirement{}, ErrInvalidAssurancePolicy
		}
		if _, duplicate := seen[policy.ID]; duplicate {
			return EffectiveAssuranceRequirement{}, ErrInvalidAssurancePolicy
		}
		seen[policy.ID] = struct{}{}
		if policy.EnrollmentDeadline != nil && !validAssuranceInstant(*policy.EnrollmentDeadline) {
			return EffectiveAssuranceRequirement{}, ErrInvalidAssurancePolicy
		}
		result.Level = max(result.Level, policy.Level)
		result.LocalRequired = result.LocalRequired || policy.LocalRequired
		if policy.Freshness > 0 && (result.Freshness == 0 || policy.Freshness < result.Freshness) {
			result.Freshness = policy.Freshness
		}
		if policy.EnrollmentDeadline != nil &&
			(result.EnrollmentDeadline == nil || policy.EnrollmentDeadline.Before(*result.EnrollmentDeadline)) {
			value := policy.EnrollmentDeadline.UTC()
			result.EnrollmentDeadline = &value
		}
		result.PolicyRevisions = append(result.PolicyRevisions, AssurancePolicyRevision{
			PolicyID: policy.ID, Revision: policy.Revision,
		})
	}
	slices.SortFunc(result.PolicyRevisions, func(left, right AssurancePolicyRevision) int {
		return bytes.Compare(left.PolicyID[:], right.PolicyID[:])
	})
	return result, nil
}

// EvaluateAssurance decides only the assurance boundary. Admission, identity,
// provider lifecycle, mapping, and authorization must already have been
// revalidated by the calling use case. Malformed or conflicting evidence
// denies instead of degrading to primary.
func EvaluateAssurance(
	now time.Time,
	requirement EffectiveAssuranceRequirement,
	evidence []AssuranceEvidence,
	hasEnrollableFactor bool,
) AssuranceDecision {
	if !validAssuranceInstant(now) || !validEffectiveAssuranceRequirement(requirement) ||
		len(evidence) > 1_024 {
		return AssuranceDenied
	}
	for _, proof := range evidence {
		if !validAssuranceEvidence(proof) {
			return AssuranceDenied
		}
	}
	for _, proof := range evidence {
		if proof.AuthenticatedAt.After(now) || proof.ExpiresAt != nil && !proof.ExpiresAt.After(now) {
			continue
		}
		if requirement.Freshness > 0 && now.Sub(proof.AuthenticatedAt) > requirement.Freshness {
			continue
		}
		if requirement.LocalRequired && !proof.Source.Local {
			continue
		}
		if proof.Kind == AssuranceEvidenceRecovery {
			continue
		}
		if proof.Level >= requirement.Level {
			return AssuranceSatisfied
		}
	}
	if hasEnrollableFactor {
		if requirement.EnrollmentDeadline == nil {
			return AssuranceStepUpRequired
		}
		if now.Before(*requirement.EnrollmentDeadline) {
			return AssuranceEnrollmentOnly
		}
		return AssuranceEnrollmentEnded
	}
	return AssuranceStepUpRequired
}

func validEffectiveAssuranceRequirement(value EffectiveAssuranceRequirement) bool {
	if !validAssuranceLevel(value.Level) || value.Freshness < 0 || value.Freshness > 365*24*time.Hour ||
		len(value.PolicyRevisions) == 0 || len(value.PolicyRevisions) > 1_024 ||
		value.EnrollmentDeadline != nil && !validAssuranceInstant(*value.EnrollmentDeadline) {
		return false
	}
	zeroID := EntityID{}
	for index, revision := range value.PolicyRevisions {
		if revision.PolicyID == zeroID || revision.Revision < 1 || index > 0 &&
			bytes.Compare(revision.PolicyID[:], value.PolicyRevisions[index-1].PolicyID[:]) <= 0 {
			return false
		}
	}
	return true
}

func validAssuranceEvidence(value AssuranceEvidence) bool {
	if !validAssuranceLevel(value.Level) || !validAssuranceInstant(value.AuthenticatedAt) ||
		value.ExpiresAt != nil && (!validAssuranceInstant(*value.ExpiresAt) ||
			!value.ExpiresAt.After(value.AuthenticatedAt)) {
		return false
	}
	if value.Kind != AssuranceEvidenceFactor && value.Kind != AssuranceEvidenceRecovery {
		return false
	}
	zeroID := EntityID{}
	source := value.Source
	local := source.Local && !source.DirectPlatform && source.ProviderID == zeroID && source.BindingID == zeroID
	tenantProvider := !source.Local && !source.DirectPlatform &&
		source.ProviderID != zeroID && source.BindingID != zeroID
	directPlatform := !source.Local && source.DirectPlatform &&
		source.ProviderID != zeroID && source.BindingID == zeroID
	if !local && !tenantProvider && !directPlatform {
		return false
	}
	if local {
		return value.FactorRevision != nil && *value.FactorRevision > 0 && value.TrustRuleRevision == nil
	}
	return value.TrustRuleRevision != nil && *value.TrustRuleRevision > 0 && value.FactorRevision == nil
}

func validAssuranceLevel(value AssuranceLevel) bool {
	return value >= AssurancePrimary && value <= AssurancePhishingResistant
}

func validAssuranceInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
}
