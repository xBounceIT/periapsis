// Package mfa composes MFA policy, step-up factors, and session assurance
// without owning HTTP or persistence adapters.
package mfa

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

var (
	ErrInvalidPolicySet      = errors.New("invalid MFA policy set")
	ErrInvalidStepUp         = errors.New("invalid MFA step-up request")
	ErrStepUpRejected        = errors.New("MFA step-up rejected")
	ErrStepUpPersistence     = errors.New("MFA step-up persistence failed")
	ErrFactorRejected        = errors.New("MFA factor rejected")
	ErrAssuranceInsufficient = errors.New("MFA assurance insufficient")
	ErrSessionRejected       = errors.New("session assurance rejected")
)

// PolicyScope fixes explicit precedence. Combination remains monotonic, so a
// later/more specific scope can strengthen but never weaken an earlier floor.
type PolicyScope uint8

const (
	PolicyPlatformFloor PolicyScope = iota + 1
	PolicyTenantBaseline
	PolicySecurityGroup
	PolicyRole
	PolicyAction
)

// ScopedPolicy is one immutable, already-authorized policy projection.
type ScopedPolicy struct {
	Scope    PolicyScope
	TenantID identity.EntityID
	TargetID identity.EntityID
	Action   string
	Policy   identity.AssurancePolicy
}

// PolicyContext is the exact prospective or live authority set for which the
// caller loaded policies. Unknown or unrelated targets reject the entire set.
type PolicyContext struct {
	TenantID         identity.EntityID
	RoleIDs          []identity.EntityID
	SecurityGroupIDs []identity.EntityID
	Action           string
}

type PolicyApplication struct {
	Scope    PolicyScope
	TargetID identity.EntityID
	PolicyID identity.EntityID
	Revision int64
}

type ResolvedPolicy struct {
	Requirement  identity.EffectiveAssuranceRequirement
	Applications []PolicyApplication
}

// ResolvePolicy validates explicit scope/target membership, sorts by
// platform->tenant->group->role->action precedence, then delegates the
// security fold to the canonical monotonic combiner.
func ResolvePolicy(context PolicyContext, policies []ScopedPolicy) (ResolvedPolicy, error) {
	roles, rolesOK := normalizeIDs(context.RoleIDs, 512)
	groups, groupsOK := normalizeIDs(context.SecurityGroupIDs, 512)
	zero := identity.EntityID{}
	if context.TenantID == zero || !validAudience(context.Action) || !rolesOK || !groupsOK ||
		len(policies) == 0 || len(policies) > 1024 {
		return ResolvedPolicy{}, ErrInvalidPolicySet
	}
	applications := make([]PolicyApplication, 0, len(policies))
	basePolicies := make([]identity.AssurancePolicy, 0, len(policies))
	seenTargets := make(map[policyTarget]struct{}, len(policies))
	hasTenantBaseline := false
	for _, scoped := range policies {
		if !policyApplies(context, roles, groups, scoped) || !validStoredRevision(scoped.Policy.Revision) {
			return ResolvedPolicy{}, ErrInvalidPolicySet
		}
		key := policyTarget{scope: scoped.Scope, tenantID: scoped.TenantID, targetID: scoped.TargetID, action: scoped.Action}
		if _, duplicate := seenTargets[key]; duplicate {
			return ResolvedPolicy{}, ErrInvalidPolicySet
		}
		seenTargets[key] = struct{}{}
		hasTenantBaseline = hasTenantBaseline || scoped.Scope == PolicyTenantBaseline
		basePolicies = append(basePolicies, scoped.Policy)
		applications = append(applications, PolicyApplication{
			Scope: scoped.Scope, TargetID: scoped.TargetID,
			PolicyID: scoped.Policy.ID, Revision: scoped.Policy.Revision,
		})
	}
	if !hasTenantBaseline {
		return ResolvedPolicy{}, ErrInvalidPolicySet
	}
	requirement, err := identity.CombineAssurancePolicies(basePolicies)
	if err != nil {
		return ResolvedPolicy{}, ErrInvalidPolicySet
	}
	slices.SortFunc(applications, comparePolicyApplications)
	return ResolvedPolicy{Requirement: requirement, Applications: applications}, nil
}

type policyTarget struct {
	scope    PolicyScope
	tenantID identity.EntityID
	targetID identity.EntityID
	action   string
}

func policyApplies(context PolicyContext, roles, groups []identity.EntityID, scoped ScopedPolicy) bool {
	zero := identity.EntityID{}
	switch scoped.Scope {
	case PolicyPlatformFloor:
		return scoped.TenantID == zero && scoped.TargetID == zero && scoped.Action == ""
	case PolicyTenantBaseline:
		return scoped.TenantID == context.TenantID && scoped.TargetID == zero && scoped.Action == ""
	case PolicySecurityGroup:
		return scoped.TenantID == context.TenantID && scoped.TargetID != zero && scoped.Action == "" &&
			containsID(groups, scoped.TargetID)
	case PolicyRole:
		return scoped.TenantID == context.TenantID && scoped.TargetID != zero && scoped.Action == "" &&
			containsID(roles, scoped.TargetID)
	case PolicyAction:
		return scoped.TenantID == context.TenantID && scoped.TargetID == zero && scoped.Action == context.Action
	default:
		return false
	}
}

func comparePolicyApplications(left, right PolicyApplication) int {
	if left.Scope != right.Scope {
		if left.Scope < right.Scope {
			return -1
		}
		return 1
	}
	if comparison := bytes.Compare(left.TargetID[:], right.TargetID[:]); comparison != 0 {
		return comparison
	}
	return bytes.Compare(left.PolicyID[:], right.PolicyID[:])
}

func normalizeIDs(values []identity.EntityID, maximum int) ([]identity.EntityID, bool) {
	if len(values) > maximum {
		return nil, false
	}
	result := append([]identity.EntityID(nil), values...)
	slices.SortFunc(result, func(left, right identity.EntityID) int { return bytes.Compare(left[:], right[:]) })
	zero := identity.EntityID{}
	for index, value := range result {
		if value == zero || index > 0 && value == result[index-1] {
			return nil, false
		}
	}
	return result, true
}

func containsID(values []identity.EntityID, target identity.EntityID) bool {
	_, found := slices.BinarySearchFunc(values, target, func(value, needle identity.EntityID) int {
		return bytes.Compare(value[:], needle[:])
	})
	return found
}

func validAudience(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func cloneRequirement(value identity.EffectiveAssuranceRequirement) identity.EffectiveAssuranceRequirement {
	value.PolicyRevisions = append([]identity.AssurancePolicyRevision(nil), value.PolicyRevisions...)
	if value.EnrollmentDeadline != nil {
		deadline := *value.EnrollmentDeadline
		value.EnrollmentDeadline = &deadline
	}
	return value
}

func validRequirement(now time.Time, value identity.EffectiveAssuranceRequirement) bool {
	for _, revision := range value.PolicyRevisions {
		if !validStoredRevision(revision.Revision) {
			return false
		}
	}
	return identity.EvaluateAssurance(now, value, nil, false) != identity.AssuranceDenied
}

func validEvidence(now time.Time, evidence []identity.AssuranceEvidence) bool {
	if len(evidence) > 1024 {
		return false
	}
	for _, proof := range evidence {
		if proof.FactorRevision != nil && !validStoredRevision(*proof.FactorRevision) ||
			proof.TrustRuleRevision != nil && !validStoredRevision(*proof.TrustRuleRevision) {
			return false
		}
	}
	requirement := identity.EffectiveAssuranceRequirement{
		Level:           identity.AssurancePrimary,
		PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: identity.EntityID{1}, Revision: 1}},
	}
	return identity.EvaluateAssurance(now, requirement, evidence, false) != identity.AssuranceDenied
}

func cloneEvidence(values []identity.AssuranceEvidence) []identity.AssuranceEvidence {
	result := append([]identity.AssuranceEvidence(nil), values...)
	for index := range result {
		if result[index].ExpiresAt != nil {
			expires := *result[index].ExpiresAt
			result[index].ExpiresAt = &expires
		}
		if result[index].FactorRevision != nil {
			revision := *result[index].FactorRevision
			result[index].FactorRevision = &revision
		}
		if result[index].TrustRuleRevision != nil {
			revision := *result[index].TrustRuleRevision
			result[index].TrustRuleRevision = &revision
		}
	}
	return result
}
