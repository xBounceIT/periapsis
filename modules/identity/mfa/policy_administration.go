package mfa

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const (
	MaximumPolicyFreshness = 365 * 24 * time.Hour
	MaximumPolicyTargets   = 512
)

var ErrInvalidPolicyAdministration = errors.New("invalid MFA policy administration value")

type PolicyStatus string

const (
	PolicyLive    PolicyStatus = "live"
	PolicyRetired PolicyStatus = "retired"
)

type PolicyChangeOperation string

const (
	PolicyPublish PolicyChangeOperation = "publish"
	PolicyRetire  PolicyChangeOperation = "retire"
)

// AdministrationTarget is the exact immutable target of one published policy.
// TenantID is absent only for the platform floor. A tenant target carries
// exactly one scope discriminator; unrelated IDs and actions are rejected.
type AdministrationTarget struct {
	Scope           PolicyScope
	TenantID        identity.EntityID
	RoleID          identity.EntityID
	SecurityGroupID identity.EntityID
	Action          string
}

// PolicyRequirement is the authoring representation of an assurance policy.
// Freshness is always an integral number of seconds on the public/persistence
// boundary; zero means that this policy adds no proof-age restriction.
type PolicyRequirement struct {
	Level              identity.AssuranceLevel
	LocalRequired      bool
	Freshness          time.Duration
	EnrollmentDeadline *time.Time
}

// PolicyDocument is one immutable publication revision. A mutation replay may
// return its original stored document after a newer publication or retirement,
// so callers must not reinterpret it as the current live projection.
type PolicyDocument struct {
	ID          identity.EntityID
	Revision    int64
	Target      AdministrationTarget
	Requirement PolicyRequirement
	Status      PolicyStatus
	CreatedAt   time.Time
	RetiredAt   *time.Time
}

type PolicySimulationContext struct {
	RoleIDs          []identity.EntityID
	SecurityGroupIDs []identity.EntityID
	Action           string
}

type PolicyRecoveryReason string

const (
	RecoveryNoEligibleDirectAdministrator PolicyRecoveryReason = "no_eligible_direct_administrator"
	RecoveryNoReadyLocalPrimary           PolicyRecoveryReason = "no_ready_local_primary"
	RecoveryNoReadyLocalMFA               PolicyRecoveryReason = "no_ready_local_mfa"
	RecoveryNoReadyLocalPhishingResistant PolicyRecoveryReason = "no_ready_local_phishing_resistant"
)

type PolicyRecoverySafety struct {
	Safe                         bool
	EligibleDirectAdministrators int64
	ReadyDirectAdministrators    int64
	ReasonCodes                  []PolicyRecoveryReason
}

type PolicySimulationCandidate struct {
	Target      AdministrationTarget
	Requirement PolicyRequirement
}

type PolicySimulationSourceKind string

const (
	PolicySimulationCurrentSource   PolicySimulationSourceKind = "current"
	PolicySimulationCandidateSource PolicySimulationSourceKind = "candidate"
)

type PolicySimulationSource struct {
	Source      PolicySimulationSourceKind
	PolicyID    identity.EntityID
	Revision    int64
	Target      AdministrationTarget
	Requirement PolicyRequirement
}

type PolicyEffectiveSimulation struct {
	Requirement *PolicyRequirement
	Sources     []PolicySimulationSource
}

type PolicySimulation struct {
	Operation PolicyChangeOperation
	Target    AdministrationTarget
	Context   *PolicySimulationContext
	Current   *PolicyDocument
	Candidate *PolicySimulationCandidate
	Effective PolicyEffectiveSimulation
	Recovery  PolicyRecoverySafety
}

// NormalizeAdministrationTarget validates and returns the canonical target for
// one authority boundary. expectedTenant is zero for platform administration
// and non-zero for tenant administration.
func NormalizeAdministrationTarget(
	value AdministrationTarget,
	expectedTenant identity.EntityID,
) (AdministrationTarget, error) {
	zero := identity.EntityID{}
	switch value.Scope {
	case PolicyPlatformFloor:
		if expectedTenant != zero || value.TenantID != zero || value.RoleID != zero ||
			value.SecurityGroupID != zero || value.Action != "" {
			return AdministrationTarget{}, ErrInvalidPolicyAdministration
		}
	case PolicyTenantBaseline:
		if expectedTenant == zero || value.TenantID != expectedTenant || value.RoleID != zero ||
			value.SecurityGroupID != zero || value.Action != "" {
			return AdministrationTarget{}, ErrInvalidPolicyAdministration
		}
	case PolicyRole:
		if expectedTenant == zero || value.TenantID != expectedTenant || value.RoleID == zero ||
			value.SecurityGroupID != zero || value.Action != "" {
			return AdministrationTarget{}, ErrInvalidPolicyAdministration
		}
	case PolicySecurityGroup:
		if expectedTenant == zero || value.TenantID != expectedTenant || value.RoleID != zero ||
			value.SecurityGroupID == zero || value.Action != "" {
			return AdministrationTarget{}, ErrInvalidPolicyAdministration
		}
	case PolicyAction:
		if expectedTenant == zero || value.TenantID != expectedTenant || value.RoleID != zero ||
			value.SecurityGroupID != zero || !validAudience(value.Action) {
			return AdministrationTarget{}, ErrInvalidPolicyAdministration
		}
	default:
		return AdministrationTarget{}, ErrInvalidPolicyAdministration
	}
	return value, nil
}

func NormalizePolicyRequirement(value PolicyRequirement) (PolicyRequirement, error) {
	if value.Level < identity.AssurancePrimary || value.Level > identity.AssurancePhishingResistant ||
		value.Freshness < 0 || value.Freshness > MaximumPolicyFreshness ||
		value.Freshness%time.Second != 0 {
		return PolicyRequirement{}, ErrInvalidPolicyAdministration
	}
	if value.EnrollmentDeadline != nil {
		deadline := *value.EnrollmentDeadline
		if !validPolicyInstant(deadline) {
			return PolicyRequirement{}, ErrInvalidPolicyAdministration
		}
		deadline = deadline.UTC()
		value.EnrollmentDeadline = &deadline
	}
	return value, nil
}

func ValidatePolicyDocument(value PolicyDocument, expectedTenant identity.EntityID) error {
	zero := identity.EntityID{}
	if value.ID == zero || !validStoredRevision(value.Revision) ||
		!validPolicyInstant(value.CreatedAt) {
		return ErrInvalidPolicyAdministration
	}
	if _, err := NormalizeAdministrationTarget(value.Target, expectedTenant); err != nil {
		return err
	}
	requirement, err := NormalizePolicyRequirement(value.Requirement)
	if err != nil || requirement.EnrollmentDeadline != nil &&
		!requirement.EnrollmentDeadline.After(value.CreatedAt) {
		return ErrInvalidPolicyAdministration
	}
	switch value.Status {
	case PolicyLive:
		if value.RetiredAt != nil {
			return ErrInvalidPolicyAdministration
		}
	case PolicyRetired:
		if value.RetiredAt == nil || !validPolicyInstant(*value.RetiredAt) ||
			value.RetiredAt.Before(value.CreatedAt) {
			return ErrInvalidPolicyAdministration
		}
	default:
		return ErrInvalidPolicyAdministration
	}
	return nil
}

func NormalizePolicySimulationContext(
	value PolicySimulationContext,
) (PolicySimulationContext, error) {
	roles, rolesOK := normalizeIDs(value.RoleIDs, MaximumPolicyTargets)
	groups, groupsOK := normalizeIDs(value.SecurityGroupIDs, MaximumPolicyTargets)
	if !rolesOK || !groupsOK || !validAudience(value.Action) {
		return PolicySimulationContext{}, ErrInvalidPolicyAdministration
	}
	value.RoleIDs = roles
	value.SecurityGroupIDs = groups
	return value, nil
}

func ValidatePolicyRecoverySafety(value PolicyRecoverySafety) error {
	if value.EligibleDirectAdministrators < 0 || value.ReadyDirectAdministrators < 0 ||
		value.ReadyDirectAdministrators > value.EligibleDirectAdministrators ||
		value.EligibleDirectAdministrators > int64(maximumStoredVersion) ||
		value.ReadyDirectAdministrators > int64(maximumStoredVersion) ||
		len(value.ReasonCodes) > 3 {
		return ErrInvalidPolicyAdministration
	}
	seen := make(map[PolicyRecoveryReason]struct{}, len(value.ReasonCodes))
	for _, reason := range value.ReasonCodes {
		if !validRecoveryReason(reason) {
			return ErrInvalidPolicyAdministration
		}
		if _, duplicate := seen[reason]; duplicate {
			return ErrInvalidPolicyAdministration
		}
		seen[reason] = struct{}{}
	}
	if value.ReadyDirectAdministrators > 0 {
		if !value.Safe || len(value.ReasonCodes) != 0 {
			return ErrInvalidPolicyAdministration
		}
		return nil
	}
	if value.Safe || len(value.ReasonCodes) == 0 {
		return ErrInvalidPolicyAdministration
	}
	if value.EligibleDirectAdministrators == 0 {
		if len(value.ReasonCodes) != 1 || value.ReasonCodes[0] != RecoveryNoEligibleDirectAdministrator {
			return ErrInvalidPolicyAdministration
		}
		return nil
	}
	for index, reason := range value.ReasonCodes {
		if reason == RecoveryNoEligibleDirectAdministrator || index > 0 && strings.Compare(
			string(value.ReasonCodes[index-1]), string(reason),
		) >= 0 {
			return ErrInvalidPolicyAdministration
		}
	}
	return nil
}

func ValidatePolicySimulation(value PolicySimulation, expectedTenant identity.EntityID) error {
	target, err := NormalizeAdministrationTarget(value.Target, expectedTenant)
	if err != nil || target != value.Target || ValidatePolicyRecoverySafety(value.Recovery) != nil {
		return ErrInvalidPolicyAdministration
	}
	if expectedTenant == (identity.EntityID{}) {
		if value.Context != nil {
			return ErrInvalidPolicyAdministration
		}
	} else {
		if value.Context == nil {
			return ErrInvalidPolicyAdministration
		}
		normalizedContext, contextErr := NormalizePolicySimulationContext(*value.Context)
		if contextErr != nil || !simulationContextsEqual(normalizedContext, *value.Context) {
			return ErrInvalidPolicyAdministration
		}
	}
	if value.Current != nil {
		if ValidatePolicyDocument(*value.Current, expectedTenant) != nil ||
			value.Current.Target != value.Target || value.Current.Status != PolicyLive {
			return ErrInvalidPolicyAdministration
		}
	}
	switch value.Operation {
	case PolicyPublish:
		if value.Candidate == nil || value.Candidate.Target != value.Target {
			return ErrInvalidPolicyAdministration
		}
		if _, err = NormalizePolicyRequirement(value.Candidate.Requirement); err != nil {
			return ErrInvalidPolicyAdministration
		}
	case PolicyRetire:
		if value.Current == nil || value.Candidate != nil {
			return ErrInvalidPolicyAdministration
		}
	default:
		return ErrInvalidPolicyAdministration
	}
	if value.Effective.Requirement == nil {
		if expectedTenant != (identity.EntityID{}) || value.Operation != PolicyRetire ||
			len(value.Effective.Sources) != 0 {
			return ErrInvalidPolicyAdministration
		}
	} else {
		if _, err = NormalizePolicyRequirement(*value.Effective.Requirement); err != nil ||
			len(value.Effective.Sources) == 0 || len(value.Effective.Sources) > 1024 ||
			value.Candidate != nil && !RequirementAtLeast(
				*value.Effective.Requirement, value.Candidate.Requirement,
			) {
			return ErrInvalidPolicyAdministration
		}
	}
	candidateSources := 0
	tenantBaselineSources := 0
	seenCurrentPolicies := make(map[identity.EntityID]struct{}, len(value.Effective.Sources))
	for index, source := range value.Effective.Sources {
		sourceTenant := expectedTenant
		if source.Target.Scope == PolicyPlatformFloor {
			sourceTenant = identity.EntityID{}
		}
		if _, err = NormalizeAdministrationTarget(source.Target, sourceTenant); err != nil ||
			!simulationTargetApplies(source.Target, expectedTenant, value.Context) {
			return ErrInvalidPolicyAdministration
		}
		if _, err = NormalizePolicyRequirement(source.Requirement); err != nil {
			return ErrInvalidPolicyAdministration
		}
		if source.Target.Scope == PolicyTenantBaseline {
			tenantBaselineSources++
		}
		if index > 0 && compareAdministrationTarget(
			value.Effective.Sources[index-1].Target, source.Target,
		) >= 0 {
			return ErrInvalidPolicyAdministration
		}
		switch source.Source {
		case PolicySimulationCurrentSource:
			if source.PolicyID == (identity.EntityID{}) || !validStoredRevision(source.Revision) {
				return ErrInvalidPolicyAdministration
			}
			if _, duplicate := seenCurrentPolicies[source.PolicyID]; duplicate {
				return ErrInvalidPolicyAdministration
			}
			seenCurrentPolicies[source.PolicyID] = struct{}{}
		case PolicySimulationCandidateSource:
			candidateSources++
			if source.PolicyID != (identity.EntityID{}) || source.Revision != 0 ||
				value.Candidate == nil || source.Target != value.Candidate.Target ||
				!policyRequirementsEqual(source.Requirement, value.Candidate.Requirement) {
				return ErrInvalidPolicyAdministration
			}
		default:
			return ErrInvalidPolicyAdministration
		}
	}
	if candidateSources != boolCount(value.Candidate != nil) ||
		expectedTenant != (identity.EntityID{}) && tenantBaselineSources != 1 {
		return ErrInvalidPolicyAdministration
	}
	folded, foldOK := foldPolicyRequirements(value.Effective.Sources)
	if !foldOK || value.Effective.Requirement == nil && folded != nil ||
		value.Effective.Requirement != nil && (folded == nil ||
			!policyRequirementsEqual(*value.Effective.Requirement, *folded)) {
		return ErrInvalidPolicyAdministration
	}
	return nil
}

// RequirementAtLeast reports whether effective is a monotonic strengthening
// of floor. Zero freshness and nil enrollment deadlines mean no restriction.
func RequirementAtLeast(effective, floor PolicyRequirement) bool {
	effective, effectiveErr := NormalizePolicyRequirement(effective)
	floor, floorErr := NormalizePolicyRequirement(floor)
	if effectiveErr != nil || floorErr != nil || effective.Level < floor.Level ||
		floor.LocalRequired && !effective.LocalRequired {
		return false
	}
	if floor.Freshness > 0 && (effective.Freshness == 0 || effective.Freshness > floor.Freshness) {
		return false
	}
	return floor.EnrollmentDeadline == nil || effective.EnrollmentDeadline != nil &&
		!effective.EnrollmentDeadline.After(*floor.EnrollmentDeadline)
}

func ClonePolicyDocument(value PolicyDocument) PolicyDocument {
	value.Requirement = clonePolicyRequirement(value.Requirement)
	if value.RetiredAt != nil {
		retiredAt := *value.RetiredAt
		value.RetiredAt = &retiredAt
	}
	return value
}

func ClonePolicyRecoverySafety(value PolicyRecoverySafety) PolicyRecoverySafety {
	value.ReasonCodes = append([]PolicyRecoveryReason(nil), value.ReasonCodes...)
	return value
}

func ClonePolicySimulation(value PolicySimulation) PolicySimulation {
	if value.Context != nil {
		contextValue := *value.Context
		contextValue.RoleIDs = append([]identity.EntityID(nil), value.Context.RoleIDs...)
		contextValue.SecurityGroupIDs = append([]identity.EntityID(nil), value.Context.SecurityGroupIDs...)
		value.Context = &contextValue
	}
	if value.Current != nil {
		current := ClonePolicyDocument(*value.Current)
		value.Current = &current
	}
	if value.Candidate != nil {
		candidate := *value.Candidate
		candidate.Requirement = clonePolicyRequirement(candidate.Requirement)
		value.Candidate = &candidate
	}
	if value.Effective.Requirement != nil {
		requirement := clonePolicyRequirement(*value.Effective.Requirement)
		value.Effective.Requirement = &requirement
	}
	value.Effective.Sources = append([]PolicySimulationSource(nil), value.Effective.Sources...)
	for index := range value.Effective.Sources {
		value.Effective.Sources[index].Requirement = clonePolicyRequirement(value.Effective.Sources[index].Requirement)
	}
	value.Recovery = ClonePolicyRecoverySafety(value.Recovery)
	return value
}

func ComparePolicyDocumentCursor(left, right PolicyDocument) int {
	if comparison := bytes.Compare(left.ID[:], right.ID[:]); comparison != 0 {
		return comparison
	}
	if left.Revision < right.Revision {
		return -1
	}
	if left.Revision > right.Revision {
		return 1
	}
	return 0
}

func compareAdministrationTarget(left, right AdministrationTarget) int {
	leftRank, leftOK := administrationScopeRank(left.Scope)
	rightRank, rightOK := administrationScopeRank(right.Scope)
	if !leftOK || !rightOK {
		return strings.Compare(string(left.Scope), string(right.Scope))
	}
	if leftRank != rightRank {
		if leftRank < rightRank {
			return -1
		}
		return 1
	}
	for _, pair := range [][2]identity.EntityID{
		{left.TenantID, right.TenantID},
		{left.SecurityGroupID, right.SecurityGroupID},
		{left.RoleID, right.RoleID},
	} {
		if comparison := bytes.Compare(pair[0][:], pair[1][:]); comparison != 0 {
			return comparison
		}
	}
	return strings.Compare(left.Action, right.Action)
}

func administrationScopeRank(scope PolicyScope) (int, bool) {
	switch scope {
	case PolicyPlatformFloor:
		return 0, true
	case PolicyTenantBaseline:
		return 1, true
	case PolicySecurityGroup:
		return 2, true
	case PolicyRole:
		return 3, true
	case PolicyAction:
		return 4, true
	default:
		return 0, false
	}
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

func clonePolicyRequirement(value PolicyRequirement) PolicyRequirement {
	if value.EnrollmentDeadline != nil {
		deadline := *value.EnrollmentDeadline
		value.EnrollmentDeadline = &deadline
	}
	return value
}

func validPolicyInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1970 &&
		value.Year() <= 9999 && value.Nanosecond()%1_000_000 == 0
}

func simulationContextsEqual(left, right PolicySimulationContext) bool {
	return left.Action == right.Action && slices.Equal(left.RoleIDs, right.RoleIDs) &&
		slices.Equal(left.SecurityGroupIDs, right.SecurityGroupIDs)
}

func simulationTargetApplies(
	target AdministrationTarget,
	tenantID identity.EntityID,
	context *PolicySimulationContext,
) bool {
	if tenantID == (identity.EntityID{}) {
		return target.Scope == PolicyPlatformFloor
	}
	if context == nil {
		return false
	}
	switch target.Scope {
	case PolicyPlatformFloor, PolicyTenantBaseline:
		return true
	case PolicySecurityGroup:
		return containsID(context.SecurityGroupIDs, target.SecurityGroupID)
	case PolicyRole:
		return containsID(context.RoleIDs, target.RoleID)
	case PolicyAction:
		return target.Action == context.Action
	default:
		return false
	}
}

func foldPolicyRequirements(sources []PolicySimulationSource) (*PolicyRequirement, bool) {
	if len(sources) == 0 {
		return nil, true
	}
	result := PolicyRequirement{Level: identity.AssurancePrimary}
	for _, source := range sources {
		requirement, err := NormalizePolicyRequirement(source.Requirement)
		if err != nil {
			return nil, false
		}
		result.Level = max(result.Level, requirement.Level)
		result.LocalRequired = result.LocalRequired || requirement.LocalRequired
		if requirement.Freshness > 0 && (result.Freshness == 0 || requirement.Freshness < result.Freshness) {
			result.Freshness = requirement.Freshness
		}
		if requirement.EnrollmentDeadline != nil &&
			(result.EnrollmentDeadline == nil || requirement.EnrollmentDeadline.Before(*result.EnrollmentDeadline)) {
			deadline := *requirement.EnrollmentDeadline
			result.EnrollmentDeadline = &deadline
		}
	}
	return &result, true
}

func policyRequirementsEqual(left, right PolicyRequirement) bool {
	return left.Level == right.Level && left.LocalRequired == right.LocalRequired &&
		left.Freshness == right.Freshness && (left.EnrollmentDeadline == nil && right.EnrollmentDeadline == nil ||
		left.EnrollmentDeadline != nil && right.EnrollmentDeadline != nil &&
			left.EnrollmentDeadline.Equal(*right.EnrollmentDeadline))
}

func validRecoveryReason(value PolicyRecoveryReason) bool {
	switch value {
	case RecoveryNoEligibleDirectAdministrator, RecoveryNoReadyLocalPrimary,
		RecoveryNoReadyLocalMFA, RecoveryNoReadyLocalPhishingResistant:
		return true
	default:
		return false
	}
}
