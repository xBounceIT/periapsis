package identity

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalidFederatedMappingObservation = errors.New("invalid federated mapping observation")
	ErrInvalidFederatedPlanningSnapshot   = errors.New("invalid federated planning snapshot")
)

const (
	maximumFederatedMappingGroups     = 4_096
	maximumFederatedMappingScalars    = 64
	maximumFederatedMappingClaimBytes = 256
	maximumFederatedMappingValueBytes = 4_096
	maximumFederatedMappingValueRunes = 1_024
)

// FederatedMappingMatcherKind is intentionally distinct from LDAP DN/CN
// matchers. Values are exact normalized OIDC/SAML strings; no case folding,
// regex fallback, or DN synthesis is available.
type FederatedMappingMatcherKind uint8

const (
	FederatedMappingGroupEquals FederatedMappingMatcherKind = iota + 1
	FederatedMappingScalarEquals
)

type FederatedMappingMatcherSpec struct {
	Kind      FederatedMappingMatcherKind
	ClaimName string
	Value     string `json:"-"`
}

func (spec FederatedMappingMatcherSpec) String() string {
	return fmt.Sprintf(
		"identity.FederatedMappingMatcherSpec{kind:%d,claim:%t,value:[REDACTED]}",
		spec.Kind, spec.ClaimName != "",
	)
}
func (spec FederatedMappingMatcherSpec) GoString() string { return spec.String() }

type CompiledFederatedMappingMatcher struct {
	kind      FederatedMappingMatcherKind
	claimName string
	value     string
	valid     bool
}

func (matcher CompiledFederatedMappingMatcher) String() string {
	return fmt.Sprintf(
		"identity.CompiledFederatedMappingMatcher{kind:%d,claim:%t,value:[REDACTED],valid:%t}",
		matcher.kind, matcher.claimName != "", matcher.valid,
	)
}
func (matcher CompiledFederatedMappingMatcher) GoString() string { return matcher.String() }

func CompileFederatedMappingMatcher(
	spec FederatedMappingMatcherSpec,
) (CompiledFederatedMappingMatcher, error) {
	if !validFederatedMappingValue(spec.Value) {
		return CompiledFederatedMappingMatcher{}, ErrInvalidFederatedPlanningSnapshot
	}
	switch spec.Kind {
	case FederatedMappingGroupEquals:
		if spec.ClaimName != "" {
			return CompiledFederatedMappingMatcher{}, ErrInvalidFederatedPlanningSnapshot
		}
	case FederatedMappingScalarEquals:
		if !validFederatedClaimName(spec.ClaimName) {
			return CompiledFederatedMappingMatcher{}, ErrInvalidFederatedPlanningSnapshot
		}
	default:
		return CompiledFederatedMappingMatcher{}, ErrInvalidFederatedPlanningSnapshot
	}
	return CompiledFederatedMappingMatcher{
		kind: spec.Kind, claimName: spec.ClaimName, value: spec.Value, valid: true,
	}, nil
}

type FederatedMappingScalar struct {
	Name  string
	Value string `json:"-"`
}

func (value FederatedMappingScalar) String() string {
	return fmt.Sprintf(
		"identity.FederatedMappingScalar{name:%t,value:[REDACTED]}",
		value.Name != "",
	)
}
func (value FederatedMappingScalar) GoString() string { return value.String() }

type FederatedMappingObservationInput struct {
	Subject  Subject
	Profile  LDAPProfileValues
	Scalars  []FederatedMappingScalar
	Groups   []string `json:"-"`
	Complete bool
}

type FederatedMappingObservation struct {
	subject  Subject
	profile  LDAPProfileValues
	scalars  []FederatedMappingScalar
	groups   []string
	complete bool
	valid    bool
}

func NewFederatedMappingObservation(
	input FederatedMappingObservationInput,
) (FederatedMappingObservation, error) {
	if !validCanonicalSubject(input.Subject) || len(input.Scalars) > maximumFederatedMappingScalars ||
		len(input.Groups) > maximumFederatedMappingGroups {
		return FederatedMappingObservation{}, ErrInvalidFederatedMappingObservation
	}
	profile, err := normalizeLDAPProfile(input.Profile)
	if err != nil {
		return FederatedMappingObservation{}, ErrInvalidFederatedMappingObservation
	}
	scalars := append([]FederatedMappingScalar(nil), input.Scalars...)
	for _, scalar := range scalars {
		if !validFederatedClaimName(scalar.Name) || !validFederatedMappingValue(scalar.Value) {
			return FederatedMappingObservation{}, ErrInvalidFederatedMappingObservation
		}
	}
	slices.SortFunc(scalars, func(left, right FederatedMappingScalar) int {
		return strings.Compare(left.Name, right.Name)
	})
	for index := 1; index < len(scalars); index++ {
		if scalars[index-1].Name == scalars[index].Name {
			return FederatedMappingObservation{}, ErrInvalidFederatedMappingObservation
		}
	}
	groups := append([]string(nil), input.Groups...)
	for _, group := range groups {
		if !validFederatedMappingValue(group) {
			return FederatedMappingObservation{}, ErrInvalidFederatedMappingObservation
		}
	}
	slices.Sort(groups)
	groups = slices.Compact(groups)
	return FederatedMappingObservation{
		subject: Subject{format: input.Subject.format, value: append([]byte(nil), input.Subject.value...)},
		profile: cloneLDAPProfileValues(profile), scalars: scalars, groups: groups,
		complete: input.Complete, valid: true,
	}, nil
}

func (observation FederatedMappingObservation) String() string {
	return fmt.Sprintf(
		"identity.FederatedMappingObservation{subjectFormat:%d,profile:%s,scalars:%d,groups:%d,complete:%t,values:[REDACTED]}",
		observation.subject.Format(), observation.profile, len(observation.scalars), len(observation.groups),
		observation.complete,
	)
}
func (observation FederatedMappingObservation) GoString() string { return observation.String() }

type FederatedMappingRule struct {
	RuleID             EntityID
	RuleEpochID        EntityID
	SourceID           EntityID
	Revision           int64
	Priority           int32
	Enabled            bool
	Matcher            CompiledFederatedMappingMatcher
	Mode               LDAPReconciliationMode
	SecurityGroupID    EntityID
	RoleIDs            []EntityID
	OperatorTeam       *LDAPOperatorTeamTarget
	AdministrativeNote string
}

func (rule FederatedMappingRule) String() string {
	return fmt.Sprintf(
		"identity.FederatedMappingRule{revision:%d,priority:%d,enabled:%t,matcher:%s,mode:%d,roles:%d,operatorTeam:%t,note:[REDACTED]}",
		rule.Revision, rule.Priority, rule.Enabled, rule.Matcher, rule.Mode, len(rule.RoleIDs),
		rule.OperatorTeam != nil,
	)
}
func (rule FederatedMappingRule) GoString() string { return rule.String() }

// FederatedPlanningSnapshot shares every admission, delegation, source-edge,
// and reconciliation fact with LDAP. Only the typed matcher differs.
type FederatedPlanningSnapshot struct {
	TenantID                 EntityID
	Provider                 ProviderContext
	BindingID                EntityID
	ConfigurationRevision    int64
	RuleSetRevision          int64
	AuthorizationRevision    int64
	JITMode                  LDAPJITMode
	NoMatchPolicy            LDAPNoMatchPolicy
	EffectiveUntil           *time.Time
	ProviderAccess           LDAPProviderAccessState
	Rules                    []FederatedMappingRule
	SecurityGroups           []LDAPSecurityGroupPolicy
	LiveAssignments          []LDAPOperatorTeamAssignment
	RolePolicies             []LDAPRolePolicy
	ExistingEffectiveRoleIDs []EntityID
	Delegation               []LDAPDelegationGrant
	LiveOwnedEdges           []LDAPOwnedMappingEdge
}

// CloneFederatedPlanningSnapshot returns a fully independent snapshot for
// crossing an adapter/cache boundary without sharing mutable slices or time
// pointers with the planner.
func CloneFederatedPlanningSnapshot(value FederatedPlanningSnapshot) FederatedPlanningSnapshot {
	if value.EffectiveUntil != nil {
		copyValue := *value.EffectiveUntil
		value.EffectiveUntil = &copyValue
	}
	value.Rules = append([]FederatedMappingRule(nil), value.Rules...)
	for index := range value.Rules {
		value.Rules[index].RoleIDs = append([]EntityID(nil), value.Rules[index].RoleIDs...)
		if value.Rules[index].OperatorTeam != nil {
			copyValue := *value.Rules[index].OperatorTeam
			value.Rules[index].OperatorTeam = &copyValue
		}
	}
	value.SecurityGroups = append([]LDAPSecurityGroupPolicy(nil), value.SecurityGroups...)
	for index := range value.SecurityGroups {
		value.SecurityGroups[index].ActiveRoleIDs = append(
			[]EntityID(nil), value.SecurityGroups[index].ActiveRoleIDs...,
		)
	}
	value.LiveAssignments = append([]LDAPOperatorTeamAssignment(nil), value.LiveAssignments...)
	value.RolePolicies = append([]LDAPRolePolicy(nil), value.RolePolicies...)
	for index := range value.RolePolicies {
		value.RolePolicies[index].Policy = append([]LDAPPermissionTuple(nil), value.RolePolicies[index].Policy...)
	}
	value.ExistingEffectiveRoleIDs = append([]EntityID(nil), value.ExistingEffectiveRoleIDs...)
	value.Delegation = append([]LDAPDelegationGrant(nil), value.Delegation...)
	for index := range value.Delegation {
		if value.Delegation[index].NotAfter != nil {
			copyValue := *value.Delegation[index].NotAfter
			value.Delegation[index].NotAfter = &copyValue
		}
	}
	value.LiveOwnedEdges = append([]LDAPOwnedMappingEdge(nil), value.LiveOwnedEdges...)
	return value
}

func (snapshot FederatedPlanningSnapshot) String() string {
	return fmt.Sprintf(
		"identity.FederatedPlanningSnapshot{configurationRevision:%d,ruleSetRevision:%d,authorizationRevision:%d,jitMode:%d,noMatchPolicy:%d,rules:%d,groups:%d,assignments:%d,roles:%d,edges:%d,values:[REDACTED]}",
		snapshot.ConfigurationRevision, snapshot.RuleSetRevision, snapshot.AuthorizationRevision,
		snapshot.JITMode, snapshot.NoMatchPolicy, len(snapshot.Rules), len(snapshot.SecurityGroups),
		len(snapshot.LiveAssignments), len(snapshot.RolePolicies), len(snapshot.LiveOwnedEdges),
	)
}
func (snapshot FederatedPlanningSnapshot) GoString() string { return snapshot.String() }

// FederatedMappingPlan is a protocol-neutral view of the same shared planner
// result. All accessors are defensive and formatting never exposes claims.
type FederatedMappingPlan struct {
	inner LDAPMappingPlan
}

func (plan FederatedMappingPlan) Disposition() LDAPPlanDisposition { return plan.inner.Disposition() }
func (plan FederatedMappingPlan) Reason() LDAPPlanReason           { return plan.inner.Reason() }
func (plan FederatedMappingPlan) IdentityAction() LDAPIdentityPlanAction {
	return plan.inner.IdentityAction()
}
func (plan FederatedMappingPlan) ProviderAccessAction() LDAPProviderAccessPlanAction {
	return plan.inner.ProviderAccessAction()
}
func (plan FederatedMappingPlan) MatchedRuleIDs() []EntityID { return plan.inner.MatchedRuleIDs() }
func (plan FederatedMappingPlan) ProspectiveSecurityGroupIDs() []EntityID {
	return plan.inner.ProspectiveSecurityGroupIDs()
}
func (plan FederatedMappingPlan) ProspectiveRoleIDs() []EntityID {
	return plan.inner.ProspectiveRoleIDs()
}
func (plan FederatedMappingPlan) ProspectiveOperatorTeamAssignments() []LDAPOperatorTeamTarget {
	return plan.inner.ProspectiveOperatorTeamAssignments()
}
func (plan FederatedMappingPlan) Changes() []LDAPMappingChange { return plan.inner.Changes() }
func (plan FederatedMappingPlan) ProfilePresence() map[LDAPProfileField]bool {
	return plan.inner.ProfilePresence()
}
func (plan FederatedMappingPlan) RevealProfileField(field LDAPProfileField) (string, bool, error) {
	return plan.inner.RevealProfileField(field)
}
func (plan FederatedMappingPlan) String() string {
	return fmt.Sprintf(
		"identity.FederatedMappingPlan{disposition:%d,reason:%s,matchedRules:%d,groups:%d,roles:%d,teams:%d,changes:%d}",
		plan.Disposition(), plan.Reason(), len(plan.MatchedRuleIDs()), len(plan.ProspectiveSecurityGroupIDs()),
		len(plan.ProspectiveRoleIDs()), len(plan.ProspectiveOperatorTeamAssignments()), len(plan.Changes()),
	)
}
func (plan FederatedMappingPlan) GoString() string { return plan.String() }

// CloneFederatedMappingPlan returns an independently owned plan while
// preserving the unforgeable result boundary of PlanFederatedMapping.
func CloneFederatedMappingPlan(plan FederatedMappingPlan) FederatedMappingPlan {
	clone := plan.inner
	clone.profile = cloneLDAPProfileValues(plan.inner.profile)
	clone.matchedRuleIDs = append([]EntityID(nil), plan.inner.matchedRuleIDs...)
	clone.securityGroupIDs = append([]EntityID(nil), plan.inner.securityGroupIDs...)
	clone.roleIDs = append([]EntityID(nil), plan.inner.roleIDs...)
	clone.teamAssignments = append([]LDAPOperatorTeamTarget(nil), plan.inner.teamAssignments...)
	clone.changes = append([]LDAPMappingChange(nil), plan.inner.changes...)
	return FederatedMappingPlan{inner: clone}
}

func PlanFederatedMapping(
	observation FederatedMappingObservation,
	snapshot FederatedPlanningSnapshot,
) (FederatedMappingPlan, error) {
	if !validFederatedMappingObservation(observation) {
		return FederatedMappingPlan{}, ErrInvalidFederatedPlanningSnapshot
	}
	coreSnapshot, matchers := federatedCoreSnapshot(snapshot)
	compiled, err := compileProviderPlanningSnapshot(coreSnapshot, func(rule LDAPMappingRule) bool {
		matcher, exists := matchers[rule.RuleID]
		return exists && matcher.valid
	})
	if err != nil {
		return FederatedMappingPlan{}, ErrInvalidFederatedPlanningSnapshot
	}
	plan, err := planProviderMapping(mappingCoreObservation{
		complete: observation.complete, accountState: LDAPAccountActive,
		profile: cloneLDAPProfileValues(observation.profile),
	}, coreSnapshot, compiled, func(rule LDAPMappingRule) (bool, error) {
		matcher, exists := matchers[rule.RuleID]
		if !exists {
			return false, ErrInvalidFederatedPlanningSnapshot
		}
		return matcher.match(observation)
	})
	if err != nil {
		return FederatedMappingPlan{}, ErrInvalidFederatedPlanningSnapshot
	}
	return FederatedMappingPlan{inner: plan}, nil
}

func (matcher CompiledFederatedMappingMatcher) match(
	observation FederatedMappingObservation,
) (bool, error) {
	if !matcher.valid || !validFederatedMappingObservation(observation) {
		return false, ErrInvalidFederatedPlanningSnapshot
	}
	switch matcher.kind {
	case FederatedMappingGroupEquals:
		_, present := slices.BinarySearch(observation.groups, matcher.value)
		return present, nil
	case FederatedMappingScalarEquals:
		index, present := slices.BinarySearchFunc(observation.scalars, matcher.claimName, func(
			value FederatedMappingScalar,
			name string,
		) int {
			return strings.Compare(value.Name, name)
		})
		return present && observation.scalars[index].Value == matcher.value, nil
	default:
		return false, ErrInvalidFederatedPlanningSnapshot
	}
}

func federatedCoreSnapshot(
	snapshot FederatedPlanningSnapshot,
) (LDAPPlanningSnapshot, map[EntityID]CompiledFederatedMappingMatcher) {
	core := LDAPPlanningSnapshot{
		TenantID: snapshot.TenantID, Provider: snapshot.Provider, BindingID: snapshot.BindingID,
		ConfigurationRevision: snapshot.ConfigurationRevision, RuleSetRevision: snapshot.RuleSetRevision,
		AuthorizationRevision: snapshot.AuthorizationRevision, JITMode: snapshot.JITMode,
		NoMatchPolicy: snapshot.NoMatchPolicy, EffectiveUntil: snapshot.EffectiveUntil,
		ProviderAccess: snapshot.ProviderAccess, SecurityGroups: snapshot.SecurityGroups,
		LiveAssignments: snapshot.LiveAssignments, RolePolicies: snapshot.RolePolicies,
		ExistingEffectiveRoleIDs: snapshot.ExistingEffectiveRoleIDs, Delegation: snapshot.Delegation,
		LiveOwnedEdges: snapshot.LiveOwnedEdges,
	}
	matchers := make(map[EntityID]CompiledFederatedMappingMatcher, len(snapshot.Rules))
	core.Rules = make([]LDAPMappingRule, 0, len(snapshot.Rules))
	for _, rule := range snapshot.Rules {
		matchers[rule.RuleID] = rule.Matcher
		core.Rules = append(core.Rules, LDAPMappingRule{
			RuleID: rule.RuleID, RuleEpochID: rule.RuleEpochID, SourceID: rule.SourceID,
			Revision: rule.Revision, Priority: rule.Priority, Enabled: rule.Enabled, Mode: rule.Mode,
			SecurityGroupID: rule.SecurityGroupID, RoleIDs: append([]EntityID(nil), rule.RoleIDs...),
			OperatorTeam: rule.OperatorTeam, AdministrativeNote: rule.AdministrativeNote,
		})
	}
	return core, matchers
}

func validFederatedMappingObservation(observation FederatedMappingObservation) bool {
	return observation.valid && validCanonicalSubject(observation.subject) &&
		len(observation.scalars) <= maximumFederatedMappingScalars &&
		len(observation.groups) <= maximumFederatedMappingGroups
}

func validFederatedClaimName(value string) bool {
	if value == "" || len(value) > maximumFederatedMappingClaimBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || character == '"' || character == '\\' {
			return false
		}
	}
	return true
}

func validFederatedMappingValue(value string) bool {
	if value == "" || len(value) > maximumFederatedMappingValueBytes || !utf8.ValidString(value) ||
		utf8.RuneCountInString(value) > maximumFederatedMappingValueRunes {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || isFederatedDirectionalControl(character) {
			return false
		}
	}
	return true
}

func isFederatedDirectionalControl(character rune) bool {
	return character == '\u200e' || character == '\u200f' ||
		character >= '\u202a' && character <= '\u202e' ||
		character >= '\u2066' && character <= '\u2069'
}
