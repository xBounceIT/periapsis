package identity

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrInvalidLDAPPlanningSnapshot combines malformed, stale, cross-scope, and
// incomplete planning inputs. It deliberately contains no directory value.
var ErrInvalidLDAPPlanningSnapshot = errors.New("invalid LDAP planning snapshot")

const (
	maximumLDAPMappingRules        = 2_000
	maximumLDAPMappingRolesPerRule = 100
	maximumLDAPMappingOwnedEdges   = 100_000
	maximumLDAPMappingRolePolicies = 10_000
	maximumLDAPPermissionKeyBytes  = 128
	maximumLDAPMappingNoteBytes    = 2_000
)

// LDAPJITMode controls which identity state an authenticated subject may
// create. ExistingIdentity never links by email, username, or DN: it requires
// an existing provider-qualified immutable-subject link.
type LDAPJITMode uint8

const (
	LDAPJITDisabled LDAPJITMode = iota + 1
	LDAPJITExistingIdentity
	LDAPJITCreate
)

// LDAPNoMatchPolicy is explicit so a new enum value cannot grant access.
type LDAPNoMatchPolicy uint8

const (
	LDAPNoMatchDeny LDAPNoMatchPolicy = iota + 1
	LDAPNoMatchProviderAccessOnly
)

// LDAPReconciliationMode defines absence semantics for one immutable mapping
// source epoch. Additive sources never remove an absent edge.
type LDAPReconciliationMode uint8

const (
	LDAPReconciliationAdditive LDAPReconciliationMode = iota + 1
	LDAPReconciliationAuthoritative
)

// LDAPPermissionScope deliberately excludes platform. A provider mapping has
// no representation with which to request a platform grant.
type LDAPPermissionScope string

const (
	LDAPScopeOwn          LDAPPermissionScope = "own"
	LDAPScopeAssigned     LDAPPermissionScope = "assigned"
	LDAPScopeOperatorTeam LDAPPermissionScope = "operator_team"
	LDAPScopeTenant       LDAPPermissionScope = "tenant"
)

// LDAPPermissionTuple is compared exactly; there is no scope hierarchy for
// delegation.
type LDAPPermissionTuple struct {
	Permission string
	Scope      LDAPPermissionScope
}

// LDAPRolePolicy is the complete current policy of one tenant human role.
type LDAPRolePolicy struct {
	RoleID EntityID
	Policy []LDAPPermissionTuple
}

// LDAPDelegationGrant is one exact tuple in the mapping's protected
// delegation boundary. A nil NotAfter is non-expiring.
type LDAPDelegationGrant struct {
	Tuple    LDAPPermissionTuple
	NotAfter *time.Time
}

// LDAPOperatorTeamTarget always names an exact tenant assignment epoch. A
// global team ID alone can never become a mapping consequence.
type LDAPOperatorTeamTarget struct {
	TeamID            EntityID
	AssignmentEpochID EntityID
}

// LDAPMappingRule is one immutable rule-epoch snapshot. All matching rules
// contribute; Priority controls deterministic presentation only.
type LDAPMappingRule struct {
	RuleID             EntityID
	RuleEpochID        EntityID
	SourceID           EntityID
	Revision           int64
	Priority           int32
	Enabled            bool
	Matcher            CompiledLDAPGroupMatcher
	Mode               LDAPReconciliationMode
	SecurityGroupID    EntityID
	RoleIDs            []EntityID
	OperatorTeam       *LDAPOperatorTeamTarget
	AdministrativeNote string
}

func (rule LDAPMappingRule) String() string {
	return fmt.Sprintf(
		"identity.LDAPMappingRule{revision:%d,priority:%d,enabled:%t,matcher:%s,mode:%d,roles:%d,operatorTeam:%t,note:[REDACTED]}",
		rule.Revision, rule.Priority, rule.Enabled, rule.Matcher, rule.Mode,
		len(rule.RoleIDs), rule.OperatorTeam != nil,
	)
}
func (rule LDAPMappingRule) GoString() string { return rule.String() }

// LDAPSecurityGroupPolicy supplies every already-live role binding that a new
// membership edge would activate, including bindings owned by other sources.
type LDAPSecurityGroupPolicy struct {
	SecurityGroupID EntityID
	ActiveRoleIDs   []EntityID
}

// LDAPOperatorTeamAssignment is a tenant-consistent, exact-epoch liveness
// fact obtained inside the authorization snapshot.
type LDAPOperatorTeamAssignment struct {
	TeamID            EntityID
	AssignmentEpochID EntityID
	Live              bool
}

// LDAPMappingEdgeKind is the closed set a rule source may reconcile.
type LDAPMappingEdgeKind uint8

const (
	LDAPSecurityGroupMembershipEdge LDAPMappingEdgeKind = iota + 1
	LDAPSecurityGroupRoleGrantEdge
	LDAPOperatorTeamRosterEdge
)

// LDAPMappingEdgeKey is source-qualified by LDAPOwnedMappingEdge.SourceID.
// PrimaryID is group/team; SecondaryID is empty for group membership, a role
// for group-role grants, and the exact assignment epoch for team rosters.
type LDAPMappingEdgeKey struct {
	Kind        LDAPMappingEdgeKind
	PrimaryID   EntityID
	SecondaryID EntityID
}

// LDAPOwnedMappingEdge describes one currently live edge owned by an exact
// immutable rule/source epoch.
type LDAPOwnedMappingEdge struct {
	SourceID    EntityID
	RuleEpochID EntityID
	Key         LDAPMappingEdgeKey
}

// LDAPProviderAccessState distinguishes identity, tenant membership, and the
// current provider-owned access epoch.
type LDAPProviderAccessState struct {
	SourceID               EntityID
	AccessEpochID          EntityID
	ExternalIdentityExists bool
	UserActive             bool
	TenantMembershipExists bool
	TenantMembershipActive bool
	AccessGrantLive        bool
}

// LDAPPlanningSnapshot pins every revision whose change invalidates the
// network observation. EffectiveUntil is nil for an indefinite consequence.
type LDAPPlanningSnapshot struct {
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
	Rules                    []LDAPMappingRule
	SecurityGroups           []LDAPSecurityGroupPolicy
	LiveAssignments          []LDAPOperatorTeamAssignment
	RolePolicies             []LDAPRolePolicy
	ExistingEffectiveRoleIDs []EntityID
	Delegation               []LDAPDelegationGrant
	LiveOwnedEdges           []LDAPOwnedMappingEdge
}

func (snapshot LDAPPlanningSnapshot) String() string {
	return fmt.Sprintf(
		"identity.LDAPPlanningSnapshot{configurationRevision:%d,ruleSetRevision:%d,authorizationRevision:%d,jitMode:%d,noMatchPolicy:%d,rules:%d,groups:%d,assignments:%d,roles:%d,edges:%d,values:[REDACTED]}",
		snapshot.ConfigurationRevision, snapshot.RuleSetRevision, snapshot.AuthorizationRevision,
		snapshot.JITMode, snapshot.NoMatchPolicy, len(snapshot.Rules), len(snapshot.SecurityGroups),
		len(snapshot.LiveAssignments), len(snapshot.RolePolicies), len(snapshot.LiveOwnedEdges),
	)
}
func (snapshot LDAPPlanningSnapshot) GoString() string { return snapshot.String() }

// LDAPIdentityPlanAction is intentionally not a generic link action. Creation
// means a new User plus provider-qualified external identity; automatic
// linking to a mutable local identifier is impossible through this API.
type LDAPIdentityPlanAction uint8

const (
	LDAPIdentityNoChange LDAPIdentityPlanAction = iota
	LDAPIdentityCreateUserAndExternalIdentity
)

type LDAPProviderAccessPlanAction uint8

const (
	LDAPProviderAccessNoChange LDAPProviderAccessPlanAction = iota
	LDAPProviderAccessEnsure
	LDAPProviderAccessSuspend
)

type LDAPMappingChangeOperation uint8

const (
	LDAPMappingEnsure LDAPMappingChangeOperation = iota + 1
	LDAPMappingRefresh
	LDAPMappingRevoke
)

// LDAPMappingChange retains exact source provenance. Apply code must pass this
// through protected source-owned database commands rather than write an
// authorization table directly.
type LDAPMappingChange struct {
	Operation   LDAPMappingChangeOperation
	SourceID    EntityID
	RuleEpochID EntityID
	Key         LDAPMappingEdgeKey
}

type LDAPPlanDisposition uint8

const (
	LDAPPlanDenied LDAPPlanDisposition = iota + 1
	LDAPPlanAdmitted
)

// LDAPPlanReason is safe for dry-run, audit metadata, and metrics.
type LDAPPlanReason string

const (
	LDAPPlanReasonMapped                   LDAPPlanReason = "mapped"
	LDAPPlanReasonProviderAccessOnly       LDAPPlanReason = "provider_access_only"
	LDAPPlanReasonIncompleteObservation    LDAPPlanReason = "incomplete_observation"
	LDAPPlanReasonAccountDisabled          LDAPPlanReason = "account_disabled"
	LDAPPlanReasonLocalIdentityDisabled    LDAPPlanReason = "local_identity_disabled"
	LDAPPlanReasonTenantMembershipInactive LDAPPlanReason = "tenant_membership_inactive"
	LDAPPlanReasonJITDisabled              LDAPPlanReason = "jit_disabled"
	LDAPPlanReasonExistingIdentityRequired LDAPPlanReason = "existing_identity_required"
	LDAPPlanReasonNoMapping                LDAPPlanReason = "no_mapping"
	LDAPPlanReasonAssignmentInactive       LDAPPlanReason = "assignment_inactive"
	LDAPPlanReasonDelegationExceeded       LDAPPlanReason = "delegation_exceeded"
	LDAPPlanReasonDeprovisionRetained      LDAPPlanReason = "deprovision_retained"
	LDAPPlanReasonDeprovisionGracePending  LDAPPlanReason = "deprovision_grace_pending"
	LDAPPlanReasonDeprovisioned            LDAPPlanReason = "deprovisioned"
)

// LDAPDeprovisionPolicy is the closed v1 timing policy for a disabled or absent
// provider identity. No value can disable the platform User globally.
type LDAPDeprovisionPolicy uint8

const (
	LDAPDeprovisionRetain LDAPDeprovisionPolicy = iota + 1
	LDAPDeprovisionImmediate
	LDAPDeprovisionGrace
)

// LDAPDeprovisionInput carries proofs established outside the planner. A
// staged sync sets SourceComplete only after validated paging termination; a
// normalized disabled entry uses its complete bounded observation.
type LDAPDeprovisionInput struct {
	Policy         LDAPDeprovisionPolicy
	SourceComplete bool
	GraceElapsed   bool
}

// LDAPMappingPlan owns the only unredacted profile projection. Formatting and
// summary methods disclose counts, IDs, and presence bits only.
type LDAPMappingPlan struct {
	disposition      LDAPPlanDisposition
	reason           LDAPPlanReason
	identityAction   LDAPIdentityPlanAction
	accessAction     LDAPProviderAccessPlanAction
	profile          LDAPProfileValues
	matchedRuleIDs   []EntityID
	securityGroupIDs []EntityID
	roleIDs          []EntityID
	teamAssignments  []LDAPOperatorTeamTarget
	changes          []LDAPMappingChange
}

func (plan LDAPMappingPlan) Disposition() LDAPPlanDisposition { return plan.disposition }
func (plan LDAPMappingPlan) Reason() LDAPPlanReason           { return plan.reason }
func (plan LDAPMappingPlan) IdentityAction() LDAPIdentityPlanAction {
	return plan.identityAction
}
func (plan LDAPMappingPlan) ProviderAccessAction() LDAPProviderAccessPlanAction {
	return plan.accessAction
}
func (plan LDAPMappingPlan) MatchedRuleIDs() []EntityID {
	return append([]EntityID(nil), plan.matchedRuleIDs...)
}
func (plan LDAPMappingPlan) ProspectiveSecurityGroupIDs() []EntityID {
	return append([]EntityID(nil), plan.securityGroupIDs...)
}
func (plan LDAPMappingPlan) ProspectiveRoleIDs() []EntityID {
	return append([]EntityID(nil), plan.roleIDs...)
}
func (plan LDAPMappingPlan) ProspectiveOperatorTeamAssignments() []LDAPOperatorTeamTarget {
	return append([]LDAPOperatorTeamTarget(nil), plan.teamAssignments...)
}
func (plan LDAPMappingPlan) Changes() []LDAPMappingChange {
	return append([]LDAPMappingChange(nil), plan.changes...)
}
func (plan LDAPMappingPlan) ProfilePresence() map[LDAPProfileField]bool {
	return LDAPObservation{profile: plan.profile}.ProfilePresence()
}
func (plan LDAPMappingPlan) RevealProfileField(field LDAPProfileField) (string, bool, error) {
	return LDAPObservation{profile: plan.profile}.RevealProfileField(field)
}
func (plan LDAPMappingPlan) String() string {
	return fmt.Sprintf(
		"identity.LDAPMappingPlan{disposition:%d,reason:%s,matchedRules:%d,groups:%d,roles:%d,teams:%d,changes:%d}",
		plan.disposition, plan.reason, len(plan.matchedRuleIDs), len(plan.securityGroupIDs),
		len(plan.roleIDs), len(plan.teamAssignments), len(plan.changes),
	)
}
func (plan LDAPMappingPlan) GoString() string { return plan.String() }

// PlanLDAPMapping is the single evaluator used by dry-run, login, and sync.
// Expected policy denials return a redacted denied plan and nil error; invalid
// snapshots return ErrInvalidLDAPPlanningSnapshot and never a partial plan.
func PlanLDAPMapping(
	observation LDAPObservation,
	snapshot LDAPPlanningSnapshot,
) (LDAPMappingPlan, error) {
	compiled, err := compileLDAPPlanningSnapshot(snapshot)
	if err != nil || !validLDAPObservationForPlanning(observation) {
		return LDAPMappingPlan{}, ErrInvalidLDAPPlanningSnapshot
	}
	return planProviderMapping(mappingCoreObservation{
		complete: observation.complete, accountState: observation.accountState,
		profile: cloneLDAPProfileValues(observation.profile),
	}, snapshot, compiled, func(rule LDAPMappingRule) (bool, error) {
		matches := false
		for _, group := range observation.mappingGroups() {
			match, matchErr := rule.Matcher.Match(group)
			if matchErr != nil {
				return false, ErrInvalidLDAPPlanningSnapshot
			}
			matches = matches || match
		}
		return matches, nil
	})
}

type mappingCoreObservation struct {
	complete     bool
	accountState LDAPAccountState
	profile      LDAPProfileValues
}

// planProviderMapping is the matcher-neutral admission and reconciliation
// core shared by LDAP and federated protocols. Protocol adapters retain sole
// ownership of parsing and matching their typed observations.
func planProviderMapping(
	observation mappingCoreObservation,
	snapshot LDAPPlanningSnapshot,
	compiled compiledLDAPPlanningSnapshot,
	matcher func(LDAPMappingRule) (bool, error),
) (LDAPMappingPlan, error) {
	if matcher == nil {
		return LDAPMappingPlan{}, ErrInvalidLDAPPlanningSnapshot
	}
	if !observation.complete {
		return deniedLDAPMappingPlan(LDAPPlanReasonIncompleteObservation), nil
	}
	if observation.accountState == LDAPAccountDisabled {
		return deniedLDAPMappingPlan(LDAPPlanReasonAccountDisabled), nil
	}
	if observation.accountState != LDAPAccountActive {
		return LDAPMappingPlan{}, ErrInvalidLDAPPlanningSnapshot
	}
	if snapshot.ProviderAccess.ExternalIdentityExists && !snapshot.ProviderAccess.UserActive {
		return deniedLDAPMappingPlan(LDAPPlanReasonLocalIdentityDisabled), nil
	}
	if snapshot.ProviderAccess.TenantMembershipExists && !snapshot.ProviderAccess.TenantMembershipActive {
		return deniedLDAPMappingPlan(LDAPPlanReasonTenantMembershipInactive), nil
	}

	switch snapshot.JITMode {
	case LDAPJITDisabled:
		if !snapshot.ProviderAccess.ExternalIdentityExists ||
			!snapshot.ProviderAccess.TenantMembershipExists ||
			!snapshot.ProviderAccess.AccessGrantLive {
			return deniedLDAPMappingPlan(LDAPPlanReasonJITDisabled), nil
		}
	case LDAPJITExistingIdentity:
		if !snapshot.ProviderAccess.ExternalIdentityExists {
			return deniedLDAPMappingPlan(LDAPPlanReasonExistingIdentityRequired), nil
		}
	case LDAPJITCreate:
	default:
		return LDAPMappingPlan{}, ErrInvalidLDAPPlanningSnapshot
	}

	matched := make([]LDAPMappingRule, 0, len(compiled.rules))
	for _, rule := range compiled.rules {
		if !rule.Enabled {
			continue
		}
		matches, matchErr := matcher(rule)
		if matchErr != nil {
			return LDAPMappingPlan{}, ErrInvalidLDAPPlanningSnapshot
		}
		if matches {
			matched = append(matched, rule)
		}
	}
	denyForNoMapping := len(matched) == 0 && snapshot.NoMatchPolicy == LDAPNoMatchDeny

	desiredBySource := make(map[EntityID]map[LDAPMappingEdgeKey]struct{}, len(compiled.rules))
	prospectiveGroups := make(map[EntityID]struct{})
	prospectiveRoles := make(map[EntityID]struct{})
	prospectiveTeams := make(map[LDAPOperatorTeamTarget]struct{})
	matchedRuleIDs := make([]EntityID, 0, len(matched))
	for _, roleID := range snapshot.ExistingEffectiveRoleIDs {
		prospectiveRoles[roleID] = struct{}{}
	}
	for _, rule := range compiled.rules {
		desiredBySource[rule.SourceID] = make(map[LDAPMappingEdgeKey]struct{})
	}
	for _, rule := range matched {
		matchedRuleIDs = append(matchedRuleIDs, rule.RuleID)
		prospectiveGroups[rule.SecurityGroupID] = struct{}{}
		desired := desiredBySource[rule.SourceID]
		desired[LDAPMappingEdgeKey{
			Kind: LDAPSecurityGroupMembershipEdge, PrimaryID: rule.SecurityGroupID,
		}] = struct{}{}
		for _, roleID := range rule.RoleIDs {
			prospectiveRoles[roleID] = struct{}{}
			desired[LDAPMappingEdgeKey{
				Kind: LDAPSecurityGroupRoleGrantEdge, PrimaryID: rule.SecurityGroupID, SecondaryID: roleID,
			}] = struct{}{}
		}
		for _, roleID := range compiled.groupRoles[rule.SecurityGroupID] {
			prospectiveRoles[roleID] = struct{}{}
		}
		if rule.OperatorTeam != nil {
			target := *rule.OperatorTeam
			if !compiled.liveAssignments[target] {
				return deniedLDAPMappingPlan(LDAPPlanReasonAssignmentInactive), nil
			}
			prospectiveTeams[target] = struct{}{}
			desired[LDAPMappingEdgeKey{
				Kind:      LDAPOperatorTeamRosterEdge,
				PrimaryID: target.TeamID, SecondaryID: target.AssignmentEpochID,
			}] = struct{}{}
		}
	}

	changes := make([]LDAPMappingChange, 0)
	currentBySource := make(map[EntityID]map[LDAPMappingEdgeKey]struct{}, len(compiled.rules))
	for _, edge := range snapshot.LiveOwnedEdges {
		byKey := currentBySource[edge.SourceID]
		if byKey == nil {
			byKey = make(map[LDAPMappingEdgeKey]struct{})
			currentBySource[edge.SourceID] = byKey
		}
		byKey[edge.Key] = struct{}{}
	}
	for _, rule := range compiled.rules {
		desired := desiredBySource[rule.SourceID]
		current := currentBySource[rule.SourceID]
		for key := range desired {
			operation := LDAPMappingEnsure
			if _, exists := current[key]; exists {
				operation = LDAPMappingRefresh
			}
			changes = append(changes, LDAPMappingChange{
				Operation: operation, SourceID: rule.SourceID, RuleEpochID: rule.RuleEpochID, Key: key,
			})
		}
		if rule.Mode == LDAPReconciliationAuthoritative {
			for key := range current {
				if _, remainsDesired := desired[key]; !remainsDesired {
					changes = append(changes, LDAPMappingChange{
						Operation: LDAPMappingRevoke, SourceID: rule.SourceID,
						RuleEpochID: rule.RuleEpochID, Key: key,
					})
				}
			}
		}
	}
	sortLDAPMappingChanges(changes)

	if !compiled.delegationCoversPlan(
		prospectiveGroups, prospectiveRoles, prospectiveTeams, changes, snapshot.EffectiveUntil,
	) {
		return deniedLDAPMappingPlan(LDAPPlanReasonDelegationExceeded), nil
	}
	if denyForNoMapping {
		// A complete observation may prove that authoritative mapping edges are
		// stale even though admission is denied. Return only source-owned
		// revocations; callers must never create identity/access/profile state
		// from a denied plan.
		revocations := changes[:0]
		for _, change := range changes {
			if change.Operation == LDAPMappingRevoke {
				revocations = append(revocations, change)
			}
		}
		return LDAPMappingPlan{
			disposition: LDAPPlanDenied,
			reason:      LDAPPlanReasonNoMapping,
			changes:     append([]LDAPMappingChange(nil), revocations...),
		}, nil
	}

	plan := LDAPMappingPlan{
		disposition:      LDAPPlanAdmitted,
		reason:           LDAPPlanReasonMapped,
		profile:          cloneLDAPProfileValues(observation.profile),
		matchedRuleIDs:   matchedRuleIDs,
		securityGroupIDs: sortedLDAPEntityIDSet(prospectiveGroups),
		roleIDs:          sortedLDAPEntityIDSet(prospectiveRoles),
		teamAssignments:  sortedLDAPTeamSet(prospectiveTeams),
		changes:          changes,
	}
	if len(matched) == 0 {
		plan.reason = LDAPPlanReasonProviderAccessOnly
	}
	if !snapshot.ProviderAccess.ExternalIdentityExists && snapshot.JITMode == LDAPJITCreate {
		plan.identityAction = LDAPIdentityCreateUserAndExternalIdentity
	}
	if !snapshot.ProviderAccess.TenantMembershipExists || !snapshot.ProviderAccess.AccessGrantLive {
		plan.accessAction = LDAPProviderAccessEnsure
	}
	return plan, nil
}

// PlanLDAPDeprovision returns a denial plus only the exact source-owned
// consequences permitted by policy. An incomplete source can never produce a
// removal, and additive mapping sources are never revoked for absence.
func PlanLDAPDeprovision(
	snapshot LDAPPlanningSnapshot,
	input LDAPDeprovisionInput,
) (LDAPMappingPlan, error) {
	compiled, err := compileLDAPPlanningSnapshot(snapshot)
	if err != nil || !validLDAPDeprovisionPolicy(input.Policy) {
		return LDAPMappingPlan{}, ErrInvalidLDAPPlanningSnapshot
	}
	if !input.SourceComplete {
		return deniedLDAPMappingPlan(LDAPPlanReasonIncompleteObservation), nil
	}
	if input.Policy == LDAPDeprovisionRetain {
		return deniedLDAPMappingPlan(LDAPPlanReasonDeprovisionRetained), nil
	}
	if input.Policy == LDAPDeprovisionGrace && !input.GraceElapsed {
		return deniedLDAPMappingPlan(LDAPPlanReasonDeprovisionGracePending), nil
	}

	changes := make([]LDAPMappingChange, 0, len(snapshot.LiveOwnedEdges))
	modeBySource := make(map[EntityID]LDAPReconciliationMode, len(compiled.rules))
	for _, rule := range compiled.rules {
		modeBySource[rule.SourceID] = rule.Mode
	}
	for _, edge := range snapshot.LiveOwnedEdges {
		if modeBySource[edge.SourceID] != LDAPReconciliationAuthoritative {
			continue
		}
		changes = append(changes, LDAPMappingChange{
			Operation: LDAPMappingRevoke, SourceID: edge.SourceID,
			RuleEpochID: edge.RuleEpochID, Key: edge.Key,
		})
	}
	sortLDAPMappingChanges(changes)
	roles := make(map[EntityID]struct{}, len(snapshot.ExistingEffectiveRoleIDs))
	for _, roleID := range snapshot.ExistingEffectiveRoleIDs {
		roles[roleID] = struct{}{}
	}
	if !compiled.delegationCoversPlan(nil, roles, nil, changes, snapshot.EffectiveUntil) {
		return deniedLDAPMappingPlan(LDAPPlanReasonDelegationExceeded), nil
	}
	plan := LDAPMappingPlan{
		disposition: LDAPPlanDenied,
		reason:      LDAPPlanReasonDeprovisioned,
		changes:     changes,
	}
	if snapshot.ProviderAccess.AccessGrantLive {
		plan.accessAction = LDAPProviderAccessSuspend
	}
	return plan, nil
}

type compiledLDAPPlanningSnapshot struct {
	rules           []LDAPMappingRule
	roles           map[EntityID][]LDAPPermissionTuple
	groupRoles      map[EntityID][]EntityID
	liveAssignments map[LDAPOperatorTeamTarget]bool
	delegation      map[LDAPPermissionTuple][]*time.Time
}

func compileLDAPPlanningSnapshot(snapshot LDAPPlanningSnapshot) (compiledLDAPPlanningSnapshot, error) {
	return compileProviderPlanningSnapshot(snapshot, func(rule LDAPMappingRule) bool {
		return rule.Matcher.valid()
	})
}

func compileProviderPlanningSnapshot(
	snapshot LDAPPlanningSnapshot,
	validMatcher func(LDAPMappingRule) bool,
) (compiledLDAPPlanningSnapshot, error) {
	if isZeroID(snapshot.TenantID) || validateProviderContext(snapshot.Provider) != nil ||
		isZeroID(snapshot.BindingID) || snapshot.ConfigurationRevision < 1 ||
		snapshot.RuleSetRevision < 1 || snapshot.AuthorizationRevision < 1 ||
		isZeroID(snapshot.ProviderAccess.SourceID) || isZeroID(snapshot.ProviderAccess.AccessEpochID) ||
		len(snapshot.Rules) > maximumLDAPMappingRules ||
		len(snapshot.LiveOwnedEdges) > maximumLDAPMappingOwnedEdges ||
		len(snapshot.RolePolicies) > maximumLDAPMappingRolePolicies ||
		(snapshot.Provider.Scope == TenantProviderScope && snapshot.Provider.TenantID != snapshot.TenantID) ||
		(snapshot.JITMode != LDAPJITDisabled && snapshot.JITMode != LDAPJITExistingIdentity && snapshot.JITMode != LDAPJITCreate) ||
		(snapshot.NoMatchPolicy != LDAPNoMatchDeny && snapshot.NoMatchPolicy != LDAPNoMatchProviderAccessOnly) ||
		validMatcher == nil {
		return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
	}
	if snapshot.ProviderAccess.UserActive && !snapshot.ProviderAccess.ExternalIdentityExists ||
		snapshot.ProviderAccess.TenantMembershipExists &&
			(!snapshot.ProviderAccess.ExternalIdentityExists || !snapshot.ProviderAccess.UserActive) ||
		snapshot.ProviderAccess.TenantMembershipActive && !snapshot.ProviderAccess.TenantMembershipExists ||
		snapshot.ProviderAccess.AccessGrantLive &&
			(!snapshot.ProviderAccess.ExternalIdentityExists || !snapshot.ProviderAccess.UserActive ||
				!snapshot.ProviderAccess.TenantMembershipExists || !snapshot.ProviderAccess.TenantMembershipActive) {
		return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
	}
	if snapshot.EffectiveUntil != nil && snapshot.EffectiveUntil.IsZero() {
		return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
	}
	compiled := compiledLDAPPlanningSnapshot{
		roles:           make(map[EntityID][]LDAPPermissionTuple, len(snapshot.RolePolicies)),
		groupRoles:      make(map[EntityID][]EntityID, len(snapshot.SecurityGroups)),
		liveAssignments: make(map[LDAPOperatorTeamTarget]bool, len(snapshot.LiveAssignments)),
		delegation:      make(map[LDAPPermissionTuple][]*time.Time, len(snapshot.Delegation)),
	}
	for _, policy := range snapshot.RolePolicies {
		if isZeroID(policy.RoleID) {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		if _, duplicate := compiled.roles[policy.RoleID]; duplicate {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		seen := make(map[LDAPPermissionTuple]struct{}, len(policy.Policy))
		for _, tuple := range policy.Policy {
			if !validLDAPPermissionTuple(tuple) {
				return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
			}
			if _, duplicate := seen[tuple]; duplicate {
				return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
			}
			seen[tuple] = struct{}{}
		}
		compiled.roles[policy.RoleID] = sortedLDAPPermissionSet(seen)
	}
	for _, group := range snapshot.SecurityGroups {
		if isZeroID(group.SecurityGroupID) {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		if _, duplicate := compiled.groupRoles[group.SecurityGroupID]; duplicate {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		roles, ok := uniqueLDAPEntityIDs(group.ActiveRoleIDs, maximumLDAPMappingRolePolicies)
		if !ok {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		compiled.groupRoles[group.SecurityGroupID] = roles
	}
	for _, assignment := range snapshot.LiveAssignments {
		target := LDAPOperatorTeamTarget{TeamID: assignment.TeamID, AssignmentEpochID: assignment.AssignmentEpochID}
		if isZeroID(target.TeamID) || isZeroID(target.AssignmentEpochID) {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		if _, duplicate := compiled.liveAssignments[target]; duplicate {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		compiled.liveAssignments[target] = assignment.Live
	}
	for _, grant := range snapshot.Delegation {
		if !validLDAPPermissionTuple(grant.Tuple) || (grant.NotAfter != nil && grant.NotAfter.IsZero()) {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		var end *time.Time
		if grant.NotAfter != nil {
			copyOfEnd := *grant.NotAfter
			end = &copyOfEnd
		}
		compiled.delegation[grant.Tuple] = append(compiled.delegation[grant.Tuple], end)
	}

	ruleIDs := make(map[EntityID]struct{}, len(snapshot.Rules))
	epochIDs := make(map[EntityID]struct{}, len(snapshot.Rules))
	sourceIDs := make(map[EntityID]EntityID, len(snapshot.Rules))
	compiled.rules = append([]LDAPMappingRule(nil), snapshot.Rules...)
	for index := range compiled.rules {
		rule := &compiled.rules[index]
		if isZeroID(rule.RuleID) || isZeroID(rule.RuleEpochID) || isZeroID(rule.SourceID) ||
			rule.Revision < 1 || !validMatcher(*rule) ||
			(rule.Mode != LDAPReconciliationAdditive && rule.Mode != LDAPReconciliationAuthoritative) ||
			isZeroID(rule.SecurityGroupID) || len(rule.RoleIDs) > maximumLDAPMappingRolesPerRule ||
			len(rule.AdministrativeNote) > maximumLDAPMappingNoteBytes ||
			!utf8.ValidString(rule.AdministrativeNote) || strings.ContainsRune(rule.AdministrativeNote, '\x00') {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		if _, duplicate := ruleIDs[rule.RuleID]; duplicate {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		if _, duplicate := epochIDs[rule.RuleEpochID]; duplicate {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		if _, duplicate := sourceIDs[rule.SourceID]; duplicate {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		ruleIDs[rule.RuleID] = struct{}{}
		epochIDs[rule.RuleEpochID] = struct{}{}
		sourceIDs[rule.SourceID] = rule.RuleEpochID
		roles, ok := uniqueLDAPEntityIDs(rule.RoleIDs, maximumLDAPMappingRolesPerRule)
		if !ok {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		rule.RoleIDs = roles
		if _, present := compiled.groupRoles[rule.SecurityGroupID]; !present {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		if rule.OperatorTeam != nil {
			copyOfTarget := *rule.OperatorTeam
			if isZeroID(copyOfTarget.TeamID) || isZeroID(copyOfTarget.AssignmentEpochID) {
				return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
			}
			rule.OperatorTeam = &copyOfTarget
		}
	}
	slices.SortFunc(compiled.rules, compareLDAPMappingRules)

	for _, edge := range snapshot.LiveOwnedEdges {
		expectedEpoch, sourceExists := sourceIDs[edge.SourceID]
		if !sourceExists || expectedEpoch != edge.RuleEpochID || !validLDAPMappingEdgeKey(edge.Key) {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		switch edge.Key.Kind {
		case LDAPSecurityGroupMembershipEdge:
			if _, present := compiled.groupRoles[edge.Key.PrimaryID]; !present {
				return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
			}
		case LDAPSecurityGroupRoleGrantEdge:
			if _, present := compiled.groupRoles[edge.Key.PrimaryID]; !present {
				return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
			}
		}
	}
	seenEdges := make(map[struct {
		source EntityID
		key    LDAPMappingEdgeKey
	}]struct{}, len(snapshot.LiveOwnedEdges))
	for _, edge := range snapshot.LiveOwnedEdges {
		qualified := struct {
			source EntityID
			key    LDAPMappingEdgeKey
		}{edge.SourceID, edge.Key}
		if _, duplicate := seenEdges[qualified]; duplicate {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		seenEdges[qualified] = struct{}{}
	}

	allRoleIDs := make(map[EntityID]struct{})
	for _, rule := range compiled.rules {
		for _, roleID := range rule.RoleIDs {
			allRoleIDs[roleID] = struct{}{}
		}
	}
	for _, roleIDs := range compiled.groupRoles {
		for _, roleID := range roleIDs {
			allRoleIDs[roleID] = struct{}{}
		}
	}
	for _, roleID := range snapshot.ExistingEffectiveRoleIDs {
		if isZeroID(roleID) {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
		allRoleIDs[roleID] = struct{}{}
	}
	for _, edge := range snapshot.LiveOwnedEdges {
		if edge.Key.Kind == LDAPSecurityGroupRoleGrantEdge {
			allRoleIDs[edge.Key.SecondaryID] = struct{}{}
		}
	}
	for roleID := range allRoleIDs {
		if _, exists := compiled.roles[roleID]; !exists {
			return compiledLDAPPlanningSnapshot{}, ErrInvalidLDAPPlanningSnapshot
		}
	}
	return compiled, nil
}

func (compiled compiledLDAPPlanningSnapshot) delegationCoversPlan(
	groups map[EntityID]struct{},
	roles map[EntityID]struct{},
	teams map[LDAPOperatorTeamTarget]struct{},
	changes []LDAPMappingChange,
	effectiveUntil *time.Time,
) bool {
	requiredRoles := make(map[EntityID]struct{})
	for groupID := range groups {
		for _, roleID := range compiled.groupRoles[groupID] {
			requiredRoles[roleID] = struct{}{}
		}
	}
	for _, change := range changes {
		switch change.Key.Kind {
		case LDAPSecurityGroupMembershipEdge:
			for _, roleID := range compiled.groupRoles[change.Key.PrimaryID] {
				requiredRoles[roleID] = struct{}{}
			}
		case LDAPSecurityGroupRoleGrantEdge:
			requiredRoles[change.Key.SecondaryID] = struct{}{}
		}
	}
	for roleID := range requiredRoles {
		policy, exists := compiled.roles[roleID]
		if !exists {
			return false
		}
		for _, tuple := range policy {
			if !compiled.delegates(tuple, effectiveUntil) {
				return false
			}
		}
	}
	hasTeamConsequence := len(teams) > 0
	for _, change := range changes {
		hasTeamConsequence = hasTeamConsequence || change.Key.Kind == LDAPOperatorTeamRosterEdge
	}
	if hasTeamConsequence {
		for roleID := range roles {
			for _, tuple := range compiled.roles[roleID] {
				if tuple.Scope == LDAPScopeOperatorTeam && !compiled.delegates(tuple, effectiveUntil) {
					return false
				}
			}
		}
	}
	return true
}

func (compiled compiledLDAPPlanningSnapshot) delegates(tuple LDAPPermissionTuple, until *time.Time) bool {
	for _, end := range compiled.delegation[tuple] {
		if until == nil {
			if end == nil {
				return true
			}
			continue
		}
		if end == nil || !end.Before(*until) {
			return true
		}
	}
	return false
}

func validLDAPObservationForPlanning(observation LDAPObservation) bool {
	return validCanonicalSubject(observation.subject) && observation.userDN.valid &&
		observation.loginUsername.valid &&
		(observation.accountState == LDAPAccountActive || observation.accountState == LDAPAccountDisabled)
}

func validLDAPDeprovisionPolicy(policy LDAPDeprovisionPolicy) bool {
	switch policy {
	case LDAPDeprovisionRetain, LDAPDeprovisionImmediate, LDAPDeprovisionGrace:
		return true
	default:
		return false
	}
}

func deniedLDAPMappingPlan(reason LDAPPlanReason) LDAPMappingPlan {
	return LDAPMappingPlan{disposition: LDAPPlanDenied, reason: reason}
}

func validLDAPPermissionTuple(tuple LDAPPermissionTuple) bool {
	if len(tuple.Permission) == 0 || len(tuple.Permission) > maximumLDAPPermissionKeyBytes {
		return false
	}
	segmentStart := true
	for _, character := range tuple.Permission {
		if segmentStart {
			if character < 'a' || character > 'z' {
				return false
			}
			segmentStart = false
			continue
		}
		if character == '.' {
			segmentStart = true
			continue
		}
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return false
	}
	if segmentStart {
		return false
	}
	switch tuple.Scope {
	case LDAPScopeOwn, LDAPScopeAssigned, LDAPScopeOperatorTeam, LDAPScopeTenant:
		return true
	default:
		return false
	}
}

func validLDAPMappingEdgeKey(key LDAPMappingEdgeKey) bool {
	if isZeroID(key.PrimaryID) {
		return false
	}
	switch key.Kind {
	case LDAPSecurityGroupMembershipEdge:
		return isZeroID(key.SecondaryID)
	case LDAPSecurityGroupRoleGrantEdge, LDAPOperatorTeamRosterEdge:
		return !isZeroID(key.SecondaryID)
	default:
		return false
	}
}

func compareLDAPMappingRules(left, right LDAPMappingRule) int {
	if left.Priority < right.Priority {
		return -1
	}
	if left.Priority > right.Priority {
		return 1
	}
	return compareLDAPEntityID(left.RuleID, right.RuleID)
}

func compareLDAPEntityID(left, right EntityID) int {
	return slices.Compare(left[:], right[:])
}

func uniqueLDAPEntityIDs(values []EntityID, maximum int) ([]EntityID, bool) {
	if len(values) > maximum {
		return nil, false
	}
	result := append([]EntityID(nil), values...)
	for _, value := range result {
		if isZeroID(value) {
			return nil, false
		}
	}
	slices.SortFunc(result, compareLDAPEntityID)
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil, false
		}
	}
	return result, true
}

func sortedLDAPEntityIDSet(values map[EntityID]struct{}) []EntityID {
	result := make([]EntityID, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.SortFunc(result, compareLDAPEntityID)
	return result
}

func sortedLDAPTeamSet(values map[LDAPOperatorTeamTarget]struct{}) []LDAPOperatorTeamTarget {
	result := make([]LDAPOperatorTeamTarget, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.SortFunc(result, func(left, right LDAPOperatorTeamTarget) int {
		if comparison := compareLDAPEntityID(left.TeamID, right.TeamID); comparison != 0 {
			return comparison
		}
		return compareLDAPEntityID(left.AssignmentEpochID, right.AssignmentEpochID)
	})
	return result
}

func sortedLDAPPermissionSet(values map[LDAPPermissionTuple]struct{}) []LDAPPermissionTuple {
	result := make([]LDAPPermissionTuple, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.SortFunc(result, func(left, right LDAPPermissionTuple) int {
		if comparison := strings.Compare(left.Permission, right.Permission); comparison != 0 {
			return comparison
		}
		return strings.Compare(string(left.Scope), string(right.Scope))
	})
	return result
}

func sortLDAPMappingChanges(changes []LDAPMappingChange) {
	slices.SortFunc(changes, func(left, right LDAPMappingChange) int {
		if comparison := compareLDAPEntityID(left.SourceID, right.SourceID); comparison != 0 {
			return comparison
		}
		if left.Key.Kind < right.Key.Kind {
			return -1
		}
		if left.Key.Kind > right.Key.Kind {
			return 1
		}
		if comparison := compareLDAPEntityID(left.Key.PrimaryID, right.Key.PrimaryID); comparison != 0 {
			return comparison
		}
		if comparison := compareLDAPEntityID(left.Key.SecondaryID, right.Key.SecondaryID); comparison != 0 {
			return comparison
		}
		if left.Operation < right.Operation {
			return -1
		}
		if left.Operation > right.Operation {
			return 1
		}
		return 0
	})
}

func cloneLDAPProfileValues(values LDAPProfileValues) LDAPProfileValues {
	copyString := func(value *string) *string {
		if value == nil {
			return nil
		}
		copyOfValue := *value
		return &copyOfValue
	}
	return LDAPProfileValues{
		FirstName: copyString(values.FirstName), LastName: copyString(values.LastName),
		DisplayName: copyString(values.DisplayName), Username: copyString(values.Username),
		AlternateUsername: copyString(values.AlternateUsername), Email: copyString(values.Email),
	}
}
