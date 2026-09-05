package identitysync

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type planningRuleDocument struct {
	RuleID                        uuid.UUID   `json:"ruleId"`
	RuleEpochID                   uuid.UUID   `json:"ruleEpochId"`
	SourceID                      uuid.UUID   `json:"sourceId"`
	Revision                      int64       `json:"revision"`
	Priority                      int32       `json:"priority"`
	Enabled                       bool        `json:"enabled"`
	MatcherType                   string      `json:"matcherType"`
	MatcherValue                  string      `json:"matcherValue"`
	CaseMode                      string      `json:"caseMode"`
	ReconciliationMode            string      `json:"reconciliationMode"`
	SecurityGroupID               uuid.UUID   `json:"securityGroupId"`
	RoleIDs                       []uuid.UUID `json:"roleIds"`
	OperatorTeamID                *uuid.UUID  `json:"operatorTeamId"`
	OperatorTeamAssignmentEpochID *uuid.UUID  `json:"operatorTeamAssignmentEpochId"`
	AdministrativeNote            string      `json:"administrativeNote"`
}

type planningSecurityGroupDocument struct {
	SecurityGroupID uuid.UUID   `json:"securityGroupId"`
	ActiveRoleIDs   []uuid.UUID `json:"activeRoleIds"`
}

type planningAssignmentDocument struct {
	OperatorTeamID    uuid.UUID `json:"operatorTeamId"`
	AssignmentEpochID uuid.UUID `json:"assignmentEpochId"`
	Live              bool      `json:"live"`
}

type planningPermissionDocument struct {
	Permission string `json:"permission"`
	Scope      string `json:"scope"`
}

type planningRolePolicyDocument struct {
	RoleID uuid.UUID                    `json:"roleId"`
	Policy []planningPermissionDocument `json:"policy"`
}

type planningDelegationDocument struct {
	Permission string     `json:"permission"`
	Scope      string     `json:"scope"`
	NotAfter   *time.Time `json:"notAfter"`
}

type planningOwnedEdgeDocument struct {
	SourceID    uuid.UUID  `json:"sourceId"`
	RuleEpochID uuid.UUID  `json:"ruleEpochId"`
	Kind        string     `json:"kind"`
	PrimaryID   uuid.UUID  `json:"primaryId"`
	SecondaryID *uuid.UUID `json:"secondaryId"`
}

func planningSnapshot(
	claim Claim,
	projection PlanningProjection,
) (identity.LDAPPlanningSnapshot, []planningRuleDocument, error) {
	if projection.RunID != claim.RunID || projection.TenantID != claim.TenantID ||
		projection.Fence != claim.Fence || projection.ProviderID != claim.ProviderID ||
		projection.ProviderVersion != claim.ProviderVersion ||
		projection.BindingID != claim.BindingID ||
		projection.BindingVersion != claim.BindingVersion ||
		projection.BindingAuthRevision != claim.BindingAuthRevision ||
		projection.BindingAccessEpochID != claim.BindingAccessEpochID ||
		projection.ConfigurationRevision != int64(claim.ConfigurationVersion) ||
		projection.RuleSetRevision != claim.RuleSetRevision ||
		projection.AuthorizationRevision != claim.AuthorizationRevision ||
		projection.JITMode != claim.Configuration.JITMode ||
		projection.NoMatchPolicy != claim.Configuration.NoMatchPolicy ||
		projection.ExternalIdentityExists != (projection.ExternalIdentityID != nil) ||
		projection.ExternalIdentityExists != (projection.UserID != nil) ||
		projection.TenantMembershipExists != (projection.MembershipID != nil) ||
		projection.AccessGrantLive != (projection.AccessGrantID != nil) ||
		projection.UserActive && !projection.ExternalIdentityExists ||
		projection.TenantMembershipExists && (!projection.ExternalIdentityExists || !projection.UserActive) ||
		projection.TenantMembershipActive && !projection.TenantMembershipExists ||
		projection.AccessGrantLive && (!projection.ExternalIdentityExists || !projection.UserActive ||
			!projection.TenantMembershipExists || !projection.TenantMembershipActive) {
		return identity.LDAPPlanningSnapshot{}, nil, ErrInvalidSnapshot
	}
	tenantID, err := entityID(projection.TenantID)
	if err != nil {
		return identity.LDAPPlanningSnapshot{}, nil, err
	}
	providerID, err := entityID(projection.ProviderID)
	if err != nil {
		return identity.LDAPPlanningSnapshot{}, nil, err
	}
	bindingID, err := entityID(projection.BindingID)
	if err != nil {
		return identity.LDAPPlanningSnapshot{}, nil, err
	}
	accessSourceID, err := entityID(projection.ProviderAccessSourceID)
	if err != nil {
		return identity.LDAPPlanningSnapshot{}, nil, err
	}
	accessEpochID, err := entityID(projection.BindingAccessEpochID)
	if err != nil {
		return identity.LDAPPlanningSnapshot{}, nil, err
	}
	rules, ruleDocuments, err := planningRules(projection.Rules)
	if err != nil {
		return identity.LDAPPlanningSnapshot{}, nil, err
	}
	if err := validateRulePins(claim.MappingRevisions, ruleDocuments); err != nil {
		return identity.LDAPPlanningSnapshot{}, nil, err
	}
	groups, err := planningSecurityGroups(projection.SecurityGroups)
	if err != nil {
		return identity.LDAPPlanningSnapshot{}, nil, err
	}
	assignments, err := planningAssignments(projection.LiveAssignments)
	if err != nil {
		return identity.LDAPPlanningSnapshot{}, nil, err
	}
	roles, err := planningRolePolicies(projection.RolePolicies)
	if err != nil {
		return identity.LDAPPlanningSnapshot{}, nil, err
	}
	existingRoles, err := entityIDs(projection.ExistingEffectiveRoleIDs, 10_000)
	if err != nil {
		return identity.LDAPPlanningSnapshot{}, nil, err
	}
	delegation, err := planningDelegation(projection.Delegation)
	if err != nil {
		return identity.LDAPPlanningSnapshot{}, nil, err
	}
	edges, err := planningEdges(projection.LiveOwnedEdges)
	if err != nil {
		return identity.LDAPPlanningSnapshot{}, nil, err
	}
	jitMode, err := planningJITMode(projection.JITMode)
	if err != nil {
		return identity.LDAPPlanningSnapshot{}, nil, err
	}
	noMatch, err := planningNoMatchPolicy(projection.NoMatchPolicy)
	if err != nil {
		return identity.LDAPPlanningSnapshot{}, nil, err
	}
	return identity.LDAPPlanningSnapshot{
		TenantID: tenantID,
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: providerID,
		},
		BindingID:             bindingID,
		ConfigurationRevision: projection.ConfigurationRevision,
		RuleSetRevision:       projection.RuleSetRevision,
		AuthorizationRevision: projection.AuthorizationRevision,
		JITMode:               jitMode, NoMatchPolicy: noMatch,
		ProviderAccess: identity.LDAPProviderAccessState{
			SourceID: accessSourceID, AccessEpochID: accessEpochID,
			ExternalIdentityExists: projection.ExternalIdentityExists,
			UserActive:             projection.UserActive,
			TenantMembershipExists: projection.TenantMembershipExists,
			TenantMembershipActive: projection.TenantMembershipActive,
			AccessGrantLive:        projection.AccessGrantLive,
		},
		Rules: rules, SecurityGroups: groups, LiveAssignments: assignments,
		RolePolicies: roles, ExistingEffectiveRoleIDs: existingRoles,
		Delegation: delegation, LiveOwnedEdges: edges,
	}, ruleDocuments, nil
}

func planningRules(document []byte) ([]identity.LDAPMappingRule, []planningRuleDocument, error) {
	var rows []planningRuleDocument
	if len(document) > 2<<20 || decodePlanningJSON(document, &rows) != nil || len(rows) > 1_000 {
		return nil, nil, ErrInvalidSnapshot
	}
	result := make([]identity.LDAPMappingRule, 0, len(rows))
	for _, row := range rows {
		if !row.Enabled || row.Revision < 1 || row.Revision > math.MaxInt32 ||
			row.Priority < 0 || row.Priority > 1_000_000 || row.AdministrativeNote != "" ||
			(row.OperatorTeamID == nil) != (row.OperatorTeamAssignmentEpochID == nil) {
			return nil, nil, ErrInvalidSnapshot
		}
		matcher, err := planningMatcher(row.MatcherType, row.CaseMode, row.MatcherValue)
		if err != nil {
			return nil, nil, err
		}
		mode, err := planningReconciliationMode(row.ReconciliationMode)
		if err != nil {
			return nil, nil, err
		}
		ruleID, err := entityID(row.RuleID)
		if err != nil {
			return nil, nil, err
		}
		epochID, err := entityID(row.RuleEpochID)
		if err != nil {
			return nil, nil, err
		}
		sourceID, err := entityID(row.SourceID)
		if err != nil {
			return nil, nil, err
		}
		groupID, err := entityID(row.SecurityGroupID)
		if err != nil {
			return nil, nil, err
		}
		roleIDs, err := entityIDs(row.RoleIDs, 100)
		if err != nil {
			return nil, nil, err
		}
		var team *identity.LDAPOperatorTeamTarget
		if row.OperatorTeamID != nil {
			teamID, teamErr := entityID(*row.OperatorTeamID)
			if teamErr != nil {
				return nil, nil, teamErr
			}
			assignmentID, teamErr := entityID(*row.OperatorTeamAssignmentEpochID)
			if teamErr != nil {
				return nil, nil, teamErr
			}
			team = &identity.LDAPOperatorTeamTarget{TeamID: teamID, AssignmentEpochID: assignmentID}
		}
		result = append(result, identity.LDAPMappingRule{
			RuleID: ruleID, RuleEpochID: epochID, SourceID: sourceID,
			Revision: row.Revision, Priority: row.Priority, Enabled: true,
			Matcher: matcher, Mode: mode, SecurityGroupID: groupID,
			RoleIDs: roleIDs, OperatorTeam: team,
		})
	}
	return result, rows, nil
}

func planningSecurityGroups(document []byte) ([]identity.LDAPSecurityGroupPolicy, error) {
	var rows []planningSecurityGroupDocument
	if len(document) > 2<<20 || decodePlanningJSON(document, &rows) != nil || len(rows) > 1_000 {
		return nil, ErrInvalidSnapshot
	}
	result := make([]identity.LDAPSecurityGroupPolicy, 0, len(rows))
	for _, row := range rows {
		group, err := entityID(row.SecurityGroupID)
		if err != nil {
			return nil, err
		}
		roles, err := entityIDs(row.ActiveRoleIDs, 10_000)
		if err != nil {
			return nil, err
		}
		result = append(result, identity.LDAPSecurityGroupPolicy{SecurityGroupID: group, ActiveRoleIDs: roles})
	}
	return result, nil
}

func planningAssignments(document []byte) ([]identity.LDAPOperatorTeamAssignment, error) {
	var rows []planningAssignmentDocument
	if len(document) > 2<<20 || decodePlanningJSON(document, &rows) != nil || len(rows) > 1_000 {
		return nil, ErrInvalidSnapshot
	}
	result := make([]identity.LDAPOperatorTeamAssignment, 0, len(rows))
	for _, row := range rows {
		team, err := entityID(row.OperatorTeamID)
		if err != nil {
			return nil, err
		}
		epoch, err := entityID(row.AssignmentEpochID)
		if err != nil {
			return nil, err
		}
		result = append(result, identity.LDAPOperatorTeamAssignment{
			TeamID: team, AssignmentEpochID: epoch, Live: row.Live,
		})
	}
	return result, nil
}

func planningRolePolicies(document []byte) ([]identity.LDAPRolePolicy, error) {
	var rows []planningRolePolicyDocument
	if len(document) > 16<<20 || decodePlanningJSON(document, &rows) != nil || len(rows) > 10_000 {
		return nil, ErrInvalidSnapshot
	}
	result := make([]identity.LDAPRolePolicy, 0, len(rows))
	totalPermissions := 0
	for _, row := range rows {
		totalPermissions += len(row.Policy)
		if len(row.Policy) > 10_000 || totalPermissions > 100_000 {
			return nil, ErrInvalidSnapshot
		}
		roleID, err := entityID(row.RoleID)
		if err != nil {
			return nil, err
		}
		policy := make([]identity.LDAPPermissionTuple, 0, len(row.Policy))
		for _, item := range row.Policy {
			tuple, tupleErr := planningPermission(item.Permission, item.Scope)
			if tupleErr != nil {
				return nil, tupleErr
			}
			policy = append(policy, tuple)
		}
		result = append(result, identity.LDAPRolePolicy{RoleID: roleID, Policy: policy})
	}
	return result, nil
}

func planningDelegation(document []byte) ([]identity.LDAPDelegationGrant, error) {
	var rows []planningDelegationDocument
	if len(document) > 16<<20 || decodePlanningJSON(document, &rows) != nil || len(rows) > 100_000 {
		return nil, ErrInvalidSnapshot
	}
	result := make([]identity.LDAPDelegationGrant, 0, len(rows))
	for _, row := range rows {
		tuple, err := planningPermission(row.Permission, row.Scope)
		if err != nil || row.NotAfter != nil && row.NotAfter.IsZero() {
			return nil, ErrInvalidSnapshot
		}
		var notAfter *time.Time
		if row.NotAfter != nil {
			value := row.NotAfter.UTC()
			notAfter = &value
		}
		result = append(result, identity.LDAPDelegationGrant{Tuple: tuple, NotAfter: notAfter})
	}
	return result, nil
}

func planningEdges(document []byte) ([]identity.LDAPOwnedMappingEdge, error) {
	var rows []planningOwnedEdgeDocument
	if len(document) > 32<<20 || decodePlanningJSON(document, &rows) != nil || len(rows) > 100_000 {
		return nil, ErrInvalidSnapshot
	}
	result := make([]identity.LDAPOwnedMappingEdge, 0, len(rows))
	for _, row := range rows {
		source, err := entityID(row.SourceID)
		if err != nil {
			return nil, err
		}
		epoch, err := entityID(row.RuleEpochID)
		if err != nil {
			return nil, err
		}
		primary, err := entityID(row.PrimaryID)
		if err != nil {
			return nil, err
		}
		kind, requiresSecondary, err := planningEdgeKind(row.Kind)
		if err != nil || requiresSecondary != (row.SecondaryID != nil) {
			return nil, ErrInvalidSnapshot
		}
		var secondary identity.EntityID
		if row.SecondaryID != nil {
			secondary, err = entityID(*row.SecondaryID)
			if err != nil {
				return nil, err
			}
		}
		result = append(result, identity.LDAPOwnedMappingEdge{
			SourceID: source, RuleEpochID: epoch,
			Key: identity.LDAPMappingEdgeKey{Kind: kind, PrimaryID: primary, SecondaryID: secondary},
		})
	}
	return result, nil
}

func validateRulePins(pins []PinnedMappingRevision, rules []planningRuleDocument) error {
	if len(pins) != len(rules) || len(pins) > 1_000 {
		return ErrInvalidSnapshot
	}
	byID, err := validatedMappingPins(pins)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		pin, found := byID[rule.RuleID]
		if !found || pin.MappingVersion != rule.Revision || pin.SourceEpochID != rule.RuleEpochID ||
			pin.SourceID != rule.SourceID || pin.Priority != rule.Priority {
			return ErrInvalidSnapshot
		}
		delete(byID, rule.RuleID)
	}
	if len(byID) != 0 {
		return ErrInvalidSnapshot
	}
	return nil
}

func validatedMappingPins(pins []PinnedMappingRevision) (map[uuid.UUID]PinnedMappingRevision, error) {
	if len(pins) > 1_000 {
		return nil, ErrInvalidSnapshot
	}
	byID := make(map[uuid.UUID]PinnedMappingRevision, len(pins))
	for _, pin := range pins {
		if _, err := entityID(pin.MappingID); err != nil {
			return nil, err
		}
		if _, err := entityID(pin.SourceEpochID); err != nil {
			return nil, err
		}
		if _, err := entityID(pin.SourceID); err != nil {
			return nil, err
		}
		if pin.MappingVersion < 1 || pin.ConfigurationVersion < 1 ||
			pin.Priority < 0 || pin.Priority > 1_000_000 {
			return nil, ErrInvalidSnapshot
		}
		if _, duplicate := byID[pin.MappingID]; duplicate {
			return nil, ErrInvalidSnapshot
		}
		byID[pin.MappingID] = pin
	}
	return byID, nil
}

func decodePlanningJSON(document []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalidSnapshot
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ErrInvalidSnapshot
	}
	return nil
}

func planningMatcher(kindValue, caseValue, pattern string) (identity.CompiledLDAPGroupMatcher, error) {
	var kind identity.LDAPGroupMatcherKind
	switch kindValue {
	case "exact_dn":
		kind = identity.LDAPGroupMatcherExactDN
	case "exact_cn":
		kind = identity.LDAPGroupMatcherExactCN
	case "regex":
		kind = identity.LDAPGroupMatcherRegex
	default:
		return identity.CompiledLDAPGroupMatcher{}, ErrInvalidSnapshot
	}
	var caseMode identity.LDAPGroupCaseMode
	switch caseValue {
	case "sensitive":
		caseMode = identity.LDAPGroupCaseSensitive
	case "insensitive":
		caseMode = identity.LDAPGroupCaseInsensitive
	default:
		return identity.CompiledLDAPGroupMatcher{}, ErrInvalidSnapshot
	}
	matcher, err := identity.CompileLDAPGroupMatcher(identity.LDAPGroupMatcherSpec{
		Kind: kind, CaseMode: caseMode, Pattern: pattern,
	})
	if err != nil {
		return identity.CompiledLDAPGroupMatcher{}, ErrInvalidSnapshot
	}
	return matcher, nil
}

func planningReconciliationMode(value string) (identity.LDAPReconciliationMode, error) {
	switch value {
	case "additive":
		return identity.LDAPReconciliationAdditive, nil
	case "authoritative":
		return identity.LDAPReconciliationAuthoritative, nil
	default:
		return 0, ErrInvalidSnapshot
	}
}

func planningJITMode(value string) (identity.LDAPJITMode, error) {
	switch value {
	case "disabled":
		return identity.LDAPJITDisabled, nil
	case "existing_identity":
		return identity.LDAPJITExistingIdentity, nil
	case "create":
		return identity.LDAPJITCreate, nil
	default:
		return 0, ErrInvalidSnapshot
	}
}

func planningNoMatchPolicy(value string) (identity.LDAPNoMatchPolicy, error) {
	switch value {
	case "deny":
		return identity.LDAPNoMatchDeny, nil
	case "provider_access_only":
		return identity.LDAPNoMatchProviderAccessOnly, nil
	default:
		return 0, ErrInvalidSnapshot
	}
}

func planningPermission(permission, scopeValue string) (identity.LDAPPermissionTuple, error) {
	if len(permission) < 1 || len(permission) > 128 || strings.TrimSpace(permission) != permission {
		return identity.LDAPPermissionTuple{}, ErrInvalidSnapshot
	}
	var scope identity.LDAPPermissionScope
	switch scopeValue {
	case "own":
		scope = identity.LDAPScopeOwn
	case "assigned":
		scope = identity.LDAPScopeAssigned
	case "operator_team":
		scope = identity.LDAPScopeOperatorTeam
	case "tenant":
		scope = identity.LDAPScopeTenant
	default:
		return identity.LDAPPermissionTuple{}, ErrInvalidSnapshot
	}
	return identity.LDAPPermissionTuple{Permission: permission, Scope: scope}, nil
}

func planningEdgeKind(value string) (identity.LDAPMappingEdgeKind, bool, error) {
	switch value {
	case "security_group_membership":
		return identity.LDAPSecurityGroupMembershipEdge, false, nil
	case "security_group_role_grant":
		return identity.LDAPSecurityGroupRoleGrantEdge, true, nil
	case "operator_team_roster":
		return identity.LDAPOperatorTeamRosterEdge, true, nil
	default:
		return 0, false, ErrInvalidSnapshot
	}
}

func matchedEpochIDs(
	plan identity.LDAPMappingPlan,
	rules []planningRuleDocument,
) ([]uuid.UUID, error) {
	matched := plan.MatchedRuleIDs()
	if len(matched) == 0 {
		return []uuid.UUID{}, nil
	}
	epochByRule := make(map[identity.EntityID]uuid.UUID, len(rules))
	for _, rule := range rules {
		epochByRule[identity.EntityID(rule.RuleID)] = rule.RuleEpochID
	}
	result := make([]uuid.UUID, 0, len(matched))
	for _, ruleID := range matched {
		epoch, ok := epochByRule[ruleID]
		if !ok {
			return nil, ErrInvalidSnapshot
		}
		result = append(result, epoch)
	}
	return result, nil
}

func entityID(value uuid.UUID) (identity.EntityID, error) {
	if value == uuid.Nil || value.Version() != 7 || value.Variant() != uuid.RFC4122 {
		return identity.EntityID{}, ErrInvalidSnapshot
	}
	return identity.EntityID(value), nil
}

func entityIDs(values []uuid.UUID, maximum int) ([]identity.EntityID, error) {
	if len(values) > maximum {
		return nil, ErrInvalidSnapshot
	}
	result := make([]identity.EntityID, 0, len(values))
	for _, value := range values {
		mapped, err := entityID(value)
		if err != nil {
			return nil, err
		}
		result = append(result, mapped)
	}
	return result, nil
}
