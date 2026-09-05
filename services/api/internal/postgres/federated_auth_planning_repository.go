package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

const (
	loadFederatedAuthenticationPlanningStateSQL = `select app.load_federated_authentication_planning_state_v1($1::jsonb)`
	maximumFederatedPlanningWireBytes           = 32 * 1024 * 1024
	maximumFederatedPlanningRules               = 2_000
	maximumFederatedPlanningRolesPerRule        = 100
	maximumFederatedPlanningAliases             = 16
)

type federatedSubjectAliasWire struct {
	KeyVersion int16  `json:"keyVersion"`
	Digest     []byte `json:"digest"`
}

type federatedPlanningLookupWire struct {
	Protocol                string                        `json:"protocol"`
	TenantID                string                        `json:"tenantId"`
	Provider                federatedProviderBindingWire  `json:"provider"`
	Admission               *federatedTenantAdmissionWire `json:"admission,omitempty"`
	SubjectFormat           string                        `json:"subjectFormat"`
	SubjectAliases          []federatedSubjectAliasWire   `json:"subjectAliases"`
	ProviderRevision        uint64                        `json:"providerRevision"`
	BindingRevision         uint64                        `json:"bindingRevision"`
	ConfigurationRevision   uint64                        `json:"configurationRevision"`
	SecurityRevision        uint64                        `json:"securityRevision"`
	MappingRevision         uint64                        `json:"mappingRevision"`
	AuthorizationRevision   uint64                        `json:"authorizationRevision"`
	AssurancePolicyRevision uint64                        `json:"assurancePolicyRevision"`
}

type federatedSubjectMatchWire struct {
	ExternalIdentityID string                    `json:"externalIdentityId"`
	Alias              federatedSubjectAliasWire `json:"alias"`
}

type federatedMappingMatcherWire struct {
	Kind      string `json:"kind"`
	ClaimName string `json:"claimName,omitempty"`
	Value     string `json:"value"`
}

type federatedPlanningRuleWire struct {
	RuleID                        uuid.UUID                   `json:"ruleId"`
	RuleEpochID                   uuid.UUID                   `json:"ruleEpochId"`
	SourceID                      uuid.UUID                   `json:"sourceId"`
	Revision                      int64                       `json:"revision"`
	Priority                      int32                       `json:"priority"`
	Enabled                       bool                        `json:"enabled"`
	Matcher                       federatedMappingMatcherWire `json:"matcher"`
	ReconciliationMode            string                      `json:"reconciliationMode"`
	SecurityGroupID               uuid.UUID                   `json:"securityGroupId"`
	RoleIDs                       []uuid.UUID                 `json:"roleIds"`
	OperatorTeamID                *uuid.UUID                  `json:"operatorTeamId"`
	OperatorTeamAssignmentEpochID *uuid.UUID                  `json:"operatorTeamAssignmentEpochId"`
}

type federatedProviderAccessWire struct {
	SourceID               string `json:"sourceId"`
	AccessEpochID          string `json:"accessEpochId"`
	ExternalIdentityExists bool   `json:"externalIdentityExists"`
	UserActive             bool   `json:"userActive"`
	TenantMembershipExists bool   `json:"tenantMembershipExists"`
	TenantMembershipActive bool   `json:"tenantMembershipActive"`
	AccessGrantLive        bool   `json:"accessGrantLive"`
}

type federatedMappingPlanningSnapshotWire struct {
	TenantID                 string                              `json:"tenantId"`
	Provider                 federatedProviderBindingWire        `json:"provider"`
	Admission                *federatedTenantAdmissionWire       `json:"admission,omitempty"`
	ConfigurationRevision    int64                               `json:"configurationRevision"`
	RuleSetRevision          int64                               `json:"ruleSetRevision"`
	AuthorizationRevision    int64                               `json:"authorizationRevision"`
	JITMode                  string                              `json:"jitMode"`
	NoMatchPolicy            string                              `json:"noMatchPolicy"`
	EffectiveUntil           *time.Time                          `json:"effectiveUntil"`
	ProviderAccess           federatedProviderAccessWire         `json:"providerAccess"`
	Rules                    []federatedPlanningRuleWire         `json:"rules"`
	SecurityGroups           []ldapPlanningSecurityGroupDocument `json:"securityGroups"`
	LiveAssignments          []ldapPlanningAssignmentDocument    `json:"liveAssignments"`
	RolePolicies             []ldapPlanningRolePolicyDocument    `json:"rolePolicies"`
	ExistingEffectiveRoleIDs []uuid.UUID                         `json:"existingEffectiveRoleIds"`
	Delegation               []ldapPlanningDelegationDocument    `json:"delegation"`
	LiveOwnedEdges           []ldapPlanningOwnedEdgeDocument     `json:"liveOwnedEdges"`
}

type federatedPlanningStateWire struct {
	Lookup                  federatedPlanningLookupWire          `json:"lookup"`
	PlanRevision            uint64                               `json:"planRevision"`
	UserID                  string                               `json:"userId,omitempty"`
	IdentityEpoch           uint64                               `json:"identityEpoch"`
	ExternalIdentityID      string                               `json:"externalIdentityId"`
	SubjectMatch            *federatedSubjectMatchWire           `json:"subjectMatch"`
	ProviderRevision        uint64                               `json:"providerRevision"`
	BindingRevision         uint64                               `json:"bindingRevision"`
	SecurityRevision        uint64                               `json:"securityRevision"`
	AssurancePolicyRevision uint64                               `json:"assurancePolicyRevision"`
	Mapping                 federatedMappingPlanningSnapshotWire `json:"mapping"`
	Requirement             assuranceRequirementWire             `json:"requirement"`
	HasEnrollableFactor     bool                                 `json:"hasEnrollableFactor"`
}

var _ federatedauth.FederatedPlanningStateSource = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) LoadFederatedPlanningState(
	ctx context.Context,
	lookup federatedauth.FederatedPlanningLookup,
) (federatedauth.FederatedPlanningState, error) {
	wire, err := federatedPlanningLookupToWire(lookup)
	if err != nil {
		return federatedauth.FederatedPlanningState{}, errFederatedAuthPersistence
	}
	defer clearFederatedPlanningLookupWire(&wire)
	var response federatedPlanningStateWire
	defer clearFederatedPlanningStateWire(&response)
	if err := repository.queryBoundedJSON(
		ctx, loadFederatedAuthenticationPlanningStateSQL, wire, &response, maximumFederatedPlanningWireBytes,
	); err != nil {
		return federatedauth.FederatedPlanningState{}, err
	}
	return federatedPlanningStateFromWire(response, lookup)
}

func federatedPlanningLookupToWire(
	lookup federatedauth.FederatedPlanningLookup,
) (federatedPlanningLookupWire, error) {
	_, validAdmission := effectiveTenantAdmission(
		lookup.Provider, lookup.TenantID, lookup.BindingID, lookup.Admission,
	)
	if lookup.Protocol != federatedauth.ProtocolOIDC && lookup.Protocol != federatedauth.ProtocolSAML ||
		!validAdmission ||
		lookup.SubjectFormat != identity.UTF8ExactSubject || !validFederatedPlanningAliases(lookup.SubjectAliases) ||
		!validFederatedRevision(lookup.ProviderRevision) || !validFederatedRevision(lookup.BindingRevision) ||
		!validFederatedRevision(lookup.ConfigurationRevision) || !validFederatedRevision(lookup.SecurityRevision) ||
		!validFederatedRevision(lookup.MappingRevision) || !validFederatedRevision(lookup.AuthorizationRevision) ||
		!validFederatedRevision(lookup.AssurancePolicyRevision) {
		return federatedPlanningLookupWire{}, errFederatedAuthPersistence
	}
	tenantID, err := requiredFederatedEntityIDWire(lookup.TenantID)
	if err != nil {
		return federatedPlanningLookupWire{}, errFederatedAuthPersistence
	}
	provider, admission, err := providerTenantAdmissionToWire(
		lookup.Provider, lookup.TenantID, lookup.BindingID, lookup.Admission,
	)
	if err != nil {
		return federatedPlanningLookupWire{}, errFederatedAuthPersistence
	}
	return federatedPlanningLookupWire{
		Protocol: string(lookup.Protocol), TenantID: tenantID, Provider: provider, Admission: admission,
		SubjectFormat:    "utf8_exact",
		SubjectAliases:   federatedSubjectAliasesToWire(lookup.SubjectAliases),
		ProviderRevision: lookup.ProviderRevision, BindingRevision: lookup.BindingRevision,
		ConfigurationRevision: lookup.ConfigurationRevision, SecurityRevision: lookup.SecurityRevision,
		MappingRevision: lookup.MappingRevision, AuthorizationRevision: lookup.AuthorizationRevision,
		AssurancePolicyRevision: lookup.AssurancePolicyRevision,
	}, nil
}

func federatedPlanningLookupFromWire(
	wire federatedPlanningLookupWire,
) (federatedauth.FederatedPlanningLookup, error) {
	protocol := federatedauth.Protocol(wire.Protocol)
	if protocol != federatedauth.ProtocolOIDC && protocol != federatedauth.ProtocolSAML || wire.SubjectFormat != "utf8_exact" {
		return federatedauth.FederatedPlanningLookup{}, errFederatedAuthPersistence
	}
	tenantID, err := parseFederatedEntityIDWire(wire.TenantID, false)
	if err != nil {
		return federatedauth.FederatedPlanningLookup{}, errFederatedAuthPersistence
	}
	provider, admission, binding, err := providerTenantAdmissionFromWire(wire.Provider, wire.Admission, tenantID)
	aliases, aliasErr := federatedSubjectAliasesFromWire(wire.SubjectAliases)
	if err != nil || aliasErr != nil ||
		!validFederatedRevision(wire.ProviderRevision) || !validFederatedRevision(wire.BindingRevision) ||
		!validFederatedRevision(wire.ConfigurationRevision) || !validFederatedRevision(wire.SecurityRevision) ||
		!validFederatedRevision(wire.MappingRevision) || !validFederatedRevision(wire.AuthorizationRevision) ||
		!validFederatedRevision(wire.AssurancePolicyRevision) {
		return federatedauth.FederatedPlanningLookup{}, errFederatedAuthPersistence
	}
	return federatedauth.FederatedPlanningLookup{
		Protocol: protocol, TenantID: tenantID, Admission: admission, Provider: provider, BindingID: binding,
		SubjectFormat: identity.UTF8ExactSubject, SubjectAliases: aliases,
		ProviderRevision: wire.ProviderRevision, BindingRevision: wire.BindingRevision,
		ConfigurationRevision: wire.ConfigurationRevision, SecurityRevision: wire.SecurityRevision,
		MappingRevision: wire.MappingRevision, AuthorizationRevision: wire.AuthorizationRevision,
		AssurancePolicyRevision: wire.AssurancePolicyRevision,
	}, nil
}

func federatedPlanningStateFromWire(
	wire federatedPlanningStateWire,
	wanted federatedauth.FederatedPlanningLookup,
) (federatedauth.FederatedPlanningState, error) {
	lookup, err := federatedPlanningLookupFromWire(wire.Lookup)
	if err != nil || !sameFederatedPlanningLookup(lookup, wanted) || !validFederatedRevision(wire.PlanRevision) ||
		wire.ProviderRevision != wanted.ProviderRevision || wire.BindingRevision != wanted.BindingRevision ||
		wire.SecurityRevision != wanted.SecurityRevision ||
		wire.AssurancePolicyRevision != wanted.AssurancePolicyRevision {
		return federatedauth.FederatedPlanningState{}, errFederatedAuthPersistence
	}
	externalIdentityID, err := parseFederatedEntityIDWire(wire.ExternalIdentityID, false)
	if err != nil {
		return federatedauth.FederatedPlanningState{}, errFederatedAuthPersistence
	}
	userID, err := parseFederatedEntityIDWire(wire.UserID, true)
	if err != nil || (userID == (identity.EntityID{})) != (wire.IdentityEpoch == 0) {
		return federatedauth.FederatedPlanningState{}, errFederatedAuthPersistence
	}
	match, err := federatedSubjectMatchFromWire(wire.SubjectMatch, externalIdentityID, wanted.SubjectAliases)
	if err != nil || (userID == (identity.EntityID{})) != (match == nil) {
		return federatedauth.FederatedPlanningState{}, errFederatedAuthPersistence
	}
	mapping, err := federatedMappingPlanningSnapshotFromWire(wire.Mapping, wanted)
	if err != nil {
		return federatedauth.FederatedPlanningState{}, errFederatedAuthPersistence
	}
	identityExists := mapping.ProviderAccess.ExternalIdentityExists
	if identityExists != (userID != (identity.EntityID{})) || identityExists != (match != nil) {
		return federatedauth.FederatedPlanningState{}, errFederatedAuthPersistence
	}
	requirement, err := requirementFromWire(wire.Requirement)
	if err != nil {
		return federatedauth.FederatedPlanningState{}, errFederatedAuthPersistence
	}
	if requirement.EnrollmentDeadline != nil {
		value, valid := canonicalFederatedDatabaseTimeFromWire(*requirement.EnrollmentDeadline)
		if !valid {
			return federatedauth.FederatedPlanningState{}, errFederatedAuthPersistence
		}
		requirement.EnrollmentDeadline = &value
	}
	if !validFederatedPlanningRequirement(requirement) {
		return federatedauth.FederatedPlanningState{}, errFederatedAuthPersistence
	}
	return federatedauth.FederatedPlanningState{
		PlanRevision: wire.PlanRevision, UserID: userID, IdentityEpoch: wire.IdentityEpoch,
		ExternalIdentityID: externalIdentityID, SubjectMatch: match,
		ProviderRevision: wire.ProviderRevision, BindingRevision: wire.BindingRevision,
		SecurityRevision: wire.SecurityRevision, AssurancePolicyRevision: wire.AssurancePolicyRevision,
		Mapping: mapping, Requirement: requirement, HasEnrollableFactor: wire.HasEnrollableFactor,
	}, nil
}

func federatedMappingPlanningSnapshotFromWire(
	wire federatedMappingPlanningSnapshotWire,
	wanted federatedauth.FederatedPlanningLookup,
) (identity.FederatedPlanningSnapshot, error) {
	tenantID, err := parseFederatedEntityIDWire(wire.TenantID, false)
	provider, admission, binding, providerErr := providerTenantAdmissionFromWire(
		wire.Provider, wire.Admission, tenantID,
	)
	var effectiveUntil *time.Time
	if wire.EffectiveUntil != nil {
		value, valid := canonicalFederatedDatabaseTimeFromWire(*wire.EffectiveUntil)
		if !valid {
			return identity.FederatedPlanningSnapshot{}, errFederatedAuthPersistence
		}
		effectiveUntil = &value
	}
	_, validAdmission := effectiveTenantAdmission(provider, tenantID, binding, admission)
	_, validWantedAdmission := effectiveTenantAdmission(
		wanted.Provider, wanted.TenantID, wanted.BindingID, wanted.Admission,
	)
	if err != nil || providerErr != nil || !validAdmission || !validWantedAdmission ||
		tenantID != wanted.TenantID || provider != wanted.Provider ||
		binding != wanted.BindingID || wire.ConfigurationRevision != int64(wanted.ConfigurationRevision) ||
		wire.RuleSetRevision != int64(wanted.MappingRevision) ||
		wire.AuthorizationRevision != int64(wanted.AuthorizationRevision) ||
		wire.ConfigurationRevision < 1 || wire.RuleSetRevision < 1 || wire.AuthorizationRevision < 1 {
		return identity.FederatedPlanningSnapshot{}, errFederatedAuthPersistence
	}
	access, err := federatedProviderAccessFromWire(wire.ProviderAccess)
	if err != nil {
		return identity.FederatedPlanningSnapshot{}, errFederatedAuthPersistence
	}
	rules, err := federatedPlanningRulesFromWire(wire.Rules)
	if err != nil {
		return identity.FederatedPlanningSnapshot{}, errFederatedAuthPersistence
	}
	securityGroups, err := federatedMapPlanningDocument(wire.SecurityGroups, mapLDAPPlanningSecurityGroups)
	if err != nil {
		return identity.FederatedPlanningSnapshot{}, errFederatedAuthPersistence
	}
	assignments, err := federatedMapPlanningDocument(wire.LiveAssignments, mapLDAPPlanningAssignments)
	if err != nil {
		return identity.FederatedPlanningSnapshot{}, errFederatedAuthPersistence
	}
	rolePolicies, err := federatedMapPlanningDocument(wire.RolePolicies, mapLDAPPlanningRolePolicies)
	if err != nil {
		return identity.FederatedPlanningSnapshot{}, errFederatedAuthPersistence
	}
	existingRoles, err := mapLDAPPlanningUUIDs(wire.ExistingEffectiveRoleIDs, maximumLDAPDryRunMappings*10)
	if err != nil {
		return identity.FederatedPlanningSnapshot{}, errFederatedAuthPersistence
	}
	delegation, err := federatedMapPlanningDocument(wire.Delegation, mapLDAPPlanningDelegation)
	if err != nil {
		return identity.FederatedPlanningSnapshot{}, errFederatedAuthPersistence
	}
	edges, err := federatedMapPlanningDocument(wire.LiveOwnedEdges, mapLDAPPlanningEdges)
	if err != nil {
		return identity.FederatedPlanningSnapshot{}, errFederatedAuthPersistence
	}
	jitMode, err := mapLDAPPlanningJITMode(wire.JITMode)
	if err != nil {
		return identity.FederatedPlanningSnapshot{}, errFederatedAuthPersistence
	}
	noMatchPolicy, err := mapLDAPPlanningNoMatchPolicy(wire.NoMatchPolicy)
	if err != nil {
		return identity.FederatedPlanningSnapshot{}, errFederatedAuthPersistence
	}
	return identity.FederatedPlanningSnapshot{
		TenantID: tenantID, Provider: provider, BindingID: binding,
		ConfigurationRevision: wire.ConfigurationRevision, RuleSetRevision: wire.RuleSetRevision,
		AuthorizationRevision: wire.AuthorizationRevision, JITMode: jitMode, NoMatchPolicy: noMatchPolicy,
		EffectiveUntil: effectiveUntil, ProviderAccess: access, Rules: rules, SecurityGroups: securityGroups,
		LiveAssignments: assignments, RolePolicies: rolePolicies, ExistingEffectiveRoleIDs: existingRoles,
		Delegation: delegation, LiveOwnedEdges: edges,
	}, nil
}

func federatedPlanningRulesFromWire(values []federatedPlanningRuleWire) ([]identity.FederatedMappingRule, error) {
	if len(values) > maximumFederatedPlanningRules {
		return nil, errFederatedAuthPersistence
	}
	result := make([]identity.FederatedMappingRule, len(values))
	for index := range values {
		value := values[index]
		if !value.Enabled || value.Revision < 1 || value.Priority < 0 || value.Priority > 1_000_000 ||
			len(value.RoleIDs) > maximumFederatedPlanningRolesPerRule ||
			(value.OperatorTeamID == nil) != (value.OperatorTeamAssignmentEpochID == nil) {
			return nil, errFederatedAuthPersistence
		}
		ruleID, err := ldapPlanningEntityID(value.RuleID)
		if err != nil {
			return nil, errFederatedAuthPersistence
		}
		epochID, err := ldapPlanningEntityID(value.RuleEpochID)
		if err != nil {
			return nil, errFederatedAuthPersistence
		}
		sourceID, err := ldapPlanningEntityID(value.SourceID)
		if err != nil {
			return nil, errFederatedAuthPersistence
		}
		groupID, err := ldapPlanningEntityID(value.SecurityGroupID)
		if err != nil {
			return nil, errFederatedAuthPersistence
		}
		roles, err := mapLDAPPlanningUUIDs(value.RoleIDs, maximumFederatedPlanningRolesPerRule)
		if err != nil {
			return nil, errFederatedAuthPersistence
		}
		matcher, err := federatedMappingMatcherFromWire(value.Matcher)
		if err != nil {
			return nil, errFederatedAuthPersistence
		}
		mode, err := mapLDAPPlanningReconciliationMode(value.ReconciliationMode)
		if err != nil {
			return nil, errFederatedAuthPersistence
		}
		var team *identity.LDAPOperatorTeamTarget
		if value.OperatorTeamID != nil {
			teamID, teamErr := ldapPlanningEntityID(*value.OperatorTeamID)
			if teamErr != nil {
				return nil, errFederatedAuthPersistence
			}
			assignmentID, assignmentErr := ldapPlanningEntityID(*value.OperatorTeamAssignmentEpochID)
			if assignmentErr != nil {
				return nil, errFederatedAuthPersistence
			}
			team = &identity.LDAPOperatorTeamTarget{TeamID: teamID, AssignmentEpochID: assignmentID}
		}
		result[index] = identity.FederatedMappingRule{
			RuleID: ruleID, RuleEpochID: epochID, SourceID: sourceID, Revision: value.Revision,
			Priority: value.Priority, Enabled: true, Matcher: matcher, Mode: mode,
			SecurityGroupID: groupID, RoleIDs: roles, OperatorTeam: team,
		}
	}
	return result, nil
}

func federatedMappingMatcherFromWire(
	wire federatedMappingMatcherWire,
) (identity.CompiledFederatedMappingMatcher, error) {
	var kind identity.FederatedMappingMatcherKind
	switch wire.Kind {
	case "group_equals":
		kind = identity.FederatedMappingGroupEquals
	case "scalar_equals":
		kind = identity.FederatedMappingScalarEquals
	default:
		return identity.CompiledFederatedMappingMatcher{}, errFederatedAuthPersistence
	}
	matcher, err := identity.CompileFederatedMappingMatcher(identity.FederatedMappingMatcherSpec{
		Kind: kind, ClaimName: wire.ClaimName, Value: wire.Value,
	})
	if err != nil {
		return identity.CompiledFederatedMappingMatcher{}, errFederatedAuthPersistence
	}
	return matcher, nil
}

func federatedProviderAccessFromWire(
	wire federatedProviderAccessWire,
) (identity.LDAPProviderAccessState, error) {
	sourceID, err := parseFederatedEntityIDWire(wire.SourceID, false)
	if err != nil {
		return identity.LDAPProviderAccessState{}, errFederatedAuthPersistence
	}
	accessEpochID, err := parseFederatedEntityIDWire(wire.AccessEpochID, false)
	if err != nil || wire.UserActive && !wire.ExternalIdentityExists ||
		wire.TenantMembershipExists && (!wire.ExternalIdentityExists || !wire.UserActive) ||
		wire.TenantMembershipActive && !wire.TenantMembershipExists ||
		wire.AccessGrantLive && (!wire.ExternalIdentityExists || !wire.UserActive ||
			!wire.TenantMembershipExists || !wire.TenantMembershipActive) {
		return identity.LDAPProviderAccessState{}, errFederatedAuthPersistence
	}
	return identity.LDAPProviderAccessState{
		SourceID: sourceID, AccessEpochID: accessEpochID,
		ExternalIdentityExists: wire.ExternalIdentityExists, UserActive: wire.UserActive,
		TenantMembershipExists: wire.TenantMembershipExists,
		TenantMembershipActive: wire.TenantMembershipActive, AccessGrantLive: wire.AccessGrantLive,
	}, nil
}

func federatedSubjectMatchFromWire(
	wire *federatedSubjectMatchWire,
	externalIdentityID identity.EntityID,
	aliases []identity.SubjectAlias,
) (*federatedauth.FederatedSubjectMatch, error) {
	if wire == nil {
		return nil, nil
	}
	matchedIdentityID, err := parseFederatedEntityIDWire(wire.ExternalIdentityID, false)
	if err != nil || matchedIdentityID != externalIdentityID {
		return nil, errFederatedAuthPersistence
	}
	values, err := federatedSubjectAliasesFromWire([]federatedSubjectAliasWire{wire.Alias})
	if err != nil || len(values) != 1 || !federatedSubjectAliasPresent(aliases, values[0]) {
		return nil, errFederatedAuthPersistence
	}
	return &federatedauth.FederatedSubjectMatch{ExternalIdentityID: matchedIdentityID, Alias: values[0]}, nil
}

func federatedSubjectAliasesToWire(values []identity.SubjectAlias) []federatedSubjectAliasWire {
	result := make([]federatedSubjectAliasWire, len(values))
	for index := range values {
		result[index] = federatedSubjectAliasWire{
			KeyVersion: values[index].KeyVersion, Digest: append([]byte(nil), values[index].Digest[:]...),
		}
	}
	return result
}

func federatedSubjectAliasesFromWire(values []federatedSubjectAliasWire) ([]identity.SubjectAlias, error) {
	if len(values) < 1 || len(values) > maximumFederatedPlanningAliases {
		return nil, errFederatedAuthPersistence
	}
	result := make([]identity.SubjectAlias, len(values))
	for index := range values {
		if values[index].KeyVersion < 1 || !validDigestWire(values[index].Digest) ||
			index > 0 && values[index-1].KeyVersion >= values[index].KeyVersion {
			return nil, errFederatedAuthPersistence
		}
		result[index].KeyVersion = values[index].KeyVersion
		copy(result[index].Digest[:], values[index].Digest)
	}
	return result, nil
}

func validFederatedPlanningAliases(values []identity.SubjectAlias) bool {
	if len(values) < 1 || len(values) > maximumFederatedPlanningAliases {
		return false
	}
	for index := range values {
		if values[index].KeyVersion < 1 || values[index].Digest == ([sha256.Size]byte{}) ||
			index > 0 && values[index-1].KeyVersion >= values[index].KeyVersion {
			return false
		}
	}
	return true
}

func sameFederatedPlanningLookup(left, right federatedauth.FederatedPlanningLookup) bool {
	leftAdmission, leftValid := effectiveTenantAdmission(
		left.Provider, left.TenantID, left.BindingID, left.Admission,
	)
	rightAdmission, rightValid := effectiveTenantAdmission(
		right.Provider, right.TenantID, right.BindingID, right.Admission,
	)
	return left.Protocol == right.Protocol && left.TenantID == right.TenantID && left.Provider == right.Provider &&
		left.BindingID == right.BindingID && left.SubjectFormat == right.SubjectFormat &&
		leftValid && rightValid && leftAdmission == rightAdmission &&
		left.ProviderRevision == right.ProviderRevision && left.BindingRevision == right.BindingRevision &&
		left.ConfigurationRevision == right.ConfigurationRevision && left.SecurityRevision == right.SecurityRevision &&
		left.MappingRevision == right.MappingRevision && left.AuthorizationRevision == right.AuthorizationRevision &&
		left.AssurancePolicyRevision == right.AssurancePolicyRevision &&
		federatedSubjectAliasesEqual(left.SubjectAliases, right.SubjectAliases)
}

func federatedSubjectAliasesEqual(left, right []identity.SubjectAlias) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].KeyVersion != right[index].KeyVersion ||
			subtle.ConstantTimeCompare(left[index].Digest[:], right[index].Digest[:]) != 1 {
			return false
		}
	}
	return true
}

func federatedSubjectAliasPresent(values []identity.SubjectAlias, wanted identity.SubjectAlias) bool {
	for index := range values {
		if values[index].KeyVersion == wanted.KeyVersion &&
			subtle.ConstantTimeCompare(values[index].Digest[:], wanted.Digest[:]) == 1 {
			return true
		}
	}
	return false
}

func validFederatedPlanningRequirement(value identity.EffectiveAssuranceRequirement) bool {
	if value.Level < identity.AssurancePrimary || value.Level > identity.AssurancePhishingResistant ||
		value.Freshness < 0 || value.Freshness > 365*24*time.Hour || value.Freshness%time.Microsecond != 0 ||
		len(value.PolicyRevisions) < 1 ||
		len(value.PolicyRevisions) > 1_024 || value.EnrollmentDeadline != nil &&
		!validFederatedDatabaseTime(*value.EnrollmentDeadline) {
		return false
	}
	for index := range value.PolicyRevisions {
		current := value.PolicyRevisions[index]
		if _, err := requiredFederatedEntityIDWire(current.PolicyID); err != nil || current.Revision < 1 || index > 0 &&
			bytes.Compare(value.PolicyRevisions[index-1].PolicyID[:], current.PolicyID[:]) >= 0 {
			return false
		}
	}
	return true
}

func federatedMapPlanningDocument[T any, R any](value T, mapper func([]byte) (R, error)) (R, error) {
	var zero R
	document, err := json.Marshal(value)
	if err != nil || len(document) == 0 || len(document) > maximumFederatedPlanningWireBytes {
		clear(document)
		return zero, errFederatedAuthPersistence
	}
	defer clear(document)
	result, err := mapper(document)
	if err != nil {
		return zero, errFederatedAuthPersistence
	}
	return result, nil
}

func clearFederatedPlanningLookupWire(value *federatedPlanningLookupWire) {
	if value == nil {
		return
	}
	for index := range value.SubjectAliases {
		clear(value.SubjectAliases[index].Digest)
	}
	clear(value.SubjectAliases)
}

func clearFederatedPlanningStateWire(value *federatedPlanningStateWire) {
	if value == nil {
		return
	}
	clearFederatedPlanningLookupWire(&value.Lookup)
	if value.SubjectMatch != nil {
		clear(value.SubjectMatch.Alias.Digest)
	}
	for index := range value.Mapping.Rules {
		value.Mapping.Rules[index].Matcher.ClaimName = ""
		value.Mapping.Rules[index].Matcher.Value = ""
	}
}
