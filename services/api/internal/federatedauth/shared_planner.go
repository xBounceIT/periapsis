package federatedauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

// FederatedPlanningLookup deliberately excludes profile, email, scalar, and
// group values. Persistence may resolve an existing identity only through the
// exact provider-qualified issuer/subject tuple; the in-process planner alone
// evaluates mapping inputs.
type FederatedPlanningLookup struct {
	Protocol                Protocol
	TenantID                identity.EntityID
	Admission               identity.TenantAdmissionContext
	Provider                identity.ProviderContext
	BindingID               identity.EntityID
	SubjectFormat           identity.SubjectFormat
	SubjectAliases          []identity.SubjectAlias
	ProviderRevision        uint64
	BindingRevision         uint64
	ConfigurationRevision   uint64
	SecurityRevision        uint64
	MappingRevision         uint64
	AuthorizationRevision   uint64
	AssurancePolicyRevision uint64
}

func (lookup FederatedPlanningLookup) String() string {
	return fmt.Sprintf(
		"federatedauth.FederatedPlanningLookup{protocol:%s,providerRevision:%t,bindingRevision:%t,configurationRevision:%t,securityRevision:%t,mappingRevision:%t,authorizationRevision:%t,policyRevision:%t,subjectFormat:%d,aliases:%d,subject:[REDACTED]}",
		lookup.Protocol, lookup.ProviderRevision != 0, lookup.BindingRevision != 0,
		lookup.ConfigurationRevision != 0, lookup.SecurityRevision != 0, lookup.MappingRevision != 0,
		lookup.AuthorizationRevision != 0, lookup.AssurancePolicyRevision != 0,
		lookup.SubjectFormat, len(lookup.SubjectAliases),
	)
}
func (lookup FederatedPlanningLookup) GoString() string { return lookup.String() }

// FederatedPlanningState is the RLS-scoped immutable snapshot loaded without
// mutation. Mapping carries the exact shared LDAP/federated authorization
// consequences; the remaining fields bind assurance and identity liveness.
type FederatedPlanningState struct {
	PlanRevision            uint64
	UserID                  identity.EntityID
	IdentityEpoch           uint64
	ExternalIdentityID      identity.EntityID
	SubjectMatch            *FederatedSubjectMatch
	ProviderRevision        uint64
	BindingRevision         uint64
	SecurityRevision        uint64
	AssurancePolicyRevision uint64
	Mapping                 identity.FederatedPlanningSnapshot
	Requirement             identity.EffectiveAssuranceRequirement
	HasEnrollableFactor     bool
}

// FederatedSubjectMatch is the exact alias row selected by persistence. The
// duplicated identity ID makes it impossible for an adapter to return an
// alias match detached from the external identity snapshot used for apply.
type FederatedSubjectMatch struct {
	ExternalIdentityID identity.EntityID
	Alias              identity.SubjectAlias
}

func (match FederatedSubjectMatch) String() string {
	return fmt.Sprintf(
		"federatedauth.FederatedSubjectMatch{identity:%t,alias:%q,material:[REDACTED]}",
		match.ExternalIdentityID != (identity.EntityID{}), match.Alias.String(),
	)
}
func (match FederatedSubjectMatch) GoString() string { return match.String() }

func (state FederatedPlanningState) String() string {
	return fmt.Sprintf(
		"federatedauth.FederatedPlanningState{planRevision:%t,user:%t,identityEpoch:%t,externalIdentity:%t,matchedAlias:%t,providerRevision:%t,bindingRevision:%t,securityRevision:%t,policyRevision:%t,mapping:%q}",
		state.PlanRevision != 0, state.UserID != (identity.EntityID{}), state.IdentityEpoch != 0,
		state.ExternalIdentityID != (identity.EntityID{}), state.SubjectMatch != nil,
		state.ProviderRevision != 0, state.BindingRevision != 0, state.SecurityRevision != 0,
		state.AssurancePolicyRevision != 0, state.Mapping.String(),
	)
}
func (state FederatedPlanningState) GoString() string { return state.String() }

type FederatedPlanningStateSource interface {
	LoadFederatedPlanningState(context.Context, FederatedPlanningLookup) (FederatedPlanningState, error)
}

// SharedFederatedPlanner adapts verified OIDC claims to the exact matcher-
// neutral core also used by PlanLDAPMapping.
type SharedFederatedPlanner struct {
	source  FederatedPlanningStateSource
	keyring identity.Keyring
}

type SharedFederatedPlannerOptions struct {
	Source  FederatedPlanningStateSource
	Keyring identity.Keyring
}

func NewSharedFederatedPlanner(options SharedFederatedPlannerOptions) (*SharedFederatedPlanner, error) {
	if options.Source == nil || options.Keyring.ActiveVersion() < 1 {
		return nil, ErrInvalidOptions
	}
	return &SharedFederatedPlanner{source: options.Source, keyring: options.Keyring}, nil
}

func (planner *SharedFederatedPlanner) String() string {
	return fmt.Sprintf(
		"federatedauth.SharedFederatedPlanner{configured:%t}",
		planner != nil && planner.source != nil && planner.keyring.ActiveVersion() > 0,
	)
}
func (planner *SharedFederatedPlanner) GoString() string { return planner.String() }

func (planner *SharedFederatedPlanner) PlanFederatedAuthentication(
	ctx context.Context,
	request PlanningRequest,
) (AuthenticationPlan, error) {
	if planner == nil || planner.source == nil || ctx == nil || ctx.Err() != nil ||
		request.Action != "session.create" || request.Authentication.Protocol != ProtocolOIDC ||
		!validProjection(request.Authentication) || request.Authentication.OIDCCompletion == nil ||
		planner.keyring.ActiveVersion() < 1 {
		return AuthenticationPlan{}, ErrAuthentication
	}
	lookup, subject, ok := planner.oidcFederatedPlanningLookup(request.Authentication)
	if !ok {
		return AuthenticationPlan{}, ErrAuthentication
	}
	defer subject.Clear()
	state, err := planner.source.LoadFederatedPlanningState(ctx, cloneFederatedPlanningLookup(lookup))
	state = cloneFederatedPlanningState(state)
	if err != nil || ctx.Err() != nil || !validFederatedPlanningState(state, lookup) {
		return AuthenticationPlan{}, ErrAuthentication
	}
	observation, err := federatedMappingObservation(request.Authentication, subject)
	if err != nil {
		return AuthenticationPlan{}, ErrAuthentication
	}
	mapping, err := identity.PlanFederatedMapping(observation, state.Mapping)
	if err != nil || mapping.Disposition() != identity.LDAPPlanAdmitted {
		return AuthenticationPlan{}, ErrAuthentication
	}
	envelope, err := planner.keyring.EncryptExternalSubject(identity.ExternalSubjectContext{
		Provider: lookup.Provider, ExternalIdentityID: state.ExternalIdentityID,
	}, subject)
	if err != nil {
		return AuthenticationPlan{}, ErrAuthentication
	}
	protectedSubject := ProtectedFederatedSubject{
		ExternalIdentityID: state.ExternalIdentityID,
		Aliases:            append([]identity.SubjectAlias(nil), lookup.SubjectAliases...),
		Envelope:           envelope,
	}
	mappingCopy := identity.CloneFederatedMappingPlan(mapping)
	return AuthenticationPlan{
		PlanRevision: state.PlanRevision, TenantID: lookup.TenantID, UserID: state.UserID,
		IdentityEpoch: state.IdentityEpoch, ProviderRevision: lookup.ProviderRevision,
		BindingRevision: state.BindingRevision, ConfigurationRevision: lookup.ConfigurationRevision,
		SecurityRevision: state.SecurityRevision, MappingRevision: lookup.MappingRevision,
		AuthorizationRevision: lookup.AuthorizationRevision, PolicyRevision: state.AssurancePolicyRevision,
		RoleIDs: mapping.ProspectiveRoleIDs(), SecurityGroupIDs: mapping.ProspectiveSecurityGroupIDs(),
		Subject: &protectedSubject, Mapping: &mappingCopy,
		Requirement: state.Requirement, HasEnrollableFactor: state.HasEnrollableFactor,
	}, nil
}

func (planner *SharedFederatedPlanner) oidcFederatedPlanningLookup(
	projection AuthenticationProjection,
) (FederatedPlanningLookup, identity.Subject, bool) {
	if projection.OIDCCompletion == nil {
		return FederatedPlanningLookup{}, identity.Subject{}, false
	}
	subject, err := identity.CanonicalOIDCIssuerSubject(projection.Subject.Issuer, projection.Subject.Value)
	if err != nil {
		return FederatedPlanningLookup{}, identity.Subject{}, false
	}
	aliases, err := planner.keyring.SubjectAliases(projection.Subject.Provider, subject)
	if err != nil {
		subject.Clear()
		return FederatedPlanningLookup{}, identity.Subject{}, false
	}
	pins := projection.OIDCCompletion.Pins
	admission, validAdmission := projectionOIDCAdmission(projection)
	if !validAdmission {
		subject.Clear()
		return FederatedPlanningLookup{}, identity.Subject{}, false
	}
	lookup := FederatedPlanningLookup{
		Protocol: ProtocolOIDC, TenantID: projection.TenantID, Admission: projection.Admission,
		Provider: pins.Provider, BindingID: admission.BindingID,
		SubjectFormat: subject.Format(), SubjectAliases: aliases,
		ProviderRevision: pins.ProviderRevision, BindingRevision: pins.BindingRevision,
		ConfigurationRevision: pins.ConfigurationRevision, SecurityRevision: pins.SecurityRevision,
		MappingRevision: pins.MappingRevision, AuthorizationRevision: pins.AuthorizationRevision,
		AssurancePolicyRevision: pins.AssurancePolicyRevision,
	}
	if !validFederatedPlanningLookup(lookup) {
		subject.Clear()
		return FederatedPlanningLookup{}, identity.Subject{}, false
	}
	return lookup, subject, true
}

func validFederatedPlanningLookup(lookup FederatedPlanningLookup) bool {
	admission := lookup.Admission
	if admission == (identity.TenantAdmissionContext{}) && lookup.Provider.Scope == identity.TenantProviderScope {
		admission = identity.TenantAdmissionContext{TenantID: lookup.TenantID, BindingID: lookup.BindingID}
	}
	return lookup.Protocol == ProtocolOIDC && admission.TenantID == lookup.TenantID &&
		admission.BindingID == lookup.BindingID && validTenantAdmission(lookup.Provider, admission) &&
		lookup.SubjectFormat == identity.UTF8ExactSubject && validSubjectAliases(lookup.SubjectAliases) &&
		validDatabaseRevision(lookup.ProviderRevision) && validDatabaseRevision(lookup.BindingRevision) &&
		validDatabaseRevision(lookup.ConfigurationRevision) && validDatabaseRevision(lookup.SecurityRevision) &&
		validDatabaseRevision(lookup.MappingRevision) && validDatabaseRevision(lookup.AuthorizationRevision) &&
		validDatabaseRevision(lookup.AssurancePolicyRevision)
}

func validFederatedPlanningState(state FederatedPlanningState, lookup FederatedPlanningLookup) bool {
	mapping := state.Mapping
	identityExists := mapping.ProviderAccess.ExternalIdentityExists
	return validDatabaseRevision(state.PlanRevision) && state.ProviderRevision == lookup.ProviderRevision &&
		state.BindingRevision == lookup.BindingRevision &&
		state.SecurityRevision == lookup.SecurityRevision &&
		state.AssurancePolicyRevision == lookup.AssurancePolicyRevision &&
		mapping.TenantID == lookup.TenantID && mapping.Provider == lookup.Provider &&
		mapping.BindingID == lookup.BindingID &&
		mapping.ConfigurationRevision == int64(lookup.ConfigurationRevision) &&
		mapping.RuleSetRevision == int64(lookup.MappingRevision) &&
		mapping.AuthorizationRevision == int64(lookup.AuthorizationRevision) &&
		state.ExternalIdentityID != (identity.EntityID{}) &&
		(identityExists && state.SubjectMatch != nil &&
			state.SubjectMatch.ExternalIdentityID == state.ExternalIdentityID &&
			subjectAliasPresent(lookup.SubjectAliases, state.SubjectMatch.Alias) ||
			!identityExists && state.SubjectMatch == nil) &&
		(identityExists && state.UserID != (identity.EntityID{}) && state.IdentityEpoch > 0 ||
			!identityExists && state.UserID == (identity.EntityID{}) && state.IdentityEpoch == 0) &&
		(lookup.Provider.Scope != identity.PlatformProviderScope || validPlatformFederatedPlanningSnapshot(mapping))
}

// A platform provider may establish provider-global identity and explicit
// tenant access, but its claims are never an authorization source. Reject a
// poisoned persistence snapshot before the shared mapping kernel can turn
// provider-controlled values into tenant roles, groups, or team membership.
func validPlatformFederatedPlanningSnapshot(snapshot identity.FederatedPlanningSnapshot) bool {
	return len(snapshot.Rules) == 0 && len(snapshot.SecurityGroups) == 0 &&
		len(snapshot.LiveAssignments) == 0 && len(snapshot.RolePolicies) == 0 &&
		len(snapshot.ExistingEffectiveRoleIDs) == 0 && len(snapshot.Delegation) == 0 &&
		len(snapshot.LiveOwnedEdges) == 0
}

func federatedMappingObservation(
	projection AuthenticationProjection,
	subject identity.Subject,
) (identity.FederatedMappingObservation, error) {
	profile := identity.LDAPProfileValues{}
	seenProfile := make(map[string]struct{}, len(projection.Profiles))
	for _, value := range projection.Profiles {
		if _, duplicate := seenProfile[value.Field]; duplicate {
			return identity.FederatedMappingObservation{}, ErrAuthentication
		}
		seenProfile[value.Field] = struct{}{}
		copyValue := value.Value
		switch value.Field {
		case string(identityFieldUsername):
			profile.Username = &copyValue
		case string(identityFieldEmail):
			profile.Email = &copyValue
		case string(identityFieldDisplayName):
			profile.DisplayName = &copyValue
		default:
			return identity.FederatedMappingObservation{}, ErrAuthentication
		}
	}
	scalars := make([]identity.FederatedMappingScalar, 0, len(projection.Scalars))
	for _, value := range projection.Scalars {
		scalars = append(scalars, identity.FederatedMappingScalar{Name: value.Name, Value: value.Value})
	}
	return identity.NewFederatedMappingObservation(identity.FederatedMappingObservationInput{
		Subject: subject, Profile: profile, Scalars: scalars,
		Groups: append([]string(nil), projection.Groups...), Complete: true,
	})
}

func cloneFederatedPlanningLookup(value FederatedPlanningLookup) FederatedPlanningLookup {
	value.SubjectAliases = append([]identity.SubjectAlias(nil), value.SubjectAliases...)
	return value
}

func cloneFederatedPlanningState(value FederatedPlanningState) FederatedPlanningState {
	value.Mapping = identity.CloneFederatedPlanningSnapshot(value.Mapping)
	value.Requirement.PolicyRevisions = append(
		[]identity.AssurancePolicyRevision(nil), value.Requirement.PolicyRevisions...,
	)
	if value.Requirement.EnrollmentDeadline != nil {
		copyValue := *value.Requirement.EnrollmentDeadline
		value.Requirement.EnrollmentDeadline = &copyValue
	}
	if value.SubjectMatch != nil {
		copyValue := *value.SubjectMatch
		value.SubjectMatch = &copyValue
	}
	return value
}

func validSubjectAliases(values []identity.SubjectAlias) bool {
	if len(values) < 1 || len(values) > 16 {
		return false
	}
	for index, alias := range values {
		if alias.KeyVersion < 1 || alias.Digest == ([sha256.Size]byte{}) ||
			index > 0 && values[index-1].KeyVersion >= alias.KeyVersion {
			return false
		}
	}
	return true
}

func subjectAliasPresent(values []identity.SubjectAlias, wanted identity.SubjectAlias) bool {
	for _, value := range values {
		if value.KeyVersion == wanted.KeyVersion &&
			subtle.ConstantTimeCompare(value.Digest[:], wanted.Digest[:]) == 1 {
			return true
		}
	}
	return false
}

const (
	identityFieldUsername    = "username"
	identityFieldEmail       = "email"
	identityFieldDisplayName = "display_name"
)
