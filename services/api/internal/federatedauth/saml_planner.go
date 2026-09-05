package federatedauth

import (
	"context"
	"fmt"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type SAMLSharedFederatedPlannerOptions struct {
	Source  FederatedPlanningStateSource
	Keyring identity.Keyring
}

// SAMLSharedFederatedPlanner applies the same source-owned mapping and
// collision rules as OIDC while domain-separating the exact SAML issuer,
// subject source, name/format, and value tuple.
type SAMLSharedFederatedPlanner struct {
	source  FederatedPlanningStateSource
	keyring identity.Keyring
}

func NewSAMLSharedFederatedPlanner(options SAMLSharedFederatedPlannerOptions) (*SAMLSharedFederatedPlanner, error) {
	if options.Source == nil || options.Keyring.ActiveVersion() < 1 {
		return nil, ErrInvalidOptions
	}
	return &SAMLSharedFederatedPlanner{source: options.Source, keyring: options.Keyring}, nil
}

func (planner *SAMLSharedFederatedPlanner) String() string {
	return fmt.Sprintf(
		"federatedauth.SAMLSharedFederatedPlanner{configured:%t}",
		planner != nil && planner.source != nil && planner.keyring.ActiveVersion() > 0,
	)
}
func (planner *SAMLSharedFederatedPlanner) GoString() string { return planner.String() }

func (planner *SAMLSharedFederatedPlanner) PlanSAMLAuthentication(
	ctx context.Context,
	request SAMLPlanningRequest,
) (AuthenticationPlan, error) {
	if planner == nil || planner.source == nil || ctx == nil || ctx.Err() != nil ||
		request.Action != "session.create" || !validSAMLAuthenticationProjection(request.Authentication) ||
		planner.keyring.ActiveVersion() < 1 {
		return AuthenticationPlan{}, ErrAuthentication
	}
	lookup, subject, ok := planner.samlFederatedPlanningLookup(request.Authentication)
	if !ok {
		return AuthenticationPlan{}, ErrAuthentication
	}
	defer subject.Clear()
	state, err := planner.source.LoadFederatedPlanningState(ctx, cloneFederatedPlanningLookup(lookup))
	state = cloneFederatedPlanningState(state)
	if err != nil || ctx.Err() != nil || !validFederatedPlanningState(state, lookup) {
		return AuthenticationPlan{}, ErrAuthentication
	}
	observation, err := federatedMappingObservation(genericSAMLAuthenticationProjection(request.Authentication), subject)
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

func (planner *SAMLSharedFederatedPlanner) samlFederatedPlanningLookup(
	projection SAMLAuthenticationProjection,
) (FederatedPlanningLookup, identity.Subject, bool) {
	subject, err := identity.CanonicalSAMLSubjectTuple(
		projection.Issuer,
		string(projection.Subject.Source),
		projection.Subject.Name,
		projection.Subject.Format,
		projection.Subject.Value,
	)
	if err != nil {
		return FederatedPlanningLookup{}, identity.Subject{}, false
	}
	aliases, err := planner.keyring.SubjectAliases(projection.Provider, subject)
	if err != nil {
		subject.Clear()
		return FederatedPlanningLookup{}, identity.Subject{}, false
	}
	pins := projection.Consumption.Pins
	lookup := FederatedPlanningLookup{
		Protocol: ProtocolSAML, TenantID: projection.TenantID, Provider: pins.Provider,
		BindingID: pins.BindingID, SubjectFormat: subject.Format(), SubjectAliases: aliases,
		ProviderRevision: pins.ProviderRevision, BindingRevision: pins.BindingRevision,
		ConfigurationRevision: pins.ConfigurationRevision, SecurityRevision: pins.SecurityRevision,
		MappingRevision: pins.MappingRevision, AuthorizationRevision: pins.AuthorizationRevision,
		AssurancePolicyRevision: pins.AssurancePolicyRevision,
	}
	if !validSAMLFederatedPlanningLookup(lookup) {
		subject.Clear()
		return FederatedPlanningLookup{}, identity.Subject{}, false
	}
	return lookup, subject, true
}

func validSAMLFederatedPlanningLookup(lookup FederatedPlanningLookup) bool {
	return lookup.Protocol == ProtocolSAML && lookup.TenantID != (identity.EntityID{}) &&
		validTenantProviderForTenant(lookup.Provider, lookup.TenantID) && lookup.BindingID != (identity.EntityID{}) &&
		lookup.SubjectFormat == identity.UTF8ExactSubject && validSubjectAliases(lookup.SubjectAliases) &&
		validDatabaseRevision(lookup.ProviderRevision) && validDatabaseRevision(lookup.BindingRevision) &&
		validDatabaseRevision(lookup.ConfigurationRevision) && validDatabaseRevision(lookup.SecurityRevision) &&
		validDatabaseRevision(lookup.MappingRevision) && validDatabaseRevision(lookup.AuthorizationRevision) &&
		validDatabaseRevision(lookup.AssurancePolicyRevision)
}
