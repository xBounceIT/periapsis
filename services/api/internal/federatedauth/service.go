package federatedauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
	"github.com/periapsis-im/periapsis/services/api/internal/returnpath"
)

const (
	minimumOperationTimeout = 100 * time.Millisecond
	maximumOperationTimeout = 2 * time.Minute
	maximumJSONSafeRevision = uint64(9_007_199_254_740_991)
)

type Options struct {
	Planner           Planner
	OIDCTrust         OIDCTrustResolver
	Applier           TransactionalApplier
	OIDCApplier       OIDCTransactionalApplier
	OIDCSessionSealer OIDCSessionMaterialSealer
	Credentials       ApplyCredentialIssuer
	Sessions          SessionStore
	Refreshes         RefreshStore
	TokenProtector    TokenProtector
	ClientSecrets     ClientSecretSource
	OIDCRefresh       OIDCRefreshExchanger
	LogoutRetries     LogoutRetryStore
	LogoutExecutor    LogoutRetryExecutor
	OperationTimeout  time.Duration
	Now               func() time.Time
}

type Service struct {
	planner           Planner
	oidcTrust         OIDCTrustResolver
	applier           TransactionalApplier
	oidcApplier       OIDCTransactionalApplier
	oidcSessionSealer OIDCSessionMaterialSealer
	credentials       ApplyCredentialIssuer
	sessions          SessionStore
	refreshes         RefreshStore
	tokenProtector    TokenProtector
	clientSecrets     ClientSecretSource
	oidcRefresh       OIDCRefreshExchanger
	logoutRetries     LogoutRetryStore
	logoutExecutor    LogoutRetryExecutor
	operationTimeout  time.Duration
	now               func() time.Time
}

func New(options Options) (*Service, error) {
	if options.Planner == nil || options.OIDCTrust == nil || options.Applier == nil || options.Credentials == nil || options.Sessions == nil ||
		(options.OIDCApplier == nil) != (options.OIDCSessionSealer == nil) ||
		!validOptionalRefreshOptions(options) || !validOptionalLogoutOptions(options) ||
		options.OperationTimeout < minimumOperationTimeout || options.OperationTimeout > maximumOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidOptions
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Service{
		planner: options.Planner, oidcTrust: options.OIDCTrust, applier: options.Applier,
		oidcApplier: options.OIDCApplier, oidcSessionSealer: options.OIDCSessionSealer,
		credentials: options.Credentials,
		sessions:    options.Sessions, refreshes: options.Refreshes, tokenProtector: options.TokenProtector,
		clientSecrets: options.ClientSecrets, oidcRefresh: options.OIDCRefresh,
		logoutRetries: options.LogoutRetries, logoutExecutor: options.LogoutExecutor,
		operationTimeout: options.OperationTimeout, now: options.Now,
	}, nil
}

func validOptionalRefreshOptions(options Options) bool {
	configured := 0
	for _, present := range []bool{
		options.Refreshes != nil,
		options.TokenProtector != nil,
		options.ClientSecrets != nil,
		options.OIDCRefresh != nil,
	} {
		if present {
			configured++
		}
	}
	return configured == 0 || configured == 4
}

func validOptionalLogoutOptions(options Options) bool {
	return options.LogoutRetries == nil && options.LogoutExecutor == nil ||
		options.LogoutRetries != nil && options.LogoutExecutor != nil
}

func (service *Service) ApplyOIDC(
	ctx context.Context,
	request OIDCApplicationRequest,
) (ApplyResult, error) {
	tenantID, proof := request.TenantID, request.Proof
	if service == nil || proof == nil || tenantID == (identity.EntityID{}) {
		return ApplyResult{}, ErrInvalidInput
	}
	completion := proof.Completion()
	pins := completion.Pins
	admission, validAdmission := pins.TenantAdmission()
	if !validAdmission || admission.TenantID != tenantID || !validProviderForTenant(pins.Provider, admission.TenantID) ||
		!validSensitiveText(proof.Issuer(), 2048) || !validSensitiveText(proof.Subject(), 1024) ||
		!validInstant(proof.AuthenticatedAt()) || !validInstant(proof.ExpiresAt()) ||
		!proof.ExpiresAt().After(proof.AuthenticatedAt()) {
		return ApplyResult{}, ErrInvalidInput
	}
	operation, cancel, err := service.operation(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	defer cancel()
	claims := proof.Claims()
	trustedEvidence, err := service.oidcTrust.ResolveOIDCAssurance(operation, OIDCTrustRequest{
		TenantID: admission.TenantID, Admission: admission,
		Provider: pins.Provider, BindingID: admission.BindingID,
		ProviderRevision: pins.ProviderRevision, BindingRevision: pins.BindingRevision,
		SecurityRevision: pins.SecurityRevision, AssurancePolicyRevision: pins.AssurancePolicyRevision,
		AuthenticatedAt: proof.AuthenticatedAt(), ValidUntil: proof.ExpiresAt(),
		ACR: claims.ACR(), AMR: claims.AMR(),
	})
	if err != nil {
		return ApplyResult{}, ErrAuthentication
	}
	evidence, ok := oidcEvidenceWithPrimary(
		pins.Provider, admission.BindingID, proof.AuthenticatedAt(), proof.ExpiresAt(), pins.SecurityRevision,
		trustedEvidence,
	)
	if !ok {
		return ApplyResult{}, ErrAuthentication
	}
	projection := AuthenticationProjection{
		Protocol: ProtocolOIDC, TenantID: admission.TenantID, Admission: admission,
		Subject: ExternalSubject{
			Provider: pins.Provider, BindingID: admission.BindingID, Issuer: proof.Issuer(), Value: proof.Subject(),
		},
		AuthenticatedAt: proof.AuthenticatedAt(), ValidUntil: proof.ExpiresAt(), Evidence: cloneEvidence(evidence),
		OIDCCompletion: &completion, Groups: claims.Groups(),
	}
	for _, value := range claims.Scalars() {
		projection.Scalars = append(projection.Scalars, NamedValue{Name: value.Name, Value: value.Value})
	}
	for _, value := range claims.Profiles() {
		projection.Profiles = append(projection.Profiles, ProfileValue{Field: string(value.Field), Value: value.Value})
	}
	return service.planAndApplyOIDC(operation, projection, request.Configuration, request.Session)
}

func (service *Service) ApplyPasskey(
	ctx context.Context,
	tenantID identity.EntityID,
	artifact webauthn.AuthenticationArtifact,
) (ApplyResult, error) {
	if service == nil || tenantID == (identity.EntityID{}) || artifact.TenantID != tenantID ||
		artifact.UserID == (identity.EntityID{}) || artifact.CredentialVersion == 0 ||
		artifact.CredentialVersion > maximumJSONSafeRevision || artifact.CredentialDigest == ([sha256.Size]byte{}) ||
		artifact.Evidence.FactorRevision == nil ||
		*artifact.Evidence.FactorRevision < 1 ||
		uint64(*artifact.Evidence.FactorRevision) > artifact.CredentialVersion {
		return ApplyResult{}, ErrInvalidInput
	}
	now := service.currentTime()
	if !validInstant(now) {
		return ApplyResult{}, ErrAuthentication
	}
	projection := AuthenticationProjection{
		Protocol: ProtocolPasskey, TenantID: tenantID, AuthenticatedAt: artifact.Evidence.AuthenticatedAt,
		ValidUntil: now.Add(service.operationTimeout), Evidence: []identity.AssuranceEvidence{artifact.Evidence},
		Passkey: &artifact,
	}
	return service.planAndApply(ctx, projection)
}

func (service *Service) planAndApply(ctx context.Context, projection AuthenticationProjection) (ApplyResult, error) {
	operation, cancel, err := service.operation(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	defer cancel()
	if !validProjection(projection) {
		return ApplyResult{}, ErrInvalidInput
	}
	var collidedPlan AuthenticationPlan
	for planningAttempt := range 2 {
		plan, planErr := service.planner.PlanFederatedAuthentication(operation, PlanningRequest{
			Authentication: cloneProjection(projection), Action: "session.create",
		})
		if planErr != nil || !validPlan(plan, projection) ||
			planningAttempt == 1 && !validConvergedFirstJITPlan(collidedPlan, plan) {
			return ApplyResult{}, ErrAuthentication
		}
		now := service.currentTime()
		if !validInstant(now) || !projection.ValidUntil.After(now) {
			return ApplyResult{}, ErrAuthentication
		}
		assurance := identity.EvaluateAssurance(now, plan.Requirement, projection.Evidence, plan.HasEnrollableFactor)
		disposition := ApplyContinuation
		switch assurance {
		case identity.AssuranceSatisfied:
			disposition = ApplySession
		case identity.AssuranceStepUpRequired, identity.AssuranceEnrollmentOnly:
			disposition = ApplyContinuation
		default:
			return ApplyResult{}, ErrAuthentication
		}
		request := ApplyRequest{
			Authentication: applyAuthenticationProjection(projection), Plan: clonePlan(plan),
			Disposition: disposition, Assurance: assurance, AppliedAt: now,
		}
		credentialRequest := ApplyCredentialRequest{
			Disposition: disposition, Method: request.Authentication.Method, IssuedAt: now,
		}
		credential, credentialErr := service.credentials.ReserveApplyCredential(credentialRequest)
		if credentialErr != nil || credential == nil || !credential.validFor(credentialRequest) {
			if credential != nil {
				credential.Destroy()
			}
			return ApplyResult{}, ErrAuthentication
		}
		request.Session, request.Continuation = credential.Session(), credential.Continuation()
		var result ApplyResult
		for range 2 {
			result, err = service.applier.ApplyFederatedAuthentication(operation, cloneApplyRequest(request))
			if err == nil || operation.Err() != nil {
				break
			}
		}
		if err != nil {
			credential.Destroy()
			return ApplyResult{}, ErrAuthentication
		}
		if result.Credential != nil {
			result.Credential.Destroy()
			credential.Destroy()
			return ApplyResult{}, ErrAuthentication
		}
		switch result.Category {
		case ApplySuccess:
			if result.UserID == (identity.EntityID{}) || plan.UserID != (identity.EntityID{}) && result.UserID != plan.UserID ||
				result.ReturnPath != projectionReturnPath(projection) ||
				disposition == ApplySession && (result.SessionID != request.Session.SessionID() || result.ContinuationID != (identity.EntityID{})) ||
				disposition == ApplyContinuation && (result.ContinuationID != request.Continuation.ContinuationID() || result.SessionID != (identity.EntityID{})) {
				credential.Destroy()
				return ApplyResult{}, ErrAuthentication
			}
			var released bool
			result.Credential, released = credential.ReleaseBrowserCredential(result.SessionID, result.ContinuationID)
			if !released {
				credential.Destroy()
				return ApplyResult{}, ErrAuthentication
			}
			return result, nil
		case ApplyCollision:
			credential.Destroy()
			if planningAttempt == 0 && eligibleFirstJITCollisionPlan(projection, plan) {
				collidedPlan = clonePlan(plan)
				continue
			}
			return ApplyResult{}, ErrIdentityCollision
		case ApplyStale:
			credential.Destroy()
			return ApplyResult{}, ErrStaleConfiguration
		case ApplyReplay, ApplyDenied:
			credential.Destroy()
			return ApplyResult{}, ErrAuthentication
		default:
			credential.Destroy()
			return ApplyResult{}, ErrAuthentication
		}
	}
	return ApplyResult{}, ErrAuthentication
}

func eligibleFirstJITCollisionPlan(projection AuthenticationProjection, plan AuthenticationPlan) bool {
	return projection.Protocol == ProtocolOIDC && plan.UserID == (identity.EntityID{}) && plan.IdentityEpoch == 0 &&
		plan.Subject != nil && plan.Mapping != nil &&
		plan.Mapping.IdentityAction() == identity.LDAPIdentityCreateUserAndExternalIdentity
}

func validConvergedFirstJITPlan(collided, current AuthenticationPlan) bool {
	return collided.PlanRevision != 0 && collided.Subject != nil && collided.Mapping != nil &&
		collided.Mapping.IdentityAction() == identity.LDAPIdentityCreateUserAndExternalIdentity &&
		current.UserID != (identity.EntityID{}) && current.IdentityEpoch > 0 &&
		current.Subject != nil && slices.Equal(collided.Subject.Aliases, current.Subject.Aliases) && current.Mapping != nil &&
		current.Mapping.IdentityAction() == identity.LDAPIdentityNoChange
}

func (service *Service) RevalidateSession(ctx context.Context, lookup SessionLookup) (SessionResult, error) {
	if service == nil {
		return SessionResult{}, ErrInvalidInput
	}
	return revalidateSession(
		ctx, lookup, service.sessions, service.credentials, service.operationTimeout, service.now,
	)
}

func revalidateSession(
	ctx context.Context,
	lookup SessionLookup,
	sessions SessionStore,
	credentials ApplyCredentialIssuer,
	operationTimeout time.Duration,
	now func() time.Time,
) (SessionResult, error) {
	if ctx == nil {
		return SessionResult{}, ErrInvalidInput
	}
	operation, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	for attempt := 0; ; attempt++ {
		result, err := revalidateSessionOnce(operation, lookup, sessions, credentials, operationTimeout, now)
		if !errors.Is(err, ErrSessionRevalidationConflict) {
			return result, err
		}
		if attempt >= 5 {
			return SessionResult{}, ErrSessionRejected
		}
		// Another request may advance the session version. Reread authority
		// and recompute the decision after an aborted usable-session mutation.
		timer := time.NewTimer(10 * time.Millisecond << attempt)
		select {
		case <-operation.Done():
			timer.Stop()
			return SessionResult{}, ErrSessionRejected
		case <-timer.C:
		}
	}
}

func revalidateSessionOnce(
	ctx context.Context,
	lookup SessionLookup,
	sessions SessionStore,
	credentials ApplyCredentialIssuer,
	operationTimeout time.Duration,
	now func() time.Time,
) (SessionResult, error) {
	if sessions == nil || credentials == nil || now == nil ||
		lookup.SessionID == (identity.EntityID{}) || lookup.TenantID == (identity.EntityID{}) ||
		!validPublicText(lookup.Audience, 256) || !validSessionLookupAuthenticationMethod(lookup.AuthenticationMethod) {
		return SessionResult{}, ErrInvalidInput
	}
	if ctx == nil {
		return SessionResult{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return SessionResult{}, err
	}
	observedAt := now().UTC().Truncate(time.Microsecond)
	if !validInstant(observedAt) {
		return SessionResult{}, ErrSessionRejected
	}
	// The repository must make the same request-time decision as the in-memory
	// revalidator. Overwrite any caller-provided value so an expired federated
	// session can never be kept alive by choosing an earlier instant.
	lookup.ObservedAt = observedAt
	operation, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	projection, err := sessions.LoadSessionForRevalidation(operation, lookup)
	if err != nil || projection.Snapshot.SessionID != lookup.SessionID || projection.Snapshot.TenantID != lookup.TenantID ||
		projection.Live.Audience != lookup.Audience || projection.AuthenticationMethod != lookup.AuthenticationMethod ||
		!validSessionAuthenticationMethod(projection) {
		return SessionResult{}, ErrSessionRejected
	}
	decision := mfa.RevalidateSession(observedAt, projection.Snapshot, projection.Live)
	mutationRequest := SessionMutation{
		SessionID: lookup.SessionID, TenantID: lookup.TenantID, UserID: projection.Snapshot.UserID,
		Audience: lookup.Audience, AuthenticationMethod: projection.AuthenticationMethod,
		ExpectedVersion: projection.Snapshot.Version, ObservedAt: observedAt,
		Decision: decision.Decision, Reason: decision.Reason, Requirement: decision.Requirement,
	}
	var credential *ApplyCredentialReservation
	if decision.Decision == mfa.SessionRotate || decision.Decision == mfa.SessionStepUp {
		disposition := ApplyContinuation
		credentialRequest := ApplyCredentialRequest{
			Disposition: disposition, Method: projection.AuthenticationMethod, IssuedAt: observedAt,
		}
		if decision.Decision == mfa.SessionRotate {
			credentialRequest.Disposition = ApplySession
			credentialRequest.Rotation = &SessionRotationAnchor{
				SessionID: projection.Snapshot.SessionID, FamilyID: projection.Snapshot.RotationFamilyID,
				AbsoluteExpiresAt: projection.Snapshot.AbsoluteExpiresAt,
			}
		}
		credential, err = credentials.ReserveApplyCredential(credentialRequest)
		if err != nil || credential == nil || !credential.validFor(credentialRequest) {
			if credential != nil {
				credential.Destroy()
			}
			return SessionResult{}, ErrSessionRejected
		}
		mutationRequest.Session, mutationRequest.Continuation = credential.Session(), credential.Continuation()
	}
	var mutation SessionMutationResult
	for range 2 {
		mutation, err = sessions.ApplySessionRevalidation(operation, mutationRequest)
		if err == nil || operation.Err() != nil || errors.Is(err, ErrSessionRevalidationConflict) {
			break
		}
	}
	if err != nil || !validSessionMutationResult(decision.Decision, mutation, mutationRequest) {
		if credential != nil {
			credential.Destroy()
		}
		if credential == nil && decision.Decision == mfa.SessionUsable && errors.Is(err, ErrSessionRevalidationConflict) {
			return SessionResult{}, ErrSessionRevalidationConflict
		}
		return SessionResult{}, ErrSessionRejected
	}
	result := SessionResult{
		SessionID: lookup.SessionID, TenantID: lookup.TenantID, UserID: projection.Snapshot.UserID,
		AuthenticationMethod: projection.AuthenticationMethod,
		Decision:             decision.Decision, Reason: decision.Reason,
	}
	switch decision.Decision {
	case mfa.SessionUsable:
		result.AllowAuthority, result.AllowIdleTouch = decision.AllowAuthority, decision.AllowIdleTouch
	case mfa.SessionRotate:
		result.NewSessionID = mutation.NewSessionID
		result.AbsoluteExpiresAt = projection.Snapshot.AbsoluteExpiresAt
	case mfa.SessionStepUp:
		result.ContinuationID = mutation.ContinuationID
	case mfa.SessionRevoke, mfa.SessionDeny:
	default:
		return SessionResult{}, ErrSessionRejected
	}
	if credential != nil {
		var released bool
		result.Credential, released = credential.ReleaseBrowserCredential(result.NewSessionID, result.ContinuationID)
		if !released {
			credential.Destroy()
			return SessionResult{}, ErrSessionRejected
		}
	}
	return result, nil
}

func validSessionLookupAuthenticationMethod(method AuthenticationMethod) bool {
	switch method {
	case AuthenticationMethodOIDC, AuthenticationMethodSAML, AuthenticationMethodPasskey, AuthenticationMethodLDAP:
		return true
	default:
		return false
	}
}

func validSessionMutationResult(
	decision mfa.SessionDecision,
	result SessionMutationResult,
	request SessionMutation,
) bool {
	if !result.Applied {
		return false
	}
	zero := identity.EntityID{}
	switch decision {
	case mfa.SessionRotate:
		return !request.Session.IsZero() && request.Continuation.IsZero() &&
			result.NewSessionID == request.Session.SessionID() && result.ContinuationID == zero
	case mfa.SessionStepUp:
		return request.Session.IsZero() && !request.Continuation.IsZero() &&
			result.NewSessionID == zero && result.ContinuationID == request.Continuation.ContinuationID()
	case mfa.SessionUsable, mfa.SessionRevoke, mfa.SessionDeny:
		return request.Session.IsZero() && request.Continuation.IsZero() &&
			result.NewSessionID == zero && result.ContinuationID == zero
	default:
		return false
	}
}

func validSessionAuthenticationMethod(projection SessionProjection) bool {
	switch projection.AuthenticationMethod {
	case AuthenticationMethodPasskey:
		return projection.Snapshot.Primary.Kind == mfa.PrimaryPasskey
	case AuthenticationMethodOIDC, AuthenticationMethodSAML, AuthenticationMethodLDAP:
		return projection.Snapshot.Primary.Kind == mfa.PrimaryTenantProvider ||
			projection.Snapshot.Primary.Kind == mfa.PrimaryPlatformProviderBinding
	default:
		return false
	}
}

func (service *Service) operation(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, service.operationTimeout)
	return bounded, cancel, nil
}

func (service *Service) currentTime() time.Time {
	return service.now().UTC().Truncate(time.Microsecond)
}

func validProjection(value AuthenticationProjection) bool {
	if value.TenantID == (identity.EntityID{}) || !validInstant(value.AuthenticatedAt) ||
		!validInstant(value.ValidUntil) || !value.ValidUntil.After(value.AuthenticatedAt) ||
		len(value.Scalars) > 64 || len(value.Profiles) > 32 || len(value.Groups) > 4096 ||
		len(value.Evidence) == 0 || len(value.Evidence) > 64 {
		return false
	}
	switch value.Protocol {
	case ProtocolOIDC:
		admission, validAdmission := projectionOIDCAdmission(value)
		return value.OIDCCompletion != nil && value.SAMLConsumption == nil && value.Passkey == nil &&
			validAdmission && admission.TenantID == value.TenantID && admission.BindingID == value.Subject.BindingID &&
			validSensitiveText(value.Subject.Issuer, 2048) && validSensitiveText(value.Subject.Value, 16*1024) &&
			validFederatedEvidence(value.Evidence, value.Subject.Provider, value.Subject.BindingID) &&
			validOIDCCompletion(*value.OIDCCompletion, admission, value.Subject)
	case ProtocolSAML:
		return value.SAMLConsumption != nil && value.OIDCCompletion == nil && value.Passkey == nil &&
			validProviderForTenant(value.Subject.Provider, value.TenantID) && value.Subject.BindingID != (identity.EntityID{}) &&
			validSensitiveText(value.Subject.Issuer, 2048) && validSensitiveText(value.Subject.Value, 16*1024) &&
			validFederatedEvidence(value.Evidence, value.Subject.Provider, value.Subject.BindingID) &&
			validSAMLConsumption(*value.SAMLConsumption, value.Subject)
	case ProtocolPasskey:
		return value.Passkey != nil && value.OIDCCompletion == nil && value.SAMLConsumption == nil &&
			value.Subject == (ExternalSubject{}) && validLocalEvidence(value.Evidence)
	default:
		return false
	}
}

func projectionOIDCAdmission(value AuthenticationProjection) (identity.TenantAdmissionContext, bool) {
	admission := value.Admission
	if admission == (identity.TenantAdmissionContext{}) && value.Subject.Provider.Scope == identity.TenantProviderScope {
		admission = identity.TenantAdmissionContext{TenantID: value.TenantID, BindingID: value.Subject.BindingID}
	}
	return admission, validTenantAdmission(value.Subject.Provider, admission)
}

func validOIDCCompletion(
	value federatedoidc.TransactionCompletion,
	admission identity.TenantAdmissionContext,
	subject ExternalSubject,
) bool {
	pins := value.Pins
	pinnedAdmission, validAdmission := pins.TenantAdmission()
	return value.ID != (federatedoidc.TransactionID{}) && validDatabaseSuccessorRevision(value.ExpectedVersion) &&
		validAdmission && pinnedAdmission == admission && pins.Provider == subject.Provider &&
		pinnedAdmission.BindingID == subject.BindingID &&
		validDatabaseRevision(pins.ProviderRevision) && validDatabaseRevision(pins.BindingRevision) &&
		validDatabaseRevision(pins.ConfigurationRevision) && validDatabaseRevision(pins.SecurityRevision) &&
		validDatabaseRevision(pins.MappingRevision) && validDatabaseRevision(pins.AuthorizationRevision) &&
		validDatabaseRevision(pins.AssurancePolicyRevision) && validDatabaseRevision(pins.ClientSecretRevision) &&
		validDatabaseRevision(pins.DiscoveryRevision) &&
		pins.DiscoveryDigest != ([sha256.Size]byte{}) &&
		validDatabaseRevision(pins.JWKSRevision) && pins.JWKSDigest != ([sha256.Size]byte{}) && validInstant(value.CompletedAt) &&
		validReturnPath(value.ReturnPath)
}

func validSAMLConsumption(value federatedsaml.ConsumptionRequest, subject ExternalSubject) bool {
	pins := value.Pins
	validSessionReplay := value.HasSessionIndex == (value.SessionIndexDigest != ([sha256.Size]byte{}))
	return value.TransactionID != (federatedsaml.TransactionID{}) && validDatabaseSuccessorRevision(value.ExpectedVersion) &&
		pins.Provider == subject.Provider && pins.BindingID == subject.BindingID &&
		validDatabaseRevision(pins.ProviderRevision) && validDatabaseRevision(pins.BindingRevision) &&
		validDatabaseRevision(pins.ConfigurationRevision) && validDatabaseRevision(pins.SecurityRevision) &&
		validDatabaseRevision(pins.MappingRevision) && validDatabaseRevision(pins.AuthorizationRevision) &&
		validDatabaseRevision(pins.AssurancePolicyRevision) && validDatabaseRevision(pins.MetadataRevision) &&
		pins.MetadataDigest != ([sha256.Size]byte{}) && validDatabaseRevision(pins.SPKeyRevision) &&
		pins.ConfigurationDigest != ([sha256.Size]byte{}) &&
		validPublicText(value.ResponseID, 1024) && validPublicText(value.AssertionID, 1024) &&
		validInstant(value.ConsumedAt) && validReturnPath(value.ReturnPath) && validSessionReplay
}

func validFederatedEvidence(
	values []identity.AssuranceEvidence,
	provider identity.ProviderContext,
	bindingID identity.EntityID,
) bool {
	for _, value := range values {
		if value.Source.Local || value.Source.ProviderID != provider.ProviderID ||
			value.Source.BindingID != bindingID || value.FactorRevision != nil || value.TrustRuleRevision == nil {
			return false
		}
	}
	return true
}

func validLocalEvidence(values []identity.AssuranceEvidence) bool {
	for _, value := range values {
		if !value.Source.Local || value.Source.ProviderID != (identity.EntityID{}) ||
			value.Source.BindingID != (identity.EntityID{}) || value.FactorRevision == nil || value.TrustRuleRevision != nil {
			return false
		}
	}
	return true
}

func projectionReturnPath(projection AuthenticationProjection) string {
	switch projection.Protocol {
	case ProtocolOIDC:
		if projection.OIDCCompletion != nil {
			return projection.OIDCCompletion.ReturnPath
		}
	case ProtocolSAML:
		if projection.SAMLConsumption != nil {
			return projection.SAMLConsumption.ReturnPath
		}
	}
	return ""
}

func providerPrimaryEvidence(
	provider identity.ProviderContext,
	bindingID identity.EntityID,
	authenticatedAt time.Time,
	validUntil time.Time,
	securityRevision uint64,
) (identity.AssuranceEvidence, bool) {
	if provider.ProviderID == (identity.EntityID{}) || bindingID == (identity.EntityID{}) ||
		!validInstant(authenticatedAt) || !validInstant(validUntil) || !validUntil.After(authenticatedAt) ||
		securityRevision == 0 || securityRevision > maximumJSONSafeRevision {
		return identity.AssuranceEvidence{}, false
	}
	revision := int64(securityRevision)
	expires := validUntil
	return identity.AssuranceEvidence{
		Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
		Source:          identity.AssuranceSource{ProviderID: provider.ProviderID, BindingID: bindingID},
		AuthenticatedAt: authenticatedAt, ExpiresAt: &expires, TrustRuleRevision: &revision,
	}, true
}

func oidcEvidenceWithPrimary(
	provider identity.ProviderContext,
	bindingID identity.EntityID,
	authenticatedAt time.Time,
	validUntil time.Time,
	securityRevision uint64,
	trusted []identity.AssuranceEvidence,
) ([]identity.AssuranceEvidence, bool) {
	primary, ok := providerPrimaryEvidence(provider, bindingID, authenticatedAt, validUntil, securityRevision)
	if !ok || len(trusted) > 63 {
		return nil, false
	}
	// Primary provenance is mandatory even when a configured trust rule adds
	// stronger evidence. Expired or otherwise unusable elevated evidence must
	// fall back to the still-valid primary proof rather than erase it.
	evidence := make([]identity.AssuranceEvidence, 1, 1+len(trusted))
	evidence[0] = primary
	evidence = append(evidence, cloneEvidence(trusted)...)
	return evidence, true
}

func validPlan(value AuthenticationPlan, projection AuthenticationProjection) bool {
	if !validDatabaseRevision(value.PlanRevision) || value.TenantID != projection.TenantID ||
		!validDatabaseRevision(value.PolicyRevision) ||
		len(value.Requirement.PolicyRevisions) == 0 || !validPlanIDs(value.RoleIDs, 1_024) ||
		!validPlanIDs(value.SecurityGroupIDs, 1_024) {
		return false
	}
	if projection.Protocol == ProtocolPasskey {
		return projection.Passkey != nil && value.UserID == projection.Passkey.UserID &&
			value.UserID != (identity.EntityID{}) && value.IdentityEpoch > 0 &&
			value.ProviderRevision == 0 && value.BindingRevision == 0 && value.ConfigurationRevision == 0 &&
			value.SecurityRevision == 0 && value.MappingRevision == 0 && value.AuthorizationRevision == 0 &&
			value.Subject == nil && value.Mapping == nil
	}
	if !validDatabaseRevision(value.ProviderRevision) || !validDatabaseRevision(value.BindingRevision) ||
		!validDatabaseRevision(value.ConfigurationRevision) || !validDatabaseRevision(value.SecurityRevision) ||
		!validDatabaseRevision(value.MappingRevision) {
		return false
	}
	switch projection.Protocol {
	case ProtocolOIDC:
		if projection.OIDCCompletion == nil ||
			value.ProviderRevision != projection.OIDCCompletion.Pins.ProviderRevision ||
			value.BindingRevision != projection.OIDCCompletion.Pins.BindingRevision ||
			value.ConfigurationRevision != projection.OIDCCompletion.Pins.ConfigurationRevision ||
			value.SecurityRevision != projection.OIDCCompletion.Pins.SecurityRevision ||
			value.MappingRevision != projection.OIDCCompletion.Pins.MappingRevision ||
			value.AuthorizationRevision != projection.OIDCCompletion.Pins.AuthorizationRevision ||
			value.PolicyRevision != projection.OIDCCompletion.Pins.AssurancePolicyRevision ||
			!validProtectedFederatedSubject(value.Subject) || value.Mapping == nil ||
			value.Mapping.Disposition() != identity.LDAPPlanAdmitted ||
			!slices.Equal(value.RoleIDs, value.Mapping.ProspectiveRoleIDs()) ||
			!slices.Equal(value.SecurityGroupIDs, value.Mapping.ProspectiveSecurityGroupIDs()) ||
			!validOIDCPlanIdentityState(value) || !validPlatformOIDCPlan(value, projection) {
			return false
		}
	case ProtocolSAML:
		if projection.SAMLConsumption == nil ||
			value.ProviderRevision != projection.SAMLConsumption.Pins.ProviderRevision ||
			value.ConfigurationRevision != projection.SAMLConsumption.Pins.ConfigurationRevision ||
			value.SecurityRevision != projection.SAMLConsumption.Pins.SecurityRevision ||
			value.MappingRevision != projection.SAMLConsumption.Pins.MappingRevision ||
			value.PolicyRevision != projection.SAMLConsumption.Pins.AssurancePolicyRevision {
			return false
		}
	default:
		return false
	}
	// A first collision-safe JIT has no User or identity epoch yet. Existing
	// identities must pin both so the transactional applier can recheck drift.
	return value.UserID == (identity.EntityID{}) && value.IdentityEpoch == 0 ||
		value.UserID != (identity.EntityID{}) && value.IdentityEpoch > 0
}

func validPlatformOIDCPlan(value AuthenticationPlan, projection AuthenticationProjection) bool {
	if projection.OIDCCompletion == nil ||
		projection.OIDCCompletion.Pins.Provider.Scope != identity.PlatformProviderScope {
		return true
	}
	if value.Mapping == nil || len(value.RoleIDs) != 0 || len(value.SecurityGroupIDs) != 0 ||
		value.Mapping.Reason() != identity.LDAPPlanReasonProviderAccessOnly ||
		len(value.Mapping.MatchedRuleIDs()) != 0 || len(value.Mapping.ProspectiveSecurityGroupIDs()) != 0 ||
		len(value.Mapping.ProspectiveRoleIDs()) != 0 || len(value.Mapping.ProspectiveOperatorTeamAssignments()) != 0 ||
		len(value.Mapping.Changes()) != 0 {
		return false
	}
	identityAction := value.Mapping.IdentityAction()
	accessAction := value.Mapping.ProviderAccessAction()
	return validPlatformOIDCPlanActions(identityAction, accessAction)
}

func validPlatformOIDCPlanActions(
	identityAction identity.LDAPIdentityPlanAction,
	accessAction identity.LDAPProviderAccessPlanAction,
) bool {
	if identityAction == identity.LDAPIdentityCreateUserAndExternalIdentity {
		// A new provider-qualified identity cannot already own the exact live
		// tenant admission grant. Treat that impossible planner combination as
		// hostile rather than letting the database discover it after mutation.
		return accessAction == identity.LDAPProviderAccessEnsure
	}
	return identityAction == identity.LDAPIdentityNoChange &&
		(accessAction == identity.LDAPProviderAccessNoChange ||
			accessAction == identity.LDAPProviderAccessEnsure)
}

func validOIDCPlanIdentityState(value AuthenticationPlan) bool {
	if value.UserID == (identity.EntityID{}) {
		return value.IdentityEpoch == 0 &&
			value.Mapping.IdentityAction() == identity.LDAPIdentityCreateUserAndExternalIdentity
	}
	return value.IdentityEpoch > 0 && value.Mapping.IdentityAction() == identity.LDAPIdentityNoChange
}

func validPlanIDs(values []identity.EntityID, maximum int) bool {
	if len(values) > maximum {
		return false
	}
	seen := make(map[identity.EntityID]struct{}, len(values))
	for _, value := range values {
		if value == (identity.EntityID{}) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validProviderForTenant(provider identity.ProviderContext, tenantID identity.EntityID) bool {
	if !validProviderContext(provider) {
		return false
	}
	return provider.Scope == identity.TenantProviderScope && provider.TenantID == tenantID ||
		provider.Scope == identity.PlatformProviderScope && provider.TenantID == (identity.EntityID{})
}

func validTenantAdmission(
	provider identity.ProviderContext,
	admission identity.TenantAdmissionContext,
) bool {
	return admission.TenantID != (identity.EntityID{}) && admission.BindingID != (identity.EntityID{}) &&
		validProviderForTenant(provider, admission.TenantID)
}

func validTenantProviderForTenant(provider identity.ProviderContext, tenantID identity.EntityID) bool {
	return provider.Scope == identity.TenantProviderScope && provider.TenantID == tenantID &&
		tenantID != (identity.EntityID{}) && provider.ProviderID != (identity.EntityID{})
}

func validProviderContext(provider identity.ProviderContext) bool {
	zero := identity.EntityID{}
	if provider.ProviderID == zero {
		return false
	}
	return provider.Scope == identity.TenantProviderScope && provider.TenantID != zero ||
		provider.Scope == identity.PlatformProviderScope && provider.TenantID == zero
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
}

func validSensitiveText(value string, maximum int) bool {
	return validPublicText(value, maximum)
}

func validPublicText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validReturnPath(value string) bool {
	return returnpath.Valid(value)
}

func cloneProjection(value AuthenticationProjection) AuthenticationProjection {
	value.Scalars = append([]NamedValue(nil), value.Scalars...)
	value.Profiles = append([]ProfileValue(nil), value.Profiles...)
	value.Groups = append([]string(nil), value.Groups...)
	value.Evidence = cloneEvidence(value.Evidence)
	if value.OIDCCompletion != nil {
		copyValue := *value.OIDCCompletion
		value.OIDCCompletion = &copyValue
	}
	if value.SAMLConsumption != nil {
		copyValue := *value.SAMLConsumption
		value.SAMLConsumption = &copyValue
	}
	if value.Passkey != nil {
		copyValue := *value.Passkey
		copyValue.Evidence = cloneEvidenceValue(value.Passkey.Evidence)
		value.Passkey = &copyValue
	}
	return value
}

func applyAuthenticationProjection(value AuthenticationProjection) ApplyAuthenticationProjection {
	result := ApplyAuthenticationProjection{
		Protocol: value.Protocol, Method: authenticationMethodForProtocol(value.Protocol), TenantID: value.TenantID,
		Admission:       value.Admission,
		AuthenticatedAt: value.AuthenticatedAt, ValidUntil: value.ValidUntil,
		Evidence: cloneEvidence(value.Evidence),
	}
	if value.OIDCCompletion != nil {
		copyValue := *value.OIDCCompletion
		result.OIDCCompletion = &copyValue
	}
	if value.SAMLConsumption != nil {
		copyValue := *value.SAMLConsumption
		result.SAMLConsumption = &copyValue
	}
	if value.Passkey != nil {
		copyValue := *value.Passkey
		copyValue.Evidence = cloneEvidenceValue(value.Passkey.Evidence)
		result.Passkey = &copyValue
	}
	return result
}

func cloneApplyRequest(value ApplyRequest) ApplyRequest {
	value.Plan = clonePlan(value.Plan)
	value.Authentication.Evidence = cloneEvidence(value.Authentication.Evidence)
	if value.Authentication.OIDCCompletion != nil {
		copyValue := *value.Authentication.OIDCCompletion
		value.Authentication.OIDCCompletion = &copyValue
	}
	if value.Authentication.SAMLConsumption != nil {
		copyValue := *value.Authentication.SAMLConsumption
		value.Authentication.SAMLConsumption = &copyValue
	}
	if value.Authentication.Passkey != nil {
		copyValue := *value.Authentication.Passkey
		copyValue.Evidence = cloneEvidenceValue(value.Authentication.Passkey.Evidence)
		value.Authentication.Passkey = &copyValue
	}
	return value
}

func authenticationMethodForProtocol(protocol Protocol) AuthenticationMethod {
	switch protocol {
	case ProtocolOIDC:
		return AuthenticationMethodOIDC
	case ProtocolSAML:
		return AuthenticationMethodSAML
	case ProtocolPasskey:
		return AuthenticationMethodPasskey
	default:
		return ""
	}
}

func cloneEvidence(values []identity.AssuranceEvidence) []identity.AssuranceEvidence {
	result := append([]identity.AssuranceEvidence(nil), values...)
	for index := range result {
		result[index] = cloneEvidenceValue(result[index])
	}
	return result
}

func cloneEvidenceValue(value identity.AssuranceEvidence) identity.AssuranceEvidence {
	if value.ExpiresAt != nil {
		copyValue := *value.ExpiresAt
		value.ExpiresAt = &copyValue
	}
	if value.FactorRevision != nil {
		copyValue := *value.FactorRevision
		value.FactorRevision = &copyValue
	}
	if value.TrustRuleRevision != nil {
		copyValue := *value.TrustRuleRevision
		value.TrustRuleRevision = &copyValue
	}
	return value
}

func clonePlan(value AuthenticationPlan) AuthenticationPlan {
	value.RoleIDs = append([]identity.EntityID(nil), value.RoleIDs...)
	value.SecurityGroupIDs = append([]identity.EntityID(nil), value.SecurityGroupIDs...)
	value.Requirement.PolicyRevisions = append([]identity.AssurancePolicyRevision(nil), value.Requirement.PolicyRevisions...)
	if value.Subject != nil {
		copyValue := *value.Subject
		copyValue.Aliases = append([]identity.SubjectAlias(nil), value.Subject.Aliases...)
		copyValue.Envelope.Ciphertext = append([]byte(nil), value.Subject.Envelope.Ciphertext...)
		value.Subject = &copyValue
	}
	if value.Mapping != nil {
		clone := identity.CloneFederatedMappingPlan(*value.Mapping)
		value.Mapping = &clone
	}
	if value.Requirement.EnrollmentDeadline != nil {
		copyValue := *value.Requirement.EnrollmentDeadline
		value.Requirement.EnrollmentDeadline = &copyValue
	}
	slices.SortFunc(value.RoleIDs, func(left, right identity.EntityID) int { return bytes.Compare(left[:], right[:]) })
	slices.SortFunc(value.SecurityGroupIDs, func(left, right identity.EntityID) int { return bytes.Compare(left[:], right[:]) })
	return value
}

func validProtectedFederatedSubject(value *ProtectedFederatedSubject) bool {
	if value == nil || value.ExternalIdentityID == (identity.EntityID{}) || len(value.Aliases) < 1 ||
		len(value.Aliases) > 16 || value.Envelope.KeyVersion < 1 ||
		value.Envelope.Format != identity.UTF8ExactSubject || len(value.Envelope.Ciphertext) < 17 ||
		len(value.Envelope.Ciphertext) > 4*1024+16 {
		return false
	}
	envelopeAliasPresent := false
	for index, alias := range value.Aliases {
		if alias.KeyVersion < 1 || alias.Digest == ([sha256.Size]byte{}) ||
			index > 0 && value.Aliases[index-1].KeyVersion >= alias.KeyVersion {
			return false
		}
		if alias.KeyVersion == value.Envelope.KeyVersion {
			envelopeAliasPresent = true
		}
	}
	return envelopeAliasPresent
}
