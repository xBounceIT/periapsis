package federatedauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

type SAMLSubjectIdentity struct {
	Source federatedsaml.SubjectSource
	Name   string
	Format string
	Value  string `json:"-"`
}

func (subject SAMLSubjectIdentity) String() string {
	return fmt.Sprintf(
		"federatedauth.SAMLSubjectIdentity{source:%s,name:%t,format:%t,value:[REDACTED]}",
		subject.Source, subject.Name != "", subject.Format != "",
	)
}
func (subject SAMLSubjectIdentity) GoString() string { return subject.String() }

type SAMLAuthenticationProjection struct {
	TenantID        identity.EntityID
	Provider        identity.ProviderContext
	BindingID       identity.EntityID
	Issuer          string `json:"-"`
	Subject         SAMLSubjectIdentity
	AuthenticatedAt time.Time
	ValidUntil      time.Time
	Scalars         []NamedValue
	Profiles        []ProfileValue
	Groups          []string `json:"-"`
	Evidence        []identity.AssuranceEvidence
	Consumption     federatedsaml.ConsumptionRequest
}

func (projection SAMLAuthenticationProjection) String() string {
	return fmt.Sprintf(
		"federatedauth.SAMLAuthenticationProjection{groups:%d,evidence:%d,subject:%q,material:[REDACTED]}",
		len(projection.Groups), len(projection.Evidence), projection.Subject.String(),
	)
}
func (projection SAMLAuthenticationProjection) GoString() string { return projection.String() }

type SAMLPlanningRequest struct {
	Authentication SAMLAuthenticationProjection
	Action         string
}

func (request SAMLPlanningRequest) String() string {
	return fmt.Sprintf(
		"federatedauth.SAMLPlanningRequest{action:%t,authentication:%q}",
		request.Action != "", request.Authentication.String(),
	)
}
func (request SAMLPlanningRequest) GoString() string { return request.String() }

type SAMLPlanner interface {
	PlanSAMLAuthentication(context.Context, SAMLPlanningRequest) (AuthenticationPlan, error)
}

// SAMLApplyRequest carries the protocol-neutral atomic mutation plus the
// verified logout provenance. The persistence adapter must protect
// SessionMaterial before commit and must never persist or log it as plaintext.
type SAMLApplyRequest struct {
	Apply           ApplyRequest
	MaterialID      identity.EntityID
	SessionMaterial federatedsaml.SessionMaterial `json:"-"`
}

func (request SAMLApplyRequest) String() string {
	return fmt.Sprintf(
		"federatedauth.SAMLApplyRequest{apply:%q,material_present:%t,session_material:%q}",
		request.Apply.String(), validApplyUUIDv7(request.MaterialID), request.SessionMaterial.String(),
	)
}
func (request SAMLApplyRequest) GoString() string { return request.String() }

// SAMLTransactionalApplier must atomically consume all replay identifiers,
// recheck the exact plan/configuration pins, apply JIT/mapping, protect the
// optional SAML logout provenance, and create the session or continuation.
// Exact retries after an ambiguous response must return the original result.
type SAMLTransactionalApplier interface {
	ApplySAMLAuthentication(context.Context, SAMLApplyRequest) (ApplyResult, error)
}

// SAMLSessionMaterialAnchor is retained only across the rolling adapter
// transition that introduces immutable material rows. New cryptographic code
// must use MaterialID and never authenticate either legacy ownership anchor.
type SAMLSessionMaterialAnchor string

const (
	SAMLSessionMaterialSessionAnchor      SAMLSessionMaterialAnchor = "session"
	SAMLSessionMaterialContinuationAnchor SAMLSessionMaterialAnchor = "continuation"
)

// SAMLSessionMaterialSealContext binds logout provenance to the exact row
// that owns it. Session and continuation ownership can change during MFA
// promotion without changing this immutable cryptographic anchor.
type SAMLSessionMaterialSealContext struct {
	Provider   identity.ProviderContext
	BindingID  identity.EntityID
	MaterialID identity.EntityID
	// Deprecated: rolling-compatibility fields, never cryptographic AAD.
	Anchor   SAMLSessionMaterialAnchor
	AnchorID identity.EntityID
}

// SAMLSessionMaterialSealer owns the purpose-separated keyring used before
// transactional persistence. Plaintext NameID and SessionIndex never enter a
// repository request or database function.
type SAMLSessionMaterialSealer interface {
	SealSAMLSession(
		context.Context,
		SAMLSessionMaterialSealContext,
		federatedsaml.SessionMaterial,
	) (federatedsaml.ProtectedSessionMaterial, error)
}

type SAMLApplicationOptions struct {
	Planner          SAMLPlanner
	Applier          SAMLTransactionalApplier
	Credentials      ApplyCredentialIssuer
	OperationTimeout time.Duration
	Now              func() time.Time
}

// SAMLApplication owns no XML or cryptography. It converts one kernel-verified
// proof into the shared collision-safe mapping plan and exact atomic apply.
type SAMLApplication struct {
	planner          SAMLPlanner
	applier          SAMLTransactionalApplier
	credentials      ApplyCredentialIssuer
	operationTimeout time.Duration
	now              func() time.Time
}

func NewSAMLApplication(options SAMLApplicationOptions) (*SAMLApplication, error) {
	if options.Planner == nil || options.Applier == nil || options.Credentials == nil ||
		options.OperationTimeout < minimumOperationTimeout || options.OperationTimeout > maximumOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidOptions
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &SAMLApplication{
		planner: options.Planner, applier: options.Applier, credentials: options.Credentials,
		operationTimeout: options.OperationTimeout, now: options.Now,
	}, nil
}

func (application *SAMLApplication) String() string {
	return fmt.Sprintf("federatedauth.SAMLApplication{configured:%t}", application != nil && application.planner != nil)
}
func (application *SAMLApplication) GoString() string { return application.String() }

func (application *SAMLApplication) ApplySAML(
	ctx context.Context,
	flow SAMLConsumptionFlow,
	configuration TenantSAMLConfiguration,
	validated *federatedsaml.ValidatedAuthentication,
) (ApplyResult, error) {
	if application == nil || application.planner == nil || application.applier == nil || flow == nil ||
		validated == nil || !validTenantSAMLConfiguration(configuration) {
		return ApplyResult{}, ErrInvalidInput
	}
	proof, ok := newSAMLObservedProof(validated.JIT(), configuration.Authentication)
	if !ok {
		return ApplyResult{}, ErrAuthentication
	}
	operation, cancel, err := application.operation(ctx)
	if err != nil {
		return ApplyResult{}, ErrAuthentication
	}
	defer cancel()
	consumer := &samlApplicationConsumer{
		application:   application,
		configuration: cloneTenantSAMLConfiguration(configuration),
		expected:      proof,
	}
	consumption, err := flow.Consume(operation, validated, consumer)
	consumer.resultGuard.Lock()
	result, consumerErr, applied := consumer.result, consumer.err, consumer.applied
	consumer.resultGuard.Unlock()
	if err != nil || consumption.Category != federatedsaml.ConsumerSuccess || !applied {
		return ApplyResult{}, mapSAMLConsumptionError(consumerErr)
	}
	if !validCompletedSAMLApplyResult(result) {
		return ApplyResult{}, ErrAuthentication
	}
	return result, nil
}

// samlObservedProof is constructor-only in production. Tests in this package
// may build it directly to exercise planner/application fail-closed behavior.
type samlObservedProof struct {
	issuer           string
	subject          SAMLSubjectIdentity
	authenticatedAt  time.Time
	validUntil       time.Time
	scalars          []NamedValue
	profiles         []ProfileValue
	groups           []string
	elevatedEvidence *identity.AssuranceEvidence
	sessionMaterial  federatedsaml.SessionMaterial
}

func newSAMLObservedProof(
	jit federatedsaml.JITAuthentication,
	configuration federatedsaml.Configuration,
) (samlObservedProof, bool) {
	proof := samlObservedProof{
		issuer: jit.Issuer(),
		subject: SAMLSubjectIdentity{
			Source: jit.SubjectSource(), Name: jit.SubjectName(), Format: jit.SubjectFormat(), Value: jit.SubjectValue(),
		},
		authenticatedAt: jit.AuthenticatedAt(), validUntil: jit.ValidUntil(), groups: jit.Groups(),
		elevatedEvidence: jit.AssuranceEvidence(), sessionMaterial: jit.SessionMaterial(),
	}
	for _, value := range jit.Scalars() {
		proof.scalars = append(proof.scalars, NamedValue{Name: value.Name, Value: value.Value})
	}
	for _, value := range jit.Profiles() {
		proof.profiles = append(proof.profiles, ProfileValue{Field: string(value.Field), Value: value.Value})
	}
	return proof, validSAMLObservedProof(proof, configuration)
}

type samlApplicationConsumer struct {
	application   *SAMLApplication
	configuration TenantSAMLConfiguration
	expected      samlObservedProof
	called        atomic.Bool
	resultGuard   sync.Mutex
	applied       bool
	result        ApplyResult
	err           error
}

func (consumer *samlApplicationConsumer) ConsumeSAML(
	ctx context.Context,
	request federatedsaml.ConsumptionRequest,
) (federatedsaml.ConsumptionResult, error) {
	if consumer == nil || consumer.application == nil || !consumer.called.CompareAndSwap(false, true) {
		return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerDenied}, ErrInvalidInput
	}
	observed, ok := newSAMLObservedProof(request.Authentication, consumer.configuration.Authentication)
	if !ok || !sameSAMLObservedProof(consumer.expected, observed) ||
		!validSAMLConsumptionForConfiguration(request, consumer.configuration.Authentication) {
		consumer.setResult(ApplyResult{}, ErrInvalidInput, false)
		return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerDenied}, ErrInvalidInput
	}
	projection, ok := buildSAMLAuthenticationProjection(consumer.configuration, observed, request)
	if !ok {
		consumer.setResult(ApplyResult{}, ErrAuthentication, false)
		return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerDenied}, ErrAuthentication
	}
	result, err := consumer.application.planAndApply(ctx, projection, observed.sessionMaterial)
	if err != nil {
		consumer.setResult(ApplyResult{}, err, false)
		return federatedsaml.ConsumptionResult{Category: samlConsumerCategory(err)}, err
	}
	consumer.setResult(result, nil, true)
	return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerSuccess}, nil
}

func (consumer *samlApplicationConsumer) setResult(result ApplyResult, err error, applied bool) {
	consumer.resultGuard.Lock()
	defer consumer.resultGuard.Unlock()
	consumer.result, consumer.err, consumer.applied = result, err, applied
}

func (application *SAMLApplication) planAndApply(
	ctx context.Context,
	projection SAMLAuthenticationProjection,
	sessionMaterial federatedsaml.SessionMaterial,
) (ApplyResult, error) {
	operation, cancel, err := application.operation(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	defer cancel()
	if !validSAMLAuthenticationProjection(projection) ||
		!validSAMLSessionMaterial(sessionMaterial, projection.Consumption) {
		return ApplyResult{}, ErrInvalidInput
	}
	var collidedPlan AuthenticationPlan
	for planningAttempt := range 2 {
		plan, planErr := application.planner.PlanSAMLAuthentication(operation, SAMLPlanningRequest{
			Authentication: cloneSAMLAuthenticationProjection(projection), Action: "session.create",
		})
		if planErr != nil || !validSAMLPlan(plan, projection) ||
			planningAttempt == 1 && !validConvergedFirstJITPlan(collidedPlan, plan) {
			return ApplyResult{}, ErrAuthentication
		}
		now := application.currentTime()
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
		generic := genericSAMLAuthenticationProjection(projection)
		apply := SAMLApplyRequest{Apply: ApplyRequest{
			Authentication: applyAuthenticationProjection(generic), Plan: clonePlan(plan),
			Disposition: disposition, Assurance: assurance, AppliedAt: now,
		}, MaterialID: projection.Consumption.MaterialID, SessionMaterial: sessionMaterial}
		credentialRequest := ApplyCredentialRequest{
			Disposition: disposition, Method: apply.Apply.Authentication.Method, IssuedAt: now,
		}
		credential, credentialErr := application.credentials.ReserveApplyCredential(credentialRequest)
		if credentialErr != nil || credential == nil || !credential.validFor(credentialRequest) {
			if credential != nil {
				credential.Destroy()
			}
			return ApplyResult{}, ErrAuthentication
		}
		apply.Apply.Session, apply.Apply.Continuation = credential.Session(), credential.Continuation()
		if !validApplyUUIDv7(apply.MaterialID) ||
			apply.MaterialID == apply.Apply.Session.SessionID() ||
			apply.MaterialID == apply.Apply.Continuation.ContinuationID() {
			credential.Destroy()
			return ApplyResult{}, ErrAuthentication
		}
		var result ApplyResult
		for range 2 {
			result, err = application.applier.ApplySAMLAuthentication(operation, cloneSAMLApplyRequest(apply))
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
				result.ReturnPath != projection.Consumption.ReturnPath ||
				disposition == ApplySession && (result.SessionID != apply.Apply.Session.SessionID() || result.ContinuationID != (identity.EntityID{})) ||
				disposition == ApplyContinuation && (result.ContinuationID != apply.Apply.Continuation.ContinuationID() || result.SessionID != (identity.EntityID{})) {
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
			if planningAttempt == 0 && eligibleSAMLFirstJITCollisionPlan(plan) {
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

func (application *SAMLApplication) operation(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil || ctx.Err() != nil || application == nil || application.operationTimeout <= 0 {
		return nil, nil, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, application.operationTimeout)
	return bounded, cancel, nil
}

func (application *SAMLApplication) currentTime() time.Time {
	return application.now().UTC().Truncate(time.Microsecond)
}

func buildSAMLAuthenticationProjection(
	configuration TenantSAMLConfiguration,
	proof samlObservedProof,
	consumption federatedsaml.ConsumptionRequest,
) (SAMLAuthenticationProjection, bool) {
	value := configuration.Authentication
	primary, ok := providerPrimaryEvidence(
		value.Provider, value.BindingID, proof.authenticatedAt, proof.validUntil, value.SecurityRevision,
	)
	if !ok {
		return SAMLAuthenticationProjection{}, false
	}
	evidence := []identity.AssuranceEvidence{primary}
	if proof.elevatedEvidence != nil {
		elevated := cloneEvidenceValue(*proof.elevatedEvidence)
		// The validated configuration is pinned by one aggregate security
		// revision. Persist that snapshot revision for every provider-sourced
		// evidence item so session revalidation has one unambiguous live key.
		securityRevision := int64(value.SecurityRevision)
		elevated.TrustRuleRevision = &securityRevision
		evidence = append(evidence, elevated)
	}
	projection := SAMLAuthenticationProjection{
		TenantID: value.Provider.TenantID, Provider: value.Provider, BindingID: value.BindingID,
		Issuer: proof.issuer, Subject: proof.subject, AuthenticatedAt: proof.authenticatedAt,
		ValidUntil: proof.validUntil, Scalars: append([]NamedValue(nil), proof.scalars...),
		Profiles: append([]ProfileValue(nil), proof.profiles...), Groups: append([]string(nil), proof.groups...),
		Evidence: cloneEvidence(evidence), Consumption: consumption,
	}
	return projection, validSAMLAuthenticationProjection(projection)
}

func validSAMLObservedProof(proof samlObservedProof, configuration federatedsaml.Configuration) bool {
	limits := federatedsaml.DefaultLimits()
	if !validSensitiveText(proof.issuer, 2048) || proof.issuer != configuration.Metadata.EntityID() ||
		!validInstant(proof.authenticatedAt) || !validInstant(proof.validUntil) ||
		!proof.validUntil.After(proof.authenticatedAt) || len(proof.scalars) > limits.MaxMappedScalars ||
		len(proof.profiles) > limits.MaxMappedProfiles || len(proof.groups) > limits.MaxGroups ||
		!validSAMLSubjectIdentity(proof.subject, configuration) ||
		!validSAMLObservedValues(proof.scalars, proof.profiles, proof.groups) {
		return false
	}
	if proof.elevatedEvidence != nil {
		if !validFederatedEvidence([]identity.AssuranceEvidence{*proof.elevatedEvidence}, configuration.Provider, configuration.BindingID) ||
			proof.elevatedEvidence.Level <= identity.AssurancePrimary ||
			proof.elevatedEvidence.AuthenticatedAt != proof.authenticatedAt || proof.elevatedEvidence.ExpiresAt == nil ||
			proof.elevatedEvidence.ExpiresAt.After(proof.validUntil) {
			return false
		}
	}
	material := proof.sessionMaterial
	return (material.NameID == "" || validSensitiveText(material.NameID, 16*1024)) &&
		(material.NameIDFormat == "" || validSensitiveText(material.NameIDFormat, 512)) &&
		(material.SessionIndex == "" || validSensitiveText(material.SessionIndex, 2048))
}

func validSAMLSubjectIdentity(subject SAMLSubjectIdentity, configuration federatedsaml.Configuration) bool {
	if subject.Source != configuration.Subject.Source || !validSensitiveText(subject.Value, 4*1024) {
		return false
	}
	switch subject.Source {
	case federatedsaml.SubjectPersistentNameID:
		return subject.Name == "NameID" && subject.Format == federatedsaml.PersistentNameIDFormat &&
			configuration.Subject.AttributeName == "" && configuration.Subject.AttributeNameFormat == ""
	case federatedsaml.SubjectImmutableAttribute:
		return subject.Name == configuration.Subject.AttributeName && subject.Format == configuration.Subject.AttributeNameFormat &&
			validSensitiveText(subject.Name, 512) && validSensitiveText(subject.Format, 512)
	default:
		return false
	}
}

func validSAMLObservedValues(scalars []NamedValue, profiles []ProfileValue, groups []string) bool {
	seenScalars := make(map[string]struct{}, len(scalars))
	for _, value := range scalars {
		if !validPublicText(value.Name, 512) || !validSensitiveText(value.Value, 16*1024) {
			return false
		}
		if _, duplicate := seenScalars[value.Name]; duplicate {
			return false
		}
		seenScalars[value.Name] = struct{}{}
	}
	seenProfiles := make(map[string]struct{}, len(profiles))
	for _, value := range profiles {
		if !validPublicText(value.Field, 64) || !validSensitiveText(value.Value, 16*1024) {
			return false
		}
		if _, duplicate := seenProfiles[value.Field]; duplicate {
			return false
		}
		seenProfiles[value.Field] = struct{}{}
	}
	if !slices.IsSorted(groups) {
		return false
	}
	for index, group := range groups {
		if !validSensitiveText(group, 16*1024) || index > 0 && groups[index-1] == group {
			return false
		}
	}
	return true
}

func sameSAMLObservedProof(left, right samlObservedProof) bool {
	return left.issuer == right.issuer && left.subject == right.subject &&
		left.authenticatedAt.Equal(right.authenticatedAt) && left.validUntil.Equal(right.validUntil) &&
		slices.Equal(left.scalars, right.scalars) && slices.Equal(left.profiles, right.profiles) &&
		slices.Equal(left.groups, right.groups) && sameSAMLEvidence(left.elevatedEvidence, right.elevatedEvidence) &&
		left.sessionMaterial.NameID == right.sessionMaterial.NameID &&
		left.sessionMaterial.NameIDFormat == right.sessionMaterial.NameIDFormat &&
		left.sessionMaterial.SessionIndex == right.sessionMaterial.SessionIndex
}

func sameSAMLEvidence(left, right *identity.AssuranceEvidence) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Level == right.Level && left.Kind == right.Kind && left.Source == right.Source &&
		left.AuthenticatedAt.Equal(right.AuthenticatedAt) && sameTimePointer(left.ExpiresAt, right.ExpiresAt) &&
		sameInt64Pointer(left.TrustRuleRevision, right.TrustRuleRevision) &&
		sameInt64Pointer(left.FactorRevision, right.FactorRevision)
}

func sameTimePointer(left, right *time.Time) bool {
	return left == nil && right == nil || left != nil && right != nil && left.Equal(*right)
}

func sameInt64Pointer(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func validSAMLConsumptionForConfiguration(
	request federatedsaml.ConsumptionRequest,
	configuration federatedsaml.Configuration,
) bool {
	pins := request.Pins
	sessionReplay := request.HasSessionIndex == (request.SessionIndexDigest != ([sha256.Size]byte{}))
	return request.TransactionID != (federatedsaml.TransactionID{}) && validApplyUUIDv7(request.MaterialID) &&
		validSAMLSuccessorRevision(request.ExpectedVersion) &&
		federatedsaml.ValidatePinnedConfiguration(configuration, pins, request.ConsumedAt) == nil &&
		pins.Provider == configuration.Provider && pins.BindingID == configuration.BindingID &&
		pins.ProviderRevision == configuration.ProviderRevision && pins.BindingRevision == configuration.BindingRevision &&
		pins.ConfigurationRevision == configuration.ConfigurationRevision && pins.SecurityRevision == configuration.SecurityRevision &&
		pins.MappingRevision == configuration.MappingRevision && pins.AuthorizationRevision == configuration.AuthorizationRevision &&
		pins.AssurancePolicyRevision == configuration.AssurancePolicyRevision &&
		pins.MetadataRevision == configuration.Metadata.Revision() && pins.MetadataDigest == configuration.Metadata.Digest() &&
		pins.SPKeyRevision == configuration.SPKeyRevision && pins.ConfigurationDigest != ([sha256.Size]byte{}) &&
		validPublicText(request.ResponseID, 1024) && validPublicText(request.AssertionID, 1024) &&
		request.ResponseID != request.AssertionID && validInstant(request.ConsumedAt) && validReturnPath(request.ReturnPath) && sessionReplay
}

func validSAMLAuthenticationProjection(value SAMLAuthenticationProjection) bool {
	limits := federatedsaml.DefaultLimits()
	if value.TenantID == (identity.EntityID{}) || value.Provider.Scope != identity.TenantProviderScope ||
		value.Provider.TenantID != value.TenantID || value.Provider.ProviderID == (identity.EntityID{}) ||
		value.BindingID == (identity.EntityID{}) || !validSensitiveText(value.Issuer, 2048) ||
		!validInstant(value.AuthenticatedAt) || !validInstant(value.ValidUntil) || !value.ValidUntil.After(value.AuthenticatedAt) ||
		len(value.Scalars) > limits.MaxMappedScalars || len(value.Profiles) > limits.MaxMappedProfiles ||
		len(value.Groups) > limits.MaxGroups || len(value.Evidence) < 1 || len(value.Evidence) > 2 ||
		!validSAMLEvidenceProjection(value) ||
		!validSAMLObservedValues(value.Scalars, value.Profiles, value.Groups) {
		return false
	}
	configuration := federatedsaml.Configuration{
		Provider: value.Provider, BindingID: value.BindingID, Subject: federatedsaml.SubjectPolicy{
			Source: value.Subject.Source, AttributeName: value.Subject.Name, AttributeNameFormat: value.Subject.Format,
		},
	}
	if value.Subject.Source == federatedsaml.SubjectPersistentNameID {
		configuration.Subject.AttributeName = ""
		configuration.Subject.AttributeNameFormat = ""
	}
	return validSAMLSubjectIdentity(value.Subject, configuration) &&
		validSAMLConsumptionForProjection(value.Consumption, value)
}

func validSAMLEvidenceProjection(value SAMLAuthenticationProjection) bool {
	if !validFederatedEvidence(value.Evidence, value.Provider, value.BindingID) || len(value.Evidence) < 1 ||
		!validSAMLRevision(value.Consumption.Pins.SecurityRevision) {
		return false
	}
	primary := value.Evidence[0]
	securityRevision := int64(value.Consumption.Pins.SecurityRevision)
	if primary.Level != identity.AssurancePrimary || primary.Kind != identity.AssuranceEvidenceFactor ||
		!primary.AuthenticatedAt.Equal(value.AuthenticatedAt) || primary.ExpiresAt == nil ||
		!primary.ExpiresAt.Equal(value.ValidUntil) || primary.TrustRuleRevision == nil ||
		*primary.TrustRuleRevision != securityRevision {
		return false
	}
	if len(value.Evidence) == 1 {
		return true
	}
	elevated := value.Evidence[1]
	return elevated.Level > identity.AssurancePrimary && elevated.Level <= identity.AssurancePhishingResistant &&
		elevated.Kind == identity.AssuranceEvidenceFactor && elevated.AuthenticatedAt.Equal(value.AuthenticatedAt) &&
		elevated.ExpiresAt != nil && validInstant(*elevated.ExpiresAt) && elevated.ExpiresAt.After(elevated.AuthenticatedAt) &&
		!elevated.ExpiresAt.After(value.ValidUntil) &&
		elevated.TrustRuleRevision != nil && *elevated.TrustRuleRevision == securityRevision
}

func validSAMLConsumptionForProjection(request federatedsaml.ConsumptionRequest, projection SAMLAuthenticationProjection) bool {
	pins := request.Pins
	return pins.Provider == projection.Provider && pins.BindingID == projection.BindingID &&
		validSAMLRevision(pins.ProviderRevision) && validSAMLRevision(pins.BindingRevision) &&
		validSAMLRevision(pins.ConfigurationRevision) && validSAMLRevision(pins.SecurityRevision) &&
		validSAMLRevision(pins.MappingRevision) && validSAMLRevision(pins.AuthorizationRevision) &&
		validSAMLRevision(pins.AssurancePolicyRevision) && validSAMLRevision(pins.MetadataRevision) &&
		pins.MetadataDigest != ([sha256.Size]byte{}) && validSAMLRevision(pins.SPKeyRevision) &&
		pins.ConfigurationDigest != ([sha256.Size]byte{}) && request.TransactionID != (federatedsaml.TransactionID{}) &&
		validApplyUUIDv7(request.MaterialID) &&
		validSAMLSuccessorRevision(request.ExpectedVersion) && validPublicText(request.ResponseID, 1024) &&
		validPublicText(request.AssertionID, 1024) && request.ResponseID != request.AssertionID &&
		validInstant(request.ConsumedAt) && validReturnPath(request.ReturnPath) &&
		request.HasSessionIndex == (request.SessionIndexDigest != ([sha256.Size]byte{}))
}

func validSAMLPlan(plan AuthenticationPlan, projection SAMLAuthenticationProjection) bool {
	pins := projection.Consumption.Pins
	return validDatabaseRevision(plan.PlanRevision) && plan.TenantID == projection.TenantID &&
		validDatabaseRevision(plan.ProviderRevision) && plan.ProviderRevision == pins.ProviderRevision &&
		validDatabaseRevision(plan.BindingRevision) && plan.BindingRevision == pins.BindingRevision &&
		validDatabaseRevision(plan.ConfigurationRevision) && plan.ConfigurationRevision == pins.ConfigurationRevision &&
		validDatabaseRevision(plan.SecurityRevision) && plan.SecurityRevision == pins.SecurityRevision &&
		validDatabaseRevision(plan.MappingRevision) && plan.MappingRevision == pins.MappingRevision &&
		validDatabaseRevision(plan.AuthorizationRevision) && plan.AuthorizationRevision == pins.AuthorizationRevision &&
		validDatabaseRevision(plan.PolicyRevision) && plan.PolicyRevision == pins.AssurancePolicyRevision &&
		len(plan.Requirement.PolicyRevisions) > 0 && validPlanIDs(plan.RoleIDs, 1_024) &&
		validPlanIDs(plan.SecurityGroupIDs, 1_024) && validProtectedFederatedSubject(plan.Subject) && plan.Mapping != nil &&
		plan.Mapping.Disposition() == identity.LDAPPlanAdmitted &&
		slices.Equal(plan.RoleIDs, plan.Mapping.ProspectiveRoleIDs()) &&
		slices.Equal(plan.SecurityGroupIDs, plan.Mapping.ProspectiveSecurityGroupIDs()) &&
		(plan.UserID == (identity.EntityID{}) && plan.IdentityEpoch == 0 &&
			plan.Mapping.IdentityAction() == identity.LDAPIdentityCreateUserAndExternalIdentity ||
			plan.UserID != (identity.EntityID{}) && plan.IdentityEpoch > 0 &&
				plan.Mapping.IdentityAction() == identity.LDAPIdentityNoChange)
}

func eligibleSAMLFirstJITCollisionPlan(plan AuthenticationPlan) bool {
	return plan.UserID == (identity.EntityID{}) && plan.IdentityEpoch == 0 && plan.Subject != nil && plan.Mapping != nil &&
		plan.Mapping.IdentityAction() == identity.LDAPIdentityCreateUserAndExternalIdentity
}

func genericSAMLAuthenticationProjection(value SAMLAuthenticationProjection) AuthenticationProjection {
	consumption := value.Consumption
	return AuthenticationProjection{
		Protocol: ProtocolSAML, TenantID: value.TenantID,
		Subject:         ExternalSubject{Provider: value.Provider, BindingID: value.BindingID, Issuer: value.Issuer, Value: value.Subject.Value},
		AuthenticatedAt: value.AuthenticatedAt, ValidUntil: value.ValidUntil,
		Scalars: append([]NamedValue(nil), value.Scalars...), Profiles: append([]ProfileValue(nil), value.Profiles...),
		Groups: append([]string(nil), value.Groups...), Evidence: cloneEvidence(value.Evidence), SAMLConsumption: &consumption,
	}
}

func cloneSAMLAuthenticationProjection(value SAMLAuthenticationProjection) SAMLAuthenticationProjection {
	value.Scalars = append([]NamedValue(nil), value.Scalars...)
	value.Profiles = append([]ProfileValue(nil), value.Profiles...)
	value.Groups = append([]string(nil), value.Groups...)
	value.Evidence = cloneEvidence(value.Evidence)
	return value
}

func validSAMLSessionMaterial(
	material federatedsaml.SessionMaterial,
	consumption federatedsaml.ConsumptionRequest,
) bool {
	if (material.NameID == "") != (material.NameIDFormat == "") ||
		material.NameID != "" && (!validSensitiveText(material.NameID, 16*1024) ||
			material.NameIDFormat != federatedsaml.PersistentNameIDFormat) ||
		material.SessionIndex != "" && !validSensitiveText(material.SessionIndex, 2048) {
		return false
	}
	return consumption.HasSessionIndex == (material.SessionIndex != "")
}

func cloneSAMLApplyRequest(value SAMLApplyRequest) SAMLApplyRequest {
	value.Apply = cloneApplyRequest(value.Apply)
	return value
}

func samlConsumerCategory(err error) federatedsaml.AuthenticationConsumerCategory {
	switch {
	case errors.Is(err, ErrIdentityCollision):
		return federatedsaml.ConsumerCollision
	case errors.Is(err, ErrStaleConfiguration):
		return federatedsaml.ConsumerStale
	case errors.Is(err, ErrAuthentication), errors.Is(err, ErrInvalidInput):
		return federatedsaml.ConsumerDenied
	default:
		return federatedsaml.ConsumerUnavailable
	}
}

func mapSAMLConsumptionError(err error) error {
	switch {
	case errors.Is(err, ErrIdentityCollision):
		return ErrIdentityCollision
	case errors.Is(err, ErrStaleConfiguration):
		return ErrStaleConfiguration
	default:
		return ErrAuthentication
	}
}
