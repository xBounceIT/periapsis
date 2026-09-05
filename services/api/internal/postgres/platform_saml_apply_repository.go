package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"slices"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

const (
	applyPlatformSAMLAuthenticationSQL   = `select app.apply_platform_saml_authentication_v1($1::jsonb)`
	recoverPlatformSAMLApplySQL          = `select app.recover_platform_saml_authentication_apply_v1($1::jsonb)`
	rejectPlatformSAMLAuthenticationSQL  = `select app.reject_platform_saml_authentication_v1($1::jsonb)`
	cleanupPlatformSAMLAuthenticationSQL = `select app.cleanup_platform_saml_authentication_v1($1::jsonb)`
	maximumPlatformSAMLApplyWireBytes    = 2 * 1024 * 1024
)

type platformSAMLApplyAuthorityWire struct {
	TransactionID      []byte                       `json:"transactionId"`
	MaterialID         string                       `json:"materialId"`
	ExpectedVersion    uint64                       `json:"expectedVersion"`
	Pins               platformSAMLProtocolPinsWire `json:"pins"`
	ResponseIDDigest   []byte                       `json:"responseIdDigest"`
	AssertionIDDigest  []byte                       `json:"assertionIdDigest"`
	SessionIndexDigest []byte                       `json:"sessionIndexDigest,omitempty"`
	HasSessionIndex    bool                         `json:"hasSessionIndex"`
	HasSessionMaterial bool                         `json:"hasSessionMaterial"`
	ConsumedAt         time.Time                    `json:"consumedAt"`
	ReturnPath         string                       `json:"returnPath"`
}

type platformSAMLApplyProvenanceWire struct {
	Provider                   platformSAMLProviderWire          `json:"provider"`
	ProviderKind               string                            `json:"providerKind"`
	ExternalIdentityID         string                            `json:"externalIdentityId"`
	UserID                     string                            `json:"userId"`
	IdentityRevision           uint64                            `json:"identityRevision"`
	UserAuthenticationRevision uint64                            `json:"userAuthenticationRevision"`
	PlatformAuthorityID        string                            `json:"platformAuthorityId"`
	PlatformAuthorityRevision  uint64                            `json:"platformAuthorityRevision"`
	MatchedAliasKeyVersion     int16                             `json:"matchedAliasKeyVersion"`
	AuthenticatedAt            time.Time                         `json:"authenticatedAt"`
	ValidUntil                 time.Time                         `json:"validUntil"`
	SelectedAssurance          platformSAMLSelectedAssuranceWire `json:"selectedAssurance"`
}

type platformSAMLSelectedAssuranceWire struct {
	Level             string    `json:"level"`
	AuthenticatedAt   time.Time `json:"authenticatedAt"`
	TrustRuleID       *string   `json:"trustRuleId,omitempty"`
	TrustRuleRevision *uint64   `json:"trustRuleRevision,omitempty"`
}

type platformSAMLSubjectEnvelopeWire struct {
	KeyVersion int16  `json:"keyVersion"`
	Format     string `json:"format"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type platformSAMLSubjectObservationWire struct {
	ExternalIdentityID string                          `json:"externalIdentityId"`
	SubjectFormat      string                          `json:"subjectFormat"`
	Aliases            []platformSAMLSubjectAliasWire  `json:"aliases"`
	Envelope           platformSAMLSubjectEnvelopeWire `json:"envelope"`
}

type platformSAMLAssuranceEvidenceWire struct {
	Level             string     `json:"level"`
	Kind              string     `json:"kind"`
	Local             bool       `json:"local"`
	DirectPlatform    bool       `json:"directPlatform"`
	ProviderID        string     `json:"providerId"`
	AuthenticatedAt   time.Time  `json:"authenticatedAt"`
	ExpiresAt         *time.Time `json:"expiresAt"`
	FactorRevision    *int64     `json:"factorRevision,omitempty"`
	TrustRuleRevision *int64     `json:"trustRuleRevision,omitempty"`
}

type platformSAMLEffectiveRequirementWire struct {
	Level                string                           `json:"level"`
	LocalRequired        bool                             `json:"localRequired"`
	FreshnessNanoseconds int64                            `json:"freshnessNanoseconds"`
	EnrollmentDeadline   *time.Time                       `json:"enrollmentDeadline"`
	PolicyRevisions      []platformSAMLPolicyRevisionWire `json:"policyRevisions"`
}

type platformSAMLPolicyRevisionWire struct {
	PolicyID string `json:"policyId"`
	Revision int64  `json:"revision"`
}

type platformSAMLTOTPSelectionWire struct {
	FactorID string `json:"factorId"`
	Revision uint64 `json:"revision"`
}

type platformSAMLApplyPlanWire struct {
	Disposition   string                               `json:"disposition"`
	Pins          platformSAMLDirectPinsWire           `json:"pins"`
	Provenance    platformSAMLApplyProvenanceWire      `json:"provenance"`
	Subject       platformSAMLSubjectObservationWire   `json:"subject"`
	Evidence      []platformSAMLAssuranceEvidenceWire  `json:"evidence"`
	PlatformFloor platformSAMLEffectiveRequirementWire `json:"platformFloor"`
	TOTP          *platformSAMLTOTPSelectionWire       `json:"totp,omitempty"`
}

type platformSAMLSessionReservationWire struct {
	ID                   string    `json:"id"`
	RotationFamilyID     string    `json:"rotationFamilyId"`
	TokenDigest          []byte    `json:"tokenDigest"`
	CSRFSecretDigest     []byte    `json:"csrfSecretDigest"`
	AuthenticationMethod string    `json:"authenticationMethod"`
	IdleExpiresAt        time.Time `json:"idleExpiresAt"`
	AbsoluteExpiresAt    time.Time `json:"absoluteExpiresAt"`
}

type platformSAMLContinuationReservationWire struct {
	ID             string    `json:"id"`
	FactorID       string    `json:"factorId"`
	FactorRevision uint64    `json:"factorRevision"`
	ReceiptDigest  []byte    `json:"receiptDigest"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type platformSAMLProtectedSessionMaterialWire struct {
	MaterialID string `json:"materialId"`
	KeyVersion int16  `json:"keyVersion"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type platformSAMLApplyWire struct {
	Authority                platformSAMLApplyAuthorityWire            `json:"authority"`
	Plan                     platformSAMLApplyPlanWire                 `json:"plan"`
	Session                  *platformSAMLSessionReservationWire       `json:"session,omitempty"`
	Continuation             *platformSAMLContinuationReservationWire  `json:"continuation,omitempty"`
	SessionAudience          string                                    `json:"sessionAudience"`
	RecoveryRestricted       bool                                      `json:"recoveryRestricted"`
	ProtectedSessionMaterial *platformSAMLProtectedSessionMaterialWire `json:"protectedSessionMaterial,omitempty"`
	AppliedAt                time.Time                                 `json:"appliedAt"`
	Audit                    platformSAMLAuditWire                     `json:"audit"`
	ProofDigest              []byte                                    `json:"proofDigest"`
}

type platformSAMLApplyResultWire struct {
	Category       string    `json:"category"`
	TransactionID  []byte    `json:"transactionId"`
	ProofDigest    []byte    `json:"proofDigest"`
	UserID         string    `json:"userId"`
	SessionID      *string   `json:"sessionId"`
	ContinuationID *string   `json:"continuationId"`
	ReturnPath     string    `json:"returnPath"`
	AppliedAt      time.Time `json:"appliedAt"`
}

type platformSAMLRejectWire struct {
	Authority  platformSAMLApplyAuthorityWire `json:"authority"`
	Reason     string                         `json:"reason"`
	RejectedAt time.Time                      `json:"rejectedAt"`
	Audit      platformSAMLAuditWire          `json:"audit"`
}

type platformSAMLCleanupWire struct {
	Result      platformSAMLApplyResultWire `json:"result"`
	Reason      string                      `json:"reason"`
	CleanedUpAt time.Time                   `json:"cleanedUpAt"`
	Audit       platformSAMLAuditWire       `json:"audit"`
}

var _ platformsamlauth.AtomicApplyPort = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) ApplyDirectSAML(
	ctx context.Context,
	request platformsamlauth.ApplyRequest,
) (platformsamlauth.ApplyResult, error) {
	wire, err := platformSAMLApplyToWire(request)
	if err != nil {
		return platformsamlauth.ApplyResult{}, errPlatformSAMLPersistence
	}
	defer clearPlatformSAMLApplyWire(&wire)
	var response platformSAMLApplyResultWire
	defer clearPlatformSAMLApplyResultWire(&response)
	if err = repository.queryJSONWithResponseLimit(
		ctx, applyPlatformSAMLAuthenticationSQL, wire, &response, maximumPlatformSAMLApplyWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformsamlauth.ApplyResult{}, errPlatformSAMLPersistence
	}
	return platformSAMLApplyResultFromWire(response, request)
}

func (repository *FederatedAuthRepository) RecoverDirectSAML(
	ctx context.Context,
	lookup platformsamlauth.RecoveryLookup,
) (platformsamlauth.RecoveryResult, error) {
	wire, err := platformSAMLApplyToWire(lookup.Request)
	if err != nil {
		return platformsamlauth.RecoveryResult{}, errPlatformSAMLPersistence
	}
	defer clearPlatformSAMLApplyWire(&wire)
	type recoveryWire struct {
		Matched bool                         `json:"matched"`
		Result  *platformSAMLApplyResultWire `json:"result,omitempty"`
	}
	var response recoveryWire
	if err = repository.queryJSONWithResponseLimit(
		ctx, recoverPlatformSAMLApplySQL, wire, &response, maximumPlatformSAMLApplyWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformsamlauth.RecoveryResult{}, errPlatformSAMLPersistence
	}
	if !response.Matched {
		if response.Result != nil {
			clearPlatformSAMLApplyResultWire(response.Result)
			return platformsamlauth.RecoveryResult{}, errPlatformSAMLPersistence
		}
		return platformsamlauth.RecoveryResult{Matched: false}, nil
	}
	if response.Result == nil {
		return platformsamlauth.RecoveryResult{}, errPlatformSAMLPersistence
	}
	defer clearPlatformSAMLApplyResultWire(response.Result)
	result, err := platformSAMLApplyResultFromWire(*response.Result, lookup.Request)
	if err != nil || result.Category != platformsamlauth.ApplyAlreadyApplied {
		return platformsamlauth.RecoveryResult{}, errPlatformSAMLPersistence
	}
	return platformsamlauth.RecoveryResult{Matched: true, Result: result}, nil
}

func (repository *FederatedAuthRepository) RejectDirectSAML(
	ctx context.Context,
	request platformsamlauth.RejectRequest,
) error {
	authority, err := platformSAMLApplyAuthorityToWire(request.Authority)
	audit, auditErr := platformSAMLAuditToWire(request.Audit)
	if err != nil || auditErr != nil || !validPlatformSAMLInstant(request.RejectedAt) ||
		request.Reason != platformsamlauth.RejectMalformed && request.Reason != platformsamlauth.RejectDenied &&
			request.Reason != platformsamlauth.RejectStale && request.Reason != platformsamlauth.RejectCollision &&
			request.Reason != platformsamlauth.RejectUnavailable {
		return errPlatformSAMLPersistence
	}
	wire := platformSAMLRejectWire{
		Authority: authority, Reason: string(request.Reason), RejectedAt: request.RejectedAt, Audit: audit,
	}
	defer clearPlatformSAMLApplyAuthorityWire(&wire.Authority)
	var applied bool
	if err = repository.queryJSONWithResponseLimit(
		ctx, rejectPlatformSAMLAuthenticationSQL, wire, &applied, 64,
	); err != nil || ctx.Err() != nil || !applied {
		return errPlatformSAMLPersistence
	}
	return nil
}

func (repository *FederatedAuthRepository) CleanupDirectSAML(
	ctx context.Context,
	request platformsamlauth.CleanupRequest,
) error {
	result, err := platformSAMLApplyResultToWire(request.Result)
	audit, auditErr := platformSAMLAuditToWire(request.Audit)
	if err != nil || auditErr != nil || !validPlatformSAMLInstant(request.CleanedUpAt) ||
		request.CleanedUpAt.Before(request.Result.AppliedAt) ||
		request.Reason != platformsamlauth.CleanupCredentialReleaseFailed &&
			request.Reason != platformsamlauth.CleanupProtocolFailed &&
			request.Reason != platformsamlauth.CleanupInvalidOutcome &&
			request.Reason != platformsamlauth.CleanupDeliveryFailed {
		return errPlatformSAMLPersistence
	}
	wire := platformSAMLCleanupWire{
		Result: result, Reason: string(request.Reason), CleanedUpAt: request.CleanedUpAt, Audit: audit,
	}
	defer clearPlatformSAMLApplyResultWire(&wire.Result)
	var cleaned bool
	if err = repository.queryJSONWithResponseLimit(
		ctx, cleanupPlatformSAMLAuthenticationSQL, wire, &cleaned, 64,
	); err != nil || ctx.Err() != nil || !cleaned {
		return errPlatformSAMLPersistence
	}
	return nil
}

func platformSAMLApplyToWire(request platformsamlauth.ApplyRequest) (platformSAMLApplyWire, error) {
	authority, err := platformSAMLApplyAuthorityToWire(request.Authority)
	plan, planErr := platformSAMLApplyPlanToWire(request.Plan, request.Authority, request.AppliedAt)
	audit, auditErr := platformSAMLAuditToWire(request.Audit)
	if err != nil || planErr != nil || auditErr != nil || request.SessionAudience != platformsamlauth.SessionAudience ||
		request.RecoveryRestricted || !validPlatformSAMLInstant(request.AppliedAt) ||
		request.AppliedAt.Before(request.Authority.ConsumedAt) || request.ProofDigest == ([sha256.Size]byte{}) {
		clearPlatformSAMLApplyAuthorityWire(&authority)
		clearPlatformSAMLApplyPlanWire(&plan)
		return platformSAMLApplyWire{}, errPlatformSAMLPersistence
	}
	wire := platformSAMLApplyWire{
		Authority: authority, Plan: plan, SessionAudience: request.SessionAudience,
		RecoveryRestricted: false, AppliedAt: request.AppliedAt, Audit: audit,
		ProofDigest: append([]byte(nil), request.ProofDigest[:]...),
	}
	switch request.Plan.Disposition {
	case platformsamlauth.ImmediateSession:
		if request.Session.IsZero() || !request.Continuation.IsZero() || request.Plan.TOTP != nil {
			clearPlatformSAMLApplyWire(&wire)
			return platformSAMLApplyWire{}, errPlatformSAMLPersistence
		}
		session, sessionErr := platformSAMLSessionReservationToWire(request.Session, request.AppliedAt)
		if sessionErr != nil {
			clearPlatformSAMLApplyWire(&wire)
			return platformSAMLApplyWire{}, errPlatformSAMLPersistence
		}
		wire.Session = &session
	case platformsamlauth.TOTPContinuation:
		if !request.Session.IsZero() || request.Continuation.IsZero() || request.Plan.TOTP == nil ||
			!request.Continuation.ValidAt(request.AppliedAt) || request.Continuation.FactorID() != request.Plan.TOTP.FactorID ||
			request.Continuation.FactorRevision() != request.Plan.TOTP.Revision {
			clearPlatformSAMLApplyWire(&wire)
			return platformSAMLApplyWire{}, errPlatformSAMLPersistence
		}
		receiptDigest := request.Continuation.ReceiptDigest()
		wire.Continuation = &platformSAMLContinuationReservationWire{
			ID:             entityIDWire(request.Continuation.ContinuationID()),
			FactorID:       entityIDWire(request.Continuation.FactorID()),
			FactorRevision: request.Continuation.FactorRevision(),
			ReceiptDigest:  append([]byte(nil), receiptDigest[:]...),
			ExpiresAt:      request.Continuation.ExpiresAt(),
		}
	default:
		clearPlatformSAMLApplyWire(&wire)
		return platformSAMLApplyWire{}, errPlatformSAMLPersistence
	}
	if request.Authority.HasSessionMaterial {
		envelope := request.ProtectedSessionMaterial.Envelope
		if envelope.KeyVersion < 1 || envelope.Nonce == ([12]byte{}) || len(envelope.Ciphertext) < 17 ||
			len(envelope.Ciphertext) > 16384 {
			clearPlatformSAMLApplyWire(&wire)
			return platformSAMLApplyWire{}, errPlatformSAMLPersistence
		}
		wire.ProtectedSessionMaterial = &platformSAMLProtectedSessionMaterialWire{
			MaterialID: entityIDWire(request.Authority.MaterialID), KeyVersion: envelope.KeyVersion,
			Nonce: append([]byte(nil), envelope.Nonce[:]...), Ciphertext: append([]byte(nil), envelope.Ciphertext...),
		}
	} else if envelope := request.ProtectedSessionMaterial.Envelope; envelope.KeyVersion != 0 ||
		envelope.Nonce != ([12]byte{}) || len(envelope.Ciphertext) != 0 {
		clearPlatformSAMLApplyWire(&wire)
		return platformSAMLApplyWire{}, errPlatformSAMLPersistence
	}
	return wire, nil
}

func platformSAMLApplyAuthorityToWire(
	authority platformsamlauth.ConsumptionAuthority,
) (platformSAMLApplyAuthorityWire, error) {
	pins, err := platformSAMLProtocolPinsToWire(authority.Pins)
	if err != nil || authority.TransactionID == (federatedsaml.TransactionID{}) ||
		authority.MaterialID == (identity.EntityID{}) || authority.ExpectedVersion == 0 ||
		authority.ResponseID == "" || authority.AssertionID == "" || authority.ResponseID == authority.AssertionID ||
		!validPlatformSAMLInstant(authority.ConsumedAt) || authority.ReturnPath == "" ||
		authority.HasSessionIndex != (authority.SessionIndexDigest != ([sha256.Size]byte{})) {
		return platformSAMLApplyAuthorityWire{}, errPlatformSAMLPersistence
	}
	responseDigest := platformSAMLReplayDigest("response", authority.ResponseID)
	assertionDigest := platformSAMLReplayDigest("assertion", authority.AssertionID)
	if responseDigest == assertionDigest {
		return platformSAMLApplyAuthorityWire{}, errPlatformSAMLPersistence
	}
	wire := platformSAMLApplyAuthorityWire{
		TransactionID: append([]byte(nil), authority.TransactionID[:]...), MaterialID: entityIDWire(authority.MaterialID),
		ExpectedVersion: authority.ExpectedVersion, Pins: pins,
		ResponseIDDigest:  append([]byte(nil), responseDigest[:]...),
		AssertionIDDigest: append([]byte(nil), assertionDigest[:]...),
		HasSessionIndex:   authority.HasSessionIndex, HasSessionMaterial: authority.HasSessionMaterial,
		ConsumedAt: authority.ConsumedAt, ReturnPath: authority.ReturnPath,
	}
	if authority.HasSessionIndex {
		wire.SessionIndexDigest = append([]byte(nil), authority.SessionIndexDigest[:]...)
	}
	return wire, nil
}

func platformSAMLApplyPlanToWire(
	plan platformsamlauth.AuthenticationPlan,
	authority platformsamlauth.ConsumptionAuthority,
	appliedAt time.Time,
) (platformSAMLApplyPlanWire, error) {
	pins, err := platformSAMLDirectPinsToWire(plan.Pins)
	provider, providerErr := platformSAMLProviderToWire(plan.Provenance.Provider)
	selected, selectedErr := platformSAMLSelectedAssuranceToWire(plan.Provenance.SelectedAssurance)
	if err != nil || providerErr != nil || selectedErr != nil || plan.Pins.Protocol != authority.Pins ||
		plan.Provenance.Provider != authority.Pins.Provider || plan.Provenance.ProviderKind != platformsamlauth.ProviderKindSAML ||
		plan.Provenance.ExternalIdentityID == (identity.EntityID{}) || plan.Provenance.UserID == (identity.EntityID{}) ||
		!validPlatformSAMLRevision(plan.Provenance.IdentityRevision) ||
		!validPlatformSAMLRevision(plan.Provenance.UserAuthenticationRevision) ||
		!validPlatformSAMLRevision(plan.Provenance.PlatformAuthorityRevision) ||
		plan.Provenance.MatchedAliasKeyVersion < 1 || !validPlatformSAMLInstant(plan.Provenance.AuthenticatedAt) ||
		!validPlatformSAMLInstant(plan.Provenance.ValidUntil) || !plan.Provenance.ValidUntil.After(plan.Provenance.AuthenticatedAt) ||
		plan.Provenance.AuthenticatedAt.After(appliedAt) || plan.Subject.ExternalIdentityID != plan.Provenance.ExternalIdentityID ||
		plan.Subject.SubjectFormat != identity.UTF8ExactSubject || plan.Subject.Envelope.Format != identity.UTF8ExactSubject ||
		len(plan.Subject.Aliases) < 1 || len(plan.Subject.Aliases) > 16 || len(plan.Evidence) < 1 || len(plan.Evidence) > 2 {
		return platformSAMLApplyPlanWire{}, errPlatformSAMLPersistence
	}
	aliases := make([]platformSAMLSubjectAliasWire, len(plan.Subject.Aliases))
	foundAlias := false
	foundEnvelope := false
	for index, alias := range plan.Subject.Aliases {
		if alias.KeyVersion < 1 || alias.Digest == ([sha256.Size]byte{}) ||
			index > 0 && plan.Subject.Aliases[index-1].KeyVersion >= alias.KeyVersion {
			clearPlatformSAMLSubjectAliasesWire(aliases)
			return platformSAMLApplyPlanWire{}, errPlatformSAMLPersistence
		}
		foundAlias = foundAlias || alias.KeyVersion == plan.Provenance.MatchedAliasKeyVersion
		foundEnvelope = foundEnvelope || alias.KeyVersion == plan.Subject.Envelope.KeyVersion
		aliases[index] = platformSAMLSubjectAliasWire{KeyVersion: alias.KeyVersion, Digest: append([]byte(nil), alias.Digest[:]...)}
	}
	if !foundAlias || !foundEnvelope || plan.Subject.Envelope.Nonce == ([12]byte{}) ||
		len(plan.Subject.Envelope.Ciphertext) < 17 || len(plan.Subject.Envelope.Ciphertext) > 4112 {
		clearPlatformSAMLSubjectAliasesWire(aliases)
		return platformSAMLApplyPlanWire{}, errPlatformSAMLPersistence
	}
	evidence := make([]platformSAMLAssuranceEvidenceWire, len(plan.Evidence))
	for index, value := range plan.Evidence {
		level, levelErr := assuranceLevelToWire(value.Level)
		if levelErr != nil || value.Kind != identity.AssuranceEvidenceFactor || value.Source.Local ||
			!value.Source.DirectPlatform || value.Source.ProviderID != plan.Pins.Protocol.Provider.ProviderID ||
			value.Source.BindingID != (identity.EntityID{}) || !validPlatformSAMLInstant(value.AuthenticatedAt) ||
			value.ExpiresAt == nil || !validPlatformSAMLInstant(*value.ExpiresAt) ||
			!value.ExpiresAt.After(value.AuthenticatedAt) || value.FactorRevision != nil || value.TrustRuleRevision == nil ||
			*value.TrustRuleRevision < 1 {
			clearPlatformSAMLSubjectAliasesWire(aliases)
			return platformSAMLApplyPlanWire{}, errPlatformSAMLPersistence
		}
		expiresAt := *value.ExpiresAt
		trustRevision := *value.TrustRuleRevision
		evidence[index] = platformSAMLAssuranceEvidenceWire{
			Level: level, Kind: "factor", DirectPlatform: true,
			ProviderID: entityIDWire(value.Source.ProviderID), AuthenticatedAt: value.AuthenticatedAt,
			ExpiresAt: &expiresAt, TrustRuleRevision: &trustRevision,
		}
	}
	requirement, requirementErr := platformSAMLEffectiveRequirementToWire(plan.PlatformFloor, plan.Pins)
	if requirementErr != nil {
		clearPlatformSAMLSubjectAliasesWire(aliases)
		return platformSAMLApplyPlanWire{}, errPlatformSAMLPersistence
	}
	wire := platformSAMLApplyPlanWire{
		Disposition: string(plan.Disposition), Pins: pins,
		Provenance: platformSAMLApplyProvenanceWire{
			Provider: provider, ProviderKind: plan.Provenance.ProviderKind,
			ExternalIdentityID: entityIDWire(plan.Provenance.ExternalIdentityID), UserID: entityIDWire(plan.Provenance.UserID),
			IdentityRevision:           plan.Provenance.IdentityRevision,
			UserAuthenticationRevision: plan.Provenance.UserAuthenticationRevision,
			PlatformAuthorityID:        entityIDWire(plan.Provenance.PlatformAuthorityID),
			PlatformAuthorityRevision:  plan.Provenance.PlatformAuthorityRevision,
			MatchedAliasKeyVersion:     plan.Provenance.MatchedAliasKeyVersion,
			AuthenticatedAt:            plan.Provenance.AuthenticatedAt, ValidUntil: plan.Provenance.ValidUntil,
			SelectedAssurance: selected,
		},
		Subject: platformSAMLSubjectObservationWire{
			ExternalIdentityID: entityIDWire(plan.Subject.ExternalIdentityID), SubjectFormat: "utf8_exact",
			Aliases: aliases, Envelope: platformSAMLSubjectEnvelopeWire{
				KeyVersion: plan.Subject.Envelope.KeyVersion, Format: "utf8_exact",
				Nonce:      append([]byte(nil), plan.Subject.Envelope.Nonce[:]...),
				Ciphertext: append([]byte(nil), plan.Subject.Envelope.Ciphertext...),
			},
		},
		Evidence: evidence, PlatformFloor: requirement,
	}
	if plan.TOTP != nil {
		if plan.Disposition != platformsamlauth.TOTPContinuation || plan.TOTP.FactorID == (identity.EntityID{}) ||
			!validPlatformSAMLRevision(plan.TOTP.Revision) {
			clearPlatformSAMLApplyPlanWire(&wire)
			return platformSAMLApplyPlanWire{}, errPlatformSAMLPersistence
		}
		wire.TOTP = &platformSAMLTOTPSelectionWire{FactorID: entityIDWire(plan.TOTP.FactorID), Revision: plan.TOTP.Revision}
	} else if plan.Disposition != platformsamlauth.ImmediateSession {
		clearPlatformSAMLApplyPlanWire(&wire)
		return platformSAMLApplyPlanWire{}, errPlatformSAMLPersistence
	}
	return wire, nil
}

func platformSAMLSelectedAssuranceToWire(
	value platformsamlauth.SelectedAssurance,
) (platformSAMLSelectedAssuranceWire, error) {
	level, err := assuranceLevelToWire(value.Level)
	if err != nil || !validPlatformSAMLInstant(value.AuthenticatedAt) ||
		(value.TrustRuleID == nil) != (value.TrustRuleRevision == nil) {
		return platformSAMLSelectedAssuranceWire{}, errPlatformSAMLPersistence
	}
	wire := platformSAMLSelectedAssuranceWire{Level: level, AuthenticatedAt: value.AuthenticatedAt}
	if value.Level == identity.AssurancePrimary {
		if value.TrustRuleID != nil {
			return platformSAMLSelectedAssuranceWire{}, errPlatformSAMLPersistence
		}
		return wire, nil
	}
	if value.TrustRuleID == nil || !validPlatformSAMLRevision(*value.TrustRuleRevision) {
		return platformSAMLSelectedAssuranceWire{}, errPlatformSAMLPersistence
	}
	id := entityIDWire(*value.TrustRuleID)
	revision := *value.TrustRuleRevision
	wire.TrustRuleID = &id
	wire.TrustRuleRevision = &revision
	return wire, nil
}

func platformSAMLEffectiveRequirementToWire(
	value identity.EffectiveAssuranceRequirement,
	pins platformsamlauth.DirectSAMLPins,
) (platformSAMLEffectiveRequirementWire, error) {
	level, err := assuranceLevelToWire(value.Level)
	if err != nil || value.Freshness < 0 || value.Freshness > 30*24*time.Hour ||
		value.Freshness%time.Second != 0 || len(value.PolicyRevisions) != 1 ||
		value.PolicyRevisions[0].PolicyID != pins.PlatformFloorPolicyID ||
		value.PolicyRevisions[0].Revision != int64(pins.PlatformFloorPolicyRevision) {
		return platformSAMLEffectiveRequirementWire{}, errPlatformSAMLPersistence
	}
	wire := platformSAMLEffectiveRequirementWire{
		Level: level, LocalRequired: value.LocalRequired, FreshnessNanoseconds: int64(value.Freshness),
		PolicyRevisions: []platformSAMLPolicyRevisionWire{{
			PolicyID: entityIDWire(value.PolicyRevisions[0].PolicyID), Revision: value.PolicyRevisions[0].Revision,
		}},
	}
	if value.EnrollmentDeadline != nil {
		if !validPlatformSAMLInstant(*value.EnrollmentDeadline) {
			return platformSAMLEffectiveRequirementWire{}, errPlatformSAMLPersistence
		}
		deadline := *value.EnrollmentDeadline
		wire.EnrollmentDeadline = &deadline
	}
	return wire, nil
}

func platformSAMLSessionReservationToWire(
	value mfa.SessionReservation,
	issuedAt time.Time,
) (platformSAMLSessionReservationWire, error) {
	tokenDigest := value.TokenDigest()
	csrfDigest := value.CSRFDigest()
	if value.IsZero() || value.AuthenticationMethod() != mfa.SessionAuthenticationSAML ||
		!value.ValidAt(issuedAt.Truncate(time.Millisecond)) || tokenDigest == ([sha256.Size]byte{}) ||
		csrfDigest == ([sha256.Size]byte{}) || tokenDigest == csrfDigest {
		return platformSAMLSessionReservationWire{}, errPlatformSAMLPersistence
	}
	return platformSAMLSessionReservationWire{
		ID: entityIDWire(value.SessionID()), RotationFamilyID: entityIDWire(value.FamilyID()),
		TokenDigest: append([]byte(nil), tokenDigest[:]...), CSRFSecretDigest: append([]byte(nil), csrfDigest[:]...),
		AuthenticationMethod: string(value.AuthenticationMethod()), IdleExpiresAt: value.IdleExpiresAt(),
		AbsoluteExpiresAt: value.AbsoluteExpiresAt(),
	}, nil
}

func platformSAMLApplyResultFromWire(
	wire platformSAMLApplyResultWire,
	request platformsamlauth.ApplyRequest,
) (platformsamlauth.ApplyResult, error) {
	transactionID, transactionErr := platformSAMLTransactionIDFromWire(wire.TransactionID)
	userID, userErr := parseEntityIDWire(wire.UserID, false)
	appliedAt := platformSAMLUTC(wire.AppliedAt)
	if transactionErr != nil || userErr != nil || len(wire.ProofDigest) != sha256.Size ||
		transactionID != request.Authority.TransactionID || userID != request.Plan.Provenance.UserID ||
		!slices.Equal(wire.ProofDigest, request.ProofDigest[:]) || wire.ReturnPath != request.Authority.ReturnPath ||
		!validPlatformSAMLInstant(appliedAt) || !appliedAt.Equal(request.AppliedAt) {
		return platformsamlauth.ApplyResult{}, errPlatformSAMLPersistence
	}
	result := platformsamlauth.ApplyResult{
		Category: platformsamlauth.ApplyCategory(wire.Category), TransactionID: transactionID,
		ProofDigest: request.ProofDigest, UserID: userID, ReturnPath: wire.ReturnPath, AppliedAt: appliedAt,
	}
	if request.Plan.Disposition == platformsamlauth.ImmediateSession {
		if wire.SessionID == nil || wire.ContinuationID != nil || *wire.SessionID != entityIDWire(request.Session.SessionID()) {
			return platformsamlauth.ApplyResult{}, errPlatformSAMLPersistence
		}
		result.SessionID = request.Session.SessionID()
	} else {
		if wire.ContinuationID == nil || wire.SessionID != nil ||
			*wire.ContinuationID != entityIDWire(request.Continuation.ContinuationID()) {
			return platformsamlauth.ApplyResult{}, errPlatformSAMLPersistence
		}
		result.ContinuationID = request.Continuation.ContinuationID()
	}
	switch result.Category {
	case platformsamlauth.ApplySuccess, platformsamlauth.ApplyAlreadyApplied,
		platformsamlauth.ApplyProtocolReplay, platformsamlauth.ApplyStale,
		platformsamlauth.ApplyCollision, platformsamlauth.ApplyDenied:
		return result, nil
	default:
		return platformsamlauth.ApplyResult{}, errPlatformSAMLPersistence
	}
}

func platformSAMLApplyResultToWire(value platformsamlauth.ApplyResult) (platformSAMLApplyResultWire, error) {
	if value.TransactionID == (federatedsaml.TransactionID{}) || value.ProofDigest == ([sha256.Size]byte{}) ||
		value.UserID == (identity.EntityID{}) || value.ReturnPath == "" || !validPlatformSAMLInstant(value.AppliedAt) ||
		(value.Category != platformsamlauth.ApplySuccess && value.Category != platformsamlauth.ApplyAlreadyApplied) ||
		(value.SessionID == (identity.EntityID{})) == (value.ContinuationID == (identity.EntityID{})) {
		return platformSAMLApplyResultWire{}, errPlatformSAMLPersistence
	}
	wire := platformSAMLApplyResultWire{
		Category: string(value.Category), TransactionID: append([]byte(nil), value.TransactionID[:]...),
		ProofDigest: append([]byte(nil), value.ProofDigest[:]...), UserID: entityIDWire(value.UserID),
		ReturnPath: value.ReturnPath, AppliedAt: value.AppliedAt,
	}
	if value.SessionID != (identity.EntityID{}) {
		id := entityIDWire(value.SessionID)
		wire.SessionID = &id
	} else {
		id := entityIDWire(value.ContinuationID)
		wire.ContinuationID = &id
	}
	return wire, nil
}

func platformSAMLReplayDigest(kind, value string) [sha256.Size]byte {
	digest := sha256.New()
	platformSAMLWriteDigestField(digest, []byte("periapsis/platform-saml/replay/v1"))
	platformSAMLWriteDigestField(digest, []byte(kind))
	platformSAMLWriteDigestField(digest, []byte(value))
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func platformSAMLWriteDigestField(destination hash.Hash, value []byte) {
	length := [4]byte{}
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = destination.Write(length[:])
	_, _ = destination.Write(value)
}

func clearPlatformSAMLApplyAuthorityWire(value *platformSAMLApplyAuthorityWire) {
	if value == nil {
		return
	}
	clear(value.TransactionID)
	clearPlatformSAMLProtocolPinsWire(&value.Pins)
	clear(value.ResponseIDDigest)
	clear(value.AssertionIDDigest)
	clear(value.SessionIndexDigest)
	*value = platformSAMLApplyAuthorityWire{}
}

func clearPlatformSAMLApplyPlanWire(value *platformSAMLApplyPlanWire) {
	if value == nil {
		return
	}
	clearPlatformSAMLProtocolPinsWire(&value.Pins.Protocol)
	clearPlatformSAMLSubjectAliasesWire(value.Subject.Aliases)
	clear(value.Subject.Envelope.Nonce)
	clear(value.Subject.Envelope.Ciphertext)
	*value = platformSAMLApplyPlanWire{}
}

func clearPlatformSAMLApplyWire(value *platformSAMLApplyWire) {
	if value == nil {
		return
	}
	clearPlatformSAMLApplyAuthorityWire(&value.Authority)
	clearPlatformSAMLApplyPlanWire(&value.Plan)
	if value.Session != nil {
		clear(value.Session.TokenDigest)
		clear(value.Session.CSRFSecretDigest)
	}
	if value.Continuation != nil {
		clear(value.Continuation.ReceiptDigest)
	}
	if value.ProtectedSessionMaterial != nil {
		clear(value.ProtectedSessionMaterial.Nonce)
		clear(value.ProtectedSessionMaterial.Ciphertext)
	}
	clear(value.ProofDigest)
	*value = platformSAMLApplyWire{}
}

func clearPlatformSAMLApplyResultWire(value *platformSAMLApplyResultWire) {
	if value == nil {
		return
	}
	clear(value.TransactionID)
	clear(value.ProofDigest)
	*value = platformSAMLApplyResultWire{}
}
