package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

const applyPlatformOIDCDirectAuthenticationSQL = `select app.apply_platform_oidc_authentication_v1($1::jsonb)`

type platformOIDCDirectApplySubjectWire struct {
	ProviderID                 string  `json:"providerId"`
	UserID                     string  `json:"userId"`
	ExternalIdentityID         string  `json:"externalIdentityId"`
	ProviderRevision           uint64  `json:"providerRevision"`
	SecurityRevision           uint64  `json:"securityRevision"`
	LoginPolicyRevision        uint64  `json:"loginPolicyRevision"`
	UserAuthenticationRevision uint64  `json:"userAuthenticationRevision"`
	IdentityVersion            uint64  `json:"identityVersion"`
	AliasKeyVersion            int16   `json:"aliasKeyVersion"`
	AssurancePolicyRevision    uint64  `json:"assurancePolicyRevision"`
	PlatformFloorPolicyID      string  `json:"platformFloorPolicyId"`
	PlatformFloorRevision      uint64  `json:"platformFloorPolicyRevision"`
	TOTPCredentialID           *string `json:"totpCredentialId,omitempty"`
	TOTPSecurityRevision       *uint64 `json:"totpSecurityRevision,omitempty"`
}

type platformOIDCDirectApplyAliasWire struct {
	KeyVersion int16  `json:"keyVersion"`
	Digest     []byte `json:"digest"`
}

type platformOIDCDirectApplyEnvelopeWire struct {
	KeyVersion int16  `json:"keyVersion"`
	Format     string `json:"format"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type platformOIDCDirectApplyObservationWire struct {
	ExternalIdentityID string                              `json:"externalIdentityId"`
	Format             string                              `json:"format"`
	Envelope           platformOIDCDirectApplyEnvelopeWire `json:"envelope"`
	Aliases            []platformOIDCDirectApplyAliasWire  `json:"aliases"`
}

type platformOIDCDirectApplyAssuranceWire struct {
	Level             string    `json:"level"`
	AuthenticatedAt   time.Time `json:"authenticatedAt"`
	TrustRuleID       *string   `json:"trustRuleId,omitempty"`
	TrustRuleRevision *uint64   `json:"trustRuleRevision,omitempty"`
}

type platformOIDCDirectApplyContinuationWire struct {
	ID            string    `json:"id"`
	ReceiptDigest []byte    `json:"receiptDigest"`
	Audience      string    `json:"audience"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

type platformOIDCDirectApplyWire struct {
	TransactionID           []byte                                   `json:"transactionId"`
	ClaimAttemptID          []byte                                   `json:"claimAttemptId"`
	ExpectedVersion         uint64                                   `json:"expectedVersion"`
	OperationDigest         []byte                                   `json:"operationDigest"`
	BrowserCapabilityDigest []byte                                   `json:"browserCapabilityDigest"`
	ReturnPath              string                                   `json:"returnPath"`
	Subject                 platformOIDCDirectApplySubjectWire       `json:"subject"`
	Observation             platformOIDCDirectApplyObservationWire   `json:"observation"`
	Assurance               platformOIDCDirectApplyAssuranceWire     `json:"assurance"`
	Disposition             string                                   `json:"disposition"`
	Session                 *platformOIDCDirectSessionWire           `json:"session,omitempty"`
	Continuation            *platformOIDCDirectApplyContinuationWire `json:"continuation,omitempty"`
	ObservedAt              time.Time                                `json:"observedAt"`
	ValidUntil              time.Time                                `json:"validUntil"`
	Audit                   platformOIDCDirectAuditWire              `json:"audit"`
	MaterialID              string                                   `json:"materialId"`
	OIDCSession             *federatedOIDCSessionMaterialWire        `json:"oidcSession,omitempty"`
}

type platformOIDCDirectApplyResultWire struct {
	Applied              bool    `json:"applied"`
	Category             string  `json:"category"`
	Disposition          *string `json:"disposition,omitempty"`
	SessionID            *string `json:"sessionId,omitempty"`
	ContinuationID       *string `json:"continuationId,omitempty"`
	UserID               *string `json:"userId,omitempty"`
	ExternalIdentityID   *string `json:"externalIdentityId,omitempty"`
	TOTPCredentialID     *string `json:"totpCredentialId,omitempty"`
	TOTPSecurityRevision *uint64 `json:"totpSecurityRevision,omitempty"`
}

var _ platformoidcauth.DirectOIDCAtomicApplyPort = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) ApplyDirectOIDC(
	ctx context.Context,
	request platformoidcauth.DirectOIDCApplyRequest,
) (platformoidcauth.DirectOIDCApplyResult, error) {
	wire, err := platformOIDCDirectApplyToWire(request)
	if err != nil {
		return platformoidcauth.DirectOIDCApplyResult{}, errFederatedAuthPersistence
	}
	defer clearPlatformOIDCDirectApplyWire(&wire)
	var response platformOIDCDirectApplyResultWire
	if err = repository.queryBoundedJSON(
		ctx, applyPlatformOIDCDirectAuthenticationSQL, wire, &response,
		maximumPlatformOIDCDirectTransactionWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformoidcauth.DirectOIDCApplyResult{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectApplyResultFromWire(response, request)
}

func platformOIDCDirectApplyToWire(
	request platformoidcauth.DirectOIDCApplyRequest,
) (platformOIDCDirectApplyWire, error) {
	completion := request.Plan.Completion
	pins, pinsErr := platformOIDCDirectPinsFromTransaction(completion.Pins)
	providerID, providerErr := requiredFederatedEntityIDWire(request.Plan.Provider.ProviderID)
	userID, userErr := requiredFederatedEntityIDWire(request.Plan.UserID)
	externalID, externalErr := requiredFederatedEntityIDWire(request.Plan.ExternalIdentityID)
	floorID, floorErr := requiredFederatedEntityIDWire(pins.PlatformFloorPolicyID)
	if pinsErr != nil || providerErr != nil || userErr != nil || externalErr != nil || floorErr != nil ||
		request.Plan.Provider != pins.Provider || request.Plan.ProviderRevision != pins.ProviderRevision ||
		request.Plan.PlatformLoginRevision != pins.PlatformLoginRevision ||
		request.Plan.ConfigurationRevision != pins.ConfigurationRevision ||
		request.Plan.SecurityRevision != pins.SecurityRevision || request.Plan.PlanRevision != pins.PlanRevision ||
		request.Plan.AssurancePolicyRevision != pins.AssurancePolicyRevision ||
		completion.ExpectedVersion != 2 || completion.ID == (federatedoidc.TransactionID{}) ||
		completion.ReturnPath != request.ReturnPath || !validPlatformOIDCDirectReturnPath(request.ReturnPath) ||
		!validFederatedDatabaseTime(completion.CompletedAt) || completion.CompletedAt.After(request.AppliedAt) ||
		!validFederatedDatabaseTime(request.AppliedAt) || request.ClaimAttemptID == (federatedoidc.TransactionID{}) ||
		!validFederatedDatabaseTime(request.Plan.ValidUntil) || !request.Plan.ValidUntil.After(request.AppliedAt) ||
		!validPlatformOIDCDigest(request.BrowserCapabilityDigest[:]) || request.Observation.ExternalIdentityID != request.Plan.ExternalIdentityID ||
		!equalPlatformOIDCDirectObservation(request.Observation, request.Plan.Subject) ||
		!equalPlatformOIDCDirectAssurance(request.Assurance, request.Plan.SelectedAssurance) ||
		!validFederatedRevision(request.Plan.UserAuthenticationRevision) ||
		!validFederatedRevision(request.Plan.IdentityRevision) || request.Plan.MatchedAliasKeyVersion < 1 ||
		!platformOIDCDirectFloorMatchesPins(request.Plan.PlatformFloor, pins) ||
		!platformOIDCDirectObservationHasAliasKey(request.Observation, request.Plan.MatchedAliasKeyVersion) ||
		request.Configuration.Pins() != completion.Pins || request.MaterialID != completion.MaterialID ||
		entityIDWire(request.MaterialID) == "" || !validFederatedDatabaseTime(request.MaterialExpiresAt) ||
		request.MaterialExpiresAt.After(request.Plan.ValidUntil) {
		return platformOIDCDirectApplyWire{}, errFederatedAuthPersistence
	}
	observation, err := platformOIDCDirectObservationToWire(request.Observation)
	if err != nil {
		return platformOIDCDirectApplyWire{}, errFederatedAuthPersistence
	}
	assurance, err := platformOIDCDirectAssuranceToWire(request.Assurance, request.AppliedAt)
	if err != nil {
		clearPlatformOIDCDirectApplyObservationWire(&observation)
		return platformOIDCDirectApplyWire{}, errFederatedAuthPersistence
	}
	subject := platformOIDCDirectApplySubjectWire{
		ProviderID: providerID, UserID: userID, ExternalIdentityID: externalID,
		ProviderRevision: request.Plan.ProviderRevision, SecurityRevision: request.Plan.SecurityRevision,
		LoginPolicyRevision:        request.Plan.PlatformLoginRevision,
		UserAuthenticationRevision: request.Plan.UserAuthenticationRevision,
		IdentityVersion:            request.Plan.IdentityRevision, AliasKeyVersion: request.Plan.MatchedAliasKeyVersion,
		AssurancePolicyRevision: request.Plan.AssurancePolicyRevision,
		PlatformFloorPolicyID:   floorID, PlatformFloorRevision: pins.PlatformFloorPolicyRevision,
	}
	wire := platformOIDCDirectApplyWire{
		TransactionID:  append([]byte(nil), completion.ID[:]...),
		ClaimAttemptID: append([]byte(nil), request.ClaimAttemptID[:]...), ExpectedVersion: 2,
		BrowserCapabilityDigest: append([]byte(nil), request.BrowserCapabilityDigest[:]...),
		ReturnPath:              request.ReturnPath, Subject: subject, Observation: observation, Assurance: assurance,
		ObservedAt: request.AppliedAt, ValidUntil: request.Plan.ValidUntil,
		MaterialID: entityIDWire(request.MaterialID),
	}
	switch request.Plan.Disposition {
	case platformoidcauth.DirectAuthenticationImmediateSession:
		if request.ContinuationAuthority != federatedauth.ContinuationAuthorityTenant ||
			!request.Continuation.IsZero() || request.Plan.TOTP != nil {
			clearPlatformOIDCDirectApplyWire(&wire)
			return platformOIDCDirectApplyWire{}, errFederatedAuthPersistence
		}
		session, sessionErr := platformOIDCDirectSessionToWire(
			request.Session, request.AppliedAt.Truncate(time.Millisecond),
		)
		if sessionErr != nil {
			clearPlatformOIDCDirectApplyWire(&wire)
			return platformOIDCDirectApplyWire{}, errFederatedAuthPersistence
		}
		wire.Disposition = "session"
		wire.Session = &session
	case platformoidcauth.DirectAuthenticationTOTPContinuation:
		if request.ContinuationAuthority != federatedauth.ContinuationAuthorityDirectPlatformOIDC ||
			!request.Session.IsZero() || request.Plan.TOTP == nil ||
			!request.Continuation.ValidAt(request.AppliedAt) ||
			request.Continuation.Authority() != federatedauth.ContinuationAuthorityDirectPlatformOIDC {
			clearPlatformOIDCDirectApplyWire(&wire)
			return platformOIDCDirectApplyWire{}, errFederatedAuthPersistence
		}
		factorID, factorErr := requiredFederatedEntityIDWire(request.Plan.TOTP.FactorID)
		continuationID, continuationErr := requiredFederatedEntityIDWire(request.Continuation.ContinuationID())
		receiptDigest := request.Continuation.ReceiptDigest()
		if factorErr != nil || continuationErr != nil || !validFederatedRevision(request.Plan.TOTP.Revision) ||
			!validPlatformOIDCDigest(receiptDigest[:]) {
			clearPlatformOIDCDirectApplyWire(&wire)
			return platformOIDCDirectApplyWire{}, errFederatedAuthPersistence
		}
		revision := request.Plan.TOTP.Revision
		wire.Subject.TOTPCredentialID = &factorID
		wire.Subject.TOTPSecurityRevision = &revision
		wire.Disposition = "continuation"
		wire.Continuation = &platformOIDCDirectApplyContinuationWire{
			ID: continuationID, ReceiptDigest: append([]byte(nil), receiptDigest[:]...),
			Audience: "api", ExpiresAt: request.Continuation.ExpiresAt(),
		}
	default:
		clearPlatformOIDCDirectApplyWire(&wire)
		return platformOIDCDirectApplyWire{}, errFederatedAuthPersistence
	}
	ownerExpiresAt := request.Session.AbsoluteExpiresAt()
	if request.Plan.Disposition == platformoidcauth.DirectAuthenticationTOTPContinuation {
		ownerExpiresAt = request.Continuation.ExpiresAt()
	}
	if ownerExpiresAt.IsZero() || request.MaterialExpiresAt.After(ownerExpiresAt) {
		clearPlatformOIDCDirectApplyWire(&wire)
		return platformOIDCDirectApplyWire{}, errFederatedAuthPersistence
	}
	wantMaterial := request.Configuration.Discovery.Endpoints().EndSession != "" ||
		request.Configuration.AllowRefreshToken
	if wantMaterial != (request.SessionMaterial != nil) {
		clearPlatformOIDCDirectApplyWire(&wire)
		return platformOIDCDirectApplyWire{}, errFederatedAuthPersistence
	}
	if request.SessionMaterial != nil {
		wire.OIDCSession, err = federatedOIDCSessionMaterialValuesToWire(
			request.Configuration, request.MaterialID, request.SessionMaterial, request.MaterialExpiresAt,
		)
		if err != nil {
			clearPlatformOIDCDirectApplyWire(&wire)
			return platformOIDCDirectApplyWire{}, errFederatedAuthPersistence
		}
	}
	eventID, err := platformOIDCDirectStableAuditEventID(
		request.Audit, "authentication.apply", completion.ID[:], request.ClaimAttemptID[:],
		request.BrowserCapabilityDigest[:],
	)
	if err != nil {
		clearPlatformOIDCDirectApplyWire(&wire)
		return platformOIDCDirectApplyWire{}, errFederatedAuthPersistence
	}
	wire.Audit, err = platformOIDCDirectAuditToWire(request.Audit, eventID)
	if err != nil {
		clearPlatformOIDCDirectApplyWire(&wire)
		return platformOIDCDirectApplyWire{}, errFederatedAuthPersistence
	}
	semantic := wire
	semantic.OperationDigest = nil
	if wire.OIDCSession != nil {
		semanticMaterial := *wire.OIDCSession
		if semanticMaterial.IDToken != nil {
			semanticMaterial.IDToken = &federatedProtectedOIDCTokenWire{
				Digest: append([]byte(nil), semanticMaterial.IDToken.Digest...),
			}
		}
		if semanticMaterial.RefreshToken != nil {
			semanticMaterial.RefreshToken = &federatedProtectedOIDCRefreshWire{
				Digest:          append([]byte(nil), semanticMaterial.RefreshToken.Digest...),
				Generation:      semanticMaterial.RefreshToken.Generation,
				AccessExpiresAt: semanticMaterial.RefreshToken.AccessExpiresAt,
			}
		}
		semantic.OIDCSession = &semanticMaterial
	}
	document, err := json.Marshal(semantic)
	if semantic.OIDCSession != nil && semantic.OIDCSession.IDToken != nil {
		clear(semantic.OIDCSession.IDToken.Digest)
	}
	if semantic.OIDCSession != nil && semantic.OIDCSession.RefreshToken != nil {
		clear(semantic.OIDCSession.RefreshToken.Digest)
	}
	if err != nil || len(document) == 0 || len(document) > maximumPlatformOIDCDirectTransactionWireBytes {
		clear(document)
		clearPlatformOIDCDirectApplyWire(&wire)
		return platformOIDCDirectApplyWire{}, errFederatedAuthPersistence
	}
	digest := sha256.Sum256(document)
	clear(document)
	wire.OperationDigest = append([]byte(nil), digest[:]...)
	return wire, nil
}

func platformOIDCDirectObservationToWire(
	value platformoidcauth.DirectSubjectObservation,
) (platformOIDCDirectApplyObservationWire, error) {
	externalID, err := requiredFederatedEntityIDWire(value.ExternalIdentityID)
	if err != nil || value.SubjectFormat != identity.UTF8ExactSubject ||
		value.Envelope.Format != identity.UTF8ExactSubject || value.Envelope.KeyVersion < 1 ||
		len(value.Envelope.Ciphertext) < 17 || len(value.Envelope.Ciphertext) > 4112 ||
		len(value.Aliases) < 1 || len(value.Aliases) > 16 {
		return platformOIDCDirectApplyObservationWire{}, errFederatedAuthPersistence
	}
	aliases := make([]platformOIDCDirectApplyAliasWire, len(value.Aliases))
	foundEnvelopeKey := false
	for index, alias := range value.Aliases {
		if alias.KeyVersion < 1 || !validPlatformOIDCDigest(alias.Digest[:]) ||
			index > 0 && value.Aliases[index-1].KeyVersion >= alias.KeyVersion {
			clearPlatformOIDCDirectApplyAliasesWire(aliases)
			return platformOIDCDirectApplyObservationWire{}, errFederatedAuthPersistence
		}
		foundEnvelopeKey = foundEnvelopeKey || alias.KeyVersion == value.Envelope.KeyVersion
		aliases[index] = platformOIDCDirectApplyAliasWire{
			KeyVersion: alias.KeyVersion, Digest: append([]byte(nil), alias.Digest[:]...),
		}
	}
	if !foundEnvelopeKey || len(value.Envelope.Nonce) != 12 || allZeroFederatedBytes(value.Envelope.Nonce[:]) {
		clearPlatformOIDCDirectApplyAliasesWire(aliases)
		return platformOIDCDirectApplyObservationWire{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectApplyObservationWire{
		ExternalIdentityID: externalID, Format: "utf8_exact",
		Envelope: platformOIDCDirectApplyEnvelopeWire{
			KeyVersion: value.Envelope.KeyVersion, Format: "utf8_exact",
			Nonce:      append([]byte(nil), value.Envelope.Nonce[:]...),
			Ciphertext: append([]byte(nil), value.Envelope.Ciphertext...),
		},
		Aliases: aliases,
	}, nil
}

func platformOIDCDirectAssuranceToWire(
	value platformoidcauth.DirectSelectedAssurance,
	observedAt time.Time,
) (platformOIDCDirectApplyAssuranceWire, error) {
	if !validFederatedDatabaseTime(value.AuthenticatedAt) || value.AuthenticatedAt.After(observedAt) ||
		observedAt.Sub(value.AuthenticatedAt) > 30*24*time.Hour {
		return platformOIDCDirectApplyAssuranceWire{}, errFederatedAuthPersistence
	}
	wire := platformOIDCDirectApplyAssuranceWire{AuthenticatedAt: value.AuthenticatedAt}
	switch value.Level {
	case identity.AssurancePrimary:
		if value.TrustRuleID != nil || value.TrustRuleRevision != nil {
			return platformOIDCDirectApplyAssuranceWire{}, errFederatedAuthPersistence
		}
		wire.Level = "primary"
	case identity.AssuranceMFA, identity.AssurancePhishingResistant:
		if value.TrustRuleID == nil || value.TrustRuleRevision == nil ||
			!validFederatedRevision(*value.TrustRuleRevision) {
			return platformOIDCDirectApplyAssuranceWire{}, errFederatedAuthPersistence
		}
		ruleID, err := requiredFederatedEntityIDWire(*value.TrustRuleID)
		if err != nil {
			return platformOIDCDirectApplyAssuranceWire{}, errFederatedAuthPersistence
		}
		wire.TrustRuleID = &ruleID
		revision := *value.TrustRuleRevision
		wire.TrustRuleRevision = &revision
		if value.Level == identity.AssuranceMFA {
			wire.Level = "mfa"
		} else {
			wire.Level = "phishing_resistant"
		}
	default:
		return platformOIDCDirectApplyAssuranceWire{}, errFederatedAuthPersistence
	}
	return wire, nil
}

func platformOIDCDirectApplyResultFromWire(
	wire platformOIDCDirectApplyResultWire,
	request platformoidcauth.DirectOIDCApplyRequest,
) (platformoidcauth.DirectOIDCApplyResult, error) {
	if !wire.Applied {
		if (wire.Category != "stale" && wire.Category != "identity_collision" && wire.Category != "denied") ||
			wire.Disposition != nil || wire.SessionID != nil || wire.ContinuationID != nil ||
			wire.UserID != nil || wire.ExternalIdentityID != nil || wire.TOTPCredentialID != nil ||
			wire.TOTPSecurityRevision != nil {
			return platformoidcauth.DirectOIDCApplyResult{}, errFederatedAuthPersistence
		}
		return platformoidcauth.DirectOIDCApplyResult{}, errFederatedAuthPersistence
	}
	if wire.Category != "success" || wire.Disposition == nil || wire.UserID == nil ||
		wire.ExternalIdentityID == nil || *wire.UserID != entityIDWire(request.Plan.UserID) ||
		*wire.ExternalIdentityID != entityIDWire(request.Plan.ExternalIdentityID) {
		return platformoidcauth.DirectOIDCApplyResult{}, errFederatedAuthPersistence
	}
	result := platformoidcauth.DirectOIDCApplyResult{
		Disposition: request.Plan.Disposition, TransactionID: request.Plan.Completion.ID,
		BrowserCapabilityDigest: request.BrowserCapabilityDigest, UserID: request.Plan.UserID,
		ReturnPath: request.ReturnPath, AppliedAt: request.AppliedAt,
	}
	switch request.Plan.Disposition {
	case platformoidcauth.DirectAuthenticationImmediateSession:
		if *wire.Disposition != "session" || wire.SessionID == nil || wire.ContinuationID != nil ||
			wire.TOTPCredentialID != nil || wire.TOTPSecurityRevision != nil ||
			*wire.SessionID != entityIDWire(request.Session.SessionID()) {
			return platformoidcauth.DirectOIDCApplyResult{}, errFederatedAuthPersistence
		}
		result.SessionID = request.Session.SessionID()
	case platformoidcauth.DirectAuthenticationTOTPContinuation:
		if *wire.Disposition != "continuation" || wire.ContinuationID == nil || wire.SessionID != nil ||
			wire.TOTPCredentialID == nil || wire.TOTPSecurityRevision == nil || request.Plan.TOTP == nil ||
			*wire.ContinuationID != entityIDWire(request.Continuation.ContinuationID()) ||
			*wire.TOTPCredentialID != entityIDWire(request.Plan.TOTP.FactorID) ||
			*wire.TOTPSecurityRevision != request.Plan.TOTP.Revision {
			return platformoidcauth.DirectOIDCApplyResult{}, errFederatedAuthPersistence
		}
		result.ContinuationID = request.Continuation.ContinuationID()
	default:
		return platformoidcauth.DirectOIDCApplyResult{}, errFederatedAuthPersistence
	}
	return result, nil
}

func equalPlatformOIDCDirectObservation(left, right platformoidcauth.DirectSubjectObservation) bool {
	return left.ExternalIdentityID == right.ExternalIdentityID && left.SubjectFormat == right.SubjectFormat &&
		left.Envelope.KeyVersion == right.Envelope.KeyVersion && left.Envelope.Format == right.Envelope.Format &&
		left.Envelope.Nonce == right.Envelope.Nonce && slices.Equal(left.Envelope.Ciphertext, right.Envelope.Ciphertext) &&
		slices.Equal(left.Aliases, right.Aliases)
}

func equalPlatformOIDCDirectAssurance(left, right platformoidcauth.DirectSelectedAssurance) bool {
	if left.Level != right.Level || !left.AuthenticatedAt.Equal(right.AuthenticatedAt) ||
		(left.TrustRuleID == nil) != (right.TrustRuleID == nil) ||
		(left.TrustRuleRevision == nil) != (right.TrustRuleRevision == nil) {
		return false
	}
	return (left.TrustRuleID == nil || *left.TrustRuleID == *right.TrustRuleID) &&
		(left.TrustRuleRevision == nil || *left.TrustRuleRevision == *right.TrustRuleRevision)
}

func platformOIDCDirectFloorMatchesPins(
	requirement identity.EffectiveAssuranceRequirement,
	pins platformoidcauth.DirectOIDCConfigurationPins,
) bool {
	return len(requirement.PolicyRevisions) == 1 &&
		requirement.PolicyRevisions[0].PolicyID == pins.PlatformFloorPolicyID &&
		requirement.PolicyRevisions[0].Revision > 0 &&
		uint64(requirement.PolicyRevisions[0].Revision) == pins.PlatformFloorPolicyRevision
}

func platformOIDCDirectObservationHasAliasKey(
	observation platformoidcauth.DirectSubjectObservation,
	keyVersion int16,
) bool {
	return slices.ContainsFunc(observation.Aliases, func(alias identity.SubjectAlias) bool {
		return alias.KeyVersion == keyVersion
	})
}

func clearPlatformOIDCDirectApplyAliasesWire(values []platformOIDCDirectApplyAliasWire) {
	for index := range values {
		clear(values[index].Digest)
	}
}

func clearPlatformOIDCDirectApplyObservationWire(value *platformOIDCDirectApplyObservationWire) {
	if value == nil {
		return
	}
	clear(value.Envelope.Nonce)
	clear(value.Envelope.Ciphertext)
	clearPlatformOIDCDirectApplyAliasesWire(value.Aliases)
	*value = platformOIDCDirectApplyObservationWire{}
}

func clearPlatformOIDCDirectApplyWire(value *platformOIDCDirectApplyWire) {
	if value == nil {
		return
	}
	clear(value.TransactionID)
	clear(value.ClaimAttemptID)
	clear(value.OperationDigest)
	clear(value.BrowserCapabilityDigest)
	clearPlatformOIDCDirectApplyObservationWire(&value.Observation)
	if value.Session != nil {
		clearPlatformOIDCDirectSessionWire(value.Session)
	}
	if value.Continuation != nil {
		clear(value.Continuation.ReceiptDigest)
	}
	clearFederatedOIDCSessionMaterialWire(value.OIDCSession)
	*value = platformOIDCDirectApplyWire{}
}
