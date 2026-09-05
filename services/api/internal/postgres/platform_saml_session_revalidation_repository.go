package postgres

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"slices"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

const (
	loadPlatformSAMLSessionRevalidationSQL          = `select app.load_platform_saml_session_revalidation_v1($1::jsonb)`
	applyPlatformSAMLSessionRevalidationSQL         = `select app.apply_platform_saml_session_revalidation_v1($1::jsonb)`
	recoverPlatformSAMLSessionRevalidationSQL       = `select app.recover_platform_saml_session_revalidation_apply_v1($1::jsonb)`
	cleanupPlatformSAMLSessionRevalidationSQL       = `select app.cleanup_platform_saml_session_revalidation_delivery_v1($1::jsonb)`
	maximumPlatformSAMLSessionRevalidationWireBytes = 512 * 1024
)

type platformSAMLSessionRevalidationLookupWire struct {
	SessionID  string    `json:"sessionId"`
	ObservedAt time.Time `json:"observedAt"`
}

type platformSAMLSessionStateWire struct {
	SessionID                  string    `json:"sessionId"`
	RotationFamilyID           string    `json:"rotationFamilyId"`
	UserID                     string    `json:"userId"`
	ActiveTenantID             *string   `json:"activeTenantId"`
	Authority                  string    `json:"authority"`
	AuthenticationMethod       string    `json:"authenticationMethod"`
	Audience                   string    `json:"audience"`
	PrimaryKind                string    `json:"primaryKind"`
	SAMLStateCount             int       `json:"samlStateCount"`
	SAMLProvenanceCount        int       `json:"samlProvenanceCount"`
	OIDCStateCount             int       `json:"oidcStateCount"`
	TenantProvenanceCount      int       `json:"tenantProvenanceCount"`
	ProviderEvidenceCount      int       `json:"providerEvidenceCount"`
	TOTPEvidenceCount          int       `json:"totpEvidenceCount"`
	CurrentVersion             uint64    `json:"currentVersion"`
	UserAuthenticationRevision uint64    `json:"userAuthenticationRevision"`
	RecoveryRestricted         bool      `json:"recoveryRestricted"`
	IssuedAt                   time.Time `json:"issuedAt"`
	IdleExpiresAt              time.Time `json:"idleExpiresAt"`
	AbsoluteExpiresAt          time.Time `json:"absoluteExpiresAt"`
	Active                     bool      `json:"active"`
	RotationFamilyLive         bool      `json:"rotationFamilyLive"`
}

type platformSAMLSessionRequirementWire struct {
	Level                string                           `json:"level"`
	LocalRequired        bool                             `json:"localRequired"`
	FreshnessNanoseconds int64                            `json:"freshnessNanoseconds"`
	EnrollmentDeadline   *time.Time                       `json:"enrollmentDeadline"`
	PolicyRevisions      []platformSAMLPolicyRevisionWire `json:"policyRevisions"`
}

type platformSAMLSessionAuthorityWire struct {
	ProviderID         string `json:"providerId"`
	ExternalIdentityID string `json:"externalIdentityId"`
	ProviderKind       string `json:"providerKind"`
	AccountMode        string `json:"accountMode"`

	PinnedProviderRevision            uint64 `json:"pinnedProviderRevision"`
	CurrentProviderRevision           uint64 `json:"currentProviderRevision"`
	PinnedLoginPolicyRevision         uint64 `json:"pinnedLoginPolicyRevision"`
	CurrentLoginPolicyRevision        uint64 `json:"currentLoginPolicyRevision"`
	PinnedConfigurationRevision       uint64 `json:"pinnedConfigurationRevision"`
	CurrentConfigurationRevision      uint64 `json:"currentConfigurationRevision"`
	PinnedSecurityRevision            uint64 `json:"pinnedSecurityRevision"`
	CurrentSecurityRevision           uint64 `json:"currentSecurityRevision"`
	PinnedPlanRevision                uint64 `json:"pinnedPlanRevision"`
	CurrentPlanRevision               uint64 `json:"currentPlanRevision"`
	PinnedAssurancePolicyRevision     uint64 `json:"pinnedAssurancePolicyRevision"`
	CurrentAssurancePolicyRevision    uint64 `json:"currentAssurancePolicyRevision"`
	PinnedMetadataRevision            uint64 `json:"pinnedMetadataRevision"`
	CurrentMetadataRevision           uint64 `json:"currentMetadataRevision"`
	PinnedSPKeyRevision               uint64 `json:"pinnedSpKeyRevision"`
	CurrentSPKeyRevision              uint64 `json:"currentSpKeyRevision"`
	PinnedUserAuthenticationRevision  uint64 `json:"pinnedUserAuthenticationRevision"`
	CurrentUserAuthenticationRevision uint64 `json:"currentUserAuthenticationRevision"`
	PinnedIdentityRevision            uint64 `json:"pinnedIdentityRevision"`
	CurrentIdentityRevision           uint64 `json:"currentIdentityRevision"`
	PinnedAliasKeyVersion             int16  `json:"pinnedAliasKeyVersion"`
	CurrentAliasKeyVersion            int16  `json:"currentAliasKeyVersion"`

	PinnedMetadataDigest       []byte `json:"pinnedMetadataDigest"`
	CurrentMetadataDigest      []byte `json:"currentMetadataDigest"`
	PinnedConfigurationDigest  []byte `json:"pinnedConfigurationDigest"`
	CurrentConfigurationDigest []byte `json:"currentConfigurationDigest"`

	IdentityCurrentProviderID string `json:"identityCurrentProviderId"`
	IdentityCurrentUserID     string `json:"identityCurrentUserId"`
	AliasCurrentProviderID    string `json:"aliasCurrentProviderId"`
	AliasCurrentIdentityID    string `json:"aliasCurrentIdentityId"`

	PinnedPlatformAuthorityID        string `json:"pinnedPlatformAuthorityId"`
	CurrentPlatformAuthorityID       string `json:"currentPlatformAuthorityId"`
	PinnedPlatformAuthorityRevision  uint64 `json:"pinnedPlatformAuthorityRevision"`
	CurrentPlatformAuthorityRevision uint64 `json:"currentPlatformAuthorityRevision"`
	PinnedPlatformFloorID            string `json:"pinnedPlatformFloorId"`
	CurrentPlatformFloorID           string `json:"currentPlatformFloorId"`
	PinnedPlatformFloorRevision      uint64 `json:"pinnedPlatformFloorRevision"`
	CurrentPlatformFloorRevision     uint64 `json:"currentPlatformFloorRevision"`

	ProviderEnabled       bool `json:"providerEnabled"`
	PlatformLoginLive     bool `json:"platformLoginLive"`
	UserActive            bool `json:"userActive"`
	IdentityLive          bool `json:"identityLive"`
	SubjectAliasLive      bool `json:"subjectAliasLive"`
	FactorEvidenceLive    bool `json:"factorEvidenceLive"`
	EvidenceFresh         bool `json:"evidenceFresh"`
	PolicyPinsExact       bool `json:"policyPinsExact"`
	TrustEvidenceLive     bool `json:"trustEvidenceLive"`
	ConfigurationLive     bool `json:"configurationLive"`
	MetadataLive          bool `json:"metadataLive"`
	SPKeyLive             bool `json:"spKeyLive"`
	PlatformAuthorityLive bool `json:"platformAuthorityLive"`
	PlatformFloorLive     bool `json:"platformFloorLive"`

	PlatformFloor platformSAMLSessionRequirementWire `json:"platformFloor"`
	StepUpTOTP    *platformSAMLTOTPSelectionWire     `json:"stepUpTotp"`
}

type platformSAMLSessionEvidenceWire struct {
	ID                 string     `json:"id"`
	UserID             string     `json:"userId"`
	Kind               string     `json:"kind"`
	Level              string     `json:"level"`
	PlatformProviderID *string    `json:"platformProviderId,omitempty"`
	ExternalIdentityID *string    `json:"externalIdentityId,omitempty"`
	TOTPCredentialID   *string    `json:"totpCredentialId,omitempty"`
	FactorRevision     *uint64    `json:"factorRevision,omitempty"`
	TrustRuleID        *string    `json:"trustRuleId,omitempty"`
	TrustRuleRevision  *uint64    `json:"trustRuleRevision,omitempty"`
	AuthenticatedAt    time.Time  `json:"authenticatedAt"`
	ExpiresAt          *time.Time `json:"expiresAt,omitempty"`
}

type platformSAMLSessionFactorAuthorityWire struct {
	EvidenceID              string     `json:"evidenceId"`
	EvidenceUserID          string     `json:"evidenceUserId"`
	TOTPCredentialID        string     `json:"totpCredentialId"`
	PinnedSecurityRevision  uint64     `json:"pinnedSecurityRevision"`
	CurrentUserID           string     `json:"currentUserId"`
	CurrentSecurityRevision uint64     `json:"currentSecurityRevision"`
	ConfirmedAt             *time.Time `json:"confirmedAt"`
	DisabledAt              *time.Time `json:"disabledAt"`
}

type platformSAMLSessionTrustAuthorityWire struct {
	EvidenceID          string     `json:"evidenceId"`
	TrustRuleID         string     `json:"trustRuleId"`
	PinnedRevision      uint64     `json:"pinnedRevision"`
	CurrentProviderID   string     `json:"currentProviderId"`
	CurrentProviderKind string     `json:"currentProviderKind"`
	CurrentRevision     uint64     `json:"currentRevision"`
	CurrentLevel        string     `json:"currentLevel"`
	Enabled             bool       `json:"enabled"`
	RetiredAt           *time.Time `json:"retiredAt"`
}

type platformSAMLSessionPolicyPinWire struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Revision uint64 `json:"revision"`
}

type platformSAMLSessionRevalidationSnapshotWire struct {
	Session           platformSAMLSessionStateWire             `json:"session"`
	Authority         platformSAMLSessionAuthorityWire         `json:"authority"`
	Evidence          []platformSAMLSessionEvidenceWire        `json:"evidence"`
	FactorAuthorities []platformSAMLSessionFactorAuthorityWire `json:"factorAuthorities"`
	TrustAuthorities  []platformSAMLSessionTrustAuthorityWire  `json:"trustAuthorities"`
	PolicyPins        []platformSAMLSessionPolicyPinWire       `json:"policyPins"`
}

type platformSAMLSessionRevalidationCommandWire struct {
	SessionID       string                                   `json:"sessionId"`
	ExpectedVersion uint64                                   `json:"expectedVersion"`
	RequestDigest   []byte                                   `json:"requestDigest"`
	Decision        string                                   `json:"decision"`
	Reason          string                                   `json:"reason"`
	ObservedAt      time.Time                                `json:"observedAt"`
	Session         *platformSAMLSessionReservationWire      `json:"session,omitempty"`
	Continuation    *platformSAMLContinuationReservationWire `json:"continuation,omitempty"`
	Audit           platformSAMLAuditWire                    `json:"audit"`
}

type platformSAMLSessionRevalidationResultWire struct {
	Applied         bool       `json:"applied"`
	Category        string     `json:"category"`
	Decision        string     `json:"decision"`
	SessionID       string     `json:"sessionId"`
	UserID          string     `json:"userId"`
	ExpectedVersion uint64     `json:"expectedVersion"`
	NewVersion      uint64     `json:"newVersion"`
	NewSessionID    *string    `json:"newSessionId,omitempty"`
	ContinuationID  *string    `json:"continuationId,omitempty"`
	AppliedAt       *time.Time `json:"appliedAt,omitempty"`
}

type platformSAMLSessionRevalidationRecoveryWire struct {
	Command platformSAMLSessionRevalidationCommandWire `json:"command"`
}

type platformSAMLSessionRevalidationRecoveryResultWire struct {
	Matched bool                                       `json:"matched"`
	Result  *platformSAMLSessionRevalidationResultWire `json:"result,omitempty"`
}

type platformSAMLSessionRevalidationCleanupWire struct {
	Command     platformSAMLSessionRevalidationCommandWire `json:"command"`
	Result      platformSAMLSessionRevalidationResultWire  `json:"result"`
	Reason      string                                     `json:"reason"`
	CleanedUpAt time.Time                                  `json:"cleanedUpAt"`
	Audit       platformSAMLAuditWire                      `json:"audit"`
}

var _ platformsamlauth.DirectSAMLSessionRevalidationStore = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) LoadDirectSAMLSessionForRevalidation(
	ctx context.Context,
	lookup platformsamlauth.DirectSAMLSessionRevalidationLookup,
) (platformsamlauth.DirectSAMLSessionRevalidationSnapshot, error) {
	wire := platformSAMLSessionRevalidationLookupWire{
		SessionID: entityIDWire(lookup.SessionID), ObservedAt: lookup.ObservedAt,
	}
	if wire.SessionID == "" || !validPlatformSAMLInstant(lookup.ObservedAt) {
		return platformsamlauth.DirectSAMLSessionRevalidationSnapshot{}, errPlatformSAMLPersistence
	}
	var response platformSAMLSessionRevalidationSnapshotWire
	if err := repository.queryJSONWithResponseLimit(
		ctx, loadPlatformSAMLSessionRevalidationSQL, wire, &response,
		maximumPlatformSAMLSessionRevalidationWireBytes,
	); err != nil {
		return platformsamlauth.DirectSAMLSessionRevalidationSnapshot{}, err
	}
	return platformSAMLSessionRevalidationSnapshotFromWire(response)
}

func (repository *FederatedAuthRepository) ApplyDirectSAMLSessionRevalidation(
	ctx context.Context,
	command platformsamlauth.DirectSAMLSessionRevalidationCommand,
) (platformsamlauth.DirectSAMLSessionRevalidationResult, error) {
	wire, err := platformSAMLSessionRevalidationCommandToWire(command)
	if err != nil {
		return platformsamlauth.DirectSAMLSessionRevalidationResult{}, err
	}
	defer clearPlatformSAMLSessionRevalidationCommandWire(&wire)
	var response platformSAMLSessionRevalidationResultWire
	if err = repository.queryJSONWithResponseLimit(
		ctx, applyPlatformSAMLSessionRevalidationSQL, wire, &response,
		maximumPlatformSAMLSessionRevalidationWireBytes,
	); err != nil {
		return platformsamlauth.DirectSAMLSessionRevalidationResult{}, err
	}
	return platformSAMLSessionRevalidationResultFromWire(response, command, false)
}

func (repository *FederatedAuthRepository) RecoverDirectSAMLSessionRevalidationApply(
	ctx context.Context,
	lookup platformsamlauth.DirectSAMLSessionRevalidationRecoveryLookup,
) (platformsamlauth.DirectSAMLSessionRevalidationRecoveryResult, error) {
	wire, err := platformSAMLSessionRevalidationCommandToWire(lookup.Command)
	if err != nil {
		return platformsamlauth.DirectSAMLSessionRevalidationRecoveryResult{}, err
	}
	defer clearPlatformSAMLSessionRevalidationCommandWire(&wire)
	request := platformSAMLSessionRevalidationRecoveryWire{Command: wire}
	var response platformSAMLSessionRevalidationRecoveryResultWire
	if err = repository.queryJSONWithResponseLimit(
		ctx, recoverPlatformSAMLSessionRevalidationSQL, request, &response,
		maximumPlatformSAMLSessionRevalidationWireBytes,
	); err != nil {
		return platformsamlauth.DirectSAMLSessionRevalidationRecoveryResult{}, err
	}
	if !response.Matched {
		if response.Result != nil {
			return platformsamlauth.DirectSAMLSessionRevalidationRecoveryResult{}, errPlatformSAMLPersistence
		}
		return platformsamlauth.DirectSAMLSessionRevalidationRecoveryResult{Matched: false}, nil
	}
	if response.Result == nil {
		return platformsamlauth.DirectSAMLSessionRevalidationRecoveryResult{}, errPlatformSAMLPersistence
	}
	result, err := platformSAMLSessionRevalidationResultFromWire(*response.Result, lookup.Command, true)
	if err != nil || result.Category != platformsamlauth.DirectSAMLSessionRevalidationAlreadyApplied {
		return platformsamlauth.DirectSAMLSessionRevalidationRecoveryResult{}, errPlatformSAMLPersistence
	}
	return platformsamlauth.DirectSAMLSessionRevalidationRecoveryResult{Matched: true, Result: result}, nil
}

func (repository *FederatedAuthRepository) CleanupDirectSAMLSessionRevalidationDelivery(
	ctx context.Context,
	cleanup platformsamlauth.DirectSAMLSessionRevalidationCleanup,
) error {
	command, err := platformSAMLSessionRevalidationCommandToWire(cleanup.Command)
	if err != nil {
		return err
	}
	defer clearPlatformSAMLSessionRevalidationCommandWire(&command)
	result, err := platformSAMLSessionRevalidationResultToWire(cleanup.Result, cleanup.Command)
	audit, auditErr := platformSAMLAuditToWire(cleanup.Audit)
	if err != nil || auditErr != nil || cleanup.Reason != platformsamlauth.CleanupDeliveryFailed ||
		!validPlatformSAMLInstant(cleanup.CleanedUpAt) || cleanup.CleanedUpAt.Before(cleanup.Command.ObservedAt) {
		return errPlatformSAMLPersistence
	}
	request := platformSAMLSessionRevalidationCleanupWire{
		Command: command, Result: result, Reason: string(cleanup.Reason),
		CleanedUpAt: cleanup.CleanedUpAt, Audit: audit,
	}
	var cleaned bool
	if err = repository.queryJSONWithResponseLimit(
		ctx, cleanupPlatformSAMLSessionRevalidationSQL, request, &cleaned,
		maximumPlatformSAMLSessionRevalidationWireBytes,
	); err != nil || !cleaned {
		return errPlatformSAMLPersistence
	}
	return nil
}

func platformSAMLSessionRevalidationCommandToWire(
	command platformsamlauth.DirectSAMLSessionRevalidationCommand,
) (platformSAMLSessionRevalidationCommandWire, error) {
	audit, err := platformSAMLAuditToWire(command.Audit)
	wire := platformSAMLSessionRevalidationCommandWire{
		SessionID: entityIDWire(command.SessionID), ExpectedVersion: command.ExpectedVersion,
		RequestDigest: append([]byte(nil), command.RequestDigest[:]...),
		Decision:      string(command.Decision), Reason: string(command.Reason),
		ObservedAt: command.ObservedAt, Audit: audit,
	}
	if err != nil || wire.SessionID == "" || !validPlatformSAMLRevision(command.ExpectedVersion) ||
		!validPlatformSAMLInstant(command.ObservedAt) || command.RequestDigest == ([sha256.Size]byte{}) ||
		!validPlatformSAMLSessionDecision(command.Decision, command.Reason) {
		clearPlatformSAMLSessionRevalidationCommandWire(&wire)
		return platformSAMLSessionRevalidationCommandWire{}, errPlatformSAMLPersistence
	}
	switch command.Decision {
	case mfa.SessionRotate:
		reservation, reservationErr := platformSAMLSessionReservationToWire(command.Session, command.ObservedAt)
		if reservationErr != nil || !command.Continuation.IsZero() {
			clearPlatformSAMLSessionRevalidationCommandWire(&wire)
			return platformSAMLSessionRevalidationCommandWire{}, errPlatformSAMLPersistence
		}
		wire.Session = &reservation
	case mfa.SessionStepUp:
		if !command.Session.IsZero() || !command.Continuation.ValidAt(command.ObservedAt) {
			clearPlatformSAMLSessionRevalidationCommandWire(&wire)
			return platformSAMLSessionRevalidationCommandWire{}, errPlatformSAMLPersistence
		}
		receipt := command.Continuation.ReceiptDigest()
		wire.Continuation = &platformSAMLContinuationReservationWire{
			ID:             entityIDWire(command.Continuation.ContinuationID()),
			FactorID:       entityIDWire(command.Continuation.FactorID()),
			FactorRevision: command.Continuation.FactorRevision(),
			ReceiptDigest:  append([]byte(nil), receipt[:]...),
			ExpiresAt:      command.Continuation.ExpiresAt(),
		}
	default:
		if !command.Session.IsZero() || !command.Continuation.IsZero() {
			clearPlatformSAMLSessionRevalidationCommandWire(&wire)
			return platformSAMLSessionRevalidationCommandWire{}, errPlatformSAMLPersistence
		}
	}
	digest := platformSAMLSessionRevalidationDigest(wire)
	if !slices.Equal(digest[:], wire.RequestDigest) {
		clearPlatformSAMLSessionRevalidationCommandWire(&wire)
		return platformSAMLSessionRevalidationCommandWire{}, errPlatformSAMLPersistence
	}
	return wire, nil
}

func platformSAMLSessionRevalidationDigest(wire platformSAMLSessionRevalidationCommandWire) [sha256.Size]byte {
	digest := sha256.New()
	platformSAMLWriteField(digest, []byte(platformsamlauth.DirectSAMLSessionRequestDigestV1))
	platformSAMLWriteField(digest, []byte(platformsamlauth.DirectSAMLSessionAuthority))
	platformSAMLWriteField(digest, []byte(platformsamlauth.DirectSAMLSessionMethod))
	platformSAMLWriteField(digest, []byte(platformsamlauth.DirectSAMLSessionAudience))
	sessionID, _ := parseEntityIDWire(wire.SessionID, false)
	platformSAMLWriteField(digest, sessionID[:])
	platformSAMLWriteField(digest, platformSAMLU64(wire.ExpectedVersion))
	platformSAMLWriteField(digest, []byte(wire.Decision))
	platformSAMLWriteField(digest, []byte(wire.Reason))
	platformSAMLWriteField(digest, platformSAMLU64(uint64(wire.ObservedAt.UnixMicro())))
	if wire.Session != nil {
		platformSAMLWriteField(digest, []byte{1})
		id, _ := parseEntityIDWire(wire.Session.ID, false)
		familyID, _ := parseEntityIDWire(wire.Session.RotationFamilyID, false)
		platformSAMLWriteField(digest, id[:])
		platformSAMLWriteField(digest, familyID[:])
		platformSAMLWriteField(digest, wire.Session.TokenDigest)
		platformSAMLWriteField(digest, wire.Session.CSRFSecretDigest)
		platformSAMLWriteField(digest, []byte(wire.Session.AuthenticationMethod))
		platformSAMLWriteField(digest, platformSAMLU64(uint64(wire.Session.IdleExpiresAt.UnixMicro())))
		platformSAMLWriteField(digest, platformSAMLU64(uint64(wire.Session.AbsoluteExpiresAt.UnixMicro())))
	} else {
		platformSAMLWriteField(digest, []byte{0})
	}
	if wire.Continuation != nil {
		platformSAMLWriteField(digest, []byte{1})
		id, _ := parseEntityIDWire(wire.Continuation.ID, false)
		factorID, _ := parseEntityIDWire(wire.Continuation.FactorID, false)
		platformSAMLWriteField(digest, id[:])
		platformSAMLWriteField(digest, factorID[:])
		platformSAMLWriteField(digest, platformSAMLU64(wire.Continuation.FactorRevision))
		platformSAMLWriteField(digest, wire.Continuation.ReceiptDigest)
		platformSAMLWriteField(digest, platformSAMLU64(uint64(wire.Continuation.ExpiresAt.UnixMicro())))
	} else {
		platformSAMLWriteField(digest, []byte{0})
	}
	requestID, _ := parseEntityIDWire(wire.Audit.RequestID, false)
	correlationID, _ := parseEntityIDWire(wire.Audit.CorrelationID, false)
	platformSAMLWriteField(digest, requestID[:])
	platformSAMLWriteField(digest, correlationID[:])
	platformSAMLWriteField(digest, commandAddressBytes(wire.Audit.IPAddress))
	platformSAMLWriteField(digest, []byte(wire.Audit.UserAgent))
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func commandAddressBytes(value string) []byte {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return nil
	}
	return address.AsSlice()
}

func platformSAMLSessionRevalidationResultFromWire(
	wire platformSAMLSessionRevalidationResultWire,
	command platformsamlauth.DirectSAMLSessionRevalidationCommand,
	recovered bool,
) (platformsamlauth.DirectSAMLSessionRevalidationResult, error) {
	sessionID, sessionErr := parseEntityIDWire(wire.SessionID, false)
	userID, userErr := parseEntityIDWire(wire.UserID, false)
	if sessionErr != nil || userErr != nil || sessionID != command.SessionID ||
		wire.ExpectedVersion != command.ExpectedVersion || wire.Decision != string(command.Decision) {
		return platformsamlauth.DirectSAMLSessionRevalidationResult{}, errPlatformSAMLPersistence
	}
	result := platformsamlauth.DirectSAMLSessionRevalidationResult{
		Applied: wire.Applied, Category: platformsamlauth.DirectSAMLSessionRevalidationCategory(wire.Category),
		Decision: command.Decision, SessionID: sessionID, UserID: userID,
		ExpectedVersion: wire.ExpectedVersion, NewVersion: wire.NewVersion,
	}
	if wire.NewSessionID != nil {
		id, err := parseEntityIDWire(*wire.NewSessionID, false)
		if err != nil {
			return platformsamlauth.DirectSAMLSessionRevalidationResult{}, errPlatformSAMLPersistence
		}
		result.NewSessionID = id
	}
	if wire.ContinuationID != nil {
		id, err := parseEntityIDWire(*wire.ContinuationID, false)
		if err != nil {
			return platformsamlauth.DirectSAMLSessionRevalidationResult{}, errPlatformSAMLPersistence
		}
		result.ContinuationID = id
	}
	if wire.AppliedAt != nil {
		result.AppliedAt = platformSAMLUTC(*wire.AppliedAt)
	}
	if !validPlatformSAMLSessionResult(result, command, recovered) {
		return platformsamlauth.DirectSAMLSessionRevalidationResult{}, errPlatformSAMLPersistence
	}
	return result, nil
}

func platformSAMLSessionRevalidationResultToWire(
	result platformsamlauth.DirectSAMLSessionRevalidationResult,
	command platformsamlauth.DirectSAMLSessionRevalidationCommand,
) (platformSAMLSessionRevalidationResultWire, error) {
	if !validPlatformSAMLSessionResult(result, command, true) || !result.Applied {
		return platformSAMLSessionRevalidationResultWire{}, errPlatformSAMLPersistence
	}
	wire := platformSAMLSessionRevalidationResultWire{
		Applied: true, Category: string(result.Category), Decision: string(result.Decision),
		SessionID: entityIDWire(result.SessionID), UserID: entityIDWire(result.UserID),
		ExpectedVersion: result.ExpectedVersion, NewVersion: result.NewVersion,
	}
	appliedAt := result.AppliedAt
	wire.AppliedAt = &appliedAt
	if result.NewSessionID != (identity.EntityID{}) {
		value := entityIDWire(result.NewSessionID)
		wire.NewSessionID = &value
	}
	if result.ContinuationID != (identity.EntityID{}) {
		value := entityIDWire(result.ContinuationID)
		wire.ContinuationID = &value
	}
	return wire, nil
}

func validPlatformSAMLSessionResult(
	result platformsamlauth.DirectSAMLSessionRevalidationResult,
	command platformsamlauth.DirectSAMLSessionRevalidationCommand,
	recovered bool,
) bool {
	if result.SessionID != command.SessionID || result.UserID == (identity.EntityID{}) ||
		result.ExpectedVersion != command.ExpectedVersion || result.Decision != command.Decision {
		return false
	}
	if result.Applied {
		if result.Category != platformsamlauth.DirectSAMLSessionRevalidationSuccess &&
			result.Category != platformsamlauth.DirectSAMLSessionRevalidationAlreadyApplied ||
			!validPlatformSAMLInstant(result.AppliedAt) || !result.AppliedAt.Equal(command.ObservedAt) {
			return false
		}
		if recovered && result.Category != platformsamlauth.DirectSAMLSessionRevalidationAlreadyApplied {
			return false
		}
		switch command.Decision {
		case mfa.SessionUsable:
			return result.NewVersion == command.ExpectedVersion+1 &&
				result.NewSessionID == (identity.EntityID{}) && result.ContinuationID == (identity.EntityID{})
		case mfa.SessionRotate:
			return result.NewVersion == 0 && result.NewSessionID == command.Session.SessionID() &&
				result.ContinuationID == (identity.EntityID{})
		case mfa.SessionStepUp:
			return result.NewVersion == command.ExpectedVersion+1 &&
				result.NewSessionID == (identity.EntityID{}) &&
				result.ContinuationID == command.Continuation.ContinuationID()
		case mfa.SessionRevoke, mfa.SessionDeny:
			return result.NewVersion == 0 && result.NewSessionID == (identity.EntityID{}) &&
				result.ContinuationID == (identity.EntityID{})
		default:
			return false
		}
	}
	return !recovered && (result.Category == platformsamlauth.DirectSAMLSessionRevalidationStale ||
		result.Category == platformsamlauth.DirectSAMLSessionRevalidationReplay) &&
		result.NewVersion == 0 && result.NewSessionID == (identity.EntityID{}) &&
		result.ContinuationID == (identity.EntityID{}) && result.AppliedAt.IsZero()
}

func validPlatformSAMLSessionDecision(decision mfa.SessionDecision, reason mfa.SessionReason) bool {
	switch decision {
	case mfa.SessionUsable:
		return reason == mfa.SessionReasonCurrent
	case mfa.SessionRotate:
		return reason == mfa.SessionReasonPolicyRefresh
	case mfa.SessionStepUp:
		return reason == mfa.SessionReasonAssuranceInsufficient || reason == mfa.SessionReasonRecoveryRestricted
	case mfa.SessionRevoke:
		switch reason {
		case mfa.SessionReasonExpired, mfa.SessionReasonLifecycle, mfa.SessionReasonIdentityEpoch,
			mfa.SessionReasonPrimaryDrift, mfa.SessionReasonFactorDrift, mfa.SessionReasonTrustDrift:
			return true
		}
		return false
	case mfa.SessionDeny:
		return reason == mfa.SessionReasonMalformed || reason == mfa.SessionReasonAssuranceInsufficient ||
			reason == mfa.SessionReasonRecoveryRestricted
	default:
		return false
	}
}

func platformSAMLSessionRevalidationSnapshotFromWire(
	wire platformSAMLSessionRevalidationSnapshotWire,
) (platformsamlauth.DirectSAMLSessionRevalidationSnapshot, error) {
	session, err := platformSAMLSessionStateFromWire(wire.Session)
	if err != nil {
		return platformsamlauth.DirectSAMLSessionRevalidationSnapshot{}, err
	}
	authority, err := platformSAMLSessionAuthorityFromWire(wire.Authority)
	if err != nil {
		return platformsamlauth.DirectSAMLSessionRevalidationSnapshot{}, err
	}
	result := platformsamlauth.DirectSAMLSessionRevalidationSnapshot{Session: session, Authority: authority}
	for _, value := range wire.Evidence {
		mapped, mapErr := platformSAMLSessionEvidenceFromWire(value)
		if mapErr != nil {
			return platformsamlauth.DirectSAMLSessionRevalidationSnapshot{}, mapErr
		}
		result.Evidence = append(result.Evidence, mapped)
	}
	for _, value := range wire.FactorAuthorities {
		mapped, mapErr := platformSAMLSessionFactorAuthorityFromWire(value)
		if mapErr != nil {
			return platformsamlauth.DirectSAMLSessionRevalidationSnapshot{}, mapErr
		}
		result.FactorAuthorities = append(result.FactorAuthorities, mapped)
	}
	for _, value := range wire.TrustAuthorities {
		mapped, mapErr := platformSAMLSessionTrustAuthorityFromWire(value)
		if mapErr != nil {
			return platformsamlauth.DirectSAMLSessionRevalidationSnapshot{}, mapErr
		}
		result.TrustAuthorities = append(result.TrustAuthorities, mapped)
	}
	for _, value := range wire.PolicyPins {
		mapped, mapErr := platformSAMLSessionPolicyPinFromWire(value)
		if mapErr != nil {
			return platformsamlauth.DirectSAMLSessionRevalidationSnapshot{}, mapErr
		}
		result.PolicyPins = append(result.PolicyPins, mapped)
	}
	if len(result.Evidence) > platformsamlauth.DirectSAMLSessionMaximumEvidence ||
		len(result.FactorAuthorities) > 1 || len(result.TrustAuthorities) > 1 ||
		len(result.PolicyPins) > platformsamlauth.DirectSAMLSessionMaximumPolicies {
		return platformsamlauth.DirectSAMLSessionRevalidationSnapshot{}, errPlatformSAMLPersistence
	}
	return result, nil
}

func platformSAMLSessionStateFromWire(
	wire platformSAMLSessionStateWire,
) (platformsamlauth.DirectSAMLSessionState, error) {
	sessionID, sessionErr := parseEntityIDWire(wire.SessionID, false)
	familyID, familyErr := parseEntityIDWire(wire.RotationFamilyID, false)
	userID, userErr := parseEntityIDWire(wire.UserID, false)
	issuedAt := platformSAMLUTC(wire.IssuedAt)
	idleExpiresAt := platformSAMLUTC(wire.IdleExpiresAt)
	absoluteExpiresAt := platformSAMLUTC(wire.AbsoluteExpiresAt)
	if sessionErr != nil || familyErr != nil || userErr != nil || wire.ActiveTenantID != nil ||
		wire.Authority != platformsamlauth.DirectSAMLSessionAuthority ||
		wire.AuthenticationMethod != platformsamlauth.DirectSAMLSessionMethod ||
		wire.Audience != platformsamlauth.DirectSAMLSessionAudience ||
		wire.PrimaryKind != platformsamlauth.DirectSAMLSessionPrimaryKind ||
		!validPlatformSAMLRevision(wire.CurrentVersion) ||
		!validPlatformSAMLRevision(wire.UserAuthenticationRevision) ||
		!validPlatformSAMLInstant(issuedAt) || !validPlatformSAMLInstant(idleExpiresAt) ||
		!validPlatformSAMLInstant(absoluteExpiresAt) || sessionID == familyID {
		return platformsamlauth.DirectSAMLSessionState{}, errPlatformSAMLPersistence
	}
	return platformsamlauth.DirectSAMLSessionState{
		SessionID: sessionID, RotationFamilyID: familyID, UserID: userID,
		Authority: wire.Authority, AuthenticationMethod: wire.AuthenticationMethod,
		Audience: wire.Audience, PrimaryKind: wire.PrimaryKind,
		SAMLStateCount: wire.SAMLStateCount, SAMLProvenanceCount: wire.SAMLProvenanceCount,
		OIDCStateCount: wire.OIDCStateCount, TenantProvenanceCount: wire.TenantProvenanceCount,
		ProviderEvidenceCount: wire.ProviderEvidenceCount, TOTPEvidenceCount: wire.TOTPEvidenceCount,
		CurrentVersion: wire.CurrentVersion, UserAuthenticationRevision: wire.UserAuthenticationRevision,
		RecoveryRestricted: wire.RecoveryRestricted, IssuedAt: issuedAt,
		IdleExpiresAt: idleExpiresAt, AbsoluteExpiresAt: absoluteExpiresAt,
		Active: wire.Active, RotationFamilyLive: wire.RotationFamilyLive,
	}, nil
}

func platformSAMLSessionAuthorityFromWire(
	wire platformSAMLSessionAuthorityWire,
) (platformsamlauth.DirectSAMLSessionAuthorityFacts, error) {
	ids := []string{
		wire.ProviderID, wire.ExternalIdentityID, wire.IdentityCurrentProviderID, wire.IdentityCurrentUserID,
		wire.AliasCurrentProviderID, wire.AliasCurrentIdentityID, wire.PinnedPlatformAuthorityID,
		wire.CurrentPlatformAuthorityID, wire.PinnedPlatformFloorID, wire.CurrentPlatformFloorID,
	}
	parsed := make([]identity.EntityID, len(ids))
	for index, value := range ids {
		id, err := parseEntityIDWire(value, false)
		if err != nil {
			return platformsamlauth.DirectSAMLSessionAuthorityFacts{}, errPlatformSAMLPersistence
		}
		parsed[index] = id
	}
	revisions := []uint64{
		wire.PinnedProviderRevision, wire.CurrentProviderRevision,
		wire.PinnedLoginPolicyRevision, wire.CurrentLoginPolicyRevision,
		wire.PinnedConfigurationRevision, wire.CurrentConfigurationRevision,
		wire.PinnedSecurityRevision, wire.CurrentSecurityRevision,
		wire.PinnedPlanRevision, wire.CurrentPlanRevision,
		wire.PinnedAssurancePolicyRevision, wire.CurrentAssurancePolicyRevision,
		wire.PinnedMetadataRevision, wire.CurrentMetadataRevision,
		wire.PinnedSPKeyRevision, wire.CurrentSPKeyRevision,
		wire.PinnedUserAuthenticationRevision, wire.CurrentUserAuthenticationRevision,
		wire.PinnedIdentityRevision, wire.CurrentIdentityRevision,
		wire.PinnedPlatformAuthorityRevision, wire.CurrentPlatformAuthorityRevision,
		wire.PinnedPlatformFloorRevision, wire.CurrentPlatformFloorRevision,
	}
	for _, value := range revisions {
		if !validPlatformSAMLRevision(value) {
			return platformsamlauth.DirectSAMLSessionAuthorityFacts{}, errPlatformSAMLPersistence
		}
	}
	if wire.ProviderKind != platformsamlauth.DirectSAMLSessionProviderKind ||
		(wire.AccountMode != string(platformsamlauth.DirectSAMLSessionAccountExisting) &&
			wire.AccountMode != string(platformsamlauth.DirectSAMLSessionAccountDisabled)) ||
		wire.PinnedAliasKeyVersion < 1 || wire.CurrentAliasKeyVersion < 1 {
		return platformsamlauth.DirectSAMLSessionAuthorityFacts{}, errPlatformSAMLPersistence
	}
	digests := [][]byte{wire.PinnedMetadataDigest, wire.CurrentMetadataDigest,
		wire.PinnedConfigurationDigest, wire.CurrentConfigurationDigest}
	for _, value := range digests {
		if len(value) != sha256.Size || slices.Equal(value, make([]byte, sha256.Size)) {
			return platformsamlauth.DirectSAMLSessionAuthorityFacts{}, errPlatformSAMLPersistence
		}
	}
	requirement, err := platformSAMLSessionRequirementFromWire(wire.PlatformFloor)
	if err != nil {
		return platformsamlauth.DirectSAMLSessionAuthorityFacts{}, err
	}
	result := platformsamlauth.DirectSAMLSessionAuthorityFacts{
		ProviderID: parsed[0], ExternalIdentityID: parsed[1], ProviderKind: wire.ProviderKind,
		AccountMode:            platformsamlauth.DirectSAMLSessionAccountMode(wire.AccountMode),
		PinnedProviderRevision: wire.PinnedProviderRevision, CurrentProviderRevision: wire.CurrentProviderRevision,
		PinnedLoginPolicyRevision: wire.PinnedLoginPolicyRevision, CurrentLoginPolicyRevision: wire.CurrentLoginPolicyRevision,
		PinnedConfigurationRevision: wire.PinnedConfigurationRevision, CurrentConfigurationRevision: wire.CurrentConfigurationRevision,
		PinnedSecurityRevision: wire.PinnedSecurityRevision, CurrentSecurityRevision: wire.CurrentSecurityRevision,
		PinnedPlanRevision: wire.PinnedPlanRevision, CurrentPlanRevision: wire.CurrentPlanRevision,
		PinnedAssurancePolicyRevision:  wire.PinnedAssurancePolicyRevision,
		CurrentAssurancePolicyRevision: wire.CurrentAssurancePolicyRevision,
		PinnedMetadataRevision:         wire.PinnedMetadataRevision, CurrentMetadataRevision: wire.CurrentMetadataRevision,
		PinnedSPKeyRevision: wire.PinnedSPKeyRevision, CurrentSPKeyRevision: wire.CurrentSPKeyRevision,
		PinnedUserAuthenticationRevision:  wire.PinnedUserAuthenticationRevision,
		CurrentUserAuthenticationRevision: wire.CurrentUserAuthenticationRevision,
		PinnedIdentityRevision:            wire.PinnedIdentityRevision, CurrentIdentityRevision: wire.CurrentIdentityRevision,
		PinnedAliasKeyVersion: wire.PinnedAliasKeyVersion, CurrentAliasKeyVersion: wire.CurrentAliasKeyVersion,
		IdentityCurrentProviderID: parsed[2], IdentityCurrentUserID: parsed[3],
		AliasCurrentProviderID: parsed[4], AliasCurrentIdentityID: parsed[5],
		PinnedPlatformAuthorityID: parsed[6], CurrentPlatformAuthorityID: parsed[7],
		PinnedPlatformAuthorityRevision:  wire.PinnedPlatformAuthorityRevision,
		CurrentPlatformAuthorityRevision: wire.CurrentPlatformAuthorityRevision,
		PinnedPlatformFloorID:            parsed[8], CurrentPlatformFloorID: parsed[9],
		PinnedPlatformFloorRevision:  wire.PinnedPlatformFloorRevision,
		CurrentPlatformFloorRevision: wire.CurrentPlatformFloorRevision,
		ProviderEnabled:              wire.ProviderEnabled, PlatformLoginLive: wire.PlatformLoginLive,
		UserActive: wire.UserActive, IdentityLive: wire.IdentityLive, SubjectAliasLive: wire.SubjectAliasLive,
		FactorEvidenceLive: wire.FactorEvidenceLive, EvidenceFresh: wire.EvidenceFresh,
		PolicyPinsExact: wire.PolicyPinsExact, TrustEvidenceLive: wire.TrustEvidenceLive,
		ConfigurationLive: wire.ConfigurationLive, MetadataLive: wire.MetadataLive, SPKeyLive: wire.SPKeyLive,
		PlatformAuthorityLive: wire.PlatformAuthorityLive, PlatformFloorLive: wire.PlatformFloorLive,
		PlatformFloor: requirement,
	}
	copy(result.PinnedMetadataDigest[:], wire.PinnedMetadataDigest)
	copy(result.CurrentMetadataDigest[:], wire.CurrentMetadataDigest)
	copy(result.PinnedConfigurationDigest[:], wire.PinnedConfigurationDigest)
	copy(result.CurrentConfigurationDigest[:], wire.CurrentConfigurationDigest)
	if wire.StepUpTOTP != nil {
		id, err := parseEntityIDWire(wire.StepUpTOTP.FactorID, false)
		if err != nil || !validPlatformSAMLRevision(wire.StepUpTOTP.Revision) {
			return platformsamlauth.DirectSAMLSessionAuthorityFacts{}, errPlatformSAMLPersistence
		}
		result.StepUpTOTP = &platformsamlauth.TOTPSelection{FactorID: id, Revision: wire.StepUpTOTP.Revision}
	}
	return result, nil
}

func platformSAMLSessionRequirementFromWire(
	wire platformSAMLSessionRequirementWire,
) (identity.EffectiveAssuranceRequirement, error) {
	level, err := assuranceLevelFromWire(wire.Level)
	if err != nil || wire.FreshnessNanoseconds < 0 || wire.FreshnessNanoseconds > int64(365*24*time.Hour) ||
		len(wire.PolicyRevisions) == 0 || len(wire.PolicyRevisions) > platformsamlauth.DirectSAMLSessionMaximumPolicies {
		return identity.EffectiveAssuranceRequirement{}, errPlatformSAMLPersistence
	}
	result := identity.EffectiveAssuranceRequirement{
		Level: level, LocalRequired: wire.LocalRequired,
		Freshness: time.Duration(wire.FreshnessNanoseconds), EnrollmentDeadline: copyTimePointer(wire.EnrollmentDeadline),
	}
	for _, value := range wire.PolicyRevisions {
		id, idErr := parseEntityIDWire(value.PolicyID, false)
		if idErr != nil || value.Revision < 1 || value.Revision > 9_007_199_254_740_991 {
			return identity.EffectiveAssuranceRequirement{}, errPlatformSAMLPersistence
		}
		result.PolicyRevisions = append(result.PolicyRevisions, identity.AssurancePolicyRevision{
			PolicyID: id, Revision: value.Revision,
		})
	}
	return result, nil
}

func platformSAMLSessionEvidenceFromWire(
	wire platformSAMLSessionEvidenceWire,
) (platformsamlauth.DirectSAMLSessionEvidence, error) {
	id, idErr := parseEntityIDWire(wire.ID, false)
	userID, userErr := parseEntityIDWire(wire.UserID, false)
	level, levelErr := assuranceLevelFromWire(wire.Level)
	authenticatedAt := platformSAMLUTC(wire.AuthenticatedAt)
	if idErr != nil || userErr != nil || levelErr != nil || !validPlatformSAMLInstant(authenticatedAt) {
		return platformsamlauth.DirectSAMLSessionEvidence{}, errPlatformSAMLPersistence
	}
	result := platformsamlauth.DirectSAMLSessionEvidence{
		ID: id, UserID: userID, Kind: platformsamlauth.DirectSAMLSessionEvidenceKind(wire.Kind),
		Level: level, FactorRevision: wire.FactorRevision, TrustRuleRevision: wire.TrustRuleRevision,
		AuthenticatedAt: authenticatedAt,
	}
	if wire.ExpiresAt != nil {
		value := platformSAMLUTC(*wire.ExpiresAt)
		if !validPlatformSAMLInstant(value) {
			return platformsamlauth.DirectSAMLSessionEvidence{}, errPlatformSAMLPersistence
		}
		result.ExpiresAt = &value
	}
	var err error
	result.PlatformProviderID, err = optionalPlatformSAMLEntityID(wire.PlatformProviderID)
	if err != nil {
		return platformsamlauth.DirectSAMLSessionEvidence{}, err
	}
	result.ExternalIdentityID, err = optionalPlatformSAMLEntityID(wire.ExternalIdentityID)
	if err != nil {
		return platformsamlauth.DirectSAMLSessionEvidence{}, err
	}
	result.TOTPCredentialID, err = optionalPlatformSAMLEntityID(wire.TOTPCredentialID)
	if err != nil {
		return platformsamlauth.DirectSAMLSessionEvidence{}, err
	}
	result.TrustRuleID, err = optionalPlatformSAMLEntityID(wire.TrustRuleID)
	if err != nil {
		return platformsamlauth.DirectSAMLSessionEvidence{}, err
	}
	if result.Kind != platformsamlauth.DirectSAMLSessionEvidenceProvider &&
		result.Kind != platformsamlauth.DirectSAMLSessionEvidenceTOTP {
		return platformsamlauth.DirectSAMLSessionEvidence{}, errPlatformSAMLPersistence
	}
	return result, nil
}

func platformSAMLSessionFactorAuthorityFromWire(
	wire platformSAMLSessionFactorAuthorityWire,
) (platformsamlauth.DirectSAMLSessionFactorAuthority, error) {
	ids := []string{wire.EvidenceID, wire.EvidenceUserID, wire.TOTPCredentialID, wire.CurrentUserID}
	parsed := make([]identity.EntityID, len(ids))
	for index, value := range ids {
		id, err := parseEntityIDWire(value, false)
		if err != nil {
			return platformsamlauth.DirectSAMLSessionFactorAuthority{}, errPlatformSAMLPersistence
		}
		parsed[index] = id
	}
	if !validPlatformSAMLRevision(wire.PinnedSecurityRevision) || !validPlatformSAMLRevision(wire.CurrentSecurityRevision) {
		return platformsamlauth.DirectSAMLSessionFactorAuthority{}, errPlatformSAMLPersistence
	}
	return platformsamlauth.DirectSAMLSessionFactorAuthority{
		EvidenceID: parsed[0], EvidenceUserID: parsed[1], TOTPCredentialID: parsed[2],
		PinnedSecurityRevision: wire.PinnedSecurityRevision, CurrentUserID: parsed[3],
		CurrentSecurityRevision: wire.CurrentSecurityRevision,
		ConfirmedAt:             normalizedPlatformSAMLTimePointer(wire.ConfirmedAt),
		DisabledAt:              normalizedPlatformSAMLTimePointer(wire.DisabledAt),
	}, nil
}

func platformSAMLSessionTrustAuthorityFromWire(
	wire platformSAMLSessionTrustAuthorityWire,
) (platformsamlauth.DirectSAMLSessionTrustAuthority, error) {
	ids := []string{wire.EvidenceID, wire.TrustRuleID, wire.CurrentProviderID}
	parsed := make([]identity.EntityID, len(ids))
	for index, value := range ids {
		id, err := parseEntityIDWire(value, false)
		if err != nil {
			return platformsamlauth.DirectSAMLSessionTrustAuthority{}, errPlatformSAMLPersistence
		}
		parsed[index] = id
	}
	level, err := assuranceLevelFromWire(wire.CurrentLevel)
	if err != nil || !validPlatformSAMLRevision(wire.PinnedRevision) ||
		!validPlatformSAMLRevision(wire.CurrentRevision) || wire.CurrentProviderKind != platformsamlauth.ProviderKindSAML {
		return platformsamlauth.DirectSAMLSessionTrustAuthority{}, errPlatformSAMLPersistence
	}
	return platformsamlauth.DirectSAMLSessionTrustAuthority{
		EvidenceID: parsed[0], TrustRuleID: parsed[1], PinnedRevision: wire.PinnedRevision,
		CurrentProviderID: parsed[2], CurrentProviderKind: wire.CurrentProviderKind,
		CurrentRevision: wire.CurrentRevision, CurrentLevel: level, Enabled: wire.Enabled,
		RetiredAt: normalizedPlatformSAMLTimePointer(wire.RetiredAt),
	}, nil
}

func platformSAMLSessionPolicyPinFromWire(
	wire platformSAMLSessionPolicyPinWire,
) (platformsamlauth.DirectSAMLSessionPolicyPin, error) {
	id, err := parseEntityIDWire(wire.ID, false)
	kind := platformsamlauth.DirectSAMLSessionPolicyKind(wire.Kind)
	if err != nil || !validPlatformSAMLRevision(wire.Revision) ||
		(kind != platformsamlauth.DirectSAMLSessionPolicyLogin &&
			kind != platformsamlauth.DirectSAMLSessionPolicyAssurance &&
			kind != platformsamlauth.DirectSAMLSessionPolicyPlatformFloor) {
		return platformsamlauth.DirectSAMLSessionPolicyPin{}, errPlatformSAMLPersistence
	}
	return platformsamlauth.DirectSAMLSessionPolicyPin{Kind: kind, ID: id, Revision: wire.Revision}, nil
}

func optionalPlatformSAMLEntityID(value *string) (*identity.EntityID, error) {
	if value == nil {
		return nil, nil
	}
	id, err := parseEntityIDWire(*value, false)
	if err != nil {
		return nil, errPlatformSAMLPersistence
	}
	return &id, nil
}

func normalizedPlatformSAMLTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := platformSAMLUTC(*value)
	return &normalized
}

func platformSAMLSessionRevalidationResultToClear(value *platformSAMLSessionRevalidationResultWire) {
	if value == nil {
		return
	}
	*value = platformSAMLSessionRevalidationResultWire{}
}

func clearPlatformSAMLSessionRevalidationCommandWire(value *platformSAMLSessionRevalidationCommandWire) {
	if value == nil {
		return
	}
	clear(value.RequestDigest)
	if value.Session != nil {
		clear(value.Session.TokenDigest)
		clear(value.Session.CSRFSecretDigest)
	}
	if value.Continuation != nil {
		clear(value.Continuation.ReceiptDigest)
	}
	*value = platformSAMLSessionRevalidationCommandWire{}
}
