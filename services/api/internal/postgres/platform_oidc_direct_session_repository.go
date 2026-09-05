package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

const (
	loadPlatformOIDCDirectSessionRevalidationSQL  = `select app.load_platform_oidc_session_revalidation_v1($1::jsonb)`
	applyPlatformOIDCDirectSessionRevalidationSQL = `select app.apply_platform_oidc_session_revalidation_v1($1::jsonb)`

	platformOIDCDirectSessionDigestDomain = "periapsis/platform-oidc-auth/session-revalidation/v1"
)

type platformOIDCDirectSessionLookupWire struct {
	SessionID  string    `json:"sessionId"`
	ObservedAt time.Time `json:"observedAt"`
}

type platformOIDCDirectExactRevisionWire struct {
	Pinned  int64 `json:"pinned"`
	Current int64 `json:"current"`
}

type platformOIDCDirectSessionRevalidationStateWire struct {
	ID                         string          `json:"id"`
	RotationFamilyID           string          `json:"rotationFamilyId"`
	UserID                     string          `json:"userId"`
	ActiveTenantID             json.RawMessage `json:"activeTenantId"`
	AuthenticationMethod       string          `json:"authenticationMethod"`
	Audience                   string          `json:"audience"`
	PrimaryKind                string          `json:"primaryKind"`
	IssuedAt                   time.Time       `json:"issuedAt"`
	RecoveryRestricted         *bool           `json:"recoveryRestricted"`
	UserAuthenticationRevision int64           `json:"userAuthenticationRevision"`
	DirectStateCount           *int            `json:"directStateCount"`
	DirectProvenanceCount      *int            `json:"directProvenanceCount"`
	TenantProvenanceCount      *int            `json:"tenantProvenanceCount"`
	ProviderEvidenceCount      *int            `json:"providerEvidenceCount"`
	TOTPEvidenceCount          *int            `json:"totpEvidenceCount"`
	CurrentVersion             int64           `json:"currentVersion"`
	IdleExpiresAt              time.Time       `json:"idleExpiresAt"`
	AbsoluteExpiresAt          time.Time       `json:"absoluteExpiresAt"`
	Active                     *bool           `json:"active"`
	RotationFamilyLive         *bool           `json:"rotationFamilyLive"`
}

type platformOIDCDirectFloorWire struct {
	PinnedID           string          `json:"pinnedId"`
	PinnedRevision     int64           `json:"pinnedRevision"`
	CurrentID          string          `json:"currentId"`
	CurrentRevision    int64           `json:"currentRevision"`
	Level              string          `json:"level"`
	LocalRequired      *bool           `json:"localRequired"`
	Freshness          *int64          `json:"freshnessNanoseconds"`
	EnrollmentDeadline json.RawMessage `json:"enrollmentDeadline"`
	CurrentScope       string          `json:"currentScope"`
	CurrentTenantID    json.RawMessage `json:"currentTenantId"`
	CurrentRetiredAt   json.RawMessage `json:"currentRetiredAt"`
	CurrentCount       *int            `json:"currentCount"`
}

type platformOIDCDirectSessionAuthorityWire struct {
	ProviderID                 string                              `json:"providerId"`
	ExternalIdentityID         string                              `json:"externalIdentityId"`
	ProviderKind               string                              `json:"providerKind"`
	RuntimePolicyEnabled       *bool                               `json:"runtimePolicyEnabled"`
	LegacyPlatformLoginEnabled *bool                               `json:"legacyPlatformLoginEnabled"`
	LoginPolicyEnabled         *bool                               `json:"loginPolicyEnabled"`
	AccountMode                string                              `json:"accountMode"`
	IdentityCurrentProviderID  string                              `json:"identityCurrentProviderId"`
	IdentityCurrentUserID      string                              `json:"identityCurrentUserId"`
	IdentityProviderKind       string                              `json:"identityProviderKind"`
	IdentityRetiredAt          json.RawMessage                     `json:"identityRetiredAt"`
	AliasCurrentProviderID     string                              `json:"aliasCurrentProviderId"`
	AliasCurrentIdentityID     string                              `json:"aliasCurrentIdentityId"`
	AliasRetiredAt             json.RawMessage                     `json:"aliasRetiredAt"`
	ProviderRevision           platformOIDCDirectExactRevisionWire `json:"providerRevision"`
	SecurityRevision           platformOIDCDirectExactRevisionWire `json:"securityRevision"`
	LoginPolicyRevision        platformOIDCDirectExactRevisionWire `json:"loginPolicyRevision"`
	UserAuthenticationRevision platformOIDCDirectExactRevisionWire `json:"userAuthenticationRevision"`
	IdentityVersion            platformOIDCDirectExactRevisionWire `json:"identityVersion"`
	AliasKeyVersion            platformOIDCDirectExactRevisionWire `json:"aliasKeyVersion"`
	AssurancePolicyRevision    platformOIDCDirectExactRevisionWire `json:"assurancePolicyRevision"`
	PlatformFloor              platformOIDCDirectFloorWire         `json:"platformFloor"`
	TrustRuleID                json.RawMessage                     `json:"trustRuleId"`
	TrustRuleRevision          json.RawMessage                     `json:"trustRuleRevision"`
	ProviderEnabled            *bool                               `json:"providerEnabled"`
	PlatformLoginLive          *bool                               `json:"platformLoginLive"`
	UserActive                 *bool                               `json:"userActive"`
	IdentityLive               *bool                               `json:"identityLive"`
	SubjectAliasLive           *bool                               `json:"subjectAliasLive"`
	FactorEvidenceLive         *bool                               `json:"factorEvidenceLive"`
	EvidenceFresh              *bool                               `json:"evidenceFresh"`
	PolicyPinsExact            *bool                               `json:"policyPinsExact"`
	TrustEvidenceLive          *bool                               `json:"trustEvidenceLive"`
}

type platformOIDCDirectSessionEvidenceWire struct {
	ID                 string          `json:"id"`
	UserID             string          `json:"userId"`
	Kind               string          `json:"kind"`
	Level              string          `json:"level"`
	PlatformProviderID json.RawMessage `json:"platformProviderId"`
	ExternalIdentityID json.RawMessage `json:"externalIdentityId"`
	AuthenticatedAt    time.Time       `json:"authenticatedAt"`
	ExpiresAt          json.RawMessage `json:"expiresAt"`
	TOTPCredentialID   json.RawMessage `json:"totpCredentialId"`
	FactorRevision     json.RawMessage `json:"factorRevision"`
	TrustRuleID        json.RawMessage `json:"trustRuleId"`
	TrustRuleRevision  json.RawMessage `json:"trustRuleRevision"`
}

type platformOIDCDirectFactorAuthorityWire struct {
	EvidenceID              string          `json:"evidenceId"`
	EvidenceUserID          string          `json:"evidenceUserId"`
	TOTPCredentialID        string          `json:"totpCredentialId"`
	PinnedSecurityRevision  int64           `json:"pinnedSecurityRevision"`
	CurrentUserID           string          `json:"currentUserId"`
	CurrentSecurityRevision int64           `json:"currentSecurityRevision"`
	ConfirmedAt             json.RawMessage `json:"confirmedAt"`
	DisabledAt              json.RawMessage `json:"disabledAt"`
}

type platformOIDCDirectTrustAuthorityWire struct {
	EvidenceID          string          `json:"evidenceId"`
	TrustRuleID         string          `json:"trustRuleId"`
	PinnedRevision      int64           `json:"pinnedRevision"`
	CurrentProviderID   string          `json:"currentProviderId"`
	CurrentProviderKind string          `json:"currentProviderKind"`
	CurrentRevision     int64           `json:"currentRevision"`
	CurrentLevel        string          `json:"currentLevel"`
	Enabled             *bool           `json:"enabled"`
	RetiredAt           json.RawMessage `json:"retiredAt"`
}

type platformOIDCDirectPolicyPinWire struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
}

type platformOIDCDirectSessionSnapshotWire struct {
	Session           platformOIDCDirectSessionRevalidationStateWire `json:"session"`
	Authority         platformOIDCDirectSessionAuthorityWire         `json:"authority"`
	Evidence          []platformOIDCDirectSessionEvidenceWire        `json:"evidence"`
	FactorAuthorities []platformOIDCDirectFactorAuthorityWire        `json:"factorAuthorities"`
	TrustAuthorities  []platformOIDCDirectTrustAuthorityWire         `json:"trustAuthorities"`
	PolicyPins        []platformOIDCDirectPolicyPinWire              `json:"policyPins"`
}

type platformOIDCDirectSessionMutationWire struct {
	SessionID       string    `json:"sessionId"`
	ExpectedVersion int64     `json:"expectedVersion"`
	RequestDigest   []byte    `json:"requestDigest"`
	Decision        string    `json:"decision"`
	Reason          string    `json:"reason"`
	ObservedAt      time.Time `json:"observedAt"`
}

type platformOIDCDirectSessionMutationResultWire struct {
	Applied         *bool  `json:"applied"`
	Category        string `json:"category,omitempty"`
	SessionID       string `json:"sessionId,omitempty"`
	UserID          string `json:"userId,omitempty"`
	ExpectedVersion int64  `json:"expectedVersion"`
	NewVersion      int64  `json:"newVersion"`
	Decision        string `json:"decision"`
}

var _ platformoidcauth.DirectSessionRevalidationStore = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) LoadDirectPlatformSessionForRevalidation(
	ctx context.Context,
	lookup platformoidcauth.DirectSessionRevalidationLookup,
) (platformoidcauth.DirectSessionRevalidationSnapshot, error) {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil ||
		!platformOIDCDirectUUIDv7(lookup.SessionID) || !validFederatedDatabaseTime(lookup.ObservedAt) {
		return platformoidcauth.DirectSessionRevalidationSnapshot{}, errFederatedAuthPersistence
	}
	wire := platformOIDCDirectSessionLookupWire{
		SessionID: lookup.SessionID.String(), ObservedAt: lookup.ObservedAt,
	}
	var response platformOIDCDirectSessionSnapshotWire
	if err := repository.queryJSONWithResponseLimit(
		ctx, loadPlatformOIDCDirectSessionRevalidationSQL, wire, &response,
		maximumFederatedAuthenticationWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformoidcauth.DirectSessionRevalidationSnapshot{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectSessionSnapshotFromWire(response, lookup)
}

func (repository *FederatedAuthRepository) ApplyDirectPlatformSessionRevalidation(
	ctx context.Context,
	mutation platformoidcauth.DirectSessionRevalidationMutation,
) (platformoidcauth.DirectSessionRevalidationMutationResult, error) {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil {
		return platformoidcauth.DirectSessionRevalidationMutationResult{}, errFederatedAuthPersistence
	}
	wire, err := platformOIDCDirectSessionMutationToWire(mutation)
	if err != nil {
		return platformoidcauth.DirectSessionRevalidationMutationResult{}, errFederatedAuthPersistence
	}
	defer clearPlatformOIDCDirectSessionMutationWire(&wire)
	var response platformOIDCDirectSessionMutationResultWire
	if err = repository.queryJSONWithResponseLimit(
		ctx, applyPlatformOIDCDirectSessionRevalidationSQL, wire, &response,
		maximumFederatedAuthenticationWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformoidcauth.DirectSessionRevalidationMutationResult{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectSessionMutationResultFromWire(response, wire)
}

func platformOIDCDirectSessionSnapshotFromWire(
	value platformOIDCDirectSessionSnapshotWire,
	wanted platformoidcauth.DirectSessionRevalidationLookup,
) (platformoidcauth.DirectSessionRevalidationSnapshot, error) {
	session, err := platformOIDCDirectSessionFromWire(value.Session)
	if err != nil || session.SessionID != wanted.SessionID {
		return platformoidcauth.DirectSessionRevalidationSnapshot{}, errFederatedAuthPersistence
	}
	authority, err := platformOIDCDirectSessionAuthorityFromWire(value.Authority)
	if err != nil {
		return platformoidcauth.DirectSessionRevalidationSnapshot{}, errFederatedAuthPersistence
	}
	evidence := make([]platformoidcauth.DirectSessionEvidence, len(value.Evidence))
	if len(evidence) < 1 || len(evidence) > 2 {
		return platformoidcauth.DirectSessionRevalidationSnapshot{}, errFederatedAuthPersistence
	}
	for index := range value.Evidence {
		evidence[index], err = platformOIDCDirectSessionEvidenceFromWire(value.Evidence[index])
		if err != nil {
			return platformoidcauth.DirectSessionRevalidationSnapshot{}, errFederatedAuthPersistence
		}
	}
	factors := make([]platformoidcauth.DirectSessionFactorAuthority, len(value.FactorAuthorities))
	if len(factors) > 1 {
		return platformoidcauth.DirectSessionRevalidationSnapshot{}, errFederatedAuthPersistence
	}
	for index := range value.FactorAuthorities {
		factors[index], err = platformOIDCDirectFactorAuthorityFromWire(value.FactorAuthorities[index])
		if err != nil {
			return platformoidcauth.DirectSessionRevalidationSnapshot{}, errFederatedAuthPersistence
		}
	}
	trust := make([]platformoidcauth.DirectSessionTrustAuthority, len(value.TrustAuthorities))
	if len(trust) > 1 {
		return platformoidcauth.DirectSessionRevalidationSnapshot{}, errFederatedAuthPersistence
	}
	for index := range value.TrustAuthorities {
		trust[index], err = platformOIDCDirectTrustAuthorityFromWire(value.TrustAuthorities[index])
		if err != nil {
			return platformoidcauth.DirectSessionRevalidationSnapshot{}, errFederatedAuthPersistence
		}
	}
	pins := make([]platformoidcauth.DirectSessionPolicyPin, len(value.PolicyPins))
	if len(pins) != 3 {
		return platformoidcauth.DirectSessionRevalidationSnapshot{}, errFederatedAuthPersistence
	}
	for index := range value.PolicyPins {
		pins[index], err = platformOIDCDirectPolicyPinFromWire(value.PolicyPins[index])
		if err != nil {
			return platformoidcauth.DirectSessionRevalidationSnapshot{}, errFederatedAuthPersistence
		}
	}
	return platformoidcauth.DirectSessionRevalidationSnapshot{
		Session: session, Authority: authority, Evidence: evidence,
		FactorAuthorities: factors, TrustAuthorities: trust, PolicyPins: pins,
	}, nil
}

func platformOIDCDirectSessionFromWire(
	value platformOIDCDirectSessionRevalidationStateWire,
) (platformoidcauth.DirectSessionState, error) {
	identifier, err := platformOIDCDirectSessionUUID(value.ID)
	familyID, familyErr := platformOIDCDirectSessionUUID(value.RotationFamilyID)
	userID, userErr := platformOIDCDirectSessionUUID(value.UserID)
	activeTenantID, tenantErr := platformOIDCDirectNullableUUID(value.ActiveTenantID)
	issuedAt, validIssued := canonicalFederatedDatabaseTimeFromWire(value.IssuedAt)
	idleExpiresAt, validIdle := canonicalFederatedDatabaseTimeFromWire(value.IdleExpiresAt)
	absoluteExpiresAt, validAbsolute := canonicalFederatedDatabaseTimeFromWire(value.AbsoluteExpiresAt)
	if err != nil || familyErr != nil || userErr != nil || tenantErr != nil || !validIssued || !validIdle ||
		!validAbsolute || value.RecoveryRestricted == nil || value.DirectStateCount == nil ||
		value.DirectProvenanceCount == nil || value.TenantProvenanceCount == nil ||
		value.ProviderEvidenceCount == nil || value.TOTPEvidenceCount == nil || value.Active == nil ||
		value.RotationFamilyLive == nil || !platformOIDCDirectSessionRevision(value.UserAuthenticationRevision) ||
		value.CurrentVersion < 1 || value.CurrentVersion > 2_147_483_647 {
		return platformoidcauth.DirectSessionState{}, errFederatedAuthPersistence
	}
	return platformoidcauth.DirectSessionState{
		SessionID: identifier, RotationFamilyID: familyID, UserID: userID, ActiveTenantID: activeTenantID,
		AuthenticationMethod: value.AuthenticationMethod, Audience: value.Audience, PrimaryKind: value.PrimaryKind,
		DirectStateCount: *value.DirectStateCount, DirectProvenanceCount: *value.DirectProvenanceCount,
		TenantProvenanceCount: *value.TenantProvenanceCount, ProviderEvidenceCount: *value.ProviderEvidenceCount,
		TOTPEvidenceCount: *value.TOTPEvidenceCount, CurrentVersion: value.CurrentVersion,
		UserAuthenticationRevision: value.UserAuthenticationRevision, RecoveryRestricted: *value.RecoveryRestricted,
		IssuedAt: issuedAt, IdleExpiresAt: idleExpiresAt, AbsoluteExpiresAt: absoluteExpiresAt,
		Active: *value.Active, RotationFamilyLive: *value.RotationFamilyLive,
	}, nil
}

func platformOIDCDirectSessionAuthorityFromWire(
	value platformOIDCDirectSessionAuthorityWire,
) (platformoidcauth.DirectSessionAuthorityFacts, error) {
	providerID, err := platformOIDCDirectSessionUUID(value.ProviderID)
	externalIdentityID, externalErr := platformOIDCDirectSessionUUID(value.ExternalIdentityID)
	identityProviderID, identityProviderErr := platformOIDCDirectSessionUUID(value.IdentityCurrentProviderID)
	identityUserID, identityUserErr := platformOIDCDirectSessionUUID(value.IdentityCurrentUserID)
	aliasProviderID, aliasProviderErr := platformOIDCDirectSessionUUID(value.AliasCurrentProviderID)
	aliasIdentityID, aliasIdentityErr := platformOIDCDirectSessionUUID(value.AliasCurrentIdentityID)
	identityRetiredAt, identityRetiredErr := platformOIDCDirectNullableTime(value.IdentityRetiredAt)
	aliasRetiredAt, aliasRetiredErr := platformOIDCDirectNullableTime(value.AliasRetiredAt)
	trustRuleID, trustIDErr := platformOIDCDirectNullableUUID(value.TrustRuleID)
	trustRuleRevision, trustRevisionErr := platformOIDCDirectNullableRevision(value.TrustRuleRevision)
	floor, floorErr := platformOIDCDirectFloorFromWire(value.PlatformFloor)
	if err != nil || externalErr != nil || identityProviderErr != nil || identityUserErr != nil ||
		aliasProviderErr != nil || aliasIdentityErr != nil || identityRetiredErr != nil || aliasRetiredErr != nil ||
		trustIDErr != nil || trustRevisionErr != nil || floorErr != nil || value.RuntimePolicyEnabled == nil ||
		value.LegacyPlatformLoginEnabled == nil || value.LoginPolicyEnabled == nil || value.ProviderEnabled == nil ||
		value.PlatformLoginLive == nil || value.UserActive == nil || value.IdentityLive == nil ||
		value.SubjectAliasLive == nil || value.FactorEvidenceLive == nil || value.EvidenceFresh == nil ||
		value.PolicyPinsExact == nil || value.TrustEvidenceLive == nil ||
		!platformOIDCDirectExactRevisionWireValid(value.ProviderRevision) ||
		!platformOIDCDirectExactRevisionWireValid(value.SecurityRevision) ||
		!platformOIDCDirectExactRevisionWireValid(value.LoginPolicyRevision) ||
		!platformOIDCDirectExactRevisionWireValid(value.UserAuthenticationRevision) ||
		!platformOIDCDirectExactRevisionWireValid(value.IdentityVersion) ||
		!platformOIDCDirectExactRevisionWireValid(value.AliasKeyVersion) ||
		!platformOIDCDirectExactRevisionWireValid(value.AssurancePolicyRevision) ||
		(trustRuleID == nil) != (trustRuleRevision == nil) {
		return platformoidcauth.DirectSessionAuthorityFacts{}, errFederatedAuthPersistence
	}
	return platformoidcauth.DirectSessionAuthorityFacts{
		ProviderID: providerID, ExternalIdentityID: externalIdentityID, ProviderKind: value.ProviderKind,
		ProviderEnabled: *value.ProviderEnabled, RuntimePolicyEnabled: *value.RuntimePolicyEnabled,
		LegacyPlatformLoginEnabled: *value.LegacyPlatformLoginEnabled,
		LoginPolicyEnabled:         *value.LoginPolicyEnabled, AccountMode: platformoidcauth.AccountMode(value.AccountMode),
		UserActive: *value.UserActive, IdentityCurrentProviderID: identityProviderID,
		IdentityCurrentUserID: identityUserID, IdentityProviderKind: value.IdentityProviderKind,
		IdentityRetiredAt: identityRetiredAt, AliasCurrentProviderID: aliasProviderID,
		AliasCurrentIdentityID: aliasIdentityID, AliasRetiredAt: aliasRetiredAt,
		Revisions: platformoidcauth.DirectSessionAuthorityRevisions{
			Provider:           platformOIDCDirectExactRevisionFromWire(value.ProviderRevision),
			Security:           platformOIDCDirectExactRevisionFromWire(value.SecurityRevision),
			LoginPolicy:        platformOIDCDirectExactRevisionFromWire(value.LoginPolicyRevision),
			UserAuthentication: platformOIDCDirectExactRevisionFromWire(value.UserAuthenticationRevision),
			ExternalIdentity:   platformOIDCDirectExactRevisionFromWire(value.IdentityVersion),
			SubjectAliasKey:    platformOIDCDirectExactRevisionFromWire(value.AliasKeyVersion),
			AssurancePolicy:    platformOIDCDirectExactRevisionFromWire(value.AssurancePolicyRevision),
		},
		PlatformFloor: floor, TrustRuleID: trustRuleID, TrustRuleRevision: trustRuleRevision,
	}, nil
}

func platformOIDCDirectFloorFromWire(
	value platformOIDCDirectFloorWire,
) (platformoidcauth.DirectSessionPlatformFloor, error) {
	pinnedID, err := platformOIDCDirectSessionUUID(value.PinnedID)
	currentID, currentErr := platformOIDCDirectOptionalUUIDString(value.CurrentID)
	currentTenantID, tenantErr := platformOIDCDirectNullableUUID(value.CurrentTenantID)
	currentRetiredAt, retiredErr := platformOIDCDirectNullableTime(value.CurrentRetiredAt)
	enrollmentDeadline, enrollmentErr := platformOIDCDirectNullableTime(value.EnrollmentDeadline)
	level, levelErr := assuranceLevelFromWire(value.Level)
	if err != nil || currentErr != nil || tenantErr != nil || retiredErr != nil || enrollmentErr != nil ||
		levelErr != nil || value.LocalRequired == nil || value.Freshness == nil || value.CurrentCount == nil ||
		!platformOIDCDirectSessionRevision(value.PinnedRevision) || value.CurrentRevision < 0 ||
		*value.Freshness < 0 {
		return platformoidcauth.DirectSessionPlatformFloor{}, errFederatedAuthPersistence
	}
	return platformoidcauth.DirectSessionPlatformFloor{
		PinnedID: pinnedID, PinnedRevision: value.PinnedRevision, CurrentID: currentID,
		CurrentRevision: value.CurrentRevision, CurrentCount: *value.CurrentCount, CurrentScope: value.CurrentScope,
		CurrentTenantID: currentTenantID, CurrentRetiredAt: currentRetiredAt, Level: level,
		LocalRequired: *value.LocalRequired, Freshness: time.Duration(*value.Freshness),
		EnrollmentDeadline: enrollmentDeadline,
	}, nil
}

func platformOIDCDirectSessionEvidenceFromWire(
	value platformOIDCDirectSessionEvidenceWire,
) (platformoidcauth.DirectSessionEvidence, error) {
	identifier, err := platformOIDCDirectSessionUUID(value.ID)
	userID, userErr := platformOIDCDirectSessionUUID(value.UserID)
	providerID, providerErr := platformOIDCDirectNullableUUID(value.PlatformProviderID)
	externalIdentityID, externalErr := platformOIDCDirectNullableUUID(value.ExternalIdentityID)
	totpID, totpErr := platformOIDCDirectNullableUUID(value.TOTPCredentialID)
	factorRevision, factorErr := platformOIDCDirectNullableRevision(value.FactorRevision)
	trustRuleID, trustIDErr := platformOIDCDirectNullableUUID(value.TrustRuleID)
	trustRevision, trustRevisionErr := platformOIDCDirectNullableRevision(value.TrustRuleRevision)
	expiresAt, expiresErr := platformOIDCDirectNullableTime(value.ExpiresAt)
	authenticatedAt, validAuthenticated := canonicalFederatedDatabaseTimeFromWire(value.AuthenticatedAt)
	level, levelErr := assuranceLevelFromWire(value.Level)
	if err != nil || userErr != nil || providerErr != nil || externalErr != nil || totpErr != nil ||
		factorErr != nil || trustIDErr != nil || trustRevisionErr != nil || expiresErr != nil ||
		!validAuthenticated || levelErr != nil || (trustRuleID == nil) != (trustRevision == nil) {
		return platformoidcauth.DirectSessionEvidence{}, errFederatedAuthPersistence
	}
	return platformoidcauth.DirectSessionEvidence{
		ID: identifier, UserID: userID, Kind: platformoidcauth.DirectSessionEvidenceKind(value.Kind), Level: level,
		PlatformProviderID: providerID, ExternalIdentityID: externalIdentityID, TOTPCredentialID: totpID,
		FactorRevision: factorRevision, TrustRuleID: trustRuleID, TrustRuleRevision: trustRevision,
		AuthenticatedAt: authenticatedAt, ExpiresAt: expiresAt,
	}, nil
}

func platformOIDCDirectFactorAuthorityFromWire(
	value platformOIDCDirectFactorAuthorityWire,
) (platformoidcauth.DirectSessionFactorAuthority, error) {
	evidenceID, err := platformOIDCDirectSessionUUID(value.EvidenceID)
	evidenceUserID, evidenceUserErr := platformOIDCDirectSessionUUID(value.EvidenceUserID)
	totpID, totpErr := platformOIDCDirectSessionUUID(value.TOTPCredentialID)
	currentUserID, currentUserErr := platformOIDCDirectSessionUUID(value.CurrentUserID)
	confirmedAt, confirmedErr := platformOIDCDirectNullableTime(value.ConfirmedAt)
	disabledAt, disabledErr := platformOIDCDirectNullableTime(value.DisabledAt)
	if err != nil || evidenceUserErr != nil || totpErr != nil || currentUserErr != nil ||
		confirmedErr != nil || disabledErr != nil || !platformOIDCDirectSessionRevision(value.PinnedSecurityRevision) ||
		!platformOIDCDirectSessionRevision(value.CurrentSecurityRevision) {
		return platformoidcauth.DirectSessionFactorAuthority{}, errFederatedAuthPersistence
	}
	return platformoidcauth.DirectSessionFactorAuthority{
		EvidenceID: evidenceID, EvidenceUserID: evidenceUserID, TOTPCredentialID: totpID,
		PinnedSecurityRevision: value.PinnedSecurityRevision, CurrentUserID: currentUserID,
		CurrentSecurityRevision: value.CurrentSecurityRevision, ConfirmedAt: confirmedAt, DisabledAt: disabledAt,
	}, nil
}

func platformOIDCDirectTrustAuthorityFromWire(
	value platformOIDCDirectTrustAuthorityWire,
) (platformoidcauth.DirectSessionTrustAuthority, error) {
	evidenceID, err := platformOIDCDirectSessionUUID(value.EvidenceID)
	trustRuleID, trustErr := platformOIDCDirectSessionUUID(value.TrustRuleID)
	providerID, providerErr := platformOIDCDirectSessionUUID(value.CurrentProviderID)
	retiredAt, retiredErr := platformOIDCDirectNullableTime(value.RetiredAt)
	level, levelErr := assuranceLevelFromWire(value.CurrentLevel)
	if err != nil || trustErr != nil || providerErr != nil || retiredErr != nil || levelErr != nil ||
		value.Enabled == nil || !platformOIDCDirectSessionRevision(value.PinnedRevision) ||
		!platformOIDCDirectSessionRevision(value.CurrentRevision) {
		return platformoidcauth.DirectSessionTrustAuthority{}, errFederatedAuthPersistence
	}
	return platformoidcauth.DirectSessionTrustAuthority{
		EvidenceID: evidenceID, TrustRuleID: trustRuleID, PinnedRevision: value.PinnedRevision,
		CurrentProviderID: providerID, CurrentProviderKind: value.CurrentProviderKind,
		CurrentRevision: value.CurrentRevision, CurrentLevel: level, Enabled: *value.Enabled, RetiredAt: retiredAt,
	}, nil
}

func platformOIDCDirectPolicyPinFromWire(
	value platformOIDCDirectPolicyPinWire,
) (platformoidcauth.DirectSessionPolicyPin, error) {
	identifier, err := platformOIDCDirectSessionUUID(value.ID)
	if err != nil || !platformOIDCDirectSessionRevision(value.Revision) {
		return platformoidcauth.DirectSessionPolicyPin{}, errFederatedAuthPersistence
	}
	return platformoidcauth.DirectSessionPolicyPin{
		Kind: platformoidcauth.DirectSessionPolicyKind(value.Kind), ID: identifier, Revision: value.Revision,
	}, nil
}

func platformOIDCDirectSessionMutationToWire(
	value platformoidcauth.DirectSessionRevalidationMutation,
) (platformOIDCDirectSessionMutationWire, error) {
	if !platformOIDCDirectUUIDv7(value.SessionID) || value.ExpectedVersion < 1 ||
		value.ExpectedVersion >= 2_147_483_647 || !validFederatedDatabaseTime(value.ObservedAt) ||
		value.RequestDigest == (platformoidcauth.DirectSessionRevalidationRequestDigest{}) ||
		!platformOIDCDirectSessionDecisionReason(value.Decision, value.Reason) ||
		value.RequestDigest != platformOIDCDirectSessionMutationDigest(value) {
		return platformOIDCDirectSessionMutationWire{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectSessionMutationWire{
		SessionID: value.SessionID.String(), ExpectedVersion: value.ExpectedVersion,
		RequestDigest: append([]byte(nil), value.RequestDigest[:]...), Decision: string(value.Decision),
		Reason: string(value.Reason), ObservedAt: value.ObservedAt,
	}, nil
}

func platformOIDCDirectSessionMutationResultFromWire(
	value platformOIDCDirectSessionMutationResultWire,
	wanted platformOIDCDirectSessionMutationWire,
) (platformoidcauth.DirectSessionRevalidationMutationResult, error) {
	if value.Applied == nil || value.Decision != wanted.Decision || value.ExpectedVersion != wanted.ExpectedVersion {
		return platformoidcauth.DirectSessionRevalidationMutationResult{}, errFederatedAuthPersistence
	}
	if !*value.Applied {
		if value.Category != "stale" || value.NewVersion != 0 || value.SessionID != wanted.SessionID {
			return platformoidcauth.DirectSessionRevalidationMutationResult{}, errFederatedAuthPersistence
		}
		if value.UserID != "" {
			if _, err := platformOIDCDirectSessionUUID(value.UserID); err != nil {
				return platformoidcauth.DirectSessionRevalidationMutationResult{}, errFederatedAuthPersistence
			}
		}
		return platformoidcauth.DirectSessionRevalidationMutationResult{}, nil
	}
	sessionID, err := platformOIDCDirectSessionUUID(value.SessionID)
	userID, userErr := platformOIDCDirectSessionUUID(value.UserID)
	decision := platformoidcauth.DirectSessionRevalidationDecision(value.Decision)
	if err != nil || userErr != nil || sessionID.String() != wanted.SessionID || value.Category != "" ||
		(decision == platformoidcauth.DirectSessionRevalidationUsable && value.NewVersion != wanted.ExpectedVersion+1) ||
		(decision == platformoidcauth.DirectSessionRevalidationRevoke && value.NewVersion != 0) {
		return platformoidcauth.DirectSessionRevalidationMutationResult{}, errFederatedAuthPersistence
	}
	return platformoidcauth.DirectSessionRevalidationMutationResult{
		Applied: true, SessionID: sessionID, UserID: userID, ExpectedVersion: value.ExpectedVersion,
		NewVersion: value.NewVersion, Decision: decision,
	}, nil
}

func platformOIDCDirectSessionDecisionReason(
	decision platformoidcauth.DirectSessionRevalidationDecision,
	reason platformoidcauth.DirectSessionRevalidationReason,
) bool {
	if decision == platformoidcauth.DirectSessionRevalidationUsable {
		return reason == platformoidcauth.DirectSessionReasonCurrent
	}
	if decision != platformoidcauth.DirectSessionRevalidationRevoke {
		return false
	}
	switch reason {
	case platformoidcauth.DirectSessionReasonExpired, platformoidcauth.DirectSessionReasonLifecycle,
		platformoidcauth.DirectSessionReasonPrimaryDrift, platformoidcauth.DirectSessionReasonFactorDrift,
		platformoidcauth.DirectSessionReasonTrustDrift:
		return true
	default:
		return false
	}
}

func platformOIDCDirectSessionMutationDigest(
	value platformoidcauth.DirectSessionRevalidationMutation,
) platformoidcauth.DirectSessionRevalidationRequestDigest {
	digest := sha256.New()
	platformOIDCDirectWriteSessionDigestField(digest, []byte(platformOIDCDirectSessionDigestDomain))
	platformOIDCDirectWriteSessionDigestField(digest, value.SessionID[:])
	platformOIDCDirectWriteSessionDigestField(digest, []byte(value.Decision))
	platformOIDCDirectWriteSessionDigestField(digest, []byte(value.Reason))
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], uint64(value.ExpectedVersion))
	platformOIDCDirectWriteSessionDigestField(digest, number[:])
	binary.BigEndian.PutUint64(number[:], uint64(value.ObservedAt.UnixMicro()))
	platformOIDCDirectWriteSessionDigestField(digest, number[:])
	var result platformoidcauth.DirectSessionRevalidationRequestDigest
	copy(result[:], digest.Sum(nil))
	return result
}

func platformOIDCDirectWriteSessionDigestField(writer interface{ Write([]byte) (int, error) }, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func platformOIDCDirectSessionUUID(value string) (uuid.UUID, error) {
	identifier, err := uuid.Parse(value)
	if err != nil || !platformOIDCDirectUUIDv7(identifier) {
		return uuid.Nil, errFederatedAuthPersistence
	}
	return identifier, nil
}

func platformOIDCDirectOptionalUUIDString(value string) (uuid.UUID, error) {
	if value == "" {
		return uuid.Nil, nil
	}
	return platformOIDCDirectSessionUUID(value)
}

func platformOIDCDirectNullableUUID(value json.RawMessage) (*uuid.UUID, error) {
	if len(value) == 0 {
		return nil, errFederatedAuthPersistence
	}
	if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return nil, nil
	}
	var encoded string
	if err := json.Unmarshal(value, &encoded); err != nil {
		return nil, errFederatedAuthPersistence
	}
	identifier, err := platformOIDCDirectSessionUUID(encoded)
	if err != nil {
		return nil, errFederatedAuthPersistence
	}
	return &identifier, nil
}

func platformOIDCDirectNullableRevision(value json.RawMessage) (*int64, error) {
	if len(value) == 0 {
		return nil, errFederatedAuthPersistence
	}
	if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return nil, nil
	}
	var revision int64
	if err := json.Unmarshal(value, &revision); err != nil || !platformOIDCDirectSessionRevision(revision) {
		return nil, errFederatedAuthPersistence
	}
	return &revision, nil
}

func platformOIDCDirectNullableTime(value json.RawMessage) (*time.Time, error) {
	if len(value) == 0 {
		return nil, errFederatedAuthPersistence
	}
	if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return nil, nil
	}
	var instant time.Time
	if err := json.Unmarshal(value, &instant); err != nil {
		return nil, errFederatedAuthPersistence
	}
	canonical, ok := canonicalFederatedDatabaseTimeFromWire(instant)
	if !ok {
		return nil, errFederatedAuthPersistence
	}
	return &canonical, nil
}

func platformOIDCDirectExactRevisionWireValid(value platformOIDCDirectExactRevisionWire) bool {
	return platformOIDCDirectSessionRevision(value.Pinned) && platformOIDCDirectSessionRevision(value.Current)
}

func platformOIDCDirectExactRevisionFromWire(
	value platformOIDCDirectExactRevisionWire,
) platformoidcauth.ExactRevision {
	return platformoidcauth.ExactRevision{Pinned: value.Pinned, Current: value.Current}
}

func platformOIDCDirectSessionRevision(value int64) bool {
	return value > 0 && value <= maximumMFAJSONSafeInteger
}

func clearPlatformOIDCDirectSessionMutationWire(value *platformOIDCDirectSessionMutationWire) {
	if value == nil {
		return
	}
	clear(value.RequestDigest)
	*value = platformOIDCDirectSessionMutationWire{}
}
