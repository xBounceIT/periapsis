package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
)

const (
	createWebAuthnCeremonySQL           = `select app.create_webauthn_ceremony_v1($1::jsonb)`
	claimWebAuthnCeremonySQL            = `select app.claim_webauthn_ceremony_v2($1::bytea, $2::bytea, $3::timestamptz, $4::bytea)`
	failWebAuthnCeremonySQL             = `select app.fail_webauthn_ceremony_v1($1::bytea, $2::bigint, $3::text, $4::text, $5::timestamptz)`
	loadWebAuthnCredentialSQL           = `select app.load_webauthn_credential_v1($1::uuid, $2::bytea, $3::bytea, $4::boolean)`
	completeMFAPasskeyRegistrationSQL   = `select app.complete_mfa_passkey_registration_v1($1::jsonb)`
	completeMFAPasskeyAuthenticationSQL = `select app.complete_mfa_passkey_authentication_v1($1::jsonb)`
)

// WebAuthnRepository combines the read-only verifier projection with narrow
// protected completion functions. It never parses or verifies WebAuthn
// cryptography; that remains in the maintained identity library adapter.
type WebAuthnRepository struct {
	queryer mfaQueryer
}

var (
	_ webauthn.CeremonyRepository         = (*WebAuthnRepository)(nil)
	_ webauthn.CredentialLookupRepository = (*WebAuthnRepository)(nil)
	_ mfaauth.PasskeyTransaction          = (*WebAuthnRepository)(nil)
)

func NewWebAuthnRepository(pool *pgxpool.Pool) *WebAuthnRepository {
	return &WebAuthnRepository{queryer: pool}
}

type webauthnCeremonyWire struct {
	ID                   []byte              `json:"id"`
	ChallengeDigest      []byte              `json:"challengeDigest"`
	BrowserDigest        []byte              `json:"browserDigest"`
	RP                   relyingPartyWire    `json:"relyingParty"`
	Binding              webauthnBindingWire `json:"binding"`
	Policy               ceremonyPolicyWire  `json:"policy"`
	Mode                 string              `json:"mode,omitempty"`
	UserHandleDigest     []byte              `json:"userHandleDigest,omitempty"`
	AllowedCredentialIDs [][]byte            `json:"allowedCredentialIds"`
	CreatedAt            time.Time           `json:"createdAt"`
	ExpiresAt            time.Time           `json:"expiresAt"`
	State                string              `json:"state"`
	Version              int64               `json:"version"`
	ClaimedAt            *time.Time          `json:"claimedAt,omitempty"`
}

func (repository *WebAuthnRepository) Create(ctx context.Context, value webauthn.PendingCeremony) error {
	if repository == nil || repository.queryer == nil {
		return errMFAPersistence
	}
	wire, err := webauthnCeremonyToWire(value)
	if err != nil {
		return errMFAPersistence
	}
	payload, err := marshalMFAWire(wire)
	if err != nil {
		return errMFAPersistence
	}
	defer clear(payload)
	var created bool
	if err := repository.queryer.QueryRow(ctx, createWebAuthnCeremonySQL, payload).Scan(&created); err != nil || !created {
		return errMFAPersistence
	}
	return nil
}

func (repository *WebAuthnRepository) Claim(
	ctx context.Context,
	claim webauthn.CeremonyClaim,
) (webauthn.ClaimedCeremony, error) {
	if repository == nil || repository.queryer == nil || claim.ID == (webauthn.CeremonyID{}) {
		return webauthn.ClaimedCeremony{}, errMFAPersistence
	}
	var raw []byte
	if err := repository.queryer.QueryRow(
		ctx, claimWebAuthnCeremonySQL, claim.ID[:], claim.BrowserDigest[:], databaseTime(claim.ClaimedAt),
		digestArgument(claim.ContinuationReceiptDigest),
	).Scan(&raw); err != nil {
		return webauthn.ClaimedCeremony{}, errMFAPersistence
	}
	defer clear(raw)
	var wire webauthnCeremonyWire
	if err := unmarshalMFAWire(raw, &wire); err != nil || wire.ClaimedAt == nil {
		return webauthn.ClaimedCeremony{}, errMFAPersistence
	}
	pending, err := webauthnCeremonyFromWire(wire)
	if err != nil {
		return webauthn.ClaimedCeremony{}, errMFAPersistence
	}
	return webauthn.ClaimedCeremony{PendingCeremony: pending, ClaimedAt: wire.ClaimedAt.UTC()}, nil
}

func (repository *WebAuthnRepository) Fail(ctx context.Context, value webauthn.CeremonyFailure) error {
	if repository == nil || repository.queryer == nil || value.ID == (webauthn.CeremonyID{}) || value.ExpectedVersion < 1 {
		return errMFAPersistence
	}
	state, err := webauthnStateToWire(value.State)
	if err != nil || state != "failed" && state != "expired" {
		return errMFAPersistence
	}
	reason, err := webauthnFailureToWire(value.Reason)
	if err != nil {
		return errMFAPersistence
	}
	var applied bool
	if err := repository.queryer.QueryRow(
		ctx, failWebAuthnCeremonySQL, value.ID[:], int64(value.ExpectedVersion), state, reason,
		databaseTime(value.FailedAt),
	).Scan(&applied); err != nil || !applied {
		return errMFAPersistence
	}
	return nil
}

type webauthnCredentialWire struct {
	ID               []byte   `json:"id"`
	PublicKey        []byte   `json:"publicKey"`
	TenantID         string   `json:"tenantId"`
	UserID           string   `json:"userId"`
	IdentityEpoch    int64    `json:"identityEpoch"`
	UserHandleDigest []byte   `json:"userHandleDigest"`
	RPID             string   `json:"rpId"`
	RPRevision       int64    `json:"rpRevision"`
	Version          int64    `json:"version"`
	SecurityRevision int64    `json:"securityRevision"`
	Status           string   `json:"status"`
	SignCount        int64    `json:"signCount"`
	Discoverable     bool     `json:"discoverable"`
	UserVerification bool     `json:"userVerification"`
	BackupEligible   bool     `json:"backupEligible"`
	BackedUp         bool     `json:"backedUp"`
	Transports       []string `json:"transports"`
}

func (repository *WebAuthnRepository) LoadForAuthentication(
	ctx context.Context,
	lookup webauthn.CredentialLookup,
) (webauthn.Credential, error) {
	if repository == nil || repository.queryer == nil {
		return webauthn.Credential{}, errMFAPersistence
	}
	var raw []byte
	if err := repository.queryer.QueryRow(
		ctx, loadWebAuthnCredentialSQL, entityIDWire(lookup.TenantID), lookup.CredentialID,
		lookup.UserHandle, lookup.Discoverable,
	).Scan(&raw); err != nil {
		return webauthn.Credential{}, errMFAPersistence
	}
	defer clear(raw)
	var wire webauthnCredentialWire
	if err := unmarshalMFAWire(raw, &wire); err != nil {
		return webauthn.Credential{}, errMFAPersistence
	}
	credential, err := webauthnCredentialFromWire(wire)
	if err != nil || credential.TenantID != lookup.TenantID ||
		!bytes.Equal(credential.ID, lookup.CredentialID) {
		return webauthn.Credential{}, errMFAPersistence
	}
	return credential, nil
}

type auditIntentWire struct {
	Kind            string               `json:"kind"`
	TenantID        string               `json:"tenantId"`
	UserID          string               `json:"userId"`
	Action          string               `json:"action"`
	OccurredAt      time.Time            `json:"occurredAt"`
	PolicyRevisions []policyRevisionWire `json:"policyRevisions"`
}

type sessionIntentWire struct {
	Mutation                  string                   `json:"mutation"`
	ExpectedSessionID         string                   `json:"expectedSessionId,omitempty"`
	ExpectedFamilyID          string                   `json:"expectedFamilyId,omitempty"`
	ExpectedContinuationID    string                   `json:"expectedContinuationId,omitempty"`
	ExpectedAnchorVersion     int64                    `json:"expectedAnchorVersion"`
	ExpectedIdentityEpoch     int64                    `json:"expectedIdentityEpoch"`
	ExpectedAnchorExpiry      *time.Time               `json:"expectedAnchorExpiry"`
	Audience                  string                   `json:"audience"`
	Requirement               assuranceRequirementWire `json:"requirement"`
	RecoveryRestricted        bool                     `json:"recoveryRestricted"`
	Reservation               *sessionReservationWire  `json:"reservation,omitempty"`
	ContinuationReceiptDigest []byte                   `json:"continuationReceiptDigest,omitempty"`
}

type sessionReservationWire struct {
	SessionID            string    `json:"sessionId"`
	FamilyID             string    `json:"familyId"`
	TokenDigest          []byte    `json:"tokenDigest"`
	CSRFDigest           []byte    `json:"csrfDigest"`
	AuthenticationMethod string    `json:"authenticationMethod"`
	IdleExpiresAt        time.Time `json:"idleExpiresAt"`
	AbsoluteExpiresAt    time.Time `json:"absoluteExpiresAt"`
}

type passkeyRegistrationApplyWire struct {
	Completion  registrationCompletionWire `json:"completion"`
	DisplayName string                     `json:"displayName"`
	Audit       auditIntentWire            `json:"audit"`
	Session     sessionIntentWire          `json:"session"`
}

type passkeyAuthenticationApplyWire struct {
	Completion authenticationCompletionWire `json:"completion"`
	Audit      auditIntentWire              `json:"audit"`
	Session    sessionIntentWire            `json:"session"`
}

func (repository *WebAuthnRepository) CompletePasskeyRegistration(
	ctx context.Context,
	value mfaauth.PasskeyRegistrationApply,
) (mfaauth.PasskeyRegistrationApplyResult, error) {
	if repository == nil {
		return mfaauth.PasskeyRegistrationApplyResult{}, errMFAPersistence
	}
	completion, err := registrationCompletionToWire(value.Completion)
	if err != nil {
		return mfaauth.PasskeyRegistrationApplyResult{}, errMFAPersistence
	}
	audit, err := auditIntentToWire(value.Audit)
	if err != nil {
		return mfaauth.PasskeyRegistrationApplyResult{}, errMFAPersistence
	}
	session, err := sessionIntentToWire(value.Session, value.Completion.CompletedAt)
	if err != nil {
		return mfaauth.PasskeyRegistrationApplyResult{}, errMFAPersistence
	}
	var result passkeyRegistrationResultWire
	if err := queryMFAJSON(ctx, repository.queryer, completeMFAPasskeyRegistrationSQL, passkeyRegistrationApplyWire{
		Completion: completion, DisplayName: value.DisplayName, Audit: audit, Session: session,
	}, &result); err != nil {
		return mfaauth.PasskeyRegistrationApplyResult{}, err
	}
	return passkeyRegistrationResultFromWire(result)
}

func (repository *WebAuthnRepository) CompletePasskeyAuthentication(
	ctx context.Context,
	value mfaauth.PasskeyAuthenticationApply,
) (mfaauth.PasskeyAuthenticationApplyResult, error) {
	if repository == nil {
		return mfaauth.PasskeyAuthenticationApplyResult{}, errMFAPersistence
	}
	completion, err := authenticationCompletionToWire(value.Completion)
	if err != nil {
		return mfaauth.PasskeyAuthenticationApplyResult{}, errMFAPersistence
	}
	audit, err := auditIntentToWire(value.Audit)
	if err != nil {
		return mfaauth.PasskeyAuthenticationApplyResult{}, errMFAPersistence
	}
	session, err := sessionIntentToWire(value.Session, value.Completion.CompletedAt)
	if err != nil {
		return mfaauth.PasskeyAuthenticationApplyResult{}, errMFAPersistence
	}
	var result passkeyAuthenticationResultWire
	if err := queryMFAJSON(ctx, repository.queryer, completeMFAPasskeyAuthenticationSQL, passkeyAuthenticationApplyWire{
		Completion: completion, Audit: audit, Session: session,
	}, &result); err != nil {
		return mfaauth.PasskeyAuthenticationApplyResult{}, err
	}
	return passkeyAuthenticationResultFromWire(result)
}

type registrationCompletionWire struct {
	CeremonyID              []byte                 `json:"ceremonyId"`
	ExpectedCeremonyVersion int64                  `json:"expectedCeremonyVersion"`
	Binding                 webauthnBindingWire    `json:"binding"`
	CompletedAt             time.Time              `json:"completedAt"`
	Credential              webauthnCredentialWire `json:"credential"`
	AAGUID                  []byte                 `json:"aaguid"`
	AttestationFormat       string                 `json:"attestationFormat"`
	AttestationType         string                 `json:"attestationType"`
	AttestationTrusted      bool                   `json:"attestationTrusted"`
	MetadataRevision        int64                  `json:"metadataRevision"`
}

type authenticationCompletionWire struct {
	CeremonyID                []byte              `json:"ceremonyId"`
	ExpectedCeremonyVersion   int64               `json:"expectedCeremonyVersion"`
	Binding                   webauthnBindingWire `json:"binding"`
	ResolvedUserID            string              `json:"resolvedUserId"`
	ExpectedIdentityEpoch     int64               `json:"expectedIdentityEpoch"`
	CredentialID              []byte              `json:"credentialId"`
	ExpectedCredentialVersion int64               `json:"expectedCredentialVersion"`
	CompletedAt               time.Time           `json:"completedAt"`
	ExpectedSignCount         int64               `json:"expectedSignCount"`
	ObservedSignCount         int64               `json:"observedSignCount"`
	ExpectedBackedUp          bool                `json:"expectedBackedUp"`
	CounterDisposition        string              `json:"counterDisposition"`
	UserVerified              bool                `json:"userVerified"`
	BackupEligible            bool                `json:"backupEligible"`
	BackedUp                  bool                `json:"backedUp"`
}

type webauthnAuthenticationResultWire struct {
	CredentialVersion int64  `json:"credentialVersion"`
	SecurityRevision  int64  `json:"securityRevision"`
	Status            string `json:"status"`
	SignCount         int64  `json:"signCount"`
	BackupEligible    bool   `json:"backupEligible"`
	BackedUp          bool   `json:"backedUp"`
}

type passkeyRegistrationResultWire struct {
	Outcome                string                 `json:"outcome"`
	Credential             webauthnCredentialWire `json:"credential"`
	AuditID                string                 `json:"auditId"`
	Mutation               string                 `json:"mutation"`
	NewSessionID           string                 `json:"newSessionId,omitempty"`
	NewSessionFamilyID     string                 `json:"newSessionFamilyId,omitempty"`
	RetainedContinuationID string                 `json:"retainedContinuationId,omitempty"`
	SessionVersion         int64                  `json:"sessionVersion"`
	RecoveryRestricted     bool                   `json:"recoveryRestricted"`
}

type passkeyAuthenticationResultWire struct {
	Outcome                string                           `json:"outcome"`
	Credential             webauthnAuthenticationResultWire `json:"credential"`
	TenantID               string                           `json:"tenantId"`
	UserID                 string                           `json:"userId"`
	IdentityEpoch          int64                            `json:"identityEpoch"`
	AuditID                string                           `json:"auditId"`
	Mutation               string                           `json:"mutation"`
	NewSessionID           string                           `json:"newSessionId,omitempty"`
	NewSessionFamilyID     string                           `json:"newSessionFamilyId,omitempty"`
	ConsumedContinuationID string                           `json:"consumedContinuationId,omitempty"`
	RevokedAnchorID        string                           `json:"revokedAnchorId,omitempty"`
	SessionVersion         int64                            `json:"sessionVersion"`
	RecoveryRestricted     bool                             `json:"recoveryRestricted"`
}

func webauthnCeremonyToWire(value webauthn.PendingCeremony) (webauthnCeremonyWire, error) {
	rp, err := rpToWire(value.RP)
	if err != nil {
		return webauthnCeremonyWire{}, err
	}
	binding, err := webauthnBindingToWire(value.Binding)
	if err != nil {
		return webauthnCeremonyWire{}, err
	}
	policy, err := ceremonyPolicyToWire(value.Policy)
	if err != nil || value.Version > uint64(maximumMFAJSONSafeInteger) {
		return webauthnCeremonyWire{}, errInvalidMFAWire
	}
	mode, err := authenticationModeToWire(value.Mode, value.Binding.Purpose == webauthn.PurposeRegistration)
	if err != nil {
		return webauthnCeremonyWire{}, err
	}
	state, err := webauthnStateToWire(value.State)
	if err != nil {
		return webauthnCeremonyWire{}, err
	}
	return webauthnCeremonyWire{
		ID: append([]byte(nil), value.ID[:]...), ChallengeDigest: append([]byte(nil), value.ChallengeDigest[:]...),
		BrowserDigest: append([]byte(nil), value.BrowserDigest[:]...), RP: rp, Binding: binding, Policy: policy,
		Mode: mode, UserHandleDigest: append([]byte(nil), value.UserHandleDigest[:]...),
		AllowedCredentialIDs: cloneWireBytes2D(value.AllowedCredentialIDs), CreatedAt: value.CreatedAt,
		ExpiresAt: value.ExpiresAt, State: state, Version: int64(value.Version),
	}, nil
}

func webauthnCeremonyFromWire(value webauthnCeremonyWire) (webauthn.PendingCeremony, error) {
	if len(value.ID) != len(webauthn.CeremonyID{}) || len(value.ChallengeDigest) != sha256.Size ||
		len(value.BrowserDigest) != sha256.Size || value.Version < 1 || value.Version > maximumMFAJSONSafeInteger {
		return webauthn.PendingCeremony{}, errInvalidMFAWire
	}
	var identifier webauthn.CeremonyID
	copy(identifier[:], value.ID)
	var challengeDigest, browserDigest, userHandleDigest [sha256.Size]byte
	copy(challengeDigest[:], value.ChallengeDigest)
	copy(browserDigest[:], value.BrowserDigest)
	if len(value.UserHandleDigest) != 0 && len(value.UserHandleDigest) != sha256.Size {
		return webauthn.PendingCeremony{}, errInvalidMFAWire
	}
	copy(userHandleDigest[:], value.UserHandleDigest)
	rp, err := rpFromWire(value.RP)
	if err != nil {
		return webauthn.PendingCeremony{}, err
	}
	binding, err := webauthnBindingFromWire(value.Binding)
	if err != nil {
		return webauthn.PendingCeremony{}, err
	}
	policy, err := ceremonyPolicyFromWire(value.Policy)
	if err != nil {
		return webauthn.PendingCeremony{}, err
	}
	mode, err := authenticationModeFromWire(value.Mode, binding.Purpose == webauthn.PurposeRegistration)
	if err != nil {
		return webauthn.PendingCeremony{}, err
	}
	state, err := webauthnStateFromWire(value.State)
	if err != nil {
		return webauthn.PendingCeremony{}, err
	}
	return webauthn.PendingCeremony{
		ID: identifier, ChallengeDigest: challengeDigest, BrowserDigest: browserDigest,
		RP: rp, Binding: binding, Policy: policy, Mode: mode, UserHandleDigest: userHandleDigest,
		AllowedCredentialIDs: cloneWireBytes2D(value.AllowedCredentialIDs), CreatedAt: value.CreatedAt.UTC(),
		ExpiresAt: value.ExpiresAt.UTC(), State: state, Version: uint64(value.Version),
	}, nil
}

func webauthnCredentialToWire(value webauthn.Credential) (webauthnCredentialWire, error) {
	status, err := webauthnCredentialStatusToWire(value.Status)
	if err != nil || value.IdentityEpoch < 1 || value.IdentityEpoch > uint64(maximumMFAJSONSafeInteger) ||
		value.RPRevision < 1 || value.RPRevision > uint64(maximumMFAJSONSafeInteger) ||
		value.Version > uint64(maximumMFAJSONSafeInteger) ||
		value.SecurityRevision < 1 || value.SecurityRevision > value.Version {
		return webauthnCredentialWire{}, errInvalidMFAWire
	}
	transports := make([]string, len(value.Transports))
	for index, transport := range value.Transports {
		mapped, mapErr := transportToWire(transport)
		if mapErr != nil {
			return webauthnCredentialWire{}, mapErr
		}
		transports[index] = mapped
	}
	return webauthnCredentialWire{
		ID: append([]byte(nil), value.ID...), PublicKey: append([]byte(nil), value.PublicKey...),
		TenantID: entityIDWire(value.TenantID), UserID: entityIDWire(value.UserID), IdentityEpoch: int64(value.IdentityEpoch),
		UserHandleDigest: append([]byte(nil), value.UserHandleDigest[:]...), RPID: value.RPID,
		RPRevision: int64(value.RPRevision), Version: int64(value.Version),
		SecurityRevision: int64(value.SecurityRevision), Status: status,
		SignCount: int64(value.SignCount), Discoverable: value.Discoverable, UserVerification: value.UserVerification,
		BackupEligible: value.BackupEligible, BackedUp: value.BackedUp, Transports: transports,
	}, nil
}

func webauthnCredentialFromWire(value webauthnCredentialWire) (webauthn.Credential, error) {
	if len(value.UserHandleDigest) != sha256.Size || value.IdentityEpoch < 1 ||
		value.IdentityEpoch > maximumMFAJSONSafeInteger || value.RPRevision < 1 ||
		value.RPRevision > maximumMFAJSONSafeInteger ||
		value.Version < 1 || value.Version > maximumMFAJSONSafeInteger || value.SecurityRevision < 1 ||
		value.SecurityRevision > value.Version || value.SignCount < 0 || value.SignCount > 1<<32-1 {
		return webauthn.Credential{}, errMFAPersistence
	}
	tenantID, err := parseEntityIDWire(value.TenantID, false)
	if err != nil {
		return webauthn.Credential{}, errMFAPersistence
	}
	userID, err := parseEntityIDWire(value.UserID, false)
	if err != nil {
		return webauthn.Credential{}, errMFAPersistence
	}
	status, err := webauthnCredentialStatusFromWire(value.Status)
	if err != nil {
		return webauthn.Credential{}, errMFAPersistence
	}
	transports := make([]webauthn.CredentialTransport, len(value.Transports))
	for index, transport := range value.Transports {
		mapped, mapErr := transportFromWire(transport)
		if mapErr != nil {
			return webauthn.Credential{}, errMFAPersistence
		}
		transports[index] = mapped
	}
	var userHandleDigest [sha256.Size]byte
	copy(userHandleDigest[:], value.UserHandleDigest)
	return webauthn.Credential{
		ID: append([]byte(nil), value.ID...), PublicKey: append([]byte(nil), value.PublicKey...),
		TenantID: tenantID, UserID: userID, IdentityEpoch: uint64(value.IdentityEpoch),
		UserHandleDigest: userHandleDigest, RPID: value.RPID, RPRevision: uint64(value.RPRevision),
		Version: uint64(value.Version), SecurityRevision: uint64(value.SecurityRevision),
		Status: status, SignCount: uint32(value.SignCount),
		Discoverable: value.Discoverable, UserVerification: value.UserVerification,
		BackupEligible: value.BackupEligible, BackedUp: value.BackedUp, Transports: transports,
	}, nil
}

func registrationCompletionToWire(value webauthn.RegistrationCompletion) (registrationCompletionWire, error) {
	if value.ExpectedCeremonyVersion < 1 || value.ExpectedCeremonyVersion >= uint64(maximumMFAJSONSafeInteger) ||
		value.MetadataRevision > uint64(maximumMFAJSONSafeInteger) || value.Credential.SecurityRevision != 1 {
		return registrationCompletionWire{}, errInvalidMFAWire
	}
	binding, err := webauthnBindingToWire(value.Binding)
	if err != nil {
		return registrationCompletionWire{}, err
	}
	credential, err := webauthnCredentialToWire(value.Credential)
	if err != nil {
		return registrationCompletionWire{}, err
	}
	attestation, err := attestationTypeToWire(value.AttestationType)
	if err != nil {
		return registrationCompletionWire{}, err
	}
	return registrationCompletionWire{
		CeremonyID: append([]byte(nil), value.CeremonyID[:]...), ExpectedCeremonyVersion: int64(value.ExpectedCeremonyVersion),
		Binding: binding, CompletedAt: value.CompletedAt, Credential: credential,
		AAGUID: append([]byte(nil), value.AAGUID[:]...), AttestationFormat: value.AttestationFormat,
		AttestationType: attestation, AttestationTrusted: value.AttestationTrusted,
		MetadataRevision: int64(value.MetadataRevision),
	}, nil
}

func authenticationCompletionToWire(value webauthn.AuthenticationCompletion) (authenticationCompletionWire, error) {
	if value.ExpectedCeremonyVersion < 1 || value.ExpectedCeremonyVersion >= uint64(maximumMFAJSONSafeInteger) ||
		value.ExpectedCredentialVersion < 1 || value.ExpectedCredentialVersion >= uint64(maximumMFAJSONSafeInteger) ||
		!validWebAuthnSecurityTransition(value) {
		return authenticationCompletionWire{}, errInvalidMFAWire
	}
	binding, err := webauthnBindingToWire(value.Binding)
	if err != nil {
		return authenticationCompletionWire{}, err
	}
	disposition, err := counterDispositionToWire(value.CounterDisposition)
	if err != nil {
		return authenticationCompletionWire{}, err
	}
	return authenticationCompletionWire{
		CeremonyID: append([]byte(nil), value.CeremonyID[:]...), ExpectedCeremonyVersion: int64(value.ExpectedCeremonyVersion),
		Binding: binding, ResolvedUserID: entityIDWire(value.ResolvedUserID),
		ExpectedIdentityEpoch: int64(value.ExpectedIdentityEpoch), CredentialID: append([]byte(nil), value.CredentialID...),
		ExpectedCredentialVersion: int64(value.ExpectedCredentialVersion), CompletedAt: value.CompletedAt,
		ExpectedSignCount: int64(value.ExpectedSignCount), ObservedSignCount: int64(value.ObservedSignCount),
		ExpectedBackedUp: value.ExpectedBackedUp, CounterDisposition: disposition, UserVerified: value.UserVerified,
		BackupEligible: value.BackupEligible, BackedUp: value.BackedUp,
	}, nil
}

func validWebAuthnSecurityTransition(value webauthn.AuthenticationCompletion) bool {
	if value.ExpectedSecurityRevision < 1 || value.ExpectedSecurityRevision > value.ExpectedCredentialVersion ||
		value.ExpectedBackedUp && !value.ExpectedBackupEligible || value.BackedUp && !value.BackupEligible {
		return false
	}
	next := value.ExpectedSecurityRevision
	if value.CounterDisposition == webauthn.CounterCloneSuspected ||
		value.ExpectedBackupEligible != value.BackupEligible || value.ExpectedBackedUp != value.BackedUp {
		next++
	}
	return next <= uint64(maximumMFAJSONSafeInteger) && next <= value.ExpectedCredentialVersion+1
}

func auditIntentToWire(value mfaauth.AuditIntent) (auditIntentWire, error) {
	revisions := make([]policyRevisionWire, len(value.PolicyRevisions))
	for index, revision := range value.PolicyRevisions {
		if !validMFAJSONRevision(revision.Revision) {
			return auditIntentWire{}, errInvalidMFAWire
		}
		revisions[index] = policyRevisionWire{PolicyID: entityIDWire(revision.PolicyID), Revision: revision.Revision}
	}
	return auditIntentWire{
		Kind: string(value.Kind), TenantID: entityIDWire(value.TenantID), UserID: entityIDWire(value.UserID),
		Action: value.Action, OccurredAt: value.OccurredAt, PolicyRevisions: revisions,
	}, nil
}

func sessionIntentToWire(value mfaauth.SessionIntent, issuedAt time.Time) (sessionIntentWire, error) {
	mutation, err := sessionMutationToWire(value.Mutation)
	if err != nil || value.ExpectedIdentityEpoch > uint64(maximumMFAJSONSafeInteger) ||
		!validMFAJSONRevision(int64(value.ExpectedIdentityEpoch)) ||
		!validSessionIntentAnchorRevision(value) {
		return sessionIntentWire{}, errInvalidMFAWire
	}
	requirement, err := requirementToWire(value.Requirement)
	if err != nil {
		return sessionIntentWire{}, err
	}
	receiptDigest, err := sessionIntentReceiptDigestToWire(value)
	if err != nil {
		return sessionIntentWire{}, err
	}
	reservation, err := sessionReservationToWire(value.Reservation, issuedAt)
	if err != nil {
		return sessionIntentWire{}, err
	}
	var expiry *time.Time
	if !value.ExpectedAnchorExpiry.IsZero() {
		expiry = copyTimePointer(&value.ExpectedAnchorExpiry)
	}
	return sessionIntentWire{
		Mutation: mutation, ExpectedSessionID: entityIDWire(value.ExpectedSessionID),
		ExpectedFamilyID: entityIDWire(value.ExpectedFamilyID), ExpectedContinuationID: entityIDWire(value.ExpectedContinuationID),
		ExpectedAnchorVersion: int64(value.ExpectedAnchorVersion), ExpectedIdentityEpoch: int64(value.ExpectedIdentityEpoch),
		ExpectedAnchorExpiry: expiry, Audience: value.Audience, Requirement: requirement,
		RecoveryRestricted:        value.RecoveryRestricted,
		Reservation:               reservation,
		ContinuationReceiptDigest: receiptDigest,
	}, nil
}

func validSessionIntentAnchorRevision(value mfaauth.SessionIntent) bool {
	if value.Mutation == mfaauth.SessionCreate {
		return value.ExpectedAnchorVersion == 0
	}
	return value.ExpectedAnchorVersion <= uint64(maximumMFAJSONSafeInteger) &&
		validMFAJSONSuccessorRevision(int64(value.ExpectedAnchorVersion))
}

func sessionIntentReceiptDigestToWire(value mfaauth.SessionIntent) ([]byte, error) {
	digest := value.ContinuationReceiptDigest
	zero := [32]byte{}
	requiresReceipt := value.Mutation == mfaauth.SessionConsumeContinuation ||
		value.Mutation == mfaauth.SessionRetainContinuation ||
		value.Mutation == mfaauth.SessionRevoke && value.ExpectedContinuationID != (identity.EntityID{})
	if requiresReceipt {
		if digest == zero {
			return nil, errInvalidMFAWire
		}
		return append([]byte(nil), digest[:]...), nil
	}
	if digest != zero {
		return nil, errInvalidMFAWire
	}
	return nil, nil
}

func sessionReservationToWire(
	value mfa.SessionReservation,
	issuedAt time.Time,
) (*sessionReservationWire, error) {
	if value.IsZero() {
		return nil, nil
	}
	if !value.ValidAt(issuedAt) {
		return nil, errInvalidMFAWire
	}
	tokenDigest := value.TokenDigest()
	csrfDigest := value.CSRFDigest()
	return &sessionReservationWire{
		SessionID: entityIDWire(value.SessionID()), FamilyID: entityIDWire(value.FamilyID()),
		TokenDigest: append([]byte(nil), tokenDigest[:]...), CSRFDigest: append([]byte(nil), csrfDigest[:]...),
		AuthenticationMethod: string(value.AuthenticationMethod()),
		IdleExpiresAt:        value.IdleExpiresAt(), AbsoluteExpiresAt: value.AbsoluteExpiresAt(),
	}, nil
}

func webauthnAuthenticationResultFromWire(value webauthnAuthenticationResultWire) (webauthn.AuthenticationApplyResult, error) {
	if value.CredentialVersion < 1 || value.CredentialVersion > maximumMFAJSONSafeInteger ||
		value.SecurityRevision < 1 || value.SecurityRevision > value.CredentialVersion ||
		value.SignCount < 0 || value.SignCount > 1<<32-1 {
		return webauthn.AuthenticationApplyResult{}, errMFAPersistence
	}
	status, err := webauthnCredentialStatusFromWire(value.Status)
	if err != nil {
		return webauthn.AuthenticationApplyResult{}, errMFAPersistence
	}
	return webauthn.AuthenticationApplyResult{
		CredentialVersion: uint64(value.CredentialVersion), SecurityRevision: uint64(value.SecurityRevision),
		Status: status, SignCount: uint32(value.SignCount),
		BackupEligible: value.BackupEligible, BackedUp: value.BackedUp,
	}, nil
}

func passkeyRegistrationResultFromWire(value passkeyRegistrationResultWire) (mfaauth.PasskeyRegistrationApplyResult, error) {
	outcome, err := applyOutcomeFromWire(value.Outcome)
	if err != nil || outcome != mfaauth.ApplyCommitted || value.RecoveryRestricted {
		return mfaauth.PasskeyRegistrationApplyResult{}, errMFAPersistence
	}
	credential, err := webauthnCredentialFromWire(value.Credential)
	if err != nil || credential.Status != webauthn.CredentialActive {
		return mfaauth.PasskeyRegistrationApplyResult{}, errMFAPersistence
	}
	mutation, err := sessionMutationFromWire(value.Mutation)
	if err != nil {
		return mfaauth.PasskeyRegistrationApplyResult{}, errMFAPersistence
	}
	ids, err := parseRegistrationResultIDs(value.AuditID, value.NewSessionID, value.NewSessionFamilyID, value.RetainedContinuationID)
	if err != nil || !validPasskeyRegistrationSessionResult(mutation, ids, value.SessionVersion) {
		return mfaauth.PasskeyRegistrationApplyResult{}, errMFAPersistence
	}
	return mfaauth.PasskeyRegistrationApplyResult{
		Outcome: outcome, Credential: credential, AuditID: ids[0], Mutation: mutation,
		NewSessionID: ids[1], NewSessionFamilyID: ids[2], RetainedContinuationID: ids[3],
		SessionVersion: uint64(value.SessionVersion), RecoveryRestricted: value.RecoveryRestricted,
	}, nil
}

func validPasskeyRegistrationSessionResult(
	mutation mfaauth.SessionMutation,
	ids [4]identity.EntityID,
	sessionVersion int64,
) bool {
	if !validMFAJSONRevision(sessionVersion) {
		return false
	}
	zero := identity.EntityID{}
	switch mutation {
	case mfaauth.SessionRotate:
		return ids[1] != zero && ids[2] != zero && ids[3] == zero
	case mfaauth.SessionRetainContinuation:
		return ids[1] == zero && ids[2] == zero && ids[3] != zero
	default:
		return false
	}
}

func passkeyAuthenticationResultFromWire(value passkeyAuthenticationResultWire) (mfaauth.PasskeyAuthenticationApplyResult, error) {
	outcome, err := applyOutcomeFromWire(value.Outcome)
	if err != nil || outcome != mfaauth.ApplyCommitted || value.RecoveryRestricted {
		return mfaauth.PasskeyAuthenticationApplyResult{}, errMFAPersistence
	}
	credential, err := webauthnAuthenticationResultFromWire(value.Credential)
	if err != nil {
		return mfaauth.PasskeyAuthenticationApplyResult{}, errMFAPersistence
	}
	mutation, err := sessionMutationFromWire(value.Mutation)
	if err != nil {
		return mfaauth.PasskeyAuthenticationApplyResult{}, errMFAPersistence
	}
	ids, err := parseAuthenticationResultIDs(
		value.TenantID, value.UserID, value.AuditID, value.NewSessionID, value.NewSessionFamilyID,
		value.ConsumedContinuationID, value.RevokedAnchorID,
	)
	if err != nil || !validMFAJSONRevision(value.IdentityEpoch) ||
		!validPasskeyAuthenticationSessionResult(mutation, credential.Status, ids, value.SessionVersion) {
		return mfaauth.PasskeyAuthenticationApplyResult{}, errMFAPersistence
	}
	return mfaauth.PasskeyAuthenticationApplyResult{
		Outcome: outcome, Credential: credential, TenantID: ids[0], UserID: ids[1],
		IdentityEpoch: uint64(value.IdentityEpoch), AuditID: ids[2], Mutation: mutation,
		NewSessionID: ids[3], NewSessionFamilyID: ids[4], ConsumedContinuationID: ids[5],
		RevokedAnchorID: ids[6], SessionVersion: uint64(value.SessionVersion),
		RecoveryRestricted: value.RecoveryRestricted,
	}, nil
}

func validPasskeyAuthenticationSessionResult(
	mutation mfaauth.SessionMutation,
	credentialStatus webauthn.CredentialStatus,
	ids [7]identity.EntityID,
	sessionVersion int64,
) bool {
	zero := identity.EntityID{}
	if mutation != mfaauth.SessionRevoke {
		if credentialStatus != webauthn.CredentialActive || ids[6] != zero ||
			!validMFAJSONRevision(sessionVersion) {
			return false
		}
		switch mutation {
		case mfaauth.SessionCreate, mfaauth.SessionRotate:
			return ids[3] != zero && ids[4] != zero && ids[5] == zero
		case mfaauth.SessionConsumeContinuation:
			return ids[3] != zero && ids[4] != zero && ids[5] != zero
		default:
			return false
		}
	}
	if credentialStatus != webauthn.CredentialCloneSuspected ||
		ids[3] != zero || ids[4] != zero || ids[5] != zero {
		return false
	}
	if ids[6] == zero {
		// A clone detected during primary authentication creates no session and
		// has no live anchor to revoke. This is the sole valid zero version.
		return sessionVersion == 0
	}
	return validMFAJSONRevision(sessionVersion)
}

func parseRegistrationResultIDs(values ...string) ([4]identity.EntityID, error) {
	var result [4]identity.EntityID
	for index, value := range values {
		identifier, err := parseEntityIDWire(value, index > 0)
		if err != nil {
			return [4]identity.EntityID{}, err
		}
		result[index] = identifier
	}
	return result, nil
}

func parseAuthenticationResultIDs(values ...string) ([7]identity.EntityID, error) {
	var result [7]identity.EntityID
	for index, value := range values {
		identifier, err := parseEntityIDWire(value, index >= 3)
		if err != nil {
			return [7]identity.EntityID{}, err
		}
		result[index] = identifier
	}
	return result, nil
}

func authenticationModeToWire(value webauthn.AuthenticationMode, registration bool) (string, error) {
	if registration && value == 0 {
		return "", nil
	}
	if value == webauthn.AuthenticationKnownUser {
		return "known_user", nil
	}
	if value == webauthn.AuthenticationDiscoverable {
		return "discoverable", nil
	}
	return "", errInvalidMFAWire
}

func authenticationModeFromWire(value string, registration bool) (webauthn.AuthenticationMode, error) {
	if registration && value == "" {
		return 0, nil
	}
	if value == "known_user" {
		return webauthn.AuthenticationKnownUser, nil
	}
	if value == "discoverable" {
		return webauthn.AuthenticationDiscoverable, nil
	}
	return 0, errInvalidMFAWire
}

func webauthnStateToWire(value webauthn.CeremonyState) (string, error) {
	switch value {
	case webauthn.CeremonyPending:
		return "pending", nil
	case webauthn.CeremonyClaimed:
		return "claimed", nil
	case webauthn.CeremonyCompleted:
		return "completed", nil
	case webauthn.CeremonyFailed:
		return "failed", nil
	case webauthn.CeremonyExpired:
		return "expired", nil
	default:
		return "", errInvalidMFAWire
	}
}

func webauthnStateFromWire(value string) (webauthn.CeremonyState, error) {
	switch value {
	case "pending":
		return webauthn.CeremonyPending, nil
	case "claimed":
		return webauthn.CeremonyClaimed, nil
	case "completed":
		return webauthn.CeremonyCompleted, nil
	case "failed":
		return webauthn.CeremonyFailed, nil
	case "expired":
		return webauthn.CeremonyExpired, nil
	default:
		return 0, errInvalidMFAWire
	}
}

func webauthnFailureToWire(value webauthn.CeremonyFailureReason) (string, error) {
	switch value {
	case webauthn.FailureExpired, webauthn.FailureMalformed, webauthn.FailureVerification, webauthn.FailureCredential:
		return string(value), nil
	default:
		return "", errInvalidMFAWire
	}
}

func webauthnCredentialStatusToWire(value webauthn.CredentialStatus) (string, error) {
	switch value {
	case webauthn.CredentialActive:
		return "active", nil
	case webauthn.CredentialRevoked:
		return "revoked", nil
	case webauthn.CredentialCloneSuspected:
		return "clone_suspected", nil
	default:
		return "", errInvalidMFAWire
	}
}

func webauthnCredentialStatusFromWire(value string) (webauthn.CredentialStatus, error) {
	switch value {
	case "active":
		return webauthn.CredentialActive, nil
	case "revoked":
		return webauthn.CredentialRevoked, nil
	case "clone_suspected":
		return webauthn.CredentialCloneSuspected, nil
	default:
		return 0, errInvalidMFAWire
	}
}

func transportToWire(value webauthn.CredentialTransport) (string, error) {
	switch value {
	case webauthn.TransportUSB, webauthn.TransportNFC, webauthn.TransportBLE, webauthn.TransportInternal,
		webauthn.TransportHybrid, webauthn.TransportSmartCard:
		return string(value), nil
	default:
		return "", errInvalidMFAWire
	}
}

func transportFromWire(value string) (webauthn.CredentialTransport, error) {
	transport := webauthn.CredentialTransport(value)
	if _, err := transportToWire(transport); err != nil {
		return "", err
	}
	return transport, nil
}

func attestationTypeToWire(value webauthn.AttestationType) (string, error) {
	switch value {
	case webauthn.AttestationTypeNone:
		return "none", nil
	case webauthn.AttestationTypeSelf:
		return "self", nil
	case webauthn.AttestationTypeBasic:
		return "basic", nil
	case webauthn.AttestationTypeEnterprise:
		return "enterprise", nil
	default:
		return "", errInvalidMFAWire
	}
}

func counterDispositionToWire(value webauthn.CounterDisposition) (string, error) {
	switch value {
	case webauthn.CounterUnsupported:
		return "unsupported", nil
	case webauthn.CounterAdvance:
		return "advance", nil
	case webauthn.CounterCloneSuspected:
		return "clone_suspected", nil
	default:
		return "", errInvalidMFAWire
	}
}

func sessionMutationToWire(value mfaauth.SessionMutation) (string, error) {
	switch value {
	case mfaauth.SessionCreate:
		return "create", nil
	case mfaauth.SessionRotate:
		return "rotate", nil
	case mfaauth.SessionConsumeContinuation:
		return "consume_continuation", nil
	case mfaauth.SessionRetainContinuation:
		return "retain_continuation", nil
	case mfaauth.SessionRevoke:
		return "revoke", nil
	default:
		return "", errInvalidMFAWire
	}
}

func sessionMutationFromWire(value string) (mfaauth.SessionMutation, error) {
	switch value {
	case "create":
		return mfaauth.SessionCreate, nil
	case "rotate":
		return mfaauth.SessionRotate, nil
	case "consume_continuation":
		return mfaauth.SessionConsumeContinuation, nil
	case "retain_continuation":
		return mfaauth.SessionRetainContinuation, nil
	case "revoke":
		return mfaauth.SessionRevoke, nil
	default:
		return 0, errInvalidMFAWire
	}
}

func applyOutcomeFromWire(value string) (mfaauth.ApplyOutcome, error) {
	switch value {
	case "committed":
		return mfaauth.ApplyCommitted, nil
	case "replay_rejected":
		return mfaauth.ApplyReplayRejected, nil
	case "stale":
		return mfaauth.ApplyStale, nil
	case "denied":
		return mfaauth.ApplyDenied, nil
	default:
		return 0, errInvalidMFAWire
	}
}

func cloneWireBytes2D(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = append([]byte(nil), values[index]...)
	}
	return result
}
