package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
)

const (
	startTOTPEnrollmentSQL    = `select app.start_totp_enrollment_v1($1::jsonb)`
	claimTOTPEnrollmentSQL    = `select app.claim_totp_enrollment_v2($1::uuid, $2::bytea, $3::timestamptz, $4::bytea)`
	completeTOTPEnrollmentSQL = `select app.complete_totp_enrollment_v1($1::jsonb)`
	failTOTPEnrollmentSQL     = `select app.fail_totp_enrollment_v1($1::uuid, $2::bigint, $3::timestamptz)`
	replaceRecoveryCodesSQL   = `select app.replace_mfa_recovery_codes_v1($1::jsonb)`
)

// MFAEnrollmentRepository keeps enrollment claims, factor creation, recovery
// replacement, session transitions, and audit behind protected transactions.
type MFAEnrollmentRepository struct {
	queryer mfaQueryer
}

var (
	_ mfaauth.TOTPEnrollmentStore = (*MFAEnrollmentRepository)(nil)
	_ mfaauth.RecoveryCodeStore   = (*MFAEnrollmentRepository)(nil)
)

func NewMFAEnrollmentRepository(pool *pgxpool.Pool) *MFAEnrollmentRepository {
	return &MFAEnrollmentRepository{queryer: pool}
}

type policyApplicationWire struct {
	Scope    string `json:"scope"`
	TargetID string `json:"targetId,omitempty"`
	PolicyID string `json:"policyId"`
	Revision int64  `json:"revision"`
}

type startTOTPEnrollmentWire struct {
	EnrollmentID   string                  `json:"enrollmentId"`
	FactorID       string                  `json:"factorId"`
	BrowserDigest  []byte                  `json:"browserDigest"`
	Binding        stepUpBindingWire       `json:"binding"`
	PolicyPins     []policyApplicationWire `json:"policyPins"`
	KeyVersion     int64                   `json:"keyVersion"`
	SecretEnvelope []byte                  `json:"secretEnvelope"`
	CreatedAt      time.Time               `json:"createdAt"`
	ExpiresAt      time.Time               `json:"expiresAt"`
}

func (repository *MFAEnrollmentRepository) StartTOTPEnrollment(
	ctx context.Context,
	value mfaauth.StartTOTPEnrollmentWrite,
) error {
	if repository == nil || repository.queryer == nil {
		return errMFAPersistence
	}
	binding, err := stepUpBindingToWire(value.Binding)
	if err != nil {
		return errMFAPersistence
	}
	pins := make([]policyApplicationWire, len(value.PolicyPins))
	for index, pin := range value.PolicyPins {
		mapped, mapErr := policyApplicationToWire(pin)
		if mapErr != nil {
			return errMFAPersistence
		}
		pins[index] = mapped
	}
	wire := startTOTPEnrollmentWire{
		EnrollmentID: entityIDWire(value.EnrollmentID), FactorID: entityIDWire(value.FactorID),
		BrowserDigest: append([]byte(nil), value.BrowserDigest[:]...), Binding: binding, PolicyPins: pins,
		KeyVersion:     int64(value.ProtectedSecret.KeyVersion),
		SecretEnvelope: append([]byte(nil), value.ProtectedSecret.Ciphertext...),
		CreatedAt:      value.CreatedAt, ExpiresAt: value.ExpiresAt,
	}
	defer clear(wire.SecretEnvelope)
	payload, err := marshalMFAWire(wire)
	if err != nil {
		return errMFAPersistence
	}
	defer clear(payload)
	var created bool
	if err := repository.queryer.QueryRow(ctx, startTOTPEnrollmentSQL, payload).Scan(&created); err != nil || !created {
		return errMFAPersistence
	}
	return nil
}

type claimedTOTPEnrollmentWire struct {
	EnrollmentID   string            `json:"enrollmentId"`
	FactorID       string            `json:"factorId"`
	Version        int64             `json:"version"`
	BrowserDigest  []byte            `json:"browserDigest"`
	Binding        stepUpBindingWire `json:"binding"`
	KeyVersion     int64             `json:"keyVersion"`
	SecretEnvelope []byte            `json:"secretEnvelope"`
	CreatedAt      time.Time         `json:"createdAt"`
	ExpiresAt      time.Time         `json:"expiresAt"`
	ClaimedAt      time.Time         `json:"claimedAt"`
}

func (repository *MFAEnrollmentRepository) ClaimTOTPEnrollment(
	ctx context.Context,
	value mfaauth.ClaimTOTPEnrollmentRequest,
) (mfaauth.ClaimedTOTPEnrollment, error) {
	if repository == nil || repository.queryer == nil {
		return mfaauth.ClaimedTOTPEnrollment{}, errMFAPersistence
	}
	var raw []byte
	if err := repository.queryer.QueryRow(
		ctx, claimTOTPEnrollmentSQL, entityIDWire(value.EnrollmentID), value.BrowserDigest[:],
		databaseTime(value.ClaimedAt), digestArgument(value.ContinuationReceiptDigest),
	).Scan(&raw); err != nil {
		return mfaauth.ClaimedTOTPEnrollment{}, errMFAPersistence
	}
	defer clear(raw)
	var wire claimedTOTPEnrollmentWire
	if err := unmarshalMFAWire(raw, &wire); err != nil {
		return mfaauth.ClaimedTOTPEnrollment{}, errMFAPersistence
	}
	defer clear(wire.SecretEnvelope)
	enrollmentID, err := parseEntityIDWire(wire.EnrollmentID, false)
	if err != nil {
		return mfaauth.ClaimedTOTPEnrollment{}, errMFAPersistence
	}
	factorID, err := parseEntityIDWire(wire.FactorID, false)
	if err != nil || !validMFAJSONSuccessorRevision(wire.Version) ||
		wire.KeyVersion < 1 || wire.KeyVersion > 32767 || len(wire.BrowserDigest) != 32 {
		return mfaauth.ClaimedTOTPEnrollment{}, errMFAPersistence
	}
	binding, err := stepUpBindingFromWire(wire.Binding)
	if err != nil {
		return mfaauth.ClaimedTOTPEnrollment{}, errMFAPersistence
	}
	var digest [32]byte
	copy(digest[:], wire.BrowserDigest)
	return mfaauth.ClaimedTOTPEnrollment{
		EnrollmentID: enrollmentID, FactorID: factorID, Version: uint64(wire.Version), BrowserDigest: digest,
		Binding: binding,
		ProtectedSecret: mfa.ProtectedTOTPSecret{
			KeyVersion: uint32(wire.KeyVersion), Ciphertext: append([]byte(nil), wire.SecretEnvelope...),
		},
		CreatedAt: wire.CreatedAt.UTC(), ExpiresAt: wire.ExpiresAt.UTC(), ClaimedAt: wire.ClaimedAt.UTC(),
	}, nil
}

type completeTOTPEnrollmentWire struct {
	EnrollmentID    string            `json:"enrollmentId"`
	ExpectedVersion int64             `json:"expectedVersion"`
	FactorID        string            `json:"factorId"`
	Binding         stepUpBindingWire `json:"binding"`
	AcceptedCounter int64             `json:"acceptedCounter"`
	CompletedAt     time.Time         `json:"completedAt"`
	Audit           auditIntentWire   `json:"audit"`
	Session         sessionIntentWire `json:"session"`
}

type totpEnrollmentResultWire struct {
	TenantID               string `json:"tenantId"`
	UserID                 string `json:"userId"`
	IdentityEpoch          int64  `json:"identityEpoch"`
	FactorID               string `json:"factorId"`
	FactorSecurityRevision int64  `json:"factorSecurityRevision"`
	AuditID                string `json:"auditId"`
	Mutation               string `json:"mutation"`
	NewSessionID           string `json:"newSessionId,omitempty"`
	NewSessionFamilyID     string `json:"newSessionFamilyId,omitempty"`
	RetainedContinuationID string `json:"retainedContinuationId,omitempty"`
	SessionVersion         int64  `json:"sessionVersion"`
	RecoveryRestricted     bool   `json:"recoveryRestricted"`
}

func (repository *MFAEnrollmentRepository) CompleteTOTPEnrollment(
	ctx context.Context,
	value mfaauth.CompleteTOTPEnrollmentWrite,
) (mfaauth.TOTPEnrollmentApplyResult, error) {
	if repository == nil {
		return mfaauth.TOTPEnrollmentApplyResult{}, errMFAPersistence
	}
	binding, err := stepUpBindingToWire(value.Binding)
	if err != nil || !validMFAJSONSuccessorVersion(value.ExpectedVersion) {
		return mfaauth.TOTPEnrollmentApplyResult{}, errMFAPersistence
	}
	audit, err := auditIntentToWire(value.Audit)
	if err != nil {
		return mfaauth.TOTPEnrollmentApplyResult{}, errMFAPersistence
	}
	session, err := sessionIntentToWire(value.Session, value.CompletedAt)
	if err != nil {
		return mfaauth.TOTPEnrollmentApplyResult{}, errMFAPersistence
	}
	request := completeTOTPEnrollmentWire{
		EnrollmentID: entityIDWire(value.EnrollmentID), ExpectedVersion: int64(value.ExpectedVersion),
		FactorID: entityIDWire(value.FactorID), Binding: binding, AcceptedCounter: value.AcceptedCounter,
		CompletedAt: value.CompletedAt, Audit: audit, Session: session,
	}
	var result totpEnrollmentResultWire
	if err := queryMFAJSON(ctx, repository.queryer, completeTOTPEnrollmentSQL, request, &result); err != nil {
		return mfaauth.TOTPEnrollmentApplyResult{}, err
	}
	return totpEnrollmentResultFromWire(result)
}

func (repository *MFAEnrollmentRepository) FailTOTPEnrollment(
	ctx context.Context,
	value mfaauth.FailTOTPEnrollmentWrite,
) error {
	if repository == nil || repository.queryer == nil ||
		!validMFAJSONSuccessorVersion(value.ExpectedVersion) {
		return errMFAPersistence
	}
	var applied bool
	if err := repository.queryer.QueryRow(
		ctx, failTOTPEnrollmentSQL, entityIDWire(value.EnrollmentID), int64(value.ExpectedVersion),
		databaseTime(value.FailedAt),
	).Scan(&applied); err != nil || !applied {
		return errMFAPersistence
	}
	return nil
}

type replaceRecoveryCodesWire struct {
	NewSetID           string            `json:"newSetId"`
	DigestKeyVersion   int64             `json:"digestKeyVersion"`
	ExpectedSetID      string            `json:"expectedSetId,omitempty"`
	ExpectedSetVersion int64             `json:"expectedSetVersion"`
	Binding            stepUpBindingWire `json:"binding"`
	Digests            [][]byte          `json:"digests"`
	GeneratedAt        time.Time         `json:"generatedAt"`
	Audit              auditIntentWire   `json:"audit"`
	Session            sessionIntentWire `json:"session"`
}

type recoveryCodesResultWire struct {
	TenantID           string `json:"tenantId"`
	UserID             string `json:"userId"`
	IdentityEpoch      int64  `json:"identityEpoch"`
	SetID              string `json:"setId"`
	SetVersion         int64  `json:"setVersion"`
	AuditID            string `json:"auditId"`
	NewSessionID       string `json:"newSessionId"`
	NewSessionFamilyID string `json:"newSessionFamilyId"`
	SessionVersion     int64  `json:"sessionVersion"`
}

func (repository *MFAEnrollmentRepository) ReplaceRecoveryCodes(
	ctx context.Context,
	value mfaauth.ReplaceRecoveryCodesWrite,
) (mfaauth.RecoveryCodesApplyResult, error) {
	if repository == nil || value.DigestKeyVersion < 1 || value.DigestKeyVersion > 32767 ||
		value.ExpectedSetVersion != 0 && !validMFAJSONSuccessorVersion(value.ExpectedSetVersion) {
		return mfaauth.RecoveryCodesApplyResult{}, errMFAPersistence
	}
	binding, err := stepUpBindingToWire(value.Binding)
	if err != nil {
		return mfaauth.RecoveryCodesApplyResult{}, errMFAPersistence
	}
	audit, err := auditIntentToWire(value.Audit)
	if err != nil {
		return mfaauth.RecoveryCodesApplyResult{}, errMFAPersistence
	}
	session, err := sessionIntentToWire(value.Session, value.GeneratedAt)
	if err != nil {
		return mfaauth.RecoveryCodesApplyResult{}, errMFAPersistence
	}
	digests := make([][]byte, len(value.Digests))
	for index, digest := range value.Digests {
		digests[index] = append([]byte(nil), digest[:]...)
	}
	request := replaceRecoveryCodesWire{
		NewSetID: entityIDWire(value.NewSetID), DigestKeyVersion: int64(value.DigestKeyVersion),
		ExpectedSetID:      entityIDWire(value.ExpectedSetID),
		ExpectedSetVersion: int64(value.ExpectedSetVersion), Binding: binding, Digests: digests,
		GeneratedAt: value.GeneratedAt, Audit: audit, Session: session,
	}
	var result recoveryCodesResultWire
	if err := queryMFAJSON(ctx, repository.queryer, replaceRecoveryCodesSQL, request, &result); err != nil {
		return mfaauth.RecoveryCodesApplyResult{}, err
	}
	return recoveryCodesResultFromWire(result)
}

func policyApplicationToWire(value mfa.PolicyApplication) (policyApplicationWire, error) {
	scope := ""
	switch value.Scope {
	case mfa.PolicyPlatformFloor:
		scope = "platform_floor"
	case mfa.PolicyTenantBaseline:
		scope = "tenant_baseline"
	case mfa.PolicySecurityGroup:
		scope = "security_group"
	case mfa.PolicyRole:
		scope = "role"
	case mfa.PolicyAction:
		scope = "action"
	default:
		return policyApplicationWire{}, errInvalidMFAWire
	}
	if !validMFAJSONRevision(value.Revision) {
		return policyApplicationWire{}, errInvalidMFAWire
	}
	return policyApplicationWire{
		Scope: scope, TargetID: entityIDWire(value.TargetID),
		PolicyID: entityIDWire(value.PolicyID), Revision: value.Revision,
	}, nil
}

func totpEnrollmentResultFromWire(value totpEnrollmentResultWire) (mfaauth.TOTPEnrollmentApplyResult, error) {
	ids, err := parseTOTPEnrollmentResultIDs(
		value.TenantID, value.UserID, value.FactorID, value.AuditID, value.NewSessionID,
		value.NewSessionFamilyID, value.RetainedContinuationID,
	)
	if err != nil || !validMFAJSONRevision(value.IdentityEpoch) ||
		!validMFAJSONRevision(value.FactorSecurityRevision) ||
		!validMFAJSONRevision(value.SessionVersion) {
		return mfaauth.TOTPEnrollmentApplyResult{}, errMFAPersistence
	}
	mutation, err := sessionMutationFromWire(value.Mutation)
	if err != nil {
		return mfaauth.TOTPEnrollmentApplyResult{}, errMFAPersistence
	}
	return mfaauth.TOTPEnrollmentApplyResult{
		TenantID: ids[0], UserID: ids[1], IdentityEpoch: uint64(value.IdentityEpoch), FactorID: ids[2],
		FactorSecurityRevision: value.FactorSecurityRevision, AuditID: ids[3], Mutation: mutation,
		NewSessionID: ids[4], NewSessionFamilyID: ids[5], RetainedContinuationID: ids[6],
		SessionVersion: uint64(value.SessionVersion), RecoveryRestricted: value.RecoveryRestricted,
	}, nil
}

func recoveryCodesResultFromWire(value recoveryCodesResultWire) (mfaauth.RecoveryCodesApplyResult, error) {
	ids, err := parseRecoveryCodesResultIDs(
		value.TenantID, value.UserID, value.SetID, value.AuditID, value.NewSessionID, value.NewSessionFamilyID,
	)
	if err != nil || !validMFAJSONRevision(value.IdentityEpoch) ||
		!validMFAJSONRevision(value.SetVersion) || !validMFAJSONRevision(value.SessionVersion) {
		return mfaauth.RecoveryCodesApplyResult{}, errMFAPersistence
	}
	return mfaauth.RecoveryCodesApplyResult{
		TenantID: ids[0], UserID: ids[1], IdentityEpoch: uint64(value.IdentityEpoch), SetID: ids[2],
		SetVersion: uint64(value.SetVersion), AuditID: ids[3], NewSessionID: ids[4],
		NewSessionFamilyID: ids[5], SessionVersion: uint64(value.SessionVersion),
	}, nil
}

func parseTOTPEnrollmentResultIDs(values ...string) ([7]identity.EntityID, error) {
	var result [7]identity.EntityID
	for index, value := range values {
		// Session rotation returns indexes 4-5, while continuation retention
		// returns index 6. The application layer validates the mutation-specific
		// XOR after decoding; the wire decoder must allow either closed shape.
		identifier, err := parseEntityIDWire(value, index >= 4)
		if err != nil {
			return [7]identity.EntityID{}, err
		}
		result[index] = identifier
	}
	return result, nil
}

func parseRecoveryCodesResultIDs(values ...string) ([6]identity.EntityID, error) {
	var result [6]identity.EntityID
	for index, value := range values {
		identifier, err := parseEntityIDWire(value, false)
		if err != nil {
			return [6]identity.EntityID{}, err
		}
		result[index] = identifier
	}
	return result, nil
}
