package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

const (
	createMFAStepUpChallengeSQL = `select app.create_mfa_step_up_challenge_v1($1::jsonb)`
	claimMFAStepUpChallengeSQL  = `select app.claim_mfa_step_up_challenge_v2($1::bytea, $2::bytea, $3::text, $4::timestamptz, $5::bytea)`
	failMFAStepUpChallengeSQL   = `select app.fail_mfa_step_up_challenge_v1($1::bytea, $2::bigint, $3::text, $4::text, $5::timestamptz)`
	loadMFATOTPFactorSQL        = `select app.load_mfa_totp_factor_v1($1::uuid, $2::uuid, $3::uuid)`
	loadMFARecoverySetSQL       = `select app.load_mfa_recovery_set_v1($1::uuid, $2::uuid)`
	completeMFATOTPSQL          = `select app.complete_mfa_totp_step_up_v1($1::jsonb)`
	completeMFARecoverySQL      = `select app.complete_mfa_recovery_step_up_v1($1::jsonb)`
)

var errMFAPersistence = errors.New("MFA persistence operation rejected")

type mfaQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// MFAStepUpRepository uses only narrow SECURITY DEFINER functions. Direct
// table access is intentionally absent from the API runtime adapter.
type MFAStepUpRepository struct {
	queryer mfaQueryer
}

var (
	_ mfa.ChallengeRepository = (*MFAStepUpRepository)(nil)
	_ mfa.FactorRepository    = (*MFAStepUpRepository)(nil)
	_ mfa.FactorConsumer      = (*MFAStepUpRepository)(nil)
)

func NewMFAStepUpRepository(pool *pgxpool.Pool) *MFAStepUpRepository {
	return &MFAStepUpRepository{queryer: pool}
}

type stepUpChallengeWire struct {
	ID                []byte            `json:"id"`
	BrowserDigest     []byte            `json:"browserDigest"`
	Binding           stepUpBindingWire `json:"binding"`
	AllowedFactors    []string          `json:"allowedFactors"`
	CreatedAt         time.Time         `json:"createdAt"`
	ExpiresAt         time.Time         `json:"expiresAt"`
	State             string            `json:"state"`
	Version           int64             `json:"version"`
	ClaimedAt         *time.Time        `json:"claimedAt,omitempty"`
	ClaimedFactorKind string            `json:"claimedFactorKind,omitempty"`
}

func (repository *MFAStepUpRepository) Create(ctx context.Context, value mfa.PendingChallenge) error {
	if repository == nil || repository.queryer == nil {
		return errMFAPersistence
	}
	wire, err := stepUpChallengeToWire(value)
	if err != nil {
		return errMFAPersistence
	}
	payload, err := marshalMFAWire(wire)
	if err != nil {
		return errMFAPersistence
	}
	defer clear(payload)
	var created bool
	if err := repository.queryer.QueryRow(ctx, createMFAStepUpChallengeSQL, payload).Scan(&created); err != nil || !created {
		return errMFAPersistence
	}
	return nil
}

func (repository *MFAStepUpRepository) Claim(
	ctx context.Context,
	claim mfa.ChallengeClaim,
) (mfa.ClaimedChallenge, error) {
	if repository == nil || repository.queryer == nil || claim.ID == (mfa.ChallengeID{}) {
		return mfa.ClaimedChallenge{}, errMFAPersistence
	}
	factor, err := factorKindToWire(claim.Factor)
	if err != nil {
		return mfa.ClaimedChallenge{}, errMFAPersistence
	}
	var raw []byte
	if err := repository.queryer.QueryRow(
		ctx, claimMFAStepUpChallengeSQL, claim.ID[:], claim.BrowserDigest[:], factor, databaseTime(claim.ClaimedAt),
		digestArgument(claim.ContinuationReceiptDigest),
	).Scan(&raw); err != nil {
		return mfa.ClaimedChallenge{}, errMFAPersistence
	}
	defer clear(raw)
	var wire stepUpChallengeWire
	if err := unmarshalMFAWire(raw, &wire); err != nil {
		return mfa.ClaimedChallenge{}, errMFAPersistence
	}
	pending, err := stepUpChallengeFromWire(wire)
	claimedFactor, factorErr := factorKindFromWire(wire.ClaimedFactorKind)
	if err != nil || factorErr != nil || wire.ClaimedAt == nil || claimedFactor != claim.Factor {
		return mfa.ClaimedChallenge{}, errMFAPersistence
	}
	return mfa.ClaimedChallenge{
		PendingChallenge: pending, ClaimedAt: wire.ClaimedAt.UTC(), ClaimedFactor: claimedFactor,
	}, nil
}

func (repository *MFAStepUpRepository) Fail(ctx context.Context, value mfa.ChallengeFailure) error {
	if repository == nil || repository.queryer == nil || value.ID == (mfa.ChallengeID{}) ||
		!validMFAJSONSuccessorVersion(value.ExpectedVersion) {
		return errMFAPersistence
	}
	state, err := challengeStateToWire(value.State)
	if err != nil || state != "failed" && state != "expired" {
		return errMFAPersistence
	}
	reason, err := challengeFailureToWire(value.Reason)
	if err != nil {
		return errMFAPersistence
	}
	var applied bool
	if err := repository.queryer.QueryRow(
		ctx, failMFAStepUpChallengeSQL, value.ID[:], int64(value.ExpectedVersion), state, reason,
		databaseTime(value.FailedAt),
	).Scan(&applied); err != nil || !applied {
		return errMFAPersistence
	}
	return nil
}

type totpFactorWire struct {
	ID               string `json:"id"`
	TenantID         string `json:"tenantId"`
	UserID           string `json:"userId"`
	RecordVersion    int64  `json:"recordVersion"`
	SecurityRevision int64  `json:"securityRevision"`
	Status           string `json:"status"`
	LastCounter      int64  `json:"lastCounter"`
	KeyVersion       int64  `json:"keyVersion"`
	SecretEnvelope   []byte `json:"secretEnvelope"`
}

func (repository *MFAStepUpRepository) LoadTOTP(
	ctx context.Context,
	tenantID identity.EntityID,
	userID identity.EntityID,
	factorID identity.EntityID,
) (mfa.TOTPFactor, error) {
	if repository == nil || repository.queryer == nil {
		return mfa.TOTPFactor{}, errMFAPersistence
	}
	var raw []byte
	if err := repository.queryer.QueryRow(
		ctx, loadMFATOTPFactorSQL, entityIDWire(tenantID), entityIDWire(userID), entityIDWire(factorID),
	).Scan(&raw); err != nil {
		return mfa.TOTPFactor{}, errMFAPersistence
	}
	defer clear(raw)
	var wire totpFactorWire
	if err := unmarshalMFAWire(raw, &wire); err != nil {
		return mfa.TOTPFactor{}, errMFAPersistence
	}
	defer clear(wire.SecretEnvelope)
	identifier, err := parseEntityIDWire(wire.ID, false)
	if err != nil {
		return mfa.TOTPFactor{}, errMFAPersistence
	}
	returnedTenant, err := parseEntityIDWire(wire.TenantID, false)
	if err != nil {
		return mfa.TOTPFactor{}, errMFAPersistence
	}
	returnedUser, err := parseEntityIDWire(wire.UserID, false)
	if err != nil || identifier != factorID || returnedTenant != tenantID || returnedUser != userID ||
		!validMFAJSONSuccessorRevision(wire.RecordVersion) ||
		!validMFAJSONRevision(wire.SecurityRevision) ||
		wire.KeyVersion < 1 || wire.KeyVersion > 32767 {
		return mfa.TOTPFactor{}, errMFAPersistence
	}
	status, err := factorStatusFromWire(wire.Status)
	if err != nil {
		return mfa.TOTPFactor{}, errMFAPersistence
	}
	return mfa.TOTPFactor{
		ID: identifier, TenantID: returnedTenant, UserID: returnedUser,
		RecordVersion: uint64(wire.RecordVersion), SecurityRevision: wire.SecurityRevision,
		Status: status, LastCounter: wire.LastCounter,
		Secret: mfa.ProtectedTOTPSecret{
			KeyVersion: uint32(wire.KeyVersion), Ciphertext: append([]byte(nil), wire.SecretEnvelope...),
		},
	}, nil
}

type recoverySetWire struct {
	ID               string `json:"id"`
	TenantID         string `json:"tenantId"`
	UserID           string `json:"userId"`
	RecordVersion    int64  `json:"recordVersion"`
	SecurityRevision int64  `json:"securityRevision"`
	Status           string `json:"status"`
	DigestKeyVersion int64  `json:"digestKeyVersion"`
}

func (repository *MFAStepUpRepository) LoadRecoverySet(
	ctx context.Context,
	tenantID identity.EntityID,
	userID identity.EntityID,
) (mfa.RecoverySet, error) {
	if repository == nil || repository.queryer == nil {
		return mfa.RecoverySet{}, errMFAPersistence
	}
	var raw []byte
	if err := repository.queryer.QueryRow(
		ctx, loadMFARecoverySetSQL, entityIDWire(tenantID), entityIDWire(userID),
	).Scan(&raw); err != nil {
		return mfa.RecoverySet{}, errMFAPersistence
	}
	defer clear(raw)
	var wire recoverySetWire
	if err := unmarshalMFAWire(raw, &wire); err != nil {
		return mfa.RecoverySet{}, errMFAPersistence
	}
	identifier, err := parseEntityIDWire(wire.ID, false)
	if err != nil {
		return mfa.RecoverySet{}, errMFAPersistence
	}
	returnedTenant, err := parseEntityIDWire(wire.TenantID, false)
	if err != nil {
		return mfa.RecoverySet{}, errMFAPersistence
	}
	returnedUser, err := parseEntityIDWire(wire.UserID, false)
	if err != nil || returnedTenant != tenantID || returnedUser != userID ||
		!validMFAJSONSuccessorRevision(wire.RecordVersion) ||
		!validMFAJSONRevision(wire.SecurityRevision) ||
		wire.DigestKeyVersion < 1 || wire.DigestKeyVersion > 32767 {
		return mfa.RecoverySet{}, errMFAPersistence
	}
	status, err := factorStatusFromWire(wire.Status)
	if err != nil {
		return mfa.RecoverySet{}, errMFAPersistence
	}
	return mfa.RecoverySet{
		ID: identifier, TenantID: returnedTenant, UserID: returnedUser,
		RecordVersion: uint64(wire.RecordVersion), SecurityRevision: wire.SecurityRevision,
		Status: status, DigestKeyVersion: uint32(wire.DigestKeyVersion),
	}, nil
}

type factorCompletionWire struct {
	TenantID               string `json:"tenantId"`
	UserID                 string `json:"userId"`
	IdentityEpoch          int64  `json:"identityEpoch"`
	FactorSecurityRevision int64  `json:"factorSecurityRevision"`
	AuditID                string `json:"auditId"`
	NewSessionID           string `json:"newSessionId"`
	NewSessionFamilyID     string `json:"newSessionFamilyId"`
	ConsumedContinuationID string `json:"consumedContinuationId,omitempty"`
	SessionVersion         int64  `json:"sessionVersion"`
	RecoveryRestricted     bool   `json:"recoveryRestricted"`
}

type completeFactorWire struct {
	ChallengeID               []byte                  `json:"challengeId"`
	ExpectedChallengeVersion  int64                   `json:"expectedChallengeVersion"`
	Binding                   stepUpBindingWire       `json:"binding"`
	FactorID                  string                  `json:"factorId"`
	ExpectedFactorVersion     int64                   `json:"expectedFactorVersion"`
	ExpectedSecurityRevision  int64                   `json:"expectedSecurityRevision"`
	Counter                   *int64                  `json:"counter,omitempty"`
	SetID                     string                  `json:"setId,omitempty"`
	CodeDigest                []byte                  `json:"codeDigest,omitempty"`
	CompletedAt               time.Time               `json:"completedAt"`
	SessionMutation           string                  `json:"sessionMutation"`
	AuditKind                 string                  `json:"auditKind"`
	RecoveryRestricted        bool                    `json:"recoveryRestricted"`
	Session                   *sessionReservationWire `json:"session"`
	ContinuationReceiptDigest []byte                  `json:"continuationReceiptDigest,omitempty"`
}

func (repository *MFAStepUpRepository) CompleteTOTP(
	ctx context.Context,
	value mfa.TOTPCompletion,
) (mfa.FactorCompletionResult, error) {
	session, err := sessionReservationToWire(value.Session, value.CompletedAt)
	if err != nil || session == nil || value.Session.AuthenticationMethod() != mfa.SessionAuthenticationTOTP {
		return mfa.FactorCompletionResult{}, errMFAPersistence
	}
	counter := value.Counter
	wire, err := completeFactorToWire(
		value.ChallengeID, value.ExpectedChallengeVersion, value.Binding, value.FactorID,
		value.ExpectedFactorVersion, value.ExpectedSecurityRevision, &counter, identity.EntityID{}, nil,
		value.CompletedAt, value.Intent,
	)
	if err != nil {
		return mfa.FactorCompletionResult{}, errMFAPersistence
	}
	wire.Session = session
	wire.ContinuationReceiptDigest, err = completionReceiptDigestToWire(
		value.Binding.Flow, value.ContinuationReceiptDigest,
	)
	if err != nil {
		return mfa.FactorCompletionResult{}, errMFAPersistence
	}
	return repository.completeFactor(ctx, completeMFATOTPSQL, wire)
}

func (repository *MFAStepUpRepository) CompleteRecovery(
	ctx context.Context,
	value mfa.RecoveryCompletion,
) (mfa.FactorCompletionResult, error) {
	session, err := sessionReservationToWire(value.Session, value.CompletedAt)
	if err != nil || session == nil || value.Session.AuthenticationMethod() != mfa.SessionAuthenticationRecovery {
		return mfa.FactorCompletionResult{}, errMFAPersistence
	}
	wire, err := completeFactorToWire(
		value.ChallengeID, value.ExpectedChallengeVersion, value.Binding, identity.EntityID{},
		value.ExpectedSetVersion, value.ExpectedSecurityRevision, nil, value.SetID, value.CodeDigest[:],
		value.CompletedAt, value.Intent,
	)
	if err != nil {
		return mfa.FactorCompletionResult{}, errMFAPersistence
	}
	wire.Session = session
	wire.ContinuationReceiptDigest, err = completionReceiptDigestToWire(
		value.Binding.Flow, value.ContinuationReceiptDigest,
	)
	if err != nil {
		return mfa.FactorCompletionResult{}, errMFAPersistence
	}
	return repository.completeFactor(ctx, completeMFARecoverySQL, wire)
}

func completionReceiptDigestToWire(
	flow mfa.StepUpFlow,
	digest [32]byte,
) ([]byte, error) {
	zero := [32]byte{}
	switch flow {
	case mfa.FlowExistingSession:
		if digest != zero {
			return nil, errInvalidMFAWire
		}
		return nil, nil
	case mfa.FlowPostPrimaryContinuation:
		if digest == zero {
			return nil, errInvalidMFAWire
		}
		return append([]byte(nil), digest[:]...), nil
	default:
		return nil, errInvalidMFAWire
	}
}

func (repository *MFAStepUpRepository) completeFactor(
	ctx context.Context,
	query string,
	wire completeFactorWire,
) (mfa.FactorCompletionResult, error) {
	if repository == nil || repository.queryer == nil {
		return mfa.FactorCompletionResult{}, errMFAPersistence
	}
	payload, err := marshalMFAWire(wire)
	if err != nil {
		return mfa.FactorCompletionResult{}, errMFAPersistence
	}
	defer clear(payload)
	var raw []byte
	if err := repository.queryer.QueryRow(ctx, query, payload).Scan(&raw); err != nil {
		return mfa.FactorCompletionResult{}, errMFAPersistence
	}
	defer clear(raw)
	var result factorCompletionWire
	if err := unmarshalMFAWire(raw, &result); err != nil {
		return mfa.FactorCompletionResult{}, errMFAPersistence
	}
	return factorCompletionFromWire(result)
}

func stepUpChallengeToWire(value mfa.PendingChallenge) (stepUpChallengeWire, error) {
	binding, err := stepUpBindingToWire(value.Binding)
	if err != nil {
		return stepUpChallengeWire{}, err
	}
	factors := make([]string, len(value.AllowedFactors))
	for index, factor := range value.AllowedFactors {
		mapped, mapErr := factorKindToWire(factor)
		if mapErr != nil {
			return stepUpChallengeWire{}, mapErr
		}
		factors[index] = mapped
	}
	state, err := challengeStateToWire(value.State)
	if err != nil || !validMFAJSONVersion(value.Version) {
		return stepUpChallengeWire{}, errInvalidMFAWire
	}
	return stepUpChallengeWire{
		ID: append([]byte(nil), value.ID[:]...), BrowserDigest: append([]byte(nil), value.BrowserDigest[:]...),
		Binding: binding, AllowedFactors: factors, CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt,
		State: state, Version: int64(value.Version),
	}, nil
}

func stepUpChallengeFromWire(value stepUpChallengeWire) (mfa.PendingChallenge, error) {
	if len(value.ID) != len(mfa.ChallengeID{}) || len(value.BrowserDigest) != 32 ||
		!validMFAJSONRevision(value.Version) {
		return mfa.PendingChallenge{}, errInvalidMFAWire
	}
	var identifier mfa.ChallengeID
	copy(identifier[:], value.ID)
	var digest [32]byte
	copy(digest[:], value.BrowserDigest)
	binding, err := stepUpBindingFromWire(value.Binding)
	if err != nil {
		return mfa.PendingChallenge{}, err
	}
	factors := make([]mfa.FactorKind, len(value.AllowedFactors))
	for index, factor := range value.AllowedFactors {
		mapped, mapErr := factorKindFromWire(factor)
		if mapErr != nil {
			return mfa.PendingChallenge{}, mapErr
		}
		factors[index] = mapped
	}
	state, err := challengeStateFromWire(value.State)
	if err != nil {
		return mfa.PendingChallenge{}, err
	}
	return mfa.PendingChallenge{
		ID: identifier, BrowserDigest: digest, Binding: binding, AllowedFactors: factors,
		CreatedAt: value.CreatedAt.UTC(), ExpiresAt: value.ExpiresAt.UTC(), State: state, Version: uint64(value.Version),
	}, nil
}

func completeFactorToWire(
	challengeID mfa.ChallengeID,
	expectedChallengeVersion uint64,
	binding mfa.StepUpBinding,
	factorID identity.EntityID,
	expectedFactorVersion uint64,
	expectedSecurityRevision int64,
	counter *int64,
	setID identity.EntityID,
	digest []byte,
	completedAt time.Time,
	intent mfa.CompletionIntent,
) (completeFactorWire, error) {
	bindingWire, err := stepUpBindingToWire(binding)
	if err != nil || !validMFAJSONSuccessorVersion(expectedChallengeVersion) ||
		!validMFAJSONSuccessorVersion(expectedFactorVersion) ||
		!validMFAJSONRevision(expectedSecurityRevision) {
		return completeFactorWire{}, errInvalidMFAWire
	}
	mutation := ""
	switch intent.Session {
	case mfa.StepUpSessionRotate:
		mutation = "rotate"
	case mfa.StepUpSessionCreateFromContinuation:
		mutation = "consume_continuation"
	default:
		return completeFactorWire{}, errInvalidMFAWire
	}
	audit := string(intent.Audit)
	if audit != string(mfa.AuditTOTPStepUpCompleted) && audit != string(mfa.AuditRecoveryCodeUsed) {
		return completeFactorWire{}, errInvalidMFAWire
	}
	return completeFactorWire{
		ChallengeID: append([]byte(nil), challengeID[:]...), ExpectedChallengeVersion: int64(expectedChallengeVersion),
		Binding: bindingWire, FactorID: entityIDWire(factorID), ExpectedFactorVersion: int64(expectedFactorVersion),
		ExpectedSecurityRevision: expectedSecurityRevision, Counter: counter, SetID: entityIDWire(setID),
		CodeDigest: append([]byte(nil), digest...), CompletedAt: completedAt,
		SessionMutation: mutation, AuditKind: audit, RecoveryRestricted: intent.RecoveryRestricted,
	}, nil
}

func factorCompletionFromWire(value factorCompletionWire) (mfa.FactorCompletionResult, error) {
	ids, err := parseCompletionIDs(
		value.TenantID, value.UserID, value.AuditID, value.NewSessionID,
		value.NewSessionFamilyID, value.ConsumedContinuationID,
	)
	if err != nil || !validMFAJSONRevision(value.IdentityEpoch) ||
		!validMFAJSONRevision(value.FactorSecurityRevision) ||
		!validMFAJSONRevision(value.SessionVersion) {
		return mfa.FactorCompletionResult{}, errMFAPersistence
	}
	return mfa.FactorCompletionResult{
		TenantID: ids[0], UserID: ids[1], IdentityEpoch: uint64(value.IdentityEpoch),
		FactorSecurityRevision: value.FactorSecurityRevision, AuditID: ids[2],
		NewSessionID: ids[3], NewSessionFamilyID: ids[4], ConsumedContinuationID: ids[5],
		SessionVersion: uint64(value.SessionVersion), RecoveryRestricted: value.RecoveryRestricted,
	}, nil
}

func parseCompletionIDs(values ...string) ([6]identity.EntityID, error) {
	var result [6]identity.EntityID
	for index, value := range values {
		identifier, err := parseEntityIDWire(value, index == 5)
		if err != nil {
			return [6]identity.EntityID{}, err
		}
		result[index] = identifier
	}
	return result, nil
}

func factorKindToWire(value mfa.FactorKind) (string, error) {
	if value == mfa.FactorTOTP {
		return "totp", nil
	}
	if value == mfa.FactorRecoveryCode {
		return "recovery_code", nil
	}
	return "", errInvalidMFAWire
}

func factorKindFromWire(value string) (mfa.FactorKind, error) {
	if value == "totp" {
		return mfa.FactorTOTP, nil
	}
	if value == "recovery_code" {
		return mfa.FactorRecoveryCode, nil
	}
	return 0, errInvalidMFAWire
}

func challengeStateToWire(value mfa.ChallengeState) (string, error) {
	switch value {
	case mfa.ChallengePending:
		return "pending", nil
	case mfa.ChallengeClaimed:
		return "claimed", nil
	case mfa.ChallengeCompleted:
		return "completed", nil
	case mfa.ChallengeFailed:
		return "failed", nil
	case mfa.ChallengeExpired:
		return "expired", nil
	default:
		return "", errInvalidMFAWire
	}
}

func challengeStateFromWire(value string) (mfa.ChallengeState, error) {
	switch value {
	case "pending":
		return mfa.ChallengePending, nil
	case "claimed":
		return mfa.ChallengeClaimed, nil
	case "completed":
		return mfa.ChallengeCompleted, nil
	case "failed":
		return mfa.ChallengeFailed, nil
	case "expired":
		return mfa.ChallengeExpired, nil
	default:
		return 0, errInvalidMFAWire
	}
}

func challengeFailureToWire(value mfa.ChallengeFailureReason) (string, error) {
	if value == mfa.ChallengeFailureExpired || value == mfa.ChallengeFailureFactor {
		return string(value), nil
	}
	return "", errInvalidMFAWire
}

func factorStatusFromWire(value string) (mfa.FactorStatus, error) {
	if value == "active" {
		return mfa.FactorActive, nil
	}
	if value == "revoked" {
		return mfa.FactorRevoked, nil
	}
	return 0, errInvalidMFAWire
}
