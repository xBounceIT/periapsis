package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/localaccount"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/platformlocalaccount"
)

const (
	listPlatformLocalAccountsSQL             = `select document from app.list_platform_local_accounts_v1($1,$2,$3,$4,$5)`
	getPlatformLocalAccountSQL               = `select app.get_platform_local_account_v1($1,$2,$3)`
	preparePlatformLocalAccountTransitionSQL = `select * from app.prepare_platform_local_account_transition_v1(
		$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12
	)`
	applyPlatformLocalAccountTransitionSQL         = `select app.apply_platform_local_account_transition_v1($1::jsonb)`
	recordPlatformLocalAccountEnrollmentFailureSQL = `select app.record_platform_local_account_enrollment_failure_v1($1::jsonb)`
	platformLocalAccountReadinessSQL               = `select app.platform_local_account_runtime_schema_readiness_v51()`

	maximumPlatformLocalAccountDocumentBytes = 32 * 1024
	maximumPlatformLocalAccountCommandBytes  = 128 * 1024
)

type platformLocalAccountQueryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// PlatformLocalAccountRepository is the protected platform local-account
// adapter. The database functions re-resolve live platform authority and
// fresh local MFA; application-supplied actor projections are never trusted.
type PlatformLocalAccountRepository struct {
	queryer platformLocalAccountQueryer
	begin   transactionBeginner
}

var _ platformlocalaccount.Repository = (*PlatformLocalAccountRepository)(nil)

func NewPlatformLocalAccountRepository(pool *pgxpool.Pool) (*PlatformLocalAccountRepository, error) {
	if pool == nil {
		return nil, errors.New("platform local-account repository requires a database pool")
	}
	return &PlatformLocalAccountRepository{queryer: pool, begin: poolTransactionBeginner(pool)}, nil
}

func newPlatformLocalAccountRepositoryForTest(
	queryer platformLocalAccountQueryer,
	begin transactionBeginner,
) *PlatformLocalAccountRepository {
	return &PlatformLocalAccountRepository{queryer: queryer, begin: begin}
}

func (repository *PlatformLocalAccountRepository) List(
	ctx context.Context,
	params platformlocalaccount.ListParams,
) ([]platformlocalaccount.Account, error) {
	if repository == nil || repository.queryer == nil {
		return nil, authentication.ErrUnavailable
	}
	if ctx == nil {
		return nil, authentication.ErrUnavailable
	}
	if err := validatePlatformLocalAccountSession(params.SessionParams); err != nil ||
		params.Limit < 1 || params.Limit > 101 ||
		params.After != nil && !authorizationUUIDv7(*params.After) {
		return nil, authentication.ErrInvalidInput
	}
	rows, err := repository.queryer.Query(
		ctx, listPlatformLocalAccountsSQL, params.SessionID, params.AuthenticationMethod,
		params.After, params.Limit, params.IncludeDisabled,
	)
	if err != nil {
		return nil, mapPlatformLocalAccountDatabaseError(err)
	}
	defer rows.Close()
	accounts := make([]platformlocalaccount.Account, 0, params.Limit)
	for rows.Next() {
		var document []byte
		if err = rows.Scan(&document); err != nil {
			return nil, mapPlatformLocalAccountDatabaseError(err)
		}
		account, decodeErr := decodePlatformLocalAccount(document)
		clear(document)
		if decodeErr != nil {
			return nil, authentication.ErrUnavailable
		}
		accounts = append(accounts, account)
		if len(accounts) > int(params.Limit) {
			return nil, authentication.ErrUnavailable
		}
	}
	if err = rows.Err(); err != nil {
		return nil, mapPlatformLocalAccountDatabaseError(err)
	}
	return accounts, nil
}

func (repository *PlatformLocalAccountRepository) Get(
	ctx context.Context,
	params platformlocalaccount.GetParams,
) (platformlocalaccount.Account, error) {
	if repository == nil || repository.queryer == nil {
		return platformlocalaccount.Account{}, authentication.ErrUnavailable
	}
	if ctx == nil {
		return platformlocalaccount.Account{}, authentication.ErrUnavailable
	}
	if err := validatePlatformLocalAccountSession(params.SessionParams); err != nil ||
		!authorizationUUIDv7(params.AccountID) {
		return platformlocalaccount.Account{}, authentication.ErrInvalidInput
	}
	var document []byte
	if err := repository.queryer.QueryRow(
		ctx, getPlatformLocalAccountSQL, params.SessionID, params.AccountID,
		params.AuthenticationMethod,
	).Scan(&document); err != nil {
		return platformlocalaccount.Account{}, mapPlatformLocalAccountDatabaseError(err)
	}
	defer clear(document)
	account, err := decodePlatformLocalAccount(document)
	if err != nil || account.ID != params.AccountID {
		return platformlocalaccount.Account{}, authentication.ErrUnavailable
	}
	return account, nil
}

func (repository *PlatformLocalAccountRepository) Apply(
	ctx context.Context,
	params platformlocalaccount.ApplyParams,
) (platformlocalaccount.ApplyResult, error) {
	if repository == nil || repository.begin == nil {
		return platformlocalaccount.ApplyResult{}, authentication.ErrUnavailable
	}
	if ctx == nil {
		return platformlocalaccount.ApplyResult{}, authentication.ErrUnavailable
	}
	if err := validatePlatformLocalAccountApply(params); err != nil {
		return platformlocalaccount.ApplyResult{}, authentication.ErrInvalidInput
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, pgx.TxOptions{IsoLevel: pgx.Serializable},
		func(tx databaseTransaction) (platformlocalaccount.ApplyResult, error) {
			return applyPlatformLocalAccountTransition(ctx, tx, params)
		},
	)
	mapped := mapPlatformLocalAccountDatabaseError(err)
	if errors.Is(mapped, platformlocalaccount.ErrEnrollmentProofRejected) {
		recordContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if recordErr := repository.recordEnrollmentFailure(recordContext, params); recordErr != nil {
			return platformlocalaccount.ApplyResult{}, authentication.ErrUnavailable
		}
		return platformlocalaccount.ApplyResult{}, platformlocalaccount.ErrEnrollmentProofRejected
	}
	if err != nil {
		return platformlocalaccount.ApplyResult{}, mapped
	}
	return result, nil
}

func (repository *PlatformLocalAccountRepository) ReadyPlatformLocalAccounts(ctx context.Context) error {
	if repository == nil || repository.queryer == nil || ctx == nil {
		return errors.New("platform local-account repository is unavailable")
	}
	var ready bool
	if err := repository.queryer.QueryRow(ctx, platformLocalAccountReadinessSQL).Scan(&ready); err != nil || !ready {
		return errors.New("platform local-account runtime schema is not ready")
	}
	return nil
}

type platformLocalAccountPreparation struct {
	replayed                   bool
	result                     []byte
	planning                   []byte
	passwordHistory            []string
	pendingFactorID            pgtype.UUID
	pendingUserID              pgtype.UUID
	pendingPurpose             pgtype.Text
	pendingVersion             pgtype.Int8
	pendingFactorRevision      pgtype.Int8
	pendingSecretCiphertext    []byte
	pendingSecretNonce         []byte
	pendingSecretAAD           []byte
	pendingKeyVersion          pgtype.Int4
	pendingExpiresAt           pgtype.Timestamptz
	pendingLastAcceptedCounter pgtype.Int8
}

func (preparation *platformLocalAccountPreparation) clear() {
	if preparation == nil {
		return
	}
	clear(preparation.result)
	clear(preparation.planning)
	for index := range preparation.passwordHistory {
		preparation.passwordHistory[index] = ""
	}
	clear(preparation.passwordHistory)
	clear(preparation.pendingSecretCiphertext)
	clear(preparation.pendingSecretNonce)
	clear(preparation.pendingSecretAAD)
	*preparation = platformLocalAccountPreparation{}
}

func applyPlatformLocalAccountTransition(
	ctx context.Context,
	tx databaseTransaction,
	params platformlocalaccount.ApplyParams,
) (platformlocalaccount.ApplyResult, error) {
	action, err := platformLocalAccountAction(params.Action)
	if err != nil {
		return platformlocalaccount.ApplyResult{}, err
	}
	var ceremonyDigest any
	if params.Action == localaccount.ActionActivate {
		ceremonyDigest = params.CeremonyTokenDigest[:]
	}
	preparation := platformLocalAccountPreparation{}
	if err = tx.QueryRow(
		ctx, preparePlatformLocalAccountTransitionSQL,
		params.SessionID, params.AuthenticationMethod, params.CommandID, action,
		params.AccountID, params.NewAccountID, params.NewUserID, int64(params.ExpectedRevision),
		params.IdempotencyKeyDigest[:], params.PublicRequestDigest[:], ceremonyDigest,
		params.At,
	).Scan(
		&preparation.replayed, &preparation.result, &preparation.planning,
		&preparation.passwordHistory, &preparation.pendingFactorID,
		&preparation.pendingUserID, &preparation.pendingPurpose,
		&preparation.pendingVersion, &preparation.pendingFactorRevision,
		&preparation.pendingSecretCiphertext, &preparation.pendingSecretNonce,
		&preparation.pendingSecretAAD, &preparation.pendingKeyVersion,
		&preparation.pendingExpiresAt, &preparation.pendingLastAcceptedCounter,
	); err != nil {
		preparation.clear()
		return platformlocalaccount.ApplyResult{}, err
	}
	defer preparation.clear()
	if preparation.replayed {
		if len(preparation.planning) != 0 || len(preparation.passwordHistory) != 0 ||
			preparation.pendingFactorID.Valid {
			return platformlocalaccount.ApplyResult{}, authentication.ErrUnavailable
		}
		result, decodeErr := decodePlatformLocalAccountApplyResult(preparation.result)
		if decodeErr != nil || !result.Replayed || result.ArtifactIssued {
			return platformlocalaccount.ApplyResult{}, authentication.ErrUnavailable
		}
		return params.ValidateResult(result)
	}
	if len(preparation.result) != 0 {
		return platformlocalaccount.ApplyResult{}, authentication.ErrUnavailable
	}
	planning, err := decodePlatformLocalAccountPlanning(preparation.planning)
	if err != nil || !planning.FreshLocalMFA || !planning.ProtectedWorkflow {
		return platformlocalaccount.ApplyResult{}, authentication.ErrUnavailable
	}
	if params.Action == localaccount.ActionActivate || params.Action == localaccount.ActionRotatePassword {
		if params.ValidatePasswordHistory == nil {
			return platformlocalaccount.ApplyResult{}, authentication.ErrUnavailable
		}
		history, historyErr := platformLocalAccountHistory(preparation.passwordHistory)
		if historyErr != nil {
			return platformlocalaccount.ApplyResult{}, authentication.ErrUnavailable
		}
		defer clearPlatformLocalAccountHistory(history)
		if err = params.ValidatePasswordHistory(history); err != nil {
			return platformlocalaccount.ApplyResult{}, err
		}
	} else if len(preparation.passwordHistory) != 0 || params.ValidatePasswordHistory != nil {
		return platformlocalaccount.ApplyResult{}, authentication.ErrUnavailable
	}

	var confirmed *platformLocalAccountConfirmedFactorWire
	if params.Action == localaccount.ActionActivate {
		if params.ConfirmTOTPEnrollment == nil {
			return platformlocalaccount.ApplyResult{}, authentication.ErrUnavailable
		}
		pending, pendingErr := platformLocalAccountPendingEnrollment(preparation, params)
		if pendingErr != nil {
			return platformlocalaccount.ApplyResult{}, authentication.ErrUnavailable
		}
		defer pending.Destroy()
		var lastCounter *int64
		if preparation.pendingLastAcceptedCounter.Valid {
			value := preparation.pendingLastAcceptedCounter.Int64
			lastCounter = &value
		}
		factor, confirmErr := params.ConfirmTOTPEnrollment(pending, lastCounter)
		if confirmErr != nil {
			return platformlocalaccount.ApplyResult{}, confirmErr
		}
		defer factor.Destroy()
		confirmed = platformLocalAccountConfirmedFactor(factor)
		defer confirmed.clear()
		// Activation stages the verified identifier, replacement credential and
		// confirmed factor before the pure planner observes the locked state.
		planning.Snapshot.LoginIdentifier = localaccount.LoginIdentifierVerified
		planning.Snapshot.Credential = localaccount.CredentialActive
		planning.Snapshot.ConfirmedAcceptableFactors = 1
	} else if preparation.pendingFactorID.Valid || params.ConfirmTOTPEnrollment != nil {
		return platformlocalaccount.ApplyResult{}, authentication.ErrUnavailable
	}
	plan, err := params.Plan(planning)
	if err != nil {
		return platformlocalaccount.ApplyResult{}, err
	}
	command, err := encodePlatformLocalAccountCommand(params, action, plan, confirmed)
	if err != nil {
		return platformlocalaccount.ApplyResult{}, authentication.ErrUnavailable
	}
	defer clear(command)
	var resultDocument []byte
	if err = tx.QueryRow(ctx, applyPlatformLocalAccountTransitionSQL, command).Scan(&resultDocument); err != nil {
		return platformlocalaccount.ApplyResult{}, err
	}
	defer clear(resultDocument)
	result, err := decodePlatformLocalAccountApplyResult(resultDocument)
	if err != nil || result.Replayed {
		return platformlocalaccount.ApplyResult{}, authentication.ErrUnavailable
	}
	return params.ValidateResult(result)
}

func (repository *PlatformLocalAccountRepository) recordEnrollmentFailure(
	ctx context.Context,
	params platformlocalaccount.ApplyParams,
) error {
	command, err := json.Marshal(platformLocalAccountEnrollmentFailureWire{
		SessionID: params.SessionID, AuthenticationMethod: params.AuthenticationMethod,
		AccountID: params.AccountID, ExpectedRevision: params.ExpectedRevision,
		CeremonyTokenDigest: base64.StdEncoding.EncodeToString(params.CeremonyTokenDigest[:]),
		At:                  params.At,
	})
	if err != nil || len(command) == 0 || len(command) > maximumPlatformLocalAccountCommandBytes {
		clear(command)
		return authentication.ErrUnavailable
	}
	defer clear(command)
	_, err = withinTransactionWithOptions(
		ctx, repository.begin, pgx.TxOptions{IsoLevel: pgx.Serializable},
		func(tx databaseTransaction) (struct{}, error) {
			if _, execErr := tx.Exec(
				ctx, recordPlatformLocalAccountEnrollmentFailureSQL, command,
			); execErr != nil {
				return struct{}{}, execErr
			}
			return struct{}{}, nil
		},
	)
	return err
}

type platformLocalAccountWire struct {
	ID                         uuid.UUID                                  `json:"id"`
	UserID                     uuid.UUID                                  `json:"userId"`
	DisplayName                string                                     `json:"displayName"`
	LoginIdentifier            string                                     `json:"loginIdentifier"`
	Status                     platformlocalaccount.Status                `json:"status"`
	LoginIdentifierStatus      platformlocalaccount.LoginIdentifierStatus `json:"loginIdentifierStatus"`
	CredentialStatus           platformlocalaccount.CredentialStatus      `json:"credentialStatus"`
	CredentialVersion          uint64                                     `json:"credentialVersion"`
	ConfirmedAcceptableFactors uint16                                     `json:"confirmedAcceptableFactors"`
	ProtectedRecoveryPrincipal bool                                       `json:"protectedRecoveryPrincipal"`
	Revision                   uint64                                     `json:"revision"`
	IdentityEpoch              uint64                                     `json:"identityEpoch"`
	InvitedAt                  time.Time                                  `json:"invitedAt"`
	ActivatedAt                *time.Time                                 `json:"activatedAt"`
	DisabledAt                 *time.Time                                 `json:"disabledAt"`
	RecoveryStartedAt          *time.Time                                 `json:"recoveryStartedAt"`
	UpdatedAt                  time.Time                                  `json:"updatedAt"`
}

type platformLocalAccountApplyResultWire struct {
	Account        json.RawMessage `json:"account"`
	Replayed       bool            `json:"replayed"`
	ArtifactIssued bool            `json:"artifactIssued"`
}

type platformLocalAccountPlanningWire struct {
	Snapshot struct {
		AccountID                  *uuid.UUID `json:"accountId"`
		UserID                     *uuid.UUID `json:"userId"`
		Revision                   uint64     `json:"revision"`
		IdentityEpoch              uint64     `json:"identityEpoch"`
		Status                     string     `json:"status"`
		LoginIdentifierStatus      string     `json:"loginIdentifierStatus"`
		CredentialStatus           string     `json:"credentialStatus"`
		ConfirmedAcceptableFactors uint16     `json:"confirmedAcceptableFactors"`
		ProtectedRecoveryPrincipal bool       `json:"protectedRecoveryPrincipal"`
	} `json:"snapshot"`
	RecoveryFleet struct {
		CurrentPrincipalReady     bool   `json:"currentPrincipalReady"`
		OtherReadyHumanPrincipals uint32 `json:"otherReadyHumanPrincipals"`
	} `json:"recoveryFleet"`
	FreshLocalMFA     bool `json:"freshLocalMFA"`
	ProtectedWorkflow bool `json:"protectedWorkflow"`
}

type platformLocalAccountIssueEnrollmentWire struct {
	AccountID           uuid.UUID `json:"accountId"`
	UserID              uuid.UUID `json:"userId"`
	FactorID            uuid.UUID `json:"factorId"`
	Purpose             string    `json:"purpose"`
	Version             uint64    `json:"version"`
	FactorRevision      uint64    `json:"factorRevision"`
	CeremonyTokenDigest string    `json:"ceremonyTokenDigest"`
	Ciphertext          string    `json:"ciphertext"`
	Nonce               string    `json:"nonce"`
	AAD                 string    `json:"aad"`
	KeyVersion          int16     `json:"keyVersion"`
	ExpiresAt           time.Time `json:"expiresAt"`
}

type platformLocalAccountConfirmedFactorWire struct {
	FactorID            uuid.UUID `json:"factorId"`
	Revision            uint64    `json:"revision"`
	Ciphertext          string    `json:"ciphertext"`
	Nonce               string    `json:"nonce"`
	AAD                 string    `json:"aad"`
	KeyVersion          int16     `json:"keyVersion"`
	AcceptedCounter     int64     `json:"acceptedCounter"`
	EncryptionAlgorithm string    `json:"encryptionAlgorithm"`
	OTPAlgorithm        string    `json:"otpAlgorithm"`
	Digits              uint8     `json:"digits"`
	PeriodSeconds       uint16    `json:"periodSeconds"`
}

func (wire *platformLocalAccountConfirmedFactorWire) clear() {
	if wire == nil {
		return
	}
	wire.Ciphertext, wire.Nonce, wire.AAD = "", "", ""
	*wire = platformLocalAccountConfirmedFactorWire{}
}

type platformLocalAccountPlanWire struct {
	Action            string    `json:"action"`
	AccountID         uuid.UUID `json:"accountId"`
	UserID            uuid.UUID `json:"userId"`
	ExpectedRevision  uint64    `json:"expectedRevision"`
	NextRevision      uint64    `json:"nextRevision"`
	NextIdentityEpoch uint64    `json:"nextIdentityEpoch"`
}

type platformLocalAccountAuditWire struct {
	RequestID     uuid.UUID `json:"requestId"`
	CorrelationID uuid.UUID `json:"correlationId"`
	IPAddress     string    `json:"ipAddress"`
	UserAgent     string    `json:"userAgent"`
}

type platformLocalAccountCommandWire struct {
	SessionID                  uuid.UUID                                `json:"sessionId"`
	AuthenticationMethod       string                                   `json:"authenticationMethod"`
	CommandID                  uuid.UUID                                `json:"commandId"`
	Action                     string                                   `json:"action"`
	AccountID                  *uuid.UUID                               `json:"accountId"`
	NewAccountID               *uuid.UUID                               `json:"newAccountId"`
	NewUserID                  *uuid.UUID                               `json:"newUserId"`
	ExpectedRevision           uint64                                   `json:"expectedRevision"`
	At                         time.Time                                `json:"at"`
	DisplayName                *string                                  `json:"displayName"`
	CanonicalLoginIdentifier   *string                                  `json:"canonicalLoginIdentifier"`
	ProtectedRecoveryPrincipal *bool                                    `json:"protectedRecoveryPrincipal"`
	Reason                     string                                   `json:"reason"`
	IdempotencyKeyDigest       string                                   `json:"idempotencyKeyDigest"`
	PublicRequestDigest        string                                   `json:"publicRequestDigest"`
	IssueEnrollment            *platformLocalAccountIssueEnrollmentWire `json:"issueEnrollment"`
	ReplacementPasswordPHC     *string                                  `json:"replacementPasswordPhc"`
	ConfirmedFactor            *platformLocalAccountConfirmedFactorWire `json:"confirmedFactor"`
	Plan                       platformLocalAccountPlanWire             `json:"plan"`
	Audit                      platformLocalAccountAuditWire            `json:"audit"`
}

type platformLocalAccountEnrollmentFailureWire struct {
	SessionID            uuid.UUID `json:"sessionId"`
	AuthenticationMethod string    `json:"authenticationMethod"`
	AccountID            uuid.UUID `json:"accountId"`
	ExpectedRevision     uint64    `json:"expectedRevision"`
	CeremonyTokenDigest  string    `json:"ceremonyTokenDigest"`
	At                   time.Time `json:"at"`
}

func encodePlatformLocalAccountCommand(
	params platformlocalaccount.ApplyParams,
	action string,
	plan localaccount.Plan,
	confirmed *platformLocalAccountConfirmedFactorWire,
) ([]byte, error) {
	wire := platformLocalAccountCommandWire{
		SessionID: params.SessionID, AuthenticationMethod: params.AuthenticationMethod,
		CommandID: params.CommandID, Action: action, ExpectedRevision: params.ExpectedRevision,
		At: params.At, Reason: params.Reason,
		IdempotencyKeyDigest: base64.StdEncoding.EncodeToString(params.IdempotencyKeyDigest[:]),
		PublicRequestDigest:  base64.StdEncoding.EncodeToString(params.PublicRequestDigest[:]),
		ConfirmedFactor:      confirmed,
		Plan: platformLocalAccountPlanWire{
			Action: action, AccountID: uuid.UUID(plan.AccountID), UserID: uuid.UUID(plan.UserID),
			ExpectedRevision: plan.ExpectedRevision, NextRevision: plan.NextRevision,
			NextIdentityEpoch: plan.NextIdentityEpoch,
		},
		Audit: platformLocalAccountAuditWire{
			RequestID: params.Event.RequestID, CorrelationID: params.Event.CorrelationID,
			IPAddress: params.Event.RemoteAddress.String(), UserAgent: params.Event.UserAgent,
		},
	}
	if params.Action == localaccount.ActionInvite {
		wire.NewAccountID, wire.NewUserID = &params.NewAccountID, &params.NewUserID
		wire.DisplayName, wire.CanonicalLoginIdentifier = &params.DisplayName, &params.CanonicalLoginIdentifier
		wire.ProtectedRecoveryPrincipal = &params.ProtectedRecoveryPrincipal
	} else {
		wire.AccountID = &params.AccountID
	}
	if params.PendingTOTPEnrollment != nil {
		pending := params.PendingTOTPEnrollment
		wire.IssueEnrollment = &platformLocalAccountIssueEnrollmentWire{
			AccountID: pending.AccountID, UserID: pending.UserID, FactorID: pending.FactorID,
			Purpose: string(pending.Purpose), Version: pending.Version,
			FactorRevision:      pending.FactorRevision,
			CeremonyTokenDigest: base64.StdEncoding.EncodeToString(pending.CeremonyTokenDigest[:]),
			Ciphertext:          base64.StdEncoding.EncodeToString(pending.ProtectedSecret.Ciphertext),
			Nonce:               base64.StdEncoding.EncodeToString(pending.ProtectedSecret.Nonce),
			AAD:                 base64.StdEncoding.EncodeToString(pending.ProtectedSecret.AAD),
			KeyVersion:          pending.ProtectedSecret.KeyVersion, ExpiresAt: pending.ExpiresAt,
		}
	}
	if len(params.ReplacementPasswordPHC) != 0 {
		value := string(params.ReplacementPasswordPHC)
		wire.ReplacementPasswordPHC = &value
		defer func() { value = "" }()
	}
	encoded, err := json.Marshal(wire)
	if wire.IssueEnrollment != nil {
		wire.IssueEnrollment.CeremonyTokenDigest = ""
		wire.IssueEnrollment.Ciphertext = ""
		wire.IssueEnrollment.Nonce = ""
		wire.IssueEnrollment.AAD = ""
	}
	if err != nil || len(encoded) == 0 || len(encoded) > maximumPlatformLocalAccountCommandBytes {
		clear(encoded)
		return nil, errors.New("encode platform local-account command")
	}
	return encoded, nil
}

func platformLocalAccountPendingEnrollment(
	preparation platformLocalAccountPreparation,
	params platformlocalaccount.ApplyParams,
) (platformlocalaccount.PendingTOTPEnrollment, error) {
	if !preparation.pendingFactorID.Valid || !preparation.pendingUserID.Valid ||
		!preparation.pendingPurpose.Valid || !preparation.pendingVersion.Valid ||
		!preparation.pendingFactorRevision.Valid || !preparation.pendingKeyVersion.Valid ||
		!preparation.pendingExpiresAt.Valid || len(preparation.pendingSecretCiphertext) == 0 ||
		len(preparation.pendingSecretNonce) == 0 || len(preparation.pendingSecretAAD) == 0 {
		return platformlocalaccount.PendingTOTPEnrollment{}, errors.New("missing pending enrollment")
	}
	purpose := platformlocalaccount.TOTPEnrollmentPurpose(preparation.pendingPurpose.String)
	if purpose != platformlocalaccount.TOTPEnrollmentInvite && purpose != platformlocalaccount.TOTPEnrollmentRecover ||
		preparation.pendingVersion.Int64 < 1 || preparation.pendingFactorRevision.Int64 < 1 ||
		preparation.pendingKeyVersion.Int32 < 1 {
		return platformlocalaccount.PendingTOTPEnrollment{}, errors.New("invalid pending enrollment")
	}
	return platformlocalaccount.PendingTOTPEnrollment{
		AccountID: params.AccountID, UserID: uuid.UUID(preparation.pendingUserID.Bytes),
		FactorID: uuid.UUID(preparation.pendingFactorID.Bytes), Purpose: purpose,
		Version:             uint64(preparation.pendingVersion.Int64),
		FactorRevision:      uint64(preparation.pendingFactorRevision.Int64),
		CeremonyTokenDigest: params.CeremonyTokenDigest,
		ProtectedSecret: authentication.EncryptedSecret{
			Ciphertext: append([]byte(nil), preparation.pendingSecretCiphertext...),
			Nonce:      append([]byte(nil), preparation.pendingSecretNonce...),
			AAD:        append([]byte(nil), preparation.pendingSecretAAD...),
			KeyVersion: int16(preparation.pendingKeyVersion.Int32),
		},
		ExpiresAt: preparation.pendingExpiresAt.Time,
	}, nil
}

func platformLocalAccountConfirmedFactor(
	factor platformlocalaccount.ConfirmedTOTPFactor,
) *platformLocalAccountConfirmedFactorWire {
	return &platformLocalAccountConfirmedFactorWire{
		FactorID: factor.FactorID, Revision: factor.Revision,
		Ciphertext: base64.StdEncoding.EncodeToString(factor.ProtectedSecret.Ciphertext),
		Nonce:      base64.StdEncoding.EncodeToString(factor.ProtectedSecret.Nonce),
		AAD:        base64.StdEncoding.EncodeToString(factor.ProtectedSecret.AAD),
		KeyVersion: factor.ProtectedSecret.KeyVersion, AcceptedCounter: factor.AcceptedCounter,
		EncryptionAlgorithm: factor.EncryptionAlgorithm, OTPAlgorithm: factor.OTPAlgorithm,
		Digits: factor.Digits, PeriodSeconds: factor.PeriodSeconds,
	}
}

func decodePlatformLocalAccount(document []byte) (platformlocalaccount.Account, error) {
	if err := requirePlatformLocalAccountObjectKeys(document,
		"id", "userId", "displayName", "loginIdentifier", "status",
		"loginIdentifierStatus", "credentialStatus", "credentialVersion",
		"confirmedAcceptableFactors", "protectedRecoveryPrincipal", "revision",
		"identityEpoch", "invitedAt", "activatedAt", "disabledAt",
		"recoveryStartedAt", "updatedAt",
	); err != nil {
		return platformlocalaccount.Account{}, err
	}
	var wire platformLocalAccountWire
	if err := decodePlatformLocalAccountJSON(document, &wire, maximumPlatformLocalAccountDocumentBytes); err != nil {
		return platformlocalaccount.Account{}, err
	}
	account := platformlocalaccount.Account{
		ID: wire.ID, UserID: wire.UserID, DisplayName: wire.DisplayName,
		LoginIdentifier: wire.LoginIdentifier, Status: wire.Status,
		LoginIdentifierStatus: wire.LoginIdentifierStatus, CredentialStatus: wire.CredentialStatus,
		CredentialVersion:          wire.CredentialVersion,
		ConfirmedAcceptableFactors: wire.ConfirmedAcceptableFactors,
		ProtectedRecoveryPrincipal: wire.ProtectedRecoveryPrincipal,
		Revision:                   wire.Revision, IdentityEpoch: wire.IdentityEpoch, InvitedAt: wire.InvitedAt,
		ActivatedAt: wire.ActivatedAt, DisabledAt: wire.DisabledAt,
		RecoveryStartedAt: wire.RecoveryStartedAt, UpdatedAt: wire.UpdatedAt,
	}
	if !platformlocalaccount.ValidAccountProjection(account) {
		return platformlocalaccount.Account{}, errors.New("invalid platform local-account projection")
	}
	return account, nil
}

func decodePlatformLocalAccountApplyResult(document []byte) (platformlocalaccount.ApplyResult, error) {
	if err := requirePlatformLocalAccountObjectKeys(document, "account", "replayed", "artifactIssued"); err != nil {
		return platformlocalaccount.ApplyResult{}, err
	}
	var wire platformLocalAccountApplyResultWire
	if err := decodePlatformLocalAccountJSON(document, &wire, maximumPlatformLocalAccountDocumentBytes); err != nil {
		return platformlocalaccount.ApplyResult{}, err
	}
	account, err := decodePlatformLocalAccount(wire.Account)
	if err != nil {
		return platformlocalaccount.ApplyResult{}, err
	}
	return platformlocalaccount.ApplyResult{
		Account: account, Replayed: wire.Replayed, ArtifactIssued: wire.ArtifactIssued,
	}, nil
}

func decodePlatformLocalAccountPlanning(document []byte) (platformlocalaccount.PlanningState, error) {
	if err := requirePlatformLocalAccountObjectKeys(
		document, "snapshot", "recoveryFleet", "freshLocalMFA", "protectedWorkflow",
	); err != nil {
		return platformlocalaccount.PlanningState{}, err
	}
	var envelope map[string]json.RawMessage
	if err := decodePlatformLocalAccountJSON(document, &envelope, maximumPlatformLocalAccountDocumentBytes); err != nil {
		return platformlocalaccount.PlanningState{}, err
	}
	if err := requirePlatformLocalAccountObjectKeys(
		envelope["recoveryFleet"], "currentPrincipalReady", "otherReadyHumanPrincipals",
	); err != nil {
		return platformlocalaccount.PlanningState{}, err
	}
	var wire platformLocalAccountPlanningWire
	if err := decodePlatformLocalAccountJSON(document, &wire, maximumPlatformLocalAccountDocumentBytes); err != nil {
		return platformlocalaccount.PlanningState{}, err
	}
	snapshot := localaccount.Snapshot{Revision: wire.Snapshot.Revision, IdentityEpoch: wire.Snapshot.IdentityEpoch,
		ConfirmedAcceptableFactors: wire.Snapshot.ConfirmedAcceptableFactors,
		ProtectedRecoveryPrincipal: wire.Snapshot.ProtectedRecoveryPrincipal}
	if wire.Snapshot.Status == "absent" {
		if err := requirePlatformLocalAccountObjectKeys(
			envelope["snapshot"], "status", "revision", "identityEpoch",
		); err != nil {
			return platformlocalaccount.PlanningState{}, err
		}
		if wire.Snapshot.AccountID != nil || wire.Snapshot.UserID != nil || snapshot.Revision != 0 ||
			snapshot.IdentityEpoch != 0 || wire.Snapshot.LoginIdentifierStatus != "" ||
			wire.Snapshot.CredentialStatus != "" || snapshot.ConfirmedAcceptableFactors != 0 ||
			snapshot.ProtectedRecoveryPrincipal {
			return platformlocalaccount.PlanningState{}, errors.New("invalid absent planning snapshot")
		}
	} else {
		if err := requirePlatformLocalAccountObjectKeys(
			envelope["snapshot"], "accountId", "userId", "revision", "identityEpoch",
			"status", "loginIdentifierStatus", "credentialStatus",
			"confirmedAcceptableFactors", "protectedRecoveryPrincipal",
		); err != nil {
			return platformlocalaccount.PlanningState{}, err
		}
		if wire.Snapshot.AccountID == nil || wire.Snapshot.UserID == nil ||
			!authorizationUUIDv7(*wire.Snapshot.AccountID) || !authorizationUUIDv7(*wire.Snapshot.UserID) {
			return platformlocalaccount.PlanningState{}, errors.New("invalid planning identity")
		}
		snapshot.AccountID = identity.EntityID(*wire.Snapshot.AccountID)
		snapshot.UserID = identity.EntityID(*wire.Snapshot.UserID)
		status, identifier, credential, err := platformLocalAccountPlanningEnums(
			wire.Snapshot.Status, wire.Snapshot.LoginIdentifierStatus, wire.Snapshot.CredentialStatus,
		)
		if err != nil {
			return platformlocalaccount.PlanningState{}, err
		}
		snapshot.Status, snapshot.LoginIdentifier, snapshot.Credential = status, identifier, credential
	}
	return platformlocalaccount.PlanningState{
		Snapshot: snapshot,
		RecoveryFleet: localaccount.RecoveryFleet{
			CurrentPrincipalReady:     wire.RecoveryFleet.CurrentPrincipalReady,
			OtherReadyHumanPrincipals: wire.RecoveryFleet.OtherReadyHumanPrincipals,
		},
		FreshLocalMFA: wire.FreshLocalMFA, ProtectedWorkflow: wire.ProtectedWorkflow,
	}, nil
}

func platformLocalAccountPlanningEnums(
	status, identifier, credential string,
) (localaccount.Status, localaccount.LoginIdentifierStatus, localaccount.CredentialStatus, error) {
	statuses := map[string]localaccount.Status{
		"invited": localaccount.StatusInvited, "active": localaccount.StatusActive,
		"disabled": localaccount.StatusDisabled, "recovery_restricted": localaccount.StatusRecoveryRestricted,
	}
	identifiers := map[string]localaccount.LoginIdentifierStatus{
		"pending": localaccount.LoginIdentifierPending, "verified": localaccount.LoginIdentifierVerified,
		"disabled": localaccount.LoginIdentifierDisabled,
	}
	credentials := map[string]localaccount.CredentialStatus{
		"pending": localaccount.CredentialPending, "active": localaccount.CredentialActive,
		"disabled": localaccount.CredentialDisabled,
	}
	mappedStatus, statusOK := statuses[status]
	mappedIdentifier, identifierOK := identifiers[identifier]
	mappedCredential, credentialOK := credentials[credential]
	if !statusOK || !identifierOK || !credentialOK {
		return 0, 0, 0, errors.New("invalid planning lifecycle")
	}
	return mappedStatus, mappedIdentifier, mappedCredential, nil
}

func decodePlatformLocalAccountJSON(document []byte, target any, maximum int) error {
	if target == nil || len(document) == 0 || len(document) > maximum {
		return errors.New("invalid platform local-account document")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("platform local-account document has trailing data")
	}
	return nil
}

func requirePlatformLocalAccountObjectKeys(document []byte, expected ...string) error {
	if len(document) == 0 || len(document) > maximumPlatformLocalAccountDocumentBytes {
		return errors.New("invalid platform local-account object")
	}
	var object map[string]json.RawMessage
	if err := decodePlatformLocalAccountJSON(
		document, &object, maximumPlatformLocalAccountDocumentBytes,
	); err != nil || len(object) != len(expected) {
		return errors.New("invalid platform local-account object shape")
	}
	for _, key := range expected {
		if _, found := object[key]; !found {
			return errors.New("invalid platform local-account object shape")
		}
	}
	return nil
}

func platformLocalAccountHistory(values []string) ([][]byte, error) {
	if len(values) > 25 {
		return nil, errors.New("platform local-account password history is oversized")
	}
	history := make([][]byte, len(values))
	for index, value := range values {
		if len(value) < 32 || len(value) > 1024 {
			clearPlatformLocalAccountHistory(history)
			return nil, errors.New("invalid platform local-account password history")
		}
		history[index] = []byte(value)
	}
	return history, nil
}

func clearPlatformLocalAccountHistory(history [][]byte) {
	for index := range history {
		clear(history[index])
		history[index] = nil
	}
	clear(history)
}

func platformLocalAccountAction(action localaccount.Action) (string, error) {
	switch action {
	case localaccount.ActionInvite:
		return "invite", nil
	case localaccount.ActionActivate:
		return "activate", nil
	case localaccount.ActionDisable:
		return "disable", nil
	case localaccount.ActionRecover:
		return "recover", nil
	case localaccount.ActionEnable:
		return "enable", nil
	case localaccount.ActionRotatePassword:
		return "rotate_password", nil
	default:
		return "", authentication.ErrInvalidInput
	}
}

func validatePlatformLocalAccountSession(params platformlocalaccount.SessionParams) error {
	if !authorizationUUIDv7(params.ActorID) || !authorizationUUIDv7(params.SessionID) {
		return authentication.ErrInvalidInput
	}
	switch params.AuthenticationMethod {
	case "bootstrap_totp", "oidc", "passkey", "recovery_code", "saml", "totp":
		return nil
	default:
		return authentication.ErrInvalidInput
	}
}

func validatePlatformLocalAccountApply(params platformlocalaccount.ApplyParams) error {
	if err := validatePlatformLocalAccountSession(params.SessionParams); err != nil ||
		!authorizationUUIDv7(params.CommandID) || params.ExpectedRevision > 9_007_199_254_740_990 ||
		params.At.IsZero() || params.At.Location() != time.UTC ||
		params.At.Nanosecond()%int(time.Millisecond) != 0 || params.Plan == nil || params.ValidateResult == nil {
		return authentication.ErrInvalidInput
	}
	if _, err := platformLocalAccountAction(params.Action); err != nil {
		return err
	}
	if params.Action == localaccount.ActionInvite {
		if params.AccountID != uuid.Nil || !authorizationUUIDv7(params.NewAccountID) ||
			!authorizationUUIDv7(params.NewUserID) || params.ExpectedRevision != 0 ||
			params.PendingTOTPEnrollment == nil {
			return authentication.ErrInvalidInput
		}
	} else if !authorizationUUIDv7(params.AccountID) || params.NewAccountID != uuid.Nil ||
		params.NewUserID != uuid.Nil || params.ExpectedRevision == 0 {
		return authentication.ErrInvalidInput
	}
	return nil
}

func mapPlatformLocalAccountDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	for _, preserved := range []error{
		context.Canceled, context.DeadlineExceeded, platformlocalaccount.ErrPreconditionFailed,
		platformlocalaccount.ErrTransitionConflict, platformlocalaccount.ErrPasswordReused,
		platformlocalaccount.ErrEnrollmentProofRejected, authentication.ErrForbidden,
		authentication.ErrNotFound, authentication.ErrConflict, authentication.ErrInvalidInput,
	} {
		if errors.Is(err, preserved) {
			return preserved
		}
	}
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) {
		return authentication.ErrUnavailable
	}
	switch databaseError.Code {
	case "42501", "28000":
		return authentication.ErrForbidden
	case "P0002":
		return authentication.ErrNotFound
	case "P1003":
		return platformlocalaccount.ErrEnrollmentProofRejected
	case "40001":
		if databaseError.Message == "platform local-account revision conflict" {
			return platformlocalaccount.ErrPreconditionFailed
		}
		return authentication.ErrUnavailable
	case "23505":
		return authentication.ErrConflict
	case "55000":
		return platformlocalaccount.ErrTransitionConflict
	case "22023", "22P02", "23514":
		return authentication.ErrInvalidInput
	default:
		return authentication.ErrUnavailable
	}
}

func (repository *PlatformLocalAccountRepository) String() string {
	return "postgres.PlatformLocalAccountRepository{dependencies:[REDACTED]}"
}

func (repository *PlatformLocalAccountRepository) GoString() string { return repository.String() }
