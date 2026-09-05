package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/localaccount"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/platformlocalaccount"
)

var platformLocalAccountAdapterTestNow = time.Date(2026, 8, 30, 20, 0, 0, 123_000_000, time.UTC)

func TestPlatformLocalAccountInviteUsesFrozenCommandAndValidatesBeforeCommit(t *testing.T) {
	accountID := platformLocalAccountAdapterTestID(t)
	userID := platformLocalAccountAdapterTestID(t)
	commandID := platformLocalAccountAdapterTestID(t)
	tx := &platformLocalAccountAdapterTransaction{}
	tx.queryRow = func(query string, arguments []any, destinations []any) error {
		switch {
		case strings.Contains(query, "prepare_platform_local_account_transition_v1"):
			if len(arguments) != 12 || arguments[3] != "invite" || arguments[4] != uuid.Nil ||
				arguments[5] != accountID || arguments[6] != userID || arguments[10] != nil {
				t.Fatalf("prepare arguments = %#v", arguments)
			}
			setPlatformLocalAccountPreparation(t, destinations, false, nil,
				[]byte(`{"snapshot":{"status":"absent","revision":0,"identityEpoch":0},"recoveryFleet":{"currentPrincipalReady":false,"otherReadyHumanPrincipals":0},"freshLocalMFA":true,"protectedWorkflow":true}`),
				nil, platformLocalAccountPendingRow{})
			return nil
		case strings.Contains(query, "apply_platform_local_account_transition_v1"):
			if len(arguments) != 1 {
				t.Fatalf("apply arguments = %#v", arguments)
			}
			command := append([]byte(nil), arguments[0].([]byte)...)
			defer clear(command)
			if err := requirePlatformLocalAccountObjectKeys(command,
				"sessionId", "authenticationMethod", "commandId", "action", "accountId",
				"newAccountId", "newUserId", "expectedRevision", "at", "displayName",
				"canonicalLoginIdentifier", "protectedRecoveryPrincipal", "reason",
				"idempotencyKeyDigest", "publicRequestDigest", "issueEnrollment",
				"replacementPasswordPhc", "confirmedFactor", "plan", "audit",
			); err != nil {
				t.Fatal(err)
			}
			var wire platformLocalAccountCommandWire
			if err := decodePlatformLocalAccountJSON(command, &wire, maximumPlatformLocalAccountCommandBytes); err != nil {
				t.Fatal(err)
			}
			if wire.Action != "invite" || wire.AccountID != nil || wire.NewAccountID == nil ||
				*wire.NewAccountID != accountID || wire.NewUserID == nil || *wire.NewUserID != userID ||
				wire.IssueEnrollment == nil || wire.ReplacementPasswordPHC != nil || wire.ConfirmedFactor != nil {
				t.Fatalf("command = %#v", wire)
			}
			result := platformLocalAccountAdapterApplyResultJSON(t,
				platformLocalAccountAdapterInvitedAccount(accountID, userID), false, true)
			*destinations[0].(*[]byte) = result
			return nil
		default:
			return errors.New("unexpected platform local-account query")
		}
	}
	validatedBeforeCommit := false
	params := platformLocalAccountAdapterApplyParams(accountID, userID, commandID, localaccount.ActionInvite)
	params.Plan = func(state platformlocalaccount.PlanningState) (localaccount.Plan, error) {
		if state.Snapshot != (localaccount.Snapshot{}) || !state.FreshLocalMFA || !state.ProtectedWorkflow {
			t.Fatalf("planning state = %#v", state)
		}
		return localaccount.Plan{
			AccountID: identity.EntityID(accountID), UserID: identity.EntityID(userID),
			ExpectedRevision: 0, NextRevision: 1, NextIdentityEpoch: 1,
		}, nil
	}
	params.ValidateResult = func(result platformlocalaccount.ApplyResult) (platformlocalaccount.ApplyResult, error) {
		validatedBeforeCommit = !tx.committed
		return result, nil
	}
	repository := newPlatformLocalAccountRepositoryForTest(nil, platformLocalAccountAdapterBegin(t, tx))
	result, err := repository.Apply(context.Background(), params)
	if err != nil || result.Account.ID != accountID || result.Replayed || !result.ArtifactIssued ||
		!validatedBeforeCommit || !tx.committed || tx.queryRowCalls != 2 {
		t.Fatalf("Apply(invite) = %#v, %v; tx=%#v validated=%t", result, err, tx, validatedBeforeCommit)
	}
}

func TestPlatformLocalAccountActivationStagesCallbacksAndNeverSerializesProof(t *testing.T) {
	accountID := platformLocalAccountAdapterTestID(t)
	userID := platformLocalAccountAdapterTestID(t)
	factorID := platformLocalAccountAdapterTestID(t)
	commandID := platformLocalAccountAdapterTestID(t)
	ceremonyDigest := sha256.Sum256([]byte("ceremony-token"))
	pendingAAD := []byte("platform-local-account-test-pending-aad")
	tx := &platformLocalAccountAdapterTransaction{}
	tx.queryRow = func(query string, arguments []any, destinations []any) error {
		switch {
		case strings.Contains(query, "prepare_platform_local_account_transition_v1"):
			setPlatformLocalAccountPreparation(t, destinations, false, nil,
				platformLocalAccountAdapterPlanningJSON(t, accountID, userID, "invited", "pending", "pending", 0),
				[]string{"$argon2id$v=19$m=65536,t=3,p=1$history$history-value-that-is-long-enough"},
				platformLocalAccountPendingRow{
					factorID: factorID, userID: userID, purpose: "invite", version: 1,
					factorRevision: 1, ciphertext: bytes.Repeat([]byte{0x31}, 32),
					nonce: bytes.Repeat([]byte{0x32}, 12), aad: pendingAAD, keyVersion: 1,
					expiresAt: platformLocalAccountAdapterTestNow.Add(15 * time.Minute),
				})
			return nil
		case strings.Contains(query, "apply_platform_local_account_transition_v1"):
			command := append([]byte(nil), arguments[0].([]byte)...)
			defer clear(command)
			if bytes.Contains(command, []byte("123456")) || bytes.Contains(command, []byte("plain-ceremony")) {
				t.Fatalf("proof material leaked into command: %s", command)
			}
			var wire platformLocalAccountCommandWire
			if err := decodePlatformLocalAccountJSON(command, &wire, maximumPlatformLocalAccountCommandBytes); err != nil {
				t.Fatal(err)
			}
			if wire.Action != "activate" || wire.AccountID == nil || *wire.AccountID != accountID ||
				wire.ConfirmedFactor == nil || wire.ConfirmedFactor.FactorID != factorID ||
				wire.ReplacementPasswordPHC == nil || wire.IssueEnrollment != nil {
				t.Fatalf("activation command = %#v", wire)
			}
			result := platformLocalAccountAdapterApplyResultJSON(t,
				platformLocalAccountAdapterActiveAccount(accountID, userID, 2), false, false)
			*destinations[0].(*[]byte) = result
			return nil
		default:
			return errors.New("unexpected platform local-account query")
		}
	}
	historyCalls, factorCalls, planCalls := 0, 0, 0
	params := platformLocalAccountAdapterApplyParams(accountID, uuid.Nil, commandID, localaccount.ActionActivate)
	params.ExpectedRevision = 1
	params.CeremonyTokenDigest = ceremonyDigest
	params.ReplacementPasswordPHC = []byte("$argon2id$v=19$m=65536,t=3,p=1$replacement$replacement-value-long-enough")
	params.ValidatePasswordHistory = func(history [][]byte) error {
		historyCalls++
		if len(history) != 1 || !bytes.HasPrefix(history[0], []byte("$argon2id$")) {
			t.Fatalf("history = %q", history)
		}
		clearPlatformLocalAccountHistory(history)
		return nil
	}
	params.ConfirmTOTPEnrollment = func(
		pending platformlocalaccount.PendingTOTPEnrollment,
		lastCounter *int64,
	) (platformlocalaccount.ConfirmedTOTPFactor, error) {
		factorCalls++
		defer pending.Destroy()
		if pending.AccountID != accountID || pending.UserID != userID || pending.FactorID != factorID ||
			pending.CeremonyTokenDigest != ceremonyDigest || lastCounter != nil ||
			!bytes.Equal(pending.ProtectedSecret.AAD, pendingAAD) {
			t.Fatalf("pending = %#v counter=%v", pending, lastCounter)
		}
		return platformlocalaccount.ConfirmedTOTPFactor{
			FactorID: factorID, Revision: 1,
			ProtectedSecret: authentication.EncryptedSecret{
				Ciphertext: bytes.Repeat([]byte{0x41}, 32), Nonce: bytes.Repeat([]byte{0x42}, 12),
				AAD: []byte("confirmed-factor-aad"), KeyVersion: 1,
			},
			AcceptedCounter: 73, EncryptionAlgorithm: "aes-256-gcm", OTPAlgorithm: "SHA1",
			Digits: 6, PeriodSeconds: 30,
		}, nil
	}
	params.Plan = func(state platformlocalaccount.PlanningState) (localaccount.Plan, error) {
		planCalls++
		if state.Snapshot.Status != localaccount.StatusInvited ||
			state.Snapshot.LoginIdentifier != localaccount.LoginIdentifierVerified ||
			state.Snapshot.Credential != localaccount.CredentialActive ||
			state.Snapshot.ConfirmedAcceptableFactors != 1 {
			t.Fatalf("activation planner observed unstaged state: %#v", state)
		}
		return localaccount.Plan{
			AccountID: identity.EntityID(accountID), UserID: identity.EntityID(userID),
			ExpectedRevision: 1, NextRevision: 2, NextIdentityEpoch: 2,
		}, nil
	}
	params.ValidateResult = func(result platformlocalaccount.ApplyResult) (platformlocalaccount.ApplyResult, error) {
		return result, nil
	}
	repository := newPlatformLocalAccountRepositoryForTest(nil, platformLocalAccountAdapterBegin(t, tx))
	result, err := repository.Apply(context.Background(), params)
	if err != nil || result.Account.Status != platformlocalaccount.StatusActive ||
		historyCalls != 1 || factorCalls != 1 || planCalls != 1 || !tx.committed {
		t.Fatalf("Apply(activate) = %#v, %v; callbacks=%d/%d/%d", result, err, historyCalls, factorCalls, planCalls)
	}
}

func TestPlatformLocalAccountRejectedEnrollmentRecordsOneDetachedAttempt(t *testing.T) {
	accountID := platformLocalAccountAdapterTestID(t)
	userID := platformLocalAccountAdapterTestID(t)
	factorID := platformLocalAccountAdapterTestID(t)
	commandID := platformLocalAccountAdapterTestID(t)
	ceremonyDigest := sha256.Sum256([]byte("rejected-ceremony"))
	mutation := &platformLocalAccountAdapterTransaction{}
	mutation.queryRow = func(query string, _ []any, destinations []any) error {
		if !strings.Contains(query, "prepare_platform_local_account_transition_v1") {
			return errors.New("unexpected mutation query")
		}
		setPlatformLocalAccountPreparation(t, destinations, false, nil,
			platformLocalAccountAdapterPlanningJSON(t, accountID, userID, "invited", "pending", "pending", 0),
			[]string{}, platformLocalAccountPendingRow{
				factorID: factorID, userID: userID, purpose: "invite", version: 1, factorRevision: 1,
				ciphertext: bytes.Repeat([]byte{0x51}, 32), nonce: bytes.Repeat([]byte{0x52}, 12),
				aad: []byte("rejected-factor-aad"), keyVersion: 1,
				expiresAt: platformLocalAccountAdapterTestNow.Add(time.Minute),
			})
		return nil
	}
	record := &platformLocalAccountAdapterTransaction{}
	record.exec = func(query string, arguments []any) error {
		if !strings.Contains(query, "record_platform_local_account_enrollment_failure_v1") || len(arguments) != 1 {
			t.Fatalf("record query/arguments = %s / %#v", query, arguments)
		}
		command := arguments[0].([]byte)
		if err := requirePlatformLocalAccountObjectKeys(command,
			"sessionId", "authenticationMethod", "accountId", "expectedRevision",
			"ceremonyTokenDigest", "at",
		); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(command, []byte("123456")) {
			t.Fatal("factor proof leaked into failure record")
		}
		return nil
	}
	transactions := []*platformLocalAccountAdapterTransaction{mutation, record}
	beginCalls := 0
	repository := newPlatformLocalAccountRepositoryForTest(nil, func(_ context.Context, options pgx.TxOptions) (databaseTransaction, error) {
		if options.IsoLevel != pgx.Serializable || beginCalls >= len(transactions) {
			t.Fatalf("begin options/calls = %#v / %d", options, beginCalls)
		}
		tx := transactions[beginCalls]
		beginCalls++
		return tx, nil
	})
	params := platformLocalAccountAdapterApplyParams(accountID, uuid.Nil, commandID, localaccount.ActionActivate)
	params.ExpectedRevision = 1
	params.CeremonyTokenDigest = ceremonyDigest
	params.ReplacementPasswordPHC = []byte("$argon2id$v=19$m=65536,t=3,p=1$replacement$replacement-value-long-enough")
	params.ValidatePasswordHistory = func([][]byte) error { return nil }
	params.ConfirmTOTPEnrollment = func(
		pending platformlocalaccount.PendingTOTPEnrollment,
		_ *int64,
	) (platformlocalaccount.ConfirmedTOTPFactor, error) {
		pending.Destroy()
		return platformlocalaccount.ConfirmedTOTPFactor{}, platformlocalaccount.ErrEnrollmentProofRejected
	}
	params.Plan = func(platformlocalaccount.PlanningState) (localaccount.Plan, error) {
		t.Fatal("planner called after rejected proof")
		return localaccount.Plan{}, nil
	}
	params.ValidateResult = func(result platformlocalaccount.ApplyResult) (platformlocalaccount.ApplyResult, error) {
		return result, nil
	}
	_, err := repository.Apply(context.Background(), params)
	if !errors.Is(err, platformlocalaccount.ErrEnrollmentProofRejected) || beginCalls != 2 ||
		mutation.committed || mutation.rollbackCalls != 1 || !record.committed || record.execCalls != 1 {
		t.Fatalf("Apply(rejected proof) = %v; begin=%d mutation=%#v record=%#v", err, beginCalls, mutation, record)
	}
}

func TestPlatformLocalAccountDocumentsAndDatabaseErrorsFailClosed(t *testing.T) {
	account := platformLocalAccountAdapterActiveAccount(
		platformLocalAccountAdapterTestID(t), platformLocalAccountAdapterTestID(t), 4,
	)
	document, err := json.Marshal(platformLocalAccountWireFromAccount(account))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodePlatformLocalAccount(append(document, []byte(` {}`)...)); err == nil {
		t.Fatal("trailing document was accepted")
	}
	var object map[string]any
	if err = json.Unmarshal(document, &object); err != nil {
		t.Fatal(err)
	}
	delete(object, "revision")
	missing, _ := json.Marshal(object)
	if _, err = decodePlatformLocalAccount(missing); err == nil {
		t.Fatal("missing required account key was accepted")
	}
	object["revision"] = account.Revision
	object["secret"] = "must-not-be-accepted"
	extra, _ := json.Marshal(object)
	if _, err = decodePlatformLocalAccount(extra); err == nil {
		t.Fatal("unknown account key was accepted")
	}

	tests := []struct {
		code    string
		message string
		want    error
	}{
		{code: "42501", want: authentication.ErrForbidden},
		{code: "P0002", want: authentication.ErrNotFound},
		{code: "P1003", want: platformlocalaccount.ErrEnrollmentProofRejected},
		{code: "40001", message: "platform local-account revision conflict", want: platformlocalaccount.ErrPreconditionFailed},
		{code: "40001", message: "could not serialize access", want: authentication.ErrUnavailable},
		{code: "23505", want: authentication.ErrConflict},
		{code: "55000", want: platformlocalaccount.ErrTransitionConflict},
		{code: "22023", want: authentication.ErrInvalidInput},
		{code: "XX000", want: authentication.ErrUnavailable},
	}
	for _, test := range tests {
		if got := mapPlatformLocalAccountDatabaseError(&pgconn.PgError{Code: test.code, Message: test.message}); !errors.Is(got, test.want) {
			t.Errorf("map error %s/%q = %v, want %v", test.code, test.message, got, test.want)
		}
	}
}

type platformLocalAccountPendingRow struct {
	factorID       uuid.UUID
	userID         uuid.UUID
	purpose        string
	version        int64
	factorRevision int64
	ciphertext     []byte
	nonce          []byte
	aad            []byte
	keyVersion     int32
	expiresAt      time.Time
	lastCounter    *int64
}

func setPlatformLocalAccountPreparation(
	t *testing.T,
	destinations []any,
	replayed bool,
	result, planning []byte,
	history []string,
	pending platformLocalAccountPendingRow,
) {
	t.Helper()
	if len(destinations) != 15 {
		t.Fatalf("prepare destination count = %d", len(destinations))
	}
	*destinations[0].(*bool) = replayed
	*destinations[1].(*[]byte) = append([]byte(nil), result...)
	*destinations[2].(*[]byte) = append([]byte(nil), planning...)
	*destinations[3].(*[]string) = append([]string(nil), history...)
	if pending.factorID == uuid.Nil {
		return
	}
	*destinations[4].(*pgtype.UUID) = pgtype.UUID{Bytes: pending.factorID, Valid: true}
	*destinations[5].(*pgtype.UUID) = pgtype.UUID{Bytes: pending.userID, Valid: true}
	*destinations[6].(*pgtype.Text) = pgtype.Text{String: pending.purpose, Valid: true}
	*destinations[7].(*pgtype.Int8) = pgtype.Int8{Int64: pending.version, Valid: true}
	*destinations[8].(*pgtype.Int8) = pgtype.Int8{Int64: pending.factorRevision, Valid: true}
	*destinations[9].(*[]byte) = append([]byte(nil), pending.ciphertext...)
	*destinations[10].(*[]byte) = append([]byte(nil), pending.nonce...)
	*destinations[11].(*[]byte) = append([]byte(nil), pending.aad...)
	*destinations[12].(*pgtype.Int4) = pgtype.Int4{Int32: pending.keyVersion, Valid: true}
	*destinations[13].(*pgtype.Timestamptz) = pgtype.Timestamptz{Time: pending.expiresAt, Valid: true}
	if pending.lastCounter != nil {
		*destinations[14].(*pgtype.Int8) = pgtype.Int8{Int64: *pending.lastCounter, Valid: true}
	}
}

type platformLocalAccountAdapterTransaction struct {
	queryRow      func(string, []any, []any) error
	exec          func(string, []any) error
	queryRowCalls int
	execCalls     int
	committed     bool
	rollbackCalls int
}

func (tx *platformLocalAccountAdapterTransaction) Exec(
	_ context.Context,
	query string,
	arguments ...any,
) (pgconn.CommandTag, error) {
	tx.execCalls++
	if tx.exec == nil {
		return pgconn.CommandTag{}, errors.New("unexpected Exec")
	}
	return pgconn.CommandTag{}, tx.exec(query, arguments)
}

func (*platformLocalAccountAdapterTransaction) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query")
}

func (tx *platformLocalAccountAdapterTransaction) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) pgx.Row {
	tx.queryRowCalls++
	return platformLocalAccountAdapterRow(func(destinations ...any) error {
		if tx.queryRow == nil {
			return errors.New("unexpected QueryRow")
		}
		return tx.queryRow(query, arguments, destinations)
	})
}

func (tx *platformLocalAccountAdapterTransaction) Commit(context.Context) error {
	tx.committed = true
	return nil
}

func (tx *platformLocalAccountAdapterTransaction) Rollback(context.Context) error {
	tx.rollbackCalls++
	if tx.committed {
		return pgx.ErrTxClosed
	}
	return nil
}

type platformLocalAccountAdapterRow func(...any) error

func (row platformLocalAccountAdapterRow) Scan(destinations ...any) error {
	return row(destinations...)
}

func platformLocalAccountAdapterBegin(
	t *testing.T,
	tx *platformLocalAccountAdapterTransaction,
) transactionBeginner {
	t.Helper()
	return func(_ context.Context, options pgx.TxOptions) (databaseTransaction, error) {
		if options.IsoLevel != pgx.Serializable || options.AccessMode != "" {
			t.Fatalf("transaction options = %#v", options)
		}
		return tx, nil
	}
}

func platformLocalAccountAdapterApplyParams(
	accountID, newUserID, commandID uuid.UUID,
	action localaccount.Action,
) platformlocalaccount.ApplyParams {
	actorID := uuid.Must(uuid.NewV7())
	sessionID := uuid.Must(uuid.NewV7())
	idempotency := sha256.Sum256([]byte("idempotency"))
	request := sha256.Sum256([]byte("request"))
	params := platformlocalaccount.ApplyParams{
		SessionParams: platformlocalaccount.SessionParams{
			ActorID: actorID, SessionID: sessionID, AuthenticationMethod: "totp",
		},
		CommandID: commandID, Action: action, At: platformLocalAccountAdapterTestNow,
		Reason: "Reviewed protected identity transition", IdempotencyKeyDigest: idempotency,
		PublicRequestDigest: request,
		Event: authentication.EventContext{
			RequestID: uuid.Must(uuid.NewV7()), CorrelationID: uuid.Must(uuid.NewV7()),
			RemoteAddress: netip.MustParseAddr("192.0.2.45"), UserAgent: "platform-local-account-adapter-test/1.0",
		},
	}
	if action == localaccount.ActionInvite {
		params.NewAccountID, params.NewUserID = accountID, newUserID
		params.DisplayName = "Recovery Administrator"
		params.CanonicalLoginIdentifier = "recovery.admin@example.test"
		params.ProtectedRecoveryPrincipal = true
		ceremony := sha256.Sum256([]byte("issued-ceremony"))
		params.IssueCeremonyTokenDigest = ceremony
		params.IssueCeremonyTokenExpiresAt = platformLocalAccountAdapterTestNow.Add(30 * time.Minute)
		params.PendingTOTPEnrollment = &platformlocalaccount.PendingTOTPEnrollment{
			AccountID: accountID, UserID: newUserID, FactorID: uuid.Must(uuid.NewV7()),
			Purpose: platformlocalaccount.TOTPEnrollmentInvite, Version: 1, FactorRevision: 1,
			CeremonyTokenDigest: ceremony,
			ProtectedSecret: authentication.EncryptedSecret{
				Ciphertext: bytes.Repeat([]byte{0x61}, 32), Nonce: bytes.Repeat([]byte{0x62}, 12),
				AAD: []byte("issued-enrollment-aad"), KeyVersion: 1,
			},
			ExpiresAt: params.IssueCeremonyTokenExpiresAt,
		}
	} else {
		params.AccountID = accountID
	}
	return params
}

func platformLocalAccountAdapterPlanningJSON(
	t *testing.T,
	accountID, userID uuid.UUID,
	status, identifier, credential string,
	factors uint16,
) []byte {
	t.Helper()
	document, err := json.Marshal(map[string]any{
		"snapshot": map[string]any{
			"accountId": accountID, "userId": userID, "revision": 1, "identityEpoch": 1,
			"status": status, "loginIdentifierStatus": identifier, "credentialStatus": credential,
			"confirmedAcceptableFactors": factors, "protectedRecoveryPrincipal": true,
		},
		"recoveryFleet": map[string]any{
			"currentPrincipalReady": false, "otherReadyHumanPrincipals": 1,
		},
		"freshLocalMFA": true, "protectedWorkflow": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func platformLocalAccountAdapterApplyResultJSON(
	t *testing.T,
	account platformlocalaccount.Account,
	replayed, artifactIssued bool,
) []byte {
	t.Helper()
	document, err := json.Marshal(platformLocalAccountApplyResultWire{
		Account: func() json.RawMessage {
			encoded, encodeErr := json.Marshal(platformLocalAccountWireFromAccount(account))
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			return encoded
		}(),
		Replayed: replayed, ArtifactIssued: artifactIssued,
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func platformLocalAccountWireFromAccount(account platformlocalaccount.Account) platformLocalAccountWire {
	return platformLocalAccountWire{
		ID: account.ID, UserID: account.UserID, DisplayName: account.DisplayName,
		LoginIdentifier: account.LoginIdentifier, Status: account.Status,
		LoginIdentifierStatus: account.LoginIdentifierStatus,
		CredentialStatus:      account.CredentialStatus, CredentialVersion: account.CredentialVersion,
		ConfirmedAcceptableFactors: account.ConfirmedAcceptableFactors,
		ProtectedRecoveryPrincipal: account.ProtectedRecoveryPrincipal,
		Revision:                   account.Revision, IdentityEpoch: account.IdentityEpoch,
		InvitedAt: account.InvitedAt, ActivatedAt: account.ActivatedAt,
		DisabledAt: account.DisabledAt, RecoveryStartedAt: account.RecoveryStartedAt,
		UpdatedAt: account.UpdatedAt,
	}
}

func platformLocalAccountAdapterInvitedAccount(accountID, userID uuid.UUID) platformlocalaccount.Account {
	return platformlocalaccount.Account{
		ID: accountID, UserID: userID, DisplayName: "Recovery Administrator",
		LoginIdentifier: "recovery.admin@example.test", Status: platformlocalaccount.StatusInvited,
		LoginIdentifierStatus:      platformlocalaccount.LoginIdentifierPending,
		CredentialStatus:           platformlocalaccount.CredentialPending,
		ProtectedRecoveryPrincipal: true, Revision: 1, IdentityEpoch: 1,
		InvitedAt: platformLocalAccountAdapterTestNow, UpdatedAt: platformLocalAccountAdapterTestNow,
	}
}

func platformLocalAccountAdapterActiveAccount(accountID, userID uuid.UUID, revision uint64) platformlocalaccount.Account {
	activatedAt := platformLocalAccountAdapterTestNow
	return platformlocalaccount.Account{
		ID: accountID, UserID: userID, DisplayName: "Recovery Administrator",
		LoginIdentifier: "recovery.admin@example.test", Status: platformlocalaccount.StatusActive,
		LoginIdentifierStatus: platformlocalaccount.LoginIdentifierVerified,
		CredentialStatus:      platformlocalaccount.CredentialActive, CredentialVersion: 1,
		ConfirmedAcceptableFactors: 1, ProtectedRecoveryPrincipal: true,
		Revision: revision, IdentityEpoch: revision, InvitedAt: platformLocalAccountAdapterTestNow,
		ActivatedAt: &activatedAt, UpdatedAt: platformLocalAccountAdapterTestNow,
	}
}

func platformLocalAccountAdapterTestID(t *testing.T) uuid.UUID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
