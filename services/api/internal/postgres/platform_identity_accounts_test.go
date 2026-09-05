package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityaccount"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

func TestNewPlatformIdentityAccountRepositoryRejectsNilPool(t *testing.T) {
	t.Parallel()
	repository, err := NewPlatformIdentityAccountRepository(nil)
	if err == nil || repository != nil {
		t.Fatalf("NewPlatformIdentityAccountRepository(nil) = %#v, %v", repository, err)
	}
}

func TestPlatformIdentityAccountReadsUseClosedProtectedProjection(t *testing.T) {
	t.Parallel()
	session, _ := platformIdentityAccountRepositoryAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	firstID := mustPostgresUUIDv7(t)
	secondID := mustPostgresUUIDv7(t)
	firstDocument := platformIdentityAccountDocument(t, firstID, providerID, mustPostgresUUIDv7(t), 1, false)
	secondDocument := platformIdentityAccountDocument(t, secondID, providerID, mustPostgresUUIDv7(t), 2, true)
	tx := &platformIdentityAccountTransaction{
		actorID:   session.ActorID,
		documents: [][]byte{firstDocument, secondDocument},
	}
	repository, beginCalls := platformIdentityAccountRepositoryHarness(t, tx, uuid.Nil)
	accounts, err := repository.List(context.Background(), platformidentityaccount.ListParams{
		SessionParams: session, ProviderID: providerID, Limit: 51, IncludeRetired: true,
	})
	if err != nil || len(accounts) != 2 || accounts[0].ID != firstID || accounts[1].ID != secondID ||
		accounts[0].State != platformidentityaccount.AccountStateActive ||
		accounts[1].State != platformidentityaccount.AccountStateRetired {
		t.Fatalf("List() accounts=%#v error=%v", accounts, err)
	}
	assertPlatformIdentityAccountTransaction(
		t, tx, beginCalls, "app.list_platform_identity_accounts_v2",
	)
	wantListArguments := []any{
		toDatabaseUUID(session.SessionID), session.AuthenticationMethod, toDatabaseUUID(providerID),
		pgtype.UUID{}, int32(51), true,
	}
	if !reflect.DeepEqual(tx.arguments[1], wantListArguments) {
		t.Fatalf("List() arguments = %#v, want %#v", tx.arguments[1], wantListArguments)
	}

	getTx := &platformIdentityAccountTransaction{actorID: session.ActorID}
	getTx.row = platformIdentityAccountDocumentRow(
		"app.get_platform_identity_account_v2", firstDocument,
	)
	getRepository, getBeginCalls := platformIdentityAccountRepositoryHarness(t, getTx, uuid.Nil)
	account, err := getRepository.Get(context.Background(), platformidentityaccount.GetParams{
		SessionParams: session, ProviderID: providerID, AccountID: firstID,
	})
	if err != nil || account.ID != firstID || account.ProviderID != providerID || account.User.Email == nil {
		t.Fatalf("Get() account=%#v error=%v", account, err)
	}
	assertPlatformIdentityAccountTransaction(
		t, getTx, getBeginCalls, "app.get_platform_identity_account_v2",
	)
}

func TestPlatformIdentityAccountProjectionRejectsPoisonAndMissingFields(t *testing.T) {
	t.Parallel()
	providerID := mustPostgresUUIDv7(t)
	document := platformIdentityAccountDocument(
		t, mustPostgresUUIDv7(t), providerID, mustPostgresUUIDv7(t), 1, false,
	)
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "protected ciphertext",
			mutate: func(value map[string]any) {
				value["subjectCiphertext"] = "do-not-project"
			},
		},
		{
			name: "protected issuer",
			mutate: func(value map[string]any) {
				value["issuer"] = "https://idp.example.invalid"
			},
		},
		{
			name: "missing nullable retirement key",
			mutate: func(value map[string]any) {
				delete(value, "retiredAt")
			},
		},
		{
			name: "missing observation state",
			mutate: func(value map[string]any) {
				delete(value, "lastObservationState")
			},
		},
		{
			name: "known observation without timestamp",
			mutate: func(value map[string]any) {
				value["lastObservedAt"] = nil
			},
		},
		{
			name: "unknown observation state",
			mutate: func(value map[string]any) {
				value["lastObservationState"] = "guessed"
			},
		},
		{
			name: "missing nullable email key",
			mutate: func(value map[string]any) {
				delete(value["user"].(map[string]any), "email")
			},
		},
		{
			name: "missing user version",
			mutate: func(value map[string]any) {
				delete(value["user"].(map[string]any), "version")
			},
		},
		{
			name: "nested user poison",
			mutate: func(value map[string]any) {
				value["user"].(map[string]any)["credential"] = "secret"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			poisoned := mutatePlatformIdentityAccountDocument(t, document, test.mutate)
			if _, err := decodePlatformIdentityAccount(poisoned); !errors.Is(err, authentication.ErrUnavailable) {
				t.Fatalf("decodePlatformIdentityAccount() error = %v, want unavailable", err)
			}
		})
	}
}

func TestPlatformIdentityAccountProjectionAcceptsOnlyRetiredLegacyUnknownWithoutTimestamp(t *testing.T) {
	t.Parallel()
	document := platformIdentityAccountDocument(
		t, mustPostgresUUIDv7(t), mustPostgresUUIDv7(t), mustPostgresUUIDv7(t), 1, true,
	)
	legacy := mutatePlatformIdentityAccountDocument(t, document, func(value map[string]any) {
		value["lastObservationState"] = "legacy_unknown"
		value["lastObservedAt"] = nil
	})
	account, err := decodePlatformIdentityAccount(legacy)
	if err != nil || account.LastObservationState != platformidentityaccount.LastObservationStateLegacyUnknown ||
		account.LastObservedAt != nil {
		t.Fatalf("decodePlatformIdentityAccount(legacy) = %#v, %v", account, err)
	}

	for name, mutate := range map[string]func(map[string]any){
		"timestamp present": func(value map[string]any) {
			value["lastObservedAt"] = value["retiredAt"]
		},
		"advanced version": func(value map[string]any) { value["version"] = float64(2) },
		"active": func(value map[string]any) {
			value["state"] = "active"
			value["retiredAt"] = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			poisoned := mutatePlatformIdentityAccountDocument(t, legacy, mutate)
			if _, decodeErr := decodePlatformIdentityAccount(poisoned); !errors.Is(decodeErr, authentication.ErrUnavailable) {
				t.Fatalf("decodePlatformIdentityAccount() error = %v, want unavailable", decodeErr)
			}
		})
	}
}

func TestPlatformIdentityAccountPrelinkOwnsProtectedBuffersAndValidatesBeforeCommit(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityAccountRepositoryAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	accountID := mustPostgresUUIDv7(t)
	userID := mustPostgresUUIDv7(t)
	auditID := mustPostgresUUIDv7(t)
	params := platformIdentityAccountPrelinkParams(t, session, event, providerID, accountID, userID)
	validatedWhileLive := false
	tx := &platformIdentityAccountTransaction{actorID: session.ActorID}
	params.ValidateResult = func(result platformidentityaccount.PrelinkResult) (
		platformidentityaccount.PrelinkResult,
		error,
	) {
		if tx.committed || tx.rolledBack {
			return platformidentityaccount.PrelinkResult{}, errors.New("validator ran outside live transaction")
		}
		validatedWhileLive = true
		return result, nil
	}
	tx.row = func(query string, arguments []any, destinations []any) error {
		if !strings.Contains(query, "app.prelink_platform_identity_account_v2") || len(destinations) != 4 {
			return errors.New("unexpected platform account prelink query")
		}
		*destinations[0].(*pgtype.UUID) = toDatabaseUUID(accountID)
		*destinations[1].(*int64) = 1
		*destinations[2].(*bool) = false
		*destinations[3].(*[]byte) = platformIdentityAccountDocument(t, accountID, providerID, userID, 1, false)
		tx.protectedBuffers = []any{
			arguments[7], arguments[8], arguments[10], arguments[11], arguments[12], arguments[13],
		}
		return nil
	}
	repository, beginCalls := platformIdentityAccountRepositoryHarness(t, tx, auditID)
	result, err := repository.Prelink(context.Background(), params)
	if err != nil || !validatedWhileLive || result.AccountID() != accountID || result.Replayed() ||
		result.Account().User.ID != userID {
		t.Fatalf("Prelink() result=%#v validated=%t error=%v", result, validatedWhileLive, err)
	}
	assertPlatformIdentityAccountTransaction(
		t, tx, beginCalls, "app.prelink_platform_identity_account_v2",
	)
	if len(tx.arguments[1]) != 21 || tx.arguments[1][5] != params.Issuer ||
		tx.arguments[1][6] != dbsql.IdentitySubjectFormatUtf8Exact ||
		!reflect.DeepEqual(tx.arguments[1][14], toDatabaseUUID(auditID)) {
		t.Fatalf("Prelink() arguments = %#v", tx.arguments[1])
	}
	assertPlatformIdentityAccountBuffersCleared(t, tx.protectedBuffers)
}

func TestPlatformIdentityAccountPrelinkReplayKeepsStableReceiptAndLiveProjection(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityAccountRepositoryAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	generatedAccountID := mustPostgresUUIDv7(t)
	replayedAccountID := mustPostgresUUIDv7(t)
	userID := mustPostgresUUIDv7(t)
	params := platformIdentityAccountPrelinkParams(
		t, session, event, providerID, generatedAccountID, userID,
	)
	tx := &platformIdentityAccountTransaction{actorID: session.ActorID}
	tx.row = func(query string, _ []any, destinations []any) error {
		if !strings.Contains(query, "app.prelink_platform_identity_account_v2") || len(destinations) != 4 {
			return errors.New("unexpected platform account replay query")
		}
		*destinations[0].(*pgtype.UUID) = toDatabaseUUID(replayedAccountID)
		*destinations[1].(*int64) = 1
		*destinations[2].(*bool) = true
		*destinations[3].(*[]byte) = platformIdentityAccountDocument(
			t, replayedAccountID, providerID, userID, 3, true,
		)
		return nil
	}
	repository, _ := platformIdentityAccountRepositoryHarness(t, tx, mustPostgresUUIDv7(t))
	result, err := repository.Prelink(context.Background(), params)
	if err != nil || !result.Replayed() || result.AccountID() != replayedAccountID ||
		result.Version() != 1 || result.Account().Version != 3 {
		t.Fatalf("Prelink() replay result=%#v account=%#v error=%v", result, result.Account(), err)
	}
}

func TestPlatformIdentityAccountMutationValidatorFailureRollsBack(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityAccountRepositoryAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	accountID := mustPostgresUUIDv7(t)
	userID := mustPostgresUUIDv7(t)
	params := platformIdentityAccountPrelinkParams(t, session, event, providerID, accountID, userID)
	params.ValidateResult = func(platformidentityaccount.PrelinkResult) (
		platformidentityaccount.PrelinkResult,
		error,
	) {
		return platformidentityaccount.PrelinkResult{}, authentication.ErrUnavailable
	}
	tx := &platformIdentityAccountTransaction{actorID: session.ActorID}
	tx.row = func(_ string, _ []any, destinations []any) error {
		*destinations[0].(*pgtype.UUID) = toDatabaseUUID(accountID)
		*destinations[1].(*int64) = 1
		*destinations[2].(*bool) = false
		*destinations[3].(*[]byte) = platformIdentityAccountDocument(t, accountID, providerID, userID, 1, false)
		return nil
	}
	repository, _ := platformIdentityAccountRepositoryHarness(t, tx, mustPostgresUUIDv7(t))
	_, err := repository.Prelink(context.Background(), params)
	if !errors.Is(err, authentication.ErrUnavailable) || tx.committed || !tx.rolledBack {
		t.Fatalf("Prelink() error=%v transaction commit=%t rollback=%t", err, tx.committed, tx.rolledBack)
	}
}

func TestPlatformIdentityAccountRetireUsesCASAndReturnsClosedProjection(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityAccountRepositoryAuthority(t)
	providerID := mustPostgresUUIDv7(t)
	accountID := mustPostgresUUIDv7(t)
	userID := mustPostgresUUIDv7(t)
	auditID := mustPostgresUUIDv7(t)
	validatedWhileLive := false
	tx := &platformIdentityAccountTransaction{actorID: session.ActorID}
	tx.row = func(query string, _ []any, destinations []any) error {
		if strings.Contains(query, "app.get_platform_identity_account_v2") && len(destinations) == 1 {
			*destinations[0].(*[]byte) = platformIdentityAccountDocument(
				t, accountID, providerID, userID, 1, false,
			)
			return nil
		}
		if !strings.Contains(query, "app.retire_platform_identity_account_v3") || len(destinations) != 3 {
			return errors.New("unexpected platform account retire query")
		}
		*destinations[0].(*pgtype.UUID) = toDatabaseUUID(accountID)
		*destinations[1].(*int64) = 2
		*destinations[2].(*[]byte) = platformIdentityAccountDocument(t, accountID, providerID, userID, 2, true)
		return nil
	}
	repository, beginCalls := platformIdentityAccountRepositoryHarness(t, tx, auditID)
	result, err := repository.Retire(context.Background(), platformidentityaccount.RetireParams{
		SessionParams: session, ProviderID: providerID, AccountID: accountID,
		ExpectedVersion: 1, ExpectedUserVersion: 1,
		Reason: "Approved account retirement", Event: event,
		ValidateResult: func(previous platformidentityaccount.Account, result platformidentityaccount.RetireResult) (
			platformidentityaccount.RetireResult,
			error,
		) {
			if previous.State != platformidentityaccount.AccountStateActive ||
				previous.Version != 1 || previous.User.Version != 1 {
				return platformidentityaccount.RetireResult{}, errors.New("invalid previous account")
			}
			validatedWhileLive = !tx.committed && !tx.rolledBack
			return result, nil
		},
	})
	if err != nil || !validatedWhileLive || result.Version() != 2 ||
		result.Account().State != platformidentityaccount.AccountStateRetired {
		t.Fatalf("Retire() result=%#v validated=%t error=%v", result, validatedWhileLive, err)
	}
	assertPlatformIdentityAccountTransaction(
		t, tx, beginCalls, "app.retire_platform_identity_account_v3",
	)
	if len(tx.arguments[2]) != 12 || tx.arguments[2][3] != int64(1) ||
		tx.arguments[2][4] != int64(1) ||
		!reflect.DeepEqual(tx.arguments[2][5], toDatabaseUUID(auditID)) {
		t.Fatalf("Retire() arguments = %#v", tx.arguments[2])
	}
}

func TestPlatformIdentityAccountRetireRejectsStaleEmbeddedUserBeforeMutation(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityAccountRepositoryAuthority(t)
	providerID, accountID, userID :=
		mustPostgresUUIDv7(t), mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)
	tx := &platformIdentityAccountTransaction{actorID: session.ActorID}
	tx.row = platformIdentityAccountDocumentRow(
		"app.get_platform_identity_account_v2",
		platformIdentityAccountDocument(t, accountID, providerID, userID, 1, false),
	)
	repository, beginCalls := platformIdentityAccountRepositoryHarness(t, tx, mustPostgresUUIDv7(t))
	_, err := repository.Retire(context.Background(), platformidentityaccount.RetireParams{
		SessionParams: session, ProviderID: providerID, AccountID: accountID,
		ExpectedVersion: 1, ExpectedUserVersion: 2,
		Reason: "Approved account retirement", Event: event,
		ValidateResult: func(
			platformidentityaccount.Account,
			platformidentityaccount.RetireResult,
		) (platformidentityaccount.RetireResult, error) {
			t.Fatal("Retire validator called after stale user revision")
			return platformidentityaccount.RetireResult{}, nil
		},
	})
	if !errors.Is(err, platformidentityaccount.ErrPreconditionFailed) ||
		*beginCalls != 1 || tx.committed || !tx.rolledBack || len(tx.queries) != 2 ||
		strings.Contains(strings.Join(tx.queries, "\n"), "app.retire_platform_identity_account_v3") {
		t.Fatalf(
			"Retire() error=%v begin=%d commit=%t rollback=%t queries=%#v",
			err, *beginCalls, tx.committed, tx.rolledBack, tx.queries,
		)
	}
}

func TestMapPlatformIdentityAccountDatabaseErrorIsClosed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "forbidden", err: &pgconn.PgError{Code: "42501"}, want: authentication.ErrForbidden},
		{name: "not found", err: &pgconn.PgError{Code: "P0002"}, want: authentication.ErrNotFound},
		{name: "no rows", err: pgx.ErrNoRows, want: authentication.ErrNotFound},
		{
			name: "precondition",
			err: &pgconn.PgError{
				Code: "40001", Message: platformIdentityAccountRevisionConflictMessage,
			},
			want: platformidentityaccount.ErrPreconditionFailed,
		},
		{name: "idempotency conflict", err: &pgconn.PgError{Code: "23505"}, want: authentication.ErrConflict},
		{
			name: "already retired",
			err: &pgconn.PgError{
				Code: "55000", Message: platformIdentityAccountAlreadyRetiredMessage,
			},
			want: authentication.ErrConflict,
		},
		{name: "invalid lifecycle", err: &pgconn.PgError{Code: "55000", Message: "account dependency is unavailable"}, want: authentication.ErrUnavailable},
		{name: "invalid", err: &pgconn.PgError{Code: "22023"}, want: authentication.ErrInvalidInput},
		{name: "constraint", err: &pgconn.PgError{Code: "23514"}, want: authentication.ErrInvalidInput},
		{name: "ambiguous serialization", err: &pgconn.PgError{Code: "40001", Message: "ambiguous alias"}, want: authentication.ErrUnavailable},
		{name: "internal", err: &pgconn.PgError{Code: "XX000"}, want: authentication.ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := mapPlatformIdentityAccountDatabaseError(test.err); !errors.Is(got, test.want) {
				t.Fatalf("mapPlatformIdentityAccountDatabaseError(%v) = %v, want %v", test.err, got, test.want)
			}
		})
	}
}

type platformIdentityAccountTransaction struct {
	recordingTransaction
	actorID          uuid.UUID
	row              func(string, []any, []any) error
	documents        [][]byte
	queries          []string
	arguments        [][]any
	protectedBuffers []any
}

func (tx *platformIdentityAccountTransaction) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) pgx.Row {
	tx.queries = append(tx.queries, query)
	tx.arguments = append(tx.arguments, append([]any(nil), arguments...))
	if strings.Contains(query, "set_config('app.user_id'") {
		return platformIdentityAccountRow(func(destinations ...any) error {
			if len(destinations) != 1 {
				return errors.New("unexpected platform identity account user context cardinality")
			}
			*destinations[0].(*string) = tx.actorID.String()
			return nil
		})
	}
	return platformIdentityAccountRow(func(destinations ...any) error {
		if tx.row == nil {
			return errors.New("unexpected platform identity account QueryRow")
		}
		return tx.row(query, arguments, destinations)
	})
}

func (tx *platformIdentityAccountTransaction) Query(
	_ context.Context,
	query string,
	arguments ...any,
) (pgx.Rows, error) {
	tx.queries = append(tx.queries, query)
	tx.arguments = append(tx.arguments, append([]any(nil), arguments...))
	if !strings.Contains(query, "app.list_platform_identity_accounts_v2") {
		return nil, errors.New("unexpected platform identity account Query")
	}
	return &platformIdentityAccountRows{documents: tx.documents}, nil
}

type platformIdentityAccountRow func(...any) error

func (row platformIdentityAccountRow) Scan(destinations ...any) error { return row(destinations...) }

type platformIdentityAccountRows struct {
	documents [][]byte
	index     int
}

func (*platformIdentityAccountRows) Close()                                       {}
func (*platformIdentityAccountRows) Err() error                                   { return nil }
func (*platformIdentityAccountRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (*platformIdentityAccountRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (rows *platformIdentityAccountRows) Next() bool {
	if rows.index >= len(rows.documents) {
		return false
	}
	rows.index++
	return true
}
func (rows *platformIdentityAccountRows) Scan(destinations ...any) error {
	if rows.index == 0 || rows.index > len(rows.documents) || len(destinations) != 1 {
		return errors.New("invalid platform identity account row scan")
	}
	document, ok := destinations[0].(*[]byte)
	if !ok {
		return errors.New("invalid platform identity account scan destination")
	}
	*document = append((*document)[:0], rows.documents[rows.index-1]...)
	return nil
}
func (rows *platformIdentityAccountRows) Values() ([]any, error) {
	if rows.index == 0 || rows.index > len(rows.documents) {
		return nil, errors.New("platform identity account row is not current")
	}
	return []any{rows.documents[rows.index-1]}, nil
}
func (*platformIdentityAccountRows) RawValues() [][]byte { return nil }
func (*platformIdentityAccountRows) Conn() *pgx.Conn     { return nil }

func platformIdentityAccountRepositoryHarness(
	t testing.TB,
	tx *platformIdentityAccountTransaction,
	auditID uuid.UUID,
) (*PlatformIdentityAccountRepository, *int) {
	t.Helper()
	beginCalls := 0
	repository := &PlatformIdentityAccountRepository{
		begin: func(_ context.Context, options pgx.TxOptions) (databaseTransaction, error) {
			beginCalls++
			if options.IsoLevel != pgx.ReadCommitted {
				t.Fatalf("transaction isolation = %q", options.IsoLevel)
			}
			return tx, nil
		},
		newID: func() (uuid.UUID, error) { return auditID, nil },
	}
	return repository, &beginCalls
}

func assertPlatformIdentityAccountTransaction(
	t testing.TB,
	tx *platformIdentityAccountTransaction,
	beginCalls *int,
	abi string,
) {
	t.Helper()
	if *beginCalls != 1 || !tx.committed || !tx.rolledBack {
		t.Fatalf("transaction state = begin:%d commit:%t rollback:%t", *beginCalls, tx.committed, tx.rolledBack)
	}
	wantQueryCount := 2
	finalQueryIndex := 1
	if strings.Contains(abi, "retire_platform_identity_account_v3") {
		wantQueryCount = 3
		finalQueryIndex = 2
		if len(tx.queries) >= 2 &&
			!strings.Contains(tx.queries[1], "app.get_platform_identity_account_v2") {
			t.Fatalf("queries = %#v", tx.queries)
		}
	}
	if len(tx.queries) != wantQueryCount || !strings.Contains(tx.queries[0], "set_config('app.user_id'") ||
		!strings.Contains(tx.queries[finalQueryIndex], abi) {
		t.Fatalf("queries = %#v", tx.queries)
	}
	if len(tx.arguments[0]) != 1 || !reflect.DeepEqual(tx.arguments[0][0], toDatabaseUUID(tx.actorID)) {
		t.Fatalf("user context arguments = %#v", tx.arguments[0])
	}
}

func platformIdentityAccountRepositoryAuthority(
	t testing.TB,
) (platformidentityaccount.SessionParams, authentication.EventContext) {
	t.Helper()
	return platformidentityaccount.SessionParams{
			ActorID: mustPostgresUUIDv7(t), SessionID: mustPostgresUUIDv7(t), AuthenticationMethod: "passkey",
		}, authentication.EventContext{
			RequestID: mustPostgresUUIDv7(t), CorrelationID: mustPostgresUUIDv7(t),
			RemoteAddress: netip.MustParseAddr("198.51.100.48"),
			UserAgent:     "platform-identity-account-adapter-test/1",
		}
}

func platformIdentityAccountPrelinkParams(
	t testing.TB,
	session platformidentityaccount.SessionParams,
	event authentication.EventContext,
	providerID, accountID, userID uuid.UUID,
) platformidentityaccount.PrelinkParams {
	t.Helper()
	aliases := []identity.SubjectAlias{
		{KeyVersion: 1, Digest: [32]byte{1}},
		{KeyVersion: 2, Digest: [32]byte{2}},
	}
	params := platformidentityaccount.PrelinkParams{
		SessionParams: session, CommandID: mustPostgresUUIDv7(t), AccountID: accountID,
		ProviderID: providerID, UserID: userID, Issuer: "https://idp.example.invalid",
		Subject: platformidentityaccount.ProtectedSubject{
			Aliases: aliases,
			Envelope: identity.ExternalSubjectEnvelope{
				KeyVersion: 2, Format: identity.UTF8ExactSubject,
				Nonce: [12]byte{1}, Ciphertext: []byte("0123456789abcdef1"),
			},
		},
		Reason: "Approved account prelink", Event: event,
		ValidateResult: func(result platformidentityaccount.PrelinkResult) (
			platformidentityaccount.PrelinkResult,
			error,
		) {
			return result, nil
		},
	}
	params.KeyDigest = [32]byte{3}
	params.PublicRequestDigest = [32]byte{4}
	return params
}

func platformIdentityAccountDocument(
	t testing.TB,
	accountID, providerID, userID uuid.UUID,
	version int64,
	retired bool,
) []byte {
	t.Helper()
	createdAt := time.Date(2026, 8, 29, 13, 30, 0, 123_456_000, time.UTC)
	updatedAt := createdAt
	var retiredAt *time.Time
	state := "active"
	if retired {
		updated := createdAt.Add(time.Minute)
		updatedAt = updated
		retiredAt = &updated
		state = "retired"
	}
	email := "operator@example.invalid"
	document, err := json.Marshal(map[string]any{
		"id": accountID, "providerId": providerID,
		"user": map[string]any{
			"id": userID, "displayName": "SOC Operator", "email": email, "active": true,
			"version": int64(1),
		},
		"state": state, "admittedConfigurationRevision": int64(1),
		"admittedSecurityRevision": int64(1), "lastObservationState": "known",
		"lastObservedAt": createdAt,
		"retiredAt":      retiredAt, "version": version, "createdAt": createdAt, "updatedAt": updatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func mutatePlatformIdentityAccountDocument(
	t testing.TB,
	document []byte,
	mutate func(map[string]any),
) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(document, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func platformIdentityAccountDocumentRow(
	abi string,
	document []byte,
) func(string, []any, []any) error {
	return func(query string, _ []any, destinations []any) error {
		if !strings.Contains(query, abi) || len(destinations) != 1 {
			return errors.New("unexpected platform identity account document query")
		}
		*destinations[0].(*[]byte) = append([]byte(nil), document...)
		return nil
	}
}

func assertPlatformIdentityAccountBuffersCleared(t testing.TB, values []any) {
	t.Helper()
	for _, raw := range values {
		switch value := raw.(type) {
		case []byte:
			if !platformIdentityAccountAllZero(value) {
				t.Fatalf("protected byte buffer was retained: %x", value)
			}
		case [][]byte:
			for _, item := range value {
				if !platformIdentityAccountAllZero(item) {
					t.Fatalf("protected digest buffer was retained: %x", item)
				}
			}
		case []int32:
			for _, item := range value {
				if item != 0 {
					t.Fatalf("protected key-version buffer was retained: %#v", value)
				}
			}
		default:
			t.Fatalf("unexpected protected buffer type %T", raw)
		}
	}
}
