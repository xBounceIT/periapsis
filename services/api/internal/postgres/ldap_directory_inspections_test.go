package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

var (
	ldapDirectoryRunID      = uuid.MustParse("00000000-0000-7000-8000-000000000219")
	ldapDirectorySecretID   = uuid.MustParse("00000000-0000-7000-8000-000000000220")
	ldapDirectoryEndAuditID = uuid.MustParse("00000000-0000-7000-8000-000000000221")
)

func TestLDAPDirectoryInspectionRepositoryCommitsBeginAndOwnsSecretProjection(t *testing.T) {
	t.Parallel()

	h := newLDAPDirectoryInspectionHarness(t)
	params := ldapDirectoryInspectionBeginParams()
	snapshot, err := h.repository.BeginAdministrativeDirectoryInspection(h.context(), params)
	if err != nil {
		t.Fatalf("BeginAdministrativeDirectoryInspection() error = %v", err)
	}
	if snapshot.OperationRunID != ldapDirectoryRunID || snapshot.TenantID != ldapAdminTenantID ||
		snapshot.ProviderID != ldapAdminProviderID || snapshot.OperationKind != identityprovider.DirectoryOperationSearchUser ||
		snapshot.Secret.SecretID != ldapDirectorySecretID || snapshot.SecretVersion != 4 ||
		len(snapshot.Secret.Envelope.Ciphertext) != 32 || snapshot.Secret.Envelope.KeyVersion != 1 ||
		snapshot.ExpiresAt.Sub(snapshot.StartedAt) != time.Minute {
		t.Fatalf("directory snapshot = %#v", snapshot)
	}
	if h.queries.beginParams.OperationKind != "search_user" ||
		h.queries.beginParams.Reason != "administrative user search" ||
		domainUUIDMust(h.queries.beginParams.AuditEventID) != ldapAdminAuditEventID {
		t.Fatalf("begin query params = %#v", h.queries.beginParams)
	}
	if !allZero(h.queries.beginRow.BindSecretCiphertext) ||
		!allZero(h.queries.beginRow.BindSecretNonce) ||
		!allZero(h.queries.beginRow.EndpointSnapshotDigest) {
		t.Fatal("database secret-bearing projection was not cleared")
	}
	if allZero(snapshot.Secret.Envelope.Ciphertext) || allZero(snapshot.EndpointSnapshotDigest[:]) {
		t.Fatal("returned snapshot did not own independent protected bytes")
	}
	h.assertSuccess(t, "begin-directory-inspection")
}

func TestLDAPDirectoryInspectionRepositoryMapsDatabaseCompletionOverride(t *testing.T) {
	t.Parallel()

	h := newLDAPDirectoryInspectionHarness(t)
	h.queries.completeRow = &dbsql.CompleteTenantLDAPDirectoryInspectionRow{
		OperationRunID: toDatabaseUUID(ldapDirectoryRunID),
		Outcome:        string(identityprovider.TestOutcomeInconclusive),
		Category:       string(identityprovider.TestCategoryStaleConfiguration),
		DurationMs:     17,
		Stale:          true,
		CompletedAt:    pgtype.Timestamptz{Time: ldapAdminNow.Add(time.Second), Valid: true},
	}
	priority := 1
	completion, err := h.repository.CompleteDirectoryInspection(
		h.context(),
		identityprovider.CompleteDirectoryInspectionParams{
			HumanParams: ldapAdministrationHuman(), Audit: ldapAdministrationAudit(),
			OccurredAt: ldapAdminNow, OperationRunID: ldapDirectoryRunID,
			AuditEventID:     ldapDirectoryEndAuditID,
			ReportedOutcome:  identityprovider.TestOutcomeSuccess,
			ReportedCategory: identityprovider.TestCategorySuccess,
			EndpointPriority: &priority, Duration: 17 * time.Millisecond,
			MatchedEntryCount: 1, Truncated: true,
		},
	)
	if err != nil {
		t.Fatalf("CompleteDirectoryInspection() error = %v", err)
	}
	if completion.Diagnostic.TestRunID != ldapDirectoryRunID ||
		completion.Diagnostic.Outcome != identityprovider.TestOutcomeInconclusive ||
		completion.Diagnostic.Category != identityprovider.TestCategoryStaleConfiguration ||
		!completion.Diagnostic.Stale || completion.Diagnostic.EndpointPriority != nil ||
		completion.MatchedEntryCount != 0 || completion.Truncated {
		t.Fatalf("completion override = %#v", completion)
	}
	if h.queries.completeParams.EndpointPriority == nil ||
		*h.queries.completeParams.EndpointPriority != 1 ||
		h.queries.completeParams.MatchedEntryCount != 1 ||
		!h.queries.completeParams.Truncated ||
		domainUUIDMust(h.queries.completeParams.AuditEventID) != ldapDirectoryEndAuditID {
		t.Fatalf("completion query params = %#v", h.queries.completeParams)
	}
	h.assertSuccess(t, "complete-directory-inspection")
}

func TestLDAPDirectoryInspectionRepositoryRejectsInvalidProjectionAndCallerReport(t *testing.T) {
	t.Parallel()

	t.Run("foreign tenant projection rolls back", func(t *testing.T) {
		h := newLDAPDirectoryInspectionHarness(t)
		h.queries.beginRow.TenantID = toDatabaseUUID(ldapAdminProviderID)
		_, err := h.repository.BeginAdministrativeDirectoryInspection(
			h.context(),
			ldapDirectoryInspectionBeginParams(),
		)
		if !errors.Is(err, identityprovider.ErrUnavailable) {
			t.Fatalf("foreign projection error = %v", err)
		}
		h.assertRollback(t, "begin-directory-inspection")
	})

	t.Run("failure cannot retain result data", func(t *testing.T) {
		h := newLDAPDirectoryInspectionHarness(t)
		priority := 1
		_, err := h.repository.CompleteDirectoryInspection(
			h.context(),
			identityprovider.CompleteDirectoryInspectionParams{
				HumanParams: ldapAdministrationHuman(), Audit: ldapAdministrationAudit(),
				OccurredAt: ldapAdminNow, OperationRunID: ldapDirectoryRunID,
				AuditEventID:     ldapDirectoryEndAuditID,
				ReportedOutcome:  identityprovider.TestOutcomeFailure,
				ReportedCategory: identityprovider.TestCategoryProtocolFailed,
				EndpointPriority: &priority, Duration: time.Millisecond,
				MatchedEntryCount: 1,
			},
		)
		if !errors.Is(err, identityprovider.ErrInvalidInput) || len(h.events) != 0 {
			t.Fatalf("invalid completion error = %v, events = %v", err, h.events)
		}
	})
}

type ldapDirectoryInspectionQueriesStub struct {
	events                 *[]string
	expectedContextValue   any
	contextMismatch        bool
	setTenantContextResult *dbsql.SetTenantContextRow
	setTenantContextParams dbsql.SetTenantContextParams
	beginParams            dbsql.BeginTenantLDAPAdministrativeDirectoryInspectionParams
	beginRow               *dbsql.BeginTenantLDAPAdministrativeDirectoryInspectionRow
	dryRunBeginParams      dbsql.BeginTenantLDAPMappingDryRunParams
	dryRunBeginRow         *dbsql.BeginTenantLDAPMappingDryRunRow
	dryRunPlanningParams   dbsql.GetTenantLDAPMappingDryRunPlanningSnapshotParams
	dryRunPlanningRow      *dbsql.GetTenantLDAPMappingDryRunPlanningSnapshotRow
	completeParams         dbsql.CompleteTenantLDAPDirectoryInspectionParams
	completeRow            *dbsql.CompleteTenantLDAPDirectoryInspectionRow
	errors                 map[string]error
}

func (q *ldapDirectoryInspectionQueriesStub) record(ctx context.Context, operation string) error {
	*q.events = append(*q.events, operation)
	if ctx.Value(ldapAdministrationContextKey{}) != q.expectedContextValue {
		q.contextMismatch = true
	}
	return q.errors[operation]
}

func (q *ldapDirectoryInspectionQueriesStub) SetTenantContext(
	ctx context.Context,
	params dbsql.SetTenantContextParams,
) (*dbsql.SetTenantContextRow, error) {
	q.setTenantContextParams = params
	if err := q.record(ctx, "set-context"); err != nil {
		return nil, err
	}
	return q.setTenantContextResult, nil
}

func (q *ldapDirectoryInspectionQueriesStub) BeginTenantLDAPAdministrativeDirectoryInspection(
	ctx context.Context,
	params dbsql.BeginTenantLDAPAdministrativeDirectoryInspectionParams,
) (*dbsql.BeginTenantLDAPAdministrativeDirectoryInspectionRow, error) {
	q.beginParams = params
	if err := q.record(ctx, "begin-directory-inspection"); err != nil {
		return nil, err
	}
	return q.beginRow, nil
}

func (q *ldapDirectoryInspectionQueriesStub) CompleteTenantLDAPDirectoryInspection(
	ctx context.Context,
	params dbsql.CompleteTenantLDAPDirectoryInspectionParams,
) (*dbsql.CompleteTenantLDAPDirectoryInspectionRow, error) {
	q.completeParams = params
	if err := q.record(ctx, "complete-directory-inspection"); err != nil {
		return nil, err
	}
	return q.completeRow, nil
}

func (q *ldapDirectoryInspectionQueriesStub) BeginTenantLDAPMappingDryRun(
	ctx context.Context,
	params dbsql.BeginTenantLDAPMappingDryRunParams,
) (*dbsql.BeginTenantLDAPMappingDryRunRow, error) {
	q.dryRunBeginParams = params
	if err := q.record(ctx, "begin-mapping-dry-run"); err != nil {
		return nil, err
	}
	return q.dryRunBeginRow, nil
}

func (q *ldapDirectoryInspectionQueriesStub) GetTenantLDAPMappingDryRunPlanningSnapshot(
	ctx context.Context,
	params dbsql.GetTenantLDAPMappingDryRunPlanningSnapshotParams,
) (*dbsql.GetTenantLDAPMappingDryRunPlanningSnapshotRow, error) {
	q.dryRunPlanningParams = params
	if err := q.record(ctx, "get-mapping-dry-run-planning-snapshot"); err != nil {
		return nil, err
	}
	return q.dryRunPlanningRow, nil
}

type ldapDirectoryInspectionHarness struct {
	repository  *IdentityProviderRepository
	queries     *ldapDirectoryInspectionQueriesStub
	transaction *ldapAdministrationTransactionStub
	events      []string
	beginCalls  int
}

func newLDAPDirectoryInspectionHarness(t *testing.T) *ldapDirectoryInspectionHarness {
	t.Helper()
	harness := &ldapDirectoryInspectionHarness{}
	contextValue := &struct{}{}
	configuration, endpoints := identityProviderIntegrationDocuments()
	configurationDocument, endpointDocument, err := identityProviderDocuments(configuration, endpoints)
	if err != nil {
		t.Fatalf("identityProviderDocuments() error = %v", err)
	}
	ciphertext := make([]byte, 32)
	for index := range ciphertext {
		ciphertext[index] = byte(index + 1)
	}
	nonce := make([]byte, 12)
	for index := range nonce {
		nonce[index] = byte(index + 1)
	}
	harness.queries = &ldapDirectoryInspectionQueriesStub{
		events:               &harness.events,
		expectedContextValue: contextValue,
		setTenantContextResult: &dbsql.SetTenantContextRow{
			TenantID: ldapAdminTenantID.String(), UserID: ldapAdminUserID.String(),
		},
		beginRow: &dbsql.BeginTenantLDAPAdministrativeDirectoryInspectionRow{
			OperationRunID:         toDatabaseUUID(ldapDirectoryRunID),
			TenantID:               toDatabaseUUID(ldapAdminTenantID),
			ProviderID:             toDatabaseUUID(ldapAdminProviderID),
			ProviderVersion:        2,
			ConfigurationVersion:   3,
			EndpointSnapshotDigest: append([]byte(nil), ciphertext...),
			Configuration:          configurationDocument,
			Endpoints:              endpointDocument,
			BindSecretID:           toDatabaseUUID(ldapDirectorySecretID),
			BindSecretCiphertext:   ciphertext,
			BindSecretNonce:        nonce,
			BindSecretVersion:      4,
			BindSecretKeyVersion:   1,
			BindSecretAlgorithm:    "aes-256-gcm",
			StartedAt:              pgtype.Timestamptz{Time: ldapAdminNow, Valid: true},
			ExpiresAt:              pgtype.Timestamptz{Time: ldapAdminNow.Add(time.Minute), Valid: true},
		},
		completeRow: &dbsql.CompleteTenantLDAPDirectoryInspectionRow{
			OperationRunID:    toDatabaseUUID(ldapDirectoryRunID),
			Outcome:           string(identityprovider.TestOutcomeSuccess),
			Category:          string(identityprovider.TestCategorySuccess),
			EndpointPriority:  1,
			DurationMs:        17,
			MatchedEntryCount: 1,
			Truncated:         true,
			CompletedAt:       pgtype.Timestamptz{Time: ldapAdminNow.Add(time.Second), Valid: true},
		},
		errors: make(map[string]error),
	}
	harness.transaction = &ldapAdministrationTransactionStub{
		events: &harness.events, contextValue: contextValue,
	}
	harness.repository = &IdentityProviderRepository{
		begin: func(ctx context.Context, _ pgx.TxOptions) (databaseTransaction, error) {
			harness.events = append(harness.events, "begin")
			harness.beginCalls++
			if ctx.Value(ldapAdministrationContextKey{}) != contextValue {
				t.Fatalf("begin received a different context")
			}
			return harness.transaction, nil
		},
		directoryInspectionQueryFactory: func(tx databaseTransaction) ldapDirectoryInspectionQueries {
			harness.events = append(harness.events, "factory")
			if tx != harness.transaction {
				t.Fatalf("query factory transaction = %T", tx)
			}
			return harness.queries
		},
	}
	return harness
}

func (h *ldapDirectoryInspectionHarness) context() context.Context {
	return context.WithValue(
		context.Background(),
		ldapAdministrationContextKey{},
		h.transaction.contextValue,
	)
}

func (h *ldapDirectoryInspectionHarness) assertSuccess(t *testing.T, operation string) {
	t.Helper()
	want := []string{"begin", "factory", "set-context", operation, "commit", "rollback"}
	if !reflect.DeepEqual(h.events, want) || h.beginCalls != 1 ||
		h.queries.contextMismatch || h.transaction.commits != 1 || h.transaction.rollbacks != 1 {
		t.Fatalf(
			"successful transaction = events %v, begin %d, context mismatch %t, commits %d, rollbacks %d",
			h.events, h.beginCalls, h.queries.contextMismatch,
			h.transaction.commits, h.transaction.rollbacks,
		)
	}
}

func (h *ldapDirectoryInspectionHarness) assertRollback(t *testing.T, operation string) {
	t.Helper()
	want := []string{"begin", "factory", "set-context", operation, "rollback"}
	if !reflect.DeepEqual(h.events, want) || h.transaction.commits != 0 ||
		h.transaction.rollbacks != 1 {
		t.Fatalf("rolled-back transaction = events %v, commits %d, rollbacks %d",
			h.events, h.transaction.commits, h.transaction.rollbacks)
	}
}

func ldapDirectoryInspectionBeginParams() identityprovider.BeginAdministrativeDirectoryInspectionParams {
	return identityprovider.BeginAdministrativeDirectoryInspectionParams{
		HumanParams: ldapAdministrationHuman(), Audit: ldapAdministrationAudit(),
		OccurredAt: ldapAdminNow, OperationRunID: ldapDirectoryRunID,
		AuditEventID: ldapAdminAuditEventID, ProviderID: ldapAdminProviderID,
		OperationKind: identityprovider.DirectoryOperationSearchUser,
		Reason:        "administrative user search",
	}
}
