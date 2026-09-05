package postgres

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

var (
	ldapSyncRunID       = uuid.MustParse("00000000-0000-7000-8000-000000000230")
	ldapSyncRunTailID   = uuid.MustParse("00000000-0000-7000-8000-000000000231")
	ldapSyncAuditID     = uuid.MustParse("00000000-0000-7000-8000-000000000232")
	ldapSyncAccessEpoch = uuid.MustParse("00000000-0000-7000-8000-000000000233")
)

type ldapSyncAdministrationQueriesStub struct {
	events               *[]string
	expectedContextValue any
	setContextResult     *dbsql.SetTenantContextRow
	statusRow            *dbsql.GetTenantLDAPSyncStatusRow
	listRows             []*dbsql.ListTenantLDAPSyncRunsRow
	getRow               *dbsql.GetTenantLDAPSyncRunRow
	beginRow             *dbsql.BeginTenantLDAPManualSyncV2Row
	setContextParams     dbsql.SetTenantContextParams
	statusParams         dbsql.GetTenantLDAPSyncStatusParams
	listParams           dbsql.ListTenantLDAPSyncRunsParams
	getParams            []dbsql.GetTenantLDAPSyncRunParams
	beginParams          dbsql.BeginTenantLDAPManualSyncV2Params
	errors               map[string]error
	contextMismatch      bool
}

func (q *ldapSyncAdministrationQueriesStub) record(ctx context.Context, operation string) error {
	*q.events = append(*q.events, operation)
	if ctx.Value(ldapAdministrationContextKey{}) != q.expectedContextValue {
		q.contextMismatch = true
	}
	return q.errors[operation]
}

func (q *ldapSyncAdministrationQueriesStub) SetTenantContext(
	ctx context.Context,
	params dbsql.SetTenantContextParams,
) (*dbsql.SetTenantContextRow, error) {
	q.setContextParams = params
	if err := q.record(ctx, "set-context"); err != nil {
		return nil, err
	}
	return q.setContextResult, nil
}

func (q *ldapSyncAdministrationQueriesStub) GetTenantLDAPSyncStatus(
	ctx context.Context,
	params dbsql.GetTenantLDAPSyncStatusParams,
) (*dbsql.GetTenantLDAPSyncStatusRow, error) {
	q.statusParams = params
	if err := q.record(ctx, "get-status"); err != nil {
		return nil, err
	}
	return q.statusRow, nil
}

func (q *ldapSyncAdministrationQueriesStub) ListTenantLDAPSyncRuns(
	ctx context.Context,
	params dbsql.ListTenantLDAPSyncRunsParams,
) ([]*dbsql.ListTenantLDAPSyncRunsRow, error) {
	q.listParams = params
	if err := q.record(ctx, "list-runs"); err != nil {
		return nil, err
	}
	return q.listRows, nil
}

func (q *ldapSyncAdministrationQueriesStub) GetTenantLDAPSyncRun(
	ctx context.Context,
	params dbsql.GetTenantLDAPSyncRunParams,
) (*dbsql.GetTenantLDAPSyncRunRow, error) {
	q.getParams = append(q.getParams, params)
	if err := q.record(ctx, "get-run"); err != nil {
		return nil, err
	}
	return q.getRow, nil
}

func (q *ldapSyncAdministrationQueriesStub) BeginTenantLDAPManualSyncV2(
	ctx context.Context,
	params dbsql.BeginTenantLDAPManualSyncV2Params,
) (*dbsql.BeginTenantLDAPManualSyncV2Row, error) {
	q.beginParams = params
	if err := q.record(ctx, "begin-manual"); err != nil {
		return nil, err
	}
	return q.beginRow, nil
}

type ldapSyncAdministrationHarness struct {
	repository  *IdentityProviderRepository
	queries     *ldapSyncAdministrationQueriesStub
	transaction *ldapAdministrationTransactionStub
	events      []string
	beginCalls  int
}

func newLDAPSyncAdministrationHarness(t *testing.T) *ldapSyncAdministrationHarness {
	t.Helper()
	harness := &ldapSyncAdministrationHarness{}
	contextValue := &struct{}{}
	harness.queries = &ldapSyncAdministrationQueriesStub{
		events: &harness.events, expectedContextValue: contextValue,
		setContextResult: &dbsql.SetTenantContextRow{
			TenantID: ldapAdminTenantID.String(), UserID: ldapAdminUserID.String(),
		},
		statusRow: ldapSyncStatusRow(), getRow: ldapSyncGotRunRow(ldapSyncRunID),
		beginRow: &dbsql.BeginTenantLDAPManualSyncV2Row{SyncRunID: toDatabaseUUID(ldapSyncRunID)},
		errors:   make(map[string]error),
	}
	harness.transaction = &ldapAdministrationTransactionStub{events: &harness.events, contextValue: contextValue}
	harness.repository = &IdentityProviderRepository{
		begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
			harness.events = append(harness.events, "begin")
			harness.beginCalls++
			return harness.transaction, nil
		},
		syncAdministrationQueryFactory: func(tx databaseTransaction) ldapSyncAdministrationQueries {
			harness.events = append(harness.events, "factory")
			if tx != harness.transaction {
				t.Fatalf("query factory transaction = %T", tx)
			}
			return harness.queries
		},
	}
	return harness
}

func (h *ldapSyncAdministrationHarness) context() context.Context {
	return context.WithValue(context.Background(), ldapAdministrationContextKey{}, h.transaction.contextValue)
}

func (h *ldapSyncAdministrationHarness) assertSuccess(t *testing.T, operations ...string) {
	t.Helper()
	want := append([]string{"begin", "factory", "set-context"}, operations...)
	want = append(want, "commit", "rollback")
	if !slices.Equal(h.events, want) || h.beginCalls != 1 || h.queries.contextMismatch ||
		h.transaction.commits != 1 || h.transaction.rollbacks != 1 {
		t.Fatalf("transaction = events:%v want:%v begin:%d context-mismatch:%t commit:%d rollback:%d",
			h.events, want, h.beginCalls, h.queries.contextMismatch,
			h.transaction.commits, h.transaction.rollbacks)
	}
	if domainUUIDMust(h.queries.setContextParams.TenantID) != ldapAdminTenantID ||
		domainUUIDMust(h.queries.setContextParams.UserID) != ldapAdminUserID {
		t.Fatalf("installed context = %#v", h.queries.setContextParams)
	}
}

func TestLDAPSyncAdministrationReadsUseProtectedBoundedTransactions(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		h := newLDAPSyncAdministrationHarness(t)
		status, err := h.repository.GetSyncStatus(h.context(), identityprovider.GetSyncStatusParams{
			HumanParams: ldapAdministrationHuman(), BindingID: ldapAdminBindingID,
		})
		if err != nil || status.BindingID != ldapAdminBindingID || status.SyncIntervalSeconds == nil ||
			*status.SyncIntervalSeconds != 900 {
			t.Fatalf("GetSyncStatus() = (%#v, %v)", status, err)
		}
		if domainUUIDMust(h.queries.statusParams.BindingID) != ldapAdminBindingID {
			t.Fatalf("status params = %#v", h.queries.statusParams)
		}
		h.assertSuccess(t, "get-status")
	})

	t.Run("list", func(t *testing.T) {
		h := newLDAPSyncAdministrationHarness(t)
		h.queries.listRows = []*dbsql.ListTenantLDAPSyncRunsRow{
			ldapSyncListedRunRow(ldapSyncRunID), ldapSyncListedRunRow(ldapSyncRunTailID),
		}
		rows, err := h.repository.ListSyncRuns(h.context(), identityprovider.ListSyncRunParams{
			HumanParams: ldapAdministrationHuman(), BindingID: ldapAdminBindingID, Limit: 2,
		})
		if err != nil || len(rows) != 2 || rows[1].ID != ldapSyncRunTailID {
			t.Fatalf("ListSyncRuns() = (%#v, %v)", rows, err)
		}
		if h.queries.listParams.PageSize != 2 || domainUUIDMust(h.queries.listParams.BindingID) != ldapAdminBindingID {
			t.Fatalf("list params = %#v", h.queries.listParams)
		}
		h.assertSuccess(t, "list-runs")
	})

	t.Run("get", func(t *testing.T) {
		h := newLDAPSyncAdministrationHarness(t)
		run, err := h.repository.GetSyncRun(h.context(), identityprovider.GetSyncRunParams{
			HumanParams: ldapAdministrationHuman(), BindingID: ldapAdminBindingID, RunID: ldapSyncRunID,
		})
		if err != nil || run.ID != ldapSyncRunID || run.Snapshot.AccessEpochID != ldapSyncAccessEpoch {
			t.Fatalf("GetSyncRun() = (%#v, %v)", run, err)
		}
		h.assertSuccess(t, "get-run")
	})
}

func TestLDAPSyncAdministrationManualStartIsAtomicAndReplaySafe(t *testing.T) {
	h := newLDAPSyncAdministrationHarness(t)
	params := identityprovider.StartManualSyncParams{
		HumanParams: ldapAdministrationHuman(), Audit: ldapAdministrationAudit(), OccurredAt: ldapAdminNow,
		RunID: ldapSyncRunID, AuditEventID: ldapSyncAuditID, BindingID: ldapAdminBindingID,
		ExpectedVersion: 2, Reason: "Operator requested reconciliation",
		IdempotencyKeyDigest: [32]byte{1}, RequestDigest: [32]byte{2},
	}
	result, err := h.repository.StartManualSync(h.context(), params)
	if err != nil || result.Replayed || result.Run.ID != ldapSyncRunID {
		t.Fatalf("StartManualSync() = (%#v, %v)", result, err)
	}
	if h.queries.beginParams.ExpectedBindingVersion != 2 || h.queries.beginParams.Reason != params.Reason ||
		domainUUIDMust(h.queries.beginParams.SyncRunID) != ldapSyncRunID ||
		domainUUIDMust(h.queries.beginParams.AuditEventID) != ldapSyncAuditID ||
		!slices.Equal(h.queries.beginParams.IdempotencyKeyDigest, params.IdempotencyKeyDigest[:]) ||
		!slices.Equal(h.queries.beginParams.RequestDigest, params.RequestDigest[:]) {
		t.Fatalf("manual sync params = %#v", h.queries.beginParams)
	}
	h.assertSuccess(t, "begin-manual", "get-run")

	t.Run("response lost replay", func(t *testing.T) {
		replay := newLDAPSyncAdministrationHarness(t)
		replay.queries.beginRow = &dbsql.BeginTenantLDAPManualSyncV2Row{
			SyncRunID: toDatabaseUUID(ldapSyncRunTailID), Replayed: true,
		}
		replay.queries.getRow = ldapSyncGotRunRow(ldapSyncRunTailID)
		result, err := replay.repository.StartManualSync(replay.context(), params)
		if err != nil || !result.Replayed || result.Run.ID != ldapSyncRunTailID {
			t.Fatalf("replayed StartManualSync() = (%#v, %v)", result, err)
		}
		replay.assertSuccess(t, "begin-manual", "get-run")
	})
}

func TestLDAPSyncAdministrationRejectsCrossTenantAndMalformedProjections(t *testing.T) {
	t.Run("cross tenant", func(t *testing.T) {
		h := newLDAPSyncAdministrationHarness(t)
		h.queries.getRow.TenantID = toDatabaseUUID(ldapAdminProviderID)
		_, err := h.repository.GetSyncRun(h.context(), identityprovider.GetSyncRunParams{
			HumanParams: ldapAdministrationHuman(), BindingID: ldapAdminBindingID, RunID: ldapSyncRunID,
		})
		if !errors.Is(err, identityprovider.ErrUnavailable) || h.transaction.commits != 0 || h.transaction.rollbacks != 1 {
			t.Fatalf("cross-tenant GetSyncRun() = error:%v commit:%d rollback:%d", err, h.transaction.commits, h.transaction.rollbacks)
		}
	})

	t.Run("malformed pins", func(t *testing.T) {
		h := newLDAPSyncAdministrationHarness(t)
		h.queries.getRow.MappingRevisions = []byte(`[{"mappingId":"raw LDAP value"}]`)
		_, err := h.repository.GetSyncRun(h.context(), identityprovider.GetSyncRunParams{
			HumanParams: ldapAdministrationHuman(), BindingID: ldapAdminBindingID, RunID: ldapSyncRunID,
		})
		if !errors.Is(err, identityprovider.ErrUnavailable) {
			t.Fatalf("malformed GetSyncRun() error = %v", err)
		}
	})

	t.Run("non monotonic page", func(t *testing.T) {
		h := newLDAPSyncAdministrationHarness(t)
		h.queries.listRows = []*dbsql.ListTenantLDAPSyncRunsRow{
			ldapSyncListedRunRow(ldapSyncRunTailID), ldapSyncListedRunRow(ldapSyncRunID),
		}
		_, err := h.repository.ListSyncRuns(h.context(), identityprovider.ListSyncRunParams{
			HumanParams: ldapAdministrationHuman(), BindingID: ldapAdminBindingID, Limit: 2,
		})
		if !errors.Is(err, identityprovider.ErrUnavailable) {
			t.Fatalf("non-monotonic ListSyncRuns() error = %v", err)
		}
	})
}

func ldapSyncStatusRow() *dbsql.GetTenantLDAPSyncStatusRow {
	return &dbsql.GetTenantLDAPSyncStatusRow{
		BindingID: toDatabaseUUID(ldapAdminBindingID), ScheduleState: "idle", SyncIntervalSeconds: 900,
		Version: 1, UpdatedAt: ldapAdministrationTime(ldapAdminNow),
	}
}

func ldapSyncGotRunRow(id uuid.UUID) *dbsql.GetTenantLDAPSyncRunRow {
	return &dbsql.GetTenantLDAPSyncRunRow{
		ID: idToDatabaseUUID(id), TenantID: toDatabaseUUID(ldapAdminTenantID),
		BindingID: toDatabaseUUID(ldapAdminBindingID), ProviderID: toDatabaseUUID(ldapAdminProviderID),
		Trigger: "manual", ManualReason: "Operator requested reconciliation", State: "queued",
		ProviderVersion: 3, BindingVersion: 2, ConfigurationRevision: 4,
		AccessEpochID: toDatabaseUUID(ldapSyncAccessEpoch), MappingRevisions: []byte("[]"),
		EnumerationState: "not_started", CursorState: "none",
		CreatedAt: ldapAdministrationTime(ldapAdminNow), Version: 1, UpdatedAt: ldapAdministrationTime(ldapAdminNow),
	}
}

func ldapSyncListedRunRow(id uuid.UUID) *dbsql.ListTenantLDAPSyncRunsRow {
	row := ldapSyncGotRunRow(id)
	return &dbsql.ListTenantLDAPSyncRunsRow{
		ID: row.ID, TenantID: row.TenantID, BindingID: row.BindingID, ProviderID: row.ProviderID,
		Trigger: row.Trigger, ManualReason: row.ManualReason, State: row.State,
		ProviderVersion: row.ProviderVersion, BindingVersion: row.BindingVersion,
		ConfigurationRevision: row.ConfigurationRevision, AccessEpochID: row.AccessEpochID,
		MappingRevisions: row.MappingRevisions, EnumerationState: row.EnumerationState,
		EnumerationComplete: row.EnumerationComplete, ResultTruncated: row.ResultTruncated,
		AbsenceAllowed: row.AbsenceAllowed, EntryCount: row.EntryCount, PageCount: row.PageCount,
		ResponseBytes: row.ResponseBytes, CursorState: row.CursorState,
		EnumerationErrorCategory: row.EnumerationErrorCategory, Observed: row.Observed,
		Staged: row.Staged, IdentitiesCreated: row.IdentitiesCreated, IdentitiesLinked: row.IdentitiesLinked,
		ProviderAccessAdded: row.ProviderAccessAdded, ProviderAccessSuspended: row.ProviderAccessSuspended,
		GroupEdgesAdded: row.GroupEdgesAdded, GroupEdgesRefreshed: row.GroupEdgesRefreshed,
		GroupEdgesRevoked: row.GroupEdgesRevoked, RoleEdgesAdded: row.RoleEdgesAdded,
		RoleEdgesRefreshed: row.RoleEdgesRefreshed, RoleEdgesRevoked: row.RoleEdgesRevoked,
		RosterEdgesAdded: row.RosterEdgesAdded, RosterEdgesRefreshed: row.RosterEdgesRefreshed,
		RosterEdgesRevoked: row.RosterEdgesRevoked, Failed: row.Failed,
		RunErrorCategory: row.RunErrorCategory, CreatedAt: row.CreatedAt, StartedAt: row.StartedAt,
		CompletedAt: row.CompletedAt, Version: row.Version, UpdatedAt: row.UpdatedAt,
	}
}

func idToDatabaseUUID(value uuid.UUID) pgtype.UUID {
	return toDatabaseUUID(value)
}
