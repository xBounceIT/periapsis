package postgres

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

var (
	ldapAdminTenantID          = uuid.MustParse("00000000-0000-7000-8000-000000000200")
	ldapAdminUserID            = uuid.MustParse("00000000-0000-7000-8000-000000000201")
	ldapAdminSessionID         = uuid.MustParse("00000000-0000-7000-8000-000000000202")
	ldapAdminMembershipID      = uuid.MustParse("00000000-0000-7000-8000-000000000203")
	ldapAdminProviderID        = uuid.MustParse("00000000-0000-7000-8000-000000000204")
	ldapAdminBindingID         = uuid.MustParse("00000000-0000-7000-8000-000000000205")
	ldapAdminBindingTailID     = uuid.MustParse("00000000-0000-7000-8000-000000000206")
	ldapAdminBindingEpochID    = uuid.MustParse("00000000-0000-7000-8000-000000000207")
	ldapAdminMappingID         = uuid.MustParse("00000000-0000-7000-8000-000000000208")
	ldapAdminMappingTailID     = uuid.MustParse("00000000-0000-7000-8000-000000000209")
	ldapAdminMappingLastID     = uuid.MustParse("00000000-0000-7000-8000-000000000210")
	ldapAdminSecurityGroupID   = uuid.MustParse("00000000-0000-7000-8000-000000000211")
	ldapAdminRoleID            = uuid.MustParse("00000000-0000-7000-8000-000000000212")
	ldapAdminMappingEpochID    = uuid.MustParse("00000000-0000-7000-8000-000000000213")
	ldapAdminAuditEventID      = uuid.MustParse("00000000-0000-7000-8000-000000000214")
	ldapAdminRequestID         = uuid.MustParse("00000000-0000-7000-8000-000000000215")
	ldapAdminCorrelationID     = uuid.MustParse("00000000-0000-7000-8000-000000000216")
	ldapAdminOperatorTeamID    = uuid.MustParse("00000000-0000-7000-8000-000000000217")
	ldapAdminAssignmentEpochID = uuid.MustParse("00000000-0000-7000-8000-000000000218")
	ldapAdminNow               = time.Date(2026, time.August, 25, 10, 30, 0, 123000000, time.UTC)
)

type ldapAdministrationQueriesStub struct {
	events                   *[]string
	expectedContextValue     any
	contextMismatch          bool
	setTenantContextResult   *dbsql.SetTenantContextRow
	errors                   map[string]error
	bindingRows              []*dbsql.ListTenantLDAPBindingsRow
	bindingRow               *dbsql.GetTenantLDAPBindingRow
	bindingMutationRow       *dbsql.GetTenantLDAPBindingMutationResultRow
	createBindingRow         *dbsql.CreateTenantLDAPBindingRow
	bindingMutationVersion   int32
	mappingRows              []*dbsql.ListTenantLDAPMappingsRow
	mappingRow               *dbsql.GetTenantLDAPMappingRow
	mappingMutationRow       *dbsql.GetTenantLDAPMappingMutationResultRow
	createMappingRow         *dbsql.CreateTenantLDAPMappingRow
	mappingMutationVersion   int32
	setTenantContextParams   dbsql.SetTenantContextParams
	listBindingParams        dbsql.ListTenantLDAPBindingsParams
	getBindingParams         []dbsql.GetTenantLDAPBindingParams
	getBindingMutationParams []dbsql.GetTenantLDAPBindingMutationResultParams
	createBindingParams      dbsql.CreateTenantLDAPBindingParams
	updateBindingParams      dbsql.UpdateTenantLDAPBindingParams
	archiveBindingParams     dbsql.ArchiveTenantLDAPBindingParams
	listMappingParams        dbsql.ListTenantLDAPMappingsParams
	getMappingParams         []dbsql.GetTenantLDAPMappingParams
	getMappingMutationParams []dbsql.GetTenantLDAPMappingMutationResultParams
	createMappingParams      dbsql.CreateTenantLDAPMappingParams
	updateMappingParams      dbsql.UpdateTenantLDAPMappingParams
	archiveMappingParams     dbsql.ArchiveTenantLDAPMappingParams
}

func (q *ldapAdministrationQueriesStub) record(ctx context.Context, operation string) error {
	*q.events = append(*q.events, operation)
	if ctx.Value(ldapAdministrationContextKey{}) != q.expectedContextValue {
		q.contextMismatch = true
	}
	return q.errors[operation]
}

func (q *ldapAdministrationQueriesStub) SetTenantContext(
	ctx context.Context,
	params dbsql.SetTenantContextParams,
) (*dbsql.SetTenantContextRow, error) {
	q.setTenantContextParams = params
	if err := q.record(ctx, "set-context"); err != nil {
		return nil, err
	}
	return q.setTenantContextResult, nil
}

func (q *ldapAdministrationQueriesStub) ListTenantLDAPBindings(
	ctx context.Context,
	params dbsql.ListTenantLDAPBindingsParams,
) ([]*dbsql.ListTenantLDAPBindingsRow, error) {
	q.listBindingParams = params
	if err := q.record(ctx, "list-bindings"); err != nil {
		return nil, err
	}
	return q.bindingRows, nil
}

func (q *ldapAdministrationQueriesStub) GetTenantLDAPBinding(
	ctx context.Context,
	params dbsql.GetTenantLDAPBindingParams,
) (*dbsql.GetTenantLDAPBindingRow, error) {
	q.getBindingParams = append(q.getBindingParams, params)
	if err := q.record(ctx, "get-binding"); err != nil {
		return nil, err
	}
	return q.bindingRow, nil
}

func (q *ldapAdministrationQueriesStub) GetTenantLDAPBindingMutationResult(
	ctx context.Context,
	params dbsql.GetTenantLDAPBindingMutationResultParams,
) (*dbsql.GetTenantLDAPBindingMutationResultRow, error) {
	q.getBindingMutationParams = append(q.getBindingMutationParams, params)
	if err := q.record(ctx, "get-binding-mutation-result"); err != nil {
		return nil, err
	}
	return q.bindingMutationRow, nil
}

func (q *ldapAdministrationQueriesStub) CreateTenantLDAPBinding(
	ctx context.Context,
	params dbsql.CreateTenantLDAPBindingParams,
) (*dbsql.CreateTenantLDAPBindingRow, error) {
	q.createBindingParams = params
	if err := q.record(ctx, "create-binding"); err != nil {
		return nil, err
	}
	return q.createBindingRow, nil
}

func (q *ldapAdministrationQueriesStub) UpdateTenantLDAPBinding(
	ctx context.Context,
	params dbsql.UpdateTenantLDAPBindingParams,
) (int32, error) {
	q.updateBindingParams = params
	if err := q.record(ctx, "update-binding"); err != nil {
		return 0, err
	}
	return q.bindingMutationVersion, nil
}

func (q *ldapAdministrationQueriesStub) ArchiveTenantLDAPBinding(
	ctx context.Context,
	params dbsql.ArchiveTenantLDAPBindingParams,
) (int32, error) {
	q.archiveBindingParams = params
	if err := q.record(ctx, "archive-binding"); err != nil {
		return 0, err
	}
	return q.bindingMutationVersion, nil
}

func (q *ldapAdministrationQueriesStub) ListTenantLDAPMappings(
	ctx context.Context,
	params dbsql.ListTenantLDAPMappingsParams,
) ([]*dbsql.ListTenantLDAPMappingsRow, error) {
	q.listMappingParams = params
	if err := q.record(ctx, "list-mappings"); err != nil {
		return nil, err
	}
	return q.mappingRows, nil
}

func (q *ldapAdministrationQueriesStub) GetTenantLDAPMapping(
	ctx context.Context,
	params dbsql.GetTenantLDAPMappingParams,
) (*dbsql.GetTenantLDAPMappingRow, error) {
	q.getMappingParams = append(q.getMappingParams, params)
	if err := q.record(ctx, "get-mapping"); err != nil {
		return nil, err
	}
	return q.mappingRow, nil
}

func (q *ldapAdministrationQueriesStub) GetTenantLDAPMappingMutationResult(
	ctx context.Context,
	params dbsql.GetTenantLDAPMappingMutationResultParams,
) (*dbsql.GetTenantLDAPMappingMutationResultRow, error) {
	q.getMappingMutationParams = append(q.getMappingMutationParams, params)
	if err := q.record(ctx, "get-mapping-mutation-result"); err != nil {
		return nil, err
	}
	return q.mappingMutationRow, nil
}

func (q *ldapAdministrationQueriesStub) CreateTenantLDAPMapping(
	ctx context.Context,
	params dbsql.CreateTenantLDAPMappingParams,
) (*dbsql.CreateTenantLDAPMappingRow, error) {
	q.createMappingParams = params
	if err := q.record(ctx, "create-mapping"); err != nil {
		return nil, err
	}
	return q.createMappingRow, nil
}

func (q *ldapAdministrationQueriesStub) UpdateTenantLDAPMapping(
	ctx context.Context,
	params dbsql.UpdateTenantLDAPMappingParams,
) (int32, error) {
	q.updateMappingParams = params
	if err := q.record(ctx, "update-mapping"); err != nil {
		return 0, err
	}
	return q.mappingMutationVersion, nil
}

func (q *ldapAdministrationQueriesStub) ArchiveTenantLDAPMapping(
	ctx context.Context,
	params dbsql.ArchiveTenantLDAPMappingParams,
) (int32, error) {
	q.archiveMappingParams = params
	if err := q.record(ctx, "archive-mapping"); err != nil {
		return 0, err
	}
	return q.mappingMutationVersion, nil
}

type ldapAdministrationContextKey struct{}

type ldapAdministrationTransactionStub struct {
	events       *[]string
	commits      int
	rollbacks    int
	closed       bool
	commitError  error
	contextValue any
}

func (*ldapAdministrationTransactionStub) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("unexpected Exec")
}

func (*ldapAdministrationTransactionStub) Query(context.Context, string, ...any) (pgx.Rows, error) {
	panic("unexpected Query")
}

func (*ldapAdministrationTransactionStub) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("unexpected QueryRow")
}

func (tx *ldapAdministrationTransactionStub) Commit(ctx context.Context) error {
	*tx.events = append(*tx.events, "commit")
	if ctx.Value(ldapAdministrationContextKey{}) != tx.contextValue {
		return errors.New("commit received a different context")
	}
	tx.commits++
	if tx.commitError == nil {
		tx.closed = true
	}
	return tx.commitError
}

func (tx *ldapAdministrationTransactionStub) Rollback(context.Context) error {
	*tx.events = append(*tx.events, "rollback")
	tx.rollbacks++
	if tx.closed {
		return pgx.ErrTxClosed
	}
	return nil
}

type ldapAdministrationHarness struct {
	repository     *IdentityProviderRepository
	queries        *ldapAdministrationQueriesStub
	transaction    *ldapAdministrationTransactionStub
	events         []string
	beginCalls     int
	beginContextOK bool
	options        pgx.TxOptions
}

func newLDAPAdministrationHarness(t *testing.T) *ldapAdministrationHarness {
	t.Helper()
	harness := &ldapAdministrationHarness{}
	contextValue := &struct{}{}
	harness.queries = &ldapAdministrationQueriesStub{
		events:               &harness.events,
		expectedContextValue: contextValue,
		setTenantContextResult: &dbsql.SetTenantContextRow{
			TenantID: ldapAdminTenantID.String(), UserID: ldapAdminUserID.String(),
		},
		errors:                 make(map[string]error),
		bindingRow:             ldapAdministrationBindingRow(ldapAdminBindingID, 1, false, false),
		bindingMutationRow:     ldapAdministrationBindingMutationRow(ldapAdminBindingID, 1, false, false),
		createBindingRow:       &dbsql.CreateTenantLDAPBindingRow{BindingID: toDatabaseUUID(ldapAdminBindingID), ResultVersion: 1},
		bindingMutationVersion: 2,
		mappingRow:             ldapAdministrationMappingRow(ldapAdminMappingID, 10, 1, false, false),
		mappingMutationRow:     ldapAdministrationMappingMutationRow(ldapAdminMappingID, 10, 1, false, false),
		createMappingRow:       &dbsql.CreateTenantLDAPMappingRow{MappingID: toDatabaseUUID(ldapAdminMappingID), ResultVersion: 1},
		mappingMutationVersion: 2,
	}
	harness.transaction = &ldapAdministrationTransactionStub{
		events: &harness.events, contextValue: contextValue,
	}
	harness.repository = &IdentityProviderRepository{
		begin: func(ctx context.Context, options pgx.TxOptions) (databaseTransaction, error) {
			harness.events = append(harness.events, "begin")
			harness.beginCalls++
			harness.beginContextOK = ctx.Value(ldapAdministrationContextKey{}) == contextValue
			harness.options = options
			return harness.transaction, nil
		},
		administrationQueryFactory: func(tx databaseTransaction) ldapAdministrationQueries {
			harness.events = append(harness.events, "factory")
			if tx != harness.transaction {
				t.Fatalf("query factory transaction = %T, want harness transaction", tx)
			}
			return harness.queries
		},
	}
	return harness
}

func (h *ldapAdministrationHarness) context() context.Context {
	return context.WithValue(context.Background(), ldapAdministrationContextKey{}, h.transaction.contextValue)
}

func (h *ldapAdministrationHarness) assertSuccess(t *testing.T, operations ...string) {
	t.Helper()
	want := append([]string{"begin", "factory", "set-context"}, operations...)
	want = append(want, "commit", "rollback")
	if !slices.Equal(h.events, want) {
		t.Fatalf("transaction events = %v, want %v", h.events, want)
	}
	if h.beginCalls != 1 || !h.beginContextOK || h.queries.contextMismatch ||
		h.options.IsoLevel != pgx.ReadCommitted || h.transaction.commits != 1 || h.transaction.rollbacks != 1 {
		t.Fatalf("transaction state = begin:%d begin-context:%t query-context-mismatch:%t options:%#v commit:%d rollback:%d",
			h.beginCalls, h.beginContextOK, h.queries.contextMismatch, h.options,
			h.transaction.commits, h.transaction.rollbacks)
	}
	if gotTenant, gotUser := domainUUIDMust(h.queries.setTenantContextParams.TenantID), domainUUIDMust(h.queries.setTenantContextParams.UserID); gotTenant != ldapAdminTenantID || gotUser != ldapAdminUserID {
		t.Fatalf("installed context = (%s, %s)", gotTenant, gotUser)
	}
}

func (h *ldapAdministrationHarness) assertRollback(t *testing.T, operations ...string) {
	t.Helper()
	want := append([]string{"begin", "factory", "set-context"}, operations...)
	want = append(want, "rollback")
	if !slices.Equal(h.events, want) {
		t.Fatalf("transaction events = %v, want %v", h.events, want)
	}
	if h.transaction.commits != 0 || h.transaction.rollbacks != 1 {
		t.Fatalf("transaction commit = %d, rollback = %d", h.transaction.commits, h.transaction.rollbacks)
	}
}

func TestLDAPAdministrationBindingCRUDUsesProtectedTransactions(t *testing.T) {
	t.Run("list", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.queries.bindingRows = []*dbsql.ListTenantLDAPBindingsRow{
			ldapAdministrationListedBindingRow(ldapAdminBindingID, 1, false),
			ldapAdministrationListedBindingRow(ldapAdminBindingTailID, 2, true),
		}
		rows, err := h.repository.ListBindings(h.context(), identityprovider.ListBindingParams{
			HumanParams: ldapAdministrationHuman(), Limit: 2, IncludeArchived: true,
		})
		if err != nil || len(rows) != 2 || rows[1].ID != ldapAdminBindingTailID || rows[1].ArchivedAt == nil {
			t.Fatalf("ListBindings() = (%#v, %v)", rows, err)
		}
		if h.queries.listBindingParams.PageSize != 2 || !h.queries.listBindingParams.IncludeArchived {
			t.Fatalf("list binding params = %#v", h.queries.listBindingParams)
		}
		h.assertSuccess(t, "list-bindings")
	})

	t.Run("get", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		binding, err := h.repository.GetBinding(h.context(), identityprovider.GetBindingParams{
			HumanParams: ldapAdministrationHuman(), BindingID: ldapAdminBindingID,
		})
		if err != nil || binding.ID != ldapAdminBindingID || len(h.queries.getBindingParams) != 1 {
			t.Fatalf("GetBinding() = (%#v, %v), params = %v", binding, err, h.queries.getBindingParams)
		}
		h.assertSuccess(t, "get-binding")
	})

	t.Run("create", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		result, err := h.repository.CreateBinding(h.context(), ldapAdministrationCreateBindingParams())
		if err != nil || result.Replayed || result.Binding.Version != 1 {
			t.Fatalf("CreateBinding() = (%#v, %v)", result, err)
		}
		if h.queries.createBindingParams.LoginKey != "corp_ldap" || h.queries.createBindingParams.Enabled ||
			h.queries.createBindingParams.ProfilePriority != 20 || len(h.queries.createBindingParams.IdempotencyKeyDigest) != 32 {
			t.Fatalf("create binding params = %#v", h.queries.createBindingParams)
		}
		h.assertSuccess(t, "create-binding", "get-binding-mutation-result")
	})

	t.Run("replay returns current representation", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.queries.createBindingRow.Replayed = true
		h.queries.bindingMutationRow = ldapAdministrationBindingMutationRow(ldapAdminBindingID, 4, false, false)
		h.queries.bindingMutationRow.LoginKey = "current_login"
		result, err := h.repository.CreateBinding(h.context(), ldapAdministrationCreateBindingParams())
		if err != nil || !result.Replayed || result.Binding.Version != 4 || result.Binding.LoginKey != "current_login" {
			t.Fatalf("replayed CreateBinding() = (%#v, %v)", result, err)
		}
		h.assertSuccess(t, "create-binding", "get-binding-mutation-result")
	})

	t.Run("update", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.queries.bindingMutationRow = ldapAdministrationBindingMutationRow(ldapAdminBindingID, 2, true, false)
		h.queries.bindingMutationRow.ProfilePriority = 25
		params := ldapAdministrationUpdateBindingParams()
		binding, err := h.repository.UpdateBinding(h.context(), params)
		if err != nil || binding.Version != 2 || !binding.Enabled || binding.CurrentAccessEpochID == nil {
			t.Fatalf("UpdateBinding() = (%#v, %v)", binding, err)
		}
		if h.queries.updateBindingParams.ExpectedVersion != 1 || h.queries.updateBindingParams.LoginKey != params.LoginKey ||
			!h.queries.updateBindingParams.Enabled || h.queries.updateBindingParams.ProfilePriority != int32(params.ProfilePriority) {
			t.Fatalf("update binding params = %#v", h.queries.updateBindingParams)
		}
		h.assertSuccess(t, "update-binding", "get-binding-mutation-result")
	})

	t.Run("archive", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		version, err := h.repository.ArchiveBinding(h.context(), ldapAdministrationArchiveBindingParams())
		if err != nil || version != 2 || h.queries.archiveBindingParams.Reason != "Retire binding" {
			t.Fatalf("ArchiveBinding() = (%d, %v), params = %#v", version, err, h.queries.archiveBindingParams)
		}
		h.assertSuccess(t, "archive-binding")
	})
}

func TestLDAPAdministrationMappingCRUDReplayOrderingAndArguments(t *testing.T) {
	t.Run("list uses supplied composite cursor without lookup", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.queries.mappingRow.Priority = 100
		h.queries.mappingRows = []*dbsql.ListTenantLDAPMappingsRow{
			ldapAdministrationListedMappingRow(ldapAdminMappingTailID, 10, 1, false),
			ldapAdministrationListedMappingRow(ldapAdminMappingLastID, 20, 2, false),
		}
		after := identityprovider.MappingCursor{Priority: 10, ID: ldapAdminMappingID}
		bindingID := ldapAdminBindingID
		rows, err := h.repository.ListMappings(h.context(), identityprovider.ListMappingParams{
			HumanParams: ldapAdministrationHuman(), After: &after, Limit: 2, BindingID: &bindingID,
		})
		if err != nil || len(rows) != 2 || rows[0].ID != ldapAdminMappingTailID || rows[1].Priority != 20 {
			t.Fatalf("ListMappings() = (%#v, %v)", rows, err)
		}
		if h.queries.listMappingParams.AfterPriority == nil || *h.queries.listMappingParams.AfterPriority != 10 ||
			domainUUIDMust(h.queries.listMappingParams.AfterMappingID) != ldapAdminMappingID ||
			domainUUIDMust(h.queries.listMappingParams.BindingID) != ldapAdminBindingID {
			t.Fatalf("list mapping params = %#v", h.queries.listMappingParams)
		}
		h.assertSuccess(t, "list-mappings")
	})

	t.Run("get", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		mapping, err := h.repository.GetMapping(h.context(), identityprovider.GetMappingParams{
			HumanParams: ldapAdministrationHuman(), MappingID: ldapAdminMappingID,
		})
		if err != nil || mapping.ID != ldapAdminMappingID || len(mapping.Target.RoleIDs) != 1 {
			t.Fatalf("GetMapping() = (%#v, %v)", mapping, err)
		}
		h.assertSuccess(t, "get-mapping")
	})

	t.Run("create", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		result, err := h.repository.CreateMapping(h.context(), ldapAdministrationCreateMappingParams())
		if err != nil || result.Replayed || result.Mapping.Version != 1 {
			t.Fatalf("CreateMapping() = (%#v, %v)", result, err)
		}
		arguments := h.queries.createMappingParams
		if arguments.MatcherType != "exact_cn" || arguments.MatcherValue != "SOC" || arguments.CaseMode != "insensitive" ||
			arguments.Priority != 10 || arguments.ReconciliationMode != "additive" || len(arguments.RoleIds) != 1 ||
			domainUUIDMust(arguments.SecurityGroupID) != ldapAdminSecurityGroupID ||
			domainUUIDMust(arguments.OperatorTeamID) != ldapAdminOperatorTeamID ||
			domainUUIDMust(arguments.OperatorTeamAssignmentEpochID) != ldapAdminAssignmentEpochID {
			t.Fatalf("create mapping params = %#v", arguments)
		}
		h.assertSuccess(t, "create-mapping", "get-mapping-mutation-result")
	})

	t.Run("replay returns current representation", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.queries.createMappingRow.Replayed = true
		h.queries.mappingMutationRow = ldapAdministrationMappingMutationRow(ldapAdminMappingID, 50, 4, false, false)
		h.queries.mappingMutationRow.MatcherValue = "CURRENT-SOC"
		result, err := h.repository.CreateMapping(h.context(), ldapAdministrationCreateMappingParams())
		if err != nil || !result.Replayed || result.Mapping.Version != 4 || result.Mapping.Matcher.Value != "CURRENT-SOC" {
			t.Fatalf("replayed CreateMapping() = (%#v, %v)", result, err)
		}
		h.assertSuccess(t, "create-mapping", "get-mapping-mutation-result")
	})

	t.Run("update", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.queries.mappingMutationRow = ldapAdministrationMappingMutationRow(ldapAdminMappingID, 25, 2, true, false)
		params := ldapAdministrationUpdateMappingParams()
		mapping, err := h.repository.UpdateMapping(h.context(), params)
		if err != nil || mapping.Version != 2 || !mapping.Enabled || mapping.CurrentSourceEpoch == nil {
			t.Fatalf("UpdateMapping() = (%#v, %v)", mapping, err)
		}
		arguments := h.queries.updateMappingParams
		if arguments.ExpectedVersion != 1 || arguments.Priority != 25 || !arguments.Enabled ||
			arguments.ReconciliationMode != "authoritative" || arguments.Reason != "Activate reviewed mapping" ||
			domainUUIDMust(arguments.AuditEventID) != ldapAdminAuditEventID {
			t.Fatalf("update mapping params = %#v", arguments)
		}
		h.assertSuccess(t, "update-mapping", "get-mapping-mutation-result")
	})

	t.Run("archive", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		version, err := h.repository.ArchiveMapping(h.context(), ldapAdministrationArchiveMappingParams())
		if err != nil || version != 2 || h.queries.archiveMappingParams.Reason != "Retire mapping" ||
			domainUUIDMust(h.queries.archiveMappingParams.AuditEventID) != ldapAdminAuditEventID {
			t.Fatalf("ArchiveMapping() = (%d, %v), params = %#v", version, err, h.queries.archiveMappingParams)
		}
		h.assertSuccess(t, "archive-mapping")
	})
}

func TestLDAPAdministrationRejectsMalformedDatabaseResults(t *testing.T) {
	t.Run("binding archive after update", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		row := ldapAdministrationListedBindingRow(ldapAdminBindingID, 2, true)
		row.ArchivedAt.Time = row.UpdatedAt.Time.Add(time.Second)
		h.queries.bindingRows = []*dbsql.ListTenantLDAPBindingsRow{row}
		_, err := h.repository.ListBindings(h.context(), identityprovider.ListBindingParams{
			HumanParams: ldapAdministrationHuman(), Limit: 1, IncludeArchived: true,
		})
		if !errors.Is(err, identityprovider.ErrUnavailable) {
			t.Fatalf("ListBindings() error = %v", err)
		}
		h.assertRollback(t, "list-bindings")
	})

	t.Run("unknown mapping matcher", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.queries.mappingRow.MatcherType = "future_matcher"
		_, err := h.repository.GetMapping(h.context(), identityprovider.GetMappingParams{
			HumanParams: ldapAdministrationHuman(), MappingID: ldapAdminMappingID,
		})
		if !errors.Is(err, identityprovider.ErrUnavailable) {
			t.Fatalf("GetMapping() error = %v", err)
		}
		h.assertRollback(t, "get-mapping")
	})

	t.Run("mapping notes contain control character", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.queries.mappingRow.Notes = "SOC\taccess"
		_, err := h.repository.GetMapping(h.context(), identityprovider.GetMappingParams{
			HumanParams: ldapAdministrationHuman(), MappingID: ldapAdminMappingID,
		})
		if !errors.Is(err, identityprovider.ErrUnavailable) {
			t.Fatalf("GetMapping() error = %v", err)
		}
		h.assertRollback(t, "get-mapping")
	})

	t.Run("mapping roles are not canonical", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.queries.mappingRow.RoleIds = []pgtype.UUID{
			toDatabaseUUID(ldapAdminAuditEventID), toDatabaseUUID(ldapAdminRoleID),
		}
		_, err := h.repository.GetMapping(h.context(), identityprovider.GetMappingParams{
			HumanParams: ldapAdministrationHuman(), MappingID: ldapAdminMappingID,
		})
		if !errors.Is(err, identityprovider.ErrUnavailable) {
			t.Fatalf("GetMapping() error = %v", err)
		}
		h.assertRollback(t, "get-mapping")
	})

	t.Run("mapping page does not advance cursor", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.queries.mappingRows = []*dbsql.ListTenantLDAPMappingsRow{
			ldapAdministrationListedMappingRow(ldapAdminMappingID, 10, 1, false),
		}
		after := identityprovider.MappingCursor{Priority: 10, ID: ldapAdminMappingID}
		_, err := h.repository.ListMappings(h.context(), identityprovider.ListMappingParams{
			HumanParams: ldapAdministrationHuman(), After: &after, Limit: 1,
		})
		if !errors.Is(err, identityprovider.ErrUnavailable) {
			t.Fatalf("ListMappings() error = %v", err)
		}
		h.assertRollback(t, "list-mappings")
	})

	t.Run("non replay create must start at version one", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.queries.createBindingRow.ResultVersion = 2
		_, err := h.repository.CreateBinding(h.context(), ldapAdministrationCreateBindingParams())
		if !errors.Is(err, identityprovider.ErrUnavailable) {
			t.Fatalf("CreateBinding() error = %v", err)
		}
		h.assertRollback(t, "create-binding")
	})

	t.Run("divergent create projection rolls back", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.queries.mappingMutationRow.Notes = ""
		_, err := h.repository.CreateMapping(h.context(), ldapAdministrationCreateMappingParams())
		if !errors.Is(err, identityprovider.ErrUnavailable) {
			t.Fatalf("CreateMapping() error = %v", err)
		}
		h.assertRollback(t, "create-mapping", "get-mapping-mutation-result")
	})

	t.Run("mutation must advance exactly one version", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.queries.mappingMutationVersion = 7
		_, err := h.repository.UpdateMapping(h.context(), ldapAdministrationUpdateMappingParams())
		if !errors.Is(err, identityprovider.ErrUnavailable) {
			t.Fatalf("UpdateMapping() error = %v", err)
		}
		h.assertRollback(t, "update-mapping")
	})

	t.Run("database context mismatch", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.queries.setTenantContextResult.TenantID = ldapAdminProviderID.String()
		_, err := h.repository.GetBinding(h.context(), identityprovider.GetBindingParams{
			HumanParams: ldapAdministrationHuman(), BindingID: ldapAdminBindingID,
		})
		if !errors.Is(err, identityprovider.ErrUnavailable) {
			t.Fatalf("GetBinding() error = %v", err)
		}
		h.assertRollback(t)
	})
}

func TestLDAPAdministrationMapsErrorsAndRejectsInvalidHumanBeforeBegin(t *testing.T) {
	t.Run("serialization failure", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.queries.errors["list-bindings"] = &pgconn.PgError{Code: "40001"}
		_, err := h.repository.ListBindings(h.context(), identityprovider.ListBindingParams{
			HumanParams: ldapAdministrationHuman(), Limit: 1,
		})
		if !errors.Is(err, identityprovider.ErrPreconditionFailed) {
			t.Fatalf("ListBindings() error = %v", err)
		}
		h.assertRollback(t, "list-bindings")
	})

	t.Run("context cancellation", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.queries.errors["get-mapping"] = context.Canceled
		_, err := h.repository.GetMapping(h.context(), identityprovider.GetMappingParams{
			HumanParams: ldapAdministrationHuman(), MappingID: ldapAdminMappingID,
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("GetMapping() error = %v", err)
		}
		h.assertRollback(t, "get-mapping")
	})

	t.Run("commit error", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		h.transaction.commitError = &pgconn.PgError{Code: "53300"}
		_, err := h.repository.GetBinding(h.context(), identityprovider.GetBindingParams{
			HumanParams: ldapAdministrationHuman(), BindingID: ldapAdminBindingID,
		})
		if !errors.Is(err, identityprovider.ErrRateLimited) {
			t.Fatalf("GetBinding() error = %v", err)
		}
		want := []string{"begin", "factory", "set-context", "get-binding", "commit", "rollback"}
		if !slices.Equal(h.events, want) || h.transaction.commits != 1 || h.transaction.rollbacks != 1 {
			t.Fatalf("commit-error transaction = events:%v commits:%d rollbacks:%d", h.events, h.transaction.commits, h.transaction.rollbacks)
		}
	})

	t.Run("invalid active tenant", func(t *testing.T) {
		h := newLDAPAdministrationHarness(t)
		human := ldapAdministrationHuman()
		human.Actor.ActiveTenantID = ldapAdminProviderID
		_, err := h.repository.GetBinding(h.context(), identityprovider.GetBindingParams{
			HumanParams: human, BindingID: ldapAdminBindingID,
		})
		if !errors.Is(err, identityprovider.ErrInvalidInput) || h.beginCalls != 0 || len(h.events) != 0 {
			t.Fatalf("GetBinding() error = %v, begin calls = %d, events = %v", err, h.beginCalls, h.events)
		}
	})
}

func ldapAdministrationHuman() identityprovider.HumanParams {
	return identityprovider.HumanParams{
		Actor: authorization.Actor{
			UserID: ldapAdminUserID, SessionID: ldapAdminSessionID, ActiveTenantID: ldapAdminTenantID,
			AuthenticationMethod: "session",
		},
		MembershipID: ldapAdminMembershipID, TenantID: ldapAdminTenantID,
	}
}

func ldapAdministrationAudit() authorization.AuditContext {
	return authorization.AuditContext{
		RequestID: ldapAdminRequestID, CorrelationID: ldapAdminCorrelationID,
		RemoteAddress: netip.MustParseAddr("192.0.2.25"), UserAgent: "ldap-administration-repository-test",
	}
}

func ldapAdministrationCreateBindingParams() identityprovider.CreateBindingParams {
	return identityprovider.CreateBindingParams{
		HumanParams: ldapAdministrationHuman(), Audit: ldapAdministrationAudit(), OccurredAt: ldapAdminNow,
		AuditEventID: ldapAdminAuditEventID, IdempotencyKeyDigest: [32]byte{1},
		ProviderID: ldapAdminProviderID, LoginKey: "corp_ldap", ProfilePriority: 20,
	}
}

func ldapAdministrationUpdateBindingParams() identityprovider.UpdateBindingParams {
	return identityprovider.UpdateBindingParams{
		HumanParams: ldapAdministrationHuman(), Audit: ldapAdministrationAudit(), OccurredAt: ldapAdminNow,
		BindingID: ldapAdminBindingID, ExpectedVersion: 1, LoginKey: "corp_ldap",
		Enabled: true, ProfilePriority: 25,
	}
}

func ldapAdministrationArchiveBindingParams() identityprovider.ArchiveBindingParams {
	return identityprovider.ArchiveBindingParams{
		HumanParams: ldapAdministrationHuman(), Audit: ldapAdministrationAudit(), OccurredAt: ldapAdminNow,
		BindingID: ldapAdminBindingID, ExpectedVersion: 1, Reason: "Retire binding",
	}
}

func ldapAdministrationCreateMappingParams() identityprovider.CreateMappingParams {
	return identityprovider.CreateMappingParams{
		HumanParams: ldapAdministrationHuman(), Audit: ldapAdministrationAudit(), OccurredAt: ldapAdminNow,
		AuditEventID: ldapAdminAuditEventID, IdempotencyKeyDigest: [32]byte{1}, BindingID: ldapAdminBindingID,
		Matcher: identityprovider.MappingMatcher{
			Type: identityprovider.MappingMatcherExactCN, Value: "SOC", CaseMode: identityprovider.MappingCaseInsensitive,
		},
		Priority: 10, Target: identityprovider.MappingTarget{
			TenantSecurityGroupID: ldapAdminSecurityGroupID, RoleIDs: []uuid.UUID{ldapAdminRoleID},
			OperatorTeamAssignment: &identityprovider.OperatorTeamAssignmentTarget{
				OperatorTeamID: ldapAdminOperatorTeamID, AssignmentEpochID: ldapAdminAssignmentEpochID,
			},
		},
		ReconciliationMode: identityprovider.ReconciliationAdditive, Notes: "SOC access",
		Reason: "Create reviewed mapping",
	}
}

func ldapAdministrationUpdateMappingParams() identityprovider.UpdateMappingParams {
	params := ldapAdministrationCreateMappingParams()
	return identityprovider.UpdateMappingParams{
		HumanParams: params.HumanParams, Audit: params.Audit, OccurredAt: params.OccurredAt,
		AuditEventID: params.AuditEventID, MappingID: ldapAdminMappingID, ExpectedVersion: 1,
		Matcher: params.Matcher, Priority: 25, Target: params.Target,
		ReconciliationMode: identityprovider.ReconciliationAuthoritative, Enabled: true,
		Notes: "SOC access", Reason: "Activate reviewed mapping",
	}
}

func ldapAdministrationArchiveMappingParams() identityprovider.ArchiveMappingParams {
	return identityprovider.ArchiveMappingParams{
		HumanParams: ldapAdministrationHuman(), Audit: ldapAdministrationAudit(), OccurredAt: ldapAdminNow,
		AuditEventID: ldapAdminAuditEventID, MappingID: ldapAdminMappingID,
		ExpectedVersion: 1, Reason: "Retire mapping",
	}
}

func ldapAdministrationBindingRow(
	id uuid.UUID,
	version int32,
	enabled bool,
	archived bool,
) *dbsql.GetTenantLDAPBindingRow {
	row := &dbsql.GetTenantLDAPBindingRow{
		ID: toDatabaseUUID(id), ProviderID: toDatabaseUUID(ldapAdminProviderID), LoginKey: "corp_ldap",
		Enabled: enabled, ProfilePriority: 20, AuthRevision: 1, Version: version,
		CreatedAt: ldapAdministrationTime(ldapAdminNow.Add(-time.Hour)), UpdatedAt: ldapAdministrationTime(ldapAdminNow),
	}
	if enabled {
		row.CurrentAccessEpochID = toDatabaseUUID(ldapAdminBindingEpochID)
	}
	if archived {
		row.ArchivedAt = ldapAdministrationTime(ldapAdminNow)
	}
	return row
}

func ldapAdministrationBindingMutationRow(
	id uuid.UUID,
	version int32,
	enabled bool,
	archived bool,
) *dbsql.GetTenantLDAPBindingMutationResultRow {
	row := ldapAdministrationBindingRow(id, version, enabled, archived)
	return &dbsql.GetTenantLDAPBindingMutationResultRow{
		ID: row.ID, ProviderID: row.ProviderID, LoginKey: row.LoginKey, Enabled: row.Enabled,
		ProfilePriority: row.ProfilePriority, AuthRevision: row.AuthRevision,
		CurrentAccessEpochID: row.CurrentAccessEpochID, ArchivedAt: row.ArchivedAt,
		Version: row.Version, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
}

func ldapAdministrationListedBindingRow(
	id uuid.UUID,
	version int32,
	archived bool,
) *dbsql.ListTenantLDAPBindingsRow {
	row := ldapAdministrationBindingRow(id, version, false, archived)
	return &dbsql.ListTenantLDAPBindingsRow{
		ID: row.ID, ProviderID: row.ProviderID, LoginKey: row.LoginKey, Enabled: row.Enabled,
		ProfilePriority: row.ProfilePriority, AuthRevision: row.AuthRevision,
		CurrentAccessEpochID: row.CurrentAccessEpochID, ArchivedAt: row.ArchivedAt,
		Version: row.Version, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
}

func ldapAdministrationMappingRow(
	id uuid.UUID,
	priority int32,
	version int32,
	enabled bool,
	archived bool,
) *dbsql.GetTenantLDAPMappingRow {
	row := &dbsql.GetTenantLDAPMappingRow{
		ID: toDatabaseUUID(id), BindingID: toDatabaseUUID(ldapAdminBindingID),
		MatcherType: "exact_cn", MatcherValue: "SOC", CaseMode: "insensitive", Priority: priority,
		SecurityGroupID: toDatabaseUUID(ldapAdminSecurityGroupID), ReconciliationMode: "additive",
		RoleIds: []pgtype.UUID{toDatabaseUUID(ldapAdminRoleID)}, Enabled: enabled,
		OperatorTeamID:                toDatabaseUUID(ldapAdminOperatorTeamID),
		OperatorTeamAssignmentEpochID: toDatabaseUUID(ldapAdminAssignmentEpochID),
		Notes:                         "SOC access", Version: version,
		CreatedAt: ldapAdministrationTime(ldapAdminNow.Add(-time.Hour)), UpdatedAt: ldapAdministrationTime(ldapAdminNow),
	}
	if enabled {
		row.CurrentSourceEpochID = toDatabaseUUID(ldapAdminMappingEpochID)
		row.CurrentSourceEpochSequence = 1
		row.CurrentSourceEpochActivatedAt = ldapAdministrationTime(ldapAdminNow)
		row.ReconciliationMode = "authoritative"
	}
	if archived {
		row.ArchivedAt = ldapAdministrationTime(ldapAdminNow)
	}
	return row
}

func ldapAdministrationMappingMutationRow(
	id uuid.UUID,
	priority int32,
	version int32,
	enabled bool,
	archived bool,
) *dbsql.GetTenantLDAPMappingMutationResultRow {
	row := ldapAdministrationMappingRow(id, priority, version, enabled, archived)
	return &dbsql.GetTenantLDAPMappingMutationResultRow{
		ID: row.ID, BindingID: row.BindingID, MatcherType: row.MatcherType, MatcherValue: row.MatcherValue,
		CaseMode: row.CaseMode, Priority: row.Priority, SecurityGroupID: row.SecurityGroupID,
		ReconciliationMode: row.ReconciliationMode, RoleIds: row.RoleIds,
		OperatorTeamID: row.OperatorTeamID, OperatorTeamAssignmentEpochID: row.OperatorTeamAssignmentEpochID,
		Enabled: row.Enabled, CurrentSourceEpochID: row.CurrentSourceEpochID,
		CurrentSourceEpochSequence:    row.CurrentSourceEpochSequence,
		CurrentSourceEpochActivatedAt: row.CurrentSourceEpochActivatedAt,
		Notes:                         row.Notes, LastMatchedAt: row.LastMatchedAt, ArchivedAt: row.ArchivedAt,
		Version: row.Version, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
}

func ldapAdministrationListedMappingRow(
	id uuid.UUID,
	priority int32,
	version int32,
	archived bool,
) *dbsql.ListTenantLDAPMappingsRow {
	row := ldapAdministrationMappingRow(id, priority, version, false, archived)
	return &dbsql.ListTenantLDAPMappingsRow{
		ID: row.ID, BindingID: row.BindingID, MatcherType: row.MatcherType, MatcherValue: row.MatcherValue,
		CaseMode: row.CaseMode, Priority: row.Priority, SecurityGroupID: row.SecurityGroupID,
		ReconciliationMode: row.ReconciliationMode, RoleIds: row.RoleIds,
		OperatorTeamID: row.OperatorTeamID, OperatorTeamAssignmentEpochID: row.OperatorTeamAssignmentEpochID,
		Enabled: row.Enabled, CurrentSourceEpochID: row.CurrentSourceEpochID,
		CurrentSourceEpochSequence:    row.CurrentSourceEpochSequence,
		CurrentSourceEpochActivatedAt: row.CurrentSourceEpochActivatedAt,
		Notes:                         row.Notes, LastMatchedAt: row.LastMatchedAt, ArchivedAt: row.ArchivedAt,
		Version: row.Version, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
}

func ldapAdministrationTime(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value, Valid: true}
}

func domainUUIDMust(value pgtype.UUID) uuid.UUID {
	result, err := domainUUID(value)
	if err != nil {
		panic(err)
	}
	return result
}
