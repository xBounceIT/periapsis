package httpserver

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

type ldapAdministrationTransportFixture struct {
	tenantID        uuid.UUID
	userID          uuid.UUID
	providerID      uuid.UUID
	bindingID       uuid.UUID
	mappingID       uuid.UUID
	mappingAfter    identityprovider.MappingCursor
	securityGroupID uuid.UUID
	roleID          uuid.UUID
	accessEpochID   uuid.UUID
	syncRunID       uuid.UUID
	checkedAt       time.Time
	binding         identityprovider.Binding
	mapping         identityprovider.Mapping
	directoryResult identityprovider.DirectoryTestResult
	dryRun          identityprovider.DryRunResult
	syncStatus      identityprovider.SyncStatus
	syncRun         identityprovider.SyncRun
}

func newLDAPAdministrationTransportFixture() ldapAdministrationTransportFixture {
	tenantID := uuid.Must(uuid.NewV7())
	providerID := uuid.Must(uuid.NewV7())
	bindingID := uuid.Must(uuid.NewV7())
	mappingID := uuid.Must(uuid.NewV7())
	accessEpochID := uuid.Must(uuid.NewV7())
	now := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	snapshot := identityprovider.PinnedPlannerSnapshot{
		ProviderID: providerID, ProviderVersion: 4, BindingID: bindingID,
		BindingVersion: 7, ConfigurationRevision: 3, AccessEpochID: accessEpochID,
		MappingRevisions: []identityprovider.PinnedMappingRevision{},
	}
	manualReason := "operator requested"
	priority := 10
	fixture := ldapAdministrationTransportFixture{
		tenantID: tenantID, userID: uuid.Must(uuid.NewV7()), providerID: providerID,
		bindingID: bindingID, mappingID: mappingID,
		mappingAfter:    identityprovider.MappingCursor{Priority: 29, ID: uuid.Must(uuid.NewV7())},
		securityGroupID: uuid.Must(uuid.NewV7()),
		roleID:          uuid.Must(uuid.NewV7()), accessEpochID: accessEpochID,
		syncRunID: uuid.Must(uuid.NewV7()), checkedAt: now,
	}
	fixture.binding = identityprovider.Binding{
		ID: bindingID, TenantID: tenantID, ProviderID: providerID, LoginKey: "corp_ldap",
		Enabled: false, ProfilePriority: 20, AuthRevision: 2, Version: 7,
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	fixture.mapping = identityprovider.Mapping{
		ID: mappingID, TenantID: tenantID, BindingID: bindingID,
		Matcher: identityprovider.MappingMatcher{
			Type: identityprovider.MappingMatcherExactCN, Value: "incident-responders",
			CaseMode: identityprovider.MappingCaseInsensitive,
		},
		Priority: 30, Target: identityprovider.MappingTarget{
			TenantSecurityGroupID: fixture.securityGroupID, RoleIDs: []uuid.UUID{fixture.roleID},
		},
		ReconciliationMode: identityprovider.ReconciliationAdditive, Enabled: false,
		Notes: "reviewed mapping", Version: 8, CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	fixture.directoryResult = identityprovider.DirectoryTestResult{
		Diagnostic: identityprovider.TestResult{
			TestRunID: uuid.Must(uuid.NewV7()), Outcome: "success", Category: "success",
			EndpointPriority: &priority, Duration: 12 * time.Millisecond, CompletedAt: now,
		},
		MatchedEntryCount: 1,
		Entries: []identityprovider.RedactedEntry{{
			Ordinal: 1, DNPresent: true, GroupValueCount: 2,
			Attributes: []identityprovider.RedactedEntryAttribute{{Name: "uid", ValueCount: 1}},
		}},
	}
	fixture.dryRun = identityprovider.DryRunResult{
		ID: uuid.Must(uuid.NewV7()), Outcome: "success", Decision: "allow",
		IdentityDisposition: "existing_identity", ObservationComplete: true,
		DenialReasons: []string{}, MatchedMappingIDs: []uuid.UUID{}, Snapshot: snapshot,
		Plan: identityprovider.DryRunPlan{
			ProfileAction: "none", ProviderAccessAction: identityprovider.DryRunActionNone,
			GroupActions: []identityprovider.DryRunGroupAction{}, RoleActions: []identityprovider.DryRunRoleAction{},
			OperatorTeamActions: []identityprovider.DryRunOperatorTeamAction{},
		},
		GeneratedAt: now,
	}
	fixture.syncStatus = identityprovider.SyncStatus{
		BindingID: bindingID, ScheduleState: "idle", Version: 9, UpdatedAt: now,
	}
	fixture.syncRun = identityprovider.SyncRun{
		ID: fixture.syncRunID, TenantID: tenantID, BindingID: bindingID, ProviderID: providerID,
		Trigger: "manual", ManualReason: &manualReason, State: identityprovider.SyncRunQueued,
		Snapshot: snapshot, Enumeration: identityprovider.SyncEnumeration{
			State: "not_started", CursorState: "none",
		},
		Counters: identityprovider.SyncCounters{}, CreatedAt: now, UpdatedAt: now, Version: 11,
	}
	return fixture
}

func newLDAPAdministrationTestRouter(
	t *testing.T,
	auth AuthenticationService,
	service LDAPAdministrationService,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: service, MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{},
			OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
			PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func successfulLDAPAdministrationStub(
	t *testing.T,
	fixture ldapAdministrationTransportFixture,
	calls map[string]int,
) *transportLDAPAdministrationStub {
	t.Helper()
	record := func(name string, actor authorization.Actor, tenantID uuid.UUID) {
		t.Helper()
		calls[name]++
		if tenantID != fixture.tenantID || actor.UserID != fixture.userID ||
			actor.ActiveTenantID != fixture.tenantID || actor.AuthenticationMethod != "totp" {
			t.Fatalf("%s actor/tenant = %#v/%s", name, actor, tenantID)
		}
	}
	validAudit := func(audit authorization.AuditContext) bool {
		return audit.RequestID != uuid.Nil && audit.CorrelationID != uuid.Nil &&
			audit.RemoteAddress.String() == "198.51.100.42"
	}
	return &transportLDAPAdministrationStub{
		searchUser: func(_ context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.UserSearchTestInput) (identityprovider.DirectoryTestResult, error) {
			record("searchUser", actor, tenantID)
			if providerID != fixture.providerID || input.Username != "sensitive-login" || !validAudit(input.Audit) {
				t.Fatalf("search input = %s/%#v", providerID, input)
			}
			return fixture.directoryResult, nil
		},
		testFilter: func(_ context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.FilterTestInput) (identityprovider.DirectoryTestResult, error) {
			record("testFilter", actor, tenantID)
			if providerID != fixture.providerID || input.Kind != identityprovider.DirectoryFilterKindGroup ||
				input.Username != "sensitive-login" || input.MaxResults != 2 || input.GIDNumber == nil || *input.GIDNumber != 1000 || !validAudit(input.Audit) {
				t.Fatalf("filter input = %s/%#v", providerID, input)
			}
			return fixture.directoryResult, nil
		},
		listBindings: func(_ context.Context, actor authorization.Actor, tenantID uuid.UUID, input identityprovider.ListBindingsInput) (identityprovider.BindingPage, error) {
			record("listBindings", actor, tenantID)
			if input.Limit != 25 || !input.IncludeArchived {
				t.Fatalf("list bindings input = %#v", input)
			}
			return identityprovider.BindingPage{Items: []identityprovider.Binding{fixture.binding}}, nil
		},
		createBinding: func(_ context.Context, actor authorization.Actor, tenantID uuid.UUID, input identityprovider.CreateBindingInput) (identityprovider.Binding, error) {
			record("createBinding", actor, tenantID)
			if input.ProviderID != fixture.providerID || input.LoginKey != "corp_ldap" || input.Enabled ||
				input.ProfilePriority != 20 || input.IdempotencyKey != "ldap-admin-0123456789" || !validAudit(input.Audit) {
				t.Fatalf("create binding input = %#v", input)
			}
			return fixture.binding, nil
		},
		getBinding: func(_ context.Context, actor authorization.Actor, tenantID, bindingID uuid.UUID) (identityprovider.Binding, error) {
			record("getBinding", actor, tenantID)
			if bindingID != fixture.bindingID {
				t.Fatalf("binding id = %s", bindingID)
			}
			return fixture.binding, nil
		},
		updateBinding: func(_ context.Context, actor authorization.Actor, tenantID, bindingID uuid.UUID, input identityprovider.UpdateBindingInput) (identityprovider.Binding, error) {
			record("updateBinding", actor, tenantID)
			if bindingID != fixture.bindingID || input.ExpectedEntityTag == nil || *input.ExpectedEntityTag != `"v7"` ||
				input.LoginKey != "corp_ldap" || input.Enabled || input.ProfilePriority != 20 || !validAudit(input.Audit) {
				t.Fatalf("update binding input = %s/%#v", bindingID, input)
			}
			return fixture.binding, nil
		},
		archiveBinding: func(_ context.Context, actor authorization.Actor, tenantID, bindingID uuid.UUID, input identityprovider.ArchiveBindingInput) (int64, error) {
			record("archiveBinding", actor, tenantID)
			if bindingID != fixture.bindingID || input.Reason != "retired" || input.ExpectedEntityTag == nil ||
				*input.ExpectedEntityTag != `"v7"` || !validAudit(input.Audit) {
				t.Fatalf("archive binding input = %s/%#v", bindingID, input)
			}
			return 9, nil
		},
		listMappings: func(_ context.Context, actor authorization.Actor, tenantID uuid.UUID, input identityprovider.ListMappingsInput) (identityprovider.MappingPage, error) {
			record("listMappings", actor, tenantID)
			if input.After == nil || *input.After != fixture.mappingAfter || input.Limit != 25 ||
				!input.IncludeArchived || input.BindingID == nil || *input.BindingID != fixture.bindingID {
				t.Fatalf("list mappings input = %#v", input)
			}
			next := identityprovider.MappingCursor{Priority: fixture.mapping.Priority, ID: fixture.mapping.ID}
			return identityprovider.MappingPage{Items: []identityprovider.Mapping{fixture.mapping}, NextCursor: &next}, nil
		},
		createMapping: func(_ context.Context, actor authorization.Actor, tenantID uuid.UUID, input identityprovider.CreateMappingInput) (identityprovider.Mapping, error) {
			record("createMapping", actor, tenantID)
			if input.BindingID != fixture.bindingID || input.Matcher.Type != identityprovider.MappingMatcherExactCN ||
				input.Target.TenantSecurityGroupID != fixture.securityGroupID || len(input.Target.RoleIDs) != 1 ||
				input.Target.RoleIDs[0] != fixture.roleID || input.ReconciliationMode != identityprovider.ReconciliationAdditive ||
				input.Reason != "reviewed" || input.IdempotencyKey != "ldap-admin-0123456789" || !validAudit(input.Audit) {
				t.Fatalf("create mapping input = %#v", input)
			}
			return fixture.mapping, nil
		},
		dryRunMappings: func(_ context.Context, actor authorization.Actor, tenantID uuid.UUID, input identityprovider.DryRunInput) (identityprovider.DryRunResult, error) {
			record("dryRunMappings", actor, tenantID)
			if input.BindingID != fixture.bindingID || input.Username != "sensitive-login" ||
				len(input.IncludeDisabledMappingIDs) != 1 || input.IncludeDisabledMappingIDs[0] != fixture.mappingID || !validAudit(input.Audit) {
				t.Fatalf("dry-run input = %#v", input)
			}
			return fixture.dryRun, nil
		},
		getMapping: func(_ context.Context, actor authorization.Actor, tenantID, mappingID uuid.UUID) (identityprovider.Mapping, error) {
			record("getMapping", actor, tenantID)
			if mappingID != fixture.mappingID {
				t.Fatalf("mapping id = %s", mappingID)
			}
			return fixture.mapping, nil
		},
		updateMapping: func(_ context.Context, actor authorization.Actor, tenantID, mappingID uuid.UUID, input identityprovider.UpdateMappingInput) (identityprovider.Mapping, error) {
			record("updateMapping", actor, tenantID)
			if mappingID != fixture.mappingID || input.ExpectedEntityTag == nil || *input.ExpectedEntityTag != `"v8"` ||
				input.Enabled || input.Reason != "reviewed" || input.Matcher.Type != identityprovider.MappingMatcherExactCN || !validAudit(input.Audit) {
				t.Fatalf("update mapping input = %s/%#v", mappingID, input)
			}
			return fixture.mapping, nil
		},
		archiveMapping: func(_ context.Context, actor authorization.Actor, tenantID, mappingID uuid.UUID, input identityprovider.ArchiveMappingInput) (int64, error) {
			record("archiveMapping", actor, tenantID)
			if mappingID != fixture.mappingID || input.Reason != "retired" || input.ExpectedEntityTag == nil ||
				*input.ExpectedEntityTag != `"v8"` || !validAudit(input.Audit) {
				t.Fatalf("archive mapping input = %s/%#v", mappingID, input)
			}
			return 10, nil
		},
		getSyncStatus: func(_ context.Context, actor authorization.Actor, tenantID, bindingID uuid.UUID) (identityprovider.SyncStatus, error) {
			record("getSyncStatus", actor, tenantID)
			if bindingID != fixture.bindingID {
				t.Fatalf("sync status binding = %s", bindingID)
			}
			return fixture.syncStatus, nil
		},
		listSyncRuns: func(_ context.Context, actor authorization.Actor, tenantID, bindingID uuid.UUID, input identityprovider.PageInput) (identityprovider.SyncRunPage, error) {
			record("listSyncRuns", actor, tenantID)
			if bindingID != fixture.bindingID || input.Limit != 25 {
				t.Fatalf("sync list input = %s/%#v", bindingID, input)
			}
			return identityprovider.SyncRunPage{Items: []identityprovider.SyncRun{fixture.syncRun}}, nil
		},
		startManualSync: func(_ context.Context, actor authorization.Actor, tenantID, bindingID uuid.UUID, input identityprovider.StartManualSyncInput) (identityprovider.SyncRun, error) {
			record("startManualSync", actor, tenantID)
			if bindingID != fixture.bindingID || input.Reason != "operator requested" ||
				input.IdempotencyKey != "ldap-admin-0123456789" || input.ExpectedEntityTag == nil ||
				*input.ExpectedEntityTag != `"v7"` || !validAudit(input.Audit) {
				t.Fatalf("manual sync input = %s/%#v", bindingID, input)
			}
			return fixture.syncRun, nil
		},
		getSyncRun: func(_ context.Context, actor authorization.Actor, tenantID, bindingID, syncRunID uuid.UUID) (identityprovider.SyncRun, error) {
			record("getSyncRun", actor, tenantID)
			if bindingID != fixture.bindingID || syncRunID != fixture.syncRunID {
				t.Fatalf("sync run ids = %s/%s", bindingID, syncRunID)
			}
			return fixture.syncRun, nil
		},
	}
}

func TestTenantLDAPAdministrationTransportWiresAllOperations(t *testing.T) {
	fixture := newLDAPAdministrationTransportFixture()
	calls := make(map[string]int)
	service := successfulLDAPAdministrationStub(t, fixture, calls)
	router := newLDAPAdministrationTestRouter(
		t, tenantLDAPTransportAuthentication(fixture.tenantID, fixture.userID), service,
	)
	base := "/api/v1/tenants/" + fixture.tenantID.String()
	providerBase := base + "/auth-providers/" + fixture.providerID.String()
	bindingBase := base + "/auth-provider-bindings"
	bindingPath := bindingBase + "/" + fixture.bindingID.String()
	mappingBase := base + "/ldap-mappings"
	mappingPath := mappingBase + "/" + fixture.mappingID.String()
	syncBase := bindingPath + "/sync-runs"
	mappingAfter, err := identityprovider.EncodeMappingCursor(fixture.mappingAfter)
	if err != nil {
		t.Fatalf("EncodeMappingCursor() error = %v", err)
	}
	mappingNext, err := identityprovider.EncodeMappingCursor(identityprovider.MappingCursor{
		Priority: fixture.mapping.Priority,
		ID:       fixture.mapping.ID,
	})
	if err != nil {
		t.Fatalf("EncodeMappingCursor(next) error = %v", err)
	}
	mappingCreate := fmt.Sprintf(
		`{"bindingId":%q,"matcher":{"type":"exact_cn","cn":"incident-responders","caseMode":"insensitive"},"priority":30,"target":{"tenantSecurityGroupId":%q,"roleIds":[%q],"operatorTeamAssignment":null},"reconciliationMode":"additive","notes":"reviewed mapping","reason":"reviewed"}`,
		fixture.bindingID, fixture.securityGroupID, fixture.roleID,
	)
	mappingUpdate := fmt.Sprintf(
		`{"matcher":{"type":"exact_cn","cn":"incident-responders","caseMode":"insensitive"},"priority":30,"target":{"tenantSecurityGroupId":%q,"roleIds":[%q],"operatorTeamAssignment":null},"reconciliationMode":"additive","enabled":false,"notes":"reviewed mapping","reason":"reviewed"}`,
		fixture.securityGroupID, fixture.roleID,
	)
	tests := []struct {
		name, method, path, body string
		mutation, idempotent     bool
		ifMatch                  string
		wantStatus               int
		wantETag, wantLocation   string
	}{
		{name: "bounded user search", method: http.MethodPost, path: providerBase + "/tests/user-search", body: `{"username":"sensitive-login"}`, mutation: true, wantStatus: http.StatusOK},
		{name: "bounded filter test", method: http.MethodPost, path: providerBase + "/tests/filter", body: `{"kind":"group","filterTemplate":"(cn={username})","username":"sensitive-login","userDn":null,"gidNumber":1000,"maxResults":2}`, mutation: true, wantStatus: http.StatusOK},
		{name: "list bindings", method: http.MethodGet, path: bindingBase + "?includeArchived=true&limit=25", wantStatus: http.StatusOK},
		{name: "create binding", method: http.MethodPost, path: bindingBase, body: fmt.Sprintf(`{"providerId":%q,"loginKey":"corp_ldap","enabled":false,"profilePriority":20}`, fixture.providerID), mutation: true, idempotent: true, wantStatus: http.StatusCreated, wantETag: `"v7"`, wantLocation: bindingPath},
		{name: "get binding", method: http.MethodGet, path: bindingPath, wantStatus: http.StatusOK, wantETag: `"v7"`},
		{name: "update binding", method: http.MethodPut, path: bindingPath, body: `{"loginKey":"corp_ldap","enabled":false,"profilePriority":20}`, mutation: true, ifMatch: `"v7"`, wantStatus: http.StatusOK, wantETag: `"v7"`},
		{name: "archive binding", method: http.MethodDelete, path: bindingPath, body: `{"reason":"retired"}`, mutation: true, ifMatch: `"v7"`, wantStatus: http.StatusNoContent, wantETag: `"v9"`},
		{name: "list mappings", method: http.MethodGet, path: mappingBase + "?after=" + mappingAfter + "&bindingId=" + fixture.bindingID.String() + "&includeArchived=true&limit=25", wantStatus: http.StatusOK},
		{name: "create mapping", method: http.MethodPost, path: mappingBase, body: mappingCreate, mutation: true, idempotent: true, wantStatus: http.StatusCreated, wantETag: `"v8"`, wantLocation: mappingPath},
		{name: "mapping dry run", method: http.MethodPost, path: mappingBase + "/dry-run", body: fmt.Sprintf(`{"bindingId":%q,"username":"sensitive-login","includeDisabledMappingIds":[%q]}`, fixture.bindingID, fixture.mappingID), mutation: true, wantStatus: http.StatusOK},
		{name: "get mapping", method: http.MethodGet, path: mappingPath, wantStatus: http.StatusOK, wantETag: `"v8"`},
		{name: "update mapping", method: http.MethodPut, path: mappingPath, body: mappingUpdate, mutation: true, ifMatch: `"v8"`, wantStatus: http.StatusOK, wantETag: `"v8"`},
		{name: "archive mapping", method: http.MethodDelete, path: mappingPath, body: `{"reason":"retired"}`, mutation: true, ifMatch: `"v8"`, wantStatus: http.StatusNoContent, wantETag: `"v10"`},
		{name: "sync status", method: http.MethodGet, path: bindingPath + "/sync-status", wantStatus: http.StatusOK, wantETag: `"v9"`},
		{name: "list sync runs", method: http.MethodGet, path: syncBase + "?limit=25", wantStatus: http.StatusOK},
		{name: "start manual sync", method: http.MethodPost, path: syncBase, body: `{"reason":"operator requested"}`, mutation: true, idempotent: true, ifMatch: `"v7"`, wantStatus: http.StatusAccepted, wantETag: `"v11"`, wantLocation: syncBase + "/" + fixture.syncRunID.String()},
		{name: "get sync run", method: http.MethodGet, path: syncBase + "/" + fixture.syncRunID.String(), wantStatus: http.StatusOK, wantETag: `"v11"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			prepareTenantLDAPTransportRequest(request, test.mutation)
			if test.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			if test.idempotent {
				request.Header.Set(idempotencyKeyHeader, "ldap-admin-0123456789")
			}
			if test.ifMatch != "" {
				request.Header.Set("If-Match", test.ifMatch)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.wantStatus, response.Body.String())
			}
			if got := response.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q", got)
			}
			if got := response.Header().Get("ETag"); got != test.wantETag {
				t.Fatalf("ETag = %q, want %q", got, test.wantETag)
			}
			if got := response.Header().Get("Location"); got != test.wantLocation {
				t.Fatalf("Location = %q, want %q", got, test.wantLocation)
			}
			body := response.Body.String()
			if strings.Contains(body, "sensitive-login") || strings.Contains(body, "cn=secret-user") {
				t.Fatalf("response leaked request or directory identity: %s", body)
			}
			if strings.Contains(test.name, "search") || strings.Contains(test.name, "filter") {
				if !strings.Contains(body, `"valuesRedacted":true`) || !strings.Contains(body, `"immutableSubjectRedacted":true`) {
					t.Fatalf("directory diagnostic is not structurally redacted: %s", body)
				}
			}
			if test.name == "list mappings" && !strings.Contains(body, `"nextCursor":"`+mappingNext+`"`) {
				t.Fatalf("mapping response cursor = %s", body)
			}
		})
	}
	for _, name := range []string{
		"searchUser", "testFilter", "listBindings", "createBinding", "getBinding", "updateBinding",
		"archiveBinding", "listMappings", "createMapping", "dryRunMappings", "getMapping", "updateMapping",
		"archiveMapping", "getSyncStatus", "listSyncRuns", "startManualSync", "getSyncRun",
	} {
		if calls[name] != 1 {
			t.Fatalf("%s calls = %d, want 1", name, calls[name])
		}
	}
}

func TestTenantLDAPAdministrationRejectsInvalidTransportInputBeforeService(t *testing.T) {
	fixture := newLDAPAdministrationTransportFixture()
	router := newLDAPAdministrationTestRouter(
		t, tenantLDAPTransportAuthentication(fixture.tenantID, fixture.userID), &transportLDAPAdministrationStub{},
	)
	base := "/api/v1/tenants/" + fixture.tenantID.String()
	bindingBase := base + "/auth-provider-bindings"
	bindingPath := bindingBase + "/" + fixture.bindingID.String()
	mappingBase := base + "/ldap-mappings"
	mappingPath := mappingBase + "/" + fixture.mappingID.String()
	validBindingBody := fmt.Sprintf(
		`{"providerId":%q,"loginKey":"corp_ldap","enabled":false,"profilePriority":20}`,
		fixture.providerID,
	)
	validMappingBody := fmt.Sprintf(
		`{"bindingId":%q,"matcher":{"type":"exact_cn","cn":"responders","caseMode":"insensitive"},"priority":30,"target":{"tenantSecurityGroupId":%q,"roleIds":[%q],"operatorTeamAssignment":null},"reconciliationMode":"additive","notes":"","reason":"reviewed"}`,
		fixture.bindingID, fixture.securityGroupID, fixture.roleID,
	)
	v4 := uuid.New()
	tests := []struct {
		name, method, path, body string
		mutation                 bool
		headers                  map[string][]string
		wantStatus               int
		wantCode                 string
	}{
		{name: "body on read", method: http.MethodGet, path: bindingBase, body: `{}`, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "non-v7 path identifier", method: http.MethodGet, path: bindingBase + "/" + v4.String(), wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "non-v7 cursor", method: http.MethodGet, path: bindingBase + "?after=" + v4.String(), wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "malformed mapping cursor", method: http.MethodGet, path: mappingBase + "?after=short", wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "well-shaped invalid mapping cursor", method: http.MethodGet, path: mappingBase + "?after=" + strings.Repeat("A", identityprovider.LDAPMappingCursorLength), wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "zero page limit", method: http.MethodGet, path: bindingBase + "?limit=0", wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "missing idempotency key", method: http.MethodPost, path: bindingBase, body: validBindingBody, mutation: true, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate idempotency key", method: http.MethodPost, path: bindingBase, body: validBindingBody, mutation: true, headers: map[string][]string{idempotencyKeyHeader: {"ldap-admin-0123456789", "ldap-admin-9876543210"}}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "missing precondition", method: http.MethodPut, path: bindingPath, body: `{"loginKey":"corp_ldap","enabled":false,"profilePriority":20}`, mutation: true, wantStatus: http.StatusPreconditionRequired, wantCode: "precondition_required"},
		{name: "weak precondition", method: http.MethodPut, path: bindingPath, body: `{"loginKey":"corp_ldap","enabled":false,"profilePriority":20}`, mutation: true, headers: map[string][]string{"If-Match": {`W/"v7"`}}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate top-level member", method: http.MethodPost, path: bindingBase, body: strings.Replace(validBindingBody, `"loginKey":"corp_ldap"`, `"loginKey":"corp_ldap","loginKey":"other"`, 1), mutation: true, headers: map[string][]string{idempotencyKeyHeader: {"ldap-admin-0123456789"}}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "unknown top-level member", method: http.MethodPost, path: bindingBase, body: strings.TrimSuffix(validBindingBody, "}") + `,"unexpected":true}`, mutation: true, headers: map[string][]string{idempotencyKeyHeader: {"ldap-admin-0123456789"}}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate nested member", method: http.MethodPost, path: mappingBase, body: strings.Replace(validMappingBody, `"cn":"responders"`, `"cn":"responders","cn":"operators"`, 1), mutation: true, headers: map[string][]string{idempotencyKeyHeader: {"ldap-admin-0123456789"}}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "unknown nested member", method: http.MethodPost, path: mappingBase, body: strings.Replace(validMappingBody, `"caseMode":"insensitive"`, `"caseMode":"insensitive","firstMatchWins":true`, 1), mutation: true, headers: map[string][]string{idempotencyKeyHeader: {"ldap-admin-0123456789"}}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "invalid regex", method: http.MethodPost, path: mappingBase, body: strings.Replace(validMappingBody, `"type":"exact_cn","cn":"responders"`, `"type":"regex","pattern":"["`, 1), mutation: true, headers: map[string][]string{idempotencyKeyHeader: {"ldap-admin-0123456789"}}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate role target", method: http.MethodPost, path: mappingBase, body: strings.Replace(validMappingBody, fmt.Sprintf(`"roleIds":[%q]`, fixture.roleID), fmt.Sprintf(`"roleIds":[%q,%q]`, fixture.roleID, fixture.roleID), 1), mutation: true, headers: map[string][]string{idempotencyKeyHeader: {"ldap-admin-0123456789"}}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate dry-run mapping", method: http.MethodPost, path: mappingBase + "/dry-run", body: fmt.Sprintf(`{"bindingId":%q,"username":"login","includeDisabledMappingIds":[%q,%q]}`, fixture.bindingID, fixture.mappingID, fixture.mappingID), mutation: true, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "gid above uint32", method: http.MethodPost, path: base + "/auth-providers/" + fixture.providerID.String() + "/tests/filter", body: `{"kind":"group","filterTemplate":"(gidNumber={gidNumber})","username":"login","userDn":null,"gidNumber":4294967296,"maxResults":2}`, mutation: true, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "malformed json", method: http.MethodPut, path: mappingPath, body: `{`, mutation: true, headers: map[string][]string{"If-Match": {`"v8"`}}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "wrong content type", method: http.MethodPost, path: mappingBase, body: validMappingBody, mutation: true, headers: map[string][]string{idempotencyKeyHeader: {"ldap-admin-0123456789"}, "Content-Type": {"text/plain"}}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			prepareTenantLDAPTransportRequest(request, test.mutation)
			if test.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			for name, values := range test.headers {
				request.Header.Del(name)
				for _, value := range values {
					request.Header.Add(name, value)
				}
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			assertProblem(t, response, test.wantStatus, test.wantCode)
			if got := response.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q", got)
			}
		})
	}
}

func TestTenantLDAPAdministrationEnforcesAuthenticationCSRFAndSelectedTenant(t *testing.T) {
	fixture := newLDAPAdministrationTransportFixture()
	t.Run("anonymous", func(t *testing.T) {
		router := newLDAPAdministrationTestRouter(t, &transportAuthStub{}, &transportLDAPAdministrationStub{})
		request := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+fixture.tenantID.String()+"/auth-provider-bindings", nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		assertProblem(t, response, http.StatusUnauthorized, "authentication_failed")
	})

	t.Run("missing csrf", func(t *testing.T) {
		called := 0
		service := &transportLDAPAdministrationStub{createBinding: func(context.Context, authorization.Actor, uuid.UUID, identityprovider.CreateBindingInput) (identityprovider.Binding, error) {
			called++
			return fixture.binding, nil
		}}
		router := newLDAPAdministrationTestRouter(t, tenantLDAPTransportAuthentication(fixture.tenantID, fixture.userID), service)
		request := tenantLDAPMutationRequest(
			http.MethodPost, "/api/v1/tenants/"+fixture.tenantID.String()+"/auth-provider-bindings",
			[]byte(fmt.Sprintf(`{"providerId":%q,"loginKey":"corp_ldap","enabled":false,"profilePriority":20}`, fixture.providerID)),
		)
		request.Header.Set(idempotencyKeyHeader, "ldap-admin-0123456789")
		request.Header.Del(csrfTokenHeader)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		assertProblem(t, response, http.StatusForbidden, "forbidden")
		if called != 0 {
			t.Fatal("mutation without CSRF reached LDAP administration service")
		}
	})

	t.Run("different selected tenant", func(t *testing.T) {
		activeTenantID := uuid.Must(uuid.NewV7())
		called := 0
		service := &transportLDAPAdministrationStub{listBindings: func(context.Context, authorization.Actor, uuid.UUID, identityprovider.ListBindingsInput) (identityprovider.BindingPage, error) {
			called++
			return identityprovider.BindingPage{}, nil
		}}
		router := newLDAPAdministrationTestRouter(t, tenantLDAPTransportAuthentication(activeTenantID, fixture.userID), service)
		request := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+fixture.tenantID.String()+"/auth-provider-bindings", nil)
		prepareTenantLDAPTransportRequest(request, false)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		assertProblem(t, response, http.StatusForbidden, "forbidden")
		if called != 0 {
			t.Fatal("cross-tenant actor reached LDAP administration service")
		}
	})
}

func TestTenantLDAPAdministrationMapsServiceErrorsToProblemDetails(t *testing.T) {
	fixture := newLDAPAdministrationTransportFixture()
	tests := []struct {
		err        error
		wantStatus int
		wantCode   string
		retryAfter string
	}{
		{err: identityprovider.ErrInvalidInput, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{err: identityprovider.ErrForbidden, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{err: identityprovider.ErrNotFound, wantStatus: http.StatusNotFound, wantCode: "not_found"},
		{err: identityprovider.ErrConflict, wantStatus: http.StatusConflict, wantCode: "conflict"},
		{err: identityprovider.ErrPreconditionFailed, wantStatus: http.StatusPreconditionFailed, wantCode: "precondition_failed"},
		{err: identityprovider.ErrPreconditionRequired, wantStatus: http.StatusPreconditionRequired, wantCode: "precondition_required"},
		{err: identityprovider.ErrRateLimited, wantStatus: http.StatusTooManyRequests, wantCode: "rate_limited", retryAfter: "60"},
		{err: identityprovider.ErrUnavailable, wantStatus: http.StatusServiceUnavailable, wantCode: "service_unavailable", retryAfter: "5"},
	}
	for _, test := range tests {
		t.Run(test.wantCode, func(t *testing.T) {
			service := &transportLDAPAdministrationStub{getBinding: func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (identityprovider.Binding, error) {
				return identityprovider.Binding{}, test.err
			}}
			router := newLDAPAdministrationTestRouter(t, tenantLDAPTransportAuthentication(fixture.tenantID, fixture.userID), service)
			request := httptest.NewRequest(
				http.MethodGet,
				fmt.Sprintf("/api/v1/tenants/%s/auth-provider-bindings/%s", fixture.tenantID, fixture.bindingID),
				nil,
			)
			prepareTenantLDAPTransportRequest(request, false)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			assertProblem(t, response, test.wantStatus, test.wantCode)
			if got := response.Header().Get("Retry-After"); got != test.retryAfter {
				t.Fatalf("Retry-After = %q, want %q", got, test.retryAfter)
			}
		})
	}
}

func TestTenantLDAPAdministrationFailsClosedOnDivergentProjection(t *testing.T) {
	fixture := newLDAPAdministrationTransportFixture()
	divergent := fixture.binding
	divergent.TenantID = uuid.Must(uuid.NewV7())
	service := &transportLDAPAdministrationStub{getBinding: func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (identityprovider.Binding, error) {
		return divergent, nil
	}}
	router := newLDAPAdministrationTestRouter(t, tenantLDAPTransportAuthentication(fixture.tenantID, fixture.userID), service)
	request := httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf("/api/v1/tenants/%s/auth-provider-bindings/%s", fixture.tenantID, fixture.bindingID),
		nil,
	)
	prepareTenantLDAPTransportRequest(request, false)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
}

func TestApplicationHandlerRequiresLDAPAdministrationBoundary(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, ApplicationOptions{
		Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: &transportAuthStub{}, Authorization: &transportAuthorizationStub{},
		Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, OperatorTeams: &transportOperatorTeamStub{},
		Platform: &transportPlatformStub{}, PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{},
	})
	if err == nil || !strings.Contains(err.Error(), "LDAP administration") {
		t.Fatalf("NewApplicationHandler() error = %v, want missing LDAP administration failure", err)
	}
}

func TestTransportLDAPAdministrationStubIsFailClosed(t *testing.T) {
	if _, err := (&transportLDAPAdministrationStub{}).ListBindings(
		context.Background(), authorization.Actor{}, uuid.Nil, identityprovider.ListBindingsInput{},
	); err != identityprovider.ErrUnavailable {
		t.Fatalf("default LDAP administration stub error = %v", err)
	}
}
