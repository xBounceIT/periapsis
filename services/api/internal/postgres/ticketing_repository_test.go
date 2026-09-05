package postgres

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	customkernel "github.com/periapsis-im/periapsis/modules/customfields"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestTicketActivityKindMapsCommentVisibilityFailClosed(t *testing.T) {
	tests := []struct {
		name       string
		stored     string
		principal  string
		visibility string
		want       string
	}{
		{name: "operator public", stored: "alert.commented", principal: "operator", visibility: "public", want: "comment.public"},
		{name: "operator private", stored: "case.commented", principal: "operator", visibility: "private", want: "comment.private"},
		{name: "missing visibility", stored: "alert.commented", principal: "operator"},
		{name: "unknown visibility", stored: "alert.commented", principal: "operator", visibility: "operator"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			principal, err := ticketPrincipal(test.principal)
			if err != nil {
				t.Fatal(err)
			}
			if got := mapTicketActivityKind(test.stored, principal, test.visibility); got != test.want {
				t.Fatalf("mapTicketActivityKind() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestTicketActivityActorProjectionIsClosed(t *testing.T) {
	membershipID := mustPostgresUUIDv7(t)
	serviceAccountID := mustPostgresUUIDv7(t)
	membership := pgtype.UUID{Bytes: [16]byte(membershipID), Valid: true}
	serviceAccount := pgtype.UUID{Bytes: [16]byte(serviceAccountID), Valid: true}
	tests := []struct {
		name       string
		storedKind string
		membership pgtype.UUID
		service    pgtype.UUID
		wantKind   application.ActivityActorKind
		wantID     uuid.UUID
		wantError  bool
	}{
		{name: "human membership", storedKind: "human", membership: membership, wantKind: application.ActivityActorHuman, wantID: membershipID},
		{name: "service account", storedKind: "service_account", service: serviceAccount, wantKind: application.ActivityActorServiceAccount, wantID: serviceAccountID},
		{name: "system", storedKind: "system", wantKind: application.ActivityActorSystem},
		{name: "redacted customer projection", storedKind: "redacted", wantKind: application.ActivityActorRedacted},
		{name: "human missing membership", storedKind: "human", wantError: true},
		{name: "service missing identity", storedKind: "service_account", wantError: true},
		{name: "mixed identity", storedKind: "human", membership: membership, service: serviceAccount, wantError: true},
		{name: "unknown kind", storedKind: "robot", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kind, id, err := mapTicketActivityActor(test.storedKind, test.membership, test.service)
			if test.wantError {
				if !errors.Is(err, application.ErrUnavailable) {
					t.Fatalf("mapTicketActivityActor() error = %v", err)
				}
				return
			}
			if err != nil || kind != test.wantKind || id != test.wantID {
				t.Fatalf("mapTicketActivityActor() = (%v, %v, %v), want (%v, %v, nil)", kind, id, err, test.wantKind, test.wantID)
			}
		})
	}
}

func TestCustomerActivityQueryRedactsIdentityTopologyAndDetails(t *testing.T) {
	projection := strings.Split(customerTicketActivitySelect, "FROM public.ticket_activities")[0]
	for _, required := range []string{
		"'redacted'::text", "NULL::uuid", "CASE author_snapshot.audience",
		"'Customer'", "'Support team'", `'{"visibility":"public"}'::jsonb`,
	} {
		if !strings.Contains(projection, required) {
			t.Fatalf("customer activity projection is missing %q: %q", required, projection)
		}
	}
	for _, forbidden := range []string{
		"activity.actor_principal_kind", "activity.actor_membership_id",
		"activity.actor_user_id", "activity.actor_service_account_id",
		"activity.details", "identity.display_name", "service_account.display_name",
		"public.tenant_memberships", "public.users", "public.tenant_service_accounts",
	} {
		if strings.Contains(customerTicketActivitySelect, forbidden) {
			t.Fatalf("customer activity query reads forbidden field %q: %q", forbidden, customerTicketActivitySelect)
		}
	}
	if !strings.Contains(customerTicketActivitySelect, "LEFT JOIN public.ticket_activity_author_snapshots") {
		t.Fatalf("customer activity query does not depend on immutable audience provenance: %q", customerTicketActivitySelect)
	}
}

func TestOperatorActivityUsesTenantSafeServiceAccountAttribution(t *testing.T) {
	if !strings.Contains(ticketActivitySelect, "app.ticket_service_account_attributions_v1") ||
		strings.Contains(ticketActivitySelect, "public.tenant_service_accounts") {
		t.Fatalf("operator activity attribution bypasses the tenant-safe projection: %q", ticketActivitySelect)
	}
}

func TestTicketQueriesProjectTenantScopedPrincipalIdentifiers(t *testing.T) {
	alertQuery, err := ticketRecordQuery(kernel.AggregateAlert)
	if err != nil {
		t.Fatal(err)
	}
	caseQuery, err := ticketRecordQuery(kernel.AggregateCase)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(alertQuery, "coalesce(ticket.created_by_membership_id, ticket.created_by_service_account_id)") ||
		!strings.Contains(caseQuery, "ticket.created_by_membership_id") {
		t.Fatal("ticket creator projection does not use tenant-scoped membership/service-account IDs")
	}
	for kind, query := range map[string]string{"alert": alertQuery, "case": caseQuery} {
		if strings.Contains(query, "membership.role") || strings.Contains(query, "creator_membership") || strings.Contains(query, "%!") {
			t.Fatalf("%s creator projection depends on a legacy role classifier or malformed format: %q", kind, query)
		}
	}
	if !strings.Contains(alertQuery, "app.ticket_service_account_attributions_v1") ||
		strings.Contains(alertQuery, "public.tenant_service_accounts") {
		t.Fatalf("alert creator attribution bypasses the tenant-safe projection: %q", alertQuery)
	}
}

func TestTicketPrincipalIsRouteIntentNotLegacyRole(t *testing.T) {
	for _, capability := range []application.Capability{
		application.CapabilityPortalAlertRead,
		application.CapabilityPortalCaseRead,
		application.CapabilityPortalCommentPublic,
		application.CapabilityPortalAlertExport,
		application.CapabilityPortalCaseExport,
	} {
		principal, err := ticketPrincipalForCapability(capability)
		if err != nil || principal != kernel.PrincipalCustomer {
			t.Fatalf("ticketPrincipalForCapability(%q) = (%v, %v), want customer", capability, principal, err)
		}
	}
	for _, capability := range []application.Capability{
		application.CapabilityAlertRead,
		application.CapabilityAlertRelationManage,
		application.CapabilityAlertCommentPublic,
		application.CapabilityAlertDelete,
		application.CapabilityCaseRead,
		application.CapabilityCaseCommentPrivate,
		application.CapabilityDFIRIOCRead,
		application.CapabilityDFIRAssetRead,
		application.CapabilityDFIRAttachmentRead,
	} {
		principal, err := ticketPrincipalForCapability(capability)
		if err != nil || principal != kernel.PrincipalOperator {
			t.Fatalf("ticketPrincipalForCapability(%q) = (%v, %v), want operator", capability, principal, err)
		}
	}
	if _, err := ticketPrincipalForCapability(application.Capability("portal.future")); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("unknown portal capability error = %v, want forbidden", err)
	}
}

func TestAlertRelationCapabilityRequiresReadAndUpdateAtOneExactScope(t *testing.T) {
	required, err := ticketCapabilityPermissions(application.CapabilityAlertRelationManage)
	if err != nil || !slices.Equal(required, []authorization.TenantPermission{"alert.read", "alert.update"}) {
		t.Fatalf("alert relation requirements = (%v, %v)", required, err)
	}
	if got := intersectTicketScopes([]map[application.Scope]struct{}{
		{application.ScopeOwn: {}, application.ScopeOperatorTeam: {}},
		{application.ScopeOperatorTeam: {}},
	}); len(got) != 1 || got[0] != application.ScopeOperatorTeam {
		t.Fatalf("common relation scopes = %v, want operator_team", got)
	}
	if got := intersectTicketScopes([]map[application.Scope]struct{}{
		{application.ScopeOwn: {}},
		{application.ScopeTenant: {}},
	}); len(got) != 0 {
		t.Fatalf("mismatched relation scopes = %v, want deny", got)
	}
}

func TestPortalExportCapabilityRequiresBothPermissionsAtOneExactScope(t *testing.T) {
	required, err := ticketCapabilityPermissions(application.CapabilityPortalAlertExport)
	if err != nil || len(required) != 2 ||
		required[0] != "portal.alert.read" || required[1] != "portal.comment.public" {
		t.Fatalf("alert export requirements = (%v, %v)", required, err)
	}
	if got := intersectTicketScopes([]map[application.Scope]struct{}{
		{application.ScopeOwn: {}, application.ScopeTenant: {}},
		{application.ScopeOwn: {}},
	}); len(got) != 1 || got[0] != application.ScopeOwn {
		t.Fatalf("common export scopes = %v, want own", got)
	}
	if got := intersectTicketScopes([]map[application.Scope]struct{}{
		{application.ScopeOwn: {}},
		{application.ScopeTenant: {}},
	}); len(got) != 0 {
		t.Fatalf("mismatched export scopes = %v, want deny", got)
	}
}

func TestActivityFeedCapabilityRequiresReadAndActivityAtOneExactScope(t *testing.T) {
	tests := []struct {
		capability application.Capability
		want       []authorization.TenantPermission
	}{
		{
			capability: application.CapabilityAlertActivityFeed,
			want:       []authorization.TenantPermission{"alert.read", "alert.activity.read"},
		},
		{
			capability: application.CapabilityCaseActivityFeed,
			want:       []authorization.TenantPermission{"case.read", "case.activity.read"},
		},
	}
	for _, test := range tests {
		required, err := ticketCapabilityPermissions(test.capability)
		if err != nil || !slices.Equal(required, test.want) {
			t.Fatalf("activity feed requirements for %q = (%v, %v), want %v",
				test.capability, required, err, test.want)
		}
		principal, err := ticketPrincipalForCapability(test.capability)
		if err != nil || principal != kernel.PrincipalOperator {
			t.Fatalf("activity feed principal for %q = (%v, %v)", test.capability, principal, err)
		}
	}
	if got := intersectTicketScopes([]map[application.Scope]struct{}{
		{application.ScopeAssigned: {}, application.ScopeTenant: {}},
		{application.ScopeAssigned: {}},
	}); len(got) != 1 || got[0] != application.ScopeAssigned {
		t.Fatalf("common activity feed scopes = %v, want assigned", got)
	}
	if got := intersectTicketScopes([]map[application.Scope]struct{}{
		{application.ScopeAssigned: {}},
		{application.ScopeTenant: {}},
	}); len(got) != 0 {
		t.Fatalf("mismatched activity feed scopes = %v, want deny", got)
	}
}

func TestCustomerTicketQueriesSelectOnlyCustomerSafeTicketColumns(t *testing.T) {
	queries := map[kernel.AggregateKind][]string{
		kernel.AggregateAlert: {
			"ticket.id", "ticket.number", "ticket.title", "ticket.description",
			"ticket.customer_custom_fields", "ticket.detected_at", "ticket.received_at",
		},
		kernel.AggregateCase: {
			"ticket.id", "ticket.number", "ticket.title", "ticket.description", "ticket.summary",
			"ticket.customer_custom_fields", "ticket.detection_time", "ticket.opened_at",
		},
	}
	for kind, required := range queries {
		t.Run(kind.String(), func(t *testing.T) {
			query, err := customerTicketRecordQuery(kind)
			if err != nil {
				t.Fatal(err)
			}
			projection := strings.Split(query, "\nFROM public.")[0]
			for _, field := range required {
				if !strings.Contains(projection, field) {
					t.Fatalf("customer %s projection is missing %q: %q", kind, field, projection)
				}
			}
			for _, forbidden := range []string{
				"ticket.raw_payload", "ticket.custom_fields", "ticket.classification",
				"ticket.source", "ticket.external_id", "ticket.deduplication_key",
				"ticket.created_by", "ticket.assigned_team_id", "ticket.assignee_user_id",
				"ticket.claimed_by_user_id", "creator_", "tenant_memberships", "tenant_service_accounts",
			} {
				if strings.Contains(query, forbidden) {
					t.Fatalf("customer %s query selects or joins operator-only data %q: %q", kind, forbidden, query)
				}
			}
			if strings.Count(projection, "ticket.customer_custom_fields") != 1 || strings.Contains(query, "membership.role") {
				t.Fatalf("customer %s custom-field or identity projection is not fail closed: %q", kind, query)
			}
			if strings.Contains(projection, "workflow_version.states") || strings.Contains(query, "workflow_version.transitions") ||
				!strings.Contains(query, "JOIN LATERAL") || !strings.Contains(query, "HAVING count(*) = 1") ||
				!strings.Contains(projection, "customer_state.visibility") {
				t.Fatalf("customer %s workflow projection is not current-state-only: %q", kind, query)
			}
		})
	}

	operatorQuery, err := ticketRecordQueryForPrincipal(kernel.AggregateAlert, kernel.PrincipalOperator)
	if err != nil || !strings.Contains(operatorQuery, "ticket.raw_payload") {
		t.Fatalf("operator query lost its full projection: (%q, %v)", operatorQuery, err)
	}
	customerQuery, err := ticketRecordQueryForPrincipal(kernel.AggregateAlert, kernel.PrincipalCustomer)
	if err != nil || strings.Contains(customerQuery, "ticket.raw_payload") {
		t.Fatalf("customer query did not select the allowlist: (%q, %v)", customerQuery, err)
	}
}

func TestCustomerProjectionWorkflowPreservesOnlyCurrentStateSemantics(t *testing.T) {
	workflowID := mustPostgresUUIDv7(t)
	ticketID, err := ticketEntityID(mustPostgresUUIDv7(t))
	if err != nil {
		t.Fatal(err)
	}
	tenantID, err := ticketEntityID(mustPostgresUUIDv7(t))
	if err != nil {
		t.Fatal(err)
	}
	currentKey, err := kernel.NewKey("customer_visible_state")
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := kernel.NewAssignment(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		initial     bool
		terminal    bool
		states      int
		transitions int
	}{
		{name: "initial", initial: true, states: 2, transitions: 1},
		{name: "intermediate", states: 3, transitions: 2},
		{name: "terminal", terminal: true, states: 2, transitions: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			workflow, workflowErr := customerProjectionWorkflow(
				workflowID, kernel.AggregateAlert, 7, currentKey.String(), test.initial, test.terminal, "customer",
			)
			if workflowErr != nil {
				t.Fatal(workflowErr)
			}
			if len(workflow.States()) != test.states || len(workflow.Transitions()) != test.transitions {
				t.Fatalf("projection topology = (%d states, %d transitions)", len(workflow.States()), len(workflow.Transitions()))
			}
			var current kernel.StateDefinition
			found := false
			for _, state := range workflow.States() {
				if state.Key() == currentKey {
					current, found = state, true
				}
			}
			if !found || current.Initial() != test.initial || current.Terminal() != test.terminal ||
				current.Visibility() != kernel.VisibilityCustomer {
				t.Fatalf("current state flags drifted: %#v", current)
			}
			snapshot, snapshotErr := kernel.NewTicketSnapshot(
				workflow, tenantID, ticketID, currentKey, 3, true, assignment,
			)
			if snapshotErr != nil || !kernel.CanProjectTicket(workflow, snapshot, kernel.ProjectionCustomerAPI) {
				t.Fatalf("customer projection is not kernel-valid: (%v, %v)", snapshot, snapshotErr)
			}
		})
	}
	for _, invalid := range []struct {
		initial    bool
		terminal   bool
		visibility string
	}{
		{initial: true, terminal: true, visibility: "customer"},
		{visibility: "internal"},
		{visibility: "operator"},
	} {
		if _, err := customerProjectionWorkflow(
			workflowID, kernel.AggregateAlert, 7, currentKey.String(), invalid.initial, invalid.terminal, invalid.visibility,
		); err == nil {
			t.Fatalf("incoherent customer workflow state was accepted: %#v", invalid)
		}
	}
}

func TestCustomerTicketQueryRetainsCanonicalCursorOrdering(t *testing.T) {
	sortName, order, predicate, err := ticketSort("updated_at_desc", "", [32]byte{}, func(any) string { return "$2" })
	if err != nil || sortName != "updated_at_desc" || order != "ticket.updated_at DESC, ticket.id DESC" || predicate != "" {
		t.Fatalf("canonical customer cursor order drifted: (%q, %q, %q, %v)", sortName, order, predicate, err)
	}
	query, err := customerTicketRecordQuery(kernel.AggregateAlert)
	if err != nil || !strings.Contains(query, "FROM public.alerts AS ticket") {
		t.Fatalf("customer query no longer preserves the ticket alias used by cursor ordering: (%q, %v)", query, err)
	}
}

func TestCustomerTicketListRejectsOperatorOnlyFilters(t *testing.T) {
	id := mustPostgresUUIDv7(t)
	tests := []application.ListInput{
		{AssignedTeamID: &id}, {AssigneeUserID: &id}, {ClaimedBy: &id}, {Queue: "assigned_to_me"},
	}
	for _, input := range tests {
		if !hasOperatorOnlyTicketListFilters(input) {
			t.Fatalf("operator-only customer list filter was accepted: %#v", input)
		}
	}
	if hasOperatorOnlyTicketListFilters(application.ListInput{Search: "safe"}) {
		t.Fatal("customer-safe list filters were rejected")
	}
}

func TestCustomerPortalExportQueryIsOperationShapedAndPublicOnly(t *testing.T) {
	for _, kind := range []kernel.AggregateKind{
		kernel.AggregateAlert, kernel.AggregateCase,
	} {
		t.Run(kind.String(), func(t *testing.T) {
			query, err := customerPortalExportQuery(kind)
			if err != nil {
				t.Fatal(err)
			}
			for _, required := range []string{
				"app.get_customer_portal_ticket_export_v2",
				"$1::public.ticket_aggregate_kind,$2,$3,$4",
				"result_public_comments",
			} {
				if !strings.Contains(query, required) {
					t.Fatalf("customer %s export query is missing %q: %q", kind, required, query)
				}
			}
			for _, forbidden := range []string{
				"public.ticket_comments", "public.ticket_comment_author_snapshots",
				"ticket.raw_payload", "ticket.custom_fields", "ticket.customer_custom_fields",
				"ticket.classification", "ticket.source", "ticket.external_id",
				"ticket.created_by", "ticket.assigned_team_id", "ticket.assignee_user_id",
				"ticket.claimed_by_user_id", "comment.body_html", "comment.mentioned_user_ids",
				"workflow_version.transitions", "membership.role", "creator_membership",
				"public.users", "identity.display_name",
			} {
				if strings.Contains(query, forbidden) {
					t.Fatalf("customer %s export query reads forbidden data %q: %q", kind, forbidden, query)
				}
			}
			projection := customerPortalExportProjection(query)
			if !strings.Contains(projection, "result_state") ||
				strings.Contains(projection, "workflow_version") {
				t.Fatalf("customer export projection contains workflow topology: %q", projection)
			}
		})
	}
}

func TestCustomerPortalExportScannerRejectsNonPublicOrMalformedComments(t *testing.T) {
	tenantID, resourceID, commentID := mustPostgresUUIDv7(t), mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)
	now := time.Date(2026, 8, 25, 9, 0, 0, 123000, time.UTC)
	row := func(comments string) rowFunc {
		return func(destinations ...any) error {
			*destinations[0].(*string) = "ALT-42"
			*destinations[1].(*string) = "Customer-safe alert"
			*destinations[2].(*string) = ""
			*destinations[3].(*string) = "Public description"
			*destinations[4].(*string) = "investigating"
			*destinations[5].(*string) = "high"
			*destinations[6].(*string) = "urgent"
			*destinations[7].(*string) = "endpoint"
			*destinations[8].(*time.Time) = now
			*destinations[9].(*time.Time) = now.Add(time.Minute)
			*destinations[10].(*int32) = 3
			*destinations[11].(*[]byte) = []byte(comments)
			return nil
		}
	}
	publicJSON := fmt.Sprintf(
		`[{"id":%q,"visibility":"public","bodyMarkdown":"Public update","author":"Incident team","audience":"operator","createdAt":%q}]`,
		commentID.String(), now.Format(time.RFC3339Nano),
	)
	result, err := scanCustomerPortalExport(row(publicJSON), tenantID, kernel.AggregateAlert, resourceID)
	if err != nil || len(result.Comments) != 1 || result.Comments[0].Visibility != kernel.CommentPublic ||
		result.TenantID != tenantID || result.ResourceID != resourceID {
		t.Fatalf("scanCustomerPortalExport() = (%+v, %v)", result, err)
	}
	privateJSON := strings.Replace(publicJSON, `"visibility":"public"`, `"visibility":"private"`, 1)
	if _, err := scanCustomerPortalExport(row(privateJSON), tenantID, kernel.AggregateAlert, resourceID); !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("private comment scanner error = %v, want unavailable", err)
	}
	unknownJSON := strings.Replace(publicJSON, `"createdAt":`, `"privateBody":"secret","createdAt":`, 1)
	if _, err := scanCustomerPortalExport(row(unknownJSON), tenantID, kernel.AggregateAlert, resourceID); !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("unknown comment field scanner error = %v, want unavailable", err)
	}
	malformed := map[string]string{
		"duplicate comment field": strings.Replace(
			publicJSON, `"audience":"operator"`, `"audience":"operator","audience":"customer"`, 1,
		),
		"lone escaped surrogate": strings.Replace(publicJSON, "Public update", `\ud800`, 1),
		"raw invalid UTF-8":      strings.Replace(publicJSON, "Public update", string([]byte{0xff}), 1),
	}
	for name, document := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := scanCustomerPortalExport(
				row(document), tenantID, kernel.AggregateAlert, resourceID,
			); !errors.Is(err, application.ErrUnavailable) {
				t.Fatalf("malformed comment scanner error = %v, want unavailable", err)
			}
		})
	}
}

func TestTicketFullTextSearchUsesCustomerSafeIndexedDocument(t *testing.T) {
	predicate := ticketFullTextSearchPredicate("$2")
	for _, required := range []string{
		"to_tsvector('simple'::regconfig",
		"coalesce(ticket.number, '')",
		"coalesce(ticket.title, '')",
		"coalesce(ticket.description, '')",
		"websearch_to_tsquery('simple'::regconfig, $2)",
	} {
		if !strings.Contains(predicate, required) {
			t.Fatalf("full-text predicate %q does not contain %q", predicate, required)
		}
	}
	for _, forbidden := range []string{"raw_payload", "custom_fields", "source", "summary", "ILIKE"} {
		if strings.Contains(predicate, forbidden) {
			t.Fatalf("full-text predicate exposes non-common field %q: %q", forbidden, predicate)
		}
	}
}

func TestTicketCustomFieldFilterEncodesOnlyScalarContractValues(t *testing.T) {
	tests := []struct {
		name     string
		dataType customkernel.DataType
		value    string
		want     string
		invalid  bool
	}{
		{name: "short text", dataType: customkernel.TypeShortText, value: "host-01", want: `"host-01"`},
		{name: "integer", dataType: customkernel.TypeInteger, value: "42", want: "42"},
		{name: "decimal", dataType: customkernel.TypeDecimal, value: "1.250", want: "1.250"},
		{name: "boolean", dataType: customkernel.TypeBoolean, value: "true", want: "true"},
		{name: "date", dataType: customkernel.TypeDate, value: "2026-08-26", want: `"2026-08-26"`},
		{name: "invalid typed scalar", dataType: customkernel.TypeInteger, value: "forty-two", invalid: true},
		{name: "multi select requires versioned operator", dataType: customkernel.TypeMultiSelect, value: "one", invalid: true},
		{name: "structured value requires versioned operator", dataType: customkernel.TypeStructuredJSON, value: `{}`, invalid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := ticketCustomFieldFilterJSON(test.dataType, test.value)
			if test.invalid {
				if !errors.Is(err, application.ErrInvalidInput) {
					t.Fatalf("ticketCustomFieldFilterJSON() error = %v, want invalid input", err)
				}
				return
			}
			if err != nil || string(raw) != test.want {
				t.Fatalf("ticketCustomFieldFilterJSON() = (%q, %v), want %q", raw, err, test.want)
			}
		})
	}
}

func TestTicketCustomFieldFilterPredicatePinsTypedRevisionWithoutRawTicketJSON(t *testing.T) {
	definitionID := mustPostgresUUIDv7(t)
	pin := ticketCustomFieldFilterPin{
		DefinitionID:     definitionID,
		DefinitionDigest: sha256.Sum256([]byte("definition-v7")),
		Key:              "risk_score",
		SchemaVersion:    7,
		DataType:         customkernel.TypeInteger,
		Canonical:        []byte("42"),
	}
	arguments := make([]any, 0, 6)
	add := func(value any) string {
		arguments = append(arguments, value)
		return fmt.Sprintf("$%d", len(arguments))
	}
	predicate, err := ticketCustomFieldFilterPredicate(kernel.AggregateAlert, pin, add)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"FROM public.custom_field_values AS filtered",
		"filtered.alert_id = ticket.id",
		"filtered.definition_id = $3",
		"filtered.definition_schema_version = $4",
		"filtered.data_type = $5::public.custom_field_data_type",
		"filtered.presence = 'present'",
		"filtered.integer_value = $1",
		"filtered.canonical_value = $6::jsonb",
	} {
		if !strings.Contains(predicate, required) {
			t.Fatalf("typed custom-field predicate is missing %q: %q", required, predicate)
		}
	}
	for _, forbidden := range []string{"ticket.custom_fields", "ticket.customer_custom_fields", "filtered.key", "42"} {
		if strings.Contains(predicate, forbidden) {
			t.Fatalf("typed custom-field predicate embeds or reads forbidden value %q: %q", forbidden, predicate)
		}
	}
	if len(arguments) != 6 || arguments[0] != int64(42) || arguments[1] != "alert" ||
		arguments[2] != definitionID || arguments[3] != int64(7) ||
		arguments[4] != string(customkernel.TypeInteger) || arguments[5] != "42" {
		t.Fatalf("typed custom-field predicate arguments drifted: %#v", arguments)
	}

	casePredicate, err := ticketCustomFieldFilterPredicate(kernel.AggregateCase, pin, func(any) string { return "$1" })
	if err != nil || !strings.Contains(casePredicate, "filtered.case_id = ticket.id") ||
		strings.Contains(casePredicate, "filtered.alert_id") {
		t.Fatalf("case custom-field predicate = (%q, %v)", casePredicate, err)
	}
}

func TestTicketCustomFieldTypedEqualityUsesCanonicalStorageColumns(t *testing.T) {
	referenceID := mustPostgresUUIDv7(t)
	tests := []struct {
		name      string
		dataType  customkernel.DataType
		canonical string
		contains  string
		want      any
		invalid   bool
	}{
		{name: "text", dataType: customkernel.TypeEmail, canonical: `"analyst@example.test"`, contains: "filtered.text_value", want: "analyst@example.test"},
		{name: "decimal", dataType: customkernel.TypeDecimal, canonical: "1.25", contains: "filtered.decimal_value", want: "1.25"},
		{name: "boolean", dataType: customkernel.TypeBoolean, canonical: "true", contains: "filtered.boolean_value", want: true},
		{name: "date", dataType: customkernel.TypeDate, canonical: `"2026-08-26"`, contains: "filtered.date_value", want: "2026-08-26"},
		{name: "datetime", dataType: customkernel.TypeDateTime, canonical: `"2026-08-26T10:11:12.123Z"`, contains: "filtered.date_time_value", want: time.Date(2026, 8, 26, 10, 11, 12, 123_000_000, time.UTC)},
		{name: "ip", dataType: customkernel.TypeIP, canonical: `"192.0.2.7"`, contains: "filtered.ip_value", want: "192.0.2.7"},
		{name: "cidr", dataType: customkernel.TypeCIDR, canonical: `"192.0.2.0/24"`, contains: "filtered.cidr_value", want: "192.0.2.0/24"},
		{name: "reference", dataType: customkernel.TypeAssetReference, canonical: `"` + referenceID.String() + `"`, contains: "filtered.reference_id", want: referenceID},
		{name: "single select", dataType: customkernel.TypeSingleSelect, canonical: `"malware"`, contains: "filtered.option_keys", want: "malware"},
		{name: "collection denied", dataType: customkernel.TypeMultiSelect, canonical: `[]`, invalid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arguments := make([]any, 0, 1)
			query, err := ticketCustomFieldTypedEquality(
				ticketCustomFieldFilterPin{DataType: test.dataType, Canonical: []byte(test.canonical)},
				func(value any) string { arguments = append(arguments, value); return "$1" },
			)
			if test.invalid {
				if !errors.Is(err, application.ErrInvalidInput) {
					t.Fatalf("ticketCustomFieldTypedEquality() error = %v, want invalid input", err)
				}
				return
			}
			if err != nil || !strings.Contains(query, test.contains) || len(arguments) != 1 || arguments[0] != test.want {
				t.Fatalf("ticketCustomFieldTypedEquality() = (%q, %#v, %v), want column %q and %#v", query, arguments, err, test.contains, test.want)
			}
		})
	}
}

func TestTicketListCursorFingerprintPinsCustomDefinitionAndCanonicalValue(t *testing.T) {
	tenantID, actorID := mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)
	tenant, err := ticketEntityID(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ticketEntityID(actorID)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := kernel.NewAuthorizationSnapshot(
		tenant, actor, kernel.PrincipalOperator, true, nil, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	key, err := kernel.NewKey("risk_score")
	if err != nil {
		t.Fatal(err)
	}
	value := "1.250"
	input := application.ListInput{CustomFieldKey: &key, CustomFieldValue: &value}
	access := application.LiveAccess{Authority: authority, Scopes: []application.Scope{application.ScopeTenant}}
	base := ticketCustomFieldFilterPin{
		DefinitionID:     mustPostgresUUIDv7(t),
		DefinitionDigest: sha256.Sum256([]byte("definition-v1")),
		Key:              key.String(),
		SchemaVersion:    1,
		DataType:         customkernel.TypeDecimal,
		Canonical:        []byte("1.25"),
	}
	fingerprint, err := ticketListCursorFingerprint(tenantID, kernel.AggregateAlert, input, access, []ticketCustomFieldFilterPin{base}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []ticketCustomFieldFilterPin{base, base, base, base}
	mutations[0].DefinitionID = mustPostgresUUIDv7(t)
	mutations[1].DefinitionDigest = sha256.Sum256([]byte("definition-v2"))
	mutations[2].SchemaVersion++
	mutations[3].Canonical = []byte("1.2500")
	for index := range mutations {
		got, fingerprintErr := ticketListCursorFingerprint(
			tenantID, kernel.AggregateAlert, input, access, []ticketCustomFieldFilterPin{mutations[index]}, nil,
		)
		if fingerprintErr != nil {
			t.Fatal(fingerprintErr)
		}
		if got == fingerprint {
			t.Fatalf("cursor fingerprint ignored custom-field pin mutation %d", index)
		}
	}
}

type rowFunc func(...any) error

func (scan rowFunc) Scan(destinations ...any) error { return scan(destinations...) }

func mustPostgresUUIDv7(t testing.TB) uuid.UUID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
