package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	slakernel "github.com/periapsis-im/periapsis/modules/sla"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/sla"
)

func TestSLACustomerResourceContextUsesExactCurrentContactRelationship(t *testing.T) {
	for _, objectType := range []slakernel.ObjectType{slakernel.ObjectAlert, slakernel.ObjectCase} {
		t.Run(string(objectType), func(t *testing.T) {
			tenantID := uuid.Must(uuid.NewV7())
			membershipID := uuid.Must(uuid.NewV7())
			principalID := uuid.Must(uuid.NewV7())
			objectUUID := uuid.Must(uuid.NewV7())
			objectID, err := slakernel.NewEntityID([16]byte(objectUUID))
			if err != nil {
				t.Fatal(err)
			}
			actor := application.Actor{
				TenantID: tenantID, MembershipID: membershipID, PrincipalID: principalID,
				SessionID: uuid.Must(uuid.NewV7()), AuthenticationMethod: "oidc", Kind: application.PrincipalCustomer,
			}
			tx := &slaResourceTransaction{principal: principalID}

			context, err := loadSLAResourceContext(
				context.Background(), tx, actor, tenantID,
				application.Resource{ObjectType: objectType, ObjectID: objectID}, true,
			)
			if err != nil {
				t.Fatal(err)
			}
			if context.OwnerID == nil || *context.OwnerID != principalID || context.TenantID != tenantID {
				t.Fatalf("customer resource context = %#v", context)
			}
			for _, fragment := range []string{
				"FROM public.customer_contacts AS contact",
				"JOIN public.ticket_customer_contacts AS link",
				"contact.linked_membership_id = $2",
				"contact.linked_user_id = $3",
				"link.archived_at IS NULL",
				"contact.active",
				"contact.archived_at IS NULL",
				"ticket.customer_visible",
				"HAVING count(*) = 1",
				"customer_state.visibility = 'customer'",
			} {
				if !strings.Contains(tx.query, fragment) {
					t.Fatalf("customer authorization query omitted %q:\n%s", fragment, tx.query)
				}
			}
			resourceColumn, aggregateKind := "alert_id", "alert"
			if objectType == slakernel.ObjectCase {
				resourceColumn, aggregateKind = "case_id", "case"
			}
			if !strings.Contains(tx.query, "link."+resourceColumn+" = $4") ||
				len(tx.arguments) != 5 || tx.arguments[0] != tenantID || tx.arguments[1] != membershipID ||
				tx.arguments[2] != principalID || tx.arguments[3] != objectUUID || tx.arguments[4] != aggregateKind {
				t.Fatalf("customer authorization binding drifted: query=%s args=%#v", tx.query, tx.arguments)
			}
			if strings.Contains(tx.query, "portal_ticket_is_visible") || strings.Contains(tx.query, "transitions") {
				t.Fatalf("customer authorization query used an undeclared ABI or private topology: %s", tx.query)
			}
		})
	}
}

func TestSLACustomerResourceContextCollapsesMissingAndRevokedLinks(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	principalID := uuid.Must(uuid.NewV7())
	objectUUID := uuid.Must(uuid.NewV7())
	objectID, err := slakernel.NewEntityID([16]byte(objectUUID))
	if err != nil {
		t.Fatal(err)
	}
	actor := application.Actor{
		TenantID: tenantID, MembershipID: uuid.Must(uuid.NewV7()), PrincipalID: principalID,
		SessionID: uuid.Must(uuid.NewV7()), AuthenticationMethod: "oidc", Kind: application.PrincipalCustomer,
	}
	resource := application.Resource{ObjectType: slakernel.ObjectCase, ObjectID: objectID}
	tx := &slaResourceTransaction{principal: principalID}
	if _, err := loadSLAResourceContext(context.Background(), tx, actor, tenantID, resource, true); err != nil {
		t.Fatalf("linked customer authorization failed: %v", err)
	}

	// A missing ticket and a link revoked between authority resolution and the
	// protected read both collapse to the same no-row result at this boundary.
	tx.rowErr = pgx.ErrNoRows
	for _, scenario := range []string{"missing", "revoked"} {
		if _, err := loadSLAResourceContext(context.Background(), tx, actor, tenantID, resource, true); !errors.Is(err, authorization.ErrForbidden) {
			t.Fatalf("%s customer relationship error = %v, want forbidden", scenario, err)
		}
	}
}

func TestSLAPrincipalCapabilitiesCannotCrossRouteIntents(t *testing.T) {
	tests := []struct {
		kind       application.PrincipalKind
		capability application.Capability
		want       bool
	}{
		{application.PrincipalOperator, application.CapabilityAlertRead, true},
		{application.PrincipalOperator, application.CapabilityCaseRead, true},
		{application.PrincipalOperator, application.CapabilityRead, true},
		{application.PrincipalOperator, application.CapabilityPortalAlertRead, false},
		{application.PrincipalOperator, application.CapabilityPortalCaseRead, false},
		{application.PrincipalOperator, application.Capability("future.capability"), false},
		{application.PrincipalCustomer, application.CapabilityPortalAlertRead, true},
		{application.PrincipalCustomer, application.CapabilityPortalCaseRead, true},
		{application.PrincipalCustomer, application.CapabilityAlertRead, false},
		{application.PrincipalCustomer, application.CapabilityCaseRead, false},
		{application.PrincipalCustomer, application.CapabilityManage, false},
		{application.PrincipalKind("service"), application.CapabilityPortalCaseRead, false},
	}
	for _, test := range tests {
		if got := slaPrincipalMayUseCapability(test.kind, test.capability); got != test.want {
			t.Fatalf("kind=%q capability=%q allowed=%t want=%t", test.kind, test.capability, got, test.want)
		}
	}
}

func TestSLACustomerRuntimeProjectionIsOperationShaped(t *testing.T) {
	for _, fragment := range []string{
		"WITH runtime AS MATERIALIZED",
		"app.read_sla_runtime_state_v2($1, $2, $3, $4, $5)",
		"metric_document #>> '{definition,api_visible}'",
		"metric_document #>> '{definition,customer_visible}'",
		"column_document ->> 'customer_visible'",
		"'facts', '[]'::jsonb",
		"'active_policies', '[]'::jsonb",
		"'active_calendars', '[]'::jsonb",
		"'active_columns', '[]'::jsonb",
		"'triggers', '[]'::jsonb",
		"'cursors', '[]'::jsonb",
	} {
		if !strings.Contains(readSLACustomerRuntimeStateQuery, fragment) {
			t.Fatalf("customer SLA runtime query omitted %q:\n%s", fragment, readSLACustomerRuntimeStateQuery)
		}
	}
	for _, fragment := range []string{
		"runtime.document -> 'facts'",
		"runtime.document -> 'active_policies'",
		"runtime.document -> 'active_calendars'",
		"runtime.document -> 'active_columns'",
		"metric_document -> 'triggers'",
		"metric_document -> 'cursors'",
		"metric_document -> 'last_event_id'",
		"metric_document -> 'last_override_digest'",
		"metric_document ||",
	} {
		if strings.Contains(readSLACustomerRuntimeStateQuery, fragment) {
			t.Fatalf("customer SLA runtime query selected private fragment %q:\n%s", fragment, readSLACustomerRuntimeStateQuery)
		}
	}
}

func TestSLACustomerRuntimeProjectionRejectsPrivateShapes(t *testing.T) {
	fresh := func() slaRuntimeStateDocument {
		return slaRuntimeStateDocument{
			Facts: slaFactSnapshotDocument{Facts: []slaFactValueDocument{}},
		}
	}
	if err := validateSLACustomerRuntimeDocument(fresh()); err != nil {
		t.Fatalf("empty customer runtime shape rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*slaRuntimeStateDocument)
	}{
		{
			name: "ticket facts",
			mutate: func(document *slaRuntimeStateDocument) {
				document.Facts.Facts = []slaFactValueDocument{{
					Kind: slakernel.FactSeverity, Values: []string{"private"},
				}}
			},
		},
		{
			name: "policy catalog",
			mutate: func(document *slaRuntimeStateDocument) {
				document.ActivePolicies = []slaPolicyDocument{{}}
			},
		},
		{
			name: "hidden metric",
			mutate: func(document *slaRuntimeStateDocument) {
				document.Metrics = []slaRuntimeMetricDocument{{
					Definition: slaMetricDocument{APIVisible: true},
				}}
			},
		},
		{
			name: "trigger topology",
			mutate: func(document *slaRuntimeStateDocument) {
				document.Metrics = []slaRuntimeMetricDocument{{
					Definition: slaMetricDocument{APIVisible: true, CustomerVisible: true},
					Triggers:   []slaTriggerDocument{{}},
				}}
			},
		},
		{
			name: "cursor history",
			mutate: func(document *slaRuntimeStateDocument) {
				document.Metrics = []slaRuntimeMetricDocument{{
					Definition: slaMetricDocument{APIVisible: true, CustomerVisible: true},
					Cursors:    []slaTriggerCursorDocument{{}},
				}}
			},
		},
		{
			name: "private column",
			mutate: func(document *slaRuntimeStateDocument) {
				document.Metrics = []slaRuntimeMetricDocument{{
					Definition: slaMetricDocument{APIVisible: true, CustomerVisible: true},
					Columns:    []slaColumnDocument{{CustomerVisible: false}},
				}}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := fresh()
			test.mutate(&document)
			if err := validateSLACustomerRuntimeDocument(document); err == nil {
				t.Fatal("private customer runtime shape was accepted")
			}
		})
	}
}

func TestDecodeSLACustomerRuntimeProjectionAcceptsVisibleNonContiguousMetric(t *testing.T) {
	now := time.Date(2026, 8, 26, 6, 0, 0, 0, time.UTC)
	newEntity := func() slakernel.EntityID {
		value := uuid.Must(uuid.NewV7())
		entity, err := slakernel.NewEntityID([16]byte(value))
		if err != nil {
			t.Fatal(err)
		}
		return entity
	}
	newKey := func(value string) slakernel.Key {
		key, err := slakernel.NewKey(value)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	tenantID := uuid.Must(uuid.NewV7())
	tenant, err := slakernel.NewEntityID([16]byte(tenantID))
	if err != nil {
		t.Fatal(err)
	}
	objectID, policyID, slaInstanceID := newEntity(), newEntity(), newEntity()
	metric, err := slakernel.NewMetricDefinition(slakernel.MetricDefinitionInput{
		ID: newEntity(), Key: newKey("customer_response"), Label: "Customer response",
		Description: "Customer-visible response target", Duration: 4 * time.Hour,
		Clock: slakernel.ClockElapsed, StartEvent: newKey("ticket.created"),
		CompletionEvent: newKey("ticket.responded"), ResetPolicy: slakernel.ResetIgnore,
		Warning:       slakernel.WarningThreshold{Kind: slakernel.WarningConsumedPercent, ConsumedPercent: 75},
		DisplayFormat: "duration", CustomerVisible: true, APIVisible: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	instance, err := slakernel.NewMetricInstance(slakernel.MetricInstanceInput{
		ID: newEntity(), SLAInstanceID: slaInstanceID, TenantID: tenant,
		ObjectType: slakernel.ObjectAlert, ObjectID: objectID, PolicyID: policyID,
		PolicyVersion: 1, Definition: metric, CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := instance.Snapshot()
	document := slaRuntimeStateDocument{
		Facts: slaFactSnapshotDocument{
			TenantID: tenantID, ObjectType: slakernel.ObjectAlert, ObjectID: slaUUID(objectID),
			EvaluatedAt: now, Timezone: "UTC", Facts: []slaFactValueDocument{},
		},
		PermissionEpoch: 1, SubjectEpoch: 1, OccurredAt: now,
		Aggregate: &slaAggregateDocument{
			ID: slaUUID(slaInstanceID), TenantID: tenantID, ObjectType: slakernel.ObjectAlert,
			ObjectID: slaUUID(objectID), PolicyID: slaUUID(policyID), PolicyVersion: 1,
			AggregateVersion: 1, CreatedAt: now, UpdatedAt: now,
		},
		Metrics: []slaRuntimeMetricDocument{{
			ID: slaUUID(snapshot.ID), SLAInstanceID: slaUUID(snapshot.SLAInstanceID), TenantID: tenantID,
			DefinitionID: slaUUID(snapshot.Definition.ID()), PolicyID: slaUUID(snapshot.PolicyID),
			PolicyVersion: snapshot.PolicyVersion, Version: snapshot.Version, Lifecycle: snapshot.Lifecycle,
			CreatedAt: snapshot.CreatedAt, UpdatedAt: snapshot.UpdatedAt,
			ExtensionMicros: snapshot.Extension.Microseconds(), ConsumedMicros: snapshot.Consumed.Microseconds(),
			Definition: encodeSLAMetric(metric, 7), Triggers: []slaTriggerDocument{},
			Cursors: []slaTriggerCursorDocument{}, Columns: []slaColumnDocument{},
		}},
	}
	raw, err := marshalSLADocument(document)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeSLACustomerRuntimeState(
		tenantID, application.Resource{ObjectType: slakernel.ObjectAlert, ObjectID: objectID}, raw,
	)
	if err != nil || len(decoded.Metrics) != 1 || decoded.Metrics[0].Instance.ID() != snapshot.ID {
		t.Fatalf("decoded customer runtime=%#v error=%v", decoded, err)
	}
}

func TestSLACustomerRuntimeReaderRejectsOperatorCapabilityBeforeSQL(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	objectUUID := uuid.Must(uuid.NewV7())
	objectID, err := slakernel.NewEntityID([16]byte(objectUUID))
	if err != nil {
		t.Fatal(err)
	}
	_, err = readSLACustomerRuntimeState(
		context.Background(), nil, tenantID,
		application.Resource{ObjectType: slakernel.ObjectAlert, ObjectID: objectID},
		application.CapabilityAlertRead, time.Now().UTC(),
	)
	if !errors.Is(err, application.ErrRepositoryForbidden) {
		t.Fatalf("operator capability on customer runtime reader = %v, want forbidden", err)
	}
}

type slaResourceTransaction struct {
	recordingTransaction
	query     string
	arguments []any
	principal uuid.UUID
	rowErr    error
}

func (tx *slaResourceTransaction) QueryRow(_ context.Context, query string, arguments ...any) pgx.Row {
	tx.query = query
	tx.arguments = arguments
	return slaResourceRow(func(destinations ...any) error {
		if tx.rowErr != nil {
			return tx.rowErr
		}
		if len(destinations) != 1 {
			return errors.New("unexpected SLA customer resource projection")
		}
		*destinations[0].(*uuid.UUID) = tx.principal
		return nil
	})
}

type slaResourceRow func(...any) error

func (row slaResourceRow) Scan(destinations ...any) error { return row(destinations...) }
