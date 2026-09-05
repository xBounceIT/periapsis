package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func TestDFIRAlertAccessIsOperatorOnlyLiveAndCapabilityBound(t *testing.T) {
	t.Parallel()
	tenantID := alertTestUUID(1)
	alertID := alertTestUUID(2)
	userID := alertTestUUID(3)
	membershipID := alertTestUUID(4)
	actor := application.Actor{
		TenantID: tenantID, ActiveTenantID: tenantID, UserID: userID,
		MembershipID: membershipID, SessionID: alertTestUUID(5),
		AuthenticationMethod: "oidc", Kind: application.PrincipalHuman,
	}
	authority := authorization.TenantAuthority{
		TenantID: tenantID, MembershipID: membershipID,
		MembershipStatus: authorization.MembershipStatusActive,
		Principal:        authorization.TenantPrincipal{ID: userID, Kind: authorization.PrincipalKindHuman},
		Permissions: []authorization.ScopedPermission{
			{Permission: authorization.TenantPermissionDFIRIOCRead, Scope: authorization.ScopeTenant},
			{Permission: authorization.TenantPermissionDFIREvidenceRead, Scope: authorization.ScopeTenant},
		},
	}
	queries := 0
	tx := &dfirTransactionStub{row: func(query string, arguments []any, destinations []any) error {
		queries++
		if !strings.Contains(query, "FROM public.alerts AS alert") || !strings.Contains(query, "alert.deleted_at IS NULL") ||
			len(arguments) != 2 || arguments[0] != tenantID || arguments[1] != alertID || len(destinations) != 4 {
			return errors.New("Alert access query was not tenant/root/live bound")
		}
		*(destinations[0].(**uuid.UUID)) = nil
		*(destinations[1].(**uuid.UUID)) = nil
		*(destinations[2].(**uuid.UUID)) = nil
		*(destinations[3].(**uuid.UUID)) = nil
		return nil
	}}
	access, err := dfirAccessForAlert(context.Background(), tx, authority, actor, application.CapabilityIOCRead, alertID)
	if err != nil || access != (application.Access{Audience: kernel.AudienceOperator, Scope: application.ScopeTenant}) || queries != 1 {
		t.Fatalf("Alert access = (%#v, %v), queries=%d", access, err, queries)
	}
	access, err = dfirAccessForAlert(context.Background(), tx, authority, actor, application.CapabilityEvidenceRead, alertID)
	if err != nil || access != (application.Access{Audience: kernel.AudienceOperator, Scope: application.ScopeTenant}) || queries != 2 {
		t.Fatalf("Alert evidence access = (%#v, %v), queries=%d", access, err, queries)
	}
	actor.Kind = application.PrincipalCustomer
	if _, err := dfirAccessForAlert(context.Background(), tx, authority, actor, application.CapabilityIOCRead, alertID); !errors.Is(err, authorization.ErrForbidden) || queries != 2 {
		t.Fatalf("customer Alert access = (%v, queries=%d)", err, queries)
	}
	tx.row = func(string, []any, []any) error { return pgx.ErrNoRows }
	actor.Kind = application.PrincipalHuman
	if _, err := dfirAccessForAlert(context.Background(), tx, authority, actor, application.CapabilityIOCRead, alertID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("deleted/missing Alert access error = %v", err)
	}
}

func TestResolveDFIRAlertSubjectUsesOnlyDirectUnarchivedLinks(t *testing.T) {
	t.Parallel()
	tenantID, alertID, iocID := alertTestUUID(10), alertTestUUID(11), alertTestUUID(12)
	subject, err := kernel.NewEntityReference(entityID(tenantID), kernel.EntityIOC, entityID(iocID))
	if err != nil {
		t.Fatal(err)
	}
	linked := true
	tx := &dfirTransactionStub{row: func(query string, arguments []any, destinations []any) error {
		if !strings.Contains(query, "FROM public.dfir_ioc_links AS link") ||
			!strings.Contains(query, "JOIN public.dfir_iocs AS resource") ||
			!strings.Contains(query, "resource.archived_at IS NULL") ||
			strings.Contains(query, "alert_case_links") || len(arguments) != 3 ||
			arguments[0] != tenantID || arguments[1] != alertID || arguments[2] != iocID {
			return errors.New("Alert subject resolution was not a direct unarchived link lookup")
		}
		*(destinations[0].(*bool)) = linked
		return nil
	}}
	visibility, err := resolveDFIRAlertSubject(context.Background(), tx, tenantID, alertID, subject)
	if err != nil || visibility != kernel.VisibilityPrivate {
		t.Fatalf("direct Alert IOC subject = (%q, %v)", visibility, err)
	}
	linked = false
	if _, err := resolveDFIRAlertSubject(context.Background(), tx, tenantID, alertID, subject); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("unlinked Alert IOC error = %v", err)
	}
	caseSubject, err := kernel.NewEntityReference(entityID(tenantID), kernel.EntityCase, alertTestEntityID(13))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolveDFIRAlertSubject(context.Background(), tx, tenantID, alertID, caseSubject); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("Case subject on Alert error = %v", err)
	}
}

func TestAlertDFIRReservationAndEffectsUseExactABIAndRedactedJournal(t *testing.T) {
	t.Parallel()
	tenantID, alertID, commandID, resourceID := alertTestUUID(19), alertTestUUID(20), alertTestUUID(21), alertTestUUID(22)
	keyDigest := sha256.Sum256([]byte("key"))
	requestDigest := sha256.Sum256([]byte("request"))
	binding := application.CommandBinding{
		Operation: "dfir.ioc.replace", KeyDigest: keyDigest, RequestDigest: requestDigest,
	}
	coordinate := dfirMutationCoordinate{
		tenantID: tenantID, rootKind: dfirMutationRootAlert, rootID: alertID,
		operation: binding.Operation, resourceKind: dfirMutationKindIOC,
		resourceID: resourceID, resultVersion: 4,
	}
	replaySnapshot := []byte(`{"snapshot":"stored"}`)
	tx := &dfirTransactionStub{row: func(query string, arguments []any, destinations []any) error {
		if !strings.Contains(query, "app.reserve_dfir_mutation_command_v1") || len(arguments) != 10 ||
			arguments[0] != commandID || arguments[1] != dfirMutationRootAlert || arguments[2] != alertID ||
			arguments[3] != binding.Operation || arguments[4] != dfirMutationKindIOC ||
			arguments[5] != resourceID || arguments[6] != (*uuid.UUID)(nil) || arguments[7] != int64(4) ||
			!equalAlertTestBytes(arguments[8], keyDigest[:]) || !equalAlertTestBytes(arguments[9], requestDigest[:]) {
			return errors.New("Alert reservation ABI drifted")
		}
		*(destinations[0].(*uuid.UUID)) = commandID
		*(destinations[1].(*uuid.UUID)) = resourceID
		*(destinations[2].(**uuid.UUID)) = nil
		*(destinations[3].(*int64)) = 4
		*(destinations[4].(*[]byte)) = replaySnapshot
		*(destinations[5].(*bool)) = true
		return nil
	}}
	reservation, err := reserveDFIRMutationCommand(context.Background(), tx, commandID, coordinate, binding)
	if err != nil || !reservation.replayed || !bytes.Equal(reservation.snapshot, replaySnapshot) {
		t.Fatalf("reserve Alert resource = (replayed=%t, snapshot=%q, %v)", reservation.replayed, reservation.snapshot, err)
	}

	indicator, err := kernel.NewIndicator(kernel.IndicatorInput{
		ID: entityID(resourceID), TenantID: alertTestEntityID(23), Type: kernel.IndicatorDomain,
		Value: "secret-observable.example", Source: "analyst", Confidence: 80,
		TLP: kernel.TLPAmber, FirstSeen: alertTestTime(0), LastSeen: alertTestTime(1),
		Malicious: kernel.MaliciousSuspicious,
	})
	if err != nil {
		t.Fatal(err)
	}
	base := application.BaseWrite{
		Actor:   application.Actor{MembershipID: alertTestUUID(24), AuthenticationMethod: "oidc"},
		Command: binding,
		Audit: application.AuditContext{
			RequestID: alertTestUUID(25), CorrelationID: alertTestUUID(26),
			IPAddress: netip.MustParseAddr("192.0.2.25"), UserAgent: "alert-dfir-test",
		},
	}
	tx.exec = func(query string, arguments []any) (pgconn.CommandTag, error) {
		if !strings.Contains(query, "app.append_alert_dfir_mutation_effects_v1") || len(arguments) != 20 ||
			arguments[0] != alertID || arguments[1] != "dfir.ioc.manage" ||
			arguments[2] != "dfir.ioc.replaced" || arguments[3] != "dfir_ioc" ||
			arguments[4] != resourceID || arguments[5] != int64(4) || arguments[6] != binding.Operation {
			return pgconn.CommandTag{}, errors.New("Alert mutation effects ABI drifted")
		}
		for _, index := range []int{10, 11, 12} {
			encoded, ok := arguments[index].([]byte)
			if !ok || strings.Contains(string(encoded), "secret-observable.example") {
				return pgconn.CommandTag{}, errors.New("Alert journal leaked an observable")
			}
		}
		return pgconn.NewCommandTag("SELECT 1"), nil
	}
	err = appendAlertDFIRMutationEffects(context.Background(), tx, base, alertID, alertDFIRMutationEffect{
		PermissionKey: "dfir.ioc.manage", Action: "dfir.ioc.replaced", ResourceType: "dfir_ioc",
		ResourceID: resourceID, ResourceVersion: 4, ActivityID: alertTestUUID(27),
		Before: dfirIndicatorJournal(indicator, 3), After: dfirIndicatorJournal(indicator, 4),
		Metadata: map[string]any{"rootKind": "alert"}, AuditEventID: alertTestUUID(28), OutboxEventID: alertTestUUID(29),
	})
	if err != nil {
		t.Fatal(err)
	}

	tx.row = func(string, []any, []any) error {
		return &pgconn.PgError{Code: "23505", ConstraintName: "dfir_mutation_commands_replay_key"}
	}
	_, err = reserveDFIRMutationCommand(context.Background(), tx, commandID, coordinate, binding)
	if !errors.Is(mapDFIRDatabaseError(err), application.ErrRepositoryConflict) {
		t.Fatalf("idempotency payload mismatch error = %v", err)
	}
}

func TestAlertDFIRStaleCASAndAttachmentPurposeMismatchFailClosed(t *testing.T) {
	t.Parallel()
	tenantID, alertID := alertTestUUID(30), alertTestUUID(31)
	indicator, err := kernel.NewIndicator(kernel.IndicatorInput{
		ID: alertTestEntityID(32), TenantID: entityID(tenantID), Type: kernel.IndicatorDomain,
		Value: "example.com", Source: "analyst", Confidence: 80, TLP: kernel.TLPAmber,
		FirstSeen: alertTestTime(0), LastSeen: alertTestTime(1), Malicious: kernel.MaliciousSuspicious,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx := &dfirTransactionStub{exec: func(query string, arguments []any) (pgconn.CommandTag, error) {
		if !strings.Contains(query, "WHERE tenant_id = $1 AND id = $2 AND version = $3") ||
			len(arguments) != 17 || arguments[0] != tenantID || arguments[1] != uuid.UUID(indicator.ID().Bytes()) || arguments[2] != int64(3) {
			return pgconn.CommandTag{}, errors.New("IOC CAS update was not exact")
		}
		return pgconn.NewCommandTag("UPDATE 0"), nil
	}}
	if err := updateDFIRIndicator(context.Background(), tx, application.IndicatorWrite{
		BaseWrite: application.BaseWrite{Actor: application.Actor{MembershipID: alertTestUUID(33)}},
		Indicator: indicator, ExpectedVersion: 3,
	}); !errors.Is(err, application.ErrRepositoryPrecondition) {
		t.Fatalf("stale Alert IOC CAS error = %v", err)
	}

	attachmentID, storageID := alertTestUUID(34), alertTestUUID(35)
	tx.row = func(query string, arguments []any, destinations []any) error {
		if !strings.Contains(query, "id = $2 AND storage_object_id = $3") || len(arguments) != 3 ||
			arguments[0] != tenantID || arguments[1] != attachmentID || arguments[2] != storageID {
			return errors.New("attachment purpose lookup was not exact")
		}
		*(destinations[0].(*uuid.UUID)) = alertTestUUID(36)
		return nil
	}
	if _, err := loadExactDFIRAlertStorageObject(
		context.Background(), tx, tenantID, alertID, attachmentID, storageID,
	); err == nil || !strings.Contains(err.Error(), "purpose mismatch") {
		t.Fatalf("attachment/storage purpose mismatch error = %v", err)
	}
}

func TestAlertDFIRWorkspaceIDsAreHardBoundedAndCancellationPropagates(t *testing.T) {
	t.Parallel()
	tenantID, alertID := alertTestUUID(40), alertTestUUID(41)
	values := make([][]any, 501)
	for index := range values {
		id, err := uuid.NewV7()
		if err != nil {
			t.Fatal(err)
		}
		values[index] = []any{id}
	}
	tx := &dfirTransactionStub{query: func(_ string, arguments []any) (pgx.Rows, error) {
		if len(arguments) != 3 || arguments[0] != tenantID || arguments[1] != alertID || arguments[2] != 501 {
			return nil, errors.New("workspace query did not request the one-row overflow sentinel")
		}
		return &dfirRowsStub{rows: values}, nil
	}}
	if _, err := queryBoundedDFIRIDs(
		context.Background(), tx, "SELECT id FROM direct_alert_resources LIMIT $3", tenantID, alertID, 500,
	); err == nil || !strings.Contains(err.Error(), "bound exceeded") {
		t.Fatalf("501-row Alert projection error = %v", err)
	}
	tx.query = func(string, []any) (pgx.Rows, error) { return nil, context.Canceled }
	if _, err := queryBoundedDFIRIDs(
		context.Background(), tx, "SELECT id FROM direct_alert_resources LIMIT $3", tenantID, alertID, 500,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Alert projection error = %v", err)
	}
}

func TestAlertTimelineReplayIgnoresOnlyServerIngestionTime(t *testing.T) {
	t.Parallel()
	input := kernel.TimelineEventInput{
		ID: alertTestEntityID(50), TenantID: alertTestEntityID(51), AlertID: alertTestEntityID(52),
		EventTime: alertTestTime(0), IngestedAt: alertTestTime(1), OriginalTimezone: "UTC",
		Precision: kernel.PrecisionSecond, Source: "sensor", Category: "network_event", Title: "Observed event",
	}
	first, err := kernel.NewTimelineEvent(input)
	if err != nil {
		t.Fatal(err)
	}
	input.IngestedAt = alertTestTime(2)
	second, err := kernel.NewTimelineEvent(input)
	if err != nil {
		t.Fatal(err)
	}
	if sameDFIRTimelineEvent(first, second) || !sameDFIRTimelineRequest(first, second) {
		t.Fatal("timeline replay did not isolate its server-generated ingestion time")
	}
	input.Title = "Different event"
	different, err := kernel.NewTimelineEvent(input)
	if err != nil {
		t.Fatal(err)
	}
	if sameDFIRTimelineRequest(first, different) {
		t.Fatal("timeline replay accepted a changed client payload")
	}
}

func TestValidateAlertTimelineLinksRequiresDirectUnarchivedResources(t *testing.T) {
	t.Parallel()
	tenantID, alertID := alertTestUUID(55), alertTestUUID(56)
	iocID, assetID := alertTestEntityID(57), alertTestEntityID(58)
	event, err := kernel.NewTimelineEvent(kernel.TimelineEventInput{
		ID: alertTestEntityID(59), TenantID: entityID(tenantID), AlertID: entityID(alertID),
		EventTime: alertTestTime(0), IngestedAt: alertTestTime(1), OriginalTimezone: "UTC",
		Precision: kernel.PrecisionSecond, Source: "sensor", Category: "network_event", Title: "Observed event",
		IOCIDs: []kernel.EntityID{iocID}, AssetIDs: []kernel.EntityID{assetID},
	})
	if err != nil {
		t.Fatal(err)
	}
	queries := 0
	tx := &dfirTransactionStub{row: func(query string, arguments []any, destinations []any) error {
		queries++
		resourceTable, column, expectedID := "public.dfir_iocs", "ioc_id", uuid.UUID(iocID.Bytes())
		if queries == 2 {
			resourceTable, column, expectedID = "public.dfir_assets", "asset_id", uuid.UUID(assetID.Bytes())
		}
		ids, ok := arguments[2].([]uuid.UUID)
		if !strings.Contains(query, "JOIN "+resourceTable+" AS resource") ||
			!strings.Contains(query, "resource.archived_at IS NULL") ||
			!strings.Contains(query, "link."+column+" = ANY($3::uuid[])") ||
			len(arguments) != 3 || arguments[0] != tenantID || arguments[1] != alertID ||
			!ok || len(ids) != 1 || ids[0] != expectedID {
			return errors.New("Alert timeline link validation was not direct and archive-safe")
		}
		*(destinations[0].(*int64)) = 1
		return nil
	}}
	if err := validateAlertTimelineLinks(context.Background(), tx, tenantID, alertID, event); err != nil || queries != 2 {
		t.Fatalf("direct live timeline links = (%v, queries=%d)", err, queries)
	}
	tx.row = func(_ string, _ []any, destinations []any) error {
		*(destinations[0].(*int64)) = 0
		return nil
	}
	if err := validateAlertTimelineLinks(context.Background(), tx, tenantID, alertID, event); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("missing timeline link error = %v", err)
	}
}

func TestValidateCaseTimelineLinksRequiresDirectLiveResources(t *testing.T) {
	t.Parallel()
	tenantID, caseID := alertTestUUID(60), alertTestUUID(61)
	iocID, assetID, evidenceID := alertTestEntityID(62), alertTestEntityID(63), alertTestEntityID(64)
	event, err := kernel.NewTimelineEvent(kernel.TimelineEventInput{
		ID: alertTestEntityID(65), TenantID: entityID(tenantID), CaseID: entityID(caseID),
		EventTime: alertTestTime(0), IngestedAt: alertTestTime(1), OriginalTimezone: "UTC",
		Precision: kernel.PrecisionSecond, Source: "sensor", Category: "network_event", Title: "Observed event",
		IOCIDs: []kernel.EntityID{iocID}, AssetIDs: []kernel.EntityID{assetID}, EvidenceIDs: []kernel.EntityID{evidenceID},
	})
	if err != nil {
		t.Fatal(err)
	}
	queries := 0
	tx := &dfirTransactionStub{row: func(query string, arguments []any, destinations []any) error {
		queries++
		if len(arguments) != 3 || arguments[0] != tenantID || arguments[1] != caseID ||
			!strings.Contains(query, "alert_id IS NULL") {
			return errors.New("Case timeline lookup was not directly root-bound")
		}
		if queries <= 2 {
			resourceTable, column := "public.dfir_iocs", "ioc_id"
			if queries == 2 {
				resourceTable, column = "public.dfir_assets", "asset_id"
			}
			if !strings.Contains(query, "JOIN "+resourceTable+" AS resource") ||
				!strings.Contains(query, "resource.archived_at IS NULL") ||
				!strings.Contains(query, "link."+column+" = ANY($3::uuid[])") {
				return errors.New("Case timeline inventory lookup was not live and direct")
			}
		} else if !strings.Contains(query, "evidence.destroyed = false") ||
			!strings.Contains(query, "evidence.scan_state <> 'deleted'") {
			return errors.New("Case timeline evidence lookup was not live")
		}
		*(destinations[0].(*int64)) = 1
		return nil
	}}
	if err := validateCaseTimelineLinks(context.Background(), tx, tenantID, caseID, event); err != nil || queries != 3 {
		t.Fatalf("direct live Case timeline links = (%v, queries=%d)", err, queries)
	}
	tx.row = func(_ string, _ []any, destinations []any) error {
		*(destinations[0].(*int64)) = 0
		return nil
	}
	if err := validateCaseTimelineLinks(context.Background(), tx, tenantID, caseID, event); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("missing Case timeline link error = %v", err)
	}
}

func TestValidateDFIRRelationshipResourceEndpointIsRootAndLivenessBound(t *testing.T) {
	t.Parallel()
	tenantID, rootID, resourceID := alertTestUUID(66), alertTestUUID(67), alertTestUUID(68)
	for _, test := range []struct {
		name     string
		rootKind string
		kind     kernel.EntityKind
		required []string
	}{
		{name: "Case IOC", rootKind: dfirMutationRootCase, kind: kernel.EntityIOC, required: []string{"link.case_id = $3", "link.alert_id IS NULL", "resource.archived_at IS NULL"}},
		{name: "Alert asset", rootKind: dfirMutationRootAlert, kind: kernel.EntityAsset, required: []string{"link.alert_id = $3", "link.case_id IS NULL", "resource.archived_at IS NULL"}},
		{name: "Case evidence", rootKind: dfirMutationRootCase, kind: kernel.EntityEvidence, required: []string{"resource.case_id = $3", "resource.destroyed = false", "resource.scan_state <> 'deleted'"}},
		{name: "Alert task", rootKind: dfirMutationRootAlert, kind: kernel.EntityTask, required: []string{"resource.alert_id = $3", "resource.case_id IS NULL"}},
		{name: "Case attachment", rootKind: dfirMutationRootCase, kind: kernel.EntityAttachment, required: []string{"app.dfir_attachment_belongs_to_root_v1($1, $2, $3, $5)"}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			tx := &dfirTransactionStub{row: func(query string, arguments []any, destinations []any) error {
				if len(arguments) != 5 || arguments[0] != tenantID || arguments[1] != test.rootKind ||
					arguments[2] != rootID || arguments[3] != string(test.kind) || arguments[4] != resourceID {
					return errors.New("relationship endpoint query coordinates drifted")
				}
				for _, fragment := range test.required {
					if !strings.Contains(query, fragment) {
						return errors.New("relationship endpoint liveness predicate is missing")
					}
				}
				*(destinations[0].(*bool)) = true
				return nil
			}}
			valid, err := validateDFIRRelationshipResourceEndpoint(
				context.Background(), tx, tenantID, test.rootKind, rootID, test.kind, resourceID,
			)
			if err != nil || !valid {
				t.Fatalf("validate endpoint = (%t, %v)", valid, err)
			}
		})
	}
}

func TestValidateDFIRRelationshipEndpointsAcceptsExternalButRejectsCrossTenant(t *testing.T) {
	t.Parallel()
	tenantID, otherTenantID, caseID := alertTestEntityID(69), alertTestEntityID(70), alertTestEntityID(71)
	external, err := kernel.NewExternalEntityReference(tenantID, "host", "external-asset")
	if err != nil {
		t.Fatal(err)
	}
	root, err := kernel.NewEntityReference(tenantID, kernel.EntityCase, caseID)
	if err != nil {
		t.Fatal(err)
	}
	actor := application.Actor{TenantID: uuid.UUID(tenantID.Bytes()), Kind: application.PrincipalHuman}
	if err := validateDFIRRelationshipEndpoints(
		context.Background(), &dfirTransactionStub{}, actor, actor.TenantID,
		dfirMutationRootCase, uuid.UUID(caseID.Bytes()), root, external,
	); err != nil {
		t.Fatalf("root plus external endpoint = %v", err)
	}
	crossTenant, err := kernel.NewExternalEntityReference(otherTenantID, "host", "external-asset")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDFIRRelationshipEndpoints(
		context.Background(), &dfirTransactionStub{}, actor, actor.TenantID,
		dfirMutationRootCase, uuid.UUID(caseID.Bytes()), root, crossTenant,
	); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("cross-tenant endpoint error = %v", err)
	}
}

func TestValidateDFIRRelationshipEndpointsRejectsResourceOutsidePathRoot(t *testing.T) {
	t.Parallel()
	tenantID, caseID, taskID := alertTestEntityID(72), alertTestEntityID(73), alertTestEntityID(74)
	root, err := kernel.NewEntityReference(tenantID, kernel.EntityCase, caseID)
	if err != nil {
		t.Fatal(err)
	}
	task, err := kernel.NewEntityReference(tenantID, kernel.EntityTask, taskID)
	if err != nil {
		t.Fatal(err)
	}
	queries := 0
	tx := &dfirTransactionStub{row: func(query string, arguments []any, destinations []any) error {
		queries++
		if len(arguments) != 5 || arguments[0] != uuid.UUID(tenantID.Bytes()) ||
			arguments[1] != dfirMutationRootCase || arguments[2] != uuid.UUID(caseID.Bytes()) ||
			arguments[3] != string(kernel.EntityTask) || arguments[4] != uuid.UUID(taskID.Bytes()) ||
			!strings.Contains(query, "resource.case_id = $3") ||
			!strings.Contains(query, "resource.alert_id IS NULL") {
			return errors.New("relationship task endpoint lost its exact path-root binding")
		}
		*(destinations[0].(*bool)) = false
		return nil
	}}
	actor := application.Actor{
		TenantID: uuid.UUID(tenantID.Bytes()), Kind: application.PrincipalHuman,
	}
	if err = validateDFIRRelationshipEndpoints(
		context.Background(), tx, actor, actor.TenantID,
		dfirMutationRootCase, uuid.UUID(caseID.Bytes()), root, task,
	); !errors.Is(err, authorization.ErrForbidden) || queries != 1 {
		t.Fatalf("unassociated task endpoint = (%v, queries=%d)", err, queries)
	}
}

func alertTestUUID(seed byte) uuid.UUID {
	return uuid.UUID{0x01, 0x9d, 0x02, 0x00, 0, seed, 0x70, seed, 0x80, seed, 0, 0, 0, 0, 0, seed}
}

func alertTestEntityID(seed byte) kernel.EntityID { return entityID(alertTestUUID(seed)) }

func alertTestTime(offset int) time.Time {
	return time.Date(2026, 8, 30, 12, 0, offset, 0, time.UTC)
}

func equalAlertTestBytes(value any, expected []byte) bool {
	actual, ok := value.([]byte)
	if !ok || len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}
