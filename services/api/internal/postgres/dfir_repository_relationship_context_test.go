package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func TestCaseRelationshipRetractionUsesExplicitRootNotEitherEndpoint(t *testing.T) {
	t.Parallel()
	for _, sourceKind := range []kernel.EntityKind{kernel.EntityIOC, kernel.EntityCase} {
		t.Run(string(sourceKind), func(t *testing.T) {
			relationship := relationshipContextFixture(t, sourceKind)
			rootID, commandID := alertTestUUID(180), alertTestUUID(181)
			retracted, err := relationship.Retract(1, kernel.RelationshipRetractionInput{
				ID: alertTestEntityID(182), ActorID: alertTestEntityID(183),
				Reason: "association disproved", OccurredAt: relationship.CreatedAt().Add(time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			tx := &dfirTransactionStub{row: func(query string, args []any, destinations []any) error {
				calls++
				if !strings.Contains(query, "app.retract_case_dfir_relationship_v1") || len(args) != 7 ||
					args[0] != commandID || args[1] != uuid.UUID(relationship.ID().Bytes()) ||
					args[2] != rootID || args[3] != int64(1) || args[4] != alertTestUUID(182) {
					return errors.New("retraction inferred ownership from an endpoint")
				}
				*(destinations[0].(*uuid.UUID)) = uuid.UUID(relationship.ID().Bytes())
				*(destinations[1].(*int64)) = 2
				return nil
			}}
			if err := retractCaseRelationship(context.Background(), tx, commandID, rootID, retracted, retracted.Retractions()[0], 1); err != nil || calls != 1 {
				t.Fatalf("explicit-root retraction = (%v, calls=%d)", err, calls)
			}
		})
	}
}

func TestChildRelationshipReceiptIsBoundToIndependentCaseCoordinate(t *testing.T) {
	t.Parallel()
	relationship := relationshipContextFixture(t, kernel.EntityIOC)
	coordinate := dfirMutationCoordinate{
		tenantID: uuid.UUID(relationship.TenantID().Bytes()), rootKind: dfirMutationRootCase,
		rootID: alertTestUUID(180), operation: "dfir.relationship.create",
		resourceKind: dfirMutationKindRelationship, resourceID: uuid.UUID(relationship.ID().Bytes()), resultVersion: 1,
	}
	document, err := encodeDFIRRelationshipResult(coordinate, relationship)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := decodeDFIRRelationshipResult(document, coordinate)
	if err != nil || !sameDFIRRelationship(restored, relationship) {
		t.Fatalf("child relationship receipt = (%v, %v)", restored, err)
	}
	for _, mutate := range []func(*dfirMutationCoordinate){
		func(value *dfirMutationCoordinate) { value.rootID = alertTestUUID(181) },
		func(value *dfirMutationCoordinate) { value.tenantID = alertTestUUID(182) },
		func(value *dfirMutationCoordinate) { value.rootKind = dfirMutationRootAlert },
		func(value *dfirMutationCoordinate) { value.resourceID = alertTestUUID(183) },
	} {
		wrong := coordinate
		mutate(&wrong)
		if _, err := decodeDFIRRelationshipResult(document, wrong); err == nil {
			t.Fatal("receipt accepted a different tenant/root/resource coordinate")
		}
	}
}

func TestChildRelationshipValidatesBothLiveEndpointsAgainstPathRoot(t *testing.T) {
	t.Parallel()
	relationship := relationshipContextFixture(t, kernel.EntityIOC)
	tenantID, rootID := uuid.UUID(relationship.TenantID().Bytes()), alertTestUUID(180)
	for _, rootKind := range []string{dfirMutationRootCase, dfirMutationRootAlert} {
		for _, missing := range []int{-1, 0, 1} {
			calls := 0
			references := []kernel.EntityReference{relationship.Source(), relationship.Target()}
			tx := &dfirTransactionStub{row: func(query string, args []any, destinations []any) error {
				if calls >= len(references) || len(args) != 5 || args[0] != tenantID || args[1] != rootKind || args[2] != rootID ||
					args[3] != string(references[calls].Kind()) || args[4] != uuid.UUID(references[calls].ID().Bytes()) ||
					!strings.Contains(query, "resource.archived_at IS NULL") {
					return errors.New("child endpoint validation lost root or live-resource identity")
				}
				*(destinations[0].(*bool)) = calls != missing
				calls++
				return nil
			}}
			err := validateDFIRRelationshipEndpoints(context.Background(), tx, application.Actor{TenantID: tenantID}, tenantID, rootKind, rootID, references...)
			if missing == -1 {
				if err != nil || calls != 2 {
					t.Fatalf("%s child endpoints = (%v, calls=%d)", rootKind, err, calls)
				}
			} else if !errors.Is(err, authorization.ErrForbidden) || calls != missing+1 {
				t.Fatalf("%s missing child %d = (%v, calls=%d)", rootKind, missing, err, calls)
			}
		}
	}
}

func TestCaseWorkspaceSelectsRelationshipByPersistedRoot(t *testing.T) {
	t.Parallel()
	tenantID, caseID := alertTestUUID(190), alertTestUUID(191)
	checked := false
	tx := &dfirTransactionStub{query: func(query string, args []any) (pgx.Rows, error) {
		if strings.Contains(query, "FROM public.dfir_relationships") {
			checked = true
			if len(args) != 3 || args[0] != tenantID || args[1] != caseID ||
				!strings.Contains(query, "case_id = $2 AND alert_id IS NULL") ||
				strings.Contains(query, "source_kind") || strings.Contains(query, "target_kind") {
				return nil, errors.New("workspace relationship selection inferred ownership from an endpoint")
			}
		}
		return &dfirRowsStub{}, nil
	}}
	if _, err := loadDFIRWorkspace(context.Background(), tx, tenantID, caseID, false); err != nil || !checked {
		t.Fatalf("relationship workspace selection = (%v, checked=%t)", err, checked)
	}
}

func relationshipContextFixture(t *testing.T, sourceKind kernel.EntityKind) kernel.Relationship {
	t.Helper()
	tenant := alertTestEntityID(170)
	source, err := kernel.NewEntityReference(tenant, sourceKind, alertTestEntityID(171))
	if err != nil {
		t.Fatal(err)
	}
	target, err := kernel.NewEntityReference(tenant, kernel.EntityAsset, alertTestEntityID(172))
	if err != nil {
		t.Fatal(err)
	}
	relationship, err := kernel.NewRelationship(kernel.RelationshipInput{
		ID: alertTestEntityID(173), TenantID: tenant, Source: source, Target: target,
		RelationshipType: "observed_on", CreatedBy: alertTestEntityID(174), CreatedAt: alertTestTime(0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return relationship
}
