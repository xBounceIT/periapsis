package dfir

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func TestRetractRelationshipCommitsFreshAndReturnsExactReplayWithoutCallback(t *testing.T) {
	t.Parallel()
	for _, endpoints := range []string{"root-to-external", "ioc-to-asset"} {
		t.Run(endpoints, func(t *testing.T) {
			testCaseRelationshipRetractionReplay(t, endpoints)
		})
	}
}

func testCaseRelationshipRetractionReplay(t *testing.T, endpoints string) {
	t.Helper()
	tenantID := testUUID(170)
	tenant := testEntityIDFromUUID(t, tenantID)
	caseID := testEntityID(t, 171)
	relationshipID := testEntityID(t, 172)
	retractionID := testEntityID(t, 173)
	caseReference, err := kernel.NewEntityReference(tenant, kernel.EntityCase, caseID)
	if err != nil {
		t.Fatal(err)
	}
	externalReference, err := kernel.NewExternalEntityReference(tenant, "cloud.object", "object-1")
	if err != nil {
		t.Fatal(err)
	}
	if endpoints == "ioc-to-asset" {
		caseReference, err = kernel.NewEntityReference(tenant, kernel.EntityIOC, testEntityID(t, 176))
		if err != nil {
			t.Fatal(err)
		}
		externalReference, err = kernel.NewEntityReference(tenant, kernel.EntityAsset, testEntityID(t, 177))
		if err != nil {
			t.Fatal(err)
		}
	}
	current, err := kernel.NewRelationship(kernel.RelationshipInput{
		ID: relationshipID, TenantID: tenant, Source: caseReference, Target: externalReference,
		RelationshipType: "observed_on", CreatedBy: testEntityID(t, 174), CreatedAt: testTime(0), Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := testActor(tenantID, PrincipalHuman)
	access := Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}
	repository := &fakeRepository{
		resolveAccess: func(_ context.Context, gotActor Actor, gotTenant uuid.UUID, capability Capability, scope ResourceScope) (Access, error) {
			if gotActor != actor || gotTenant != tenantID || capability != CapabilityRelationshipManage || scope.CaseID != caseID {
				t.Fatal("relationship preflight authorization coordinates drifted")
			}
			return access, nil
		},
	}
	var committed kernel.Relationship
	applyCalls := 0
	repository.mutateRelationship = func(_ context.Context, write RelationshipMutationWrite) (MutationResult[kernel.Relationship], error) {
		if write.Command.Operation != operationRelationshipRetract || write.CaseID != caseID ||
			write.RelationshipID != relationshipID || write.RetractionID != retractionID || write.ExpectedVersion != 1 {
			t.Fatalf("relationship write coordinates = %#v", write)
		}
		applyCalls++
		updated, applyErr := write.Apply(current)
		committed = updated
		return MutationResult[kernel.Relationship]{Resource: updated}, applyErr
	}
	service := mustServiceAt(t, repository, &fakeObjectStorage{}, &fakeScanner{}, testTime(1))
	command := RelationshipRetractCommand{
		CaseID: caseID, RelationshipID: relationshipID, ExpectedVersion: 1,
		RetractionID: retractionID, Reason: "duplicate forensic link", Envelope: testEnvelope(175),
	}
	result, err := service.RetractRelationship(context.Background(), actor, tenantID, command)
	if err != nil || result.Replayed || result.Resource.Active() || result.Resource.Version() != 2 || applyCalls != 1 {
		t.Fatalf("fresh RetractRelationship() = (%#v, %v), applyCalls=%d", result, err, applyCalls)
	}

	repository.mutateRelationship = func(_ context.Context, write RelationshipMutationWrite) (MutationResult[kernel.Relationship], error) {
		return MutationResult[kernel.Relationship]{Resource: committed, Replayed: true}, nil
	}
	replayed, err := service.RetractRelationship(context.Background(), actor, tenantID, command)
	if err != nil || !replayed.Replayed ||
		!sameFingerprint(relationshipFingerprint(replayed.Resource), relationshipFingerprint(committed)) {
		t.Fatalf("replayed RetractRelationship() = (%#v, %v)", replayed, err)
	}
}

func TestRetractRelationshipMapsCASAndRejectsMalformedCoordinates(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(180)
	caseID := testEntityID(t, 181)
	actor := testActor(tenantID, PrincipalHuman)
	repository := &fakeRepository{
		resolveAccess: func(context.Context, Actor, uuid.UUID, Capability, ResourceScope) (Access, error) {
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
		mutateRelationship: func(context.Context, RelationshipMutationWrite) (MutationResult[kernel.Relationship], error) {
			return MutationResult[kernel.Relationship]{}, ErrRepositoryPrecondition
		},
	}
	service := mustServiceAt(t, repository, &fakeObjectStorage{}, &fakeScanner{}, testTime(1))
	command := RelationshipRetractCommand{
		CaseID: caseID, RelationshipID: testEntityID(t, 182), ExpectedVersion: 1,
		RetractionID: testEntityID(t, 183), Reason: "invalid relationship", Envelope: testEnvelope(184),
	}
	if _, err := service.RetractRelationship(context.Background(), actor, tenantID, command); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("CAS error = %v", err)
	}
	command.ExpectedVersion = kernel.MaximumResourceVersion
	if _, err := service.RetractRelationship(context.Background(), actor, tenantID, command); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("maximum-version error = %v", err)
	}
	command.ExpectedVersion = 1
	command.Reason = "line one\nline two"
	if _, err := service.RetractRelationship(context.Background(), actor, tenantID, command); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("multiline reason error = %v", err)
	}
}
