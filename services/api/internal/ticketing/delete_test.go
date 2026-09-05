package ticketing

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDeleteAlertUsesLiveDeleteScopeAndReturnsTombstone(t *testing.T) {
	fixture := newServiceFixture(t)
	deletedAt := time.Date(2026, 8, 25, 10, 0, 1, 0, time.UTC)
	repository := &fakeRepository{fixture: fixture, record: fixture.record}
	expected := fixture.record.Snapshot.Version()
	repository.deleteReceipt = DeleteAlertReceipt{
		TenantID: fixture.tenantUUID, AlertID: fixture.ticketUUID,
		PreviousVersion: expected, TombstoneVersion: expected + 1, DeletedAt: deletedAt,
	}
	service := mustService(t, repository)
	receipt, err := service.DeleteAlert(context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, DeleteAlertInput{
		ExpectedVersion: expected, Reason: "Duplicate telemetry confirmed by the incident lead.",
		IdempotencyKey: "delete-alert-request-0001",
	})
	if err != nil {
		t.Fatalf("DeleteAlert returned error: %v", err)
	}
	if receipt != repository.deleteReceipt || repository.deleteCalls.Load() != 1 {
		t.Fatalf("receipt=%+v delete calls=%d", receipt, repository.deleteCalls.Load())
	}
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	if len(repository.accessCalls) != 1 || repository.accessCalls[0] != CapabilityAlertDelete ||
		repository.deleteWrite.Current.Snapshot.ID() != fixture.record.Snapshot.ID() ||
		repository.deleteWrite.KeyHash == ([32]byte{}) || repository.deleteWrite.Fingerprint == ([32]byte{}) {
		t.Fatalf("unexpected delete write/access: calls=%v write=%+v", repository.accessCalls, repository.deleteWrite)
	}
}

func TestDeleteAlertExactReplayDoesNotReloadTombstonedAlert(t *testing.T) {
	fixture := newServiceFixture(t)
	expected := fixture.record.Snapshot.Version()
	repository := &fakeRepository{fixture: fixture, deleteReplayFound: true}
	repository.deleteReplay = DeleteAlertReceipt{
		TenantID: fixture.tenantUUID, AlertID: fixture.ticketUUID,
		PreviousVersion: expected, TombstoneVersion: expected + 1,
		DeletedAt: time.Date(2026, 8, 25, 10, 0, 1, 0, time.UTC), Replayed: true,
	}
	receipt, err := mustService(t, repository).DeleteAlert(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID,
		DeleteAlertInput{ExpectedVersion: expected, Reason: "Duplicate.", IdempotencyKey: "delete-alert-request-0002"},
	)
	if err != nil || !receipt.Replayed || repository.getCalls.Load() != 0 || repository.deleteCalls.Load() != 0 {
		t.Fatalf("receipt=%+v error=%v get=%d delete=%d", receipt, err, repository.getCalls.Load(), repository.deleteCalls.Load())
	}
}

func TestDeleteAlertRejectsStaleVersionBeforeWrite(t *testing.T) {
	fixture := newServiceFixture(t)
	repository := &fakeRepository{fixture: fixture, record: fixture.record}
	_, err := mustService(t, repository).DeleteAlert(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID,
		DeleteAlertInput{ExpectedVersion: fixture.record.Snapshot.Version() + 1, Reason: "Duplicate.", IdempotencyKey: "delete-alert-request-0003"},
	)
	if !errors.Is(err, ErrPreconditionFailed) || repository.deleteCalls.Load() != 0 {
		t.Fatalf("error=%v delete calls=%d", err, repository.deleteCalls.Load())
	}
}

func TestDeleteAlertFailsClosedBeforeRecordLookupWithoutPermission(t *testing.T) {
	fixture := newServiceFixture(t)
	repository := &fakeRepository{fixture: fixture, accessErrors: map[Capability]error{CapabilityAlertDelete: ErrForbidden}}
	_, err := mustService(t, repository).DeleteAlert(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID,
		DeleteAlertInput{ExpectedVersion: 1, Reason: "Duplicate.", IdempotencyKey: "delete-alert-request-0004"},
	)
	if !errors.Is(err, ErrForbidden) || repository.getCalls.Load() != 0 || repository.deleteCalls.Load() != 0 {
		t.Fatalf("error=%v get=%d delete=%d", err, repository.getCalls.Load(), repository.deleteCalls.Load())
	}
}

func TestDeleteAlertRejectsUnboundedOrAmbiguousInputs(t *testing.T) {
	fixture := newServiceFixture(t)
	repository := &fakeRepository{fixture: fixture}
	service := mustService(t, repository)
	tests := []DeleteAlertInput{
		{ExpectedVersion: 0, Reason: "Duplicate.", IdempotencyKey: "delete-alert-request-0005"},
		{ExpectedVersion: 1, Reason: "", IdempotencyKey: "delete-alert-request-0005"},
		{ExpectedVersion: 1, Reason: "Duplicate.", IdempotencyKey: "short"},
		{ExpectedVersion: maxResourceVersion, Reason: "Duplicate.", IdempotencyKey: "delete-alert-request-0005"},
	}
	for _, input := range tests {
		if _, err := service.DeleteAlert(context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, input); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("input=%+v error=%v", input, err)
		}
	}
	if repository.deleteCalls.Load() != 0 {
		t.Fatalf("invalid input reached repository %d times", repository.deleteCalls.Load())
	}
}

func TestAlertDeleteFingerprintBindsReasonAndExpectedVersion(t *testing.T) {
	fixture := newServiceFixture(t)
	base := DeleteAlertInput{ExpectedVersion: 3, Reason: "Duplicate.", IdempotencyKey: "ignored-by-fingerprint"}
	first, err := alertDeleteFingerprint(fixture.tenantUUID, fixture.actor.UserID, fixture.ticketUUID, base)
	if err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.Reason = "Retention request."
	second, _ := alertDeleteFingerprint(fixture.tenantUUID, fixture.actor.UserID, fixture.ticketUUID, changed)
	changed = base
	changed.ExpectedVersion++
	third, _ := alertDeleteFingerprint(fixture.tenantUUID, fixture.actor.UserID, fixture.ticketUUID, changed)
	if first == second || first == third {
		t.Fatal("delete fingerprint did not bind mutable request fields")
	}
}

func TestAlertDeleteCapabilityIsOperatorOnly(t *testing.T) {
	if !validCapability(CapabilityAlertDelete) {
		t.Fatal("alert.delete was not admitted by the application catalog")
	}
}
