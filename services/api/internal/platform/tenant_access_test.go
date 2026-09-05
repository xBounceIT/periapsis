package platform

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func TestPlatformTenantAccessServiceAuthorizesExactExplicitBoundary(t *testing.T) {
	command, session, event, receipt := platformTenantAccessFixture(t)
	repository := &platformTenantAccessRepositoryStub{receipt: receipt}
	service, err := NewPlatformTenantAccessService(repository)
	if err != nil {
		t.Fatalf("NewPlatformTenantAccessService() error = %v", err)
	}

	got, err := service.Authorize(context.Background(), session, command, event)
	if err != nil || got != receipt || repository.calls != 1 {
		t.Fatalf("Authorize() = %#v, %v; calls = %d", got, err, repository.calls)
	}
	if repository.params.ActorID != session.User.ID ||
		repository.params.SessionID != session.ID ||
		repository.params.AuthenticationMethod != session.AuthenticationMethod ||
		repository.params.Command != command || repository.params.Event != event {
		t.Fatalf("AuthorizePlatformTenantAccess() params = %#v", repository.params)
	}
}

func TestPlatformTenantAccessServiceDeniesBeforeInputValidation(t *testing.T) {
	_, session, event, receipt := platformTenantAccessFixture(t)
	session.Permissions = nil
	repository := &platformTenantAccessRepositoryStub{receipt: receipt}
	service, _ := NewPlatformTenantAccessService(repository)

	_, err := service.Authorize(context.Background(), session, PlatformTenantAccessCommand{}, event)
	if !errors.Is(err, authentication.ErrForbidden) || repository.calls != 0 {
		t.Fatalf("Authorize() error = %v, calls = %d", err, repository.calls)
	}
}

func TestPlatformTenantAccessServiceRejectsRecoveryAndMalformedBoundaries(t *testing.T) {
	command, session, event, receipt := platformTenantAccessFixture(t)
	tests := []struct {
		name    string
		ctx     context.Context
		session authentication.Session
		command PlatformTenantAccessCommand
		event   authentication.EventContext
		want    error
	}{
		{name: "invalid command", ctx: context.Background(), session: session, event: event, want: authentication.ErrInvalidInput},
		{name: "invalid actor", ctx: context.Background(), session: session, command: command, event: event, want: authentication.ErrUnavailable},
		{name: "invalid session", ctx: context.Background(), session: session, command: command, event: event, want: authentication.ErrUnavailable},
		{name: "recovery session", ctx: context.Background(), session: session, command: command, event: event, want: authentication.ErrUnavailable},
		{name: "empty user agent", ctx: context.Background(), session: session, command: command, event: event, want: authentication.ErrUnavailable},
		{name: "nil context", session: session, command: command, event: event, want: authentication.ErrUnavailable},
	}
	tests[1].session.User.ID = uuid.Nil
	tests[2].session.ID = uuid.Nil
	tests[3].session.AuthenticationMethod = "recovery_code"
	tests[4].event.UserAgent = ""

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &platformTenantAccessRepositoryStub{receipt: receipt}
			service, _ := NewPlatformTenantAccessService(repository)
			_, err := service.Authorize(test.ctx, test.session, test.command, test.event)
			if !errors.Is(err, test.want) || repository.calls != 0 {
				t.Fatalf("Authorize() error = %v, calls = %d, want %v/zero", err, repository.calls, test.want)
			}
		})
	}
}

func TestPlatformTenantAccessServicePreservesClosedOutcomes(t *testing.T) {
	command, session, event, _ := platformTenantAccessFixture(t)
	for _, test := range []struct {
		name string
		in   error
		want error
	}{
		{name: "permission", in: authentication.ErrForbidden, want: authentication.ErrForbidden},
		{name: "not found", in: authentication.ErrNotFound, want: authentication.ErrNotFound},
		{name: "conflict", in: ErrPlatformTenantAccessConflict, want: authentication.ErrConflict},
		{name: "precondition", in: ErrPlatformTenantAccessPreconditionFailed, want: ErrPlatformTenantAccessPreconditionFailed},
		{name: "invalid", in: ErrInvalidPlatformTenantAccess, want: authentication.ErrInvalidInput},
		{name: "unknown", in: errors.New("secret diagnostic"), want: authentication.ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &platformTenantAccessRepositoryStub{err: test.in}
			service, _ := NewPlatformTenantAccessService(repository)
			_, err := service.Authorize(context.Background(), session, command, event)
			if err != test.want || repository.calls != 1 {
				t.Fatalf("Authorize() error = %v, calls = %d", err, repository.calls)
			}
		})
	}
}

func TestPlatformTenantAccessServiceRejectsForgedReceipt(t *testing.T) {
	command, session, event, receipt := platformTenantAccessFixture(t)
	for _, mutate := range []func(*PlatformTenantAccessReceipt){
		func(value *PlatformTenantAccessReceipt) { value.tenantID = mustPlatformUUIDv7(t) },
		func(value *PlatformTenantAccessReceipt) { value.userID = mustPlatformUUIDv7(t) },
		func(value *PlatformTenantAccessReceipt) { value.tenantVersion++ },
		func(value *PlatformTenantAccessReceipt) { value.authorizedAt = value.authorizedAt.Add(time.Nanosecond) },
	} {
		candidate := receipt
		mutate(&candidate)
		service, _ := NewPlatformTenantAccessService(&platformTenantAccessRepositoryStub{receipt: candidate})
		if _, err := service.Authorize(context.Background(), session, command, event); err != authentication.ErrUnavailable {
			t.Fatalf("Authorize() error = %v, want unavailable", err)
		}
	}
}

func TestPlatformTenantAccessCommandAndReceiptAreClosedAndRedacted(t *testing.T) {
	command, _, event, receipt := platformTenantAccessFixture(t)
	if ValidatePlatformTenantAccessCommand(command) != nil ||
		ValidatePlatformTenantAccessReceipt(receipt) != nil || receipt.MembershipRevision() != 1 ||
		receipt.AuthorizationRevision() != 17 || receipt.Replayed() {
		t.Fatalf("invalid fixture: %#v / %#v", command, receipt)
	}
	params := AuthorizePlatformTenantAccessParams{Command: command, Event: event}
	for _, diagnostic := range []string{
		command.String(), command.GoString(), receipt.String(), receipt.GoString(),
		params.String(), params.GoString(), fmt.Sprintf("%#v", params),
		(&PlatformTenantAccessService{}).String(),
	} {
		if strings.Contains(diagnostic, command.TenantID().String()) ||
			strings.Contains(diagnostic, command.Reason()) ||
			strings.Contains(diagnostic, command.IdempotencyKey()) ||
			!strings.Contains(diagnostic, "[REDACTED]") {
			t.Fatalf("diagnostic was not redacted: %s", diagnostic)
		}
	}
}

func TestPlatformTenantAccessCommandValidationRejectsUnsafeInput(t *testing.T) {
	tenantID := mustPlatformUUIDv7(t)
	for _, test := range []struct {
		version int32
		reason  string
		key     string
	}{
		{version: 1, reason: "Approved", key: "short"},
		{version: 1, reason: "Approved", key: strings.Repeat("a", 129)},
		{version: 1, reason: "Approved", key: "invalid,key-000000"},
		{version: 1, reason: " trailing", key: "access-key-0000001"},
		{version: 0, reason: "Approved", key: "access-key-0000001"},
	} {
		if _, err := NewPlatformTenantAccessCommand(tenantID, test.version, test.reason, test.key); !errors.Is(err, ErrInvalidPlatformTenantAccess) {
			t.Fatalf("NewPlatformTenantAccessCommand(%#v) error = %v", test, err)
		}
	}
}

func TestPlatformTenantAccessAuthenticationMethodCatalog(t *testing.T) {
	for _, method := range []string{"bootstrap_totp", "ldap", "oidc", "passkey", "saml", "totp"} {
		if !validPlatformTenantAccessAuthenticationMethod(method) {
			t.Fatalf("valid method %q rejected", method)
		}
	}
	for _, method := range []string{"", "recovery_code", "password", "OIDC", "totp+recovery"} {
		if validPlatformTenantAccessAuthenticationMethod(method) {
			t.Fatalf("invalid method %q accepted", method)
		}
	}
}

func TestPlatformTenantAccessServiceRejectsNilDependencies(t *testing.T) {
	if _, err := NewPlatformTenantAccessService(nil); err == nil {
		t.Fatal("NewPlatformTenantAccessService(nil) succeeded")
	}
	var typedNil *platformTenantAccessRepositoryStub
	if _, err := NewPlatformTenantAccessService(typedNil); err == nil {
		t.Fatal("NewPlatformTenantAccessService(typed nil) succeeded")
	}
	command, session, event, _ := platformTenantAccessFixture(t)
	var service *PlatformTenantAccessService
	if _, err := service.Authorize(context.Background(), session, command, event); err != authentication.ErrUnavailable {
		t.Fatalf("nil service error = %v", err)
	}
}

func platformTenantAccessFixture(
	t *testing.T,
) (PlatformTenantAccessCommand, authentication.Session, authentication.EventContext, PlatformTenantAccessReceipt) {
	t.Helper()
	tenantID := mustPlatformUUIDv7(t)
	userID := mustPlatformUUIDv7(t)
	command, err := NewPlatformTenantAccessCommand(
		tenantID, 7, "Approved emergency investigation SEC-2048", "tenant-access-key-0001",
	)
	if err != nil {
		t.Fatalf("NewPlatformTenantAccessCommand() error = %v", err)
	}
	session := authentication.Session{
		ID: mustPlatformUUIDv7(t), User: authentication.User{ID: userID},
		Permissions:          []authorization.Permission{authorization.PermissionPlatformTenantAccess},
		AuthenticationMethod: "passkey",
	}
	event := authentication.EventContext{
		RequestID: mustPlatformUUIDv7(t), CorrelationID: mustPlatformUUIDv7(t),
		RemoteAddress: netip.MustParseAddr("198.51.100.42"), UserAgent: "tenant-access-test/1",
	}
	receipt, err := RestorePlatformTenantAccessReceipt(PlatformTenantAccessReceiptInput{
		TenantID: tenantID, MembershipID: mustPlatformUUIDv7(t), UserID: userID,
		TenantVersion: 7, MembershipRevision: 1, AuthorizationRevision: 17,
		AuthorizedAt: time.Date(2026, 9, 1, 20, 30, 0, 123_456_000, time.UTC),
	})
	if err != nil {
		t.Fatalf("RestorePlatformTenantAccessReceipt() error = %v", err)
	}
	return command, session, event, receipt
}

type platformTenantAccessRepositoryStub struct {
	calls   int
	params  AuthorizePlatformTenantAccessParams
	receipt PlatformTenantAccessReceipt
	err     error
}

func (repository *platformTenantAccessRepositoryStub) AuthorizePlatformTenantAccess(
	_ context.Context,
	params AuthorizePlatformTenantAccessParams,
) (PlatformTenantAccessReceipt, error) {
	repository.calls++
	repository.params = params
	return repository.receipt, repository.err
}

var _ PlatformTenantAccessRepository = (*platformTenantAccessRepositoryStub)(nil)
