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

func TestTenantLifecycleServiceChangesTenantWithExactAttribution(t *testing.T) {
	command, session, event, receipt := validTenantLifecycleServiceFixture(t)
	repository := &tenantLifecycleRepositoryStub{receipt: receipt}
	service, err := NewTenantLifecycleService(repository)
	if err != nil {
		t.Fatalf("NewTenantLifecycleService() error = %v", err)
	}

	got, err := service.Change(context.Background(), session, command, event)
	if err != nil {
		t.Fatalf("Change() error = %v", err)
	}
	if got != receipt || repository.calls != 1 {
		t.Fatalf("Change() = %#v, calls = %d", got, repository.calls)
	}
	if repository.params.ActorID != session.User.ID || repository.params.SessionID != session.ID ||
		repository.params.AuthenticationMethod != session.AuthenticationMethod ||
		repository.params.Command != command || repository.params.Event != event {
		t.Fatalf("ChangeTenantLifecycle() params = %#v", repository.params)
	}
}

func TestTenantLifecycleServiceAcceptsExactReplayedReceipt(t *testing.T) {
	command, session, event, receipt := validTenantLifecycleServiceFixture(t)
	receipt.replayed = true
	repository := &tenantLifecycleRepositoryStub{receipt: receipt}
	service, _ := NewTenantLifecycleService(repository)

	got, err := service.Change(context.Background(), session, command, event)
	if err != nil {
		t.Fatalf("Change() error = %v", err)
	}
	if !got.Replayed() || got.Action() != TenantLifecycleSuspend {
		t.Fatalf("Change() = %#v", got)
	}
}

func TestTenantLifecycleServiceAcceptsOnlyClosedSessionProvenance(t *testing.T) {
	t.Parallel()

	for _, method := range []string{
		"bootstrap_totp", "oidc", "passkey", "recovery_code", "saml", "totp",
	} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			command, session, event, receipt := validTenantLifecycleServiceFixture(t)
			session.AuthenticationMethod = method
			repository := &tenantLifecycleRepositoryStub{receipt: receipt}
			service, _ := NewTenantLifecycleService(repository)
			if _, err := service.Change(context.Background(), session, command, event); err != nil {
				t.Fatalf("Change() error = %v", err)
			}
		})
	}

	command, session, event, receipt := validTenantLifecycleServiceFixture(t)
	session.AuthenticationMethod = "future_method"
	repository := &tenantLifecycleRepositoryStub{receipt: receipt}
	service, _ := NewTenantLifecycleService(repository)
	if _, err := service.Change(context.Background(), session, command, event); !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("Change() error = %v, want unavailable", err)
	}
	if repository.calls != 0 {
		t.Fatalf("repository calls = %d, want zero", repository.calls)
	}
}

func TestTenantLifecycleServiceDeniesBeforeValidationAndRepository(t *testing.T) {
	_, session, event, receipt := validTenantLifecycleServiceFixture(t)
	session.Permissions = nil
	repository := &tenantLifecycleRepositoryStub{receipt: receipt}
	service, _ := NewTenantLifecycleService(repository)

	_, err := service.Change(context.Background(), session, TenantLifecycleCommand{}, event)
	if !errors.Is(err, authentication.ErrForbidden) {
		t.Fatalf("Change() error = %v, want forbidden", err)
	}
	if repository.calls != 0 {
		t.Fatalf("repository calls = %d, want zero", repository.calls)
	}
}

func TestTenantLifecycleServiceRejectsMalformedBoundaryStateBeforeRepository(t *testing.T) {
	command, session, event, receipt := validTenantLifecycleServiceFixture(t)
	type testCase struct {
		name    string
		ctx     context.Context
		session authentication.Session
		command TenantLifecycleCommand
		event   authentication.EventContext
		want    error
	}
	tests := []testCase{
		{name: "invalid command", ctx: context.Background(), session: session, command: TenantLifecycleCommand{}, event: event, want: authentication.ErrInvalidInput},
		{name: "invalid actor", ctx: context.Background(), session: session, command: command, event: event, want: authentication.ErrUnavailable},
		{name: "invalid session", ctx: context.Background(), session: session, command: command, event: event, want: authentication.ErrUnavailable},
		{name: "invalid authentication method", ctx: context.Background(), session: session, command: command, event: event, want: authentication.ErrUnavailable},
		{name: "invalid event", ctx: context.Background(), session: session, command: command, event: authentication.EventContext{}, want: authentication.ErrUnavailable},
		{name: "nil context", session: session, command: command, event: event, want: authentication.ErrUnavailable},
	}
	tests[1].session.User.ID = uuid.Nil
	tests[2].session.ID = uuid.Nil
	tests[3].session.AuthenticationMethod = "OIDC bearer"

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &tenantLifecycleRepositoryStub{receipt: receipt}
			service, _ := NewTenantLifecycleService(repository)
			_, err := service.Change(test.ctx, test.session, test.command, test.event)
			if !errors.Is(err, test.want) {
				t.Fatalf("Change() error = %v, want %v", err, test.want)
			}
			if repository.calls != 0 {
				t.Fatalf("repository calls = %d, want zero", repository.calls)
			}
		})
	}
}

func TestTenantLifecycleServiceRejectsNilDependenciesAndReceivers(t *testing.T) {
	if _, err := NewTenantLifecycleService(nil); err == nil {
		t.Fatal("NewTenantLifecycleService(nil) succeeded")
	}
	var typedNilRepository *tenantLifecycleRepositoryStub
	if _, err := NewTenantLifecycleService(typedNilRepository); err == nil {
		t.Fatal("NewTenantLifecycleService(typed nil) succeeded")
	}

	command, session, event, _ := validTenantLifecycleServiceFixture(t)
	var nilService *TenantLifecycleService
	if _, err := nilService.Change(context.Background(), session, command, event); !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("nil Change() error = %v, want unavailable", err)
	}
	forged := &TenantLifecycleService{repository: typedNilRepository}
	if _, err := forged.Change(context.Background(), session, command, event); !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("typed-nil Change() error = %v, want unavailable", err)
	}

	var typedNilContext *tenantLifecycleNilContext
	service, _ := NewTenantLifecycleService(&tenantLifecycleRepositoryStub{})
	if _, err := service.Change(typedNilContext, session, command, event); !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("typed-nil context Change() error = %v, want unavailable", err)
	}
}

func TestTenantLifecycleServicePreservesClosedRepositoryOutcomes(t *testing.T) {
	command, session, event, _ := validTenantLifecycleServiceFixture(t)
	tests := []struct {
		name string
		in   error
		want error
	}{
		{name: "permission recheck", in: authentication.ErrForbidden, want: authentication.ErrForbidden},
		{name: "not found", in: authentication.ErrNotFound, want: authentication.ErrNotFound},
		{name: "database conflict", in: authentication.ErrConflict, want: authentication.ErrConflict},
		{name: "revision conflict", in: ErrTenantLifecycleConflict, want: authentication.ErrConflict},
		{name: "no change", in: ErrTenantLifecycleNoChange, want: authentication.ErrConflict},
		{name: "database invalid input", in: authentication.ErrInvalidInput, want: authentication.ErrInvalidInput},
		{name: "domain invalid input", in: ErrInvalidTenantLifecycle, want: authentication.ErrInvalidInput},
		{name: "unknown", in: errors.New("secret database diagnostic"), want: authentication.ErrUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &tenantLifecycleRepositoryStub{err: test.in}
			service, _ := NewTenantLifecycleService(repository)
			_, err := service.Change(context.Background(), session, command, event)
			if err != test.want {
				t.Fatalf("Change() error = %v, want exact %v", err, test.want)
			}
			if repository.calls != 1 {
				t.Fatalf("repository calls = %d, want one", repository.calls)
			}
		})
	}
}

func TestTenantLifecycleServiceRejectsUntrustedRepositoryReceipts(t *testing.T) {
	command, session, event, receipt := validTenantLifecycleServiceFixture(t)
	otherTenant := mustPlatformUUIDv7(t)
	tests := []struct {
		name   string
		mutate func(*TenantLifecycleReceipt)
	}{
		{name: "zero receipt", mutate: func(value *TenantLifecycleReceipt) { *value = TenantLifecycleReceipt{} }},
		{name: "wrong tenant", mutate: func(value *TenantLifecycleReceipt) { value.tenantID = otherTenant }},
		{name: "wrong target", mutate: func(value *TenantLifecycleReceipt) { value.current = TenantLifecycleActive }},
		{name: "wrong version", mutate: func(value *TenantLifecycleReceipt) { value.version++ }},
		{name: "non canonical timestamp", mutate: func(value *TenantLifecycleReceipt) { value.updatedAt = value.updatedAt.Add(time.Nanosecond) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := receipt
			test.mutate(&candidate)
			repository := &tenantLifecycleRepositoryStub{receipt: candidate}
			service, _ := NewTenantLifecycleService(repository)
			_, err := service.Change(context.Background(), session, command, event)
			if err != authentication.ErrUnavailable {
				t.Fatalf("Change() error = %v, want exact unavailable", err)
			}
		})
	}
}

func TestTenantLifecycleReceiptRestorationAndDiagnostics(t *testing.T) {
	command, _, event, receipt := validTenantLifecycleServiceFixture(t)
	if err := ValidateTenantLifecycleReceipt(receipt); err != nil {
		t.Fatalf("ValidateTenantLifecycleReceipt() error = %v", err)
	}
	if receipt.TenantID() != command.TenantID() || receipt.Previous() != TenantLifecycleActive ||
		receipt.Current() != TenantLifecycleSuspended || receipt.Version() != command.ExpectedVersion()+1 ||
		receipt.UpdatedAt().Location() != time.UTC || receipt.Action() != TenantLifecycleSuspend {
		t.Fatalf("receipt = %#v", receipt)
	}
	reactivated, err := RestoreTenantLifecycleReceipt(TenantLifecycleReceiptInput{
		TenantID: command.TenantID(), Previous: TenantLifecycleSuspended,
		Current: TenantLifecycleActive, Version: 3, UpdatedAt: receipt.UpdatedAt(), Replayed: true,
	})
	if err != nil || reactivated.Action() != TenantLifecycleReactivate || !reactivated.Replayed() {
		t.Fatalf("RestoreTenantLifecycleReceipt() = %#v, %v", reactivated, err)
	}

	params := ChangeTenantLifecycleParams{
		ActorID: uuid.Must(uuid.NewV7()), SessionID: uuid.Must(uuid.NewV7()),
		AuthenticationMethod: "passkey",
		Command:              command, Event: event,
	}
	for _, diagnostic := range []string{
		command.String(), command.GoString(), receipt.String(), receipt.GoString(),
		params.String(), params.GoString(), fmt.Sprintf("%#v", params),
		(&TenantLifecycleService{}).String(), (&TenantLifecycleService{}).GoString(),
	} {
		if strings.Contains(diagnostic, command.TenantID().String()) ||
			strings.Contains(diagnostic, command.Reason()) ||
			strings.Contains(diagnostic, event.UserAgent) || !strings.Contains(diagnostic, "[REDACTED]") {
			t.Fatalf("diagnostic was not redacted: %s", diagnostic)
		}
	}
}

func TestTenantLifecycleReceiptRestorationRejectsMalformedValues(t *testing.T) {
	command, _, _, receipt := validTenantLifecycleServiceFixture(t)
	valid := TenantLifecycleReceiptInput{
		TenantID: command.TenantID(), Previous: TenantLifecycleActive,
		Current: TenantLifecycleSuspended, Version: 2, UpdatedAt: receipt.UpdatedAt(),
	}
	tests := []struct {
		name   string
		mutate func(*TenantLifecycleReceiptInput)
	}{
		{name: "nil tenant", mutate: func(value *TenantLifecycleReceiptInput) { value.TenantID = uuid.Nil }},
		{name: "same state", mutate: func(value *TenantLifecycleReceiptInput) { value.Current = value.Previous }},
		{name: "unknown state", mutate: func(value *TenantLifecycleReceiptInput) { value.Previous = "pending" }},
		{name: "version one", mutate: func(value *TenantLifecycleReceiptInput) { value.Version = 1 }},
		{name: "zero timestamp", mutate: func(value *TenantLifecycleReceiptInput) { value.UpdatedAt = time.Time{} }},
		{name: "local timestamp", mutate: func(value *TenantLifecycleReceiptInput) {
			value.UpdatedAt = value.UpdatedAt.In(time.FixedZone("test", 0))
		}},
		{name: "nanosecond timestamp", mutate: func(value *TenantLifecycleReceiptInput) { value.UpdatedAt = value.UpdatedAt.Add(time.Nanosecond) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if _, err := RestoreTenantLifecycleReceipt(candidate); !errors.Is(err, ErrInvalidTenantLifecycle) {
				t.Fatalf("RestoreTenantLifecycleReceipt() error = %v", err)
			}
		})
	}
}

func TestTenantLifecycleBoundaryValidatorsAreClosed(t *testing.T) {
	for _, method := range []string{
		"bootstrap_totp", "oidc", "passkey", "recovery_code", "saml", "totp",
	} {
		if !validTenantLifecycleAuthenticationMethod(method) {
			t.Fatalf("valid authentication method %q was rejected", method)
		}
	}
	for _, method := range []string{
		"", "password", "webauthn", " password", "OIDC", "oidc:totp",
		"passkey+stepup", "oidc bearer", "oidc/path", "método", strings.Repeat("a", 129),
	} {
		if validTenantLifecycleAuthenticationMethod(method) {
			t.Fatalf("invalid authentication method %q was accepted", method)
		}
	}

	_, _, event, _ := validTenantLifecycleServiceFixture(t)
	if !validTenantLifecycleEvent(event) {
		t.Fatal("valid event was rejected")
	}
	tests := []authentication.EventContext{
		{},
		{RequestID: event.RequestID, CorrelationID: event.CorrelationID, RemoteAddress: netip.MustParseAddr("fe80::1%eth0")},
		{RequestID: event.RequestID, CorrelationID: event.CorrelationID, RemoteAddress: event.RemoteAddress, UserAgent: "line\nbreak"},
		{RequestID: event.RequestID, CorrelationID: event.CorrelationID, RemoteAddress: event.RemoteAddress, UserAgent: strings.Repeat("a", 513)},
		{RequestID: event.RequestID, CorrelationID: event.CorrelationID, RemoteAddress: event.RemoteAddress, UserAgent: string([]byte{0xff})},
	}
	for _, candidate := range tests {
		if validTenantLifecycleEvent(candidate) {
			t.Fatalf("invalid event was accepted: %#v", candidate)
		}
	}
}

func validTenantLifecycleServiceFixture(
	t *testing.T,
) (TenantLifecycleCommand, authentication.Session, authentication.EventContext, TenantLifecycleReceipt) {
	t.Helper()
	tenantID := mustPlatformUUIDv7(t)
	command, err := NewTenantLifecycleCommand(
		tenantID, TenantLifecycleSuspended, 4, "customer-sensitive suspension reason",
	)
	if err != nil {
		t.Fatalf("NewTenantLifecycleCommand() error = %v", err)
	}
	session := authentication.Session{
		ID:                   mustPlatformUUIDv7(t),
		User:                 authentication.User{ID: mustPlatformUUIDv7(t)},
		Permissions:          []authorization.Permission{authorization.PermissionPlatformTenantManage},
		AuthenticationMethod: "passkey",
	}
	event := authentication.EventContext{
		RequestID: mustPlatformUUIDv7(t), CorrelationID: mustPlatformUUIDv7(t),
		RemoteAddress: netip.MustParseAddr("198.51.100.17"), UserAgent: "lifecycle-test/1",
	}
	receipt, err := RestoreTenantLifecycleReceipt(TenantLifecycleReceiptInput{
		TenantID: tenantID, Previous: TenantLifecycleActive,
		Current: TenantLifecycleSuspended, Version: 5,
		UpdatedAt: time.Date(2026, 8, 26, 12, 34, 56, 789_123_000, time.UTC),
	})
	if err != nil {
		t.Fatalf("RestoreTenantLifecycleReceipt() error = %v", err)
	}
	return command, session, event, receipt
}

type tenantLifecycleRepositoryStub struct {
	calls   int
	params  ChangeTenantLifecycleParams
	receipt TenantLifecycleReceipt
	err     error
}

func (repository *tenantLifecycleRepositoryStub) ChangeTenantLifecycle(
	_ context.Context,
	params ChangeTenantLifecycleParams,
) (TenantLifecycleReceipt, error) {
	repository.calls++
	repository.params = params
	return repository.receipt, repository.err
}

type tenantLifecycleNilContext struct{}

func (*tenantLifecycleNilContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*tenantLifecycleNilContext) Done() <-chan struct{}       { return nil }
func (*tenantLifecycleNilContext) Err() error                  { return nil }
func (*tenantLifecycleNilContext) Value(any) any               { return nil }

var _ TenantLifecycleRepository = (*tenantLifecycleRepositoryStub)(nil)
var _ context.Context = (*tenantLifecycleNilContext)(nil)
