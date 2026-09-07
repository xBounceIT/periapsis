package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	apiconfig "github.com/periapsis-im/periapsis/services/api/internal/config"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/httpserver"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres"
)

type staticReadiness struct{}

func (staticReadiness) Check(context.Context) []postgres.DependencyCheck {
	return []postgres.DependencyCheck{{Name: "postgresql", Ready: true}}
}

type unavailableReadiness struct{}

func (unavailableReadiness) Check(context.Context) []postgres.DependencyCheck {
	return []postgres.DependencyCheck{{Name: "postgresql", Ready: false}}
}

type countingReadiness struct{ calls *int }

func (s countingReadiness) Check(context.Context) []postgres.DependencyCheck {
	(*s.calls)++
	return []postgres.DependencyCheck{{Name: "postgresql", Ready: true}}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		value string
		want  slog.Level
	}{
		{value: "", want: slog.LevelInfo},
		{value: "info", want: slog.LevelInfo},
		{value: "error", want: slog.LevelError},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got, err := parseLogLevel(tt.value)
			if err != nil {
				t.Fatalf("parseLogLevel(%q): %v", tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("parseLogLevel(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
	for _, value := range []string{"debug", "INFO", " info "} {
		if _, err := parseLogLevel(value); err == nil {
			t.Fatalf("parseLogLevel(%q) unexpectedly succeeded", value)
		}
	}
}

type federatedSessionRevalidatorStub struct {
	result federatedauth.SessionResult
	err    error
	during func()
	calls  int
	lookup federatedauth.SessionLookup
}

type directPlatformOIDCSessionRevalidatorStub struct {
	result platformoidcauth.DirectSessionAuthorityResult
	err    error
	during func()
	calls  int
	lookup platformoidcauth.DirectSessionAuthorityLookup
}

type directPlatformSAMLSessionRevalidatorStub struct {
	result platformsamlauth.DirectSAMLSessionAuthorityOutcome
	err    error
	during func()
	calls  int
	lookup platformsamlauth.DirectSAMLSessionAuthorityLookup
}

func (stub *directPlatformSAMLSessionRevalidatorStub) RevalidateDirectPlatformSession(
	_ context.Context,
	lookup platformsamlauth.DirectSAMLSessionAuthorityLookup,
) (platformsamlauth.DirectSAMLSessionAuthorityOutcome, error) {
	stub.calls++
	stub.lookup = lookup
	if stub.during != nil {
		stub.during()
	}
	return stub.result, stub.err
}

func (stub *directPlatformOIDCSessionRevalidatorStub) RevalidateDirectPlatformSession(
	_ context.Context,
	lookup platformoidcauth.DirectSessionAuthorityLookup,
) (platformoidcauth.DirectSessionAuthorityResult, error) {
	stub.calls++
	stub.lookup = lookup
	if stub.during != nil {
		stub.during()
	}
	return stub.result, stub.err
}

func (stub *federatedSessionRevalidatorStub) RevalidateSession(
	_ context.Context,
	lookup federatedauth.SessionLookup,
) (federatedauth.SessionResult, error) {
	stub.calls++
	stub.lookup = lookup
	if stub.during != nil {
		stub.during()
	}
	return stub.result, stub.err
}

type protectedVerifierStub struct {
	err           error
	calls         *int
	invalidations *int
}

type credentialVerifierStub struct {
	err   error
	calls *int
}

type identityVerifierStub struct {
	err   error
	calls *int
}

type notificationVerifierStub struct {
	err   error
	calls *int
}

type federatedVerifierStub struct {
	err    error
	during func()
	calls  *int
}

type dependencyVerifierStub struct {
	err   error
	calls *int
}

type ticketOperationsVerifierStub struct {
	err   error
	calls *int
}

type platformLocalAccountVerifierStub struct {
	err   error
	calls *int
}

func (stub ticketOperationsVerifierStub) ReadyTicketOperations(context.Context) error {
	if stub.calls != nil {
		(*stub.calls)++
	}
	return stub.err
}

func (stub platformLocalAccountVerifierStub) ReadyPlatformLocalAccounts(context.Context) error {
	if stub.calls != nil {
		(*stub.calls)++
	}
	return stub.err
}

func (s dependencyVerifierStub) Check(context.Context) error {
	if s.calls != nil {
		(*s.calls)++
	}
	return s.err
}

func TestApplicationStartupBindsLDAPAdministrationToIdentityProviderService(t *testing.T) {
	service := (*identityprovider.Service)(nil)
	options := bindIdentityProviderServices(httpserver.ApplicationOptions{}, service)

	if _, ok := options.IdentityProviders.(*identityprovider.Service); !ok {
		t.Fatal("identity-provider surface was not bound to the concrete service")
	}
	if _, ok := options.LDAPAdministration.(*identityprovider.Service); !ok {
		t.Fatal("LDAP administration surface was not bound to the concrete service")
	}
}

func (s identityVerifierStub) Verify(context.Context) error {
	if s.calls != nil {
		(*s.calls)++
	}
	return s.err
}

func (s notificationVerifierStub) Verify(context.Context) error {
	if s.calls != nil {
		(*s.calls)++
	}
	return s.err
}

func (s federatedVerifierStub) Ready(context.Context) error {
	if s.calls != nil {
		(*s.calls)++
	}
	if s.during != nil {
		s.during()
	}
	return s.err
}

func (s credentialVerifierStub) VerifyLiveKeyVersions(context.Context) error {
	if s.calls != nil {
		(*s.calls)++
	}
	return s.err
}

func (s protectedVerifierStub) VerifyProtectedConfiguration(context.Context) error {
	if s.calls != nil {
		(*s.calls)++
	}
	return s.err
}

func (s protectedVerifierStub) InvalidateProtectedConfiguration() {
	if s.invalidations != nil {
		(*s.invalidations)++
	}
}

func TestProtectedAuthenticationConfigurationParticipatesInReadiness(t *testing.T) {
	failedInvalidations := 0
	checks := (&protectedConfigReadiness{
		database: staticReadiness{}, authentication: protectedVerifierStub{
			err: errors.New("mismatch"), invalidations: &failedInvalidations,
		}, credentialKeyring: credentialVerifierStub{}, dfirObjectStorage: dependencyVerifierStub{}, dfirMalwareScanner: dependencyVerifierStub{}, identityKeyring: identityVerifierStub{}, notificationKeyring: notificationVerifierStub{}, ticketOperations: ticketOperationsVerifierStub{}, platformLocalAccounts: platformLocalAccountVerifierStub{},
	}).Check(context.Background())
	if len(checks) != 9 || !checks[0].Ready || checks[1].Name != "protected_authentication_configuration" ||
		checks[1].Ready || failedInvalidations != 1 {
		t.Fatalf("readiness checks = %#v", checks)
	}
	checks = (&protectedConfigReadiness{
		database: staticReadiness{}, authentication: protectedVerifierStub{}, credentialKeyring: credentialVerifierStub{}, dfirObjectStorage: dependencyVerifierStub{}, dfirMalwareScanner: dependencyVerifierStub{}, identityKeyring: identityVerifierStub{}, notificationKeyring: notificationVerifierStub{}, ticketOperations: ticketOperationsVerifierStub{}, platformLocalAccounts: platformLocalAccountVerifierStub{},
	}).Check(context.Background())
	if len(checks) != 9 || !checks[1].Ready || !checks[2].Ready || !checks[3].Ready || !checks[4].Ready || !checks[5].Ready || !checks[6].Ready || !checks[7].Ready || !checks[8].Ready {
		t.Fatalf("verified readiness checks = %#v", checks)
	}
	calls := 0
	invalidations := 0
	checks = (&protectedConfigReadiness{
		database: unavailableReadiness{},
		authentication: protectedVerifierStub{
			calls: &calls, invalidations: &invalidations,
		},
		credentialKeyring: credentialVerifierStub{}, dfirObjectStorage: dependencyVerifierStub{}, dfirMalwareScanner: dependencyVerifierStub{}, identityKeyring: identityVerifierStub{}, notificationKeyring: notificationVerifierStub{}, ticketOperations: ticketOperationsVerifierStub{}, platformLocalAccounts: platformLocalAccountVerifierStub{},
	}).Check(context.Background())
	if len(checks) != 9 || checks[1].Ready || checks[2].Ready || checks[3].Ready || checks[4].Ready || checks[5].Ready || checks[6].Ready || checks[7].Ready || checks[8].Ready || calls != 0 || invalidations != 1 {
		t.Fatalf(
			"unready prerequisite checks = %#v, verifier calls = %d, invalidations = %d",
			checks, calls, invalidations,
		)
	}
}

func TestCredentialKeyringParticipatesInReadiness(t *testing.T) {
	invalidations := 0
	checks := (&protectedConfigReadiness{
		database:              staticReadiness{},
		authentication:        protectedVerifierStub{invalidations: &invalidations},
		credentialKeyring:     credentialVerifierStub{err: errors.New("missing live version")},
		dfirObjectStorage:     dependencyVerifierStub{},
		dfirMalwareScanner:    dependencyVerifierStub{},
		identityKeyring:       identityVerifierStub{},
		notificationKeyring:   notificationVerifierStub{},
		ticketOperations:      ticketOperationsVerifierStub{},
		platformLocalAccounts: platformLocalAccountVerifierStub{},
	}).Check(context.Background())
	if len(checks) != 9 || checks[2].Name != "api_credential_keyring" || checks[2].Ready || !checks[3].Ready || !checks[4].Ready || !checks[5].Ready || !checks[6].Ready || !checks[7].Ready || !checks[8].Ready || invalidations != 1 {
		t.Fatalf("readiness checks = %#v, invalidations = %d", checks, invalidations)
	}
}

func TestIdentityKeyringParticipatesInReadiness(t *testing.T) {
	invalidations := 0
	checks := (&protectedConfigReadiness{
		database:              staticReadiness{},
		authentication:        protectedVerifierStub{invalidations: &invalidations},
		credentialKeyring:     credentialVerifierStub{},
		dfirObjectStorage:     dependencyVerifierStub{},
		dfirMalwareScanner:    dependencyVerifierStub{},
		identityKeyring:       identityVerifierStub{err: errors.New("database evidence mismatch")},
		notificationKeyring:   notificationVerifierStub{},
		ticketOperations:      ticketOperationsVerifierStub{},
		platformLocalAccounts: platformLocalAccountVerifierStub{},
	}).Check(context.Background())
	if len(checks) != 9 || checks[3].Name != "identity_keyring" || checks[3].Ready || !checks[4].Ready || !checks[5].Ready || !checks[6].Ready || !checks[7].Ready || !checks[8].Ready || invalidations != 1 {
		t.Fatalf("readiness checks = %#v, invalidations = %d", checks, invalidations)
	}
}

func TestNotificationKeyringParticipatesInReadinessWithoutInvalidatingAuthentication(t *testing.T) {
	invalidations := 0
	checks := (&protectedConfigReadiness{
		database:              staticReadiness{},
		authentication:        protectedVerifierStub{invalidations: &invalidations},
		credentialKeyring:     credentialVerifierStub{},
		dfirObjectStorage:     dependencyVerifierStub{},
		dfirMalwareScanner:    dependencyVerifierStub{},
		identityKeyring:       identityVerifierStub{},
		notificationKeyring:   notificationVerifierStub{err: errors.New("missing live notification key version")},
		ticketOperations:      ticketOperationsVerifierStub{},
		platformLocalAccounts: platformLocalAccountVerifierStub{},
	}).Check(context.Background())
	if len(checks) != 9 || checks[4].Name != "notification_keyring" || checks[4].Ready || !checks[5].Ready || !checks[6].Ready || !checks[7].Ready || !checks[8].Ready || invalidations != 0 {
		t.Fatalf("readiness checks = %#v, invalidations = %d", checks, invalidations)
	}
}

func TestFederatedRuntimeParticipatesInReadinessWithoutInvalidatingLocalAuthentication(t *testing.T) {
	invalidations := 0
	calls := 0
	checks := (&protectedConfigReadiness{
		database:              staticReadiness{},
		authentication:        protectedVerifierStub{invalidations: &invalidations},
		credentialKeyring:     credentialVerifierStub{},
		dfirObjectStorage:     dependencyVerifierStub{},
		dfirMalwareScanner:    dependencyVerifierStub{},
		identityKeyring:       identityVerifierStub{},
		notificationKeyring:   notificationVerifierStub{},
		ticketOperations:      ticketOperationsVerifierStub{},
		platformLocalAccounts: platformLocalAccountVerifierStub{},
		federated: federatedVerifierStub{
			err: errors.New("federated schema unavailable"), calls: &calls,
		},
	}).Check(context.Background())
	if len(checks) != 10 || checks[9].Name != "federated_authentication" || checks[9].Ready ||
		calls != 1 || invalidations != 0 {
		t.Fatalf("readiness checks = %#v, calls = %d, invalidations = %d", checks, calls, invalidations)
	}
}

func TestTicketOperationsParticipateInReadinessAndTypedNilFailsClosed(t *testing.T) {
	calls := 0
	checks := (&protectedConfigReadiness{
		database:            staticReadiness{},
		authentication:      protectedVerifierStub{},
		credentialKeyring:   credentialVerifierStub{},
		dfirObjectStorage:   dependencyVerifierStub{},
		dfirMalwareScanner:  dependencyVerifierStub{},
		identityKeyring:     identityVerifierStub{},
		notificationKeyring: notificationVerifierStub{},
		ticketOperations: ticketOperationsVerifierStub{
			err: errors.New("ticket ABI unavailable"), calls: &calls,
		},
		platformLocalAccounts: platformLocalAccountVerifierStub{},
	}).Check(context.Background())
	if len(checks) != 9 || checks[7].Name != "ticket_operations" || checks[7].Ready || !checks[8].Ready || calls != 1 {
		t.Fatalf("ticket readiness checks = %#v, calls = %d", checks, calls)
	}

	var typedNil *ticketOperationsVerifierStub
	checks = (&protectedConfigReadiness{
		database: staticReadiness{}, authentication: protectedVerifierStub{},
		credentialKeyring: credentialVerifierStub{}, identityKeyring: identityVerifierStub{},
		notificationKeyring: notificationVerifierStub{}, dfirObjectStorage: dependencyVerifierStub{},
		dfirMalwareScanner: dependencyVerifierStub{}, ticketOperations: typedNil,
		platformLocalAccounts: platformLocalAccountVerifierStub{},
	}).Check(context.Background())
	if len(checks) != 9 || checks[7].Ready || !checks[8].Ready {
		t.Fatalf("typed-nil ticket readiness failed open: %#v", checks)
	}
}

func TestPlatformLocalAccountsParticipateInReadinessAndTypedNilFailsClosed(t *testing.T) {
	calls := 0
	checks := (&protectedConfigReadiness{
		database:            staticReadiness{},
		authentication:      protectedVerifierStub{},
		credentialKeyring:   credentialVerifierStub{},
		dfirObjectStorage:   dependencyVerifierStub{},
		dfirMalwareScanner:  dependencyVerifierStub{},
		identityKeyring:     identityVerifierStub{},
		notificationKeyring: notificationVerifierStub{},
		ticketOperations:    ticketOperationsVerifierStub{},
		platformLocalAccounts: platformLocalAccountVerifierStub{
			err: errors.New("platform local-account ABI unavailable"), calls: &calls,
		},
	}).Check(context.Background())
	if len(checks) != 9 || checks[8].Name != "platform_local_accounts" ||
		checks[8].Ready || calls != 1 {
		t.Fatalf("platform local-account readiness checks = %#v, calls = %d", checks, calls)
	}

	var typedNil *platformLocalAccountVerifierStub
	checks = (&protectedConfigReadiness{
		database: staticReadiness{}, authentication: protectedVerifierStub{},
		credentialKeyring: credentialVerifierStub{}, identityKeyring: identityVerifierStub{},
		notificationKeyring: notificationVerifierStub{}, dfirObjectStorage: dependencyVerifierStub{},
		dfirMalwareScanner: dependencyVerifierStub{}, ticketOperations: ticketOperationsVerifierStub{},
		platformLocalAccounts: typedNil,
	}).Check(context.Background())
	if len(checks) != 9 || checks[8].Ready {
		t.Fatalf("typed-nil platform local-account readiness failed open: %#v", checks)
	}
}

func TestFederatedRuntimeReadinessRequiresTenantOIDCAndSAMLGraphs(t *testing.T) {
	t.Parallel()

	tenantCalls := 0
	directOIDCCalls := 0
	directSAMLCalls := 0
	readiness := &federatedRuntimeReadiness{
		tenant:     federatedVerifierStub{calls: &tenantCalls},
		directOIDC: federatedVerifierStub{calls: &directOIDCCalls},
		directSAML: federatedVerifierStub{calls: &directSAMLCalls},
	}
	if err := readiness.Ready(context.Background()); err != nil ||
		tenantCalls != 1 || directOIDCCalls != 1 || directSAMLCalls != 1 {
		t.Fatalf(
			"ready result = %v, calls = tenant:%d oidc:%d saml:%d",
			err, tenantCalls, directOIDCCalls, directSAMLCalls,
		)
	}

	tenantFailureCalls := 0
	directOIDCAfterTenantFailureCalls := 0
	directSAMLAfterTenantFailureCalls := 0
	readiness = &federatedRuntimeReadiness{
		tenant: federatedVerifierStub{
			err: errors.New("tenant runtime unavailable"), calls: &tenantFailureCalls,
		},
		directOIDC: federatedVerifierStub{calls: &directOIDCAfterTenantFailureCalls},
		directSAML: federatedVerifierStub{calls: &directSAMLAfterTenantFailureCalls},
	}
	if err := readiness.Ready(context.Background()); err == nil ||
		tenantFailureCalls != 1 || directOIDCAfterTenantFailureCalls != 0 ||
		directSAMLAfterTenantFailureCalls != 0 {
		t.Fatalf(
			"tenant failure = %v, calls = tenant:%d oidc:%d saml:%d",
			err, tenantFailureCalls, directOIDCAfterTenantFailureCalls, directSAMLAfterTenantFailureCalls,
		)
	}

	directOIDCFailureCalls := 0
	directSAMLAfterOIDCFailureCalls := 0
	readiness = &federatedRuntimeReadiness{
		tenant: federatedVerifierStub{}, directOIDC: federatedVerifierStub{
			err: errors.New("direct OIDC runtime unavailable"), calls: &directOIDCFailureCalls,
		},
		directSAML: federatedVerifierStub{calls: &directSAMLAfterOIDCFailureCalls},
	}
	if err := readiness.Ready(context.Background()); err == nil || directOIDCFailureCalls != 1 ||
		directSAMLAfterOIDCFailureCalls != 0 {
		t.Fatalf(
			"direct OIDC failure = %v, calls = oidc:%d saml:%d",
			err, directOIDCFailureCalls, directSAMLAfterOIDCFailureCalls,
		)
	}

	directSAMLFailureCalls := 0
	readiness = &federatedRuntimeReadiness{
		tenant: federatedVerifierStub{}, directOIDC: federatedVerifierStub{},
		directSAML: federatedVerifierStub{
			err: errors.New("direct SAML runtime unavailable"), calls: &directSAMLFailureCalls,
		},
	}
	if err := readiness.Ready(context.Background()); err == nil || directSAMLFailureCalls != 1 {
		t.Fatalf("direct SAML failure = %v, calls = %d", err, directSAMLFailureCalls)
	}

	if err := (*federatedRuntimeReadiness)(nil).Ready(context.Background()); err == nil {
		t.Fatal("nil combined readiness was accepted")
	}
	var typedNil *federatedVerifierStub
	if err := (&federatedRuntimeReadiness{
		tenant: typedNil, directOIDC: federatedVerifierStub{}, directSAML: federatedVerifierStub{},
	}).Ready(context.Background()); err == nil {
		t.Fatal("typed nil readiness dependency was accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := readiness.Ready(cancelled); err == nil {
		t.Fatal("cancelled combined readiness was accepted")
	}

	for _, cancellationPoint := range []string{"tenant", "oidc", "saml"} {
		cancellationPoint := cancellationPoint
		t.Run("cancellation after "+cancellationPoint, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			calls := [3]int{}
			cancelAt := func(name string) func() {
				if name == cancellationPoint {
					return cancel
				}
				return nil
			}
			readiness := &federatedRuntimeReadiness{
				tenant:     federatedVerifierStub{calls: &calls[0], during: cancelAt("tenant")},
				directOIDC: federatedVerifierStub{calls: &calls[1], during: cancelAt("oidc")},
				directSAML: federatedVerifierStub{calls: &calls[2], during: cancelAt("saml")},
			}
			if err := readiness.Ready(ctx); err == nil {
				t.Fatal("readiness accepted cancellation during verification")
			}
			want := [3]int{1, 1, 1}
			switch cancellationPoint {
			case "tenant":
				want = [3]int{1, 0, 0}
			case "oidc":
				want = [3]int{1, 1, 0}
			}
			if calls != want {
				t.Fatalf("readiness calls = %v, want %v", calls, want)
			}
		})
	}
}

func TestFederatedCompositionKeepsNonTLSDevelopmentExplicitlyDisabled(t *testing.T) {
	t.Parallel()
	development := apiconfig.Config{Environment: "development", PublicOrigin: "http://localhost:8081"}
	composition, err := newFederatedRuntimeComposition(nil, &development, nil)
	if err != nil || composition.enabled || composition.browser != nil ||
		composition.platformOIDCBrowser != nil || composition.platformSAMLBrowser != nil ||
		composition.platformSAMLContinuation != nil || composition.httpClient != nil || composition.readiness != nil {
		t.Fatalf("development composition = %#v, %v", composition, err)
	}

	production := apiconfig.Config{Environment: "production", PublicOrigin: "http://app.example.test"}
	if composition, err = newFederatedRuntimeComposition(nil, &production, nil); err == nil ||
		composition != (federatedRuntimeComposition{}) {
		t.Fatalf("production composition = %#v, %v", composition, err)
	}
}

func TestPlatformIdentityProviderAdministrationKeepsNonTLSDevelopmentExplicitlyDisabled(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		config  *apiconfig.Config
		enabled bool
		wantErr bool
	}{
		{name: "HTTPS development", config: &apiconfig.Config{Environment: "development", PublicOrigin: "https://localhost:8443"}, enabled: true},
		{name: "HTTP development", config: &apiconfig.Config{Environment: "development", PublicOrigin: "http://localhost:8081"}},
		{name: "HTTP production", config: &apiconfig.Config{Environment: "production", PublicOrigin: "http://app.example.test"}, wantErr: true},
		{name: "missing configuration", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			enabled, err := platformIdentityProviderAdministrationEnabled(test.config)
			if enabled != test.enabled || (err != nil) != test.wantErr {
				t.Fatalf("enabled = %t, error = %v", enabled, err)
			}
		})
	}
}

func TestRuntimeFederatedSessionAuthorityAllowsOnlyExactUsableDecision(t *testing.T) {
	t.Parallel()
	sessionID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	lookup := authentication.FederatedSessionAuthorityLookup{
		SessionID: sessionID, TenantID: tenantID, UserID: userID,
		AuthenticationMethod: "oidc", Audience: "api",
	}
	stub := &federatedSessionRevalidatorStub{result: federatedauth.SessionResult{
		SessionID: identity.EntityID(sessionID), TenantID: identity.EntityID(tenantID),
		UserID: identity.EntityID(userID), AuthenticationMethod: federatedauth.AuthenticationMethodOIDC,
		Decision: mfa.SessionUsable,
		Reason:   mfa.SessionReasonCurrent, AllowAuthority: true, AllowIdleTouch: true,
	}}
	authority := &runtimeFederatedSessionAuthority{revalidator: stub}
	result, err := authority.RevalidateFederatedSession(context.Background(), lookup)
	if err != nil || !result.AllowAuthority || !result.AllowIdleTouch ||
		result.SessionID != sessionID || result.TenantID != tenantID || result.UserID != userID {
		t.Fatalf("RevalidateFederatedSession() = %#v, %v", result, err)
	}
	wantLookup := federatedauth.SessionLookup{
		SessionID: identity.EntityID(sessionID), TenantID: identity.EntityID(tenantID), Audience: "api",
		AuthenticationMethod: federatedauth.AuthenticationMethodOIDC,
	}
	if stub.calls != 1 || stub.lookup != wantLookup {
		t.Fatalf("revalidator calls/lookup = %d / %#v", stub.calls, stub.lookup)
	}
}

func TestRuntimeDirectPlatformSessionAuthorityRoutesOnlyExactOIDCLookup(t *testing.T) {
	t.Parallel()
	sessionID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	stub := &directPlatformOIDCSessionRevalidatorStub{result: platformoidcauth.DirectSessionAuthorityResult{
		SessionID: sessionID, UserID: userID, AllowAuthority: true, AllowIdleTouch: true,
	}}
	authority := &runtimeDirectPlatformSessionAuthority{oidc: stub}
	lookup := authentication.DirectPlatformSessionAuthorityLookup{
		SessionID: sessionID, UserID: userID, AuthenticationMethod: "oidc", Audience: "api",
	}
	result, err := authority.RevalidateDirectPlatformSession(context.Background(), lookup)
	if err != nil || result.SessionID != sessionID || result.UserID != userID ||
		!result.AllowAuthority || !result.AllowIdleTouch || result.Transition != nil {
		t.Fatalf("RevalidateDirectPlatformSession() = %#v, %v", result, err)
	}
	wantLookup := platformoidcauth.DirectSessionAuthorityLookup{
		SessionID: sessionID, UserID: userID, AuthenticationMethod: "oidc", Audience: "api",
	}
	if stub.calls != 1 || stub.lookup != wantLookup {
		t.Fatalf("OIDC revalidator calls/lookup = %d / %#v", stub.calls, stub.lookup)
	}

	samlLookup := lookup
	samlLookup.AuthenticationMethod = "saml"
	if result, err = authority.RevalidateDirectPlatformSession(context.Background(), samlLookup); err == nil || result != (authentication.DirectPlatformSessionAuthorityResult{}) || stub.calls != 1 {
		t.Fatalf("SAML crossed OIDC authority = %#v, %v; calls=%d", result, err, stub.calls)
	}
}

func TestRuntimeDirectPlatformSessionAuthorityRoutesSAMLWithExactRequestAudit(t *testing.T) {
	t.Parallel()
	sessionID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	requestID := uuid.Must(uuid.NewV7())
	correlationID := uuid.Must(uuid.NewV7())
	stub := &directPlatformSAMLSessionRevalidatorStub{result: platformsamlauth.DirectSAMLSessionAuthorityOutcome{
		SessionID: identity.EntityID(sessionID), UserID: identity.EntityID(userID),
		Decision: mfa.SessionUsable, Reason: mfa.SessionReasonCurrent,
		AllowAuthority: true, AllowIdleTouch: true,
	}}
	authority := &runtimeDirectPlatformSessionAuthority{saml: stub}
	lookup := authentication.DirectPlatformSessionAuthorityLookup{
		SessionID: sessionID, UserID: userID, AuthenticationMethod: "saml", Audience: "api",
	}
	ctx, err := authentication.WithEventContext(context.Background(), authentication.EventContext{
		RequestID: requestID, CorrelationID: correlationID,
		RemoteAddress: netip.MustParseAddr("198.51.100.44"), UserAgent: "periapsis-session-test/1",
	})
	if err != nil {
		t.Fatalf("WithEventContext() error = %v", err)
	}
	result, err := authority.RevalidateDirectPlatformSession(ctx, lookup)
	if err != nil || result.SessionID != sessionID || result.UserID != userID ||
		!result.AllowAuthority || !result.AllowIdleTouch || result.Transition != nil {
		t.Fatalf("RevalidateDirectPlatformSession() = %#v, %v", result, err)
	}
	wantLookup := platformsamlauth.DirectSAMLSessionAuthorityLookup{
		SessionID: identity.EntityID(sessionID), UserID: identity.EntityID(userID),
		AuthenticationMethod: "saml", Audience: "api",
		Audit: platformsamlauth.AuditContext{
			RequestID: identity.EntityID(requestID), CorrelationID: identity.EntityID(correlationID),
			RemoteAddress: netip.MustParseAddr("198.51.100.44"), UserAgent: "periapsis-session-test/1",
		},
	}
	if stub.calls != 1 || stub.lookup != wantLookup {
		t.Fatalf("SAML revalidator calls/lookup = %d / %#v", stub.calls, stub.lookup)
	}

	if result, err = authority.RevalidateDirectPlatformSession(context.Background(), lookup); err == nil ||
		result != (authentication.DirectPlatformSessionAuthorityResult{}) || stub.calls != 1 {
		t.Fatalf("missing audit crossed SAML authority = %#v, %v; calls=%d", result, err, stub.calls)
	}
}

func TestRuntimeSessionAuthoritiesRejectTypedNilDependencies(t *testing.T) {
	t.Parallel()
	sessionID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())

	var federated *federatedSessionRevalidatorStub
	if result, err := (&runtimeFederatedSessionAuthority{revalidator: federated}).RevalidateFederatedSession(
		context.Background(),
		authentication.FederatedSessionAuthorityLookup{
			SessionID: sessionID, TenantID: tenantID, UserID: userID,
			AuthenticationMethod: "saml", Audience: "api",
		},
	); err == nil || result != (authentication.FederatedSessionAuthorityResult{}) {
		t.Fatalf("typed nil federated authority = %#v, %v", result, err)
	}

	var oidc *directPlatformOIDCSessionRevalidatorStub
	direct := &runtimeDirectPlatformSessionAuthority{oidc: oidc}
	lookup := authentication.DirectPlatformSessionAuthorityLookup{
		SessionID: sessionID, UserID: userID, AuthenticationMethod: "oidc", Audience: "api",
	}
	if result, err := direct.RevalidateDirectPlatformSession(context.Background(), lookup); err == nil ||
		result != (authentication.DirectPlatformSessionAuthorityResult{}) {
		t.Fatalf("typed nil OIDC authority = %#v, %v", result, err)
	}

	var saml *directPlatformSAMLSessionRevalidatorStub
	direct = &runtimeDirectPlatformSessionAuthority{saml: saml}
	lookup.AuthenticationMethod = "saml"
	if result, err := direct.RevalidateDirectPlatformSession(context.Background(), lookup); err == nil ||
		result != (authentication.DirectPlatformSessionAuthorityResult{}) {
		t.Fatalf("typed nil SAML authority = %#v, %v", result, err)
	}
}

func TestRuntimeFederatedSessionAuthorityRejectsCancelledContextBeforeRevalidation(t *testing.T) {
	t.Parallel()
	sessionID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	stub := &federatedSessionRevalidatorStub{result: federatedauth.SessionResult{
		SessionID: identity.EntityID(sessionID), TenantID: identity.EntityID(tenantID),
		UserID: identity.EntityID(userID), AuthenticationMethod: federatedauth.AuthenticationMethodSAML,
		Decision: mfa.SessionUsable, Reason: mfa.SessionReasonCurrent,
		AllowAuthority: true, AllowIdleTouch: true,
	}}
	authority := &runtimeFederatedSessionAuthority{revalidator: stub}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := authority.RevalidateFederatedSession(
		ctx,
		authentication.FederatedSessionAuthorityLookup{
			SessionID: sessionID, TenantID: tenantID, UserID: userID,
			AuthenticationMethod: "saml", Audience: "api",
		},
	)
	if err == nil || result != (authentication.FederatedSessionAuthorityResult{}) || stub.calls != 0 {
		t.Fatalf("cancelled federated authority = %#v, %v; calls=%d", result, err, stub.calls)
	}
}

func TestRuntimeSessionAuthoritiesRejectCancellationDuringRevalidation(t *testing.T) {
	t.Parallel()
	sessionID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())

	federatedContext, cancelFederated := context.WithCancel(context.Background())
	federated := &federatedSessionRevalidatorStub{
		result: federatedauth.SessionResult{
			SessionID: identity.EntityID(sessionID), TenantID: identity.EntityID(tenantID),
			UserID: identity.EntityID(userID), AuthenticationMethod: federatedauth.AuthenticationMethodSAML,
			Decision: mfa.SessionUsable, Reason: mfa.SessionReasonCurrent,
			AllowAuthority: true, AllowIdleTouch: true,
		},
		during: cancelFederated,
	}
	if result, err := (&runtimeFederatedSessionAuthority{revalidator: federated}).RevalidateFederatedSession(
		federatedContext,
		authentication.FederatedSessionAuthorityLookup{
			SessionID: sessionID, TenantID: tenantID, UserID: userID,
			AuthenticationMethod: "saml", Audience: "api",
		},
	); err == nil || result != (authentication.FederatedSessionAuthorityResult{}) || federated.calls != 1 {
		t.Fatalf("cancelled federated result = %#v, %v; calls=%d", result, err, federated.calls)
	}

	oidcContext, cancelOIDC := context.WithCancel(context.Background())
	oidc := &directPlatformOIDCSessionRevalidatorStub{
		result: platformoidcauth.DirectSessionAuthorityResult{
			SessionID: sessionID, UserID: userID, AllowAuthority: true, AllowIdleTouch: true,
		},
		during: cancelOIDC,
	}
	directLookup := authentication.DirectPlatformSessionAuthorityLookup{
		SessionID: sessionID, UserID: userID, AuthenticationMethod: "oidc", Audience: "api",
	}
	if result, err := (&runtimeDirectPlatformSessionAuthority{oidc: oidc}).RevalidateDirectPlatformSession(
		oidcContext, directLookup,
	); err == nil || result != (authentication.DirectPlatformSessionAuthorityResult{}) || oidc.calls != 1 {
		t.Fatalf("cancelled OIDC result = %#v, %v; calls=%d", result, err, oidc.calls)
	}

	samlBase, cancelSAML := context.WithCancel(context.Background())
	samlContext, err := authentication.WithEventContext(samlBase, authentication.EventContext{
		RequestID: uuid.Must(uuid.NewV7()), CorrelationID: uuid.Must(uuid.NewV7()),
		RemoteAddress: netip.MustParseAddr("198.51.100.45"), UserAgent: "periapsis-session-test/1",
	})
	if err != nil {
		t.Fatalf("WithEventContext() error = %v", err)
	}
	saml := &directPlatformSAMLSessionRevalidatorStub{
		result: platformsamlauth.DirectSAMLSessionAuthorityOutcome{
			SessionID: identity.EntityID(sessionID), UserID: identity.EntityID(userID),
			Decision: mfa.SessionUsable, Reason: mfa.SessionReasonCurrent,
			AllowAuthority: true, AllowIdleTouch: true,
		},
		during: cancelSAML,
	}
	directLookup.AuthenticationMethod = "saml"
	if result, callErr := (&runtimeDirectPlatformSessionAuthority{saml: saml}).RevalidateDirectPlatformSession(
		samlContext, directLookup,
	); callErr == nil || result != (authentication.DirectPlatformSessionAuthorityResult{}) || saml.calls != 1 {
		t.Fatalf("cancelled SAML result = %#v, %v; calls=%d", result, callErr, saml.calls)
	}
}

func TestRuntimeFederatedSessionAuthorityRevalidatesPasskeyProvenance(t *testing.T) {
	t.Parallel()
	sessionID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	stub := &federatedSessionRevalidatorStub{result: federatedauth.SessionResult{
		SessionID: identity.EntityID(sessionID), TenantID: identity.EntityID(tenantID),
		UserID: identity.EntityID(userID), AuthenticationMethod: federatedauth.AuthenticationMethodPasskey,
		Decision: mfa.SessionUsable, Reason: mfa.SessionReasonCurrent,
		AllowAuthority: true, AllowIdleTouch: true,
	}}
	authority := &runtimeFederatedSessionAuthority{revalidator: stub}
	result, err := authority.RevalidateFederatedSession(
		context.Background(),
		authentication.FederatedSessionAuthorityLookup{
			SessionID: sessionID, TenantID: tenantID, UserID: userID,
			AuthenticationMethod: "passkey", Audience: "api",
		},
	)
	if err != nil || !result.AllowAuthority || !result.AllowIdleTouch ||
		result.SessionID != sessionID || result.TenantID != tenantID || result.UserID != userID {
		t.Fatalf("RevalidateFederatedSession(passkey) = %#v, %v", result, err)
	}
	if stub.calls != 1 || stub.lookup != (federatedauth.SessionLookup{
		SessionID: identity.EntityID(sessionID), TenantID: identity.EntityID(tenantID), Audience: "api",
		AuthenticationMethod: federatedauth.AuthenticationMethodPasskey,
	}) {
		t.Fatalf("passkey revalidator calls/lookup = %d / %#v", stub.calls, stub.lookup)
	}
}

func TestRuntimeFederatedSessionAuthorityRejectsTransitionsAndIdentityMismatch(t *testing.T) {
	t.Parallel()
	sessionID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	lookup := authentication.FederatedSessionAuthorityLookup{
		SessionID: sessionID, TenantID: tenantID, UserID: userID,
		AuthenticationMethod: "saml", Audience: "api",
	}
	for _, testCase := range []struct {
		name      string
		result    federatedauth.SessionResult
		wantError bool
	}{
		{name: "step up without credential is rejected", result: federatedauth.SessionResult{
			SessionID: identity.EntityID(sessionID), TenantID: identity.EntityID(tenantID),
			UserID: identity.EntityID(userID), AuthenticationMethod: federatedauth.AuthenticationMethodSAML,
			Decision: mfa.SessionStepUp,
			Reason:   mfa.SessionReasonAssuranceInsufficient,
		}, wantError: true},
		{name: "missing idle permission is rejected", result: federatedauth.SessionResult{
			SessionID: identity.EntityID(sessionID), TenantID: identity.EntityID(tenantID),
			UserID: identity.EntityID(userID), AuthenticationMethod: federatedauth.AuthenticationMethodSAML,
			Decision: mfa.SessionUsable,
			Reason:   mfa.SessionReasonCurrent, AllowAuthority: true,
		}, wantError: true},
		{name: "user mismatch is rejected", result: federatedauth.SessionResult{
			SessionID: identity.EntityID(sessionID), TenantID: identity.EntityID(tenantID),
			UserID: identity.EntityID(uuid.Must(uuid.NewV7())), AuthenticationMethod: federatedauth.AuthenticationMethodSAML,
			Decision: mfa.SessionUsable,
			Reason:   mfa.SessionReasonCurrent, AllowAuthority: true, AllowIdleTouch: true,
		}, wantError: true},
		{name: "method mismatch is rejected", result: federatedauth.SessionResult{
			SessionID: identity.EntityID(sessionID), TenantID: identity.EntityID(tenantID),
			UserID: identity.EntityID(userID), AuthenticationMethod: federatedauth.AuthenticationMethodOIDC,
			Decision: mfa.SessionUsable, Reason: mfa.SessionReasonCurrent,
			AllowAuthority: true, AllowIdleTouch: true,
		}, wantError: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			authority := &runtimeFederatedSessionAuthority{revalidator: &federatedSessionRevalidatorStub{
				result: testCase.result,
			}}
			result, err := authority.RevalidateFederatedSession(context.Background(), lookup)
			if testCase.wantError {
				if err == nil || result != (authentication.FederatedSessionAuthorityResult{}) {
					t.Fatalf("RevalidateFederatedSession() = %#v, %v", result, err)
				}
				return
			}
			if err != nil || result.SessionID != sessionID || result.TenantID != tenantID ||
				result.UserID != userID || result.AllowAuthority || result.AllowIdleTouch {
				t.Fatalf("RevalidateFederatedSession() = %#v, %v", result, err)
			}
		})
	}
}

func TestRuntimeFederatedSessionAuthorityTransfersCommittedTransitionsOnce(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Millisecond)
	sessionID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	lookup := authentication.FederatedSessionAuthorityLookup{
		SessionID: sessionID, TenantID: tenantID, UserID: userID,
		AuthenticationMethod: "oidc", Audience: "api",
	}

	for _, testCase := range []struct {
		name       string
		result     func(testing.TB) federatedauth.SessionResult
		wantKind   authentication.FederatedSessionTransitionKind
		wantExpiry time.Time
	}{
		{
			name: "rotation",
			result: func(t testing.TB) federatedauth.SessionResult {
				newSessionID := identity.EntityID(uuid.Must(uuid.NewV7()))
				expiresAt := now.Add(8 * time.Hour)
				token := runtimeFederatedOpaque(0x31)
				csrf := runtimeFederatedOpaque(0x32)
				reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
					SessionID: newSessionID, FamilyID: identity.EntityID(uuid.Must(uuid.NewV7())),
					TokenDigest: sha256.Sum256(token), CSRFDigest: sha256.Sum256(csrf),
					AuthenticationMethod: mfa.SessionAuthenticationMethod(federatedauth.AuthenticationMethodOIDC),
					IdleExpiresAt:        now.Add(time.Hour), AbsoluteExpiresAt: expiresAt,
				}, now)
				if err != nil {
					t.Fatalf("session reservation: %v", err)
				}
				owned, err := federatedauth.NewSessionApplyCredentialReservation(reservation, token, csrf)
				if err != nil {
					t.Fatalf("browser credential: %v", err)
				}
				credential, released := owned.ReleaseBrowserCredential(newSessionID, identity.EntityID{})
				if !released {
					t.Fatal("release rotation credential")
				}
				return federatedauth.SessionResult{
					SessionID: identity.EntityID(sessionID), TenantID: identity.EntityID(tenantID),
					UserID: identity.EntityID(userID), AuthenticationMethod: federatedauth.AuthenticationMethodOIDC,
					Decision: mfa.SessionRotate, Reason: mfa.SessionReasonPolicyRefresh,
					NewSessionID: newSessionID, AbsoluteExpiresAt: expiresAt, Credential: credential,
				}
			},
			wantKind: authentication.FederatedSessionTransitionRotated, wantExpiry: now.Add(8 * time.Hour),
		},
		{
			name: "step up",
			result: func(t testing.TB) federatedauth.SessionResult {
				continuationID := identity.EntityID(uuid.Must(uuid.NewV7()))
				expiresAt := now.Add(5 * time.Minute)
				receipt := runtimeFederatedOpaque(0x41)
				reservation, err := federatedauth.NewPostPrimaryContinuationReservation(
					federatedauth.PostPrimaryContinuationMaterial{
						ContinuationID: continuationID, ReceiptDigest: sha256.Sum256(receipt), ExpiresAt: expiresAt,
					},
					now,
				)
				if err != nil {
					t.Fatalf("continuation reservation: %v", err)
				}
				owned, err := federatedauth.NewContinuationApplyCredentialReservation(reservation, receipt)
				if err != nil {
					t.Fatalf("continuation credential: %v", err)
				}
				credential, released := owned.ReleaseBrowserCredential(identity.EntityID{}, continuationID)
				if !released {
					t.Fatal("release continuation credential")
				}
				return federatedauth.SessionResult{
					SessionID: identity.EntityID(sessionID), TenantID: identity.EntityID(tenantID),
					UserID: identity.EntityID(userID), AuthenticationMethod: federatedauth.AuthenticationMethodOIDC,
					Decision: mfa.SessionStepUp, Reason: mfa.SessionReasonAssuranceInsufficient,
					ContinuationID: continuationID, Credential: credential,
				}
			},
			wantKind: authentication.FederatedSessionTransitionStepUp, wantExpiry: now.Add(5 * time.Minute),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			result := testCase.result(t)
			credential := result.Credential
			authority := &runtimeFederatedSessionAuthority{revalidator: &federatedSessionRevalidatorStub{result: result}}
			mapped, err := authority.RevalidateFederatedSession(context.Background(), lookup)
			if err != nil || mapped.Transition == nil || mapped.AllowAuthority || mapped.AllowIdleTouch {
				t.Fatalf("RevalidateFederatedSession() = %#v, %v", mapped, err)
			}
			material, consumed := mapped.Transition.Consume()
			if !consumed || material.Kind != testCase.wantKind || !material.ExpiresAt.Equal(testCase.wantExpiry) {
				t.Fatalf("transition material = %s, consumed=%t", material, consumed)
			}
			material.Destroy()
			if _, consumed = mapped.Transition.Consume(); consumed {
				t.Fatal("transition was consumable twice")
			}
			if _, consumed = credential.Consume(); consumed {
				t.Fatal("source browser credential remained consumable")
			}
		})
	}
}

func TestRuntimeLDAPSessionAuthorityTransfersAuthorizationRotationOnce(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Millisecond)
	sessionID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	lookup := authentication.FederatedSessionAuthorityLookup{
		SessionID: sessionID, TenantID: tenantID, UserID: userID,
		AuthenticationMethod: "ldap", Audience: "api",
	}

	for _, testCase := range []struct {
		name       string
		result     func(testing.TB) federatedauth.SessionResult
		wantKind   authentication.FederatedSessionTransitionKind
		wantExpiry time.Time
	}{
		{
			name: "rotation",
			result: func(t testing.TB) federatedauth.SessionResult {
				newSessionID := identity.EntityID(uuid.Must(uuid.NewV7()))
				expiresAt := now.Add(8 * time.Hour)
				token := runtimeFederatedOpaque(0x31)
				csrf := runtimeFederatedOpaque(0x32)
				reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
					SessionID: newSessionID, FamilyID: identity.EntityID(uuid.Must(uuid.NewV7())),
					TokenDigest: sha256.Sum256(token), CSRFDigest: sha256.Sum256(csrf),
					AuthenticationMethod: mfa.SessionAuthenticationMethod(federatedauth.AuthenticationMethodLDAP),
					IdleExpiresAt:        now.Add(time.Hour), AbsoluteExpiresAt: expiresAt,
				}, now)
				if err != nil {
					t.Fatalf("session reservation: %v", err)
				}
				owned, err := federatedauth.NewSessionApplyCredentialReservation(reservation, token, csrf)
				if err != nil {
					t.Fatalf("browser credential: %v", err)
				}
				credential, released := owned.ReleaseBrowserCredential(newSessionID, identity.EntityID{})
				if !released {
					t.Fatal("release rotation credential")
				}
				return federatedauth.SessionResult{
					SessionID: identity.EntityID(sessionID), TenantID: identity.EntityID(tenantID),
					UserID: identity.EntityID(userID), AuthenticationMethod: federatedauth.AuthenticationMethodLDAP,
					Decision: mfa.SessionRotate, Reason: mfa.SessionReasonAuthorizationRefresh,
					NewSessionID: newSessionID, AbsoluteExpiresAt: expiresAt, Credential: credential,
				}
			},
			wantKind: authentication.FederatedSessionTransitionRotated, wantExpiry: now.Add(8 * time.Hour),
		},
		{
			name: "step up",
			result: func(t testing.TB) federatedauth.SessionResult {
				continuationID := identity.EntityID(uuid.Must(uuid.NewV7()))
				expiresAt := now.Add(5 * time.Minute)
				receipt := runtimeFederatedOpaque(0x41)
				reservation, err := federatedauth.NewPostPrimaryContinuationReservation(
					federatedauth.PostPrimaryContinuationMaterial{
						ContinuationID: continuationID, ReceiptDigest: sha256.Sum256(receipt), ExpiresAt: expiresAt,
					},
					now,
				)
				if err != nil {
					t.Fatalf("continuation reservation: %v", err)
				}
				owned, err := federatedauth.NewContinuationApplyCredentialReservation(reservation, receipt)
				if err != nil {
					t.Fatalf("continuation credential: %v", err)
				}
				credential, released := owned.ReleaseBrowserCredential(identity.EntityID{}, continuationID)
				if !released {
					t.Fatal("release continuation credential")
				}
				return federatedauth.SessionResult{
					SessionID: identity.EntityID(sessionID), TenantID: identity.EntityID(tenantID),
					UserID: identity.EntityID(userID), AuthenticationMethod: federatedauth.AuthenticationMethodLDAP,
					Decision: mfa.SessionStepUp, Reason: mfa.SessionReasonAssuranceInsufficient,
					ContinuationID: continuationID, Credential: credential,
				}
			},
			wantKind: authentication.FederatedSessionTransitionStepUp, wantExpiry: now.Add(5 * time.Minute),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			result := testCase.result(t)
			credential := result.Credential
			authority := &runtimeFederatedSessionAuthority{revalidator: &federatedSessionRevalidatorStub{result: result}}
			mapped, err := authority.RevalidateFederatedSession(context.Background(), lookup)
			if err != nil || mapped.Transition == nil || mapped.AllowAuthority || mapped.AllowIdleTouch {
				t.Fatalf("RevalidateFederatedSession() = %#v, %v", mapped, err)
			}
			material, consumed := mapped.Transition.Consume()
			if !consumed || material.Kind != testCase.wantKind || !material.ExpiresAt.Equal(testCase.wantExpiry) {
				t.Fatalf("transition material = %s, consumed=%t", material, consumed)
			}
			material.Destroy()
			if _, consumed = mapped.Transition.Consume(); consumed {
				t.Fatal("transition was consumable twice")
			}
			if _, consumed = credential.Consume(); consumed {
				t.Fatal("source browser credential remained consumable")
			}
		})
	}
}

func TestRuntimeFederatedSessionAuthorityRejectsDirectContinuationRelabeling(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Millisecond)
	sessionID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	continuationID := identity.EntityID(uuid.Must(uuid.NewV7()))
	receipt := runtimeFederatedOpaque(0x49)
	digest, err := federatedauth.ContinuationReceiptDigest(
		federatedauth.ContinuationAuthorityDirectPlatformOIDC, continuationID, receipt,
	)
	if err != nil {
		t.Fatalf("direct receipt digest: %v", err)
	}
	continuation, err := federatedauth.NewPostPrimaryContinuationReservation(
		federatedauth.PostPrimaryContinuationMaterial{
			ContinuationID: continuationID,
			Authority:      federatedauth.ContinuationAuthorityDirectPlatformOIDC,
			ReceiptDigest:  digest,
			ExpiresAt:      now.Add(5 * time.Minute),
		},
		now,
	)
	if err != nil {
		t.Fatalf("direct continuation reservation: %v", err)
	}
	owned, err := federatedauth.NewContinuationApplyCredentialReservation(continuation, receipt)
	if err != nil {
		t.Fatalf("direct browser credential: %v", err)
	}
	credential, released := owned.ReleaseBrowserCredential(identity.EntityID{}, continuationID)
	if !released {
		t.Fatal("release direct browser credential")
	}
	result := federatedauth.SessionResult{
		SessionID: identity.EntityID(sessionID), TenantID: identity.EntityID(tenantID),
		UserID: identity.EntityID(userID), AuthenticationMethod: federatedauth.AuthenticationMethodOIDC,
		Decision: mfa.SessionStepUp, Reason: mfa.SessionReasonAssuranceInsufficient,
		ContinuationID: continuationID, Credential: credential,
	}
	lookup := authentication.FederatedSessionAuthorityLookup{
		SessionID: sessionID, TenantID: tenantID, UserID: userID,
		AuthenticationMethod: "oidc", Audience: "api",
	}
	authority := &runtimeFederatedSessionAuthority{
		revalidator: &federatedSessionRevalidatorStub{result: result},
	}
	if mapped, mapErr := authority.RevalidateFederatedSession(context.Background(), lookup); mapErr == nil || mapped != (authentication.FederatedSessionAuthorityResult{}) {
		t.Fatalf("direct continuation was relabeled: %#v, %v", mapped, mapErr)
	}
	if _, consumed := credential.Consume(); consumed {
		t.Fatal("rejected direct credential remained consumable")
	}
}

func runtimeFederatedOpaque(fill byte) []byte {
	return []byte(base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{fill}), 32))))
}

func TestRuntimeFederatedSessionAuthorityRejectsMalformedLookupBeforeDependency(t *testing.T) {
	t.Parallel()
	stub := &federatedSessionRevalidatorStub{}
	authority := &runtimeFederatedSessionAuthority{revalidator: stub}
	if result, err := authority.RevalidateFederatedSession(
		context.Background(), authentication.FederatedSessionAuthorityLookup{},
	); err == nil || result != (authentication.FederatedSessionAuthorityResult{}) || stub.calls != 0 {
		t.Fatalf("RevalidateFederatedSession() = %#v, %v; calls = %d", result, err, stub.calls)
	}
}

func TestDFIRDependenciesParticipateInReadinessWithoutInvalidatingAuthentication(t *testing.T) {
	invalidations := 0
	checks := (&protectedConfigReadiness{
		database:              staticReadiness{},
		authentication:        protectedVerifierStub{invalidations: &invalidations},
		credentialKeyring:     credentialVerifierStub{},
		identityKeyring:       identityVerifierStub{},
		notificationKeyring:   notificationVerifierStub{},
		dfirObjectStorage:     dependencyVerifierStub{err: errors.New("bucket unavailable")},
		dfirMalwareScanner:    dependencyVerifierStub{err: errors.New("scanner unavailable")},
		ticketOperations:      ticketOperationsVerifierStub{},
		platformLocalAccounts: platformLocalAccountVerifierStub{},
	}).Check(context.Background())
	if len(checks) != 9 || checks[5].Name != "dfir_object_storage" || checks[5].Ready ||
		checks[6].Name != "dfir_malware_scanner" || checks[6].Ready || !checks[7].Ready || !checks[8].Ready || invalidations != 0 {
		t.Fatalf("readiness checks = %#v, invalidations = %d", checks, invalidations)
	}
}

func TestConcurrentReadinessChecksReuseOneWholeDependencySnapshot(t *testing.T) {
	databaseCalls := 0
	verifierCalls := 0
	credentialCalls := 0
	identityCalls := 0
	notificationCalls := 0
	storageCalls := 0
	scannerCalls := 0
	ticketCalls := 0
	localAccountCalls := 0
	checker := &protectedConfigReadiness{
		database:              countingReadiness{calls: &databaseCalls},
		authentication:        protectedVerifierStub{calls: &verifierCalls},
		credentialKeyring:     credentialVerifierStub{calls: &credentialCalls},
		dfirObjectStorage:     dependencyVerifierStub{calls: &storageCalls},
		dfirMalwareScanner:    dependencyVerifierStub{calls: &scannerCalls},
		identityKeyring:       identityVerifierStub{calls: &identityCalls},
		notificationKeyring:   notificationVerifierStub{calls: &notificationCalls},
		ticketOperations:      ticketOperationsVerifierStub{calls: &ticketCalls},
		platformLocalAccounts: platformLocalAccountVerifierStub{calls: &localAccountCalls},
	}
	const callers = 24
	var group sync.WaitGroup
	group.Add(callers)
	for range callers {
		go func() {
			defer group.Done()
			checks := checker.Check(context.Background())
			if len(checks) != 9 || !checks[0].Ready || !checks[1].Ready || !checks[2].Ready || !checks[3].Ready || !checks[4].Ready || !checks[5].Ready || !checks[6].Ready || !checks[7].Ready || !checks[8].Ready {
				t.Errorf("checks = %#v", checks)
			}
		}()
	}
	group.Wait()
	if databaseCalls != 1 || verifierCalls != 1 || credentialCalls != 1 || identityCalls != 1 || notificationCalls != 1 || storageCalls != 1 || scannerCalls != 1 || ticketCalls != 1 || localAccountCalls != 1 {
		t.Fatalf(
			"concurrent readiness calls = database %d, auth %d, credential %d, identity %d, notification %d, storage %d, scanner %d, ticket %d, local account %d; want one each",
			databaseCalls, verifierCalls, credentialCalls, identityCalls, notificationCalls, storageCalls, scannerCalls, ticketCalls, localAccountCalls,
		)
	}
}

func TestDatabasePoolConfigPinsUTCRuntimeParameters(t *testing.T) {
	want := map[string]string{
		"application_name":                    "periapsis-api",
		"timezone":                            "UTC",
		"statement_timeout":                   "1500",
		"idle_in_transaction_session_timeout": "3000",
	}
	tests := []struct {
		name        string
		databaseURL string
	}{
		{
			name: "URL DSN",
			databaseURL: "postgresql://api@localhost:5432/periapsis?sslmode=disable" +
				"&application_name=untrusted&Application_Name=also-untrusted" +
				"&timezone=Asia%2FTokyo&TimeZone=Europe%2FRome" +
				"&statement_timeout=1&Statement_Timeout=2" +
				"&idle_in_transaction_session_timeout=3&Idle_In_Transaction_Session_Timeout=4",
		},
		{
			name: "keyword DSN",
			databaseURL: "host=localhost user=api dbname=periapsis sslmode=disable " +
				"application_name=untrusted Application_Name=also-untrusted " +
				"timezone=Asia/Tokyo TimeZone=Europe/Rome " +
				"statement_timeout=1 Statement_Timeout=2 " +
				"idle_in_transaction_session_timeout=3 Idle_In_Transaction_Session_Timeout=4",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := databasePoolConfig(test.databaseURL, 1500*time.Millisecond)
			if err != nil {
				t.Fatalf("databasePoolConfig() error = %v", err)
			}
			assertPinnedRuntimeParameters(t, config.ConnConfig.RuntimeParams, want)
		})
	}
}

func assertPinnedRuntimeParameters(t *testing.T, runtimeParams, want map[string]string) {
	t.Helper()
	for name, value := range want {
		matchingNames := 0
		for actualName, actualValue := range runtimeParams {
			if !strings.EqualFold(actualName, name) {
				continue
			}
			matchingNames++
			if actualName != name || actualValue != value {
				t.Fatalf(
					"runtime parameter %q = %q, want canonical %q = %q",
					actualName, actualValue, name, value,
				)
			}
		}
		if matchingNames != 1 {
			t.Fatalf("case-insensitive runtime parameter count for %q = %d, want 1", name, matchingNames)
		}
	}
}

func TestRuntimeDatabaseRoleRejectsEveryAuthorityBeyondAPI(t *testing.T) {
	valid := runtimeRoleMetadata{name: "periapsis_api_login", apiMember: true}
	if err := validateRuntimeRoleMetadata(valid); err != nil {
		t.Fatalf("valid API role rejected: %v", err)
	}

	tests := map[string]runtimeRoleMetadata{
		"missing api membership": {name: "login"},
		"superuser":              {name: "login", apiMember: true, superuser: true},
		"create database":        {name: "login", apiMember: true, createDB: true},
		"create role":            {name: "login", apiMember: true, createRole: true},
		"replication":            {name: "login", apiMember: true, replication: true},
		"bypass rls":             {name: "login", apiMember: true, bypassRLS: true},
		"migrator membership": {
			name: "login", apiMember: true,
			incompatibleMemberships: []string{"periapsis_migrator"},
		},
		"nested unrelated membership": {
			name: "login", apiMember: true,
			incompatibleMemberships: []string{"indirect_privileged_role"},
		},
	}
	for name, metadata := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateRuntimeRoleMetadata(metadata); err == nil {
				t.Fatal("unsafe runtime role accepted")
			}
		})
	}
}

func TestClearAuthenticationSourceConfigWipesBackingMaterial(t *testing.T) {
	t.Parallel()

	masterKey := []byte("0123456789abcdef0123456789abcdef")
	bootstrapDigest := []byte("abcdef0123456789abcdef0123456789")
	cfg := apiconfig.Config{MasterKey: masterKey, BootstrapTokenDigest: bootstrapDigest}

	clearAuthenticationSourceConfig(&cfg)

	if cfg.MasterKey != nil || cfg.BootstrapTokenDigest != nil {
		t.Fatalf("secret config fields were retained: %#v", cfg)
	}
	for index, value := range append(masterKey, bootstrapDigest...) {
		if value != 0 {
			t.Fatalf("secret backing byte %d was not cleared", index)
		}
	}
}

func TestClearNotifierPreviewSourceConfigWipesBackingMaterial(t *testing.T) {
	t.Parallel()

	previewToken := []byte("notification-preview-token-material")
	cfg := apiconfig.Config{NotifierPreviewToken: previewToken}

	clearNotifierPreviewSourceConfig(&cfg)

	if cfg.NotifierPreviewToken != nil {
		t.Fatal("notifier preview token remains reachable from configuration")
	}
	for index, value := range previewToken {
		if value != 0 {
			t.Fatalf("notifier preview token backing byte %d was not cleared", index)
		}
	}
}
