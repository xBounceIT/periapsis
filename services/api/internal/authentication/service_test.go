package authentication

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

type repositoryStub struct {
	verifyProtectedConfig  func(context.Context, []byte, []byte) (bool, error)
	reserveBootstrap       func(context.Context, ReserveBootstrapParams) error
	getBootstrapEnrollment func(context.Context, []byte, []byte, time.Time) (StoredBootstrapEnrollment, error)
	confirmBootstrap       func(context.Context, ConfirmBootstrapParams) (Session, error)
	admitRateLimits        func(context.Context, AdmitRateLimitsParams) (time.Time, error)
	checkRateLimit         func(context.Context, []RateLimitKey, time.Time) (time.Time, error)
	recordAuthFailure      func(context.Context, RecordAuthFailureParams) (time.Time, error)
	recordPasswordFailure  func(context.Context, RecordPasswordFailureParams) error
	recordBootstrapFailure func(context.Context, RecordBootstrapFailureParams) (time.Time, error)
	recordMFAFailure       func(context.Context, RecordMFAFailureParams) (time.Time, error)
	findLocalCredential    func(context.Context, string) (LocalCredential, error)
	createMFAChallenge     func(context.Context, CreateMFAChallengeParams) error
	getMFAChallenge        func(context.Context, []byte, time.Time) (StoredMFAChallenge, error)
	completeTOTPChallenge  func(context.Context, CompleteTOTPParams) (Session, error)
	completeRecovery       func(context.Context, CompleteRecoveryParams) (Session, error)
	resolveSession         func(context.Context, []byte, time.Time) (Session, error)
	rotateSession          func(context.Context, RotateSessionParams) (Session, error)
	touchSession           func(context.Context, []byte, time.Time, time.Time) error
	revokeCurrentSession   func(context.Context, uuid.UUID, uuid.UUID, EventContext) error
	listSessions           func(context.Context, ListSessionsParams) ([]SessionSummary, error)
	revokeSession          func(context.Context, uuid.UUID, uuid.UUID, EventContext) error
	listTenantMemberships  func(context.Context, ListTenantMembershipsParams) ([]TenantMembership, error)
	switchActiveTenant     func(context.Context, SwitchTenantParams) (Session, error)
}

func (s *repositoryStub) VerifyProtectedConfiguration(ctx context.Context, authority, verifier []byte) (bool, error) {
	if s.verifyProtectedConfig != nil {
		return s.verifyProtectedConfig(ctx, authority, verifier)
	}
	return false, nil
}
func (s *repositoryStub) ReserveBootstrap(ctx context.Context, params ReserveBootstrapParams) error {
	if s.reserveBootstrap != nil {
		return s.reserveBootstrap(ctx, params)
	}
	return ErrNotFound
}
func (s *repositoryStub) GetBootstrapEnrollment(ctx context.Context, authority, enrollment []byte, now time.Time) (StoredBootstrapEnrollment, error) {
	if s.getBootstrapEnrollment != nil {
		return s.getBootstrapEnrollment(ctx, authority, enrollment, now)
	}
	return StoredBootstrapEnrollment{}, ErrNotFound
}
func (s *repositoryStub) ConfirmBootstrap(ctx context.Context, params ConfirmBootstrapParams) (Session, error) {
	if s.confirmBootstrap != nil {
		return s.confirmBootstrap(ctx, params)
	}
	return Session{}, ErrNotFound
}
func (s *repositoryStub) AdmitRateLimits(ctx context.Context, params AdmitRateLimitsParams) (time.Time, error) {
	if s.admitRateLimits != nil {
		return s.admitRateLimits(ctx, params)
	}
	return time.Time{}, nil
}
func (s *repositoryStub) CheckRateLimit(ctx context.Context, keys []RateLimitKey, now time.Time) (time.Time, error) {
	if s.checkRateLimit != nil {
		return s.checkRateLimit(ctx, keys, now)
	}
	return time.Time{}, nil
}
func (s *repositoryStub) RecordAuthFailure(ctx context.Context, params RecordAuthFailureParams) (time.Time, error) {
	if s.recordAuthFailure != nil {
		return s.recordAuthFailure(ctx, params)
	}
	return time.Time{}, nil
}
func (s *repositoryStub) RecordPasswordFailure(ctx context.Context, params RecordPasswordFailureParams) error {
	if s.recordPasswordFailure != nil {
		return s.recordPasswordFailure(ctx, params)
	}
	return nil
}
func (s *repositoryStub) RecordBootstrapFailure(ctx context.Context, params RecordBootstrapFailureParams) (time.Time, error) {
	if s.recordBootstrapFailure != nil {
		return s.recordBootstrapFailure(ctx, params)
	}
	return time.Time{}, nil
}
func (s *repositoryStub) RecordMFAFailure(ctx context.Context, params RecordMFAFailureParams) (time.Time, error) {
	if s.recordMFAFailure != nil {
		return s.recordMFAFailure(ctx, params)
	}
	return time.Time{}, nil
}
func (s *repositoryStub) FindLocalCredential(ctx context.Context, email string) (LocalCredential, error) {
	if s.findLocalCredential != nil {
		return s.findLocalCredential(ctx, email)
	}
	return LocalCredential{}, ErrNotFound
}
func (s *repositoryStub) CreateMFAChallenge(ctx context.Context, params CreateMFAChallengeParams) error {
	if s.createMFAChallenge != nil {
		return s.createMFAChallenge(ctx, params)
	}
	return ErrNotFound
}
func (s *repositoryStub) GetMFAChallenge(ctx context.Context, token []byte, now time.Time) (StoredMFAChallenge, error) {
	if s.getMFAChallenge != nil {
		return s.getMFAChallenge(ctx, token, now)
	}
	return StoredMFAChallenge{}, ErrNotFound
}
func (s *repositoryStub) CompleteTOTPChallenge(ctx context.Context, params CompleteTOTPParams) (Session, error) {
	if s.completeTOTPChallenge != nil {
		return s.completeTOTPChallenge(ctx, params)
	}
	return Session{}, ErrNotFound
}
func (s *repositoryStub) CompleteRecoveryChallenge(ctx context.Context, params CompleteRecoveryParams) (Session, error) {
	if s.completeRecovery != nil {
		return s.completeRecovery(ctx, params)
	}
	return Session{}, ErrNotFound
}
func (s *repositoryStub) ResolveSession(ctx context.Context, digest []byte, now time.Time) (Session, error) {
	if s.resolveSession != nil {
		return s.resolveSession(ctx, digest, now)
	}
	return Session{}, ErrNotFound
}
func (s *repositoryStub) RotateSession(ctx context.Context, params RotateSessionParams) (Session, error) {
	if s.rotateSession != nil {
		return s.rotateSession(ctx, params)
	}
	return Session{}, ErrNotFound
}
func (s *repositoryStub) TouchSession(ctx context.Context, tokenDigest []byte, now, idle time.Time) error {
	if s.touchSession != nil {
		return s.touchSession(ctx, tokenDigest, now, idle)
	}
	return nil
}
func (s *repositoryStub) RevokeCurrentSession(ctx context.Context, userID, sessionID uuid.UUID, event EventContext) error {
	if s.revokeCurrentSession != nil {
		return s.revokeCurrentSession(ctx, userID, sessionID, event)
	}
	return ErrNotFound
}
func (s *repositoryStub) ListSessions(ctx context.Context, params ListSessionsParams) ([]SessionSummary, error) {
	if s.listSessions != nil {
		return s.listSessions(ctx, params)
	}
	return nil, nil
}
func (s *repositoryStub) RevokeSession(ctx context.Context, userID, targetID uuid.UUID, event EventContext) error {
	if s.revokeSession != nil {
		return s.revokeSession(ctx, userID, targetID, event)
	}
	return ErrNotFound
}
func (s *repositoryStub) ListTenantMemberships(ctx context.Context, params ListTenantMembershipsParams) ([]TenantMembership, error) {
	if s.listTenantMemberships != nil {
		return s.listTenantMemberships(ctx, params)
	}
	return nil, nil
}
func (s *repositoryStub) SwitchActiveTenant(ctx context.Context, params SwitchTenantParams) (Session, error) {
	if s.switchActiveTenant != nil {
		return s.switchActiveTenant(ctx, params)
	}
	return Session{}, ErrNotFound
}

type passwordEngineStub struct {
	verifyInputs []string
}

type blockingPasswordEngine struct {
	entered chan struct{}
	release chan struct{}
}

type blockingPasswordHashEngine struct {
	entered chan struct{}
	release chan struct{}
}

func (s *blockingPasswordHashEngine) Hash(value string) (string, error) {
	if value == "periapsis-enumeration-resistant-dummy-password" {
		return "dummy-hash", nil
	}
	s.entered <- struct{}{}
	<-s.release
	return "password-hash", nil
}
func (*blockingPasswordHashEngine) Verify(string, string) bool { return false }

func (s *blockingPasswordEngine) Hash(string) (string, error) { return "dummy-hash", nil }
func (s *blockingPasswordEngine) Verify(string, string) bool {
	s.entered <- struct{}{}
	<-s.release
	return true
}

func (s *passwordEngineStub) Hash(value string) (string, error) { return "hash:" + value, nil }
func (s *passwordEngineStub) Verify(value, encoded string) bool {
	s.verifyInputs = append(s.verifyInputs, value)
	return encoded == "valid-hash" && value == "valid-password-value"
}

type tokenSourceStub struct{}

func (tokenSourceStub) Opaque() (string, error) { return validTestToken(0x42), nil }
func (tokenSourceStub) RecoveryCode() (string, []byte, error) {
	code := strings.Repeat("A", 52)
	return code, digest(code), nil
}

type federatedSessionAuthorityStub struct {
	result FederatedSessionAuthorityResult
	err    error
	calls  int
	lookup FederatedSessionAuthorityLookup
}

func (stub *federatedSessionAuthorityStub) RevalidateFederatedSession(
	_ context.Context,
	lookup FederatedSessionAuthorityLookup,
) (FederatedSessionAuthorityResult, error) {
	stub.calls++
	stub.lookup = lookup
	return stub.result, stub.err
}

type totpEngineStub struct {
	validateError error
	counter       int64
}

func (totpEngineStub) Generate(email string) (string, string, error) {
	return "TOTPSECRET", "otpauth://totp/Periapsis:" + email, nil
}
func (s totpEngineStub) Validate(string, string, time.Time, int64) (int64, error) {
	return s.counter, s.validateError
}

type secretCryptorStub struct{}

func (secretCryptorStub) EncryptTOTP(context, secret string) (EncryptedSecret, error) {
	return EncryptedSecret{Ciphertext: []byte(secret), Nonce: []byte("nonce"), AAD: []byte(context), KeyVersion: 1}, nil
}
func (secretCryptorStub) DecryptTOTP(_ string, encrypted EncryptedSecret) (string, error) {
	return string(encrypted.Ciphertext), nil
}

func TestNewServiceRejectsMissingRateKeyAndInvalidExpiryOrder(t *testing.T) {
	base := ServiceOptions{
		Repository: &repositoryStub{}, Passwords: &passwordEngineStub{}, Tokens: tokenSourceStub{},
		TOTP: totpEngineStub{}, Cipher: secretCryptorStub{}, BootstrapEnrollmentTimeout: time.Minute,
		MFAChallengeTimeout: time.Minute, SessionIdleTimeout: 30 * time.Minute,
		SessionAbsoluteTimeout: time.Hour,
	}
	if _, err := NewService(base); err == nil {
		t.Fatal("NewService() accepted missing rate-limit key material")
	}
	base.RateLimitKeyMaterial = bytes.Repeat([]byte{0x42}, 32)
	base.SessionAbsoluteTimeout = 10 * time.Minute
	if _, err := NewService(base); err == nil {
		t.Fatal("NewService() accepted an absolute expiry below idle expiry")
	}
	base.SessionAbsoluteTimeout = time.Hour
	base.ProtectedConfigurationTimeout = 31 * time.Second
	if _, err := NewService(base); err == nil {
		t.Fatal("NewService() accepted an unbounded protected configuration timeout")
	}
}

func TestNewServiceBlocksRequestsUntilForcedReadinessSucceeds(t *testing.T) {
	var verificationCalls atomic.Int32
	var resolveCalls atomic.Int32
	repository := &repositoryStub{
		verifyProtectedConfig: func(context.Context, []byte, []byte) (bool, error) {
			verificationCalls.Add(1)
			return false, nil
		},
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			resolveCalls.Add(1)
			return Session{}, ErrNotFound
		},
	}
	service := newAuthenticationServiceAtDefaultState(
		t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("deployment-authority"),
		time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
	)

	if _, err := service.Authenticate(context.Background(), validTestToken(0x5f)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Authenticate() before readiness error = %v, want unavailable", err)
	}
	if available, err := service.BootstrapStatus(context.Background()); available || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("BootstrapStatus() before readiness = (%v, %v), want unavailable", available, err)
	}
	if verificationCalls.Load() != 0 || resolveCalls.Load() != 0 {
		t.Fatalf("pre-readiness repository calls = verifier %d, resolve %d", verificationCalls.Load(), resolveCalls.Load())
	}

	if err := service.VerifyProtectedConfiguration(context.Background()); err != nil {
		t.Fatalf("VerifyProtectedConfiguration() error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), validTestToken(0x5f)); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("Authenticate() after readiness error = %v", err)
	}
	if verificationCalls.Load() != 1 || resolveCalls.Load() != 1 {
		t.Fatalf("post-readiness repository calls = verifier %d, resolve %d", verificationCalls.Load(), resolveCalls.Load())
	}
}

func TestBootstrapStatusFailsClosedWithoutAuthoritySecret(t *testing.T) {
	service := newAuthenticationServiceDefaultState(t, &repositoryStub{}, &passwordEngineStub{}, totpEngineStub{}, nil)
	available, err := service.BootstrapStatus(context.Background())
	if available || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("BootstrapStatus() = (%v, %v), want (false, unavailable)", available, err)
	}
}

func TestBootstrapMutationsFailClosedWithoutAuthoritySecret(t *testing.T) {
	repository := &repositoryStub{
		checkRateLimit: func(context.Context, []RateLimitKey, time.Time) (time.Time, error) {
			t.Fatal("missing bootstrap authority reached persistence")
			return time.Time{}, nil
		},
	}
	service := newAuthenticationServiceDefaultState(t, repository, &passwordEngineStub{}, totpEngineStub{}, nil)

	if _, err := service.StartBootstrap(
		context.Background(), "provided-but-unconfigured", "admin@example.test", testEvent(),
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("StartBootstrap() error = %v, want unavailable", err)
	}
	if _, err := service.ConfirmBootstrap(
		context.Background(), "provided-but-unconfigured", BootstrapConfirmation{Event: testEvent()},
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ConfirmBootstrap() error = %v, want unavailable", err)
	}
}

func TestProtectedConfigurationGuardsEveryAuthenticationEntryPointBeforeWork(t *testing.T) {
	var persistenceCalls atomic.Int32
	repository := &repositoryStub{
		verifyProtectedConfig: func(context.Context, []byte, []byte) (bool, error) {
			return false, ErrInvalidAuthentication
		},
		admitRateLimits: func(context.Context, AdmitRateLimitsParams) (time.Time, error) {
			persistenceCalls.Add(1)
			return time.Time{}, nil
		},
		checkRateLimit: func(context.Context, []RateLimitKey, time.Time) (time.Time, error) {
			persistenceCalls.Add(1)
			return time.Time{}, nil
		},
		recordAuthFailure: func(context.Context, RecordAuthFailureParams) (time.Time, error) {
			persistenceCalls.Add(1)
			return time.Time{}, nil
		},
		getBootstrapEnrollment: func(context.Context, []byte, []byte, time.Time) (StoredBootstrapEnrollment, error) {
			persistenceCalls.Add(1)
			return StoredBootstrapEnrollment{}, ErrNotFound
		},
		getMFAChallenge: func(context.Context, []byte, time.Time) (StoredMFAChallenge, error) {
			persistenceCalls.Add(1)
			return StoredMFAChallenge{}, ErrNotFound
		},
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			persistenceCalls.Add(1)
			return Session{}, ErrNotFound
		},
	}
	passwords := &passwordEngineStub{}
	service := newAuthenticationServiceDefaultState(
		t, repository, passwords, totpEngineStub{}, digest("deployment-authority"),
	)
	if err := service.VerifyProtectedConfiguration(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("VerifyProtectedConfiguration() error = %v, want unavailable", err)
	}

	operations := map[string]func() error{
		"start bootstrap": func() error {
			_, err := service.StartBootstrap(
				context.Background(), "invalid-authority", "admin@example.test", testEvent(),
			)
			return err
		},
		"confirm bootstrap": func() error {
			_, err := service.ConfirmBootstrap(
				context.Background(), "invalid-authority", BootstrapConfirmation{
					EnrollmentToken: validTestToken(0x61), Event: testEvent(),
				},
			)
			return err
		},
		"start password login": func() error {
			_, err := service.StartPasswordLogin(
				context.Background(), "admin@example.test", "password-value", testEvent(),
			)
			return err
		},
		"complete mfa": func() error {
			_, err := service.CompleteMFA(
				context.Background(), validTestToken(0x62), "totp", "123456", testEvent(),
			)
			return err
		},
		"authenticate": func() error {
			_, err := service.Authenticate(context.Background(), validTestToken(0x63))
			return err
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			if err := operation(); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("operation error = %v, want unavailable", err)
			}
		})
	}
	if calls := persistenceCalls.Load(); calls != 0 {
		t.Fatalf("guarded repository work calls = %d, want zero", calls)
	}
	if len(passwords.verifyInputs) != 0 {
		t.Fatalf("password verifier inputs = %#v, want no KDF work", passwords.verifyInputs)
	}
}

func TestProtectedConfigurationMatchPermitsStatusAndBootstrapReservation(t *testing.T) {
	authority := "deployment-authority"
	var reservations atomic.Int32
	repository := &repositoryStub{
		verifyProtectedConfig: func(context.Context, []byte, []byte) (bool, error) {
			return true, nil
		},
		reserveBootstrap: func(context.Context, ReserveBootstrapParams) error {
			reservations.Add(1)
			return nil
		},
	}
	service := newAuthenticationServiceAtDefaultState(
		t, repository, &passwordEngineStub{}, totpEngineStub{}, digest(authority),
		time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
	)
	if err := service.VerifyProtectedConfiguration(context.Background()); err != nil {
		t.Fatalf("VerifyProtectedConfiguration() error = %v", err)
	}
	available, err := service.BootstrapStatus(context.Background())
	if err != nil || !available {
		t.Fatalf("BootstrapStatus() = (%v, %v), want available", available, err)
	}
	if _, err := service.StartBootstrap(
		context.Background(), authority, "admin@example.test", testEvent(),
	); err != nil {
		t.Fatalf("StartBootstrap() error = %v", err)
	}
	if reservations.Load() != 1 {
		t.Fatalf("bootstrap reservations = %d, want one", reservations.Load())
	}
}

func TestSuccessfulBootstrapCompletionImmediatelyUpdatesCachedAvailability(t *testing.T) {
	var verificationCalls atomic.Int32
	repository := &repositoryStub{
		verifyProtectedConfig: func(context.Context, []byte, []byte) (bool, error) {
			verificationCalls.Add(1)
			return true, nil
		},
	}
	service := newAuthenticationServiceAtDefaultState(
		t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("deployment-authority"),
		time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
	)
	if err := service.VerifyProtectedConfiguration(context.Background()); err != nil {
		t.Fatalf("VerifyProtectedConfiguration() error = %v", err)
	}
	if available, err := service.BootstrapStatus(context.Background()); err != nil || !available {
		t.Fatalf("initial BootstrapStatus() = (%v, %v), want available", available, err)
	}
	service.markBootstrapCompleted()
	if available, err := service.BootstrapStatus(context.Background()); err != nil || available {
		t.Fatalf("completed BootstrapStatus() = (%v, %v), want unavailable without error", available, err)
	}
	if verificationCalls.Load() != 1 {
		t.Fatalf("verification calls = %d, want cached completion", verificationCalls.Load())
	}
}

func TestBootstrapCompletionInvalidatesConcurrentStaleReadinessRefresh(t *testing.T) {
	authority := "bootstrap-authority-value-000000"
	enrollmentID := uuid.Must(uuid.NewV7())
	confirmEntered := make(chan struct{})
	confirmRelease := make(chan struct{})
	verifyEntered := make(chan struct{})
	verifyRelease := make(chan struct{})
	var verificationCalls atomic.Int32
	repository := &repositoryStub{
		verifyProtectedConfig: func(context.Context, []byte, []byte) (bool, error) {
			if verificationCalls.Add(1) == 1 {
				close(verifyEntered)
				<-verifyRelease
				return true, nil
			}
			return false, nil
		},
		getBootstrapEnrollment: func(context.Context, []byte, []byte, time.Time) (StoredBootstrapEnrollment, error) {
			return StoredBootstrapEnrollment{
				ID: enrollmentID, CanonicalEmail: "admin@example.test",
				EncryptedTOTP: EncryptedSecret{Ciphertext: []byte("secret")},
			}, nil
		},
		confirmBootstrap: func(_ context.Context, params ConfirmBootstrapParams) (Session, error) {
			close(confirmEntered)
			<-confirmRelease
			return Session{
				ID: params.Session.ID, User: User{ID: params.UserID, Email: stringPointer(params.CanonicalEmail)},
				CSRFDigest: params.Session.CSRFDigest, CreatedAt: params.Session.CreatedAt,
				LastSeenAt: params.Session.LastSeenAt, IdleExpiresAt: params.Session.IdleExpiresAt,
				AbsoluteExpiresAt: params.Session.AbsoluteExpiresAt, AuthenticationMethod: "bootstrap_totp",
			}, nil
		},
	}
	service := newAuthenticationService(
		t, repository, &passwordEngineStub{}, totpEngineStub{counter: 100}, digest(authority),
	)
	service.protectedConfigurationMu.Lock()
	service.protectedConfigurationAvailable = true
	service.protectedConfigurationMu.Unlock()
	confirmationResult := make(chan error, 1)
	go func() {
		_, err := service.ConfirmBootstrap(context.Background(), authority, BootstrapConfirmation{
			EnrollmentToken: validTestToken(0x5e), Email: "admin@example.test",
			DisplayName: "Platform Admin", Password: "long password value", Code: "123456",
			Event: testEvent(),
		})
		confirmationResult <- err
	}()
	<-confirmEntered
	readinessResult := make(chan error, 1)
	go func() {
		readinessResult <- service.VerifyProtectedConfiguration(context.Background())
	}()
	<-verifyEntered
	close(confirmRelease)
	if err := <-confirmationResult; err != nil {
		t.Fatalf("ConfirmBootstrap() error = %v", err)
	}
	if available, err := service.BootstrapStatus(context.Background()); available || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("BootstrapStatus() during invalidated refresh = (%v, %v)", available, err)
	}
	close(verifyRelease)
	if err := <-readinessResult; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("stale readiness refresh error = %v, want unavailable", err)
	}
	if available, err := service.BootstrapStatus(context.Background()); available || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("BootstrapStatus() after stale refresh = (%v, %v)", available, err)
	}
	if err := service.VerifyProtectedConfiguration(context.Background()); err != nil {
		t.Fatalf("post-bootstrap readiness refresh error = %v", err)
	}
	if available, err := service.BootstrapStatus(context.Background()); err != nil || available {
		t.Fatalf("completed BootstrapStatus() = (%v, %v), want false without error", available, err)
	}
	if verificationCalls.Load() != 2 {
		t.Fatalf("verification calls = %d, want two", verificationCalls.Load())
	}
}

func TestBootstrapConfirmationBindsTOTPToTheBootstrapDatabaseABI(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 123456789, time.UTC)
	enrollmentID := uuid.Must(uuid.NewV7())
	confirmed := false
	repository := &repositoryStub{
		getBootstrapEnrollment: func(context.Context, []byte, []byte, time.Time) (StoredBootstrapEnrollment, error) {
			return StoredBootstrapEnrollment{
				ID: enrollmentID, CanonicalEmail: "admin@example.test",
				EncryptedTOTP: EncryptedSecret{Ciphertext: []byte("secret")},
			}, nil
		},
		confirmBootstrap: func(_ context.Context, params ConfirmBootstrapParams) (Session, error) {
			confirmed = true
			if !params.Session.IdleExpiresAt.Equal(now.Add(30*time.Minute).Truncate(time.Millisecond)) ||
				!params.Session.AbsoluteExpiresAt.Equal(now.Add(8*time.Hour).Truncate(time.Millisecond)) {
				t.Fatal("bootstrap session deadlines must use the database millisecond precision")
			}
			want := "totp_credential:" + params.TOTPCredentialID.String() + ":user:" + params.UserID.String()
			if params.TOTPCredentialID == params.UserID || string(params.TOTP.AAD) != want {
				t.Fatal("bootstrap TOTP does not bind its factor and owner using the database ABI")
			}
			if params.AcceptedTOTPCounter != 100 || len(params.RecoveryCodes) != 10 {
				t.Fatal("bootstrap lost its MFA proof or recovery material")
			}
			return Session{}, nil
		},
	}
	const authority = "bootstrap-authority-value-000000"
	service := newAuthenticationServiceAt(t, repository, &passwordEngineStub{}, totpEngineStub{counter: 100}, digest(authority), now)
	_, err := service.ConfirmBootstrap(context.Background(), authority, BootstrapConfirmation{
		EnrollmentToken: validTestToken(0x5e), Email: "admin@example.test",
		DisplayName: "Platform Admin", Password: "long password value", Code: "123456", Event: testEvent(),
	})
	if err != nil || !confirmed {
		t.Fatalf("bootstrap confirmation did not reach its database boundary: %v", err)
	}
}

func TestConcurrentForcedReadinessUsesOneDatabaseVerification(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var verificationCalls atomic.Int32
	repository := &repositoryStub{
		verifyProtectedConfig: func(context.Context, []byte, []byte) (bool, error) {
			if verificationCalls.Add(1) == 1 {
				close(entered)
			}
			<-release
			return false, nil
		},
	}
	service := newAuthenticationServiceAtDefaultState(
		t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("deployment-authority"),
		time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
	)

	const callers = 12
	errorsSeen := make(chan error, callers)
	go func() {
		errorsSeen <- service.VerifyProtectedConfiguration(context.Background())
	}()
	<-entered
	for range callers - 1 {
		go func() {
			errorsSeen <- service.VerifyProtectedConfiguration(context.Background())
		}()
	}
	close(release)
	for range callers {
		if err := <-errorsSeen; err != nil {
			t.Fatalf("VerifyProtectedConfiguration() error = %v", err)
		}
	}
	if verificationCalls.Load() != 1 {
		t.Fatalf("protected verification calls = %d, want one", verificationCalls.Load())
	}
}

func TestForcedProtectedConfigurationFailureBlocksUntilReadinessRecovers(t *testing.T) {
	var matches atomic.Bool
	matches.Store(true)
	var verifierCalls atomic.Int32
	var resolveCalls atomic.Int32
	repository := &repositoryStub{
		verifyProtectedConfig: func(context.Context, []byte, []byte) (bool, error) {
			verifierCalls.Add(1)
			if !matches.Load() {
				return false, ErrInvalidAuthentication
			}
			return false, nil
		},
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			resolveCalls.Add(1)
			return Session{}, ErrNotFound
		},
	}
	service := newAuthenticationServiceAtDefaultState(
		t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("deployment-authority"),
		time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
	)
	if err := service.VerifyProtectedConfiguration(context.Background()); err != nil {
		t.Fatalf("initial readiness verification error = %v", err)
	}

	if _, err := service.Authenticate(context.Background(), validTestToken(0x65)); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("initial Authenticate() error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), validTestToken(0x65)); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("cached Authenticate() error = %v", err)
	}
	if verifierCalls.Load() != 1 {
		t.Fatalf("cached verifier calls = %d, want one", verifierCalls.Load())
	}

	matches.Store(false)
	expireProtectedConfigurationCache(service)
	if err := service.VerifyProtectedConfiguration(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("forced verification error = %v, want unavailable", err)
	}
	if _, err := service.Authenticate(context.Background(), validTestToken(0x65)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("guard after mismatch error = %v, want unavailable", err)
	}
	if resolveCalls.Load() != 2 {
		t.Fatalf("resolve calls after mismatch = %d, want only the two pre-mismatch calls", resolveCalls.Load())
	}
	if verifierCalls.Load() != 2 {
		t.Fatalf("verifier calls after blocked request = %d, want two", verifierCalls.Load())
	}

	matches.Store(true)
	expireProtectedConfigurationCache(service)
	if err := service.VerifyProtectedConfiguration(context.Background()); err != nil {
		t.Fatalf("recovery readiness verification error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), validTestToken(0x65)); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("recovered Authenticate() error = %v", err)
	}
	if verifierCalls.Load() != 3 || resolveCalls.Load() != 3 {
		t.Fatalf(
			"recovery calls = verifier %d, resolve %d; want 3 and 3",
			verifierCalls.Load(), resolveCalls.Load(),
		)
	}

	service.InvalidateProtectedConfiguration()
	if _, err := service.Authenticate(context.Background(), validTestToken(0x65)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("guard after readiness invalidation error = %v, want unavailable", err)
	}
	if available, err := service.BootstrapStatus(context.Background()); available || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("BootstrapStatus() after readiness invalidation = (%v, %v)", available, err)
	}
	if verifierCalls.Load() != 3 {
		t.Fatalf("blocked direct paths invoked verifier %d times, want three", verifierCalls.Load())
	}
	if resolveCalls.Load() != 3 {
		t.Fatalf("resolve calls after readiness invalidation = %d, want unchanged", resolveCalls.Load())
	}
}

func TestForcedProtectedConfigurationRefreshBlocksWarmRequestWork(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var verificationCalls atomic.Int32
	var resolveCalls atomic.Int32
	repository := &repositoryStub{
		verifyProtectedConfig: func(context.Context, []byte, []byte) (bool, error) {
			if verificationCalls.Add(1) == 2 {
				close(entered)
				<-release
				return false, ErrInvalidAuthentication
			}
			return false, nil
		},
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			resolveCalls.Add(1)
			return Session{}, ErrNotFound
		},
	}
	service := newAuthenticationServiceAtDefaultState(
		t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("deployment-authority"),
		time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
	)
	if err := service.VerifyProtectedConfiguration(context.Background()); err != nil {
		t.Fatalf("initial readiness verification error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), validTestToken(0x66)); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("warm Authenticate() error = %v", err)
	}
	expireProtectedConfigurationCache(service)

	refreshResult := make(chan error, 1)
	go func() {
		refreshResult <- service.VerifyProtectedConfiguration(context.Background())
	}()
	<-entered
	requestStarted := make(chan struct{})
	requestResult := make(chan error, 1)
	go func() {
		close(requestStarted)
		_, err := service.Authenticate(context.Background(), validTestToken(0x66))
		requestResult <- err
	}()
	<-requestStarted
	select {
	case err := <-requestResult:
		t.Fatalf("Authenticate() completed during forced refresh: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if resolveCalls.Load() != 1 {
		t.Fatalf("resolve calls during forced refresh = %d, want one", resolveCalls.Load())
	}
	close(release)
	if err := <-refreshResult; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("forced refresh error = %v, want unavailable", err)
	}
	if err := <-requestResult; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Authenticate() after failed forced refresh error = %v, want unavailable", err)
	}
}

func TestWarmRequestWaitsForSuccessfulForcedProtectedConfigurationRefresh(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var verificationCalls atomic.Int32
	var resolveCalls atomic.Int32
	repository := &repositoryStub{
		verifyProtectedConfig: func(context.Context, []byte, []byte) (bool, error) {
			if verificationCalls.Add(1) == 2 {
				close(entered)
				<-release
			}
			return false, nil
		},
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			resolveCalls.Add(1)
			return Session{}, ErrNotFound
		},
	}
	service := newAuthenticationServiceAtDefaultState(
		t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("deployment-authority"),
		time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
	)
	if err := service.VerifyProtectedConfiguration(context.Background()); err != nil {
		t.Fatalf("initial readiness verification error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), validTestToken(0x68)); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("warm Authenticate() error = %v", err)
	}
	expireProtectedConfigurationCache(service)

	refreshResult := make(chan error, 1)
	go func() {
		refreshResult <- service.VerifyProtectedConfiguration(context.Background())
	}()
	<-entered
	requestStarted := make(chan struct{})
	requestResult := make(chan error, 1)
	go func() {
		close(requestStarted)
		_, err := service.Authenticate(context.Background(), validTestToken(0x68))
		requestResult <- err
	}()
	<-requestStarted
	select {
	case err := <-requestResult:
		t.Fatalf("Authenticate() completed during successful forced refresh: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if resolveCalls.Load() != 1 {
		t.Fatalf("resolve calls during successful forced refresh = %d, want one", resolveCalls.Load())
	}
	close(release)
	if err := <-refreshResult; err != nil {
		t.Fatalf("forced refresh error = %v", err)
	}
	if err := <-requestResult; !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("Authenticate() after successful refresh error = %v", err)
	}
	if resolveCalls.Load() != 2 {
		t.Fatalf("resolve calls after successful refresh = %d, want two", resolveCalls.Load())
	}
}

func TestBootstrapStatusFloodUsesNoDatabaseVerificationAndDoesNotPauseAuthentication(t *testing.T) {
	var verificationCalls atomic.Int32
	var resolveCalls atomic.Int32
	repository := &repositoryStub{
		verifyProtectedConfig: func(context.Context, []byte, []byte) (bool, error) {
			verificationCalls.Add(1)
			return false, nil
		},
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			resolveCalls.Add(1)
			return Session{}, ErrNotFound
		},
	}
	service := newAuthenticationService(
		t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("deployment-authority"),
	)
	if _, err := service.Authenticate(context.Background(), validTestToken(0x69)); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("warm Authenticate() error = %v", err)
	}

	const statusCallers = 32
	statusResults := make(chan error, statusCallers)
	for range statusCallers {
		go func() {
			available, err := service.BootstrapStatus(context.Background())
			if available && err == nil {
				err = errors.New("completed deployment reported bootstrap available")
			}
			statusResults <- err
		}()
	}
	for range statusCallers {
		if err := <-statusResults; err != nil {
			t.Fatalf("BootstrapStatus() error = %v", err)
		}
	}
	if _, err := service.Authenticate(context.Background(), validTestToken(0x69)); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("Authenticate() after status flood error = %v", err)
	}
	if verificationCalls.Load() != 0 || resolveCalls.Load() != 2 {
		t.Fatalf(
			"flood calls = verifier %d, resolve %d; want 0 and 2",
			verificationCalls.Load(), resolveCalls.Load(),
		)
	}
}

func TestCanceledForcedReadinessLeaderCannotPoisonSharedProtectedConfiguration(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var verificationCalls atomic.Int32
	var internalContextCanceled atomic.Bool
	repository := &repositoryStub{
		verifyProtectedConfig: func(ctx context.Context, _ []byte, _ []byte) (bool, error) {
			verificationCalls.Add(1)
			close(entered)
			select {
			case <-ctx.Done():
				internalContextCanceled.Store(true)
				return false, ctx.Err()
			case <-release:
				return false, nil
			}
		},
	}
	service := newAuthenticationServiceAtDefaultState(
		t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("deployment-authority"),
		time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
	)
	leaderContext, cancelLeader := context.WithCancel(context.Background())
	leaderResult := make(chan error, 1)
	go func() {
		leaderResult <- service.VerifyProtectedConfiguration(leaderContext)
	}()
	<-entered
	cancelLeader()
	select {
	case err := <-leaderResult:
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("canceled VerifyProtectedConfiguration() error = %v, want unavailable", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled VerifyProtectedConfiguration() did not abandon the shared refresh")
	}
	waiterResult := make(chan error, 1)
	go func() {
		_, err := service.Authenticate(context.Background(), validTestToken(0x6a))
		waiterResult <- err
	}()
	select {
	case err := <-waiterResult:
		t.Fatalf("Authenticate() completed before shared refresh: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-waiterResult; !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("Authenticate() after canceled leader error = %v", err)
	}
	if internalContextCanceled.Load() || verificationCalls.Load() != 1 {
		t.Fatalf(
			"shared verifier canceled = %t, calls = %d; want false and one",
			internalContextCanceled.Load(), verificationCalls.Load(),
		)
	}
}

func TestFailedForcedReadinessCannotBeRetriedByBootstrapStatus(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var verificationCalls atomic.Int32
	repository := &repositoryStub{
		verifyProtectedConfig: func(context.Context, []byte, []byte) (bool, error) {
			if verificationCalls.Add(1) == 1 {
				close(entered)
				<-release
				return false, ErrInvalidAuthentication
			}
			return false, nil
		},
	}
	service := newAuthenticationServiceAtDefaultState(
		t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("deployment-authority"),
		time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
	)

	readinessResult := make(chan error, 1)
	go func() {
		readinessResult <- service.VerifyProtectedConfiguration(context.Background())
	}()
	<-entered
	close(release)
	if err := <-readinessResult; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("VerifyProtectedConfiguration() failure = %v, want unavailable", err)
	}

	expireProtectedConfigurationCache(service)
	if available, err := service.BootstrapStatus(context.Background()); available || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("BootstrapStatus() recovery = (%v, %v), want unavailable", available, err)
	}
	if verificationCalls.Load() != 1 {
		t.Fatalf("BootstrapStatus() verifier calls = %d, want one", verificationCalls.Load())
	}
	if err := service.VerifyProtectedConfiguration(context.Background()); err != nil {
		t.Fatalf("forced recovery error = %v", err)
	}
	if verificationCalls.Load() != 2 {
		t.Fatalf("forced recovery verifier calls = %d, want two", verificationCalls.Load())
	}
}

func TestReadinessInvalidationWinsAgainstInFlightForcedVerification(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var verificationCalls atomic.Int32
	var resolveCalls atomic.Int32
	repository := &repositoryStub{
		verifyProtectedConfig: func(context.Context, []byte, []byte) (bool, error) {
			verificationCalls.Add(1)
			close(entered)
			<-release
			return false, nil
		},
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			resolveCalls.Add(1)
			return Session{}, ErrNotFound
		},
	}
	service := newAuthenticationServiceAtDefaultState(
		t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("deployment-authority"),
		time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
	)
	verificationResult := make(chan error, 1)
	go func() {
		verificationResult <- service.VerifyProtectedConfiguration(context.Background())
	}()
	<-entered
	invalidationStarted := make(chan struct{})
	invalidationDone := make(chan struct{})
	go func() {
		close(invalidationStarted)
		service.InvalidateProtectedConfiguration()
		close(invalidationDone)
	}()
	<-invalidationStarted
	close(release)
	if err := <-verificationResult; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("invalidated VerifyProtectedConfiguration() error = %v", err)
	}
	<-invalidationDone
	if _, err := service.Authenticate(context.Background(), validTestToken(0x67)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("blocked Authenticate() error = %v, want unavailable", err)
	}
	if verificationCalls.Load() != 1 || resolveCalls.Load() != 0 {
		t.Fatalf(
			"calls after invalidation race = verifier %d, resolve %d; want 1 and 0",
			verificationCalls.Load(), resolveCalls.Load(),
		)
	}
}

func TestCanceledForcedVerificationCannotPublishAfterReadinessInvalidation(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	completed := make(chan struct{})
	var verificationCalls atomic.Int32
	var resolveCalls atomic.Int32
	repository := &repositoryStub{
		verifyProtectedConfig: func(context.Context, []byte, []byte) (bool, error) {
			if verificationCalls.Add(1) == 1 {
				close(entered)
				<-release
				close(completed)
			}
			return false, nil
		},
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			resolveCalls.Add(1)
			return Session{}, ErrNotFound
		},
	}
	service := newAuthenticationServiceAtDefaultState(
		t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("deployment-authority"),
		time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
	)
	verificationContext, cancelVerification := context.WithCancel(context.Background())
	verificationResult := make(chan error, 1)
	go func() {
		verificationResult <- service.VerifyProtectedConfiguration(verificationContext)
	}()
	<-entered
	cancelVerification()
	if err := <-verificationResult; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("canceled forced verification error = %v, want unavailable", err)
	}
	service.InvalidateProtectedConfiguration()
	close(release)
	<-completed
	deadline := time.Now().Add(time.Second)
	for {
		service.protectedConfigurationMu.Lock()
		refreshComplete := service.protectedConfigurationRefresh == nil
		state := service.protectedConfigurationState
		service.protectedConfigurationMu.Unlock()
		if refreshComplete {
			if state != protectedConfigurationReadinessBlocked {
				t.Fatalf("late verification published state %d, want readiness blocked", state)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("detached protected verification did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := service.Authenticate(context.Background(), validTestToken(0x6b)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Authenticate() after late success = %v, want unavailable", err)
	}
	if resolveCalls.Load() != 0 {
		t.Fatalf("late success reached resolve %d times", resolveCalls.Load())
	}
	if err := service.VerifyProtectedConfiguration(context.Background()); err != nil {
		t.Fatalf("later full readiness verification error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), validTestToken(0x6b)); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("Authenticate() after recovered readiness = %v", err)
	}
	if verificationCalls.Load() != 2 || resolveCalls.Load() != 1 {
		t.Fatalf("recovery calls = verifier %d, resolve %d", verificationCalls.Load(), resolveCalls.Load())
	}
}

func TestInvalidOversizedPasswordUsesBoundedDummyVerification(t *testing.T) {
	passwords := &passwordEngineStub{}
	repository := &repositoryStub{}
	service := newAuthenticationService(t, repository, passwords, totpEngineStub{}, digest("bootstrap-authority-value-000000"))
	oversized := strings.Repeat("x", maxPasswordBytes+100)

	_, err := service.StartPasswordLogin(context.Background(), "not-an-email", oversized, testEvent())
	if !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("StartPasswordLogin() error = %v, want generic authentication failure", err)
	}
	if len(passwords.verifyInputs) != 1 || passwords.verifyInputs[0] == oversized || len(passwords.verifyInputs[0]) > maxPasswordBytes {
		t.Fatalf("Verify inputs = %#v, oversized input reached the password KDF", passwords.verifyInputs)
	}
}

func TestPasswordFailureAuditBindsKnownUserWithoutExposingUnknownIdentity(t *testing.T) {
	knownID := uuid.Must(uuid.NewV7())
	for name, credential := range map[string]*LocalCredential{
		"known":   {User: User{ID: knownID}, PasswordHash: "wrong-hash", Enabled: true},
		"unknown": nil,
	} {
		t.Run(name, func(t *testing.T) {
			var recorded RecordPasswordFailureParams
			repository := &repositoryStub{
				findLocalCredential: func(context.Context, string) (LocalCredential, error) {
					if credential == nil {
						return LocalCredential{}, ErrNotFound
					}
					return *credential, nil
				},
				recordPasswordFailure: func(_ context.Context, params RecordPasswordFailureParams) error {
					recorded = params
					return nil
				},
			}
			service := newAuthenticationService(
				t, repository, &passwordEngineStub{}, totpEngineStub{},
				digest("bootstrap-authority-value-000000"),
			)
			_, err := service.StartPasswordLogin(
				context.Background(), "admin@example.test", "invalid-password", testEvent(),
			)
			if !errors.Is(err, ErrInvalidAuthentication) {
				t.Fatalf("StartPasswordLogin() error = %v", err)
			}
			if credential == nil && recorded.UserID != nil {
				t.Fatalf("unknown user audit attribution = %v", recorded.UserID)
			}
			if credential != nil && (recorded.UserID == nil || *recorded.UserID != knownID) {
				t.Fatalf("known user audit attribution = %v, want %v", recorded.UserID, knownID)
			}
			if recorded.MeteredAccountKey.Scope != rateScopeLogin || len(recorded.MeteredAccountKey.Digest) != sha256DigestLength {
				t.Fatalf("metered account key = %#v", recorded.MeteredAccountKey)
			}
		})
	}
}

func TestPasswordVerificationConcurrencyIsStrictlyBounded(t *testing.T) {
	userID := uuid.Must(uuid.NewV7())
	repository := &repositoryStub{
		findLocalCredential: func(context.Context, string) (LocalCredential, error) {
			return LocalCredential{User: User{ID: userID}, PasswordHash: "valid-hash", Enabled: true}, nil
		},
		createMFAChallenge: func(context.Context, CreateMFAChallengeParams) error { return nil },
	}
	passwords := &blockingPasswordEngine{entered: make(chan struct{}, 1), release: make(chan struct{})}
	service, err := NewService(ServiceOptions{
		Repository: repository, Passwords: passwords, Tokens: tokenSourceStub{}, TOTP: totpEngineStub{},
		Cipher: secretCryptorStub{}, RateLimitKeyMaterial: bytes.Repeat([]byte{0x91}, 32),
		BootstrapTokenDigest:       digest("bootstrap-authority-value-000000"),
		BootstrapEnrollmentTimeout: 10 * time.Minute, MFAChallengeTimeout: 5 * time.Minute,
		SessionIdleTimeout: 30 * time.Minute, SessionAbsoluteTimeout: 8 * time.Hour,
		PasswordKDFConcurrency: 1,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	markProtectedConfigurationVerifiedForTest(service)

	firstResult := make(chan error, 1)
	go func() {
		_, loginErr := service.StartPasswordLogin(
			context.Background(), "admin@example.test", "valid-password-value", testEvent(),
		)
		firstResult <- loginErr
	}()
	<-passwords.entered

	_, secondErr := service.StartPasswordLogin(
		context.Background(), "admin@example.test", "valid-password-value", testEvent(),
	)
	var throttled *RateLimitError
	if !errors.As(secondErr, &throttled) || throttled.RetryAfter <= 0 {
		t.Fatalf("second StartPasswordLogin() error = %v, want bounded admission throttle", secondErr)
	}
	close(passwords.release)
	if err := <-firstResult; err != nil {
		t.Fatalf("first StartPasswordLogin() error = %v", err)
	}
}

func TestConcurrentCorrectPasswordsRequireAtomicPersistentAdmissionBeforeKDF(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	userID := uuid.Must(uuid.NewV7())
	var admissionLock sync.Mutex
	admissions := 0
	repository := &repositoryStub{
		admitRateLimits: func(_ context.Context, params AdmitRateLimitsParams) (time.Time, error) {
			if len(params.Rules) != 2 || params.Rules[0].Policy != loginRatePolicy || params.Rules[1].Policy != loginNetworkRatePolicy {
				t.Fatalf("admission rules = %#v", params.Rules)
			}
			admissionLock.Lock()
			defer admissionLock.Unlock()
			admissions++
			if admissions > 1 {
				return now.Add(time.Minute), nil
			}
			return time.Time{}, nil
		},
		findLocalCredential: func(context.Context, string) (LocalCredential, error) {
			return LocalCredential{User: User{ID: userID}, PasswordHash: "valid-hash", Enabled: true}, nil
		},
		createMFAChallenge: func(context.Context, CreateMFAChallengeParams) error { return nil },
	}
	passwords := &blockingPasswordEngine{entered: make(chan struct{}, 1), release: make(chan struct{})}
	service, err := NewService(ServiceOptions{
		Repository: repository, Passwords: passwords, Tokens: tokenSourceStub{}, TOTP: totpEngineStub{},
		Cipher: secretCryptorStub{}, RateLimitKeyMaterial: bytes.Repeat([]byte{0x91}, 32),
		BootstrapTokenDigest:       digest("bootstrap-authority-value-000000"),
		BootstrapEnrollmentTimeout: 10 * time.Minute, MFAChallengeTimeout: 5 * time.Minute,
		SessionIdleTimeout: 30 * time.Minute, SessionAbsoluteTimeout: 8 * time.Hour,
		PasswordKDFConcurrency: 2, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	markProtectedConfigurationVerifiedForTest(service)
	firstResult := make(chan error, 1)
	go func() {
		_, loginErr := service.StartPasswordLogin(
			context.Background(), "admin@example.test", "valid-password-value", testEvent(),
		)
		firstResult <- loginErr
	}()
	<-passwords.entered

	_, secondErr := service.StartPasswordLogin(
		context.Background(), "admin@example.test", "valid-password-value", testEvent(),
	)
	var throttled *RateLimitError
	if !errors.As(secondErr, &throttled) || throttled.RetryAfter != time.Minute {
		t.Fatalf("second StartPasswordLogin() error = %v, want persistent admission throttle", secondErr)
	}
	close(passwords.release)
	if err := <-firstResult; err != nil {
		t.Fatalf("first StartPasswordLogin() error = %v", err)
	}
}

func TestBootstrapPasswordHashConcurrencyIsStrictlyBounded(t *testing.T) {
	authority := "bootstrap-authority-value-000000"
	enrollmentID := uuid.Must(uuid.NewV7())
	repository := &repositoryStub{
		getBootstrapEnrollment: func(context.Context, []byte, []byte, time.Time) (StoredBootstrapEnrollment, error) {
			return StoredBootstrapEnrollment{
				ID: enrollmentID, CanonicalEmail: "admin@example.test",
				EncryptedTOTP: EncryptedSecret{Ciphertext: []byte("secret")},
			}, nil
		},
		confirmBootstrap: func(_ context.Context, params ConfirmBootstrapParams) (Session, error) {
			return Session{
				ID:         params.Session.ID,
				User:       User{ID: params.UserID, Email: stringPointer(params.CanonicalEmail), DisplayName: params.DisplayName},
				CSRFDigest: params.Session.CSRFDigest, CreatedAt: params.Session.CreatedAt,
				LastSeenAt: params.Session.LastSeenAt, IdleExpiresAt: params.Session.IdleExpiresAt,
				AbsoluteExpiresAt: params.Session.AbsoluteExpiresAt, AuthenticationMethod: "bootstrap_totp",
			}, nil
		},
	}
	passwords := &blockingPasswordHashEngine{entered: make(chan struct{}, 1), release: make(chan struct{})}
	service, err := NewService(ServiceOptions{
		Repository: repository, Passwords: passwords, Tokens: tokenSourceStub{}, TOTP: totpEngineStub{counter: 100},
		Cipher: secretCryptorStub{}, RateLimitKeyMaterial: bytes.Repeat([]byte{0x91}, 32),
		BootstrapTokenDigest: digest(authority), BootstrapEnrollmentTimeout: 10 * time.Minute,
		MFAChallengeTimeout: 5 * time.Minute, SessionIdleTimeout: 30 * time.Minute,
		SessionAbsoluteTimeout: 8 * time.Hour, PasswordKDFConcurrency: 1,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	markProtectedConfigurationVerifiedForTest(service)
	input := BootstrapConfirmation{
		EnrollmentToken: validTestToken(0x71), Email: "admin@example.test", DisplayName: "Platform Admin",
		Password: "long password value", Code: "123456", Event: testEvent(),
	}
	firstResult := make(chan error, 1)
	go func() {
		_, confirmErr := service.ConfirmBootstrap(context.Background(), authority, input)
		firstResult <- confirmErr
	}()
	<-passwords.entered

	_, secondErr := service.ConfirmBootstrap(context.Background(), authority, input)
	var throttled *RateLimitError
	if !errors.As(secondErr, &throttled) || throttled.RetryAfter <= 0 {
		t.Fatalf("second ConfirmBootstrap() error = %v, want bounded admission throttle", secondErr)
	}
	close(passwords.release)
	if err := <-firstResult; err != nil {
		t.Fatalf("first ConfirmBootstrap() error = %v", err)
	}
}

func TestRateLimitKeysUsePurposeSeparatedHMAC(t *testing.T) {
	service := newAuthenticationService(t, &repositoryStub{}, &passwordEngineStub{}, totpEngineStub{}, digest("bootstrap-authority-value-000000"))
	keys := service.loginRateKeys("admin@example.test", testEvent())
	if len(keys) != 2 || keys[0].Scope != rateScopeLogin || keys[1].Scope != rateScopeLogin {
		t.Fatalf("login rate keys = %#v", keys)
	}
	oldReversibleDigest := digest("login.account:admin@example.test")
	if bytes.Equal(keys[0].Digest, oldReversibleDigest) {
		t.Fatal("account key remains a reversible plain SHA-256 digest")
	}
	if bytes.Equal(keys[0].Digest, keys[1].Digest) {
		t.Fatal("account and network keys are not purpose-separated")
	}
}

func TestPasswordSuccessCannotMintChallengeWhileUserMFALimitIsBlocked(t *testing.T) {
	userID := uuid.Must(uuid.NewV7())
	var created CreateMFAChallengeParams
	repository := &repositoryStub{
		findLocalCredential: func(context.Context, string) (LocalCredential, error) {
			return LocalCredential{User: User{ID: userID}, PasswordHash: "valid-hash", Enabled: true}, nil
		},
		createMFAChallenge: func(_ context.Context, params CreateMFAChallengeParams) error {
			created = params
			return nil
		},
	}
	service := newAuthenticationService(t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("bootstrap-authority-value-000000"))

	if _, err := service.StartPasswordLogin(
		context.Background(), "admin@example.test", "valid-password-value", testEvent(),
	); err != nil {
		t.Fatalf("StartPasswordLogin() error = %v", err)
	}
	if created.UserID != userID || len(created.ChallengeRateKey) != sha256DigestLength || len(created.UserRateKey) != sha256DigestLength {
		t.Fatalf("CreateMFAChallenge params = %#v", created)
	}
	if len(created.LoginAccountRateKey) != sha256DigestLength {
		t.Fatalf("login account admission key was not bound to challenge: %#v", created)
	}
	if bytes.Equal(created.UserRateKey, digest(userID.String())) {
		t.Fatal("MFA user key is an unkeyed user identifier digest")
	}
	if len(created.ClearKeys) != 0 {
		t.Fatalf("password-only success cleared shared rate limits: %#v", created.ClearKeys)
	}
}

func TestChallengeCreationPreservesPersistentMFAThrottle(t *testing.T) {
	userID := uuid.Must(uuid.NewV7())
	repository := &repositoryStub{
		findLocalCredential: func(context.Context, string) (LocalCredential, error) {
			return LocalCredential{User: User{ID: userID}, PasswordHash: "valid-hash", Enabled: true}, nil
		},
		createMFAChallenge: func(context.Context, CreateMFAChallengeParams) error {
			return &RateLimitError{RetryAfter: 3 * time.Minute}
		},
	}
	service := newAuthenticationService(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"),
	)
	_, err := service.StartPasswordLogin(
		context.Background(), "admin@example.test", "valid-password-value", testEvent(),
	)
	var throttled *RateLimitError
	if !errors.As(err, &throttled) || throttled.RetryAfter != 3*time.Minute {
		t.Fatalf("StartPasswordLogin() error = %v, want persistent MFA throttle", err)
	}
}

func TestMFAFailureAtomicallyIncludesUserLevelThrottle(t *testing.T) {
	userID := uuid.Must(uuid.NewV7())
	challengeID := uuid.Must(uuid.NewV7())
	credentialID := uuid.Must(uuid.NewV7())
	var recorded RecordMFAFailureParams
	repository := &repositoryStub{
		getMFAChallenge: func(context.Context, []byte, time.Time) (StoredMFAChallenge, error) {
			return StoredMFAChallenge{
				ID: challengeID, User: User{ID: userID}, TOTPContextID: credentialID,
				EncryptedTOTP: EncryptedSecret{
					Ciphertext: []byte("secret"), AAD: []byte(credentialTOTPContext(credentialID, userID)),
				},
				MaxAttempts: maxMFAAttempts,
			}, nil
		},
		recordMFAFailure: func(_ context.Context, params RecordMFAFailureParams) (time.Time, error) {
			recorded = params
			return time.Time{}, nil
		},
	}
	service := newAuthenticationService(
		t, repository, &passwordEngineStub{}, totpEngineStub{validateError: ErrInvalidAuthentication},
		digest("bootstrap-authority-value-000000"),
	)

	_, err := service.CompleteMFA(context.Background(), validTestToken(0x31), "totp", "123456", testEvent())
	if !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("CompleteMFA() error = %v", err)
	}
	if recorded.ChallengeID != challengeID || recorded.UserID != userID || len(recorded.Keys) != 3 {
		t.Fatalf("recorded MFA failure = %#v", recorded)
	}
	for _, key := range recorded.Keys {
		if key.Scope != rateScopeMFA || len(key.Digest) != sha256DigestLength {
			t.Fatalf("MFA rate key = %#v", key)
		}
	}
}

func TestPasswordMFAFailsClosedForV2FactorBeyondRevisionOne(t *testing.T) {
	userID := uuid.Must(uuid.NewV7())
	factorID := uuid.Must(uuid.NewV7())
	challengeID := uuid.Must(uuid.NewV7())
	v2Context, err := CredentialTOTPContextAtRevision(factorID, userID, 2)
	if err != nil {
		t.Fatal(err)
	}
	completionCalls := 0
	repository := &repositoryStub{
		getMFAChallenge: func(context.Context, []byte, time.Time) (StoredMFAChallenge, error) {
			return StoredMFAChallenge{
				ID: challengeID, User: User{ID: userID}, TOTPContextID: factorID,
				EncryptedTOTP: EncryptedSecret{
					Ciphertext: []byte("protected-secret-material"), Nonce: []byte("123456789012"),
					AAD: []byte(v2Context), KeyVersion: 1,
				},
				MaxAttempts: maxMFAAttempts,
			}, nil
		},
		completeTOTPChallenge: func(context.Context, CompleteTOTPParams) (Session, error) {
			completionCalls++
			return Session{}, nil
		},
	}
	decryptCalls := 0
	service := newAuthenticationService(
		t, repository, &passwordEngineStub{}, totpEngineStub{counter: 1},
		digest("bootstrap-authority-value-000000"),
	)
	service.cipher = directPlatformTOTPSecretCryptorFunc(func(string, EncryptedSecret) (string, error) {
		decryptCalls++
		return "JBSWY3DPEHPK3PXP", nil
	})

	_, err = service.CompleteMFA(context.Background(), validTestToken(0x38), "totp", "123456", testEvent())
	if !errors.Is(err, ErrUnavailable) || decryptCalls != 0 || completionCalls != 0 {
		t.Fatalf("revision-two password MFA = %v, decrypt=%d complete=%d", err, decryptCalls, completionCalls)
	}
}

func TestValidFormatRecoveryMissPropagatesAtomicThrottleResult(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	blockedUntil := now.Add(15 * time.Minute)
	userID := uuid.Must(uuid.NewV7())
	var completed CompleteRecoveryParams
	repository := &repositoryStub{
		getMFAChallenge: func(context.Context, []byte, time.Time) (StoredMFAChallenge, error) {
			return StoredMFAChallenge{ID: uuid.Must(uuid.NewV7()), User: User{ID: userID}, MaxAttempts: maxMFAAttempts}, nil
		},
		completeRecovery: func(_ context.Context, params CompleteRecoveryParams) (Session, error) {
			completed = params
			if len(params.ClearKeys) != 2 || len(params.FailureKeys) != 3 || params.FailurePolicy != mfaRatePolicy {
				t.Fatalf("recovery completion lacks atomic failure inputs: %#v", params)
			}
			return Session{}, &RateLimitError{RetryAfter: blockedUntil.Sub(now)}
		},
	}
	service := newAuthenticationServiceAt(t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("bootstrap-authority-value-000000"), now)

	challengeToken := validTestToken(0x32)
	event := testEvent()
	_, err := service.CompleteMFA(context.Background(), challengeToken, "recovery_code", strings.Repeat("A", 52), event)
	var rateLimit *RateLimitError
	if !errors.As(err, &rateLimit) || rateLimit.RetryAfter != 15*time.Minute {
		t.Fatalf("CompleteMFA() error = %v, want propagated repository throttle", err)
	}
	networkKey := service.networkRateKeys(rateScopeMFA, "mfa", event)[0]
	failureIncludesNetwork := false
	for _, key := range completed.FailureKeys {
		failureIncludesNetwork = failureIncludesNetwork || hmac.Equal(key.Digest, networkKey.Digest)
	}
	if !failureIncludesNetwork {
		t.Fatal("atomic recovery failure omitted the shared MFA network counter")
	}
	for _, key := range completed.ClearKeys {
		if hmac.Equal(key.Digest, networkKey.Digest) {
			t.Fatal("successful principal could clear a shared MFA network counter")
		}
	}
}

func TestBootstrapEmailMismatchAdvancesEnrollmentAttempt(t *testing.T) {
	authority := "bootstrap-authority-value-000000"
	enrollmentID := uuid.Must(uuid.NewV7())
	var recorded RecordBootstrapFailureParams
	repository := &repositoryStub{
		getBootstrapEnrollment: func(context.Context, []byte, []byte, time.Time) (StoredBootstrapEnrollment, error) {
			return StoredBootstrapEnrollment{ID: enrollmentID, CanonicalEmail: "bound@example.test"}, nil
		},
		recordBootstrapFailure: func(_ context.Context, params RecordBootstrapFailureParams) (time.Time, error) {
			recorded = params
			return time.Time{}, nil
		},
	}
	service := newAuthenticationService(t, repository, &passwordEngineStub{}, totpEngineStub{}, digest(authority))

	_, err := service.ConfirmBootstrap(context.Background(), authority, BootstrapConfirmation{
		EnrollmentToken: validTestToken(0x33), Email: "other@example.test", DisplayName: "Platform Admin",
		Password: "long password value", Code: "123456", Event: testEvent(),
	})
	if !errors.Is(err, ErrInvalidAuthentication) || recorded.EnrollmentID != enrollmentID {
		t.Fatalf("ConfirmBootstrap() error = %v, recorded = %#v", err, recorded)
	}
}

func TestCompletedBootstrapReplayPreservesConflict(t *testing.T) {
	authority := "bootstrap-authority-value-000000"
	repository := &repositoryStub{
		getBootstrapEnrollment: func(context.Context, []byte, []byte, time.Time) (StoredBootstrapEnrollment, error) {
			return StoredBootstrapEnrollment{}, ErrConflict
		},
	}
	service := newAuthenticationService(t, repository, &passwordEngineStub{}, totpEngineStub{}, digest(authority))

	_, err := service.ConfirmBootstrap(context.Background(), authority, BootstrapConfirmation{
		EnrollmentToken: validTestToken(0x74), Email: "admin@example.test", DisplayName: "Platform Admin",
		Password: "long password value", Code: "123456", Event: testEvent(),
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("ConfirmBootstrap() error = %v, want conflict", err)
	}
}

func TestBootstrapDisplayNameRejectsDatabaseControlCharacters(t *testing.T) {
	for name, displayName := range map[string]string{
		"nul": "Admin\x00Operator",
		"c1":  "Admin\u0085Operator",
	} {
		t.Run(name, func(t *testing.T) {
			repository := &repositoryStub{
				getBootstrapEnrollment: func(context.Context, []byte, []byte, time.Time) (StoredBootstrapEnrollment, error) {
					t.Fatal("invalid display name reached persistence")
					return StoredBootstrapEnrollment{}, nil
				},
			}
			service := newAuthenticationService(
				t, repository, &passwordEngineStub{}, totpEngineStub{},
				digest("bootstrap-authority-value-000000"),
			)
			_, err := service.ConfirmBootstrap(
				context.Background(), "bootstrap-authority-value-000000",
				BootstrapConfirmation{
					EnrollmentToken: validTestToken(0x75), Email: "admin@example.test",
					DisplayName: displayName, Password: "long password value", Code: "123456",
					Event: testEvent(),
				},
			)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("ConfirmBootstrap() error = %v, want invalid input", err)
			}
		})
	}
}

func TestBootstrapConfirmationIsOneShot(t *testing.T) {
	authority := "bootstrap-authority-value-000000"
	enrollmentID := uuid.Must(uuid.NewV7())
	confirmations := 0
	repository := &repositoryStub{
		getBootstrapEnrollment: func(context.Context, []byte, []byte, time.Time) (StoredBootstrapEnrollment, error) {
			return StoredBootstrapEnrollment{
				ID: enrollmentID, CanonicalEmail: "admin@example.test",
				EncryptedTOTP: EncryptedSecret{Ciphertext: []byte("secret")},
			}, nil
		},
		confirmBootstrap: func(_ context.Context, params ConfirmBootstrapParams) (Session, error) {
			confirmations++
			if confirmations > 1 {
				return Session{}, ErrConflict
			}
			return Session{
				ID: params.Session.ID, User: User{ID: params.UserID, Email: stringPointer(params.CanonicalEmail), DisplayName: params.DisplayName},
				CSRFDigest: params.Session.CSRFDigest, CreatedAt: params.Session.CreatedAt,
				LastSeenAt: params.Session.LastSeenAt, IdleExpiresAt: params.Session.IdleExpiresAt,
				AbsoluteExpiresAt: params.Session.AbsoluteExpiresAt, AuthenticationMethod: "bootstrap_totp",
			}, nil
		},
	}
	service := newAuthenticationService(t, repository, &passwordEngineStub{}, totpEngineStub{counter: 100}, digest(authority))
	input := BootstrapConfirmation{
		EnrollmentToken: validTestToken(0x34), Email: "admin@example.test", DisplayName: "Platform Admin",
		Password: "long password value", Code: "123456", Event: testEvent(),
	}
	first, err := service.ConfirmBootstrap(context.Background(), authority, input)
	if err != nil || len(first.RecoveryCodes) != recoveryCodeCount {
		t.Fatalf("first ConfirmBootstrap() = (%#v, %v)", first, err)
	}
	if _, err := service.ConfirmBootstrap(context.Background(), authority, input); !errors.Is(err, ErrConflict) {
		t.Fatalf("second ConfirmBootstrap() error = %v, want conflict", err)
	}
}

func TestSessionUpdatesUseMillisecondDeadlinesAndPreserveAbsoluteExpiry(t *testing.T) {
	for _, operation := range []string{"touch", "rotate", "switch"} {
		for _, remaining := range []time.Duration{10 * time.Minute, 8 * time.Hour} {
			t.Run(operation+"/"+remaining.String(), func(t *testing.T) {
				now := time.Date(2026, 9, 7, 12, 0, 0, 123456789, time.UTC)
				absolute := now.Add(remaining).Truncate(time.Millisecond)
				wantIdle := now.Add(30 * time.Minute).Truncate(time.Millisecond)
				if wantIdle.After(absolute) {
					wantIdle = absolute
				}
				csrf := validTestToken(0x45)
				check := func(idle, expiry time.Time) {
					t.Helper()
					if !idle.Equal(wantIdle) || !expiry.Equal(absolute) {
						t.Fatalf("deadlines = (%v, %v), want (%v, %v)", idle, expiry, wantIdle, absolute)
					}
				}
				touched, rotated, switched := false, false, false
				repository := &repositoryStub{
					resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
						return Session{
							ID: uuid.Must(uuid.NewV7()), User: User{ID: uuid.Must(uuid.NewV7())}, CSRFDigest: digest(csrf),
							AuthenticationMethod: "totp", IdleExpiresAt: absolute, AbsoluteExpiresAt: absolute,
						}, nil
					},
					touchSession: func(_ context.Context, _ []byte, observed, idle time.Time) error {
						touched = true
						check(idle, absolute)
						if !observed.Equal(now) {
							t.Fatal("session observation time lost precision")
						}
						return nil
					},
					rotateSession: func(_ context.Context, params RotateSessionParams) (Session, error) {
						rotated = true
						check(params.IdleExpiresAt, params.AbsoluteExpiresAt)
						return Session{}, nil
					},
					switchActiveTenant: func(_ context.Context, params SwitchTenantParams) (Session, error) {
						switched = true
						check(params.IdleExpiresAt, params.AbsoluteExpiresAt)
						return Session{}, nil
					},
				}
				service := newAuthenticationServiceAt(t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("bootstrap-authority-value-000000"), now)
				var err error
				switch operation {
				case "touch":
					_, err = service.Authenticate(context.Background(), validTestToken(0x44))
				case "rotate":
					_, err = service.RotateCurrentSession(context.Background(), validTestToken(0x44), testEvent())
				case "switch":
					_, err = service.SwitchTenant(context.Background(), validTestToken(0x44), csrf, uuid.Must(uuid.NewV7()), testEvent())
				}
				if err != nil || !touched || rotated != (operation == "rotate") || switched != (operation == "switch") {
					t.Fatalf("session update did not reach its expected database boundaries: %v", err)
				}
			})
		}
	}
}

func TestSwitchTenantDeniesIdentifiersOutsideTheDatabaseUUIDNamespace(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	csrf := validTestToken(0x45)
	repository := &repositoryStub{
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			return Session{
				ID: uuid.Must(uuid.NewV7()), CSRFDigest: digest(csrf), AuthenticationMethod: "bootstrap_totp",
				IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
			}, nil
		},
		switchActiveTenant: func(context.Context, SwitchTenantParams) (Session, error) {
			t.Fatal("an impossible tenant identifier reached the database rotation ABI")
			return Session{}, nil
		},
	}
	service := newAuthenticationServiceAt(t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("bootstrap-authority-value-000000"), now)
	_, err := service.SwitchTenant(context.Background(), validTestToken(0x44), csrf, uuid.New(), testEvent())
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("SwitchTenant() = %v, want forbidden", err)
	}
}

func TestSwitchTenantCapsIdleExpiryAtAbsoluteExpiry(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	absolute := now.Add(10 * time.Minute)
	userID := uuid.Must(uuid.NewV7())
	csrf := validTestToken(0x45)
	var switched SwitchTenantParams
	repository := &repositoryStub{
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			return Session{
				ID: uuid.Must(uuid.NewV7()), User: User{ID: userID}, CSRFDigest: digest(csrf),
				AuthenticationMethod: "totp", IdleExpiresAt: now.Add(5 * time.Minute), AbsoluteExpiresAt: absolute,
			}, nil
		},
		switchActiveTenant: func(_ context.Context, params SwitchTenantParams) (Session, error) {
			switched = params
			return Session{AbsoluteExpiresAt: absolute}, nil
		},
	}
	service := newAuthenticationServiceAt(t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("bootstrap-authority-value-000000"), now)

	_, err := service.SwitchTenant(context.Background(), validTestToken(0x44), csrf, uuid.Must(uuid.NewV7()), testEvent())
	if err != nil {
		t.Fatalf("SwitchTenant() error = %v", err)
	}
	if !switched.IdleExpiresAt.Equal(absolute) {
		t.Fatalf("IdleExpiresAt = %v, want absolute cap %v", switched.IdleExpiresAt, absolute)
	}
	if len(switched.AdmissionRules) != 1 || switched.AdmissionRules[0].Key.Scope != rateScopeTenantSwitch ||
		switched.AdmissionRules[0].Policy != tenantSwitchRatePolicy {
		t.Fatalf("tenant-switch admission = %#v", switched.AdmissionRules)
	}
}

func TestSwitchToCurrentTenantIsIdempotentAndDoesNotRotate(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	tenantID := uuid.Must(uuid.NewV7())
	sessionID := uuid.Must(uuid.NewV7())
	sessionToken := validTestToken(0x76)
	repository := &repositoryStub{}
	service := newAuthenticationServiceAt(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	)
	csrf := service.csrfForSession(sessionID)
	repository.resolveSession = func(context.Context, []byte, time.Time) (Session, error) {
		return Session{
			ID: sessionID, User: User{ID: uuid.Must(uuid.NewV7())}, ActiveTenantID: &tenantID,
			AuthenticationMethod: "totp", CSRFDigest: digest(csrf), IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
		}, nil
	}
	repository.switchActiveTenant = func(context.Context, SwitchTenantParams) (Session, error) {
		t.Fatal("same-tenant switch reached rotation persistence")
		return Session{}, nil
	}

	credential, err := service.SwitchTenant(
		context.Background(), sessionToken, csrf, tenantID, testEvent(),
	)
	if err != nil {
		t.Fatalf("SwitchTenant() error = %v", err)
	}
	if credential.SessionToken != sessionToken || credential.CSRFToken != csrf || credential.Session.ID != sessionID {
		t.Fatalf("same-tenant switch changed credential: %#v", credential)
	}
}

func TestSwitchTenantFailsClosedForTypedProvenanceUntilDedicatedRotation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	for _, method := range []string{"oidc", "saml", "passkey"} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			sessionID := uuid.Must(uuid.NewV7())
			currentTenantID := uuid.Must(uuid.NewV7())
			targetTenantID := uuid.Must(uuid.NewV7())
			userID := uuid.Must(uuid.NewV7())
			csrf := validTestToken(0x79)
			repository := &repositoryStub{
				resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
					return Session{
						ID: sessionID, User: User{ID: userID}, ActiveTenantID: &currentTenantID,
						AuthenticationMethod: method, CSRFDigest: digest(csrf),
						IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
					}, nil
				},
				switchActiveTenant: func(context.Context, SwitchTenantParams) (Session, error) {
					t.Fatal("typed-provenance tenant switch reached legacy rotation persistence")
					return Session{}, nil
				},
			}
			service := newAuthenticationServiceAt(
				t, repository, &passwordEngineStub{}, totpEngineStub{},
				digest("bootstrap-authority-value-000000"), now,
			)
			if err := service.BindFederatedSessionAuthority(&federatedSessionAuthorityStub{
				result: FederatedSessionAuthorityResult{
					SessionID: sessionID, TenantID: currentTenantID, UserID: userID,
					AllowAuthority: true, AllowIdleTouch: true,
				},
			}); err != nil {
				t.Fatalf("BindFederatedSessionAuthority() error = %v", err)
			}

			if _, err := service.SwitchTenant(
				context.Background(), validTestToken(0x7a), csrf, targetTenantID, testEvent(),
			); !errors.Is(err, ErrForbidden) {
				t.Fatalf("SwitchTenant() error = %v, want forbidden", err)
			}
		})
	}
}

func TestSwitchToCurrentFederatedTenantRemainsIdempotent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	sessionID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	sessionToken := validTestToken(0x7b)
	var csrf string
	repository := &repositoryStub{
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			return Session{
				ID: sessionID, User: User{ID: userID}, ActiveTenantID: &tenantID,
				AuthenticationMethod: "oidc", CSRFDigest: digest(csrf),
				IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
			}, nil
		},
		switchActiveTenant: func(context.Context, SwitchTenantParams) (Session, error) {
			t.Fatal("same-tenant federated selection reached rotation persistence")
			return Session{}, nil
		},
	}
	service := newAuthenticationServiceAt(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	)
	csrf = service.csrfForSession(sessionID)
	if err := service.BindFederatedSessionAuthority(&federatedSessionAuthorityStub{
		result: FederatedSessionAuthorityResult{
			SessionID: sessionID, TenantID: tenantID, UserID: userID,
			AllowAuthority: true, AllowIdleTouch: true,
		},
	}); err != nil {
		t.Fatalf("BindFederatedSessionAuthority() error = %v", err)
	}

	credential, err := service.SwitchTenant(
		context.Background(), sessionToken, csrf, tenantID, testEvent(),
	)
	if err != nil {
		t.Fatalf("SwitchTenant() error = %v", err)
	}
	if credential.Session.ID != sessionID || credential.SessionToken != sessionToken ||
		credential.CSRFToken != csrf {
		t.Fatalf("same-tenant switch changed credential: %#v", credential)
	}
}

func TestCSRFUsesTheSessionBoundDigest(t *testing.T) {
	service := newAuthenticationService(t, &repositoryStub{}, &passwordEngineStub{}, totpEngineStub{}, digest("bootstrap-authority-value-000000"))
	token := validTestToken(0x51)
	session := Session{CSRFDigest: digest(token)}
	if err := service.ValidateCSRF(session, token); err != nil {
		t.Fatalf("ValidateCSRF(valid) error = %v", err)
	}
	if err := service.ValidateCSRF(session, validTestToken(0x52)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ValidateCSRF(wrong) error = %v, want forbidden", err)
	}
	if err := service.ValidateCSRF(session, "not-a-token"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ValidateCSRF(malformed) error = %v, want forbidden", err)
	}
}

func TestAuthenticateRejectsExpiredAndRevokedSessionsAndSurfacesDatabaseOutage(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	revokedAt := now.Add(-time.Minute)
	for name, result := range map[string]Session{
		"idle expired": {
			IdleExpiresAt: now, AbsoluteExpiresAt: now.Add(time.Hour),
		},
		"absolute expired": {
			IdleExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: now,
		},
		"revoked": {
			IdleExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: now.Add(time.Hour), RevokedAt: &revokedAt,
		},
	} {
		t.Run(name, func(t *testing.T) {
			repository := &repositoryStub{resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
				return result, nil
			}}
			service := newAuthenticationServiceAt(t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("bootstrap-authority-value-000000"), now)
			if _, err := service.Authenticate(context.Background(), validTestToken(0x53)); !errors.Is(err, ErrInvalidAuthentication) {
				t.Fatalf("Authenticate() error = %v, want invalid authentication", err)
			}
		})
	}
	repository := &repositoryStub{resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
		return Session{}, errors.New("database offline")
	}}
	service := newAuthenticationServiceAt(t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("bootstrap-authority-value-000000"), now)
	if _, err := service.Authenticate(context.Background(), validTestToken(0x54)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Authenticate(database outage) error = %v, want unavailable", err)
	}
}

func TestAuthenticateRevalidatesFederatedAuthorityBeforeIdleTouch(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	for _, method := range []string{"oidc", "saml", "passkey"} {
		t.Run(method, func(t *testing.T) {
			sessionID := uuid.Must(uuid.NewV7())
			tenantID := uuid.Must(uuid.NewV7())
			userID := uuid.Must(uuid.NewV7())
			order := make([]string, 0, 2)
			repository := &repositoryStub{
				resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
					return Session{
						ID: sessionID, User: User{ID: userID}, ActiveTenantID: &tenantID,
						AuthenticationMethod: method, IdleExpiresAt: now.Add(time.Hour),
						AbsoluteExpiresAt: now.Add(8 * time.Hour),
					}, nil
				},
				touchSession: func(context.Context, []byte, time.Time, time.Time) error {
					order = append(order, "touch")
					return nil
				},
			}
			authority := &federatedSessionAuthorityStub{result: FederatedSessionAuthorityResult{
				SessionID: sessionID, TenantID: tenantID, UserID: userID,
				AllowAuthority: true, AllowIdleTouch: true,
			}}
			service := newAuthenticationServiceAt(
				t, repository, &passwordEngineStub{}, totpEngineStub{},
				digest("bootstrap-authority-value-000000"), now,
			)
			if err := service.BindFederatedSessionAuthority(federatedSessionAuthorityFunc(func(
				ctx context.Context,
				lookup FederatedSessionAuthorityLookup,
			) (FederatedSessionAuthorityResult, error) {
				order = append(order, "revalidate")
				return authority.RevalidateFederatedSession(ctx, lookup)
			})); err != nil {
				t.Fatalf("BindFederatedSessionAuthority() error = %v", err)
			}
			if _, err := service.Authenticate(context.Background(), validTestToken(0x6d)); err != nil {
				t.Fatalf("Authenticate() error = %v", err)
			}
			if !slices.Equal(order, []string{"revalidate", "touch"}) {
				t.Fatalf("operation order = %v", order)
			}
			wantLookup := FederatedSessionAuthorityLookup{
				SessionID: sessionID, TenantID: tenantID, UserID: userID,
				AuthenticationMethod: method, Audience: "api",
			}
			if authority.calls != 1 || authority.lookup != wantLookup {
				t.Fatalf("authority calls/lookup = %d / %#v", authority.calls, authority.lookup)
			}
		})
	}
}

func TestAuthenticateFederatedSessionFailsClosedWithoutTouch(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	sessionID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	for _, testCase := range []struct {
		name      string
		authority FederatedSessionAuthority
	}{
		{name: "unbound"},
		{name: "dependency rejected", authority: &federatedSessionAuthorityStub{err: errors.New("hidden")}},
		{name: "authority denied", authority: &federatedSessionAuthorityStub{result: FederatedSessionAuthorityResult{
			SessionID: sessionID, TenantID: tenantID, UserID: userID, AllowIdleTouch: true,
		}}},
		{name: "idle touch denied", authority: &federatedSessionAuthorityStub{result: FederatedSessionAuthorityResult{
			SessionID: sessionID, TenantID: tenantID, UserID: userID, AllowAuthority: true,
		}}},
		{name: "identity mismatch", authority: &federatedSessionAuthorityStub{result: FederatedSessionAuthorityResult{
			SessionID: sessionID, TenantID: tenantID, UserID: uuid.Must(uuid.NewV7()),
			AllowAuthority: true, AllowIdleTouch: true,
		}}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			touched := false
			repository := &repositoryStub{
				resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
					return Session{
						ID: sessionID, User: User{ID: userID}, ActiveTenantID: &tenantID,
						AuthenticationMethod: "oidc", IdleExpiresAt: now.Add(time.Hour),
						AbsoluteExpiresAt: now.Add(8 * time.Hour),
					}, nil
				},
				touchSession: func(context.Context, []byte, time.Time, time.Time) error {
					touched = true
					return nil
				},
			}
			service := newAuthenticationServiceAt(
				t, repository, &passwordEngineStub{}, totpEngineStub{},
				digest("bootstrap-authority-value-000000"), now,
			)
			if testCase.authority != nil {
				if err := service.BindFederatedSessionAuthority(testCase.authority); err != nil {
					t.Fatalf("BindFederatedSessionAuthority() error = %v", err)
				}
			}
			if _, err := service.Authenticate(context.Background(), validTestToken(0x6e)); !errors.Is(err, ErrInvalidAuthentication) {
				t.Fatalf("Authenticate() error = %v", err)
			}
			if touched {
				t.Fatal("rejected federated authority touched idle expiry")
			}
		})
	}
}

func TestBindFederatedSessionAuthorityIsOneTimeAndLocalSessionsRemainIndependent(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	touched := 0
	repository := &repositoryStub{
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			return Session{
				ID: uuid.Must(uuid.NewV7()), User: User{ID: uuid.Must(uuid.NewV7())},
				AuthenticationMethod: "totp", IdleExpiresAt: now.Add(time.Hour),
				AbsoluteExpiresAt: now.Add(8 * time.Hour),
			}, nil
		},
		touchSession: func(context.Context, []byte, time.Time, time.Time) error {
			touched++
			return nil
		},
	}
	service := newAuthenticationServiceAt(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	)
	authority := &federatedSessionAuthorityStub{}
	if err := service.BindFederatedSessionAuthority(nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("BindFederatedSessionAuthority(nil) error = %v", err)
	}
	if err := service.BindFederatedSessionAuthority(authority); err != nil {
		t.Fatalf("BindFederatedSessionAuthority() error = %v", err)
	}
	if err := service.BindFederatedSessionAuthority(&federatedSessionAuthorityStub{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("second BindFederatedSessionAuthority() error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), validTestToken(0x6f)); err != nil {
		t.Fatalf("Authenticate(local) error = %v", err)
	}
	if authority.calls != 0 || touched != 1 {
		t.Fatalf("local session authority/touch calls = %d / %d", authority.calls, touched)
	}
}

func TestAuthenticateRejectsUnknownAuthenticationMethodBeforeIdleTouch(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	touched := false
	repository := &repositoryStub{
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			return Session{
				ID: uuid.Must(uuid.NewV7()), User: User{ID: uuid.Must(uuid.NewV7())},
				AuthenticationMethod: "OIDC", IdleExpiresAt: now.Add(time.Hour),
				AbsoluteExpiresAt: now.Add(8 * time.Hour),
			}, nil
		},
		touchSession: func(context.Context, []byte, time.Time, time.Time) error {
			touched = true
			return nil
		},
	}
	service := newAuthenticationServiceAt(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	)
	if _, err := service.Authenticate(context.Background(), validTestToken(0x70)); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if touched {
		t.Fatal("unknown authentication method touched idle expiry")
	}
}

type federatedSessionAuthorityFunc func(
	context.Context,
	FederatedSessionAuthorityLookup,
) (FederatedSessionAuthorityResult, error)

func (function federatedSessionAuthorityFunc) RevalidateFederatedSession(
	ctx context.Context,
	lookup FederatedSessionAuthorityLookup,
) (FederatedSessionAuthorityResult, error) {
	return function(ctx, lookup)
}

func TestAuthenticateDoesNotReturnSessionRevokedBetweenResolveAndTouch(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	repository := &repositoryStub{
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			return Session{
				ID: uuid.Must(uuid.NewV7()), User: User{ID: uuid.Must(uuid.NewV7())},
				AuthenticationMethod: "totp", IdleExpiresAt: now.Add(time.Hour),
				AbsoluteExpiresAt: now.Add(8 * time.Hour),
			}, nil
		},
		touchSession: func(context.Context, []byte, time.Time, time.Time) error {
			return ErrNotFound
		},
	}
	service := newAuthenticationServiceAt(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	)

	if _, err := service.Authenticate(context.Background(), validTestToken(0x5a)); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("Authenticate() error = %v, want invalid authentication", err)
	}
}

func TestSwitchTenantMapsMissingMembershipToForbidden(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	csrf := validTestToken(0x55)
	repository := &repositoryStub{
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			return Session{
				ID: uuid.Must(uuid.NewV7()), User: User{ID: uuid.Must(uuid.NewV7())}, CSRFDigest: digest(csrf),
				AuthenticationMethod: "totp", IdleExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: now.Add(time.Hour),
			}, nil
		},
		switchActiveTenant: func(context.Context, SwitchTenantParams) (Session, error) {
			return Session{}, ErrNotFound
		},
	}
	service := newAuthenticationServiceAt(t, repository, &passwordEngineStub{}, totpEngineStub{}, digest("bootstrap-authority-value-000000"), now)
	_, err := service.SwitchTenant(context.Background(), validTestToken(0x56), csrf, uuid.Must(uuid.NewV7()), testEvent())
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("SwitchTenant() error = %v, want forbidden", err)
	}
}

func TestSwitchTenantPreservesPersistentAdmissionThrottle(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	csrf := validTestToken(0x77)
	repository := &repositoryStub{
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			return Session{
				ID: uuid.Must(uuid.NewV7()), User: User{ID: uuid.Must(uuid.NewV7())},
				AuthenticationMethod: "totp", CSRFDigest: digest(csrf), IdleExpiresAt: now.Add(time.Hour),
				AbsoluteExpiresAt: now.Add(8 * time.Hour),
			}, nil
		},
		switchActiveTenant: func(context.Context, SwitchTenantParams) (Session, error) {
			return Session{}, &RateLimitError{RetryAfter: 2 * time.Minute}
		},
	}
	service := newAuthenticationServiceAt(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	)
	_, err := service.SwitchTenant(
		context.Background(), validTestToken(0x78), csrf, uuid.Must(uuid.NewV7()), testEvent(),
	)
	var throttled *RateLimitError
	if !errors.As(err, &throttled) || throttled.RetryAfter != 2*time.Minute {
		t.Fatalf("SwitchTenant() error = %v, want persistent admission throttle", err)
	}
}

func TestRevokeSessionIsIdempotentForMissingOrAlreadyRevokedTarget(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	csrf := validTestToken(0x73)
	repository := &repositoryStub{
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			return Session{
				ID: uuid.Must(uuid.NewV7()), User: User{ID: uuid.Must(uuid.NewV7())},
				AuthenticationMethod: "totp", CSRFDigest: digest(csrf), IdleExpiresAt: now.Add(time.Hour),
				AbsoluteExpiresAt: now.Add(8 * time.Hour),
			}, nil
		},
		revokeSession: func(context.Context, uuid.UUID, uuid.UUID, EventContext) error {
			return ErrNotFound
		},
	}
	service := newAuthenticationServiceAt(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	)
	if err := service.RevokeSession(
		context.Background(), validTestToken(0x74), csrf, uuid.Must(uuid.NewV7()), testEvent(),
	); err != nil {
		t.Fatalf("RevokeSession() error = %v, want idempotent success", err)
	}
}

func TestSessionAndMembershipPagesUseBoundedSentinels(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	userID := uuid.Must(uuid.NewV7())
	currentID := uuid.Must(uuid.NewV7())
	afterSession := uuid.Must(uuid.NewV7())
	afterMembership := uuid.Must(uuid.NewV7())
	sessionIDs := []uuid.UUID{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())}
	membershipIDs := []uuid.UUID{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())}
	repository := &repositoryStub{
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			return Session{
				ID: currentID, User: User{ID: userID}, AuthenticationMethod: "totp", IdleExpiresAt: now.Add(time.Hour),
				AbsoluteExpiresAt: now.Add(8 * time.Hour),
			}, nil
		},
		listSessions: func(_ context.Context, params ListSessionsParams) ([]SessionSummary, error) {
			if params.ActorID != userID || params.CurrentSessionID != currentID ||
				params.After == nil || *params.After != afterSession || params.Limit != 3 {
				t.Fatalf("ListSessions params = %+v, want actor/current/cursor and sentinel limit 3", params)
			}
			return []SessionSummary{{ID: sessionIDs[0]}, {ID: sessionIDs[1]}, {ID: sessionIDs[2]}}, nil
		},
		listTenantMemberships: func(_ context.Context, params ListTenantMembershipsParams) ([]TenantMembership, error) {
			if params.ActorID != userID || params.After == nil || *params.After != afterMembership || params.Limit != 3 {
				t.Fatalf("ListTenantMemberships params = %+v, want actor/cursor and sentinel limit 3", params)
			}
			return []TenantMembership{{ID: membershipIDs[0]}, {ID: membershipIDs[1]}, {ID: membershipIDs[2]}}, nil
		},
	}
	service := newAuthenticationServiceAt(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	)

	sessionPage, err := service.Sessions(context.Background(), validTestToken(0x81), &afterSession, 2)
	if err != nil {
		t.Fatalf("Sessions() error = %v", err)
	}
	if len(sessionPage.Items) != 2 || sessionPage.NextCursor == nil || *sessionPage.NextCursor != sessionIDs[1] {
		t.Fatalf("Sessions() page = %+v, want two items and second item cursor", sessionPage)
	}
	membershipPage, err := service.TenantMemberships(
		context.Background(), validTestToken(0x82), &afterMembership, 2,
	)
	if err != nil {
		t.Fatalf("TenantMemberships() error = %v", err)
	}
	if len(membershipPage.Items) != 2 || membershipPage.NextCursor == nil ||
		*membershipPage.NextCursor != membershipIDs[1] {
		t.Fatalf("TenantMemberships() page = %+v, want two items and second item cursor", membershipPage)
	}
}

func TestMembershipPagePreservesInvalidAuthenticationFromRepository(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	repository := &repositoryStub{
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			return Session{
				ID: uuid.Must(uuid.NewV7()), User: User{ID: uuid.Must(uuid.NewV7())},
				AuthenticationMethod: "totp", IdleExpiresAt: now.Add(time.Hour),
				AbsoluteExpiresAt: now.Add(8 * time.Hour),
			}, nil
		},
		listTenantMemberships: func(context.Context, ListTenantMembershipsParams) ([]TenantMembership, error) {
			return nil, ErrInvalidAuthentication
		},
	}
	service := newAuthenticationServiceAt(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	)
	_, err := service.TenantMemberships(context.Background(), validTestToken(0x83), nil, 50)
	if !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("TenantMemberships() error = %v, want invalid authentication", err)
	}
}

func newAuthenticationService(
	t *testing.T,
	repository Repository,
	passwords passwordEngine,
	totp totpEngine,
	bootstrapDigest []byte,
) *Service {
	t.Helper()
	return newAuthenticationServiceAt(
		t, repository, passwords, totp, bootstrapDigest,
		time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
	)
}

func newAuthenticationServiceDefaultState(
	t *testing.T,
	repository Repository,
	passwords passwordEngine,
	totp totpEngine,
	bootstrapDigest []byte,
) *Service {
	t.Helper()
	return newAuthenticationServiceAtDefaultState(
		t, repository, passwords, totp, bootstrapDigest,
		time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
	)
}

func newAuthenticationServiceAt(
	t *testing.T,
	repository Repository,
	passwords passwordEngine,
	totp totpEngine,
	bootstrapDigest []byte,
	now time.Time,
) *Service {
	t.Helper()
	service := newAuthenticationServiceAtDefaultState(t, repository, passwords, totp, bootstrapDigest, now)
	service.protectedConfigurationMu.Lock()
	service.protectedConfigurationState = protectedConfigurationVerified
	service.protectedConfigurationMu.Unlock()
	return service
}

func newAuthenticationServiceAtDefaultState(
	t *testing.T,
	repository Repository,
	passwords passwordEngine,
	totp totpEngine,
	bootstrapDigest []byte,
	now time.Time,
) *Service {
	t.Helper()
	service, err := NewService(ServiceOptions{
		Repository: repository, Passwords: passwords, Tokens: tokenSourceStub{}, TOTP: totp,
		Cipher: secretCryptorStub{}, RateLimitKeyMaterial: bytes.Repeat([]byte{0x91}, 32),
		BootstrapTokenDigest: bootstrapDigest, BootstrapEnrollmentTimeout: 10 * time.Minute,
		MFAChallengeTimeout: 5 * time.Minute, SessionIdleTimeout: 30 * time.Minute,
		SessionAbsoluteTimeout: 8 * time.Hour, Now: func() time.Time { return now }, NewID: uuid.NewV7,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func validTestToken(fill byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, tokenBytes))
}

func stringPointer(value string) *string {
	return &value
}

func testEvent() EventContext {
	return EventContext{
		RequestID: uuid.Must(uuid.NewV7()), CorrelationID: uuid.Must(uuid.NewV7()),
		RemoteAddress: netip.MustParseAddr("198.51.100.20"), UserAgent: "service-test",
	}
}

func expireProtectedConfigurationCache(service *Service) {
	now := service.now().UTC().Add(protectedConfigurationRefreshInterval)
	service.now = func() time.Time { return now }
}

func markProtectedConfigurationVerifiedForTest(service *Service) {
	service.protectedConfigurationMu.Lock()
	service.protectedConfigurationState = protectedConfigurationVerified
	service.protectedConfigurationMu.Unlock()
}
