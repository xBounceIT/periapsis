package authentication

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/mail"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

const (
	defaultPasswordVerificationConcurrency = 2
	defaultProtectedConfigurationTimeout   = 5 * time.Second
	protectedConfigurationRefreshInterval  = time.Second
	maxPasswordBytes                       = 512
	recoveryCodeCount                      = 10
	maxMFAAttempts                         = 5
)

var (
	loginRatePolicy        = RateLimitPolicy{Limit: 5, Window: 15 * time.Minute, BlockFor: 15 * time.Minute}
	mfaRatePolicy          = RateLimitPolicy{Limit: 5, Window: 10 * time.Minute, BlockFor: 15 * time.Minute}
	bootstrapRatePolicy    = RateLimitPolicy{Limit: 5, Window: 10 * time.Minute, BlockFor: 15 * time.Minute}
	loginNetworkRatePolicy = RateLimitPolicy{Limit: 20, Window: 15 * time.Minute, BlockFor: 15 * time.Minute}
	tenantSwitchRatePolicy = RateLimitPolicy{Limit: 10, Window: time.Minute, BlockFor: 5 * time.Minute}
)

const (
	csrfKeyInfo           = "periapsis/authentication/csrf-key/v1"
	rateLimitKeyInfo      = "periapsis/authentication/rate-limit-key/v1"
	masterKeyVerifierInfo = "periapsis/authentication/master-key-verifier/v1"
)

const (
	rateScopeBootstrap    = "bootstrap_totp"
	rateScopeLogin        = "local_login"
	rateScopeMFA          = "mfa_challenge"
	rateScopeTenantSwitch = "tenant_switch"
)

const (
	protectedConfigurationReadinessBlocked uint32 = iota
	protectedConfigurationVerified
)

type passwordEngine interface {
	Hash(string) (string, error)
	Verify(string, string) bool
}

type tokenSource interface {
	Opaque() (string, error)
	RecoveryCode() (string, []byte, error)
}

type totpEngine interface {
	Generate(string) (string, string, error)
	Validate(string, string, time.Time, int64) (int64, error)
}

type secretCryptor interface {
	EncryptTOTP(string, string) (EncryptedSecret, error)
	DecryptTOTP(string, EncryptedSecret) (string, error)
}

type ServiceOptions struct {
	Repository                    Repository
	Passwords                     passwordEngine
	Tokens                        tokenSource
	TOTP                          totpEngine
	Cipher                        secretCryptor
	RateLimitKeyMaterial          []byte
	BootstrapTokenDigest          []byte
	BootstrapEnrollmentTimeout    time.Duration
	MFAChallengeTimeout           time.Duration
	SessionIdleTimeout            time.Duration
	SessionAbsoluteTimeout        time.Duration
	PasswordKDFConcurrency        int
	ProtectedConfigurationTimeout time.Duration
	Now                           func() time.Time
	NewID                         func() (uuid.UUID, error)
}

// Service owns authentication policy and orchestrates transactional repository operations.
type Service struct {
	repository                        Repository
	passwords                         passwordEngine
	tokens                            tokenSource
	totp                              totpEngine
	cipher                            secretCryptor
	bootstrapTokenDigest              []byte
	bootstrapEnrollmentTimeout        time.Duration
	mfaChallengeTimeout               time.Duration
	sessionIdleTimeout                time.Duration
	sessionAbsoluteTimeout            time.Duration
	dummyPasswordHash                 string
	csrfKey                           []byte
	rateLimitKey                      []byte
	masterKeyVerifier                 []byte
	protectedConfigurationTimeout     time.Duration
	protectedConfigurationMu          sync.Mutex
	protectedConfigurationState       uint32
	protectedConfigurationAvailable   bool
	protectedConfigurationCheckedAt   time.Time
	protectedConfigurationCheckFailed bool
	protectedConfigurationRefresh     *protectedConfigurationRefresh
	passwordWorkSlots                 chan struct{}
	now                               func() time.Time
	newID                             func() (uuid.UUID, error)
	federatedSessionAuthorityMu       sync.RWMutex
	federatedSessionAuthority         FederatedSessionAuthority
	directPlatformSessionAuthorityMu  sync.RWMutex
	directPlatformSessionAuthority    DirectPlatformSessionAuthority
	directPlatformTenantSwitcherMu    sync.RWMutex
	directPlatformTenantSwitcher      DirectPlatformTenantSwitcher
}

type protectedConfigurationRefresh struct {
	done        chan struct{}
	invalidated bool
}

func NewService(options ServiceOptions) (*Service, error) {
	if options.Repository == nil || options.Passwords == nil || options.Tokens == nil || options.TOTP == nil || options.Cipher == nil {
		return nil, errors.New("authentication service dependencies are required")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.NewID == nil {
		options.NewID = uuid.NewV7
	}
	if len(options.RateLimitKeyMaterial) < 32 {
		return nil, errors.New("authentication rate-limit key material must contain at least 32 bytes")
	}
	if options.BootstrapEnrollmentTimeout <= 0 || options.MFAChallengeTimeout <= 0 ||
		options.SessionIdleTimeout <= 0 || options.SessionAbsoluteTimeout < options.SessionIdleTimeout {
		return nil, errors.New("authentication service timeouts are invalid")
	}
	if options.PasswordKDFConcurrency == 0 {
		options.PasswordKDFConcurrency = defaultPasswordVerificationConcurrency
	}
	if options.PasswordKDFConcurrency < 1 || options.PasswordKDFConcurrency > 16 {
		return nil, errors.New("password KDF concurrency must be between 1 and 16")
	}
	if options.ProtectedConfigurationTimeout <= 0 {
		options.ProtectedConfigurationTimeout = defaultProtectedConfigurationTimeout
	}
	if options.ProtectedConfigurationTimeout > 30*time.Second {
		return nil, errors.New("protected configuration timeout must not exceed 30s")
	}
	rateLimitKey, err := hkdf.Key(sha256.New, options.RateLimitKeyMaterial, nil, rateLimitKeyInfo, sha256DigestLength)
	if err != nil {
		return nil, errors.New("derive authentication rate-limit key")
	}
	csrfKey, err := hkdf.Key(sha256.New, options.RateLimitKeyMaterial, nil, csrfKeyInfo, sha256DigestLength)
	if err != nil {
		return nil, errors.New("derive authentication CSRF key")
	}
	masterKeyVerifier, err := hkdf.Key(
		sha256.New, options.RateLimitKeyMaterial, nil, masterKeyVerifierInfo, sha256DigestLength,
	)
	if err != nil {
		return nil, errors.New("derive authentication master-key verifier")
	}
	dummyHash, err := options.Passwords.Hash("periapsis-enumeration-resistant-dummy-password")
	if err != nil {
		return nil, errors.New("initialize password verifier")
	}
	return &Service{
		repository:                    options.Repository,
		passwords:                     options.Passwords,
		tokens:                        options.Tokens,
		totp:                          options.TOTP,
		cipher:                        options.Cipher,
		bootstrapTokenDigest:          append([]byte(nil), options.BootstrapTokenDigest...),
		bootstrapEnrollmentTimeout:    options.BootstrapEnrollmentTimeout,
		mfaChallengeTimeout:           options.MFAChallengeTimeout,
		sessionIdleTimeout:            options.SessionIdleTimeout,
		sessionAbsoluteTimeout:        options.SessionAbsoluteTimeout,
		dummyPasswordHash:             dummyHash,
		csrfKey:                       csrfKey,
		rateLimitKey:                  rateLimitKey,
		masterKeyVerifier:             masterKeyVerifier,
		protectedConfigurationTimeout: options.ProtectedConfigurationTimeout,
		protectedConfigurationState:   protectedConfigurationReadinessBlocked,
		passwordWorkSlots:             make(chan struct{}, options.PasswordKDFConcurrency),
		now:                           options.Now,
		newID:                         options.NewID,
	}, nil
}

// VerifyProtectedConfiguration binds the deployment's domain-separated master
// key verifier before bootstrap and compare-checks it thereafter. Neither raw
// key material nor a reversible derivative crosses the repository boundary.
func (s *Service) VerifyProtectedConfiguration(ctx context.Context) error {
	_, err := s.refreshProtectedConfiguration(ctx)
	return err
}

// InvalidateProtectedConfiguration prevents request paths from relying on a
// previously verified secret binding after a readiness prerequisite fails.
// Only a later successful forced readiness check may unblock request traffic.
func (s *Service) InvalidateProtectedConfiguration() {
	s.protectedConfigurationMu.Lock()
	defer s.protectedConfigurationMu.Unlock()
	if s.protectedConfigurationRefresh != nil {
		s.protectedConfigurationRefresh.invalidated = true
	}
	s.protectedConfigurationState = protectedConfigurationReadinessBlocked
	s.protectedConfigurationCheckedAt = time.Time{}
	s.protectedConfigurationCheckFailed = false
}

func (s *Service) requireProtectedConfiguration(ctx context.Context) error {
	for {
		s.protectedConfigurationMu.Lock()
		if s.protectedConfigurationState == protectedConfigurationVerified &&
			s.protectedConfigurationRefresh == nil {
			s.protectedConfigurationMu.Unlock()
			return nil
		}
		refresh := s.protectedConfigurationRefresh
		if refresh == nil || refresh.invalidated {
			s.protectedConfigurationMu.Unlock()
			return ErrUnavailable
		}
		s.protectedConfigurationMu.Unlock()
		if !waitForProtectedConfigurationRefresh(ctx, refresh.done) ||
			s.protectedConfigurationRefreshWasInvalidated(refresh) {
			return ErrUnavailable
		}
	}
}

func (s *Service) verifyProtectedConfiguration() (bool, error) {
	if len(s.bootstrapTokenDigest) != sha256DigestLength ||
		len(s.masterKeyVerifier) != sha256DigestLength {
		return false, ErrUnavailable
	}
	verificationContext, cancel := context.WithTimeout(
		context.Background(), s.protectedConfigurationTimeout,
	)
	defer cancel()
	available, err := s.repository.VerifyProtectedConfiguration(
		verificationContext, s.bootstrapTokenDigest, s.masterKeyVerifier,
	)
	if err != nil {
		return false, ErrUnavailable
	}
	return available, nil
}

func (s *Service) BootstrapStatus(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, ErrUnavailable
	}
	s.protectedConfigurationMu.Lock()
	defer s.protectedConfigurationMu.Unlock()
	if s.protectedConfigurationState != protectedConfigurationVerified ||
		s.protectedConfigurationRefresh != nil {
		return false, ErrUnavailable
	}
	return s.protectedConfigurationAvailable, nil
}

func (s *Service) refreshProtectedConfiguration(ctx context.Context) (bool, error) {
	for {
		now := s.now().UTC()
		s.protectedConfigurationMu.Lock()
		if s.protectedConfigurationRefresh == nil &&
			protectedConfigurationCheckIsFresh(now, s.protectedConfigurationCheckedAt) {
			if s.protectedConfigurationCheckFailed {
				s.protectedConfigurationMu.Unlock()
				return false, ErrUnavailable
			}
			if s.protectedConfigurationState == protectedConfigurationVerified {
				available := s.protectedConfigurationAvailable
				s.protectedConfigurationMu.Unlock()
				return available, nil
			}
		}

		refresh := s.protectedConfigurationRefresh
		joinedInvalidatedRefresh := refresh != nil && refresh.invalidated
		if refresh == nil {
			refresh = s.startProtectedConfigurationRefreshLocked()
			s.protectedConfigurationMu.Unlock()
			go s.runProtectedConfigurationRefresh(refresh)
		} else {
			s.protectedConfigurationMu.Unlock()
		}
		if !waitForProtectedConfigurationRefresh(ctx, refresh.done) {
			return false, ErrUnavailable
		}
		if s.protectedConfigurationRefreshWasInvalidated(refresh) && !joinedInvalidatedRefresh {
			return false, ErrUnavailable
		}
	}
}

func (s *Service) startProtectedConfigurationRefreshLocked() *protectedConfigurationRefresh {
	refresh := &protectedConfigurationRefresh{done: make(chan struct{})}
	s.protectedConfigurationRefresh = refresh
	s.protectedConfigurationState = protectedConfigurationReadinessBlocked
	return refresh
}

func (s *Service) runProtectedConfigurationRefresh(refresh *protectedConfigurationRefresh) {
	available, err := s.verifyProtectedConfiguration()
	completedAt := s.now().UTC()

	s.protectedConfigurationMu.Lock()
	if s.protectedConfigurationRefresh == refresh {
		if !refresh.invalidated {
			s.protectedConfigurationCheckedAt = completedAt
			s.protectedConfigurationCheckFailed = err != nil
			if err == nil {
				s.protectedConfigurationState = protectedConfigurationVerified
				s.protectedConfigurationAvailable = available
			} else {
				s.protectedConfigurationState = protectedConfigurationReadinessBlocked
			}
		}
		s.protectedConfigurationRefresh = nil
		close(refresh.done)
	}
	s.protectedConfigurationMu.Unlock()
}

func waitForProtectedConfigurationRefresh(ctx context.Context, done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Service) protectedConfigurationRefreshWasInvalidated(refresh *protectedConfigurationRefresh) bool {
	s.protectedConfigurationMu.Lock()
	defer s.protectedConfigurationMu.Unlock()
	return refresh.invalidated
}

func protectedConfigurationCheckIsFresh(now time.Time, checkedAt time.Time) bool {
	return !checkedAt.IsZero() && !now.Before(checkedAt) &&
		now.Sub(checkedAt) < protectedConfigurationRefreshInterval
}

func (s *Service) StartBootstrap(
	ctx context.Context,
	authorityToken string,
	email string,
	event EventContext,
) (BootstrapEnrollment, error) {
	if err := s.requireProtectedConfiguration(ctx); err != nil {
		return BootstrapEnrollment{}, ErrUnavailable
	}
	now := s.now().UTC()
	keys := s.networkRateKeys(rateScopeBootstrap, "bootstrap", event)
	if len(keys) == 0 {
		return BootstrapEnrollment{}, ErrUnavailable
	}
	if err := s.requireRateLimit(ctx, keys, now); err != nil {
		return BootstrapEnrollment{}, err
	}
	authorityDigest, ok := s.validateBootstrapAuthority(authorityToken)
	if !ok {
		return BootstrapEnrollment{}, s.recordFailure(ctx, RecordAuthFailureParams{
			Keys: keys, Policy: bootstrapRatePolicy, OccurredAt: now,
			Action: "authentication.bootstrap_authority_failed", Event: event,
		})
	}
	canonicalEmail, err := canonicalEmail(email)
	if err != nil {
		return BootstrapEnrollment{}, ErrInvalidInput
	}
	enrollmentToken, err := s.tokens.Opaque()
	if err != nil {
		return BootstrapEnrollment{}, ErrUnavailable
	}
	enrollmentID, err := s.newID()
	if err != nil {
		return BootstrapEnrollment{}, ErrUnavailable
	}
	secret, provisioningURI, err := s.totp.Generate(canonicalEmail)
	if err != nil {
		return BootstrapEnrollment{}, ErrUnavailable
	}
	encrypted, err := s.cipher.EncryptTOTP(bootstrapTOTPContext(enrollmentID, canonicalEmail), secret)
	if err != nil {
		return BootstrapEnrollment{}, ErrUnavailable
	}
	expiresAt := now.Add(s.bootstrapEnrollmentTimeout)
	err = s.repository.ReserveBootstrap(ctx, ReserveBootstrapParams{
		AuthorityDigest:   authorityDigest,
		EnrollmentDigest:  digest(enrollmentToken),
		EnrollmentRateKey: s.rateKey(rateScopeBootstrap, "bootstrap.enrollment", enrollmentToken).Digest,
		CanonicalEmail:    canonicalEmail,
		Enrollment: StoredBootstrapEnrollment{
			ID:             enrollmentID,
			CanonicalEmail: canonicalEmail,
			EncryptedTOTP:  encrypted,
			ExpiresAt:      expiresAt,
		},
		MaxAttempts: maxMFAAttempts,
		Event:       event,
	})
	if err != nil {
		return BootstrapEnrollment{}, publicRepositoryError(err)
	}
	return BootstrapEnrollment{
		EnrollmentToken: enrollmentToken,
		ExpiresAt:       expiresAt,
		TOTPSecret:      secret,
		TOTPURI:         provisioningURI,
	}, nil
}

func (s *Service) ConfirmBootstrap(
	ctx context.Context,
	authorityToken string,
	input BootstrapConfirmation,
) (BootstrapResult, error) {
	if err := s.requireProtectedConfiguration(ctx); err != nil {
		return BootstrapResult{}, ErrUnavailable
	}
	now := s.now().UTC()
	keys := s.networkRateKeys(rateScopeBootstrap, "bootstrap", input.Event)
	if len(keys) == 0 {
		return BootstrapResult{}, ErrUnavailable
	}
	if err := s.requireRateLimit(ctx, keys, now); err != nil {
		return BootstrapResult{}, err
	}
	authorityDigest, ok := s.validateBootstrapAuthority(authorityToken)
	if !ok || !validOpaqueToken(input.EnrollmentToken) {
		return BootstrapResult{}, s.recordFailure(ctx, RecordAuthFailureParams{
			Keys: keys, Policy: bootstrapRatePolicy, OccurredAt: now,
			Action: "authentication.bootstrap_proof_failed", Event: input.Event,
		})
	}
	keys = append(keys, s.rateKey(rateScopeBootstrap, "bootstrap.enrollment", input.EnrollmentToken))
	if err := s.requireRateLimit(ctx, keys, now); err != nil {
		return BootstrapResult{}, err
	}
	canonicalEmail, err := canonicalEmail(input.Email)
	if err != nil || !validDisplayName(input.DisplayName) || !validNewPassword(input.Password) {
		return BootstrapResult{}, ErrInvalidInput
	}
	enrollmentDigest := digest(input.EnrollmentToken)
	enrollment, err := s.repository.GetBootstrapEnrollment(ctx, authorityDigest, enrollmentDigest, now)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return BootstrapResult{}, ErrConflict
		}
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidAuthentication) {
			return BootstrapResult{}, s.recordFailure(ctx, RecordAuthFailureParams{
				Keys: keys, Policy: bootstrapRatePolicy, OccurredAt: now,
				Action: "authentication.bootstrap_proof_failed", Event: input.Event,
			})
		}
		return BootstrapResult{}, ErrUnavailable
	}
	if enrollment.CanonicalEmail != canonicalEmail {
		return BootstrapResult{}, s.recordBootstrapFailure(
			ctx, authorityDigest, enrollmentDigest, enrollment.ID, keys, now, input.Event,
		)
	}
	secret, err := s.cipher.DecryptTOTP(
		bootstrapTOTPContext(enrollment.ID, enrollment.CanonicalEmail),
		enrollment.EncryptedTOTP,
	)
	if err != nil {
		return BootstrapResult{}, ErrUnavailable
	}
	acceptedCounter, err := s.totp.Validate(secret, input.Code, now, -1)
	if err != nil {
		return BootstrapResult{}, s.recordBootstrapFailure(
			ctx, authorityDigest, enrollmentDigest, enrollment.ID, keys, now, input.Event,
		)
	}
	if !s.acquirePasswordWorkSlot(ctx) {
		return BootstrapResult{}, &RateLimitError{RetryAfter: time.Second}
	}
	passwordHash, err := func() (string, error) {
		defer s.releasePasswordWorkSlot()
		return s.passwords.Hash(input.Password)
	}()
	if err != nil {
		return BootstrapResult{}, ErrUnavailable
	}
	userID, err := s.newID()
	if err != nil {
		return BootstrapResult{}, ErrUnavailable
	}
	localCredentialID, err := s.newID()
	if err != nil {
		return BootstrapResult{}, ErrUnavailable
	}
	totpCredentialID, err := s.newID()
	if err != nil {
		return BootstrapResult{}, ErrUnavailable
	}
	platformRoleGrantID, err := s.newID()
	if err != nil {
		return BootstrapResult{}, ErrUnavailable
	}
	auditID, err := s.newID()
	if err != nil {
		return BootstrapResult{}, ErrUnavailable
	}
	// The sealed, unversioned bootstrap ABI requires the original owner/factor
	// context. Revision-bound writes belong to the administrative enrollment ABI.
	confirmedContext := credentialTOTPContext(totpCredentialID, userID)
	confirmedTOTP, err := s.cipher.EncryptTOTP(confirmedContext, secret)
	if err != nil {
		return BootstrapResult{}, ErrUnavailable
	}
	recoveryCodes, recoveryMaterial, err := s.generateRecoveryCodes()
	if err != nil {
		return BootstrapResult{}, ErrUnavailable
	}
	sessionMaterial, sessionToken, csrfToken, err := s.newSessionMaterial(now, "bootstrap_totp")
	if err != nil {
		return BootstrapResult{}, ErrUnavailable
	}
	session, err := s.repository.ConfirmBootstrap(ctx, ConfirmBootstrapParams{
		AuthorityDigest:     authorityDigest,
		EnrollmentDigest:    enrollmentDigest,
		EnrollmentID:        enrollment.ID,
		CanonicalEmail:      canonicalEmail,
		DisplayName:         strings.TrimSpace(input.DisplayName),
		PasswordHash:        passwordHash,
		TOTP:                confirmedTOTP,
		AcceptedTOTPCounter: acceptedCounter,
		UserID:              userID,
		LocalCredentialID:   localCredentialID,
		TOTPCredentialID:    totpCredentialID,
		PlatformRoleGrantID: platformRoleGrantID,
		AuditID:             auditID,
		RecoveryCodes:       recoveryMaterial,
		Session:             sessionMaterial,
		Event:               input.Event,
	})
	if err != nil {
		return BootstrapResult{}, publicRepositoryError(err)
	}
	s.markBootstrapCompleted()
	return BootstrapResult{
		Credential:    SessionCredential{Session: session, SessionToken: sessionToken, CSRFToken: csrfToken},
		RecoveryCodes: recoveryCodes,
	}, nil
}

func (s *Service) markBootstrapCompleted() {
	s.protectedConfigurationMu.Lock()
	defer s.protectedConfigurationMu.Unlock()
	s.protectedConfigurationAvailable = false
	if s.protectedConfigurationRefresh != nil {
		s.protectedConfigurationRefresh.invalidated = true
		s.protectedConfigurationState = protectedConfigurationReadinessBlocked
		s.protectedConfigurationCheckedAt = time.Time{}
		s.protectedConfigurationCheckFailed = false
		return
	}
	if s.protectedConfigurationState == protectedConfigurationVerified {
		s.protectedConfigurationCheckedAt = s.now().UTC()
	} else {
		s.protectedConfigurationCheckedAt = time.Time{}
	}
	s.protectedConfigurationCheckFailed = false
}

func (s *Service) StartPasswordLogin(
	ctx context.Context,
	email string,
	password string,
	event EventContext,
) (MFAChallenge, error) {
	if err := s.requireProtectedConfiguration(ctx); err != nil {
		return MFAChallenge{}, ErrUnavailable
	}
	canonical, emailErr := canonicalEmail(email)
	passwordForVerification := password
	if emailErr != nil || !validLoginPassword(password) {
		canonical = "invalid@invalid.invalid"
		passwordForVerification = "periapsis-invalid-login-password"
	}
	now := s.now().UTC()
	rules := s.loginRateRules(canonical, event)
	blockedUntil, err := s.repository.AdmitRateLimits(ctx, AdmitRateLimitsParams{Rules: rules, OccurredAt: now})
	if err != nil {
		return MFAChallenge{}, ErrUnavailable
	}
	if blockedUntil.After(now) {
		return MFAChallenge{}, &RateLimitError{RetryAfter: blockedUntil.Sub(now)}
	}
	if len(rules) == 0 {
		return MFAChallenge{}, ErrUnavailable
	}
	credential, err := s.repository.FindLocalCredential(ctx, canonical)
	credentialExists := err == nil && credential.Enabled
	if err != nil && !errors.Is(err, ErrNotFound) {
		return MFAChallenge{}, ErrUnavailable
	}
	hash := s.dummyPasswordHash
	if credentialExists {
		hash = credential.PasswordHash
	}
	if !s.acquirePasswordWorkSlot(ctx) {
		return MFAChallenge{}, &RateLimitError{RetryAfter: time.Second}
	}
	passwordValid := func() bool {
		defer s.releasePasswordWorkSlot()
		return s.passwords.Verify(passwordForVerification, hash)
	}()
	if emailErr != nil || !credentialExists || !passwordValid {
		var failedUserID *uuid.UUID
		if credentialExists {
			userID := credential.User.ID
			failedUserID = &userID
		}
		if err := s.repository.RecordPasswordFailure(ctx, RecordPasswordFailureParams{
			OccurredAt: now, UserID: failedUserID, MeteredAccountKey: rules[0].Key, Event: event,
		}); err != nil {
			return MFAChallenge{}, ErrUnavailable
		}
		return MFAChallenge{}, ErrInvalidAuthentication
	}
	challengeID, err := s.newID()
	if err != nil {
		return MFAChallenge{}, ErrUnavailable
	}
	challengeToken, err := s.tokens.Opaque()
	if err != nil {
		return MFAChallenge{}, ErrUnavailable
	}
	expiresAt := now.Add(s.mfaChallengeTimeout)
	err = s.repository.CreateMFAChallenge(ctx, CreateMFAChallengeParams{
		ID: challengeID, TokenDigest: digest(challengeToken), UserID: credential.User.ID,
		ChallengeRateKey:    s.rateKey(rateScopeMFA, "mfa.challenge", challengeToken).Digest,
		UserRateKey:         s.rateKey(rateScopeMFA, "mfa.user", credential.User.ID.String()).Digest,
		LoginAccountRateKey: rules[0].Key.Digest,
		ExpiresAt:           expiresAt, MaxAttempts: maxMFAAttempts, OccurredAt: now,
		Event: event,
	})
	if err != nil {
		return MFAChallenge{}, publicRepositoryError(err)
	}
	return MFAChallenge{
		ChallengeToken: challengeToken,
		ExpiresAt:      expiresAt,
		Methods:        []string{"totp", "recovery_code"},
	}, nil
}

func (s *Service) acquirePasswordWorkSlot(ctx context.Context) bool {
	select {
	case s.passwordWorkSlots <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	default:
		return false
	}
}

func (s *Service) releasePasswordWorkSlot() {
	<-s.passwordWorkSlots
}

func (s *Service) CompleteMFA(
	ctx context.Context,
	challengeToken string,
	method string,
	code string,
	event EventContext,
) (SessionCredential, error) {
	if err := s.requireProtectedConfiguration(ctx); err != nil {
		return SessionCredential{}, ErrUnavailable
	}
	now := s.now().UTC()
	keys := s.mfaPreLookupRateKeys(challengeToken, event)
	if err := s.requireRateLimit(ctx, keys, now); err != nil {
		return SessionCredential{}, err
	}
	if !validOpaqueToken(challengeToken) || (method != "totp" && method != "recovery_code") || len(code) > 64 {
		return SessionCredential{}, s.recordFailure(ctx, RecordAuthFailureParams{
			Keys: keys, Policy: mfaRatePolicy, OccurredAt: now,
			Action: "authentication.mfa_failed", Event: event,
		})
	}
	challengeDigest := digest(challengeToken)
	challenge, err := s.repository.GetMFAChallenge(ctx, challengeDigest, now)
	if err != nil {
		if err != nil && !errors.Is(err, ErrNotFound) {
			return SessionCredential{}, ErrUnavailable
		}
		return SessionCredential{}, s.recordFailure(ctx, RecordAuthFailureParams{
			Keys: keys, Policy: mfaRatePolicy, OccurredAt: now,
			Action: "authentication.mfa_failed", Event: event,
		})
	}
	keys = append(keys, s.rateKey(rateScopeMFA, "mfa.user", challenge.User.ID.String()))
	if err := s.requireRateLimit(ctx, keys, now); err != nil {
		return SessionCredential{}, err
	}
	if challenge.Attempts >= challenge.MaxAttempts {
		return SessionCredential{}, ErrInvalidAuthentication
	}
	sessionMaterial, sessionToken, csrfToken, err := s.newSessionMaterial(now, method)
	if err != nil {
		return SessionCredential{}, ErrUnavailable
	}
	var session Session
	switch method {
	case "totp":
		context, factorRevision, validContext := credentialTOTPDecryptionContext(
			challenge.TOTPContextID, challenge.User.ID, challenge.EncryptedTOTP.AAD,
		)
		// The legacy password challenge ABI does not yet return the factor
		// security revision. New revision-one factors are accepted; a later
		// revision must be rewrapped and exposed by that ABI before use.
		if !validContext || factorRevision > 1 {
			return SessionCredential{}, ErrUnavailable
		}
		secret, decryptErr := s.cipher.DecryptTOTP(context, challenge.EncryptedTOTP)
		if decryptErr != nil {
			return SessionCredential{}, ErrUnavailable
		}
		counter, validationErr := s.totp.Validate(secret, code, now, challenge.LastAcceptedCounter)
		if validationErr != nil {
			return SessionCredential{}, s.recordMFAFailure(ctx, challenge, challengeDigest, keys, now, event)
		}
		auditID, auditErr := s.newID()
		if auditErr != nil {
			return SessionCredential{}, ErrUnavailable
		}
		session, err = s.repository.CompleteTOTPChallenge(ctx, CompleteTOTPParams{
			ChallengeDigest: challengeDigest, ChallengeID: challenge.ID, UserID: challenge.User.ID,
			AcceptedCounter: counter, AuditID: auditID, Session: sessionMaterial,
			ClearKeys: s.mfaSuccessClearKeys(keys), FailureKeys: keys,
			FailurePolicy: mfaRatePolicy, Event: event,
		})
	case "recovery_code":
		recoveryDigest, valid := recoveryCodeDigest(code)
		if !valid {
			return SessionCredential{}, s.recordMFAFailure(ctx, challenge, challengeDigest, keys, now, event)
		}
		auditID, auditErr := s.newID()
		if auditErr != nil {
			return SessionCredential{}, ErrUnavailable
		}
		session, err = s.repository.CompleteRecoveryChallenge(ctx, CompleteRecoveryParams{
			ChallengeDigest: challengeDigest, ChallengeID: challenge.ID, UserID: challenge.User.ID,
			RecoveryDigest: recoveryDigest, AuditID: auditID, Session: sessionMaterial,
			ClearKeys: s.mfaSuccessClearKeys(keys), FailureKeys: keys,
			FailurePolicy: mfaRatePolicy, Event: event,
		})
	}
	if err != nil {
		var rateLimit *RateLimitError
		if errors.As(err, &rateLimit) {
			return SessionCredential{}, rateLimit
		}
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidAuthentication) {
			return SessionCredential{}, ErrInvalidAuthentication
		}
		return SessionCredential{}, ErrUnavailable
	}
	return SessionCredential{Session: session, SessionToken: sessionToken, CSRFToken: csrfToken}, nil
}

func (s *Service) RotateCurrentSession(
	ctx context.Context,
	currentToken string,
	event EventContext,
) (SessionCredential, error) {
	if !validOpaqueToken(currentToken) {
		return SessionCredential{}, ErrInvalidAuthentication
	}
	current, err := s.Authenticate(ctx, currentToken)
	if err != nil {
		return SessionCredential{}, err
	}
	now := s.now().UTC()
	newSessionID, err := s.newID()
	if err != nil {
		return SessionCredential{}, ErrUnavailable
	}
	newToken, err := s.tokens.Opaque()
	if err != nil {
		return SessionCredential{}, ErrUnavailable
	}
	csrfToken := s.csrfForSession(newSessionID)
	idleExpiresAt := now.Add(s.sessionIdleTimeout).Truncate(time.Millisecond)
	if idleExpiresAt.After(current.AbsoluteExpiresAt) {
		idleExpiresAt = current.AbsoluteExpiresAt
	}
	session, err := s.repository.RotateSession(ctx, RotateSessionParams{
		CurrentTokenDigest: digest(currentToken),
		NewSessionID:       newSessionID,
		NewTokenDigest:     digest(newToken),
		NewCSRFDigest:      digest(csrfToken),
		Now:                now,
		IdleExpiresAt:      idleExpiresAt,
		AbsoluteExpiresAt:  current.AbsoluteExpiresAt,
		Event:              event,
	})
	if err != nil {
		return SessionCredential{}, publicSessionError(err)
	}
	return SessionCredential{Session: session, SessionToken: newToken, CSRFToken: csrfToken}, nil
}

// CurrentSession rehydrates the session-bound CSRF value without rotating the
// cookie credential, so concurrent and retried safe reads remain idempotent.
func (s *Service) CurrentSession(ctx context.Context, sessionToken string) (SessionCredential, error) {
	session, err := s.Authenticate(ctx, sessionToken)
	if err != nil {
		return SessionCredential{}, err
	}
	csrfToken := s.csrfForSession(session.ID)
	if len(session.CSRFDigest) != sha256DigestLength ||
		subtle.ConstantTimeCompare(session.CSRFDigest, digest(csrfToken)) != 1 {
		return SessionCredential{}, ErrUnavailable
	}
	return SessionCredential{Session: session, SessionToken: sessionToken, CSRFToken: csrfToken}, nil
}

func (s *Service) Authenticate(ctx context.Context, sessionToken string) (Session, error) {
	if err := s.requireProtectedConfiguration(ctx); err != nil {
		return Session{}, ErrUnavailable
	}
	if !validOpaqueToken(sessionToken) {
		return Session{}, ErrInvalidAuthentication
	}
	now := s.now().UTC()
	session, err := s.repository.ResolveSession(ctx, digest(sessionToken), now)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidAuthentication) {
			return Session{}, ErrInvalidAuthentication
		}
		return Session{}, ErrUnavailable
	}
	if session.RevokedAt != nil || !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) {
		return Session{}, ErrInvalidAuthentication
	}
	if err := s.revalidateFederatedSession(ctx, session); err != nil {
		return Session{}, err
	}
	idleExpiresAt := now.Add(s.sessionIdleTimeout).Truncate(time.Millisecond)
	if idleExpiresAt.After(session.AbsoluteExpiresAt) {
		idleExpiresAt = session.AbsoluteExpiresAt
	}
	if err := s.repository.TouchSession(ctx, digest(sessionToken), now, idleExpiresAt); err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidAuthentication) {
			return Session{}, ErrInvalidAuthentication
		}
		return Session{}, ErrUnavailable
	}
	session.LastSeenAt = now
	session.IdleExpiresAt = idleExpiresAt
	return session, nil
}

func (s *Service) ValidateCSRF(session Session, csrfToken string) error {
	if !validOpaqueToken(csrfToken) || len(session.CSRFDigest) != sha256DigestLength {
		return ErrForbidden
	}
	if subtle.ConstantTimeCompare(session.CSRFDigest, digest(csrfToken)) != 1 {
		return ErrForbidden
	}
	return nil
}

func (s *Service) Logout(ctx context.Context, sessionToken, csrfToken string, event EventContext) error {
	session, err := s.Authenticate(ctx, sessionToken)
	if err != nil {
		return err
	}
	if err := s.ValidateCSRF(session, csrfToken); err != nil {
		return err
	}
	if err := s.repository.RevokeCurrentSession(ctx, session.User.ID, session.ID, event); err != nil {
		return publicSessionError(err)
	}
	return nil
}

func (s *Service) Sessions(
	ctx context.Context,
	sessionToken string,
	after *uuid.UUID,
	pageSize int,
) (SessionPage, error) {
	session, err := s.Authenticate(ctx, sessionToken)
	if err != nil {
		return SessionPage{}, err
	}
	if pageSize == 0 {
		pageSize = 50
	}
	if pageSize < 1 || pageSize > 100 || after != nil && *after == uuid.Nil {
		return SessionPage{}, ErrInvalidInput
	}
	items, err := s.repository.ListSessions(ctx, ListSessionsParams{
		ActorID: session.User.ID, CurrentSessionID: session.ID, After: after,
		Limit: int32(pageSize + 1), Now: s.now().UTC(),
	})
	if err != nil {
		if errors.Is(err, ErrInvalidAuthentication) {
			return SessionPage{}, ErrInvalidAuthentication
		}
		if errors.Is(err, ErrInvalidInput) {
			return SessionPage{}, ErrInvalidInput
		}
		return SessionPage{}, ErrUnavailable
	}
	page := SessionPage{Items: items}
	if len(items) > pageSize {
		next := items[pageSize-1].ID
		page.Items = items[:pageSize]
		page.NextCursor = &next
	}
	return page, nil
}

func (s *Service) RevokeSession(
	ctx context.Context,
	sessionToken, csrfToken string,
	targetSessionID uuid.UUID,
	event EventContext,
) error {
	session, err := s.Authenticate(ctx, sessionToken)
	if err != nil {
		return err
	}
	if err := s.ValidateCSRF(session, csrfToken); err != nil {
		return err
	}
	if targetSessionID == uuid.Nil {
		return ErrInvalidInput
	}
	if err := s.repository.RevokeSession(ctx, session.User.ID, targetSessionID, event); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return publicSessionError(err)
	}
	return nil
}

func (s *Service) TenantMemberships(
	ctx context.Context,
	sessionToken string,
	after *uuid.UUID,
	pageSize int,
) (TenantMembershipPage, error) {
	session, err := s.Authenticate(ctx, sessionToken)
	if err != nil {
		return TenantMembershipPage{}, err
	}
	if pageSize == 0 {
		pageSize = 50
	}
	if pageSize < 1 || pageSize > 100 || after != nil && *after == uuid.Nil {
		return TenantMembershipPage{}, ErrInvalidInput
	}
	memberships, err := s.repository.ListTenantMemberships(ctx, ListTenantMembershipsParams{
		ActorID: session.User.ID, After: after, Limit: int32(pageSize + 1),
	})
	if err != nil {
		if errors.Is(err, ErrInvalidAuthentication) {
			return TenantMembershipPage{}, ErrInvalidAuthentication
		}
		if errors.Is(err, ErrInvalidInput) {
			return TenantMembershipPage{}, ErrInvalidInput
		}
		return TenantMembershipPage{}, ErrUnavailable
	}
	page := TenantMembershipPage{Items: memberships}
	if len(memberships) > pageSize {
		next := memberships[pageSize-1].ID
		page.Items = memberships[:pageSize]
		page.NextCursor = &next
	}
	return page, nil
}

func (s *Service) SwitchTenant(
	ctx context.Context,
	sessionToken, csrfToken string,
	tenantID uuid.UUID,
	event EventContext,
) (SessionCredential, error) {
	session, err := s.Authenticate(ctx, sessionToken)
	if err != nil {
		return SessionCredential{}, err
	}
	if err := s.ValidateCSRF(session, csrfToken); err != nil {
		return SessionCredential{}, err
	}
	if tenantID == uuid.Nil {
		return SessionCredential{}, ErrInvalidInput
	}
	if tenantID.Version() != 7 {
		return SessionCredential{}, ErrForbidden
	}
	if session.ActiveTenantID != nil && *session.ActiveTenantID == tenantID {
		return SessionCredential{
			Session: session, SessionToken: sessionToken, CSRFToken: s.csrfForSession(session.ID),
		}, nil
	}
	if session.ActiveTenantID == nil {
		if directPlatformTenantSwitchAuthenticationMethod(session.AuthenticationMethod) {
			return s.switchDirectPlatformTenant(ctx, sessionToken, session, tenantID, event)
		}
	}
	// The legacy tenant rotation ABI preserves only the flat session row. It
	// cannot safely move typed passkey or federated MFA/provenance state, and a
	// provider-backed session additionally needs source-specific target-tenant
	// authorization. Fail closed until the dedicated provenance-aware switch
	// path has accepted the exact target binding and evidence.
	if !legacyTenantRotationMethod(session.AuthenticationMethod) {
		return SessionCredential{}, ErrForbidden
	}
	newToken, err := s.tokens.Opaque()
	if err != nil {
		return SessionCredential{}, ErrUnavailable
	}
	newSessionID, err := s.newID()
	if err != nil {
		return SessionCredential{}, ErrUnavailable
	}
	newCSRF := s.csrfForSession(newSessionID)
	now := s.now().UTC()
	idleExpiresAt := now.Add(s.sessionIdleTimeout).Truncate(time.Millisecond)
	if idleExpiresAt.After(session.AbsoluteExpiresAt) {
		idleExpiresAt = session.AbsoluteExpiresAt
	}
	updated, err := s.repository.SwitchActiveTenant(ctx, SwitchTenantParams{
		CurrentTokenDigest: digest(sessionToken), NewSessionID: newSessionID, NewTokenDigest: digest(newToken),
		NewCSRFDigest: digest(newCSRF), UserID: session.User.ID, TenantID: tenantID,
		Now: now, IdleExpiresAt: idleExpiresAt, AbsoluteExpiresAt: session.AbsoluteExpiresAt, Event: event,
		AdmissionRules: []RateLimitRule{{
			Key:    s.rateKey(rateScopeTenantSwitch, "tenant-switch.user", session.User.ID.String()),
			Policy: tenantSwitchRatePolicy,
		}},
	})
	if err != nil {
		var rateLimit *RateLimitError
		if errors.As(err, &rateLimit) {
			return SessionCredential{}, rateLimit
		}
		if errors.Is(err, ErrForbidden) || errors.Is(err, ErrNotFound) {
			return SessionCredential{}, ErrForbidden
		}
		return SessionCredential{}, ErrUnavailable
	}
	return SessionCredential{Session: updated, SessionToken: newToken, CSRFToken: newCSRF}, nil
}

func legacyTenantRotationMethod(method string) bool {
	switch method {
	case "bootstrap_totp", "totp", "recovery_code":
		return true
	default:
		return false
	}
}

func (s *Service) validateBootstrapAuthority(raw string) ([]byte, bool) {
	provided := digest(raw)
	if len(s.bootstrapTokenDigest) != sha256DigestLength {
		return provided, false
	}
	return provided, subtle.ConstantTimeCompare(provided, s.bootstrapTokenDigest) == 1
}

func (s *Service) generateRecoveryCodes() ([]string, []RecoveryCodeMaterial, error) {
	display := make([]string, 0, recoveryCodeCount)
	material := make([]RecoveryCodeMaterial, 0, recoveryCodeCount)
	for range recoveryCodeCount {
		code, codeDigest, err := s.tokens.RecoveryCode()
		if err != nil {
			return nil, nil, err
		}
		id, err := s.newID()
		if err != nil {
			return nil, nil, err
		}
		display = append(display, code)
		material = append(material, RecoveryCodeMaterial{ID: id, Digest: codeDigest})
	}
	return display, material, nil
}

func (s *Service) newSessionMaterial(now time.Time, method string) (SessionMaterial, string, string, error) {
	id, err := s.newID()
	if err != nil {
		return SessionMaterial{}, "", "", err
	}
	familyID, err := s.newID()
	if err != nil {
		return SessionMaterial{}, "", "", err
	}
	token, err := s.tokens.Opaque()
	if err != nil {
		return SessionMaterial{}, "", "", err
	}
	csrf := s.csrfForSession(id)
	return SessionMaterial{
		ID: id, FamilyID: familyID, TokenDigest: digest(token), CSRFDigest: digest(csrf),
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(s.sessionIdleTimeout).Truncate(time.Millisecond),
		AbsoluteExpiresAt: now.Add(s.sessionAbsoluteTimeout).Truncate(time.Millisecond), AuthenticationMethod: method,
	}, token, csrf, nil
}

// ReserveMFASession allocates browser credentials before an MFA transaction.
// The caller must discard them unless the transaction commits. Existing
// sessions rotate inside their pinned family and never extend absolute expiry.
func (s *Service) ReserveMFASession(
	current *Session,
	method mfa.SessionAuthenticationMethod,
) (MFASessionReservation, error) {
	if s == nil || s.tokens == nil || s.newID == nil || s.now == nil {
		return MFASessionReservation{}, ErrUnavailable
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	return s.reserveMFASessionAt(current, method, now)
}

// ReserveMFASessionAt allocates the exact browser credential described by an
// authority-backed MFA completion plan. The database-observed issue instant is
// retained at UTC microsecond precision; only persisted expiry deadlines are
// rounded to UTC milliseconds.
func (s *Service) ReserveMFASessionAt(
	current *Session,
	method mfa.SessionAuthenticationMethod,
	issuedAt time.Time,
) (MFASessionReservation, error) {
	if s == nil || s.tokens == nil || s.newID == nil {
		return MFASessionReservation{}, ErrUnavailable
	}
	return s.reserveMFASessionAt(current, method, issuedAt)
}

func (s *Service) reserveMFASessionAt(
	current *Session,
	method mfa.SessionAuthenticationMethod,
	issuedAt time.Time,
) (MFASessionReservation, error) {
	if s == nil || s.tokens == nil || s.newID == nil {
		return MFASessionReservation{}, ErrUnavailable
	}
	switch method {
	case mfa.SessionAuthenticationPasskey, mfa.SessionAuthenticationTOTP,
		mfa.SessionAuthenticationRecovery, mfa.SessionAuthenticationOIDC,
		mfa.SessionAuthenticationSAML, mfa.SessionAuthenticationLDAP:
	default:
		return MFASessionReservation{}, ErrInvalidInput
	}
	now := issuedAt.UTC().Truncate(time.Microsecond)
	if now.IsZero() || now.Nanosecond()%int(time.Microsecond) != 0 {
		return MFASessionReservation{}, ErrUnavailable
	}
	sessionID, err := s.newID()
	if err != nil || sessionID == uuid.Nil || sessionID.Version() != 7 {
		return MFASessionReservation{}, ErrUnavailable
	}
	familyID := uuid.Nil
	idleExpiresAt := now.Add(s.sessionIdleTimeout).Truncate(time.Millisecond)
	absoluteExpiresAt := now.Add(s.sessionAbsoluteTimeout).Truncate(time.Millisecond)
	if current == nil {
		familyID, err = s.newID()
		if err != nil || familyID == uuid.Nil || familyID.Version() != 7 || familyID == sessionID {
			return MFASessionReservation{}, ErrUnavailable
		}
	} else {
		if current.ID == uuid.Nil || current.RotationFamilyID == uuid.Nil ||
			current.RotationFamilyID.Version() != 7 || current.AbsoluteExpiresAt.IsZero() ||
			!current.AbsoluteExpiresAt.After(now) || sessionID == current.ID ||
			sessionID == current.RotationFamilyID {
			return MFASessionReservation{}, ErrInvalidAuthentication
		}
		familyID = current.RotationFamilyID
		absoluteExpiresAt = current.AbsoluteExpiresAt.UTC().Truncate(time.Millisecond)
		if idleExpiresAt.After(absoluteExpiresAt) {
			idleExpiresAt = absoluteExpiresAt
		}
	}
	token, err := s.tokens.Opaque()
	if err != nil || !validOpaqueToken(token) {
		return MFASessionReservation{}, ErrUnavailable
	}
	csrf := s.csrfForSession(sessionID)
	if !validOpaqueToken(csrf) || csrf == token {
		return MFASessionReservation{}, ErrUnavailable
	}
	tokenDigest := sha256.Sum256([]byte(token))
	csrfDigest := sha256.Sum256([]byte(csrf))
	reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID: identity.EntityID(sessionID), FamilyID: identity.EntityID(familyID),
		TokenDigest: tokenDigest, CSRFDigest: csrfDigest, AuthenticationMethod: method,
		IdleExpiresAt: idleExpiresAt, AbsoluteExpiresAt: absoluteExpiresAt,
	}, now)
	if err != nil {
		return MFASessionReservation{}, ErrUnavailable
	}
	tokenBytes := []byte(token)
	csrfBytes := []byte(csrf)
	defer clear(tokenBytes)
	defer clear(csrfBytes)
	result, err := NewMFASessionReservation(reservation, tokenBytes, csrfBytes)
	if err != nil {
		return MFASessionReservation{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) csrfForSession(sessionID uuid.UUID) string {
	mac := hmac.New(sha256.New, s.csrfKey)
	_, _ = mac.Write([]byte(sessionID.String()))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Service) requireRateLimit(ctx context.Context, keys []RateLimitKey, now time.Time) error {
	blockedUntil, err := s.repository.CheckRateLimit(ctx, keys, now)
	if err != nil {
		return ErrUnavailable
	}
	if blockedUntil.After(now) {
		return &RateLimitError{RetryAfter: blockedUntil.Sub(now)}
	}
	return nil
}

func (s *Service) recordFailure(ctx context.Context, params RecordAuthFailureParams) error {
	blockedUntil, err := s.repository.RecordAuthFailure(ctx, params)
	if err != nil {
		return ErrUnavailable
	}
	if blockedUntil.After(params.OccurredAt) {
		return &RateLimitError{RetryAfter: blockedUntil.Sub(params.OccurredAt)}
	}
	return ErrInvalidAuthentication
}

func (s *Service) loginRateKeys(email string, event EventContext) []RateLimitKey {
	rules := s.loginRateRules(email, event)
	keys := make([]RateLimitKey, 0, len(rules))
	for _, rule := range rules {
		keys = append(keys, rule.Key)
	}
	return keys
}

func (s *Service) loginRateRules(email string, event EventContext) []RateLimitRule {
	rules := []RateLimitRule{{
		Key: s.rateKey(rateScopeLogin, "login.account", email), Policy: loginRatePolicy,
	}}
	for _, key := range s.networkRateKeys(rateScopeLogin, "login", event) {
		rules = append(rules, RateLimitRule{Key: key, Policy: loginNetworkRatePolicy})
	}
	return rules
}

func (s *Service) mfaPreLookupRateKeys(challengeToken string, event EventContext) []RateLimitKey {
	keys := []RateLimitKey{s.rateKey(rateScopeMFA, "mfa.challenge", challengeToken)}
	return append(keys, s.networkRateKeys(rateScopeMFA, "mfa", event)...)
}

// mfaSuccessClearKeys clears only proof-bound counters. A principal must never
// erase the shared source-network history used to protect other accounts.
func (s *Service) mfaSuccessClearKeys(keys []RateLimitKey) []RateLimitKey {
	if len(keys) == 0 {
		return nil
	}
	clear := []RateLimitKey{keys[0]}
	if len(keys) > 1 && !hmac.Equal(keys[0].Digest, keys[len(keys)-1].Digest) {
		clear = append(clear, keys[len(keys)-1])
	}
	return clear
}

func (s *Service) networkRateKeys(storageScope, purpose string, event EventContext) []RateLimitKey {
	if !event.RemoteAddress.IsValid() {
		return nil
	}
	return []RateLimitKey{s.rateKey(storageScope, purpose+".network", event.RemoteAddress.String())}
}

func (s *Service) rateKey(storageScope, purpose, value string) RateLimitKey {
	mac := hmac.New(sha256.New, s.rateLimitKey)
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	return RateLimitKey{Scope: storageScope, Digest: mac.Sum(nil)}
}

func (s *Service) recordMFAFailure(
	ctx context.Context,
	challenge StoredMFAChallenge,
	challengeDigest []byte,
	keys []RateLimitKey,
	now time.Time,
	event EventContext,
) error {
	blockedUntil, err := s.repository.RecordMFAFailure(ctx, RecordMFAFailureParams{
		ChallengeDigest: challengeDigest,
		ChallengeID:     challenge.ID,
		UserID:          challenge.User.ID,
		Keys:            keys,
		Policy:          mfaRatePolicy,
		OccurredAt:      now,
		Event:           event,
	})
	if err != nil {
		return ErrUnavailable
	}
	if blockedUntil.After(now) {
		return &RateLimitError{RetryAfter: blockedUntil.Sub(now)}
	}
	return ErrInvalidAuthentication
}

func (s *Service) recordBootstrapFailure(
	ctx context.Context,
	authorityDigest []byte,
	enrollmentDigest []byte,
	enrollmentID uuid.UUID,
	keys []RateLimitKey,
	now time.Time,
	event EventContext,
) error {
	blockedUntil, err := s.repository.RecordBootstrapFailure(ctx, RecordBootstrapFailureParams{
		AuthorityDigest: authorityDigest, EnrollmentDigest: enrollmentDigest,
		EnrollmentID: enrollmentID, Keys: keys, Policy: bootstrapRatePolicy,
		OccurredAt: now, Event: event,
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidAuthentication) {
			return ErrInvalidAuthentication
		}
		return ErrUnavailable
	}
	if blockedUntil.After(now) {
		return &RateLimitError{RetryAfter: blockedUntil.Sub(now)}
	}
	return ErrInvalidAuthentication
}

func canonicalEmail(value string) (string, error) {
	canonical := strings.ToLower(strings.TrimSpace(value))
	if len(canonical) == 0 || len(canonical) > 320 || !utf8.ValidString(canonical) {
		return "", ErrInvalidInput
	}
	parsed, err := mail.ParseAddress(canonical)
	if err != nil || parsed.Address != canonical {
		return "", ErrInvalidInput
	}
	return canonical, nil
}

func validDisplayName(value string) bool {
	trimmed := strings.TrimSpace(value)
	count := utf8.RuneCountInString(trimmed)
	return utf8.ValidString(trimmed) && !containsControl(trimmed) && count >= 1 && count <= 160
}

func containsControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func validNewPassword(value string) bool {
	count := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && count >= 15 && count <= 128 && len(value) <= maxPasswordBytes
}

func validLoginPassword(value string) bool {
	count := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && count >= 1 && count <= 128 && len(value) <= maxPasswordBytes
}

func validOpaqueToken(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	var combined byte
	for _, item := range decoded {
		combined |= item
	}
	valid := err == nil && len(decoded) == tokenBytes && combined != 0
	clear(decoded)
	return valid
}

func publicRepositoryError(err error) error {
	var rateLimit *RateLimitError
	if errors.As(err, &rateLimit) {
		return rateLimit
	}
	switch {
	case errors.Is(err, ErrConflict):
		return ErrConflict
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrInvalidAuthentication):
		return ErrInvalidAuthentication
	default:
		return ErrUnavailable
	}
}

func publicSessionError(err error) error {
	if errors.Is(err, ErrForbidden) {
		return ErrForbidden
	}
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidAuthentication) {
		return ErrInvalidAuthentication
	}
	return ErrUnavailable
}
