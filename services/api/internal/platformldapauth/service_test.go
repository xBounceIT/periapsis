package platformldapauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

var platformLDAPTestNow = time.Date(2026, 9, 1, 18, 0, 0, 123000000, time.UTC)

type repositoryStub struct {
	begin   func(context.Context, BeginRequest) (NetworkSnapshot, error)
	loadMFA func(context.Context, LoadMFARequest) (MFASnapshot, error)
	apply   func(context.Context, ApplyRequest) (ApplyResult, error)
	fail    func(context.Context, FailureRequest) error

	beginCalls           int
	loadCalls            int
	applyCalls           int
	failures             []FailureRequest
	beginInput           BeginRequest
	loadInput            LoadMFARequest
	applyInput           ApplyRequest
	applySession         mfa.SessionReservation
	applyHadContinuation bool
}

func (repository *repositoryStub) Begin(ctx context.Context, request BeginRequest) (NetworkSnapshot, error) {
	repository.beginCalls++
	repository.beginInput = request
	return repository.begin(ctx, request)
}

func (repository *repositoryStub) LoadMFA(ctx context.Context, request LoadMFARequest) (MFASnapshot, error) {
	repository.loadCalls++
	repository.loadInput = request
	return repository.loadMFA(ctx, request)
}

func (repository *repositoryStub) Apply(ctx context.Context, request ApplyRequest) (ApplyResult, error) {
	repository.applyCalls++
	repository.applyInput = cloneApplyRequestForTest(request)
	if request.Session != nil {
		repository.applySession = request.Session.Session()
		repository.applyHadContinuation = !request.Session.Continuation().IsZero()
	}
	return repository.apply(ctx, request)
}

func (repository *repositoryStub) Fail(ctx context.Context, request FailureRequest) error {
	repository.failures = append(repository.failures, request)
	if repository.fail == nil {
		return nil
	}
	return repository.fail(ctx, request)
}

type directoryStub struct {
	authenticate func(context.Context, ldapclient.DirectoryRequest, []byte, []byte) (ldapclient.DirectoryResult, error)
	bindBytes    []byte
	password     []byte
	calls        int
}

func (directory *directoryStub) AuthenticateDirectory(
	ctx context.Context,
	request ldapclient.DirectoryRequest,
	bindSecret []byte,
	password []byte,
) (ldapclient.DirectoryResult, error) {
	directory.calls++
	directory.bindBytes = bindSecret
	directory.password = password
	return directory.authenticate(ctx, request, bindSecret, password)
}

type totpVerifierStub struct {
	verify  func(context.Context, platformoidcauth.DirectTOTPVerificationRequest) (platformoidcauth.DirectTOTPProof, error)
	request platformoidcauth.DirectTOTPVerificationRequest
	calls   int
}

func (verifier *totpVerifierStub) VerifyDirectTOTP(
	ctx context.Context,
	request platformoidcauth.DirectTOTPVerificationRequest,
) (platformoidcauth.DirectTOTPProof, error) {
	verifier.calls++
	verifier.request = request
	return verifier.verify(ctx, request)
}

type credentialIssuerFunc func(federatedauth.ApplyCredentialRequest) (*federatedauth.ApplyCredentialReservation, error)

func (function credentialIssuerFunc) ReserveApplyCredential(
	request federatedauth.ApplyCredentialRequest,
) (*federatedauth.ApplyCredentialReservation, error) {
	return function(request)
}

type platformLDAPHarness struct {
	service         *Service
	repository      *repositoryStub
	directory       *directoryStub
	verifier        *totpVerifierStub
	keyring         identity.Keyring
	providerID      uuid.UUID
	secretID        uuid.UUID
	userID          uuid.UUID
	factorID        uuid.UUID
	sessionID       identity.EntityID
	configuration   identityprovider.Configuration
	directoryResult ldapclient.DirectoryResult
	lastCounter     int64
	issuer          federatedauth.ApplyCredentialIssuer
}

func newPlatformLDAPHarness(t *testing.T) *platformLDAPHarness {
	t.Helper()
	keyring, err := identity.NewKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{0x42}, 32)})
	if err != nil {
		t.Fatalf("identity.NewKeyring() error = %v", err)
	}
	harness := &platformLDAPHarness{
		keyring: keyring, providerID: testUUID(30), secretID: testUUID(31),
		userID: testUUID(32), factorID: testUUID(33), lastCounter: 4,
		configuration: testPlatformLDAPConfiguration(), directoryResult: successfulDirectoryResult(),
	}
	harness.repository = &repositoryStub{}
	harness.directory = &directoryStub{}
	harness.verifier = &totpVerifierStub{}
	harness.directory.authenticate = func(
		_ context.Context,
		_ ldapclient.DirectoryRequest,
		_ []byte,
		_ []byte,
	) (ldapclient.DirectoryResult, error) {
		return harness.directoryResult, nil
	}
	harness.verifier.verify = func(
		_ context.Context,
		request platformoidcauth.DirectTOTPVerificationRequest,
	) (platformoidcauth.DirectTOTPProof, error) {
		if request.UserID != identity.EntityID(harness.userID) ||
			request.FactorID != identity.EntityID(harness.factorID) {
			return platformoidcauth.DirectTOTPProof{}, errors.New("wrong TOTP authority")
		}
		return platformoidcauth.DirectTOTPProof{Counter: harness.lastCounter + 1}, nil
	}
	bindEnvelope, err := keyring.EncryptBindSecret(identity.BindSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: identity.EntityID(harness.providerID),
		},
		SecretID: identity.EntityID(harness.secretID),
	}, []byte("bind-secret-canary"))
	if err != nil {
		t.Fatalf("EncryptBindSecret() error = %v", err)
	}
	harness.repository.begin = func(_ context.Context, request BeginRequest) (NetworkSnapshot, error) {
		return NetworkSnapshot{
			RunID: request.RunID, State: RunPending, Allowed: true,
			ProviderID: harness.providerID, ProviderVersion: 7,
			ConfigurationRevision: 11, SecurityRevision: 12, MappingRevision: 13,
			Configuration: harness.configuration, Endpoints: testPlatformLDAPEndpoints(),
			BindSecretID: harness.secretID, BindSecretRevision: 5, BindSecret: bindEnvelope,
		}, nil
	}
	harness.repository.loadMFA = func(_ context.Context, request LoadMFARequest) (MFASnapshot, error) {
		return validMFASnapshotFixture(harness, request), nil
	}
	harness.repository.apply = func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
		return ApplyResult{
			RunID: request.RunID, State: RunSucceeded,
			SessionID: request.Session.Session().SessionID(), UserID: request.UserID,
		}, nil
	}
	harness.issuer = testSessionIssuer(t, &harness.sessionID)
	identifiers := []uuid.UUID{testUUID(1), testUUID(2), testUUID(3), testUUID(4), testUUID(5)}
	service, err := New(Options{
		Repository: harness.repository, Directory: harness.directory, Keyring: keyring,
		TOTPVerifier: harness.verifier, Credentials: harness.issuer,
		RateDigestKey: bytes.Repeat([]byte{0x5a}, sha256.Size), OperationTimeout: 5 * time.Second,
		Now: func() time.Time { return platformLDAPTestNow },
		NewID: func() (uuid.UUID, error) {
			if len(identifiers) == 0 {
				return uuid.Nil, errors.New("identifier sequence exhausted")
			}
			value := identifiers[0]
			identifiers = identifiers[1:]
			return value, nil
		},
		Random: bytes.NewReader(bytes.Repeat([]byte{0x73}, sha256.Size)),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	harness.service = service
	return harness
}

func TestAuthenticateExistingPlatformUserUsesTOTPAndDeterministicMappings(t *testing.T) {
	harness := newPlatformLDAPHarness(t)
	password := []byte("directory-password-canary")
	code := []byte("123456")
	result, err := harness.service.Authenticate(context.Background(), validCommandFixture(password, code))
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	defer result.Credential.Destroy()
	if result.UserID != harness.userID || result.SessionID != harness.sessionID ||
		result.Credential == nil || result.ReturnPath != "/platform" || result.Replayed {
		t.Fatalf("Authenticate() result = %s", result)
	}
	if harness.repository.beginCalls != 1 || harness.repository.loadCalls != 1 ||
		harness.repository.applyCalls != 1 || len(harness.repository.failures) != 0 {
		t.Fatalf("repository calls = begin %d, load %d, apply %d, fail %d",
			harness.repository.beginCalls, harness.repository.loadCalls,
			harness.repository.applyCalls, len(harness.repository.failures))
	}
	apply := harness.repository.applyInput
	if apply.UserID != harness.userID || apply.ExternalIdentityID != testUUID(2) ||
		apply.IdentityVersion != 0 || apply.TOTPCounter != 5 ||
		apply.SubjectEnvelope.KeyVersion != harness.keyring.ActiveVersion() ||
		apply.SubjectAlias.KeyVersion != harness.keyring.ActiveVersion() ||
		apply.GroupsDigest == ([sha256.Size]byte{}) || apply.ResultDigest == ([sha256.Size]byte{}) {
		t.Fatalf("Apply input lost authority pins: %#v", apply)
	}
	wantMappings := []uuid.UUID{testUUID(42), testUUID(43)}
	if !slices.Equal(apply.SelectedMappingIDs, wantMappings) {
		t.Fatalf("selected mappings = %v, want %v", apply.SelectedMappingIDs, wantMappings)
	}
	if harness.repository.applyHadContinuation || harness.repository.applySession.IsZero() {
		t.Fatal("platform LDAP emitted a continuation")
	}
	if harness.repository.applySession.AuthenticationMethod() != mfa.SessionAuthenticationLDAP {
		t.Fatalf("session method = %q", harness.repository.applySession.AuthenticationMethod())
	}
	if !allBytesZero(password) || !allBytesZero(code) ||
		!allBytesZero(harness.directory.bindBytes) || !allBytesZero(harness.directory.password) ||
		!allBytesZero(harness.verifier.request.Code) ||
		!allBytesZero(harness.verifier.request.Secret.Ciphertext) {
		t.Fatal("authentication retained a password, bind secret, code, or TOTP envelope")
	}
	provider := identity.ProviderContext{
		Scope: identity.PlatformProviderScope, ProviderID: identity.EntityID(harness.providerID),
	}
	subject, err := harness.keyring.DecryptExternalSubject(identity.ExternalSubjectContext{
		Provider: provider, ExternalIdentityID: identity.EntityID(testUUID(2)),
	}, apply.SubjectEnvelope)
	if err != nil || !strings.Contains(subject.String(), "format") {
		t.Fatalf("platform-scoped subject envelope is invalid: %v", err)
	}
	if material, ok := result.Credential.Consume(); !ok {
		t.Fatal("browser credential was not deliverable")
	} else {
		material.Destroy()
	}
}

func TestAuthenticateRejectsMaliciousSuperAdminProjectionBeforeApply(t *testing.T) {
	harness := newPlatformLDAPHarness(t)
	harness.repository.loadMFA = func(_ context.Context, request LoadMFARequest) (MFASnapshot, error) {
		snapshot := validMFASnapshotFixture(harness, request)
		// The ID is ordinary; the role key alone is authoritative and must be
		// rejected even if an adapter or SQL projection is compromised.
		snapshot.Mappings[0].PlatformRoleKey = platformSuperAdminKey
		return snapshot, nil
	}
	_, err := harness.service.Authenticate(context.Background(), validCommandFixture(
		[]byte("password"), []byte("123456"),
	))
	if !errors.Is(err, ErrAuthentication) || harness.repository.applyCalls != 0 {
		t.Fatalf("malicious super-admin mapping = %v, apply calls %d", err, harness.repository.applyCalls)
	}
	assertLastFailure(t, harness.repository, FailureMappingUnmatched)
}

func TestAuthenticateDirectoryIdentityFailuresAreNonOracular(t *testing.T) {
	for _, category := range []ldapclient.DirectoryCategory{
		ldapclient.DirectoryCategoryCredentialsRejected,
		ldapclient.DirectoryCategoryUserNotFound,
		ldapclient.DirectoryCategoryUserAmbiguous,
	} {
		t.Run(string(category), func(t *testing.T) {
			harness := newPlatformLDAPHarness(t)
			harness.directory.authenticate = func(
				context.Context, ldapclient.DirectoryRequest, []byte, []byte,
			) (ldapclient.DirectoryResult, error) {
				return ldapclient.DirectoryResult{Category: category}, nil
			}
			_, err := harness.service.Authenticate(context.Background(), validCommandFixture(
				[]byte("wrong-password"), []byte("123456"),
			))
			if !errors.Is(err, ErrAuthentication) || err.Error() != ErrAuthentication.Error() {
				t.Fatalf("directory category %q disclosed an oracle: %v", category, err)
			}
			if harness.repository.loadCalls != 0 || harness.repository.applyCalls != 0 {
				t.Fatal("credential failure reached identity planning")
			}
			assertLastFailure(t, harness.repository, FailureCredentialsRejected)
		})
	}
}

func TestAuthenticateBindSecretFailureNeverReachesDirectory(t *testing.T) {
	harness := newPlatformLDAPHarness(t)
	originalBegin := harness.repository.begin
	harness.repository.begin = func(ctx context.Context, request BeginRequest) (NetworkSnapshot, error) {
		snapshot, err := originalBegin(ctx, request)
		snapshot.BindSecret.Ciphertext[0] ^= 0xff
		return snapshot, err
	}
	_, err := harness.service.Authenticate(context.Background(), validCommandFixture(
		[]byte("password"), []byte("123456"),
	))
	if !errors.Is(err, ErrUnavailable) || harness.directory.calls != 0 || harness.repository.applyCalls != 0 {
		t.Fatalf("tampered bind secret = %v, directory %d, apply %d", err, harness.directory.calls, harness.repository.applyCalls)
	}
	assertLastFailure(t, harness.repository, FailureProviderUnavailable)
}

func TestAuthenticateRejectsInactiveAccountAndNeverLoadsMFA(t *testing.T) {
	harness := newPlatformLDAPHarness(t)
	disabled := "disabled"
	statusAttribute := "accountStatus"
	harness.configuration.AccountStatusMode = identityprovider.AccountStatusModeAttributeEquals
	harness.configuration.AccountStatusAttribute = &statusAttribute
	harness.configuration.AccountDisabledValue = &disabled
	harness.directoryResult.Observation.User.Attributes = append(
		harness.directoryResult.Observation.User.Attributes,
		ldapclient.DirectoryAttribute{Name: statusAttribute, Values: [][]byte{[]byte(disabled)}},
	)
	_, err := harness.service.Authenticate(context.Background(), validCommandFixture(
		[]byte("password"), []byte("123456"),
	))
	if !errors.Is(err, ErrAuthentication) || harness.repository.loadCalls != 0 {
		t.Fatalf("inactive account = %v, load calls %d", err, harness.repository.loadCalls)
	}
	assertLastFailure(t, harness.repository, FailureAccountDisabled)
}

func TestAuthenticateDeniesMissingIdentityFactorAndMappings(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*MFASnapshot)
		loadErr     error
		wantFailure FailureCategory
	}{
		{name: "missing existing identity", loadErr: ErrAuthentication, wantFailure: FailureIdentityUnmatched},
		{name: "ambiguous existing identity", loadErr: ErrReplayConflict, wantFailure: FailureIdentityUnmatched},
		{name: "no TOTP factor", mutate: func(snapshot *MFASnapshot) {
			snapshot.TOTP = TOTPFactor{}
		}, wantFailure: FailureMFARequired},
		{name: "empty mapping", mutate: func(snapshot *MFASnapshot) {
			snapshot.Mappings = nil
		}, wantFailure: FailureMappingUnmatched},
		{name: "unmatched mapping", mutate: func(snapshot *MFASnapshot) {
			snapshot.Mappings[0].MatcherValue = "cn=elsewhere,dc=example,dc=com"
			snapshot.Mappings = snapshot.Mappings[:1]
		}, wantFailure: FailureMappingUnmatched},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newPlatformLDAPHarness(t)
			harness.repository.loadMFA = func(_ context.Context, request LoadMFARequest) (MFASnapshot, error) {
				if testCase.loadErr != nil {
					return MFASnapshot{}, testCase.loadErr
				}
				snapshot := validMFASnapshotFixture(harness, request)
				testCase.mutate(&snapshot)
				return snapshot, nil
			}
			_, err := harness.service.Authenticate(context.Background(), validCommandFixture(
				[]byte("password"), []byte("123456"),
			))
			if !errors.Is(err, ErrAuthentication) || harness.repository.applyCalls != 0 {
				t.Fatalf("Authenticate() = %v, apply calls %d", err, harness.repository.applyCalls)
			}
			assertLastFailure(t, harness.repository, testCase.wantFailure)
		})
	}
}

func TestAuthenticateTOTPIsMandatoryAndRejectsWrongOrReplayedProof(t *testing.T) {
	tests := []struct {
		name         string
		code         []byte
		verification func(*platformLDAPHarness)
		wantFailure  FailureCategory
		wantCalls    int
	}{
		{name: "missing", code: nil, wantFailure: FailureMFARequired, wantCalls: 0},
		{name: "malformed", code: []byte("12x456"), wantFailure: FailureMFARejected, wantCalls: 0},
		{name: "wrong", code: []byte("123456"), verification: func(harness *platformLDAPHarness) {
			harness.verifier.verify = func(context.Context, platformoidcauth.DirectTOTPVerificationRequest) (platformoidcauth.DirectTOTPProof, error) {
				return platformoidcauth.DirectTOTPProof{}, platformoidcauth.ErrDirectTOTPInvalidProof
			}
		}, wantFailure: FailureMFARejected, wantCalls: 1},
		{name: "replayed counter", code: []byte("123456"), verification: func(harness *platformLDAPHarness) {
			harness.verifier.verify = func(context.Context, platformoidcauth.DirectTOTPVerificationRequest) (platformoidcauth.DirectTOTPProof, error) {
				return platformoidcauth.DirectTOTPProof{Counter: harness.lastCounter}, nil
			}
		}, wantFailure: FailureMFARejected, wantCalls: 1},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newPlatformLDAPHarness(t)
			if testCase.verification != nil {
				testCase.verification(harness)
			}
			_, err := harness.service.Authenticate(context.Background(), validCommandFixture(
				[]byte("password"), testCase.code,
			))
			if !errors.Is(err, ErrAuthentication) || harness.verifier.calls != testCase.wantCalls ||
				harness.repository.applyCalls != 0 {
				t.Fatalf("Authenticate() = %v, verifier %d, apply %d", err, harness.verifier.calls, harness.repository.applyCalls)
			}
			assertLastFailure(t, harness.repository, testCase.wantFailure)
		})
	}
}

func TestAuthenticateTOTPVerifierInfrastructureFailureHasNoWeakFallback(t *testing.T) {
	harness := newPlatformLDAPHarness(t)
	harness.verifier.verify = func(
		context.Context,
		platformoidcauth.DirectTOTPVerificationRequest,
	) (platformoidcauth.DirectTOTPProof, error) {
		return platformoidcauth.DirectTOTPProof{}, errors.New("key service unavailable canary")
	}
	_, err := harness.service.Authenticate(context.Background(), validCommandFixture(
		[]byte("password"), []byte("123456"),
	))
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "canary") ||
		harness.repository.applyCalls != 0 {
		t.Fatalf("TOTP infrastructure failure = %v, apply calls %d", err, harness.repository.applyCalls)
	}
	assertLastFailure(t, harness.repository, FailureProviderUnavailable)
}

func TestAuthenticateMapsRateLimitStaleReplayAndApplyFailure(t *testing.T) {
	t.Run("rate limited begin", func(t *testing.T) {
		harness := newPlatformLDAPHarness(t)
		harness.repository.begin = func(context.Context, BeginRequest) (NetworkSnapshot, error) {
			return NetworkSnapshot{}, ErrRateLimited
		}
		_, err := harness.service.Authenticate(context.Background(), validCommandFixture(
			[]byte("password"), []byte("123456"),
		))
		if !errors.Is(err, ErrRateLimited) || harness.directory.calls != 0 {
			t.Fatalf("rate limited Begin = %v, directory calls %d", err, harness.directory.calls)
		}
	})

	t.Run("exact apply replay", func(t *testing.T) {
		harness := newPlatformLDAPHarness(t)
		harness.repository.apply = func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
			return ApplyResult{
				RunID: request.RunID, State: RunSucceeded, SessionID: request.Session.Session().SessionID(),
				UserID: request.UserID, Replayed: true,
			}, nil
		}
		result, err := harness.service.Authenticate(context.Background(), validCommandFixture(
			[]byte("password"), []byte("123456"),
		))
		if err != nil || !result.Replayed || result.Credential == nil {
			t.Fatalf("exact replay = %s, %v", result, err)
		}
		result.Credential.Destroy()
	})

	t.Run("stale configuration", func(t *testing.T) {
		harness := newPlatformLDAPHarness(t)
		harness.repository.apply = func(context.Context, ApplyRequest) (ApplyResult, error) {
			return ApplyResult{}, ErrStaleConfiguration
		}
		_, err := harness.service.Authenticate(context.Background(), validCommandFixture(
			[]byte("password"), []byte("123456"),
		))
		if !errors.Is(err, ErrAuthentication) {
			t.Fatalf("stale apply = %v", err)
		}
		assertLastFailure(t, harness.repository, FailureStaleConfiguration)
	})

	t.Run("apply unavailable", func(t *testing.T) {
		harness := newPlatformLDAPHarness(t)
		harness.repository.apply = func(context.Context, ApplyRequest) (ApplyResult, error) {
			return ApplyResult{}, errors.New("database canary must not escape")
		}
		_, err := harness.service.Authenticate(context.Background(), validCommandFixture(
			[]byte("password"), []byte("123456"),
		))
		if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "canary") {
			t.Fatalf("apply error = %v", err)
		}
	})
}

func TestAuthenticateCancellationStopsBeforeApplyAndClearsSecrets(t *testing.T) {
	harness := newPlatformLDAPHarness(t)
	entered := make(chan struct{})
	harness.directory.authenticate = func(
		ctx context.Context,
		_ ldapclient.DirectoryRequest,
		_ []byte,
		_ []byte,
	) (ldapclient.DirectoryResult, error) {
		close(entered)
		<-ctx.Done()
		return ldapclient.DirectoryResult{Category: ldapclient.DirectoryCategoryCancelled}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	password := []byte("cancel-password-canary")
	code := []byte("123456")
	go func() {
		_, err := harness.service.Authenticate(ctx, validCommandFixture(password, code))
		done <- err
	}()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cancelled Authenticate() error = %v", err)
	}
	if harness.repository.applyCalls != 0 || !allBytesZero(password) || !allBytesZero(code) ||
		!allBytesZero(harness.directory.bindBytes) || !allBytesZero(harness.directory.password) {
		t.Fatal("cancellation retained secret material or reached Apply")
	}
	if len(harness.repository.failures) != 1 {
		t.Fatalf("cancellation finalized the run %d times", len(harness.repository.failures))
	}
	assertLastFailure(t, harness.repository, FailureProviderUnavailable)
}

func TestAuthenticateFinalizesEveryPostBeginFailureExactlyOnce(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*platformLDAPHarness)
		wantErr error
		want    FailureCategory
	}{
		{
			name: "invalid network projection",
			mutate: func(harness *platformLDAPHarness) {
				original := harness.repository.begin
				harness.repository.begin = func(ctx context.Context, request BeginRequest) (NetworkSnapshot, error) {
					snapshot, err := original(ctx, request)
					snapshot.ProviderVersion = 0
					return snapshot, err
				}
			},
			wantErr: ErrAuthentication, want: FailureProtocolFailed,
		},
		{
			name: "credential reservation unavailable",
			mutate: func(harness *platformLDAPHarness) {
				harness.service.credentials = credentialIssuerFunc(func(federatedauth.ApplyCredentialRequest) (*federatedauth.ApplyCredentialReservation, error) {
					return nil, errors.New("credential issuer canary")
				})
			},
			wantErr: ErrUnavailable, want: FailureProviderUnavailable,
		},
		{
			name: "malformed apply result",
			mutate: func(harness *platformLDAPHarness) {
				harness.repository.apply = func(context.Context, ApplyRequest) (ApplyResult, error) {
					return ApplyResult{RunID: testUUID(99), State: RunSucceeded}, nil
				}
			},
			wantErr: ErrAuthentication, want: FailureProtocolFailed,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newPlatformLDAPHarness(t)
			testCase.mutate(harness)
			_, err := harness.service.Authenticate(context.Background(), validCommandFixture(
				[]byte("password"), []byte("123456"),
			))
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("Authenticate() error = %v, want %v", err, testCase.wantErr)
			}
			if len(harness.repository.failures) != 1 {
				t.Fatalf("post-Begin failure finalized %d times", len(harness.repository.failures))
			}
			assertLastFailure(t, harness.repository, testCase.want)
		})
	}
}

func TestAuthenticateRejectsContinuationReservation(t *testing.T) {
	harness := newPlatformLDAPHarness(t)
	harness.service.credentials = credentialIssuerFunc(func(request federatedauth.ApplyCredentialRequest) (*federatedauth.ApplyCredentialReservation, error) {
		receipt := opaqueCredential(0x55)
		continuationID := identity.EntityID(testUUID(90))
		digest, err := federatedauth.ContinuationReceiptDigest(
			federatedauth.ContinuationAuthorityDirectPlatformOIDC, continuationID, receipt,
		)
		if err != nil {
			return nil, err
		}
		continuation, err := federatedauth.NewPostPrimaryContinuationReservation(
			federatedauth.PostPrimaryContinuationMaterial{
				ContinuationID: continuationID,
				Authority:      federatedauth.ContinuationAuthorityDirectPlatformOIDC,
				ReceiptDigest:  digest, ExpiresAt: request.IssuedAt.Add(5 * time.Minute),
			}, request.IssuedAt,
		)
		if err != nil {
			return nil, err
		}
		return federatedauth.NewContinuationApplyCredentialReservation(continuation, receipt)
	})
	_, err := harness.service.Authenticate(context.Background(), validCommandFixture(
		[]byte("password"), []byte("123456"),
	))
	if !errors.Is(err, ErrUnavailable) || harness.repository.applyCalls != 0 {
		t.Fatalf("continuation reservation = %v, apply calls %d", err, harness.repository.applyCalls)
	}
}

func TestOwnedSecretValidationAndFormattingNeverLeakMaterial(t *testing.T) {
	passwordCanary := "directory-password-canary"
	codeCanary := "87654321"
	command := validCommandFixture([]byte(passwordCanary), []byte(codeCanary))
	for _, formatted := range []string{
		command.String(), fmt.Sprintf("%v", command), fmt.Sprintf("%#v", command),
		Profile{Username: "sensitive-username"}.String(),
		Mapping{MatcherValue: "cn=secret,dc=example"}.String(), Result{}.String(),
	} {
		if strings.Contains(formatted, passwordCanary) || strings.Contains(formatted, codeCanary) ||
			strings.Contains(formatted, command.Username) || strings.Contains(formatted, "sensitive-username") ||
			strings.Contains(formatted, "cn=secret") {
			t.Fatalf("formatter leaked authentication material: %q", formatted)
		}
	}
	password := []byte(passwordCanary)
	code := []byte(codeCanary)
	var service *Service
	_, err := service.Authenticate(nil, Command{Password: password, TOTPCode: code})
	if !errors.Is(err, ErrInvalidInput) || !allBytesZero(password) || !allBytesZero(code) {
		t.Fatalf("validation error = %v; owned secrets were retained", err)
	}
}

func TestReturnPathValidationRejectsNonCanonicalAndAuthorityConfusion(t *testing.T) {
	invalid := []string{
		`/\evil.example`, `/safe/../admin`, `/safe/./admin`, `/safe//admin`,
		`/%2e%2e/admin`, `/%5cevil.example`, "/safe\nadmin", `//evil.example`,
		`https://evil.example/path`, `/safe#fragment`,
	}
	for _, value := range invalid {
		if validReturnPath(value) {
			t.Errorf("validReturnPath(%q) = true", value)
		}
	}
	for _, value := range []string{"/", "/platform", "/platform?tab=security"} {
		if !validReturnPath(value) {
			t.Errorf("validReturnPath(%q) = false", value)
		}
	}
}

func validMFASnapshotFixture(harness *platformLDAPHarness, request LoadMFARequest) MFASnapshot {
	return MFASnapshot{
		RunID: request.RunID, UserID: harness.userID, UserAuthenticationRevision: 17,
		ExternalIdentityID: request.ExternalIdentityID, IdentityVersion: 0,
		TOTP: TOTPFactor{
			ID: harness.factorID, SecurityRevision: 3,
			Secret: platformoidcauth.DirectProtectedTOTPSecret{
				Ciphertext: bytes.Repeat([]byte{0x91}, 48), Nonce: bytes.Repeat([]byte{0x92}, 12),
				AAD: []byte("platform-ldap-totp-aad"), KeyVersion: 1,
				EncryptionAlgorithm: "aes-256-gcm", OTPAlgorithm: "SHA256", Digits: 6, PeriodSeconds: 30,
			},
			LastAcceptedCounter: &harness.lastCounter,
		},
		Mappings: []Mapping{
			{
				ID: testUUID(41), MatcherType: MappingExactDN,
				MatcherValue: "cn=SOC-L2,ou=groups,dc=example,dc=com", CaseSensitive: false,
				Priority: 20, PlatformRoleID: testUUID(70), PlatformRoleKey: "analyst",
				ReconciliationMode: ReconciliationAuthoritative,
			},
			{
				ID: testUUID(42), MatcherType: MappingExactCN, MatcherValue: "soc-l2",
				CaseSensitive: false, Priority: 10, PlatformRoleID: testUUID(70),
				PlatformRoleKey: "analyst", ReconciliationMode: ReconciliationAuthoritative,
			},
			{
				ID: testUUID(43), MatcherType: MappingRegex,
				MatcherValue: `cn=IR-.*,ou=groups,dc=example,dc=com`, CaseSensitive: true,
				Priority: 30, PlatformRoleID: testUUID(71), PlatformRoleKey: "incident_responder",
				ReconciliationMode: ReconciliationAdditive,
			},
		},
	}
}

func testPlatformLDAPConfiguration() identityprovider.Configuration {
	email := "mail"
	memberOf := "memberOf"
	return identityprovider.Configuration{
		Template: identityprovider.ProviderTemplateOpenLDAP, VerifyCertificate: true,
		ConnectTimeoutMS: 1_000, OperationTimeoutMS: 5_000,
		BindDN: "cn=svc,dc=example,dc=com", UserBaseDN: "ou=users,dc=example,dc=com",
		UserSearchFilter: "(uid={username})", PageSize: 100, MaxPages: 10,
		MaxEntries: 1_000, MaxResponseBytes: 1_048_576,
		ReferralMode:    identityprovider.ReferralModeDisabled,
		NestedGroupMode: identityprovider.NestedGroupModeDisabled, MaxGroups: 100,
		FirstNameAttribute: "givenName", LastNameAttribute: "sn",
		DisplayNameAttribute: "displayName", UsernameAttribute: "uid", EmailAttribute: &email,
		ImmutableSubjectAttribute: "entryUUID",
		ImmutableSubjectFormat:    identityprovider.SubjectFormatEntryUUID,
		GroupMembershipAttribute:  &memberOf,
		AccountStatusMode:         identityprovider.AccountStatusModeNone,
		JITMode:                   identityprovider.JITModeExistingIdentity,
		NoMatchPolicy:             identityprovider.NoMatchPolicyDeny,
		DeprovisionMode:           identityprovider.DeprovisionModeRetain,
	}
}

func testPlatformLDAPEndpoints() []identityprovider.Endpoint {
	return []identityprovider.Endpoint{{
		Priority: 1, Host: "ldap.example.com", Port: 636,
		Transport: ldapclient.TransportLDAPS, TLSServerName: "ldap.example.com", Enabled: true,
	}}
}

func successfulDirectoryResult() ldapclient.DirectoryResult {
	return ldapclient.DirectoryResult{
		Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1,
		Observation: ldapclient.DirectoryObservation{
			User: ldapclient.DirectoryEntry{
				DistinguishedName: "uid=alice,ou=users,dc=example,dc=com",
				Attributes: []ldapclient.DirectoryAttribute{
					{Name: "givenName", Values: [][]byte{[]byte("Alice")}},
					{Name: "sn", Values: [][]byte{[]byte("Example")}},
					{Name: "displayName", Values: [][]byte{[]byte("Alice Example")}},
					{Name: "uid", Values: [][]byte{[]byte("alice")}},
					{Name: "mail", Values: [][]byte{[]byte("Alice@Example.test")}},
					{Name: "entryUUID", Values: [][]byte{[]byte("550e8400-e29b-41d4-a716-446655440000")}},
					{Name: "memberOf", Values: [][]byte{
						[]byte("cn=SOC-L2,ou=groups,dc=example,dc=com"),
						[]byte("cn=IR-Lead,ou=groups,dc=example,dc=com"),
					}},
				},
			},
			Groups: []ldapclient.DirectoryEntry{
				{DistinguishedName: "cn=SOC-L2,ou=groups,dc=example,dc=com"},
				{DistinguishedName: "cn=IR-Lead,ou=groups,dc=example,dc=com"},
			},
		},
	}
}

func validCommandFixture(password, code []byte) Command {
	return Command{
		ProviderKey: "corporate_ldap", Username: "alice", Password: password, TOTPCode: code,
		ReturnPath: "/platform", ClientIP: netip.MustParseAddr("192.0.2.44"),
		UserAgent: "platform-ldap-auth-test", RequestID: testUUID(20), CorrelationID: testUUID(21),
	}
}

func testSessionIssuer(t *testing.T, sessionID *identity.EntityID) federatedauth.ApplyCredentialIssuer {
	t.Helper()
	return credentialIssuerFunc(func(request federatedauth.ApplyCredentialRequest) (*federatedauth.ApplyCredentialReservation, error) {
		if request.Disposition != federatedauth.ApplySession || request.Method != federatedauth.AuthenticationMethodLDAP {
			return nil, errors.New("unexpected credential reservation")
		}
		token := opaqueCredential(0x61)
		csrf := opaqueCredential(0x62)
		*sessionID = identity.EntityID(testUUID(80))
		reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
			SessionID: *sessionID, FamilyID: identity.EntityID(testUUID(81)),
			TokenDigest: sha256.Sum256(token), CSRFDigest: sha256.Sum256(csrf),
			AuthenticationMethod: mfa.SessionAuthenticationLDAP,
			IdleExpiresAt:        request.IssuedAt.Add(time.Hour).Truncate(time.Millisecond),
			AbsoluteExpiresAt:    request.IssuedAt.Add(8 * time.Hour).Truncate(time.Millisecond),
		}, request.IssuedAt.Truncate(time.Millisecond))
		if err != nil {
			return nil, err
		}
		return federatedauth.NewSessionApplyCredentialReservation(reservation, token, csrf)
	})
}

func opaqueCredential(seed byte) []byte {
	return []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{seed}, sha256.Size)))
}

func testUUID(seed byte) uuid.UUID {
	return uuid.UUID{0, 0, 0, 0, 0, seed, 0x70, seed, 0x80, seed, 0, 0, 0, 0, 0, seed}
}

func assertLastFailure(t *testing.T, repository *repositoryStub, want FailureCategory) {
	t.Helper()
	if len(repository.failures) == 0 || repository.failures[len(repository.failures)-1].Category != want {
		t.Fatalf("failure requests = %#v, want last category %q", repository.failures, want)
	}
}

func allBytesZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func cloneApplyRequestForTest(request ApplyRequest) ApplyRequest {
	request.SubjectEnvelope.Ciphertext = append([]byte(nil), request.SubjectEnvelope.Ciphertext...)
	request.SelectedMappingIDs = append([]uuid.UUID(nil), request.SelectedMappingIDs...)
	request.Profile.Email = cloneString(request.Profile.Email)
	request.Profile.FirstName = cloneString(request.Profile.FirstName)
	request.Profile.LastName = cloneString(request.Profile.LastName)
	request.Session = nil
	return request
}
