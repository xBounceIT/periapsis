package federatedauth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

type samlLogoutStoreFake struct {
	mu       sync.Mutex
	snapshot SAMLLogoutSnapshot
	errors   []error
	calls    []SAMLLogoutCommand
}

func (store *samlLogoutStoreFake) RevokeLocalSAMLSession(
	_ context.Context,
	command SAMLLogoutCommand,
) (SAMLLogoutSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.calls = append(store.calls, command)
	if len(store.errors) != 0 {
		err := store.errors[0]
		store.errors = store.errors[1:]
		return SAMLLogoutSnapshot{}, err
	}
	return cloneSAMLLogoutSnapshot(store.snapshot), nil
}

func (store *samlLogoutStoreFake) callCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.calls)
}

type samlLogoutFlowFunc func(context.Context, federatedsaml.LogoutBuildRequest) (federatedsaml.LogoutRequest, error)

func (function samlLogoutFlowFunc) BuildLogoutRequest(
	ctx context.Context,
	request federatedsaml.LogoutBuildRequest,
) (federatedsaml.LogoutRequest, error) {
	return function(ctx, request)
}

type samlLogoutStoreFunc func(context.Context, SAMLLogoutCommand) (SAMLLogoutSnapshot, error)

func (function samlLogoutStoreFunc) RevokeLocalSAMLSession(
	ctx context.Context,
	command SAMLLogoutCommand,
) (SAMLLogoutSnapshot, error) {
	return function(ctx, command)
}

type samlLogoutSessionProtector struct{}

func (samlLogoutSessionProtector) OpenSAMLSession(
	context.Context,
	federatedsaml.SessionMaterialContext,
	federatedsaml.ProtectedSessionMaterial,
) (federatedsaml.SessionMaterial, error) {
	return federatedsaml.SessionMaterial{
		NameID: "logout-subject-secret", NameIDFormat: testSAMLPersistentNameID,
		SessionIndex: "logout-session-secret",
	}, nil
}

func TestSAMLLogoutRevokesLocallyBeforeBuildingOptionalUpstreamRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	command, snapshot := samlLogoutFixture(t, now, true)
	store := &samlLogoutStoreFake{snapshot: snapshot, errors: []error{errors.New("lost response")}}
	kernel, err := federatedsaml.New(federatedsaml.Options{
		Transactions: &samlTestTransactions{}, RedirectSigner: samlTestSigner{},
		SignatureVerifier: samlTestVerifier{}, AssertionDecrypter: samlTestDecrypter{},
		SessionProtector: samlLogoutSessionProtector{}, TransactionTTL: 5 * time.Minute,
		OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	logout, err := NewSAMLLogout(SAMLLogoutOptions{
		Flow: kernel, Store: store, OperationTimeout: time.Second, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := logout.Logout(context.Background(), command)
	if err != nil || !result.LocalRevoked || result.Upstream != SAMLUpstreamLogoutReady ||
		result.RedirectURL == "" || store.callCount() != 2 {
		t.Fatalf("Logout()=%v,%v calls=%d", result, err, store.callCount())
	}
	if strings.Contains(result.RedirectURL, "logout-subject-secret") ||
		strings.Contains(result.RedirectURL, "logout-session-secret") {
		t.Fatalf("redirect exposed unencoded session material: %s", result.RedirectURL)
	}
}

func TestSAMLLogoutKeepsLocalRevocationWhenUpstreamIsUnavailable(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	for name, fixture := range map[string]struct {
		configure func(*SAMLLogoutCommand, *SAMLLogoutSnapshot)
		want      SAMLUpstreamLogoutStatus
		flowCalls int
	}{
		"not requested": {
			configure: func(command *SAMLLogoutCommand, _ *SAMLLogoutSnapshot) { command.RequestUpstream = false },
			want:      SAMLUpstreamLogoutNotRequested,
		},
		"provider has no slo": {
			configure: func(_ *SAMLLogoutCommand, snapshot *SAMLLogoutSnapshot) {
				*snapshot = samlLogoutSnapshotFixture(t, now, false)
			},
			want: SAMLUpstreamLogoutNotConfigured,
		},
		"configuration unavailable after local revocation": {
			configure: func(_ *SAMLLogoutCommand, snapshot *SAMLLogoutSnapshot) {
				snapshot.Configuration = TenantSAMLConfiguration{}
			},
			want: SAMLUpstreamLogoutNotConfigured,
		},
		"session provenance unavailable": {
			configure: func(_ *SAMLLogoutCommand, snapshot *SAMLLogoutSnapshot) {
				snapshot.ProtectedMaterial = federatedsaml.ProtectedSessionMaterial{}
			},
			want: SAMLUpstreamLogoutNotConfirmed,
		},
		"upstream confirmation window elapsed": {
			configure: func(_ *SAMLLogoutCommand, snapshot *SAMLLogoutSnapshot) {
				snapshot.RevokedAt = now.Add(-16 * time.Minute)
			},
			want: SAMLUpstreamLogoutNotConfirmed,
		},
		"artifact build rejected": {
			configure: func(*SAMLLogoutCommand, *SAMLLogoutSnapshot) {},
			want:      SAMLUpstreamLogoutNotConfirmed,
			flowCalls: 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			command, snapshot := samlLogoutFixture(t, now, true)
			fixture.configure(&command, &snapshot)
			store := &samlLogoutStoreFake{snapshot: snapshot}
			calls := 0
			logout, err := NewSAMLLogout(SAMLLogoutOptions{
				Flow: samlLogoutFlowFunc(func(context.Context, federatedsaml.LogoutBuildRequest) (federatedsaml.LogoutRequest, error) {
					calls++
					return federatedsaml.LogoutRequest{}, errors.New("upstream unavailable")
				}),
				Store: store, OperationTimeout: time.Second, Now: func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := logout.Logout(context.Background(), command)
			if err != nil || !result.LocalRevoked || result.Upstream != fixture.want ||
				result.RedirectURL != "" || calls != fixture.flowCalls {
				t.Fatalf("Logout()=%v,%v flowCalls=%d", result, err, calls)
			}
		})
	}
}

func TestSAMLLogoutDoesNotRequireUpstreamConfigurationOrEnvelopeForLocalOnlyRevocation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	command, snapshot := samlLogoutFixture(t, now, true)
	command.RequestUpstream = false
	snapshot.Configuration = TenantSAMLConfiguration{}
	snapshot.ProtectedMaterial = federatedsaml.ProtectedSessionMaterial{}
	flowCalls := 0
	logout, err := NewSAMLLogout(SAMLLogoutOptions{
		Flow: samlLogoutFlowFunc(func(context.Context, federatedsaml.LogoutBuildRequest) (federatedsaml.LogoutRequest, error) {
			flowCalls++
			return federatedsaml.LogoutRequest{}, errors.New("upstream must not be reached")
		}),
		Store: &samlLogoutStoreFake{snapshot: snapshot}, OperationTimeout: time.Second,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := logout.Logout(context.Background(), command)
	if err != nil || !result.LocalRevoked || result.Upstream != SAMLUpstreamLogoutNotRequested ||
		result.RedirectURL != "" || flowCalls != 0 {
		t.Fatalf("Logout()=%v,%v flowCalls=%d", result, err, flowCalls)
	}
}

func TestSAMLLogoutClearsEveryOwnedProtectedMaterialCopy(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	command, snapshot := samlLogoutFixture(t, now, true)
	returnedCiphertext := []byte("ciphertext-secret")
	snapshot.ProtectedMaterial.Ciphertext = returnedCiphertext
	var flowCiphertext []byte
	logout, err := NewSAMLLogout(SAMLLogoutOptions{
		Flow: samlLogoutFlowFunc(func(_ context.Context, request federatedsaml.LogoutBuildRequest) (federatedsaml.LogoutRequest, error) {
			flowCiphertext = request.ProtectedMaterial.Ciphertext
			return federatedsaml.LogoutRequest{}, errors.New("upstream unavailable")
		}),
		Store: samlLogoutStoreFunc(func(context.Context, SAMLLogoutCommand) (SAMLLogoutSnapshot, error) {
			return snapshot, nil
		}),
		OperationTimeout: time.Second,
		Now:              func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := logout.Logout(context.Background(), command)
	if err != nil || !result.LocalRevoked || result.Upstream != SAMLUpstreamLogoutNotConfirmed {
		t.Fatalf("Logout()=%v,%v", result, err)
	}
	for name, ciphertext := range map[string][]byte{
		"repository transfer": returnedCiphertext,
		"flow transfer":       flowCiphertext,
	} {
		if len(ciphertext) == 0 {
			t.Fatalf("%s ciphertext alias was not captured", name)
		}
		for _, value := range ciphertext {
			if value != 0 {
				t.Fatalf("%s ciphertext was not cleared", name)
			}
		}
	}
}

func TestSAMLLogoutRejectsPartialProtectedEnvelope(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	command, base := samlLogoutFixture(t, now, true)
	for name, material := range map[string]federatedsaml.ProtectedSessionMaterial{
		"key only":        {KeyVersion: 1},
		"ciphertext only": {Ciphertext: []byte("ciphertext-secret")},
		"short envelope":  {KeyVersion: 1, Ciphertext: []byte("short")},
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := cloneSAMLLogoutSnapshot(base)
			snapshot.ProtectedMaterial = material
			logout, err := NewSAMLLogout(SAMLLogoutOptions{
				Flow: samlLogoutFlowFunc(func(context.Context, federatedsaml.LogoutBuildRequest) (federatedsaml.LogoutRequest, error) {
					t.Fatal("partial envelope reached upstream flow")
					return federatedsaml.LogoutRequest{}, nil
				}),
				Store: &samlLogoutStoreFake{snapshot: snapshot}, OperationTimeout: time.Second,
				Now: func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			if result, err := logout.Logout(context.Background(), command); !errors.Is(err, ErrSessionRejected) ||
				result != (SAMLLogoutResult{}) {
				t.Fatalf("Logout()=%v,%v", result, err)
			}
		})
	}
}

func TestSAMLLogoutRejectsMismatchedRepositorySnapshots(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	command, base := samlLogoutFixture(t, now, true)
	for name, mutate := range map[string]func(*SAMLLogoutSnapshot){
		"operation":   func(value *SAMLLogoutSnapshot) { value.OperationRunID = serviceID(90) },
		"tenant":      func(value *SAMLLogoutSnapshot) { value.TenantID = serviceID(91) },
		"user":        func(value *SAMLLogoutSnapshot) { value.AuthenticatedUserID = serviceID(95) },
		"session":     func(value *SAMLLogoutSnapshot) { value.SessionID = serviceID(92) },
		"version":     func(value *SAMLLogoutSnapshot) { value.PreviousVersion++ },
		"provider":    func(value *SAMLLogoutSnapshot) { value.Provider.ProviderID = serviceID(93) },
		"binding":     func(value *SAMLLogoutSnapshot) { value.BindingID = serviceID(94) },
		"material":    func(value *SAMLLogoutSnapshot) { value.MaterialID = identity.EntityID{} },
		"future time": func(value *SAMLLogoutSnapshot) { value.RevokedAt = now.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := cloneSAMLLogoutSnapshot(base)
			mutate(&snapshot)
			store := &samlLogoutStoreFake{snapshot: snapshot}
			flowCalls := 0
			logout, err := NewSAMLLogout(SAMLLogoutOptions{
				Flow: samlLogoutFlowFunc(func(context.Context, federatedsaml.LogoutBuildRequest) (federatedsaml.LogoutRequest, error) {
					flowCalls++
					return federatedsaml.LogoutRequest{}, nil
				}),
				Store: store, OperationTimeout: time.Second, Now: func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			if result, err := logout.Logout(context.Background(), command); !errors.Is(err, ErrSessionRejected) ||
				result != (SAMLLogoutResult{}) || flowCalls != 0 {
				t.Fatalf("Logout()=%v,%v flowCalls=%d", result, err, flowCalls)
			}
		})
	}
}

func TestSAMLLogoutIsSafeForConcurrentIdempotentLocalRevocation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	command, snapshot := samlLogoutFixture(t, now, true)
	command.RequestUpstream = false
	store := &samlLogoutStoreFake{snapshot: snapshot}
	logout, err := NewSAMLLogout(SAMLLogoutOptions{
		Flow: samlLogoutFlowFunc(func(context.Context, federatedsaml.LogoutBuildRequest) (federatedsaml.LogoutRequest, error) {
			t.Fatal("upstream flow reached")
			return federatedsaml.LogoutRequest{}, nil
		}),
		Store: store, OperationTimeout: time.Second, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	const attempts = 32
	errorsFound := make(chan error, attempts)
	var wait sync.WaitGroup
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, callErr := logout.Logout(context.Background(), command)
			if callErr != nil || !result.LocalRevoked || result.Upstream != SAMLUpstreamLogoutNotRequested {
				errorsFound <- errors.Join(callErr, errors.New("unexpected logout result"))
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for callErr := range errorsFound {
		t.Fatal(callErr)
	}
	if store.callCount() != attempts {
		t.Fatalf("store calls=%d, want %d", store.callCount(), attempts)
	}
}

func TestSAMLLogoutFormattingRedactsSessionAndUpstreamArtifacts(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	command, snapshot := samlLogoutFixture(t, now, true)
	formatted := []string{
		command.String(), snapshot.String(),
		SAMLLogoutResult{LocalRevoked: true, Upstream: SAMLUpstreamLogoutReady, RedirectURL: "https://idp.example.test/?secret"}.String(),
	}
	for _, value := range formatted {
		for _, secret := range []string{"ciphertext-secret", "https://idp.example.test", "?secret"} {
			if strings.Contains(value, secret) {
				t.Fatalf("format leaked %q: %s", secret, value)
			}
		}
	}
}

func samlLogoutFixture(t *testing.T, now time.Time, withSLO bool) (SAMLLogoutCommand, SAMLLogoutSnapshot) {
	t.Helper()
	snapshot := samlLogoutSnapshotFixture(t, now, withSLO)
	return SAMLLogoutCommand{
		OperationRunID: snapshot.OperationRunID, TenantID: snapshot.TenantID,
		AuthenticatedUserID: snapshot.AuthenticatedUserID, SessionID: snapshot.SessionID,
		ExpectedVersion: snapshot.PreviousVersion, RequestUpstream: true,
	}, snapshot
}

func samlLogoutSnapshotFixture(t *testing.T, now time.Time, withSLO bool) SAMLLogoutSnapshot {
	t.Helper()
	configuration := samlConfigurationFixture(t, now, withSLO)
	operationID := serviceID(61)
	operationID[6], operationID[8] = 0x70, 0x80
	return SAMLLogoutSnapshot{
		OperationRunID: operationID, TenantID: configuration.Authentication.Provider.TenantID,
		AuthenticatedUserID: serviceID(64), SessionID: serviceID(62), PreviousVersion: 3,
		Provider: configuration.Authentication.Provider, BindingID: configuration.Authentication.BindingID,
		MaterialID:    serviceID(63),
		Configuration: configuration,
		ProtectedMaterial: federatedsaml.ProtectedSessionMaterial{
			KeyVersion: 1, Ciphertext: []byte("ciphertext-secret"),
		},
		RevokedAt: now.Add(-time.Minute),
	}
}
