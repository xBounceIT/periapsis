package sessionlogout

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

var logoutTestNow = time.Date(2026, time.September, 3, 9, 10, 0, 0, time.UTC)

type logoutStoreFake struct {
	credential   Credential
	resolveErr   error
	revoke       LocalRevokeSnapshot
	revokeErr    error
	claim        ContinuationSnapshot
	claimErr     error
	resolveCalls int
	revokeCalls  int
	claimCalls   int
	command      LocalRevokeCommand
	claimed      ContinuationClaim
}

func (store *logoutStoreFake) ResolveSessionForLogout(
	_ context.Context,
	digest [sha256.Size]byte,
) (Credential, error) {
	store.resolveCalls++
	result := store.credential
	result.TokenDigest = digest
	return result, store.resolveErr
}

func (store *logoutStoreFake) RevokeLocalSession(
	_ context.Context,
	command LocalRevokeCommand,
) (LocalRevokeSnapshot, error) {
	store.revokeCalls++
	store.command = command
	result := store.revoke
	result.OperationRunID = command.OperationRunID
	result.SessionID = command.Credential.SessionID
	result.UserID = command.Credential.UserID
	result.TenantID = command.Credential.TenantID
	result.RequestedAt = command.RequestedAt
	if result.ObservedAt.IsZero() {
		result.ObservedAt = command.RequestedAt
	}
	if result.Category == LogoutContinuation {
		result.ContinuationID = command.ContinuationID
		result.ContinuationExpiresAt = result.ObservedAt.Add(
			command.ContinuationExpiresAt.Sub(command.RequestedAt),
		)
	}
	return result, store.revokeErr
}

func (store *logoutStoreFake) ClaimLogoutContinuation(
	_ context.Context,
	claim ContinuationClaim,
) (ContinuationSnapshot, error) {
	store.claimCalls++
	store.claimed = claim
	result := store.claim
	result.RequestedClaimedAt = claim.ClaimedAt
	if result.ObservedAt.IsZero() {
		result.ObservedAt = claim.ClaimedAt
	}
	result.ContinuationID = claim.ContinuationID
	result.ProtectedIDToken.Ciphertext = append([]byte(nil), result.ProtectedIDToken.Ciphertext...)
	result.ProtectedSAML.Ciphertext = append([]byte(nil), result.ProtectedSAML.Ciphertext...)
	return result, store.claimErr
}

type idTokenOpenerFake struct {
	token      []byte
	err        error
	protection federatedauth.OIDCSessionMaterialSealContext
	calls      int
}

func (opener *idTokenOpenerFake) OpenOIDCIDToken(
	_ context.Context,
	protection federatedauth.OIDCSessionMaterialSealContext,
	_ federatedauth.ProtectedToken,
) ([]byte, error) {
	opener.calls++
	opener.protection = protection
	return append([]byte(nil), opener.token...), opener.err
}

type endSessionBuilderFake struct {
	redirect string
	err      error
	request  federatedoidc.StoredEndSessionBuildRequest
	calls    int
}

func (builder *endSessionBuilderFake) BuildEndSession(
	_ context.Context,
	request federatedoidc.StoredEndSessionBuildRequest,
) (string, error) {
	builder.calls++
	builder.request = request
	builder.request.IDTokenHint = append([]byte(nil), request.IDTokenHint...)
	return builder.redirect, builder.err
}

type samlBuilderFake struct {
	redirect string
	err      error
	request  federatedsaml.StoredLogoutBuildRequest
	calls    int
}

type samlLogoutFlowFunc func(context.Context, federatedsaml.StoredLogoutBuildRequest) (federatedsaml.LogoutRequest, error)

func (function samlLogoutFlowFunc) BuildStoredLogoutRequest(
	ctx context.Context,
	request federatedsaml.StoredLogoutBuildRequest,
) (federatedsaml.LogoutRequest, error) {
	return function(ctx, request)
}

func TestAuthoritySAMLLogoutBuilderDispatchesOnlyToPinnedAuthority(t *testing.T) {
	tenantCalls, directCalls := 0, 0
	tenant := samlLogoutFlowFunc(func(
		context.Context, federatedsaml.StoredLogoutBuildRequest,
	) (federatedsaml.LogoutRequest, error) {
		tenantCalls++
		return federatedsaml.LogoutRequest{}, errors.New("tenant sentinel")
	})
	direct := samlLogoutFlowFunc(func(
		context.Context, federatedsaml.StoredLogoutBuildRequest,
	) (federatedsaml.LogoutRequest, error) {
		directCalls++
		return federatedsaml.LogoutRequest{}, errors.New("direct sentinel")
	})
	builder, err := NewAuthoritySAMLLogoutBuilder(tenant, direct)
	if err != nil {
		t.Fatal(err)
	}

	for _, authority := range []federatedsaml.CeremonyAuthority{
		federatedsaml.TenantCeremonyAuthority,
		federatedsaml.DirectPlatformCeremonyAuthority,
	} {
		if _, err := builder.BuildSAMLLogout(context.Background(), federatedsaml.StoredLogoutBuildRequest{
			Configuration: federatedsaml.StoredLogoutConfiguration{Authority: authority},
		}); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("BuildSAMLLogout(%v) error = %v", authority, err)
		}
	}
	if tenantCalls != 1 || directCalls != 1 {
		t.Fatalf("dispatch calls = tenant:%d direct:%d", tenantCalls, directCalls)
	}
	if _, err := builder.BuildSAMLLogout(context.Background(), federatedsaml.StoredLogoutBuildRequest{
		Configuration: federatedsaml.StoredLogoutConfiguration{Authority: federatedsaml.CeremonyAuthority(99)},
	}); !errors.Is(err, ErrUnavailable) || tenantCalls != 1 || directCalls != 1 {
		t.Fatalf("unknown authority error/calls = %v, %d/%d", err, tenantCalls, directCalls)
	}
}

func (builder *samlBuilderFake) BuildSAMLLogout(
	_ context.Context,
	request federatedsaml.StoredLogoutBuildRequest,
) (string, error) {
	builder.calls++
	builder.request = request
	builder.request.ProtectedMaterial.Ciphertext = append([]byte(nil), request.ProtectedMaterial.Ciphertext...)
	return builder.redirect, builder.err
}

func TestLogoutRevokesAnySessionWithoutLiveAuthority(t *testing.T) {
	for _, state := range []string{
		"active", "membership suspended", "user disabled", "tenant disabled", "already revoked", "expired",
	} {
		t.Run(state, func(t *testing.T) {
			sessionToken, csrfToken := logoutTokens(0x21, 0x41)
			store := localLogoutStore(sessionToken, csrfToken)
			service := newLogoutService(t, store, nil, nil, nil)
			result, err := service.Logout(context.Background(), sessionToken, csrfToken, logoutEvent())
			if err != nil || !result.LocalRevoked || result.Continuation != nil ||
				store.resolveCalls != 1 || store.revokeCalls != 1 {
				t.Fatalf("Logout() = %s, %v; resolve=%d revoke=%d", result, err, store.resolveCalls, store.revokeCalls)
			}
			if !store.command.RequestUpstream || store.command.RequestDigest == ([sha256.Size]byte{}) ||
				store.command.ContinuationDigest == ([sha256.Size]byte{}) ||
				store.command.ContinuationExpiresAt != logoutTestNow.Add(time.Minute) {
				t.Fatalf("local revoke command drifted: %s", store.command)
			}
		})
	}
}

func TestLogoutAcceptsTheHTTPRequestIDAsDefaultCorrelation(t *testing.T) {
	sessionToken, csrfToken := logoutTokens(0x21, 0x41)
	store := localLogoutStore(sessionToken, csrfToken)
	service := newLogoutService(t, store, nil, nil, nil)
	event := logoutEvent()
	event.CorrelationID = event.RequestID
	result, err := service.Logout(context.Background(), sessionToken, csrfToken, event)
	if err != nil || !result.LocalRevoked || store.revokeCalls != 1 {
		t.Fatalf("logout with default HTTP correlation = %s, %v", result, err)
	}
	if store.command.Audit != event {
		t.Fatal("logout changed the HTTP audit correlation")
	}
}

func TestLogoutRejectsCSRFBeforeLocalMutation(t *testing.T) {
	sessionToken, csrfToken := logoutTokens(0x22, 0x42)
	_, wrongCSRF := logoutTokens(0x23, 0x43)
	store := localLogoutStore(sessionToken, csrfToken)
	service := newLogoutService(t, store, nil, nil, nil)
	result, err := service.Logout(context.Background(), sessionToken, wrongCSRF, logoutEvent())
	if !errors.Is(err, ErrForbidden) || result.LocalRevoked || store.resolveCalls != 1 || store.revokeCalls != 0 {
		t.Fatalf("Logout() = %s, %v; resolve=%d revoke=%d", result, err, store.resolveCalls, store.revokeCalls)
	}
}

func TestLogoutContinuationCredentialIsOneUseAndNeverInURLReceipt(t *testing.T) {
	sessionToken, csrfToken := logoutTokens(0x24, 0x44)
	store := localLogoutStore(sessionToken, csrfToken)
	store.revoke.Category = LogoutContinuation
	service := newLogoutService(t, store, nil, nil, nil)
	result, err := service.Logout(context.Background(), sessionToken, csrfToken, logoutEvent())
	if err != nil || !result.LocalRevoked || result.Continuation == nil {
		t.Fatalf("Logout() = %s, %v", result, err)
	}
	id, credential, expiresAt, ok := result.Continuation.Take()
	defer clear(credential)
	if !ok || id != store.command.ContinuationID || expiresAt != store.command.ContinuationExpiresAt ||
		sha256.Sum256(credential) != store.command.ContinuationDigest || !validOpaqueBytes(credential) {
		t.Fatalf("continuation ownership drifted: id=%x expires=%s", id, expiresAt)
	}
	if _, duplicate, _, ok := result.Continuation.Take(); ok || len(duplicate) != 0 {
		t.Fatal("continuation credential was consumed twice")
	}
}

func TestLogoutAcceptsDatabaseOwnedClockAndContinuationTTL(t *testing.T) {
	sessionToken, csrfToken := logoutTokens(0x27, 0x47)
	store := localLogoutStore(sessionToken, csrfToken)
	store.revoke.Category = LogoutContinuation
	store.revoke.ObservedAt = logoutTestNow.Add(750 * time.Millisecond)
	store.revoke.RevokedAt = store.revoke.ObservedAt
	service := newLogoutService(t, store, nil, nil, nil)
	result, err := service.Logout(context.Background(), sessionToken, csrfToken, logoutEvent())
	if err != nil || result.Continuation == nil {
		t.Fatalf("Logout() = %s, %v", result, err)
	}
	_, credential, expiresAt, ok := result.Continuation.Take()
	defer clear(credential)
	if !ok || !store.revoke.ObservedAt.After(store.command.RequestedAt) ||
		!expiresAt.Equal(store.revoke.ObservedAt.Add(time.Minute)) {
		t.Fatalf("DB-owned continuation expiry = %s, observed=%s requested=%s", expiresAt, store.revoke.ObservedAt, store.command.RequestedAt)
	}
}

func TestContinueConsumesOIDCProofBeforeBuildingServerSideRedirect(t *testing.T) {
	sessionToken, csrfToken := logoutTokens(0x25, 0x45)
	continuationCredential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, 32)))
	idToken := []byte("header.payload.signature")
	store := directPlatformOIDCLogoutStore(sessionToken, csrfToken, idToken)
	opener := &idTokenOpenerFake{token: idToken}
	builder := &endSessionBuilderFake{
		redirect: "https://provider.example/end-session?id_token_hint=secret",
	}
	service := newLogoutService(t, store, opener, builder, nil)
	redirect, err := service.Continue(context.Background(), logoutID(40), continuationCredential)
	if err != nil || redirect != builder.redirect || store.claimCalls != 1 || opener.calls != 1 || builder.calls != 1 ||
		store.claimed.ContinuationDigest != sha256.Sum256(continuationCredential) {
		t.Fatalf("Continue() = %q, %v; claim=%d open=%d build=%d", redirect, err, store.claimCalls, opener.calls, builder.calls)
	}
	if opener.protection.Provider != store.claim.Provider || opener.protection.MaterialID != store.claim.MaterialID ||
		!opener.protection.KeepIDToken || !bytes.Equal(builder.request.IDTokenHint, idToken) ||
		builder.request.PostLogoutRedirectURI != store.claim.PostLogoutRedirectURI ||
		builder.request.Confirmation == nil {
		t.Fatalf("OIDC continuation context drifted: protection=%+v request=%+v", opener.protection, builder.request)
	}
}

type borrowingEndSessionBuilder struct{ borrowed []byte }

func (builder *borrowingEndSessionBuilder) BuildEndSession(
	_ context.Context,
	request federatedoidc.StoredEndSessionBuildRequest,
) (string, error) {
	builder.borrowed = request.IDTokenHint
	return "https://provider.example/end-session", nil
}

func TestContinueClearsOwnedEndSessionIDTokenHint(t *testing.T) {
	credential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x79}, 32)))
	idToken := []byte("sensitive.header.payload.signature")
	store := directPlatformOIDCLogoutStore("", "", idToken)
	builder := &borrowingEndSessionBuilder{}
	service := newLogoutService(t, store, &idTokenOpenerFake{token: idToken}, builder, nil)
	if redirect, err := service.Continue(context.Background(), logoutID(104), credential); err != nil || redirect == "" {
		t.Fatalf("Continue() = %q, %v", redirect, err)
	}
	if len(builder.borrowed) != len(idToken) || !bytes.Equal(builder.borrowed, make([]byte, len(idToken))) {
		t.Fatalf("owned ID token hint was not cleared: %x", builder.borrowed)
	}
}

func TestContinueAcceptsDatabaseClockAheadAndBehind(t *testing.T) {
	for _, offset := range []time.Duration{-299 * time.Second, 299 * time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			credential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x7a}, 32)))
			idToken := []byte("clock.header.payload.signature")
			store := directPlatformOIDCLogoutStore("", "", idToken)
			store.claim.ObservedAt = logoutTestNow.Add(offset)
			store.claim.RevokedAt = store.claim.ObservedAt.Add(-time.Second)
			store.claim.ExpiresAt = store.claim.ObservedAt.Add(time.Minute)
			store.claim.MaterialExpiresAt = store.claim.ObservedAt.Add(time.Hour)
			builder := &endSessionBuilderFake{redirect: "https://provider.example/end-session"}
			service := newLogoutService(t, store, &idTokenOpenerFake{token: idToken}, builder, nil)
			if redirect, err := service.Continue(context.Background(), logoutID(105), credential); err != nil ||
				redirect != builder.redirect {
				t.Fatalf("Continue() at DB offset %s = %q, %v", offset, redirect, err)
			}
		})
	}
}

func TestContinueKeepsDirectOIDCMaterialAADAfterTenantSwitch(t *testing.T) {
	credential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x70}, 32)))
	idToken := []byte("switched.header.payload.signature")
	store := directPlatformOIDCLogoutStore("", "", idToken)
	store.claim.TenantID = logoutID(47)
	opener := &idTokenOpenerFake{token: idToken}
	builder := &endSessionBuilderFake{redirect: "https://provider.example/end-session"}
	service := newLogoutService(t, store, opener, builder, nil)
	redirect, err := service.Continue(context.Background(), logoutID(48), credential)
	if err != nil || redirect != builder.redirect || opener.calls != 1 || builder.calls != 1 ||
		opener.protection.Admission != (identity.TenantAdmissionContext{}) ||
		builder.request.Admission != (identity.TenantAdmissionContext{}) ||
		builder.request.SessionID != store.claim.SessionID {
		t.Fatalf("switched direct OIDC Continue() = %q, %v; protection=%+v request=%+v", redirect, err, opener.protection, builder.request)
	}
}

func TestContinueBuildsSAMLOnlyAfterAtomicClaim(t *testing.T) {
	credential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x72}, 32)))
	store := localLogoutStore("", "")
	store.claim = ContinuationSnapshot{
		Category: ClaimSAML, ContinuationID: logoutID(56), OperationRunID: logoutID(57),
		SessionID: logoutID(50), UserID: logoutID(51), TenantID: logoutID(52), PreviousVersion: 4,
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: logoutID(52), ProviderID: logoutID(53),
		},
		BindingID: logoutID(54), MaterialID: logoutID(55), RevokedAt: logoutTestNow,
		ExpiresAt: logoutTestNow.Add(time.Minute),
		SAMLConfiguration: logoutSAMLConfiguration(identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: logoutID(52), ProviderID: logoutID(53),
		}, logoutID(54), 0),
		ProtectedSAML: federatedsaml.ProtectedSessionMaterial{
			KeyVersion: 2, Ciphertext: bytes.Repeat([]byte{0x51}, 32),
		},
	}
	builder := &samlBuilderFake{redirect: "https://saml.example.test/slo?SAMLRequest=secret"}
	service := newLogoutService(t, store, nil, nil, builder)
	redirect, err := service.Continue(context.Background(), logoutID(56), credential)
	if err != nil || redirect != builder.redirect || store.claimCalls != 1 || builder.calls != 1 ||
		builder.request.SessionID != store.claim.SessionID || builder.request.MaterialID != store.claim.MaterialID ||
		builder.request.Confirmation == nil {
		t.Fatalf("Continue() = %q, %v, request=%+v", redirect, err, builder.request)
	}
}

func TestContinueBuildsDirectPlatformSAMLWithZeroBinding(t *testing.T) {
	credential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x74}, 32)))
	store := localLogoutStore("", "")
	store.claim = ContinuationSnapshot{
		Category: ClaimSAML, OperationRunID: logoutID(81), SessionID: logoutID(82),
		UserID: logoutID(83), PreviousVersion: 7,
		Provider:   identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: logoutID(84)},
		MaterialID: logoutID(85), RevokedAt: logoutTestNow, ExpiresAt: logoutTestNow.Add(time.Minute),
		SAMLConfiguration: logoutSAMLConfiguration(
			identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: logoutID(84)},
			identity.EntityID{}, 9,
		),
		ProtectedSAML: federatedsaml.ProtectedSessionMaterial{
			KeyVersion: 2, Ciphertext: bytes.Repeat([]byte{0x59}, minimumProtectedBytes),
		},
	}
	builder := &samlBuilderFake{redirect: "https://saml.example.test/slo?SAMLRequest=direct"}
	service := newLogoutService(t, store, nil, nil, builder)
	redirect, err := service.Continue(context.Background(), logoutID(86), credential)
	if err != nil || redirect != builder.redirect || builder.calls != 1 ||
		builder.request.Confirmation.SAMLBindingID() != (identity.EntityID{}) {
		t.Fatalf("direct platform Continue()=%q,%v request=%+v", redirect, err, builder.request)
	}
}

func TestContinueBuildsTenantAdmittedPlatformSAMLFromDirectMaterialContext(t *testing.T) {
	credential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x76}, 32)))
	tenantID := logoutID(88)
	admissionBindingID := logoutID(89)
	store := localLogoutStore("", "")
	store.claim = ContinuationSnapshot{
		Category: ClaimSAML, OperationRunID: logoutID(90), SessionID: logoutID(91),
		UserID: logoutID(92), TenantID: tenantID, PreviousVersion: 8,
		Provider:   identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: logoutID(93)},
		Admission:  identity.TenantAdmissionContext{TenantID: tenantID, BindingID: admissionBindingID},
		MaterialID: logoutID(94), RevokedAt: logoutTestNow, ExpiresAt: logoutTestNow.Add(time.Minute),
		SAMLConfiguration: logoutSAMLConfiguration(
			identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: logoutID(93)},
			identity.EntityID{}, 10,
		),
		ProtectedSAML: federatedsaml.ProtectedSessionMaterial{
			KeyVersion: 2, Ciphertext: bytes.Repeat([]byte{0x5a}, minimumProtectedBytes),
		},
	}
	builder := &samlBuilderFake{redirect: "https://saml.example.test/slo?SAMLRequest=switched"}
	service := newLogoutService(t, store, nil, nil, builder)
	redirect, err := service.Continue(context.Background(), logoutID(95), credential)
	if err != nil || redirect != builder.redirect || builder.calls != 1 ||
		builder.request.Confirmation.SAMLBindingID() != (identity.EntityID{}) {
		t.Fatalf("tenant-admitted platform Continue()=%q,%v request=%+v", redirect, err, builder.request)
	}
}

func TestContinueRejectsPlatformSAMLWithTenantMaterialBinding(t *testing.T) {
	credential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32)))
	provider := identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: logoutID(96)}
	store := localLogoutStore("", "")
	store.claim = ContinuationSnapshot{
		Category: ClaimSAML, OperationRunID: logoutID(97), SessionID: logoutID(98), UserID: logoutID(99),
		PreviousVersion: 9, Provider: provider, BindingID: logoutID(100), MaterialID: logoutID(101),
		RevokedAt: logoutTestNow, ExpiresAt: logoutTestNow.Add(time.Minute),
		SAMLConfiguration: logoutSAMLConfiguration(provider, identity.EntityID{}, 11),
		ProtectedSAML: federatedsaml.ProtectedSessionMaterial{
			KeyVersion: 2, Ciphertext: bytes.Repeat([]byte{0x5b}, minimumProtectedBytes),
		},
	}
	builder := &samlBuilderFake{redirect: "https://must-not-run.example/slo"}
	service := newLogoutService(t, store, nil, nil, builder)
	if redirect, err := service.Continue(context.Background(), logoutID(102), credential); !errors.Is(err, ErrUnavailable) || redirect != "" || store.claimCalls != 1 || builder.calls != 0 {
		t.Fatalf("Continue()=%q,%v claims=%d builds=%d", redirect, err, store.claimCalls, builder.calls)
	}
}

func TestContinueRejectsExpiredOrOverlongClaimAfterAtomicConsumption(t *testing.T) {
	credential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x75}, 32)))
	for name, expiry := range map[string]time.Time{
		"expired":  logoutTestNow,
		"overlong": logoutTestNow.Add(maximumContinuationTTL + time.Microsecond),
	} {
		t.Run(name, func(t *testing.T) {
			store := directPlatformOIDCLogoutStore("", "", []byte("header.payload.signature"))
			store.claim.ExpiresAt = expiry
			service := newLogoutService(t, store, &idTokenOpenerFake{}, &endSessionBuilderFake{}, nil)
			if redirect, err := service.Continue(context.Background(), logoutID(87), credential); !errors.Is(err, ErrUnavailable) || redirect != "" || store.claimCalls != 1 {
				t.Fatalf("Continue()=%q,%v claims=%d", redirect, err, store.claimCalls)
			}
		})
	}
}

func TestContinueRejectsOIDCMaterialAtExactExpiryAfterAtomicConsumption(t *testing.T) {
	credential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x78}, 32)))
	store := directPlatformOIDCLogoutStore("", "", []byte("header.payload.signature"))
	store.claim.MaterialExpiresAt = logoutTestNow
	service := newLogoutService(t, store, &idTokenOpenerFake{}, &endSessionBuilderFake{}, nil)
	if redirect, err := service.Continue(context.Background(), logoutID(103), credential); !errors.Is(err, ErrUnavailable) ||
		redirect != "" || store.claimCalls != 1 {
		t.Fatalf("Continue()=%q,%v claims=%d", redirect, err, store.claimCalls)
	}
}

func TestContinueFallsBackAfterConsumedOrUnavailableUpstream(t *testing.T) {
	credential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x73}, 32)))
	sessionToken, csrfToken := logoutTokens(0x26, 0x46)
	store := directPlatformOIDCLogoutStore(sessionToken, csrfToken, []byte("header.payload.signature"))
	store.claim.Category = ClaimGone
	service := newLogoutService(t, store, nil, nil, nil)
	if redirect, err := service.Continue(context.Background(), logoutID(60), credential); err != nil || redirect != "" {
		t.Fatalf("gone Continue() = %q, %v", redirect, err)
	}
	store.claim.Category = ClaimOIDC
	opener := &idTokenOpenerFake{err: errors.New("key unavailable")}
	builder := &endSessionBuilderFake{redirect: "https://must-not-run.example"}
	service = newLogoutService(t, store, opener, builder, nil)
	if redirect, err := service.Continue(context.Background(), logoutID(61), credential); err != nil || redirect != "" || builder.calls != 0 {
		t.Fatalf("failed open Continue() = %q, %v, builds=%d", redirect, err, builder.calls)
	}
}

func TestLogoutFormattingRedactsCredentialsEnvelopesAndRedirects(t *testing.T) {
	canary := "logout-canary-token-secret-url"
	continuation := BrowserContinuation{state: &browserContinuationState{
		id: logoutID(70), credential: []byte(canary), expiresAt: logoutTestNow.Add(time.Minute),
	}}
	values := []any{
		Credential{TokenDigest: sha256.Sum256([]byte(canary))},
		LocalRevokeCommand{Audit: EventContext{UserAgent: canary}},
		LocalRevokeSnapshot{}, ContinuationClaim{},
		ContinuationSnapshot{
			EndSessionEndpoint: "https://" + canary,
			ProtectedIDToken:   federatedauth.ProtectedToken{Ciphertext: []byte(canary)},
			ProtectedSAML:      federatedsaml.ProtectedSessionMaterial{Ciphertext: []byte(canary)},
		},
		continuation, &continuation, Result{LocalRevoked: true, Continuation: &continuation},
	}
	for _, value := range values {
		for _, formatted := range []string{
			fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value),
		} {
			if strings.Contains(formatted, canary) {
				t.Fatalf("%T format leaked material: %s", value, formatted)
			}
		}
	}
}

func newLogoutService(
	t *testing.T,
	store Store,
	opener federatedauth.OIDCSessionTokenOpener,
	oidc EndSessionBuilder,
	saml SAMLLogoutBuilder,
) *Service {
	t.Helper()
	ids := []identity.EntityID{logoutID(30), logoutID(31)}
	service, err := New(Options{
		Store: store, IDTokenOpener: opener, EndSessionBuilder: oidc, SAMLBuilder: saml,
		OperationTimeout: time.Second, ContinuationTTL: time.Minute,
		Now: func() time.Time { return logoutTestNow }, Random: bytes.NewReader(bytes.Repeat([]byte{0x77}, 256)),
		NewID: func() (identity.EntityID, error) {
			if len(ids) == 0 {
				return identity.EntityID{}, errors.New("no ID")
			}
			result := ids[0]
			ids = ids[1:]
			return result, nil
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return service
}

func localLogoutStore(sessionToken, csrfToken string) *logoutStoreFake {
	return &logoutStoreFake{
		credential: Credential{
			SessionID: logoutID(1), UserID: logoutID(2),
			TokenDigest: sha256.Sum256([]byte(sessionToken)), CSRFDigest: sha256.Sum256([]byte(csrfToken)),
		},
		revoke: LocalRevokeSnapshot{Category: LocalOnly, PreviousVersion: 3, RevokedAt: logoutTestNow},
	}
}

func directPlatformOIDCLogoutStore(sessionToken, csrfToken string, idToken []byte) *logoutStoreFake {
	store := localLogoutStore(sessionToken, csrfToken)
	store.claim = ContinuationSnapshot{
		Category: ClaimOIDC, OperationRunID: logoutID(8), SessionID: logoutID(4), UserID: logoutID(5),
		PreviousVersion: 4,
		Provider:        identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: logoutID(6)},
		MaterialID:      logoutID(7), RevokedAt: logoutTestNow, ExpiresAt: logoutTestNow.Add(time.Minute),
		EndSessionEndpoint:    "https://provider.example/end-session",
		PostLogoutRedirectURI: "https://historical-app.example/signed-out",
		ProtectedIDToken: federatedauth.ProtectedToken{
			KeyVersion: 2, Ciphertext: bytes.Repeat([]byte{0x63}, minimumProtectedBytes),
		},
		IDTokenDigest: sha256.Sum256(idToken), MaterialExpiresAt: logoutTestNow.Add(time.Hour),
	}
	return store
}

func logoutSAMLConfiguration(
	provider identity.ProviderContext,
	bindingID identity.EntityID,
	platformLoginRevision uint64,
) federatedsaml.StoredLogoutConfiguration {
	authority := federatedsaml.TenantCeremonyAuthority
	if provider.Scope == identity.PlatformProviderScope {
		authority = federatedsaml.DirectPlatformCeremonyAuthority
	}
	return federatedsaml.StoredLogoutConfiguration{
		Authority: authority, Provider: provider, MaterialBindingID: bindingID,
		PlatformLoginRevision: platformLoginRevision,
		SPEntityID:            "https://sp.example.test/saml/metadata",
		SLORedirectURL:        "https://idp.example.test/slo", SPKeyRevision: 7,
		RedirectSignatureAlgorithm: federatedsaml.RedirectRSASHA256,
	}
}

func logoutTokens(sessionByte, csrfByte byte) (string, string) {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{sessionByte}, opaqueCredentialBytes)),
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{csrfByte}, opaqueCredentialBytes))
}

func logoutEvent() EventContext {
	return EventContext{
		RequestID: logoutID(20), CorrelationID: logoutID(21),
		RemoteAddress: netip.MustParseAddr("203.0.113.20"), UserAgent: "session-logout-test/1",
	}
}

func logoutID(value byte) identity.EntityID {
	var result identity.EntityID
	result[6] = 0x70
	result[8] = 0x80
	result[15] = value
	return result
}
