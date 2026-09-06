package platformoidcauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

type directBrowserResolver struct{}

func (directBrowserResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
}

type directBrowserDialer struct{}

func (directBrowserDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("network disabled in test")
}

type directBrowserStartSourceFunc func(
	context.Context,
	DirectOIDCStartAuthority,
) (DirectOIDCStartGrant, error)

func (function directBrowserStartSourceFunc) BeginDirectOIDCLogin(
	ctx context.Context,
	authority DirectOIDCStartAuthority,
) (DirectOIDCStartGrant, error) {
	return function(ctx, authority)
}

type directBrowserConfigurationSource struct {
	mu             sync.Mutex
	configuration  DirectOIDCConfiguration
	pins           DirectOIDCConfigurationPins
	returnPath     string
	startCalls     []DirectOIDCStartGrant
	callbackCalls  []DirectOIDCCallbackConfigurationLookup
	startErrors    []error
	callbackErrors []error
	mutateStart    func(*DirectOIDCStartConfigurationSnapshot)
	mutateCallback func(*DirectOIDCCallbackConfigurationSnapshot)
}

func (source *directBrowserConfigurationSource) LoadDirectOIDCStartConfiguration(
	_ context.Context,
	grant DirectOIDCStartGrant,
) (DirectOIDCStartConfigurationSnapshot, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.startCalls = append(source.startCalls, grant)
	snapshot := DirectOIDCStartConfigurationSnapshot{Grant: grant, Configuration: source.configuration}
	if source.mutateStart != nil {
		source.mutateStart(&snapshot)
	}
	if len(source.startErrors) != 0 {
		err := source.startErrors[0]
		source.startErrors = source.startErrors[1:]
		return snapshot, err
	}
	return snapshot, nil
}

func (source *directBrowserConfigurationSource) ResolveDirectOIDCCallbackConfiguration(
	_ context.Context,
	lookup DirectOIDCCallbackConfigurationLookup,
) (DirectOIDCCallbackConfigurationSnapshot, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.callbackCalls = append(source.callbackCalls, lookup)
	snapshot := DirectOIDCCallbackConfigurationSnapshot{
		Lookup: lookup, Pins: source.pins, ReturnPath: source.returnPath,
		Configuration: source.configuration,
	}
	if source.mutateCallback != nil {
		source.mutateCallback(&snapshot)
	}
	if len(source.callbackErrors) != 0 {
		err := source.callbackErrors[0]
		source.callbackErrors = source.callbackErrors[1:]
		return snapshot, err
	}
	return snapshot, nil
}

type directBrowserFlowFake struct {
	mu               sync.Mutex
	calls            []string
	startRequest     federatedoidc.StartAuthorizationRequest
	startGrant       DirectOIDCStartGrant
	callbackRequest  federatedoidc.ResolvedCallbackRequest
	callbackAudit    DirectAuditContext
	callbackLookup   federatedoidc.CallbackConfigurationLookup
	claimAttemptID   federatedoidc.TransactionID
	claimErr         error
	exchangeErr      error
	verifyErr        error
	abortErrors      []error
	aborts           int
	abortContextErrs []error
	abortAudits      []DirectAuditContext
	abortClaims      []DirectClaimedAuthorization
	credentialSecret []byte
	claimHook        func(context.Context)
	startHook        func(*federatedoidc.StartAuthorizationRequest)
	verifyHook       func(*federatedoidc.ClaimExtractionPolicy)
	materialID       identity.EntityID
}

func (flow *directBrowserFlowFake) StartDirectAuthorization(
	_ context.Context,
	directRequest DirectOIDCStartAuthorizationRequest,
) (federatedoidc.AuthorizationStart, error) {
	flow.mu.Lock()
	defer flow.mu.Unlock()
	flow.calls = append(flow.calls, "start")
	request := directRequest.Protocol
	if flow.startHook != nil {
		flow.startHook(&request)
	}
	request.PreviousBrowserHandle = append([]byte(nil), request.PreviousBrowserHandle...)
	request.Configuration.ExtraScopes = append([]string(nil), request.Configuration.ExtraScopes...)
	flow.startRequest = request
	flow.startGrant = directRequest.Grant
	return federatedoidc.AuthorizationStart{}, nil
}

func (flow *directBrowserFlowFake) ClaimCallbackResolved(
	ctx context.Context,
	directRequest DirectOIDCCallbackRequest,
	resolver federatedoidc.CallbackConfigurationResolver,
) (DirectClaimedAuthorization, error) {
	request := directRequest.Protocol
	flow.mu.Lock()
	flow.calls = append(flow.calls, "claim")
	flow.callbackRequest = federatedoidc.ResolvedCallbackRequest{
		RawQuery: request.RawQuery, BrowserHandle: append([]byte(nil), request.BrowserHandle...),
	}
	flow.callbackAudit = directRequest.Audit
	lookup := flow.callbackLookup
	err := flow.claimErr
	hook := flow.claimHook
	flow.mu.Unlock()
	if hook != nil {
		hook(ctx)
	}
	if err != nil {
		return DirectClaimedAuthorization{}, err
	}
	if _, err = resolver.ResolveOIDCCallbackConfiguration(ctx, lookup); err != nil {
		return DirectClaimedAuthorization{}, err
	}
	return DirectClaimedAuthorization{
		Authorization:  &federatedoidc.ClaimedAuthorization{},
		ClaimAttemptID: flow.claimAttemptID,
	}, nil
}

func (flow *directBrowserFlowFake) ExchangeCode(
	_ context.Context,
	_ *federatedoidc.ClaimedAuthorization,
	credential federatedoidc.ClientCredential,
) (*federatedoidc.TokenBundle, error) {
	flow.mu.Lock()
	defer flow.mu.Unlock()
	flow.calls = append(flow.calls, "exchange")
	flow.credentialSecret = credential.Secret
	if flow.exchangeErr != nil {
		return nil, flow.exchangeErr
	}
	return &federatedoidc.TokenBundle{}, nil
}

func (flow *directBrowserFlowFake) VerifyIDToken(
	_ context.Context,
	_ *federatedoidc.ClaimedAuthorization,
	_ *federatedoidc.TokenBundle,
	policy federatedoidc.ClaimExtractionPolicy,
) (*federatedoidc.VerifiedAuthentication, error) {
	flow.mu.Lock()
	defer flow.mu.Unlock()
	flow.calls = append(flow.calls, "verify")
	if flow.verifyHook != nil {
		flow.verifyHook(&policy)
	}
	if flow.verifyErr != nil {
		return nil, flow.verifyErr
	}
	return &federatedoidc.VerifiedAuthentication{}, nil
}

type directBrowserSessionMaterial struct {
	id        identity.EntityID
	destroyed bool
}

func (material *directBrowserSessionMaterial) MaterialID() identity.EntityID {
	if material == nil || material.destroyed {
		return identity.EntityID{}
	}
	return material.id
}
func (*directBrowserSessionMaterial) HasIDToken() bool      { return true }
func (*directBrowserSessionMaterial) HasRefreshToken() bool { return false }
func (*directBrowserSessionMaterial) TakeTokens() (*federatedoidc.OwnedSessionTokens, bool) {
	return nil, false
}
func (material *directBrowserSessionMaterial) Destroy() {
	if material != nil {
		material.destroyed = true
		material.id = identity.EntityID{}
	}
}

func (flow *directBrowserFlowFake) TakeSessionMaterial(
	configuration federatedoidc.AuthorizationConfiguration,
	_ *federatedoidc.TokenBundle,
) (federatedauth.OIDCSessionMaterial, error) {
	flow.mu.Lock()
	defer flow.mu.Unlock()
	flow.calls = append(flow.calls, "take_session_material")
	if configuration.Discovery.Endpoints().EndSession == "" && !configuration.AllowRefreshToken {
		return nil, nil
	}
	return &directBrowserSessionMaterial{id: flow.materialID}, nil
}

func (flow *directBrowserFlowFake) AbortDirectClaimedAuthorization(
	ctx context.Context,
	claimed DirectClaimedAuthorization,
	audit DirectAuditContext,
) error {
	flow.mu.Lock()
	defer flow.mu.Unlock()
	flow.calls = append(flow.calls, "abort")
	flow.aborts++
	flow.abortContextErrs = append(flow.abortContextErrs, ctx.Err())
	flow.abortClaims = append(flow.abortClaims, claimed)
	flow.abortAudits = append(flow.abortAudits, audit)
	if len(flow.abortErrors) != 0 {
		err := flow.abortErrors[0]
		flow.abortErrors = flow.abortErrors[1:]
		return err
	}
	return nil
}

type directBrowserSecretSourceFunc func(
	context.Context,
	DirectOIDCClientSecretLookup,
) ([]byte, error)

func (function directBrowserSecretSourceFunc) OpenDirectOIDCClientSecret(
	ctx context.Context,
	lookup DirectOIDCClientSecretLookup,
) ([]byte, error) {
	return function(ctx, lookup)
}

type directBrowserTrustPlannerFunc func(
	context.Context,
	DirectOIDCTrustPlanRequest,
) (DirectAuthenticationPlan, error)

func (function directBrowserTrustPlannerFunc) Plan(
	ctx context.Context,
	request DirectOIDCTrustPlanRequest,
) (DirectAuthenticationPlan, error) {
	return function(ctx, request)
}

type directBrowserApplyPortFunc func(
	context.Context,
	DirectOIDCApplyRequest,
) (DirectOIDCApplyResult, error)

func (function directBrowserApplyPortFunc) ApplyDirectOIDC(
	ctx context.Context,
	request DirectOIDCApplyRequest,
) (DirectOIDCApplyResult, error) {
	return function(ctx, request)
}

type directBrowserSessionSealerFunc func(
	context.Context,
	federatedauth.OIDCSessionMaterialSealContext,
	federatedauth.OIDCSessionMaterial,
) (federatedauth.ProtectedOIDCSessionMaterial, error)

func (function directBrowserSessionSealerFunc) SealOIDCSessionMaterial(
	ctx context.Context,
	protection federatedauth.OIDCSessionMaterialSealContext,
	material federatedauth.OIDCSessionMaterial,
) (federatedauth.ProtectedOIDCSessionMaterial, error) {
	return function(ctx, protection, material)
}

type directBrowserCredentialIssuerFunc func(
	federatedauth.ApplyCredentialRequest,
) (*federatedauth.ApplyCredentialReservation, error)

func (function directBrowserCredentialIssuerFunc) ReserveApplyCredential(
	request federatedauth.ApplyCredentialRequest,
) (*federatedauth.ApplyCredentialReservation, error) {
	return function(request)
}

type directBrowserFixture struct {
	application   *DirectOIDCBrowserApplication
	configuration DirectOIDCConfiguration
	pins          DirectOIDCConfigurationPins
	lookup        DirectOIDCStartLookup
	digester      *DirectOIDCStartDigester
	flow          *directBrowserFlowFake
	configs       *directBrowserConfigurationSource
	capability    []byte
	audit         DirectAuditContext
	secret        []byte
	plan          DirectAuthenticationPlan
	applyCalls    []DirectOIDCApplyRequest
	secretCalls   []DirectOIDCClientSecretLookup
	trustCalls    []DirectOIDCTrustPlanRequest
}

func newDirectBrowserFixture(t *testing.T) *directBrowserFixture {
	t.Helper()
	configuration := directBrowserConfigurationFixture(t)
	pins := directBrowserConfigurationPinsFixture(configuration)
	digester, err := NewDirectOIDCStartDigester(bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	capability := bytes.Repeat([]byte{0x63}, 32)
	lookup, err := digester.BuildLookup(
		directTestEntityID(70), bytes.Repeat([]byte{0x52}, 32), capability,
		"provider_oracle_canary", "203.0.113.70",
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &directBrowserFixture{
		configuration: configuration, pins: pins, lookup: lookup, digester: digester,
		capability: capability, secret: []byte("direct-client-secret-canary"),
		audit: DirectAuditContext{
			RequestID: directTestEntityID(86), CorrelationID: directTestEntityID(87),
			RemoteAddress: netip.MustParseAddr("198.51.100.70"), UserAgent: "direct-browser-test/1.0",
		},
	}
	fixture.plan = directBrowserPlanFixture(configuration, DirectAuthenticationImmediateSession)
	fixture.flow = &directBrowserFlowFake{
		callbackLookup: directBrowserCallbackLookup(configuration),
		claimAttemptID: federatedoidc.TransactionID{9},
		materialID:     fixture.plan.Completion.MaterialID,
	}
	fixture.configs = &directBrowserConfigurationSource{
		configuration: configuration, pins: pins, returnPath: "/platform?from=login",
	}
	start := directBrowserStartSourceFunc(func(
		_ context.Context,
		authority DirectOIDCStartAuthority,
	) (DirectOIDCStartGrant, error) {
		if authority.Lookup != fixture.lookup {
			return DirectOIDCStartGrant{}, ErrDirectAuthenticationDenied
		}
		return DirectOIDCStartGrant{Authority: authority, Pins: pins}, nil
	})
	secret := directBrowserSecretSourceFunc(func(
		_ context.Context,
		lookup DirectOIDCClientSecretLookup,
	) ([]byte, error) {
		fixture.secretCalls = append(fixture.secretCalls, lookup)
		return fixture.secret, nil
	})
	planner := directBrowserTrustPlannerFunc(func(
		_ context.Context,
		request DirectOIDCTrustPlanRequest,
	) (DirectAuthenticationPlan, error) {
		fixture.trustCalls = append(fixture.trustCalls, request)
		return fixture.plan, nil
	})
	apply := directBrowserApplyPortFunc(func(
		_ context.Context,
		request DirectOIDCApplyRequest,
	) (DirectOIDCApplyResult, error) {
		fixture.applyCalls = append(fixture.applyCalls, cloneDirectOIDCApplyRequest(request))
		return directBrowserApplyResult(request), nil
	})
	fixture.application, err = NewDirectOIDCBrowserApplication(DirectOIDCBrowserApplicationOptions{
		Transactions: fixture.flow, Starts: start, Configurations: fixture.configs,
		ClientSecrets: secret, Trust: planner, Credentials: directBrowserCredentialIssuer(),
		Apply: apply,
		SessionSealer: directBrowserSessionSealerFunc(func(
			_ context.Context,
			protection federatedauth.OIDCSessionMaterialSealContext,
			_ federatedauth.OIDCSessionMaterial,
		) (federatedauth.ProtectedOIDCSessionMaterial, error) {
			result := federatedauth.ProtectedOIDCSessionMaterial{MaterialID: protection.MaterialID}
			if protection.KeepIDToken {
				result.IDToken = &federatedauth.ProtectedToken{KeyVersion: 1, Ciphertext: bytes.Repeat([]byte{0xa5}, 29)}
				result.IDTokenDigest = sha256.Sum256([]byte("id-token"))
			}
			if protection.KeepRefreshToken {
				result.RefreshToken = &federatedauth.ProtectedToken{KeyVersion: 1, Ciphertext: bytes.Repeat([]byte{0xa6}, 29)}
				result.RefreshTokenDigest = sha256.Sum256([]byte("refresh"))
				result.RefreshGeneration = 1
				result.AccessExpiresAt = directTestNow.Add(30 * time.Minute)
			}
			return result, nil
		}),
		Digester: digester,
		Now:      func() time.Time { return directTestNow }, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestDirectOIDCBrowserStartBindsExactDirectAuthority(t *testing.T) {
	fixture := newDirectBrowserFixture(t)
	previous := []byte("previous-browser-handle-canary")
	request := StartDirectOIDCRequest{
		Lookup: fixture.lookup, ReturnPath: "/platform?from=login", PreviousBrowserHandle: previous,
		Audit: fixture.audit,
	}
	if _, err := fixture.application.Start(context.Background(), request); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	fixture.configs.mu.Lock()
	startCalls := append([]DirectOIDCStartGrant(nil), fixture.configs.startCalls...)
	fixture.configs.mu.Unlock()
	fixture.flow.mu.Lock()
	flowRequest := fixture.flow.startRequest
	flowGrant := fixture.flow.startGrant
	flowCalls := append([]string(nil), fixture.flow.calls...)
	fixture.flow.mu.Unlock()
	if len(startCalls) != 1 || startCalls[0].Authority.Lookup != fixture.lookup ||
		startCalls[0].Authority.ReturnPath != request.ReturnPath ||
		startCalls[0].Authority.Audit != fixture.audit ||
		!slices.Equal(flowCalls, []string{"start"}) || flowGrant.Pins != fixture.pins ||
		flowGrant.Authority != startCalls[0].Authority ||
		flowRequest.ReturnPath != request.ReturnPath ||
		flowRequest.Configuration.Authority != federatedoidc.DirectPlatformCeremonyAuthority ||
		flowRequest.Configuration.Provider != fixture.pins.Provider ||
		flowRequest.Configuration.Admission != (identity.TenantAdmissionContext{}) ||
		flowRequest.Configuration.BindingID != (identity.EntityID{}) ||
		flowRequest.Configuration.BindingRevision != 0 || flowRequest.Configuration.MappingRevision != 0 ||
		flowRequest.Configuration.AuthorizationRevision != 0 ||
		flowRequest.Configuration.PlatformLoginRevision != fixture.pins.PlatformLoginRevision ||
		!slices.Equal(flowRequest.PreviousBrowserHandle, previous) {
		t.Fatalf("direct start authority drift: grants=%#v request=%s calls=%v", startCalls, flowRequest, flowCalls)
	}
	previous[0] ^= 0xff
	if slices.Equal(flowRequest.PreviousBrowserHandle, previous) {
		t.Fatal("protocol request retained caller browser storage")
	}
	if flowRequest.Begin.OperationRunID != fixture.lookup.OperationRunID ||
		flowRequest.Begin.ReceiptDigest != federatedoidc.StartReceiptDigest(fixture.lookup.ReceiptDigest) ||
		flowRequest.Begin.NetworkDigest != federatedoidc.NetworkThrottleDigest(fixture.lookup.NetworkDigest) ||
		flowRequest.Begin.AccountDigest != federatedoidc.AccountThrottleDigest(fixture.lookup.AccountDigest) ||
		flowRequest.Begin.ProviderDigest != federatedoidc.ProviderThrottleDigest(fixture.lookup.ProviderDigest) {
		t.Fatalf("protocol begin did not retain exact direct metering receipt: %s", flowRequest.Begin)
	}
	for name, rejected := range map[string]StartDirectOIDCRequest{
		"authenticated session": {
			Lookup: fixture.lookup, ReturnPath: "/", HasAuthenticatedSession: true, Audit: fixture.audit,
		},
		"absolute return":          {Lookup: fixture.lookup, ReturnPath: "https://evil.example/", Audit: fixture.audit},
		"ambiguous return":         {Lookup: fixture.lookup, ReturnPath: "//evil.example/", Audit: fixture.audit},
		"backslash return":         {Lookup: fixture.lookup, ReturnPath: `/\evil.example/`, Audit: fixture.audit},
		"decoded backslash return": {Lookup: fixture.lookup, ReturnPath: "/%5Cevil.example/", Audit: fixture.audit},
		"decoded control return":   {Lookup: fixture.lookup, ReturnPath: "/%0Aevil.example/", Audit: fixture.audit},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fixture.application.Start(context.Background(), rejected); !errors.Is(err, ErrDirectAuthenticationDenied) {
				t.Fatalf("Start() error = %v", err)
			}
		})
	}
	fixture.flow.mu.Lock()
	postRejectCalls := append([]string(nil), fixture.flow.calls...)
	fixture.flow.mu.Unlock()
	if !slices.Equal(postRejectCalls, []string{"start"}) {
		t.Fatalf("rejected starts reached protocol: %v", postRejectCalls)
	}
}

func TestDirectOIDCBrowserCompleteAppliesExactAssuranceAndContinuationAuthority(t *testing.T) {
	for name, disposition := range map[string]DirectAuthenticationDisposition{
		"immediate session":        DirectAuthenticationImmediateSession,
		"direct TOTP continuation": DirectAuthenticationTOTPContinuation,
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newDirectBrowserFixture(t)
			fixture.plan = directBrowserPlanFixture(fixture.configuration, disposition)
			rawQuery := "code=raw-code-canary&state=raw-state-canary"
			browser := []byte("browser-handle-canary")
			capability := append([]byte(nil), fixture.capability...)
			outcome, err := fixture.application.Complete(context.Background(), CompleteDirectOIDCRequest{
				RawQuery: rawQuery, BrowserHandle: browser, BrowserCapability: capability, Audit: fixture.audit,
			})
			if err != nil {
				t.Fatalf("Complete() error = %v", err)
			}
			wantAuthority := directContinuationAuthority(disposition)
			if outcome.Disposition != disposition || outcome.UserID != fixture.plan.UserID ||
				outcome.Credential == nil || len(fixture.applyCalls) != 1 ||
				len(fixture.secretCalls) != 1 {
				t.Fatalf("Complete()=%s apply=%d secret=%d", outcome, len(fixture.applyCalls), len(fixture.secretCalls))
			}
			if disposition == DirectAuthenticationImmediateSession {
				if outcome.SessionID == (identity.EntityID{}) || outcome.ContinuationID != (identity.EntityID{}) ||
					wantAuthority != federatedauth.ContinuationAuthorityTenant {
					t.Fatalf("immediate outcome = %s", outcome)
				}
			} else if outcome.SessionID != (identity.EntityID{}) ||
				outcome.ContinuationID == (identity.EntityID{}) ||
				wantAuthority != federatedauth.ContinuationAuthorityDirectPlatformOIDC {
				t.Fatalf("continuation outcome = %s", outcome)
			}
			apply := fixture.applyCalls[0]
			if apply.ContinuationAuthority != wantAuthority ||
				apply.ClaimAttemptID != fixture.flow.claimAttemptID || apply.Audit != fixture.audit ||
				!equalDirectSubjectObservation(apply.Observation, apply.Plan.Subject) ||
				!equalDirectSubjectObservation(apply.Observation, fixture.plan.Subject) ||
				!equalDirectSelectedAssurance(apply.Assurance, fixture.plan.SelectedAssurance) ||
				!equalDirectSelectedAssurance(apply.Assurance, apply.Plan.SelectedAssurance) ||
				apply.Plan.Completion != fixture.plan.Completion || apply.ReturnPath != fixture.plan.Completion.ReturnPath ||
				apply.BrowserCapabilityDigest != fixture.lookup.BrowserCapabilityDigest {
				t.Fatalf("atomic apply ABI = %s", apply)
			}
			if disposition == DirectAuthenticationImmediateSession &&
				(apply.Assurance.TrustRuleID == nil || *apply.Assurance.TrustRuleID != directTestEntityID(79) ||
					apply.Assurance.TrustRuleRevision == nil || *apply.Assurance.TrustRuleRevision != 29) {
				t.Fatalf("elevated assurance lost exact rule row: %s", apply.Assurance)
			}
			fixture.configs.mu.Lock()
			callbacks := append([]DirectOIDCCallbackConfigurationLookup(nil), fixture.configs.callbackCalls...)
			fixture.configs.mu.Unlock()
			if len(callbacks) != 1 || callbacks[0].BrowserCapabilityDigest != fixture.lookup.BrowserCapabilityDigest {
				t.Fatalf("callback browser binding = %#v", callbacks)
			}
			if len(fixture.trustCalls) != 1 ||
				fixture.trustCalls[0].TransactionID != fixture.flow.callbackLookup.TransactionID ||
				fixture.trustCalls[0].ClaimAttemptID != fixture.flow.claimAttemptID ||
				!fixture.trustCalls[0].ObservedAt.Equal(directTestNow) ||
				fixture.trustCalls[0].Pins != fixture.pins || fixture.trustCalls[0].Proof == nil {
				t.Fatalf("trust authority propagation = %#v", fixture.trustCalls)
			}
			if fixture.secretCalls[0] != (DirectOIDCClientSecretLookup{Pins: fixture.pins}) {
				t.Fatalf("direct zero-binding secret lookup = %s", fixture.secretCalls[0])
			}
			if !allZeroDirectBrowserBytes(fixture.secret) {
				t.Fatal("client-secret source storage was not cleared")
			}
			fixture.flow.mu.Lock()
			flowSecret := fixture.flow.credentialSecret
			flowCalls := append([]string(nil), fixture.flow.calls...)
			callbackRequest := fixture.flow.callbackRequest
			fixture.flow.mu.Unlock()
			if !allZeroDirectBrowserBytes(flowSecret) ||
				!slices.Equal(flowCalls, []string{"claim", "exchange", "verify", "take_session_material"}) {
				t.Fatalf("protocol material/calls = %v/%v", flowSecret, flowCalls)
			}
			if callbackRequest.RawQuery != rawQuery || !slices.Equal(callbackRequest.BrowserHandle, browser) ||
				!slices.Equal(capability, fixture.capability) {
				t.Fatal("callback inputs were not copied or caller capability was destroyed")
			}
			material, consumed := outcome.Credential.Consume()
			if !consumed || material.SessionID != outcome.SessionID ||
				material.ContinuationID != outcome.ContinuationID || material.Authority != wantAuthority {
				t.Fatalf("browser credential = %s consumed=%t", material, consumed)
			}
			material.Destroy()
		})
	}
}

func TestDirectOIDCBrowserRejectsReturnPathRecoveredOutsideClaimedRecord(t *testing.T) {
	fixture := newDirectBrowserFixture(t)
	fixture.configs.returnPath = "/different"
	outcome, err := fixture.application.Complete(context.Background(), CompleteDirectOIDCRequest{
		RawQuery: "opaque", BrowserHandle: []byte("opaque"),
		BrowserCapability: fixture.capability, Audit: fixture.audit,
	})
	if !errors.Is(err, ErrDirectAuthenticationDenied) || outcome != (DirectOIDCBrowserOutcome{}) ||
		len(fixture.secretCalls) != 0 || len(fixture.applyCalls) != 0 {
		t.Fatalf("Complete() = %s, %v secret=%d apply=%d", outcome, err, len(fixture.secretCalls), len(fixture.applyCalls))
	}
}

func TestDirectOIDCBrowserPersistenceCannotPoisonPlaintextCredentialOwnership(t *testing.T) {
	for name, disposition := range map[string]DirectAuthenticationDisposition{
		"session":      DirectAuthenticationImmediateSession,
		"continuation": DirectAuthenticationTOTPContinuation,
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newDirectBrowserFixture(t)
			fixture.plan = directBrowserPlanFixture(fixture.configuration, disposition)
			fixture.application.apply = directBrowserApplyPortFunc(func(
				_ context.Context,
				request DirectOIDCApplyRequest,
			) (DirectOIDCApplyResult, error) {
				result := directBrowserApplyResult(request)
				request.Session = mfa.SessionReservation{}
				request.Continuation = federatedauth.PostPrimaryContinuationReservation{}
				request.ContinuationAuthority = federatedauth.ContinuationAuthorityTenant
				return result, nil
			})
			outcome, err := fixture.application.Complete(context.Background(), CompleteDirectOIDCRequest{
				RawQuery: "opaque", BrowserHandle: []byte("opaque"),
				BrowserCapability: fixture.capability, Audit: fixture.audit,
			})
			if err != nil || outcome.Credential == nil {
				t.Fatalf("Complete() = %s, %v", outcome, err)
			}
			material, consumed := outcome.Credential.Consume()
			if !consumed || material.SessionID != outcome.SessionID ||
				material.ContinuationID != outcome.ContinuationID ||
				material.Authority != directContinuationAuthority(disposition) {
				t.Fatalf("credential after persistence poisoning = %s consumed=%t", material, consumed)
			}
			material.Destroy()
		})
	}
}

func TestDirectOIDCBrowserRejectsTenantConfigurationAndTransactionFamilies(t *testing.T) {
	t.Run("start tenant configuration", func(t *testing.T) {
		fixture := newDirectBrowserFixture(t)
		fixture.configs.mutateStart = func(snapshot *DirectOIDCStartConfigurationSnapshot) {
			makeTenantBrowserConfiguration(&snapshot.Configuration.Authorization)
		}
		if _, err := fixture.application.Start(context.Background(), StartDirectOIDCRequest{
			Lookup: fixture.lookup, ReturnPath: "/", Audit: fixture.audit,
		}); !errors.Is(err, ErrDirectAuthenticationDenied) {
			t.Fatalf("Start() error = %v", err)
		}
		fixture.flow.mu.Lock()
		calls := append([]string(nil), fixture.flow.calls...)
		fixture.flow.mu.Unlock()
		if len(calls) != 0 {
			t.Fatalf("tenant configuration reached protocol start: %v", calls)
		}
	})

	t.Run("callback tenant transaction", func(t *testing.T) {
		fixture := newDirectBrowserFixture(t)
		pins := fixture.flow.callbackLookup.Pins
		pins.Authority = federatedoidc.TenantCeremonyAuthority
		pins.Provider.Scope = identity.TenantProviderScope
		pins.Provider.TenantID = directTestEntityID(81)
		pins.BindingID = directTestEntityID(82)
		pins.BindingRevision = 31
		pins.MappingRevision = 32
		pins.AuthorizationRevision = 33
		pins.PlatformLoginRevision = 0
		fixture.flow.callbackLookup.Pins = pins
		if _, err := fixture.application.Complete(context.Background(), CompleteDirectOIDCRequest{
			RawQuery: "opaque", BrowserHandle: []byte("opaque"), BrowserCapability: fixture.capability,
			Audit: fixture.audit,
		}); !errors.Is(err, ErrDirectAuthenticationDenied) {
			t.Fatalf("Complete() error = %v", err)
		}
		fixture.configs.mu.Lock()
		resolveCount := len(fixture.configs.callbackCalls)
		fixture.configs.mu.Unlock()
		if resolveCount != 0 || len(fixture.secretCalls) != 0 {
			t.Fatalf("tenant callback reached direct adapters: resolves=%d secrets=%d", resolveCount, len(fixture.secretCalls))
		}
	})
}

func TestDirectOIDCBrowserRejectsEveryCallbackPinDriftUniformly(t *testing.T) {
	tests := map[string]func(*federatedoidc.TransactionPins){
		"provider":           func(value *federatedoidc.TransactionPins) { value.ProviderRevision++ },
		"login policy":       func(value *federatedoidc.TransactionPins) { value.PlatformLoginRevision++ },
		"configuration":      func(value *federatedoidc.TransactionPins) { value.ConfigurationRevision++ },
		"security":           func(value *federatedoidc.TransactionPins) { value.SecurityRevision++ },
		"assurance":          func(value *federatedoidc.TransactionPins) { value.AssurancePolicyRevision++ },
		"client secret":      func(value *federatedoidc.TransactionPins) { value.ClientSecretRevision++ },
		"discovery revision": func(value *federatedoidc.TransactionPins) { value.DiscoveryRevision++ },
		"discovery digest":   func(value *federatedoidc.TransactionPins) { value.DiscoveryDigest[0] ^= 0xff },
		"JWKS revision":      func(value *federatedoidc.TransactionPins) { value.JWKSRevision++ },
		"JWKS digest":        func(value *federatedoidc.TransactionPins) { value.JWKSDigest[0] ^= 0xff },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newDirectBrowserFixture(t)
			mutate(&fixture.flow.callbackLookup.Pins)
			outcome, err := fixture.application.Complete(context.Background(), CompleteDirectOIDCRequest{
				RawQuery: "provider-query-canary", BrowserHandle: []byte("browser-canary"),
				BrowserCapability: fixture.capability, Audit: fixture.audit,
			})
			if !errors.Is(err, ErrDirectAuthenticationDenied) || outcome != (DirectOIDCBrowserOutcome{}) {
				t.Fatalf("Complete() = %s, %v", outcome, err)
			}
			if len(fixture.secretCalls) != 0 || len(fixture.applyCalls) != 0 {
				t.Fatalf("stale pins reached secret/apply: %d/%d", len(fixture.secretCalls), len(fixture.applyCalls))
			}
		})
	}
}

func TestDirectOIDCBrowserRejectsEveryFullSnapshotPinDrift(t *testing.T) {
	tests := map[string]func(*DirectOIDCConfigurationPins){
		"plan":                    func(value *DirectOIDCConfigurationPins) { value.PlanRevision++ },
		"platform floor id":       func(value *DirectOIDCConfigurationPins) { value.PlatformFloorPolicyID = directTestEntityID(118) },
		"platform floor revision": func(value *DirectOIDCConfigurationPins) { value.PlatformFloorPolicyRevision++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newDirectBrowserFixture(t)
			fixture.configs.mutateCallback = func(snapshot *DirectOIDCCallbackConfigurationSnapshot) {
				mutate(&snapshot.Pins)
			}
			outcome, err := fixture.application.Complete(context.Background(), CompleteDirectOIDCRequest{
				RawQuery: "opaque", BrowserHandle: []byte("opaque"),
				BrowserCapability: fixture.capability, Audit: fixture.audit,
			})
			if !errors.Is(err, ErrDirectAuthenticationDenied) || outcome != (DirectOIDCBrowserOutcome{}) ||
				len(fixture.applyCalls) != 0 {
				t.Fatalf("Complete() = %s, %v apply=%d", outcome, err, len(fixture.applyCalls))
			}
		})
	}
}

func TestDirectOIDCBrowserRequiresClaimAttemptAuthority(t *testing.T) {
	fixture := newDirectBrowserFixture(t)
	fixture.flow.claimAttemptID = federatedoidc.TransactionID{}
	outcome, err := fixture.application.Complete(context.Background(), CompleteDirectOIDCRequest{
		RawQuery: "opaque", BrowserHandle: []byte("opaque"),
		BrowserCapability: fixture.capability, Audit: fixture.audit,
	})
	if !errors.Is(err, ErrDirectAuthenticationDenied) || outcome != (DirectOIDCBrowserOutcome{}) ||
		len(fixture.secretCalls) != 0 || len(fixture.applyCalls) != 0 {
		t.Fatalf("Complete() = %s, %v secret=%d apply=%d", outcome, err, len(fixture.secretCalls), len(fixture.applyCalls))
	}
}

func TestDirectOIDCBrowserRejectsMalformedAuditBeforeAnyEffect(t *testing.T) {
	tests := map[string]func(*DirectAuditContext){
		"zero request":          func(value *DirectAuditContext) { value.RequestID = identity.EntityID{} },
		"wrong request variant": func(value *DirectAuditContext) { value.RequestID[8] = 0x40 },
		"future correlation":    func(value *DirectAuditContext) { value.CorrelationID = directFutureEntityID() },
		"mapped IPv4": func(value *DirectAuditContext) {
			value.RemoteAddress = netip.MustParseAddr("::ffff:192.0.2.70")
		},
		"zoned IPv6": func(value *DirectAuditContext) {
			value.RemoteAddress = netip.MustParseAddr("fe80::1%eth0")
		},
		"empty agent": func(value *DirectAuditContext) { value.UserAgent = "" },
		"oversized agent": func(value *DirectAuditContext) {
			value.UserAgent = strings.Repeat("a", maximumDirectAuditUserAgentBytes+1)
		},
		"control agent":       func(value *DirectAuditContext) { value.UserAgent = "agent\nforged" },
		"directional agent":   func(value *DirectAuditContext) { value.UserAgent = "agent\u202eforged" },
		"invalid UTF-8 agent": func(value *DirectAuditContext) { value.UserAgent = string([]byte{0xff}) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newDirectBrowserFixture(t)
			audit := fixture.audit
			mutate(&audit)
			if _, err := fixture.application.Start(context.Background(), StartDirectOIDCRequest{
				Lookup: fixture.lookup, ReturnPath: "/", Audit: audit,
			}); !errors.Is(err, ErrDirectAuthenticationDenied) {
				t.Fatalf("Start() error = %v", err)
			}
			if _, err := fixture.application.Complete(context.Background(), CompleteDirectOIDCRequest{
				RawQuery: "opaque", BrowserHandle: []byte("opaque"),
				BrowserCapability: fixture.capability, Audit: audit,
			}); !errors.Is(err, ErrDirectAuthenticationDenied) {
				t.Fatalf("Complete() error = %v", err)
			}
			fixture.flow.mu.Lock()
			calls := append([]string(nil), fixture.flow.calls...)
			fixture.flow.mu.Unlock()
			if len(calls) != 0 || len(fixture.secretCalls) != 0 || len(fixture.applyCalls) != 0 {
				t.Fatalf("malformed audit reached effects: flow=%v secret=%d apply=%d", calls, len(fixture.secretCalls), len(fixture.applyCalls))
			}
		})
	}
}

func TestDirectOIDCBrowserRejectsTenantDigestTransplantAtStartPort(t *testing.T) {
	fixture := newDirectBrowserFixture(t)
	tenantDigester, err := federatedauth.NewOIDCStartDigester(bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := tenantDigester.BuildLookup(
		fixture.lookup.OperationRunID, bytes.Repeat([]byte{0x52}, 32),
		"tenant-canary", "provider_oracle_canary", "203.0.113.70",
	)
	if err != nil {
		t.Fatal(err)
	}
	transplanted := fixture.lookup
	transplanted.ReceiptDigest = DirectStartReceiptDigest(tenant.ReceiptDigest)
	transplanted.NetworkDigest = DirectNetworkRateDigest(tenant.NetworkDigest)
	transplanted.AccountDigest = DirectAccountRateDigest(tenant.AccountDigest)
	transplanted.ProviderDigest = DirectProviderRateDigest(tenant.ProviderDigest)
	if _, err = fixture.application.Start(context.Background(), StartDirectOIDCRequest{
		Lookup: transplanted, ReturnPath: "/", Audit: fixture.audit,
	}); !errors.Is(err, ErrDirectAuthenticationDenied) {
		t.Fatalf("Start() error = %v", err)
	}
	fixture.flow.mu.Lock()
	calls := append([]string(nil), fixture.flow.calls...)
	fixture.flow.mu.Unlock()
	if len(calls) != 0 {
		t.Fatalf("tenant-family digest reached protocol start: %v", calls)
	}
}

func TestDirectOIDCBrowserRejectsUnsupportedClaimProjectionExpansion(t *testing.T) {
	tests := map[string]func(*DirectOIDCConfiguration){
		"userinfo": func(value *DirectOIDCConfiguration) { value.Authorization.UseUserInfo = true },
		"scalar": func(value *DirectOIDCConfiguration) {
			value.IDTokenClaims.Scalars = []federatedoidc.ScalarClaimRule{{Claim: "department"}}
		},
		"profile": func(value *DirectOIDCConfiguration) {
			value.IDTokenClaims.Profiles = []federatedoidc.ProfileClaimRule{{Claim: "email", Field: federatedoidc.ProfileEmail}}
		},
		"groups": func(value *DirectOIDCConfiguration) {
			value.IDTokenClaims.Groups = &federatedoidc.StringArrayClaimRule{Claim: "groups"}
		},
		"required ACR": func(value *DirectOIDCConfiguration) { value.IDTokenClaims.ACR.Required = true },
		"renamed ACR":  func(value *DirectOIDCConfiguration) { value.IDTokenClaims.ACR.Claim = "loa" },
		"required AMR": func(value *DirectOIDCConfiguration) { value.IDTokenClaims.AMR.Required = true },
		"renamed AMR":  func(value *DirectOIDCConfiguration) { value.IDTokenClaims.AMR.Claim = "methods" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newDirectBrowserFixture(t)
			fixture.configs.mutateStart = func(snapshot *DirectOIDCStartConfigurationSnapshot) {
				mutate(&snapshot.Configuration)
			}
			if _, err := fixture.application.Start(context.Background(), StartDirectOIDCRequest{
				Lookup: fixture.lookup, ReturnPath: "/", Audit: fixture.audit,
			}); !errors.Is(err, ErrDirectAuthenticationDenied) {
				t.Fatalf("Start() error = %v", err)
			}
			fixture.flow.mu.Lock()
			calls := append([]string(nil), fixture.flow.calls...)
			fixture.flow.mu.Unlock()
			if len(calls) != 0 {
				t.Fatalf("expanded protocol configuration reached start: %v", calls)
			}
		})
	}
}

func TestDirectOIDCBrowserAllowsOptionalRefreshMaterial(t *testing.T) {
	fixture := newDirectBrowserFixture(t)
	fixture.configuration.Authorization.AllowRefreshToken = true
	fixture.configuration.Authorization.ExtraScopes = []string{"offline_access"}
	fixture.configs.configuration = fixture.configuration
	outcome, err := fixture.application.Complete(context.Background(), CompleteDirectOIDCRequest{
		RawQuery: "code=ok&state=ok", BrowserHandle: bytes.Repeat([]byte{0x51}, 32),
		BrowserCapability: fixture.capability, Audit: fixture.audit,
	})
	if err != nil || outcome.Credential == nil || len(fixture.applyCalls) != 1 {
		t.Fatalf("Complete()=%s,%v apply=%d", outcome, err, len(fixture.applyCalls))
	}
	defer outcome.Credential.Destroy()
	material := fixture.applyCalls[0].SessionMaterial
	if material == nil || material.IDToken != nil || material.RefreshToken == nil ||
		material.RefreshGeneration != 1 || material.RefreshTokenDigest == ([sha256.Size]byte{}) {
		t.Fatalf("refresh material not atomically applied: %v", material)
	}
}

func TestDirectOIDCBrowserRevalidatesEveryAtomicPlanPin(t *testing.T) {
	tests := map[string]func(*DirectAuthenticationPlan){
		"transaction": func(value *DirectAuthenticationPlan) { value.Completion.ID[0] ^= 0xff },
		"transaction version": func(value *DirectAuthenticationPlan) {
			value.Completion.ExpectedVersion++
		},
		"return path": func(value *DirectAuthenticationPlan) { value.Completion.ReturnPath = "/other" },
		"plan":        func(value *DirectAuthenticationPlan) { value.PlanRevision++ },
		"platform floor id": func(value *DirectAuthenticationPlan) {
			value.PlatformFloor.PolicyRevisions[0].PolicyID = directTestEntityID(119)
		},
		"platform floor revision": func(value *DirectAuthenticationPlan) {
			value.PlatformFloor.PolicyRevisions[0].Revision++
		},
		"user authentication": func(value *DirectAuthenticationPlan) { value.UserAuthenticationRevision = 0 },
		"identity":            func(value *DirectAuthenticationPlan) { value.IdentityRevision = 0 },
		"matched alias key":   func(value *DirectAuthenticationPlan) { value.MatchedAliasKeyVersion++ },
		"tenant evidence": func(value *DirectAuthenticationPlan) {
			value.Evidence[1].Source.DirectPlatform = false
			value.Evidence[1].Source.BindingID = directTestEntityID(88)
		},
		"local evidence": func(value *DirectAuthenticationPlan) {
			value.Evidence[1].Source = identity.AssuranceSource{Local: true}
		},
		"primary security revision": func(value *DirectAuthenticationPlan) {
			*value.Evidence[0].TrustRuleRevision++
		},
		"selected rule revision": func(value *DirectAuthenticationPlan) {
			*value.SelectedAssurance.TrustRuleRevision++
		},
		"selected rule id": func(value *DirectAuthenticationPlan) {
			*value.SelectedAssurance.TrustRuleID = identity.EntityID{}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newDirectBrowserFixture(t)
			mutate(&fixture.plan)
			outcome, err := fixture.application.Complete(context.Background(), CompleteDirectOIDCRequest{
				RawQuery: "opaque", BrowserHandle: []byte("opaque"),
				BrowserCapability: fixture.capability, Audit: fixture.audit,
			})
			if !errors.Is(err, ErrDirectAuthenticationDenied) || outcome != (DirectOIDCBrowserOutcome{}) ||
				len(fixture.applyCalls) != 0 {
				t.Fatalf("Complete() = %s, %v apply=%d", outcome, err, len(fixture.applyCalls))
			}
		})
	}
}

func TestDirectOIDCBrowserFailureIsUniformAndDestroysCredential(t *testing.T) {
	for name, testCase := range map[string]struct {
		mutate      func(*directBrowserFixture, *federatedauth.ApplyCredentialReservation)
		expectAbort int
	}{
		"claim": {
			mutate: func(fixture *directBrowserFixture, _ *federatedauth.ApplyCredentialReservation) {
				fixture.flow.claimErr = errors.New("provider canary")
			},
		},
		"secret": {
			mutate: func(fixture *directBrowserFixture, _ *federatedauth.ApplyCredentialReservation) {
				fixture.application.clientSecrets = directBrowserSecretSourceFunc(func(context.Context, DirectOIDCClientSecretLookup) ([]byte, error) {
					return []byte("secret canary"), errors.New("kms canary")
				})
			}, expectAbort: 1,
		},
		"exchange": {
			mutate: func(fixture *directBrowserFixture, _ *federatedauth.ApplyCredentialReservation) {
				fixture.flow.exchangeErr = errors.New("exchange canary")
			}, expectAbort: 1,
		},
		"verify": {
			mutate: func(fixture *directBrowserFixture, _ *federatedauth.ApplyCredentialReservation) {
				fixture.flow.verifyErr = errors.New("verify canary")
			}, expectAbort: 1,
		},
		"trust": {
			mutate: func(fixture *directBrowserFixture, _ *federatedauth.ApplyCredentialReservation) {
				fixture.application.trust = directBrowserTrustPlannerFunc(func(context.Context, DirectOIDCTrustPlanRequest) (DirectAuthenticationPlan, error) {
					return DirectAuthenticationPlan{}, errors.New("account oracle canary")
				})
			}, expectAbort: 1,
		},
		"credential": {
			mutate: func(fixture *directBrowserFixture, _ *federatedauth.ApplyCredentialReservation) {
				fixture.application.credentials = directBrowserCredentialIssuerFunc(func(federatedauth.ApplyCredentialRequest) (*federatedauth.ApplyCredentialReservation, error) {
					return nil, errors.New("entropy canary")
				})
			}, expectAbort: 1,
		},
		"apply": {
			mutate: func(fixture *directBrowserFixture, captured *federatedauth.ApplyCredentialReservation) {
				fixture.application.credentials = directBrowserCredentialIssuerFunc(func(request federatedauth.ApplyCredentialRequest) (*federatedauth.ApplyCredentialReservation, error) {
					reservation, err := directBrowserCredentialIssuer().ReserveApplyCredential(request)
					if reservation != nil {
						*captured = *reservation
						return captured, err
					}
					return nil, err
				})
				fixture.application.apply = directBrowserApplyPortFunc(func(context.Context, DirectOIDCApplyRequest) (DirectOIDCApplyResult, error) {
					return DirectOIDCApplyResult{}, errors.New("database oracle canary")
				})
			}, expectAbort: 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newDirectBrowserFixture(t)
			captured := &federatedauth.ApplyCredentialReservation{}
			testCase.mutate(fixture, captured)
			outcome, err := fixture.application.Complete(context.Background(), CompleteDirectOIDCRequest{
				RawQuery: "raw-provider-oracle", BrowserHandle: []byte("browser-oracle"),
				BrowserCapability: fixture.capability, Audit: fixture.audit,
			})
			if !errors.Is(err, ErrDirectAuthenticationDenied) || outcome != (DirectOIDCBrowserOutcome{}) {
				t.Fatalf("Complete() = %s, %v", outcome, err)
			}
			fixture.flow.mu.Lock()
			aborts := fixture.flow.aborts
			fixture.flow.mu.Unlock()
			if aborts != testCase.expectAbort {
				t.Fatalf("aborts = %d, want %d", aborts, testCase.expectAbort)
			}
			if name == "apply" && (!captured.Session().IsZero() || !captured.Continuation().IsZero()) {
				t.Fatal("failed apply retained credential reservation")
			}
		})
	}
}

func TestDirectOIDCBrowserRejectsRelabeledCredentialReservation(t *testing.T) {
	for name, disposition := range map[string]DirectAuthenticationDisposition{
		"session with SAML method":        DirectAuthenticationImmediateSession,
		"continuation with tenant digest": DirectAuthenticationTOTPContinuation,
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newDirectBrowserFixture(t)
			fixture.plan = directBrowserPlanFixture(fixture.configuration, disposition)
			var captured *federatedauth.ApplyCredentialReservation
			fixture.application.credentials = directBrowserCredentialIssuerFunc(func(request federatedauth.ApplyCredentialRequest) (*federatedauth.ApplyCredentialReservation, error) {
				if disposition == DirectAuthenticationImmediateSession {
					request.Method = federatedauth.AuthenticationMethodSAML
				} else {
					request.ContinuationAuthority = federatedauth.ContinuationAuthorityTenant
				}
				var err error
				captured, err = directBrowserCredentialIssuer().ReserveApplyCredential(request)
				return captured, err
			})
			outcome, err := fixture.application.Complete(context.Background(), CompleteDirectOIDCRequest{
				RawQuery: "opaque", BrowserHandle: []byte("opaque"),
				BrowserCapability: fixture.capability, Audit: fixture.audit,
			})
			if !errors.Is(err, ErrDirectAuthenticationDenied) || outcome != (DirectOIDCBrowserOutcome{}) ||
				len(fixture.applyCalls) != 0 || captured == nil ||
				!captured.Session().IsZero() || !captured.Continuation().IsZero() {
				t.Fatalf("Complete() = %s, %v apply=%d reservation=%v", outcome, err, len(fixture.applyCalls), captured)
			}
		})
	}
}

func TestDirectOIDCBrowserHonorsCancellationAndUsesIndependentAbortContext(t *testing.T) {
	t.Run("pre-canceled", func(t *testing.T) {
		fixture := newDirectBrowserFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := fixture.application.Start(ctx, StartDirectOIDCRequest{
			Lookup: fixture.lookup, ReturnPath: "/", Audit: fixture.audit,
		}); !errors.Is(err, ErrDirectAuthenticationDenied) {
			t.Fatalf("Start() error = %v", err)
		}
		if _, err := fixture.application.Complete(ctx, CompleteDirectOIDCRequest{
			RawQuery: "opaque", BrowserHandle: []byte("opaque"),
			BrowserCapability: fixture.capability, Audit: fixture.audit,
		}); !errors.Is(err, ErrDirectAuthenticationDenied) {
			t.Fatalf("Complete() error = %v", err)
		}
		fixture.flow.mu.Lock()
		calls := append([]string(nil), fixture.flow.calls...)
		fixture.flow.mu.Unlock()
		if len(calls) != 0 {
			t.Fatalf("pre-canceled operation reached protocol: %v", calls)
		}
	})

	t.Run("post-claim cancellation", func(t *testing.T) {
		fixture := newDirectBrowserFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		secret := []byte("cancellation-secret-canary")
		fixture.application.clientSecrets = directBrowserSecretSourceFunc(func(context.Context, DirectOIDCClientSecretLookup) ([]byte, error) {
			cancel()
			return secret, nil
		})
		if _, err := fixture.application.Complete(ctx, CompleteDirectOIDCRequest{
			RawQuery: "opaque", BrowserHandle: []byte("opaque"),
			BrowserCapability: fixture.capability, Audit: fixture.audit,
		}); !errors.Is(err, ErrDirectAuthenticationDenied) {
			t.Fatalf("Complete() error = %v", err)
		}
		fixture.flow.mu.Lock()
		aborts := fixture.flow.aborts
		abortContextErrs := append([]error(nil), fixture.flow.abortContextErrs...)
		abortAudits := append([]DirectAuditContext(nil), fixture.flow.abortAudits...)
		abortClaims := append([]DirectClaimedAuthorization(nil), fixture.flow.abortClaims...)
		fixture.flow.mu.Unlock()
		if aborts != 1 || len(abortContextErrs) != 1 || abortContextErrs[0] != nil ||
			len(abortAudits) != 1 || abortAudits[0] != fixture.audit || len(abortClaims) != 1 ||
			abortClaims[0].ClaimAttemptID != fixture.flow.claimAttemptID ||
			!allZeroDirectBrowserBytes(secret) {
			t.Fatalf("abort authority/context/secret = %d/%v/%v/%v/%v", aborts, abortContextErrs, abortAudits, abortClaims, secret)
		}
	})
}

func TestDirectOIDCBrowserRetriesExactInputsAndOwnsAdapterSlices(t *testing.T) {
	fixture := newDirectBrowserFixture(t)
	var startMu sync.Mutex
	var authorities []DirectOIDCStartAuthority
	fixture.application.starts = directBrowserStartSourceFunc(func(
		_ context.Context,
		authority DirectOIDCStartAuthority,
	) (DirectOIDCStartGrant, error) {
		startMu.Lock()
		defer startMu.Unlock()
		authorities = append(authorities, authority)
		grant := DirectOIDCStartGrant{Authority: authority, Pins: fixture.pins}
		if len(authorities) == 1 {
			return grant, errors.New("begin response lost")
		}
		return grant, nil
	})
	fixture.configs.startErrors = []error{errors.New("configuration response lost")}
	previous := []byte("previous-browser-owned-by-caller")
	fixture.flow.startHook = func(request *federatedoidc.StartAuthorizationRequest) {
		request.PreviousBrowserHandle[0] ^= 0xff
	}
	if _, err := fixture.application.Start(context.Background(), StartDirectOIDCRequest{
		Lookup: fixture.lookup, ReturnPath: "/retry", PreviousBrowserHandle: previous, Audit: fixture.audit,
	}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	startMu.Lock()
	startCalls := append([]DirectOIDCStartAuthority(nil), authorities...)
	startMu.Unlock()
	fixture.configs.mu.Lock()
	configurationCalls := append([]DirectOIDCStartGrant(nil), fixture.configs.startCalls...)
	fixture.configs.mu.Unlock()
	if len(startCalls) != 2 || startCalls[0] != startCalls[1] || len(configurationCalls) != 2 ||
		configurationCalls[0] != configurationCalls[1] ||
		string(previous) != "previous-browser-owned-by-caller" {
		t.Fatalf("start retries/caller storage = %#v/%#v/%q", startCalls, configurationCalls, previous)
	}

	fixture = newDirectBrowserFixture(t)
	wantAlias := fixture.plan.Subject.Aliases[0]
	wantCiphertext := append([]byte(nil), fixture.plan.Subject.Envelope.Ciphertext...)
	wantRuleID := *fixture.plan.SelectedAssurance.TrustRuleID
	wantPolicyID := fixture.plan.PlatformFloor.PolicyRevisions[0].PolicyID
	fixture.flow.verifyHook = func(policy *federatedoidc.ClaimExtractionPolicy) {
		policy.ACR.Claim = "mutated-acr"
		policy.AMR.Claim = "mutated-amr"
	}
	applyCalls := 0
	fixture.application.apply = directBrowserApplyPortFunc(func(
		_ context.Context,
		request DirectOIDCApplyRequest,
	) (DirectOIDCApplyResult, error) {
		applyCalls++
		if request.Plan.Subject.Aliases[0] != wantAlias ||
			!slices.Equal(request.Plan.Subject.Envelope.Ciphertext, wantCiphertext) ||
			*request.Assurance.TrustRuleID != wantRuleID ||
			request.Plan.PlatformFloor.PolicyRevisions[0].PolicyID != wantPolicyID {
			t.Fatalf("apply retry received mutated plan: %s", request)
		}
		if applyCalls == 1 {
			request.Plan.Subject.Aliases[0].Digest[0] ^= 0xff
			request.Plan.Subject.Envelope.Ciphertext[0] ^= 0xff
			*request.Assurance.TrustRuleID = directTestEntityID(89)
			request.Plan.PlatformFloor.PolicyRevisions[0].PolicyID = directTestEntityID(89)
			return DirectOIDCApplyResult{}, errors.New("apply response lost")
		}
		return directBrowserApplyResult(request), nil
	})
	outcome, err := fixture.application.Complete(context.Background(), CompleteDirectOIDCRequest{
		RawQuery: "opaque", BrowserHandle: []byte("opaque"),
		BrowserCapability: fixture.capability, Audit: fixture.audit,
	})
	if err != nil || applyCalls != 2 || outcome.Credential == nil {
		t.Fatalf("Complete() = %s, %v calls=%d", outcome, err, applyCalls)
	}
	outcome.Credential.Destroy()
	if fixture.configuration.IDTokenClaims.ACR.Claim != "acr" ||
		fixture.configuration.IDTokenClaims.AMR.Claim != "amr" ||
		fixture.plan.Subject.Aliases[0] != wantAlias ||
		!slices.Equal(fixture.plan.Subject.Envelope.Ciphertext, wantCiphertext) ||
		*fixture.plan.SelectedAssurance.TrustRuleID != wantRuleID ||
		fixture.plan.PlatformFloor.PolicyRevisions[0].PolicyID != wantPolicyID {
		t.Fatal("untrusted adapter retained or mutated application-owned slices")
	}
}

func TestDirectOIDCBrowserStartIsConcurrentReadSafe(t *testing.T) {
	fixture := newDirectBrowserFixture(t)
	const workers = 24
	errorsByWorker := make(chan error, workers)
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := fixture.application.Start(context.Background(), StartDirectOIDCRequest{
				Lookup: fixture.lookup, ReturnPath: "/concurrent", Audit: fixture.audit,
			})
			errorsByWorker <- err
		}()
	}
	group.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		if err != nil {
			t.Fatalf("concurrent Start() error = %v", err)
		}
	}
	fixture.flow.mu.Lock()
	flowCalls := len(fixture.flow.calls)
	fixture.flow.mu.Unlock()
	if flowCalls != workers {
		t.Fatalf("protocol starts = %d, want %d", flowCalls, workers)
	}
}

func TestDirectOIDCBrowserRejectsMalformedAtomicSuccessAndDestroysCredential(t *testing.T) {
	tests := map[string]func(*DirectOIDCApplyResult){
		"transaction":            func(value *DirectOIDCApplyResult) { value.TransactionID[0] ^= 0xff },
		"browser binding":        func(value *DirectOIDCApplyResult) { value.BrowserCapabilityDigest[0] ^= 0xff },
		"user":                   func(value *DirectOIDCApplyResult) { value.UserID = directTestEntityID(120) },
		"session reservation":    func(value *DirectOIDCApplyResult) { value.SessionID = directTestEntityID(121) },
		"ambiguous continuation": func(value *DirectOIDCApplyResult) { value.ContinuationID = directTestEntityID(122) },
		"return path":            func(value *DirectOIDCApplyResult) { value.ReturnPath = "/oracle" },
		"apply instant":          func(value *DirectOIDCApplyResult) { value.AppliedAt = value.AppliedAt.Add(time.Second) },
		"disposition":            func(value *DirectOIDCApplyResult) { value.Disposition = DirectAuthenticationTOTPContinuation },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newDirectBrowserFixture(t)
			var captured *federatedauth.ApplyCredentialReservation
			issuer := directBrowserCredentialIssuer()
			fixture.application.credentials = directBrowserCredentialIssuerFunc(func(request federatedauth.ApplyCredentialRequest) (*federatedauth.ApplyCredentialReservation, error) {
				var err error
				captured, err = issuer.ReserveApplyCredential(request)
				return captured, err
			})
			fixture.application.apply = directBrowserApplyPortFunc(func(
				_ context.Context,
				request DirectOIDCApplyRequest,
			) (DirectOIDCApplyResult, error) {
				result := directBrowserApplyResult(request)
				mutate(&result)
				return result, nil
			})
			outcome, err := fixture.application.Complete(context.Background(), CompleteDirectOIDCRequest{
				RawQuery: "raw-oracle-canary", BrowserHandle: []byte("browser-oracle-canary"),
				BrowserCapability: fixture.capability, Audit: fixture.audit,
			})
			if !errors.Is(err, ErrDirectAuthenticationDenied) || outcome != (DirectOIDCBrowserOutcome{}) ||
				captured == nil || !captured.Session().IsZero() || !captured.Continuation().IsZero() {
				t.Fatalf("Complete() = %s, %v reservation=%v", outcome, err, captured)
			}
			fixture.flow.mu.Lock()
			aborts := fixture.flow.aborts
			fixture.flow.mu.Unlock()
			if aborts != 1 {
				t.Fatalf("aborts = %d", aborts)
			}
		})
	}
}

func directBrowserConfigurationFixture(t *testing.T) DirectOIDCConfiguration {
	return directBrowserConfigurationFixtureAt(t, directTestNow)
}

func directBrowserConfigurationFixtureAt(t *testing.T, snapshotNow time.Time) DirectOIDCConfiguration {
	t.Helper()
	policy, err := federatedhttp.NewDeploymentEgressPolicy(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	httpClient, err := federatedhttp.New(federatedhttp.Options{
		Resolver: directBrowserResolver{}, Dialer: directBrowserDialer{}, EgressPolicy: policy,
		RootCAs: x509.NewCertPool(), Limits: federatedhttp.DefaultLimits(), MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := federatedoidc.New(federatedoidc.Options{HTTP: httpClient, Limits: federatedoidc.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://direct-provider.example.test"
	discoveryDocument := directBrowserJSON(t, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/jwks",
		"response_types_supported":              []string{federatedoidc.ResponseTypeCode},
		"response_modes_supported":              []string{federatedoidc.ResponseModeQuery},
		"grant_types_supported":                 []string{federatedoidc.GrantAuthorizationCode},
		"code_challenge_methods_supported":      []string{federatedoidc.CodeChallengeS256},
		"token_endpoint_auth_methods_supported": []string{string(federatedoidc.ClientSecretBasic)},
		"subject_types_supported":               []string{"public"},
		"scopes_supported":                      []string{federatedoidc.RequiredScopeOpenID},
		"id_token_signing_alg_values_supported": []string{string(federatedoidc.SigningEdDSA)},
	})
	cache := federatedhttp.CacheMetadata{
		RetrievedAt: snapshotNow.Add(-time.Minute), FreshUntil: snapshotNow.Add(time.Hour), Cacheable: true,
	}
	discovery, err := client.RestoreDiscovery(federatedoidc.DiscoverySnapshotRecord{
		Request: federatedoidc.DiscoveryRequest{
			Issuer: issuer, Revision: 17,
			Policy: federatedoidc.TrustPolicy{
				ClientAuthentication: federatedoidc.ClientSecretBasic,
				SigningAlgorithms:    []federatedoidc.SigningAlgorithm{federatedoidc.SigningEdDSA},
			},
		},
		Document: discoveryDocument, Digest: sha256.Sum256(discoveryDocument), Cache: cache,
	})
	if err != nil {
		t.Fatalf("RestoreDiscovery() error = %v", err)
	}
	seed := sha256.Sum256([]byte("direct browser deterministic Ed25519 key"))
	publicKey := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	jwksDocument := directBrowserJSON(t, map[string]any{"keys": []any{map[string]any{
		"kty": "OKP", "kid": "direct-browser-key-1", "use": "sig",
		"alg": string(federatedoidc.SigningEdDSA), "crv": "Ed25519",
		"x": base64.RawURLEncoding.EncodeToString(publicKey),
	}}})
	jwks, err := client.RestoreJWKS(federatedoidc.JWKSSnapshotRecord{
		Revision: 18, Document: jwksDocument, Digest: sha256.Sum256(jwksDocument),
		Cache: cache, Discovery: discovery,
	})
	if err != nil {
		t.Fatalf("RestoreJWKS() error = %v", err)
	}
	return DirectOIDCConfiguration{
		Authorization: federatedoidc.AuthorizationConfiguration{
			Authority: federatedoidc.DirectPlatformCeremonyAuthority,
			Provider: identity.ProviderContext{
				Scope: identity.PlatformProviderScope, ProviderID: directTestEntityID(71),
			},
			ProviderRevision: 11, PlatformLoginRevision: 12, ConfigurationRevision: 13,
			SecurityRevision: 14, AssurancePolicyRevision: 15, ClientSecretRevision: 16,
			ClientID: "direct-browser-client", RedirectURI: "https://api.example.test/auth/oidc/callback",
			Discovery: discovery, JWKS: jwks,
		},
		IDTokenClaims: federatedoidc.ClaimExtractionPolicy{
			ACR: &federatedoidc.ScalarClaimRule{Claim: "acr"},
			AMR: &federatedoidc.StringArrayClaimRule{Claim: "amr"},
		},
	}
}

func directBrowserCallbackLookup(
	configuration DirectOIDCConfiguration,
) federatedoidc.CallbackConfigurationLookup {
	directPins := directBrowserConfigurationPinsFixture(configuration)
	return federatedoidc.CallbackConfigurationLookup{
		TransactionID: federatedoidc.TransactionID{1, 2, 3}, ExpectedVersion: 2,
		Pins: federatedoidc.TransactionPins{
			Authority: federatedoidc.DirectPlatformCeremonyAuthority, Provider: directPins.Provider,
			ProviderRevision: directPins.ProviderRevision, PlatformLoginRevision: directPins.PlatformLoginRevision,
			ConfigurationRevision: directPins.ConfigurationRevision, SecurityRevision: directPins.SecurityRevision,
			PlanRevision:            directPins.PlanRevision,
			AssurancePolicyRevision: directPins.AssurancePolicyRevision,
			PlatformFloorPolicyID:   directPins.PlatformFloorPolicyID,
			PlatformFloorRevision:   directPins.PlatformFloorPolicyRevision,
			ClientSecretRevision:    directPins.ClientSecretRevision,
			DiscoveryRevision:       directPins.DiscoveryRevision, DiscoveryDigest: directPins.DiscoveryDigest,
			JWKSRevision: directPins.JWKSRevision, JWKSDigest: directPins.JWKSDigest,
		},
		ReturnPath: "/platform?from=login",
	}
}

func directBrowserConfigurationPinsFixture(
	configuration DirectOIDCConfiguration,
) DirectOIDCConfigurationPins {
	pins, ok := directConfigurationPinsFromAuthorization(configuration.Authorization)
	if !ok {
		panic("invalid direct browser configuration fixture")
	}
	pins.PlanRevision = 19
	pins.PlatformFloorPolicyID = directTestEntityID(74)
	pins.PlatformFloorPolicyRevision = 24
	return pins
}

func directBrowserPlanFixture(
	configuration DirectOIDCConfiguration,
	disposition DirectAuthenticationDisposition,
) DirectAuthenticationPlan {
	callback := directBrowserCallbackLookup(configuration)
	pins := directBrowserConfigurationPinsFixture(configuration)
	authenticatedAt := directTestNow.Add(-2 * time.Minute)
	expiresAt := directTestNow.Add(time.Hour)
	securityRevision := int64(callback.Pins.SecurityRevision)
	aliasDigest := sha256.Sum256([]byte("direct-browser-subject-alias"))
	plan := DirectAuthenticationPlan{
		Disposition: disposition,
		Completion: federatedoidc.TransactionCompletion{
			ID: callback.TransactionID, ExpectedVersion: callback.ExpectedVersion,
			MaterialID: directTestEntityID(75),
			Pins:       callback.Pins, CompletedAt: directTestNow.Add(-time.Second),
			ReturnPath: "/platform?from=login",
		},
		Provider: callback.Pins.Provider, UserID: directTestEntityID(72),
		ExternalIdentityID: directTestEntityID(73), ProviderRevision: callback.Pins.ProviderRevision,
		PlatformLoginRevision: callback.Pins.PlatformLoginRevision,
		ConfigurationRevision: callback.Pins.ConfigurationRevision,
		SecurityRevision:      callback.Pins.SecurityRevision, PlanRevision: pins.PlanRevision,
		AssurancePolicyRevision:    callback.Pins.AssurancePolicyRevision,
		UserAuthenticationRevision: 20, IdentityRevision: 21,
		MatchedAliasKeyVersion: 2,
		Subject: DirectSubjectObservation{
			ExternalIdentityID: directTestEntityID(73), SubjectFormat: identity.UTF8ExactSubject,
			Aliases: []identity.SubjectAlias{{KeyVersion: 2, Digest: aliasDigest}},
			Envelope: identity.ExternalSubjectEnvelope{
				KeyVersion: 2, Format: identity.UTF8ExactSubject,
				Ciphertext: bytes.Repeat([]byte{0xa5}, 32),
			},
		},
		Evidence: []identity.AssuranceEvidence{{
			Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
			Source: identity.AssuranceSource{
				DirectPlatform: true, ProviderID: callback.Pins.Provider.ProviderID,
			},
			AuthenticatedAt: authenticatedAt, ExpiresAt: &expiresAt,
			TrustRuleRevision: &securityRevision,
		}},
		SelectedAssurance: DirectSelectedAssurance{
			Level: identity.AssurancePrimary, AuthenticatedAt: authenticatedAt,
		},
		ValidUntil: expiresAt,
		PlatformFloor: identity.EffectiveAssuranceRequirement{
			Level: identity.AssurancePrimary,
			PolicyRevisions: []identity.AssurancePolicyRevision{{
				PolicyID: pins.PlatformFloorPolicyID, Revision: int64(pins.PlatformFloorPolicyRevision),
			}},
		},
	}
	if disposition == DirectAuthenticationImmediateSession {
		ruleRevision := int64(29)
		ruleRevisionUnsigned := uint64(29)
		ruleID := directTestEntityID(79)
		plan.Evidence = append(plan.Evidence, identity.AssuranceEvidence{
			Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
			Source: identity.AssuranceSource{
				DirectPlatform: true, ProviderID: callback.Pins.Provider.ProviderID,
			},
			AuthenticatedAt: authenticatedAt, ExpiresAt: &expiresAt,
			TrustRuleRevision: &ruleRevision,
		})
		plan.SelectedAssurance = DirectSelectedAssurance{
			Level: identity.AssuranceMFA, AuthenticatedAt: authenticatedAt,
			TrustRuleID: &ruleID, TrustRuleRevision: &ruleRevisionUnsigned,
		}
		plan.PlatformFloor.Level = identity.AssuranceMFA
	} else {
		plan.PlatformFloor.Level = identity.AssuranceMFA
		plan.PlatformFloor.LocalRequired = true
		plan.TOTP = &DirectTOTPContinuation{FactorID: directTestEntityID(75), Revision: 23}
	}
	return plan
}

func directBrowserApplyResult(request DirectOIDCApplyRequest) DirectOIDCApplyResult {
	result := DirectOIDCApplyResult{
		Disposition:             request.Plan.Disposition,
		TransactionID:           request.Plan.Completion.ID,
		BrowserCapabilityDigest: request.BrowserCapabilityDigest,
		UserID:                  request.Plan.UserID, ReturnPath: request.ReturnPath, AppliedAt: request.AppliedAt,
	}
	if request.Plan.Disposition == DirectAuthenticationImmediateSession {
		result.SessionID = request.Session.SessionID()
	} else {
		result.ContinuationID = request.Continuation.ContinuationID()
	}
	return result
}

func directBrowserCredentialIssuer() federatedauth.ApplyCredentialIssuer {
	var mu sync.Mutex
	sequence := byte(90)
	return directBrowserCredentialIssuerFunc(func(
		request federatedauth.ApplyCredentialRequest,
	) (*federatedauth.ApplyCredentialReservation, error) {
		mu.Lock()
		sequence += 3
		current := sequence
		mu.Unlock()
		switch request.Disposition {
		case federatedauth.ApplySession:
			token := directBrowserOpaqueCredential(current)
			csrf := directBrowserOpaqueCredential(current + 1)
			reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
				SessionID: directTestEntityID(current), FamilyID: directTestEntityID(current + 1),
				TokenDigest: sha256.Sum256(token), CSRFDigest: sha256.Sum256(csrf),
				AuthenticationMethod: mfa.SessionAuthenticationMethod(request.Method),
				IdleExpiresAt:        request.IssuedAt.Add(time.Hour).Truncate(time.Millisecond),
				AbsoluteExpiresAt:    request.IssuedAt.Add(8 * time.Hour).Truncate(time.Millisecond),
			}, request.IssuedAt.Truncate(time.Millisecond))
			if err != nil {
				return nil, err
			}
			return federatedauth.NewSessionApplyCredentialReservation(reservation, token, csrf)
		case federatedauth.ApplyContinuation:
			receipt := directBrowserOpaqueCredential(current)
			continuationID := directTestEntityID(current)
			digest, err := federatedauth.ContinuationReceiptDigest(
				request.ContinuationAuthority, continuationID, receipt,
			)
			if err != nil {
				return nil, err
			}
			reservation, err := federatedauth.NewPostPrimaryContinuationReservation(
				federatedauth.PostPrimaryContinuationMaterial{
					ContinuationID: continuationID, Authority: request.ContinuationAuthority,
					ReceiptDigest: digest, ExpiresAt: request.IssuedAt.Add(5 * time.Minute),
				},
				request.IssuedAt,
			)
			if err != nil {
				return nil, err
			}
			return federatedauth.NewContinuationApplyCredentialReservation(reservation, receipt)
		default:
			return nil, errors.New("invalid test credential disposition")
		}
	})
}

func directBrowserOpaqueCredential(marker byte) []byte {
	return []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{marker}, 32)))
}

func makeTenantBrowserConfiguration(configuration *federatedoidc.AuthorizationConfiguration) {
	configuration.Authority = federatedoidc.TenantCeremonyAuthority
	configuration.Provider.Scope = identity.TenantProviderScope
	configuration.Provider.TenantID = directTestEntityID(83)
	configuration.BindingID = directTestEntityID(84)
	configuration.BindingRevision = 31
	configuration.MappingRevision = 32
	configuration.AuthorizationRevision = 33
	configuration.PlatformLoginRevision = 0
}

func directBrowserJSON(t *testing.T, value any) []byte {
	t.Helper()
	result, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func allZeroDirectBrowserBytes(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func TestDirectOIDCBrowserFormattingRedactsEveryProviderAndAccountOracle(t *testing.T) {
	fixture := newDirectBrowserFixture(t)
	canaries := []string{
		"direct-provider.example.test", "direct-browser-client", "provider_oracle_canary",
		"raw-query-canary", "browser-handle-canary", "capability-canary", "client-secret-canary",
		"platform?from=login", "198.51.100.70", "direct-browser-test/1.0",
	}
	values := []any{
		fixture.application, fixture.configuration, fixture.pins, fixture.lookup,
		fixture.audit,
		DirectOIDCStartAuthority{Lookup: fixture.lookup, ReturnPath: "/platform?from=login", Audit: fixture.audit},
		StartDirectOIDCRequest{
			Lookup: fixture.lookup, ReturnPath: "/platform?from=login",
			PreviousBrowserHandle: []byte("browser-handle-canary"), Audit: fixture.audit,
		},
		CompleteDirectOIDCRequest{
			RawQuery: "raw-query-canary", BrowserHandle: []byte("browser-handle-canary"),
			BrowserCapability: []byte("capability-canary"), Audit: fixture.audit,
		},
		fixture.plan,
	}
	for _, value := range values {
		for _, rendered := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value)} {
			for _, canary := range canaries {
				if strings.Contains(rendered, canary) {
					t.Fatalf("format leaked %q from %T: %s", canary, value, rendered)
				}
			}
		}
	}
}
