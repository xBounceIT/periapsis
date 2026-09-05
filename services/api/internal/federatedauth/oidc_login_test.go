package federatedauth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

type tenantOIDCConfigurationSourceFake struct {
	configuration TenantOIDCConfiguration
	beginCalls    []OIDCStartLookup
	resolveCalls  []federatedoidc.CallbackConfigurationLookup
	beginErr      error
	beginErrors   []error
	resolveErr    error
	resolveErrors []error
}

func (source *tenantOIDCConfigurationSourceFake) BeginTenantOIDCLogin(
	_ context.Context,
	lookup OIDCStartLookup,
) (TenantOIDCConfiguration, error) {
	source.beginCalls = append(source.beginCalls, lookup)
	if len(source.beginErrors) != 0 {
		err := source.beginErrors[0]
		source.beginErrors = source.beginErrors[1:]
		return source.configuration, err
	}
	return source.configuration, source.beginErr
}

func (source *tenantOIDCConfigurationSourceFake) ResolveTenantOIDCCallback(
	_ context.Context,
	lookup federatedoidc.CallbackConfigurationLookup,
) (TenantOIDCConfiguration, error) {
	source.resolveCalls = append(source.resolveCalls, lookup)
	if len(source.resolveErrors) != 0 {
		err := source.resolveErrors[0]
		source.resolveErrors = source.resolveErrors[1:]
		return source.configuration, err
	}
	return source.configuration, source.resolveErr
}

type oidcProtocolFlowFake struct {
	calls            []string
	startRequest     federatedoidc.StartAuthorizationRequest
	callbackLookup   federatedoidc.CallbackConfigurationLookup
	callbackErr      error
	exchangeErr      error
	verifyErr        error
	buildUserInfoErr error
	mergeErr         error
	capturedSecret   []byte
	aborts           int
	abortErrors      []error
}

func (flow *oidcProtocolFlowFake) StartAuthorization(
	_ context.Context,
	request federatedoidc.StartAuthorizationRequest,
) (federatedoidc.AuthorizationStart, error) {
	flow.calls = append(flow.calls, "start")
	flow.startRequest = request
	flow.startRequest.PreviousBrowserHandle = append([]byte(nil), request.PreviousBrowserHandle...)
	return federatedoidc.AuthorizationStart{}, nil
}

func (flow *oidcProtocolFlowFake) ClaimCallbackResolved(
	ctx context.Context,
	_ federatedoidc.ResolvedCallbackRequest,
	resolver federatedoidc.CallbackConfigurationResolver,
) (*federatedoidc.ClaimedAuthorization, error) {
	flow.calls = append(flow.calls, "claim")
	if flow.callbackErr != nil {
		return nil, flow.callbackErr
	}
	if _, err := resolver.ResolveOIDCCallbackConfiguration(ctx, flow.callbackLookup); err != nil {
		return nil, err
	}
	return &federatedoidc.ClaimedAuthorization{}, nil
}

func (flow *oidcProtocolFlowFake) ExchangeCode(
	_ context.Context,
	_ *federatedoidc.ClaimedAuthorization,
	credential federatedoidc.ClientCredential,
) (*federatedoidc.TokenBundle, error) {
	flow.calls = append(flow.calls, "exchange")
	flow.capturedSecret = credential.Secret
	if flow.exchangeErr != nil {
		return nil, flow.exchangeErr
	}
	return &federatedoidc.TokenBundle{}, nil
}

func (flow *oidcProtocolFlowFake) VerifyIDToken(
	_ context.Context,
	_ *federatedoidc.ClaimedAuthorization,
	_ *federatedoidc.TokenBundle,
	_ federatedoidc.ClaimExtractionPolicy,
) (*federatedoidc.VerifiedAuthentication, error) {
	flow.calls = append(flow.calls, "verify")
	if flow.verifyErr != nil {
		return nil, flow.verifyErr
	}
	return &federatedoidc.VerifiedAuthentication{}, nil
}

func (flow *oidcProtocolFlowFake) BuildUserInfoRequest(
	_ federatedoidc.AuthorizationConfiguration,
	_ *federatedoidc.TokenBundle,
) (*federatedoidc.UserInfoRequest, error) {
	flow.calls = append(flow.calls, "build_userinfo")
	if flow.buildUserInfoErr != nil {
		return nil, flow.buildUserInfoErr
	}
	return &federatedoidc.UserInfoRequest{}, nil
}

func (flow *oidcProtocolFlowFake) MergeUserInfo(
	proof federatedoidc.VerifiedAuthentication,
	_ federatedoidc.UserInfoDocument,
	_ federatedoidc.ClaimExtractionPolicy,
) (federatedoidc.VerifiedAuthentication, error) {
	flow.calls = append(flow.calls, "merge_userinfo")
	return proof, flow.mergeErr
}

func (flow *oidcProtocolFlowFake) TakeSessionMaterial(
	_ federatedoidc.AuthorizationConfiguration,
	bundle *federatedoidc.TokenBundle,
) (*federatedoidc.SessionMaterial, error) {
	flow.calls = append(flow.calls, "take_session_material")
	if bundle != nil {
		bundle.Destroy()
	}
	return nil, nil
}

func (flow *oidcProtocolFlowFake) AbortClaimedAuthorization(
	_ context.Context,
	_ *federatedoidc.ClaimedAuthorization,
) error {
	flow.calls = append(flow.calls, "abort")
	flow.aborts++
	if len(flow.abortErrors) != 0 {
		err := flow.abortErrors[0]
		flow.abortErrors = flow.abortErrors[1:]
		return err
	}
	return nil
}

type oidcAuthenticationApplicationFunc func(
	context.Context,
	identity.EntityID,
	*federatedoidc.VerifiedAuthentication,
) (ApplyResult, error)

func (function oidcAuthenticationApplicationFunc) ApplyOIDC(
	ctx context.Context,
	request OIDCApplicationRequest,
) (ApplyResult, error) {
	return function(ctx, request.TenantID, request.Proof)
}

type oidcUserInfoSourceFunc func(
	context.Context,
	*federatedoidc.UserInfoRequest,
	string,
) (federatedoidc.UserInfoDocument, error)

func (function oidcUserInfoSourceFunc) FetchUserInfo(
	ctx context.Context,
	request *federatedoidc.UserInfoRequest,
	subject string,
) (federatedoidc.UserInfoDocument, error) {
	return function(ctx, request, subject)
}

func TestOIDCLoginStartMetersCanonicalLocatorAndRejectsSessionUpgrade(t *testing.T) {
	configuration := tenantOIDCConfigurationFixture()
	source := &tenantOIDCConfigurationSourceFake{configuration: configuration}
	flow := &oidcProtocolFlowFake{}
	login := newOIDCLoginFixture(t, flow, source, nil, nil)
	lookup := validOIDCStartLookupFixture()
	previous := []byte("previous-browser-canary")
	if _, err := login.Start(context.Background(), StartTenantOIDCLoginRequest{
		Lookup: lookup, ReturnPath: "/cases?mine=true", PreviousBrowserHandle: previous,
	}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	expectedBegin := federatedoidc.AuthorizationBegin{
		OperationRunID: lookup.OperationRunID, ReceiptDigest: lookup.ReceiptDigest,
		NetworkDigest: lookup.NetworkDigest, AccountDigest: lookup.AccountDigest,
		ProviderDigest: lookup.ProviderDigest,
	}
	if len(source.beginCalls) != 1 || source.beginCalls[0] != lookup || !slices.Equal(flow.calls, []string{"start"}) ||
		flow.startRequest.Begin != expectedBegin ||
		flow.startRequest.ReturnPath != "/cases?mine=true" ||
		!slices.Equal(flow.startRequest.PreviousBrowserHandle, previous) {
		t.Fatalf("begin=%v calls=%v request=%s", source.beginCalls, flow.calls, flow.startRequest)
	}

	if _, err := login.Start(context.Background(), StartTenantOIDCLoginRequest{
		Lookup: lookup, ReturnPath: "/", HasAuthenticatedSession: true,
	}); !errors.Is(err, ErrAuthentication) || len(source.beginCalls) != 1 {
		t.Fatalf("authenticated-session start = %v, begin calls=%d", err, len(source.beginCalls))
	}
	malformed := lookup
	malformed.NetworkDigest = OIDCNetworkRateDigest{}
	if _, err := login.Start(context.Background(), StartTenantOIDCLoginRequest{
		Lookup: malformed, ReturnPath: "/",
	}); !errors.Is(err, ErrAuthentication) || len(source.beginCalls) != 1 {
		t.Fatalf("malformed start = %v, begin calls=%d", err, len(source.beginCalls))
	}
	reusedPurpose := lookup
	reusedPurpose.AccountDigest = OIDCAccountRateDigest(reusedPurpose.NetworkDigest)
	if _, err := login.Start(context.Background(), StartTenantOIDCLoginRequest{
		Lookup: reusedPurpose, ReturnPath: "/",
	}); !errors.Is(err, ErrAuthentication) || len(source.beginCalls) != 1 {
		t.Fatalf("purpose-reused start = %v, begin calls=%d", err, len(source.beginCalls))
	}
	invalidReceipt := lookup
	invalidReceipt.ReceiptDigest = OIDCStartReceiptDigest(invalidReceipt.NetworkDigest)
	if _, err := login.Start(context.Background(), StartTenantOIDCLoginRequest{
		Lookup: invalidReceipt, ReturnPath: "/",
	}); !errors.Is(err, ErrAuthentication) || len(source.beginCalls) != 1 {
		t.Fatalf("receipt-reused start = %v, begin calls=%d", err, len(source.beginCalls))
	}
	invalidOperation := lookup
	invalidOperation.OperationRunID[6] = 0x40
	if _, err := login.Start(context.Background(), StartTenantOIDCLoginRequest{
		Lookup: invalidOperation, ReturnPath: "/",
	}); !errors.Is(err, ErrAuthentication) || len(source.beginCalls) != 1 {
		t.Fatalf("non-UUIDv7 start = %v, begin calls=%d", err, len(source.beginCalls))
	}
}

func TestOIDCLoginStartRejectsUnsafeTenantConfigurationBeforeRedirect(t *testing.T) {
	for name, mutate := range map[string]func(*TenantOIDCConfiguration){
		"platform provider without admission": func(value *TenantOIDCConfiguration) {
			value.Authorization.Provider.Scope = identity.PlatformProviderScope
			value.Authorization.Provider.TenantID = identity.EntityID{}
			value.Authorization.BindingID = identity.EntityID{}
		},
		"platform provider with cryptographic binding": func(value *TenantOIDCConfiguration) {
			value.Authorization.Provider.Scope = identity.PlatformProviderScope
			value.Authorization.Provider.TenantID = identity.EntityID{}
			value.Authorization.Admission = identity.TenantAdmissionContext{
				TenantID: serviceID(25), BindingID: serviceID(26),
			}
		},
		"tenant provider with substituted admission": func(value *TenantOIDCConfiguration) {
			value.Authorization.Admission = identity.TenantAdmissionContext{
				TenantID: serviceID(27), BindingID: value.Authorization.BindingID,
			}
		},
		"userinfo without projection": func(value *TenantOIDCConfiguration) {
			value.Authorization.UseUserInfo = true
		},
		"projection without userinfo": func(value *TenantOIDCConfiguration) {
			value.UserInfoClaims = federatedoidc.ClaimExtractionPolicy{
				Profiles: []federatedoidc.ProfileClaimRule{{Claim: "name", Field: federatedoidc.ProfileDisplayName}},
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			configuration := tenantOIDCConfigurationFixture()
			mutate(&configuration)
			source := &tenantOIDCConfigurationSourceFake{configuration: configuration}
			flow := &oidcProtocolFlowFake{}
			login := newOIDCLoginFixture(t, flow, source, nil, nil)
			if _, err := login.Start(context.Background(), StartTenantOIDCLoginRequest{
				Lookup: validOIDCStartLookupFixture(), ReturnPath: "/",
			}); !errors.Is(err, ErrAuthentication) || len(source.beginCalls) != 1 || len(flow.calls) != 0 {
				t.Fatalf("Start() error=%v begin=%d flow=%v", err, len(source.beginCalls), flow.calls)
			}
		})
	}
}

func TestOIDCLoginStartReplaysExactBeginAfterLostResponse(t *testing.T) {
	configuration := tenantOIDCConfigurationFixture()
	source := &tenantOIDCConfigurationSourceFake{
		configuration: configuration,
		beginErrors:   []error{errors.New("commit response lost"), nil},
	}
	flow := &oidcProtocolFlowFake{}
	login := newOIDCLoginFixture(t, flow, source, nil, nil)
	lookup := validOIDCStartLookupFixture()
	if _, err := login.Start(context.Background(), StartTenantOIDCLoginRequest{
		Lookup: lookup, ReturnPath: "/response-loss",
	}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if len(source.beginCalls) != 2 || source.beginCalls[0] != lookup || source.beginCalls[1] != lookup ||
		!slices.Equal(flow.calls, []string{"start"}) {
		t.Fatalf("begin calls=%v flow=%v", source.beginCalls, flow.calls)
	}
}

func TestOIDCLoginCompleteDerivesTenantAndClearsSecretMaterial(t *testing.T) {
	configuration := tenantOIDCConfigurationFixture()
	source := &tenantOIDCConfigurationSourceFake{configuration: configuration}
	flow := &oidcProtocolFlowFake{callbackLookup: federatedoidc.CallbackConfigurationLookup{
		ExpectedVersion: 2,
	}}
	secret := []byte("client-secret-canary")
	applicationCalls := 0
	login := newOIDCLoginFixture(t, flow, source,
		clientSecretSourceFunc(func(_ context.Context, key ClientSecretContext) ([]byte, error) {
			if key.Provider != configuration.Authorization.Provider || key.BindingID != configuration.Authorization.BindingID ||
				key.Admission != (identity.TenantAdmissionContext{}) ||
				key.Revision != configuration.Authorization.ClientSecretRevision {
				t.Fatalf("secret key = %+v", key)
			}
			return secret, nil
		}),
		oidcAuthenticationApplicationFunc(func(
			_ context.Context,
			tenantID identity.EntityID,
			proof *federatedoidc.VerifiedAuthentication,
		) (ApplyResult, error) {
			flow.calls = append(flow.calls, "apply")
			applicationCalls++
			if tenantID != configuration.Authorization.Provider.TenantID || proof == nil {
				t.Fatalf("application tenant/proof = %v, %v", tenantID, proof)
			}
			return ApplyResult{
				Category: ApplySuccess, UserID: serviceID(41), SessionID: serviceID(42),
				Credential: testBrowserCredentialForResult(BrowserCredentialSession, serviceID(42)),
			}, nil
		}),
	)
	result, err := login.Complete(context.Background(), CompleteTenantOIDCLoginRequest{
		RawQuery: "code=redacted&state=redacted", BrowserHandle: []byte("browser-canary"),
	})
	if err != nil || result.Category != ApplySuccess || applicationCalls != 1 ||
		!slices.Equal(flow.calls, []string{"claim", "exchange", "verify", "take_session_material", "apply"}) || len(source.resolveCalls) != 1 {
		t.Fatalf("Complete() = %+v, %v, calls=%v resolves=%d", result, err, flow.calls, len(source.resolveCalls))
	}
	if !allZero(secret) || !allZero(flow.capturedSecret) {
		t.Fatalf("secret material survived: source=%v exchange=%v", secret, flow.capturedSecret)
	}
}

func TestOIDCLoginCompleteUsesAdmissionTenantAndPlatformCryptographicBinding(t *testing.T) {
	configuration := tenantOIDCConfigurationFixture()
	configuration.Authorization.Provider = identity.ProviderContext{
		Scope: identity.PlatformProviderScope, ProviderID: serviceID(60),
	}
	configuration.Authorization.BindingID = identity.EntityID{}
	configuration.Authorization.Admission = identity.TenantAdmissionContext{
		TenantID: serviceID(61), BindingID: serviceID(62),
	}
	source := &tenantOIDCConfigurationSourceFake{configuration: configuration}
	flow := &oidcProtocolFlowFake{callbackLookup: federatedoidc.CallbackConfigurationLookup{ExpectedVersion: 2}}
	var secretContext ClientSecretContext
	var applicationTenant identity.EntityID
	login := newOIDCLoginFixture(t, flow, source,
		clientSecretSourceFunc(func(_ context.Context, context ClientSecretContext) ([]byte, error) {
			secretContext = context
			return []byte("platform-client-secret"), nil
		}),
		oidcAuthenticationApplicationFunc(func(
			_ context.Context,
			tenantID identity.EntityID,
			_ *federatedoidc.VerifiedAuthentication,
		) (ApplyResult, error) {
			applicationTenant = tenantID
			return ApplyResult{
				Category: ApplySuccess, UserID: serviceID(63), SessionID: serviceID(64),
				Credential: testBrowserCredentialForResult(BrowserCredentialSession, serviceID(64)),
			}, nil
		}),
	)
	result, err := login.Complete(context.Background(), CompleteTenantOIDCLoginRequest{
		RawQuery: "code=redacted&state=redacted", BrowserHandle: []byte("browser-canary"),
	})
	if err != nil || result.Category != ApplySuccess || applicationTenant != configuration.Authorization.Admission.TenantID {
		t.Fatalf("Complete()=%+v error=%v applicationTenant=%v", result, err, applicationTenant)
	}
	if secretContext.Provider != configuration.Authorization.Provider ||
		secretContext.Admission != configuration.Authorization.Admission ||
		secretContext.BindingID != (identity.EntityID{}) ||
		secretContext.Revision != configuration.Authorization.ClientSecretRevision {
		t.Fatalf("platform client-secret context = %+v", secretContext)
	}
}

func TestOIDCLoginCompleteReplaysExactConfigurationReadAfterLostResponse(t *testing.T) {
	configuration := tenantOIDCConfigurationFixture()
	source := &tenantOIDCConfigurationSourceFake{
		configuration: configuration,
		resolveErrors: []error{
			errors.New("read response lost"), nil,
		},
	}
	lookup := federatedoidc.CallbackConfigurationLookup{ExpectedVersion: 2}
	flow := &oidcProtocolFlowFake{callbackLookup: lookup}
	login := newOIDCLoginFixture(t, flow, source, nil,
		oidcAuthenticationApplicationFunc(func(
			context.Context, identity.EntityID, *federatedoidc.VerifiedAuthentication,
		) (ApplyResult, error) {
			return ApplyResult{
				Category: ApplySuccess, UserID: serviceID(47), SessionID: serviceID(48),
				Credential: testBrowserCredentialForResult(BrowserCredentialSession, serviceID(48)),
			}, nil
		}),
	)
	if _, err := login.Complete(context.Background(), CompleteTenantOIDCLoginRequest{
		RawQuery: "opaque", BrowserHandle: []byte("opaque"),
	}); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if len(source.resolveCalls) != 2 || source.resolveCalls[0] != lookup || source.resolveCalls[1] != lookup {
		t.Fatalf("resolve calls = %v", source.resolveCalls)
	}
}

func TestOIDCLoginCompleteFailureTerminalizationBoundary(t *testing.T) {
	for name, testCase := range map[string]struct {
		mutate      func(*oidcProtocolFlowFake)
		secretErr   error
		applyErr    error
		expectAbort int
	}{
		"secret load": {secretErr: errors.New("key unavailable"), expectAbort: 1},
		"exchange": {
			mutate: func(flow *oidcProtocolFlowFake) { flow.exchangeErr = errors.New("upstream") }, expectAbort: 1,
		},
		"verification": {
			mutate: func(flow *oidcProtocolFlowFake) { flow.verifyErr = errors.New("invalid token") }, expectAbort: 1,
		},
		"apply": {applyErr: errors.New("stale transaction"), expectAbort: 1},
	} {
		t.Run(name, func(t *testing.T) {
			configuration := tenantOIDCConfigurationFixture()
			source := &tenantOIDCConfigurationSourceFake{configuration: configuration}
			flow := &oidcProtocolFlowFake{}
			if testCase.mutate != nil {
				testCase.mutate(flow)
			}
			login := newOIDCLoginFixture(t, flow, source,
				clientSecretSourceFunc(func(context.Context, ClientSecretContext) ([]byte, error) {
					return []byte("short-lived-secret"), testCase.secretErr
				}),
				oidcAuthenticationApplicationFunc(func(context.Context, identity.EntityID, *federatedoidc.VerifiedAuthentication) (ApplyResult, error) {
					return ApplyResult{}, testCase.applyErr
				}),
			)
			if _, err := login.Complete(context.Background(), CompleteTenantOIDCLoginRequest{
				RawQuery: "opaque", BrowserHandle: []byte("opaque"),
			}); !errors.Is(err, ErrAuthentication) || flow.aborts != testCase.expectAbort {
				t.Fatalf("Complete() error=%v aborts=%d calls=%v", err, flow.aborts, flow.calls)
			}
		})
	}
}

func TestOIDCLoginRejectsMalformedApplicationSuccessAndAborts(t *testing.T) {
	for name, result := range map[string]ApplyResult{
		"non-success category": {Category: ApplyCollision},
		"missing user":         {Category: ApplySuccess, SessionID: serviceID(45)},
		"missing authority":    {Category: ApplySuccess, UserID: serviceID(44)},
		"ambiguous authority": {
			Category: ApplySuccess, UserID: serviceID(44), SessionID: serviceID(45), ContinuationID: serviceID(46),
		},
		"wrong return path": {
			Category: ApplySuccess, UserID: serviceID(44), SessionID: serviceID(45), ReturnPath: "/unexpected",
			Credential: testBrowserCredentialForResult(BrowserCredentialSession, serviceID(45)),
		},
		"credential substitution": {
			Category: ApplySuccess, UserID: serviceID(44), SessionID: serviceID(45),
			Credential: testBrowserCredentialForResult(BrowserCredentialSession, serviceID(46)),
		},
	} {
		t.Run(name, func(t *testing.T) {
			configuration := tenantOIDCConfigurationFixture()
			source := &tenantOIDCConfigurationSourceFake{configuration: configuration}
			flow := &oidcProtocolFlowFake{}
			login := newOIDCLoginFixture(t, flow, source, nil,
				oidcAuthenticationApplicationFunc(func(
					context.Context, identity.EntityID, *federatedoidc.VerifiedAuthentication,
				) (ApplyResult, error) {
					return result, nil
				}),
			)
			if _, err := login.Complete(context.Background(), CompleteTenantOIDCLoginRequest{
				RawQuery: "opaque", BrowserHandle: []byte("opaque"),
			}); !errors.Is(err, ErrAuthentication) || flow.aborts != 1 {
				t.Fatalf("Complete() error=%v aborts=%d result=%s", err, flow.aborts, result)
			}
		})
	}
}

func TestOIDCLoginUserInfoFailureAbortsVerifiedClaim(t *testing.T) {
	configuration := tenantOIDCConfigurationFixture()
	configuration.Authorization.UseUserInfo = true
	configuration.UserInfoClaims = federatedoidc.ClaimExtractionPolicy{
		Profiles: []federatedoidc.ProfileClaimRule{{Claim: "name", Field: federatedoidc.ProfileDisplayName}},
	}
	source := &tenantOIDCConfigurationSourceFake{configuration: configuration}
	flow := &oidcProtocolFlowFake{}
	login := newOIDCLoginFixtureWithUserInfo(t, flow, source,
		clientSecretSourceFunc(func(context.Context, ClientSecretContext) ([]byte, error) {
			return []byte("short-lived-secret"), nil
		}),
		oidcAuthenticationApplicationFunc(func(context.Context, identity.EntityID, *federatedoidc.VerifiedAuthentication) (ApplyResult, error) {
			t.Fatal("application called after UserInfo failure")
			return ApplyResult{}, nil
		}),
		oidcUserInfoSourceFunc(func(context.Context, *federatedoidc.UserInfoRequest, string) (federatedoidc.UserInfoDocument, error) {
			return federatedoidc.UserInfoDocument{}, errors.New("userinfo unavailable")
		}),
	)
	if _, err := login.Complete(context.Background(), CompleteTenantOIDCLoginRequest{
		RawQuery: "opaque", BrowserHandle: []byte("opaque"),
	}); !errors.Is(err, ErrAuthentication) || flow.aborts != 1 ||
		!slices.Equal(flow.calls, []string{"claim", "exchange", "verify", "build_userinfo", "abort"}) {
		t.Fatalf("Complete() error=%v aborts=%d calls=%v", err, flow.aborts, flow.calls)
	}
}

func TestOIDCLoginRetriesExactTerminalAbortAfterLostResponse(t *testing.T) {
	configuration := tenantOIDCConfigurationFixture()
	source := &tenantOIDCConfigurationSourceFake{configuration: configuration}
	flow := &oidcProtocolFlowFake{
		exchangeErr: errors.New("network failure"),
		abortErrors: []error{errors.New("response lost")},
	}
	login := newOIDCLoginFixture(t, flow, source,
		clientSecretSourceFunc(func(context.Context, ClientSecretContext) ([]byte, error) {
			return []byte("client-secret"), nil
		}), nil,
	)
	if _, err := login.Complete(context.Background(), CompleteTenantOIDCLoginRequest{
		RawQuery: "code=opaque&state=opaque", BrowserHandle: []byte("browser"),
	}); !errors.Is(err, ErrAuthentication) || flow.aborts != 2 {
		t.Fatalf("Complete() error=%v aborts=%d calls=%v", err, flow.aborts, flow.calls)
	}
}

func TestOIDCLoginFormattingRedactsPublicAndSecretInputs(t *testing.T) {
	configuration := tenantOIDCConfigurationFixture()
	configuration.Authorization.ClientID = "client-id-canary"
	configuration.Authorization.RedirectURI = "https://redirect-canary.example/callback"
	values := []string{
		configuration.String(),
		validOIDCStartLookupFixture().String(),
		(StartTenantOIDCLoginRequest{
			Lookup: validOIDCStartLookupFixture(), ReturnPath: "/return-path-canary",
			PreviousBrowserHandle: []byte("browser-canary"),
		}).String(),
		(CompleteTenantOIDCLoginRequest{
			RawQuery: "code=code-canary", BrowserHandle: []byte("browser-canary"),
		}).String(),
	}
	for _, formatted := range values {
		for _, canary := range []string{
			"acme-canary", "corp_oidc_canary", "client-id-canary", "redirect-canary",
			"return-path-canary", "browser-canary", "code-canary",
		} {
			if strings.Contains(formatted, canary) {
				t.Fatalf("format leaked %q: %s", canary, formatted)
			}
		}
	}
}

func TestCloneTenantOIDCConfigurationOwnsClaimPolicies(t *testing.T) {
	configuration := tenantOIDCConfigurationFixture()
	configuration.Authorization.ExtraScopes = []string{"profile"}
	configuration.IDTokenClaims = federatedoidc.ClaimExtractionPolicy{
		Scalars:  []federatedoidc.ScalarClaimRule{{Claim: "department"}},
		Profiles: []federatedoidc.ProfileClaimRule{{Claim: "email", Field: federatedoidc.ProfileEmail}},
		Groups:   &federatedoidc.StringArrayClaimRule{Claim: "groups"},
		ACR:      &federatedoidc.ScalarClaimRule{Claim: "acr"},
		AMR:      &federatedoidc.StringArrayClaimRule{Claim: "amr"},
	}
	clone := cloneTenantOIDCConfiguration(configuration)
	configuration.Authorization.ExtraScopes[0] = "mutated"
	configuration.IDTokenClaims.Scalars[0].Claim = "mutated"
	configuration.IDTokenClaims.Profiles[0].Claim = "mutated"
	configuration.IDTokenClaims.Groups.Claim = "mutated"
	configuration.IDTokenClaims.ACR.Claim = "mutated"
	configuration.IDTokenClaims.AMR.Claim = "mutated"
	if clone.Authorization.ExtraScopes[0] != "profile" || clone.IDTokenClaims.Scalars[0].Claim != "department" ||
		clone.IDTokenClaims.Profiles[0].Claim != "email" || clone.IDTokenClaims.Groups.Claim != "groups" ||
		clone.IDTokenClaims.ACR.Claim != "acr" || clone.IDTokenClaims.AMR.Claim != "amr" {
		t.Fatal("cloned OIDC configuration retained mutable source storage")
	}
}

func newOIDCLoginFixture(
	t *testing.T,
	flow *oidcProtocolFlowFake,
	source *tenantOIDCConfigurationSourceFake,
	secrets ClientSecretSource,
	application OIDCAuthenticationApplication,
) *OIDCLogin {
	t.Helper()
	return newOIDCLoginFixtureWithUserInfo(t, flow, source, secrets, application,
		oidcUserInfoSourceFunc(func(context.Context, *federatedoidc.UserInfoRequest, string) (federatedoidc.UserInfoDocument, error) {
			return federatedoidc.UserInfoDocument{}, nil
		}),
	)
}

func newOIDCLoginFixtureWithUserInfo(
	t *testing.T,
	flow *oidcProtocolFlowFake,
	source *tenantOIDCConfigurationSourceFake,
	secrets ClientSecretSource,
	application OIDCAuthenticationApplication,
	userInfo OIDCUserInfoSource,
) *OIDCLogin {
	t.Helper()
	if secrets == nil {
		secrets = clientSecretSourceFunc(func(context.Context, ClientSecretContext) ([]byte, error) {
			return []byte("fixture-secret"), nil
		})
	}
	if application == nil {
		application = oidcAuthenticationApplicationFunc(func(context.Context, identity.EntityID, *federatedoidc.VerifiedAuthentication) (ApplyResult, error) {
			return ApplyResult{Category: ApplySuccess}, nil
		})
	}
	login, err := NewOIDCLogin(OIDCLoginOptions{
		Flow: flow, Application: application, Configurations: source, ClientSecrets: secrets,
		UserInfo: userInfo, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewOIDCLogin() error = %v", err)
	}
	return login
}

func tenantOIDCConfigurationFixture() TenantOIDCConfiguration {
	return TenantOIDCConfiguration{Authorization: federatedoidc.AuthorizationConfiguration{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: serviceID(31), ProviderID: serviceID(32),
		},
		BindingID: serviceID(33), ClientSecretRevision: 7,
	}}
}

func validOIDCStartLookupFixture() OIDCStartLookup {
	lookup := OIDCStartLookup{TenantSlug: "acme-canary", LoginKey: "corp_oidc_canary"}
	lookup.OperationRunID[6] = 0x70
	lookup.OperationRunID[8] = 0x80
	lookup.OperationRunID[15] = 1
	lookup.ReceiptDigest[0] = 4
	lookup.NetworkDigest[0] = 1
	lookup.AccountDigest[0] = 2
	lookup.ProviderDigest[0] = 3
	return lookup
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
