package federatedauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

type tenantSAMLConfigurationSourceFake struct {
	configuration TenantSAMLConfiguration
	beginCalls    []SAMLStartLookup
	resolveCalls  []federatedsaml.CallbackConfigurationLookup
	beginErrors   []error
	resolveErrors []error
}

func (source *tenantSAMLConfigurationSourceFake) BeginTenantSAMLLogin(
	_ context.Context,
	lookup SAMLStartLookup,
) (TenantSAMLConfiguration, error) {
	source.beginCalls = append(source.beginCalls, lookup)
	if len(source.beginErrors) != 0 {
		err := source.beginErrors[0]
		source.beginErrors = source.beginErrors[1:]
		return TenantSAMLConfiguration{}, err
	}
	return cloneTenantSAMLConfiguration(source.configuration), nil
}

func (source *tenantSAMLConfigurationSourceFake) ResolveTenantSAMLCallback(
	_ context.Context,
	lookup federatedsaml.CallbackConfigurationLookup,
) (TenantSAMLConfiguration, error) {
	source.resolveCalls = append(source.resolveCalls, lookup)
	if len(source.resolveErrors) != 0 {
		err := source.resolveErrors[0]
		source.resolveErrors = source.resolveErrors[1:]
		return TenantSAMLConfiguration{}, err
	}
	return cloneTenantSAMLConfiguration(source.configuration), nil
}

type samlProtocolFlowFake struct {
	configuration   TenantSAMLConfiguration
	startCalls      int
	validateCalls   int
	startBegin      federatedsaml.AuthenticationBegin
	startReturnPath string
	previousDigest  [sha256.Size]byte
	formDigest      [sha256.Size]byte
	browserDigest   [sha256.Size]byte
	startErr        error
	validateErr     error
}

func (flow *samlProtocolFlowFake) StartAuthentication(
	_ context.Context,
	request federatedsaml.StartRequest,
) (federatedsaml.AuthorizationStart, error) {
	flow.startCalls++
	flow.startBegin = request.Begin
	flow.startReturnPath = request.ReturnPath
	flow.previousDigest = sha256.Sum256(request.PreviousBrowserHandle)
	return federatedsaml.AuthorizationStart{}, flow.startErr
}

func (flow *samlProtocolFlowFake) ValidateCallbackResolved(
	ctx context.Context,
	request federatedsaml.ResolvedCallbackRequest,
	resolver federatedsaml.CallbackConfigurationResolver,
) (*federatedsaml.ValidatedAuthentication, error) {
	flow.validateCalls++
	flow.formDigest = sha256.Sum256(request.RawForm)
	flow.browserDigest = sha256.Sum256(request.BrowserHandle)
	if flow.validateErr != nil {
		return nil, flow.validateErr
	}
	configuration := flow.configuration.Authentication
	var transactionID federatedsaml.TransactionID
	transactionID[0] = 1
	lookup := federatedsaml.CallbackConfigurationLookup{
		TransactionID: transactionID, ExpectedVersion: 1,
		Pins: federatedsaml.TransactionPins{
			Provider: configuration.Provider, BindingID: configuration.BindingID,
			ProviderRevision: configuration.ProviderRevision, BindingRevision: configuration.BindingRevision,
			ConfigurationRevision: configuration.ConfigurationRevision, SecurityRevision: configuration.SecurityRevision,
			MappingRevision: configuration.MappingRevision, AuthorizationRevision: configuration.AuthorizationRevision,
			AssurancePolicyRevision: configuration.AssurancePolicyRevision,
			MetadataRevision:        configuration.Metadata.Revision(), MetadataDigest: configuration.Metadata.Digest(),
			SPKeyRevision: configuration.SPKeyRevision, ConfigurationDigest: sha256.Sum256([]byte("configuration")),
		},
	}
	if _, err := resolver.ResolveSAMLCallbackConfiguration(ctx, lookup); err != nil {
		return nil, err
	}
	return &federatedsaml.ValidatedAuthentication{}, nil
}

func (flow *samlProtocolFlowFake) Consume(
	context.Context,
	*federatedsaml.ValidatedAuthentication,
	federatedsaml.AuthenticationConsumer,
) (federatedsaml.ConsumptionResult, error) {
	return federatedsaml.ConsumptionResult{}, errors.New("not used")
}

type samlAuthenticationApplicationFunc func(
	context.Context,
	SAMLConsumptionFlow,
	TenantSAMLConfiguration,
	*federatedsaml.ValidatedAuthentication,
) (ApplyResult, error)

func (function samlAuthenticationApplicationFunc) ApplySAML(
	ctx context.Context,
	flow SAMLConsumptionFlow,
	configuration TenantSAMLConfiguration,
	validated *federatedsaml.ValidatedAuthentication,
) (ApplyResult, error) {
	return function(ctx, flow, configuration, validated)
}

func TestSAMLLoginStartBindsMeteredReceiptAndRejectsSessionUpgrade(t *testing.T) {
	configuration := samlConfigurationFixture(t, time.Now().UTC().Truncate(time.Microsecond), false)
	source := &tenantSAMLConfigurationSourceFake{
		configuration: configuration, beginErrors: []error{errors.New("lost response")},
	}
	flow := &samlProtocolFlowFake{configuration: configuration}
	login, err := NewSAMLLogin(SAMLLoginOptions{
		Flow: flow,
		Application: samlAuthenticationApplicationFunc(func(
			context.Context, SAMLConsumptionFlow, TenantSAMLConfiguration, *federatedsaml.ValidatedAuthentication,
		) (ApplyResult, error) {
			return ApplyResult{}, errors.New("not used")
		}),
		Configurations: source, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	lookup := validSAMLStartLookupFixture()
	previous := validSAMLBrowserHandleFixture(31)
	if _, err := login.Start(context.Background(), StartTenantSAMLLoginRequest{
		Lookup: lookup, ReturnPath: "/cases", PreviousBrowserHandle: previous,
	}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if len(source.beginCalls) != 2 || source.beginCalls[0] != lookup || source.beginCalls[1] != lookup ||
		flow.startCalls != 1 || flow.startBegin.OperationRunID != lookup.OperationRunID ||
		flow.startBegin.ReceiptDigest != lookup.ReceiptDigest || flow.startReturnPath != "/cases" ||
		flow.previousDigest != sha256.Sum256(previous) {
		t.Fatalf("begin=%v flow=%d request=%v", source.beginCalls, flow.startCalls, flow.startBegin)
	}
	if _, err := login.Start(context.Background(), StartTenantSAMLLoginRequest{
		Lookup: lookup, ReturnPath: "/cases", HasAuthenticatedSession: true,
	}); !errors.Is(err, ErrAuthentication) || len(source.beginCalls) != 2 || flow.startCalls != 1 {
		t.Fatalf("session upgrade error=%v begin=%d start=%d", err, len(source.beginCalls), flow.startCalls)
	}
}

func TestSAMLLoginCompleteDerivesTenantFromResolvedTransaction(t *testing.T) {
	configuration := samlConfigurationFixture(t, time.Now().UTC().Truncate(time.Microsecond), false)
	source := &tenantSAMLConfigurationSourceFake{
		configuration: configuration, resolveErrors: []error{errors.New("lost response")},
	}
	flow := &samlProtocolFlowFake{configuration: configuration}
	applicationCalls := 0
	login, err := NewSAMLLogin(SAMLLoginOptions{
		Flow: flow,
		Application: samlAuthenticationApplicationFunc(func(
			ctx context.Context,
			observedFlow SAMLConsumptionFlow,
			observed TenantSAMLConfiguration,
			validated *federatedsaml.ValidatedAuthentication,
		) (ApplyResult, error) {
			applicationCalls++
			if ctx.Err() != nil || observedFlow != flow || validated == nil ||
				observed.Authentication.Provider != configuration.Authentication.Provider {
				return ApplyResult{}, errors.New("unexpected application input")
			}
			return ApplyResult{
				Category: ApplySuccess, UserID: serviceID(51), SessionID: serviceID(52), ReturnPath: "/cases",
				Credential: testBrowserCredentialForResult(BrowserCredentialSession, serviceID(52)),
			}, nil
		}),
		Configurations: source, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	rawForm := []byte("SAMLResponse=secret&RelayState=secret")
	browser := validSAMLBrowserHandleFixture(47)
	result, err := login.Complete(context.Background(), CompleteTenantSAMLLoginRequest{
		MediaType: "application/x-www-form-urlencoded", RawForm: rawForm, BrowserHandle: browser,
	})
	if err != nil || result.SessionID != serviceID(52) || flow.validateCalls != 1 || applicationCalls != 1 ||
		len(source.resolveCalls) != 2 || source.resolveCalls[0] != source.resolveCalls[1] ||
		flow.formDigest != sha256.Sum256(rawForm) || flow.browserDigest != sha256.Sum256(browser) {
		t.Fatalf("Complete()=%v,%v resolve=%v validate=%d application=%d", result, err, source.resolveCalls, flow.validateCalls, applicationCalls)
	}
}

func TestSAMLLoginRejectsMalformedLookupsAndApplicationProjection(t *testing.T) {
	configuration := samlConfigurationFixture(t, time.Now().UTC().Truncate(time.Microsecond), false)
	valid := validSAMLStartLookupFixture()
	invalid := []SAMLStartLookup{
		{},
		func() SAMLStartLookup { value := valid; value.TenantSlug = "UPPER"; return value }(),
		func() SAMLStartLookup { value := valid; value.LoginKey = "x"; return value }(),
		func() SAMLStartLookup {
			value := valid
			value.AccountDigest = SAMLAccountRateDigest(value.NetworkDigest)
			return value
		}(),
	}
	for _, lookup := range invalid {
		if validSAMLStartLookup(lookup) {
			t.Fatalf("accepted lookup %v", lookup)
		}
	}
	flow := &samlProtocolFlowFake{configuration: configuration}
	source := &tenantSAMLConfigurationSourceFake{configuration: configuration}
	login, err := NewSAMLLogin(SAMLLoginOptions{
		Flow: flow,
		Application: samlAuthenticationApplicationFunc(func(
			context.Context, SAMLConsumptionFlow, TenantSAMLConfiguration, *federatedsaml.ValidatedAuthentication,
		) (ApplyResult, error) {
			return ApplyResult{Category: ApplySuccess, UserID: serviceID(1), ReturnPath: "/cases"}, nil
		}),
		Configurations: source, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := login.Complete(context.Background(), CompleteTenantSAMLLoginRequest{
		MediaType: "application/x-www-form-urlencoded", RawForm: []byte("SAMLResponse=secret&RelayState=secret"),
		BrowserHandle: validSAMLBrowserHandleFixture(2),
	}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("malformed application success error=%v", err)
	}
	resolveCalls, validateCalls := len(source.resolveCalls), flow.validateCalls
	for _, returnPath := range []string{"//attacker.example", `/\attacker.example`, "/%5Cattacker.example", "/%0Aattacker.example"} {
		if _, err := login.Start(context.Background(), StartTenantSAMLLoginRequest{
			Lookup: valid, ReturnPath: returnPath, PreviousBrowserHandle: validSAMLBrowserHandleFixture(3),
		}); !errors.Is(err, ErrAuthentication) || len(source.beginCalls) != 0 || flow.startCalls != 0 {
			t.Fatalf("unsafe return path error=%v begin=%d flow=%d", err, len(source.beginCalls), flow.startCalls)
		}
	}
	if _, err := login.Start(context.Background(), StartTenantSAMLLoginRequest{
		Lookup: valid, ReturnPath: "/cases", PreviousBrowserHandle: []byte("malformed"),
	}); !errors.Is(err, ErrAuthentication) || len(source.beginCalls) != 0 || flow.startCalls != 0 {
		t.Fatalf("unsafe browser error=%v begin=%d flow=%d", err, len(source.beginCalls), flow.startCalls)
	}
	if _, err := login.Complete(context.Background(), CompleteTenantSAMLLoginRequest{
		MediaType: "application/x-www-form-urlencoded", RawForm: make([]byte, federatedsaml.DefaultLimits().MaxEncodedResponseBytes+4*1024+1),
		BrowserHandle: validSAMLBrowserHandleFixture(4),
	}); !errors.Is(err, ErrAuthentication) || len(source.resolveCalls) != resolveCalls || flow.validateCalls != validateCalls {
		t.Fatalf("oversized form error=%v resolve=%d validate=%d", err, len(source.resolveCalls), flow.validateCalls)
	}
}

func TestSAMLLoginFormattingRedactsLocatorAndBrowserArtifacts(t *testing.T) {
	lookup := validSAMLStartLookupFixture()
	values := []string{
		lookup.String(),
		StartTenantSAMLLoginRequest{Lookup: lookup, ReturnPath: "/private", PreviousBrowserHandle: []byte("browser-secret")}.String(),
		CompleteTenantSAMLLoginRequest{MediaType: "application/x-www-form-urlencoded", RawForm: []byte("assertion-secret"), BrowserHandle: []byte("browser-secret")}.String(),
	}
	for _, formatted := range values {
		for _, secret := range []string{"acme", "acme_saml", "/private", "browser-secret", "assertion-secret"} {
			if strings.Contains(formatted, secret) {
				t.Fatalf("format leaked %q: %s", secret, formatted)
			}
		}
	}
}

func FuzzValidSAMLStartLookupRejectsHostileLocators(f *testing.F) {
	f.Add("acme", "acme_saml")
	f.Add("../tenant", "provider\x00key")
	f.Fuzz(func(t *testing.T, tenantSlug, loginKey string) {
		lookup := validSAMLStartLookupFixture()
		lookup.TenantSlug, lookup.LoginKey = tenantSlug, loginKey
		accepted := validSAMLStartLookup(lookup)
		if accepted && (!tenantOIDCSlugPattern.MatchString(tenantSlug) || !tenantOIDCLoginKeyPattern.MatchString(loginKey)) {
			t.Fatalf("accepted hostile locator tenant=%q key=%q", tenantSlug, loginKey)
		}
	})
}

func FuzzValidSAMLBrowserHandleRequiresCanonicalNonzeroEntropy(f *testing.F) {
	f.Add(string(validSAMLBrowserHandleFixture(1)))
	f.Add(strings.Repeat("A", 43))
	f.Add("browser\x00secret")
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 1_024 {
			t.Skip()
		}
		accepted := validSAMLBrowserHandle([]byte(value))
		if accepted && len(value) != 43 {
			t.Fatalf("accepted noncanonical length %d", len(value))
		}
	})
}
