package federatedauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

type federatedRuntimeReadinessFunc func(context.Context) error

func (function federatedRuntimeReadinessFunc) CheckFederatedAuthenticationReadiness(ctx context.Context) error {
	return function(ctx)
}

type oidcTokenEndpointFunc func(context.Context, federatedoidc.TokenExchangeRequest) (federatedoidc.TokenEndpointResponse, error)

func (function oidcTokenEndpointFunc) Exchange(
	ctx context.Context,
	request federatedoidc.TokenExchangeRequest,
) (federatedoidc.TokenEndpointResponse, error) {
	return function(ctx, request)
}

func TestRuntimeComposesBothProtocolsAndRequiresLivePersistenceReadiness(t *testing.T) {
	readyCalls := 0
	options := federatedRuntimeOptionsFixture(t)
	options.Readiness = federatedRuntimeReadinessFunc(func(ctx context.Context) error {
		if ctx == nil || ctx.Err() != nil {
			t.Fatal("readiness received an inactive context")
		}
		readyCalls++
		return nil
	})
	runtime, err := NewRuntime(options)
	if err != nil || runtime.OIDCLogin() == nil || runtime.SAMLLogin() == nil || runtime.SAMLLogoutFlow() == nil {
		t.Fatalf("NewRuntime() = %s, %v", runtime, err)
	}
	if err := runtime.Ready(context.Background()); err != nil || readyCalls != 1 {
		t.Fatalf("Ready() = %v, calls=%d", err, readyCalls)
	}
}

func TestRuntimeTenantOIDCStartUsesDeploymentManagedRedirects(t *testing.T) {
	t.Parallel()

	for name, postLogoutRedirectURI := range map[string]string{
		"managed configuration": "https://app.example.test/signed-out",
		"configuration drift":   "https://app.example.test/logout/complete",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options := federatedRuntimeOptionsFixture(t)
			record := tenantOIDCConfigurationRecordFixture(t)
			record.Authorization.RedirectURI = options.OIDCRedirectURI
			record.Authorization.PostLogoutRedirectURI = postLogoutRedirectURI
			now := time.Now().UTC().Truncate(time.Millisecond)
			record.DiscoveryCache.RetrievedAt = now.Add(-time.Minute)
			record.DiscoveryCache.FreshUntil = now.Add(time.Hour)
			record.JWKSCache.RetrievedAt = now.Add(-time.Minute)
			record.JWKSCache.FreshUntil = now.Add(time.Hour)
			options.Configurations = &tenantFederatedConfigurationRecordsFake{oidc: record}

			createCalls := 0
			transactions := completeFederatedTransactionPersistenceFake()
			transactions.createOIDC = func(
				_ context.Context,
				request federatedoidc.CreateTransactionRequest,
			) (OIDCTransactionWriteReceipt, error) {
				createCalls++
				if request.Current.RedirectURI != options.OIDCRedirectURI ||
					request.Current.PostLogoutRedirectURI != options.OIDCPostLogoutRedirectURI {
					t.Fatalf("persisted redirects = %q, %q", request.Current.RedirectURI, request.Current.PostLogoutRedirectURI)
				}
				return OIDCTransactionWriteReceipt{
					TransactionID: request.Current.ID,
					Version:       request.Current.Version,
					State:         federatedoidc.TransactionPending,
				}, nil
			}
			options.Transactions = transactions

			runtime, err := NewRuntime(options)
			if err != nil {
				t.Fatalf("NewRuntime() error = %v", err)
			}
			start, startErr := runtime.OIDCLogin().Start(context.Background(), StartTenantOIDCLoginRequest{
				Lookup: validOIDCStartLookupFixture(), ReturnPath: "/cases?mine=true",
			})
			if name == "managed configuration" {
				if startErr != nil || createCalls != 1 || start.RedirectURL() == "" {
					t.Fatalf("Start() = %s, %v; create calls=%d", start, startErr, createCalls)
				}
				return
			}
			if !errors.Is(startErr, ErrAuthentication) || createCalls != 0 || start.RedirectURL() != "" {
				t.Fatalf("drifted Start() = %s, %v; create calls=%d", start, startErr, createCalls)
			}
		})
	}
}

func TestRuntimeReadinessFailsClosedAndRedactsDependencyErrors(t *testing.T) {
	options := federatedRuntimeOptionsFixture(t)
	options.Readiness = federatedRuntimeReadinessFunc(func(context.Context) error {
		return errors.New("relation tenant_oidc_secret_canary missing")
	})
	runtime, err := NewRuntime(options)
	if err != nil {
		t.Fatal(err)
	}
	if readyErr := runtime.Ready(context.Background()); !errors.Is(readyErr, ErrFederatedPersistence) ||
		strings.Contains(readyErr.Error(), "canary") {
		t.Fatalf("Ready() error = %v", readyErr)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if readyErr := runtime.Ready(cancelled); !errors.Is(readyErr, ErrFederatedPersistence) {
		t.Fatalf("cancelled Ready() error = %v", readyErr)
	}
	lateContext, lateCancel := context.WithCancel(context.Background())
	options.Readiness = federatedRuntimeReadinessFunc(func(context.Context) error {
		lateCancel()
		return nil
	})
	runtime, err = NewRuntime(options)
	if err != nil {
		t.Fatal(err)
	}
	if readyErr := runtime.Ready(lateContext); !errors.Is(readyErr, ErrFederatedPersistence) {
		t.Fatalf("late-cancelled Ready() error = %v", readyErr)
	}
}

func TestRuntimeRejectsEveryMissingProductionBoundary(t *testing.T) {
	for name, mutate := range map[string]func(*RuntimeOptions){
		"readiness":      func(value *RuntimeOptions) { value.Readiness = nil },
		"transactions":   func(value *RuntimeOptions) { value.Transactions = nil },
		"configurations": func(value *RuntimeOptions) { value.Configurations = nil },
		"OIDC trust":     func(value *RuntimeOptions) { value.OIDCTrust = nil },
		"OIDC PKCE":      func(value *RuntimeOptions) { value.OIDCVerifierProtector = nil },
		"OIDC POST":      func(value *RuntimeOptions) { value.OIDCTokenEndpoint = nil },
		"OIDC app":       func(value *RuntimeOptions) { value.OIDCApplication = nil },
		"OIDC secret":    func(value *RuntimeOptions) { value.OIDCClientSecrets = nil },
		"OIDC userinfo":  func(value *RuntimeOptions) { value.OIDCUserInfo = nil },
		"SAML signer":    func(value *RuntimeOptions) { value.SAMLRedirectSigner = nil },
		"SAML verifier":  func(value *RuntimeOptions) { value.SAMLSignatureVerifier = nil },
		"SAML decrypter": func(value *RuntimeOptions) { value.SAMLAssertionDecrypter = nil },
		"SAML session":   func(value *RuntimeOptions) { value.SAMLSessionProtector = nil },
		"SAML app":       func(value *RuntimeOptions) { value.SAMLApplication = nil },
	} {
		t.Run(name, func(t *testing.T) {
			options := federatedRuntimeOptionsFixture(t)
			mutate(&options)
			if runtime, err := NewRuntime(options); !errors.Is(err, ErrInvalidOptions) || runtime != nil {
				t.Fatalf("NewRuntime() = %v, %v", runtime, err)
			}
		})
	}
}

func TestRuntimeFormattingContainsNoEndpointOrSecretMaterial(t *testing.T) {
	options := federatedRuntimeOptionsFixture(t)
	runtime, err := NewRuntime(options)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		output := fmt.Sprintf(format, runtime)
		for _, canary := range []string{"app.example.test", "client-secret", "transaction"} {
			if strings.Contains(output, canary) {
				t.Fatalf("runtime leaked %q with %s: %s", canary, format, output)
			}
		}
	}
}

func federatedRuntimeOptionsFixture(t *testing.T) RuntimeOptions {
	t.Helper()
	transactions := completeFederatedTransactionPersistenceFake()
	records := &tenantFederatedConfigurationRecordsFake{}
	protector, err := NewIdentityPKCEVerifierProtector(oidcSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	return RuntimeOptions{
		Readiness:             federatedRuntimeReadinessFunc(func(context.Context) error { return nil }),
		Transactions:          transactions,
		Configurations:        records,
		OIDCTrust:             newConfigurationOIDCClient(t),
		OIDCVerifierProtector: protector,
		OIDCTokenEndpoint: oidcTokenEndpointFunc(func(
			context.Context,
			federatedoidc.TokenExchangeRequest,
		) (federatedoidc.TokenEndpointResponse, error) {
			return federatedoidc.TokenEndpointResponse{}, errors.New("not invoked")
		}),
		OIDCRedirectURI:           "https://app.example.test/api/v1/auth/federated/oidc/callback",
		OIDCPostLogoutRedirectURI: "https://app.example.test/signed-out",
		OIDCPolicy:                federatedoidc.DefaultFlowPolicy(),
		OIDCApplication: oidcAuthenticationApplicationFunc(func(
			context.Context,
			identity.EntityID,
			*federatedoidc.VerifiedAuthentication,
		) (ApplyResult, error) {
			return ApplyResult{}, errors.New("not invoked")
		}),
		OIDCClientSecrets: clientSecretSourceFunc(func(context.Context, ClientSecretContext) ([]byte, error) {
			return nil, errors.New("not invoked")
		}),
		OIDCUserInfo: oidcUserInfoSourceFunc(func(
			context.Context,
			*federatedoidc.UserInfoRequest,
			string,
		) (federatedoidc.UserInfoDocument, error) {
			return federatedoidc.UserInfoDocument{}, errors.New("not invoked")
		}),
		SAMLRedirectSigner:     samlTestSigner{},
		SAMLSignatureVerifier:  samlTestVerifier{},
		SAMLAssertionDecrypter: samlTestDecrypter{},
		SAMLSessionProtector:   samlTestSessionProtector{},
		SAMLApplication: samlAuthenticationApplicationFunc(func(
			context.Context,
			SAMLConsumptionFlow,
			TenantSAMLConfiguration,
			*federatedsaml.ValidatedAuthentication,
		) (ApplyResult, error) {
			return ApplyResult{}, errors.New("not invoked")
		}),
		SAMLLimits:         federatedsaml.DefaultLimits(),
		SAMLTransactionTTL: 5 * time.Minute,
		OperationTimeout:   time.Second,
	}
}
