package main

import (
	"errors"
	"reflect"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/httpserver"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

const directPlatformOIDCCallbackPath = "/api/v1/auth/platform/oidc/callback"

// directPlatformOIDCRuntimeRepository is the complete persistence authority
// required by anonymous direct-platform OIDC. Keeping the family as one
// interface makes partial production composition impossible: a repository
// without exact transaction, planning, apply, TOTP, or readiness support
// cannot enable any direct route.
type directPlatformOIDCRuntimeRepository interface {
	platformoidcauth.DirectOIDCTransactionPersistence
	platformoidcauth.DirectOIDCStartSource
	platformoidcauth.DirectOIDCConfigurationSource
	platformoidcauth.DirectOIDCClientSecretEnvelopeSource
	platformoidcauth.DirectPlatformPlanningStateSource
	platformoidcauth.DirectOIDCAtomicApplyPort
	platformoidcauth.DirectTOTPStore
	httpserver.PlatformOIDCReadiness
}

type directPlatformOIDCRuntimeOptions struct {
	Repository        directPlatformOIDCRuntimeRepository
	Trust             *federatedoidc.Client
	VerifierProtector federatedoidc.PKCEVerifierProtector
	TokenEndpoint     federatedoidc.TokenEndpointPort
	IdentityKeyring   identity.Keyring
	StartKey          []byte
	Credentials       federatedauth.ApplyCredentialIssuer
	SessionSealer     federatedauth.OIDCSessionMaterialSealer
	TOTPVerifier      platformoidcauth.DirectTOTPVerifier
	PublicOrigin      string
	Policy            federatedoidc.FlowPolicy
	OperationTimeout  time.Duration
	ChallengeTTL      time.Duration
	Now               func() time.Time
}

// newDirectPlatformOIDCRuntime composes one physically separate direct-login
// graph. It intentionally shares only stateless protocol/network primitives
// with tenant OIDC; persistence, transaction authority, client-secret AAD,
// planning, apply, MFA, cookies, and readiness remain direct-family ports.
func newDirectPlatformOIDCRuntime(
	options directPlatformOIDCRuntimeOptions,
) (*httpserver.RuntimePlatformOIDCBrowserAuthentication, error) {
	if runtimeDependencyIsNil(options.Repository) || options.Trust == nil ||
		runtimeDependencyIsNil(options.VerifierProtector) ||
		runtimeDependencyIsNil(options.TokenEndpoint) ||
		runtimeDependencyIsNil(options.Credentials) ||
		runtimeDependencyIsNil(options.SessionSealer) ||
		runtimeDependencyIsNil(options.TOTPVerifier) ||
		options.PublicOrigin == "" || options.Now == nil || options.OperationTimeout <= 0 ||
		options.ChallengeTTL <= 0 {
		return nil, errors.New("direct platform OIDC runtime dependencies are required")
	}

	digester, err := platformoidcauth.NewDirectOIDCStartDigester(options.StartKey)
	if err != nil {
		return nil, errors.New("initialize direct platform OIDC start protection")
	}
	clientSecrets, err := platformoidcauth.NewKeyringDirectOIDCClientSecretSource(
		options.Repository,
		options.IdentityKeyring,
	)
	if err != nil {
		return nil, errors.New("initialize direct platform OIDC client-secret source")
	}
	planner, err := platformoidcauth.NewDirectAuthenticationPlanner(
		platformoidcauth.DirectAuthenticationPlannerOptions{
			Source: options.Repository, Keyring: options.IdentityKeyring,
		},
	)
	if err != nil {
		return nil, errors.New("initialize direct platform OIDC planner")
	}

	policy := options.Policy
	policy.OperationTimeout = options.OperationTimeout
	transactions, err := platformoidcauth.NewDirectOIDCTransactionAdapter(
		platformoidcauth.DirectOIDCTransactionAdapterOptions{
			Flow: federatedoidc.FlowOptions{
				Trust: options.Trust, VerifierProtector: options.VerifierProtector,
				TokenEndpoint: options.TokenEndpoint,
				RedirectURI:   options.PublicOrigin + directPlatformOIDCCallbackPath,
				Policy:        policy,
			},
			Persistence: options.Repository,
		},
	)
	if err != nil {
		return nil, errors.New("initialize direct platform OIDC transaction runtime")
	}
	browser, err := platformoidcauth.NewDirectOIDCBrowserApplication(
		platformoidcauth.DirectOIDCBrowserApplicationOptions{
			Transactions: transactions, Starts: options.Repository,
			Configurations: options.Repository, ClientSecrets: clientSecrets,
			Trust: planner, Credentials: options.Credentials, Apply: options.Repository,
			SessionSealer: options.SessionSealer,
			Digester:      digester, Now: options.Now, OperationTimeout: options.OperationTimeout,
		},
	)
	if err != nil {
		return nil, errors.New("initialize direct platform OIDC browser application")
	}
	totp, err := platformoidcauth.NewDirectTOTPApplication(
		platformoidcauth.DirectTOTPApplicationOptions{
			Store: options.Repository, Verifier: options.TOTPVerifier,
			Credentials: options.Credentials, Now: options.Now,
			ChallengeTTL: options.ChallengeTTL, OperationTimeout: options.OperationTimeout,
		},
	)
	if err != nil {
		return nil, errors.New("initialize direct platform OIDC TOTP application")
	}
	runtime, err := httpserver.NewRuntimePlatformOIDCBrowserAuthentication(
		httpserver.RuntimePlatformOIDCBrowserAuthenticationOptions{
			Browser: browser, TOTP: totp, Digester: digester, Readiness: options.Repository,
		},
	)
	if err != nil {
		return nil, errors.New("initialize direct platform OIDC HTTP runtime")
	}
	return runtime, nil
}

func runtimeDependencyIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
