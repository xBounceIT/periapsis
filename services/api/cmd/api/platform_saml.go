package main

import (
	"errors"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/httpserver"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamladapter"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

const (
	directPlatformSAMLRecoveryTimeout = 2 * time.Second
	directPlatformSAMLAbortTimeout    = 2 * time.Second
)

// directPlatformSAMLRuntimeRepository is the complete private persistence
// authority required by direct-platform SAML. The public metadata projection
// and schema readiness stay on a separate capability below so an anonymous
// route can never acquire transaction, subject, factor, or key-envelope access.
type directPlatformSAMLRuntimeRepository interface {
	platformsamladapter.DirectSAMLTransactionPersistence
	platformsamladapter.DirectSAMLSPKeyEnvelopeRepository
	platformsamlauth.StartSource
	platformsamlauth.ConfigurationSource
	platformsamlauth.PlanningStateSource
	platformsamlauth.AtomicApplyPort
	platformsamlauth.DirectSAMLTOTPStore
	platformsamlauth.DirectSAMLSessionRevalidationStore
}

type directPlatformSAMLPublicRepository interface {
	httpserver.PlatformSAMLMetadataSource
	httpserver.PlatformSAMLReadiness
}

type directPlatformSAMLRuntimeOptions struct {
	Repository       directPlatformSAMLRuntimeRepository
	PublicRepository directPlatformSAMLPublicRepository
	SessionProtector federatedsaml.SessionMaterialProtector
	IdentityKeyring  identity.Keyring
	StartKey         []byte
	Credentials      platformsamlauth.CredentialIssuer
	TOTPVerifier     platformsamlauth.DirectSAMLTOTPVerifier
	OperationTimeout time.Duration
	TransactionTTL   time.Duration
	ChallengeTTL     time.Duration
	Now              func() time.Time
}

type directPlatformSAMLRuntime struct {
	browser          *httpserver.RuntimePlatformSAMLBrowserAuthentication
	continuation     *httpserver.RuntimePlatformSAMLContinuation
	sessionAuthority *platformsamlauth.DirectSAMLSessionAuthorityService
	logoutFlow       *platformsamladapter.ProtocolAdapter
}

// newDirectPlatformSAMLRuntime composes the physically separate SAML graph as
// one all-or-nothing capability. It shares only the deployment keyring,
// session-material protector, authentication-owned credential issuer, and
// timeout policy with the other federation families.
func newDirectPlatformSAMLRuntime(
	options directPlatformSAMLRuntimeOptions,
) (directPlatformSAMLRuntime, error) {
	if runtimeDependencyIsNil(options.Repository) || runtimeDependencyIsNil(options.PublicRepository) ||
		runtimeDependencyIsNil(options.SessionProtector) || runtimeDependencyIsNil(options.Credentials) ||
		runtimeDependencyIsNil(options.TOTPVerifier) || options.IdentityKeyring.ActiveVersion() < 1 ||
		options.Now == nil || options.OperationTimeout <= 0 || options.TransactionTTL <= 0 ||
		options.ChallengeTTL <= 0 {
		return directPlatformSAMLRuntime{}, errors.New("direct platform SAML runtime dependencies are required")
	}

	keys, err := platformsamladapter.NewProtectedDirectSAMLSPKeySource(
		platformsamladapter.ProtectedDirectSAMLSPKeySourceOptions{
			Repository: options.Repository, Keyring: options.IdentityKeyring, Now: options.Now,
		},
	)
	if err != nil {
		return directPlatformSAMLRuntime{}, errors.New("initialize direct platform SAML key source")
	}
	protocol, err := platformsamladapter.NewProtocolAdapter(platformsamladapter.ProtocolAdapterOptions{
		Persistence: options.Repository, Keys: keys, SessionProtector: options.SessionProtector,
		Limits: federatedsaml.DefaultLimits(), TransactionTTL: options.TransactionTTL,
		OperationTimeout: options.OperationTimeout, RecoveryTimeout: directPlatformSAMLRecoveryTimeout,
		AbortTimeout: directPlatformSAMLAbortTimeout, Now: options.Now,
	})
	if err != nil {
		return directPlatformSAMLRuntime{}, errors.New("initialize direct platform SAML protocol adapter")
	}
	planner, err := platformsamlauth.NewPlanner(platformsamlauth.PlannerOptions{
		Source: options.Repository, Keyring: options.IdentityKeyring,
	})
	if err != nil {
		return directPlatformSAMLRuntime{}, errors.New("initialize direct platform SAML planner")
	}
	application, err := platformsamlauth.NewApplication(platformsamlauth.ApplicationOptions{
		Protocol: protocol, Starts: options.Repository, Configurations: options.Repository,
		Planner: planner, Credentials: options.Credentials, Apply: options.Repository,
		Keyring: options.IdentityKeyring, Now: options.Now, OperationTimeout: options.OperationTimeout,
		RecoveryTimeout: directPlatformSAMLRecoveryTimeout,
	})
	if err != nil {
		return directPlatformSAMLRuntime{}, errors.New("initialize direct platform SAML application")
	}
	digester, err := platformsamlauth.NewStartDigester(options.StartKey)
	if err != nil {
		return directPlatformSAMLRuntime{}, errors.New("initialize direct platform SAML start protection")
	}
	transport, err := platformsamladapter.NewBrowserTransport(
		platformsamladapter.BrowserTransportPolicy{
			TransactionCookieName: platformsamladapter.DirectSAMLProductionTransactionCookie,
			ContinuationPath:      httpserver.FederatedContinuationPath,
		},
		options.Now,
	)
	if err != nil {
		return directPlatformSAMLRuntime{}, errors.New("initialize direct platform SAML browser transport")
	}
	browser, err := httpserver.NewRuntimePlatformSAMLBrowserAuthentication(
		httpserver.RuntimePlatformSAMLBrowserAuthenticationOptions{
			Application: application, Digester: digester, Metadata: options.PublicRepository,
			Readiness: options.PublicRepository, Transport: transport,
		},
	)
	if err != nil {
		return directPlatformSAMLRuntime{}, errors.New("initialize direct platform SAML HTTP runtime")
	}
	totp, err := platformsamlauth.NewDirectSAMLTOTPApplication(
		platformsamlauth.DirectSAMLTOTPApplicationOptions{
			Store: options.Repository, Verifier: options.TOTPVerifier, Credentials: options.Credentials,
			Now: options.Now, ChallengeTTL: options.ChallengeTTL, OperationTimeout: options.OperationTimeout,
			RecoveryTimeout: directPlatformSAMLRecoveryTimeout,
		},
	)
	if err != nil {
		return directPlatformSAMLRuntime{}, errors.New("initialize direct platform SAML TOTP application")
	}
	continuation, err := httpserver.NewRuntimePlatformSAMLContinuation(
		httpserver.RuntimePlatformSAMLContinuationOptions{TOTP: totp, Readiness: options.PublicRepository},
	)
	if err != nil {
		return directPlatformSAMLRuntime{}, errors.New("initialize direct platform SAML continuation runtime")
	}
	sessionAuthority, err := platformsamlauth.NewDirectSAMLSessionAuthority(
		platformsamlauth.DirectSAMLSessionAuthorityOptions{
			Store: options.Repository, Credentials: options.Credentials, Now: options.Now,
			OperationTimeout: options.OperationTimeout, RecoveryTimeout: directPlatformSAMLRecoveryTimeout,
		},
	)
	if err != nil {
		return directPlatformSAMLRuntime{}, errors.New("initialize direct platform SAML session authority")
	}
	return directPlatformSAMLRuntime{
		browser: browser, continuation: continuation, sessionAuthority: sessionAuthority, logoutFlow: protocol,
	}, nil
}
