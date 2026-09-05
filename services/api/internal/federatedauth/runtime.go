package federatedauth

import (
	"context"
	"fmt"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

// FederatedRuntimeReadiness proves that every required immutable provider,
// transaction, replay, JIT, session-provenance, keyring, audit, and RLS ABI is
// installed. Production construction requires this port; no in-memory or
// partial fallback is available.
type FederatedRuntimeReadiness interface {
	CheckFederatedAuthenticationReadiness(context.Context) error
}

type RuntimeOptions struct {
	Readiness      FederatedRuntimeReadiness
	Transactions   FederatedTransactionPersistence
	Configurations TenantFederatedConfigurationRecords

	OIDCTrust                 *federatedoidc.Client
	OIDCVerifierProtector     federatedoidc.PKCEVerifierProtector
	OIDCTokenEndpoint         federatedoidc.TokenEndpointPort
	OIDCRedirectURI           string
	OIDCPostLogoutRedirectURI string
	OIDCPolicy                federatedoidc.FlowPolicy
	OIDCApplication           OIDCAuthenticationApplication
	OIDCClientSecrets         ClientSecretSource
	OIDCUserInfo              OIDCUserInfoSource

	SAMLRedirectSigner     federatedsaml.RedirectSigner
	SAMLSignatureVerifier  federatedsaml.XMLSignatureVerifier
	SAMLAssertionDecrypter federatedsaml.AssertionDecrypter
	SAMLSessionProtector   federatedsaml.SessionMaterialProtector
	SAMLApplication        SAMLAuthenticationApplication
	SAMLLimits             federatedsaml.Limits
	SAMLTransactionTTL     time.Duration

	OperationTimeout time.Duration
}

// Runtime is the concrete protocol/application composition below HTTP. It
// does not own cookies, routes, SQL, or deployment configuration; those are
// required composition-root consumers after the persistence ABI is sealed.
type Runtime struct {
	readiness FederatedRuntimeReadiness
	oidc      *OIDCLogin
	saml      *SAMLLogin
	samlFlow  *federatedsaml.Kernel
}

func NewRuntime(options RuntimeOptions) (*Runtime, error) {
	if options.Readiness == nil || options.Transactions == nil || options.Configurations == nil ||
		options.OperationTimeout < minimumOperationTimeout || options.OperationTimeout > maximumOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidOptions
	}
	oidcTransactions, err := NewPersistentOIDCTransactionRepository(options.Transactions)
	if err != nil {
		return nil, ErrInvalidOptions
	}
	samlTransactions, err := NewPersistentSAMLTransactionRepository(options.Transactions)
	if err != nil {
		return nil, ErrInvalidOptions
	}
	configurations, err := NewPinnedTenantConfigurationSource(options.Configurations, options.OIDCTrust)
	if err != nil {
		return nil, ErrInvalidOptions
	}
	oidcFlow, err := federatedoidc.NewFlow(federatedoidc.FlowOptions{
		Trust: options.OIDCTrust, Transactions: oidcTransactions,
		VerifierProtector: options.OIDCVerifierProtector, TokenEndpoint: options.OIDCTokenEndpoint,
		RedirectURI: options.OIDCRedirectURI, PostLogoutRedirectURI: options.OIDCPostLogoutRedirectURI,
		Policy: options.OIDCPolicy,
	})
	if err != nil {
		return nil, ErrInvalidOptions
	}
	oidcLogin, err := NewOIDCLogin(OIDCLoginOptions{
		Flow: oidcFlow, Application: options.OIDCApplication, Configurations: configurations,
		ClientSecrets: options.OIDCClientSecrets, UserInfo: options.OIDCUserInfo,
		OperationTimeout: options.OperationTimeout,
	})
	if err != nil {
		return nil, ErrInvalidOptions
	}
	samlKernel, err := federatedsaml.New(federatedsaml.Options{
		Transactions: samlTransactions, RedirectSigner: options.SAMLRedirectSigner,
		SignatureVerifier: options.SAMLSignatureVerifier, AssertionDecrypter: options.SAMLAssertionDecrypter,
		SessionProtector: options.SAMLSessionProtector, Limits: options.SAMLLimits,
		TransactionTTL: options.SAMLTransactionTTL, OperationTimeout: options.OperationTimeout,
	})
	if err != nil {
		return nil, ErrInvalidOptions
	}
	samlLogin, err := NewSAMLLogin(SAMLLoginOptions{
		Flow: samlKernel, Application: options.SAMLApplication, Configurations: configurations,
		OperationTimeout: options.OperationTimeout,
	})
	if err != nil {
		return nil, ErrInvalidOptions
	}
	return &Runtime{readiness: options.Readiness, oidc: oidcLogin, saml: samlLogin, samlFlow: samlKernel}, nil
}

func (runtime *Runtime) String() string {
	return fmt.Sprintf(
		"federatedauth.Runtime{configured:%t,readiness_required:true}",
		runtime != nil && runtime.readiness != nil && runtime.oidc != nil && runtime.saml != nil,
	)
}
func (runtime *Runtime) GoString() string { return runtime.String() }

func (runtime *Runtime) Ready(ctx context.Context) error {
	if runtime == nil || runtime.readiness == nil || !activeContext(ctx) {
		return ErrFederatedPersistence
	}
	if err := runtime.readiness.CheckFederatedAuthenticationReadiness(ctx); err != nil || ctx.Err() != nil {
		return ErrFederatedPersistence
	}
	return nil
}

func (runtime *Runtime) OIDCLogin() *OIDCLogin {
	if runtime == nil {
		return nil
	}
	return runtime.oidc
}

func (runtime *Runtime) SAMLLogin() *SAMLLogin {
	if runtime == nil {
		return nil
	}
	return runtime.saml
}

// SAMLLogoutFlow returns the same authority-pinned protocol kernel used by
// tenant login. Composition uses it only after local session revocation has
// yielded a stored logout projection.
func (runtime *Runtime) SAMLLogoutFlow() *federatedsaml.Kernel {
	if runtime == nil {
		return nil
	}
	return runtime.samlFlow
}
