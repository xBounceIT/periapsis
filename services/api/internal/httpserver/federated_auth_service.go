package httpserver

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

var errFederatedTransportUnavailable = errors.New("federated browser authentication is unavailable")

// FederatedBrowserStart is the only protocol output the HTTP boundary may
// deliver to a browser. Provider, tenant, and transaction authority remain in
// the protocol kernel and persistence layer. BrowserHandle ownership transfers
// to the caller, which must clear it after constructing the response cookie.
type FederatedBrowserStart struct {
	RedirectURL   string    `json:"-"`
	BrowserHandle []byte    `json:"-"`
	ExpiresAt     time.Time `json:"-"`
}

func (start FederatedBrowserStart) String() string {
	return "httpserver.FederatedBrowserStart{material:[REDACTED]}"
}

func (start FederatedBrowserStart) GoString() string { return start.String() }

// FederatedAuthenticationService is the narrow browser-facing adapter over
// the OIDC and SAML runtime. Complete results retain a one-use credential that
// the handler must consume and destroy before returning.
type FederatedAuthenticationService interface {
	Ready(context.Context) error
	StartOIDC(context.Context, federatedauth.StartTenantOIDCLoginRequest) (FederatedBrowserStart, error)
	CompleteOIDC(context.Context, federatedauth.CompleteTenantOIDCLoginRequest) (federatedauth.ApplyResult, error)
	StartSAML(context.Context, federatedauth.StartTenantSAMLLoginRequest) (FederatedBrowserStart, error)
	CompleteSAML(context.Context, federatedauth.CompleteTenantSAMLLoginRequest) (federatedauth.ApplyResult, error)
}

// RuntimeFederatedAuthentication adapts the fully composed runtime without
// teaching the protocol/application layer about HTTP handlers or cookies.
// The composition root must opt in explicitly; no in-memory fallback exists.
type RuntimeFederatedAuthentication struct {
	runtime *federatedauth.Runtime
}

func NewRuntimeFederatedAuthentication(runtime *federatedauth.Runtime) (*RuntimeFederatedAuthentication, error) {
	if runtime == nil || runtime.OIDCLogin() == nil || runtime.SAMLLogin() == nil {
		return nil, errFederatedTransportUnavailable
	}
	return &RuntimeFederatedAuthentication{runtime: runtime}, nil
}

func (service *RuntimeFederatedAuthentication) Ready(ctx context.Context) error {
	if service == nil || service.runtime == nil {
		return errFederatedTransportUnavailable
	}
	return service.runtime.Ready(ctx)
}

func (service *RuntimeFederatedAuthentication) StartOIDC(
	ctx context.Context,
	request federatedauth.StartTenantOIDCLoginRequest,
) (FederatedBrowserStart, error) {
	if service == nil || service.runtime == nil || service.runtime.OIDCLogin() == nil {
		return FederatedBrowserStart{}, errFederatedTransportUnavailable
	}
	start, err := service.runtime.OIDCLogin().Start(ctx, request)
	if err != nil {
		return FederatedBrowserStart{}, err
	}
	return FederatedBrowserStart{
		RedirectURL: start.RedirectURL(), BrowserHandle: start.BrowserHandle(), ExpiresAt: start.ExpiresAt(),
	}, nil
}

func (service *RuntimeFederatedAuthentication) CompleteOIDC(
	ctx context.Context,
	request federatedauth.CompleteTenantOIDCLoginRequest,
) (federatedauth.ApplyResult, error) {
	if service == nil || service.runtime == nil || service.runtime.OIDCLogin() == nil {
		return federatedauth.ApplyResult{}, errFederatedTransportUnavailable
	}
	return service.runtime.OIDCLogin().Complete(ctx, request)
}

func (service *RuntimeFederatedAuthentication) StartSAML(
	ctx context.Context,
	request federatedauth.StartTenantSAMLLoginRequest,
) (FederatedBrowserStart, error) {
	if service == nil || service.runtime == nil || service.runtime.SAMLLogin() == nil {
		return FederatedBrowserStart{}, errFederatedTransportUnavailable
	}
	start, err := service.runtime.SAMLLogin().Start(ctx, request)
	if err != nil {
		return FederatedBrowserStart{}, err
	}
	return FederatedBrowserStart{
		RedirectURL: start.RedirectURL(), BrowserHandle: start.BrowserHandle(), ExpiresAt: start.ExpiresAt(),
	}, nil
}

func (service *RuntimeFederatedAuthentication) CompleteSAML(
	ctx context.Context,
	request federatedauth.CompleteTenantSAMLLoginRequest,
) (federatedauth.ApplyResult, error) {
	if service == nil || service.runtime == nil || service.runtime.SAMLLogin() == nil {
		return federatedauth.ApplyResult{}, errFederatedTransportUnavailable
	}
	return service.runtime.SAMLLogin().Complete(ctx, request)
}

// FederatedBrowserOptions is intentionally all-or-nothing. Passing nil keeps
// the generated routes present but unavailable until production composition
// supplies the runtime and both purpose-separated public-start digesters.
type FederatedBrowserOptions struct {
	Authentication  FederatedAuthenticationService
	SAMLMetadata    TenantSAMLMetadataService
	OIDCStartDigest *federatedauth.OIDCStartDigester
	SAMLStartDigest *federatedauth.SAMLStartDigester
}

type federatedBrowserTransport struct {
	authentication     FederatedAuthenticationService
	samlMetadata       TenantSAMLMetadataService
	oidcDigest         *federatedauth.OIDCStartDigester
	samlDigest         *federatedauth.SAMLStartDigester
	oidcCookie         federatedTransactionCookiePolicy
	samlCookie         federatedTransactionCookiePolicy
	platformOIDCCookie federatedTransactionCookiePolicy
	platformSAMLCookie federatedTransactionCookiePolicy
	random             io.Reader
	newID              func() (uuid.UUID, error)
	now                func() time.Time
	configured         bool
}

func newFederatedBrowserTransport(
	environment string,
	publicOrigin string,
	options *FederatedBrowserOptions,
) (federatedBrowserTransport, error) {
	oidcCookie, err := newFederatedTransactionCookiePolicy(environment, publicOrigin, federatedProtocolOIDC)
	if err != nil {
		return federatedBrowserTransport{}, err
	}
	samlCookie, err := newFederatedTransactionCookiePolicy(environment, publicOrigin, federatedProtocolSAML)
	if err != nil {
		return federatedBrowserTransport{}, err
	}
	platformOIDCCookie, err := newFederatedTransactionCookiePolicy(
		environment, publicOrigin, federatedProtocolPlatformOIDC,
	)
	if err != nil {
		return federatedBrowserTransport{}, err
	}
	platformSAMLCookie, err := newFederatedTransactionCookiePolicy(
		environment, publicOrigin, federatedProtocolPlatformSAML,
	)
	if err != nil {
		return federatedBrowserTransport{}, err
	}
	transport := federatedBrowserTransport{
		authentication: unavailableFederatedAuthenticationService{},
		samlMetadata:   unavailableTenantSAMLMetadataService{},
		oidcCookie:     oidcCookie, samlCookie: samlCookie,
		platformOIDCCookie: platformOIDCCookie, platformSAMLCookie: platformSAMLCookie,
		random: rand.Reader, newID: uuid.NewV7, now: time.Now,
	}
	if options == nil {
		return transport, nil
	}
	if options.Authentication == nil || options.SAMLMetadata == nil ||
		options.OIDCStartDigest == nil || options.SAMLStartDigest == nil {
		return federatedBrowserTransport{}, errors.New("federated browser authentication requires runtime, SAML metadata, and both start digesters")
	}
	transport.authentication = options.Authentication
	transport.samlMetadata = options.SAMLMetadata
	transport.oidcDigest = options.OIDCStartDigest
	transport.samlDigest = options.SAMLStartDigest
	transport.configured = true
	return transport, nil
}

type unavailableFederatedAuthenticationService struct{}

func (unavailableFederatedAuthenticationService) Ready(context.Context) error {
	return errFederatedTransportUnavailable
}
func (unavailableFederatedAuthenticationService) StartOIDC(
	context.Context,
	federatedauth.StartTenantOIDCLoginRequest,
) (FederatedBrowserStart, error) {
	return FederatedBrowserStart{}, errFederatedTransportUnavailable
}
func (unavailableFederatedAuthenticationService) CompleteOIDC(
	context.Context,
	federatedauth.CompleteTenantOIDCLoginRequest,
) (federatedauth.ApplyResult, error) {
	return federatedauth.ApplyResult{}, errFederatedTransportUnavailable
}
func (unavailableFederatedAuthenticationService) StartSAML(
	context.Context,
	federatedauth.StartTenantSAMLLoginRequest,
) (FederatedBrowserStart, error) {
	return FederatedBrowserStart{}, errFederatedTransportUnavailable
}
func (unavailableFederatedAuthenticationService) CompleteSAML(
	context.Context,
	federatedauth.CompleteTenantSAMLLoginRequest,
) (federatedauth.ApplyResult, error) {
	return federatedauth.ApplyResult{}, errFederatedTransportUnavailable
}
