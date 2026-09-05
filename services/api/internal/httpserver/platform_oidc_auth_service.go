package httpserver

import (
	"context"
	"fmt"
	"reflect"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

// PlatformOIDCBrowserStartRequest owns no authority derived from provider
// input. ProviderKey is a public locator; the runtime derives every persisted
// provider and policy pin from it. Receipt and BrowserCapability are
// independently generated one-use secrets and are never logged.
type PlatformOIDCBrowserStartRequest struct {
	OperationRunID          identity.EntityID
	Receipt                 []byte `json:"-"`
	BrowserCapability       []byte `json:"-"`
	ProviderKey             string
	NetworkAddress          string
	ReturnPath              string
	PreviousBrowserHandle   []byte `json:"-"`
	HasAuthenticatedSession bool
	Audit                   platformoidcauth.DirectAuditContext
}

func (request PlatformOIDCBrowserStartRequest) String() string {
	return fmt.Sprintf(
		"httpserver.PlatformOIDCBrowserStartRequest{operation:%t,provider:%t,network:%t,returnPath:%t,previous:%t,authenticated:%t,audit:%q,material:[REDACTED]}",
		request.OperationRunID != (identity.EntityID{}), request.ProviderKey != "",
		request.NetworkAddress != "", request.ReturnPath != "", len(request.PreviousBrowserHandle) != 0,
		request.HasAuthenticatedSession, request.Audit.String(),
	)
}

func (request PlatformOIDCBrowserStartRequest) GoString() string { return request.String() }

// PlatformOIDCBrowserAuthentication is the complete anonymous direct-login
// boundary used by HTTP. It deliberately excludes tenant MFA, recovery,
// enrollment, passkeys, logout, refresh, and any account-linking operation.
type PlatformOIDCBrowserAuthentication interface {
	Ready(context.Context) error
	Start(context.Context, PlatformOIDCBrowserStartRequest) (FederatedBrowserStart, error)
	Complete(context.Context, platformoidcauth.CompleteDirectOIDCRequest) (platformoidcauth.DirectOIDCBrowserOutcome, error)
	StartTOTP(context.Context, platformoidcauth.StartDirectTOTPCommand) (PlatformOIDCTOTPStart, error)
	CompleteTOTP(context.Context, platformoidcauth.CompleteDirectTOTPCommand) (platformoidcauth.DirectTOTPCompletionOutcome, error)
}

// PlatformOIDCTOTPStart is the only direct TOTP material exposed to HTTP.
// BrowserHandle ownership transfers to the handler and must be destroyed after
// the strict MFA ceremony cookie is written.
type PlatformOIDCTOTPStart struct {
	ChallengeID   platformoidcauth.DirectTOTPChallengeID
	BrowserHandle []byte `json:"-"`
	FactorID      identity.EntityID
	ExpiresAt     time.Time
}

func (start PlatformOIDCTOTPStart) String() string {
	return fmt.Sprintf(
		"httpserver.PlatformOIDCTOTPStart{challenge:%t,factor:%t,expires:%t,material:[REDACTED]}",
		start.ChallengeID != (platformoidcauth.DirectTOTPChallengeID{}),
		start.FactorID != (identity.EntityID{}), !start.ExpiresAt.IsZero(),
	)
}

func (start PlatformOIDCTOTPStart) GoString() string { return start.String() }

func (start *PlatformOIDCTOTPStart) Destroy() {
	if start == nil {
		return
	}
	clear(start.BrowserHandle)
	*start = PlatformOIDCTOTPStart{}
}

func platformOIDCBrowserAuthenticationIsNil(service PlatformOIDCBrowserAuthentication) bool {
	if service == nil {
		return true
	}
	value := reflect.ValueOf(service)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

type directOIDCBrowserApplication interface {
	Start(context.Context, platformoidcauth.StartDirectOIDCRequest) (federatedoidc.AuthorizationStart, error)
	Complete(context.Context, platformoidcauth.CompleteDirectOIDCRequest) (platformoidcauth.DirectOIDCBrowserOutcome, error)
}

type directTOTPApplication interface {
	Start(context.Context, platformoidcauth.StartDirectTOTPCommand) (platformoidcauth.DirectTOTPStartArtifact, error)
	Complete(context.Context, platformoidcauth.CompleteDirectTOTPCommand) (platformoidcauth.DirectTOTPCompletionOutcome, error)
}

type PlatformOIDCReadiness interface {
	ReadyDirectPlatformOIDC(context.Context) error
}

type RuntimePlatformOIDCBrowserAuthenticationOptions struct {
	Browser   directOIDCBrowserApplication
	TOTP      directTOTPApplication
	Digester  *platformoidcauth.DirectOIDCStartDigester
	Readiness PlatformOIDCReadiness
}

// RuntimePlatformOIDCBrowserAuthentication keeps the single direct-start
// digester beside the application that consumes its browser-capability digest,
// preventing composition from accidentally mixing tenant or rotated keys.
type RuntimePlatformOIDCBrowserAuthentication struct {
	browser   directOIDCBrowserApplication
	totp      directTOTPApplication
	digester  *platformoidcauth.DirectOIDCStartDigester
	readiness PlatformOIDCReadiness
}

func NewRuntimePlatformOIDCBrowserAuthentication(
	options RuntimePlatformOIDCBrowserAuthenticationOptions,
) (*RuntimePlatformOIDCBrowserAuthentication, error) {
	if options.Browser == nil || options.TOTP == nil || options.Digester == nil || options.Readiness == nil {
		return nil, errFederatedTransportUnavailable
	}
	return &RuntimePlatformOIDCBrowserAuthentication{
		browser: options.Browser, totp: options.TOTP,
		digester: options.Digester, readiness: options.Readiness,
	}, nil
}

func (service *RuntimePlatformOIDCBrowserAuthentication) String() string {
	return fmt.Sprintf(
		"httpserver.RuntimePlatformOIDCBrowserAuthentication{configured:%t}",
		service != nil && service.browser != nil && service.totp != nil &&
			service.digester != nil && service.readiness != nil,
	)
}

func (service *RuntimePlatformOIDCBrowserAuthentication) GoString() string {
	return service.String()
}

func (service *RuntimePlatformOIDCBrowserAuthentication) Ready(ctx context.Context) error {
	if service == nil || service.browser == nil || service.totp == nil ||
		service.digester == nil || service.readiness == nil || ctx == nil || ctx.Err() != nil {
		return errFederatedTransportUnavailable
	}
	if err := service.readiness.ReadyDirectPlatformOIDC(ctx); err != nil {
		return errFederatedTransportUnavailable
	}
	return nil
}

func (service *RuntimePlatformOIDCBrowserAuthentication) Start(
	ctx context.Context,
	request PlatformOIDCBrowserStartRequest,
) (FederatedBrowserStart, error) {
	if err := service.Ready(ctx); err != nil {
		return FederatedBrowserStart{}, err
	}
	receipt := append([]byte(nil), request.Receipt...)
	browserCapability := append([]byte(nil), request.BrowserCapability...)
	previousHandle := append([]byte(nil), request.PreviousBrowserHandle...)
	defer clear(receipt)
	defer clear(browserCapability)
	defer clear(previousHandle)
	lookup, err := service.digester.BuildLookup(
		request.OperationRunID, receipt, browserCapability,
		request.ProviderKey, request.NetworkAddress,
	)
	if err != nil {
		return FederatedBrowserStart{}, platformoidcauth.ErrDirectAuthenticationDenied
	}
	start, err := service.browser.Start(ctx, platformoidcauth.StartDirectOIDCRequest{
		Lookup: lookup, ReturnPath: request.ReturnPath,
		PreviousBrowserHandle:   previousHandle,
		HasAuthenticatedSession: request.HasAuthenticatedSession,
		Audit:                   request.Audit,
	})
	if err != nil {
		return FederatedBrowserStart{}, err
	}
	return FederatedBrowserStart{
		RedirectURL: start.RedirectURL(), BrowserHandle: start.BrowserHandle(), ExpiresAt: start.ExpiresAt(),
	}, nil
}

func (service *RuntimePlatformOIDCBrowserAuthentication) Complete(
	ctx context.Context,
	request platformoidcauth.CompleteDirectOIDCRequest,
) (platformoidcauth.DirectOIDCBrowserOutcome, error) {
	if err := service.Ready(ctx); err != nil {
		return platformoidcauth.DirectOIDCBrowserOutcome{}, err
	}
	return service.browser.Complete(ctx, request)
}

func (service *RuntimePlatformOIDCBrowserAuthentication) StartTOTP(
	ctx context.Context,
	command platformoidcauth.StartDirectTOTPCommand,
) (PlatformOIDCTOTPStart, error) {
	if err := service.Ready(ctx); err != nil {
		return PlatformOIDCTOTPStart{}, err
	}
	artifact, err := service.totp.Start(ctx, command)
	if err != nil {
		artifact.Destroy()
		return PlatformOIDCTOTPStart{}, err
	}
	defer artifact.Destroy()
	return PlatformOIDCTOTPStart{
		ChallengeID: artifact.ChallengeID(), BrowserHandle: artifact.BrowserHandle(),
		FactorID: artifact.FactorID(), ExpiresAt: artifact.ExpiresAt(),
	}, nil
}

func (service *RuntimePlatformOIDCBrowserAuthentication) CompleteTOTP(
	ctx context.Context,
	command platformoidcauth.CompleteDirectTOTPCommand,
) (platformoidcauth.DirectTOTPCompletionOutcome, error) {
	if err := service.Ready(ctx); err != nil {
		return platformoidcauth.DirectTOTPCompletionOutcome{}, err
	}
	return service.totp.Complete(ctx, command)
}

type unavailablePlatformOIDCBrowserAuthentication struct{}

func (unavailablePlatformOIDCBrowserAuthentication) Ready(context.Context) error {
	return errFederatedTransportUnavailable
}
func (unavailablePlatformOIDCBrowserAuthentication) Start(
	context.Context,
	PlatformOIDCBrowserStartRequest,
) (FederatedBrowserStart, error) {
	return FederatedBrowserStart{}, errFederatedTransportUnavailable
}
func (unavailablePlatformOIDCBrowserAuthentication) Complete(
	context.Context,
	platformoidcauth.CompleteDirectOIDCRequest,
) (platformoidcauth.DirectOIDCBrowserOutcome, error) {
	return platformoidcauth.DirectOIDCBrowserOutcome{}, errFederatedTransportUnavailable
}
func (unavailablePlatformOIDCBrowserAuthentication) StartTOTP(
	context.Context,
	platformoidcauth.StartDirectTOTPCommand,
) (PlatformOIDCTOTPStart, error) {
	return PlatformOIDCTOTPStart{}, errFederatedTransportUnavailable
}
func (unavailablePlatformOIDCBrowserAuthentication) CompleteTOTP(
	context.Context,
	platformoidcauth.CompleteDirectTOTPCommand,
) (platformoidcauth.DirectTOTPCompletionOutcome, error) {
	return platformoidcauth.DirectTOTPCompletionOutcome{}, errFederatedTransportUnavailable
}
