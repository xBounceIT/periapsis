package httpserver

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamladapter"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

var (
	publicPlatformProviderKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)
	errPlatformSAMLMetadataNotFound  = errors.New("direct platform SAML metadata not found")
)

type PlatformSAMLBrowserStartRequest struct {
	OperationRunID        identity.EntityID
	Receipt               []byte `json:"-"`
	ProviderKey           string
	NetworkAddress        string
	ReturnPath            string
	PreviousBrowserHandle []byte `json:"-"`
	Audit                 platformsamlauth.AuditContext
}

func (request PlatformSAMLBrowserStartRequest) String() string {
	return fmt.Sprintf(
		"httpserver.PlatformSAMLBrowserStartRequest{operation:%t,provider:%t,network:%t,returnPath:%t,previous:%t,audit:%q,material:[REDACTED]}",
		request.OperationRunID != (identity.EntityID{}), request.ProviderKey != "", request.NetworkAddress != "",
		request.ReturnPath != "", len(request.PreviousBrowserHandle) != 0, request.Audit.String(),
	)
}

func (request PlatformSAMLBrowserStartRequest) GoString() string { return request.String() }

// PlatformSAMLMetadataSource exposes only a public provider-qualified
// projection. found=false uniformly covers unknown, disabled, and otherwise
// unready providers; an error is reserved for infrastructure failure.
type PlatformSAMLMetadataSource interface {
	LoadDirectPlatformSAMLMetadata(
		context.Context,
		string,
	) (platformsamladapter.DirectSAMLMetadataProjection, bool, error)
}

type PlatformSAMLReadiness interface {
	ReadyDirectPlatformSAML(context.Context) error
}

type platformSAMLApplication interface {
	Start(context.Context, platformsamlauth.StartRequest) (platformsamlauth.AuthorizationStart, error)
	Complete(context.Context, platformsamlauth.CompleteRequest) (platformsamlauth.Outcome, error)
}

type platformSAMLStartLookupBuilder interface {
	BuildLookup(identity.EntityID, []byte, string, string) (platformsamlauth.StartLookup, error)
}

type platformSAMLBrowserTransport interface {
	StartRedirect(*platformsamlauth.AuthorizationStart) (platformsamladapter.RedirectResponse, error)
	DeliverApplicationOutcome(
		context.Context,
		*platformsamlauth.Outcome,
		platformsamladapter.BrowserDeliverySink,
	) error
}

// PlatformSAMLBrowserAuthentication is the narrow anonymous HTTP boundary.
// Provider keys are locators only; all authority and exact pins are resolved
// by the application and its persistence ports.
type PlatformSAMLBrowserAuthentication interface {
	Ready(context.Context) error
	Start(context.Context, PlatformSAMLBrowserStartRequest) (platformsamladapter.RedirectResponse, error)
	Complete(
		context.Context,
		platformsamlauth.CompleteRequest,
		platformsamladapter.BrowserDeliverySink,
	) error
	Metadata(context.Context, string) (platformsamladapter.DirectSAMLMetadataDocument, error)
}

type RuntimePlatformSAMLBrowserAuthenticationOptions struct {
	Application platformSAMLApplication
	Digester    platformSAMLStartLookupBuilder
	Metadata    PlatformSAMLMetadataSource
	Readiness   PlatformSAMLReadiness
	Transport   platformSAMLBrowserTransport
}

type RuntimePlatformSAMLBrowserAuthentication struct {
	application platformSAMLApplication
	digester    platformSAMLStartLookupBuilder
	metadata    PlatformSAMLMetadataSource
	readiness   PlatformSAMLReadiness
	transport   platformSAMLBrowserTransport
}

func NewRuntimePlatformSAMLBrowserAuthentication(
	options RuntimePlatformSAMLBrowserAuthenticationOptions,
) (*RuntimePlatformSAMLBrowserAuthentication, error) {
	if interfaceIsNil(options.Application) || interfaceIsNil(options.Digester) ||
		interfaceIsNil(options.Metadata) || interfaceIsNil(options.Readiness) ||
		interfaceIsNil(options.Transport) {
		return nil, errFederatedTransportUnavailable
	}
	return &RuntimePlatformSAMLBrowserAuthentication{
		application: options.Application,
		digester:    options.Digester,
		metadata:    options.Metadata,
		readiness:   options.Readiness,
		transport:   options.Transport,
	}, nil
}

func (service *RuntimePlatformSAMLBrowserAuthentication) String() string {
	return fmt.Sprintf(
		"httpserver.RuntimePlatformSAMLBrowserAuthentication{configured:%t}",
		service != nil && !interfaceIsNil(service.application) && !interfaceIsNil(service.digester) &&
			!interfaceIsNil(service.metadata) && !interfaceIsNil(service.readiness) &&
			!interfaceIsNil(service.transport),
	)
}

func (service *RuntimePlatformSAMLBrowserAuthentication) GoString() string { return service.String() }

func (service *RuntimePlatformSAMLBrowserAuthentication) Ready(ctx context.Context) error {
	if service == nil || interfaceIsNil(service.application) || interfaceIsNil(service.digester) ||
		interfaceIsNil(service.metadata) || interfaceIsNil(service.readiness) ||
		interfaceIsNil(service.transport) || ctx == nil || ctx.Err() != nil {
		return errFederatedTransportUnavailable
	}
	if err := service.readiness.ReadyDirectPlatformSAML(ctx); err != nil {
		return errFederatedTransportUnavailable
	}
	return nil
}

func (service *RuntimePlatformSAMLBrowserAuthentication) Start(
	ctx context.Context,
	request PlatformSAMLBrowserStartRequest,
) (platformsamladapter.RedirectResponse, error) {
	if err := service.Ready(ctx); err != nil {
		return platformsamladapter.RedirectResponse{}, err
	}
	receipt := append([]byte(nil), request.Receipt...)
	previous := append([]byte(nil), request.PreviousBrowserHandle...)
	defer clear(receipt)
	defer clear(previous)
	lookup, err := service.digester.BuildLookup(
		request.OperationRunID,
		receipt,
		request.ProviderKey,
		request.NetworkAddress,
	)
	if err != nil {
		return platformsamladapter.RedirectResponse{}, platformsamlauth.ErrAuthenticationDenied
	}
	start, err := service.application.Start(ctx, platformsamlauth.StartRequest{
		Lookup: lookup, ReturnPath: request.ReturnPath,
		PreviousBrowserHandle: previous, Audit: request.Audit,
	})
	if err != nil {
		start.Destroy()
		return platformsamladapter.RedirectResponse{}, err
	}
	response, err := service.transport.StartRedirect(&start)
	if err != nil {
		response.Destroy()
		return platformsamladapter.RedirectResponse{}, platformsamlauth.ErrAuthenticationUnavailable
	}
	return response, nil
}

func (service *RuntimePlatformSAMLBrowserAuthentication) Complete(
	ctx context.Context,
	request platformsamlauth.CompleteRequest,
	sink platformsamladapter.BrowserDeliverySink,
) error {
	if err := service.Ready(ctx); err != nil || interfaceIsNil(sink) {
		return errFederatedTransportUnavailable
	}
	outcome, err := service.application.Complete(ctx, request)
	if err != nil {
		if outcome.Credential != nil {
			outcome.Credential.Destroy()
		}
		return err
	}
	if err := service.transport.DeliverApplicationOutcome(ctx, &outcome, sink); err != nil {
		if errors.Is(err, platformsamladapter.ErrTransportUnavailable) {
			return platformsamlauth.ErrBrowserDeliveryUnavailable
		}
		return platformsamlauth.ErrBrowserDeliveryRejected
	}
	if outcome.Credential != nil {
		// The transport consumes and destroys the capability on every path.
		// Retaining a non-nil pointer here is harmless, but erasing the local
		// projection prevents accidental reuse by future wrapper code.
		outcome.Credential = nil
	}
	return nil
}

func (service *RuntimePlatformSAMLBrowserAuthentication) Metadata(
	ctx context.Context,
	providerKey string,
) (platformsamladapter.DirectSAMLMetadataDocument, error) {
	if service == nil || interfaceIsNil(service.metadata) || ctx == nil || ctx.Err() != nil ||
		!publicPlatformProviderKeyPattern.MatchString(providerKey) {
		return platformsamladapter.DirectSAMLMetadataDocument{}, errPlatformSAMLMetadataNotFound
	}
	projection, found, err := service.metadata.LoadDirectPlatformSAMLMetadata(ctx, providerKey)
	if err != nil || ctx.Err() != nil {
		return platformsamladapter.DirectSAMLMetadataDocument{}, errFederatedTransportUnavailable
	}
	if !found {
		return platformsamladapter.DirectSAMLMetadataDocument{}, errPlatformSAMLMetadataNotFound
	}
	// The route key is a public locator, but it still has to bind the exact
	// provider projection selected by the repository. Fail closed if a buggy
	// cache/source returns a different provider under the requested key.
	if projection.ProviderKey != providerKey {
		return platformsamladapter.DirectSAMLMetadataDocument{}, errFederatedTransportUnavailable
	}
	document, err := platformsamladapter.BuildDirectSAMLMetadata(projection)
	if err != nil || document.ContentType != platformsamladapter.SAMLMetadataContentType ||
		len(document.Document) == 0 {
		return platformsamladapter.DirectSAMLMetadataDocument{}, errFederatedTransportUnavailable
	}
	return document, nil
}

func platformSAMLBrowserAuthenticationIsNil(service PlatformSAMLBrowserAuthentication) bool {
	return interfaceIsNil(service)
}

func interfaceIsNil(value any) bool {
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

type unavailablePlatformSAMLBrowserAuthentication struct{}

func (unavailablePlatformSAMLBrowserAuthentication) Ready(context.Context) error {
	return errFederatedTransportUnavailable
}

func (unavailablePlatformSAMLBrowserAuthentication) Start(
	context.Context,
	PlatformSAMLBrowserStartRequest,
) (platformsamladapter.RedirectResponse, error) {
	return platformsamladapter.RedirectResponse{}, errFederatedTransportUnavailable
}

func (unavailablePlatformSAMLBrowserAuthentication) Complete(
	context.Context,
	platformsamlauth.CompleteRequest,
	platformsamladapter.BrowserDeliverySink,
) error {
	return errFederatedTransportUnavailable
}

func (unavailablePlatformSAMLBrowserAuthentication) Metadata(
	context.Context,
	string,
) (platformsamladapter.DirectSAMLMetadataDocument, error) {
	return platformsamladapter.DirectSAMLMetadataDocument{}, errFederatedTransportUnavailable
}

type PlatformSAMLStartTOTPCommand struct {
	ContinuationID identity.EntityID
	ReceiptDigest  [32]byte
	Audit          platformsamlauth.AuditContext
}

type PlatformSAMLTOTPStart struct {
	ChallengeID   mfa.ChallengeID
	BrowserHandle []byte `json:"-"`
	FactorID      identity.EntityID
	ExpiresAt     time.Time
}

func (start *PlatformSAMLTOTPStart) Destroy() {
	if start == nil {
		return
	}
	clear(start.BrowserHandle)
	*start = PlatformSAMLTOTPStart{}
}

type PlatformSAMLCompleteTOTPCommand struct {
	ChallengeID    mfa.ChallengeID
	ContinuationID identity.EntityID
	ReceiptDigest  [32]byte
	BrowserHandle  []byte `json:"-"`
	FactorID       identity.EntityID
	Code           []byte `json:"-"`
	Audit          platformsamlauth.AuditContext
}

type PlatformSAMLSessionCredential interface {
	Consume() (platformsamlauth.BrowserCredentialMaterial, bool)
	Destroy()
}

// PlatformSAMLTOTPDeliveryFinalizer owns the exact post-commit cleanup proof.
// A continuation implementation must return one with every successful
// completion so HTTP can revoke the committed session if synchronous browser
// delivery cannot be completed. Implementations must be copy-safe and
// idempotent for one compensation, as the SAML primary delivery authority is.
type PlatformSAMLTOTPDeliveryFinalizer interface {
	ConfirmBrowserDelivery() error
	CompensateBrowserDelivery(context.Context) error
}

type PlatformSAMLTOTPOutcome struct {
	UserID     identity.EntityID
	SessionID  identity.EntityID
	FactorID   identity.EntityID
	Credential PlatformSAMLSessionCredential
	Delivery   PlatformSAMLTOTPDeliveryFinalizer
}

func (outcome *PlatformSAMLTOTPOutcome) Destroy() {
	if outcome == nil {
		return
	}
	if !interfaceIsNil(outcome.Credential) {
		outcome.Credential.Destroy()
	}
	*outcome = PlatformSAMLTOTPOutcome{}
}

type PlatformSAMLContinuationService interface {
	Ready(context.Context) error
	StartTOTP(context.Context, PlatformSAMLStartTOTPCommand) (PlatformSAMLTOTPStart, error)
	CompleteTOTP(context.Context, PlatformSAMLCompleteTOTPCommand) (PlatformSAMLTOTPOutcome, error)
}

func platformSAMLContinuationServiceIsNil(service PlatformSAMLContinuationService) bool {
	return interfaceIsNil(service)
}

type unavailablePlatformSAMLContinuationService struct{}

func (unavailablePlatformSAMLContinuationService) Ready(context.Context) error {
	return errFederatedTransportUnavailable
}

func (unavailablePlatformSAMLContinuationService) StartTOTP(
	context.Context,
	PlatformSAMLStartTOTPCommand,
) (PlatformSAMLTOTPStart, error) {
	return PlatformSAMLTOTPStart{}, errFederatedTransportUnavailable
}

func (unavailablePlatformSAMLContinuationService) CompleteTOTP(
	context.Context,
	PlatformSAMLCompleteTOTPCommand,
) (PlatformSAMLTOTPOutcome, error) {
	return PlatformSAMLTOTPOutcome{}, errFederatedTransportUnavailable
}
