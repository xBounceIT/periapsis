package httpserver

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamladapter"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

const (
	maximumPlatformSAMLRelayStateBytes = 80
	platformSAMLStartReceiptBytes      = 32
)

var (
	maximumPlatformSAMLCallbackBodyBytes   = defaultPlatformSAMLCallbackBodyLimit()
	errPlatformSAMLBrowserDeliveryRejected = errors.New("direct platform SAML browser delivery rejected")
)

func defaultPlatformSAMLCallbackBodyLimit() int {
	maximum, err := federatedsaml.MaximumPOSTFormBytes(federatedsaml.DefaultLimits())
	if err != nil {
		// A future incompatible kernel default fails closed instead of silently
		// diverging from the application/parser ceiling.
		return 0
	}
	return maximum
}

// StartPlatformSAMLLogin starts direct platform SAML without accepting an
// authenticated session, bearer token, CSRF token, or continuation as ambient
// authority. The provider key is only a public locator.
func (h *Handler) StartPlatformSAMLLogin(w http.ResponseWriter, r *http.Request, providerKey string) {
	prepareFederatedResponse(w)
	if h.rejectFederatedBrowserAuthority(r) != nil || h.requireSameOrigin(r) != nil ||
		r.URL.RawQuery != "" || r.URL.ForceQuery ||
		!publicPlatformProviderKeyPattern.MatchString(providerKey) {
		writeFederatedFailure(w, r, false)
		return
	}
	returnPath, err := decodeFederatedStartReturnPath(w, r)
	if err != nil || !validFederatedReturnPath(returnPath) {
		writeFederatedFailure(w, r, false)
		return
	}
	policy := h.federated.platformSAMLCookie
	previousHandle, err := federatedTransactionHandle(r, policy, false)
	if err != nil {
		clearFederatedTransactionCookie(w, policy)
		writeFederatedFailure(w, r, false)
		return
	}
	defer clear(previousHandle)
	if !h.platformSAMLBrowserReady(r) {
		writeFederatedFailure(w, r, true)
		return
	}
	audit, err := h.platformSAMLAuditContext(r)
	if err != nil {
		writeFederatedFailure(w, r, false)
		return
	}
	operationID, err := h.federated.newID()
	if err != nil || !validFederatedEntityID(identity.EntityID(operationID)) {
		writeFederatedFailure(w, r, true)
		return
	}
	receipt := make([]byte, platformSAMLStartReceiptBytes)
	defer clear(receipt)
	if _, err = io.ReadFull(h.federated.random, receipt); err != nil ||
		!validPlatformSAMLSecret(receipt) {
		writeFederatedFailure(w, r, true)
		return
	}
	response, err := h.platformSAMLBrowser.Start(r.Context(), PlatformSAMLBrowserStartRequest{
		OperationRunID: identity.EntityID(operationID), Receipt: receipt,
		ProviderKey: providerKey, NetworkAddress: audit.RemoteAddress.String(),
		ReturnPath: returnPath, PreviousBrowserHandle: previousHandle, Audit: audit,
	})
	defer response.Destroy()
	if err != nil {
		writeDirectPlatformSAMLBrowserFailure(w, r, err)
		return
	}
	if !validPlatformSAMLRedirectResponse(response) ||
		setPlatformSAMLCookieDirective(w, response.Cookies[0], policy, h.federated.now().UTC()) != nil {
		clearFederatedTransactionCookie(w, policy)
		writeFederatedFailure(w, r, true)
		return
	}
	w.Header().Set("Location", response.Location)
	w.WriteHeader(http.StatusSeeOther)
}

// CompletePlatformSAMLACS always expires the dedicated transaction cookie
// before inspecting caller-controlled material. The original bounded form is
// passed byte-for-byte to the strict kernel parser.
func (h *Handler) CompletePlatformSAMLACS(w http.ResponseWriter, r *http.Request) {
	prepareFederatedResponse(w)
	policy := h.federated.platformSAMLCookie
	clearFederatedTransactionCookie(w, policy)
	if h.rejectFederatedBrowserAuthority(r) != nil || r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeFederatedFailure(w, r, false)
		return
	}
	handle, err := federatedTransactionHandle(r, policy, true)
	if err != nil {
		writeFederatedFailure(w, r, false)
		return
	}
	defer clear(handle)
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 || len(contentTypes[0]) == 0 || len(contentTypes[0]) > 256 {
		writeFederatedFailure(w, r, false)
		return
	}
	if !h.platformSAMLBrowserReady(r) {
		writeFederatedFailure(w, r, true)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(maximumPlatformSAMLCallbackBodyBytes))
	rawForm, err := io.ReadAll(r.Body)
	closeErr := r.Body.Close()
	if err != nil || closeErr != nil ||
		validatePlatformSAMLPOSTFormEnvelope(contentTypes[0], rawForm) != nil {
		clear(rawForm)
		writeFederatedFailure(w, r, false)
		return
	}
	defer clear(rawForm)
	audit, err := h.platformSAMLAuditContext(r)
	if err != nil {
		writeFederatedFailure(w, r, false)
		return
	}
	sink := &platformSAMLHTTPDeliverySink{handler: h, writer: w, request: r}
	if err := h.platformSAMLBrowser.Complete(r.Context(), platformsamlauth.CompleteRequest{
		MediaType: contentTypes[0], RawForm: rawForm, BrowserHandle: handle, Audit: audit,
	}, sink); err != nil {
		writeDirectPlatformSAMLBrowserFailure(w, r, err)
	}
}

// GetPlatformSAMLMetadata serves only a provider-qualified public projection.
// A valid but unknown, disabled, or unready provider shares one 404 response.
func (h *Handler) GetPlatformSAMLMetadata(w http.ResponseWriter, r *http.Request, providerKey string) {
	prepareFederatedResponse(w)
	if r.URL.RawQuery != "" || r.URL.ForceQuery || requireFederatedMFARequestBodyAbsent(r) != nil ||
		!publicPlatformProviderKeyPattern.MatchString(providerKey) {
		writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The metadata request is invalid.")
		return
	}
	if h == nil || platformSAMLBrowserAuthenticationIsNil(h.platformSAMLBrowser) {
		writePlatformSAMLMetadataUnavailable(w, r)
		return
	}
	document, err := h.platformSAMLBrowser.Metadata(r.Context(), providerKey)
	defer clear(document.Document)
	if errors.Is(err, errPlatformSAMLMetadataNotFound) {
		writeProblem(w, r, http.StatusNotFound, "not_found", "Not found", "SAML metadata is not available.")
		return
	}
	if err != nil || document.ContentType != platformsamladapter.SAMLMetadataContentType ||
		len(document.Document) == 0 {
		writePlatformSAMLMetadataUnavailable(w, r)
		return
	}
	w.Header().Set("Content-Type", document.ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(document.Document)
}

func (h *Handler) platformSAMLBrowserReady(r *http.Request) bool {
	return h != nil && r != nil && h.authentication != nil && h.federated.random != nil &&
		h.federated.newID != nil && h.federated.now != nil &&
		!platformSAMLBrowserAuthenticationIsNil(h.platformSAMLBrowser) &&
		h.platformSAMLBrowser.Ready(r.Context()) == nil
}

func validPlatformSAMLSecret(value []byte) bool {
	if len(value) != platformSAMLStartReceiptBytes {
		return false
	}
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined != 0
}

func validPlatformSAMLRedirectResponse(response platformsamladapter.RedirectResponse) bool {
	return response.StatusCode == http.StatusSeeOther &&
		response.CacheControl == platformsamladapter.CacheControlNoStore &&
		response.ReferrerPolicy == platformsamladapter.ReferrerPolicyNoReferrer &&
		validFederatedIdPRedirect(response.Location, maximumSAMLRedirectBytes) &&
		len(response.Cookies) == 1
}

func setPlatformSAMLCookieDirective(
	w http.ResponseWriter,
	directive platformsamladapter.CookieDirective,
	policy federatedTransactionCookiePolicy,
	now time.Time,
) error {
	if !validFederatedTransactionCookiePolicy(policy) || policy.sameSite != http.SameSiteNoneMode ||
		directive.Name != policy.name || directive.Path != "/" || !directive.Secure ||
		!directive.HTTPOnly || !directive.HostOnly || directive.SameSite != platformsamladapter.SameSiteNone ||
		!validMFABrowserHandle(string(directive.Value)) || directive.MaxAge < 1 ||
		directive.MaxAge > int(maximumFederatedTransactionTTL/time.Second) ||
		!validFederatedExpiry(directive.Expires, now) {
		return errPlatformSAMLBrowserDeliveryRejected
	}
	return setFederatedTransactionCookie(w, policy, directive.Value, directive.Expires, now)
}

func validatePlatformSAMLPOSTFormEnvelope(mediaType string, raw []byte) error {
	typeValue, parameters, err := mime.ParseMediaType(mediaType)
	if err != nil || strings.ToLower(typeValue) != "application/x-www-form-urlencoded" ||
		len(parameters) > 1 {
		return errPlatformSAMLBrowserDeliveryRejected
	}
	charset, present := parameters["charset"]
	if present && !strings.EqualFold(charset, "utf-8") || len(parameters) == 1 && !present ||
		len(raw) == 0 || len(raw) > maximumPlatformSAMLCallbackBodyBytes {
		return errPlatformSAMLBrowserDeliveryRejected
	}
	for _, item := range raw {
		if item < 0x20 || item > 0x7e || item == ';' {
			return errPlatformSAMLBrowserDeliveryRejected
		}
	}
	values := make(map[string]string, 2)
	for _, pair := range strings.Split(string(raw), "&") {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" ||
			parts[0] != "SAMLResponse" && parts[0] != "RelayState" {
			return errPlatformSAMLBrowserDeliveryRejected
		}
		key, keyErr := url.QueryUnescape(parts[0])
		value, valueErr := url.QueryUnescape(parts[1])
		if keyErr != nil || valueErr != nil || key != "SAMLResponse" && key != "RelayState" {
			return errPlatformSAMLBrowserDeliveryRejected
		}
		if _, duplicate := values[key]; duplicate {
			return errPlatformSAMLBrowserDeliveryRejected
		}
		values[key] = value
	}
	response := values["SAMLResponse"]
	relay := values["RelayState"]
	limits := federatedsaml.DefaultLimits()
	if len(values) != 2 || len(response) > limits.MaxEncodedResponseBytes ||
		len(relay) > maximumPlatformSAMLRelayStateBytes || len(relay) != 43 {
		return errPlatformSAMLBrowserDeliveryRejected
	}
	decodedRelay, err := base64.RawURLEncoding.Strict().DecodeString(relay)
	if err != nil || len(decodedRelay) != platformSAMLStartReceiptBytes ||
		base64.RawURLEncoding.EncodeToString(decodedRelay) != relay || !validPlatformSAMLSecret(decodedRelay) {
		clear(decodedRelay)
		return errPlatformSAMLBrowserDeliveryRejected
	}
	clear(decodedRelay)
	decodedResponse, err := base64.StdEncoding.Strict().DecodeString(response)
	if err != nil || len(decodedResponse) == 0 || len(decodedResponse) > limits.MaxDecodedResponseBytes ||
		base64.StdEncoding.EncodeToString(decodedResponse) != response {
		clear(decodedResponse)
		return errPlatformSAMLBrowserDeliveryRejected
	}
	clear(decodedResponse)
	return nil
}

type platformSAMLHTTPDeliverySink struct {
	handler *Handler
	writer  http.ResponseWriter
	request *http.Request
}

func (sink *platformSAMLHTTPDeliverySink) DeliverDirectSAML(
	ctx context.Context,
	delivery *platformsamladapter.BrowserDelivery,
) error {
	if sink == nil || sink.handler == nil || sink.writer == nil || sink.request == nil ||
		ctx == nil || ctx.Err() != nil || delivery == nil ||
		delivery.StatusCode != http.StatusSeeOther ||
		delivery.CacheControl != platformsamladapter.CacheControlNoStore ||
		delivery.ReferrerPolicy != platformsamladapter.ReferrerPolicyNoReferrer ||
		!validFederatedReturnPath(delivery.Location) || !validPlatformSAMLClearDirective(
		delivery.ClearTransaction, sink.handler.federated.platformSAMLCookie,
	) || delivery.CookieSecurity.Path != "/" || !delivery.CookieSecurity.Secure ||
		!delivery.CookieSecurity.HTTPOnly || !delivery.CookieSecurity.HostOnly ||
		delivery.CookieSecurity.SameSite != platformsamladapter.SameSiteStrict {
		return errPlatformSAMLBrowserDeliveryRejected
	}
	switch delivery.Disposition {
	case platformsamlauth.ImmediateSession:
		return sink.deliverSession(delivery)
	case platformsamlauth.TOTPContinuation:
		return sink.deliverContinuation(delivery)
	default:
		return errPlatformSAMLBrowserDeliveryRejected
	}
}

func (sink *platformSAMLHTTPDeliverySink) deliverSession(
	delivery *platformsamladapter.BrowserDelivery,
) error {
	if !validFederatedEntityID(delivery.UserID) || !validFederatedEntityID(delivery.SessionID) ||
		delivery.ContinuationID != (identity.EntityID{}) || !delivery.ExpiresAt.IsZero() ||
		len(delivery.Receipt) != 0 {
		return errPlatformSAMLBrowserDeliveryRejected
	}
	material := platformsamlauth.BrowserCredentialMaterial{
		Kind: platformsamlauth.BrowserSessionCredential, SessionID: delivery.SessionID,
		SessionToken: delivery.SessionToken, CSRFToken: delivery.CSRFToken,
	}
	_, token, expiresAt, ok := sink.handler.resolveDirectPlatformSAMLSession(
		sink.request, delivery.UserID, delivery.SessionID, material,
	)
	if !ok {
		return errPlatformSAMLBrowserDeliveryRejected
	}
	sink.handler.clearMFACookie(sink.writer)
	sink.handler.clearFederatedContinuationCookie(sink.writer)
	sink.handler.setSessionCookie(sink.writer, token, expiresAt)
	sink.writer.Header().Set("Location", delivery.Location)
	sink.writer.WriteHeader(http.StatusSeeOther)
	return nil
}

func (sink *platformSAMLHTTPDeliverySink) deliverContinuation(
	delivery *platformsamladapter.BrowserDelivery,
) error {
	now := sink.handler.federated.now().UTC()
	if !validFederatedEntityID(delivery.UserID) || delivery.SessionID != (identity.EntityID{}) ||
		!validFederatedEntityID(delivery.ContinuationID) || len(delivery.SessionToken) != 0 ||
		len(delivery.CSRFToken) != 0 || !validMFABrowserHandle(string(delivery.Receipt)) ||
		delivery.Location != federatedContinuationPath ||
		!validFederatedExpiry(delivery.ExpiresAt, now) ||
		setFederatedContinuationCookieForAuthorityWithPolicy(
			sink.writer, sink.handler.federatedContinuationCookie,
			federatedauth.ContinuationAuthorityDirectPlatformSAML,
			uuid.UUID(delivery.ContinuationID), delivery.Receipt, delivery.ExpiresAt,
			now,
		) != nil {
		return errPlatformSAMLBrowserDeliveryRejected
	}
	sink.handler.clearMFACookie(sink.writer)
	sink.writer.Header().Set("Location", delivery.Location)
	sink.writer.WriteHeader(http.StatusSeeOther)
	return nil
}

func validPlatformSAMLClearDirective(
	directive platformsamladapter.CookieDirective,
	policy federatedTransactionCookiePolicy,
) bool {
	return validFederatedTransactionCookiePolicy(policy) && policy.sameSite == http.SameSiteNoneMode &&
		directive.Name == policy.name && len(directive.Value) == 0 && directive.Path == "/" &&
		directive.Expires.Equal(time.Unix(1, 0).UTC()) && directive.MaxAge == -1 &&
		directive.Secure && directive.HTTPOnly && directive.HostOnly &&
		directive.SameSite == platformsamladapter.SameSiteNone
}

func writeDirectPlatformSAMLBrowserFailure(w http.ResponseWriter, r *http.Request, err error) {
	writeFederatedFailure(w, r,
		errors.Is(err, errFederatedTransportUnavailable) ||
			errors.Is(err, platformsamlauth.ErrAuthenticationUnavailable) ||
			errors.Is(err, platformsamlauth.ErrBrowserDeliveryUnavailable),
	)
}

func writePlatformSAMLMetadataUnavailable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", "5")
	writeProblem(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable", "SAML metadata is temporarily unavailable.")
}
