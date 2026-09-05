package httpserver

import (
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

const (
	maximumFederatedStartBodyBytes = 4 * 1024
	maximumOIDCCallbackQueryBytes  = 64 * 1024
	maximumSAMLCallbackBodyBytes   = 1024*1024 + 4*1024
	federatedStartReceiptBytes     = 32
)

func (h *Handler) StartTenantOIDCFederatedLogin(
	w http.ResponseWriter,
	r *http.Request,
	tenantSlug contract.FederatedTenantSlug,
	loginKey contract.FederatedLoginKey,
) {
	h.startTenantFederatedLogin(w, r, federatedProtocolOIDC, string(tenantSlug), string(loginKey))
}

func (h *Handler) StartTenantSAMLFederatedLogin(
	w http.ResponseWriter,
	r *http.Request,
	tenantSlug contract.FederatedTenantSlug,
	loginKey contract.FederatedLoginKey,
) {
	h.startTenantFederatedLogin(w, r, federatedProtocolSAML, string(tenantSlug), string(loginKey))
}

func (h *Handler) startTenantFederatedLogin(
	w http.ResponseWriter,
	r *http.Request,
	protocol federatedProtocol,
	tenantSlug string,
	loginKey string,
) {
	prepareFederatedResponse(w)
	if h.rejectFederatedBrowserAuthority(r) != nil || h.requireSameOrigin(r) != nil ||
		r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeFederatedFailure(w, r, false)
		return
	}

	returnPath, err := decodeFederatedStartReturnPath(w, r)
	if err != nil || !validFederatedReturnPath(returnPath) {
		writeFederatedFailure(w, r, false)
		return
	}

	policy, err := h.federatedCookiePolicy(protocol)
	if err != nil {
		writeFederatedFailure(w, r, true)
		return
	}
	previousHandle, err := federatedTransactionHandle(r, policy, false)
	if err != nil {
		clearFederatedTransactionCookie(w, policy)
		writeFederatedFailure(w, r, false)
		return
	}
	defer clear(previousHandle)

	remoteAddress, err := resolveClientAddress(r, h.trustedProxies)
	if err != nil {
		writeFederatedFailure(w, r, false)
		return
	}
	if !h.federatedTransportReady(r) {
		writeFederatedFailure(w, r, true)
		return
	}
	operationID, err := h.federated.newID()
	if err != nil {
		writeFederatedFailure(w, r, true)
		return
	}
	receipt := make([]byte, federatedStartReceiptBytes)
	defer clear(receipt)
	if _, err = io.ReadFull(h.federated.random, receipt); err != nil {
		writeFederatedFailure(w, r, true)
		return
	}

	var start FederatedBrowserStart
	switch protocol {
	case federatedProtocolOIDC:
		lookup, lookupErr := h.federated.oidcDigest.BuildLookup(
			identity.EntityID(operationID), receipt, tenantSlug, loginKey, remoteAddress.String(),
		)
		if lookupErr != nil {
			writeFederatedFailure(w, r, false)
			return
		}
		start, err = h.federated.authentication.StartOIDC(r.Context(), federatedauth.StartTenantOIDCLoginRequest{
			Lookup: lookup, ReturnPath: returnPath, PreviousBrowserHandle: previousHandle,
		})
	case federatedProtocolSAML:
		lookup, lookupErr := h.federated.samlDigest.BuildLookup(
			identity.EntityID(operationID), receipt, tenantSlug, loginKey, remoteAddress.String(),
		)
		if lookupErr != nil {
			writeFederatedFailure(w, r, false)
			return
		}
		start, err = h.federated.authentication.StartSAML(r.Context(), federatedauth.StartTenantSAMLLoginRequest{
			Lookup: lookup, ReturnPath: returnPath, PreviousBrowserHandle: previousHandle,
		})
	default:
		err = errFederatedTransportUnavailable
	}
	defer clear(start.BrowserHandle)
	if err != nil {
		writeFederatedFailure(w, r, errors.Is(err, errFederatedTransportUnavailable))
		return
	}
	handle := append([]byte(nil), start.BrowserHandle...)
	defer clear(handle)
	now := h.federated.now().UTC()
	maximumRedirect := maximumOIDCRedirectBytes
	if protocol == federatedProtocolSAML {
		maximumRedirect = maximumSAMLRedirectBytes
	}
	if !validFederatedIdPRedirect(start.RedirectURL, maximumRedirect) ||
		setFederatedTransactionCookie(w, policy, handle, start.ExpiresAt, now) != nil {
		clearFederatedTransactionCookie(w, policy)
		writeFederatedFailure(w, r, true)
		return
	}
	w.Header().Set("Location", start.RedirectURL)
	w.WriteHeader(http.StatusSeeOther)
}

// decodeFederatedStartReturnPath admits JSON for API clients and native form
// encoding for top-level browser navigation. A fetch cannot reliably expose a
// cross-origin manual redirect, while a same-origin form submission can
// follow the 303 without granting script access to the IdP response.
func decodeFederatedStartReturnPath(w http.ResponseWriter, r *http.Request) (string, error) {
	mediaType, err := requestMediaType(r)
	if err != nil {
		return "", authentication.ErrInvalidInput
	}
	r.Body = http.MaxBytesReader(w, r.Body, maximumFederatedStartBodyBytes)
	switch mediaType {
	case "application/json":
		var body contract.FederatedLoginStartRequest
		if err := decodeJSONBody(r, &body); err != nil {
			return "", authentication.ErrInvalidInput
		}
		return body.ReturnPath, nil
	case "application/x-www-form-urlencoded":
		defer r.Body.Close()
		raw, readErr := io.ReadAll(r.Body)
		if readErr != nil || len(raw) == 0 {
			clear(raw)
			return "", authentication.ErrInvalidInput
		}
		defer clear(raw)
		values, parseErr := url.ParseQuery(string(raw))
		if parseErr != nil || len(values) != 1 {
			return "", authentication.ErrInvalidInput
		}
		returnPaths, exists := values["returnPath"]
		if !exists || len(returnPaths) != 1 {
			return "", authentication.ErrInvalidInput
		}
		return returnPaths[0], nil
	default:
		return "", authentication.ErrInvalidInput
	}
}

func (h *Handler) CompleteOIDCFederatedCallback(w http.ResponseWriter, r *http.Request) {
	prepareFederatedResponse(w)
	policy := h.federated.oidcCookie
	clearFederatedTransactionCookie(w, policy)
	if h.rejectFederatedBrowserAuthority(r) != nil || len(r.URL.RawQuery) > maximumOIDCCallbackQueryBytes ||
		r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		writeFederatedFailure(w, r, false)
		return
	}
	handle, err := federatedTransactionHandle(r, policy, true)
	if err != nil {
		writeFederatedFailure(w, r, false)
		return
	}
	defer clear(handle)
	if !h.federatedTransportReady(r) {
		writeFederatedFailure(w, r, true)
		return
	}
	result, err := h.federated.authentication.CompleteOIDC(r.Context(), federatedauth.CompleteTenantOIDCLoginRequest{
		RawQuery: r.URL.RawQuery, BrowserHandle: handle,
	})
	if err != nil {
		if result.Credential != nil {
			result.Credential.Destroy()
		}
		writeFederatedFailure(w, r, errors.Is(err, errFederatedTransportUnavailable))
		return
	}
	if !h.completeFederatedBrowserCredential(w, r, federatedProtocolOIDC, result) {
		writeFederatedFailure(w, r, false)
	}
}

func (h *Handler) CompleteSAMLFederatedACS(w http.ResponseWriter, r *http.Request) {
	prepareFederatedResponse(w)
	policy := h.federated.samlCookie
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
	if !h.federatedTransportReady(r) {
		writeFederatedFailure(w, r, true)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maximumSAMLCallbackBodyBytes)
	rawForm, err := io.ReadAll(r.Body)
	closeErr := r.Body.Close()
	if err != nil || closeErr != nil || len(rawForm) == 0 {
		clear(rawForm)
		writeFederatedFailure(w, r, false)
		return
	}
	defer clear(rawForm)
	result, err := h.federated.authentication.CompleteSAML(r.Context(), federatedauth.CompleteTenantSAMLLoginRequest{
		MediaType: contentTypes[0], RawForm: rawForm, BrowserHandle: handle,
	})
	if err != nil {
		if result.Credential != nil {
			result.Credential.Destroy()
		}
		writeFederatedFailure(w, r, errors.Is(err, errFederatedTransportUnavailable))
		return
	}
	if !h.completeFederatedBrowserCredential(w, r, federatedProtocolSAML, result) {
		writeFederatedFailure(w, r, false)
	}
}

func (h *Handler) completeFederatedBrowserCredential(
	w http.ResponseWriter,
	r *http.Request,
	protocol federatedProtocol,
	result federatedauth.ApplyResult,
) bool {
	if result.Category != federatedauth.ApplySuccess || result.Credential == nil ||
		!validFederatedEntityID(result.UserID) || !validFederatedReturnPath(result.ReturnPath) {
		if result.Credential != nil {
			result.Credential.Destroy()
		}
		return false
	}
	credential := result.Credential
	defer credential.Destroy()
	material, ok := credential.Consume()
	if !ok {
		return false
	}
	defer material.Destroy()

	switch material.Kind {
	case federatedauth.BrowserCredentialSession:
		return h.completeFederatedSession(w, r, protocol, result, material)
	case federatedauth.BrowserCredentialContinuation:
		return h.completeFederatedContinuation(w, result, material)
	default:
		return false
	}
}

func (h *Handler) completeFederatedSession(
	w http.ResponseWriter,
	r *http.Request,
	protocol federatedProtocol,
	result federatedauth.ApplyResult,
	material federatedauth.BrowserCredentialMaterial,
) bool {
	if !validFederatedEntityID(result.SessionID) || result.SessionID != material.SessionID ||
		result.ContinuationID != (identity.EntityID{}) || material.ContinuationID != (identity.EntityID{}) ||
		material.Authority != federatedauth.ContinuationAuthorityTenant ||
		!material.ExpiresAt.IsZero() || !validMFABrowserHandle(string(material.SessionToken)) ||
		!validMFABrowserHandle(string(material.CSRFToken)) || len(material.Receipt) != 0 {
		return false
	}
	token := string(material.SessionToken)
	credential, err := h.authentication.CurrentSession(r.Context(), token)
	wantMethod := string(federatedauth.AuthenticationMethodOIDC)
	if protocol == federatedProtocolSAML {
		wantMethod = string(federatedauth.AuthenticationMethodSAML)
	} else if protocol == federatedProtocolLDAP || protocol == federatedProtocolPlatformLDAP {
		wantMethod = string(federatedauth.AuthenticationMethodLDAP)
	}
	if err != nil || identity.EntityID(credential.Session.ID) != material.SessionID ||
		identity.EntityID(credential.Session.User.ID) != result.UserID ||
		credential.SessionToken != token || len(credential.CSRFToken) != len(material.CSRFToken) ||
		subtle.ConstantTimeCompare([]byte(credential.CSRFToken), material.CSRFToken) != 1 ||
		credential.Session.AuthenticationMethod != wantMethod ||
		(protocol == federatedProtocolLDAP && credential.Session.ActiveTenantID == nil) ||
		(protocol == federatedProtocolPlatformLDAP && credential.Session.ActiveTenantID != nil) {
		return false
	}
	if _, err = mapSession(credential.Session, credential.CSRFToken); err != nil {
		return false
	}
	h.clearMFACookie(w)
	h.clearFederatedContinuationCookie(w)
	h.setSessionCookie(w, token, credential.Session.AbsoluteExpiresAt)
	w.Header().Set("Location", result.ReturnPath)
	w.WriteHeader(http.StatusSeeOther)
	return true
}

func (h *Handler) completeFederatedContinuation(
	w http.ResponseWriter,
	result federatedauth.ApplyResult,
	material federatedauth.BrowserCredentialMaterial,
) bool {
	now := h.federated.now().UTC()
	if result.SessionID != (identity.EntityID{}) || material.SessionID != (identity.EntityID{}) ||
		!validFederatedEntityID(result.ContinuationID) || result.ContinuationID != material.ContinuationID ||
		material.Authority != federatedauth.ContinuationAuthorityTenant ||
		len(material.SessionToken) != 0 || len(material.CSRFToken) != 0 ||
		!validMFABrowserHandle(string(material.Receipt)) || !validFederatedExpiry(material.ExpiresAt, now) ||
		setFederatedContinuationCookieWithPolicy(
			w, h.federatedContinuationCookie, uuid.UUID(material.ContinuationID), material.Receipt, material.ExpiresAt, now,
		) != nil {
		return false
	}
	w.Header().Set("Location", federatedContinuationPath)
	w.WriteHeader(http.StatusSeeOther)
	return true
}

func (h *Handler) federatedTransportReady(r *http.Request) bool {
	if !h.federated.configured || h.federated.authentication == nil || h.authentication == nil ||
		h.federated.authentication.Ready(r.Context()) != nil {
		return false
	}
	return true
}

func (h *Handler) rejectFederatedBrowserAuthority(r *http.Request) error {
	if err := h.rejectSessionAuthority(r); err != nil || len(r.Header.Values(csrfTokenHeader)) != 0 {
		return authentication.ErrInvalidAuthentication
	}
	for _, cookie := range r.Cookies() {
		if cookie.Name == h.mfaCookie.name || cookie.Name == h.federatedContinuationCookie.name {
			return authentication.ErrInvalidAuthentication
		}
	}
	return nil
}

func (h *Handler) federatedCookiePolicy(protocol federatedProtocol) (federatedTransactionCookiePolicy, error) {
	switch protocol {
	case federatedProtocolOIDC:
		return h.federated.oidcCookie, nil
	case federatedProtocolSAML:
		return h.federated.samlCookie, nil
	default:
		return federatedTransactionCookiePolicy{}, errFederatedTransportUnavailable
	}
}

func prepareFederatedResponse(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func writeFederatedFailure(w http.ResponseWriter, r *http.Request, unavailable bool) {
	prepareFederatedResponse(w)
	if unavailable {
		w.Header().Set("Retry-After", "5")
		writeProblem(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable", "Federated authentication is temporarily unavailable.")
		return
	}
	writeProblem(w, r, http.StatusUnauthorized, "authentication_failed", "Authentication failed", "Federated authentication could not be completed.")
}
