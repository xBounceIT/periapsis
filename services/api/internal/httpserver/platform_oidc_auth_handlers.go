package httpserver

import (
	"crypto/subtle"
	"errors"
	"io"
	"net/http"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

// StartPlatformOIDCLogin starts only the dormant, separately composed direct
// platform OIDC runtime. The public provider key conveys no authority and the
// browser cookie binds two independent secrets: the protocol transaction
// handle and the application-level direct capability.
func (h *Handler) StartPlatformOIDCLogin(
	w http.ResponseWriter,
	r *http.Request,
	providerKey contract.PlatformOIDCProviderKey,
) {
	prepareFederatedResponse(w)
	if h.rejectFederatedBrowserAuthority(r) != nil || h.requireSameOrigin(r) != nil ||
		r.URL.RawQuery != "" || r.URL.ForceQuery ||
		!publicPlatformProviderKeyPattern.MatchString(string(providerKey)) {
		writeFederatedFailure(w, r, false)
		return
	}
	returnPath, err := decodeFederatedStartReturnPath(w, r)
	if err != nil || !validFederatedReturnPath(returnPath) {
		writeFederatedFailure(w, r, false)
		return
	}
	previousCapability, err := platformOIDCTransactionCookie(
		r, h.federated.platformOIDCCookie, false,
	)
	defer previousCapability.destroy()
	if err != nil {
		clearFederatedTransactionCookie(w, h.federated.platformOIDCCookie)
		writeFederatedFailure(w, r, false)
		return
	}
	if !h.platformOIDCTransportReady(r) {
		writeFederatedFailure(w, r, true)
		return
	}
	audit, err := h.platformOIDCAuditContext(r)
	if err != nil {
		writeFederatedFailure(w, r, false)
		return
	}
	operationID, err := h.federated.newID()
	if err != nil || !validFederatedEntityID(identity.EntityID(operationID)) {
		writeFederatedFailure(w, r, true)
		return
	}
	receipt, browserCapability, err := h.newPlatformOIDCStartSecrets()
	if err != nil {
		writeFederatedFailure(w, r, true)
		return
	}
	defer clear(receipt)
	defer clear(browserCapability)
	previousHandle := previousCapability.transaction()
	defer clear(previousHandle)
	start, err := h.platformOIDCBrowser.Start(r.Context(), PlatformOIDCBrowserStartRequest{
		OperationRunID: identity.EntityID(operationID), Receipt: receipt,
		BrowserCapability: browserCapability, ProviderKey: string(providerKey),
		NetworkAddress: audit.RemoteAddress.String(), ReturnPath: returnPath,
		PreviousBrowserHandle: previousHandle, Audit: audit,
	})
	defer clear(start.BrowserHandle)
	if err != nil {
		writeFederatedFailure(w, r, errors.Is(err, errFederatedTransportUnavailable))
		return
	}
	now := h.federated.now().UTC()
	if !validFederatedIdPRedirect(start.RedirectURL, maximumOIDCRedirectBytes) ||
		setPlatformOIDCTransactionCookie(
			w, h.federated.platformOIDCCookie, start.BrowserHandle,
			browserCapability, start.ExpiresAt, now,
		) != nil {
		clearFederatedTransactionCookie(w, h.federated.platformOIDCCookie)
		writeFederatedFailure(w, r, true)
		return
	}
	w.Header().Set("Location", start.RedirectURL)
	w.WriteHeader(http.StatusSeeOther)
}

// CompletePlatformOIDCCallback always clears the direct transaction cookie.
// Tenant OIDC/SAML browser capabilities are never accepted as substitutes and
// all protocol/application secrets are destroyed before the handler returns.
func (h *Handler) CompletePlatformOIDCCallback(w http.ResponseWriter, r *http.Request) {
	prepareFederatedResponse(w)
	policy := h.federated.platformOIDCCookie
	clearFederatedTransactionCookie(w, policy)
	if h.rejectFederatedBrowserAuthority(r) != nil ||
		len(r.URL.RawQuery) > maximumOIDCCallbackQueryBytes ||
		r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		writeFederatedFailure(w, r, false)
		return
	}
	capability, err := platformOIDCTransactionCookie(r, policy, true)
	if err != nil {
		writeFederatedFailure(w, r, false)
		return
	}
	defer capability.destroy()
	if !h.platformOIDCTransportReady(r) {
		writeFederatedFailure(w, r, true)
		return
	}
	audit, err := h.platformOIDCAuditContext(r)
	if err != nil {
		writeFederatedFailure(w, r, false)
		return
	}
	transactionHandle := capability.transaction()
	browserCapability := capability.browser()
	defer clear(transactionHandle)
	defer clear(browserCapability)
	result, err := h.platformOIDCBrowser.Complete(r.Context(), platformoidcauth.CompleteDirectOIDCRequest{
		RawQuery: r.URL.RawQuery, BrowserHandle: transactionHandle,
		BrowserCapability: browserCapability, Audit: audit,
	})
	if err != nil {
		if result.Credential != nil {
			result.Credential.Destroy()
		}
		writeFederatedFailure(w, r, errors.Is(err, errFederatedTransportUnavailable))
		return
	}
	if !h.completePlatformOIDCBrowserCredential(w, r, result) {
		writeFederatedFailure(w, r, false)
	}
}

func (h *Handler) completePlatformOIDCBrowserCredential(
	w http.ResponseWriter,
	r *http.Request,
	result platformoidcauth.DirectOIDCBrowserOutcome,
) bool {
	if result.Credential == nil || !validFederatedEntityID(result.UserID) ||
		!validFederatedReturnPath(result.ReturnPath) {
		if result.Credential != nil {
			result.Credential.Destroy()
		}
		return false
	}
	credential := result.Credential
	defer credential.Destroy()
	material, consumed := credential.Consume()
	if !consumed {
		return false
	}
	defer material.Destroy()
	switch result.Disposition {
	case platformoidcauth.DirectAuthenticationImmediateSession:
		return h.completePlatformOIDCSession(w, r, result, material)
	case platformoidcauth.DirectAuthenticationTOTPContinuation:
		return h.completePlatformOIDCContinuation(w, result, material)
	default:
		return false
	}
}

func (h *Handler) completePlatformOIDCSession(
	w http.ResponseWriter,
	r *http.Request,
	result platformoidcauth.DirectOIDCBrowserOutcome,
	material federatedauth.BrowserCredentialMaterial,
) bool {
	if !validFederatedEntityID(result.SessionID) || result.ContinuationID != (identity.EntityID{}) {
		return false
	}
	_, token, expiresAt, ok := h.resolveDirectPlatformOIDCSession(
		r, result.UserID, result.SessionID, material,
	)
	if !ok {
		return false
	}
	h.clearMFACookie(w)
	h.clearFederatedContinuationCookie(w)
	h.setSessionCookie(w, token, expiresAt)
	w.Header().Set("Location", result.ReturnPath)
	w.WriteHeader(http.StatusSeeOther)
	return true
}

func (h *Handler) completePlatformOIDCContinuation(
	w http.ResponseWriter,
	result platformoidcauth.DirectOIDCBrowserOutcome,
	material federatedauth.BrowserCredentialMaterial,
) bool {
	now := h.federated.now().UTC()
	if result.SessionID != (identity.EntityID{}) || material.SessionID != (identity.EntityID{}) ||
		!validFederatedEntityID(result.ContinuationID) || result.ContinuationID != material.ContinuationID ||
		material.Authority != federatedauth.ContinuationAuthorityDirectPlatformOIDC ||
		len(material.SessionToken) != 0 || len(material.CSRFToken) != 0 ||
		!validMFABrowserHandle(string(material.Receipt)) || !validFederatedExpiry(material.ExpiresAt, now) ||
		setFederatedContinuationCookieForAuthorityWithPolicy(
			w, h.federatedContinuationCookie, material.Authority,
			uuid.UUID(material.ContinuationID), material.Receipt, material.ExpiresAt, now,
		) != nil {
		return false
	}
	w.Header().Set("Location", federatedContinuationPath)
	w.WriteHeader(http.StatusSeeOther)
	return true
}

func (h *Handler) platformOIDCTransportReady(r *http.Request) bool {
	return h != nil && r != nil && h.authentication != nil &&
		!platformOIDCBrowserAuthenticationIsNil(h.platformOIDCBrowser) &&
		h.federated.random != nil && h.federated.newID != nil && h.federated.now != nil &&
		h.platformOIDCBrowser.Ready(r.Context()) == nil
}

func (h *Handler) platformOIDCAuditContext(
	r *http.Request,
) (platformoidcauth.DirectAuditContext, error) {
	event, err := h.eventContext(r)
	if err != nil || !validFederatedEntityID(identity.EntityID(event.RequestID)) ||
		!validFederatedEntityID(identity.EntityID(event.CorrelationID)) {
		return platformoidcauth.DirectAuditContext{}, authentication.ErrInvalidInput
	}
	return platformoidcauth.DirectAuditContext{
		RequestID: identity.EntityID(event.RequestID), CorrelationID: identity.EntityID(event.CorrelationID),
		RemoteAddress: event.RemoteAddress, UserAgent: event.UserAgent,
	}, nil
}

func (h *Handler) newPlatformOIDCStartSecrets() ([]byte, []byte, error) {
	if h == nil || h.federated.random == nil {
		return nil, nil, errFederatedTransportUnavailable
	}
	receipt := make([]byte, platformOIDCTransactionSecretBytes)
	browserCapability := make([]byte, platformOIDCTransactionSecretBytes)
	if _, err := io.ReadFull(h.federated.random, receipt); err != nil ||
		!validPlatformOIDCBrowserCapability(receipt) {
		clear(receipt)
		clear(browserCapability)
		return nil, nil, errFederatedTransportUnavailable
	}
	if _, err := io.ReadFull(h.federated.random, browserCapability); err != nil ||
		!validPlatformOIDCBrowserCapability(browserCapability) ||
		subtle.ConstantTimeCompare(receipt, browserCapability) == 1 {
		clear(receipt)
		clear(browserCapability)
		return nil, nil, errFederatedTransportUnavailable
	}
	return receipt, browserCapability, nil
}
