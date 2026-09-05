package httpserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

const (
	federatedContinuationAction   = "session.create"
	federatedContinuationAudience = "api"

	federatedMFAStartResource                  = "auth.federated.mfa.step_up.start"
	federatedMFACancelResource                 = "auth.federated.mfa.ceremony.cancel"
	federatedMFATOTPResource                   = "auth.federated.mfa.step_up.totp"
	federatedMFARecoveryResource               = "auth.federated.mfa.step_up.recovery"
	federatedMFAPasskeyStartResource           = "auth.federated.mfa.passkey.start"
	federatedMFAPasskeyCompleteResource        = "auth.federated.mfa.passkey.complete"
	federatedMFATOTPEnrollmentStartResource    = "auth.federated.mfa.totp.enrollment.start"
	federatedMFATOTPEnrollmentCompleteResource = "auth.federated.mfa.totp.enrollment.complete"
)

type federatedMFARequest struct {
	continuationID identity.EntityID
	authority      federatedauth.ContinuationAuthority
	receiptDigest  [sha256.Size]byte
	browserHandle  []byte
	admission      mfaauth.AdmissionContext
}

func (request *federatedMFARequest) destroy() {
	if request == nil {
		return
	}
	clear(request.browserHandle)
	*request = federatedMFARequest{}
}

func isDirectPlatformContinuation(authority federatedauth.ContinuationAuthority) bool {
	return authority == federatedauth.ContinuationAuthorityDirectPlatformOIDC ||
		authority == federatedauth.ContinuationAuthorityDirectPlatformSAML
}

// authorizeFederatedMFA admits exactly one possession-bound continuation.
// The opaque receipt is reduced to its digest before crossing the HTTP
// boundary; a ceremony completion additionally requires the separate, exact
// one-use MFA cookie. Session, bearer, and CSRF authority are rejected rather
// than combined with the continuation capability.
func (h *Handler) authorizeFederatedMFA(
	w http.ResponseWriter,
	r *http.Request,
	resource string,
	requireCeremony bool,
) (federatedMFARequest, bool) {
	if !h.prepareCookieMutation(w, r) {
		return federatedMFARequest{}, false
	}
	if err := h.rejectSessionAuthority(r); err != nil || len(r.Header.Values(csrfTokenHeader)) != 0 {
		writeDomainError(w, r, authentication.ErrInvalidAuthentication)
		return federatedMFARequest{}, false
	}

	var browserHandle []byte
	if requireCeremony {
		var err error
		browserHandle, err = h.mfaBrowserHandle(r)
		if err != nil {
			writeDomainError(w, r, err)
			return federatedMFARequest{}, false
		}
	} else {
		for _, cookie := range r.Cookies() {
			if cookie.Name == h.mfaCookie.name {
				writeDomainError(w, r, authentication.ErrInvalidAuthentication)
				return federatedMFARequest{}, false
			}
		}
		if err := requireFederatedMFARequestBodyAbsent(r); err != nil {
			writeDomainError(w, r, authentication.ErrInvalidInput)
			return federatedMFARequest{}, false
		}
	}

	capability, err := federatedContinuationCapabilityCookie(r, h.federatedContinuationCookie)
	if err != nil {
		clear(browserHandle)
		writeDomainError(w, r, err)
		return federatedMFARequest{}, false
	}
	defer capability.destroy()
	receiptDigest, err := capability.receiptDigest()
	if err != nil || receiptDigest == ([sha256.Size]byte{}) {
		clear(browserHandle)
		writeDomainError(w, r, authentication.ErrInvalidAuthentication)
		return federatedMFARequest{}, false
	}
	principal := identity.EntityID(capability.continuationID)
	var admission mfaauth.AdmissionContext
	if capability.authority == federatedauth.ContinuationAuthorityTenant {
		event, eventErr := h.eventContext(r)
		if eventErr != nil {
			clear(browserHandle)
			writeDomainError(w, r, authentication.ErrInvalidInput)
			return federatedMFARequest{}, false
		}
		admission, err = h.mfa.Admission(event.RemoteAddress, principal, resource)
		if err != nil {
			clear(browserHandle)
			writeDomainError(w, r, err)
			return federatedMFARequest{}, false
		}
	} else if !isDirectPlatformContinuation(capability.authority) {
		clear(browserHandle)
		writeDomainError(w, r, authentication.ErrInvalidAuthentication)
		return federatedMFARequest{}, false
	}
	return federatedMFARequest{
		continuationID: principal,
		authority:      capability.authority,
		receiptDigest:  receiptDigest,
		browserHandle:  browserHandle,
		admission:      admission,
	}, true
}

func requireFederatedMFARequestBodyAbsent(r *http.Request) error {
	if r == nil || r.ContentLength != 0 || len(r.TransferEncoding) != 0 ||
		len(r.Header.Values("Transfer-Encoding")) != 0 || len(r.Header.Values("Content-Type")) != 0 {
		return errors.New("federated MFA browser-state operation does not accept a request body")
	}
	if r.Body == nil {
		return nil
	}
	defer r.Body.Close()
	var probe [1]byte
	read, err := r.Body.Read(probe[:])
	if read != 0 || !errors.Is(err, io.EOF) {
		return errors.New("federated MFA browser-state operation does not accept a request body")
	}
	return nil
}

// CancelFederatedMfaCeremony discards only the caller's exact, one-use MFA
// browser capability. The continuation remains possession-bound and can start
// another proof; the now-unreachable database artifact expires independently.
func (h *Handler) CancelFederatedMfaCeremony(w http.ResponseWriter, r *http.Request) {
	request, ok := h.authorizeFederatedMFA(w, r, federatedMFACancelResource, true)
	if !ok {
		return
	}
	defer request.destroy()
	if err := requireFederatedMFARequestBodyAbsent(r); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	h.clearMFACookie(w)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// AbandonFederatedMfaContinuation is an intentionally non-oracular recovery
// operation. It validates only the same-origin anonymous transport boundary,
// then expires every browser-side federated capability without consulting or
// mutating server-side authority.
func (h *Handler) AbandonFederatedMfaContinuation(w http.ResponseWriter, r *http.Request) {
	if !h.prepareCookieMutation(w, r) {
		return
	}
	if err := h.rejectSessionAuthority(r); err != nil || len(r.Header.Values(csrfTokenHeader)) != 0 {
		writeDomainError(w, r, authentication.ErrInvalidAuthentication)
		return
	}
	if err := requireFederatedMFARequestBodyAbsent(r); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	if !validMFATransportCookiePolicy(h.mfaCookie) ||
		!validFederatedContinuationTransportCookiePolicy(h.federatedContinuationCookie) ||
		!validFederatedTransactionCookiePolicy(h.federated.oidcCookie) ||
		!validFederatedTransactionCookiePolicy(h.federated.samlCookie) ||
		!validFederatedTransactionCookiePolicy(h.federated.platformOIDCCookie) ||
		!validFederatedTransactionCookiePolicy(h.federated.platformSAMLCookie) {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}

	clearFederatedTransactionCookie(w, h.federated.oidcCookie)
	clearFederatedTransactionCookie(w, h.federated.samlCookie)
	clearFederatedTransactionCookie(w, h.federated.platformOIDCCookie)
	clearFederatedTransactionCookie(w, h.federated.platformSAMLCookie)
	h.clearMFACookie(w)
	h.clearFederatedContinuationCookie(w)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func federatedAuthorityLookup(request federatedMFARequest) mfaauth.AuthorityLookup {
	return mfaauth.AuthorityLookup{
		Flow: mfa.FlowPostPrimaryContinuation, AnchorID: request.continuationID,
		Action: federatedContinuationAction, Audience: federatedContinuationAudience,
		Admission: request.admission, ContinuationReceiptDigest: request.receiptDigest,
	}
}

func federatedPasskeyLookup(request federatedMFARequest) mfaauth.PasskeyLookup {
	return mfaauth.PasskeyLookup{
		ReferenceID: request.continuationID, Purpose: webauthn.PurposeContinuationAuthentication,
		Action: federatedContinuationAction, Audience: federatedContinuationAudience,
		Admission: request.admission, ContinuationReceiptDigest: request.receiptDigest,
	}
}

func (h *Handler) StartFederatedMfaStepUp(w http.ResponseWriter, r *http.Request) {
	request, ok := h.authorizeFederatedMFA(w, r, federatedMFAStartResource, false)
	if !ok {
		return
	}
	defer request.destroy()
	if request.authority == federatedauth.ContinuationAuthorityDirectPlatformOIDC {
		h.startDirectPlatformOIDCTOTP(w, r, request)
		return
	}
	if request.authority == federatedauth.ContinuationAuthorityDirectPlatformSAML {
		h.startDirectPlatformSAMLTOTP(w, r, request)
		return
	}
	artifact, err := h.mfa.StartLocalStepUp(r.Context(), mfaauth.StartLocalStepUpCommand{
		Lookup: federatedAuthorityLookup(request),
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer artifact.Destroy()
	methods, err := mapStepUpMethods(artifact.AllowedFactors())
	totpFactorIDs, factorErr := mapStepUpTOTPFactorIDs(methods, artifact.TOTPFactorIDs())
	if err != nil || len(methods) < 1 || len(methods) > 2 ||
		len(methods) == 2 && methods[0] == methods[1] ||
		factorErr != nil ||
		h.setMFACookie(w, artifact.BrowserHandle(), artifact.ExpiresAt()) != nil {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, contract.MfaStepUpChallenge{
		ChallengeId:   encodeChallengeID(artifact.ChallengeID()),
		ExpiresAt:     artifact.ExpiresAt(),
		Methods:       methods,
		TotpFactorIds: totpFactorIDs,
	})
}

func (h *Handler) CompleteFederatedMfaTotpStepUp(
	w http.ResponseWriter,
	r *http.Request,
	challengeID contract.MfaChallengeId,
) {
	request, ok := h.authorizeFederatedMFA(w, r, federatedMFATOTPResource, true)
	if !ok {
		return
	}
	defer request.destroy()
	parsedChallenge, err := decodeChallengeID(challengeID)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.MfaTotpStepUpRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	factorID := identity.EntityID(body.FactorId)
	if request.authority == federatedauth.ContinuationAuthorityDirectPlatformOIDC {
		h.completeDirectPlatformOIDCTOTP(w, r, request, parsedChallenge, factorID, []byte(body.Code))
		return
	}
	if request.authority == federatedauth.ContinuationAuthorityDirectPlatformSAML {
		h.completeDirectPlatformSAMLTOTP(w, r, request, parsedChallenge, factorID, []byte(body.Code))
		return
	}
	ticket, plan, reservation, err := h.prepareAndReserveCompletion(r.Context(), mfaauth.CompletionTicketRequest{
		Admission: request.admission, ArtifactKind: mfaauth.CompletionArtifactStepUp,
		ArtifactID: parsedChallenge[:], BrowserHandle: request.browserHandle,
		FactorKind: mfaauth.CompletionFactorTOTP, FactorID: factorID[:],
		ContinuationID: request.continuationID, ContinuationReceiptDigest: request.receiptDigest,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer reservation.Destroy()
	h.clearMFACookie(w)
	if _, err := h.mfa.CompleteTOTP(r.Context(), mfaauth.CompleteTOTPCommand{
		Ticket: ticket, Code: []byte(body.Code), Session: reservation.Reservation,
	}); err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.clearFederatedContinuationCookie(w)
	session, ok := h.completeReservedSession(w, r, reservation, plan.ResultAuthenticationMethod)
	if !ok {
		return
	}
	writeSensitiveJSON(w, http.StatusOK, session)
}

func (h *Handler) CompleteFederatedMfaRecoveryStepUp(
	w http.ResponseWriter,
	r *http.Request,
	challengeID contract.MfaChallengeId,
) {
	request, ok := h.authorizeFederatedMFA(w, r, federatedMFARecoveryResource, true)
	if !ok {
		return
	}
	defer request.destroy()
	if isDirectPlatformContinuation(request.authority) {
		writeDomainError(w, r, authentication.ErrForbidden)
		return
	}
	parsedChallenge, err := decodeChallengeID(challengeID)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.MfaRecoveryStepUpRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	ticket, plan, reservation, err := h.prepareAndReserveCompletion(r.Context(), mfaauth.CompletionTicketRequest{
		Admission: request.admission, ArtifactKind: mfaauth.CompletionArtifactStepUp,
		ArtifactID: parsedChallenge[:], BrowserHandle: request.browserHandle,
		FactorKind:     mfaauth.CompletionFactorRecovery,
		ContinuationID: request.continuationID, ContinuationReceiptDigest: request.receiptDigest,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer reservation.Destroy()
	h.clearMFACookie(w)
	if _, err := h.mfa.CompleteRecovery(r.Context(), mfaauth.CompleteRecoveryCommand{
		Ticket: ticket, Code: []byte(body.Code), Session: reservation.Reservation,
	}); err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.clearFederatedContinuationCookie(w)
	session, ok := h.completeReservedSession(w, r, reservation, plan.ResultAuthenticationMethod)
	if !ok {
		return
	}
	writeSensitiveJSON(w, http.StatusOK, session)
}

func (h *Handler) StartFederatedPasskeyStepUp(w http.ResponseWriter, r *http.Request) {
	request, ok := h.authorizeFederatedMFA(w, r, federatedMFAPasskeyStartResource, false)
	if !ok {
		return
	}
	defer request.destroy()
	if isDirectPlatformContinuation(request.authority) {
		writeDomainError(w, r, authentication.ErrForbidden)
		return
	}
	artifact, err := h.mfa.StartPasskeyAuthentication(r.Context(), federatedPasskeyLookup(request))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer artifact.Destroy()
	mapped, err := mapWebAuthnAuthenticationOptions(artifact)
	if err != nil || h.setMFACookie(w, artifact.BrowserHandle(), artifact.ExpiresAt()) != nil {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) CompleteFederatedPasskeyStepUp(w http.ResponseWriter, r *http.Request) {
	request, ok := h.authorizeFederatedMFA(w, r, federatedMFAPasskeyCompleteResource, true)
	if !ok {
		return
	}
	defer request.destroy()
	if isDirectPlatformContinuation(request.authority) {
		writeDomainError(w, r, authentication.ErrForbidden)
		return
	}
	var body contract.WebAuthnAuthenticationResponse
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	response, err := decodeWebAuthnAuthenticationResponse(body, request.browserHandle)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	ticket, plan, reservation, err := h.prepareAndReserveCompletion(r.Context(), mfaauth.CompletionTicketRequest{
		Admission: request.admission, ArtifactKind: mfaauth.CompletionArtifactWebAuthnAuthentication,
		ArtifactID: response.CeremonyID[:], BrowserHandle: request.browserHandle,
		FactorKind: mfaauth.CompletionFactorPasskey, FactorID: response.CredentialID,
		ContinuationID: request.continuationID, ContinuationReceiptDigest: request.receiptDigest,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer reservation.Destroy()
	h.clearMFACookie(w)
	if _, err := h.mfa.FinishPasskeyAuthentication(r.Context(), mfaauth.FinishPasskeyAuthenticationCommand{
		Ticket: ticket, Response: response, Session: reservation.Reservation,
	}); err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.clearFederatedContinuationCookie(w)
	session, ok := h.completeReservedSession(w, r, reservation, plan.ResultAuthenticationMethod)
	if !ok {
		return
	}
	writeSensitiveJSON(w, http.StatusOK, session)
}

func (h *Handler) StartFederatedTotpEnrollment(w http.ResponseWriter, r *http.Request) {
	request, ok := h.authorizeFederatedMFA(w, r, federatedMFATOTPEnrollmentStartResource, false)
	if !ok {
		return
	}
	defer request.destroy()
	if isDirectPlatformContinuation(request.authority) {
		writeDomainError(w, r, authentication.ErrForbidden)
		return
	}
	artifact, err := h.mfa.StartTOTP(r.Context(), federatedAuthorityLookup(request))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer artifact.Destroy()
	if !validFederatedEntityID(artifact.EnrollmentID()) || !validFederatedEntityID(artifact.FactorID()) ||
		artifact.EnrollmentID() == artifact.FactorID() ||
		h.setMFACookie(w, artifact.BrowserHandle(), artifact.ExpiresAt()) != nil {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusCreated, contract.TotpEnrollment{
		EnrollmentId: uuid.UUID(artifact.EnrollmentID()), ExpiresAt: artifact.ExpiresAt(),
		ProvisioningUri: artifact.ProvisioningURI(), Secret: string(artifact.DisplaySecret()),
	})
}

func (h *Handler) CompleteFederatedTotpEnrollment(
	w http.ResponseWriter,
	r *http.Request,
	enrollmentID contract.MfaEnrollmentId,
) {
	request, ok := h.authorizeFederatedMFA(w, r, federatedMFATOTPEnrollmentCompleteResource, true)
	if !ok {
		return
	}
	defer request.destroy()
	if isDirectPlatformContinuation(request.authority) {
		writeDomainError(w, r, authentication.ErrForbidden)
		return
	}
	var body contract.TotpEnrollmentCompletionRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	enrollmentIdentifier := identity.EntityID(enrollmentID)
	ticket, plan, reservation, err := h.prepareAndReserveCompletion(r.Context(), mfaauth.CompletionTicketRequest{
		Admission: request.admission, ArtifactKind: mfaauth.CompletionArtifactTOTPEnrollment,
		ArtifactID: enrollmentIdentifier[:], BrowserHandle: request.browserHandle,
		FactorKind:     mfaauth.CompletionFactorTOTP,
		ContinuationID: request.continuationID, ContinuationReceiptDigest: request.receiptDigest,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer reservation.Destroy()
	if plan.Disposition != mfaauth.CompletionReservationNone || !reservation.Reservation.IsZero() {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	h.clearMFACookie(w)
	result, err := h.mfa.FinishTOTP(r.Context(), mfaauth.FinishTOTPEnrollmentCommand{
		Ticket: ticket, Code: []byte(body.Code), Session: reservation.Reservation,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	zero := identity.EntityID{}
	if result.Mutation != mfaauth.SessionRetainContinuation ||
		result.RetainedContinuationID != request.continuationID ||
		result.NewSessionID != zero || result.NewSessionFamilyID != zero ||
		!validFederatedEntityID(result.FactorID) || result.SessionVersion == 0 {
		h.clearFederatedContinuationCookie(w)
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, contract.FederatedMfaEnrollmentResult{
		FactorId: uuid.UUID(result.FactorID), Next: contract.StepUp,
	})
}

func (h *Handler) startDirectPlatformOIDCTOTP(
	w http.ResponseWriter,
	r *http.Request,
	request federatedMFARequest,
) {
	if !h.platformOIDCTransportReady(r) {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	audit, err := h.platformOIDCAuditContext(r)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	artifact, err := h.platformOIDCBrowser.StartTOTP(r.Context(), platformoidcauth.StartDirectTOTPCommand{
		ContinuationID: request.continuationID, Authority: request.authority,
		ReceiptDigest: request.receiptDigest, Audit: audit,
	})
	if err != nil {
		writeDirectPlatformOIDCAuthenticationError(w, r, err)
		return
	}
	defer artifact.Destroy()
	if !validFederatedEntityID(artifact.FactorID) ||
		h.setMFACookie(w, artifact.BrowserHandle, artifact.ExpiresAt) != nil {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, contract.MfaStepUpChallenge{
		ChallengeId: encodeChallengeID(mfa.ChallengeID(artifact.ChallengeID)),
		ExpiresAt:   artifact.ExpiresAt, Methods: []contract.MfaStepUpMethod{contract.MfaStepUpMethodTotp},
		TotpFactorIds: []uuid.UUID{uuid.UUID(artifact.FactorID)},
	})
}

func (h *Handler) startDirectPlatformSAMLTOTP(
	w http.ResponseWriter,
	r *http.Request,
	request federatedMFARequest,
) {
	if !h.platformSAMLContinuationReady(r) {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	audit, err := h.platformSAMLAuditContext(r)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	artifact, err := h.platformSAMLContinuation.StartTOTP(r.Context(), PlatformSAMLStartTOTPCommand{
		ContinuationID: request.continuationID, ReceiptDigest: request.receiptDigest, Audit: audit,
	})
	if err != nil {
		artifact.Destroy()
		writeDirectPlatformSAMLAuthenticationError(w, r, err)
		return
	}
	defer artifact.Destroy()
	encodedChallenge := encodeChallengeID(artifact.ChallengeID)
	if _, err := decodeChallengeID(encodedChallenge); err != nil ||
		!validFederatedEntityID(artifact.FactorID) ||
		h.setMFACookie(w, artifact.BrowserHandle, artifact.ExpiresAt) != nil {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, contract.MfaStepUpChallenge{
		ChallengeId: encodedChallenge, ExpiresAt: artifact.ExpiresAt,
		Methods:       []contract.MfaStepUpMethod{contract.MfaStepUpMethodTotp},
		TotpFactorIds: []uuid.UUID{uuid.UUID(artifact.FactorID)},
	})
}

func (h *Handler) completeDirectPlatformOIDCTOTP(
	w http.ResponseWriter,
	r *http.Request,
	request federatedMFARequest,
	challengeID mfa.ChallengeID,
	factorID identity.EntityID,
	code []byte,
) {
	defer clear(code)
	if !h.platformOIDCTransportReady(r) {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	audit, err := h.platformOIDCAuditContext(r)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	h.clearMFACookie(w)
	outcome, err := h.platformOIDCBrowser.CompleteTOTP(r.Context(), platformoidcauth.CompleteDirectTOTPCommand{
		ChallengeID:    platformoidcauth.DirectTOTPChallengeID(challengeID),
		ContinuationID: request.continuationID, Authority: request.authority,
		ReceiptDigest: request.receiptDigest,
		BrowserHandle: request.browserHandle, FactorID: factorID, Code: code, Audit: audit,
	})
	if err != nil {
		outcome.Destroy()
		writeDirectPlatformOIDCAuthenticationError(w, r, err)
		return
	}
	defer outcome.Destroy()
	// A nil application error means the continuation was atomically consumed
	// and a session was committed. Expire the now-dead browser capability before
	// validating the delivery projection or re-reading the session.
	h.clearFederatedContinuationCookie(w)
	if outcome.Credential == nil || !validFederatedEntityID(outcome.SessionID) ||
		!validFederatedEntityID(outcome.UserID) || !validFederatedEntityID(outcome.FactorID) ||
		outcome.FactorID != factorID {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	material, consumed := outcome.Credential.Consume()
	if !consumed {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	defer material.Destroy()
	mapped, token, expiresAt, ok := h.resolveDirectPlatformOIDCSession(
		r, outcome.UserID, outcome.SessionID, material,
	)
	if !ok {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	h.setSessionCookie(w, token, expiresAt)
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) completeDirectPlatformSAMLTOTP(
	w http.ResponseWriter,
	r *http.Request,
	request federatedMFARequest,
	challengeID mfa.ChallengeID,
	factorID identity.EntityID,
	code []byte,
) {
	defer clear(code)
	if !h.platformSAMLContinuationReady(r) {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	audit, err := h.platformSAMLAuditContext(r)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	h.clearMFACookie(w)
	outcome, err := h.platformSAMLContinuation.CompleteTOTP(r.Context(), PlatformSAMLCompleteTOTPCommand{
		ChallengeID: challengeID, ContinuationID: request.continuationID,
		ReceiptDigest: request.receiptDigest, BrowserHandle: request.browserHandle,
		FactorID: factorID, Code: code, Audit: audit,
	})
	if err != nil {
		if !interfaceIsNil(outcome.Delivery) {
			if compensateErr := compensatePlatformSAMLTOTPDelivery(r.Context(), &outcome, nil); compensateErr != nil {
				writeDomainError(w, r, authentication.ErrUnavailable)
				return
			}
		} else {
			outcome.Destroy()
		}
		writeDirectPlatformSAMLAuthenticationError(w, r, err)
		return
	}
	defer outcome.Destroy()
	h.clearFederatedContinuationCookie(w)
	if interfaceIsNil(outcome.Credential) || interfaceIsNil(outcome.Delivery) ||
		!validFederatedEntityID(outcome.SessionID) ||
		!validFederatedEntityID(outcome.UserID) || !validFederatedEntityID(outcome.FactorID) ||
		outcome.FactorID != factorID {
		_ = compensatePlatformSAMLTOTPDelivery(r.Context(), &outcome, nil)
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	material, consumed := outcome.Credential.Consume()
	if !consumed {
		_ = compensatePlatformSAMLTOTPDelivery(r.Context(), &outcome, &material)
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	defer material.Destroy()
	mapped, token, expiresAt, ok := h.resolveDirectPlatformSAMLSession(
		r, outcome.UserID, outcome.SessionID, material,
	)
	if !ok {
		_ = compensatePlatformSAMLTOTPDelivery(r.Context(), &outcome, &material)
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	if err := h.deliverPlatformSAMLTOTPSession(w, mapped, token, expiresAt); err != nil ||
		r.Context().Err() != nil {
		_ = compensatePlatformSAMLTOTPDelivery(r.Context(), &outcome, &material)
		return
	}
	if err := outcome.Delivery.ConfirmBrowserDelivery(); err != nil {
		_ = compensatePlatformSAMLTOTPDelivery(r.Context(), &outcome, &material)
	}
}

func (h *Handler) deliverPlatformSAMLTOTPSession(
	w http.ResponseWriter,
	mapped contract.Session,
	token string,
	expiresAt time.Time,
) error {
	payload, err := json.Marshal(mapped)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	defer clear(payload)
	h.setSessionCookie(w, token, expiresAt)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	written, err := w.Write(payload)
	if err != nil || written != len(payload) {
		return errors.New("direct platform SAML browser delivery failed")
	}
	return nil
}

func compensatePlatformSAMLTOTPDelivery(
	ctx context.Context,
	outcome *PlatformSAMLTOTPOutcome,
	material *platformsamlauth.BrowserCredentialMaterial,
) error {
	if material != nil {
		material.Destroy()
	}
	if outcome == nil {
		return platformsamlauth.ErrBrowserDeliveryRejected
	}
	finalizer := outcome.Delivery
	outcome.Destroy()
	if interfaceIsNil(finalizer) {
		return platformsamlauth.ErrBrowserDeliveryRejected
	}
	return finalizer.CompensateBrowserDelivery(ctx)
}

func (h *Handler) resolveDirectPlatformSAMLSession(
	r *http.Request,
	userID identity.EntityID,
	sessionID identity.EntityID,
	material platformsamlauth.BrowserCredentialMaterial,
) (contract.Session, string, time.Time, bool) {
	if material.Kind != platformsamlauth.BrowserSessionCredential || material.SessionID != sessionID ||
		material.ContinuationID != (identity.EntityID{}) || !material.ExpiresAt.IsZero() ||
		!validMFABrowserHandle(string(material.SessionToken)) ||
		!validMFABrowserHandle(string(material.CSRFToken)) || len(material.Receipt) != 0 {
		return contract.Session{}, "", time.Time{}, false
	}
	token := string(material.SessionToken)
	credential, err := h.authentication.CurrentSession(r.Context(), token)
	if err != nil || credential.Session.ActiveTenantID != nil ||
		identity.EntityID(credential.Session.ID) != sessionID ||
		identity.EntityID(credential.Session.User.ID) != userID || credential.SessionToken != token ||
		len(credential.CSRFToken) != len(material.CSRFToken) ||
		subtle.ConstantTimeCompare([]byte(credential.CSRFToken), material.CSRFToken) != 1 ||
		credential.Session.AuthenticationMethod != string(federatedauth.AuthenticationMethodSAML) {
		return contract.Session{}, "", time.Time{}, false
	}
	mapped, err := mapSession(credential.Session, credential.CSRFToken)
	if err != nil {
		return contract.Session{}, "", time.Time{}, false
	}
	return mapped, token, credential.Session.AbsoluteExpiresAt, true
}

func (h *Handler) platformSAMLContinuationReady(r *http.Request) bool {
	return h != nil && r != nil && h.authentication != nil &&
		!platformSAMLContinuationServiceIsNil(h.platformSAMLContinuation) &&
		h.platformSAMLContinuation.Ready(r.Context()) == nil
}

func (h *Handler) platformSAMLAuditContext(r *http.Request) (platformsamlauth.AuditContext, error) {
	event, err := h.eventContext(r)
	if err != nil || !validFederatedEntityID(identity.EntityID(event.RequestID)) ||
		!validFederatedEntityID(identity.EntityID(event.CorrelationID)) {
		return platformsamlauth.AuditContext{}, authentication.ErrInvalidInput
	}
	return platformsamlauth.AuditContext{
		RequestID: identity.EntityID(event.RequestID), CorrelationID: identity.EntityID(event.CorrelationID),
		RemoteAddress: event.RemoteAddress, UserAgent: event.UserAgent,
	}, nil
}

func writeDirectPlatformSAMLAuthenticationError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errFederatedTransportUnavailable) ||
		errors.Is(err, platformsamlauth.ErrAuthenticationUnavailable) ||
		errors.Is(err, platformsamlauth.ErrBrowserDeliveryUnavailable) ||
		errors.Is(err, authentication.ErrUnavailable) {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	writeDomainError(w, r, authentication.ErrInvalidAuthentication)
}

func (h *Handler) resolveDirectPlatformOIDCSession(
	r *http.Request,
	userID identity.EntityID,
	sessionID identity.EntityID,
	material federatedauth.BrowserCredentialMaterial,
) (contract.Session, string, time.Time, bool) {
	if material.Kind != federatedauth.BrowserCredentialSession || material.SessionID != sessionID ||
		material.ContinuationID != (identity.EntityID{}) ||
		material.Authority != federatedauth.ContinuationAuthorityTenant ||
		!material.ExpiresAt.IsZero() || !validMFABrowserHandle(string(material.SessionToken)) ||
		!validMFABrowserHandle(string(material.CSRFToken)) || len(material.Receipt) != 0 {
		return contract.Session{}, "", time.Time{}, false
	}
	token := string(material.SessionToken)
	credential, err := h.authentication.CurrentSession(r.Context(), token)
	if err != nil || credential.Session.ActiveTenantID != nil ||
		identity.EntityID(credential.Session.ID) != sessionID ||
		identity.EntityID(credential.Session.User.ID) != userID || credential.SessionToken != token ||
		len(credential.CSRFToken) != len(material.CSRFToken) ||
		subtle.ConstantTimeCompare([]byte(credential.CSRFToken), material.CSRFToken) != 1 ||
		credential.Session.AuthenticationMethod != string(federatedauth.AuthenticationMethodOIDC) {
		return contract.Session{}, "", time.Time{}, false
	}
	mapped, err := mapSession(credential.Session, credential.CSRFToken)
	if err != nil {
		return contract.Session{}, "", time.Time{}, false
	}
	return mapped, token, credential.Session.AbsoluteExpiresAt, true
}

func writeDirectPlatformOIDCAuthenticationError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errFederatedTransportUnavailable) || errors.Is(err, authentication.ErrUnavailable) {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	writeDomainError(w, r, authentication.ErrInvalidAuthentication)
}
