package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
)

const (
	mfaBrowserAudience               = "periapsis-web"
	passkeyLoginAction               = "auth.passkey.login"
	totpEnrollmentAction             = "mfa.totp.enroll"
	passkeyEnrollmentAction          = "mfa.passkey.enroll"
	recoveryRegenerationAction       = "mfa.recovery.regenerate"
	maximumWebAuthnBinaryBytes       = 256 * 1024
	maximumWebAuthnCredentialIDBytes = 1024
	maximumClientExtensionsBytes     = 8 * 1024
	maximumChallengeTOTPFactors      = 16
)

type authenticatedMFARequest struct {
	token     string
	session   authentication.Session
	admission mfaauth.AdmissionContext
}

func (h *Handler) authorizeMFA(
	w http.ResponseWriter,
	r *http.Request,
	resource string,
) (authenticatedMFARequest, bool) {
	if !h.prepareCookieMutation(w, r) {
		return authenticatedMFARequest{}, false
	}
	token, err := h.sessionToken(r)
	if err != nil {
		writeDomainError(w, r, err)
		return authenticatedMFARequest{}, false
	}
	csrf, err := singleHeader(r, csrfTokenHeader, 128)
	if err != nil {
		writeDomainError(w, r, authentication.ErrForbidden)
		return authenticatedMFARequest{}, false
	}
	session, err := h.authenticateRequest(r, token)
	if err != nil {
		writeDomainError(w, r, err)
		return authenticatedMFARequest{}, false
	}
	if err := h.authentication.ValidateCSRF(session, csrf); err != nil {
		writeDomainError(w, r, err)
		return authenticatedMFARequest{}, false
	}
	if session.ActiveTenantID == nil || *session.ActiveTenantID == uuid.Nil {
		writeDomainError(w, r, authentication.ErrForbidden)
		return authenticatedMFARequest{}, false
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return authenticatedMFARequest{}, false
	}
	admission, err := h.mfa.Admission(event.RemoteAddress, identity.EntityID(session.User.ID), resource)
	if err != nil {
		writeDomainError(w, r, err)
		return authenticatedMFARequest{}, false
	}
	return authenticatedMFARequest{token: token, session: session, admission: admission}, true
}

func (h *Handler) anonymousMFAAdmission(
	w http.ResponseWriter,
	r *http.Request,
	principal identity.EntityID,
	resource string,
) (mfaauth.AdmissionContext, bool) {
	if !h.prepareCookieMutation(w, r) {
		return mfaauth.AdmissionContext{}, false
	}
	if err := h.rejectSessionAuthority(r); err != nil {
		writeDomainError(w, r, err)
		return mfaauth.AdmissionContext{}, false
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return mfaauth.AdmissionContext{}, false
	}
	admission, err := h.mfa.Admission(event.RemoteAddress, principal, resource)
	if err != nil {
		writeDomainError(w, r, err)
		return mfaauth.AdmissionContext{}, false
	}
	return admission, true
}

func authorityLookup(
	request authenticatedMFARequest,
	action string,
) mfaauth.AuthorityLookup {
	return mfaauth.AuthorityLookup{
		Flow: mfa.FlowExistingSession, AnchorID: identity.EntityID(request.session.ID),
		Action: action, Audience: mfaBrowserAudience, Admission: request.admission,
	}
}

func passkeyLookup(
	request authenticatedMFARequest,
	purpose webauthn.CeremonyPurpose,
	action string,
) mfaauth.PasskeyLookup {
	return mfaauth.PasskeyLookup{
		ReferenceID: identity.EntityID(request.session.ID), Purpose: purpose,
		Action: action, Audience: mfaBrowserAudience, Admission: request.admission,
	}
}

func (h *Handler) completeReservedSession(
	w http.ResponseWriter,
	r *http.Request,
	reservation authentication.MFASessionReservation,
	expectedAuthenticationMethod string,
) (contract.Session, bool) {
	material, ok := reservation.Consume()
	if !ok {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return contract.Session{}, false
	}
	defer material.Destroy()
	sessionToken := string(material.SessionToken)
	csrfToken := string(material.CSRFToken)
	credential, err := h.authentication.CurrentSession(r.Context(), sessionToken)
	if err != nil || credential.SessionToken != sessionToken || credential.CSRFToken != csrfToken ||
		credential.Session.ID != uuid.UUID(reservation.Reservation.SessionID()) ||
		credential.Session.RotationFamilyID != uuid.UUID(reservation.Reservation.FamilyID()) ||
		credential.Session.AuthenticationMethod != expectedAuthenticationMethod {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return contract.Session{}, false
	}
	mapped, err := mapSession(credential.Session, csrfToken)
	if err != nil {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return contract.Session{}, false
	}
	h.setSessionCookie(w, sessionToken, credential.Session.AbsoluteExpiresAt)
	return mapped, true
}

func completionSessionSource(session authentication.Session) *mfaauth.CompletionSessionSource {
	if session.ActiveTenantID == nil {
		return nil
	}
	return &mfaauth.CompletionSessionSource{
		TenantID: identity.EntityID(*session.ActiveTenantID), UserID: identity.EntityID(session.User.ID),
		SessionID: identity.EntityID(session.ID), SessionFamilyID: identity.EntityID(session.RotationFamilyID),
		AuthenticationMethod: session.AuthenticationMethod, AbsoluteExpiresAt: session.AbsoluteExpiresAt,
	}
}

func (h *Handler) reserveCompletionSession(
	plan mfaauth.CompletionReservationPlan,
) (authentication.MFASessionReservation, error) {
	var current *authentication.Session
	switch plan.Disposition {
	case mfaauth.CompletionReservationNone:
		return authentication.MFASessionReservation{}, nil
	case mfaauth.CompletionReservationCreate:
	case mfaauth.CompletionReservationRotate:
		current = &authentication.Session{
			ID: uuid.UUID(plan.SourceSessionID), RotationFamilyID: uuid.UUID(plan.SourceSessionFamilyID),
			AbsoluteExpiresAt: plan.SourceAbsoluteExpiresAt,
		}
	default:
		return authentication.MFASessionReservation{}, authentication.ErrInvalidAuthentication
	}
	return h.authentication.ReserveMFASessionAt(current, plan.AuthenticationMethod, plan.IssuedAt)
}

func (h *Handler) prepareAndReserveCompletion(
	ctx context.Context,
	request mfaauth.CompletionTicketRequest,
) (mfaauth.CompletionTicket, mfaauth.CompletionReservationPlan, authentication.MFASessionReservation, error) {
	ticket, err := h.mfa.PrepareCompletion(ctx, request)
	if err != nil {
		return mfaauth.CompletionTicket{}, mfaauth.CompletionReservationPlan{}, authentication.MFASessionReservation{}, err
	}
	plan, ok := ticket.ReservationPlan()
	if !ok {
		return mfaauth.CompletionTicket{}, mfaauth.CompletionReservationPlan{}, authentication.MFASessionReservation{},
			authentication.ErrInvalidAuthentication
	}
	reservation, err := h.reserveCompletionSession(plan)
	if err != nil {
		return mfaauth.CompletionTicket{}, mfaauth.CompletionReservationPlan{}, authentication.MFASessionReservation{}, err
	}
	return ticket, plan, reservation, nil
}

func (h *Handler) StartPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var body contract.PasskeyLoginStartRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	tenantID := identity.EntityID(body.TenantId)
	admission, ok := h.anonymousMFAAdmission(w, r, tenantID, passkeyLoginAction)
	if !ok {
		return
	}
	artifact, err := h.mfa.StartPasskeyAuthentication(r.Context(), mfaauth.PasskeyLookup{
		ReferenceID: tenantID, Purpose: webauthn.PurposePrimaryAuthentication,
		Action: passkeyLoginAction, Audience: mfaBrowserAudience, Admission: admission,
	})
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

func (h *Handler) CompletePasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if !h.prepareCookieMutation(w, r) {
		return
	}
	if err := h.rejectSessionAuthority(r); err != nil {
		writeDomainError(w, r, err)
		return
	}
	browserHandle, err := h.mfaBrowserHandle(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body contract.WebAuthnAuthenticationResponse
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	response, err := decodeWebAuthnAuthenticationResponse(body, browserHandle)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	principal := ceremonyPrincipal(response.CeremonyID)
	event, err := h.eventContext(r)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	admission, err := h.mfa.Admission(event.RemoteAddress, principal, passkeyLoginAction)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	ticket, plan, reservation, err := h.prepareAndReserveCompletion(r.Context(), mfaauth.CompletionTicketRequest{
		Admission: admission, ArtifactKind: mfaauth.CompletionArtifactWebAuthnAuthentication,
		ArtifactID: response.CeremonyID[:], BrowserHandle: browserHandle,
		FactorKind: mfaauth.CompletionFactorPasskey, FactorID: response.CredentialID,
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
	session, ok := h.completeReservedSession(w, r, reservation, plan.ResultAuthenticationMethod)
	if !ok {
		return
	}
	writeSensitiveJSON(w, http.StatusOK, session)
}

func (h *Handler) StartLocalMfaStepUp(w http.ResponseWriter, r *http.Request) {
	request, ok := h.authorizeMFA(w, r, "mfa.step_up.start")
	if !ok {
		return
	}
	var body contract.MfaStepUpStartRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	artifact, err := h.mfa.StartLocalStepUp(r.Context(), mfaauth.StartLocalStepUpCommand{
		Lookup: authorityLookup(request, body.Action),
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer artifact.Destroy()
	methods, err := mapStepUpMethods(artifact.AllowedFactors())
	totpFactorIDs, factorErr := mapStepUpTOTPFactorIDs(methods, artifact.TOTPFactorIDs())
	if err != nil || factorErr != nil || h.setMFACookie(w, artifact.BrowserHandle(), artifact.ExpiresAt()) != nil {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, contract.MfaStepUpChallenge{
		ChallengeId: encodeChallengeID(artifact.ChallengeID()), ExpiresAt: artifact.ExpiresAt(), Methods: methods,
		TotpFactorIds: totpFactorIDs,
	})
}

func (h *Handler) CompleteLocalMfaTotpStepUp(
	w http.ResponseWriter,
	r *http.Request,
	challengeID contract.MfaChallengeId,
) {
	request, ok := h.authorizeMFA(w, r, "mfa.step_up.totp")
	if !ok {
		return
	}
	browserHandle, err := h.mfaBrowserHandle(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
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
	ticket, plan, reservation, err := h.prepareAndReserveCompletion(r.Context(), mfaauth.CompletionTicketRequest{
		Admission: request.admission, ArtifactKind: mfaauth.CompletionArtifactStepUp,
		ArtifactID: parsedChallenge[:], BrowserHandle: browserHandle,
		FactorKind: mfaauth.CompletionFactorTOTP, FactorID: factorID[:],
		SessionSource: completionSessionSource(request.session),
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
	session, ok := h.completeReservedSession(w, r, reservation, plan.ResultAuthenticationMethod)
	if !ok {
		return
	}
	writeSensitiveJSON(w, http.StatusOK, session)
}

func (h *Handler) CompleteLocalMfaRecoveryStepUp(
	w http.ResponseWriter,
	r *http.Request,
	challengeID contract.MfaChallengeId,
) {
	request, ok := h.authorizeMFA(w, r, "mfa.step_up.recovery")
	if !ok {
		return
	}
	browserHandle, err := h.mfaBrowserHandle(r)
	if err != nil {
		writeDomainError(w, r, err)
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
		ArtifactID: parsedChallenge[:], BrowserHandle: browserHandle,
		FactorKind:    mfaauth.CompletionFactorRecovery,
		SessionSource: completionSessionSource(request.session),
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
	session, ok := h.completeReservedSession(w, r, reservation, plan.ResultAuthenticationMethod)
	if !ok {
		return
	}
	writeSensitiveJSON(w, http.StatusOK, session)
}

func (h *Handler) StartTotpEnrollment(w http.ResponseWriter, r *http.Request) {
	request, ok := h.authorizeMFA(w, r, totpEnrollmentAction)
	if !ok {
		return
	}
	artifact, err := h.mfa.StartTOTP(r.Context(), authorityLookup(request, totpEnrollmentAction))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer artifact.Destroy()
	if h.setMFACookie(w, artifact.BrowserHandle(), artifact.ExpiresAt()) != nil {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusCreated, contract.TotpEnrollment{
		EnrollmentId: uuid.UUID(artifact.EnrollmentID()), ExpiresAt: artifact.ExpiresAt(),
		ProvisioningUri: artifact.ProvisioningURI(), Secret: string(artifact.DisplaySecret()),
	})
}

func (h *Handler) CompleteTotpEnrollment(
	w http.ResponseWriter,
	r *http.Request,
	enrollmentID contract.MfaEnrollmentId,
) {
	request, ok := h.authorizeMFA(w, r, totpEnrollmentAction)
	if !ok {
		return
	}
	browserHandle, err := h.mfaBrowserHandle(r)
	if err != nil {
		writeDomainError(w, r, err)
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
		ArtifactID: enrollmentIdentifier[:], BrowserHandle: browserHandle,
		FactorKind:    mfaauth.CompletionFactorTOTP,
		SessionSource: completionSessionSource(request.session),
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer reservation.Destroy()
	h.clearMFACookie(w)
	result, err := h.mfa.FinishTOTP(r.Context(), mfaauth.FinishTOTPEnrollmentCommand{
		Ticket: ticket, Code: []byte(body.Code), Session: reservation.Reservation,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	session, ok := h.completeReservedSession(w, r, reservation, plan.ResultAuthenticationMethod)
	if !ok {
		return
	}
	writeSensitiveJSON(w, http.StatusOK, contract.MfaFactorMutationResult{
		FactorId: uuid.UUID(result.FactorID), Session: session,
	})
}

func (h *Handler) RegenerateMfaRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	request, ok := h.authorizeMFA(w, r, recoveryRegenerationAction)
	if !ok {
		return
	}
	method := mfa.SessionAuthenticationTOTP
	switch request.session.AuthenticationMethod {
	case "passkey":
		method = mfa.SessionAuthenticationPasskey
	case "totp", "bootstrap_totp":
	case "recovery_code":
		writeDomainError(w, r, mfaauth.ErrDenied)
		return
	default:
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	reservation, err := h.authentication.ReserveMFASession(&request.session, method)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer reservation.Destroy()
	artifact, err := h.mfa.RegenerateRecoveryCodes(r.Context(), mfaauth.RegenerateRecoveryCodesCommand{
		Lookup: authorityLookup(request, recoveryRegenerationAction), Session: reservation.Reservation,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer artifact.Destroy()
	session, ok := h.completeReservedSession(w, r, reservation, request.session.AuthenticationMethod)
	if !ok {
		return
	}
	codesRaw := artifact.Codes()
	codes := make([]string, len(codesRaw))
	for index := range codesRaw {
		codes[index] = string(codesRaw[index])
		clear(codesRaw[index])
	}
	writeSensitiveJSON(w, http.StatusOK, contract.MfaRecoveryCodesResult{
		RecoveryCodes: codes, Session: session,
	})
}

func (h *Handler) StartPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	request, ok := h.authorizeMFA(w, r, passkeyEnrollmentAction)
	if !ok {
		return
	}
	artifact, err := h.mfa.StartPasskeyRegistration(r.Context(), passkeyLookup(
		request, webauthn.PurposeRegistration, passkeyEnrollmentAction,
	))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer artifact.Destroy()
	mapped, err := mapWebAuthnRegistrationOptions(artifact, request.session.User)
	if err != nil || h.setMFACookie(w, artifact.BrowserHandle(), artifact.ExpiresAt()) != nil {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) CompletePasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	request, ok := h.authorizeMFA(w, r, passkeyEnrollmentAction)
	if !ok {
		return
	}
	browserHandle, err := h.mfaBrowserHandle(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body contract.WebAuthnRegistrationResponse
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	response, err := decodeWebAuthnRegistrationResponse(body, browserHandle)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	ticket, plan, reservation, err := h.prepareAndReserveCompletion(r.Context(), mfaauth.CompletionTicketRequest{
		Admission: request.admission, ArtifactKind: mfaauth.CompletionArtifactWebAuthnRegistration,
		ArtifactID: response.CeremonyID[:], BrowserHandle: browserHandle,
		FactorKind: mfaauth.CompletionFactorPasskey, FactorID: response.CredentialID,
		SessionSource: completionSessionSource(request.session),
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer reservation.Destroy()
	h.clearMFACookie(w)
	result, err := h.mfa.FinishPasskeyRegistration(r.Context(), mfaauth.FinishPasskeyRegistrationCommand{
		Ticket: ticket, DisplayName: body.DisplayName,
		Response: response, Session: reservation.Reservation,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	session, ok := h.completeReservedSession(w, r, reservation, plan.ResultAuthenticationMethod)
	if !ok {
		return
	}
	mapped := contract.PasskeyRegistrationResult{Session: session}
	mapped.Credential.Id = base64.RawURLEncoding.EncodeToString(result.Apply.Credential.ID)
	mapped.Credential.Discoverable = result.Registration.Discoverable
	mapped.Credential.BackupEligible = result.Registration.BackupEligible
	mapped.Credential.BackedUp = result.Registration.BackedUp
	mapped.Credential.Transports, err = mapWebAuthnTransports(result.Registration.Transports)
	if err != nil {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) StartPasskeyStepUp(w http.ResponseWriter, r *http.Request) {
	request, ok := h.authorizeMFA(w, r, "mfa.passkey.step_up.start")
	if !ok {
		return
	}
	var body contract.MfaStepUpStartRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	artifact, err := h.mfa.StartPasskeyAuthentication(r.Context(), passkeyLookup(
		request, webauthn.PurposeStepUpAuthentication, body.Action,
	))
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

func (h *Handler) CompletePasskeyStepUp(w http.ResponseWriter, r *http.Request) {
	request, ok := h.authorizeMFA(w, r, "mfa.passkey.step_up.finish")
	if !ok {
		return
	}
	browserHandle, err := h.mfaBrowserHandle(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body contract.WebAuthnAuthenticationResponse
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	response, err := decodeWebAuthnAuthenticationResponse(body, browserHandle)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	ticket, plan, reservation, err := h.prepareAndReserveCompletion(r.Context(), mfaauth.CompletionTicketRequest{
		Admission: request.admission, ArtifactKind: mfaauth.CompletionArtifactWebAuthnAuthentication,
		ArtifactID: response.CeremonyID[:], BrowserHandle: browserHandle,
		FactorKind: mfaauth.CompletionFactorPasskey, FactorID: response.CredentialID,
		SessionSource: completionSessionSource(request.session),
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
	session, ok := h.completeReservedSession(w, r, reservation, plan.ResultAuthenticationMethod)
	if !ok {
		return
	}
	writeSensitiveJSON(w, http.StatusOK, session)
}

func (h *Handler) ListMfaDevices(w http.ResponseWriter, r *http.Request, params contract.ListMfaDevicesParams) {
	if !h.requireApplication(w, r) {
		return
	}
	token, err := h.sessionToken(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	session, err := h.authenticateRequest(r, token)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	authority, err := mfaDeviceAuthority(session)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	input := mfaauth.DeviceListInput{}
	if params.Limit != nil {
		input.Limit = *params.Limit
	}
	if params.IncludeRevoked != nil {
		input.IncludeRevoked = *params.IncludeRevoked
	}
	if params.After != nil {
		cursor, decodeErr := decodeMFADeviceCursor(*params.After)
		if decodeErr != nil {
			writeDomainError(w, r, mfaauth.ErrInvalidInput)
			return
		}
		input.After = &cursor
	}
	page, err := h.mfa.ListDevices(r.Context(), authority, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapMFADevicePage(page)
	if err != nil {
		writeDomainError(w, r, mfaauth.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) RenameMfaPasskey(
	w http.ResponseWriter,
	r *http.Request,
	deviceID contract.MfaDeviceId,
	params contract.RenameMfaPasskeyParams,
) {
	request, ok := h.authorizeMFA(w, r, "mfa.passkey.rename")
	if !ok {
		return
	}
	var body contract.MfaPasskeyRenameRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, mfaauth.ErrInvalidInput)
		return
	}
	expected, ok := mfaDevicePrecondition(w, r, params.IfMatch, body.ExpectedVersion)
	if !ok {
		return
	}
	authority, err := mfaDeviceAuthority(request.session)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.mfa.RenamePasskey(
		r.Context(), authority, identity.EntityID(deviceID), body.DisplayName, expected,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeMFADeviceMutation(w, r, result)
}

func (h *Handler) RevokeMfaDevice(
	w http.ResponseWriter,
	r *http.Request,
	deviceID contract.MfaDeviceId,
	params contract.RevokeMfaDeviceParams,
) {
	request, ok := h.authorizeMFA(w, r, "mfa.device.revoke")
	if !ok {
		return
	}
	var body contract.MfaDeviceRevokeRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, mfaauth.ErrInvalidInput)
		return
	}
	expected, ok := mfaDevicePrecondition(w, r, params.IfMatch, body.ExpectedVersion)
	if !ok {
		return
	}
	authority, err := mfaDeviceAuthority(request.session)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	kind := mfaauth.DeviceKind(body.Kind)
	result, err := h.mfa.RevokeDevice(
		r.Context(), authority, identity.EntityID(deviceID), kind, expected,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if result.CurrentSessionRevoked {
		h.clearSessionCookie(w)
	}
	h.writeMFADeviceMutation(w, r, result)
}

func (h *Handler) writeMFADeviceMutation(
	w http.ResponseWriter,
	r *http.Request,
	result mfaauth.DeviceMutationResult,
) {
	mapped, err := mapMFADevice(result.Device)
	if err != nil {
		writeDomainError(w, r, mfaauth.ErrUnavailable)
		return
	}
	etag, err := strongVersionETag(mapped.Version)
	if err != nil {
		writeDomainError(w, r, mfaauth.ErrUnavailable)
		return
	}
	w.Header().Set("ETag", etag)
	writeSensitiveJSON(w, http.StatusOK, contract.MfaDeviceMutationResult{
		Device: mapped, CurrentSessionRevoked: result.CurrentSessionRevoked,
	})
}

func mfaDeviceAuthority(session authentication.Session) (mfaauth.DeviceAuthority, error) {
	if session.ID == uuid.Nil || session.User.ID == uuid.Nil || session.ActiveTenantID == nil ||
		*session.ActiveTenantID == uuid.Nil {
		return mfaauth.DeviceAuthority{}, mfaauth.ErrDenied
	}
	return mfaauth.DeviceAuthority{
		SessionID: identity.EntityID(session.ID), TenantID: identity.EntityID(*session.ActiveTenantID),
		UserID: identity.EntityID(session.User.ID),
	}, nil
}

func mfaDevicePrecondition(
	w http.ResponseWriter,
	r *http.Request,
	ifMatch contract.IfMatch,
	expectedVersion int64,
) (uint64, bool) {
	version, present, err := strongVersionPrecondition(r)
	if !present {
		writeProblem(w, r, http.StatusPreconditionRequired, "precondition_required", "Precondition required", "A current strong If-Match entity tag is required.")
		return 0, false
	}
	canonical, canonicalErr := strongVersionETag(version)
	if err != nil || canonicalErr != nil || strings.TrimSpace(string(ifMatch)) != canonical || expectedVersion != version {
		writeDomainError(w, r, mfaauth.ErrInvalidInput)
		return 0, false
	}
	return uint64(version), true
}

func mapMFADevicePage(page mfaauth.DevicePage) (contract.MfaDeviceList, error) {
	items := make([]contract.MfaDevice, len(page.Items))
	for index, device := range page.Items {
		mapped, err := mapMFADevice(device)
		if err != nil {
			return contract.MfaDeviceList{}, err
		}
		items[index] = mapped
	}
	result := contract.MfaDeviceList{Items: items}
	if page.NextCursor != nil {
		encoded, err := encodeMFADeviceCursor(*page.NextCursor)
		if err != nil {
			return contract.MfaDeviceList{}, err
		}
		result.NextCursor = &encoded
	}
	return result, nil
}

func mapMFADevice(device mfaauth.Device) (contract.MfaDevice, error) {
	if device.Version() == 0 || device.Version() > uint64(maximumResourceVersion) {
		return contract.MfaDevice{}, errors.New("unsupported MFA device version")
	}
	kind := contract.MfaDeviceKind(device.Kind())
	status := contract.MfaDeviceStatus(device.Status())
	if !kind.Valid() || !status.Valid() {
		return contract.MfaDevice{}, errors.New("unsupported MFA device projection")
	}
	transports, err := mapWebAuthnTransports(device.Transports())
	if err != nil {
		return contract.MfaDevice{}, err
	}
	return contract.MfaDevice{
		Id: uuid.UUID(device.ID()), Kind: kind, Status: status,
		DisplayName: device.DisplayName(), Version: int64(device.Version()),
		Discoverable: device.Discoverable(), BackupEligible: device.BackupEligible(),
		BackedUp: device.BackedUp(), Transports: transports, CreatedAt: device.CreatedAt(),
		LastUsedAt: device.LastUsedAt(), RevokedAt: device.RevokedAt(),
	}, nil
}

func encodeMFADeviceCursor(cursor mfaauth.DeviceCursor) (contract.MfaDeviceCursor, error) {
	payload := make([]byte, 18)
	payload[0] = 1
	switch cursor.Kind {
	case mfaauth.DeviceTOTP:
		payload[1] = 1
	case mfaauth.DevicePasskey:
		payload[1] = 2
	default:
		return "", errors.New("unsupported MFA device cursor kind")
	}
	copy(payload[2:], cursor.ID[:])
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeMFADeviceCursor(value contract.MfaDeviceCursor) (mfaauth.DeviceCursor, error) {
	if len(value) != base64.RawURLEncoding.EncodedLen(18) {
		return mfaauth.DeviceCursor{}, errors.New("MFA device cursor length is invalid")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(payload) != 18 || base64.RawURLEncoding.EncodeToString(payload) != value || payload[0] != 1 {
		return mfaauth.DeviceCursor{}, errors.New("MFA device cursor is invalid")
	}
	var kind mfaauth.DeviceKind
	switch payload[1] {
	case 1:
		kind = mfaauth.DeviceTOTP
	case 2:
		kind = mfaauth.DevicePasskey
	default:
		return mfaauth.DeviceCursor{}, errors.New("MFA device cursor kind is invalid")
	}
	var id identity.EntityID
	copy(id[:], payload[2:])
	return mfaauth.DeviceCursor{Kind: kind, ID: id}, nil
}

func mapStepUpMethods(values []mfa.FactorKind) ([]contract.MfaStepUpMethod, error) {
	result := make([]contract.MfaStepUpMethod, len(values))
	for index, value := range values {
		switch value {
		case mfa.FactorTOTP:
			result[index] = contract.MfaStepUpMethodTotp
		case mfa.FactorRecoveryCode:
			result[index] = contract.MfaStepUpMethodRecoveryCode
		default:
			return nil, errors.New("unsupported MFA factor")
		}
	}
	return result, nil
}

func mapStepUpTOTPFactorIDs(
	methods []contract.MfaStepUpMethod,
	values []identity.EntityID,
) ([]uuid.UUID, error) {
	hasTOTP := false
	for _, method := range methods {
		if method == contract.MfaStepUpMethodTotp {
			hasTOTP = true
		}
	}
	if hasTOTP != (len(values) > 0) || len(values) > maximumChallengeTOTPFactors {
		return nil, errors.New("invalid TOTP factor inventory")
	}
	result := make([]uuid.UUID, len(values))
	seen := make(map[uuid.UUID]struct{}, len(values))
	for index, value := range values {
		if !validFederatedEntityID(value) {
			return nil, errors.New("invalid TOTP factor identifier")
		}
		identifier := uuid.UUID(value)
		if _, exists := seen[identifier]; exists {
			return nil, errors.New("duplicate TOTP factor identifier")
		}
		seen[identifier] = struct{}{}
		result[index] = identifier
	}
	return result, nil
}

func mapWebAuthnRegistrationOptions(
	artifact webauthn.StartArtifact,
	user authentication.User,
) (contract.WebAuthnRegistrationOptions, error) {
	timeout, err := webAuthnTimeoutMilliseconds(artifact.ExpiresAt())
	if err != nil {
		return contract.WebAuthnRegistrationOptions{}, err
	}
	residentKey, userVerification, attestation, err := mapWebAuthnCreationPolicy(artifact.Policy())
	if err != nil {
		return contract.WebAuthnRegistrationOptions{}, err
	}
	descriptors := mapCredentialDescriptors(artifact.CredentialIDs())
	result := contract.WebAuthnRegistrationOptions{
		CeremonyId: encodeCeremonyID(artifact.CeremonyID()), ExpiresAt: artifact.ExpiresAt(),
	}
	result.PublicKey.Attestation = attestation
	result.PublicKey.AuthenticatorSelection.RequireResidentKey = artifact.Policy().ResidentKey == webauthn.ResidentKeyRequired
	result.PublicKey.AuthenticatorSelection.ResidentKey = residentKey
	result.PublicKey.AuthenticatorSelection.UserVerification = userVerification
	result.PublicKey.Challenge = base64.RawURLEncoding.EncodeToString(artifact.Challenge())
	result.PublicKey.ExcludeCredentials = descriptors
	result.PublicKey.PubKeyCredParams = []struct {
		Alg  contract.WebAuthnPublicKeyCredentialCreationOptionsPubKeyCredParamsAlg  `json:"alg"`
		Type contract.WebAuthnPublicKeyCredentialCreationOptionsPubKeyCredParamsType `json:"type"`
	}{
		{Alg: contract.Minus7, Type: contract.WebAuthnPublicKeyCredentialCreationOptionsPubKeyCredParamsTypePublicKey},
		{Alg: contract.Minus257, Type: contract.WebAuthnPublicKeyCredentialCreationOptionsPubKeyCredParamsTypePublicKey},
	}
	result.PublicKey.Rp.Id = artifact.RelyingParty().ID()
	result.PublicKey.Rp.Name = contract.WebAuthnPublicKeyCredentialCreationOptionsRpNamePeriapsis
	result.PublicKey.Timeout = timeout
	result.PublicKey.User.Id = base64.RawURLEncoding.EncodeToString(artifact.UserHandle())
	result.PublicKey.User.DisplayName = user.DisplayName
	result.PublicKey.User.Name = user.ID.String()
	if user.Email != nil {
		result.PublicKey.User.Name = *user.Email
	}
	return result, nil
}

func mapWebAuthnAuthenticationOptions(
	artifact webauthn.StartArtifact,
) (contract.WebAuthnAuthenticationOptions, error) {
	timeout, err := webAuthnTimeoutMilliseconds(artifact.ExpiresAt())
	if err != nil {
		return contract.WebAuthnAuthenticationOptions{}, err
	}
	userVerification, err := mapRequestUserVerification(artifact.Policy().UserVerification)
	if err != nil {
		return contract.WebAuthnAuthenticationOptions{}, err
	}
	result := contract.WebAuthnAuthenticationOptions{
		CeremonyId: encodeCeremonyID(artifact.CeremonyID()), ExpiresAt: artifact.ExpiresAt(),
	}
	result.PublicKey.AllowCredentials = mapCredentialDescriptors(artifact.CredentialIDs())
	result.PublicKey.Challenge = base64.RawURLEncoding.EncodeToString(artifact.Challenge())
	result.PublicKey.RpId = artifact.RelyingParty().ID()
	result.PublicKey.Timeout = timeout
	result.PublicKey.UserVerification = userVerification
	return result, nil
}

func mapWebAuthnCreationPolicy(
	policy webauthn.CeremonyPolicy,
) (
	contract.WebAuthnPublicKeyCredentialCreationOptionsAuthenticatorSelectionResidentKey,
	contract.WebAuthnPublicKeyCredentialCreationOptionsAuthenticatorSelectionUserVerification,
	contract.WebAuthnPublicKeyCredentialCreationOptionsAttestation,
	error,
) {
	resident := contract.WebAuthnPublicKeyCredentialCreationOptionsAuthenticatorSelectionResidentKey("")
	switch policy.ResidentKey {
	case webauthn.ResidentKeyPreferred:
		resident = contract.WebAuthnPublicKeyCredentialCreationOptionsAuthenticatorSelectionResidentKeyPreferred
	case webauthn.ResidentKeyRequired:
		resident = contract.WebAuthnPublicKeyCredentialCreationOptionsAuthenticatorSelectionResidentKeyRequired
	default:
		return "", "", "", errors.New("unsupported resident-key policy")
	}
	verification := contract.WebAuthnPublicKeyCredentialCreationOptionsAuthenticatorSelectionUserVerification("")
	switch policy.UserVerification {
	case webauthn.UserVerificationPreferred:
		verification = contract.WebAuthnPublicKeyCredentialCreationOptionsAuthenticatorSelectionUserVerificationPreferred
	case webauthn.UserVerificationRequired:
		verification = contract.WebAuthnPublicKeyCredentialCreationOptionsAuthenticatorSelectionUserVerificationRequired
	default:
		return "", "", "", errors.New("unsupported user-verification policy")
	}
	attestation := contract.WebAuthnPublicKeyCredentialCreationOptionsAttestation("")
	switch policy.Attestation {
	case webauthn.AttestationNone:
		attestation = contract.WebAuthnPublicKeyCredentialCreationOptionsAttestationNone
	case webauthn.AttestationDirect:
		attestation = contract.WebAuthnPublicKeyCredentialCreationOptionsAttestationDirect
	case webauthn.AttestationEnterprise:
		attestation = contract.WebAuthnPublicKeyCredentialCreationOptionsAttestationEnterprise
	default:
		return "", "", "", errors.New("unsupported attestation policy")
	}
	return resident, verification, attestation, nil
}

func mapRequestUserVerification(
	value webauthn.UserVerificationRequirement,
) (contract.WebAuthnPublicKeyCredentialRequestOptionsUserVerification, error) {
	switch value {
	case webauthn.UserVerificationPreferred:
		return contract.WebAuthnPublicKeyCredentialRequestOptionsUserVerificationPreferred, nil
	case webauthn.UserVerificationRequired:
		return contract.WebAuthnPublicKeyCredentialRequestOptionsUserVerificationRequired, nil
	default:
		return "", errors.New("unsupported user-verification policy")
	}
}

func mapCredentialDescriptors(values [][]byte) []contract.WebAuthnCredentialDescriptor {
	result := make([]contract.WebAuthnCredentialDescriptor, len(values))
	for index, value := range values {
		result[index] = contract.WebAuthnCredentialDescriptor{
			Id:   base64.RawURLEncoding.EncodeToString(value),
			Type: contract.WebAuthnCredentialDescriptorTypePublicKey,
		}
	}
	return result
}

func mapWebAuthnTransports(
	values []webauthn.CredentialTransport,
) ([]contract.WebAuthnCredentialTransport, error) {
	result := make([]contract.WebAuthnCredentialTransport, len(values))
	for index, value := range values {
		mapped := contract.WebAuthnCredentialTransport(value)
		if !mapped.Valid() {
			return nil, errors.New("unsupported credential transport")
		}
		result[index] = mapped
	}
	return result, nil
}

func decodeWebAuthnRegistrationResponse(
	value contract.WebAuthnRegistrationResponse,
	browserHandle []byte,
) (webauthn.RegistrationResponse, error) {
	if value.Credential.Type != contract.WebAuthnRegistrationResponseCredentialTypePublicKey {
		return webauthn.RegistrationResponse{}, errors.New("unsupported credential type")
	}
	ceremonyID, err := decodeCeremonyID(value.CeremonyId)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	credentialID, err := decodeWebAuthnBinary(value.Credential.Id, 1, maximumWebAuthnCredentialIDBytes)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	clientData, err := decodeWebAuthnBinary(value.Credential.Response.ClientDataJSON, 1, maximumWebAuthnBinaryBytes)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	attestation, err := decodeWebAuthnBinary(value.Credential.Response.AttestationObject, 1, maximumWebAuthnBinaryBytes)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	extensions, err := json.Marshal(value.Credential.ClientExtensionResults)
	if err != nil || len(extensions) > maximumClientExtensionsBytes ||
		webAuthnMaterialSize(credentialID, clientData, attestation, extensions) > maximumWebAuthnBinaryBytes {
		clear(credentialID)
		clear(clientData)
		clear(attestation)
		clear(extensions)
		return webauthn.RegistrationResponse{}, errors.New("client extension results are invalid")
	}
	transports := make([]webauthn.CredentialTransport, len(value.Credential.Response.Transports))
	for index, transport := range value.Credential.Response.Transports {
		if !transport.Valid() {
			return webauthn.RegistrationResponse{}, errors.New("credential transport is invalid")
		}
		transports[index] = webauthn.CredentialTransport(transport)
	}
	return webauthn.RegistrationResponse{
		CeremonyID: ceremonyID, BrowserHandle: append([]byte(nil), browserHandle...),
		CredentialID: credentialID, ClientDataJSON: clientData, AttestationObject: attestation,
		ClientExtensionResults: extensions, Transports: transports,
	}, nil
}

func decodeWebAuthnAuthenticationResponse(
	value contract.WebAuthnAuthenticationResponse,
	browserHandle []byte,
) (webauthn.AuthenticationResponse, error) {
	if value.Credential.Type != contract.WebAuthnAuthenticationResponseCredentialTypePublicKey {
		return webauthn.AuthenticationResponse{}, errors.New("unsupported credential type")
	}
	ceremonyID, err := decodeCeremonyID(value.CeremonyId)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	credentialID, err := decodeWebAuthnBinary(value.Credential.Id, 1, maximumWebAuthnCredentialIDBytes)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	clientData, err := decodeWebAuthnBinary(value.Credential.Response.ClientDataJSON, 1, maximumWebAuthnBinaryBytes)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	authenticatorData, err := decodeWebAuthnBinary(value.Credential.Response.AuthenticatorData, 1, maximumWebAuthnBinaryBytes)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	signature, err := decodeWebAuthnBinary(value.Credential.Response.Signature, 1, maximumWebAuthnBinaryBytes)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	var userHandle []byte
	if value.Credential.Response.UserHandle != nil {
		userHandle, err = decodeWebAuthnBinary(*value.Credential.Response.UserHandle, 32, 32)
		if err != nil {
			return webauthn.AuthenticationResponse{}, err
		}
	}
	if webAuthnMaterialSize(credentialID, clientData, authenticatorData, signature, userHandle) > maximumWebAuthnBinaryBytes {
		clear(credentialID)
		clear(clientData)
		clear(authenticatorData)
		clear(signature)
		clear(userHandle)
		return webauthn.AuthenticationResponse{}, errors.New("WebAuthn response exceeds the configured aggregate bound")
	}
	return webauthn.AuthenticationResponse{
		CeremonyID: ceremonyID, BrowserHandle: append([]byte(nil), browserHandle...),
		CredentialID: credentialID, ClientDataJSON: clientData, AuthenticatorData: authenticatorData,
		Signature: signature, UserHandle: userHandle,
	}, nil
}

func webAuthnMaterialSize(values ...[]byte) int {
	total := 0
	for _, value := range values {
		if len(value) > maximumWebAuthnBinaryBytes-total {
			return maximumWebAuthnBinaryBytes + 1
		}
		total += len(value)
	}
	return total
}

func decodeWebAuthnBinary(value string, minimum, maximum int) ([]byte, error) {
	if len(value) == 0 || len(value) > base64.RawURLEncoding.EncodedLen(maximum) {
		return nil, errors.New("WebAuthn binary is outside bounds")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) < minimum || len(decoded) > maximum ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, errors.New("WebAuthn binary is not canonical base64url")
	}
	return decoded, nil
}

func decodeCeremonyID(value string) (webauthn.CeremonyID, error) {
	decoded, err := decodeWebAuthnBinary(value, 32, 32)
	if err != nil {
		return webauthn.CeremonyID{}, err
	}
	defer clear(decoded)
	var result webauthn.CeremonyID
	copy(result[:], decoded)
	if result == (webauthn.CeremonyID{}) {
		return webauthn.CeremonyID{}, errors.New("WebAuthn ceremony ID must not be zero")
	}
	return result, nil
}

func decodeChallengeID(value string) (mfa.ChallengeID, error) {
	decoded, err := decodeWebAuthnBinary(value, 32, 32)
	if err != nil {
		return mfa.ChallengeID{}, err
	}
	defer clear(decoded)
	var result mfa.ChallengeID
	copy(result[:], decoded)
	if result == (mfa.ChallengeID{}) {
		return mfa.ChallengeID{}, errors.New("MFA challenge ID must not be zero")
	}
	return result, nil
}

func encodeCeremonyID(value webauthn.CeremonyID) string {
	return base64.RawURLEncoding.EncodeToString(value[:])
}

func encodeChallengeID(value mfa.ChallengeID) string {
	return base64.RawURLEncoding.EncodeToString(value[:])
}

func ceremonyPrincipal(value webauthn.CeremonyID) identity.EntityID {
	var result identity.EntityID
	copy(result[:], value[:len(result)])
	return result
}

func webAuthnTimeoutMilliseconds(expiresAt time.Time) (int, error) {
	remaining := time.Until(expiresAt)
	if remaining <= 0 || remaining > 10*time.Minute {
		return 0, errors.New("WebAuthn expiry is invalid")
	}
	value := int(math.Ceil(float64(remaining) / float64(time.Millisecond)))
	if value < 1 {
		value = 1
	}
	return value, nil
}
