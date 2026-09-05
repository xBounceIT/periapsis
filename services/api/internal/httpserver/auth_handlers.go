package httpserver

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	applicationcontacts "github.com/periapsis-im/periapsis/services/api/internal/contacts"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationcustomfieldimport "github.com/periapsis-im/periapsis/services/api/internal/customfieldimport"
	applicationcustomfields "github.com/periapsis-im/periapsis/services/api/internal/customfields"
	applicationdfir "github.com/periapsis-im/periapsis/services/api/internal/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
	"github.com/periapsis-im/periapsis/services/api/internal/notification"
	"github.com/periapsis-im/periapsis/services/api/internal/notificationinbox"
	"github.com/periapsis-im/periapsis/services/api/internal/platform"
	"github.com/periapsis-im/periapsis/services/api/internal/securityaudit"
	"github.com/periapsis-im/periapsis/services/api/internal/sessionlogout"
	applicationsla "github.com/periapsis-im/periapsis/services/api/internal/sla"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

const (
	logoutContinuationPathPrefix = "/api/v1/auth/logout/continuations/"
	maximumLogoutContinuationTTL = 2 * time.Minute
)

func (h *Handler) GetBootstrapStatus(w http.ResponseWriter, r *http.Request) {
	if !h.requireApplication(w, r) {
		return
	}
	available, err := h.authentication.BootstrapStatus(r.Context())
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, contract.BootstrapStatus{Available: available})
}

func (h *Handler) StartBootstrapEnrollment(w http.ResponseWriter, r *http.Request) {
	if !h.requireApplication(w, r) {
		return
	}
	authority, err := singleHeader(r, bootstrapTokenHeader, 1024)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidAuthentication)
		return
	}
	var body contract.BootstrapEnrollmentRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	enrollment, err := h.authentication.StartBootstrap(r.Context(), authority, string(body.Email), event)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeSensitiveJSON(w, http.StatusCreated, contract.BootstrapEnrollment{
		EnrollmentToken: enrollment.EnrollmentToken, ExpiresAt: enrollment.ExpiresAt,
		TotpSecret: enrollment.TOTPSecret, TotpUri: enrollment.TOTPURI,
	})
}

func (h *Handler) ConfirmBootstrap(w http.ResponseWriter, r *http.Request) {
	if !h.requireApplication(w, r) {
		return
	}
	authority, err := singleHeader(r, bootstrapTokenHeader, 1024)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidAuthentication)
		return
	}
	var body contract.BootstrapConfirmationRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	result, err := h.authentication.ConfirmBootstrap(r.Context(), authority, authentication.BootstrapConfirmation{
		EnrollmentToken: body.EnrollmentToken, Email: string(body.Email), DisplayName: body.DisplayName,
		Password: body.Password, Code: body.Code, Event: event,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	session, err := mapSession(result.Credential.Session, result.Credential.CSRFToken)
	if err != nil {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	h.setSessionCookie(w, result.Credential.SessionToken, result.Credential.Session.AbsoluteExpiresAt)
	writeSensitiveJSON(w, http.StatusCreated, contract.BootstrapResult{
		RecoveryCodes: result.RecoveryCodes,
		Session:       session,
	})
}

func (h *Handler) StartPasswordLogin(w http.ResponseWriter, r *http.Request) {
	if !h.requireApplication(w, r) {
		return
	}
	var body contract.PasswordLoginRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	challenge, err := h.authentication.StartPasswordLogin(r.Context(), string(body.Email), body.Password, event)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	methods := make([]contract.MfaMethod, 0, len(challenge.Methods))
	for _, method := range challenge.Methods {
		mapped := contract.MfaMethod(method)
		if !mapped.Valid() {
			writeDomainError(w, r, authentication.ErrUnavailable)
			return
		}
		methods = append(methods, mapped)
	}
	writeSensitiveJSON(w, http.StatusAccepted, contract.MfaChallenge{
		ChallengeToken: challenge.ChallengeToken, ExpiresAt: challenge.ExpiresAt, Methods: methods,
	})
}

func (h *Handler) CompleteMfaChallenge(w http.ResponseWriter, r *http.Request) {
	if !h.requireApplication(w, r) {
		return
	}
	var body contract.MfaCompletionRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	credential, err := h.authentication.CompleteMFA(
		r.Context(), body.ChallengeToken, string(body.Method), body.Code, event,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	session, err := mapSession(credential.Session, credential.CSRFToken)
	if err != nil {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	h.setSessionCookie(w, credential.SessionToken, credential.Session.AbsoluteExpiresAt)
	writeSensitiveJSON(w, http.StatusOK, session)
}

func (h *Handler) GetCurrentSession(w http.ResponseWriter, r *http.Request) {
	if !h.requireApplication(w, r) {
		return
	}
	token, err := h.sessionToken(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	credential, err := h.authentication.CurrentSession(r.Context(), token)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	session, err := mapSession(credential.Session, credential.CSRFToken)
	if err != nil {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, session)
}

func (h *Handler) LogoutCurrentSession(w http.ResponseWriter, r *http.Request) {
	if !h.prepareCookieMutation(w, r) {
		return
	}
	token, err := h.sessionToken(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	csrf, err := singleHeader(r, csrfTokenHeader, 128)
	if err != nil {
		writeDomainError(w, r, authentication.ErrForbidden)
		return
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	result, err := h.sessionLogout.Logout(r.Context(), token, csrf, sessionlogout.EventContext{
		RequestID: identity.EntityID(event.RequestID), CorrelationID: identity.EntityID(event.CorrelationID),
		RemoteAddress: event.RemoteAddress, UserAgent: event.UserAgent,
	})
	if err != nil {
		writeSessionLogoutError(w, r, err)
		return
	}
	if result.Continuation != nil {
		defer result.Continuation.Destroy()
	}
	if !result.LocalRevoked {
		writeSessionLogoutError(w, r, sessionlogout.ErrUnavailable)
		return
	}
	h.clearSessionCookie(w)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if result.Continuation == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	continuationID, credential, expiresAt, lifetime, ok := result.Continuation.TakeWithLifetime()
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	defer clear(credential)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := setLogoutContinuationCookie(
		w, h.logoutContinuationCookie, continuationID, credential, expiresAt, lifetime, now,
	); err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, struct {
		ContinuationURL string `json:"continuationUrl"`
	}{ContinuationURL: logoutContinuationPath(continuationID)})
}

// ContinueLogout consumes the HttpOnly browser proof before projecting any
// protocol material. Every public outcome is the same no-store 303 shape, so
// unknown, expired, replayed, and unavailable continuations are non-oracular.
func (h *Handler) ContinueLogout(
	w http.ResponseWriter,
	r *http.Request,
	continuationIDValue contract.LogoutContinuationId,
) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	location := h.publicOrigin + "/signed-out"
	rawContinuationID := string(continuationIDValue)
	identifier, err := uuid.Parse(rawContinuationID)
	if err == nil && identifier.String() == rawContinuationID {
		continuationID := identity.EntityID(identifier)
		if validFederatedEntityID(continuationID) {
			credential, credentialErr := logoutContinuationCredential(
				r, h.logoutContinuationCookie, continuationID,
			)
			clearLogoutContinuationCookie(w, h.logoutContinuationCookie, continuationID)
			if credentialErr == nil {
				redirect, continueErr := h.sessionLogout.Continue(r.Context(), continuationID, credential)
				clear(credential)
				if continueErr == nil && validFederatedIdPRedirect(redirect, maximumSAMLRedirectBytes) {
					location = redirect
				}
			}
		}
	}
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusSeeOther)
}

func writeSessionLogoutError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, sessionlogout.ErrInvalidInput):
		writeDomainError(w, r, authentication.ErrInvalidInput)
	case errors.Is(err, sessionlogout.ErrInvalidAuthentication), errors.Is(err, sessionlogout.ErrNotFound):
		writeDomainError(w, r, authentication.ErrInvalidAuthentication)
	case errors.Is(err, sessionlogout.ErrForbidden):
		writeDomainError(w, r, authentication.ErrForbidden)
	default:
		writeDomainError(w, r, authentication.ErrUnavailable)
	}
}

func logoutContinuationPath(continuationID identity.EntityID) string {
	if !validFederatedEntityID(continuationID) {
		return ""
	}
	return logoutContinuationPathPrefix + uuid.UUID(continuationID).String()
}

func (h *Handler) ListSessions(w http.ResponseWriter, r *http.Request, params contract.ListSessionsParams) {
	if !h.requireApplication(w, r) {
		return
	}
	token, err := h.sessionToken(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	limit := 0
	if params.Limit != nil {
		limit = *params.Limit
	}
	var after *uuid.UUID
	if params.After != nil {
		value := uuid.UUID(*params.After)
		after = &value
	}
	page, err := h.authentication.Sessions(r.Context(), token, after, limit)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.SessionSummary, 0, len(page.Items))
	for _, session := range page.Items {
		method := contract.SessionAuthenticationMethod(session.AuthenticationMethod)
		if !method.Valid() {
			writeDomainError(w, r, authentication.ErrUnavailable)
			return
		}
		items = append(items, contract.SessionSummary{
			Id: session.ID, Current: session.Current, CreatedAt: session.CreatedAt,
			LastSeenAt: session.LastSeenAt, IdleExpiresAt: session.IdleExpiresAt,
			AbsoluteExpiresAt: session.AbsoluteExpiresAt, RevokedAt: session.RevokedAt,
			AuthenticationMethod: method,
		})
	}
	writeSensitiveJSON(w, http.StatusOK, contract.SessionList{Items: items, NextCursor: page.NextCursor})
}

func (h *Handler) RevokeSession(w http.ResponseWriter, r *http.Request, sessionID contract.SessionId) {
	if !h.prepareCookieMutation(w, r) {
		return
	}
	token, err := h.sessionToken(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	csrf, err := singleHeader(r, csrfTokenHeader, 128)
	if err != nil {
		writeDomainError(w, r, authentication.ErrForbidden)
		return
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	if err := h.authentication.RevokeSession(r.Context(), token, csrf, uuid.UUID(sessionID), event); err != nil {
		writeDomainError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListTenantMemberships(
	w http.ResponseWriter,
	r *http.Request,
	params contract.ListTenantMembershipsParams,
) {
	if !h.requireApplication(w, r) {
		return
	}
	token, err := h.sessionToken(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	limit := 0
	if params.Limit != nil {
		limit = *params.Limit
	}
	var after *uuid.UUID
	if params.After != nil {
		value := uuid.UUID(*params.After)
		after = &value
	}
	page, err := h.authentication.TenantMemberships(r.Context(), token, after, limit)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.TenantMembershipSummary, 0, len(page.Items))
	for _, membership := range page.Items {
		tenant, mapErr := mapTenant(membership.Tenant)
		role := contract.TenantMembershipSummaryRole(membership.Role)
		if mapErr != nil || !role.Valid() {
			writeDomainError(w, r, authentication.ErrUnavailable)
			return
		}
		items = append(items, contract.TenantMembershipSummary{
			MembershipId: membership.ID, Role: role, Tenant: tenant,
		})
	}
	writeSensitiveJSON(w, http.StatusOK, contract.TenantMembershipList{Items: items, NextCursor: page.NextCursor})
}

func (h *Handler) SwitchActiveTenant(w http.ResponseWriter, r *http.Request) {
	if !h.prepareCookieMutation(w, r) {
		return
	}
	var body contract.TenantSwitchRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	token, err := h.sessionToken(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	csrf, err := singleHeader(r, csrfTokenHeader, 128)
	if err != nil {
		writeDomainError(w, r, authentication.ErrForbidden)
		return
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	credential, err := h.authentication.SwitchTenant(r.Context(), token, csrf, uuid.UUID(body.TenantId), event)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	session, err := mapSession(credential.Session, credential.CSRFToken)
	if err != nil {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	if credential.SessionToken != token {
		h.setSessionCookie(w, credential.SessionToken, credential.Session.AbsoluteExpiresAt)
	}
	writeSensitiveJSON(w, http.StatusOK, session)
}

func (h *Handler) ListPlatformTenants(w http.ResponseWriter, r *http.Request, params contract.ListPlatformTenantsParams) {
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
	limit := 0
	if params.Limit != nil {
		limit = *params.Limit
	}
	var after *uuid.UUID
	if params.After != nil {
		value := uuid.UUID(*params.After)
		after = &value
	}
	page, err := h.platform.ListTenants(r.Context(), session, after, limit)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.TenantSummary, 0, len(page.Items))
	for _, item := range page.Items {
		mapped, mapErr := mapTenant(item)
		if mapErr != nil {
			writeDomainError(w, r, authentication.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	writeSensitiveJSON(w, http.StatusOK, contract.TenantList{Items: items, NextCursor: page.NextCursor})
}

func (h *Handler) CreatePlatformTenant(w http.ResponseWriter, r *http.Request) {
	if !h.prepareCookieMutation(w, r) {
		return
	}
	var body contract.TenantCreateRequest
	if err := decodeJSONBody(r, &body); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	token, err := h.sessionToken(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	csrf, err := singleHeader(r, csrfTokenHeader, 128)
	if err != nil {
		writeDomainError(w, r, authentication.ErrForbidden)
		return
	}
	session, err := h.authenticateRequest(r, token)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if err := h.authentication.ValidateCSRF(session, csrf); err != nil {
		writeDomainError(w, r, err)
		return
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	tenant, err := h.platform.CreateTenant(r.Context(), session, platform.CreateTenantInput{
		Slug: body.Slug, Name: body.Name, Timezone: body.Timezone, Locale: body.Locale, Event: event,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTenant(tenant)
	if err != nil {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) requireApplication(w http.ResponseWriter, r *http.Request) bool {
	if h.alerts == nil || h.audit == nil || h.authentication == nil || h.authorization == nil || h.operatorTeams == nil ||
		h.identityProviders == nil || h.ldapAdministration == nil || h.mfa == nil || h.platform == nil || h.serviceAccounts == nil {
		writeDomainError(w, r, authentication.ErrUnavailable)
		return false
	}
	return true
}

func (h *Handler) prepareCookieMutation(w http.ResponseWriter, r *http.Request) bool {
	if !h.requireApplication(w, r) {
		return false
	}
	if err := h.requireSameOrigin(r); err != nil {
		writeDomainError(w, r, err)
		return false
	}
	return true
}

func decodeJSONBody(r *http.Request, destination any) error {
	if err := requireJSON(r); err != nil {
		return err
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func mapSession(session authentication.Session, csrfToken string) (contract.Session, error) {
	permissions := make([]contract.PlatformPermission, 0, len(session.Permissions))
	for _, permission := range session.Permissions {
		mapped := contract.PlatformPermission(permission)
		if !mapped.Valid() {
			return contract.Session{}, errors.New("unsupported platform permission")
		}
		permissions = append(permissions, mapped)
	}
	user := contract.AuthenticatedUser{Id: session.User.ID, DisplayName: session.User.DisplayName}
	if session.User.Email != nil {
		email := openapi_types.Email(*session.User.Email)
		user.Email = &email
	}
	authenticationMethod := contract.SessionAuthenticationMethod(session.AuthenticationMethod)
	if !authenticationMethod.Valid() {
		return contract.Session{}, errors.New("unsupported session authentication method")
	}
	return contract.Session{
		Id:                   session.ID,
		User:                 user,
		AuthenticationMethod: authenticationMethod,
		CsrfToken:            csrfToken, Permissions: permissions, ActiveTenantId: session.ActiveTenantID,
		CreatedAt: session.CreatedAt, LastSeenAt: session.LastSeenAt,
		IdleExpiresAt: session.IdleExpiresAt, AbsoluteExpiresAt: session.AbsoluteExpiresAt,
	}, nil
}

func mapTenant(tenant authentication.Tenant) (contract.TenantSummary, error) {
	status := contract.TenantSummaryStatus(tenant.Status)
	if !status.Valid() {
		return contract.TenantSummary{}, errors.New("unsupported tenant status")
	}
	mapped := contract.TenantSummary{
		Id: tenant.ID, Slug: tenant.Slug, Name: tenant.Name, Status: status,
		Timezone: tenant.Timezone, Locale: tenant.Locale,
		CreatedAt: tenant.CreatedAt, UpdatedAt: tenant.UpdatedAt,
	}
	if tenant.Version < 0 {
		return contract.TenantSummary{}, errors.New("invalid tenant version")
	}
	if tenant.Version > 0 {
		version := contract.ResourceVersion(tenant.Version)
		mapped.Version = &version
	}
	return mapped, nil
}

func writeSensitiveJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, value)
}

func writeDomainError(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Cache-Control", "no-store")
	if writeFederatedSessionTransition(w, r, err) {
		return
	}
	var rateLimit *authentication.RateLimitError
	if errors.As(err, &rateLimit) {
		retryAfter := int(math.Ceil(rateLimit.RetryAfter.Seconds()))
		if retryAfter < 1 {
			retryAfter = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeProblem(w, r, http.StatusTooManyRequests, "rate_limited", "Too many requests", "Authentication is temporarily throttled.")
		return
	}
	var mfaRateLimit *mfaauth.RateLimitError
	if errors.As(err, &mfaRateLimit) {
		retryAfter := int(math.Ceil(mfaRateLimit.RetryAfter().Seconds()))
		if retryAfter < 1 {
			retryAfter = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeProblem(w, r, http.StatusTooManyRequests, "rate_limited", "Too many requests", "MFA verification is temporarily throttled.")
		return
	}
	switch {
	case errors.Is(err, notification.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		writeProblem(w, r, http.StatusTooManyRequests, "rate_limited", "Too many requests", "Notification administration is temporarily throttled.")
	case errors.Is(err, identityprovider.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		writeProblem(w, r, http.StatusTooManyRequests, "rate_limited", "Too many requests", "LDAP diagnostics are temporarily throttled.")
	case errors.Is(err, authentication.ErrInvalidInput), errors.Is(err, mfaauth.ErrInvalidInput), errors.Is(err, authorization.ErrInvalidInput), errors.Is(err, identityprovider.ErrInvalidInput), errors.Is(err, notification.ErrInvalidInput), errors.Is(err, notificationinbox.ErrInvalidInput), errors.Is(err, applicationcontacts.ErrInvalidInput), errors.Is(err, applicationcustomfieldimport.ErrInvalidInput), errors.Is(err, applicationcustomfields.ErrInvalidInput), errors.Is(err, applicationdfir.ErrInvalidInput), errors.Is(err, applicationsla.ErrInvalidInput), errors.Is(err, applicationticketing.ErrInvalidInput), errors.Is(err, securityaudit.ErrInvalidInput):
		writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The request is malformed or fails bounded validation.")
	case errors.Is(err, authentication.ErrInvalidAuthentication), errors.Is(err, mfaauth.ErrAuthentication):
		writeProblem(w, r, http.StatusUnauthorized, "authentication_failed", "Authentication failed", "Authentication could not be completed.")
	case errors.Is(err, authentication.ErrForbidden), errors.Is(err, mfaauth.ErrDenied), errors.Is(err, authorization.ErrDenied), errors.Is(err, authorization.ErrForbidden), errors.Is(err, identityprovider.ErrForbidden), errors.Is(err, notification.ErrForbidden), errors.Is(err, notificationinbox.ErrForbidden), errors.Is(err, applicationcontacts.ErrForbidden), errors.Is(err, applicationcustomfieldimport.ErrForbidden), errors.Is(err, applicationcustomfields.ErrForbidden), errors.Is(err, applicationdfir.ErrForbidden), errors.Is(err, applicationsla.ErrForbidden), errors.Is(err, applicationticketing.ErrForbidden), errors.Is(err, securityaudit.ErrForbidden):
		writeProblem(w, r, http.StatusForbidden, "forbidden", "Forbidden", "The action is not permitted.")
	case errors.Is(err, mfaauth.ErrNotFound), errors.Is(err, authorization.ErrNotFound), errors.Is(err, identityprovider.ErrNotFound), errors.Is(err, notification.ErrNotFound), errors.Is(err, notificationinbox.ErrNotFound), errors.Is(err, applicationcontacts.ErrNotFound), errors.Is(err, applicationcustomfieldimport.ErrNotFound), errors.Is(err, applicationcustomfields.ErrNotFound), errors.Is(err, applicationdfir.ErrNotFound), errors.Is(err, applicationsla.ErrNotFound), errors.Is(err, applicationticketing.ErrNotFound):
		writeProblem(w, r, http.StatusNotFound, "not_found", "Resource not found", "The requested resource does not exist.")
	case errors.Is(err, authentication.ErrConflict), errors.Is(err, mfaauth.ErrConflict), errors.Is(err, authorization.ErrConflict), errors.Is(err, identityprovider.ErrConflict), errors.Is(err, notification.ErrConflict), errors.Is(err, notificationinbox.ErrConflict), errors.Is(err, applicationcontacts.ErrConflict), errors.Is(err, applicationcustomfieldimport.ErrConflict), errors.Is(err, applicationcustomfields.ErrConflict), errors.Is(err, applicationdfir.ErrConflict), errors.Is(err, applicationsla.ErrConflict), errors.Is(err, applicationticketing.ErrConflict):
		writeProblem(w, r, http.StatusConflict, "conflict", "Conflict", "The request conflicts with current state.")
	case errors.Is(err, mfaauth.ErrPrecondition), errors.Is(err, authorization.ErrPreconditionFailed), errors.Is(err, identityprovider.ErrPreconditionFailed), errors.Is(err, notification.ErrPreconditionFailed), errors.Is(err, notificationinbox.ErrPreconditionFailed), errors.Is(err, applicationcontacts.ErrPreconditionFailed), errors.Is(err, applicationcustomfieldimport.ErrPreconditionFailed), errors.Is(err, applicationcustomfields.ErrPreconditionFailed), errors.Is(err, applicationdfir.ErrPreconditionFailed), errors.Is(err, applicationsla.ErrPreconditionFailed), errors.Is(err, applicationticketing.ErrPreconditionFailed):
		writeProblem(w, r, http.StatusPreconditionFailed, "precondition_failed", "Precondition failed", "The resource changed after the supplied entity tag was issued.")
	case errors.Is(err, authorization.ErrPreconditionRequired), errors.Is(err, identityprovider.ErrPreconditionRequired), errors.Is(err, notification.ErrPreconditionRequired):
		writeProblem(w, r, http.StatusPreconditionRequired, "precondition_required", "Precondition required", "A current strong If-Match entity tag is required.")
	case errors.Is(err, authentication.ErrUnavailable), errors.Is(err, mfaauth.ErrUnavailable), errors.Is(err, authorization.ErrUnavailable), errors.Is(err, identityprovider.ErrUnavailable), errors.Is(err, notification.ErrUnavailable), errors.Is(err, notificationinbox.ErrUnavailable), errors.Is(err, applicationcontacts.ErrUnavailable), errors.Is(err, applicationcustomfieldimport.ErrUnavailable), errors.Is(err, applicationcustomfields.ErrUnavailable), errors.Is(err, applicationdfir.ErrUnavailable), errors.Is(err, applicationsla.ErrUnavailable), errors.Is(err, applicationticketing.ErrUnavailable), errors.Is(err, securityaudit.ErrUnavailable):
		w.Header().Set("Retry-After", "5")
		writeProblem(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable", "A required protected dependency is unavailable.")
	default:
		writeProblem(w, r, http.StatusInternalServerError, "internal_error", "Internal server error", "The request could not be completed.")
	}
}
