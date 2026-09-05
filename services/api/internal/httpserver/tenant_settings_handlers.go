package httpserver

import (
	"errors"
	"math"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/tenantsettings"
)

func (h *Handler) GetTenantSettings(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
) {
	session, ok := h.platformIdentityProviderSession(w, r, false)
	if !ok {
		return
	}

	targetTenantID := uuid.UUID(tenantID)
	settings, err := h.tenantSettings.Get(r.Context(), session, targetTenantID)
	if err != nil {
		h.writeTenantSettingsError(w, r, err)
		return
	}
	response, err := mapTenantSettings(settings, targetTenantID)
	if err != nil || !setVersionETag(w, int64(settings.Version)) {
		h.writeTenantSettingsError(w, r, tenantsettings.ErrUnavailable)
		return
	}
	writeTenantSettingsJSON(w, http.StatusOK, response)
}

func (h *Handler) UpdateTenantSettings(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.UpdateTenantSettingsParams,
) {
	session, ok := h.platformIdentityProviderSession(w, r, true)
	if !ok {
		return
	}

	var body contract.TenantSettingsUpdateRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeTenantSettingsError(w, r, tenantsettings.ErrInvalidInput)
		return
	}
	expectedVersion, ok := tenantSettingsPrecondition(
		w,
		r,
		params.IfMatch,
		body.ExpectedVersion,
	)
	if !ok {
		return
	}
	reason, err := tenantSettingsAuditReason(r, params.XAuditReason)
	if err != nil {
		h.writeTenantSettingsError(w, r, err)
		return
	}
	event, err := h.eventContext(r)
	if err != nil {
		h.writeTenantSettingsError(w, r, tenantsettings.ErrInvalidInput)
		return
	}

	targetTenantID := uuid.UUID(tenantID)
	settings, err := h.tenantSettings.Update(r.Context(), session, targetTenantID, tenantsettings.UpdateInput{
		ExpectedVersion: expectedVersion,
		BrandName:       body.BrandName,
		BrandMark:       body.BrandMark,
		PrimaryColor:    body.PrimaryColor,
		AccentColor:     body.AccentColor,
		Timezone:        body.Timezone,
		Locale:          body.Locale,
		Reason:          reason,
		Event:           event,
	})
	if err != nil {
		h.writeTenantSettingsError(w, r, err)
		return
	}
	response, err := mapTenantSettings(settings, targetTenantID)
	if err != nil || settings.Version != expectedVersion+1 ||
		!setVersionETag(w, int64(settings.Version)) {
		h.writeTenantSettingsError(w, r, tenantsettings.ErrUnavailable)
		return
	}
	writeTenantSettingsJSON(w, http.StatusOK, response)
}

func tenantSettingsPrecondition(
	w http.ResponseWriter,
	r *http.Request,
	contractValue contract.IfMatch,
	bodyVersion int32,
) (int32, bool) {
	version, present, err := strongVersionPrecondition(r)
	if !present {
		w.Header().Set("Cache-Control", "no-store")
		writeProblem(
			w,
			r,
			http.StatusPreconditionRequired,
			"precondition_required",
			"Precondition required",
			"A current strong If-Match entity tag is required.",
		)
		return 0, false
	}
	canonical, canonicalErr := strongVersionETag(version)
	if err != nil || canonicalErr != nil || canonical != string(contractValue) ||
		int64(bodyVersion) != version || version < 1 || version >= math.MaxInt32 {
		writeTenantSettingsDomainError(w, r, tenantsettings.ErrInvalidInput)
		return 0, false
	}
	return int32(version), true
}

func tenantSettingsAuditReason(
	r *http.Request,
	contractValue contract.TenantSettingsAuditReason,
) (string, error) {
	reason, err := singleHeader(r, "X-Audit-Reason", 500)
	if err != nil || reason != string(contractValue) ||
		!platformIdentityProviderAuditReasonIsHTTPValue(reason) {
		return "", tenantsettings.ErrInvalidInput
	}
	return reason, nil
}

func mapTenantSettings(
	settings tenantsettings.Settings,
	tenantID uuid.UUID,
) (contract.TenantSettings, error) {
	if tenantID == uuid.Nil || settings.TenantID != tenantID || settings.Version < 1 ||
		settings.UpdatedAt.IsZero() || strings.TrimSpace(settings.BrandName) == "" ||
		strings.TrimSpace(settings.BrandMark) == "" || strings.TrimSpace(settings.PrimaryColor) == "" ||
		strings.TrimSpace(settings.AccentColor) == "" || strings.TrimSpace(settings.Timezone) == "" ||
		strings.TrimSpace(settings.Locale) == "" {
		return contract.TenantSettings{}, tenantsettings.ErrUnavailable
	}
	return contract.TenantSettings{
		TenantId:     settings.TenantID,
		BrandName:    settings.BrandName,
		BrandMark:    settings.BrandMark,
		PrimaryColor: settings.PrimaryColor,
		AccentColor:  settings.AccentColor,
		Timezone:     settings.Timezone,
		Locale:       settings.Locale,
		Version:      contract.ResourceVersion(settings.Version),
		UpdatedAt:    settings.UpdatedAt,
	}, nil
}

func writeTenantSettingsJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, status, value)
}

func (h *Handler) writeTenantSettingsError(w http.ResponseWriter, r *http.Request, err error) {
	writeTenantSettingsDomainError(w, r, err)
}

func writeTenantSettingsDomainError(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case errors.Is(err, tenantsettings.ErrInvalidInput):
		writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The request is malformed or fails bounded validation.")
	case errors.Is(err, tenantsettings.ErrForbidden), errors.Is(err, authentication.ErrForbidden):
		writeProblem(w, r, http.StatusForbidden, "forbidden", "Forbidden", "The action is not permitted.")
	case errors.Is(err, tenantsettings.ErrNotFound):
		writeProblem(w, r, http.StatusNotFound, "not_found", "Resource not found", "The requested resource does not exist.")
	case errors.Is(err, tenantsettings.ErrConflict):
		writeProblem(w, r, http.StatusPreconditionFailed, "precondition_failed", "Precondition failed", "The tenant settings changed after the supplied entity tag was issued.")
	case errors.Is(err, tenantsettings.ErrUnavailable):
		w.Header().Set("Retry-After", "5")
		writeProblem(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable", "A required protected dependency is unavailable.")
	default:
		writeProblem(w, r, http.StatusInternalServerError, "internal_error", "Internal server error", "The request could not be completed.")
	}
}
