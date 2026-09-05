package httpserver

import (
	"net/http"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

// GetTenant is the compatibility resource at the tenant collection URI. Keep
// its behavior on the same use-case boundary as the canonical settings read so
// both paths re-resolve live membership and return the same safe projection.
func (h *Handler) GetTenant(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
) {
	h.GetTenantSettings(w, r, tenantID)
}

// ListTenantCustomFields is the compatibility alias required by the public API
// surface. The canonical resource remains custom-field-definitions.
func (h *Handler) ListTenantCustomFields(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantCustomFieldsParams,
) {
	h.ListTenantCustomFieldDefinitions(w, r, tenantID, contract.ListTenantCustomFieldDefinitionsParams{
		ObjectType:      params.ObjectType,
		IncludeArchived: params.IncludeArchived,
		Limit:           params.Limit,
		After:           params.After,
	})
}

// CreateTenantCustomField is the compatibility alias required by the public
// API surface. Creation still returns the canonical definition URI in Location.
func (h *Handler) CreateTenantCustomField(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.CreateTenantCustomFieldParams,
) {
	h.CreateTenantCustomFieldDefinition(w, r, tenantID, contract.CreateTenantCustomFieldDefinitionParams{
		IdempotencyKey: params.IdempotencyKey,
	})
}
