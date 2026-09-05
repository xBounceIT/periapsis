package httpserver

import (
	"errors"
	"net/http"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamladapter"
)

// GetTenantSAMLSPMetadata serves one certificate-only, provider-qualified
// public projection. Unknown, disabled, archived, and incomplete providers
// deliberately share the same non-oracular response.
func (h *Handler) GetTenantSAMLSPMetadata(
	w http.ResponseWriter,
	r *http.Request,
	tenantSlug contract.FederatedTenantSlug,
	loginKey contract.FederatedLoginKey,
) {
	prepareFederatedResponse(w)
	if r.URL.RawQuery != "" || r.URL.ForceQuery || requireFederatedMFARequestBodyAbsent(r) != nil ||
		!tenantSAMLMetadataSlugPattern.MatchString(string(tenantSlug)) ||
		!tenantSAMLMetadataLoginKeyPattern.MatchString(string(loginKey)) {
		writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The metadata request is invalid.")
		return
	}
	if h == nil || h.federated.samlMetadata == nil {
		writeTenantSAMLMetadataUnavailable(w, r)
		return
	}
	document, err := h.federated.samlMetadata.Metadata(r.Context(), string(tenantSlug), string(loginKey))
	defer clear(document.Document)
	switch {
	case errors.Is(err, errTenantSAMLMetadataInvalid):
		writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The metadata request is invalid.")
		return
	case errors.Is(err, errTenantSAMLMetadataNotFound):
		writeProblem(w, r, http.StatusNotFound, "not_found", "Not found", "SAML metadata is not available.")
		return
	case err != nil, document.ContentType != platformsamladapter.SAMLMetadataContentType,
		len(document.Document) == 0:
		writeTenantSAMLMetadataUnavailable(w, r)
		return
	}
	w.Header().Set("Content-Type", document.ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(document.Document)
}

func writeTenantSAMLMetadataUnavailable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", "5")
	writeProblem(
		w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable",
		"SAML metadata is temporarily unavailable.",
	)
}
