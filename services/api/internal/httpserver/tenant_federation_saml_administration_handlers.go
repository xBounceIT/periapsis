package httpserver

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

func (h *Handler) ReplaceTenantSAMLAuthProviderMetadata(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
	_ contract.ReplaceTenantSAMLAuthProviderMetadataParams,
) {
	actor, audit, ok := h.prepareTenantFederationMutation(w, r, uuid.UUID(tenantID), uuid.UUID(providerID))
	if !ok {
		return
	}
	entityTag, err := requestedTenantLDAPEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	body, err := decodeTenantFederationSAMLMetadataBody(r)
	defer body.destroy()
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input := tenantFederationSAMLInput(body)
	input.ExpectedEntityTag, input.Audit = entityTag, audit
	receipt, err := h.tenantFederation.ReplaceSAMLMetadata(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID), input,
	)
	if errors.Is(err, identityprovider.ErrFederationSAMLTrustApprovalRequired) {
		w.Header().Set("Cache-Control", "no-store")
		writeProblem(
			w, r, http.StatusConflict, "saml_trust_approval_required", "SAML trust approval required",
			"The metadata replacement changes protected trust without certificate continuity. Review the new trust out of band and retry the exact current-version request with explicit approval.",
		)
		return
	}
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeTenantFederationSAMLNoContent(w, r, uuid.UUID(providerID), receipt)
}

func (h *Handler) ReplaceTenantSAMLAuthProviderSPCredential(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
	_ contract.ReplaceTenantSAMLAuthProviderSPCredentialParams,
) {
	actor, audit, ok := h.prepareTenantFederationMutation(w, r, uuid.UUID(tenantID), uuid.UUID(providerID))
	if !ok {
		return
	}
	entityTag, err := requestedTenantLDAPEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	reason, err := decodeTenantFederationSAMLSPCredentialBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	receipt, err := h.tenantFederation.ReplaceSAMLSPCredential(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID),
		identityprovider.FederationReplaceSAMLSPCredentialInput{
			Reason: reason, ExpectedEntityTag: entityTag, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeTenantFederationSAMLNoContent(w, r, uuid.UUID(providerID), receipt)
}

func (h *Handler) ClearTenantSAMLAuthProviderSPCredential(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
	_ contract.ClearTenantSAMLAuthProviderSPCredentialParams,
) {
	actor, audit, ok := h.prepareTenantFederationMutation(w, r, uuid.UUID(tenantID), uuid.UUID(providerID))
	if !ok {
		return
	}
	entityTag, err := requestedTenantLDAPEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	reason, err := decodeTenantFederationSAMLSPCredentialBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	receipt, err := h.tenantFederation.ClearSAMLSPCredential(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID),
		identityprovider.FederationClearSAMLSPCredentialInput{
			Reason: reason, ExpectedEntityTag: entityTag, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeTenantFederationSAMLNoContent(w, r, uuid.UUID(providerID), receipt)
}

func writeTenantFederationSAMLNoContent(
	w http.ResponseWriter,
	r *http.Request,
	providerID uuid.UUID,
	receipt identityprovider.FederationSAMLMaterialMutationReceipt,
) {
	if receipt.ProviderID != providerID || receipt.ProviderVersion < 2 || receipt.MaterialRevision < 2 ||
		!setVersionETag(w, receipt.ProviderVersion) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Periapsis-SAML-Material-Revision", strconv.FormatInt(receipt.MaterialRevision, 10))
	w.WriteHeader(http.StatusNoContent)
}
