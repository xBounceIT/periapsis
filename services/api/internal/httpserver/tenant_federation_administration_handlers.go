package httpserver

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

func (h *Handler) ListTenantFederatedAuthProviders(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantFederatedAuthProvidersParams,
) {
	actor, ok := h.prepareTenantFederationRead(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	input := identityprovider.FederationListInput{
		IncludeArchived: params.IncludeArchived != nil && bool(*params.IncludeArchived),
	}
	if params.After != nil {
		value := uuid.UUID(*params.After)
		input.After = &value
	}
	if params.Limit != nil {
		input.Limit = int(*params.Limit)
	}
	page, err := h.tenantFederation.List(r.Context(), actor, uuid.UUID(tenantID), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.TenantFederationAuthProviderSummary, 0, len(page.Items))
	for _, item := range page.Items {
		mapped, mapErr := mapTenantFederationProviderSummary(item)
		if mapErr != nil || item.TenantID != uuid.UUID(tenantID) ||
			!input.IncludeArchived && item.ArchivedAt != nil {
			writeDomainError(w, r, identityprovider.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	writeSensitiveJSON(w, http.StatusOK, contract.TenantFederationAuthProviderList{
		Items: items, NextCursor: cloneUUIDPointer(page.NextCursor),
	})
}

func (h *Handler) CreateTenantFederatedAuthProvider(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	_ contract.CreateTenantFederatedAuthProviderParams,
) {
	actor, audit, ok := h.prepareTenantFederationMutation(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input, err := decodeTenantFederationCreateBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input.IdempotencyKey, input.Audit = idempotencyKey, audit
	result, err := h.tenantFederation.Create(r.Context(), actor, uuid.UUID(tenantID), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if result.Provider.TenantID != uuid.UUID(tenantID) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	mapped, err := mapTenantFederationProvider(result.Provider)
	if err != nil || !setVersionETag(w, result.Provider.Version) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	w.Header().Set("Location", tenantFederationProviderLocation(uuid.UUID(tenantID), result.Provider.ID))
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) GetTenantFederatedAuthProvider(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
) {
	actor, ok := h.prepareTenantFederationRead(w, r, uuid.UUID(tenantID), uuid.UUID(providerID))
	if !ok {
		return
	}
	provider, err := h.tenantFederation.Get(r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if provider.TenantID != uuid.UUID(tenantID) || provider.ID != uuid.UUID(providerID) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	mapped, err := mapTenantFederationProvider(provider)
	if err != nil || !setVersionETag(w, provider.Version) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) UpdateTenantFederatedAuthProvider(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
	_ contract.UpdateTenantFederatedAuthProviderParams,
) {
	actor, audit, ok := h.prepareTenantFederationMutation(
		w, r, uuid.UUID(tenantID), uuid.UUID(providerID),
	)
	if !ok {
		return
	}
	entityTag, err := requestedTenantLDAPEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	input, err := decodeTenantFederationUpdateBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input.ExpectedEntityTag, input.Audit = entityTag, audit
	provider, err := h.tenantFederation.Update(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID), input,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if provider.TenantID != uuid.UUID(tenantID) || provider.ID != uuid.UUID(providerID) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	mapped, err := mapTenantFederationProvider(provider)
	if err != nil || !setVersionETag(w, provider.Version) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ArchiveTenantFederatedAuthProvider(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
	_ contract.ArchiveTenantFederatedAuthProviderParams,
) {
	actor, audit, ok := h.prepareTenantFederationMutation(
		w, r, uuid.UUID(tenantID), uuid.UUID(providerID),
	)
	if !ok {
		return
	}
	entityTag, err := requestedTenantLDAPEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	reason, err := decodeTenantFederationReasonBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	version, err := h.tenantFederation.Archive(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID),
		identityprovider.FederationArchiveInput{Reason: reason, ExpectedEntityTag: entityTag, Audit: audit},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeTenantLDAPNoContent(w, r, version)
}

func (h *Handler) ReplaceTenantOIDCAuthProviderClientSecret(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
	_ contract.ReplaceTenantOIDCAuthProviderClientSecretParams,
) {
	actor, audit, ok := h.prepareTenantFederationMutation(
		w, r, uuid.UUID(tenantID), uuid.UUID(providerID),
	)
	if !ok {
		return
	}
	entityTag, err := requestedTenantLDAPEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	secret, reason, err := decodeTenantFederationOIDCSecretBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	defer clear(secret)
	receipt, err := h.tenantFederation.ReplaceOIDCClientSecret(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID),
		identityprovider.FederationReplaceOIDCSecretInput{
			Secret: secret, Reason: reason, ExpectedEntityTag: entityTag, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeTenantFederationSecretNoContent(w, r, uuid.UUID(providerID), receipt)
}

func (h *Handler) ClearTenantOIDCAuthProviderClientSecret(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
	_ contract.ClearTenantOIDCAuthProviderClientSecretParams,
) {
	actor, audit, ok := h.prepareTenantFederationMutation(
		w, r, uuid.UUID(tenantID), uuid.UUID(providerID),
	)
	if !ok {
		return
	}
	entityTag, err := requestedTenantLDAPEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	reason, err := decodeTenantFederationClearSecretBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	receipt, err := h.tenantFederation.ClearOIDCClientSecret(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID),
		identityprovider.FederationClearOIDCSecretInput{
			Reason: reason, ExpectedEntityTag: entityTag, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeTenantFederationSecretNoContent(w, r, uuid.UUID(providerID), receipt)
}

func (h *Handler) RefreshTenantOIDCAuthProviderTrustDocuments(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
	_ contract.RefreshTenantOIDCAuthProviderTrustDocumentsParams,
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
	input, err := decodeTenantFederationOIDCTrustBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input.ExpectedEntityTag, input.Audit = entityTag, audit
	receipt, err := h.tenantFederation.RefreshOIDCTrustDocuments(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID), input,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeTenantFederationOIDCTrustNoContent(w, r, uuid.UUID(providerID), receipt)
}

func (h *Handler) GetTenantFederatedAuthProviderMappingPolicy(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
) {
	actor, ok := h.prepareTenantFederationRead(w, r, uuid.UUID(tenantID), uuid.UUID(providerID))
	if !ok {
		return
	}
	policy, err := h.tenantFederation.GetMappingPolicy(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID),
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTenantFederationMappingPolicy(policy)
	if err != nil || policy.TenantID != uuid.UUID(tenantID) || policy.ProviderID != uuid.UUID(providerID) || policy.MappingRevision < 1 ||
		!setVersionETag(w, policy.ProviderVersion) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	w.Header().Set("X-Periapsis-Mapping-Revision", strconv.FormatInt(policy.MappingRevision, 10))
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ReplaceTenantFederatedAuthProviderMappingPolicy(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
	_ contract.ReplaceTenantFederatedAuthProviderMappingPolicyParams,
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
	input, err := decodeTenantFederationMappingBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input.ExpectedEntityTag, input.Audit = entityTag, audit
	receipt, err := h.tenantFederation.ReplaceMappingPolicy(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID), input,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeTenantFederationPolicyNoContent(w, r, uuid.UUID(providerID), receipt, true)
}

func (h *Handler) GetTenantFederatedAuthProviderAssurancePolicy(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
) {
	actor, ok := h.prepareTenantFederationRead(w, r, uuid.UUID(tenantID), uuid.UUID(providerID))
	if !ok {
		return
	}
	policy, err := h.tenantFederation.GetAssurancePolicy(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID),
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTenantFederationAssurancePolicy(policy)
	if err != nil || policy.TenantID != uuid.UUID(tenantID) || policy.ProviderID != uuid.UUID(providerID) || policy.AssurancePolicyRevision < 1 ||
		!setVersionETag(w, policy.ProviderVersion) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	w.Header().Set(
		"X-Periapsis-Assurance-Policy-Revision",
		strconv.FormatInt(policy.AssurancePolicyRevision, 10),
	)
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ReplaceTenantFederatedAuthProviderAssurancePolicy(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
	_ contract.ReplaceTenantFederatedAuthProviderAssurancePolicyParams,
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
	input, err := decodeTenantFederationAssuranceBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input.ExpectedEntityTag, input.Audit = entityTag, audit
	receipt, err := h.tenantFederation.ReplaceAssurancePolicy(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID), input,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeTenantFederationPolicyNoContent(w, r, uuid.UUID(providerID), receipt, false)
}

func (h *Handler) prepareTenantFederationRead(
	w http.ResponseWriter,
	r *http.Request,
	ids ...uuid.UUID,
) (authorization.Actor, bool) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return authorization.Actor{}, false
	}
	if !validLDAPAdministrationIDs(ids) || requireTenantLDAPBodyAbsent(r) != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return authorization.Actor{}, false
	}
	if actor.ActiveTenantID != ids[0] {
		writeDomainError(w, r, identityprovider.ErrForbidden)
		return authorization.Actor{}, false
	}
	return actor, true
}

func (h *Handler) prepareTenantFederationMutation(
	w http.ResponseWriter,
	r *http.Request,
	ids ...uuid.UUID,
) (authorization.Actor, authorization.AuditContext, bool) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	if !validLDAPAdministrationIDs(ids) {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	if actor.ActiveTenantID != ids[0] {
		writeDomainError(w, r, identityprovider.ErrForbidden)
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	return actor, audit, true
}

func writeTenantFederationSecretNoContent(
	w http.ResponseWriter,
	r *http.Request,
	providerID uuid.UUID,
	receipt identityprovider.FederationSecretMutationReceipt,
) {
	if receipt.ProviderID != providerID || receipt.SecretRevision < 1 ||
		!setVersionETag(w, receipt.ProviderVersion) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Periapsis-Secret-Revision", strconv.FormatInt(receipt.SecretRevision, 10))
	w.WriteHeader(http.StatusNoContent)
}

func writeTenantFederationOIDCTrustNoContent(
	w http.ResponseWriter,
	r *http.Request,
	providerID uuid.UUID,
	receipt identityprovider.FederationOIDCTrustDocumentsReceipt,
) {
	if receipt.ProviderID != providerID || receipt.DiscoveryRevision < 1 || receipt.JWKSRevision < 1 ||
		receipt.KeyCount < 1 || !setVersionETag(w, receipt.ProviderVersion) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Periapsis-OIDC-Discovery-Revision", strconv.FormatInt(receipt.DiscoveryRevision, 10))
	w.Header().Set("X-Periapsis-OIDC-JWKS-Revision", strconv.FormatInt(receipt.JWKSRevision, 10))
	w.Header().Set("X-Periapsis-OIDC-JWKS-Key-Count", strconv.Itoa(receipt.KeyCount))
	w.WriteHeader(http.StatusNoContent)
}

func writeTenantFederationPolicyNoContent(
	w http.ResponseWriter,
	r *http.Request,
	providerID uuid.UUID,
	receipt identityprovider.FederationPolicyMutationReceipt,
	mapping bool,
) {
	revision, otherRevision, header := receipt.AssurancePolicyRevision, receipt.MappingRevision,
		"X-Periapsis-Assurance-Policy-Revision"
	if mapping {
		revision, otherRevision, header = receipt.MappingRevision, receipt.AssurancePolicyRevision,
			"X-Periapsis-Mapping-Revision"
	}
	if receipt.ProviderID != providerID || revision < 2 || otherRevision != 0 ||
		!setVersionETag(w, receipt.ProviderVersion) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(header, strconv.FormatInt(revision, 10))
	w.WriteHeader(http.StatusNoContent)
}

func tenantFederationProviderLocation(tenantID, providerID uuid.UUID) string {
	return fmt.Sprintf("/api/v1/tenants/%s/federated-auth-providers/%s", tenantID, providerID)
}
