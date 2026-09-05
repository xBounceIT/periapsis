package httpserver

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

func (h *Handler) ListTenantLDAPAuthProviders(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantLDAPAuthProvidersParams,
) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return
	}
	if err := requireTenantLDAPBodyAbsent(r); err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input := identityprovider.ListInput{}
	if params.After != nil {
		value := uuid.UUID(*params.After)
		input.After = &value
	}
	if params.Limit != nil {
		input.Limit = int(*params.Limit)
	}
	input.IncludeArchived = params.IncludeArchived != nil && bool(*params.IncludeArchived)
	page, err := h.identityProviders.List(r.Context(), actor, uuid.UUID(tenantID), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.TenantLDAPAuthProviderSummary, 0, len(page.Items))
	for _, item := range page.Items {
		mapped, mapErr := mapTenantLDAPProviderSummary(item)
		if mapErr != nil {
			writeDomainError(w, r, identityprovider.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	writeSensitiveJSON(w, http.StatusOK, contract.TenantLDAPAuthProviderList{
		Items: items, NextCursor: page.NextCursor,
	})
}

func (h *Handler) CreateTenantLDAPAuthProvider(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	_ contract.CreateTenantLDAPAuthProviderParams,
) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	var body contract.TenantLDAPAuthProviderCreateRequest
	if err := decodeTenantLDAPCreateBody(r, &body); err != nil ||
		body.Kind != contract.TenantLDAPAuthProviderCreateRequestKindLdap {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	configuration, endpoints, err := tenantLDAPWriteDocuments(body.Configuration, body.Endpoints)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	description := ""
	if body.Description != nil {
		description = *body.Description
	}
	result, err := h.identityProviders.Create(
		r.Context(), actor, uuid.UUID(tenantID), identityprovider.CreateInput{
			Key: body.Key, DisplayName: body.DisplayName, Description: description,
			Configuration: configuration, Endpoints: endpoints,
			IdempotencyKey: idempotencyKey, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", tenantLDAPProviderLocation(uuid.UUID(tenantID), result.ProviderID))
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) GetTenantLDAPAuthProvider(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return
	}
	if err := requireTenantLDAPBodyAbsent(r); err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	provider, err := h.identityProviders.Get(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID),
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTenantLDAPProvider(provider)
	if err != nil || !setVersionETag(w, provider.Version) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) UpdateTenantLDAPAuthProvider(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
	_ contract.UpdateTenantLDAPAuthProviderParams,
) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return
	}
	entityTag, err := requestedTenantLDAPEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body contract.TenantLDAPAuthProviderUpdateRequest
	if err := decodeTenantLDAPUpdateBody(r, &body); err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	configuration, endpoints, err := tenantLDAPWriteDocuments(body.Configuration, body.Endpoints)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	version, err := h.identityProviders.Update(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID), identityprovider.UpdateInput{
			Key: body.Key, DisplayName: body.DisplayName, Description: body.Description, Enabled: body.Enabled,
			Configuration: configuration, Endpoints: endpoints, ExpectedEntityTag: entityTag, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeTenantLDAPNoContent(w, r, version)
}

func (h *Handler) ArchiveTenantLDAPAuthProvider(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
	_ contract.ArchiveTenantLDAPAuthProviderParams,
) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return
	}
	entityTag, err := requestedTenantLDAPEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body contract.TenantLDAPAuthProviderArchiveRequest
	if err := decodeTenantLDAPReasonBody(r, &body); err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	version, err := h.identityProviders.Archive(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID),
		identityprovider.ArchiveInput{Reason: body.Reason, ExpectedEntityTag: entityTag, Audit: audit},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeTenantLDAPNoContent(w, r, version)
}

func (h *Handler) SetTenantLDAPAuthProviderBindSecret(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
	_ contract.SetTenantLDAPAuthProviderBindSecretParams,
) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return
	}
	entityTag, err := requestedTenantLDAPEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	secret, err := decodeTenantLDAPBindSecret(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	defer clear(secret)
	version, err := h.identityProviders.RotateBindSecret(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID),
		identityprovider.RotateBindSecretInput{Secret: secret, ExpectedEntityTag: entityTag, Audit: audit},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeTenantLDAPNoContent(w, r, version)
}

func (h *Handler) ClearTenantLDAPAuthProviderBindSecret(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
	_ contract.ClearTenantLDAPAuthProviderBindSecretParams,
) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return
	}
	entityTag, err := requestedTenantLDAPEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body contract.TenantLDAPBindSecretClearRequest
	if err := decodeTenantLDAPReasonBody(r, &body); err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	version, err := h.identityProviders.ClearBindSecret(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID),
		identityprovider.ClearBindSecretInput{Reason: body.Reason, ExpectedEntityTag: entityTag, Audit: audit},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeTenantLDAPNoContent(w, r, version)
}

func (h *Handler) TestTenantLDAPAuthProviderConnection(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
) {
	h.testTenantLDAPProvider(w, r, uuid.UUID(tenantID), uuid.UUID(providerID), false)
}

func (h *Handler) TestTenantLDAPAuthProviderBind(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
) {
	h.testTenantLDAPProvider(w, r, uuid.UUID(tenantID), uuid.UUID(providerID), true)
}

func (h *Handler) testTenantLDAPProvider(
	w http.ResponseWriter,
	r *http.Request,
	tenantID, providerID uuid.UUID,
	bind bool,
) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return
	}
	if err := requireTenantLDAPBodyAbsent(r); err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	var (
		result identityprovider.TestResult
		err    error
	)
	input := identityprovider.TestInput{Audit: audit}
	if bind {
		result, err = h.identityProviders.TestBind(r.Context(), actor, tenantID, providerID, input)
	} else {
		result, err = h.identityProviders.TestConnection(r.Context(), actor, tenantID, providerID, input)
	}
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTenantLDAPDiagnostic(result)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func tenantLDAPWriteDocuments(
	configuration contract.TenantLDAPAuthProviderConfiguration,
	endpoints []contract.TenantLDAPAuthProviderEndpoint,
) (identityprovider.Configuration, []identityprovider.Endpoint, error) {
	mappedConfiguration, err := tenantLDAPConfigurationInput(configuration)
	if err != nil {
		return identityprovider.Configuration{}, nil, err
	}
	mappedEndpoints, err := tenantLDAPEndpointsInput(endpoints)
	if err != nil {
		return identityprovider.Configuration{}, nil, err
	}
	return mappedConfiguration, mappedEndpoints, nil
}

func requestedTenantLDAPEntityTag(r *http.Request) (*string, error) {
	version, err := requestedVersion(r)
	if err != nil {
		if errors.Is(err, authorization.ErrPreconditionRequired) {
			return nil, identityprovider.ErrPreconditionRequired
		}
		return nil, identityprovider.ErrInvalidInput
	}
	value, err := strongVersionETag(*version)
	if err != nil {
		return nil, identityprovider.ErrInvalidInput
	}
	return &value, nil
}

func writeTenantLDAPNoContent(w http.ResponseWriter, r *http.Request, version int64) {
	if !setVersionETag(w, version) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func tenantLDAPProviderLocation(tenantID, providerID uuid.UUID) string {
	return fmt.Sprintf("/api/v1/tenants/%s/auth-providers/%s", tenantID, providerID)
}

func requireTenantLDAPBodyAbsent(r *http.Request) error {
	if r == nil || r.ContentLength != 0 || len(r.TransferEncoding) != 0 ||
		len(r.Header.Values("Transfer-Encoding")) != 0 || len(r.Header.Values("Content-Type")) != 0 {
		return errors.New("LDAP operation does not accept a request body")
	}
	if r.Body == nil {
		return nil
	}
	defer r.Body.Close()
	var probe [1]byte
	read, err := r.Body.Read(probe[:])
	if read != 0 || !errors.Is(err, io.EOF) {
		return errors.New("LDAP operation does not accept a request body")
	}
	return nil
}
