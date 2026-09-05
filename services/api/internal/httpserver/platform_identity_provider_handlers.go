package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityprovider"
)

type platformLDAPAdministrationService interface {
	UpdateLDAP(context.Context, authentication.Session, uuid.UUID, platformidentityprovider.UpdateLDAPInput) (platformidentityprovider.UpdateResult, error)
	ReplaceLDAPBindSecret(context.Context, authentication.Session, uuid.UUID, platformidentityprovider.ReplaceLDAPBindSecretInput) (platformidentityprovider.SecretMutationReceipt, error)
	PutLDAPMapping(context.Context, authentication.Session, uuid.UUID, uuid.UUID, platformidentityprovider.PutLDAPMappingInput) (platformidentityprovider.UpdateResult, error)
	SetLDAPLoginState(context.Context, authentication.Session, uuid.UUID, platformidentityprovider.SetLDAPLoginStateInput) (platformidentityprovider.UpdateResult, error)
	TestLDAP(context.Context, authentication.Session, uuid.UUID, platformidentityprovider.LDAPTestInput) (platformidentityprovider.LDAPDiagnostic, error)
}

func (h *Handler) platformLDAPAdministration() (platformLDAPAdministrationService, bool) {
	if h == nil {
		return nil, false
	}
	service, ok := h.platformIdentityProviders.(platformLDAPAdministrationService)
	return service, ok && service != nil
}

type unavailablePlatformIdentityProviderService struct{}

func platformIdentityProviderServiceIsNil(service PlatformIdentityProviderService) bool {
	if service == nil {
		return true
	}
	value := reflect.ValueOf(service)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (unavailablePlatformIdentityProviderService) List(
	context.Context,
	authentication.Session,
	platformidentityprovider.ListInput,
) (platformidentityprovider.ProviderPage, error) {
	return platformidentityprovider.ProviderPage{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityProviderService) Get(
	context.Context,
	authentication.Session,
	uuid.UUID,
) (platformidentityprovider.Provider, error) {
	return platformidentityprovider.Provider{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityProviderService) Create(
	context.Context,
	authentication.Session,
	platformidentityprovider.CreateInput,
) (platformidentityprovider.CreateResult, error) {
	return platformidentityprovider.CreateResult{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityProviderService) Update(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformidentityprovider.UpdateInput,
) (platformidentityprovider.UpdateResult, error) {
	return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityProviderService) Archive(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformidentityprovider.ArchiveInput,
) (platformidentityprovider.MutationReceipt, error) {
	return platformidentityprovider.MutationReceipt{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityProviderService) ReplaceOIDCClientSecret(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformidentityprovider.ReplaceOIDCClientSecretInput,
) (platformidentityprovider.SecretMutationReceipt, error) {
	return platformidentityprovider.SecretMutationReceipt{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityProviderService) ReplaceSAMLMetadata(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformidentityprovider.ReplaceSAMLMetadataInput,
) (platformidentityprovider.SAMLMaterialMutationReceipt, error) {
	return platformidentityprovider.SAMLMaterialMutationReceipt{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityProviderService) ReplaceSAMLSPKey(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformidentityprovider.ReplaceSAMLSPKeyInput,
) (platformidentityprovider.SAMLMaterialMutationReceipt, error) {
	return platformidentityprovider.SAMLMaterialMutationReceipt{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityProviderService) ClearSAMLSPKey(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformidentityprovider.ClearSAMLSPKeyInput,
) (platformidentityprovider.SAMLMaterialMutationReceipt, error) {
	return platformidentityprovider.SAMLMaterialMutationReceipt{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityProviderService) Activate(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformidentityprovider.ActivateInput,
) (platformidentityprovider.UpdateResult, error) {
	return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityProviderService) Deactivate(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformidentityprovider.DeactivateInput,
) (platformidentityprovider.UpdateResult, error) {
	return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityProviderService) ActivateDirectLogin(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformidentityprovider.DirectLoginInput,
) (platformidentityprovider.UpdateResult, error) {
	return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityProviderService) DeactivateDirectLogin(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformidentityprovider.DirectLoginInput,
) (platformidentityprovider.UpdateResult, error) {
	return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
}

func (h *Handler) ListPlatformAuthProviders(
	w http.ResponseWriter,
	r *http.Request,
	params contract.ListPlatformAuthProvidersParams,
) {
	session, ok := h.platformIdentityProviderSession(w, r, false)
	if !ok {
		return
	}
	if err := requireTenantLDAPBodyAbsent(r); err != nil {
		writeDomainError(w, r, authentication.ErrInvalidInput)
		return
	}
	input := platformidentityprovider.ListInput{
		IncludeArchived: params.IncludeArchived != nil && bool(*params.IncludeArchived),
	}
	if params.After != nil {
		value := uuid.UUID(*params.After)
		input.After = &value
	}
	if params.Limit != nil {
		input.Limit = int(*params.Limit)
	}
	page, err := h.platformIdentityProviders.List(r.Context(), session, input)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	mapped, err := mapPlatformAuthProviderPage(page)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

// ListPlatformProviders is the compatibility alias for the canonical
// platform auth-provider catalog. It deliberately delegates the complete
// authorization, pagination, and safe-projection behavior.
func (h *Handler) ListPlatformProviders(
	w http.ResponseWriter,
	r *http.Request,
	params contract.ListPlatformProvidersParams,
) {
	h.ListPlatformAuthProviders(w, r, contract.ListPlatformAuthProvidersParams{
		After: params.After, Limit: params.Limit, IncludeArchived: params.IncludeArchived,
	})
}

func (h *Handler) CreatePlatformAuthProvider(
	w http.ResponseWriter,
	r *http.Request,
	params contract.CreatePlatformAuthProviderParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil || idempotencyKey != string(params.IdempotencyKey) {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformAuthProviderCreateRequest
	if err := decodePlatformAuthProviderCreateBody(r, &body); err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	input, err := platformAuthProviderCreateInput(body)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	input.IdempotencyKey = idempotencyKey
	input.Reason = reason
	input.Event = event
	result, err := h.platformIdentityProviders.Create(r.Context(), session, input)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	provider := result.Provider()
	mapped, err := mapPlatformAuthProvider(provider)
	if err != nil || !setVersionETag(w, provider.Version) {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrUnavailable)
		return
	}
	w.Header().Set("Location", platformAuthProviderLocation(result.ProviderID()))
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) GetPlatformAuthProvider(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
) {
	session, ok := h.platformIdentityProviderSession(w, r, false)
	if !ok {
		return
	}
	if err := requireTenantLDAPBodyAbsent(r); err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	provider, err := h.platformIdentityProviders.Get(r.Context(), session, uuid.UUID(providerID))
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	mapped, err := mapPlatformAuthProvider(provider)
	if err != nil || !setVersionETag(w, provider.Version) {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) UpdatePlatformAuthProvider(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.UpdatePlatformAuthProviderParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformAuthProviderUpdateRequest
	if err := decodePlatformAuthProviderUpdateBody(r, &body); err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	entityTag, ok := h.platformIdentityProviderPrecondition(
		w, r, string(params.IfMatch), body.ExpectedVersion,
	)
	if !ok {
		return
	}
	result, err := h.platformIdentityProviders.Update(
		r.Context(), session, uuid.UUID(providerID), platformidentityprovider.UpdateInput{
			Key: body.Key, DisplayName: body.DisplayName, Description: body.Description,
			Reason: reason, ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	provider := result.Provider()
	mapped, err := mapPlatformAuthProvider(provider)
	if err != nil || !setVersionETag(w, provider.Version) {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ArchivePlatformAuthProvider(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.ArchivePlatformAuthProviderParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformAuthProviderArchiveRequest
	if err := decodePlatformAuthProviderArchiveBody(r, &body); err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	entityTag, ok := h.platformIdentityProviderPrecondition(
		w, r, string(params.IfMatch), body.ExpectedVersion,
	)
	if !ok {
		return
	}
	receipt, err := h.platformIdentityProviders.Archive(
		r.Context(), session, uuid.UUID(providerID), platformidentityprovider.ArchiveInput{
			Reason: reason, ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	if !setVersionETag(w, receipt.Version()) {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ActivatePlatformAuthProviderTenantExecution(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.ActivatePlatformAuthProviderTenantExecutionParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformAuthProviderActivationRequest
	if err := decodePlatformAuthProviderActivationBody(r, &body); err != nil || !body.AccountMode.Valid() {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	entityTag, ok := h.platformIdentityProviderPrecondition(
		w, r, string(params.IfMatch), body.ExpectedVersion,
	)
	if !ok {
		return
	}
	result, err := h.platformIdentityProviders.Activate(
		r.Context(), session, uuid.UUID(providerID), platformidentityprovider.ActivateInput{
			AccountMode: platformidentityprovider.AccountMode(body.AccountMode),
			Reason:      reason, ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	h.writePlatformIdentityProviderMutationResult(w, r, result)
}

func (h *Handler) DeactivatePlatformAuthProviderTenantExecution(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.DeactivatePlatformAuthProviderTenantExecutionParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformAuthProviderDeactivationRequest
	if err := decodePlatformAuthProviderDeactivationBody(r, &body); err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	entityTag, ok := h.platformIdentityProviderPrecondition(
		w, r, string(params.IfMatch), body.ExpectedVersion,
	)
	if !ok {
		return
	}
	result, err := h.platformIdentityProviders.Deactivate(
		r.Context(), session, uuid.UUID(providerID), platformidentityprovider.DeactivateInput{
			Reason: reason, ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	h.writePlatformIdentityProviderMutationResult(w, r, result)
}

func (h *Handler) ActivatePlatformOIDCDirectLogin(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.ActivatePlatformOIDCDirectLoginParams,
) {
	h.changePlatformOIDCDirectLogin(w, r, uuid.UUID(providerID), string(params.IfMatch), string(params.XAuditReason), true)
}

func (h *Handler) DeactivatePlatformOIDCDirectLogin(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.DeactivatePlatformOIDCDirectLoginParams,
) {
	h.changePlatformOIDCDirectLogin(w, r, uuid.UUID(providerID), string(params.IfMatch), string(params.XAuditReason), false)
}

func (h *Handler) changePlatformOIDCDirectLogin(
	w http.ResponseWriter,
	r *http.Request,
	providerID uuid.UUID,
	ifMatch string,
	auditReason string,
	enabled bool,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	if !validPlatformIdentityProviderTransportUUID(providerID) {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, auditReason)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformOIDCDirectLoginCommandRequest
	if err := decodePlatformOIDCDirectLoginBody(r, &body); err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	entityTag, ok := h.platformIdentityProviderPrecondition(w, r, ifMatch, body.ExpectedVersion)
	if !ok {
		return
	}
	input := platformidentityprovider.DirectLoginInput{
		Reason: reason, ExpectedEntityTag: entityTag, Event: event,
	}
	var result platformidentityprovider.UpdateResult
	if enabled {
		result, err = h.platformIdentityProviders.ActivateDirectLogin(r.Context(), session, providerID, input)
	} else {
		result, err = h.platformIdentityProviders.DeactivateDirectLogin(r.Context(), session, providerID, input)
	}
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	h.writePlatformIdentityProviderMutationResult(w, r, result)
}

func validPlatformIdentityProviderTransportUUID(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func (h *Handler) writePlatformIdentityProviderMutationResult(
	w http.ResponseWriter,
	r *http.Request,
	result platformidentityprovider.UpdateResult,
) {
	provider := result.Provider()
	mapped, err := mapPlatformAuthProvider(provider)
	if err != nil || result.ProviderID() != provider.ID || result.Version() != provider.Version ||
		!setVersionETag(w, provider.Version) {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ReplacePlatformOIDCAuthProviderClientSecret(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.ReplacePlatformOIDCAuthProviderClientSecretParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	secret, expectedVersion, err := decodePlatformOIDCClientSecret(r)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	defer clear(secret)
	entityTag, ok := h.platformIdentityProviderPrecondition(
		w, r, string(params.IfMatch), expectedVersion,
	)
	if !ok {
		return
	}
	receipt, err := h.platformIdentityProviders.ReplaceOIDCClientSecret(
		r.Context(), session, uuid.UUID(providerID), platformidentityprovider.ReplaceOIDCClientSecretInput{
			Secret: secret, Reason: reason, ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	if !setVersionETag(w, receipt.Version()) {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) UpdatePlatformLDAPAuthProvider(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.UpdatePlatformLDAPAuthProviderParams,
) {
	service, available := h.platformLDAPAdministration()
	if !available {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrUnavailable)
		return
	}
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformLDAPAuthProviderUpdateRequest
	if _, err = decodePlatformIdentityProviderJSONBody(r, &body); err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	entityTag, ok := h.platformIdentityProviderPrecondition(
		w, r, string(params.IfMatch), body.ExpectedVersion,
	)
	if !ok {
		return
	}
	configuration, err := platformLDAPConfigurationInput(body.Configuration)
	if err != nil || len(body.Endpoints) == 0 {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	endpoints := make([]platformidentityprovider.LDAPEndpoint, len(body.Endpoints))
	for index, endpoint := range body.Endpoints {
		if endpoint.Port < 1 || endpoint.Port > 65535 {
			h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
			return
		}
		endpoints[index] = platformidentityprovider.LDAPEndpoint{
			ID: uuid.UUID(endpoint.Id), Priority: endpoint.Priority,
			Host: endpoint.Host, Port: uint16(endpoint.Port), Transport: string(endpoint.Transport),
			TLSServerName: endpoint.TlsServerName, ReferralAllowed: endpoint.ReferralAllowed,
			Enabled: endpoint.Enabled,
		}
	}
	result, err := service.UpdateLDAP(
		r.Context(), session, uuid.UUID(providerID), platformidentityprovider.UpdateLDAPInput{
			Key: body.Key, DisplayName: body.DisplayName, Description: body.Description,
			Configuration: configuration, Endpoints: endpoints, Reason: reason,
			ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	h.writePlatformIdentityProviderMutationResult(w, r, result)
}

func (h *Handler) ReplacePlatformLDAPBindSecret(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.ReplacePlatformLDAPBindSecretParams,
) {
	service, available := h.platformLDAPAdministration()
	if !available {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrUnavailable)
		return
	}
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformLDAPBindSecretWriteRequest
	if _, err = decodePlatformIdentityProviderJSONBody(r, &body); err != nil || body.BindSecret == nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	secret := []byte(*body.BindSecret)
	*body.BindSecret = ""
	defer clear(secret)
	entityTag, ok := h.platformIdentityProviderPrecondition(
		w, r, string(params.IfMatch), body.ExpectedVersion,
	)
	if !ok {
		return
	}
	receipt, err := service.ReplaceLDAPBindSecret(
		r.Context(), session, uuid.UUID(providerID), platformidentityprovider.ReplaceLDAPBindSecretInput{
			Secret: secret, Reason: reason, ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	if receipt.ProviderID() != uuid.UUID(providerID) || receipt.Version() != body.ExpectedVersion+1 ||
		receipt.SecretRevision() < 1 || !setVersionETag(w, receipt.Version()) {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrUnavailable)
		return
	}
	w.Header().Set("X-Periapsis-LDAP-Secret-Revision", strconv.FormatInt(receipt.SecretRevision(), 10))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) PutPlatformLDAPMapping(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	mappingID uuid.UUID,
	params contract.PutPlatformLDAPMappingParams,
) {
	service, available := h.platformLDAPAdministration()
	if !available {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrUnavailable)
		return
	}
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformLDAPMappingWriteRequest
	if _, err = decodePlatformIdentityProviderJSONBody(r, &body); err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	result, err := service.PutLDAPMapping(
		r.Context(), session, uuid.UUID(providerID), mappingID,
		platformidentityprovider.PutLDAPMappingInput{
			ExpectedVersion: body.ExpectedVersion,
			MatcherType:     identityprovider.MappingMatcherType(body.MatcherType),
			MatcherValue:    body.MatcherValue, CaseSensitive: body.CaseSensitive,
			Priority: body.Priority, PlatformRoleID: uuid.UUID(body.PlatformRoleId),
			ReconciliationMode: identityprovider.ReconciliationMode(body.ReconciliationMode),
			Enabled:            body.Enabled, Notes: body.Notes, Reason: reason, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	h.writePlatformIdentityProviderMutationResult(w, r, result)
}

func (h *Handler) SetPlatformLDAPLoginState(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.SetPlatformLDAPLoginStateParams,
) {
	service, available := h.platformLDAPAdministration()
	if !available {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrUnavailable)
		return
	}
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformLDAPLoginStateRequest
	if _, err = decodePlatformIdentityProviderJSONBody(r, &body); err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	entityTag, ok := h.platformIdentityProviderPrecondition(
		w, r, string(params.IfMatch), body.ExpectedVersion,
	)
	if !ok {
		return
	}
	result, err := service.SetLDAPLoginState(
		r.Context(), session, uuid.UUID(providerID), platformidentityprovider.SetLDAPLoginStateInput{
			Enabled: body.Enabled, Reason: reason, ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	h.writePlatformIdentityProviderMutationResult(w, r, result)
}

func (h *Handler) TestPlatformLDAPProvider(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.TestPlatformLDAPProviderParams,
) {
	service, available := h.platformLDAPAdministration()
	if !available {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrUnavailable)
		return
	}
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil || !validPlatformIdentityProviderTransportUUID(uuid.UUID(providerID)) {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformLDAPTestRequest
	if _, err = decodePlatformIdentityProviderJSONBody(r, &body); err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	result, err := service.TestLDAP(
		r.Context(), session, uuid.UUID(providerID), platformidentityprovider.LDAPTestInput{
			Kind: platformidentityprovider.LDAPTestKind(body.Kind), Username: body.Username,
			Reason: reason, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	kind := contract.PlatformLDAPDiagnosticKind(result.Kind)
	outcome := contract.PlatformLDAPDiagnosticOutcome(result.Outcome)
	category := contract.PlatformLDAPDiagnosticCategory(result.Category)
	if !kind.Valid() || !outcome.Valid() || !category.Valid() || result.TestID == uuid.Nil ||
		result.Duration < 0 || result.Duration > 120*time.Second {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, contract.PlatformLDAPDiagnostic{
		TestId: result.TestID, Kind: kind, Outcome: outcome, Category: category,
		EndpointPriority: result.EndpointPriority, DurationMs: int(result.Duration.Milliseconds()),
		MatchedEntryCount: result.MatchedEntryCount, Attributes: result.Attributes,
	})
}

func (h *Handler) ReplacePlatformSAMLAuthProviderMetadata(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.ReplacePlatformSAMLAuthProviderMetadataParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	id := uuid.UUID(providerID)
	if !validPlatformIdentityProviderTransportUUID(id) {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	body, err := decodePlatformSAMLMetadataBody(r)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	defer body.destroy()
	entityTag, ok := h.platformIdentityProviderPrecondition(
		w, r, string(params.IfMatch), body.expectedVersion,
	)
	if !ok {
		return
	}
	receipt, err := h.platformIdentityProviders.ReplaceSAMLMetadata(
		r.Context(), session, id, platformidentityprovider.ReplaceSAMLMetadataInput{
			MetadataURL: body.metadataURL, MetadataXML: body.metadataXML,
			ApproveTrustReset: body.approveTrustReset, Reason: reason,
			ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	h.writePlatformSAMLMaterialMutation(w, r, receipt, id, body.expectedVersion)
}

func (h *Handler) ReplacePlatformSAMLAuthProviderSPKey(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.ReplacePlatformSAMLAuthProviderSPKeyParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	id := uuid.UUID(providerID)
	if !validPlatformIdentityProviderTransportUUID(id) {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	privateKey, certificates, expectedVersion, err := decodePlatformSAMLSPKeyBody(r)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	defer clearPlatformSAMLBytes(privateKey)
	defer clearPlatformSAMLByteSlices(certificates)
	entityTag, ok := h.platformIdentityProviderPrecondition(
		w, r, string(params.IfMatch), expectedVersion,
	)
	if !ok {
		return
	}
	receipt, err := h.platformIdentityProviders.ReplaceSAMLSPKey(
		r.Context(), session, id, platformidentityprovider.ReplaceSAMLSPKeyInput{
			PrivateKeyPKCS8: privateKey, CertificateDER: certificates,
			Reason: reason, ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	h.writePlatformSAMLMaterialMutation(w, r, receipt, id, expectedVersion)
}

func (h *Handler) ClearPlatformSAMLAuthProviderSPKey(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.ClearPlatformSAMLAuthProviderSPKeyParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	id := uuid.UUID(providerID)
	if !validPlatformIdentityProviderTransportUUID(id) {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformSAMLSPKeyClearRequest
	if err := decodePlatformSAMLSPKeyClearBody(r, &body); err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return
	}
	entityTag, ok := h.platformIdentityProviderPrecondition(
		w, r, string(params.IfMatch), body.ExpectedVersion,
	)
	if !ok {
		return
	}
	receipt, err := h.platformIdentityProviders.ClearSAMLSPKey(
		r.Context(), session, id, platformidentityprovider.ClearSAMLSPKeyInput{
			Reason: reason, ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, err)
		return
	}
	h.writePlatformSAMLMaterialMutation(w, r, receipt, id, body.ExpectedVersion)
}

func (h *Handler) writePlatformSAMLMaterialMutation(
	w http.ResponseWriter,
	r *http.Request,
	receipt platformidentityprovider.SAMLMaterialMutationReceipt,
	providerID uuid.UUID,
	expectedVersion int64,
) {
	if receipt.ProviderID() != providerID || receipt.Version() != expectedVersion+1 ||
		receipt.MaterialRevision() < 2 || receipt.MaterialRevision() > maximumResourceVersion ||
		!setVersionETag(w, receipt.Version()) {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrUnavailable)
		return
	}
	w.Header().Set(
		"X-Periapsis-SAML-Material-Revision",
		strconv.FormatInt(receipt.MaterialRevision(), 10),
	)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) platformIdentityProviderSession(
	w http.ResponseWriter,
	r *http.Request,
	mutation bool,
) (authentication.Session, bool) {
	if mutation {
		if !h.prepareCookieMutation(w, r) {
			return authentication.Session{}, false
		}
	} else if !h.requireApplication(w, r) {
		return authentication.Session{}, false
	}
	token, err := h.sessionToken(r)
	if err != nil {
		writeDomainError(w, r, err)
		return authentication.Session{}, false
	}
	session, err := h.authenticateRequest(r, token)
	if err != nil {
		writeDomainError(w, r, err)
		return authentication.Session{}, false
	}
	if mutation {
		csrf, csrfErr := singleHeader(r, csrfTokenHeader, 128)
		if csrfErr != nil || h.authentication.ValidateCSRF(session, csrf) != nil {
			writeDomainError(w, r, authentication.ErrForbidden)
			return authentication.Session{}, false
		}
	}
	return session, true
}

func (h *Handler) platformIdentityProviderMutation(
	w http.ResponseWriter,
	r *http.Request,
) (authentication.Session, authentication.EventContext, bool) {
	session, ok := h.platformIdentityProviderSession(w, r, true)
	if !ok {
		return authentication.Session{}, authentication.EventContext{}, false
	}
	event, err := h.eventContext(r)
	if err != nil {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return authentication.Session{}, authentication.EventContext{}, false
	}
	return session, event, true
}

func (h *Handler) platformIdentityProviderPrecondition(
	w http.ResponseWriter,
	r *http.Request,
	contractValue string,
	bodyVersion int64,
) (*string, bool) {
	version, present, err := strongVersionPrecondition(r)
	if !present {
		writeProblem(
			w, r, http.StatusPreconditionRequired, "precondition_required", "Precondition required",
			"A current strong If-Match entity tag is required.",
		)
		return nil, false
	}
	canonical, canonicalErr := strongVersionETag(version)
	if err != nil || canonicalErr != nil || canonical != contractValue || bodyVersion != version ||
		version > maximumIncrementableResourceVersion {
		h.writePlatformIdentityProviderError(w, r, authentication.ErrInvalidInput)
		return nil, false
	}
	return &canonical, true
}

func platformIdentityProviderAuditReason(r *http.Request, contractValue string) (string, error) {
	reason, err := singleHeader(r, "X-Audit-Reason", 2048)
	if err != nil || reason != contractValue || !platformIdentityProviderAuditReasonIsHTTPValue(reason) {
		return "", authentication.ErrInvalidInput
	}
	return reason, nil
}

func platformIdentityProviderAuditReasonIsHTTPValue(reason string) bool {
	if reason == "" || reason[0] == ' ' || reason[len(reason)-1] == ' ' {
		return false
	}
	for index := 0; index < len(reason); index++ {
		if reason[index] < 0x20 || reason[index] > 0x7e || reason[index] == ',' {
			return false
		}
	}
	return true
}

func (h *Handler) writePlatformIdentityProviderError(
	w http.ResponseWriter,
	r *http.Request,
	err error,
) {
	if errors.Is(err, context.Canceled) {
		if errors.Is(r.Context().Err(), context.Canceled) {
			return
		}
		err = authentication.ErrUnavailable
	}
	if errors.Is(err, context.DeadlineExceeded) {
		err = authentication.ErrUnavailable
	}
	if errors.Is(err, authentication.ErrNotFound) {
		w.Header().Set("Cache-Control", "no-store")
		writeProblem(
			w, r, http.StatusNotFound, "not_found", "Resource not found",
			"The requested platform identity provider does not exist.",
		)
		return
	}
	if errors.Is(err, platformidentityprovider.ErrPreconditionFailed) {
		w.Header().Set("Cache-Control", "no-store")
		writeProblem(
			w, r, http.StatusPreconditionFailed, "precondition_failed", "Precondition failed",
			"The platform identity provider changed after the supplied version was issued.",
		)
		return
	}
	if errors.Is(err, platformidentityprovider.ErrSAMLTrustApprovalRequired) {
		w.Header().Set("Cache-Control", "no-store")
		writeProblem(
			w, r, http.StatusConflict, "saml_trust_approval_required", "SAML trust approval required",
			"The metadata replacement changes protected trust without certificate continuity. Review the new trust out of band and retry the exact current-version request with explicit approval.",
		)
		return
	}
	writeDomainError(w, r, err)
}

func platformAuthProviderLocation(providerID uuid.UUID) string {
	return fmt.Sprintf("/api/v1/platform/auth-providers/%s", providerID)
}

var _ PlatformIdentityProviderService = unavailablePlatformIdentityProviderService{}
