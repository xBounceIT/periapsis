package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentitybinding"
)

type unavailablePlatformIdentityBindingService struct{}

func platformIdentityBindingServiceIsNil(service PlatformIdentityBindingService) bool {
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

func (unavailablePlatformIdentityBindingService) List(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformidentitybinding.ListInput,
) (platformidentitybinding.BindingPage, error) {
	return platformidentitybinding.BindingPage{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityBindingService) Get(
	context.Context,
	authentication.Session,
	uuid.UUID,
	uuid.UUID,
) (platformidentitybinding.Binding, error) {
	return platformidentitybinding.Binding{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityBindingService) Create(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformidentitybinding.CreateInput,
) (platformidentitybinding.CreateResult, error) {
	return platformidentitybinding.CreateResult{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityBindingService) Update(
	context.Context,
	authentication.Session,
	uuid.UUID,
	uuid.UUID,
	platformidentitybinding.UpdateInput,
) (platformidentitybinding.UpdateResult, error) {
	return platformidentitybinding.UpdateResult{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityBindingService) Archive(
	context.Context,
	authentication.Session,
	uuid.UUID,
	uuid.UUID,
	platformidentitybinding.ArchiveInput,
) (platformidentitybinding.MutationReceipt, error) {
	return platformidentitybinding.MutationReceipt{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityBindingService) Activate(
	context.Context,
	authentication.Session,
	uuid.UUID,
	uuid.UUID,
	platformidentitybinding.ActivateInput,
) (platformidentitybinding.UpdateResult, error) {
	return platformidentitybinding.UpdateResult{}, authentication.ErrUnavailable
}

func (unavailablePlatformIdentityBindingService) Deactivate(
	context.Context,
	authentication.Session,
	uuid.UUID,
	uuid.UUID,
	platformidentitybinding.DeactivateInput,
) (platformidentitybinding.UpdateResult, error) {
	return platformidentitybinding.UpdateResult{}, authentication.ErrUnavailable
}

func (h *Handler) ListPlatformAuthProviderTenantBindings(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.ListPlatformAuthProviderTenantBindingsParams,
) {
	session, ok := h.platformIdentityProviderSession(w, r, false)
	if !ok {
		return
	}
	if err := requireTenantLDAPBodyAbsent(r); err != nil {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrInvalidInput)
		return
	}
	input := platformidentitybinding.ListInput{
		IncludeArchived: params.IncludeArchived != nil && bool(*params.IncludeArchived),
	}
	if params.After != nil {
		value := uuid.UUID(*params.After)
		input.After = &value
	}
	if params.Limit != nil {
		input.Limit = int(*params.Limit)
	}
	page, err := h.platformIdentityBindings.List(r.Context(), session, uuid.UUID(providerID), input)
	if err != nil {
		h.writePlatformIdentityBindingError(w, r, err)
		return
	}
	mapped, err := mapPlatformIdentityBindingPage(page)
	if err != nil {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) CreatePlatformAuthProviderTenantBinding(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	params contract.CreatePlatformAuthProviderTenantBindingParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil || idempotencyKey != string(params.IdempotencyKey) {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrInvalidInput)
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformAuthProviderTenantBindingCreateRequest
	if err := decodePlatformIdentityBindingCreateBody(r, &body); err != nil {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrInvalidInput)
		return
	}
	result, err := h.platformIdentityBindings.Create(
		r.Context(), session, uuid.UUID(providerID), platformidentitybinding.CreateInput{
			TenantID: uuid.UUID(body.TenantId), LoginKey: body.LoginKey,
			ProfilePriority: body.ProfilePriority, Reason: reason,
			IdempotencyKey: idempotencyKey, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityBindingError(w, r, err)
		return
	}
	binding := result.Binding()
	if result.BindingID() != binding.ID || binding.ProviderID != uuid.UUID(providerID) {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrUnavailable)
		return
	}
	mapped, err := mapPlatformIdentityBinding(binding)
	if err != nil || !setPlatformIdentityBindingETag(w, binding.Version, binding.Tenant.Version) {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrUnavailable)
		return
	}
	w.Header().Set("Location", platformIdentityBindingLocation(binding.ProviderID, binding.ID))
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) GetPlatformAuthProviderTenantBinding(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	bindingID contract.PlatformAuthProviderTenantBindingId,
) {
	session, ok := h.platformIdentityProviderSession(w, r, false)
	if !ok {
		return
	}
	if err := requireTenantLDAPBodyAbsent(r); err != nil {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrInvalidInput)
		return
	}
	binding, err := h.platformIdentityBindings.Get(
		r.Context(), session, uuid.UUID(providerID), uuid.UUID(bindingID),
	)
	if err != nil {
		h.writePlatformIdentityBindingError(w, r, err)
		return
	}
	if binding.ID != uuid.UUID(bindingID) || binding.ProviderID != uuid.UUID(providerID) {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrUnavailable)
		return
	}
	mapped, err := mapPlatformIdentityBinding(binding)
	if err != nil || !setPlatformIdentityBindingETag(w, binding.Version, binding.Tenant.Version) {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) UpdatePlatformAuthProviderTenantBinding(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	bindingID contract.PlatformAuthProviderTenantBindingId,
	params contract.UpdatePlatformAuthProviderTenantBindingParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformAuthProviderTenantBindingPatchRequest
	if err := decodePlatformIdentityBindingUpdateBody(r, &body); err != nil {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrInvalidInput)
		return
	}
	entityTag, ok := h.platformIdentityBindingPrecondition(
		w, r, string(params.IfMatch), body.ExpectedVersion, body.ExpectedTenantVersion,
	)
	if !ok {
		return
	}
	result, err := h.platformIdentityBindings.Update(
		r.Context(), session, uuid.UUID(providerID), uuid.UUID(bindingID),
		platformidentitybinding.UpdateInput{
			LoginKey: body.LoginKey, ProfilePriority: body.ProfilePriority,
			Reason: reason, ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityBindingError(w, r, err)
		return
	}
	binding := result.Binding()
	if result.BindingID() != uuid.UUID(bindingID) || binding.ID != uuid.UUID(bindingID) ||
		binding.ProviderID != uuid.UUID(providerID) {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrUnavailable)
		return
	}
	mapped, err := mapPlatformIdentityBinding(binding)
	if err != nil || !setPlatformIdentityBindingETag(w, binding.Version, binding.Tenant.Version) {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ArchivePlatformAuthProviderTenantBinding(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	bindingID contract.PlatformAuthProviderTenantBindingId,
	params contract.ArchivePlatformAuthProviderTenantBindingParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformAuthProviderTenantBindingArchiveRequest
	if err := decodePlatformIdentityBindingArchiveBody(r, &body); err != nil {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrInvalidInput)
		return
	}
	entityTag, ok := h.platformIdentityBindingPrecondition(
		w, r, string(params.IfMatch), body.ExpectedVersion, body.ExpectedTenantVersion,
	)
	if !ok {
		return
	}
	receipt, err := h.platformIdentityBindings.Archive(
		r.Context(), session, uuid.UUID(providerID), uuid.UUID(bindingID),
		platformidentitybinding.ArchiveInput{
			Reason: reason, ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityBindingError(w, r, err)
		return
	}
	if receipt.BindingID() != uuid.UUID(bindingID) ||
		!setPlatformIdentityBindingETag(w, receipt.Version(), receipt.TenantVersion()) {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ActivatePlatformAuthProviderTenantBinding(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	bindingID contract.PlatformAuthProviderTenantBindingId,
	params contract.ActivatePlatformAuthProviderTenantBindingParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformAuthProviderTenantBindingActivationRequest
	if err := decodePlatformIdentityBindingActivationBody(r, &body); err != nil ||
		!body.JitMode.Valid() || !body.NoMatchPolicy.Valid() {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrInvalidInput)
		return
	}
	entityTag, ok := h.platformIdentityBindingPrecondition(
		w, r, string(params.IfMatch), body.ExpectedVersion, body.ExpectedTenantVersion,
	)
	if !ok {
		return
	}
	result, err := h.platformIdentityBindings.Activate(
		r.Context(), session, uuid.UUID(providerID), uuid.UUID(bindingID),
		platformidentitybinding.ActivateInput{
			JITMode:       platformidentitybinding.JITMode(body.JitMode),
			NoMatchPolicy: platformidentitybinding.NoMatchPolicy(body.NoMatchPolicy),
			Reason:        reason, ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityBindingError(w, r, err)
		return
	}
	h.writePlatformIdentityBindingMutationResult(w, r, uuid.UUID(providerID), uuid.UUID(bindingID), result)
}

func (h *Handler) DeactivatePlatformAuthProviderTenantBinding(
	w http.ResponseWriter,
	r *http.Request,
	providerID contract.PlatformAuthProviderId,
	bindingID contract.PlatformAuthProviderTenantBindingId,
	params contract.DeactivatePlatformAuthProviderTenantBindingParams,
) {
	session, event, ok := h.platformIdentityProviderMutation(w, r)
	if !ok {
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrInvalidInput)
		return
	}
	var body contract.PlatformAuthProviderTenantBindingDeactivationRequest
	if err := decodePlatformIdentityBindingDeactivationBody(r, &body); err != nil {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrInvalidInput)
		return
	}
	entityTag, ok := h.platformIdentityBindingPrecondition(
		w, r, string(params.IfMatch), body.ExpectedVersion, body.ExpectedTenantVersion,
	)
	if !ok {
		return
	}
	result, err := h.platformIdentityBindings.Deactivate(
		r.Context(), session, uuid.UUID(providerID), uuid.UUID(bindingID),
		platformidentitybinding.DeactivateInput{
			Reason: reason, ExpectedEntityTag: entityTag, Event: event,
		},
	)
	if err != nil {
		h.writePlatformIdentityBindingError(w, r, err)
		return
	}
	h.writePlatformIdentityBindingMutationResult(w, r, uuid.UUID(providerID), uuid.UUID(bindingID), result)
}

func (h *Handler) writePlatformIdentityBindingMutationResult(
	w http.ResponseWriter,
	r *http.Request,
	providerID, bindingID uuid.UUID,
	result platformidentitybinding.UpdateResult,
) {
	binding := result.Binding()
	if result.BindingID() != bindingID || binding.ID != bindingID || binding.ProviderID != providerID {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrUnavailable)
		return
	}
	mapped, err := mapPlatformIdentityBinding(binding)
	if err != nil || !setPlatformIdentityBindingETag(w, binding.Version, binding.Tenant.Version) {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) writePlatformIdentityBindingError(
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
			"The requested platform identity binding does not exist.",
		)
		return
	}
	if errors.Is(err, platformidentitybinding.ErrPreconditionFailed) {
		w.Header().Set("Cache-Control", "no-store")
		writeProblem(
			w, r, http.StatusPreconditionFailed, "precondition_failed", "Precondition failed",
			"The platform identity binding changed after the supplied version was issued.",
		)
		return
	}
	writeDomainError(w, r, err)
}

func platformIdentityBindingLocation(providerID, bindingID uuid.UUID) string {
	return fmt.Sprintf(
		"/api/v1/platform/auth-providers/%s/tenant-bindings/%s", providerID, bindingID,
	)
}

func (h *Handler) platformIdentityBindingPrecondition(
	w http.ResponseWriter,
	r *http.Request,
	contractValue string,
	bodyVersion, bodyTenantVersion int64,
) (*string, bool) {
	values := r.Header.Values(ifMatchHeader)
	if len(values) == 0 {
		writeProblem(
			w, r, http.StatusPreconditionRequired, "precondition_required", "Precondition required",
			"A current strong tenant-binding If-Match entity tag is required.",
		)
		return nil, false
	}
	if len(values) != 1 {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrInvalidInput)
		return nil, false
	}

	value := values[0]
	bindingVersion, tenantVersion, err := platformidentitybinding.ParseEntityTag(value)
	canonical, canonicalErr := platformidentitybinding.EntityTag(bindingVersion, tenantVersion)
	if err != nil || canonicalErr != nil || value != contractValue || canonical != value ||
		bodyVersion != bindingVersion || bodyTenantVersion != tenantVersion ||
		bindingVersion > maximumIncrementableResourceVersion {
		h.writePlatformIdentityBindingError(w, r, authentication.ErrInvalidInput)
		return nil, false
	}
	return &canonical, true
}

func setPlatformIdentityBindingETag(
	w http.ResponseWriter,
	bindingVersion, tenantVersion int64,
) bool {
	value, err := platformidentitybinding.EntityTag(bindingVersion, tenantVersion)
	if err != nil {
		return false
	}
	w.Header().Set("ETag", value)
	return true
}

var _ PlatformIdentityBindingService = unavailablePlatformIdentityBindingService{}
