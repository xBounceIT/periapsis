package platformidentitybinding

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"reflect"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type Service struct {
	repository Repository
	evaluator  authorization.Evaluator
	newID      func() (uuid.UUID, error)
}

func NewService(repository Repository) (*Service, error) {
	if interfaceIsNil(repository) {
		return nil, errors.New("platform identity binding repository is required")
	}
	return &Service{repository: repository, evaluator: authorization.Evaluator{}, newID: uuid.NewV7}, nil
}

func (service *Service) List(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input ListInput,
) (BindingPage, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityBindingRead); err != nil {
		return BindingPage{}, err
	}
	if !validSession(session) {
		return BindingPage{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return BindingPage{}, err
	}
	normalized, err := normalizeList(providerID, input)
	if err != nil {
		return BindingPage{}, err
	}
	rows, err := service.repository.List(ctx, ListParams{
		SessionParams: sessionParams(session), ProviderID: providerID, After: normalized.After,
		Limit: int32(normalized.Limit + 1), IncludeArchived: normalized.IncludeArchived,
	})
	if err != nil {
		return BindingPage{}, mapRepositoryError(err)
	}
	if len(rows) > normalized.Limit+1 {
		return BindingPage{}, authentication.ErrUnavailable
	}
	for index := range rows {
		if !validBinding(rows[index]) || rows[index].ProviderID != providerID ||
			!normalized.IncludeArchived && rows[index].ArchivedAt != nil ||
			index > 0 && bytes.Compare(rows[index-1].ID[:], rows[index].ID[:]) >= 0 ||
			normalized.After != nil && bytes.Compare(rows[index].ID[:], normalized.After[:]) <= 0 {
			return BindingPage{}, authentication.ErrUnavailable
		}
	}
	page := BindingPage{Items: make([]Binding, min(len(rows), normalized.Limit))}
	for index := range page.Items {
		page.Items[index] = cloneBinding(rows[index])
	}
	if len(rows) > normalized.Limit {
		next := page.Items[len(page.Items)-1].ID
		page.NextCursor = &next
	}
	return page, nil
}

func (service *Service) Get(
	ctx context.Context,
	session authentication.Session,
	providerID, bindingID uuid.UUID,
) (Binding, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityBindingRead); err != nil {
		return Binding{}, err
	}
	if !validSession(session) {
		return Binding{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return Binding{}, err
	}
	if !validUUIDv7(providerID) || !validUUIDv7(bindingID) {
		return Binding{}, authentication.ErrInvalidInput
	}
	binding, err := service.repository.Get(ctx, GetParams{
		SessionParams: sessionParams(session), ProviderID: providerID, BindingID: bindingID,
	})
	if err != nil {
		return Binding{}, mapRepositoryError(err)
	}
	if binding.ID != bindingID || binding.ProviderID != providerID || !validBinding(binding) {
		return Binding{}, authentication.ErrUnavailable
	}
	return cloneBinding(binding), nil
}

func (service *Service) Create(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input CreateInput,
) (CreateResult, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityBindingManage); err != nil {
		return CreateResult{}, err
	}
	if err := service.require(session, authorization.PermissionPlatformIdentityBindingRead); err != nil {
		return CreateResult{}, err
	}
	if !validSession(session) {
		return CreateResult{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return CreateResult{}, err
	}
	normalized, requestDigest, err := normalizeCreate(providerID, input)
	if err != nil {
		return CreateResult{}, err
	}
	commandID, err := service.nextID()
	if err != nil {
		return CreateResult{}, err
	}
	bindingID, err := service.nextID()
	if err != nil {
		return CreateResult{}, err
	}
	keyDigest := sha256.Sum256([]byte(normalized.IdempotencyKey))
	validateResult := func(result CreateResult) (CreateResult, error) {
		validated, validationErr := validateCreateResult(result)
		binding := validated.Binding()
		if validationErr != nil || binding.ProviderID != providerID || binding.Tenant.ID != normalized.TenantID ||
			!validated.Replayed() && (validated.BindingID() != bindingID ||
				binding.LoginKey != normalized.LoginKey ||
				binding.ProfilePriority != normalized.ProfilePriority || !initialBindingProjection(binding)) {
			return CreateResult{}, authentication.ErrUnavailable
		}
		return validated, nil
	}
	result, err := service.repository.Create(ctx, CreateParams{
		SessionParams: sessionParams(session), CommandID: commandID, BindingID: bindingID,
		ProviderID: providerID, TenantID: normalized.TenantID, LoginKey: normalized.LoginKey,
		ProfilePriority: normalized.ProfilePriority, KeyDigest: keyDigest,
		RequestDigest: requestDigest, Reason: normalized.Reason, Event: normalized.Event,
		ValidateResult: validateResult,
	})
	clear(keyDigest[:])
	clear(requestDigest[:])
	if err != nil {
		return CreateResult{}, mapRepositoryError(err)
	}
	return validateResult(result)
}

func (service *Service) Update(
	ctx context.Context,
	session authentication.Session,
	providerID, bindingID uuid.UUID,
	input UpdateInput,
) (UpdateResult, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityBindingManage); err != nil {
		return UpdateResult{}, err
	}
	if err := service.require(session, authorization.PermissionPlatformIdentityBindingRead); err != nil {
		return UpdateResult{}, err
	}
	if !validSession(session) {
		return UpdateResult{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return UpdateResult{}, err
	}
	normalized, expectedVersion, expectedTenantVersion, err := normalizeUpdate(providerID, bindingID, input)
	if err != nil {
		return UpdateResult{}, err
	}
	validateResult := func(result UpdateResult) (UpdateResult, error) {
		validated, validationErr := validateUpdateResult(result)
		binding := validated.Binding()
		if validationErr != nil || validated.BindingID() != bindingID ||
			validated.Version() != expectedVersion+1 || binding.ProviderID != providerID ||
			binding.Tenant.Version != expectedTenantVersion ||
			binding.ArchivedAt != nil || binding.LoginKey != normalized.LoginKey ||
			binding.ProfilePriority != normalized.ProfilePriority {
			return UpdateResult{}, authentication.ErrUnavailable
		}
		return validated, nil
	}
	result, err := service.repository.Update(ctx, UpdateParams{
		SessionParams: sessionParams(session), ProviderID: providerID, BindingID: bindingID,
		ExpectedVersion: expectedVersion, ExpectedTenantVersion: expectedTenantVersion,
		LoginKey:        normalized.LoginKey,
		ProfilePriority: normalized.ProfilePriority, Reason: normalized.Reason,
		Event: normalized.Event, ValidateResult: validateResult,
	})
	if err != nil {
		return UpdateResult{}, mapRepositoryError(err)
	}
	return validateResult(result)
}

func (service *Service) Archive(
	ctx context.Context,
	session authentication.Session,
	providerID, bindingID uuid.UUID,
	input ArchiveInput,
) (MutationReceipt, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityBindingManage); err != nil {
		return MutationReceipt{}, err
	}
	if !validSession(session) {
		return MutationReceipt{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return MutationReceipt{}, err
	}
	normalized, expectedVersion, expectedTenantVersion, err := normalizeArchive(providerID, bindingID, input)
	if err != nil {
		return MutationReceipt{}, err
	}
	receipt, err := service.repository.Archive(ctx, ArchiveParams{
		SessionParams: sessionParams(session), ProviderID: providerID, BindingID: bindingID,
		ExpectedVersion: expectedVersion, ExpectedTenantVersion: expectedTenantVersion,
		Reason: normalized.Reason, Event: normalized.Event,
	})
	if err != nil {
		return MutationReceipt{}, mapRepositoryError(err)
	}
	if validateMutationReceipt(receipt) != nil || receipt.BindingID() != bindingID ||
		receipt.Version() != expectedVersion+1 || receipt.TenantVersion() != expectedTenantVersion {
		return MutationReceipt{}, authentication.ErrUnavailable
	}
	return receipt, nil
}

func (service *Service) Activate(
	ctx context.Context,
	session authentication.Session,
	providerID, bindingID uuid.UUID,
	input ActivateInput,
) (UpdateResult, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityBindingManage); err != nil {
		return UpdateResult{}, err
	}
	if err := service.require(session, authorization.PermissionPlatformIdentityBindingRead); err != nil {
		return UpdateResult{}, err
	}
	if !validSession(session) {
		return UpdateResult{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return UpdateResult{}, err
	}
	normalized, expectedVersion, expectedTenantVersion, err := normalizeActivate(
		providerID, bindingID, input,
	)
	if err != nil {
		return UpdateResult{}, err
	}
	validateResult := func(result UpdateResult) (UpdateResult, error) {
		validated, validationErr := validateUpdateResult(result)
		binding := validated.Binding()
		if validationErr != nil || validated.BindingID() != bindingID ||
			validated.Version() != expectedVersion+1 || binding.ProviderID != providerID ||
			binding.Tenant.Version != expectedTenantVersion || !binding.Enabled ||
			binding.ActivationAvailable || binding.CurrentAccessEpochID == nil ||
			binding.JITMode != normalized.JITMode || binding.NoMatchPolicy != normalized.NoMatchPolicy ||
			binding.ArchivedAt != nil {
			return UpdateResult{}, authentication.ErrUnavailable
		}
		return validated, nil
	}
	result, err := service.repository.Activate(ctx, ActivationParams{
		SessionParams: sessionParams(session), ProviderID: providerID, BindingID: bindingID,
		ExpectedVersion: expectedVersion, ExpectedTenantVersion: expectedTenantVersion,
		JITMode: normalized.JITMode, NoMatchPolicy: normalized.NoMatchPolicy,
		Reason: normalized.Reason, Event: normalized.Event, ValidateResult: validateResult,
	})
	if err != nil {
		return UpdateResult{}, mapRepositoryError(err)
	}
	return validateResult(result)
}

func (service *Service) Deactivate(
	ctx context.Context,
	session authentication.Session,
	providerID, bindingID uuid.UUID,
	input DeactivateInput,
) (UpdateResult, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityBindingManage); err != nil {
		return UpdateResult{}, err
	}
	if err := service.require(session, authorization.PermissionPlatformIdentityBindingRead); err != nil {
		return UpdateResult{}, err
	}
	if !validSession(session) {
		return UpdateResult{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return UpdateResult{}, err
	}
	normalized, expectedVersion, expectedTenantVersion, err := normalizeDeactivate(
		providerID, bindingID, input,
	)
	if err != nil {
		return UpdateResult{}, err
	}
	validateResult := func(result UpdateResult) (UpdateResult, error) {
		validated, validationErr := validateUpdateResult(result)
		binding := validated.Binding()
		if validationErr != nil || validated.BindingID() != bindingID ||
			validated.Version() != expectedVersion+1 || binding.ProviderID != providerID ||
			binding.Tenant.Version != expectedTenantVersion || binding.Enabled ||
			binding.CurrentAccessEpochID != nil ||
			binding.JITMode != JITModeDisabled || binding.NoMatchPolicy != NoMatchPolicyDeny ||
			binding.ArchivedAt != nil {
			return UpdateResult{}, authentication.ErrUnavailable
		}
		return validated, nil
	}
	result, err := service.repository.Deactivate(ctx, DeactivationParams{
		SessionParams: sessionParams(session), ProviderID: providerID, BindingID: bindingID,
		ExpectedVersion: expectedVersion, ExpectedTenantVersion: expectedTenantVersion,
		Reason: normalized.Reason, Event: normalized.Event, ValidateResult: validateResult,
	})
	if err != nil {
		return UpdateResult{}, mapRepositoryError(err)
	}
	return validateResult(result)
}

func (service *Service) require(session authentication.Session, permission authorization.Permission) error {
	if service == nil || interfaceIsNil(service.repository) || service.newID == nil {
		return authentication.ErrUnavailable
	}
	if err := service.evaluator.Require(session.Permissions, permission); err != nil {
		return authentication.ErrForbidden
	}
	return nil
}

func (service *Service) nextID() (uuid.UUID, error) {
	id, err := service.newID()
	if err != nil || !validUUIDv7(id) {
		return uuid.Nil, authentication.ErrUnavailable
	}
	return id, nil
}

func sessionParams(session authentication.Session) SessionParams {
	return SessionParams{
		ActorID: session.User.ID, SessionID: session.ID, AuthenticationMethod: session.AuthenticationMethod,
	}
}

func validateCreateResult(result CreateResult) (CreateResult, error) {
	restored, err := RestoreCreateResult(CreateResultInput{
		BindingID: result.receipt.bindingID, Version: result.receipt.version,
		Replayed: result.receipt.replayed, Binding: result.binding,
	})
	if err != nil || !validBinding(restored.binding) {
		return CreateResult{}, authentication.ErrInvalidInput
	}
	return restored, nil
}

func validateUpdateResult(result UpdateResult) (UpdateResult, error) {
	restored, err := RestoreUpdateResult(UpdateResultInput{
		BindingID: result.receipt.bindingID, Version: result.receipt.version, Binding: result.binding,
	})
	if err != nil || !validBinding(restored.binding) {
		return UpdateResult{}, authentication.ErrInvalidInput
	}
	return restored, nil
}

func validateMutationReceipt(receipt MutationReceipt) error {
	restored, err := RestoreMutationReceipt(MutationReceiptInput{
		BindingID: receipt.bindingID, Version: receipt.version, TenantVersion: receipt.tenantVersion,
	})
	if err != nil || restored != receipt {
		return authentication.ErrInvalidInput
	}
	return nil
}

func mapRepositoryError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, authentication.ErrForbidden):
		return authentication.ErrForbidden
	case errors.Is(err, authentication.ErrNotFound):
		return authentication.ErrNotFound
	case errors.Is(err, authentication.ErrConflict):
		return authentication.ErrConflict
	case errors.Is(err, authentication.ErrInvalidInput):
		return authentication.ErrInvalidInput
	case errors.Is(err, ErrPreconditionFailed):
		return ErrPreconditionFailed
	default:
		return authentication.ErrUnavailable
	}
}

func serviceContextError(ctx context.Context) error {
	if interfaceIsNil(ctx) {
		return authentication.ErrUnavailable
	}
	return ctx.Err()
}

func interfaceIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (*Service) String() string {
	return "platformidentitybinding.Service{dependencies:[REDACTED]}"
}

func (service *Service) GoString() string { return service.String() }
