package platformidentitybinding

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

// Repository is the cross-boundary persistence port. Implementations must use
// only the protected database ABI, reinstall the exact actor context, and
// validate mutation projections before committing their correlated audits.
type Repository interface {
	List(context.Context, ListParams) ([]Binding, error)
	Get(context.Context, GetParams) (Binding, error)
	Create(context.Context, CreateParams) (CreateResult, error)
	Update(context.Context, UpdateParams) (UpdateResult, error)
	Archive(context.Context, ArchiveParams) (MutationReceipt, error)
	Activate(context.Context, ActivationParams) (UpdateResult, error)
	Deactivate(context.Context, DeactivationParams) (UpdateResult, error)
}

type SessionParams struct {
	ActorID              uuid.UUID
	SessionID            uuid.UUID
	AuthenticationMethod string
}

type ListParams struct {
	SessionParams
	ProviderID      uuid.UUID
	After           *uuid.UUID
	Limit           int32
	IncludeArchived bool
}

type GetParams struct {
	SessionParams
	ProviderID uuid.UUID
	BindingID  uuid.UUID
}

type CreateResultValidator func(CreateResult) (CreateResult, error)
type UpdateResultValidator func(UpdateResult) (UpdateResult, error)

type CreateParams struct {
	SessionParams
	CommandID       uuid.UUID
	BindingID       uuid.UUID
	ProviderID      uuid.UUID
	TenantID        uuid.UUID
	LoginKey        string
	ProfilePriority int
	KeyDigest       [sha256.Size]byte
	RequestDigest   [sha256.Size]byte
	Reason          string
	Event           authentication.EventContext
	ValidateResult  CreateResultValidator
}

func (params CreateParams) String() string {
	return fmt.Sprintf(
		"platformidentitybinding.CreateParams{priority:%d,digests:true,metadata:[REDACTED]}",
		params.ProfilePriority,
	)
}

func (params CreateParams) GoString() string { return params.String() }

type UpdateParams struct {
	SessionParams
	ProviderID            uuid.UUID
	BindingID             uuid.UUID
	ExpectedVersion       int64
	ExpectedTenantVersion int64
	LoginKey              string
	ProfilePriority       int
	Reason                string
	Event                 authentication.EventContext
	ValidateResult        UpdateResultValidator
}

func (params UpdateParams) String() string {
	return fmt.Sprintf(
		"platformidentitybinding.UpdateParams{expected_version:%d,expected_tenant_version:%d,priority:%d,metadata:[REDACTED]}",
		params.ExpectedVersion, params.ExpectedTenantVersion, params.ProfilePriority,
	)
}

func (params UpdateParams) GoString() string { return params.String() }

type ArchiveParams struct {
	SessionParams
	ProviderID            uuid.UUID
	BindingID             uuid.UUID
	ExpectedVersion       int64
	ExpectedTenantVersion int64
	Reason                string
	Event                 authentication.EventContext
}

type ActivationParams struct {
	SessionParams
	ProviderID            uuid.UUID
	BindingID             uuid.UUID
	ExpectedVersion       int64
	ExpectedTenantVersion int64
	JITMode               JITMode
	NoMatchPolicy         NoMatchPolicy
	Reason                string
	Event                 authentication.EventContext
	ValidateResult        UpdateResultValidator
}

type DeactivationParams struct {
	SessionParams
	ProviderID            uuid.UUID
	BindingID             uuid.UUID
	ExpectedVersion       int64
	ExpectedTenantVersion int64
	Reason                string
	Event                 authentication.EventContext
	ValidateResult        UpdateResultValidator
}

func (params ArchiveParams) String() string {
	return fmt.Sprintf(
		"platformidentitybinding.ArchiveParams{expected_version:%d,expected_tenant_version:%d,metadata:[REDACTED]}",
		params.ExpectedVersion, params.ExpectedTenantVersion,
	)
}

func (params ArchiveParams) GoString() string { return params.String() }

type CreateReceiptInput struct {
	BindingID uuid.UUID
	Version   int64
	Replayed  bool
}

type CreateReceipt struct {
	bindingID uuid.UUID
	version   int64
	replayed  bool
}

func RestoreCreateReceipt(input CreateReceiptInput) (CreateReceipt, error) {
	if !validUUIDv7(input.BindingID) || input.Version != 1 {
		return CreateReceipt{}, authentication.ErrInvalidInput
	}
	return CreateReceipt{bindingID: input.BindingID, version: input.Version, replayed: input.Replayed}, nil
}

func (receipt CreateReceipt) BindingID() uuid.UUID { return receipt.bindingID }
func (receipt CreateReceipt) Version() int64       { return receipt.version }
func (receipt CreateReceipt) Replayed() bool       { return receipt.replayed }

func (receipt CreateReceipt) String() string {
	return fmt.Sprintf(
		"platformidentitybinding.CreateReceipt{version:%d,replayed:%t,metadata:[REDACTED]}",
		receipt.version, receipt.replayed,
	)
}

func (receipt CreateReceipt) GoString() string { return receipt.String() }

type CreateResultInput struct {
	BindingID uuid.UUID
	Version   int64
	Replayed  bool
	Binding   Binding
}

type CreateResult struct {
	receipt CreateReceipt
	binding Binding
}

func RestoreCreateResult(input CreateResultInput) (CreateResult, error) {
	receipt, err := RestoreCreateReceipt(CreateReceiptInput{
		BindingID: input.BindingID, Version: input.Version, Replayed: input.Replayed,
	})
	if err != nil || input.Binding.ID != input.BindingID || !validResourceVersion(input.Binding.Version) ||
		(!input.Replayed && input.Binding.Version != input.Version) ||
		(input.Replayed && input.Binding.Version < input.Version) {
		return CreateResult{}, authentication.ErrInvalidInput
	}
	return CreateResult{receipt: receipt, binding: cloneBinding(input.Binding)}, nil
}

func (result CreateResult) BindingID() uuid.UUID { return result.receipt.BindingID() }
func (result CreateResult) Version() int64       { return result.receipt.Version() }
func (result CreateResult) Replayed() bool       { return result.receipt.Replayed() }
func (result CreateResult) Binding() Binding     { return cloneBinding(result.binding) }

func (result CreateResult) String() string {
	return fmt.Sprintf(
		"platformidentitybinding.CreateResult{receipt_version:%d,projection_version:%d,replayed:%t,metadata:[REDACTED]}",
		result.Version(), result.binding.Version, result.Replayed(),
	)
}

func (result CreateResult) GoString() string { return result.String() }

type MutationReceiptInput struct {
	BindingID     uuid.UUID
	Version       int64
	TenantVersion int64
}

type MutationReceipt struct {
	bindingID     uuid.UUID
	version       int64
	tenantVersion int64
}

func RestoreMutationReceipt(input MutationReceiptInput) (MutationReceipt, error) {
	if !validUUIDv7(input.BindingID) || !validResourceVersion(input.Version) || input.Version < 2 ||
		!validResourceVersion(input.TenantVersion) {
		return MutationReceipt{}, authentication.ErrInvalidInput
	}
	return MutationReceipt{
		bindingID: input.BindingID, version: input.Version, tenantVersion: input.TenantVersion,
	}, nil
}

func (receipt MutationReceipt) BindingID() uuid.UUID { return receipt.bindingID }
func (receipt MutationReceipt) Version() int64       { return receipt.version }
func (receipt MutationReceipt) TenantVersion() int64 { return receipt.tenantVersion }

func (receipt MutationReceipt) String() string {
	return fmt.Sprintf(
		"platformidentitybinding.MutationReceipt{version:%d,tenant_version:%d,metadata:[REDACTED]}",
		receipt.version, receipt.tenantVersion,
	)
}

func (receipt MutationReceipt) GoString() string { return receipt.String() }

type UpdateResultInput struct {
	BindingID uuid.UUID
	Version   int64
	Binding   Binding
}

type UpdateResult struct {
	receipt MutationReceipt
	binding Binding
}

func RestoreUpdateResult(input UpdateResultInput) (UpdateResult, error) {
	receipt, err := RestoreMutationReceipt(MutationReceiptInput{
		BindingID: input.BindingID, Version: input.Version, TenantVersion: input.Binding.Tenant.Version,
	})
	if err != nil || input.Binding.ID != input.BindingID || input.Binding.Version != input.Version {
		return UpdateResult{}, authentication.ErrInvalidInput
	}
	return UpdateResult{receipt: receipt, binding: cloneBinding(input.Binding)}, nil
}

func (result UpdateResult) BindingID() uuid.UUID { return result.receipt.BindingID() }
func (result UpdateResult) Version() int64       { return result.receipt.Version() }
func (result UpdateResult) Binding() Binding     { return cloneBinding(result.binding) }

func (result UpdateResult) String() string {
	return fmt.Sprintf(
		"platformidentitybinding.UpdateResult{version:%d,metadata:[REDACTED]}", result.Version(),
	)
}

func (result UpdateResult) GoString() string { return result.String() }
