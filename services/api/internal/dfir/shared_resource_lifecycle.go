package dfir

import (
	"context"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

// SharedResourceLinkCommand changes only the association of an existing
// tenant-owned resource. The resource revision serializes content and links.
type SharedResourceLinkCommand struct {
	RootKind        kernel.EntityKind
	RootID          kernel.EntityID
	ResourceID      kernel.EntityID
	EventID         kernel.EntityID
	ExpectedVersion uint64
	Linked          bool
	Envelope        MutationEnvelope
}

type SharedResourceLinkWrite struct {
	BaseWrite
	ResourceID      kernel.EntityID
	EventID         kernel.EntityID
	ExpectedVersion uint64
	Linked          bool
}

type SharedResourceLinkRepository interface {
	ChangeIndicatorLink(context.Context, SharedResourceLinkWrite) (MutationResult[kernel.Indicator], error)
	ChangeAssetLink(context.Context, SharedResourceLinkWrite) (MutationResult[kernel.Asset], error)
}

func (service *Service) ChangeIndicatorLink(ctx context.Context, actor Actor, tenantID uuid.UUID, command SharedResourceLinkCommand) (MutationResult[kernel.Indicator], error) {
	write, err := service.sharedResourceLinkWrite(ctx, actor, tenantID, command, CapabilityIOCManage, "dfir.ioc")
	if err != nil {
		return MutationResult[kernel.Indicator]{}, err
	}
	repository, ok := service.repository.(SharedResourceLinkRepository)
	if !ok {
		return MutationResult[kernel.Indicator]{}, ErrUnavailable
	}
	result, err := repository.ChangeIndicatorLink(ctx, write)
	if err != nil {
		return MutationResult[kernel.Indicator]{}, repositoryError(err)
	}
	if result.Resource.ID() != command.ResourceID || !entityTenantMatches(result.Resource.TenantID(), tenantID) {
		return MutationResult[kernel.Indicator]{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) ChangeAssetLink(ctx context.Context, actor Actor, tenantID uuid.UUID, command SharedResourceLinkCommand) (MutationResult[kernel.Asset], error) {
	write, err := service.sharedResourceLinkWrite(ctx, actor, tenantID, command, CapabilityAssetManage, "dfir.asset")
	if err != nil {
		return MutationResult[kernel.Asset]{}, err
	}
	repository, ok := service.repository.(SharedResourceLinkRepository)
	if !ok {
		return MutationResult[kernel.Asset]{}, ErrUnavailable
	}
	result, err := repository.ChangeAssetLink(ctx, write)
	if err != nil {
		return MutationResult[kernel.Asset]{}, repositoryError(err)
	}
	if result.Resource.ID() != command.ResourceID || !entityTenantMatches(result.Resource.TenantID(), tenantID) {
		return MutationResult[kernel.Asset]{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) sharedResourceLinkWrite(ctx context.Context, actor Actor, tenantID uuid.UUID, command SharedResourceLinkCommand, capability Capability, prefix string) (SharedResourceLinkWrite, error) {
	if command.ResourceID == (kernel.EntityID{}) || command.EventID == (kernel.EntityID{}) ||
		command.ResourceID == command.EventID || !validResourceMutationVersion(command.ExpectedVersion) {
		return SharedResourceLinkWrite{}, ErrInvalidInput
	}
	var err error
	switch command.RootKind {
	case kernel.EntityCase:
		err = service.authorizeMutation(ctx, actor, tenantID, capability, command.RootID, command.Envelope)
	case kernel.EntityAlert:
		err = service.authorizeAlertMutation(ctx, actor, tenantID, capability, command.RootID, command.Envelope)
	default:
		return SharedResourceLinkWrite{}, ErrInvalidInput
	}
	if err != nil {
		return SharedResourceLinkWrite{}, err
	}
	operation := prefix + ".unlink"
	if command.Linked {
		operation = prefix + ".link"
	}
	payload := map[string]any{
		"tenantId": tenantID.String(), "rootKind": command.RootKind, "rootId": command.RootID.String(),
		"resourceId": command.ResourceID.String(), "eventId": command.EventID.String(), "expectedVersion": command.ExpectedVersion,
	}
	var base BaseWrite
	if command.RootKind == kernel.EntityCase {
		base, err = baseWrite(actor, command.RootID, command.Envelope, operation, payload)
	} else {
		base, err = alertBaseWrite(actor, command.RootID, command.Envelope, operation, payload)
	}
	return SharedResourceLinkWrite{BaseWrite: base, ResourceID: command.ResourceID, EventID: command.EventID,
		ExpectedVersion: command.ExpectedVersion, Linked: command.Linked}, err
}
