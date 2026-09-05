package dfir

import (
	"context"
	"errors"

	"github.com/google/uuid"
	contactkernel "github.com/periapsis-im/periapsis/modules/contacts"
	applicationcontacts "github.com/periapsis-im/periapsis/services/api/internal/contacts"
)

type contactPortalAuthorizationService interface {
	AuthorizePortalResource(
		context.Context,
		applicationcontacts.Actor,
		uuid.UUID,
		applicationcontacts.PortalResourceInput,
	) (applicationcontacts.PortalAuthorization, error)
}

type contactPortalAuthorizer struct {
	service contactPortalAuthorizationService
}

func NewContactPortalAuthorizer(service contactPortalAuthorizationService) PortalAttachmentAuthorizer {
	if service == nil {
		return nil
	}
	return contactPortalAuthorizer{service: service}
}

func (authorizer contactPortalAuthorizer) AuthorizePortalAttachment(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	root PortalAttachmentRoot,
) (PortalAttachmentAuthorization, error) {
	kind, rootCapability, ok := contactPortalRoot(root.Kind)
	if !ok {
		return PortalAttachmentAuthorization{}, ErrForbidden
	}
	result, err := authorizer.service.AuthorizePortalResource(ctx, applicationcontacts.Actor{
		TenantID: tenantID, ActiveTenantID: actor.ActiveTenantID, UserID: actor.UserID,
		MembershipID: actor.MembershipID, SessionID: actor.SessionID,
		Kind: applicationcontacts.PrincipalCustomer, AuthenticationMethod: actor.AuthenticationMethod,
	}, tenantID, applicationcontacts.PortalResourceInput{
		TicketKind: kind, TicketID: uuid.UUID(root.ID.Bytes()),
		Capability: applicationcontacts.CapabilityPortalAttachmentRead, RequiredCapability: rootCapability,
	})
	if err != nil {
		return PortalAttachmentAuthorization{}, contactPortalAuthorizationError(err)
	}
	if result.TicketKind != kind || result.TicketID != uuid.UUID(root.ID.Bytes()) {
		return PortalAttachmentAuthorization{}, ErrForbidden
	}
	return PortalAttachmentAuthorization{
		TenantID: tenantID, Root: root, ContactID: result.ContactID, TicketVersion: result.TicketVersion,
	}, nil
}

func contactPortalRoot(kind PortalTicketKind) (contactkernel.TicketKind, applicationcontacts.Capability, bool) {
	switch kind {
	case PortalTicketAlert:
		return contactkernel.TicketAlert, applicationcontacts.CapabilityPortalAlertRead, true
	case PortalTicketCase:
		return contactkernel.TicketCase, applicationcontacts.CapabilityPortalCaseRead, true
	default:
		return 0, "", false
	}
}

func contactPortalAuthorizationError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, applicationcontacts.ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, applicationcontacts.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, applicationcontacts.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, applicationcontacts.ErrConflict):
		return ErrConflict
	case errors.Is(err, applicationcontacts.ErrPreconditionFailed):
		return ErrPreconditionFailed
	default:
		return ErrUnavailable
	}
}
