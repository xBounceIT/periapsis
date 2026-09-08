package contacts

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/contacts"
)

type Clock func() time.Time

type Service struct {
	repository Repository
	clock      Clock
}

func NewService(repository Repository, clock Clock) (*Service, error) {
	if repository == nil || clock == nil {
		return nil, ErrUnavailable
	}
	return &Service{repository: repository, clock: clock}, nil
}

func (service *Service) ListContacts(ctx context.Context, actor Actor, tenantID uuid.UUID, input ContactListInput) (ContactPage, error) {
	if !validActor(actor, tenantID) || actor.Kind != PrincipalOperator {
		return ContactPage{}, ErrForbidden
	}
	normalized, err := normalizeContactList(input)
	if err != nil {
		return ContactPage{}, err
	}
	access, err := service.repository.ResolveAccess(ctx, actor, tenantID, CapabilityContactRead)
	if err != nil {
		return ContactPage{}, repositoryError(err)
	}
	if !validTenantOperatorAccess(access, CapabilityContactRead) {
		return ContactPage{}, ErrForbidden
	}
	page, err := service.repository.ListContacts(ctx, actor, tenantID, normalized, access)
	if err != nil {
		return ContactPage{}, repositoryError(err)
	}
	if len(page.Items) > normalized.Limit || page.NextCursor != "" && !cursorPattern.MatchString(page.NextCursor) {
		return ContactPage{}, ErrUnavailable
	}
	for _, contact := range page.Items {
		if !validContactProjection(contact, tenantID) || contact.ArchivedAt() != nil && !normalized.IncludeArchived {
			return ContactPage{}, ErrUnavailable
		}
	}
	return page, nil
}

func (service *Service) GetContact(ctx context.Context, actor Actor, tenantID, contactID uuid.UUID) (kernel.Contact, error) {
	if !validActor(actor, tenantID) || actor.Kind != PrincipalOperator || !validUUIDv7(contactID) {
		return kernel.Contact{}, ErrForbidden
	}
	access, err := service.repository.ResolveAccess(ctx, actor, tenantID, CapabilityContactRead)
	if err != nil {
		return kernel.Contact{}, repositoryError(err)
	}
	if !validTenantOperatorAccess(access, CapabilityContactRead) {
		return kernel.Contact{}, ErrForbidden
	}
	contact, err := service.repository.GetContact(ctx, actor, tenantID, contactID, access)
	if err != nil {
		return kernel.Contact{}, repositoryError(err)
	}
	if !validContactProjection(contact, tenantID) || uuidFromEntity(contact.ID()) != contactID {
		return kernel.Contact{}, ErrUnavailable
	}
	return contact, nil
}

func (service *Service) CreateContact(ctx context.Context, actor Actor, tenantID uuid.UUID, input CreateContactInput) (ContactResult, error) {
	if err := validMutationEnvelope(actor, tenantID, input.IdempotencyKey, input.Audit); err != nil {
		return ContactResult{}, err
	}
	access, err := service.requireTenantOperator(ctx, actor, tenantID, CapabilityContactManage)
	if err != nil {
		return ContactResult{}, err
	}
	command, err := bindCommand("contact.create", input.IdempotencyKey, contactFingerprint(input.Fields)...)
	if err != nil {
		return ContactResult{}, err
	}
	if replay, found, replayErr := service.repository.ReplayContact(
		ctx, actor, tenantID, uuid.Nil, command,
	); replayErr != nil {
		return ContactResult{}, repositoryError(replayErr)
	} else if found {
		if replay.CustomerProjection != nil || !validContactProjection(replay.Contact, tenantID) ||
			replay.Contact.Version() != 1 || !sameContactFields(replay.Contact.Fields(), input.Fields) {
			return ContactResult{}, ErrUnavailable
		}
		return replay, nil
	}
	id, err := service.repository.ReserveID(ctx, tenantID)
	if err != nil {
		return ContactResult{}, repositoryError(err)
	}
	now, err := service.now()
	if err != nil {
		return ContactResult{}, err
	}
	next, err := kernel.NewContact(id, mustEntityID(tenantID), input.Fields, now)
	if err != nil {
		return ContactResult{}, ErrInvalidInput
	}
	result, err := service.repository.CommitContact(ctx, ContactWrite{
		Actor: actor, Access: access, Next: next, Command: command, Audit: input.Audit,
	})
	if err != nil {
		return ContactResult{}, repositoryError(err)
	}
	if result.CustomerProjection != nil || !validContactProjection(result.Contact, tenantID) || result.Contact.Version() != 1 ||
		!sameContactFields(result.Contact.Fields(), next.Fields()) || !result.Replayed && result.Contact.ID() != next.ID() {
		return ContactResult{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) ReplaceContact(ctx context.Context, actor Actor, tenantID, contactID uuid.UUID, input ReplaceContactInput) (ContactResult, error) {
	if err := validMutationEnvelope(actor, tenantID, input.IdempotencyKey, input.Audit); err != nil ||
		!validUUIDv7(contactID) || input.ExpectedVersion == 0 {
		if err != nil {
			return ContactResult{}, err
		}
		return ContactResult{}, ErrInvalidInput
	}
	access, err := service.requireTenantOperator(ctx, actor, tenantID, CapabilityContactManage)
	if err != nil {
		return ContactResult{}, err
	}
	parts := append([]string{contactID.String(), strconv.FormatUint(input.ExpectedVersion, 10)}, contactFingerprint(input.Fields)...)
	command, err := bindCommand("contact.replace", input.IdempotencyKey, parts...)
	if err != nil {
		return ContactResult{}, err
	}
	if replay, found, replayErr := service.repository.ReplayContact(
		ctx, actor, tenantID, contactID, command,
	); replayErr != nil {
		return ContactResult{}, repositoryError(replayErr)
	} else if found {
		if replay.CustomerProjection != nil || !validContactProjection(replay.Contact, tenantID) ||
			uuidFromEntity(replay.Contact.ID()) != contactID || replay.Contact.Version() != input.ExpectedVersion+1 ||
			replay.Contact.ArchivedAt() != nil || !sameContactFields(replay.Contact.Fields(), input.Fields) {
			return ContactResult{}, ErrUnavailable
		}
		return replay, nil
	}
	current, err := service.repository.GetContact(ctx, actor, tenantID, contactID, access)
	if err != nil {
		return ContactResult{}, repositoryError(err)
	}
	now, err := service.now()
	if err != nil {
		return ContactResult{}, err
	}
	next, err := kernel.ReplaceContact(current, input.Fields, input.ExpectedVersion, now)
	if errors.Is(err, kernel.ErrVersionConflict) {
		return ContactResult{}, ErrPreconditionFailed
	}
	if err != nil {
		return ContactResult{}, ErrInvalidInput
	}
	result, err := service.repository.CommitContact(ctx, ContactWrite{
		Actor: actor, Access: access, Current: &current, Next: next, ExpectedVersion: input.ExpectedVersion,
		Command: command, Audit: input.Audit,
	})
	if err != nil {
		return ContactResult{}, repositoryError(err)
	}
	if result.CustomerProjection != nil || !sameCommittedContact(result.Contact, next) {
		return ContactResult{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) UpdatePortalPreferences(ctx context.Context, actor Actor, tenantID uuid.UUID, input PreferenceInput) (ContactResult, error) {
	if err := validMutationEnvelope(actor, tenantID, input.IdempotencyKey, input.Audit); err != nil || input.ExpectedVersion == 0 {
		if err != nil {
			return ContactResult{}, err
		}
		return ContactResult{}, ErrInvalidInput
	}
	if actor.Kind != PrincipalCustomer {
		return ContactResult{}, ErrForbidden
	}
	current, access, err := service.repository.ResolveSelfContact(ctx, actor, tenantID, CapabilityPortalPreferenceManage)
	if err != nil {
		return ContactResult{}, repositoryError(err)
	}
	if !validSelfAccess(actor, access, current, CapabilityPortalPreferenceManage) {
		return ContactResult{}, ErrForbidden
	}
	now, err := service.now()
	if err != nil {
		return ContactResult{}, err
	}
	canonical, err := kernel.UpdateNotificationPreferences(current, input.Categories, input.Windows,
		input.EmailAllowed, current.Version(), now)
	if err != nil {
		return ContactResult{}, ErrInvalidInput
	}
	parts := []string{current.ID().String(), strconv.FormatUint(input.ExpectedVersion, 10), strconv.FormatBool(input.EmailAllowed)}
	for _, category := range canonical.Fields().NotificationCategories {
		parts = append(parts, category.String())
	}
	for _, window := range canonical.Fields().NotificationWindows {
		parts = append(parts, strconv.Itoa(int(window.Weekday())), strconv.Itoa(window.StartMinute()), strconv.Itoa(window.EndMinute()))
	}
	command, err := bindCommand("portal.preference.replace", input.IdempotencyKey, parts...)
	if err != nil {
		return ContactResult{}, err
	}
	if replay, found, replayErr := service.repository.ReplayContact(
		ctx, actor, tenantID, uuidFromEntity(current.ID()), command,
	); replayErr != nil {
		return ContactResult{}, repositoryError(replayErr)
	} else if found {
		if replay.CustomerProjection == nil || !sameCustomerPreferenceResult(
			*replay.CustomerProjection, current.ID(), input.ExpectedVersion+1,
			canonical.Fields().NotificationCategories, canonical.Fields().NotificationWindows,
			input.EmailAllowed,
		) {
			return ContactResult{}, ErrUnavailable
		}
		return replay, nil
	}
	next, err := kernel.UpdateNotificationPreferences(current, input.Categories, input.Windows,
		input.EmailAllowed, input.ExpectedVersion, now)
	if errors.Is(err, kernel.ErrVersionConflict) {
		return ContactResult{}, ErrPreconditionFailed
	}
	if err != nil {
		return ContactResult{}, ErrInvalidInput
	}
	result, err := service.repository.CommitContact(ctx, ContactWrite{
		Actor: actor, Access: access, Current: &current, Next: next, ExpectedVersion: input.ExpectedVersion,
		Command: command, Audit: input.Audit,
	})
	if err != nil {
		return ContactResult{}, repositoryError(err)
	}
	projection, projectionErr := kernel.ProjectCustomerSafe(next)
	if projectionErr != nil || result.CustomerProjection == nil ||
		!sameCustomerSafeContact(*result.CustomerProjection, projection) {
		return ContactResult{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) ArchiveContact(ctx context.Context, actor Actor, tenantID, contactID uuid.UUID, input ArchiveInput) (ContactResult, error) {
	if err := validMutationEnvelope(actor, tenantID, input.IdempotencyKey, input.Audit); err != nil ||
		!validUUIDv7(contactID) || input.ExpectedVersion == 0 || !validReason(input.Reason) {
		if err != nil {
			return ContactResult{}, err
		}
		return ContactResult{}, ErrInvalidInput
	}
	access, err := service.requireTenantOperator(ctx, actor, tenantID, CapabilityContactManage)
	if err != nil {
		return ContactResult{}, err
	}
	command, err := bindCommand("contact.archive", input.IdempotencyKey,
		contactID.String(), strconv.FormatUint(input.ExpectedVersion, 10), input.Reason)
	if err != nil {
		return ContactResult{}, err
	}
	if replay, found, replayErr := service.repository.ReplayContact(
		ctx, actor, tenantID, contactID, command,
	); replayErr != nil {
		return ContactResult{}, repositoryError(replayErr)
	} else if found {
		if replay.CustomerProjection != nil || !validContactProjection(replay.Contact, tenantID) ||
			uuidFromEntity(replay.Contact.ID()) != contactID || replay.Contact.Version() != input.ExpectedVersion+1 ||
			replay.Contact.ArchivedAt() == nil || replay.Contact.Active() {
			return ContactResult{}, ErrUnavailable
		}
		return replay, nil
	}
	current, err := service.repository.GetContact(ctx, actor, tenantID, contactID, access)
	if err != nil {
		return ContactResult{}, repositoryError(err)
	}
	now, err := service.now()
	if err != nil {
		return ContactResult{}, err
	}
	next, err := kernel.ArchiveContact(current, input.ExpectedVersion, now)
	if errors.Is(err, kernel.ErrVersionConflict) {
		return ContactResult{}, ErrPreconditionFailed
	}
	if err != nil {
		return ContactResult{}, ErrInvalidInput
	}
	result, err := service.repository.CommitContact(ctx, ContactWrite{
		Actor: actor, Access: access, Current: &current, Next: next, ExpectedVersion: input.ExpectedVersion,
		Command: command, Reason: input.Reason, Audit: input.Audit,
	})
	if err != nil {
		return ContactResult{}, repositoryError(err)
	}
	if result.CustomerProjection != nil || !sameCommittedContact(result.Contact, next) {
		return ContactResult{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) SelfContact(ctx context.Context, actor Actor, tenantID uuid.UUID) (kernel.CustomerSafeContact, error) {
	if !validActor(actor, tenantID) || actor.Kind != PrincipalCustomer {
		return kernel.CustomerSafeContact{}, ErrForbidden
	}
	contact, access, err := service.repository.ResolveSelfContact(ctx, actor, tenantID, CapabilityPortalPreferenceManage)
	if err != nil {
		return kernel.CustomerSafeContact{}, repositoryError(err)
	}
	if !validSelfAccess(actor, access, contact, CapabilityPortalPreferenceManage) {
		return kernel.CustomerSafeContact{}, ErrForbidden
	}
	projection, err := kernel.ProjectCustomerSafe(contact)
	if err != nil {
		return kernel.CustomerSafeContact{}, ErrForbidden
	}
	return projection, nil
}

func (service *Service) ListGroups(ctx context.Context, actor Actor, tenantID uuid.UUID, input GroupListInput) (GroupPage, error) {
	if !validActor(actor, tenantID) || actor.Kind != PrincipalOperator {
		return GroupPage{}, ErrForbidden
	}
	normalized, err := normalizeGroupList(input)
	if err != nil {
		return GroupPage{}, err
	}
	access, err := service.requireTenantOperator(ctx, actor, tenantID, CapabilityContactGroupRead)
	if err != nil {
		return GroupPage{}, err
	}
	page, err := service.repository.ListGroups(ctx, actor, tenantID, normalized, access)
	if err != nil {
		return GroupPage{}, repositoryError(err)
	}
	if len(page.Items) > normalized.Limit || page.NextCursor != "" && !cursorPattern.MatchString(page.NextCursor) {
		return GroupPage{}, ErrUnavailable
	}
	for _, group := range page.Items {
		if !validGroupProjection(group, tenantID) || group.ArchivedAt() != nil && !normalized.IncludeArchived {
			return GroupPage{}, ErrUnavailable
		}
	}
	return page, nil
}

func (service *Service) GetGroup(ctx context.Context, actor Actor, tenantID, groupID uuid.UUID) (kernel.RecipientGroup, error) {
	if !validActor(actor, tenantID) || actor.Kind != PrincipalOperator || !validUUIDv7(groupID) {
		return kernel.RecipientGroup{}, ErrForbidden
	}
	access, err := service.requireTenantOperator(ctx, actor, tenantID, CapabilityContactGroupRead)
	if err != nil {
		return kernel.RecipientGroup{}, err
	}
	group, err := service.repository.GetGroup(ctx, actor, tenantID, groupID, access)
	if err != nil {
		return kernel.RecipientGroup{}, repositoryError(err)
	}
	if !validGroupProjection(group, tenantID) || uuidFromEntity(group.ID()) != groupID {
		return kernel.RecipientGroup{}, ErrUnavailable
	}
	return group, nil
}

func (service *Service) CreateGroup(ctx context.Context, actor Actor, tenantID uuid.UUID, input CreateGroupInput) (GroupResult, error) {
	if err := validMutationEnvelope(actor, tenantID, input.IdempotencyKey, input.Audit); err != nil {
		return GroupResult{}, err
	}
	access, err := service.requireTenantOperator(ctx, actor, tenantID, CapabilityContactGroupManage)
	if err != nil {
		return GroupResult{}, err
	}
	members, err := entityIDs(input.MemberIDs, 10_000)
	if err != nil {
		return GroupResult{}, err
	}
	command, err := bindCommand("contact_group.create", input.IdempotencyKey,
		groupContentFingerprint(input.Key, input.Name, input.Description, input.Mode, input.Rule, members)...)
	if err != nil {
		return GroupResult{}, err
	}
	if replay, found, replayErr := service.repository.ReplayGroup(ctx, actor, tenantID, uuid.Nil, command); replayErr != nil {
		return GroupResult{}, repositoryError(replayErr)
	} else if found {
		if !validGroupProjection(replay.Group, tenantID) || replay.Group.Current().Version() != 1 ||
			!sameGroupInput(replay.Group, input.Key, input.Name, input.Description, input.Mode, input.Rule, members) {
			return GroupResult{}, ErrUnavailable
		}
		return replay, nil
	}
	id, err := service.repository.ReserveID(ctx, tenantID)
	if err != nil {
		return GroupResult{}, repositoryError(err)
	}
	now, err := service.now()
	if err != nil {
		return GroupResult{}, err
	}
	version, err := kernel.NewGroupVersion(id, mustEntityID(tenantID), 1, input.Name, input.Description,
		input.Mode, input.Rule, members, now)
	if err != nil {
		return GroupResult{}, ErrInvalidInput
	}
	next, err := kernel.NewRecipientGroup(id, mustEntityID(tenantID), input.Key, version, now)
	if err != nil {
		return GroupResult{}, ErrInvalidInput
	}
	result, err := service.repository.CommitGroup(ctx, GroupWrite{Actor: actor, Access: access, Next: next, Command: command, Audit: input.Audit})
	if err != nil {
		return GroupResult{}, repositoryError(err)
	}
	if !validGroupProjection(result.Group, tenantID) || result.Group.Current().Version() != 1 ||
		!sameGroupContent(result.Group, next) || !result.Replayed && result.Group.ID() != next.ID() {
		return GroupResult{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) VersionGroup(ctx context.Context, actor Actor, tenantID, groupID uuid.UUID, input VersionGroupInput) (GroupResult, error) {
	if err := validMutationEnvelope(actor, tenantID, input.IdempotencyKey, input.Audit); err != nil ||
		!validUUIDv7(groupID) || input.ExpectedVersion == 0 {
		if err != nil {
			return GroupResult{}, err
		}
		return GroupResult{}, ErrInvalidInput
	}
	access, err := service.requireTenantOperator(ctx, actor, tenantID, CapabilityContactGroupManage)
	if err != nil {
		return GroupResult{}, err
	}
	current, err := service.repository.GetGroup(ctx, actor, tenantID, groupID, access)
	if err != nil {
		return GroupResult{}, repositoryError(err)
	}
	members, err := entityIDs(input.MemberIDs, 10_000)
	if err != nil {
		return GroupResult{}, err
	}
	parts := append([]string{groupID.String(), strconv.FormatUint(input.ExpectedVersion, 10)},
		groupContentFingerprint(current.Key(), input.Name, input.Description, input.Mode, input.Rule, members)...)
	command, err := bindCommand("contact_group.version", input.IdempotencyKey, parts...)
	if err != nil {
		return GroupResult{}, err
	}
	if replay, found, replayErr := service.repository.ReplayGroup(ctx, actor, tenantID, groupID, command); replayErr != nil {
		return GroupResult{}, repositoryError(replayErr)
	} else if found {
		if !validGroupProjection(replay.Group, tenantID) || replay.Group.ID() != current.ID() ||
			replay.Group.Current().Version() != input.ExpectedVersion+1 ||
			!sameGroupInput(replay.Group, current.Key(), input.Name, input.Description, input.Mode, input.Rule, members) {
			return GroupResult{}, ErrUnavailable
		}
		return replay, nil
	}
	now, err := service.now()
	if err != nil {
		return GroupResult{}, err
	}
	next, err := kernel.VersionRecipientGroup(current, input.Name, input.Description, input.Mode,
		input.Rule, members, input.ExpectedVersion, now)
	if errors.Is(err, kernel.ErrVersionConflict) {
		return GroupResult{}, ErrPreconditionFailed
	}
	if err != nil {
		return GroupResult{}, ErrInvalidInput
	}
	result, err := service.repository.CommitGroup(ctx, GroupWrite{
		Actor: actor, Access: access, Current: &current, Next: next, ExpectedVersion: input.ExpectedVersion,
		Command: command, Audit: input.Audit,
	})
	if err != nil {
		return GroupResult{}, repositoryError(err)
	}
	if !sameCommittedGroup(result.Group, next) {
		return GroupResult{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) LinkContact(ctx context.Context, actor Actor, tenantID uuid.UUID, input LinkInput) (LinkResult, error) {
	if err := validMutationEnvelope(actor, tenantID, input.IdempotencyKey, input.Audit); err != nil ||
		actor.Kind != PrincipalOperator || !validUUIDv7(input.TicketID) || !validUUIDv7(input.ContactID) ||
		input.ExpectedTicketVersion == 0 {
		if err != nil {
			return LinkResult{}, err
		}
		return LinkResult{}, ErrInvalidInput
	}
	parts := append(linkCreateFingerprint(tenantID, input), strconv.FormatUint(input.ExpectedTicketVersion, 10))
	command, err := bindCommand("ticket_contact.link", input.IdempotencyKey, parts...)
	if err != nil {
		return LinkResult{}, err
	}
	if replay, found, replayErr := service.repository.ReplayLink(
		ctx, actor, tenantID, uuid.Nil, input.TicketKind, input.TicketID, command,
	); replayErr != nil {
		return LinkResult{}, repositoryError(replayErr)
	} else if found {
		if !validLinkProjection(replay.Link, tenantID) || replay.Link.TicketKind() != input.TicketKind ||
			uuidFromEntity(replay.Link.TicketID()) != input.TicketID || uuidFromEntity(replay.Link.ContactID()) != input.ContactID ||
			replay.Link.Role() != input.Role || replay.Link.Origin() != kernel.OriginManual || replay.Link.Version() != 1 ||
			replay.Link.ArchivedAt() != nil || replay.Link.Provenance() != nil {
			return LinkResult{}, ErrUnavailable
		}
		return replay, nil
	}
	access, err := service.repository.ResolveExactLinkAccess(ctx, actor, tenantID, input.TicketKind,
		input.TicketID, input.ContactID, input.ExpectedTicketVersion)
	if err != nil {
		return LinkResult{}, repositoryError(err)
	}
	if !validExactLinkAccess(access, tenantID, input) {
		return LinkResult{}, ErrForbidden
	}
	id, err := service.repository.ReserveID(ctx, tenantID)
	if err != nil {
		return LinkResult{}, repositoryError(err)
	}
	now, err := service.now()
	if err != nil {
		return LinkResult{}, err
	}
	next, err := kernel.NewTicketContactLink(id, mustEntityID(tenantID), input.TicketKind,
		mustEntityID(input.TicketID), mustEntityID(input.ContactID), input.Role, kernel.OriginManual, nil, now)
	if err != nil {
		return LinkResult{}, ErrInvalidInput
	}
	result, err := service.repository.CommitLink(ctx, LinkWrite{
		Actor: actor, Access: access, Next: next, ExpectedTicketVersion: input.ExpectedTicketVersion,
		Command: command, Audit: input.Audit,
	})
	if err != nil {
		return LinkResult{}, repositoryError(err)
	}
	if !validLinkProjection(result.Link, tenantID) || !sameLinkContent(result.Link, next) ||
		!result.Replayed && result.Link.ID() != next.ID() {
		return LinkResult{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) ListLinks(ctx context.Context, actor Actor, tenantID uuid.UUID, input LinkListInput) (LinkPage, error) {
	if !validActor(actor, tenantID) || actor.Kind != PrincipalOperator ||
		!validUUIDv7(input.TicketID) || input.TicketKind != kernel.TicketAlert && input.TicketKind != kernel.TicketCase {
		return LinkPage{}, ErrForbidden
	}
	if input.Limit == 0 {
		input.Limit = defaultPageLimit
	}
	if input.Limit < 1 || input.Limit > maximumPageLimit || input.After != "" && !cursorPattern.MatchString(input.After) {
		return LinkPage{}, ErrInvalidInput
	}
	page, err := service.repository.ListLinks(ctx, actor, tenantID, input)
	if err != nil {
		return LinkPage{}, repositoryError(err)
	}
	if len(page.Items) > input.Limit || page.NextCursor != "" && !cursorPattern.MatchString(page.NextCursor) {
		return LinkPage{}, ErrUnavailable
	}
	for _, link := range page.Items {
		if !validLinkProjection(link, tenantID) || link.ArchivedAt() != nil ||
			link.TicketKind() != input.TicketKind || uuidFromEntity(link.TicketID()) != input.TicketID {
			return LinkPage{}, ErrUnavailable
		}
	}
	return page, nil
}

func (service *Service) ArchiveLink(
	ctx context.Context,
	actor Actor,
	tenantID, linkID uuid.UUID,
	input ArchiveLinkInput,
) (LinkResult, error) {
	if err := validMutationEnvelope(actor, tenantID, input.IdempotencyKey, input.Audit); err != nil ||
		actor.Kind != PrincipalOperator || !validUUIDv7(linkID) || !validUUIDv7(input.TicketID) ||
		(input.TicketKind != kernel.TicketAlert && input.TicketKind != kernel.TicketCase) || input.ExpectedLinkVersion == 0 ||
		input.ExpectedTicketVersion == 0 || !validReason(input.Reason) {
		if err != nil {
			return LinkResult{}, err
		}
		return LinkResult{}, ErrInvalidInput
	}
	current, err := service.repository.GetLinkForArchive(
		ctx, actor, tenantID, linkID, input.TicketKind, input.TicketID,
	)
	if err != nil {
		return LinkResult{}, repositoryError(err)
	}
	if !validLinkProjection(current, tenantID) ||
		current.TicketKind() != input.TicketKind || uuidFromEntity(current.TicketID()) != input.TicketID {
		return LinkResult{}, ErrNotFound
	}
	command, err := bindCommand("ticket_contact.archive", input.IdempotencyKey,
		linkID.String(), strconv.FormatUint(input.ExpectedLinkVersion, 10),
		strconv.FormatUint(input.ExpectedTicketVersion, 10), input.Reason)
	if err != nil {
		return LinkResult{}, err
	}
	if replay, found, replayErr := service.repository.ReplayLink(
		ctx, actor, tenantID, linkID, input.TicketKind, input.TicketID, command,
	); replayErr != nil {
		return LinkResult{}, repositoryError(replayErr)
	} else if found {
		if !validLinkProjection(replay.Link, tenantID) || uuidFromEntity(replay.Link.ID()) != linkID ||
			replay.Link.TicketKind() != input.TicketKind || uuidFromEntity(replay.Link.TicketID()) != input.TicketID ||
			replay.Link.Version() != input.ExpectedLinkVersion+1 || replay.Link.ArchivedAt() == nil {
			return LinkResult{}, ErrUnavailable
		}
		return replay, nil
	}
	if current.ArchivedAt() != nil {
		return LinkResult{}, ErrNotFound
	}
	linkInput := LinkInput{
		TicketKind: current.TicketKind(), TicketID: uuidFromEntity(current.TicketID()),
		ContactID: uuidFromEntity(current.ContactID()), ExpectedTicketVersion: input.ExpectedTicketVersion,
	}
	access, err := service.repository.ResolveExactLinkAccess(ctx, actor, tenantID, linkInput.TicketKind,
		linkInput.TicketID, linkInput.ContactID, input.ExpectedTicketVersion)
	if err != nil {
		return LinkResult{}, repositoryError(err)
	}
	if !validExactLinkAccess(access, tenantID, linkInput) {
		return LinkResult{}, ErrForbidden
	}
	now, err := service.now()
	if err != nil {
		return LinkResult{}, err
	}
	next, err := kernel.ArchiveTicketContactLink(current, input.ExpectedLinkVersion, now)
	if errors.Is(err, kernel.ErrVersionConflict) {
		return LinkResult{}, ErrPreconditionFailed
	}
	if err != nil {
		return LinkResult{}, ErrInvalidInput
	}
	result, err := service.repository.CommitLink(ctx, LinkWrite{
		Actor: actor, Access: access, Current: &current, Next: next,
		ExpectedLinkVersion: input.ExpectedLinkVersion, ExpectedTicketVersion: input.ExpectedTicketVersion,
		Command: command, Reason: input.Reason, Audit: input.Audit,
	})
	if err != nil {
		return LinkResult{}, repositoryError(err)
	}
	if !sameLinkContent(result.Link, next) || result.Link.ID() != next.ID() {
		return LinkResult{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) AuthorizePortalResource(ctx context.Context, actor Actor, tenantID uuid.UUID, input PortalResourceInput) (PortalAuthorization, error) {
	if !validActor(actor, tenantID) || actor.Kind != PrincipalCustomer || !validUUIDv7(input.TicketID) ||
		!validPortalCapabilitySet(input.TicketKind, input.Capability, input.RequiredCapability) {
		return PortalAuthorization{}, ErrForbidden
	}
	evidence, err := service.repository.ResolvePortalResource(ctx, actor, tenantID, input)
	if err != nil {
		return PortalAuthorization{}, repositoryError(err)
	}
	if !validPortalEvidence(actor, tenantID, input, evidence) {
		return PortalAuthorization{}, ErrForbidden
	}
	return PortalAuthorization{
		TicketKind: input.TicketKind, TicketID: input.TicketID,
		ContactID: evidence.ContactID, TicketVersion: evidence.TicketVersion,
	}, nil
}

func (service *Service) ResolveCustomerCommentAuthor(ctx context.Context, actor Actor, tenantID uuid.UUID, kind kernel.TicketKind, ticketID uuid.UUID) (kernel.CommentAuthorSnapshot, error) {
	authorization, err := service.AuthorizePortalResource(ctx, actor, tenantID, PortalResourceInput{
		TicketKind: kind, TicketID: ticketID, Capability: CapabilityPortalCommentPublic,
	})
	if err != nil {
		return kernel.CommentAuthorSnapshot{}, err
	}
	membershipID, userID, contactID := mustEntityID(actor.MembershipID), mustEntityID(actor.UserID), mustEntityID(authorization.ContactID)
	snapshot, err := kernel.NewCommentAuthorSnapshot(kernel.AuthorCustomer, membershipID, userID, &contactID)
	if err != nil {
		return kernel.CommentAuthorSnapshot{}, ErrUnavailable
	}
	return snapshot, nil
}

func (service *Service) requireTenantOperator(ctx context.Context, actor Actor, tenantID uuid.UUID, capability Capability) (Access, error) {
	if !validActor(actor, tenantID) || actor.Kind != PrincipalOperator || !validCapability(capability) {
		return Access{}, ErrForbidden
	}
	access, err := service.repository.ResolveAccess(ctx, actor, tenantID, capability)
	if err != nil {
		return Access{}, repositoryError(err)
	}
	if !validTenantOperatorAccess(access, capability) {
		return Access{}, ErrForbidden
	}
	return access, nil
}

func validTenantOperatorAccess(access Access, capability Capability) bool {
	return access.Capability == capability && access.Scope == ScopeTenant && access.Projection == ProjectionOperator && access.ContactID == uuid.Nil
}

func validSelfAccess(actor Actor, access Access, contact kernel.Contact, capability Capability) bool {
	if access.Capability != capability || access.Scope != ScopeContactSelf || access.Projection != ProjectionCustomer ||
		access.ContactID == uuid.Nil || uuidFromEntity(contact.ID()) != access.ContactID || !contact.Active() {
		return false
	}
	linked := contact.Fields().LinkedAccount
	return linked != nil && uuidFromEntity(linked.MembershipID()) == actor.MembershipID && uuidFromEntity(linked.UserID()) == actor.UserID
}

func validExactLinkAccess(access ExactLinkAccess, tenantID uuid.UUID, input LinkInput) bool {
	return access.TenantID == tenantID && access.TicketKind == input.TicketKind && access.TicketID == input.TicketID &&
		access.ContactID == input.ContactID && access.TicketVersion == input.ExpectedTicketVersion && access.ContactVersion > 0 &&
		validResourceCapability(input.TicketKind, access.ResourceCapability) && access.ContactReadable && access.ResourceWritable
}

func validPortalEvidence(actor Actor, tenantID uuid.UUID, input PortalResourceInput, evidence PortalResourceEvidence) bool {
	return evidence.TenantID == tenantID && evidence.TicketKind == input.TicketKind && evidence.TicketID == input.TicketID &&
		evidence.Capability == input.Capability && evidence.RequiredCapability == input.RequiredCapability &&
		validUUIDv7(evidence.ContactID) && evidence.ContactVersion > 0 &&
		evidence.TicketVersion > 0 && evidence.CustomerVisible && evidence.ContactActive && evidence.Linked &&
		actor.Kind == PrincipalCustomer
}

func validContactProjection(contact kernel.Contact, tenantID uuid.UUID) bool {
	if uuidFromEntity(contact.TenantID()) != tenantID || contact.Version() == 0 || !validInstant(contact.CreatedAt()) || !validInstant(contact.UpdatedAt()) {
		return false
	}
	_, err := kernel.RehydrateContact(contact.ID(), contact.TenantID(), contact.Fields(), contact.Version(),
		contact.CreatedAt(), contact.UpdatedAt(), contact.ArchivedAt())
	return err == nil
}

func validGroupProjection(group kernel.RecipientGroup, tenantID uuid.UUID) bool {
	if uuidFromEntity(group.TenantID()) != tenantID || !validInstant(group.CreatedAt()) || !validInstant(group.UpdatedAt()) {
		return false
	}
	_, err := kernel.RehydrateRecipientGroup(group.ID(), group.TenantID(), group.Key(), group.Current(),
		group.CreatedAt(), group.UpdatedAt(), group.ArchivedAt())
	return err == nil
}

func validLinkProjection(link kernel.TicketContactLink, tenantID uuid.UUID) bool {
	if uuidFromEntity(link.TenantID()) != tenantID || link.Version() == 0 || !validInstant(link.CreatedAt()) {
		return false
	}
	_, err := kernel.RehydrateTicketContactLink(
		link.ID(), link.TenantID(), link.TicketKind(), link.TicketID(), link.ContactID(), link.Role(),
		link.Origin(), link.Provenance(), link.Version(), link.CreatedAt(), link.ArchivedAt(),
	)
	return err == nil
}

func sameCommittedContact(left, right kernel.Contact) bool {
	return left.ID() == right.ID() && left.TenantID() == right.TenantID() && left.Version() == right.Version() &&
		sameContactFields(left.Fields(), right.Fields()) && sameTimes(left.ArchivedAt(), right.ArchivedAt())
}

func sameContactFields(left, right kernel.ContactFields) bool {
	return left.FirstName == right.FirstName && left.LastName == right.LastName && left.Email == right.Email &&
		left.Phone == right.Phone && left.Function == right.Function && left.Language == right.Language &&
		left.Timezone == right.Timezone && left.EscalationPriority == right.EscalationPriority && left.Class == right.Class &&
		slices.Equal(left.NotificationCategories, right.NotificationCategories) && slices.Equal(left.NotificationWindows, right.NotificationWindows) &&
		left.EmailAllowed == right.EmailAllowed && left.Active == right.Active && slices.Equal(left.Tags, right.Tags) &&
		sameLinkedAccount(left.LinkedAccount, right.LinkedAccount)
}

func sameLinkedAccount(left, right *kernel.LinkedAccount) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.MembershipID() == right.MembershipID() && left.UserID() == right.UserID()
}

func sameTimes(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func sameGroupContent(left, right kernel.RecipientGroup) bool {
	leftVersion, rightVersion := left.Current(), right.Current()
	return left.TenantID() == right.TenantID() && left.Key() == right.Key() &&
		leftVersion.Version() == rightVersion.Version() && leftVersion.Name() == rightVersion.Name() &&
		leftVersion.Description() == rightVersion.Description() && leftVersion.Mode() == rightVersion.Mode() &&
		sameRule(leftVersion.Rule(), rightVersion.Rule()) && slices.Equal(leftVersion.Members(), rightVersion.Members())
}

func sameCommittedGroup(left, right kernel.RecipientGroup) bool {
	return left.ID() == right.ID() && sameGroupContent(left, right) && sameTimes(left.ArchivedAt(), right.ArchivedAt())
}

func sameGroupInput(
	group kernel.RecipientGroup,
	key kernel.Key,
	name, description string,
	mode kernel.GroupMode,
	rule kernel.RuleNode,
	members []kernel.EntityID,
) bool {
	version := group.Current()
	return group.Key() == key && version.Name() == name && version.Description() == description &&
		version.Mode() == mode && sameRule(version.Rule(), rule) && slices.Equal(version.Members(), members) &&
		group.ArchivedAt() == nil
}

func sameCustomerPreferenceResult(
	contact kernel.CustomerSafeContact,
	id kernel.EntityID,
	version uint64,
	categories []kernel.Key,
	windows []kernel.NotificationWindow,
	emailAllowed bool,
) bool {
	return contact.ID == id && contact.Version == version && contact.EmailAllowed == emailAllowed && contact.Active &&
		slices.Equal(contact.NotificationCategories, categories) && slices.Equal(contact.NotificationWindows, windows)
}

func sameCustomerSafeContact(left, right kernel.CustomerSafeContact) bool {
	return left.ID == right.ID && left.FirstName == right.FirstName && left.LastName == right.LastName &&
		left.Email == right.Email && left.Phone == right.Phone && left.Function == right.Function &&
		left.Language == right.Language && left.Timezone == right.Timezone &&
		slices.Equal(left.NotificationCategories, right.NotificationCategories) &&
		slices.Equal(left.NotificationWindows, right.NotificationWindows) &&
		left.EmailAllowed == right.EmailAllowed && left.Active == right.Active && left.Version == right.Version
}

func sameRule(left, right kernel.RuleNode) bool {
	if left.Kind() != right.Kind() || left.Field() != right.Field() || left.Operator() != right.Operator() ||
		!slices.Equal(left.Values(), right.Values()) {
		return false
	}
	leftChildren, rightChildren := left.Children(), right.Children()
	if len(leftChildren) != len(rightChildren) {
		return false
	}
	for index := range leftChildren {
		if !sameRule(leftChildren[index], rightChildren[index]) {
			return false
		}
	}
	return true
}

func sameLinkContent(left, right kernel.TicketContactLink) bool {
	return left.TenantID() == right.TenantID() && left.TicketKind() == right.TicketKind() &&
		left.TicketID() == right.TicketID() && left.ContactID() == right.ContactID() && left.Role() == right.Role() &&
		left.Origin() == right.Origin() && left.Version() == right.Version() && sameProvenance(left.Provenance(), right.Provenance())
}

func sameProvenance(left, right *kernel.EscalationProvenance) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.SourceAlertID() == right.SourceAlertID() && left.SourceAlertVersion() == right.SourceAlertVersion()
}

func mustEntityID(value uuid.UUID) kernel.EntityID {
	converted, err := entityID(value)
	if err != nil {
		panic("contacts: validated UUID conversion failed")
	}
	return converted
}

func (service *Service) now() (time.Time, error) {
	now := service.clock().UTC().Truncate(time.Microsecond)
	if !validInstant(now) {
		return time.Time{}, ErrUnavailable
	}
	return now, nil
}

func repositoryError(err error) error {
	switch {
	case errors.Is(err, ErrRepositoryForbidden):
		return ErrForbidden
	case errors.Is(err, ErrRepositoryNotFound):
		return ErrNotFound
	case errors.Is(err, ErrRepositoryConflict):
		return ErrConflict
	case errors.Is(err, ErrRepositoryPrecondition):
		return ErrPreconditionFailed
	default:
		return ErrUnavailable
	}
}
