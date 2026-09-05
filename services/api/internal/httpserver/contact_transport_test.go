package httpserver

import (
	"context"

	"github.com/google/uuid"

	contactkernel "github.com/periapsis-im/periapsis/modules/contacts"
	applicationcontacts "github.com/periapsis-im/periapsis/services/api/internal/contacts"
)

type transportContactStub struct{}

func (*transportContactStub) ListContacts(context.Context, applicationcontacts.Actor, uuid.UUID, applicationcontacts.ContactListInput) (applicationcontacts.ContactPage, error) {
	return applicationcontacts.ContactPage{}, applicationcontacts.ErrUnavailable
}
func (*transportContactStub) GetContact(context.Context, applicationcontacts.Actor, uuid.UUID, uuid.UUID) (contactkernel.Contact, error) {
	return contactkernel.Contact{}, applicationcontacts.ErrUnavailable
}
func (*transportContactStub) CreateContact(context.Context, applicationcontacts.Actor, uuid.UUID, applicationcontacts.CreateContactInput) (applicationcontacts.ContactResult, error) {
	return applicationcontacts.ContactResult{}, applicationcontacts.ErrUnavailable
}
func (*transportContactStub) ReplaceContact(context.Context, applicationcontacts.Actor, uuid.UUID, uuid.UUID, applicationcontacts.ReplaceContactInput) (applicationcontacts.ContactResult, error) {
	return applicationcontacts.ContactResult{}, applicationcontacts.ErrUnavailable
}
func (*transportContactStub) ArchiveContact(context.Context, applicationcontacts.Actor, uuid.UUID, uuid.UUID, applicationcontacts.ArchiveInput) (applicationcontacts.ContactResult, error) {
	return applicationcontacts.ContactResult{}, applicationcontacts.ErrUnavailable
}
func (*transportContactStub) SelfContact(context.Context, applicationcontacts.Actor, uuid.UUID) (contactkernel.CustomerSafeContact, error) {
	return contactkernel.CustomerSafeContact{}, applicationcontacts.ErrUnavailable
}
func (*transportContactStub) UpdatePortalPreferences(context.Context, applicationcontacts.Actor, uuid.UUID, applicationcontacts.PreferenceInput) (applicationcontacts.ContactResult, error) {
	return applicationcontacts.ContactResult{}, applicationcontacts.ErrUnavailable
}
func (*transportContactStub) ListGroups(context.Context, applicationcontacts.Actor, uuid.UUID, applicationcontacts.GroupListInput) (applicationcontacts.GroupPage, error) {
	return applicationcontacts.GroupPage{}, applicationcontacts.ErrUnavailable
}
func (*transportContactStub) GetGroup(context.Context, applicationcontacts.Actor, uuid.UUID, uuid.UUID) (contactkernel.RecipientGroup, error) {
	return contactkernel.RecipientGroup{}, applicationcontacts.ErrUnavailable
}
func (*transportContactStub) CreateGroup(context.Context, applicationcontacts.Actor, uuid.UUID, applicationcontacts.CreateGroupInput) (applicationcontacts.GroupResult, error) {
	return applicationcontacts.GroupResult{}, applicationcontacts.ErrUnavailable
}
func (*transportContactStub) VersionGroup(context.Context, applicationcontacts.Actor, uuid.UUID, uuid.UUID, applicationcontacts.VersionGroupInput) (applicationcontacts.GroupResult, error) {
	return applicationcontacts.GroupResult{}, applicationcontacts.ErrUnavailable
}
func (*transportContactStub) ListLinks(context.Context, applicationcontacts.Actor, uuid.UUID, applicationcontacts.LinkListInput) (applicationcontacts.LinkPage, error) {
	return applicationcontacts.LinkPage{}, applicationcontacts.ErrUnavailable
}
func (*transportContactStub) LinkContact(context.Context, applicationcontacts.Actor, uuid.UUID, applicationcontacts.LinkInput) (applicationcontacts.LinkResult, error) {
	return applicationcontacts.LinkResult{}, applicationcontacts.ErrUnavailable
}
func (*transportContactStub) ArchiveLink(context.Context, applicationcontacts.Actor, uuid.UUID, uuid.UUID, applicationcontacts.ArchiveLinkInput) (applicationcontacts.LinkResult, error) {
	return applicationcontacts.LinkResult{}, applicationcontacts.ErrUnavailable
}
