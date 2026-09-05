package contacts

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/contacts"
)

type commandKey struct {
	operation string
	digest    [32]byte
}

type storedContactCommand struct {
	request [32]byte
	result  ContactResult
}

type storedGroupCommand struct {
	request [32]byte
	result  GroupResult
}

type storedLinkCommand struct {
	request [32]byte
	result  LinkResult
}

type fakeRepository struct {
	mu sync.Mutex

	seed            byte
	access          map[Capability]Access
	contacts        map[uuid.UUID]kernel.Contact
	groups          map[uuid.UUID]kernel.RecipientGroup
	links           map[uuid.UUID]kernel.TicketContactLink
	contactCommands map[commandKey]storedContactCommand
	groupCommands   map[commandKey]storedGroupCommand
	linkCommands    map[commandKey]storedLinkCommand
	contactCommits  int
	groupCommits    int
	linkCommits     int

	selfContact kernel.Contact
	selfAccess  Access
	exactLink   ExactLinkAccess
	portal      PortalResourceEvidence
	portalInput PortalResourceInput
}

func newFakeRepository() *fakeRepository {
	return &fakeRepository{
		seed: 100, access: make(map[Capability]Access), contacts: make(map[uuid.UUID]kernel.Contact),
		groups: make(map[uuid.UUID]kernel.RecipientGroup), links: make(map[uuid.UUID]kernel.TicketContactLink),
		contactCommands: make(map[commandKey]storedContactCommand), groupCommands: make(map[commandKey]storedGroupCommand),
		linkCommands: make(map[commandKey]storedLinkCommand),
	}
}

func (repository *fakeRepository) ResolveAccess(_ context.Context, _ Actor, _ uuid.UUID, capability Capability) (Access, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	access, found := repository.access[capability]
	if !found {
		return Access{}, ErrRepositoryForbidden
	}
	return access, nil
}

func (repository *fakeRepository) ResolveSelfContact(_ context.Context, _ Actor, _ uuid.UUID, _ Capability) (kernel.Contact, Access, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.selfContact.ID() == (kernel.EntityID{}) {
		return kernel.Contact{}, Access{}, ErrRepositoryNotFound
	}
	return repository.selfContact, repository.selfAccess, nil
}

func (repository *fakeRepository) ListContacts(_ context.Context, _ Actor, tenantID uuid.UUID, input ContactListInput, _ Access) (ContactPage, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	items := make([]kernel.Contact, 0, len(repository.contacts))
	for _, contact := range repository.contacts {
		if uuidFromEntity(contact.TenantID()) == tenantID && (input.IncludeArchived || contact.ArchivedAt() == nil) {
			items = append(items, contact)
		}
	}
	slices.SortFunc(items, func(left, right kernel.Contact) int { return strings.Compare(left.ID().String(), right.ID().String()) })
	if len(items) > input.Limit {
		items = items[:input.Limit]
	}
	return ContactPage{Items: items}, nil
}

func (repository *fakeRepository) GetContact(_ context.Context, _ Actor, tenantID, contactID uuid.UUID, _ Access) (kernel.Contact, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	contact, found := repository.contacts[contactID]
	if !found || uuidFromEntity(contact.TenantID()) != tenantID {
		return kernel.Contact{}, ErrRepositoryNotFound
	}
	return contact, nil
}

func (repository *fakeRepository) ReserveID(_ context.Context, _ uuid.UUID) (kernel.EntityID, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.seed++
	return kernelID(repository.seed), nil
}

func (repository *fakeRepository) ReplayContact(
	_ context.Context,
	_ Actor,
	tenantID, contactID uuid.UUID,
	command CommandBinding,
) (ContactResult, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	existing, found := repository.contactCommands[commandKey{operation: command.Operation, digest: command.KeyDigest}]
	if !found {
		return ContactResult{}, false, nil
	}
	if existing.request != command.RequestDigest {
		return ContactResult{}, false, ErrRepositoryConflict
	}
	result := existing.result
	var resultID uuid.UUID
	if result.CustomerProjection != nil {
		resultID = uuidFromEntity(result.CustomerProjection.ID)
	} else {
		resultID = uuidFromEntity(result.Contact.ID())
	}
	if resultID == uuid.Nil || contactID != uuid.Nil && resultID != contactID ||
		result.CustomerProjection == nil && uuidFromEntity(result.Contact.TenantID()) != tenantID {
		return ContactResult{}, false, ErrRepositoryForbidden
	}
	result.Replayed = true
	return result, true, nil
}

func (repository *fakeRepository) CommitContact(_ context.Context, write ContactWrite) (ContactResult, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := commandKey{operation: write.Command.Operation, digest: write.Command.KeyDigest}
	if existing, found := repository.contactCommands[key]; found {
		if existing.request != write.Command.RequestDigest {
			return ContactResult{}, ErrRepositoryConflict
		}
		result := existing.result
		result.Replayed = true
		return result, nil
	}
	contactID := uuidFromEntity(write.Next.ID())
	if write.Current == nil {
		if _, found := repository.contacts[contactID]; found || write.ExpectedVersion != 0 {
			return ContactResult{}, ErrRepositoryConflict
		}
	} else {
		current, found := repository.contacts[contactID]
		if !found || current.Version() != write.ExpectedVersion || current.Version() != write.Current.Version() {
			return ContactResult{}, ErrRepositoryPrecondition
		}
	}
	repository.contacts[contactID] = write.Next
	result := ContactResult{Contact: write.Next}
	if write.Command.Operation == "portal.preference.replace" {
		projection, err := kernel.ProjectCustomerSafe(write.Next)
		if err != nil {
			return ContactResult{}, ErrRepositoryConflict
		}
		result = ContactResult{CustomerProjection: &projection}
		if repository.selfContact.ID() == write.Next.ID() {
			repository.selfContact = write.Next
		}
	}
	repository.contactCommands[key] = storedContactCommand{request: write.Command.RequestDigest, result: result}
	repository.contactCommits++
	return result, nil
}

func (repository *fakeRepository) ListGroups(_ context.Context, _ Actor, tenantID uuid.UUID, input GroupListInput, _ Access) (GroupPage, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	items := make([]kernel.RecipientGroup, 0, len(repository.groups))
	for _, group := range repository.groups {
		if uuidFromEntity(group.TenantID()) == tenantID && (input.IncludeArchived || group.ArchivedAt() == nil) {
			items = append(items, group)
		}
	}
	return GroupPage{Items: items}, nil
}

func (repository *fakeRepository) GetGroup(_ context.Context, _ Actor, tenantID, groupID uuid.UUID, _ Access) (kernel.RecipientGroup, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	group, found := repository.groups[groupID]
	if !found || uuidFromEntity(group.TenantID()) != tenantID {
		return kernel.RecipientGroup{}, ErrRepositoryNotFound
	}
	return group, nil
}

func (repository *fakeRepository) ReplayGroup(
	_ context.Context,
	_ Actor,
	tenantID, groupID uuid.UUID,
	command CommandBinding,
) (GroupResult, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	existing, found := repository.groupCommands[commandKey{operation: command.Operation, digest: command.KeyDigest}]
	if !found {
		return GroupResult{}, false, nil
	}
	if existing.request != command.RequestDigest {
		return GroupResult{}, false, ErrRepositoryConflict
	}
	result := existing.result
	if uuidFromEntity(result.Group.TenantID()) != tenantID ||
		groupID != uuid.Nil && uuidFromEntity(result.Group.ID()) != groupID {
		return GroupResult{}, false, ErrRepositoryForbidden
	}
	result.Replayed = true
	return result, true, nil
}

func (repository *fakeRepository) CommitGroup(_ context.Context, write GroupWrite) (GroupResult, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := commandKey{operation: write.Command.Operation, digest: write.Command.KeyDigest}
	if existing, found := repository.groupCommands[key]; found {
		if existing.request != write.Command.RequestDigest {
			return GroupResult{}, ErrRepositoryConflict
		}
		result := existing.result
		result.Replayed = true
		return result, nil
	}
	groupID := uuidFromEntity(write.Next.ID())
	if write.Current != nil {
		current, found := repository.groups[groupID]
		if !found || current.Current().Version() != write.ExpectedVersion {
			return GroupResult{}, ErrRepositoryPrecondition
		}
	}
	repository.groups[groupID] = write.Next
	result := GroupResult{Group: write.Next}
	repository.groupCommands[key] = storedGroupCommand{request: write.Command.RequestDigest, result: result}
	repository.groupCommits++
	return result, nil
}

func (repository *fakeRepository) ResolveExactLinkAccess(_ context.Context, _ Actor, _ uuid.UUID, _ kernel.TicketKind, _ uuid.UUID, _ uuid.UUID, _ uint64) (ExactLinkAccess, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.exactLink.TenantID == uuid.Nil {
		return ExactLinkAccess{}, ErrRepositoryForbidden
	}
	return repository.exactLink, nil
}

func (repository *fakeRepository) ListLinks(_ context.Context, _ Actor, tenantID uuid.UUID, input LinkListInput) (LinkPage, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	items := make([]kernel.TicketContactLink, 0, len(repository.links))
	for _, link := range repository.links {
		if uuidFromEntity(link.TenantID()) == tenantID && link.TicketKind() == input.TicketKind &&
			uuidFromEntity(link.TicketID()) == input.TicketID && link.ArchivedAt() == nil {
			items = append(items, link)
		}
	}
	slices.SortFunc(items, func(left, right kernel.TicketContactLink) int {
		return strings.Compare(left.ID().String(), right.ID().String())
	})
	if len(items) > input.Limit {
		items = items[:input.Limit]
	}
	return LinkPage{Items: items}, nil
}

func (repository *fakeRepository) GetLinkForArchive(
	_ context.Context,
	_ Actor,
	tenantID, linkID uuid.UUID,
	kind kernel.TicketKind,
	ticketID uuid.UUID,
) (kernel.TicketContactLink, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	link, found := repository.links[linkID]
	if !found || uuidFromEntity(link.TenantID()) != tenantID || link.TicketKind() != kind ||
		uuidFromEntity(link.TicketID()) != ticketID {
		return kernel.TicketContactLink{}, ErrRepositoryNotFound
	}
	return link, nil
}

func (repository *fakeRepository) ReplayLink(
	_ context.Context,
	_ Actor,
	tenantID, linkID uuid.UUID,
	kind kernel.TicketKind,
	ticketID uuid.UUID,
	command CommandBinding,
) (LinkResult, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	existing, found := repository.linkCommands[commandKey{operation: command.Operation, digest: command.KeyDigest}]
	if !found {
		return LinkResult{}, false, nil
	}
	if existing.request != command.RequestDigest {
		return LinkResult{}, false, ErrRepositoryConflict
	}
	result := existing.result
	if uuidFromEntity(result.Link.TenantID()) != tenantID || result.Link.TicketKind() != kind ||
		uuidFromEntity(result.Link.TicketID()) != ticketID ||
		linkID != uuid.Nil && uuidFromEntity(result.Link.ID()) != linkID {
		return LinkResult{}, false, ErrRepositoryForbidden
	}
	result.Replayed = true
	return result, true, nil
}

func (repository *fakeRepository) CommitLink(_ context.Context, write LinkWrite) (LinkResult, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := commandKey{operation: write.Command.Operation, digest: write.Command.KeyDigest}
	if existing, found := repository.linkCommands[key]; found {
		if existing.request != write.Command.RequestDigest {
			return LinkResult{}, ErrRepositoryConflict
		}
		result := existing.result
		result.Replayed = true
		return result, nil
	}
	linkID := uuidFromEntity(write.Next.ID())
	repository.links[linkID] = write.Next
	result := LinkResult{Link: write.Next}
	repository.linkCommands[key] = storedLinkCommand{request: write.Command.RequestDigest, result: result}
	repository.linkCommits++
	return result, nil
}

func (repository *fakeRepository) ResolvePortalResource(_ context.Context, _ Actor, _ uuid.UUID, input PortalResourceInput) (PortalResourceEvidence, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.portalInput = input
	if repository.portal.TenantID == uuid.Nil {
		return PortalResourceEvidence{}, ErrRepositoryForbidden
	}
	return repository.portal, nil
}

func TestPortalAttachmentAuthorizationBindsCompoundPermissionEvidence(t *testing.T) {
	t.Parallel()
	repository := newFakeRepository()
	service := mustService(t, repository)
	actor, tenantID := customerActor()
	ticketID, contactID := uuidv7(73), uuidv7(74)
	input := PortalResourceInput{
		TicketKind: kernel.TicketAlert, TicketID: ticketID,
		Capability: CapabilityPortalAttachmentRead, RequiredCapability: CapabilityPortalAlertRead,
	}
	repository.portal = PortalResourceEvidence{
		TenantID: tenantID, TicketKind: input.TicketKind, TicketID: ticketID, ContactID: contactID,
		ContactVersion: 2, TicketVersion: 9, CustomerVisible: true, ContactActive: true, Linked: true,
		Capability: input.Capability, RequiredCapability: input.RequiredCapability,
	}
	authorization, err := service.AuthorizePortalResource(context.Background(), actor, tenantID, input)
	if err != nil || authorization.ContactID != contactID || authorization.TicketVersion != 9 || repository.portalInput != input {
		t.Fatalf("compound portal authorization = (%#v, %v), repository input=%#v", authorization, err, repository.portalInput)
	}

	repository.portal.RequiredCapability = ""
	if _, err = service.AuthorizePortalResource(context.Background(), actor, tenantID, input); !errors.Is(err, ErrForbidden) {
		t.Fatalf("missing compound evidence error = %v, want forbidden", err)
	}
	input.RequiredCapability = input.Capability
	if _, err = service.AuthorizePortalResource(context.Background(), actor, tenantID, input); !errors.Is(err, ErrForbidden) {
		t.Fatalf("duplicate compound capability error = %v, want forbidden", err)
	}
}

func TestCreateContactIsIdempotentUnderConcurrency(t *testing.T) {
	t.Parallel()
	repository := newFakeRepository()
	repository.access[CapabilityContactManage] = tenantOperatorAccess(CapabilityContactManage)
	service := mustService(t, repository)
	actor, tenantID := operatorActor()
	input := CreateContactInput{
		Fields: contactFields("shared@example.com"), IdempotencyKey: "contact-create-key-0001", Audit: actor.Audit,
	}
	const attempts = 32
	results := make(chan ContactResult, attempts)
	errorsChannel := make(chan error, attempts)
	var group sync.WaitGroup
	for range attempts {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := service.CreateContact(context.Background(), actor, tenantID, input)
			results <- result
			errorsChannel <- err
		}()
	}
	group.Wait()
	close(results)
	close(errorsChannel)
	var resultID kernel.EntityID
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("CreateContact() error = %v", err)
		}
	}
	for result := range results {
		if resultID == (kernel.EntityID{}) {
			resultID = result.Contact.ID()
		} else if result.Contact.ID() != resultID {
			t.Fatalf("idempotent results diverged: %s != %s", result.Contact.ID(), resultID)
		}
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.contactCommits != 1 || len(repository.contacts) != 1 {
		t.Fatalf("commits=%d contacts=%d", repository.contactCommits, len(repository.contacts))
	}
}

func TestContactOptimisticConcurrencyHasOneWinner(t *testing.T) {
	t.Parallel()
	repository := newFakeRepository()
	repository.access[CapabilityContactManage] = tenantOperatorAccess(CapabilityContactManage)
	service := mustService(t, repository)
	actor, tenantID := operatorActor()
	current := kernelContact(t, kernelID(20), kernelIDFromUUID(tenantID), contactFields("person@example.com"), fixedNow())
	repository.contacts[uuidFromEntity(current.ID())] = current

	inputs := []ReplaceContactInput{
		{Fields: contactFields("first@example.com"), ExpectedVersion: 1, IdempotencyKey: "contact-update-key-0001", Audit: actor.Audit},
		{Fields: contactFields("second@example.com"), ExpectedVersion: 1, IdempotencyKey: "contact-update-key-0002", Audit: actor.Audit},
	}
	errorsChannel := make(chan error, len(inputs))
	var group sync.WaitGroup
	for _, input := range inputs {
		input := input
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := service.ReplaceContact(context.Background(), actor, tenantID, uuidFromEntity(current.ID()), input)
			errorsChannel <- err
		}()
	}
	group.Wait()
	close(errorsChannel)
	successes, preconditions := 0, 0
	for err := range errorsChannel {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrPreconditionFailed):
			preconditions++
		default:
			t.Fatalf("unexpected error = %v", err)
		}
	}
	if successes != 1 || preconditions != 1 {
		t.Fatalf("success=%d precondition=%d", successes, preconditions)
	}
}

func TestContactReplayReturnsOriginalSnapshotAfterLaterMutation(t *testing.T) {
	t.Parallel()
	repository := newFakeRepository()
	repository.access[CapabilityContactManage] = tenantOperatorAccess(CapabilityContactManage)
	service := mustService(t, repository)
	actor, tenantID := operatorActor()
	create := CreateContactInput{
		Fields: contactFields("original@example.com"), IdempotencyKey: "contact-snapshot-key-0001", Audit: actor.Audit,
	}
	original, err := service.CreateContact(context.Background(), actor, tenantID, create)
	if err != nil {
		t.Fatal(err)
	}
	contactID := uuidFromEntity(original.Contact.ID())
	updatedFields := contactFields("updated@example.com")
	if _, err = service.ReplaceContact(context.Background(), actor, tenantID, contactID, ReplaceContactInput{
		Fields: updatedFields, ExpectedVersion: 1, IdempotencyKey: "contact-snapshot-key-0002", Audit: actor.Audit,
	}); err != nil {
		t.Fatal(err)
	}
	replayed, err := service.CreateContact(context.Background(), actor, tenantID, create)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed || replayed.Contact.ID() != original.Contact.ID() || replayed.Contact.Version() != 1 ||
		replayed.Contact.Fields().Email.String() != "original@example.com" {
		t.Fatalf("replayed snapshot = %#v", replayed)
	}
	repository.mu.Lock()
	current := repository.contacts[contactID]
	repository.mu.Unlock()
	if current.Version() != 2 || current.Fields().Email.String() != "updated@example.com" {
		t.Fatalf("current contact was altered by replay: %s", current)
	}
}

func TestPortalPreferenceReplayRequiresLiveLinkedIdentityAndKeepsCustomerProjection(t *testing.T) {
	t.Parallel()
	repository := newFakeRepository()
	service := mustService(t, repository)
	actor, tenantID := customerActor()
	linked, err := kernel.NewLinkedAccount(kernelIDFromUUID(actor.MembershipID), kernelIDFromUUID(actor.UserID))
	if err != nil {
		t.Fatal(err)
	}
	fields := contactFields("portal-replay@example.com")
	fields.LinkedAccount = &linked
	contact := kernelContact(t, kernelID(33), kernelIDFromUUID(tenantID), fields, fixedNow())
	repository.selfContact = contact
	repository.contacts[uuidFromEntity(contact.ID())] = contact
	repository.selfAccess = Access{
		Capability: CapabilityPortalPreferenceManage, Scope: ScopeContactSelf,
		Projection: ProjectionCustomer, ContactID: uuidFromEntity(contact.ID()),
	}
	first := PreferenceInput{
		Categories: []kernel.Key{kernelKey(t, "sla.warning")}, EmailAllowed: false, ExpectedVersion: 1,
		IdempotencyKey: "portal-replay-key-0001", Audit: actor.Audit,
	}
	original, err := service.UpdatePortalPreferences(context.Background(), actor, tenantID, first)
	if err != nil {
		t.Fatal(err)
	}
	if original.CustomerProjection == nil {
		t.Fatal("portal mutation omitted customer projection")
	}
	if _, err = service.UpdatePortalPreferences(context.Background(), actor, tenantID, PreferenceInput{
		Categories: []kernel.Key{kernelKey(t, "comment.public_added")}, EmailAllowed: true, ExpectedVersion: 2,
		IdempotencyKey: "portal-replay-key-0002", Audit: actor.Audit,
	}); err != nil {
		t.Fatal(err)
	}
	replayed, err := service.UpdatePortalPreferences(context.Background(), actor, tenantID, first)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed || replayed.CustomerProjection == nil || replayed.Contact.ID() != (kernel.EntityID{}) ||
		replayed.CustomerProjection.Version != 2 || replayed.CustomerProjection.EmailAllowed {
		t.Fatalf("portal replay = %#v", replayed)
	}

	repository.selfAccess.ContactID = uuidv7(94)
	if _, err = service.UpdatePortalPreferences(context.Background(), actor, tenantID, first); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked linked identity replay error = %v", err)
	}
}

func TestContactReplayRejectsDivergentIdempotencyReuse(t *testing.T) {
	t.Parallel()
	repository := newFakeRepository()
	repository.access[CapabilityContactManage] = tenantOperatorAccess(CapabilityContactManage)
	service := mustService(t, repository)
	actor, tenantID := operatorActor()
	input := CreateContactInput{
		Fields: contactFields("stable@example.com"), IdempotencyKey: "contact-divergent-key-0001", Audit: actor.Audit,
	}
	if _, err := service.CreateContact(context.Background(), actor, tenantID, input); err != nil {
		t.Fatal(err)
	}
	input.Fields = contactFields("divergent@example.com")
	if _, err := service.CreateContact(context.Background(), actor, tenantID, input); !errors.Is(err, ErrConflict) {
		t.Fatalf("divergent replay error = %v", err)
	}
}

func TestPortalPreferencesRequireExactLinkedIdentity(t *testing.T) {
	t.Parallel()
	repository := newFakeRepository()
	service := mustService(t, repository)
	actor, tenantID := customerActor()
	linked, err := kernel.NewLinkedAccount(kernelIDFromUUID(actor.MembershipID), kernelIDFromUUID(actor.UserID))
	if err != nil {
		t.Fatal(err)
	}
	fields := contactFields("customer@example.com")
	fields.LinkedAccount = &linked
	contact := kernelContact(t, kernelID(30), kernelIDFromUUID(tenantID), fields, fixedNow())
	repository.selfContact = contact
	repository.contacts[uuidFromEntity(contact.ID())] = contact
	repository.selfAccess = Access{
		Capability: CapabilityPortalPreferenceManage, Scope: ScopeContactSelf,
		Projection: ProjectionCustomer, ContactID: uuidFromEntity(contact.ID()),
	}
	result, err := service.UpdatePortalPreferences(context.Background(), actor, tenantID, PreferenceInput{
		Categories: []kernel.Key{kernelKey(t, "sla.warning")}, EmailAllowed: false, ExpectedVersion: 1,
		IdempotencyKey: "portal-pref-key-0001", Audit: actor.Audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.CustomerProjection == nil || result.CustomerProjection.EmailAllowed || result.CustomerProjection.Version != 2 {
		t.Fatalf("result = %#v", result.CustomerProjection)
	}

	wrong := repository.selfAccess
	wrong.ContactID = uuidv7(99)
	repository.selfAccess = wrong
	if _, err := service.SelfContact(context.Background(), actor, tenantID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ambiguous self relation error = %v", err)
	}
}

func TestPortalTicketAndCommentAuthorizationFailClosed(t *testing.T) {
	t.Parallel()
	repository := newFakeRepository()
	service := mustService(t, repository)
	actor, tenantID := customerActor()
	ticketID, contactID := uuidv7(70), uuidv7(71)
	repository.portal = PortalResourceEvidence{
		TenantID: tenantID, TicketKind: kernel.TicketCase, TicketID: ticketID, ContactID: contactID,
		ContactVersion: 2, TicketVersion: 9, CustomerVisible: true, ContactActive: true, Linked: true,
		Capability: CapabilityPortalCommentPublic,
	}
	snapshot, err := service.ResolveCustomerCommentAuthor(context.Background(), actor, tenantID, kernel.TicketCase, ticketID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Audience() != kernel.AuthorCustomer || snapshot.ContactID() == nil || uuidFromEntity(*snapshot.ContactID()) != contactID {
		t.Fatalf("snapshot = %s", snapshot)
	}

	for _, mutate := range []func(*PortalResourceEvidence){
		func(value *PortalResourceEvidence) { value.CustomerVisible = false },
		func(value *PortalResourceEvidence) { value.ContactActive = false },
		func(value *PortalResourceEvidence) { value.Linked = false },
		func(value *PortalResourceEvidence) { value.ContactID = uuid.Nil },
		func(value *PortalResourceEvidence) { value.Capability = CapabilityPortalCaseRead },
	} {
		evidence := repository.portal
		mutate(&evidence)
		repository.portal = evidence
		if _, err := service.ResolveCustomerCommentAuthor(context.Background(), actor, tenantID, kernel.TicketCase, ticketID); !errors.Is(err, ErrForbidden) {
			t.Fatalf("invalid evidence error = %v", err)
		}
		repository.portal = PortalResourceEvidence{
			TenantID: tenantID, TicketKind: kernel.TicketCase, TicketID: ticketID, ContactID: contactID,
			ContactVersion: 2, TicketVersion: 9, CustomerVisible: true, ContactActive: true, Linked: true,
			Capability: CapabilityPortalCommentPublic,
		}
	}
}

func TestLinkRequiresBothExactPermissions(t *testing.T) {
	t.Parallel()
	repository := newFakeRepository()
	service := mustService(t, repository)
	actor, tenantID := operatorActor()
	ticketID, contactID := uuidv7(50), uuidv7(51)
	input := LinkInput{
		TicketKind: kernel.TicketAlert, TicketID: ticketID, ContactID: contactID, Role: kernel.RolePrimary,
		ExpectedTicketVersion: 4, IdempotencyKey: "ticket-contact-key-0001", Audit: actor.Audit,
	}
	repository.exactLink = ExactLinkAccess{
		TenantID: tenantID, TicketKind: input.TicketKind, TicketID: ticketID, ContactID: contactID,
		TicketVersion: 4, ContactVersion: 2, ResourceCapability: CapabilityAlertUpdate,
		ContactReadable: true, ResourceWritable: true,
	}
	result, err := service.LinkContact(context.Background(), actor, tenantID, input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Link.ContactID() != kernelIDFromUUID(contactID) || result.Link.TicketID() != kernelIDFromUUID(ticketID) {
		t.Fatalf("link = %s", result.Link)
	}

	for _, mutate := range []func(*ExactLinkAccess){
		func(value *ExactLinkAccess) { value.ContactReadable = false },
		func(value *ExactLinkAccess) { value.ResourceWritable = false },
		func(value *ExactLinkAccess) { value.ResourceCapability = CapabilityCaseUpdate },
		func(value *ExactLinkAccess) { value.ContactID = uuidv7(90) },
	} {
		access := repository.exactLink
		mutate(&access)
		repository.exactLink = access
		input.IdempotencyKey = "ticket-contact-key-0002"
		if _, err := service.LinkContact(context.Background(), actor, tenantID, input); !errors.Is(err, ErrForbidden) {
			t.Fatalf("invalid access error = %v", err)
		}
		repository.exactLink = ExactLinkAccess{
			TenantID: tenantID, TicketKind: input.TicketKind, TicketID: ticketID, ContactID: contactID,
			TicketVersion: 4, ContactVersion: 2, ResourceCapability: CapabilityAlertUpdate,
			ContactReadable: true, ResourceWritable: true,
		}
	}
}

func TestCustomerCannotUseOperatorContactAdministration(t *testing.T) {
	t.Parallel()
	repository := newFakeRepository()
	repository.access[CapabilityContactRead] = tenantOperatorAccess(CapabilityContactRead)
	service := mustService(t, repository)
	actor, tenantID := customerActor()
	if _, err := service.ListContacts(context.Background(), actor, tenantID, ContactListInput{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("customer list error = %v", err)
	}
	operator, _ := operatorActor()
	repository.access[CapabilityContactManage] = Access{
		Capability: CapabilityContactManage, Scope: ScopeContactSelf, Projection: ProjectionCustomer,
	}
	if _, err := service.CreateContact(context.Background(), operator, tenantID, CreateContactInput{
		Fields: contactFields("x@example.com"), IdempotencyKey: "contact-create-key-0003", Audit: operator.Audit,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("wrong projection error = %v", err)
	}
}

func TestRouteIntentStillRequiresCapabilityAndExactCustomerLink(t *testing.T) {
	t.Parallel()
	t.Run("linked customer on admin route still needs operator capability", func(t *testing.T) {
		repository := newFakeRepository()
		service := mustService(t, repository)
		actor, tenantID := customerActor()
		actor.Kind = PrincipalOperator
		linked, err := kernel.NewLinkedAccount(
			kernelIDFromUUID(actor.MembershipID), kernelIDFromUUID(actor.UserID),
		)
		if err != nil {
			t.Fatal(err)
		}
		fields := contactFields("linked-admin-route@example.com")
		fields.LinkedAccount = &linked
		repository.selfContact = kernelContact(
			t, kernelID(31), kernelIDFromUUID(tenantID), fields, fixedNow(),
		)
		if _, err := service.ListContacts(
			context.Background(), actor, tenantID, ContactListInput{},
		); !errors.Is(err, ErrForbidden) {
			t.Fatalf("admin route without contact.read error = %v", err)
		}
	})

	t.Run("operator on self route still needs exact linked identity", func(t *testing.T) {
		repository := newFakeRepository()
		service := mustService(t, repository)
		actor, tenantID := operatorActor()
		actor.Kind = PrincipalCustomer
		otherMembershipID, otherUserID := uuidv7(91), uuidv7(92)
		linked, err := kernel.NewLinkedAccount(
			kernelIDFromUUID(otherMembershipID), kernelIDFromUUID(otherUserID),
		)
		if err != nil {
			t.Fatal(err)
		}
		fields := contactFields("unlinked-self-route@example.com")
		fields.LinkedAccount = &linked
		contact := kernelContact(t, kernelID(32), kernelIDFromUUID(tenantID), fields, fixedNow())
		repository.selfContact = contact
		repository.selfAccess = Access{
			Capability: CapabilityPortalPreferenceManage,
			Scope:      ScopeContactSelf,
			Projection: ProjectionCustomer,
			ContactID:  uuidFromEntity(contact.ID()),
		}
		if _, err := service.SelfContact(context.Background(), actor, tenantID); !errors.Is(err, ErrForbidden) {
			t.Fatalf("self route with mismatched linked identity error = %v", err)
		}
	})
}

func mustService(t *testing.T, repository Repository) *Service {
	t.Helper()
	service, err := NewService(repository, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func fixedNow() time.Time { return time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC) }

func uuidv7(seed byte) uuid.UUID {
	var value uuid.UUID
	for index := range value {
		value[index] = seed + byte(index)
	}
	value[6] = 0x70 | value[6]&0x0f
	value[8] = 0x80 | value[8]&0x3f
	return value
}

func kernelID(seed byte) kernel.EntityID { return kernelIDFromUUID(uuidv7(seed)) }
func kernelIDFromUUID(value uuid.UUID) kernel.EntityID {
	id, err := kernel.NewEntityID([16]byte(value))
	if err != nil {
		panic(err)
	}
	return id
}

func kernelKey(t *testing.T, value string) kernel.Key {
	t.Helper()
	key, err := kernel.NewKey(value)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func contactFields(emailValue string) kernel.ContactFields {
	email, _ := kernel.NewEmail(emailValue)
	class, _ := kernel.NewKey("gold")
	category, _ := kernel.NewKey("comment.public_added")
	tag, _ := kernel.NewKey("security")
	return kernel.ContactFields{
		FirstName: "Arianna", LastName: "Rossi", Email: email, Function: "Incident manager",
		Language: "it-it", Timezone: "Europe/Rome", EscalationPriority: 20, Class: class,
		NotificationCategories: []kernel.Key{category}, EmailAllowed: true, Active: true, Tags: []kernel.Key{tag},
	}
}

func kernelContact(t *testing.T, id, tenant kernel.EntityID, fields kernel.ContactFields, at time.Time) kernel.Contact {
	t.Helper()
	contact, err := kernel.NewContact(id, tenant, fields, at)
	if err != nil {
		t.Fatal(err)
	}
	return contact
}

func operatorActor() (Actor, uuid.UUID) {
	tenantID := uuidv7(1)
	audit := AuditContext{
		RequestID: uuid.New(), CorrelationID: uuid.New(), RemoteAddress: netip.MustParseAddr("192.0.2.10"), UserAgent: "contacts-test",
	}
	return Actor{
		TenantID: tenantID, ActiveTenantID: tenantID, UserID: uuidv7(2), MembershipID: uuidv7(3),
		SessionID: uuidv7(4), Kind: PrincipalOperator, AuthenticationMethod: "totp", Audit: audit,
	}, tenantID
}

func customerActor() (Actor, uuid.UUID) {
	actor, tenantID := operatorActor()
	actor.Kind = PrincipalCustomer
	return actor, tenantID
}

func tenantOperatorAccess(capability Capability) Access {
	return Access{Capability: capability, Scope: ScopeTenant, Projection: ProjectionOperator}
}
