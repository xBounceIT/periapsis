package httpserver

import (
	"errors"
	"math"
	"net/http"
	"slices"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	contactkernel "github.com/periapsis-im/periapsis/modules/contacts"
	ticketkernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	applicationcontacts "github.com/periapsis-im/periapsis/services/api/internal/contacts"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func (h *Handler) ListTenantCustomerContacts(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, params contract.ListTenantCustomerContactsParams) {
	actor, ok := h.contactReadActor(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	input := applicationcontacts.ContactListInput{
		Active: params.Active, IncludeArchived: params.IncludeArchived != nil && bool(*params.IncludeArchived),
	}
	if params.After != nil {
		input.After = string(*params.After)
	}
	if params.Limit != nil {
		input.Limit = int(*params.Limit)
	}
	if params.Search != nil {
		input.Search = *params.Search
	}
	if params.ContactClass != nil {
		input.Class = string(*params.ContactClass)
	}
	if params.Tag != nil {
		input.Tag = string(*params.Tag)
	}
	page, err := h.contacts.ListContacts(r.Context(), actor, uuid.UUID(tenantID), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.CustomerContact, len(page.Items))
	for index, value := range page.Items {
		items[index], err = mapCustomerContact(value)
		if err != nil {
			writeDomainError(w, r, applicationcontacts.ErrUnavailable)
			return
		}
	}
	result := contract.CustomerContactList{Items: items}
	if page.NextCursor != "" {
		result.NextCursor = &page.NextCursor
	}
	writeSensitiveJSON(w, http.StatusOK, result)
}

func (h *Handler) CreateTenantCustomerContact(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, _ contract.CreateTenantCustomerContactParams) {
	actor, audit, key, ok := h.contactMutationContext(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	var body contract.CreateTenantCustomerContactJSONRequestBody
	if decodeAuthorizationBody(r, &body, "application/json") != nil {
		writeDomainError(w, r, applicationcontacts.ErrInvalidInput)
		return
	}
	fields, err := contactFields(body)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.contacts.CreateContact(r.Context(), actor, uuid.UUID(tenantID), applicationcontacts.CreateContactInput{
		Fields: fields, IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeCustomerContact(w, r, http.StatusCreated, uuid.UUID(tenantID), result.Contact, true)
}

func (h *Handler) GetTenantCustomerContact(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, contactID contract.ContactId) {
	actor, ok := h.contactReadActor(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	value, err := h.contacts.GetContact(r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(contactID))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeCustomerContact(w, r, http.StatusOK, uuid.UUID(tenantID), value, false)
}

func (h *Handler) ReplaceTenantCustomerContact(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, contactID contract.ContactId, _ contract.ReplaceTenantCustomerContactParams) {
	actor, audit, key, ok := h.contactMutationContext(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	version, ok := contactVersionPrecondition(w, r)
	if !ok {
		return
	}
	var body contract.ReplaceTenantCustomerContactJSONRequestBody
	if decodeAuthorizationBody(r, &body, "application/json") != nil {
		writeDomainError(w, r, applicationcontacts.ErrInvalidInput)
		return
	}
	fields, err := contactFields(body)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.contacts.ReplaceContact(r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(contactID), applicationcontacts.ReplaceContactInput{
		Fields: fields, ExpectedVersion: version, IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeCustomerContact(w, r, http.StatusOK, uuid.UUID(tenantID), result.Contact, false)
}

func (h *Handler) ArchiveTenantCustomerContact(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, contactID contract.ContactId, _ contract.ArchiveTenantCustomerContactParams) {
	actor, audit, key, ok := h.contactMutationContext(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	version, ok := contactVersionPrecondition(w, r)
	if !ok {
		return
	}
	var body contract.ArchiveTenantCustomerContactJSONRequestBody
	if decodeAuthorizationBody(r, &body, "application/json") != nil {
		writeDomainError(w, r, applicationcontacts.ErrInvalidInput)
		return
	}
	result, err := h.contacts.ArchiveContact(r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(contactID), applicationcontacts.ArchiveInput{
		ExpectedVersion: version, Reason: body.Reason, IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeCustomerContact(w, r, http.StatusOK, uuid.UUID(tenantID), result.Contact, false)
}

func (h *Handler) ListTenantCustomerContactGroups(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, params contract.ListTenantCustomerContactGroupsParams) {
	actor, ok := h.contactReadActor(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	input := applicationcontacts.GroupListInput{IncludeArchived: params.IncludeArchived != nil && bool(*params.IncludeArchived)}
	if params.After != nil {
		input.After = string(*params.After)
	}
	if params.Limit != nil {
		input.Limit = int(*params.Limit)
	}
	if params.Search != nil {
		input.Search = *params.Search
	}
	page, err := h.contacts.ListGroups(r.Context(), actor, uuid.UUID(tenantID), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.CustomerContactGroup, len(page.Items))
	for index, value := range page.Items {
		items[index], err = mapCustomerContactGroup(value)
		if err != nil {
			writeDomainError(w, r, applicationcontacts.ErrUnavailable)
			return
		}
	}
	result := contract.CustomerContactGroupList{Items: items}
	if page.NextCursor != "" {
		result.NextCursor = &page.NextCursor
	}
	writeSensitiveJSON(w, http.StatusOK, result)
}

func (h *Handler) CreateTenantCustomerContactGroup(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, _ contract.CreateTenantCustomerContactGroupParams) {
	actor, audit, key, ok := h.contactMutationContext(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	var body contract.CreateTenantCustomerContactGroupJSONRequestBody
	if decodeAuthorizationBody(r, &body, "application/json") != nil || !body.Mode.Valid() {
		writeDomainError(w, r, applicationcontacts.ErrInvalidInput)
		return
	}
	groupKey, err := contactkernel.NewKey(body.Key)
	if err != nil {
		writeDomainError(w, r, applicationcontacts.ErrInvalidInput)
		return
	}
	mode, rule, err := contactGroupShape(string(body.Mode), body.Rule, schemaVersion(body.RuleSchemaVersion))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.contacts.CreateGroup(r.Context(), actor, uuid.UUID(tenantID), applicationcontacts.CreateGroupInput{
		Key: groupKey, Name: body.Name, Description: body.Description, Mode: mode, Rule: rule,
		MemberIDs: contractUUIDs(body.MemberIds), IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeCustomerContactGroup(w, r, http.StatusCreated, uuid.UUID(tenantID), result.Group, true)
}

func (h *Handler) GetTenantCustomerContactGroup(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, groupID contract.ContactGroupId) {
	actor, ok := h.contactReadActor(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	group, err := h.contacts.GetGroup(r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(groupID))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeCustomerContactGroup(w, r, http.StatusOK, uuid.UUID(tenantID), group, false)
}

func (h *Handler) VersionTenantCustomerContactGroup(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, groupID contract.ContactGroupId, _ contract.VersionTenantCustomerContactGroupParams) {
	actor, audit, key, ok := h.contactMutationContext(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	version, ok := contactVersionPrecondition(w, r)
	if !ok {
		return
	}
	var body contract.VersionTenantCustomerContactGroupJSONRequestBody
	if decodeAuthorizationBody(r, &body, "application/json") != nil || !body.Mode.Valid() {
		writeDomainError(w, r, applicationcontacts.ErrInvalidInput)
		return
	}
	mode, rule, err := contactGroupShape(string(body.Mode), body.Rule, schemaVersion(body.RuleSchemaVersion))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.contacts.VersionGroup(r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(groupID), applicationcontacts.VersionGroupInput{
		Name: body.Name, Description: body.Description, Mode: mode, Rule: rule,
		MemberIDs: contractUUIDs(body.MemberIds), ExpectedVersion: version, IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeCustomerContactGroup(w, r, http.StatusOK, uuid.UUID(tenantID), result.Group, false)
}

func (h *Handler) GetCustomerPortalContact(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId) {
	actor, ok := h.portalContactReadActor(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	value, err := h.contacts.SelfContact(r.Context(), actor, uuid.UUID(tenantID))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapCustomerPortalContact(value)
	if err != nil || !setVersionETag(w, int64(value.Version)) {
		writeDomainError(w, r, applicationcontacts.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ReplaceCustomerPortalContactPreferences(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, _ contract.ReplaceCustomerPortalContactPreferencesParams) {
	actor, audit, key, ok := h.portalContactMutationContext(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	version, ok := contactVersionPrecondition(w, r)
	if !ok {
		return
	}
	var body contract.ReplaceCustomerPortalContactPreferencesJSONRequestBody
	if decodeAuthorizationBody(r, &body, "application/json") != nil {
		writeDomainError(w, r, applicationcontacts.ErrInvalidInput)
		return
	}
	categories, windows, err := contactPreferences(body.NotificationCategories, body.NotificationWindows)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.contacts.UpdatePortalPreferences(r.Context(), actor, uuid.UUID(tenantID), applicationcontacts.PreferenceInput{
		Categories: categories, Windows: windows, EmailAllowed: body.EmailAllowed,
		ExpectedVersion: version, IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if result.CustomerProjection == nil {
		writeDomainError(w, r, applicationcontacts.ErrUnavailable)
		return
	}
	projected := *result.CustomerProjection
	mapped, err := mapCustomerPortalContact(projected)
	if err != nil || !setVersionETag(w, int64(projected.Version)) {
		writeDomainError(w, r, applicationcontacts.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ListCustomerPortalAlerts(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, params contract.ListCustomerPortalAlertsParams) {
	h.listCustomerPortalTickets(w, r, uuid.UUID(tenantID), ticketkernel.AggregateAlert, params.After, params.Limit, params.Search)
}

func (h *Handler) ListCustomerPortalCases(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, params contract.ListCustomerPortalCasesParams) {
	h.listCustomerPortalTickets(w, r, uuid.UUID(tenantID), ticketkernel.AggregateCase, params.After, params.Limit, params.Search)
}

func (h *Handler) GetCustomerPortalAlert(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId) {
	h.getCustomerPortalTicket(w, r, uuid.UUID(tenantID), ticketkernel.AggregateAlert, uuid.UUID(alertID))
}

func (h *Handler) GetCustomerPortalCase(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId) {
	h.getCustomerPortalTicket(w, r, uuid.UUID(tenantID), ticketkernel.AggregateCase, uuid.UUID(caseID))
}

func (h *Handler) listCustomerPortalTickets(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind ticketkernel.AggregateKind, after *contract.TicketAfterCursor, limit *contract.PageSize, search *string) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	input := applicationticketing.ListInput{}
	if after != nil {
		input.After = string(*after)
	}
	if limit != nil {
		input.Limit = int(*limit)
	}
	if search != nil {
		input.Search = *search
	}
	page, err := h.ticketing.ListPortal(r.Context(), actor, tenantID, kind, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	for _, value := range page.Items {
		if value.Projection != applicationticketing.ProjectionCustomer || value.Record.Snapshot.Kind() != kind {
			writeDomainError(w, r, applicationticketing.ErrUnavailable)
			return
		}
	}
	mapped, err := mapTicketPage(page)
	if err != nil {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) getCustomerPortalTicket(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind ticketkernel.AggregateKind, id uuid.UUID) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	view, err := h.ticketing.GetPortal(r.Context(), actor, tenantID, kind, id)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if view.Projection != applicationticketing.ProjectionCustomer || view.Record.Snapshot.Kind() != kind {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	mapped, err := mapTicketView(view)
	if err != nil || view.Record.Snapshot.Version() > math.MaxInt64 || !setVersionETag(w, int64(view.Record.Snapshot.Version())) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) contactReadActor(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) (applicationcontacts.Actor, bool) {
	return h.contactReadActorWithKind(w, r, tenantID, applicationcontacts.PrincipalOperator)
}

func (h *Handler) portalContactReadActor(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) (applicationcontacts.Actor, bool) {
	return h.contactReadActorWithKind(w, r, tenantID, applicationcontacts.PrincipalCustomer)
}

func (h *Handler) contactReadActorWithKind(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind applicationcontacts.PrincipalKind) (applicationcontacts.Actor, bool) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return applicationcontacts.Actor{}, false
	}
	return h.resolveContactActor(w, r, actor, applicationcontacts.AuditContext{}, tenantID, kind)
}

func (h *Handler) contactMutationContext(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) (applicationcontacts.Actor, applicationcontacts.AuditContext, string, bool) {
	return h.contactMutationContextWithKind(w, r, tenantID, applicationcontacts.PrincipalOperator)
}

func (h *Handler) portalContactMutationContext(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) (applicationcontacts.Actor, applicationcontacts.AuditContext, string, bool) {
	return h.contactMutationContextWithKind(w, r, tenantID, applicationcontacts.PrincipalCustomer)
}

func (h *Handler) contactMutationContextWithKind(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind applicationcontacts.PrincipalKind) (applicationcontacts.Actor, applicationcontacts.AuditContext, string, bool) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return applicationcontacts.Actor{}, applicationcontacts.AuditContext{}, "", false
	}
	key, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, applicationcontacts.ErrInvalidInput)
		return applicationcontacts.Actor{}, applicationcontacts.AuditContext{}, "", false
	}
	contactAudit := applicationcontacts.AuditContext{
		RequestID: audit.RequestID, CorrelationID: audit.CorrelationID,
		RemoteAddress: audit.RemoteAddress, UserAgent: audit.UserAgent,
	}
	resolved, ok := h.resolveContactActor(w, r, actor, contactAudit, tenantID, kind)
	return resolved, contactAudit, key, ok
}

func (h *Handler) resolveContactActor(w http.ResponseWriter, r *http.Request, actor authorization.Actor, audit applicationcontacts.AuditContext, tenantID uuid.UUID, kind applicationcontacts.PrincipalKind) (applicationcontacts.Actor, bool) {
	if h.contacts == nil || tenantID == uuid.Nil || actor.ActiveTenantID != tenantID || actor.UserID == uuid.Nil || actor.SessionID == uuid.Nil {
		writeDomainError(w, r, applicationcontacts.ErrForbidden)
		return applicationcontacts.Actor{}, false
	}
	authority, err := h.authorization.GetTenantAuthority(r.Context(), actor, tenantID)
	if err != nil {
		writeDomainError(w, r, err)
		return applicationcontacts.Actor{}, false
	}
	if authority.TenantID != tenantID || authority.Principal.Kind != authorization.PrincipalKindHuman ||
		authority.Principal.ID != actor.UserID || authority.MembershipID == uuid.Nil ||
		authority.MembershipStatus != authorization.MembershipStatusActive {
		writeDomainError(w, r, applicationcontacts.ErrForbidden)
		return applicationcontacts.Actor{}, false
	}
	if kind != applicationcontacts.PrincipalOperator && kind != applicationcontacts.PrincipalCustomer {
		writeDomainError(w, r, applicationcontacts.ErrForbidden)
		return applicationcontacts.Actor{}, false
	}
	return applicationcontacts.Actor{
		TenantID: tenantID, ActiveTenantID: actor.ActiveTenantID, UserID: actor.UserID,
		MembershipID: authority.MembershipID, SessionID: actor.SessionID, Kind: kind,
		AuthenticationMethod: actor.AuthenticationMethod, Audit: audit,
	}, true
}

func contactVersionPrecondition(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	version, present, err := strongVersionPrecondition(r)
	if !present {
		writeDomainError(w, r, authorization.ErrPreconditionRequired)
		return 0, false
	}
	if err != nil {
		writeDomainError(w, r, applicationcontacts.ErrInvalidInput)
		return 0, false
	}
	return uint64(version), true
}

func (h *Handler) writeCustomerContact(w http.ResponseWriter, r *http.Request, status int, tenantID uuid.UUID, value contactkernel.Contact, location bool) {
	mapped, err := mapCustomerContact(value)
	if err != nil || value.Version() > math.MaxInt64 || !setVersionETag(w, int64(value.Version())) {
		writeDomainError(w, r, applicationcontacts.ErrUnavailable)
		return
	}
	if location {
		w.Header().Set("Location", "/api/v1/tenants/"+tenantID.String()+"/contacts/"+mapped.Id.String())
	}
	writeSensitiveJSON(w, status, mapped)
}

func (h *Handler) writeCustomerContactGroup(w http.ResponseWriter, r *http.Request, status int, tenantID uuid.UUID, value contactkernel.RecipientGroup, location bool) {
	mapped, err := mapCustomerContactGroup(value)
	version := value.Current().Version()
	if err != nil || version > math.MaxInt64 || !setVersionETag(w, int64(version)) {
		writeDomainError(w, r, applicationcontacts.ErrUnavailable)
		return
	}
	if location {
		w.Header().Set("Location", "/api/v1/tenants/"+tenantID.String()+"/contact-groups/"+mapped.Id.String())
	}
	writeSensitiveJSON(w, status, mapped)
}

func contactFields(body contract.CustomerContactWrite) (contactkernel.ContactFields, error) {
	email, err := contactkernel.NewEmail(string(body.Email))
	if err != nil {
		return contactkernel.ContactFields{}, applicationcontacts.ErrInvalidInput
	}
	class, err := contactkernel.NewKey(body.ContactClass)
	if err != nil {
		return contactkernel.ContactFields{}, applicationcontacts.ErrInvalidInput
	}
	categories, windows, err := contactPreferences(body.NotificationCategories, body.NotificationWindows)
	if err != nil {
		return contactkernel.ContactFields{}, err
	}
	tags, err := contactKeys(body.Tags)
	if err != nil {
		return contactkernel.ContactFields{}, err
	}
	phone := ""
	if body.Phone != nil {
		phone = *body.Phone
	}
	var linked *contactkernel.LinkedAccount
	if body.LinkedAccount != nil {
		membership, membershipErr := contactEntityID(uuid.UUID(body.LinkedAccount.MembershipId))
		user, userErr := contactEntityID(uuid.UUID(body.LinkedAccount.UserId))
		value, linkErr := contactkernel.NewLinkedAccount(membership, user)
		if membershipErr != nil || userErr != nil || linkErr != nil {
			return contactkernel.ContactFields{}, applicationcontacts.ErrInvalidInput
		}
		linked = &value
	}
	return contactkernel.ContactFields{
		FirstName: body.FirstName, LastName: body.LastName, Email: email, Phone: phone,
		Function: body.Function, Language: body.Language, Timezone: body.Timezone,
		EscalationPriority: uint8(body.EscalationPriority), Class: class,
		NotificationCategories: categories, NotificationWindows: windows,
		EmailAllowed: body.EmailAllowed, Active: body.Active, Tags: tags, LinkedAccount: linked,
	}, nil
}

func contactPreferences(categoryValues []contract.ContactStableKey, windowValues []contract.ContactNotificationWindow) ([]contactkernel.Key, []contactkernel.NotificationWindow, error) {
	categories, err := contactKeys(categoryValues)
	if err != nil {
		return nil, nil, err
	}
	windows := make([]contactkernel.NotificationWindow, len(windowValues))
	for index, value := range windowValues {
		windows[index], err = contactkernel.NewNotificationWindow(contactkernel.ISOWeekday(value.IsoWeekday), value.StartMinute, value.EndMinute)
		if err != nil {
			return nil, nil, applicationcontacts.ErrInvalidInput
		}
	}
	return categories, windows, nil
}

func contactKeys(values []contract.ContactStableKey) ([]contactkernel.Key, error) {
	result := make([]contactkernel.Key, len(values))
	for index, value := range values {
		key, err := contactkernel.NewKey(value)
		if err != nil {
			return nil, applicationcontacts.ErrInvalidInput
		}
		result[index] = key
	}
	return result, nil
}

func contactGroupShape(modeValue string, rule *contract.ContactRecipientRuleNode, schema int) (contactkernel.GroupMode, contactkernel.RuleNode, error) {
	switch modeValue {
	case "manual":
		if rule != nil || schema != 0 && schema != 1 {
			return 0, contactkernel.RuleNode{}, applicationcontacts.ErrInvalidInput
		}
		return contactkernel.GroupManual, contactkernel.RuleNode{}, nil
	case "dynamic":
		if rule == nil || schema != 0 && schema != 1 {
			return 0, contactkernel.RuleNode{}, applicationcontacts.ErrInvalidInput
		}
		parsed, err := contactRule(*rule)
		if err != nil {
			return 0, contactkernel.RuleNode{}, err
		}
		return contactkernel.GroupDynamic, parsed, nil
	default:
		return 0, contactkernel.RuleNode{}, applicationcontacts.ErrInvalidInput
	}
}

func contactRule(value contract.ContactRecipientRuleNode) (contactkernel.RuleNode, error) {
	if !value.Kind.Valid() {
		return contactkernel.RuleNode{}, applicationcontacts.ErrInvalidInput
	}
	children := []contract.ContactRecipientRuleNode(nil)
	if value.Children != nil {
		children = *value.Children
	}
	parsedChildren := make([]contactkernel.RuleNode, len(children))
	for index, child := range children {
		parsed, err := contactRule(child)
		if err != nil {
			return contactkernel.RuleNode{}, err
		}
		parsedChildren[index] = parsed
	}
	var result contactkernel.RuleNode
	var err error
	switch value.Kind {
	case contract.ContactRecipientRuleNodeKindAll:
		result, err = contactkernel.NewAllRule(parsedChildren...)
	case contract.ContactRecipientRuleNodeKindAny:
		result, err = contactkernel.NewAnyRule(parsedChildren...)
	case contract.ContactRecipientRuleNodeKindNot:
		if len(parsedChildren) != 1 {
			return contactkernel.RuleNode{}, applicationcontacts.ErrInvalidInput
		}
		result, err = contactkernel.NewNotRule(parsedChildren[0])
	case contract.ContactRecipientRuleNodeKindPredicate:
		if len(parsedChildren) != 0 || value.Field == nil || value.Operator == nil || !value.Field.Valid() || !value.Operator.Valid() {
			return contactkernel.RuleNode{}, applicationcontacts.ErrInvalidInput
		}
		values := []string(nil)
		if value.Values != nil {
			values = *value.Values
		}
		result, err = contactkernel.NewPredicate(contactPredicateField(*value.Field), contactPredicateOperator(*value.Operator), values...)
	}
	if err != nil {
		return contactkernel.RuleNode{}, applicationcontacts.ErrInvalidInput
	}
	return result, nil
}

func contactPredicateField(value contract.ContactRecipientRuleNodeField) contactkernel.PredicateField {
	values := map[contract.ContactRecipientRuleNodeField]contactkernel.PredicateField{
		contract.ContactRecipientRuleNodeFieldActive:               contactkernel.FieldActive,
		contract.ContactRecipientRuleNodeFieldEmailAllowed:         contactkernel.FieldEmailAllowed,
		contract.ContactRecipientRuleNodeFieldContactClass:         contactkernel.FieldContactClass,
		contract.ContactRecipientRuleNodeFieldTag:                  contactkernel.FieldTag,
		contract.ContactRecipientRuleNodeFieldNotificationCategory: contactkernel.FieldNotificationCategory,
		contract.ContactRecipientRuleNodeFieldLanguage:             contactkernel.FieldLanguage,
		contract.ContactRecipientRuleNodeFieldTimezone:             contactkernel.FieldTimezone,
		contract.ContactRecipientRuleNodeFieldEscalationPriority:   contactkernel.FieldEscalationPriority,
		contract.ContactRecipientRuleNodeFieldLinkedAccount:        contactkernel.FieldLinkedAccount,
	}
	return values[value]
}

func contactPredicateOperator(value contract.ContactRecipientRuleNodeOperator) contactkernel.PredicateOperator {
	values := map[contract.ContactRecipientRuleNodeOperator]contactkernel.PredicateOperator{
		contract.ContactRecipientRuleNodeOperatorEquals:             contactkernel.OperatorEquals,
		contract.ContactRecipientRuleNodeOperatorNotEquals:          contactkernel.OperatorNotEquals,
		contract.ContactRecipientRuleNodeOperatorOneOf:              contactkernel.OperatorOneOf,
		contract.ContactRecipientRuleNodeOperatorNoneOf:             contactkernel.OperatorNoneOf,
		contract.ContactRecipientRuleNodeOperatorContains:           contactkernel.OperatorContains,
		contract.ContactRecipientRuleNodeOperatorNotContains:        contactkernel.OperatorNotContains,
		contract.ContactRecipientRuleNodeOperatorGreaterThanOrEqual: contactkernel.OperatorGreaterThanOrEqual,
		contract.ContactRecipientRuleNodeOperatorLessThanOrEqual:    contactkernel.OperatorLessThanOrEqual,
		contract.ContactRecipientRuleNodeOperatorExists:             contactkernel.OperatorExists,
		contract.ContactRecipientRuleNodeOperatorNotExists:          contactkernel.OperatorNotExists,
	}
	return values[value]
}

func mapCustomerContact(value contactkernel.Contact) (contract.CustomerContact, error) {
	fields := value.Fields()
	if value.Version() == 0 || value.Version() > math.MaxInt64 {
		return contract.CustomerContact{}, errors.New("invalid contact version")
	}
	categories, tags := keyStrings(fields.NotificationCategories), keyStrings(fields.Tags)
	windows := mapContactWindows(fields.NotificationWindows)
	result := contract.CustomerContact{
		Id: openapi_types.UUID(uuid.UUID(value.ID().Bytes())), TenantId: openapi_types.UUID(uuid.UUID(value.TenantID().Bytes())),
		FirstName: fields.FirstName, LastName: fields.LastName, Email: openapi_types.Email(fields.Email.String()),
		Function: fields.Function, Language: fields.Language, Timezone: fields.Timezone,
		EscalationPriority: int(fields.EscalationPriority), ContactClass: fields.Class.String(),
		NotificationCategories: categories, NotificationWindows: windows, EmailAllowed: fields.EmailAllowed,
		Active: fields.Active, Tags: tags, Version: int64(value.Version()), CreatedAt: value.CreatedAt(), UpdatedAt: value.UpdatedAt(),
	}
	if fields.Phone != "" {
		result.Phone = &fields.Phone
	}
	if fields.LinkedAccount != nil {
		result.LinkedAccount = &contract.ContactLinkedAccount{
			MembershipId: openapi_types.UUID(uuid.UUID(fields.LinkedAccount.MembershipID().Bytes())),
			UserId:       openapi_types.UUID(uuid.UUID(fields.LinkedAccount.UserID().Bytes())),
		}
	}
	result.ArchivedAt = value.ArchivedAt()
	return result, nil
}

func mapCustomerPortalContact(value contactkernel.CustomerSafeContact) (contract.CustomerPortalContact, error) {
	if value.Version == 0 || value.Version > math.MaxInt64 || !value.Active {
		return contract.CustomerPortalContact{}, errors.New("invalid portal contact")
	}
	result := contract.CustomerPortalContact{
		Id: openapi_types.UUID(uuid.UUID(value.ID.Bytes())), FirstName: value.FirstName, LastName: value.LastName,
		Email: openapi_types.Email(value.Email.String()), Function: value.Function, Language: value.Language,
		Timezone: value.Timezone, NotificationCategories: keyStrings(value.NotificationCategories),
		NotificationWindows: mapContactWindows(value.NotificationWindows), EmailAllowed: value.EmailAllowed,
		Active: contract.CustomerPortalContactActive(true), Version: int64(value.Version),
	}
	if value.Phone != "" {
		result.Phone = &value.Phone
	}
	return result, nil
}

func mapCustomerContactGroup(value contactkernel.RecipientGroup) (contract.CustomerContactGroup, error) {
	version := value.Current()
	if version.Version() == 0 || version.Version() > math.MaxInt64 {
		return contract.CustomerContactGroup{}, errors.New("invalid group version")
	}
	mode := contract.CustomerContactGroupMode(version.Mode().String())
	if !mode.Valid() {
		return contract.CustomerContactGroup{}, errors.New("invalid group mode")
	}
	result := contract.CustomerContactGroup{
		Id: openapi_types.UUID(uuid.UUID(value.ID().Bytes())), TenantId: openapi_types.UUID(uuid.UUID(value.TenantID().Bytes())),
		Key: value.Key().String(), Version: int64(version.Version()), Name: version.Name(), Description: version.Description(),
		Mode: mode, MemberIds: contactContractIDs(version.Members()), CreatedAt: value.CreatedAt(), UpdatedAt: value.UpdatedAt(),
	}
	result.ArchivedAt = value.ArchivedAt()
	if version.Mode() == contactkernel.GroupDynamic {
		rule, err := mapContactRule(version.Rule())
		if err != nil {
			return contract.CustomerContactGroup{}, err
		}
		result.Rule = &rule
		schema := contract.CustomerContactGroupRuleSchemaVersionN1
		result.RuleSchemaVersion = &schema
	}
	return result, nil
}

func mapContactRule(value contactkernel.RuleNode) (contract.ContactRecipientRuleNode, error) {
	kind := contract.ContactRecipientRuleNodeKind(value.Kind().String())
	if !kind.Valid() {
		return contract.ContactRecipientRuleNode{}, errors.New("invalid rule kind")
	}
	result := contract.ContactRecipientRuleNode{Kind: kind}
	children := value.Children()
	if len(children) > 0 {
		mapped := make([]contract.ContactRecipientRuleNode, len(children))
		for index, child := range children {
			var err error
			mapped[index], err = mapContactRule(child)
			if err != nil {
				return contract.ContactRecipientRuleNode{}, err
			}
		}
		result.Children = &mapped
	}
	if value.Kind() == contactkernel.RulePredicate {
		field := contract.ContactRecipientRuleNodeField(value.Field().String())
		operator := contract.ContactRecipientRuleNodeOperator(value.Operator().String())
		if !field.Valid() || !operator.Valid() {
			return contract.ContactRecipientRuleNode{}, errors.New("invalid rule predicate")
		}
		values := value.Values()
		result.Field, result.Operator, result.Values = &field, &operator, &values
	}
	return result, nil
}

func mapContactWindows(values []contactkernel.NotificationWindow) []contract.ContactNotificationWindow {
	result := make([]contract.ContactNotificationWindow, len(values))
	for index, value := range values {
		result[index] = contract.ContactNotificationWindow{
			IsoWeekday: int(value.Weekday()), StartMinute: value.StartMinute(), EndMinute: value.EndMinute(),
		}
	}
	return result
}

func keyStrings(values []contactkernel.Key) []contract.ContactStableKey {
	result := make([]contract.ContactStableKey, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

func contactContractIDs(values []contactkernel.EntityID) []openapi_types.UUID {
	result := make([]openapi_types.UUID, len(values))
	for index, value := range values {
		result[index] = openapi_types.UUID(uuid.UUID(value.Bytes()))
	}
	return result
}

func contractUUIDs(values []openapi_types.UUID) []uuid.UUID {
	result := make([]uuid.UUID, len(values))
	for index, value := range values {
		result[index] = uuid.UUID(value)
	}
	slices.SortFunc(result, func(left, right uuid.UUID) int { return slices.Compare(left[:], right[:]) })
	return result
}

func contactEntityID(value uuid.UUID) (contactkernel.EntityID, error) {
	return contactkernel.NewEntityID([16]byte(value))
}

func schemaVersion[T ~int](value *T) int {
	if value == nil {
		return 0
	}
	return int(*value)
}
