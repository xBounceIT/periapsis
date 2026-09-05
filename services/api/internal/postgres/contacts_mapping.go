package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/contacts"
)

const contactColumns = `
	contact.id, contact.tenant_id, contact.first_name, contact.last_name,
	contact.email, contact.phone, contact.function, contact.language,
	contact.timezone, contact.escalation_priority, contact.contact_class,
	contact.notification_categories, contact.email_allowed, contact.active,
	contact.tags, contact.linked_membership_id, contact.linked_user_id,
	contact.version, contact.created_at, contact.updated_at, contact.archived_at`

type contactScanner interface{ Scan(...any) error }

type contactRow struct {
	id                     uuid.UUID
	tenantID               uuid.UUID
	firstName              string
	lastName               string
	email                  string
	phone                  *string
	function               string
	language               string
	timezone               string
	escalationPriority     int
	class                  string
	notificationCategories []string
	emailAllowed           bool
	active                 bool
	tags                   []string
	linkedMembershipID     *uuid.UUID
	linkedUserID           *uuid.UUID
	version                int64
	createdAt              time.Time
	updatedAt              time.Time
	archivedAt             *time.Time
}

func scanContactRow(scanner contactScanner) (contactRow, error) {
	var row contactRow
	err := scanner.Scan(
		&row.id, &row.tenantID, &row.firstName, &row.lastName,
		&row.email, &row.phone, &row.function, &row.language,
		&row.timezone, &row.escalationPriority, &row.class,
		&row.notificationCategories, &row.emailAllowed, &row.active,
		&row.tags, &row.linkedMembershipID, &row.linkedUserID,
		&row.version, &row.createdAt, &row.updatedAt, &row.archivedAt,
	)
	return row, err
}

func scanContact(ctx context.Context, tx databaseTransaction, scanner contactScanner) (kernel.Contact, error) {
	row, err := scanContactRow(scanner)
	if err != nil {
		return kernel.Contact{}, err
	}
	return hydrateContact(ctx, tx, row)
}

func loadContact(ctx context.Context, tx databaseTransaction, tenantID, contactID uuid.UUID) (kernel.Contact, error) {
	return scanContact(ctx, tx, tx.QueryRow(ctx, `SELECT `+contactColumns+`
		FROM public.customer_contacts AS contact
		WHERE contact.tenant_id = $1 AND contact.id = $2`, tenantID, contactID))
}

func loadSelfContact(
	ctx context.Context,
	tx databaseTransaction,
	tenantID, membershipID, userID uuid.UUID,
) (kernel.Contact, error) {
	return scanContact(ctx, tx, tx.QueryRow(ctx, `SELECT `+contactColumns+`
		FROM public.customer_contacts AS contact
		WHERE contact.tenant_id = $1
		  AND contact.linked_membership_id = $2
		  AND contact.linked_user_id = $3
		  AND contact.active
		  AND contact.archived_at IS NULL`, tenantID, membershipID, userID))
}

func hydrateContact(ctx context.Context, tx databaseTransaction, row contactRow) (kernel.Contact, error) {
	windows, err := loadContactWindows(ctx, tx, row.tenantID, row.id)
	if err != nil {
		return kernel.Contact{}, err
	}
	return rehydrateContactRow(row, windows)
}

func rehydrateContactRow(row contactRow, windows []kernel.NotificationWindow) (kernel.Contact, error) {
	id, idErr := contactEntityID(row.id)
	tenant, tenantErr := contactEntityID(row.tenantID)
	email, emailErr := kernel.NewEmail(row.email)
	class, classErr := kernel.NewKey(row.class)
	categories, categoriesErr := contactKeys(row.notificationCategories)
	tags, tagsErr := contactKeys(row.tags)
	if idErr != nil || tenantErr != nil || emailErr != nil || classErr != nil || categoriesErr != nil || tagsErr != nil ||
		row.version < 1 || row.escalationPriority < 0 || row.escalationPriority > 100 ||
		(row.linkedMembershipID == nil) != (row.linkedUserID == nil) {
		return kernel.Contact{}, errors.New("database returned an invalid contact projection")
	}
	var linked *kernel.LinkedAccount
	if row.linkedMembershipID != nil {
		membership, membershipErr := contactEntityID(*row.linkedMembershipID)
		user, userErr := contactEntityID(*row.linkedUserID)
		if membershipErr != nil || userErr != nil {
			return kernel.Contact{}, errors.New("database returned an invalid linked contact identity")
		}
		value, linkErr := kernel.NewLinkedAccount(membership, user)
		if linkErr != nil {
			return kernel.Contact{}, linkErr
		}
		linked = &value
	}
	phone := ""
	if row.phone != nil {
		phone = *row.phone
	}
	createdAt, updatedAt, archivedAt := contactInstant(row.createdAt), contactInstant(row.updatedAt), optionalContactInstant(row.archivedAt)
	return kernel.RehydrateContact(id, tenant, kernel.ContactFields{
		FirstName: row.firstName, LastName: row.lastName, Email: email, Phone: phone,
		Function: row.function, Language: row.language, Timezone: row.timezone,
		EscalationPriority: uint8(row.escalationPriority), Class: class,
		NotificationCategories: categories, NotificationWindows: windows,
		EmailAllowed: row.emailAllowed, Active: row.active, Tags: tags, LinkedAccount: linked,
	}, uint64(row.version), createdAt, updatedAt, archivedAt)
}

func loadContactWindows(ctx context.Context, tx databaseTransaction, tenantID, contactID uuid.UUID) ([]kernel.NotificationWindow, error) {
	rows, err := tx.Query(ctx, `
		SELECT iso_weekday, start_minute, end_minute
		FROM public.customer_contact_notification_windows
		WHERE tenant_id = $1 AND contact_id = $2
		ORDER BY iso_weekday, start_minute, end_minute`, tenantID, contactID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]kernel.NotificationWindow, 0, 16)
	for rows.Next() {
		var weekday, startMinute, endMinute int
		if err := rows.Scan(&weekday, &startMinute, &endMinute); err != nil {
			return nil, err
		}
		window, err := kernel.NewNotificationWindow(kernel.ISOWeekday(weekday), startMinute, endMinute)
		if err != nil {
			return nil, errors.New("database returned an invalid notification window")
		}
		result = append(result, window)
	}
	return result, rows.Err()
}

func loadContactGroup(ctx context.Context, tx databaseTransaction, tenantID, groupID uuid.UUID) (kernel.RecipientGroup, error) {
	var row struct {
		id, tenantID      uuid.UUID
		key, name, desc   string
		version           int64
		mode              string
		ruleSchemaVersion int
		rule              []byte
		versionCreatedAt  time.Time
		createdAt         time.Time
		updatedAt         time.Time
		archivedAt        *time.Time
	}
	err := tx.QueryRow(ctx, `
		SELECT group_record.id, group_record.tenant_id, group_record.key,
		       version.version, version.name, version.description, version.mode,
		       version.rule_schema_version, version.rule, version.created_at,
		       group_record.created_at, group_record.updated_at, group_record.archived_at
		FROM public.customer_contact_groups AS group_record
		JOIN public.customer_contact_group_versions AS version
		  ON version.tenant_id = group_record.tenant_id
		 AND version.group_id = group_record.id
		 AND version.version = group_record.current_version
		WHERE group_record.tenant_id = $1 AND group_record.id = $2`, tenantID, groupID).Scan(
		&row.id, &row.tenantID, &row.key, &row.version, &row.name, &row.desc, &row.mode,
		&row.ruleSchemaVersion, &row.rule, &row.versionCreatedAt,
		&row.createdAt, &row.updatedAt, &row.archivedAt,
	)
	if err != nil {
		return kernel.RecipientGroup{}, err
	}
	id, idErr := contactEntityID(row.id)
	tenant, tenantErr := contactEntityID(row.tenantID)
	key, keyErr := kernel.NewKey(row.key)
	if idErr != nil || tenantErr != nil || keyErr != nil || row.version < 1 || row.ruleSchemaVersion != 1 {
		return kernel.RecipientGroup{}, errors.New("database returned invalid contact-group identity")
	}
	mode, modeErr := contactGroupMode(row.mode)
	if modeErr != nil {
		return kernel.RecipientGroup{}, modeErr
	}
	var rule kernel.RuleNode
	var members []kernel.EntityID
	if mode == kernel.GroupDynamic {
		rule, err = decodeContactRule(row.rule)
	} else if len(row.rule) != 0 && string(row.rule) != "null" {
		err = errors.New("manual contact group has a rule")
	} else {
		members, err = loadContactGroupMembers(ctx, tx, tenantID, groupID, row.version)
	}
	if err != nil {
		return kernel.RecipientGroup{}, err
	}
	version, err := kernel.NewGroupVersion(id, tenant, uint64(row.version), row.name, row.desc, mode, rule, members, contactInstant(row.versionCreatedAt))
	if err != nil {
		return kernel.RecipientGroup{}, err
	}
	return kernel.RehydrateRecipientGroup(id, tenant, key, version,
		contactInstant(row.createdAt), contactInstant(row.updatedAt), optionalContactInstant(row.archivedAt))
}

func loadContactGroupMembers(ctx context.Context, tx databaseTransaction, tenantID, groupID uuid.UUID, version int64) ([]kernel.EntityID, error) {
	rows, err := tx.Query(ctx, `
		SELECT contact_id
		FROM public.customer_contact_group_version_members
		WHERE tenant_id = $1 AND group_id = $2 AND group_version = $3
		ORDER BY contact_id`, tenantID, groupID, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]kernel.EntityID, 0, 64)
	for rows.Next() {
		var identifier uuid.UUID
		if err := rows.Scan(&identifier); err != nil {
			return nil, err
		}
		converted, err := contactEntityID(identifier)
		if err != nil {
			return nil, errors.New("database returned invalid contact-group member")
		}
		result = append(result, converted)
	}
	return result, rows.Err()
}

func loadContactLink(ctx context.Context, tx databaseTransaction, tenantID, linkID uuid.UUID) (kernel.TicketContactLink, error) {
	var row struct {
		id, tenantID, contactID uuid.UUID
		alertID, caseID         *uuid.UUID
		role, origin            string
		sourceAlertID           *uuid.UUID
		sourceAlertVersion      *int64
		version                 int64
		createdAt               time.Time
		archivedAt              *time.Time
	}
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, alert_id, case_id, contact_id, role, origin,
		       source_alert_id, source_alert_version, version, created_at, archived_at
		FROM public.ticket_customer_contacts
		WHERE tenant_id = $1 AND id = $2`, tenantID, linkID).Scan(
		&row.id, &row.tenantID, &row.alertID, &row.caseID, &row.contactID, &row.role, &row.origin,
		&row.sourceAlertID, &row.sourceAlertVersion, &row.version, &row.createdAt, &row.archivedAt,
	)
	if err != nil {
		return kernel.TicketContactLink{}, err
	}
	id, idErr := contactEntityID(row.id)
	tenant, tenantErr := contactEntityID(row.tenantID)
	contact, contactErr := contactEntityID(row.contactID)
	kind, ticketID, resourceErr := contactLinkResource(row.alertID, row.caseID)
	role, roleErr := contactRole(row.role)
	origin, originErr := contactLinkOrigin(row.origin)
	if idErr != nil || tenantErr != nil || contactErr != nil || resourceErr != nil || roleErr != nil || originErr != nil || row.version < 1 {
		return kernel.TicketContactLink{}, errors.New("database returned invalid ticket-contact link")
	}
	var provenance *kernel.EscalationProvenance
	if row.sourceAlertID != nil || row.sourceAlertVersion != nil {
		if row.sourceAlertID == nil || row.sourceAlertVersion == nil || *row.sourceAlertVersion < 1 {
			return kernel.TicketContactLink{}, errors.New("database returned partial contact-link provenance")
		}
		source, err := contactEntityID(*row.sourceAlertID)
		if err != nil {
			return kernel.TicketContactLink{}, err
		}
		value, err := kernel.NewEscalationProvenance(source, uint64(*row.sourceAlertVersion))
		if err != nil {
			return kernel.TicketContactLink{}, err
		}
		provenance = &value
	}
	return kernel.RehydrateTicketContactLink(id, tenant, kind, ticketID, contact, role, origin, provenance,
		uint64(row.version), contactInstant(row.createdAt), optionalContactInstant(row.archivedAt))
}

type storedContactRule struct {
	Kind     string              `json:"kind"`
	Children []storedContactRule `json:"children,omitempty"`
	Field    string              `json:"field,omitempty"`
	Operator string              `json:"operator,omitempty"`
	Values   []string            `json:"values,omitempty"`
}

func decodeContactRule(value []byte) (kernel.RuleNode, error) {
	if len(value) == 0 || len(value) > 32*1024 {
		return kernel.RuleNode{}, errors.New("contact rule is absent or oversized")
	}
	var stored storedContactRule
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil {
		return kernel.RuleNode{}, errors.New("contact rule is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return kernel.RuleNode{}, errors.New("contact rule has trailing data")
	}
	return buildContactRule(stored)
}

func buildContactRule(value storedContactRule) (kernel.RuleNode, error) {
	switch value.Kind {
	case "all", "any":
		if value.Field != "" || value.Operator != "" || len(value.Values) != 0 {
			return kernel.RuleNode{}, errors.New("composite contact rule has predicate fields")
		}
		children := make([]kernel.RuleNode, len(value.Children))
		for index, child := range value.Children {
			built, err := buildContactRule(child)
			if err != nil {
				return kernel.RuleNode{}, err
			}
			children[index] = built
		}
		if value.Kind == "all" {
			return kernel.NewAllRule(children...)
		}
		return kernel.NewAnyRule(children...)
	case "not":
		if len(value.Children) != 1 || value.Field != "" || value.Operator != "" || len(value.Values) != 0 {
			return kernel.RuleNode{}, errors.New("not contact rule has an invalid shape")
		}
		child, err := buildContactRule(value.Children[0])
		if err != nil {
			return kernel.RuleNode{}, err
		}
		return kernel.NewNotRule(child)
	case "predicate":
		if len(value.Children) != 0 {
			return kernel.RuleNode{}, errors.New("predicate contact rule has children")
		}
		field, fieldErr := contactPredicateField(value.Field)
		operator, operatorErr := contactPredicateOperator(value.Operator)
		if fieldErr != nil || operatorErr != nil {
			return kernel.RuleNode{}, errors.New("contact rule predicate is unknown")
		}
		return kernel.NewPredicate(field, operator, value.Values...)
	default:
		return kernel.RuleNode{}, errors.New("contact rule kind is unknown")
	}
}

func marshalContact(value kernel.Contact) ([]byte, error) {
	fields := value.Fields()
	payload := struct {
		FirstName              string                      `json:"firstName"`
		LastName               string                      `json:"lastName"`
		Email                  string                      `json:"email"`
		Phone                  *string                     `json:"phone"`
		Function               string                      `json:"function"`
		Language               string                      `json:"language"`
		Timezone               string                      `json:"timezone"`
		EscalationPriority     uint8                       `json:"escalationPriority"`
		ContactClass           string                      `json:"contactClass"`
		NotificationCategories []string                    `json:"notificationCategories"`
		NotificationWindows    []contactNotificationWindow `json:"notificationWindows"`
		EmailAllowed           bool                        `json:"emailAllowed"`
		Active                 bool                        `json:"active"`
		Tags                   []string                    `json:"tags"`
		LinkedMembershipID     *uuid.UUID                  `json:"linkedMembershipId"`
		LinkedUserID           *uuid.UUID                  `json:"linkedUserId"`
		Version                uint64                      `json:"version"`
		CreatedAt              time.Time                   `json:"createdAt"`
		UpdatedAt              time.Time                   `json:"updatedAt"`
		ArchivedAt             *time.Time                  `json:"archivedAt"`
	}{
		FirstName: fields.FirstName, LastName: fields.LastName, Email: fields.Email.String(),
		Function: fields.Function, Language: fields.Language, Timezone: fields.Timezone,
		EscalationPriority: fields.EscalationPriority, ContactClass: fields.Class.String(),
		NotificationCategories: contactKeyStrings(fields.NotificationCategories),
		NotificationWindows:    contactWindowPayload(fields.NotificationWindows), EmailAllowed: fields.EmailAllowed,
		Active: fields.Active, Tags: contactKeyStrings(fields.Tags), Version: value.Version(),
		CreatedAt: value.CreatedAt(), UpdatedAt: value.UpdatedAt(), ArchivedAt: value.ArchivedAt(),
	}
	if fields.Phone != "" {
		payload.Phone = &fields.Phone
	}
	if fields.LinkedAccount != nil {
		membership := uuid.UUID(fields.LinkedAccount.MembershipID().Bytes())
		user := uuid.UUID(fields.LinkedAccount.UserID().Bytes())
		payload.LinkedMembershipID, payload.LinkedUserID = &membership, &user
	}
	return marshalJSON(payload)
}

type contactNotificationWindow struct {
	ISOWeekday  int `json:"isoWeekday"`
	StartMinute int `json:"startMinute"`
	EndMinute   int `json:"endMinute"`
}

type contactGroupCreatedAt struct {
	Group   time.Time `json:"group"`
	Version time.Time `json:"version"`
}

func contactWindowPayload(values []kernel.NotificationWindow) []contactNotificationWindow {
	result := make([]contactNotificationWindow, len(values))
	for index, value := range values {
		result[index] = contactNotificationWindow{int(value.Weekday()), value.StartMinute(), value.EndMinute()}
	}
	return result
}

func marshalContactGroup(value kernel.RecipientGroup) ([]byte, error) {
	version := value.Current()
	var rule *storedContactRule
	if version.Mode() == kernel.GroupDynamic {
		mapped := storeContactRule(version.Rule())
		rule = &mapped
	}
	return marshalJSON(struct {
		Key               string                `json:"key"`
		Version           uint64                `json:"version"`
		Name              string                `json:"name"`
		Description       string                `json:"description"`
		Mode              string                `json:"mode"`
		RuleSchemaVersion int                   `json:"ruleSchemaVersion"`
		Rule              *storedContactRule    `json:"rule"`
		MemberIDs         []uuid.UUID           `json:"memberIds"`
		CreatedAt         contactGroupCreatedAt `json:"createdAt"`
		UpdatedAt         time.Time             `json:"updatedAt"`
		ArchivedAt        *time.Time            `json:"archivedAt"`
	}{
		Key: value.Key().String(), Version: version.Version(), Name: version.Name(), Description: version.Description(),
		Mode: version.Mode().String(), RuleSchemaVersion: 1, Rule: rule, MemberIDs: contactUUIDs(version.Members()),
		CreatedAt: contactGroupCreatedAt{Group: value.CreatedAt(), Version: version.CreatedAt()},
		UpdatedAt: value.UpdatedAt(), ArchivedAt: value.ArchivedAt(),
	})
}

func marshalContactLink(value kernel.TicketContactLink) ([]byte, error) {
	var sourceAlertID *uuid.UUID
	var sourceAlertVersion *uint64
	if provenance := value.Provenance(); provenance != nil {
		identifier := uuid.UUID(provenance.SourceAlertID().Bytes())
		version := provenance.SourceAlertVersion()
		sourceAlertID, sourceAlertVersion = &identifier, &version
	}
	return marshalJSON(struct {
		TicketKind         string     `json:"ticketKind"`
		TicketID           uuid.UUID  `json:"ticketId"`
		ContactID          uuid.UUID  `json:"contactId"`
		Role               string     `json:"role"`
		Origin             string     `json:"origin"`
		SourceAlertID      *uuid.UUID `json:"sourceAlertId"`
		SourceAlertVersion *uint64    `json:"sourceAlertVersion"`
		Version            uint64     `json:"version"`
		CreatedAt          time.Time  `json:"createdAt"`
		ArchivedAt         *time.Time `json:"archivedAt"`
	}{
		TicketKind: value.TicketKind().String(), TicketID: uuid.UUID(value.TicketID().Bytes()),
		ContactID: uuid.UUID(value.ContactID().Bytes()), Role: value.Role().String(), Origin: value.Origin().String(),
		SourceAlertID: sourceAlertID, SourceAlertVersion: sourceAlertVersion, Version: value.Version(),
		CreatedAt: value.CreatedAt(), ArchivedAt: value.ArchivedAt(),
	})
}

func decodeContactCommandSnapshot(value []byte, tenantID, contactID uuid.UUID) (kernel.Contact, error) {
	var stored struct {
		FirstName              string                      `json:"firstName"`
		LastName               string                      `json:"lastName"`
		Email                  string                      `json:"email"`
		Phone                  *string                     `json:"phone"`
		Function               string                      `json:"function"`
		Language               string                      `json:"language"`
		Timezone               string                      `json:"timezone"`
		EscalationPriority     int                         `json:"escalationPriority"`
		ContactClass           string                      `json:"contactClass"`
		NotificationCategories []string                    `json:"notificationCategories"`
		NotificationWindows    []contactNotificationWindow `json:"notificationWindows"`
		EmailAllowed           bool                        `json:"emailAllowed"`
		Active                 bool                        `json:"active"`
		Tags                   []string                    `json:"tags"`
		LinkedMembershipID     *uuid.UUID                  `json:"linkedMembershipId"`
		LinkedUserID           *uuid.UUID                  `json:"linkedUserId"`
		Version                int64                       `json:"version"`
		CreatedAt              time.Time                   `json:"createdAt"`
		UpdatedAt              time.Time                   `json:"updatedAt"`
		ArchivedAt             *time.Time                  `json:"archivedAt"`
	}
	if err := decodeContactSnapshotJSON(value, &stored); err != nil {
		return kernel.Contact{}, err
	}
	windows, err := decodeContactSnapshotWindows(stored.NotificationWindows)
	if err != nil {
		return kernel.Contact{}, err
	}
	row := contactRow{
		id: contactID, tenantID: tenantID, firstName: stored.FirstName, lastName: stored.LastName,
		email: stored.Email, phone: stored.Phone, function: stored.Function, language: stored.Language,
		timezone: stored.Timezone, escalationPriority: stored.EscalationPriority, class: stored.ContactClass,
		notificationCategories: stored.NotificationCategories, emailAllowed: stored.EmailAllowed,
		active: stored.Active, tags: stored.Tags, linkedMembershipID: stored.LinkedMembershipID,
		linkedUserID: stored.LinkedUserID, version: stored.Version, createdAt: stored.CreatedAt,
		updatedAt: stored.UpdatedAt, archivedAt: stored.ArchivedAt,
	}
	return rehydrateContactRow(row, windows)
}

func decodeCustomerContactCommandSnapshot(value []byte, contactID uuid.UUID) (kernel.CustomerSafeContact, error) {
	var stored struct {
		ID                     uuid.UUID                   `json:"id"`
		FirstName              string                      `json:"firstName"`
		LastName               string                      `json:"lastName"`
		Email                  string                      `json:"email"`
		Phone                  *string                     `json:"phone"`
		Function               string                      `json:"function"`
		Language               string                      `json:"language"`
		Timezone               string                      `json:"timezone"`
		NotificationCategories []string                    `json:"notificationCategories"`
		NotificationWindows    []contactNotificationWindow `json:"notificationWindows"`
		EmailAllowed           bool                        `json:"emailAllowed"`
		Active                 bool                        `json:"active"`
		Version                uint64                      `json:"version"`
	}
	if err := decodeContactSnapshotJSON(value, &stored); err != nil || stored.ID != contactID || stored.Version == 0 {
		return kernel.CustomerSafeContact{}, errors.New("database returned an invalid customer contact replay snapshot")
	}
	id, idErr := contactEntityID(stored.ID)
	email, emailErr := kernel.NewEmail(stored.Email)
	categories, categoriesErr := contactKeys(stored.NotificationCategories)
	windows, windowsErr := decodeContactSnapshotWindows(stored.NotificationWindows)
	if idErr != nil || emailErr != nil || categoriesErr != nil || windowsErr != nil {
		return kernel.CustomerSafeContact{}, errors.New("database returned an invalid customer contact replay snapshot")
	}
	phone := ""
	if stored.Phone != nil {
		phone = *stored.Phone
	}
	return kernel.CustomerSafeContact{
		ID: id, FirstName: stored.FirstName, LastName: stored.LastName, Email: email,
		Phone: phone, Function: stored.Function, Language: stored.Language, Timezone: stored.Timezone,
		NotificationCategories: categories, NotificationWindows: windows,
		EmailAllowed: stored.EmailAllowed, Active: stored.Active, Version: stored.Version,
	}, nil
}

func decodeContactGroupCommandSnapshot(value []byte, tenantID, groupID uuid.UUID) (kernel.RecipientGroup, error) {
	var stored struct {
		Key               string                `json:"key"`
		Version           uint64                `json:"version"`
		Name              string                `json:"name"`
		Description       string                `json:"description"`
		Mode              string                `json:"mode"`
		RuleSchemaVersion int                   `json:"ruleSchemaVersion"`
		Rule              *storedContactRule    `json:"rule"`
		MemberIDs         []uuid.UUID           `json:"memberIds"`
		CreatedAt         contactGroupCreatedAt `json:"createdAt"`
		UpdatedAt         time.Time             `json:"updatedAt"`
		ArchivedAt        *time.Time            `json:"archivedAt"`
	}
	if err := decodeContactSnapshotJSON(value, &stored); err != nil || stored.Version == 0 || stored.RuleSchemaVersion != 1 {
		return kernel.RecipientGroup{}, errors.New("database returned an invalid contact-group replay snapshot")
	}
	id, idErr := contactEntityID(groupID)
	tenant, tenantErr := contactEntityID(tenantID)
	key, keyErr := kernel.NewKey(stored.Key)
	mode, modeErr := contactGroupMode(stored.Mode)
	if idErr != nil || tenantErr != nil || keyErr != nil || modeErr != nil {
		return kernel.RecipientGroup{}, errors.New("database returned an invalid contact-group replay identity")
	}
	var rule kernel.RuleNode
	var members []kernel.EntityID
	var err error
	if mode == kernel.GroupDynamic {
		if stored.Rule == nil {
			return kernel.RecipientGroup{}, errors.New("dynamic contact-group replay omitted its rule")
		}
		rule, err = buildContactRule(*stored.Rule)
	} else {
		if stored.Rule != nil {
			return kernel.RecipientGroup{}, errors.New("manual contact-group replay included a rule")
		}
		members = make([]kernel.EntityID, len(stored.MemberIDs))
		for index, memberID := range stored.MemberIDs {
			members[index], err = contactEntityID(memberID)
			if err != nil {
				break
			}
		}
	}
	if err != nil {
		return kernel.RecipientGroup{}, err
	}
	version, err := kernel.NewGroupVersion(id, tenant, stored.Version, stored.Name, stored.Description,
		mode, rule, members, contactInstant(stored.CreatedAt.Version))
	if err != nil {
		return kernel.RecipientGroup{}, err
	}
	return kernel.RehydrateRecipientGroup(id, tenant, key, version, contactInstant(stored.CreatedAt.Group),
		contactInstant(stored.UpdatedAt), optionalContactInstant(stored.ArchivedAt))
}

func decodeContactLinkCommandSnapshot(value []byte, tenantID, linkID uuid.UUID) (kernel.TicketContactLink, error) {
	var stored struct {
		TicketKind         string     `json:"ticketKind"`
		TicketID           uuid.UUID  `json:"ticketId"`
		ContactID          uuid.UUID  `json:"contactId"`
		Role               string     `json:"role"`
		Origin             string     `json:"origin"`
		SourceAlertID      *uuid.UUID `json:"sourceAlertId"`
		SourceAlertVersion *uint64    `json:"sourceAlertVersion"`
		Version            uint64     `json:"version"`
		CreatedAt          time.Time  `json:"createdAt"`
		ArchivedAt         *time.Time `json:"archivedAt"`
	}
	if err := decodeContactSnapshotJSON(value, &stored); err != nil || stored.Version == 0 {
		return kernel.TicketContactLink{}, errors.New("database returned an invalid ticket-contact replay snapshot")
	}
	id, idErr := contactEntityID(linkID)
	tenant, tenantErr := contactEntityID(tenantID)
	ticket, ticketErr := contactEntityID(stored.TicketID)
	contact, contactErr := contactEntityID(stored.ContactID)
	role, roleErr := contactRole(stored.Role)
	origin, originErr := contactLinkOrigin(stored.Origin)
	kind := kernel.TicketAlert
	if stored.TicketKind == "case" {
		kind = kernel.TicketCase
	} else if stored.TicketKind != "alert" {
		return kernel.TicketContactLink{}, errors.New("database returned an invalid ticket-contact replay kind")
	}
	if idErr != nil || tenantErr != nil || ticketErr != nil || contactErr != nil || roleErr != nil || originErr != nil ||
		(stored.SourceAlertID == nil) != (stored.SourceAlertVersion == nil) {
		return kernel.TicketContactLink{}, errors.New("database returned an invalid ticket-contact replay identity")
	}
	var provenance *kernel.EscalationProvenance
	if stored.SourceAlertID != nil {
		source, err := contactEntityID(*stored.SourceAlertID)
		if err != nil {
			return kernel.TicketContactLink{}, err
		}
		value, err := kernel.NewEscalationProvenance(source, *stored.SourceAlertVersion)
		if err != nil {
			return kernel.TicketContactLink{}, err
		}
		provenance = &value
	}
	return kernel.RehydrateTicketContactLink(id, tenant, kind, ticket, contact, role, origin, provenance,
		stored.Version, contactInstant(stored.CreatedAt), optionalContactInstant(stored.ArchivedAt))
}

func decodeContactSnapshotWindows(values []contactNotificationWindow) ([]kernel.NotificationWindow, error) {
	result := make([]kernel.NotificationWindow, len(values))
	for index, value := range values {
		window, err := kernel.NewNotificationWindow(kernel.ISOWeekday(value.ISOWeekday), value.StartMinute, value.EndMinute)
		if err != nil {
			return nil, errors.New("database returned an invalid contact replay notification window")
		}
		result[index] = window
	}
	return result, nil
}

func decodeContactSnapshotJSON(value []byte, target any) error {
	if len(value) == 0 || len(value) > 512*1024 {
		return errors.New("database returned an absent or oversized contact replay snapshot")
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("database returned an invalid contact replay snapshot")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("database returned a contact replay snapshot with trailing data")
	}
	return nil
}

func storeContactRule(value kernel.RuleNode) storedContactRule {
	result := storedContactRule{Kind: value.Kind().String(), Field: value.Field().String(), Operator: value.Operator().String(), Values: value.Values()}
	if value.Kind() != kernel.RulePredicate {
		result.Field, result.Operator, result.Values = "", "", nil
	}
	children := value.Children()
	if len(children) != 0 {
		result.Children = make([]storedContactRule, len(children))
		for index, child := range children {
			result.Children[index] = storeContactRule(child)
		}
	}
	return result
}

func contactKeys(values []string) ([]kernel.Key, error) {
	result := make([]kernel.Key, len(values))
	for index, value := range values {
		key, err := kernel.NewKey(value)
		if err != nil {
			return nil, err
		}
		result[index] = key
	}
	return result, nil
}

func contactKeyStrings(values []kernel.Key) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

func contactUUIDs(values []kernel.EntityID) []uuid.UUID {
	result := make([]uuid.UUID, len(values))
	for index, value := range values {
		result[index] = uuid.UUID(value.Bytes())
	}
	return result
}

func contactEntityID(value uuid.UUID) (kernel.EntityID, error) {
	return kernel.NewEntityID([16]byte(value))
}

func contactGroupMode(value string) (kernel.GroupMode, error) {
	switch value {
	case "manual":
		return kernel.GroupManual, nil
	case "dynamic":
		return kernel.GroupDynamic, nil
	default:
		return 0, fmt.Errorf("unknown contact-group mode %q", value)
	}
}

func contactRole(value string) (kernel.ContactRole, error) {
	switch value {
	case "primary":
		return kernel.RolePrimary, nil
	case "escalation":
		return kernel.RoleEscalation, nil
	case "watcher":
		return kernel.RoleWatcher, nil
	default:
		return 0, fmt.Errorf("unknown contact role %q", value)
	}
}

func contactLinkOrigin(value string) (kernel.LinkOrigin, error) {
	switch value {
	case "manual":
		return kernel.OriginManual, nil
	case "escalation_copy":
		return kernel.OriginEscalationCopy, nil
	default:
		return 0, fmt.Errorf("unknown contact-link origin %q", value)
	}
}

func contactLinkResource(alertID, caseID *uuid.UUID) (kernel.TicketKind, kernel.EntityID, error) {
	if (alertID == nil) == (caseID == nil) {
		return 0, kernel.EntityID{}, errors.New("ticket-contact link has an invalid resource shape")
	}
	if alertID != nil {
		id, err := contactEntityID(*alertID)
		return kernel.TicketAlert, id, err
	}
	id, err := contactEntityID(*caseID)
	return kernel.TicketCase, id, err
}

func contactPredicateField(value string) (kernel.PredicateField, error) {
	for _, field := range []kernel.PredicateField{
		kernel.FieldActive, kernel.FieldEmailAllowed, kernel.FieldContactClass, kernel.FieldTag,
		kernel.FieldNotificationCategory, kernel.FieldLanguage, kernel.FieldTimezone,
		kernel.FieldEscalationPriority, kernel.FieldLinkedAccount,
	} {
		if field.String() == value {
			return field, nil
		}
	}
	return 0, errors.New("unknown contact predicate field")
}

func contactPredicateOperator(value string) (kernel.PredicateOperator, error) {
	for _, operator := range []kernel.PredicateOperator{
		kernel.OperatorEquals, kernel.OperatorNotEquals, kernel.OperatorOneOf, kernel.OperatorNoneOf,
		kernel.OperatorContains, kernel.OperatorNotContains, kernel.OperatorGreaterThanOrEqual,
		kernel.OperatorLessThanOrEqual, kernel.OperatorExists, kernel.OperatorNotExists,
	} {
		if operator.String() == value {
			return operator, nil
		}
	}
	return 0, errors.New("unknown contact predicate operator")
}

func contactInstant(value time.Time) time.Time { return value.UTC().Truncate(time.Microsecond) }

func optionalContactInstant(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	converted := contactInstant(*value)
	return &converted
}
