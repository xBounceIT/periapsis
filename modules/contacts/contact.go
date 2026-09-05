package contacts

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// ISOWeekday follows ISO-8601: Monday is 1 and Sunday is 7.
type ISOWeekday uint8

const (
	Monday ISOWeekday = iota + 1
	Tuesday
	Wednesday
	Thursday
	Friday
	Saturday
	Sunday
)

func validISOWeekday(value ISOWeekday) bool { return value >= Monday && value <= Sunday }

type NotificationWindow struct {
	weekday     ISOWeekday
	startMinute uint16
	endMinute   uint16
}

func NewNotificationWindow(weekday ISOWeekday, startMinute, endMinute int) (NotificationWindow, error) {
	if !validISOWeekday(weekday) || startMinute < 0 || startMinute >= 1_440 ||
		endMinute <= 0 || endMinute > 1_440 || startMinute >= endMinute {
		return NotificationWindow{}, ErrInvalidContact
	}
	return NotificationWindow{weekday: weekday, startMinute: uint16(startMinute), endMinute: uint16(endMinute)}, nil
}

func (window NotificationWindow) Weekday() ISOWeekday { return window.weekday }
func (window NotificationWindow) StartMinute() int    { return int(window.startMinute) }
func (window NotificationWindow) EndMinute() int      { return int(window.endMinute) }

func validWindow(window NotificationWindow) bool {
	return validISOWeekday(window.weekday) && window.startMinute < 1_440 &&
		window.endMinute > 0 && window.endMinute <= 1_440 && window.startMinute < window.endMinute
}

func canonicalWindows(values []NotificationWindow) ([]NotificationWindow, bool) {
	if len(values) > maximumWindows {
		return nil, false
	}
	result := slices.Clone(values)
	for _, value := range result {
		if !validWindow(value) {
			return nil, false
		}
	}
	slices.SortFunc(result, func(left, right NotificationWindow) int {
		if left.weekday != right.weekday {
			return int(left.weekday) - int(right.weekday)
		}
		if left.startMinute != right.startMinute {
			return int(left.startMinute) - int(right.startMinute)
		}
		return int(left.endMinute) - int(right.endMinute)
	})
	for index := 1; index < len(result); index++ {
		previous, current := result[index-1], result[index]
		if current.weekday == previous.weekday && current.startMinute < previous.endMinute {
			return nil, false
		}
	}
	return result, true
}

type LinkedAccount struct {
	membershipID EntityID
	userID       EntityID
}

func NewLinkedAccount(membershipID, userID EntityID) (LinkedAccount, error) {
	if !validEntityID(membershipID) || !validEntityID(userID) {
		return LinkedAccount{}, ErrInvalidContact
	}
	return LinkedAccount{membershipID: membershipID, userID: userID}, nil
}

func (account LinkedAccount) MembershipID() EntityID { return account.membershipID }
func (account LinkedAccount) UserID() EntityID       { return account.userID }

func validLinkedAccount(account LinkedAccount) bool {
	return validEntityID(account.membershipID) && validEntityID(account.userID)
}

// ContactFields contains the mutable, validated contact profile. Email and
// phone remain available only through explicit getters; Contact.String omits
// them to keep structured logs safe by default.
type ContactFields struct {
	FirstName              string
	LastName               string
	Email                  Email
	Phone                  string
	Function               string
	Language               string
	Timezone               string
	EscalationPriority     uint8
	Class                  Key
	NotificationCategories []Key
	NotificationWindows    []NotificationWindow
	EmailAllowed           bool
	Active                 bool
	Tags                   []Key
	LinkedAccount          *LinkedAccount
}

type Contact struct {
	id         EntityID
	tenantID   EntityID
	fields     ContactFields
	version    uint64
	createdAt  time.Time
	updatedAt  time.Time
	archivedAt *time.Time
}

func NewContact(id, tenantID EntityID, fields ContactFields, at time.Time) (Contact, error) {
	return RehydrateContact(id, tenantID, fields, 1, at, at, nil)
}

func RehydrateContact(
	id, tenantID EntityID,
	fields ContactFields,
	version uint64,
	createdAt, updatedAt time.Time,
	archivedAt *time.Time,
) (Contact, error) {
	canonical, ok := canonicalContactFields(fields)
	if !ok || !validEntityID(id) || !validEntityID(tenantID) || version == 0 ||
		!validInstant(createdAt) || !validInstant(updatedAt) || updatedAt.Before(createdAt) ||
		archivedAt != nil && (!validInstant(*archivedAt) || archivedAt.Before(createdAt) || canonical.Active) {
		return Contact{}, ErrInvalidContact
	}
	return Contact{
		id: id, tenantID: tenantID, fields: canonical, version: version,
		createdAt: createdAt, updatedAt: updatedAt, archivedAt: cloneInstant(archivedAt),
	}, nil
}

func ReplaceContact(current Contact, fields ContactFields, expectedVersion uint64, at time.Time) (Contact, error) {
	if !validContact(current) || expectedVersion != current.version {
		return Contact{}, ErrVersionConflict
	}
	if current.archivedAt != nil || !validInstant(at) || at.Before(current.updatedAt) {
		return Contact{}, ErrInvalidContact
	}
	return RehydrateContact(current.id, current.tenantID, fields, current.version+1, current.createdAt, at, nil)
}

func UpdateNotificationPreferences(
	current Contact,
	categories []Key,
	windows []NotificationWindow,
	emailAllowed bool,
	expectedVersion uint64,
	at time.Time,
) (Contact, error) {
	if !validContact(current) || expectedVersion != current.version {
		return Contact{}, ErrVersionConflict
	}
	fields := current.Fields()
	fields.NotificationCategories = slices.Clone(categories)
	fields.NotificationWindows = slices.Clone(windows)
	fields.EmailAllowed = emailAllowed
	return ReplaceContact(current, fields, expectedVersion, at)
}

func ArchiveContact(current Contact, expectedVersion uint64, at time.Time) (Contact, error) {
	if !validContact(current) || expectedVersion != current.version {
		return Contact{}, ErrVersionConflict
	}
	if current.archivedAt != nil || !validInstant(at) || at.Before(current.updatedAt) {
		return Contact{}, ErrInvalidContact
	}
	fields := current.Fields()
	fields.Active = false
	archivedAt := at
	return RehydrateContact(current.id, current.tenantID, fields, current.version+1, current.createdAt, at, &archivedAt)
}

func canonicalContactFields(input ContactFields) (ContactFields, bool) {
	categories, categoriesOK := canonicalKeys(input.NotificationCategories, maximumCategories)
	tags, tagsOK := canonicalKeys(input.Tags, maximumTags)
	windows, windowsOK := canonicalWindows(input.NotificationWindows)
	if !categoriesOK || !tagsOK || !windowsOK ||
		!validText(input.FirstName, maximumNameBytes, false) ||
		!validText(input.LastName, maximumNameBytes, false) ||
		!validEmail(input.Email) ||
		!validText(input.Phone, maximumPhoneBytes, true) || strings.ContainsAny(input.Phone, "<>") ||
		!validText(input.Function, maximumFunctionBytes, false) ||
		!validLanguage(input.Language) || !validTimezone(input.Timezone) ||
		input.EscalationPriority > 100 || !validKey(input.Class.value) {
		return ContactFields{}, false
	}
	result := input
	result.NotificationCategories = categories
	result.NotificationWindows = windows
	result.Tags = tags
	if input.LinkedAccount != nil {
		if !validLinkedAccount(*input.LinkedAccount) {
			return ContactFields{}, false
		}
		copy := *input.LinkedAccount
		result.LinkedAccount = &copy
	}
	return result, true
}

func validContact(value Contact) bool {
	fields, fieldsOK := canonicalContactFields(value.fields)
	return fieldsOK && sameContactFields(fields, value.fields) && validEntityID(value.id) &&
		validEntityID(value.tenantID) && value.version > 0 && validInstant(value.createdAt) &&
		validInstant(value.updatedAt) && !value.updatedAt.Before(value.createdAt) &&
		(value.archivedAt == nil || validInstant(*value.archivedAt) &&
			!value.archivedAt.Before(value.createdAt) && !value.fields.Active)
}

func sameContactFields(left, right ContactFields) bool {
	return left.FirstName == right.FirstName && left.LastName == right.LastName &&
		left.Email == right.Email && left.Phone == right.Phone && left.Function == right.Function &&
		left.Language == right.Language && left.Timezone == right.Timezone &&
		left.EscalationPriority == right.EscalationPriority && left.Class == right.Class &&
		slices.Equal(left.NotificationCategories, right.NotificationCategories) &&
		slices.Equal(left.NotificationWindows, right.NotificationWindows) &&
		left.EmailAllowed == right.EmailAllowed && left.Active == right.Active &&
		slices.Equal(left.Tags, right.Tags) && sameLinkedAccounts(left.LinkedAccount, right.LinkedAccount)
}

func sameLinkedAccounts(left, right *LinkedAccount) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func cloneInstant(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func (contact Contact) ID() EntityID           { return contact.id }
func (contact Contact) TenantID() EntityID     { return contact.tenantID }
func (contact Contact) Version() uint64        { return contact.version }
func (contact Contact) CreatedAt() time.Time   { return contact.createdAt }
func (contact Contact) UpdatedAt() time.Time   { return contact.updatedAt }
func (contact Contact) ArchivedAt() *time.Time { return cloneInstant(contact.archivedAt) }
func (contact Contact) Active() bool           { return contact.fields.Active && contact.archivedAt == nil }

func (contact Contact) Fields() ContactFields {
	result := contact.fields
	result.NotificationCategories = slices.Clone(contact.fields.NotificationCategories)
	result.NotificationWindows = slices.Clone(contact.fields.NotificationWindows)
	result.Tags = slices.Clone(contact.fields.Tags)
	if contact.fields.LinkedAccount != nil {
		copy := *contact.fields.LinkedAccount
		result.LinkedAccount = &copy
	}
	return result
}

func (contact Contact) DisplayName() string {
	return contact.fields.FirstName + " " + contact.fields.LastName
}

func (contact Contact) String() string {
	return fmt.Sprintf("contact(id=%s,tenant=%s,version=%d,active=%t)",
		contact.id, contact.tenantID, contact.version, contact.Active())
}

// CustomerSafeContact structurally excludes routing class, escalation
// priority, internal tags, and linked identity identifiers.
type CustomerSafeContact struct {
	ID                     EntityID
	FirstName              string
	LastName               string
	Email                  Email
	Phone                  string
	Function               string
	Language               string
	Timezone               string
	NotificationCategories []Key
	NotificationWindows    []NotificationWindow
	EmailAllowed           bool
	Active                 bool
	Version                uint64
}

func ProjectCustomerSafe(contact Contact) (CustomerSafeContact, error) {
	if !validContact(contact) || contact.archivedAt != nil {
		return CustomerSafeContact{}, ErrResolutionDenied
	}
	return CustomerSafeContact{
		ID: contact.id, FirstName: contact.fields.FirstName, LastName: contact.fields.LastName,
		Email: contact.fields.Email, Phone: contact.fields.Phone, Function: contact.fields.Function,
		Language: contact.fields.Language, Timezone: contact.fields.Timezone,
		NotificationCategories: slices.Clone(contact.fields.NotificationCategories),
		NotificationWindows:    slices.Clone(contact.fields.NotificationWindows),
		EmailAllowed:           contact.fields.EmailAllowed, Active: contact.fields.Active, Version: contact.version,
	}, nil
}

func (contact Contact) eligible(category Key, at time.Time) bool {
	if !validContact(contact) || !validKey(category.value) || !validInstant(at) ||
		!contact.Active() || !contact.fields.EmailAllowed ||
		!slices.Contains(contact.fields.NotificationCategories, category) {
		return false
	}
	if len(contact.fields.NotificationWindows) == 0 {
		return true
	}
	location, err := time.LoadLocation(contact.fields.Timezone)
	if err != nil {
		return false
	}
	local := at.In(location)
	weekday := isoWeekday(local.Weekday())
	minute := local.Hour()*60 + local.Minute()
	for _, window := range contact.fields.NotificationWindows {
		if window.weekday == weekday && minute >= int(window.startMinute) && minute < int(window.endMinute) {
			return true
		}
	}
	return false
}

func isoWeekday(value time.Weekday) ISOWeekday {
	if value == time.Sunday {
		return Sunday
	}
	return ISOWeekday(value)
}
