package contacts

import (
	"fmt"
	"slices"
	"time"
)

type GroupMode uint8

const (
	GroupManual GroupMode = iota + 1
	GroupDynamic
)

func (mode GroupMode) String() string {
	switch mode {
	case GroupManual:
		return "manual"
	case GroupDynamic:
		return "dynamic"
	default:
		return "unknown"
	}
}

type GroupVersion struct {
	groupID     EntityID
	tenantID    EntityID
	version     uint64
	name        string
	description string
	mode        GroupMode
	rule        RuleNode
	members     []EntityID
	createdAt   time.Time
}

func NewGroupVersion(
	groupID, tenantID EntityID,
	version uint64,
	name, description string,
	mode GroupMode,
	rule RuleNode,
	members []EntityID,
	createdAt time.Time,
) (GroupVersion, error) {
	canonicalMembers, membersOK := canonicalIDs(members, maximumGroupMembers)
	validShape := mode == GroupManual && rule.kind == 0 || mode == GroupDynamic && len(canonicalMembers) == 0 && validRule(rule)
	if !validEntityID(groupID) || !validEntityID(tenantID) || version == 0 ||
		!validText(name, maximumNameBytes, false) || !validText(description, maximumDescriptionBytes, true) ||
		!validInstant(createdAt) || !membersOK || !validShape {
		return GroupVersion{}, ErrInvalidGroup
	}
	return GroupVersion{
		groupID: groupID, tenantID: tenantID, version: version, name: name, description: description,
		mode: mode, rule: rule, members: canonicalMembers, createdAt: createdAt,
	}, nil
}

func (version GroupVersion) GroupID() EntityID    { return version.groupID }
func (version GroupVersion) TenantID() EntityID   { return version.tenantID }
func (version GroupVersion) Version() uint64      { return version.version }
func (version GroupVersion) Name() string         { return version.name }
func (version GroupVersion) Description() string  { return version.description }
func (version GroupVersion) Mode() GroupMode      { return version.mode }
func (version GroupVersion) Rule() RuleNode       { return cloneRule(version.rule) }
func (version GroupVersion) Members() []EntityID  { return slices.Clone(version.members) }
func (version GroupVersion) CreatedAt() time.Time { return version.createdAt }

func cloneRule(value RuleNode) RuleNode {
	result := value
	result.values = slices.Clone(value.values)
	result.children = make([]RuleNode, len(value.children))
	for index, child := range value.children {
		result.children[index] = cloneRule(child)
	}
	return result
}

func validGroupVersion(value GroupVersion) bool {
	canonical, err := NewGroupVersion(
		value.groupID, value.tenantID, value.version, value.name, value.description,
		value.mode, value.rule, value.members, value.createdAt,
	)
	return err == nil && sameGroupVersion(canonical, value)
}

func sameGroupVersion(left, right GroupVersion) bool {
	return left.groupID == right.groupID && left.tenantID == right.tenantID && left.version == right.version &&
		left.name == right.name && left.description == right.description && left.mode == right.mode &&
		sameRule(left.rule, right.rule) && slices.Equal(left.members, right.members) && left.createdAt.Equal(right.createdAt)
}

type RecipientGroup struct {
	id         EntityID
	tenantID   EntityID
	key        Key
	current    GroupVersion
	createdAt  time.Time
	updatedAt  time.Time
	archivedAt *time.Time
}

func NewRecipientGroup(id, tenantID EntityID, key Key, current GroupVersion, at time.Time) (RecipientGroup, error) {
	return RehydrateRecipientGroup(id, tenantID, key, current, at, at, nil)
}

func RehydrateRecipientGroup(
	id, tenantID EntityID,
	key Key,
	current GroupVersion,
	createdAt, updatedAt time.Time,
	archivedAt *time.Time,
) (RecipientGroup, error) {
	if !validEntityID(id) || !validEntityID(tenantID) || !validKey(key.value) || !validGroupVersion(current) ||
		current.groupID != id || current.tenantID != tenantID || !validInstant(createdAt) ||
		!validInstant(updatedAt) || updatedAt.Before(createdAt) || archivedAt != nil &&
		(!validInstant(*archivedAt) || archivedAt.Before(createdAt)) {
		return RecipientGroup{}, ErrInvalidGroup
	}
	return RecipientGroup{
		id: id, tenantID: tenantID, key: key, current: current,
		createdAt: createdAt, updatedAt: updatedAt, archivedAt: cloneInstant(archivedAt),
	}, nil
}

func VersionRecipientGroup(
	current RecipientGroup,
	name, description string,
	mode GroupMode,
	rule RuleNode,
	members []EntityID,
	expectedVersion uint64,
	at time.Time,
) (RecipientGroup, error) {
	if !validRecipientGroup(current) || expectedVersion != current.current.version {
		return RecipientGroup{}, ErrVersionConflict
	}
	if current.archivedAt != nil || !validInstant(at) || at.Before(current.updatedAt) {
		return RecipientGroup{}, ErrInvalidGroup
	}
	next, err := NewGroupVersion(current.id, current.tenantID, current.current.version+1,
		name, description, mode, rule, members, at)
	if err != nil {
		return RecipientGroup{}, err
	}
	return RehydrateRecipientGroup(current.id, current.tenantID, current.key, next, current.createdAt, at, nil)
}

func ArchiveRecipientGroup(current RecipientGroup, expectedVersion uint64, at time.Time) (RecipientGroup, error) {
	if !validRecipientGroup(current) || expectedVersion != current.current.version {
		return RecipientGroup{}, ErrVersionConflict
	}
	if current.archivedAt != nil || !validInstant(at) || at.Before(current.updatedAt) {
		return RecipientGroup{}, ErrInvalidGroup
	}
	archivedAt := at
	return RehydrateRecipientGroup(current.id, current.tenantID, current.key, current.current,
		current.createdAt, at, &archivedAt)
}

func validRecipientGroup(value RecipientGroup) bool {
	canonical, err := RehydrateRecipientGroup(value.id, value.tenantID, value.key, value.current,
		value.createdAt, value.updatedAt, value.archivedAt)
	return err == nil && canonical.id == value.id && canonical.tenantID == value.tenantID &&
		canonical.key == value.key && sameGroupVersion(canonical.current, value.current)
}

func (group RecipientGroup) ID() EntityID           { return group.id }
func (group RecipientGroup) TenantID() EntityID     { return group.tenantID }
func (group RecipientGroup) Key() Key               { return group.key }
func (group RecipientGroup) Current() GroupVersion  { return cloneGroupVersion(group.current) }
func (group RecipientGroup) CreatedAt() time.Time   { return group.createdAt }
func (group RecipientGroup) UpdatedAt() time.Time   { return group.updatedAt }
func (group RecipientGroup) ArchivedAt() *time.Time { return cloneInstant(group.archivedAt) }
func (group RecipientGroup) String() string {
	return fmt.Sprintf("contact_group(id=%s,tenant=%s,key=%s,version=%d,archived=%t)",
		group.id, group.tenantID, group.key.value, group.current.version, group.archivedAt != nil)
}

func cloneGroupVersion(value GroupVersion) GroupVersion {
	result := value
	result.rule = cloneRule(value.rule)
	result.members = slices.Clone(value.members)
	return result
}
