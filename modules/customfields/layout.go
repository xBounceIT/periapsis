package customfields

import (
	"fmt"
	"slices"
)

const (
	maximumLayoutSections = 64
	maximumLayoutFields   = 512
)

type LayoutSectionInput struct {
	Key           Key
	Label         string
	Position      uint16
	DefinitionIDs []EntityID
}

type LayoutInput struct {
	ID            EntityID
	TenantID      EntityID
	ObjectType    ObjectType
	Audience      Audience
	SchemaVersion uint64
	Sections      []LayoutSectionInput
}

type LayoutSection struct {
	key           Key
	label         string
	position      uint16
	definitionIDs []EntityID
}

func (section LayoutSection) Key() Key                  { return section.key }
func (section LayoutSection) Label() string             { return section.label }
func (section LayoutSection) Position() uint16          { return section.position }
func (section LayoutSection) DefinitionIDs() []EntityID { return slices.Clone(section.definitionIDs) }

type Layout struct {
	id            EntityID
	tenantID      EntityID
	objectType    ObjectType
	audience      Audience
	schemaVersion uint64
	sections      []LayoutSection
}

func NewLayout(input LayoutInput, definitions []Definition) (Layout, error) {
	if !validEntityID(input.ID) || !validEntityID(input.TenantID) ||
		!validObjectType(input.ObjectType) ||
		(input.Audience != AudienceCustomer && input.Audience != AudienceOperator) ||
		input.SchemaVersion == 0 || input.SchemaVersion >= maximumDefinitionVersion ||
		len(input.Sections) == 0 || len(input.Sections) > maximumLayoutSections {
		return Layout{}, ErrInvalidLayout
	}
	definitionsByID := make(map[EntityID]Definition, len(definitions))
	definitionKeys := make(map[Key]struct{}, len(definitions))
	for _, definition := range definitions {
		if definition.tenantID != input.TenantID || definition.objectType != input.ObjectType {
			return Layout{}, ErrInvalidLayout
		}
		if _, duplicate := definitionsByID[definition.id]; duplicate {
			return Layout{}, ErrInvalidLayout
		}
		if _, duplicate := definitionKeys[definition.key]; duplicate {
			return Layout{}, ErrInvalidLayout
		}
		definitionsByID[definition.id] = definition
		definitionKeys[definition.key] = struct{}{}
	}

	sections := make([]LayoutSection, len(input.Sections))
	seenSections := make(map[Key]struct{}, len(input.Sections))
	seenPositions := make(map[uint16]struct{}, len(input.Sections))
	seenFields := make(map[EntityID]struct{}, len(definitions))
	fieldCount := 0
	for index, source := range input.Sections {
		if !validKey(source.Key.value) || !validText(source.Label, maximumLabelBytes, false, false) ||
			len(source.DefinitionIDs) == 0 {
			return Layout{}, ErrInvalidLayout
		}
		if _, duplicate := seenSections[source.Key]; duplicate {
			return Layout{}, ErrInvalidLayout
		}
		if _, duplicate := seenPositions[source.Position]; duplicate {
			return Layout{}, ErrInvalidLayout
		}
		seenSections[source.Key] = struct{}{}
		seenPositions[source.Position] = struct{}{}
		ids := slices.Clone(source.DefinitionIDs)
		for _, definitionID := range ids {
			definition, exists := definitionsByID[definitionID]
			if !exists || !definition.VisibleTo(input.Audience) {
				return Layout{}, ErrInvalidLayout
			}
			if _, duplicate := seenFields[definitionID]; duplicate {
				return Layout{}, ErrInvalidLayout
			}
			seenFields[definitionID] = struct{}{}
			fieldCount++
		}
		sections[index] = LayoutSection{
			key: source.Key, label: source.Label, position: source.Position, definitionIDs: ids,
		}
	}
	if fieldCount > maximumLayoutFields {
		return Layout{}, ErrInvalidLayout
	}
	slices.SortFunc(sections, func(left, right LayoutSection) int {
		if left.position < right.position {
			return -1
		}
		if left.position > right.position {
			return 1
		}
		return compareKeys(left.key, right.key)
	})
	return Layout{
		id: input.ID, tenantID: input.TenantID, objectType: input.ObjectType,
		audience: input.Audience, schemaVersion: input.SchemaVersion, sections: sections,
	}, nil
}

func (layout Layout) ID() EntityID           { return layout.id }
func (layout Layout) TenantID() EntityID     { return layout.tenantID }
func (layout Layout) ObjectType() ObjectType { return layout.objectType }
func (layout Layout) Audience() Audience     { return layout.audience }
func (layout Layout) SchemaVersion() uint64  { return layout.schemaVersion }
func (layout Layout) Sections() []LayoutSection {
	result := slices.Clone(layout.sections)
	for index := range result {
		result[index].definitionIDs = slices.Clone(result[index].definitionIDs)
	}
	return result
}
func (layout Layout) String() string {
	return fmt.Sprintf(
		"customfields.Layout{object:%s,audience:%s,schemaVersion:%d,sections:%d,labels:[REDACTED]}",
		layout.objectType, layout.audience, layout.schemaVersion, len(layout.sections),
	)
}
func (layout Layout) GoString() string { return layout.String() }
