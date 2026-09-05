package ticketing

import (
	"encoding/json"

	customkernel "github.com/periapsis-im/periapsis/modules/customfields"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

// SavedViewSpecInputFromResolved reconstructs the resolution request for an
// already pinned specification. Applying a view must submit this request to
// the live catalog resolver and compare the resulting canonical digest before
// compiling SQL; persisted pins are evidence to verify, never authority.
func SavedViewSpecInputFromResolved(spec kernel.SavedViewSpec) (SavedViewSpecInput, error) {
	filters := spec.Filters()
	result := SavedViewSpecInput{
		Filters: SavedViewFiltersInput{
			States:          keyStringsForFingerprint(filters.States()),
			Severities:      filters.Severities(),
			Priorities:      filters.Priorities(),
			Queue:           filters.Queue().String(),
			CustomerVisible: filters.CustomerVisible(),
			Search:          filters.Search(),
		},
		Columns: make([]SavedViewColumnInput, len(spec.Columns())),
	}
	if value := filters.AssignedTeam(); value != nil {
		identifier := uuidFromEntity(*value)
		result.Filters.AssignedTeamID = &identifier
	}
	if value := filters.Assignee(); value != nil {
		identifier := uuidFromEntity(*value)
		result.Filters.AssigneeUserID = &identifier
	}
	if value := filters.ClaimedBy(); value != nil {
		identifier := uuidFromEntity(*value)
		result.Filters.ClaimedBy = &identifier
	}
	for _, filter := range filters.Custom() {
		pin := filter.Definition()
		result.Filters.Custom = append(result.Filters.Custom, SavedViewCustomFilterInput{
			DefinitionID: uuidFromEntity(pin.ID()), ExpectedDefinitionVersion: pin.Version(),
			Operator: customkernel.FilterEqual, Value: json.RawMessage(filter.CanonicalJSON()),
		})
	}
	result.Sort = savedViewResolvedSortInput(spec.Sort())
	for index, column := range spec.Columns() {
		result.Columns[index] = SavedViewColumnInput{
			Source:  SavedViewDefinitionSource(column.Source().String()),
			Width:   column.Width(),
			Visible: column.Visible(),
			Pin:     column.Pin().String(),
		}
		if key, core := column.CoreKey(); core {
			result.Columns[index].CoreKey = key.String()
		} else if pin, dynamic := column.Definition(); dynamic {
			identifier := uuidFromEntity(pin.ID())
			result.Columns[index].DefinitionID = &identifier
			result.Columns[index].ExpectedDefinitionVersion = pin.Version()
		} else {
			return SavedViewSpecInput{}, ErrUnavailable
		}
	}
	return NormalizeSavedViewSpecInput(result)
}

func savedViewResolvedSortInput(sort kernel.SavedViewSort) SavedViewSortInput {
	result := SavedViewSortInput{
		Source:    SavedViewDefinitionSource(sort.Source().String()),
		Direction: sort.Direction().String(), Nulls: sort.Nulls().String(),
	}
	if key, core := sort.CoreKey(); core {
		result.CoreKey = key.String()
	} else if pin, dynamic := sort.Definition(); dynamic {
		identifier := uuidFromEntity(pin.ID())
		result.DefinitionID = &identifier
		result.ExpectedDefinitionVersion = pin.Version()
	}
	return result
}
