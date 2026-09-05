package httpserver

import (
	"encoding/json"

	"github.com/google/uuid"
	customkernel "github.com/periapsis-im/periapsis/modules/customfields"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

type savedViewCreateBody struct {
	Kind string            `json:"kind"`
	Name string            `json:"name"`
	Spec savedViewSpecBody `json:"spec"`
}

type savedViewReplaceBody struct {
	Kind             string            `json:"kind"`
	ExpectedRevision int64             `json:"expectedRevision"`
	Name             string            `json:"name"`
	Spec             savedViewSpecBody `json:"spec"`
}

type savedViewLifecycleBody struct {
	Kind             string `json:"kind"`
	ExpectedRevision int64  `json:"expectedRevision"`
}

type savedViewSpecBody struct {
	Filters savedViewFiltersBody  `json:"filters"`
	Sort    savedViewSortBody     `json:"sort"`
	Columns []savedViewColumnBody `json:"columns"`
}

type savedViewFiltersBody struct {
	States          []string                    `json:"states"`
	Severities      []string                    `json:"severities"`
	Priorities      []string                    `json:"priorities"`
	AssignedTeamID  *uuid.UUID                  `json:"assignedTeamId,omitempty"`
	AssigneeUserID  *uuid.UUID                  `json:"assigneeUserId,omitempty"`
	ClaimedBy       *uuid.UUID                  `json:"claimedBy,omitempty"`
	Queue           string                      `json:"queue"`
	CustomerVisible *bool                       `json:"customerVisible,omitempty"`
	Search          *string                     `json:"search,omitempty"`
	Custom          []savedViewCustomFilterBody `json:"custom"`
}

type savedViewCustomFilterBody struct {
	DefinitionID              uuid.UUID       `json:"definitionId"`
	ExpectedDefinitionVersion int64           `json:"expectedDefinitionVersion"`
	Operator                  string          `json:"operator"`
	Value                     json.RawMessage `json:"value"`
}

type savedViewSortBody struct {
	Source                    string     `json:"source"`
	CoreKey                   *string    `json:"coreKey,omitempty"`
	DefinitionID              *uuid.UUID `json:"definitionId,omitempty"`
	ExpectedDefinitionVersion *int64     `json:"expectedDefinitionVersion,omitempty"`
	Direction                 string     `json:"direction"`
	Nulls                     string     `json:"nulls"`
}

type savedViewColumnBody struct {
	Source                    string     `json:"source"`
	CoreKey                   *string    `json:"coreKey,omitempty"`
	DefinitionID              *uuid.UUID `json:"definitionId,omitempty"`
	ExpectedDefinitionVersion *int64     `json:"expectedDefinitionVersion,omitempty"`
	Width                     *int       `json:"width,omitempty"`
	Visible                   bool       `json:"visible"`
	Pin                       string     `json:"pin"`
}

func savedViewKind(value string) (kernel.AggregateKind, error) {
	switch value {
	case "alert":
		return kernel.AggregateAlert, nil
	case "case":
		return kernel.AggregateCase, nil
	default:
		return 0, application.ErrInvalidInput
	}
}

func savedViewSpecInput(body savedViewSpecBody) (application.SavedViewSpecInput, error) {
	input := application.SavedViewSpecInput{
		Filters: application.SavedViewFiltersInput{
			States: body.Filters.States, Severities: body.Filters.Severities,
			Priorities: body.Filters.Priorities, AssignedTeamID: body.Filters.AssignedTeamID,
			AssigneeUserID: body.Filters.AssigneeUserID, ClaimedBy: body.Filters.ClaimedBy,
			Queue: body.Filters.Queue, CustomerVisible: body.Filters.CustomerVisible,
		},
		Columns: make([]application.SavedViewColumnInput, len(body.Columns)),
	}
	if body.Filters.Search != nil {
		if *body.Filters.Search == "" {
			return application.SavedViewSpecInput{}, application.ErrInvalidInput
		}
		input.Filters.Search = *body.Filters.Search
	}
	for _, filter := range body.Filters.Custom {
		if filter.ExpectedDefinitionVersion <= 0 || filter.Operator != "equal" {
			return application.SavedViewSpecInput{}, application.ErrInvalidInput
		}
		input.Filters.Custom = append(input.Filters.Custom, application.SavedViewCustomFilterInput{
			DefinitionID:              filter.DefinitionID,
			ExpectedDefinitionVersion: uint64(filter.ExpectedDefinitionVersion),
			Operator:                  customkernel.FilterEqual, Value: json.RawMessage(filter.Value),
		})
	}
	input.Sort = application.SavedViewSortInput{
		Source:       application.SavedViewDefinitionSource(body.Sort.Source),
		DefinitionID: body.Sort.DefinitionID, Direction: body.Sort.Direction, Nulls: body.Sort.Nulls,
	}
	if body.Sort.CoreKey != nil {
		input.Sort.CoreKey = *body.Sort.CoreKey
	}
	if body.Sort.ExpectedDefinitionVersion != nil {
		if *body.Sort.ExpectedDefinitionVersion <= 0 {
			return application.SavedViewSpecInput{}, application.ErrInvalidInput
		}
		input.Sort.ExpectedDefinitionVersion = uint64(*body.Sort.ExpectedDefinitionVersion)
	}
	for index, column := range body.Columns {
		input.Columns[index] = application.SavedViewColumnInput{
			Source: application.SavedViewDefinitionSource(column.Source), DefinitionID: column.DefinitionID,
			Visible: column.Visible, Pin: column.Pin,
		}
		if column.CoreKey != nil {
			input.Columns[index].CoreKey = *column.CoreKey
		}
		if column.ExpectedDefinitionVersion != nil {
			if *column.ExpectedDefinitionVersion <= 0 {
				return application.SavedViewSpecInput{}, application.ErrInvalidInput
			}
			input.Columns[index].ExpectedDefinitionVersion = uint64(*column.ExpectedDefinitionVersion)
		}
		if column.Width != nil {
			if *column.Width < 80 || *column.Width > 1200 {
				return application.SavedViewSpecInput{}, application.ErrInvalidInput
			}
			input.Columns[index].Width = uint16(*column.Width)
		}
	}
	return application.NormalizeSavedViewSpecInput(input)
}
