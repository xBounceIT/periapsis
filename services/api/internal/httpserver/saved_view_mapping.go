package httpserver

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func mapSavedTicketView(record application.SavedViewRecord) (contract.SavedTicketView, error) {
	spec, err := mapSavedTicketViewSpec(record.View.Spec())
	if err != nil || record.View.Revision() == 0 || record.View.Revision() > uint64(maximumResourceVersion) {
		return contract.SavedTicketView{}, application.ErrUnavailable
	}
	kind := contract.TicketResourceKind(record.View.Kind().String())
	status := contract.SavedTicketViewStatus(record.View.Status().String())
	if !kind.Valid() || !status.Valid() {
		return contract.SavedTicketView{}, application.ErrUnavailable
	}
	result := contract.SavedTicketView{
		Id: uuid.UUID(record.View.ID().Bytes()), TenantId: uuid.UUID(record.View.Tenant().Bytes()),
		OwnerMembershipId: uuid.UUID(record.View.Owner().Bytes()), Kind: kind, Name: record.View.Name(),
		Spec: spec, SpecSha256: hex.EncodeToString(record.SpecDigest[:]), Status: status,
		Revision: int64(record.View.Revision()), CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	}
	if record.ArchivedAt != nil {
		value := *record.ArchivedAt
		result.ArchivedAt = &value
	}
	return result, nil
}

func mapSavedTicketViewSpec(spec kernel.SavedViewSpec) (contract.SavedTicketViewSpec, error) {
	filters := spec.Filters()
	mapped := contract.SavedTicketViewSpec{
		Filters: contract.SavedTicketViewFilters{
			States: keyStringsForContract(filters.States()), Severities: make([]contract.AlertSeverity, len(filters.Severities())),
			Priorities: make([]contract.TicketPriority, len(filters.Priorities())),
			Queue:      contract.SavedTicketViewQueue(filters.Queue().String()), Custom: []contract.SavedTicketViewCustomFilter{},
			CustomerVisible: filters.CustomerVisible(),
		},
		Columns: make([]contract.SavedTicketViewColumn, len(spec.Columns())),
	}
	if filters.Search() != "" {
		value := filters.Search()
		mapped.Filters.Search = &value
	}
	if value := filters.AssignedTeam(); value != nil {
		identifier := uuid.UUID(value.Bytes())
		mapped.Filters.AssignedTeamId = &identifier
	}
	if value := filters.Assignee(); value != nil {
		identifier := uuid.UUID(value.Bytes())
		mapped.Filters.AssigneeUserId = &identifier
	}
	if value := filters.ClaimedBy(); value != nil {
		identifier := uuid.UUID(value.Bytes())
		mapped.Filters.ClaimedBy = &identifier
	}
	for index, value := range filters.Severities() {
		mapped.Filters.Severities[index] = contract.AlertSeverity(value)
		if !mapped.Filters.Severities[index].Valid() {
			return contract.SavedTicketViewSpec{}, application.ErrUnavailable
		}
	}
	for index, value := range filters.Priorities() {
		mapped.Filters.Priorities[index] = contract.TicketPriority(value)
		if !mapped.Filters.Priorities[index].Valid() {
			return contract.SavedTicketViewSpec{}, application.ErrUnavailable
		}
	}
	for _, filter := range filters.Custom() {
		value, err := mapSavedViewScalar(filter.CanonicalJSON())
		if err != nil {
			return contract.SavedTicketViewSpec{}, err
		}
		mapped.Filters.Custom = append(mapped.Filters.Custom, contract.SavedTicketViewCustomFilter{
			Definition: mapSavedViewDefinitionPin(filter.Definition()),
			DataType:   contract.SavedTicketViewScalarCustomFieldType(filter.DataType()),
			Operator:   contract.SavedTicketViewCustomFilterOperator("equal"), Value: value,
		})
	}
	sort, err := mapSavedViewSort(spec.Sort())
	if err != nil {
		return contract.SavedTicketViewSpec{}, err
	}
	mapped.Sort = sort
	for index, column := range spec.Columns() {
		width, err := mapSavedViewColumnWidth(column.Width())
		if err != nil {
			return contract.SavedTicketViewSpec{}, application.ErrUnavailable
		}
		mapped.Columns[index] = contract.SavedTicketViewColumn{
			Source: contract.SavedTicketViewDefinitionSource(column.Source().String()),
			Width:  width, Visible: column.Visible(), Pin: contract.SavedTicketViewColumnPin(column.Pin().String()),
		}
		if key, core := column.CoreKey(); core {
			value := contract.SavedTicketViewCoreColumnKey(key.String())
			mapped.Columns[index].CoreKey = &value
		} else if pin, dynamic := column.Definition(); dynamic {
			value := mapSavedViewDefinitionPin(pin)
			mapped.Columns[index].Definition = &value
		} else {
			return contract.SavedTicketViewSpec{}, application.ErrUnavailable
		}
	}
	return mapped, nil
}

func mapSavedViewColumnWidth(value uint16) (contract.SavedTicketViewColumn_Width, error) {
	var mapped contract.SavedTicketViewColumn_Width
	if value == 0 {
		err := mapped.FromSavedTicketViewColumnWidth0(contract.SavedTicketViewColumnWidth0(0))
		return mapped, err
	}
	err := mapped.FromSavedTicketViewColumnWidth1(int(value))
	return mapped, err
}

func mapSavedViewSort(sort kernel.SavedViewSort) (contract.SavedTicketViewSort, error) {
	result := contract.SavedTicketViewSort{
		Source:    contract.SavedTicketViewDefinitionSource(sort.Source().String()),
		Direction: contract.SavedTicketViewSortDirection(sort.Direction().String()),
		Nulls:     contract.SavedTicketViewNullOrder(sort.Nulls().String()),
	}
	if key, core := sort.CoreKey(); core {
		value := contract.SavedTicketViewCoreSortKey(key.String())
		result.CoreKey = &value
	} else if pin, dynamic := sort.Definition(); dynamic {
		value := mapSavedViewDefinitionPin(pin)
		result.Definition = &value
	} else {
		return contract.SavedTicketViewSort{}, application.ErrUnavailable
	}
	return result, nil
}

func mapSavedViewDefinitionPin(pin kernel.SavedViewDefinitionPin) contract.SavedTicketViewDefinitionPin {
	digest := pin.Digest()
	return contract.SavedTicketViewDefinitionPin{
		Id: uuid.UUID(pin.ID().Bytes()), TenantId: uuid.UUID(pin.Tenant().Bytes()),
		Kind: contract.TicketResourceKind(pin.Kind().String()), Key: pin.Key().String(),
		Version: int64(pin.Version()), Sha256: hex.EncodeToString(digest[:]),
	}
}

func mapSavedViewScalar(raw []byte) (contract.SavedTicketViewScalarValue, error) {
	value, err := mapLosslessTicketScalar(raw)
	if err != nil {
		return contract.SavedTicketViewScalarValue{}, errors.New("invalid saved-view scalar")
	}
	var result contract.SavedTicketViewScalarValue
	switch typed := value.(type) {
	case string:
		err = result.FromSavedTicketViewScalarValue0(typed)
	case bool:
		err = result.FromSavedTicketViewScalarValue3(typed)
	default:
		err = errors.New("invalid saved-view scalar")
	}
	if err != nil {
		return contract.SavedTicketViewScalarValue{}, errors.New("invalid saved-view scalar")
	}
	return result, nil
}

// mapLosslessTicketScalar keeps canonical numeric JSON as text at the HTTP
// boundary. JavaScript cannot represent every PostgreSQL numeric or int64
// value exactly, so emitting a JSON number would silently alter saved filters,
// dynamic columns, and later mutations in the generated browser client.
func mapLosslessTicketScalar(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("invalid ticket scalar")
	}
	switch typed := value.(type) {
	case string:
		return typed, nil
	case bool:
		return typed, nil
	case json.Number:
		return typed.String(), nil
	default:
		return nil, errors.New("invalid ticket scalar")
	}
}

func keyStringsForContract(values []kernel.Key) []contract.WorkflowStateKey {
	result := make([]contract.WorkflowStateKey, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}
