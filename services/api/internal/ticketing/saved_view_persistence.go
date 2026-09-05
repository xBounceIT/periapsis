package ticketing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	customkernel "github.com/periapsis-im/periapsis/modules/customfields"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

// SavedViewPersistenceRecord is the closed row projection accepted from the
// database ABI. It has a redacted String form because SpecCanonical can contain
// searches and customer data.
type SavedViewPersistenceRecord struct {
	ID                uuid.UUID
	TenantID          uuid.UUID
	OwnerMembershipID uuid.UUID
	Kind              string
	Name              string
	SpecCanonical     []byte
	SpecDigest        []byte
	Status            string
	Revision          uint64
	CreatedAt         time.Time
	UpdatedAt         time.Time
	ArchivedAt        *time.Time
}

func (record SavedViewPersistenceRecord) String() string {
	return fmt.Sprintf(
		"SavedViewPersistenceRecord{revision:%d,metadata:[REDACTED],spec:[REDACTED]}",
		record.Revision,
	)
}

func (record SavedViewPersistenceRecord) GoString() string { return record.String() }

// RestoreSavedViewRecord validates the complete persisted row and refuses to
// return a partially trusted aggregate when any identity, timestamp, lifecycle,
// canonical-spec, or digest field drifts.
func RestoreSavedViewRecord(
	expectedTenantID uuid.UUID,
	expectedOwnerMembershipID uuid.UUID,
	expectedKind kernel.AggregateKind,
	stored SavedViewPersistenceRecord,
) (SavedViewRecord, error) {
	if !validWorkflowUUID(expectedTenantID) || !validWorkflowUUID(expectedOwnerMembershipID) ||
		!validSavedViewKind(expectedKind) || !validWorkflowUUID(stored.ID) ||
		stored.TenantID != expectedTenantID || stored.OwnerMembershipID != expectedOwnerMembershipID ||
		!validText(stored.Name, 120, true) ||
		stored.Revision == 0 || stored.Revision > maxResourceVersion ||
		len(stored.SpecDigest) != sha256.Size {
		return SavedViewRecord{}, ErrUnavailable
	}
	kind, err := restoreSavedViewKind(stored.Kind)
	if err != nil || kind != expectedKind {
		return SavedViewRecord{}, ErrUnavailable
	}
	spec, digest, err := RestoreSavedViewSpec(stored.TenantID, kind, stored.SpecCanonical)
	if err != nil || !bytes.Equal(digest[:], stored.SpecDigest) {
		return SavedViewRecord{}, ErrUnavailable
	}
	id, err := entityID(stored.ID)
	if err != nil {
		return SavedViewRecord{}, ErrUnavailable
	}
	owner, err := entityID(stored.OwnerMembershipID)
	if err != nil {
		return SavedViewRecord{}, ErrUnavailable
	}
	status, err := restoreSavedViewStatus(stored.Status)
	if err != nil {
		return SavedViewRecord{}, ErrUnavailable
	}
	view, err := kernel.NewSavedView(
		id, workflowTenantEntity(stored.TenantID), owner, kind,
		stored.Name, spec, status, stored.Revision,
	)
	if err != nil {
		return SavedViewRecord{}, ErrUnavailable
	}
	record := SavedViewRecord{
		View: view, SpecDigest: digest,
		CreatedAt: stored.CreatedAt, UpdatedAt: stored.UpdatedAt,
	}
	if stored.ArchivedAt != nil {
		archivedAt := *stored.ArchivedAt
		record.ArchivedAt = &archivedAt
	}
	normalized, valid := normalizeSavedViewRecord(record, stored.TenantID, owner, kind)
	if !valid {
		return SavedViewRecord{}, ErrUnavailable
	}
	return normalized, nil
}

// RestoreSavedViewSpec is the inverse of CanonicalSavedViewSpec. Persistence
// adapters must store the canonical bytes losslessly (not as jsonb) and call
// this function instead of accepting a separately decoded projection. Exact
// re-encoding rejects duplicate keys, unknown fields, noncanonical ordering,
// alternate scalar spellings, and nil/empty representation drift.
func RestoreSavedViewSpec(
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	canonical []byte,
) (kernel.SavedViewSpec, [sha256.Size]byte, error) {
	if !validWorkflowUUID(tenantID) || !validSavedViewKind(kind) ||
		len(canonical) == 0 || len(canonical) > maximumSavedViewSpecBytes {
		return kernel.SavedViewSpec{}, [sha256.Size]byte{}, ErrUnavailable
	}
	var stored savedViewSpecCanonical
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		stored.Version != 1 {
		return kernel.SavedViewSpec{}, [sha256.Size]byte{}, ErrUnavailable
	}
	// Reject oversized shapes before allocating typed kernel slices. The total
	// byte cap limits parser work; these operation-shaped caps prevent a small
	// canonical document made of empty scalars from amplifying allocations.
	if len(stored.Filters.States) > maximumSavedViewStates ||
		len(stored.Filters.Severities) > maximumSavedViewEnums ||
		len(stored.Filters.Priorities) > maximumSavedViewEnums ||
		len(stored.Filters.Custom) > maximumSavedViewFilters ||
		len(stored.Columns) == 0 || len(stored.Columns) > maximumSavedViewColumns {
		return kernel.SavedViewSpec{}, [sha256.Size]byte{}, ErrUnavailable
	}

	tenant := workflowTenantEntity(tenantID)
	filters, err := restoreSavedViewFilters(tenant, kind, stored.Filters)
	if err != nil {
		return kernel.SavedViewSpec{}, [sha256.Size]byte{}, ErrUnavailable
	}
	sortPlan, err := restoreSavedViewSort(tenant, kind, stored.Sort)
	if err != nil {
		return kernel.SavedViewSpec{}, [sha256.Size]byte{}, ErrUnavailable
	}
	columns := make([]kernel.SavedViewColumn, len(stored.Columns))
	for index, column := range stored.Columns {
		columns[index], err = restoreSavedViewColumn(tenant, kind, column)
		if err != nil {
			return kernel.SavedViewSpec{}, [sha256.Size]byte{}, ErrUnavailable
		}
	}
	spec, err := kernel.NewSavedViewSpec(tenant, kind, filters, sortPlan, columns)
	if err != nil {
		return kernel.SavedViewSpec{}, [sha256.Size]byte{}, ErrUnavailable
	}
	reencoded, err := CanonicalSavedViewSpec(tenant, kind, spec)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		return kernel.SavedViewSpec{}, [sha256.Size]byte{}, ErrUnavailable
	}
	return spec, sha256.Sum256(canonical), nil
}

func restoreSavedViewFilters(
	tenant kernel.EntityID,
	kind kernel.AggregateKind,
	stored savedViewFiltersCanonical,
) (kernel.SavedViewFilters, error) {
	states := make([]kernel.Key, len(stored.States))
	for index, raw := range stored.States {
		key, err := kernel.NewKey(raw)
		if err != nil {
			return kernel.SavedViewFilters{}, err
		}
		states[index] = key
	}
	assignedTeam, err := restoreOptionalSavedViewEntity(stored.AssignedTeamID)
	if err != nil {
		return kernel.SavedViewFilters{}, err
	}
	assignee, err := restoreOptionalSavedViewEntity(stored.AssigneeUserID)
	if err != nil {
		return kernel.SavedViewFilters{}, err
	}
	claimedBy, err := restoreOptionalSavedViewEntity(stored.ClaimedBy)
	if err != nil {
		return kernel.SavedViewFilters{}, err
	}
	queue, err := restoreSavedViewQueue(stored.Queue)
	if err != nil {
		return kernel.SavedViewFilters{}, err
	}
	custom := make([]kernel.SavedViewCustomFilter, len(stored.Custom))
	for index, filter := range stored.Custom {
		if filter.Operator != string(customkernel.FilterEqual) {
			return kernel.SavedViewFilters{}, kernel.ErrInvalidSavedView
		}
		pin, pinErr := restoreSavedViewDefinition(tenant, kind, filter.Definition)
		if pinErr != nil {
			return kernel.SavedViewFilters{}, pinErr
		}
		custom[index], pinErr = kernel.RestoreSavedViewCustomFilter(
			pin, customkernel.DataType(filter.DataType), filter.Value,
		)
		if pinErr != nil {
			return kernel.SavedViewFilters{}, pinErr
		}
	}
	return kernel.NewSavedViewFilters(kernel.SavedViewFiltersInput{
		States:          states,
		Severities:      stored.Severities,
		Priorities:      stored.Priorities,
		AssignedTeam:    assignedTeam,
		Assignee:        assignee,
		ClaimedBy:       claimedBy,
		Queue:           queue,
		CustomerVisible: stored.CustomerVisible,
		Search:          stored.Search,
		Custom:          custom,
	})
}

func restoreSavedViewSort(
	tenant kernel.EntityID,
	kind kernel.AggregateKind,
	stored savedViewSortCanonical,
) (kernel.SavedViewSort, error) {
	direction, err := restoreSavedViewSortDirection(stored.Direction)
	if err != nil {
		return kernel.SavedViewSort{}, err
	}
	source, err := restoreSavedViewSource(stored.Source)
	if err != nil {
		return kernel.SavedViewSort{}, err
	}
	if source == kernel.SavedViewColumnCore {
		if stored.Definition != nil || stored.Nulls != kernel.SavedViewNullsLast.String() {
			return kernel.SavedViewSort{}, kernel.ErrInvalidSavedView
		}
		key, keyErr := kernel.NewKey(stored.CoreKey)
		if keyErr != nil {
			return kernel.SavedViewSort{}, keyErr
		}
		return kernel.NewSavedViewCoreSort(key, direction)
	}
	if stored.CoreKey != "" || stored.Definition == nil {
		return kernel.SavedViewSort{}, kernel.ErrInvalidSavedView
	}
	pin, err := restoreSavedViewDefinition(tenant, kind, *stored.Definition)
	if err != nil {
		return kernel.SavedViewSort{}, err
	}
	nulls, err := restoreSavedViewNullOrder(stored.Nulls)
	if err != nil {
		return kernel.SavedViewSort{}, err
	}
	return kernel.NewSavedViewDynamicSort(source, pin, direction, nulls)
}

func restoreSavedViewColumn(
	tenant kernel.EntityID,
	kind kernel.AggregateKind,
	stored savedViewColumnCanonical,
) (kernel.SavedViewColumn, error) {
	source, err := restoreSavedViewSource(stored.Source)
	if err != nil {
		return kernel.SavedViewColumn{}, err
	}
	pin, err := restoreSavedViewColumnPin(stored.Pin)
	if err != nil {
		return kernel.SavedViewColumn{}, err
	}
	if source == kernel.SavedViewColumnCore {
		if stored.Definition != nil {
			return kernel.SavedViewColumn{}, kernel.ErrInvalidSavedView
		}
		key, keyErr := kernel.NewKey(stored.CoreKey)
		if keyErr != nil {
			return kernel.SavedViewColumn{}, keyErr
		}
		return kernel.NewSavedViewCoreColumn(key, stored.Width, stored.Visible, pin)
	}
	if stored.CoreKey != "" || stored.Definition == nil {
		return kernel.SavedViewColumn{}, kernel.ErrInvalidSavedView
	}
	definition, err := restoreSavedViewDefinition(tenant, kind, *stored.Definition)
	if err != nil {
		return kernel.SavedViewColumn{}, err
	}
	return kernel.NewSavedViewDynamicColumn(source, definition, stored.Width, stored.Visible, pin)
}

func restoreSavedViewDefinition(
	tenant kernel.EntityID,
	kind kernel.AggregateKind,
	stored savedViewDefinitionCanonical,
) (kernel.SavedViewDefinitionPin, error) {
	id, err := restoreSavedViewEntity(stored.ID)
	if err != nil {
		return kernel.SavedViewDefinitionPin{}, err
	}
	storedTenant, err := restoreSavedViewEntity(stored.TenantID)
	if err != nil || storedTenant != tenant || stored.Kind != kind.String() {
		return kernel.SavedViewDefinitionPin{}, kernel.ErrInvalidSavedView
	}
	key, err := kernel.NewKey(stored.Key)
	if err != nil {
		return kernel.SavedViewDefinitionPin{}, err
	}
	digestBytes, err := hex.DecodeString(stored.Digest)
	if err != nil || len(digestBytes) != sha256.Size {
		return kernel.SavedViewDefinitionPin{}, kernel.ErrInvalidSavedView
	}
	var digest [sha256.Size]byte
	copy(digest[:], digestBytes)
	return kernel.NewSavedViewDefinitionPin(id, tenant, kind, key, stored.Version, digest)
}

func restoreOptionalSavedViewEntity(value string) (*kernel.EntityID, error) {
	if value == "" {
		return nil, nil
	}
	entity, err := restoreSavedViewEntity(value)
	if err != nil {
		return nil, err
	}
	return &entity, nil
}

func restoreSavedViewEntity(value string) (kernel.EntityID, error) {
	id, err := uuid.Parse(value)
	if err != nil || !validWorkflowUUID(id) || id.String() != value {
		return kernel.EntityID{}, kernel.ErrInvalidSavedView
	}
	return kernel.NewEntityID(id)
}

func restoreSavedViewSource(value string) (kernel.SavedViewColumnSource, error) {
	switch value {
	case kernel.SavedViewColumnCore.String():
		return kernel.SavedViewColumnCore, nil
	case kernel.SavedViewColumnCustomField.String():
		return kernel.SavedViewColumnCustomField, nil
	case kernel.SavedViewColumnSLA.String():
		return kernel.SavedViewColumnSLA, nil
	default:
		return 0, kernel.ErrInvalidSavedView
	}
}

func restoreSavedViewQueue(value string) (kernel.SavedViewQueue, error) {
	switch value {
	case kernel.SavedViewQueueAll.String():
		return kernel.SavedViewQueueAll, nil
	case kernel.SavedViewQueueAssignedToMe.String():
		return kernel.SavedViewQueueAssignedToMe, nil
	case kernel.SavedViewQueueMyOperatorTeams.String():
		return kernel.SavedViewQueueMyOperatorTeams, nil
	case kernel.SavedViewQueueUnassigned.String():
		return kernel.SavedViewQueueUnassigned, nil
	default:
		return 0, kernel.ErrInvalidSavedView
	}
}

func restoreSavedViewSortDirection(value string) (kernel.SavedViewSortDirection, error) {
	if value == kernel.SavedViewSortAscending.String() {
		return kernel.SavedViewSortAscending, nil
	}
	if value == kernel.SavedViewSortDescending.String() {
		return kernel.SavedViewSortDescending, nil
	}
	return 0, kernel.ErrInvalidSavedView
}

func restoreSavedViewNullOrder(value string) (kernel.SavedViewNullOrder, error) {
	if value == kernel.SavedViewNullsFirst.String() {
		return kernel.SavedViewNullsFirst, nil
	}
	if value == kernel.SavedViewNullsLast.String() {
		return kernel.SavedViewNullsLast, nil
	}
	return 0, kernel.ErrInvalidSavedView
}

func restoreSavedViewColumnPin(value string) (kernel.SavedViewColumnPin, error) {
	if value == kernel.SavedViewColumnUnpinned.String() {
		return kernel.SavedViewColumnUnpinned, nil
	}
	if value == kernel.SavedViewColumnPinnedStart.String() {
		return kernel.SavedViewColumnPinnedStart, nil
	}
	if value == kernel.SavedViewColumnPinnedEnd.String() {
		return kernel.SavedViewColumnPinnedEnd, nil
	}
	return 0, kernel.ErrInvalidSavedView
}

func restoreSavedViewKind(value string) (kernel.AggregateKind, error) {
	if value == kernel.AggregateAlert.String() {
		return kernel.AggregateAlert, nil
	}
	if value == kernel.AggregateCase.String() {
		return kernel.AggregateCase, nil
	}
	return 0, kernel.ErrInvalidSavedView
}

func restoreSavedViewStatus(value string) (kernel.SavedViewStatus, error) {
	if value == kernel.SavedViewActive.String() {
		return kernel.SavedViewActive, nil
	}
	if value == kernel.SavedViewArchived.String() {
		return kernel.SavedViewArchived, nil
	}
	return 0, kernel.ErrInvalidSavedView
}
