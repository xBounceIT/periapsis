package ticketing

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"

	customfields "github.com/periapsis-im/periapsis/modules/customfields"
)

const (
	maximumSavedViewNameBytes   = 120
	maximumSavedViewSearchBytes = 240
	maximumSavedViewColumns     = 64
	maximumSavedViewFilters     = 8
	maximumSavedViewFilterBytes = 192 * 1024
	minimumSavedViewColumnWidth = 80
	maximumSavedViewColumnWidth = 1_200
)

var (
	ErrInvalidSavedView       = errors.New("invalid saved ticket view")
	ErrSavedViewConflict      = errors.New("saved ticket view revision conflict")
	ErrSavedViewNoChange      = errors.New("saved ticket view command has no change")
	ErrSavedViewInactive      = errors.New("saved ticket view is not active")
	ErrSavedViewAlreadyActive = errors.New("saved ticket view is already active")
)

// SavedViewDefinitionPin identifies the exact immutable definition semantics
// used by a dynamic filter, column, or sort. A stable key alone is not enough:
// the schema/version and content digest prevent silent reinterpretation after
// an administrator changes visibility, constraints, type, or SLA semantics.
type SavedViewDefinitionPin struct {
	id      EntityID
	tenant  EntityID
	kind    AggregateKind
	key     Key
	version uint64
	digest  [32]byte
}

func NewSavedViewDefinitionPin(
	id EntityID,
	tenant EntityID,
	kind AggregateKind,
	key Key,
	version uint64,
	digest [32]byte,
) (SavedViewDefinitionPin, error) {
	if !validEntityID(id) || !validEntityID(tenant) || !validAggregateKind(kind) ||
		!validKey(key.value) || version == 0 || version > maxVersion || digest == ([32]byte{}) {
		return SavedViewDefinitionPin{}, ErrInvalidSavedView
	}
	return SavedViewDefinitionPin{
		id: id, tenant: tenant, kind: kind, key: key, version: version, digest: digest,
	}, nil
}

func (pin SavedViewDefinitionPin) ID() EntityID        { return pin.id }
func (pin SavedViewDefinitionPin) Tenant() EntityID    { return pin.tenant }
func (pin SavedViewDefinitionPin) Kind() AggregateKind { return pin.kind }
func (pin SavedViewDefinitionPin) Key() Key            { return pin.key }
func (pin SavedViewDefinitionPin) Version() uint64     { return pin.version }
func (pin SavedViewDefinitionPin) Digest() [32]byte    { return pin.digest }
func (pin SavedViewDefinitionPin) String() string {
	return fmt.Sprintf("SavedViewDefinitionPin{version:%d,definition:[REDACTED]}", pin.version)
}

func (pin SavedViewDefinitionPin) GoString() string { return pin.String() }

func validSavedViewDefinitionPin(pin SavedViewDefinitionPin) bool {
	rebuilt, err := NewSavedViewDefinitionPin(
		pin.id, pin.tenant, pin.kind, pin.key, pin.version, pin.digest,
	)
	return err == nil && rebuilt == pin
}

// SavedViewCustomFilter is constructed only from a capability-checked custom
// field FilterPlan. The current v1 HTTP list vocabulary supports scalar
// equality; collection and arbitrary JSON operators remain fail closed until a
// separately versioned query contract and matching indexes exist.
type SavedViewCustomFilter struct {
	tenant     EntityID
	kind       AggregateKind
	definition SavedViewDefinitionPin
	dataType   customfields.DataType
	canonical  json.RawMessage
}

func NewSavedViewCustomFilter(
	plan customfields.FilterPlan,
	definitionVersion uint64,
	definitionDigest [32]byte,
) (SavedViewCustomFilter, error) {
	if plan.Operator() != customfields.FilterEqual ||
		plan.Value().Presence() != customfields.PresencePresent ||
		!savedViewScalarCustomType(plan.DataType()) {
		return SavedViewCustomFilter{}, ErrInvalidSavedView
	}
	tenant, err := NewEntityID(plan.TenantID().Bytes())
	if err != nil {
		return SavedViewCustomFilter{}, ErrInvalidSavedView
	}
	definitionID, err := NewEntityID(plan.DefinitionID().Bytes())
	if err != nil {
		return SavedViewCustomFilter{}, ErrInvalidSavedView
	}
	key, err := NewKey(plan.Key().String())
	if err != nil {
		return SavedViewCustomFilter{}, ErrInvalidSavedView
	}
	kind, err := savedViewAggregateKind(plan.ObjectType())
	if err != nil {
		return SavedViewCustomFilter{}, err
	}
	pin, err := NewSavedViewDefinitionPin(
		definitionID, tenant, kind, key, definitionVersion, definitionDigest,
	)
	if err != nil {
		return SavedViewCustomFilter{}, err
	}
	canonical := plan.Value().CanonicalJSON()
	if len(canonical) == 0 || len(canonical) > 64*1024 || !json.Valid(canonical) {
		return SavedViewCustomFilter{}, ErrInvalidSavedView
	}
	return SavedViewCustomFilter{
		tenant: tenant, kind: kind, definition: pin,
		dataType: plan.DataType(), canonical: slices.Clone(canonical),
	}, nil
}

// RestoreSavedViewCustomFilter reconstructs a persisted filter from its exact
// immutable definition pin and canonical scalar value. This is structural
// restoration only: applying the view must still resolve the live definition,
// compare the complete pin, and repeat list/filter authorization.
func RestoreSavedViewCustomFilter(
	definition SavedViewDefinitionPin,
	dataType customfields.DataType,
	canonical json.RawMessage,
) (SavedViewCustomFilter, error) {
	if !validSavedViewDefinitionPin(definition) {
		return SavedViewCustomFilter{}, ErrInvalidSavedView
	}
	definitionID, err := customfields.NewEntityID(definition.id.Bytes())
	if err != nil {
		return SavedViewCustomFilter{}, ErrInvalidSavedView
	}
	tenantID, err := customfields.NewEntityID(definition.tenant.Bytes())
	if err != nil {
		return SavedViewCustomFilter{}, ErrInvalidSavedView
	}
	key, err := customfields.NewKey(definition.key.String())
	if err != nil {
		return SavedViewCustomFilter{}, ErrInvalidSavedView
	}
	objectType := customfields.ObjectAlert
	if definition.kind == AggregateCase {
		objectType = customfields.ObjectCase
	}
	plan, err := customfields.RestoreEqualityFilterPlan(customfields.FilterPlanSnapshot{
		DefinitionID: definitionID,
		TenantID:     tenantID,
		ObjectType:   objectType,
		Key:          key,
		DataType:     dataType,
		Operator:     customfields.FilterEqual,
		Canonical:    slices.Clone(canonical),
	})
	if err != nil {
		return SavedViewCustomFilter{}, ErrInvalidSavedView
	}
	filter, err := NewSavedViewCustomFilter(plan, definition.version, definition.digest)
	if err != nil || filter.definition != definition {
		return SavedViewCustomFilter{}, ErrInvalidSavedView
	}
	return filter, nil
}

func (filter SavedViewCustomFilter) Tenant() EntityID                   { return filter.tenant }
func (filter SavedViewCustomFilter) Kind() AggregateKind                { return filter.kind }
func (filter SavedViewCustomFilter) Definition() SavedViewDefinitionPin { return filter.definition }
func (filter SavedViewCustomFilter) DataType() customfields.DataType    { return filter.dataType }
func (filter SavedViewCustomFilter) CanonicalJSON() json.RawMessage {
	return slices.Clone(filter.canonical)
}
func (filter SavedViewCustomFilter) String() string {
	return fmt.Sprintf(
		"SavedViewCustomFilter{kind:%s,type:%s,version:%d,value:[REDACTED]}",
		filter.kind, filter.dataType, filter.definition.version,
	)
}

func (filter SavedViewCustomFilter) GoString() string { return filter.String() }

func validSavedViewCustomFilter(filter SavedViewCustomFilter) bool {
	if !validEntityID(filter.tenant) || !validAggregateKind(filter.kind) ||
		filter.tenant != filter.definition.tenant || filter.kind != filter.definition.kind ||
		!validSavedViewDefinitionPin(filter.definition) ||
		!savedViewScalarCustomType(filter.dataType) ||
		len(filter.canonical) == 0 || len(filter.canonical) > 64*1024 || !json.Valid(filter.canonical) {
		return false
	}
	restored, err := RestoreSavedViewCustomFilter(
		filter.definition, filter.dataType, filter.canonical,
	)
	return err == nil && restored.tenant == filter.tenant && restored.kind == filter.kind &&
		restored.definition == filter.definition && restored.dataType == filter.dataType &&
		bytes.Equal(restored.canonical, filter.canonical)
}

func savedViewScalarCustomType(dataType customfields.DataType) bool {
	switch dataType {
	case customfields.TypeShortText, customfields.TypeLongText,
		customfields.TypeInteger, customfields.TypeDecimal,
		customfields.TypeBoolean, customfields.TypeDate,
		customfields.TypeDateTime, customfields.TypeDuration,
		customfields.TypeSingleSelect, customfields.TypeURL,
		customfields.TypeEmail, customfields.TypeIP, customfields.TypeCIDR,
		customfields.TypeUser, customfields.TypeOperatorTeam,
		customfields.TypeCustomerContact, customfields.TypeAssetReference,
		customfields.TypeIOCReference:
		return true
	default:
		return false
	}
}

func savedViewAggregateKind(objectType customfields.ObjectType) (AggregateKind, error) {
	switch objectType {
	case customfields.ObjectAlert:
		return AggregateAlert, nil
	case customfields.ObjectCase:
		return AggregateCase, nil
	default:
		return 0, ErrInvalidSavedView
	}
}

type SavedViewQueue uint8

const (
	SavedViewQueueAll SavedViewQueue = iota + 1
	SavedViewQueueAssignedToMe
	SavedViewQueueMyOperatorTeams
	SavedViewQueueUnassigned
)

func (queue SavedViewQueue) String() string {
	switch queue {
	case SavedViewQueueAll:
		return "all"
	case SavedViewQueueAssignedToMe:
		return "assigned_to_me"
	case SavedViewQueueMyOperatorTeams:
		return "my_operator_teams"
	case SavedViewQueueUnassigned:
		return "unassigned"
	default:
		return "unknown"
	}
}

func validSavedViewQueue(queue SavedViewQueue) bool {
	return queue >= SavedViewQueueAll && queue <= SavedViewQueueUnassigned
}

type SavedViewFiltersInput struct {
	States          []Key
	Severities      []string
	Priorities      []string
	AssignedTeam    *EntityID
	Assignee        *EntityID
	ClaimedBy       *EntityID
	Queue           SavedViewQueue
	CustomerVisible *bool
	Search          string
	Custom          []SavedViewCustomFilter
}

func (input SavedViewFiltersInput) String() string {
	return fmt.Sprintf(
		"SavedViewFiltersInput{states:%d,severities:%d,priorities:%d,queue:%s,custom:%d,search:[REDACTED]}",
		len(input.States), len(input.Severities), len(input.Priorities), input.Queue, len(input.Custom),
	)
}

func (input SavedViewFiltersInput) GoString() string { return input.String() }

// SavedViewFilters is canonical: set-valued fields are sorted and duplicate
// free. This makes the persisted JSON digest stable across equivalent requests.
type SavedViewFilters struct {
	states          []Key
	severities      []string
	priorities      []string
	assignedTeam    *EntityID
	assignee        *EntityID
	claimedBy       *EntityID
	queue           SavedViewQueue
	customerVisible *bool
	search          string
	custom          []SavedViewCustomFilter
}

func NewSavedViewFilters(input SavedViewFiltersInput) (SavedViewFilters, error) {
	states, statesOK := canonicalKeys(input.States, 20)
	severities, severitiesOK := canonicalSavedViewEnums(
		input.Severities, 5, []string{"informational", "low", "medium", "high", "critical"},
	)
	priorities, prioritiesOK := canonicalSavedViewEnums(
		input.Priorities, 5, []string{"low", "medium", "high", "urgent", "critical"},
	)
	if !statesOK || !severitiesOK || !prioritiesOK || !validSavedViewQueue(input.Queue) ||
		input.Search != "" && !validText(input.Search, maximumSavedViewSearchBytes, false) ||
		!validOptionalSavedViewEntity(input.AssignedTeam) ||
		!validOptionalSavedViewEntity(input.Assignee) ||
		!validOptionalSavedViewEntity(input.ClaimedBy) ||
		len(input.Custom) > maximumSavedViewFilters {
		return SavedViewFilters{}, ErrInvalidSavedView
	}
	// Empty sets have one representation. Without this normalization, nil and
	// [] would encode as JSON null and [] respectively and produce different
	// persistence/idempotency digests for the same query.
	if states == nil {
		states = []Key{}
	}
	if severities == nil {
		severities = []string{}
	}
	if priorities == nil {
		priorities = []string{}
	}
	custom := make([]SavedViewCustomFilter, len(input.Custom))
	copy(custom, input.Custom)
	slices.SortFunc(custom, func(left, right SavedViewCustomFilter) int {
		return compareEntityID(left.definition.id, right.definition.id)
	})
	filterBytes := 0
	definitionKeys := make(map[Key]struct{}, len(custom))
	for index, filter := range custom {
		if !validSavedViewCustomFilter(filter) ||
			index > 0 && custom[index-1].definition.id == filter.definition.id ||
			len(filter.canonical) > maximumSavedViewFilterBytes-filterBytes {
			return SavedViewFilters{}, ErrInvalidSavedView
		}
		if _, duplicate := definitionKeys[filter.definition.key]; duplicate {
			return SavedViewFilters{}, ErrInvalidSavedView
		}
		definitionKeys[filter.definition.key] = struct{}{}
		filterBytes += len(filter.canonical)
		custom[index].canonical = slices.Clone(filter.canonical)
	}
	return SavedViewFilters{
		states: states, severities: severities, priorities: priorities,
		assignedTeam: cloneSavedViewEntity(input.AssignedTeam),
		assignee:     cloneSavedViewEntity(input.Assignee), claimedBy: cloneSavedViewEntity(input.ClaimedBy),
		queue: input.Queue, customerVisible: cloneSavedViewBool(input.CustomerVisible),
		search: input.Search, custom: custom,
	}, nil
}

func (filters SavedViewFilters) States() []Key        { return slices.Clone(filters.states) }
func (filters SavedViewFilters) Severities() []string { return slices.Clone(filters.severities) }
func (filters SavedViewFilters) Priorities() []string { return slices.Clone(filters.priorities) }
func (filters SavedViewFilters) AssignedTeam() *EntityID {
	return cloneSavedViewEntity(filters.assignedTeam)
}
func (filters SavedViewFilters) Assignee() *EntityID   { return cloneSavedViewEntity(filters.assignee) }
func (filters SavedViewFilters) ClaimedBy() *EntityID  { return cloneSavedViewEntity(filters.claimedBy) }
func (filters SavedViewFilters) Queue() SavedViewQueue { return filters.queue }
func (filters SavedViewFilters) CustomerVisible() *bool {
	return cloneSavedViewBool(filters.customerVisible)
}
func (filters SavedViewFilters) Search() string { return filters.search }
func (filters SavedViewFilters) Custom() []SavedViewCustomFilter {
	result := make([]SavedViewCustomFilter, len(filters.custom))
	for index, filter := range filters.custom {
		result[index] = filter
		result[index].canonical = slices.Clone(filter.canonical)
	}
	return result
}

func (filters SavedViewFilters) String() string {
	return fmt.Sprintf(
		"SavedViewFilters{states:%d,severities:%d,priorities:%d,queue:%s,custom:%d,search:[REDACTED]}",
		len(filters.states), len(filters.severities), len(filters.priorities), filters.queue, len(filters.custom),
	)
}

func (filters SavedViewFilters) GoString() string { return filters.String() }

func validSavedViewFilters(filters SavedViewFilters) bool {
	rebuilt, err := NewSavedViewFilters(SavedViewFiltersInput{
		States: filters.states, Severities: filters.severities, Priorities: filters.priorities,
		AssignedTeam: filters.assignedTeam, Assignee: filters.assignee, ClaimedBy: filters.claimedBy,
		Queue: filters.queue, CustomerVisible: filters.customerVisible,
		Search: filters.search, Custom: filters.custom,
	})
	return err == nil && reflect.DeepEqual(rebuilt, filters)
}

func canonicalSavedViewEnums(values []string, maximum int, allowed []string) ([]string, bool) {
	if len(values) > maximum {
		return nil, false
	}
	result := slices.Clone(values)
	slices.Sort(result)
	for index, value := range result {
		if !slices.Contains(allowed, value) || index > 0 && result[index-1] == value {
			return nil, false
		}
	}
	return result, true
}

func validOptionalSavedViewEntity(value *EntityID) bool {
	return value == nil || validEntityID(*value)
}

func cloneSavedViewEntity(value *EntityID) *EntityID {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneSavedViewBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

type SavedViewColumnSource uint8

const (
	SavedViewColumnCore SavedViewColumnSource = iota + 1
	SavedViewColumnCustomField
	SavedViewColumnSLA
)

func (source SavedViewColumnSource) String() string {
	switch source {
	case SavedViewColumnCore:
		return "core"
	case SavedViewColumnCustomField:
		return "custom_field"
	case SavedViewColumnSLA:
		return "sla"
	default:
		return "unknown"
	}
}

func validSavedViewColumnSource(source SavedViewColumnSource) bool {
	return source >= SavedViewColumnCore && source <= SavedViewColumnSLA
}

type SavedViewColumnPin uint8

const (
	SavedViewColumnUnpinned SavedViewColumnPin = iota + 1
	SavedViewColumnPinnedStart
	SavedViewColumnPinnedEnd
)

func (pin SavedViewColumnPin) String() string {
	switch pin {
	case SavedViewColumnUnpinned:
		return "none"
	case SavedViewColumnPinnedStart:
		return "start"
	case SavedViewColumnPinnedEnd:
		return "end"
	default:
		return "unknown"
	}
}

func validSavedViewColumnPin(pin SavedViewColumnPin) bool {
	return pin >= SavedViewColumnUnpinned && pin <= SavedViewColumnPinnedEnd
}

type SavedViewColumn struct {
	source     SavedViewColumnSource
	coreKey    Key
	definition SavedViewDefinitionPin
	width      uint16
	visible    bool
	pin        SavedViewColumnPin
}

func NewSavedViewCoreColumn(
	key Key,
	width uint16,
	visible bool,
	pin SavedViewColumnPin,
) (SavedViewColumn, error) {
	if !savedViewCoreColumn(key) || !validSavedViewColumnShape(width, pin) {
		return SavedViewColumn{}, ErrInvalidSavedView
	}
	return SavedViewColumn{
		source: SavedViewColumnCore, coreKey: key, width: width, visible: visible, pin: pin,
	}, nil
}

func NewSavedViewDynamicColumn(
	source SavedViewColumnSource,
	definition SavedViewDefinitionPin,
	width uint16,
	visible bool,
	pin SavedViewColumnPin,
) (SavedViewColumn, error) {
	if source != SavedViewColumnCustomField && source != SavedViewColumnSLA ||
		!validSavedViewDefinitionPin(definition) || !validSavedViewColumnShape(width, pin) {
		return SavedViewColumn{}, ErrInvalidSavedView
	}
	return SavedViewColumn{
		source: source, definition: definition, width: width, visible: visible, pin: pin,
	}, nil
}

func (column SavedViewColumn) Source() SavedViewColumnSource { return column.source }
func (column SavedViewColumn) CoreKey() (Key, bool) {
	return column.coreKey, column.source == SavedViewColumnCore
}
func (column SavedViewColumn) Definition() (SavedViewDefinitionPin, bool) {
	return column.definition, column.source != SavedViewColumnCore
}
func (column SavedViewColumn) Width() uint16           { return column.width }
func (column SavedViewColumn) Visible() bool           { return column.visible }
func (column SavedViewColumn) Pin() SavedViewColumnPin { return column.pin }
func (column SavedViewColumn) Identifier() string {
	if column.source == SavedViewColumnCore {
		return "core:" + column.coreKey.String()
	}
	return fmt.Sprintf(
		"%s:%s:%d", column.source, column.definition.id, column.definition.version,
	)
}

func validSavedViewColumn(column SavedViewColumn) bool {
	if !validSavedViewColumnSource(column.source) || !validSavedViewColumnShape(column.width, column.pin) {
		return false
	}
	if column.source == SavedViewColumnCore {
		return savedViewCoreColumn(column.coreKey) && column.definition == (SavedViewDefinitionPin{})
	}
	return column.coreKey == (Key{}) && validSavedViewDefinitionPin(column.definition)
}

func validSavedViewColumnShape(width uint16, pin SavedViewColumnPin) bool {
	return validSavedViewColumnPin(pin) &&
		(width == 0 || width >= minimumSavedViewColumnWidth && width <= maximumSavedViewColumnWidth)
}

func savedViewCoreColumn(key Key) bool {
	switch key.String() {
	case "ticket", "state", "risk", "assignment", "category", "source",
		"customer_visibility", "created", "updated":
		return true
	default:
		return false
	}
}

type SavedViewSortDirection uint8

const (
	SavedViewSortAscending SavedViewSortDirection = iota + 1
	SavedViewSortDescending
)

func (direction SavedViewSortDirection) String() string {
	if direction == SavedViewSortAscending {
		return "asc"
	}
	if direction == SavedViewSortDescending {
		return "desc"
	}
	return "unknown"
}

func validSavedViewSortDirection(direction SavedViewSortDirection) bool {
	return direction == SavedViewSortAscending || direction == SavedViewSortDescending
}

type SavedViewNullOrder uint8

const (
	SavedViewNullsFirst SavedViewNullOrder = iota + 1
	SavedViewNullsLast
)

func (order SavedViewNullOrder) String() string {
	if order == SavedViewNullsFirst {
		return "first"
	}
	if order == SavedViewNullsLast {
		return "last"
	}
	return "unknown"
}

func validSavedViewNullOrder(order SavedViewNullOrder) bool {
	return order == SavedViewNullsFirst || order == SavedViewNullsLast
}

type SavedViewSort struct {
	source     SavedViewColumnSource
	coreKey    Key
	definition SavedViewDefinitionPin
	direction  SavedViewSortDirection
	nulls      SavedViewNullOrder
}

func NewSavedViewCoreSort(key Key, direction SavedViewSortDirection) (SavedViewSort, error) {
	if !savedViewCoreSort(key, direction) {
		return SavedViewSort{}, ErrInvalidSavedView
	}
	return SavedViewSort{
		source: SavedViewColumnCore, coreKey: key, direction: direction, nulls: SavedViewNullsLast,
	}, nil
}

func NewSavedViewDynamicSort(
	source SavedViewColumnSource,
	definition SavedViewDefinitionPin,
	direction SavedViewSortDirection,
	nulls SavedViewNullOrder,
) (SavedViewSort, error) {
	if source != SavedViewColumnCustomField && source != SavedViewColumnSLA ||
		!validSavedViewDefinitionPin(definition) || !validSavedViewSortDirection(direction) ||
		!validSavedViewNullOrder(nulls) {
		return SavedViewSort{}, ErrInvalidSavedView
	}
	return SavedViewSort{
		source: source, definition: definition, direction: direction, nulls: nulls,
	}, nil
}

func (sort SavedViewSort) Source() SavedViewColumnSource { return sort.source }
func (sort SavedViewSort) CoreKey() (Key, bool) {
	return sort.coreKey, sort.source == SavedViewColumnCore
}
func (sort SavedViewSort) Definition() (SavedViewDefinitionPin, bool) {
	return sort.definition, sort.source != SavedViewColumnCore
}
func (sort SavedViewSort) Direction() SavedViewSortDirection { return sort.direction }
func (sort SavedViewSort) Nulls() SavedViewNullOrder         { return sort.nulls }

func validSavedViewSort(sort SavedViewSort) bool {
	if sort.source == SavedViewColumnCore {
		return savedViewCoreSort(sort.coreKey, sort.direction) &&
			sort.definition == (SavedViewDefinitionPin{}) && sort.nulls == SavedViewNullsLast
	}
	return (sort.source == SavedViewColumnCustomField || sort.source == SavedViewColumnSLA) &&
		sort.coreKey == (Key{}) && validSavedViewDefinitionPin(sort.definition) &&
		validSavedViewSortDirection(sort.direction) && validSavedViewNullOrder(sort.nulls)
}

func savedViewCoreSort(key Key, direction SavedViewSortDirection) bool {
	if !validSavedViewSortDirection(direction) {
		return false
	}
	switch key.String() {
	case "updated_at", "created_at", "priority":
		return true
	case "oldest_unclaimed":
		return direction == SavedViewSortAscending
	default:
		return false
	}
}

// SavedViewSpec is the immutable, bounded query-and-layout value persisted in
// a private saved view. Runtime use still rechecks live ticket authority and
// every pinned dynamic definition; possession of a view ID grants nothing.
type SavedViewSpec struct {
	filters SavedViewFilters
	sort    SavedViewSort
	columns []SavedViewColumn
}

func NewSavedViewSpec(
	tenant EntityID,
	kind AggregateKind,
	filters SavedViewFilters,
	sort SavedViewSort,
	columns []SavedViewColumn,
) (SavedViewSpec, error) {
	if !validEntityID(tenant) || !validAggregateKind(kind) || !validSavedViewSort(sort) ||
		!validSavedViewFilters(filters) || len(columns) == 0 || len(columns) > maximumSavedViewColumns {
		return SavedViewSpec{}, ErrInvalidSavedView
	}
	definitionPins := make(map[string]SavedViewDefinitionPin, len(filters.custom)+len(columns))
	definitionKeys := make(map[string]SavedViewDefinitionPin, len(filters.custom)+len(columns))
	for _, filter := range filters.custom {
		if filter.tenant != tenant || filter.kind != kind {
			return SavedViewSpec{}, ErrInvalidSavedView
		}
		definitionPins[savedViewDynamicIdentifier(SavedViewColumnCustomField, filter.definition)] = filter.definition
		definitionKeys[savedViewDynamicKey(SavedViewColumnCustomField, filter.definition)] = filter.definition
	}
	resultColumns := slices.Clone(columns)
	identifiers := make(map[string]struct{}, len(resultColumns))
	dynamicPins := make(map[string]SavedViewDefinitionPin, len(resultColumns))
	visible := 0
	identityVisible := false
	for _, column := range resultColumns {
		if !validSavedViewColumn(column) ||
			column.source != SavedViewColumnCore &&
				(column.definition.tenant != tenant || column.definition.kind != kind) {
			return SavedViewSpec{}, ErrInvalidSavedView
		}
		identifier := column.Identifier()
		if column.source != SavedViewColumnCore {
			// One live definition can occupy only one table position even when a
			// tampered stored document claims multiple historical versions.
			identifier = savedViewDynamicIdentifier(column.source, column.definition)
			if pinned, exists := definitionPins[identifier]; exists && pinned != column.definition {
				return SavedViewSpec{}, ErrInvalidSavedView
			}
			key := savedViewDynamicKey(column.source, column.definition)
			if pinned, exists := definitionKeys[key]; exists && pinned != column.definition {
				return SavedViewSpec{}, ErrInvalidSavedView
			}
			definitionPins[identifier] = column.definition
			definitionKeys[key] = column.definition
			dynamicPins[identifier] = column.definition
		}
		if _, duplicate := identifiers[identifier]; duplicate {
			return SavedViewSpec{}, ErrInvalidSavedView
		}
		identifiers[identifier] = struct{}{}
		if column.visible {
			visible++
			identityVisible = identityVisible ||
				column.source == SavedViewColumnCore && column.coreKey.String() == "ticket"
		}
	}
	if visible == 0 || !identityVisible {
		return SavedViewSpec{}, ErrInvalidSavedView
	}
	if sort.source != SavedViewColumnCore {
		if sort.definition.tenant != tenant || sort.definition.kind != kind {
			return SavedViewSpec{}, ErrInvalidSavedView
		}
		identifier := savedViewDynamicIdentifier(sort.source, sort.definition)
		if projected, exists := dynamicPins[identifier]; !exists || projected != sort.definition {
			return SavedViewSpec{}, ErrInvalidSavedView
		}
	}
	return SavedViewSpec{
		filters: cloneSavedViewFilters(filters), sort: sort, columns: resultColumns,
	}, nil
}

func savedViewDynamicIdentifier(
	source SavedViewColumnSource,
	definition SavedViewDefinitionPin,
) string {
	return fmt.Sprintf("%s:%s", source, definition.id)
}

func savedViewDynamicKey(
	source SavedViewColumnSource,
	definition SavedViewDefinitionPin,
) string {
	return fmt.Sprintf("%s:%s", source, definition.key)
}

// ValidateSavedViewSpec lets application and persistence boundaries recheck a
// reconstructed stored value without gaining access to its internal slices.
func ValidateSavedViewSpec(tenant EntityID, kind AggregateKind, spec SavedViewSpec) error {
	_, err := NewSavedViewSpec(tenant, kind, spec.filters, spec.sort, spec.columns)
	return err
}

func (spec SavedViewSpec) Filters() SavedViewFilters  { return cloneSavedViewFilters(spec.filters) }
func (spec SavedViewSpec) Sort() SavedViewSort        { return spec.sort }
func (spec SavedViewSpec) Columns() []SavedViewColumn { return slices.Clone(spec.columns) }
func (spec SavedViewSpec) String() string {
	return fmt.Sprintf(
		"SavedViewSpec{filters:%d,columns:%d,metadata:[REDACTED]}",
		len(spec.filters.custom), len(spec.columns),
	)
}

func (spec SavedViewSpec) GoString() string { return spec.String() }

func cloneSavedViewFilters(filters SavedViewFilters) SavedViewFilters {
	result := filters
	result.states = slices.Clone(filters.states)
	result.severities = slices.Clone(filters.severities)
	result.priorities = slices.Clone(filters.priorities)
	result.assignedTeam = cloneSavedViewEntity(filters.assignedTeam)
	result.assignee = cloneSavedViewEntity(filters.assignee)
	result.claimedBy = cloneSavedViewEntity(filters.claimedBy)
	result.customerVisible = cloneSavedViewBool(filters.customerVisible)
	result.custom = filters.Custom()
	return result
}

func cloneSavedViewSpec(spec SavedViewSpec) SavedViewSpec {
	return SavedViewSpec{
		filters: cloneSavedViewFilters(spec.filters), sort: spec.sort, columns: slices.Clone(spec.columns),
	}
}

func sameSavedViewSpec(left, right SavedViewSpec) bool {
	return reflect.DeepEqual(left, right)
}

type SavedViewStatus uint8

const (
	SavedViewActive SavedViewStatus = iota + 1
	SavedViewArchived
)

func (status SavedViewStatus) String() string {
	if status == SavedViewActive {
		return "active"
	}
	if status == SavedViewArchived {
		return "archived"
	}
	return "unknown"
}

func validSavedViewStatus(status SavedViewStatus) bool {
	return status == SavedViewActive || status == SavedViewArchived
}

type SavedView struct {
	id       EntityID
	tenant   EntityID
	owner    EntityID
	kind     AggregateKind
	name     string
	spec     SavedViewSpec
	status   SavedViewStatus
	revision uint64
}

func NewSavedView(
	id EntityID,
	tenant EntityID,
	owner EntityID,
	kind AggregateKind,
	name string,
	spec SavedViewSpec,
	status SavedViewStatus,
	revision uint64,
) (SavedView, error) {
	if !validEntityID(id) || !validEntityID(tenant) || !validEntityID(owner) ||
		!validAggregateKind(kind) || !validText(name, maximumSavedViewNameBytes, false) ||
		!validSavedViewStatus(status) || revision == 0 || revision > maxVersion {
		return SavedView{}, ErrInvalidSavedView
	}
	if _, err := NewSavedViewSpec(tenant, kind, spec.filters, spec.sort, spec.columns); err != nil {
		return SavedView{}, ErrInvalidSavedView
	}
	return SavedView{
		id: id, tenant: tenant, owner: owner, kind: kind, name: name,
		spec: cloneSavedViewSpec(spec), status: status, revision: revision,
	}, nil
}

func (view SavedView) ID() EntityID            { return view.id }
func (view SavedView) Tenant() EntityID        { return view.tenant }
func (view SavedView) Owner() EntityID         { return view.owner }
func (view SavedView) Kind() AggregateKind     { return view.kind }
func (view SavedView) Name() string            { return view.name }
func (view SavedView) Spec() SavedViewSpec     { return cloneSavedViewSpec(view.spec) }
func (view SavedView) Status() SavedViewStatus { return view.status }
func (view SavedView) Revision() uint64        { return view.revision }
func (view SavedView) String() string {
	return fmt.Sprintf(
		"SavedView{kind:%s,status:%s,revision:%d,filters:%d,columns:%d,metadata:[REDACTED]}",
		view.kind, view.status, view.revision, len(view.spec.filters.custom), len(view.spec.columns),
	)
}

func (view SavedView) GoString() string { return view.String() }

func validSavedView(view SavedView) bool {
	rebuilt, err := NewSavedView(
		view.id, view.tenant, view.owner, view.kind, view.name,
		view.spec, view.status, view.revision,
	)
	return err == nil && sameSavedView(rebuilt, view)
}

func sameSavedView(left, right SavedView) bool {
	return left.id == right.id && left.tenant == right.tenant && left.owner == right.owner &&
		left.kind == right.kind && left.name == right.name && left.status == right.status &&
		left.revision == right.revision && sameSavedViewSpec(left.spec, right.spec)
}

type SavedViewAction uint8

const (
	SavedViewCreate SavedViewAction = iota + 1
	SavedViewReplace
	SavedViewArchive
	SavedViewRestore
)

func (action SavedViewAction) String() string {
	switch action {
	case SavedViewCreate:
		return "create"
	case SavedViewReplace:
		return "replace"
	case SavedViewArchive:
		return "archive"
	case SavedViewRestore:
		return "restore"
	default:
		return "unknown"
	}
}

type SavedViewPlan struct {
	action           SavedViewAction
	expectedRevision uint64
	next             SavedView
}

func (plan SavedViewPlan) Action() SavedViewAction  { return plan.action }
func (plan SavedViewPlan) ExpectedRevision() uint64 { return plan.expectedRevision }
func (plan SavedViewPlan) Next() SavedView          { return cloneSavedView(plan.next) }
func (plan SavedViewPlan) String() string {
	return fmt.Sprintf(
		"SavedViewPlan{action:%s,expected_revision:%d,next_revision:%d}",
		plan.action, plan.expectedRevision, plan.next.revision,
	)
}

func (plan SavedViewPlan) GoString() string { return plan.String() }

func PlanSavedViewCreation(
	id EntityID,
	tenant EntityID,
	owner EntityID,
	kind AggregateKind,
	name string,
	spec SavedViewSpec,
) (SavedViewPlan, error) {
	next, err := NewSavedView(id, tenant, owner, kind, name, spec, SavedViewActive, 1)
	if err != nil {
		return SavedViewPlan{}, err
	}
	return SavedViewPlan{action: SavedViewCreate, next: next}, nil
}

func PlanSavedViewReplacement(
	current SavedView,
	expectedRevision uint64,
	name string,
	spec SavedViewSpec,
) (SavedViewPlan, error) {
	if err := validateSavedViewMutation(current, expectedRevision, true); err != nil {
		return SavedViewPlan{}, err
	}
	if current.name == name && sameSavedViewSpec(current.spec, spec) {
		return SavedViewPlan{}, ErrSavedViewNoChange
	}
	next, err := NewSavedView(
		current.id, current.tenant, current.owner, current.kind, name,
		spec, current.status, current.revision+1,
	)
	if err != nil {
		return SavedViewPlan{}, err
	}
	return SavedViewPlan{
		action: SavedViewReplace, expectedRevision: expectedRevision, next: next,
	}, nil
}

func PlanSavedViewArchive(current SavedView, expectedRevision uint64) (SavedViewPlan, error) {
	if err := validateSavedViewMutation(current, expectedRevision, true); err != nil {
		return SavedViewPlan{}, err
	}
	next, err := NewSavedView(
		current.id, current.tenant, current.owner, current.kind, current.name,
		current.spec, SavedViewArchived, current.revision+1,
	)
	if err != nil {
		return SavedViewPlan{}, err
	}
	return SavedViewPlan{action: SavedViewArchive, expectedRevision: expectedRevision, next: next}, nil
}

func PlanSavedViewRestore(current SavedView, expectedRevision uint64) (SavedViewPlan, error) {
	if err := validateSavedViewMutation(current, expectedRevision, false); err != nil {
		return SavedViewPlan{}, err
	}
	next, err := NewSavedView(
		current.id, current.tenant, current.owner, current.kind, current.name,
		current.spec, SavedViewActive, current.revision+1,
	)
	if err != nil {
		return SavedViewPlan{}, err
	}
	return SavedViewPlan{action: SavedViewRestore, expectedRevision: expectedRevision, next: next}, nil
}

func validateSavedViewMutation(current SavedView, expectedRevision uint64, requireActive bool) error {
	if !validSavedView(current) || expectedRevision == 0 || expectedRevision > maxVersion ||
		current.revision == maxVersion {
		return ErrInvalidSavedView
	}
	if current.revision != expectedRevision {
		return ErrSavedViewConflict
	}
	if requireActive && current.status != SavedViewActive {
		return ErrSavedViewInactive
	}
	if !requireActive && current.status != SavedViewArchived {
		return ErrSavedViewAlreadyActive
	}
	return nil
}

func cloneSavedView(view SavedView) SavedView {
	result := view
	result.spec = cloneSavedViewSpec(view.spec)
	return result
}
