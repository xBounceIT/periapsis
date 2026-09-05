package customfields

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"slices"
	"unicode/utf8"
)

const (
	ImportProjectionVersion   = uint64(1)
	ImportMaximumRows         = 10_000
	ImportMaximumDefinitions  = 512
	ImportMaximumFieldsPerRow = 512
	ImportMaximumCells        = 100_000
	ImportMaximumPayloadBytes = 32 * 1024 * 1024
	ImportMaximumAttempts     = uint8(5)
)

var (
	ErrInvalidImportManifest    = fmt.Errorf("invalid custom-field import manifest")
	ErrImportDefinitionConflict = fmt.Errorf("custom-field import definition pin conflict")
	ErrInvalidImportRow         = fmt.Errorf("invalid custom-field import row")
	ErrInvalidImportRowResult   = fmt.Errorf("invalid custom-field import row result")
	ErrInvalidImportJob         = fmt.Errorf("invalid custom-field import job")
	ErrImportJobConflict        = fmt.Errorf("custom-field import transition does not apply")
)

type ImportMode uint8

const (
	ImportDryRun ImportMode = iota + 1
	ImportCommit
)

func (mode ImportMode) String() string {
	switch mode {
	case ImportDryRun:
		return "dry_run"
	case ImportCommit:
		return "commit"
	default:
		return "unknown"
	}
}

func validImportMode(mode ImportMode) bool {
	return mode == ImportDryRun || mode == ImportCommit
}

// ImportCell is the canonical transport-independent representation of one
// input cell. Missing, explicit null, and a present empty string are three
// different values and remain different in the manifest digest.
type ImportCell struct {
	key      Key
	presence Presence
	value    InputValue
}

func (cell ImportCell) Key() Key           { return cell.key }
func (cell ImportCell) Presence() Presence { return cell.presence }
func (cell ImportCell) InputValue() InputValue {
	if cell.presence == PresenceMissing {
		return MissingInputValue()
	}
	return JSONInputValue(cell.value.raw)
}
func (cell ImportCell) String() string {
	return fmt.Sprintf("ImportCell{presence:%d,key:[REDACTED],value:[REDACTED]}", cell.presence)
}
func (cell ImportCell) GoString() string { return cell.String() }

type ImportRowInput struct {
	Sequence        uint32
	Target          EntityID
	ExpectedVersion uint64
	Fields          []FieldInput
}

type ImportRow struct {
	sequence        uint32
	target          EntityID
	expectedVersion uint64
	cells           []ImportCell
}

func (row ImportRow) Sequence() uint32        { return row.sequence }
func (row ImportRow) Target() EntityID        { return row.target }
func (row ImportRow) ExpectedVersion() uint64 { return row.expectedVersion }
func (row ImportRow) Cells() []ImportCell     { return cloneImportCells(row.cells) }
func (row ImportRow) String() string {
	return fmt.Sprintf(
		"ImportRow{sequence:%d,expected_version:%d,fields:%d,target:[REDACTED],values:[REDACTED]}",
		row.sequence, row.expectedVersion, len(row.cells),
	)
}
func (row ImportRow) GoString() string { return row.String() }

type ImportDefinitionPin struct {
	id            EntityID
	key           Key
	schemaVersion uint64
	fingerprint   [sha256.Size]byte
}

func (pin ImportDefinitionPin) ID() EntityID                   { return pin.id }
func (pin ImportDefinitionPin) Key() Key                       { return pin.key }
func (pin ImportDefinitionPin) SchemaVersion() uint64          { return pin.schemaVersion }
func (pin ImportDefinitionPin) Fingerprint() [sha256.Size]byte { return pin.fingerprint }
func (pin ImportDefinitionPin) String() string {
	return fmt.Sprintf(
		"ImportDefinitionPin{schema_version:%d,identity:[REDACTED],fingerprint:[REDACTED]}",
		pin.schemaVersion,
	)
}
func (pin ImportDefinitionPin) GoString() string { return pin.String() }

type ImportManifestInput struct {
	ID                EntityID
	Tenant            EntityID
	Requester         EntityID
	OwnerMembership   EntityID
	ObjectType        ObjectType
	Mode              ImportMode
	Definitions       []Definition
	Rows              []ImportRowInput
	ProjectionVersion uint64
	MaximumAttempts   uint8
}

type ImportManifest struct {
	id                EntityID
	tenant            EntityID
	requester         EntityID
	ownerMembership   EntityID
	objectType        ObjectType
	mode              ImportMode
	definitions       []Definition
	pins              []ImportDefinitionPin
	rows              []ImportRow
	requestDigest     [sha256.Size]byte
	projectionVersion uint64
	maximumAttempts   uint8
}

func NewImportManifest(input ImportManifestInput) (ImportManifest, error) {
	if !validEntityID(input.ID) || !validEntityID(input.Tenant) ||
		!validEntityID(input.Requester) || !validEntityID(input.OwnerMembership) ||
		!validObjectType(input.ObjectType) || !validImportMode(input.Mode) ||
		len(input.Rows) == 0 || len(input.Rows) > ImportMaximumRows ||
		len(input.Definitions) > ImportMaximumDefinitions ||
		input.ProjectionVersion != ImportProjectionVersion || input.MaximumAttempts == 0 ||
		input.MaximumAttempts > ImportMaximumAttempts {
		return ImportManifest{}, ErrInvalidImportManifest
	}

	definitionsByKey := make(map[Key]Definition, len(input.Definitions))
	definitionsByID := make(map[EntityID]struct{}, len(input.Definitions))
	for _, source := range input.Definitions {
		definition := cloneImportDefinition(source)
		if definition.tenantID != input.Tenant || definition.objectType != input.ObjectType ||
			!validKey(definition.key.value) || definition.schemaVersion == 0 ||
			definition.schemaVersion >= maximumDefinitionVersion || !validImportDefinition(definition) {
			return ImportManifest{}, ErrInvalidImportManifest
		}
		if _, duplicate := definitionsByKey[definition.key]; duplicate {
			return ImportManifest{}, ErrInvalidImportManifest
		}
		if _, duplicate := definitionsByID[definition.id]; duplicate {
			return ImportManifest{}, ErrInvalidImportManifest
		}
		definitionsByKey[definition.key] = definition
		definitionsByID[definition.id] = struct{}{}
	}

	rows := make([]ImportRow, len(input.Rows))
	referencedKeys := make(map[Key]struct{})
	seenTargets := make(map[EntityID]struct{}, len(input.Rows))
	payloadBytes := 0
	cellCount := 0
	for index, source := range input.Rows {
		row, size, err := canonicalImportRow(source)
		if err != nil || row.sequence != uint32(index+1) {
			return ImportManifest{}, ErrInvalidImportManifest
		}
		if _, duplicate := seenTargets[row.target]; duplicate {
			return ImportManifest{}, ErrInvalidImportManifest
		}
		seenTargets[row.target] = struct{}{}
		payloadBytes += size
		cellCount += len(row.cells)
		if payloadBytes > ImportMaximumPayloadBytes || cellCount > ImportMaximumCells {
			return ImportManifest{}, ErrInvalidImportManifest
		}
		for _, cell := range row.cells {
			if cell.presence != PresenceMissing {
				referencedKeys[cell.key] = struct{}{}
			}
		}
		rows[index] = row
	}

	definitions := make([]Definition, 0, len(referencedKeys))
	for key := range referencedKeys {
		if definition, exists := definitionsByKey[key]; exists {
			definitions = append(definitions, cloneImportDefinition(definition))
		}
	}
	slices.SortFunc(definitions, func(left, right Definition) int {
		return compareKeys(left.key, right.key)
	})
	pins := make([]ImportDefinitionPin, len(definitions))
	for index, definition := range definitions {
		pins[index] = importDefinitionPin(definition)
	}

	manifest := ImportManifest{
		id: input.ID, tenant: input.Tenant, requester: input.Requester,
		ownerMembership: input.OwnerMembership, objectType: input.ObjectType, mode: input.Mode,
		definitions: definitions, pins: pins, rows: rows,
		projectionVersion: input.ProjectionVersion, maximumAttempts: input.MaximumAttempts,
	}
	manifest.requestDigest = digestImportManifestRequest(manifest)
	return manifest, nil
}

func (manifest ImportManifest) ID() EntityID              { return manifest.id }
func (manifest ImportManifest) Tenant() EntityID          { return manifest.tenant }
func (manifest ImportManifest) Requester() EntityID       { return manifest.requester }
func (manifest ImportManifest) OwnerMembership() EntityID { return manifest.ownerMembership }
func (manifest ImportManifest) ObjectType() ObjectType    { return manifest.objectType }
func (manifest ImportManifest) Mode() ImportMode          { return manifest.mode }
func (manifest ImportManifest) Definitions() []Definition {
	return cloneImportDefinitions(manifest.definitions)
}
func (manifest ImportManifest) DefinitionPins() []ImportDefinitionPin {
	return slices.Clone(manifest.pins)
}
func (manifest ImportManifest) Rows() []ImportRow                { return cloneImportRows(manifest.rows) }
func (manifest ImportManifest) RequestDigest() [sha256.Size]byte { return manifest.requestDigest }
func (manifest ImportManifest) ProjectionVersion() uint64        { return manifest.projectionVersion }
func (manifest ImportManifest) MaximumAttempts() uint8           { return manifest.maximumAttempts }
func (manifest ImportManifest) String() string {
	return fmt.Sprintf(
		"ImportManifest{object:%s,mode:%s,rows:%d,definitions:%d,projection_version:%d,metadata:[REDACTED]}",
		manifest.objectType, manifest.mode, len(manifest.rows), len(manifest.definitions), manifest.projectionVersion,
	)
}
func (manifest ImportManifest) GoString() string { return manifest.String() }

func ValidateImportManifest(manifest ImportManifest) error {
	rows := make([]ImportRowInput, len(manifest.rows))
	for index, row := range manifest.rows {
		fields := make([]FieldInput, len(row.cells))
		for fieldIndex, cell := range row.cells {
			fields[fieldIndex] = FieldInput{Key: cell.key, Value: cell.InputValue()}
		}
		rows[index] = ImportRowInput{
			Sequence: row.sequence, Target: row.target,
			ExpectedVersion: row.expectedVersion, Fields: fields,
		}
	}
	rebuilt, err := NewImportManifest(ImportManifestInput{
		ID: manifest.id, Tenant: manifest.tenant, Requester: manifest.requester,
		OwnerMembership: manifest.ownerMembership, ObjectType: manifest.objectType,
		Mode: manifest.mode, Definitions: manifest.definitions, Rows: rows,
		ProjectionVersion: manifest.projectionVersion, MaximumAttempts: manifest.maximumAttempts,
	})
	if err != nil || !sameImportManifest(rebuilt, manifest) {
		return ErrInvalidImportManifest
	}
	return nil
}

// SameImportRequest deliberately ignores the server-generated manifest ID.
// It is the exact-replay comparison used behind an idempotency key.
func SameImportRequest(left, right ImportManifest) bool {
	return ValidateImportManifest(left) == nil && ValidateImportManifest(right) == nil &&
		left.requestDigest == right.requestDigest
}

func MatchImportDefinitionPins(manifest ImportManifest, current []Definition) error {
	if ValidateImportManifest(manifest) != nil || len(current) != len(manifest.pins) {
		return ErrImportDefinitionConflict
	}
	pins := make([]ImportDefinitionPin, len(current))
	for index, definition := range current {
		if definition.tenantID != manifest.tenant || definition.objectType != manifest.objectType ||
			!validImportDefinition(definition) {
			return ErrImportDefinitionConflict
		}
		pins[index] = importDefinitionPin(definition)
	}
	slices.SortFunc(pins, func(left, right ImportDefinitionPin) int {
		return compareKeys(left.key, right.key)
	})
	if !slices.Equal(pins, manifest.pins) {
		return ErrImportDefinitionConflict
	}
	return nil
}

func validImportDefinition(definition Definition) bool {
	options := make([]OptionInput, len(definition.options))
	for index, option := range definition.options {
		options[index] = OptionInput{
			ID: option.id, Key: option.key, Label: option.label,
			Position: option.position, Archived: option.archived,
		}
	}
	defaultValue := MissingInputValue()
	if definition.defaultValue.presence != PresenceMissing {
		defaultValue = JSONInputValue(definition.defaultValue.canonical)
	}
	rebuilt, err := NewDefinition(DefinitionInput{
		ID: definition.id, TenantID: definition.tenantID, ObjectType: definition.objectType,
		Key: definition.key, Label: definition.label, Description: definition.description,
		DataType: definition.dataType, Required: definition.required, Nullable: definition.nullable,
		Default: defaultValue, Constraints: ConstraintsInput{
			MinimumLength: cloneUint32(definition.constraints.minimumLength),
			MaximumLength: cloneUint32(definition.constraints.maximumLength),
			Minimum:       definition.constraints.minimum, Maximum: definition.constraints.maximum,
			Pattern: definition.constraints.pattern,
		},
		Options: options, Visibility: definition.visibility, EditPolicy: definition.editPolicy,
		Placement: definition.placement, RequiredOnTransitions: definition.requiredOnTransitions,
		Searchable: definition.searchable, Filterable: definition.filterable,
		Sortable: definition.sortable, AllowStructuredJSON: definition.allowStructuredJSON,
		Archived: definition.archived, SchemaVersion: definition.schemaVersion,
	})
	return err == nil && reflect.DeepEqual(rebuilt, definition)
}

func canonicalImportRow(input ImportRowInput) (ImportRow, int, error) {
	if input.Sequence == 0 || !validEntityID(input.Target) || input.ExpectedVersion == 0 ||
		input.ExpectedVersion >= maximumDefinitionVersion || len(input.Fields) > ImportMaximumFieldsPerRow {
		return ImportRow{}, 0, ErrInvalidImportRow
	}
	cells := make([]ImportCell, len(input.Fields))
	payloadBytes := 0
	for index, field := range input.Fields {
		if !validKey(field.Key.value) {
			return ImportRow{}, 0, ErrInvalidImportRow
		}
		cell, size, err := canonicalImportCell(field)
		if err != nil {
			return ImportRow{}, 0, err
		}
		cells[index] = cell
		payloadBytes += size + len(field.Key.value)
	}
	slices.SortFunc(cells, func(left, right ImportCell) int {
		return compareKeys(left.key, right.key)
	})
	for index := 1; index < len(cells); index++ {
		if cells[index-1].key == cells[index].key {
			return ImportRow{}, 0, ErrInvalidImportRow
		}
	}
	return ImportRow{
		sequence: input.Sequence, target: input.Target,
		expectedVersion: input.ExpectedVersion, cells: cells,
	}, payloadBytes, nil
}

func canonicalImportCell(field FieldInput) (ImportCell, int, error) {
	if !field.Value.provided {
		if len(field.Value.raw) != 0 {
			return ImportCell{}, 0, ErrInvalidImportRow
		}
		return ImportCell{key: field.Key, presence: PresenceMissing}, 0, nil
	}
	canonical, ok := canonicalImportJSON(field.Value.raw)
	if !ok {
		return ImportCell{}, 0, ErrInvalidImportRow
	}
	presence := PresencePresent
	if bytes.Equal(canonical, []byte("null")) {
		presence = PresenceNull
	}
	return ImportCell{
		key: field.Key, presence: presence, value: JSONInputValue(canonical),
	}, len(field.Value.raw), nil
}

func canonicalImportJSON(raw json.RawMessage) (json.RawMessage, bool) {
	if len(raw) == 0 || len(raw) > maximumJSONBytes || !utf8.Valid(raw) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	count := 0
	value, ok := decodeImportJSONValue(decoder, 0, &count)
	if !ok || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, false
	}
	canonical, err := json.Marshal(value)
	return canonical, err == nil && len(canonical) <= maximumJSONBytes
}

func decodeImportJSONValue(decoder *json.Decoder, depth int, count *int) (any, bool) {
	if depth > maximumJSONDepth || *count >= maximumJSONValues {
		return nil, false
	}
	*count++
	token, err := decoder.Token()
	if err != nil {
		return nil, false
	}
	switch typed := token.(type) {
	case nil, bool, string:
		return typed, true
	case json.Number:
		// The manifest accepts every syntactically valid JSON number. The
		// pinned field validator later decides whether that number is valid for
		// its concrete data type, yielding a per-row error instead of rejecting
		// the entire asynchronous request.
		return typed, true
	case json.Delim:
		switch typed {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, keyOK := keyToken.(string)
				if keyErr != nil || !keyOK || len(key) > maximumJSONBytes {
					return nil, false
				}
				if _, duplicate := object[key]; duplicate {
					return nil, false
				}
				child, childOK := decodeImportJSONValue(decoder, depth+1, count)
				if !childOK {
					return nil, false
				}
				object[key] = child
			}
			closing, closeErr := decoder.Token()
			return object, closeErr == nil && closing == json.Delim('}')
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				child, childOK := decodeImportJSONValue(decoder, depth+1, count)
				if !childOK {
					return nil, false
				}
				array = append(array, child)
			}
			closing, closeErr := decoder.Token()
			return array, closeErr == nil && closing == json.Delim(']')
		}
	}
	return nil, false
}

type importDefinitionFingerprint struct {
	ID                    string
	Tenant                string
	ObjectType            ObjectType
	Key                   string
	Label                 string
	Description           string
	DataType              DataType
	Required              bool
	Nullable              bool
	DefaultPresence       Presence
	Default               json.RawMessage
	MinimumLength         *uint32
	MaximumLength         *uint32
	Minimum               string
	Maximum               string
	Pattern               string
	Options               []importOptionFingerprint
	Visibility            Visibility
	EditPolicy            EditPolicy
	Placement             Placement
	RequiredOnTransitions []string
	Searchable            bool
	Filterable            bool
	Sortable              bool
	AllowStructuredJSON   bool
	Archived              bool
	SchemaVersion         uint64
}

type importOptionFingerprint struct {
	ID       string
	Key      string
	Label    string
	Position uint16
	Archived bool
}

func importDefinitionPin(definition Definition) ImportDefinitionPin {
	fingerprint := importDefinitionFingerprintOf(definition)
	encoded, err := json.Marshal(fingerprint)
	if err != nil {
		panic(err)
	}
	return ImportDefinitionPin{
		id: definition.id, key: definition.key, schemaVersion: definition.schemaVersion,
		fingerprint: sha256.Sum256(encoded),
	}
}

func importDefinitionFingerprintOf(definition Definition) importDefinitionFingerprint {
	options := make([]importOptionFingerprint, len(definition.options))
	for index, option := range definition.options {
		options[index] = importOptionFingerprint{
			ID: option.id.String(), Key: option.key.String(), Label: option.label,
			Position: option.position, Archived: option.archived,
		}
	}
	transitions := make([]string, len(definition.requiredOnTransitions))
	for index, key := range definition.requiredOnTransitions {
		transitions[index] = key.String()
	}
	return importDefinitionFingerprint{
		ID: definition.id.String(), Tenant: definition.tenantID.String(), ObjectType: definition.objectType,
		Key: definition.key.String(), Label: definition.label, Description: definition.description,
		DataType: definition.dataType, Required: definition.required, Nullable: definition.nullable,
		DefaultPresence: definition.defaultValue.presence,
		Default:         slices.Clone(definition.defaultValue.canonical),
		MinimumLength:   cloneUint32(definition.constraints.minimumLength),
		MaximumLength:   cloneUint32(definition.constraints.maximumLength),
		Minimum:         definition.constraints.minimum, Maximum: definition.constraints.maximum,
		Pattern: definition.constraints.pattern, Options: options, Visibility: definition.visibility,
		EditPolicy: definition.editPolicy, Placement: definition.placement,
		RequiredOnTransitions: transitions, Searchable: definition.searchable,
		Filterable: definition.filterable, Sortable: definition.sortable,
		AllowStructuredJSON: definition.allowStructuredJSON, Archived: definition.archived,
		SchemaVersion: definition.schemaVersion,
	}
}

type importCellDigest struct {
	Key      string
	Presence Presence
	Value    json.RawMessage
}

type importRowDigest struct {
	Sequence        uint32
	Target          string
	ExpectedVersion uint64
	Cells           []importCellDigest
}

func digestImportManifestRequest(manifest ImportManifest) [sha256.Size]byte {
	pins := make([]struct {
		ID          string
		Key         string
		Version     uint64
		Fingerprint [sha256.Size]byte
	}, len(manifest.pins))
	for index, pin := range manifest.pins {
		pins[index].ID = pin.id.String()
		pins[index].Key = pin.key.String()
		pins[index].Version = pin.schemaVersion
		pins[index].Fingerprint = pin.fingerprint
	}
	rows := make([]importRowDigest, len(manifest.rows))
	for index, row := range manifest.rows {
		cells := make([]importCellDigest, len(row.cells))
		for cellIndex, cell := range row.cells {
			cells[cellIndex] = importCellDigest{
				Key: cell.key.String(), Presence: cell.presence, Value: cell.value.RawJSON(),
			}
		}
		rows[index] = importRowDigest{
			Sequence: row.sequence, Target: row.target.String(),
			ExpectedVersion: row.expectedVersion, Cells: cells,
		}
	}
	envelope := struct {
		Domain            string
		Tenant            string
		Requester         string
		OwnerMembership   string
		ObjectType        ObjectType
		Mode              ImportMode
		Pins              any
		Rows              []importRowDigest
		ProjectionVersion uint64
		MaximumAttempts   uint8
	}{
		Domain: "periapsis.custom-field-import.v1", Tenant: manifest.tenant.String(),
		Requester: manifest.requester.String(), OwnerMembership: manifest.ownerMembership.String(),
		ObjectType: manifest.objectType, Mode: manifest.mode, Pins: pins, Rows: rows,
		ProjectionVersion: manifest.projectionVersion, MaximumAttempts: manifest.maximumAttempts,
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		panic(err)
	}
	return sha256.Sum256(encoded)
}

func sameImportManifest(left, right ImportManifest) bool {
	return left.id == right.id && left.tenant == right.tenant && left.requester == right.requester &&
		left.ownerMembership == right.ownerMembership && left.objectType == right.objectType &&
		left.mode == right.mode && left.requestDigest == right.requestDigest &&
		left.projectionVersion == right.projectionVersion && left.maximumAttempts == right.maximumAttempts &&
		reflect.DeepEqual(left.definitions, right.definitions) && slices.Equal(left.pins, right.pins) &&
		reflect.DeepEqual(left.rows, right.rows)
}

func cloneImportDefinition(definition Definition) Definition {
	result := definition
	result.defaultValue = definition.defaultValue.clone()
	result.constraints = definition.constraints.clone()
	result.options = slices.Clone(definition.options)
	result.requiredOnTransitions = slices.Clone(definition.requiredOnTransitions)
	return result
}

func cloneImportDefinitions(definitions []Definition) []Definition {
	result := make([]Definition, len(definitions))
	for index, definition := range definitions {
		result[index] = cloneImportDefinition(definition)
	}
	return result
}

func cloneImportCells(cells []ImportCell) []ImportCell {
	result := make([]ImportCell, len(cells))
	for index, cell := range cells {
		result[index] = cell
		result[index].value = cell.InputValue()
	}
	return result
}

func cloneImportRows(rows []ImportRow) []ImportRow {
	result := slices.Clone(rows)
	for index := range result {
		result[index].cells = cloneImportCells(rows[index].cells)
	}
	return result
}
