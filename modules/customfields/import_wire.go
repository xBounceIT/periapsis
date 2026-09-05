package customfields

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// ImportJobDocument is the versioned persistence/worker projection for an
// import job. It is deliberately defined in the domain module so the API and
// worker share an exact contract without importing either executable's
// internal packages.
type ImportJobDocument struct {
	SchemaVersion uint64                 `json:"schemaVersion"`
	Manifest      ImportManifestDocument `json:"manifest"`
	State         string                 `json:"state"`
	Revision      uint64                 `json:"revision"`
	Attempts      uint8                  `json:"attempts"`
	Results       []ImportResultDocument `json:"results"`
	RequestedAt   string                 `json:"requestedAt"`
	UpdatedAt     string                 `json:"updatedAt"`
	AvailableAt   string                 `json:"availableAt"`
	ExpiresAt     string                 `json:"expiresAt"`
	Fence         *string                `json:"fence"`
	LeaseUntil    *string                `json:"leaseUntil"`
	TerminalAt    *string                `json:"terminalAt"`
}

type ImportManifestDocument struct {
	ID                string                     `json:"id"`
	TenantID          string                     `json:"tenantId"`
	RequesterID       string                     `json:"requesterId"`
	OwnerMembershipID string                     `json:"ownerMembershipId"`
	ObjectType        ObjectType                 `json:"objectType"`
	Mode              string                     `json:"mode"`
	Definitions       []ImportDefinitionDocument `json:"definitions"`
	Rows              []ImportRowDocument        `json:"rows"`
	RequestSHA256     string                     `json:"requestSha256"`
	ProjectionVersion uint64                     `json:"projectionVersion"`
	MaximumAttempts   uint8                      `json:"maximumAttempts"`
}

type ImportDefinitionDocument struct {
	ID                    string                 `json:"id"`
	TenantID              string                 `json:"tenantId"`
	ObjectType            ObjectType             `json:"objectType"`
	Key                   string                 `json:"key"`
	Label                 string                 `json:"label"`
	Description           string                 `json:"description"`
	DataType              DataType               `json:"dataType"`
	Required              bool                   `json:"required"`
	Nullable              bool                   `json:"nullable"`
	DefaultValue          json.RawMessage        `json:"defaultValue,omitempty"`
	MinimumLength         *uint32                `json:"minimumLength"`
	MaximumLength         *uint32                `json:"maximumLength"`
	Minimum               string                 `json:"minimum"`
	Maximum               string                 `json:"maximum"`
	Pattern               string                 `json:"pattern"`
	Options               []ImportOptionDocument `json:"options"`
	Visibility            Visibility             `json:"visibility"`
	EditPolicy            EditPolicy             `json:"editPolicy"`
	Placement             Placement              `json:"placement"`
	RequiredOnTransitions []string               `json:"requiredOnTransitions"`
	Searchable            bool                   `json:"searchable"`
	Filterable            bool                   `json:"filterable"`
	Sortable              bool                   `json:"sortable"`
	AllowStructuredJSON   bool                   `json:"allowStructuredJson"`
	Archived              bool                   `json:"archived"`
	SchemaVersion         uint64                 `json:"schemaVersion"`
	PinSHA256             string                 `json:"pinSha256"`
}

type ImportOptionDocument struct {
	ID       string `json:"id"`
	Key      string `json:"key"`
	Label    string `json:"label"`
	Position uint16 `json:"position"`
	Archived bool   `json:"archived"`
}

type ImportRowDocument struct {
	Sequence        uint32               `json:"sequence"`
	TargetID        string               `json:"targetId"`
	ExpectedVersion uint64               `json:"expectedVersion"`
	Cells           []ImportCellDocument `json:"cells"`
}

type ImportCellDocument struct {
	Key      string          `json:"key"`
	Presence string          `json:"presence"`
	Value    json.RawMessage `json:"value,omitempty"`
}

type ImportResultDocument struct {
	Sequence         uint32                     `json:"sequence"`
	Outcome          string                     `json:"outcome"`
	ResultingVersion uint64                     `json:"resultingVersion"`
	FieldErrors      []ImportFieldErrorDocument `json:"fieldErrors"`
}

type ImportFieldErrorDocument struct {
	Field string `json:"field"`
	Code  string `json:"code"`
}

func NewImportJobDocument(job ImportJob) (ImportJobDocument, error) {
	if ValidateImportJob(job) != nil {
		return ImportJobDocument{}, ErrInvalidImportJob
	}
	manifest := job.Manifest()
	document, err := newImportManifestDocument(manifest)
	if err != nil {
		return ImportJobDocument{}, err
	}
	results := make([]ImportResultDocument, len(job.Results()))
	for index, result := range job.Results() {
		errorsDocument := make([]ImportFieldErrorDocument, len(result.FieldErrors()))
		for errorIndex, fieldError := range result.FieldErrors() {
			errorsDocument[errorIndex] = ImportFieldErrorDocument{
				Field: fieldError.Field.String(), Code: fieldError.Code,
			}
		}
		results[index] = ImportResultDocument{
			Sequence: result.Sequence(), Outcome: result.Outcome().String(),
			ResultingVersion: result.ResultingVersion(), FieldErrors: errorsDocument,
		}
	}
	var fence *string
	if value := job.Fence(); value != nil {
		text := value.String()
		fence = &text
	}
	return ImportJobDocument{
		SchemaVersion: 1, Manifest: document, State: job.State().String(),
		Revision: job.Revision(), Attempts: job.Attempts(), Results: results,
		RequestedAt: importWireInstant(job.RequestedAt()), UpdatedAt: importWireInstant(job.UpdatedAt()),
		AvailableAt: importWireInstant(job.AvailableAt()), ExpiresAt: importWireInstant(job.ExpiresAt()),
		Fence: fence, LeaseUntil: importWireOptionalInstant(job.LeaseUntil()),
		TerminalAt: importWireOptionalInstant(job.TerminalAt()),
	}, nil
}

func MarshalImportJob(job ImportJob) ([]byte, error) {
	document, err := NewImportJobDocument(job)
	if err != nil {
		return nil, err
	}
	return json.Marshal(document)
}

func RestoreImportJobDocument(document ImportJobDocument) (ImportJob, error) {
	if document.SchemaVersion != 1 {
		return ImportJob{}, ErrInvalidImportJob
	}
	manifest, err := restoreImportManifestDocument(document.Manifest)
	if err != nil {
		return ImportJob{}, ErrInvalidImportJob
	}
	state, ok := parseImportJobState(document.State)
	if !ok {
		return ImportJob{}, ErrInvalidImportJob
	}
	results := make([]ImportRowResult, len(document.Results))
	for index, source := range document.Results {
		outcome, outcomeOK := parseImportRowOutcome(source.Outcome)
		fieldErrors := make([]FieldError, len(source.FieldErrors))
		for errorIndex, raw := range source.FieldErrors {
			key, keyErr := NewKey(raw.Field)
			if keyErr != nil {
				return ImportJob{}, ErrInvalidImportJob
			}
			fieldErrors[errorIndex] = FieldError{Field: key, Code: raw.Code}
		}
		result, resultErr := NewImportRowResult(
			source.Sequence, outcome, source.ResultingVersion, fieldErrors,
		)
		if !outcomeOK || resultErr != nil {
			return ImportJob{}, ErrInvalidImportJob
		}
		results[index] = result
	}
	var fence *EntityID
	if document.Fence != nil {
		parsed, parseErr := ParseEntityID(*document.Fence)
		if parseErr != nil {
			return ImportJob{}, ErrInvalidImportJob
		}
		fence = &parsed
	}
	requestedAt, requestedErr := parseImportWireInstant(document.RequestedAt)
	updatedAt, updatedErr := parseImportWireInstant(document.UpdatedAt)
	availableAt, availableErr := parseImportWireInstant(document.AvailableAt)
	expiresAt, expiresErr := parseImportWireInstant(document.ExpiresAt)
	leaseUntil, leaseErr := parseImportWireOptionalInstant(document.LeaseUntil)
	terminalAt, terminalErr := parseImportWireOptionalInstant(document.TerminalAt)
	if requestedErr != nil || updatedErr != nil || availableErr != nil || expiresErr != nil ||
		leaseErr != nil || terminalErr != nil {
		return ImportJob{}, ErrInvalidImportJob
	}
	return RestoreImportJob(ImportJobSnapshot{
		Manifest: manifest, State: state, Revision: document.Revision,
		Attempts: document.Attempts, Results: results,
		RequestedAt: requestedAt, UpdatedAt: updatedAt,
		AvailableAt: availableAt, ExpiresAt: expiresAt,
		Fence: fence, LeaseUntil: leaseUntil, TerminalAt: terminalAt,
	})
}

const importWireInstantLayout = "2006-01-02T15:04:05.000000Z"

func importWireInstant(value time.Time) string {
	return value.UTC().Truncate(time.Microsecond).Format(importWireInstantLayout)
}

func importWireOptionalInstant(value *time.Time) *string {
	if value == nil {
		return nil
	}
	encoded := importWireInstant(*value)
	return &encoded
}

func parseImportWireInstant(value string) (time.Time, error) {
	parsed, err := time.Parse(importWireInstantLayout, value)
	if err != nil || parsed.Format(importWireInstantLayout) != value {
		return time.Time{}, ErrInvalidImportJob
	}
	return parsed, nil
}

func parseImportWireOptionalInstant(value *string) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	parsed, err := parseImportWireInstant(*value)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func UnmarshalImportJob(encoded []byte) (ImportJob, error) {
	if len(encoded) == 0 || len(encoded) > ImportMaximumPayloadBytes+2*1024*1024 {
		return ImportJob{}, ErrInvalidImportJob
	}
	var document ImportJobDocument
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return ImportJob{}, ErrInvalidImportJob
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ImportJob{}, ErrInvalidImportJob
	}
	return RestoreImportJobDocument(document)
}

func newImportManifestDocument(manifest ImportManifest) (ImportManifestDocument, error) {
	if ValidateImportManifest(manifest) != nil {
		return ImportManifestDocument{}, ErrInvalidImportManifest
	}
	pins := manifest.DefinitionPins()
	definitions := make([]ImportDefinitionDocument, len(manifest.Definitions()))
	for index, definition := range manifest.Definitions() {
		constraints := definition.Constraints()
		options := make([]ImportOptionDocument, len(definition.Options()))
		for optionIndex, option := range definition.Options() {
			options[optionIndex] = ImportOptionDocument{
				ID: option.ID().String(), Key: option.Key().String(), Label: option.Label(),
				Position: option.Position(), Archived: option.Archived(),
			}
		}
		transitions := make([]string, len(definition.RequiredOnTransitions()))
		for transitionIndex, transition := range definition.RequiredOnTransitions() {
			transitions[transitionIndex] = transition.String()
		}
		var defaultValue json.RawMessage
		if definition.Default().Presence() != PresenceMissing {
			defaultValue = definition.Default().CanonicalJSON()
		}
		pinFingerprint := pins[index].Fingerprint()
		definitions[index] = ImportDefinitionDocument{
			ID: definition.ID().String(), TenantID: definition.TenantID().String(),
			ObjectType: definition.ObjectType(), Key: definition.Key().String(),
			Label: definition.Label(), Description: definition.Description(),
			DataType: definition.DataType(), Required: definition.Required(),
			Nullable: definition.Nullable(), DefaultValue: defaultValue,
			MinimumLength: constraints.MinimumLength(), MaximumLength: constraints.MaximumLength(),
			Minimum: constraints.Minimum(), Maximum: constraints.Maximum(), Pattern: constraints.Pattern(),
			Options: options, Visibility: definition.Visibility(), EditPolicy: definition.EditPolicy(),
			Placement: definition.Placement(), RequiredOnTransitions: transitions,
			Searchable: definition.Searchable(), Filterable: definition.Filterable(),
			Sortable: definition.Sortable(), AllowStructuredJSON: definition.AllowStructuredJSON(),
			Archived: definition.Archived(), SchemaVersion: definition.SchemaVersion(),
			PinSHA256: hex.EncodeToString(pinFingerprint[:]),
		}
	}
	rows := make([]ImportRowDocument, len(manifest.Rows()))
	for index, row := range manifest.Rows() {
		cells := make([]ImportCellDocument, len(row.Cells()))
		for cellIndex, cell := range row.Cells() {
			presence := "missing"
			var value json.RawMessage
			if cell.Presence() == PresenceNull {
				presence, value = "null", json.RawMessage("null")
			} else if cell.Presence() == PresencePresent {
				presence, value = "present", cell.InputValue().raw
			}
			cells[cellIndex] = ImportCellDocument{Key: cell.Key().String(), Presence: presence, Value: value}
		}
		rows[index] = ImportRowDocument{
			Sequence: row.Sequence(), TargetID: row.Target().String(),
			ExpectedVersion: row.ExpectedVersion(), Cells: cells,
		}
	}
	digest := manifest.RequestDigest()
	return ImportManifestDocument{
		ID: manifest.ID().String(), TenantID: manifest.Tenant().String(),
		RequesterID: manifest.Requester().String(), OwnerMembershipID: manifest.OwnerMembership().String(),
		ObjectType: manifest.ObjectType(), Mode: manifest.Mode().String(),
		Definitions: definitions, Rows: rows, RequestSHA256: hex.EncodeToString(digest[:]),
		ProjectionVersion: manifest.ProjectionVersion(), MaximumAttempts: manifest.MaximumAttempts(),
	}, nil
}

func restoreImportManifestDocument(document ImportManifestDocument) (ImportManifest, error) {
	id, err := ParseEntityID(document.ID)
	if err != nil {
		return ImportManifest{}, err
	}
	tenant, err := ParseEntityID(document.TenantID)
	if err != nil {
		return ImportManifest{}, err
	}
	requester, err := ParseEntityID(document.RequesterID)
	if err != nil {
		return ImportManifest{}, err
	}
	owner, err := ParseEntityID(document.OwnerMembershipID)
	if err != nil {
		return ImportManifest{}, err
	}
	mode, ok := parseImportMode(document.Mode)
	if !ok {
		return ImportManifest{}, ErrInvalidImportManifest
	}
	definitions := make([]Definition, len(document.Definitions))
	for index, source := range document.Definitions {
		definitionID, parseErr := ParseEntityID(source.ID)
		definitionTenant, tenantErr := ParseEntityID(source.TenantID)
		key, keyErr := NewKey(source.Key)
		if parseErr != nil || tenantErr != nil || keyErr != nil {
			return ImportManifest{}, ErrInvalidImportManifest
		}
		options := make([]OptionInput, len(source.Options))
		for optionIndex, raw := range source.Options {
			optionID, optionErr := ParseEntityID(raw.ID)
			optionKey, optionKeyErr := NewKey(raw.Key)
			if optionErr != nil || optionKeyErr != nil {
				return ImportManifest{}, ErrInvalidImportManifest
			}
			options[optionIndex] = OptionInput{
				ID: optionID, Key: optionKey, Label: raw.Label,
				Position: raw.Position, Archived: raw.Archived,
			}
		}
		transitions := make([]Key, len(source.RequiredOnTransitions))
		for transitionIndex, raw := range source.RequiredOnTransitions {
			transitions[transitionIndex], err = NewKey(raw)
			if err != nil {
				return ImportManifest{}, ErrInvalidImportManifest
			}
		}
		defaultValue := MissingInputValue()
		if len(source.DefaultValue) != 0 {
			defaultValue = JSONInputValue(source.DefaultValue)
		}
		definition, definitionErr := NewDefinition(DefinitionInput{
			ID: definitionID, TenantID: definitionTenant, ObjectType: source.ObjectType,
			Key: key, Label: source.Label, Description: source.Description, DataType: source.DataType,
			Required: source.Required, Nullable: source.Nullable, Default: defaultValue,
			Constraints: ConstraintsInput{
				MinimumLength: source.MinimumLength, MaximumLength: source.MaximumLength,
				Minimum: source.Minimum, Maximum: source.Maximum, Pattern: source.Pattern,
			},
			Options: options, Visibility: source.Visibility, EditPolicy: source.EditPolicy,
			Placement: source.Placement, RequiredOnTransitions: transitions,
			Searchable: source.Searchable, Filterable: source.Filterable, Sortable: source.Sortable,
			AllowStructuredJSON: source.AllowStructuredJSON, Archived: source.Archived,
			SchemaVersion: source.SchemaVersion,
		})
		if definitionErr != nil {
			return ImportManifest{}, ErrInvalidImportManifest
		}
		definitions[index] = definition
	}
	rows := make([]ImportRowInput, len(document.Rows))
	for index, source := range document.Rows {
		target, targetErr := ParseEntityID(source.TargetID)
		if targetErr != nil {
			return ImportManifest{}, ErrInvalidImportManifest
		}
		fields := make([]FieldInput, len(source.Cells))
		for cellIndex, cell := range source.Cells {
			key, keyErr := NewKey(cell.Key)
			if keyErr != nil {
				return ImportManifest{}, ErrInvalidImportManifest
			}
			value := MissingInputValue()
			switch cell.Presence {
			case "missing":
				if len(cell.Value) != 0 {
					return ImportManifest{}, ErrInvalidImportManifest
				}
			case "null", "present":
				if len(cell.Value) == 0 {
					return ImportManifest{}, ErrInvalidImportManifest
				}
				value = JSONInputValue(cell.Value)
			default:
				return ImportManifest{}, ErrInvalidImportManifest
			}
			fields[cellIndex] = FieldInput{Key: key, Value: value}
		}
		rows[index] = ImportRowInput{
			Sequence: source.Sequence, Target: target,
			ExpectedVersion: source.ExpectedVersion, Fields: fields,
		}
	}
	manifest, err := NewImportManifest(ImportManifestInput{
		ID: id, Tenant: tenant, Requester: requester, OwnerMembership: owner,
		ObjectType: document.ObjectType, Mode: mode, Definitions: definitions, Rows: rows,
		ProjectionVersion: document.ProjectionVersion, MaximumAttempts: document.MaximumAttempts,
	})
	if err != nil {
		return ImportManifest{}, err
	}
	digest, err := hex.DecodeString(document.RequestSHA256)
	actual := manifest.RequestDigest()
	if err != nil || len(digest) != len(actual) || !bytes.Equal(digest, actual[:]) {
		return ImportManifest{}, ErrInvalidImportManifest
	}
	actualPins := manifest.DefinitionPins()
	for index, source := range document.Definitions {
		pin, pinErr := hex.DecodeString(source.PinSHA256)
		actualFingerprint := actualPins[index].Fingerprint()
		if pinErr != nil || len(pin) != len(actualFingerprint) ||
			!bytes.Equal(pin, actualFingerprint[:]) {
			return ImportManifest{}, ErrInvalidImportManifest
		}
	}
	return manifest, nil
}

func parseImportMode(value string) (ImportMode, bool) {
	switch value {
	case "dry_run":
		return ImportDryRun, true
	case "commit":
		return ImportCommit, true
	default:
		return 0, false
	}
}

func parseImportJobState(value string) (ImportJobState, bool) {
	for state := ImportJobPending; state <= ImportJobExpired; state++ {
		if state.String() == value {
			return state, true
		}
	}
	return 0, false
}

func parseImportRowOutcome(value string) (ImportRowOutcome, bool) {
	for outcome := ImportRowDryRunValid; outcome <= ImportRowInternalFailure; outcome++ {
		if outcome.String() == value {
			return outcome, true
		}
	}
	return 0, false
}
