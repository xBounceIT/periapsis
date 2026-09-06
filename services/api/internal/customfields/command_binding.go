package customfields

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"slices"

	kernel "github.com/periapsis-im/periapsis/modules/customfields"
)

type CommandBinding struct {
	Operation     string
	KeyDigest     [sha256.Size]byte
	RequestDigest [sha256.Size]byte
}

const (
	operationDefinitionCreate  = "custom_field.definition.create"
	operationDefinitionReplace = "custom_field.definition.replace"
	operationDefinitionArchive = "custom_field.definition.archive"
	operationValuesReplace     = "custom_field.values.replace"
)

func bindCommand(operation, key string, payload any) (CommandBinding, error) {
	canonical, err := json.Marshal(payload)
	if err != nil {
		return CommandBinding{}, ErrInvalidInput
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(operation))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(canonical)
	return CommandBinding{
		Operation: operation, KeyDigest: sha256.Sum256([]byte(key)),
		RequestDigest: [sha256.Size]byte(digest.Sum(nil)),
	}, nil
}

func bindDefinitionCommand(operation, key string, definition kernel.Definition) (CommandBinding, error) {
	return bindCommand(operation, key, definitionFingerprint(definition))
}

func bindDefinitionArchive(key string, definition kernel.Definition, expectedVersion uint64, reason string) (CommandBinding, error) {
	return bindCommand(operationDefinitionArchive, key, struct {
		Definition any    `json:"definition"`
		Version    uint64 `json:"expectedVersion"`
		Reason     string `json:"reason"`
	}{definitionFingerprint(definition), expectedVersion, reason})
}

func bindObjectValues(key string, write ObjectFieldWrite) (CommandBinding, error) {
	values := slices.Clone(write.Values)
	slices.SortFunc(values, func(left, right kernel.FieldValue) int {
		return compareText(left.Key().String(), right.Key().String())
	})
	items := make([]any, len(values))
	for index, field := range values {
		items[index] = map[string]any{
			"definitionId": field.DefinitionID().String(), "tenantId": field.TenantID().String(),
			"objectType": field.ObjectType(), "key": field.Key().String(),
			"schemaVersion": field.SchemaVersion(), "presence": field.Value().Presence(),
			"dataType": field.Value().DataType(), "value": field.Value().CanonicalJSON(),
		}
	}
	return bindCommand(operationValuesReplace, key, map[string]any{
		"tenantId": write.TenantID.String(), "objectType": write.ObjectType,
		"objectId": write.ObjectID.String(), "expectedVersion": write.ExpectedVersion, "values": items,
	})
}

func definitionFingerprint(definition kernel.Definition) map[string]any {
	options := definition.Options()
	optionItems := make([]any, len(options))
	for index, option := range options {
		optionItems[index] = map[string]any{
			"id": option.ID().String(), "key": option.Key().String(), "label": option.Label(),
			"position": option.Position(), "archived": option.Archived(),
		}
	}
	transitions := definition.RequiredOnTransitions()
	transitionItems := make([]string, len(transitions))
	for index, transition := range transitions {
		transitionItems[index] = transition.String()
	}
	constraints := definition.Constraints()
	return map[string]any{
		"id": definition.ID().String(), "tenantId": definition.TenantID().String(),
		"objectType": definition.ObjectType(), "key": definition.Key().String(),
		"label": definition.Label(), "description": definition.Description(),
		"dataType": definition.DataType(), "required": definition.Required(),
		"nullable": definition.Nullable(), "defaultPresence": definition.Default().Presence(),
		"default":       definition.Default().CanonicalJSON(),
		"minimumLength": constraints.MinimumLength(), "maximumLength": constraints.MaximumLength(),
		"minimum": constraints.Minimum(), "maximum": constraints.Maximum(), "pattern": constraints.Pattern(),
		"options": optionItems, "visibility": definition.Visibility(), "editPolicy": definition.EditPolicy(),
		"placement": definition.Placement(), "requiredOnTransitions": transitionItems,
		"searchable": definition.Searchable(), "filterable": definition.Filterable(),
		"sortable": definition.Sortable(), "allowStructuredJson": definition.AllowStructuredJSON(),
		"archived": definition.Archived(), "schemaVersion": definition.SchemaVersion(),
	}
}

func compareText(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func sameDefinitionProjection(left, right kernel.Definition) bool {
	return sameCanonicalPayload(definitionFingerprint(left), definitionFingerprint(right))
}

func sameFieldValueProjection(left, right []kernel.FieldValue) bool {
	if len(left) != len(right) {
		return false
	}
	leftBinding, leftErr := bindObjectValues("projection-comparison", ObjectFieldWrite{Values: left})
	rightBinding, rightErr := bindObjectValues("projection-comparison", ObjectFieldWrite{Values: right})
	return leftErr == nil && rightErr == nil && leftBinding.RequestDigest == rightBinding.RequestDigest
}

func sameCanonicalPayload(left, right any) bool {
	leftCanonical, leftErr := json.Marshal(left)
	rightCanonical, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftCanonical, rightCanonical)
}
