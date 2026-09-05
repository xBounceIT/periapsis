package customfields

import (
	"bytes"
	"slices"
)

// ValidateImportPatch validates one row as an operator update against the
// immutable definition snapshots in the manifest. Missing cells are a no-op;
// explicit null and present values produce patches. Existing values outside
// the pinned definition set are intentionally untouched by the returned patch.
func ValidateImportPatch(
	manifest ImportManifest,
	row ImportRow,
	existing []FieldValue,
) ([]FieldValue, []FieldError, error) {
	if ValidateImportManifest(manifest) != nil || !manifestContainsRow(manifest, row) ||
		len(existing) > maximumOptions {
		return nil, nil, ErrInvalidImportRow
	}

	definitionsByKey := make(map[Key]Definition, len(manifest.definitions))
	definitionsByID := make(map[EntityID]Definition, len(manifest.definitions))
	for _, definition := range manifest.definitions {
		definitionsByKey[definition.key] = definition
		definitionsByID[definition.id] = definition
	}

	existingByDefinition := make(map[EntityID]FieldValue, len(existing))
	for _, field := range existing {
		definition, pinned := definitionsByID[field.definitionID]
		if !pinned {
			continue
		}
		if field.tenantID != manifest.tenant || field.objectType != manifest.objectType ||
			field.key != definition.key || field.schemaVersion != definition.schemaVersion {
			return nil, nil, ErrImportDefinitionConflict
		}
		if _, duplicate := existingByDefinition[field.definitionID]; duplicate {
			return nil, nil, ErrInvalidImportRow
		}
		restored, err := RestoreFieldValue(definition, field.value.canonical)
		if err != nil || !sameImportFieldValue(restored, field) {
			return nil, nil, ErrInvalidImportRow
		}
		existingByDefinition[field.definitionID] = field
	}

	patches := make([]FieldValue, 0, len(row.cells))
	fieldErrors := make([]FieldError, 0)
	for _, cell := range row.cells {
		if cell.presence == PresenceMissing {
			continue
		}
		definition, known := definitionsByKey[cell.key]
		if !known {
			fieldErrors = append(fieldErrors, FieldError{Field: cell.key, Code: "unknown"})
			continue
		}
		if !definition.VisibleTo(AudienceOperator) {
			fieldErrors = append(fieldErrors, FieldError{Field: cell.key, Code: "visibility_denied"})
			continue
		}
		if !definition.CanEdit(AudienceOperator, PhaseUpdate) {
			fieldErrors = append(fieldErrors, FieldError{Field: cell.key, Code: "edit_denied"})
			continue
		}
		value, fieldError := definition.Validate(cell.InputValue(), ValidationContext{
			TenantID: manifest.tenant, ObjectType: manifest.objectType,
			Audience: AudienceOperator, Phase: PhaseUpdate,
		})
		if fieldError != nil {
			fieldErrors = append(fieldErrors, *fieldError)
			continue
		}
		field := FieldValue{
			definitionID: definition.id, tenantID: definition.tenantID,
			objectType: definition.objectType, key: definition.key,
			schemaVersion: definition.schemaVersion, value: value.clone(),
		}
		if current, exists := existingByDefinition[definition.id]; exists &&
			sameImportFieldValue(current, field) {
			continue
		}
		patches = append(patches, field)
	}
	if len(fieldErrors) != 0 {
		slices.SortFunc(fieldErrors, func(left, right FieldError) int {
			if comparison := compareKeys(left.Field, right.Field); comparison != 0 {
				return comparison
			}
			if left.Code < right.Code {
				return -1
			}
			if left.Code > right.Code {
				return 1
			}
			return 0
		})
		return nil, fieldErrors, nil
	}
	slices.SortFunc(patches, func(left, right FieldValue) int {
		return compareKeys(left.key, right.key)
	})
	return patches, nil, nil
}

func manifestContainsRow(manifest ImportManifest, row ImportRow) bool {
	if row.sequence == 0 || int(row.sequence) > len(manifest.rows) {
		return false
	}
	return sameImportRow(manifest.rows[row.sequence-1], row)
}

func sameImportRow(left, right ImportRow) bool {
	if left.sequence != right.sequence || left.target != right.target ||
		left.expectedVersion != right.expectedVersion || len(left.cells) != len(right.cells) {
		return false
	}
	for index := range left.cells {
		leftCell, rightCell := left.cells[index], right.cells[index]
		if leftCell.key != rightCell.key || leftCell.presence != rightCell.presence ||
			leftCell.value.provided != rightCell.value.provided ||
			!bytes.Equal(leftCell.value.raw, rightCell.value.raw) {
			return false
		}
	}
	return true
}

func sameImportFieldValue(left, right FieldValue) bool {
	return left.definitionID == right.definitionID && left.tenantID == right.tenantID &&
		left.objectType == right.objectType && left.key == right.key &&
		left.schemaVersion == right.schemaVersion && left.value.presence == right.value.presence &&
		left.value.dataType == right.value.dataType && bytes.Equal(left.value.canonical, right.value.canonical)
}
