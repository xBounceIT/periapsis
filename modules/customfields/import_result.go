package customfields

import (
	"fmt"
	"slices"
)

type ImportRowOutcome uint8

const (
	ImportRowDryRunValid ImportRowOutcome = iota + 1
	ImportRowCommitted
	ImportRowNoChange
	ImportRowValidationFailed
	ImportRowDefinitionChanged
	ImportRowVersionConflict
	ImportRowNotFoundOrHidden
	ImportRowAuthorizationDenied
	ImportRowCancelled
	ImportRowAuthorizationRevoked
	ImportRowExpired
	ImportRowInternalFailure
)

func (outcome ImportRowOutcome) String() string {
	switch outcome {
	case ImportRowDryRunValid:
		return "dry_run_valid"
	case ImportRowCommitted:
		return "committed"
	case ImportRowNoChange:
		return "no_change"
	case ImportRowValidationFailed:
		return "validation_failed"
	case ImportRowDefinitionChanged:
		return "definition_changed"
	case ImportRowVersionConflict:
		return "version_conflict"
	case ImportRowNotFoundOrHidden:
		return "not_found_or_hidden"
	case ImportRowAuthorizationDenied:
		return "authorization_denied"
	case ImportRowCancelled:
		return "cancelled"
	case ImportRowAuthorizationRevoked:
		return "authorization_revoked"
	case ImportRowExpired:
		return "expired"
	case ImportRowInternalFailure:
		return "internal_failure"
	default:
		return "unknown"
	}
}

func validImportRowOutcome(outcome ImportRowOutcome) bool {
	return outcome >= ImportRowDryRunValid && outcome <= ImportRowInternalFailure
}

type ImportRowResult struct {
	sequence         uint32
	outcome          ImportRowOutcome
	resultingVersion uint64
	fieldErrors      []FieldError
}

func NewImportRowResult(
	sequence uint32,
	outcome ImportRowOutcome,
	resultingVersion uint64,
	fieldErrors []FieldError,
) (ImportRowResult, error) {
	errorsCopy := slices.Clone(fieldErrors)
	slices.SortFunc(errorsCopy, func(left, right FieldError) int {
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
	if sequence == 0 || !validImportRowOutcome(outcome) ||
		len(errorsCopy) > ImportMaximumFieldsPerRow ||
		(outcome == ImportRowValidationFailed) != (len(errorsCopy) != 0) ||
		resultingVersion >= maximumDefinitionVersion {
		return ImportRowResult{}, ErrInvalidImportRowResult
	}
	for index, fieldError := range errorsCopy {
		if !validKey(fieldError.Field.value) || fieldError.Code == "" ||
			len(fieldError.Code) > 64 || !validImportErrorCode(fieldError.Code) ||
			index > 0 && fieldError == errorsCopy[index-1] {
			return ImportRowResult{}, ErrInvalidImportRowResult
		}
	}
	if outcome != ImportRowDryRunValid && outcome != ImportRowCommitted &&
		outcome != ImportRowNoChange && resultingVersion != 0 {
		return ImportRowResult{}, ErrInvalidImportRowResult
	}
	if (outcome == ImportRowDryRunValid || outcome == ImportRowCommitted ||
		outcome == ImportRowNoChange) && resultingVersion == 0 {
		return ImportRowResult{}, ErrInvalidImportRowResult
	}
	return ImportRowResult{
		sequence: sequence, outcome: outcome,
		resultingVersion: resultingVersion, fieldErrors: errorsCopy,
	}, nil
}

func validImportErrorCode(value string) bool {
	switch value {
	case "unknown", "visibility_denied", "edit_denied", "invalid_context", "malformed",
		"required", "null_not_allowed", "empty_not_allowed", "invalid_text",
		"invalid_integer", "invalid_decimal", "invalid_boolean", "invalid_date",
		"invalid_datetime", "invalid_option", "invalid_options", "invalid_url",
		"invalid_email", "invalid_ip", "invalid_cidr", "invalid_reference",
		"invalid_json", "invalid_type":
		return true
	default:
		return false
	}
}

func (result ImportRowResult) Sequence() uint32          { return result.sequence }
func (result ImportRowResult) Outcome() ImportRowOutcome { return result.outcome }
func (result ImportRowResult) ResultingVersion() uint64  { return result.resultingVersion }
func (result ImportRowResult) FieldErrors() []FieldError { return slices.Clone(result.fieldErrors) }
func (result ImportRowResult) String() string {
	return fmt.Sprintf(
		"ImportRowResult{sequence:%d,outcome:%s,resulting_version:%d,field_errors:%d,details:[REDACTED]}",
		result.sequence, result.outcome, result.resultingVersion, len(result.fieldErrors),
	)
}
func (result ImportRowResult) GoString() string { return result.String() }

type ImportProgressSnapshot struct {
	Total                uint32
	DryRunValid          uint32
	Committed            uint32
	NoChange             uint32
	ValidationFailed     uint32
	DefinitionChanged    uint32
	VersionConflict      uint32
	NotFoundOrHidden     uint32
	AuthorizationDenied  uint32
	Cancelled            uint32
	AuthorizationRevoked uint32
	Expired              uint32
	InternalFailure      uint32
}

func (progress ImportProgressSnapshot) Processed() uint32 {
	return progress.DryRunValid + progress.Committed + progress.NoChange +
		progress.ValidationFailed + progress.DefinitionChanged + progress.VersionConflict +
		progress.NotFoundOrHidden + progress.AuthorizationDenied + progress.Cancelled +
		progress.AuthorizationRevoked + progress.Expired + progress.InternalFailure
}

func (progress ImportProgressSnapshot) Complete() bool {
	return progress.Total > 0 && progress.Processed() == progress.Total
}

func (progress ImportProgressSnapshot) Count(outcome ImportRowOutcome) uint32 {
	switch outcome {
	case ImportRowDryRunValid:
		return progress.DryRunValid
	case ImportRowCommitted:
		return progress.Committed
	case ImportRowNoChange:
		return progress.NoChange
	case ImportRowValidationFailed:
		return progress.ValidationFailed
	case ImportRowDefinitionChanged:
		return progress.DefinitionChanged
	case ImportRowVersionConflict:
		return progress.VersionConflict
	case ImportRowNotFoundOrHidden:
		return progress.NotFoundOrHidden
	case ImportRowAuthorizationDenied:
		return progress.AuthorizationDenied
	case ImportRowCancelled:
		return progress.Cancelled
	case ImportRowAuthorizationRevoked:
		return progress.AuthorizationRevoked
	case ImportRowExpired:
		return progress.Expired
	case ImportRowInternalFailure:
		return progress.InternalFailure
	default:
		return 0
	}
}

func (progress ImportProgressSnapshot) String() string {
	return fmt.Sprintf("ImportProgress{total:%d,processed:%d}", progress.Total, progress.Processed())
}
func (progress ImportProgressSnapshot) GoString() string { return progress.String() }

func importProgress(total uint32, results []ImportRowResult) (ImportProgressSnapshot, error) {
	progress := ImportProgressSnapshot{Total: total}
	if total == 0 || len(results) > int(total) {
		return ImportProgressSnapshot{}, ErrInvalidImportJob
	}
	for index, result := range results {
		if result.sequence != uint32(index+1) || !validImportRowOutcome(result.outcome) {
			return ImportProgressSnapshot{}, ErrInvalidImportJob
		}
		switch result.outcome {
		case ImportRowDryRunValid:
			progress.DryRunValid++
		case ImportRowCommitted:
			progress.Committed++
		case ImportRowNoChange:
			progress.NoChange++
		case ImportRowValidationFailed:
			progress.ValidationFailed++
		case ImportRowDefinitionChanged:
			progress.DefinitionChanged++
		case ImportRowVersionConflict:
			progress.VersionConflict++
		case ImportRowNotFoundOrHidden:
			progress.NotFoundOrHidden++
		case ImportRowAuthorizationDenied:
			progress.AuthorizationDenied++
		case ImportRowCancelled:
			progress.Cancelled++
		case ImportRowAuthorizationRevoked:
			progress.AuthorizationRevoked++
		case ImportRowExpired:
			progress.Expired++
		case ImportRowInternalFailure:
			progress.InternalFailure++
		}
	}
	return progress, nil
}

func cloneImportRowResult(result ImportRowResult) ImportRowResult {
	result.fieldErrors = slices.Clone(result.fieldErrors)
	return result
}

func cloneImportRowResults(results []ImportRowResult) []ImportRowResult {
	cloned := make([]ImportRowResult, len(results))
	for index, result := range results {
		cloned[index] = cloneImportRowResult(result)
	}
	return cloned
}
