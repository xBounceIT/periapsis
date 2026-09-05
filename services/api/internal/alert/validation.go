package alert

import (
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const maximumResourceVersion = int64(2_147_483_647)

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)
var sourceTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,79}$`)

func normalizeCreateInput(input CreateInput) (CreateInput, error) {
	input.Title = strings.TrimSpace(input.Title)
	input.Category = strings.TrimSpace(input.Category)
	input.Source = strings.TrimSpace(input.Source)
	input.SourceType = strings.TrimSpace(input.SourceType)
	if input.Priority == "" {
		input.Priority = "medium"
	}
	if input.Category == "" {
		input.Category = "general"
	}
	if input.Source == "" {
		input.Source = "manual"
	}
	if input.SourceType == "" {
		input.SourceType = "manual"
	}
	if input.Tags == nil {
		input.Tags = []string{}
	}
	if input.CustomFields == nil {
		input.CustomFields = map[string]any{}
	}
	if input.RawPayload == nil {
		input.RawPayload = map[string]any{}
	}
	input.Tags = slices.Clone(input.Tags)
	slices.Sort(input.Tags)
	if !validText(input.Title, 1, 240) || !knownSeverity(input.Severity) ||
		!knownPriority(input.Priority) || !validText(input.Category, 1, 120) ||
		!validText(input.Source, 1, 120) || !sourceTypePattern.MatchString(input.SourceType) ||
		!validTags(input.Tags) || !validJSONMap(input.CustomFields, 64*1024, 100) ||
		!validJSONMap(input.RawPayload, 256*1024, 200) ||
		input.DetectedAt != (time.Time{}) && !validStoredTime(input.DetectedAt) ||
		input.AssigneeUserID != nil && input.AssignedTeamID == nil ||
		!idempotencyKeyPattern.MatchString(input.IdempotencyKey) || !validAudit(input.Audit) {
		return CreateInput{}, ErrInvalidInput
	}
	if input.ExternalID != nil {
		value := strings.TrimSpace(*input.ExternalID)
		if !validText(value, 1, 200) {
			return CreateInput{}, ErrInvalidInput
		}
		input.ExternalID = &value
	}
	if input.Description != nil {
		value := strings.TrimSpace(*input.Description)
		if !validText(value, 0, 10_000) {
			return CreateInput{}, ErrInvalidInput
		}
		input.Description = &value
	}
	for _, optional := range []*string{input.DeduplicationKey, input.Classification} {
		if optional != nil {
			value := strings.TrimSpace(*optional)
			maximum := 240
			if optional == input.Classification {
				maximum = 120
			}
			if !validText(value, 1, maximum) {
				return CreateInput{}, ErrInvalidInput
			}
			*optional = value
		}
	}
	for _, optionalID := range []*uuid.UUID{input.WorkflowID, input.AssignedTeamID, input.AssigneeUserID} {
		if optionalID != nil && !validUUIDv7(*optionalID) {
			return CreateInput{}, ErrInvalidInput
		}
	}
	input.Audit.RemoteAddress = input.Audit.RemoteAddress.Unmap()
	return input, nil
}

func createPayload(input CreateInput) CreatePayload {
	return CreatePayload{
		WorkflowID: input.WorkflowID, ExternalID: input.ExternalID, DeduplicationKey: input.DeduplicationKey,
		Title: input.Title, Description: input.Description, Severity: input.Severity,
		Priority: input.Priority, Category: input.Category, Classification: input.Classification,
		Source: input.Source, SourceType: input.SourceType, Tags: input.Tags,
		CustomFields: input.CustomFields, RawPayload: input.RawPayload,
		CustomerVisible: input.CustomerVisible, DetectedAt: input.DetectedAt,
		AssignedTeamID: input.AssignedTeamID, AssigneeUserID: input.AssigneeUserID,
		KeyDigest:     digestIdempotencyKey(input.IdempotencyKey),
		RequestDigest: digestCreateRequest(input),
	}
}

func digestIdempotencyKey(value string) [32]byte {
	return sha256.Sum256(append([]byte("periapsis/alert.create/idempotency/v1\x00"), value...))
}

func digestCreateRequest(input CreateInput) [32]byte {
	encoded, err := json.Marshal(struct {
		WorkflowID       *uuid.UUID     `json:"workflow_id"`
		ExternalID       *string        `json:"external_id"`
		DeduplicationKey *string        `json:"deduplication_key"`
		Title            string         `json:"title"`
		Description      *string        `json:"description"`
		Severity         Severity       `json:"severity"`
		Priority         string         `json:"priority"`
		Category         string         `json:"category"`
		Classification   *string        `json:"classification"`
		Source           string         `json:"source"`
		SourceType       string         `json:"source_type"`
		Tags             []string       `json:"tags"`
		CustomFields     map[string]any `json:"custom_fields"`
		RawPayload       map[string]any `json:"raw_payload"`
		CustomerVisible  bool           `json:"customer_visible"`
		DetectedAt       time.Time      `json:"detected_at"`
		AssignedTeamID   *uuid.UUID     `json:"assigned_team_id"`
		AssigneeUserID   *uuid.UUID     `json:"assignee_user_id"`
	}{input.WorkflowID, input.ExternalID, input.DeduplicationKey, input.Title, input.Description, input.Severity, input.Priority, input.Category,
		input.Classification, input.Source, input.SourceType, input.Tags, input.CustomFields, input.RawPayload, input.CustomerVisible, input.DetectedAt,
		input.AssignedTeamID, input.AssigneeUserID})
	if err != nil {
		return [32]byte{}
	}
	return sha256.Sum256(append([]byte("periapsis/alert.create/request/v2\x00"), encoded...))
}

func knownPriority(value string) bool {
	return value == "low" || value == "medium" || value == "high" || value == "urgent" || value == "critical"
}

func validTags(values []string) bool {
	if len(values) > 100 {
		return false
	}
	for index, value := range values {
		if !validText(value, 1, 64) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func validJSONMap(value map[string]any, maximumBytes, maximumKeys int) bool {
	if len(value) > maximumKeys {
		return false
	}
	encoded, err := json.Marshal(value)
	return err == nil && len(encoded) <= maximumBytes
}

func validAudit(value authorization.AuditContext) bool {
	return validAnyUUID(value.RequestID) && validAnyUUID(value.CorrelationID) &&
		value.RemoteAddress.IsValid() && value.RemoteAddress.Zone() == "" &&
		validText(value.UserAgent, 0, 512)
}

func validAnyUUID(value uuid.UUID) bool {
	return value != uuid.Nil && value.Variant() == uuid.RFC4122
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	length := utf8.RuneCountInString(value)
	return length >= minimum && length <= maximum
}

func knownSeverity(value Severity) bool {
	switch value {
	case SeverityInformational, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

func knownStatus(value Status) bool {
	return value == StatusNew || value == StatusInProgress || value == StatusClosed
}

func validStoredTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Microsecond) == 0
}

func validStoredAlert(value Alert, tenantID uuid.UUID) bool {
	if !validUUIDv7(value.ID) || value.TenantID != tenantID || !validUUIDv7(tenantID) ||
		!validStoredTicketNumber(value.Number) || !validUUIDv7(value.WorkflowID) ||
		value.WorkflowVersion < 1 || value.WorkflowVersion > maximumResourceVersion ||
		!validText(value.StateKey, 1, 64) ||
		value.Title != strings.TrimSpace(value.Title) || !validText(value.Title, 1, 240) ||
		!knownSeverity(value.Severity) || !knownStatus(value.Status) ||
		!knownPriority(value.Priority) || !validText(value.Category, 1, 120) ||
		!validText(value.Source, 1, 120) || !sourceTypePattern.MatchString(value.SourceType) ||
		!validTags(value.Tags) || !validJSONMap(value.CustomFields, 64*1024, 100) ||
		!validJSONMap(value.CustomerCustomFields, 64*1024, 100) ||
		!validJSONMap(value.RawPayload, 256*1024, 200) ||
		value.Version < 1 || value.Version > maximumResourceVersion ||
		!validStoredTime(value.DetectedAt) || !validStoredTime(value.ReceivedAt) || value.ReceivedAt.Before(value.DetectedAt) ||
		!validStoredTime(value.CreatedAt) || value.CreatedAt.Before(value.ReceivedAt) ||
		!validStoredTime(value.UpdatedAt) || value.UpdatedAt.Before(value.CreatedAt) {
		return false
	}
	if value.ExternalID != nil && (*value.ExternalID != strings.TrimSpace(*value.ExternalID) || !validText(*value.ExternalID, 1, 200)) ||
		value.DeduplicationKey != nil && !validText(*value.DeduplicationKey, 1, 240) ||
		value.Description != nil && (*value.Description != strings.TrimSpace(*value.Description) || !validText(*value.Description, 0, 10_000)) ||
		value.Classification != nil && !validText(*value.Classification, 1, 120) {
		return false
	}
	if (value.AssignedTeamID == nil) != (value.AssignedAt == nil) ||
		value.AssigneeUserID != nil && value.AssignedTeamID == nil ||
		value.ClaimedByUserID != nil && (value.AssigneeUserID == nil || *value.ClaimedByUserID != *value.AssigneeUserID) {
		return false
	}
	for _, id := range []*uuid.UUID{value.AssignedTeamID, value.AssigneeUserID, value.ClaimedByUserID} {
		if id != nil && !validUUIDv7(*id) {
			return false
		}
	}
	for _, instant := range []*time.Time{value.AcknowledgedAt, value.ClosedAt, value.AssignedAt, value.FirstResponseAt, value.ResolvedAt, value.ClaimedAt} {
		if instant != nil && (!validStoredTime(*instant) || instant.Before(value.CreatedAt) || instant.After(value.UpdatedAt)) {
			return false
		}
	}
	human := value.CreatedByMembershipID != nil && value.CreatedByUserID != nil && value.CreatedByServiceAccountID == nil &&
		validUUIDv7(*value.CreatedByMembershipID) && validUUIDv7(*value.CreatedByUserID)
	machine := value.CreatedByMembershipID == nil && value.CreatedByUserID == nil && value.CreatedByServiceAccountID != nil &&
		validUUIDv7(*value.CreatedByServiceAccountID)
	return human != machine
}

// validStoredTicketNumber accepts only the closed, non-executable grammar
// emitted by the tenant numbering allocator. It deliberately validates the
// shape instead of a hard-coded ALT prefix so a policy change cannot turn a
// successfully committed alert into an invalid repository projection.
func validStoredTicketNumber(value string) bool {
	if len(value) < 6 || len(value) > 42 || !utf8.ValidString(value) {
		return false
	}
	separatorIndex := strings.IndexAny(value, "-/._")
	if separatorIndex < 1 || separatorIndex > 12 {
		return false
	}
	prefix := value[:separatorIndex]
	if prefix[0] < 'A' || prefix[0] > 'Z' {
		return false
	}
	for index := 1; index < len(prefix); index++ {
		character := prefix[index]
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	separator := value[separatorIndex]
	parts := strings.Split(value[separatorIndex+1:], string(separator))
	if len(parts) != 1 && len(parts) != 2 {
		return false
	}
	if len(parts) == 2 && (len(parts[0]) != 4 || !asciiDigits(parts[0])) {
		return false
	}
	serial := parts[len(parts)-1]
	return len(serial) >= 4 && len(serial) <= 12 && asciiDigits(serial)
}

func asciiDigits(value string) bool {
	if value == "" {
		return false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func alertMatchesCreateInput(value Alert, input CreateInput) bool {
	return value.Title == input.Title && value.Severity == input.Severity &&
		value.Priority == input.Priority && value.Category == input.Category &&
		value.Source == input.Source && value.SourceType == input.SourceType &&
		value.CustomerVisible == input.CustomerVisible &&
		equalOptionalText(value.ExternalID, input.ExternalID) &&
		equalOptionalText(value.Description, input.Description) &&
		equalOptionalText(value.DeduplicationKey, input.DeduplicationKey) &&
		equalOptionalText(value.Classification, input.Classification) &&
		slices.Equal(value.Tags, input.Tags) && reflect.DeepEqual(value.CustomFields, input.CustomFields) &&
		reflect.DeepEqual(value.RawPayload, input.RawPayload) && equalOptionalUUID(value.AssignedTeamID, input.AssignedTeamID) &&
		equalOptionalUUID(value.AssigneeUserID, input.AssigneeUserID) &&
		(input.WorkflowID == nil || value.WorkflowID == *input.WorkflowID) &&
		(input.DetectedAt.IsZero() || value.DetectedAt.Equal(input.DetectedAt))
}

func equalOptionalUUID(left, right *uuid.UUID) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func equalOptionalText(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
