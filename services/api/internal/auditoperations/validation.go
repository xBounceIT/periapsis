package auditoperations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

const (
	maximumSafeInstantDrift = time.Second
	zeroAuditHash           = "0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)
	stableKeyPattern      = regexp.MustCompile(`^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)*$`)
	hexDigestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func normalizeFilter(filter ExportFilter, stream Stream) (ExportFilter, error) {
	if stream != StreamTenant && stream != StreamPlatform ||
		filter.OccurredFrom != nil && filter.OccurredFrom.IsZero() ||
		filter.OccurredBefore != nil && filter.OccurredBefore.IsZero() ||
		filter.OccurredFrom != nil && filter.OccurredBefore != nil && !filter.OccurredFrom.Before(*filter.OccurredBefore) ||
		stream == StreamPlatform && filter.ActorServiceAccountID != nil ||
		!validOptionalUUID(filter.ActorUserID) || !validOptionalUUID(filter.ActorServiceAccountID) ||
		!validOptionalUUID(filter.ResourceID) || !validOptionalUUID(filter.RequestID) ||
		!validOptionalUUID(filter.CorrelationID) {
		return ExportFilter{}, ErrInvalidInput
	}
	if filter.OccurredFrom != nil {
		value := filter.OccurredFrom.UTC()
		filter.OccurredFrom = &value
	}
	if filter.OccurredBefore != nil {
		value := filter.OccurredBefore.UTC()
		filter.OccurredBefore = &value
	}
	if filter.ActorType != nil {
		value := strings.TrimSpace(*filter.ActorType)
		if value != "user" && value != "service_account" && value != "system" ||
			stream == StreamPlatform && value == "service_account" {
			return ExportFilter{}, ErrInvalidInput
		}
		filter.ActorType = &value
	}
	if filter.Outcome != nil {
		value := strings.TrimSpace(*filter.Outcome)
		if value != "success" && value != "failure" && value != "denied" {
			return ExportFilter{}, ErrInvalidInput
		}
		filter.Outcome = &value
	}
	var err error
	filter.ActionPrefix, err = normalizeStableKey(filter.ActionPrefix)
	if err != nil {
		return ExportFilter{}, err
	}
	filter.ResourceType, err = normalizeStableKey(filter.ResourceType)
	if err != nil {
		return ExportFilter{}, err
	}
	if filter.Search != nil {
		value := strings.TrimSpace(*filter.Search)
		if value == "" || len([]byte(value)) > 256 || !utf8.ValidString(value) || containsUnsafeText(value) {
			return ExportFilter{}, ErrInvalidInput
		}
		filter.Search = &value
	}
	if filter.ActorType != nil {
		switch *filter.ActorType {
		case "user":
			if filter.ActorServiceAccountID != nil {
				return ExportFilter{}, ErrInvalidInput
			}
		case "service_account":
			if filter.ActorUserID != nil {
				return ExportFilter{}, ErrInvalidInput
			}
		case "system":
			if filter.ActorUserID != nil || filter.ActorServiceAccountID != nil {
				return ExportFilter{}, ErrInvalidInput
			}
		}
	}
	return filter, nil
}

func normalizeStableKey(value *string) (*string, error) {
	if value == nil {
		return nil, nil
	}
	normalized := strings.TrimSpace(*value)
	if len(normalized) < 1 || len(normalized) > 128 || !stableKeyPattern.MatchString(normalized) {
		return nil, ErrInvalidInput
	}
	return &normalized, nil
}

func marshalFilter(filter ExportFilter) (json.RawMessage, error) {
	document, err := json.Marshal(filter)
	if err != nil || len(document) < 2 || len(document) > 64*1024 || !json.Valid(document) {
		return nil, ErrInvalidInput
	}
	return json.RawMessage(document), nil
}

func normalizeMutation(key, reason string, event authentication.EventContext) (string, error) {
	if !idempotencyKeyPattern.MatchString(key) || !validReason(reason) || !validEvent(event) {
		return "", ErrInvalidInput
	}
	return reason, nil
}

func validReason(value string) bool {
	if len(value) < 1 || len(value) > 500 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e || character == ',' {
			return false
		}
	}
	return true
}

func validEvent(event authentication.EventContext) bool {
	if !validUUIDv7(event.RequestID) || !validUUIDv7(event.CorrelationID) ||
		!event.RemoteAddress.IsValid() || event.RemoteAddress.Zone() != "" ||
		len(event.UserAgent) < 1 || len(event.UserAgent) > 1024 || !utf8.ValidString(event.UserAgent) {
		return false
	}
	for _, character := range event.UserAgent {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validTenantSession(session authentication.Session, tenantID uuid.UUID, now time.Time) bool {
	return validUUIDv7(tenantID) && validSession(session, now) && session.ActiveTenantID != nil &&
		*session.ActiveTenantID == tenantID
}

func validPlatformSession(session authentication.Session, now time.Time) bool {
	return validSession(session, now) && session.ActiveTenantID == nil
}

func validSession(session authentication.Session, now time.Time) bool {
	return validUUIDv7(session.ID) && validUUIDv7(session.User.ID) &&
		session.AuthenticationMethod != "" && session.RevokedAt == nil &&
		session.IdleExpiresAt.After(now) && session.AbsoluteExpiresAt.After(now)
}

func validateExportMutation(
	result ExportMutationResult,
	stream Stream,
	tenantID *uuid.UUID,
	actorID uuid.UUID,
	now time.Time,
) error {
	return validateExportJob(result.Job, stream, tenantID, actorID, now)
}

func validateExportJob(job ExportJob, stream Stream, tenantID *uuid.UUID, actorID uuid.UUID, now time.Time) error {
	if !validUUIDv7(job.ID) || !validUUIDv7(job.RequesterUserID) || job.RequesterUserID != actorID ||
		job.Stream != stream || !matchingTenant(job.TenantID, tenantID) || job.ProjectionVersion != 1 ||
		job.Format != "jsonl" || !knownExportState(job.State) || !knownFailureCode(job.FailureCode) ||
		!hexDigestPattern.MatchString(job.FilterSHA256) || job.Revision < 1 ||
		job.Attempts < 0 || job.MaximumAttempts < 1 || job.MaximumAttempts > 10 ||
		job.Attempts > job.MaximumAttempts || job.RequestedAt.IsZero() || job.UpdatedAt.Before(job.RequestedAt) ||
		job.AvailableAt.Before(job.RequestedAt) || !job.ExpiresAt.After(job.RequestedAt) ||
		job.ExpiresAt.After(job.RequestedAt.Add(7*24*time.Hour+maximumSafeInstantDrift)) ||
		job.RequestedAt.After(now.Add(maximumSafeInstantDrift)) {
		return ErrUnavailable
	}
	normalized, err := normalizeFilter(job.Filter, stream)
	if err != nil || !equalFilters(normalized, job.Filter) {
		return ErrUnavailable
	}
	if job.Artifact != nil {
		if job.State != "succeeded" || !validUUIDv7(job.Artifact.ID) ||
			!hexDigestPattern.MatchString(job.Artifact.SHA256) || job.Artifact.Rows < 0 ||
			job.Artifact.Rows > 1_000_000 || job.Artifact.Bytes < 1 ||
			job.Artifact.Bytes > 1_073_741_824 ||
			(job.Artifact.Rows == 0) != (job.Artifact.Bytes == 0) ||
			!job.Artifact.ExpiresAt.Equal(job.ExpiresAt) {
			return ErrUnavailable
		}
	}
	return nil
}

func validateRetentionState(state RetentionState, stream Stream, tenantID *uuid.UUID, now time.Time) error {
	if state.Stream != stream || !matchingTenant(state.TenantID, tenantID) ||
		state.Policy.RetentionDays < 30 || state.Policy.RetentionDays > 3650 ||
		!validRevision(state.Policy.Revision) || state.Policy.UpdatedAt.IsZero() ||
		state.Policy.UpdatedAt.After(now.Add(maximumSafeInstantDrift)) ||
		state.Anchor.RetainedThroughSequence < 0 || !validRevision(state.Anchor.Revision) ||
		!hexDigestPattern.MatchString(state.Anchor.RetainedThroughHash) ||
		state.Anchor.RetainedThroughSequence == 0 && state.Anchor.RetainedThroughHash != zeroAuditHash ||
		state.Anchor.RetainedThroughSequence > 0 && state.Anchor.RetainedThroughHash == zeroAuditHash ||
		state.Anchor.UpdatedAt.IsZero() || state.Anchor.UpdatedAt.After(now.Add(maximumSafeInstantDrift)) {
		return ErrUnavailable
	}
	if state.ActiveLegalHold != nil && validateLegalHold(*state.ActiveLegalHold, false, now) != nil {
		return ErrUnavailable
	}
	return nil
}

func validateLegalHold(hold LegalHold, released bool, now time.Time) error {
	if !validUUIDv7(hold.ID) || hold.PlacedAt.IsZero() || hold.PlacedAt.After(now.Add(maximumSafeInstantDrift)) {
		return ErrUnavailable
	}
	if released {
		if hold.State != "released" || hold.Revision != 2 || hold.ReleasedAt == nil ||
			hold.ReleasedAt.Before(hold.PlacedAt) || hold.ReleasedAt.After(now.Add(maximumSafeInstantDrift)) {
			return ErrUnavailable
		}
	} else if hold.State != "active" || hold.Revision != 1 || hold.ReleasedAt != nil {
		return ErrUnavailable
	}
	return nil
}

func validateArtifactLocation(location ArtifactLocation, stream Stream, tenantID *uuid.UUID, exportID uuid.UUID, now time.Time) error {
	expectedKey := "platform/audit/exports/" + exportID.String() + "/v1.jsonl"
	expectedFilename := "platform-audit-" + exportID.String() + ".jsonl"
	if stream == StreamTenant && tenantID != nil {
		expectedKey = "tenants/" + tenantID.String() + "/audit/exports/" + exportID.String() + "/v1.jsonl"
		expectedFilename = "tenant-audit-" + exportID.String() + ".jsonl"
	}
	if location.Stream != stream || !matchingTenant(location.TenantID, tenantID) ||
		location.ExportID != exportID || !validUUIDv7(location.ArtifactID) ||
		location.Digest == ([32]byte{}) || location.Rows < 0 || location.Rows > 1_000_000 ||
		location.Bytes < 0 || location.Bytes > 1_073_741_824 ||
		(location.Rows == 0) != (location.Bytes == 0) ||
		!location.ExpiresAt.After(now) || location.ObjectKey != expectedKey || location.Filename != expectedFilename {
		return ErrUnavailable
	}
	return nil
}

func knownExportState(value string) bool {
	switch value {
	case "pending", "running", "cancellation_requested", "succeeded", "failed", "cancelled", "authorization_revoked", "expired":
		return true
	default:
		return false
	}
}

func knownFailureCode(value string) bool {
	switch value {
	case "none", "transient_storage", "transient_database", "authorization_revoked", "output_limit", "lease_expired", "expired", "internal":
		return true
	default:
		return false
	}
}

func matchingTenant(actual, expected *uuid.UUID) bool {
	if actual == nil || expected == nil {
		return actual == nil && expected == nil
	}
	return *actual == *expected
}

func validOptionalUUID(value *uuid.UUID) bool {
	return value == nil || *value != uuid.Nil
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validRevision(value int64) bool {
	return value >= 1 && value <= 9_007_199_254_740_990
}

func containsUnsafeText(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return true
		}
	}
	return false
}

func equalFilters(left, right ExportFilter) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func cloneExportMutation(value ExportMutationResult) ExportMutationResult {
	value.Job = cloneExportJob(value.Job)
	return value
}

func cloneExportJob(value ExportJob) ExportJob {
	value.TenantID = cloneUUID(value.TenantID)
	value.Filter = cloneFilter(value.Filter)
	value.TerminalAt = cloneTime(value.TerminalAt)
	if value.Artifact != nil {
		artifact := *value.Artifact
		value.Artifact = &artifact
	}
	return value
}

func cloneFilter(value ExportFilter) ExportFilter {
	value.OccurredFrom = cloneTime(value.OccurredFrom)
	value.OccurredBefore = cloneTime(value.OccurredBefore)
	value.ActorType = cloneString(value.ActorType)
	value.ActorUserID = cloneUUID(value.ActorUserID)
	value.ActorServiceAccountID = cloneUUID(value.ActorServiceAccountID)
	value.ActionPrefix = cloneString(value.ActionPrefix)
	value.ResourceType = cloneString(value.ResourceType)
	value.ResourceID = cloneUUID(value.ResourceID)
	value.RequestID = cloneUUID(value.RequestID)
	value.CorrelationID = cloneUUID(value.CorrelationID)
	value.Outcome = cloneString(value.Outcome)
	value.Search = cloneString(value.Search)
	return value
}

func cloneRetentionState(value RetentionState) RetentionState {
	value.TenantID = cloneUUID(value.TenantID)
	if value.ActiveLegalHold != nil {
		hold := cloneLegalHold(*value.ActiveLegalHold)
		value.ActiveLegalHold = &hold
	}
	return value
}

func cloneRetentionMutation(value RetentionMutationResult) RetentionMutationResult {
	value.State = cloneRetentionState(value.State)
	return value
}

func cloneLegalHoldMutation(value LegalHoldMutationResult) LegalHoldMutationResult {
	value.Hold = cloneLegalHold(value.Hold)
	return value
}

func cloneLegalHold(value LegalHold) LegalHold {
	value.ReleasedAt = cloneTime(value.ReleasedAt)
	return value
}

func cloneUUID(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func malformedDocumentError(kind string) error {
	return fmt.Errorf("database returned malformed %s", kind)
}
