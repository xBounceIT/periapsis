package identityprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func (s *Service) GetSyncStatus(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, bindingID uuid.UUID,
) (SyncStatus, error) {
	if !validUUIDv7(bindingID) {
		return SyncStatus{}, ErrInvalidInput
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderRead)
	if err != nil {
		return SyncStatus{}, err
	}
	if s.syncAdministration == nil {
		return SyncStatus{}, ErrUnavailable
	}
	result, err := s.syncAdministration.GetSyncStatus(ctx, GetSyncStatusParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		BindingID:   bindingID,
	})
	if err != nil {
		return SyncStatus{}, mapRepositoryError(err)
	}
	if !validSyncStatus(result, bindingID) {
		return SyncStatus{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) ListSyncRuns(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, bindingID uuid.UUID,
	input PageInput,
) (SyncRunPage, error) {
	normalized, err := normalizePage(input)
	if err != nil || !validUUIDv7(bindingID) {
		return SyncRunPage{}, ErrInvalidInput
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderRead)
	if err != nil {
		return SyncRunPage{}, err
	}
	if s.syncAdministration == nil {
		return SyncRunPage{}, ErrUnavailable
	}
	rows, err := s.syncAdministration.ListSyncRuns(ctx, ListSyncRunParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		BindingID:   bindingID, After: normalized.After, Limit: int32(normalized.Limit + 1),
	})
	if err != nil {
		return SyncRunPage{}, mapRepositoryError(err)
	}
	if len(rows) > normalized.Limit+1 || len(rows) > int(ldapAdministrationRepositoryPageLimit) {
		return SyncRunPage{}, ErrUnavailable
	}
	var previous uuid.UUID
	if normalized.After != nil {
		previous = *normalized.After
	}
	for _, row := range rows {
		if !validSyncRun(row, tenantID, bindingID) ||
			previous != uuid.Nil && bytes.Compare(previous[:], row.ID[:]) >= 0 {
			return SyncRunPage{}, ErrUnavailable
		}
		previous = row.ID
	}
	if len(rows) <= normalized.Limit {
		return SyncRunPage{Items: append([]SyncRun(nil), rows...)}, nil
	}
	items := append([]SyncRun(nil), rows[:normalized.Limit]...)
	next := items[len(items)-1].ID
	return SyncRunPage{Items: items, NextCursor: &next}, nil
}

func (s *Service) GetSyncRun(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, bindingID, runID uuid.UUID,
) (SyncRun, error) {
	if !validUUIDv7(bindingID) || !validUUIDv7(runID) {
		return SyncRun{}, ErrInvalidInput
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderRead)
	if err != nil {
		return SyncRun{}, err
	}
	if s.syncAdministration == nil {
		return SyncRun{}, ErrUnavailable
	}
	result, err := s.syncAdministration.GetSyncRun(ctx, GetSyncRunParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		BindingID:   bindingID, RunID: runID,
	})
	if err != nil {
		return SyncRun{}, mapRepositoryError(err)
	}
	if result.ID != runID || !validSyncRun(result, tenantID, bindingID) {
		return SyncRun{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) StartManualSync(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, bindingID uuid.UUID,
	input StartManualSyncInput,
) (SyncRun, error) {
	normalized, expectedVersion, err := normalizeStartManualSync(bindingID, input)
	if err != nil {
		return SyncRun{}, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentitySyncRun)
	if err != nil {
		return SyncRun{}, err
	}
	if s.syncAdministration == nil {
		return SyncRun{}, ErrUnavailable
	}
	now, err := s.currentTime()
	if err != nil {
		return SyncRun{}, err
	}
	runID, err := s.nextID()
	if err != nil {
		return SyncRun{}, err
	}
	auditEventID, err := s.nextID()
	if err != nil {
		return SyncRun{}, err
	}
	keyDigest := sha256.Sum256([]byte(normalized.IdempotencyKey))
	defer clear(keyDigest[:])
	requestDigest, err := syncRunRequestDigest(tenantID, bindingID, expectedVersion, normalized.Reason)
	if err != nil {
		return SyncRun{}, err
	}
	defer clear(requestDigest[:])
	result, err := s.syncAdministration.StartManualSync(ctx, StartManualSyncParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, RunID: runID, AuditEventID: auditEventID,
		BindingID: bindingID, ExpectedVersion: expectedVersion, Reason: normalized.Reason,
		IdempotencyKeyDigest: keyDigest, RequestDigest: requestDigest,
	})
	if err != nil {
		return SyncRun{}, mapRepositoryError(err)
	}
	if !validSyncRun(result.Run, tenantID, bindingID) || result.Run.Trigger != "manual" ||
		result.Run.ManualReason == nil || *result.Run.ManualReason != normalized.Reason ||
		result.Run.Snapshot.BindingVersion != expectedVersion ||
		!result.Replayed && (result.Run.ID != runID || result.Run.State != SyncRunQueued || result.Run.Version != 1) {
		return SyncRun{}, ErrUnavailable
	}
	return result.Run, nil
}

func syncRunRequestDigest(
	tenantID, bindingID uuid.UUID,
	expectedVersion int64,
	reason string,
) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(struct {
		Version         int       `json:"version"`
		TenantID        uuid.UUID `json:"tenant_id"`
		BindingID       uuid.UUID `json:"binding_id"`
		ExpectedVersion int64     `json:"expected_version"`
		Reason          string    `json:"reason"`
	}{1, tenantID, bindingID, expectedVersion, reason})
	if err != nil {
		return [sha256.Size]byte{}, ErrUnavailable
	}
	return sha256.Sum256(encoded), nil
}

func validSyncStatus(value SyncStatus, bindingID uuid.UUID) bool {
	if value.BindingID != bindingID || !validUUIDv7(bindingID) ||
		value.Version < 1 || value.Version > maximumResourceVersion || !validInstant(value.UpdatedAt) ||
		(value.SyncIntervalSeconds != nil && (*value.SyncIntervalSeconds < 300 || *value.SyncIntervalSeconds > 2_592_000)) ||
		(value.ActiveRunID != nil && !validUUIDv7(*value.ActiveRunID)) ||
		(value.LastRunID == nil) != (value.LastRunState == nil) ||
		(value.LastRunID != nil && !validUUIDv7(*value.LastRunID)) ||
		(value.LastRunState != nil && !knownSyncRunState(*value.LastRunState)) ||
		(value.LastCompletedAt != nil && !validInstant(*value.LastCompletedAt)) ||
		(value.NextScheduledAt != nil && !validInstant(*value.NextScheduledAt)) {
		return false
	}
	switch value.ScheduleState {
	case "disabled":
		return value.SyncIntervalSeconds == nil && value.ActiveRunID == nil && value.NextScheduledAt == nil
	case "idle":
		return value.SyncIntervalSeconds != nil && value.ActiveRunID == nil
	case "queued", "running":
		return value.ActiveRunID != nil
	case "backoff":
		return value.SyncIntervalSeconds != nil && value.ActiveRunID == nil
	default:
		return false
	}
}

func validSyncRun(value SyncRun, tenantID, bindingID uuid.UUID) bool {
	if !validUUIDv7(value.ID) || value.TenantID != tenantID || value.BindingID != bindingID ||
		!validUUIDv7(tenantID) || !validUUIDv7(bindingID) || !validUUIDv7(value.ProviderID) ||
		!knownSyncRunState(value.State) || (value.Trigger != "manual" && value.Trigger != "scheduled") ||
		value.Version < 1 || value.Version > maximumResourceVersion ||
		!validInstant(value.CreatedAt) || !validInstant(value.UpdatedAt) || value.UpdatedAt.Before(value.CreatedAt) ||
		(value.StartedAt != nil && (!validInstant(*value.StartedAt) || value.StartedAt.Before(value.CreatedAt))) ||
		(value.CompletedAt != nil && (!validInstant(*value.CompletedAt) || value.CompletedAt.Before(value.CreatedAt))) ||
		!validPinnedSyncSnapshot(value.Snapshot, value.ProviderID, bindingID) ||
		!validSyncEnumeration(value.Enumeration) || !validSyncCounters(value.Counters) {
		return false
	}
	if value.Trigger == "manual" {
		if value.ManualReason == nil || !validText(*value.ManualReason, 1, 500) {
			return false
		}
	} else if value.ManualReason != nil {
		return false
	}
	terminal := value.State == SyncRunSucceeded || value.State == SyncRunFailed ||
		value.State == SyncRunCancelled || value.State == SyncRunStale
	if terminal != (value.CompletedAt != nil) || !terminal && value.RunErrorCategory != nil ||
		terminal && value.State != SyncRunSucceeded && value.RunErrorCategory == nil ||
		value.State == SyncRunSucceeded && value.RunErrorCategory != nil {
		return false
	}
	if value.RunErrorCategory != nil && !knownSyncRunError(*value.RunErrorCategory) {
		return false
	}
	if value.State == SyncRunQueued && value.StartedAt != nil ||
		(value.State == SyncRunEnumerating || value.State == SyncRunApplying || value.State == SyncRunSucceeded) && value.StartedAt == nil {
		return false
	}
	return true
}

func validPinnedSyncSnapshot(value PinnedPlannerSnapshot, providerID, bindingID uuid.UUID) bool {
	if value.ProviderID != providerID || value.BindingID != bindingID ||
		value.ProviderVersion < 1 || value.ProviderVersion > maximumResourceVersion ||
		value.BindingVersion < 1 || value.BindingVersion > maximumResourceVersion ||
		value.ConfigurationRevision < 1 || !validUUIDv7(value.AccessEpochID) ||
		len(value.MappingRevisions) > 1_000 {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(value.MappingRevisions))
	for _, revision := range value.MappingRevisions {
		if !validUUIDv7(revision.MappingID) || revision.MappingVersion < 1 ||
			revision.MappingVersion > maximumResourceVersion ||
			(revision.SourceEpochID == nil) != (revision.SourceEpochSequence == nil) ||
			revision.SourceEpochID != nil && (!validUUIDv7(*revision.SourceEpochID) || *revision.SourceEpochSequence < 1) {
			return false
		}
		if _, duplicate := seen[revision.MappingID]; duplicate {
			return false
		}
		seen[revision.MappingID] = struct{}{}
	}
	return true
}

func validSyncEnumeration(value SyncEnumeration) bool {
	if value.EntryCount < 0 || value.EntryCount > 10_000_000 || value.PageCount < 0 ||
		value.PageCount > 100_000 || value.ResponseBytes < 0 || value.ResponseBytes > 1_073_741_824 ||
		!knownSyncCursorState(value.CursorState) ||
		(value.ErrorCategory != nil && !knownSyncEnumerationError(*value.ErrorCategory)) {
		return false
	}
	switch value.State {
	case "not_started", "enumerating", "incomplete":
		return !value.Complete && !value.Truncated && !value.AbsenceBasedRevocationAllowed
	case "truncated":
		return !value.Complete && value.Truncated && !value.AbsenceBasedRevocationAllowed
	case "complete":
		return value.Complete && !value.Truncated && value.CursorState == "terminal"
	default:
		return false
	}
}

func validSyncCounters(value SyncCounters) bool {
	counts := [...]int{
		value.Observed, value.Staged, value.IdentitiesCreated, value.IdentitiesLinked,
		value.ProviderAccessAdded, value.ProviderAccessSuspended, value.GroupEdgesAdded,
		value.GroupEdgesRefreshed, value.GroupEdgesRevoked, value.RoleEdgesAdded,
		value.RoleEdgesRefreshed, value.RoleEdgesRevoked, value.RosterEdgesAdded,
		value.RosterEdgesRefreshed, value.RosterEdgesRevoked, value.Failed,
	}
	for _, count := range counts {
		if count < 0 || count > 10_000_000 {
			return false
		}
	}
	return true
}

func knownSyncRunState(value SyncRunState) bool {
	return value == SyncRunQueued || value == SyncRunEnumerating || value == SyncRunApplying ||
		value == SyncRunSucceeded || value == SyncRunFailed || value == SyncRunCancelled || value == SyncRunStale
}

func knownSyncRunError(value string) bool {
	switch value {
	case "cancelled", "timeout", "directory_unavailable", "incomplete_enumeration", "stale_snapshot",
		"apply_conflict", "authorization_denied", "internal_failure":
		return true
	default:
		return false
	}
}

func knownSyncEnumerationError(value string) bool {
	switch value {
	case "cancelled", "timeout", "destination_blocked", "directory_unavailable", "referral_rejected",
		"duplicate_subject", "limit_exceeded", "parse_failed", "stale_snapshot", "worker_interrupted", "protocol_failed":
		return true
	default:
		return false
	}
}

func knownSyncCursorState(value string) bool {
	return value == "none" || value == "present" || value == "terminal" || value == "discarded"
}
