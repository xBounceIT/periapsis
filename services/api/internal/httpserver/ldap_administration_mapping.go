package httpserver

import (
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

var ldapAttributeNamePattern = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9-]{0,127}|[0-9]+(?:\.[0-9]+)+)$`)

func mapLDAPBinding(value identityprovider.Binding) (contract.TenantLDAPAuthProviderBinding, error) {
	if !validLDAPAdministrationID(value.ID) || !validLDAPAdministrationID(value.TenantID) ||
		!validLDAPAdministrationID(value.ProviderID) || !validLDAPLoginKey(value.LoginKey) ||
		value.ProfilePriority < 0 || value.ProfilePriority > 1_000_000 || value.AuthRevision < 1 ||
		value.Version < 1 || value.Version > maximumResourceVersion || value.CreatedAt.IsZero() ||
		value.UpdatedAt.Before(value.CreatedAt) || value.Enabled != (value.CurrentAccessEpochID != nil) ||
		value.Enabled && value.ArchivedAt != nil || value.CurrentAccessEpochID != nil &&
		!validLDAPAdministrationID(*value.CurrentAccessEpochID) {
		return contract.TenantLDAPAuthProviderBinding{}, errors.New("invalid LDAP binding projection")
	}
	return contract.TenantLDAPAuthProviderBinding{
		Id: value.ID, TenantId: value.TenantID, ProviderId: value.ProviderID,
		LoginKey: value.LoginKey, Enabled: value.Enabled, ProfilePriority: value.ProfilePriority,
		AuthRevision: value.AuthRevision, CurrentAccessEpochId: cloneUUIDPointer(value.CurrentAccessEpochID),
		ArchivedAt: utcTimePointer(value.ArchivedAt), Version: contract.ResourceVersion(value.Version),
		CreatedAt: value.CreatedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC(),
	}, nil
}

func mapLDAPDirectoryTestResult(
	value identityprovider.DirectoryTestResult,
	maximumEntries int,
) (contract.TenantLDAPUserSearchTestResult, error) {
	diagnostic, err := mapTenantLDAPDiagnostic(value.Diagnostic)
	if err != nil || maximumEntries < 1 || maximumEntries > 10 || value.MatchedEntryCount < 0 ||
		value.MatchedEntryCount > maximumEntries || len(value.Entries) != value.MatchedEntryCount ||
		len(value.Entries) > maximumEntries {
		return contract.TenantLDAPUserSearchTestResult{}, errors.New("invalid LDAP directory test projection")
	}
	entries := make([]contract.TenantLDAPRedactedEntry, 0, len(value.Entries))
	for index, entry := range value.Entries {
		if entry.Ordinal != index+1 || entry.GroupValueCount < 0 || entry.GroupValueCount > 10_000 ||
			len(entry.Attributes) > 64 {
			return contract.TenantLDAPUserSearchTestResult{}, errors.New("invalid LDAP redacted entry")
		}
		attributes := make([]contract.TenantLDAPRedactedEntryAttribute, 0, len(entry.Attributes))
		seen := make(map[string]struct{}, len(entry.Attributes))
		for _, attribute := range entry.Attributes {
			if !ldapAttributeNamePattern.MatchString(attribute.Name) || attribute.ValueCount < 0 ||
				attribute.ValueCount > 10_000 {
				return contract.TenantLDAPUserSearchTestResult{}, errors.New("invalid LDAP redacted attribute")
			}
			if _, duplicate := seen[attribute.Name]; duplicate {
				return contract.TenantLDAPUserSearchTestResult{}, errors.New("duplicate LDAP redacted attribute")
			}
			seen[attribute.Name] = struct{}{}
			attributes = append(attributes, contract.TenantLDAPRedactedEntryAttribute{
				Name: attribute.Name, ValueCount: attribute.ValueCount, Truncated: attribute.Truncated,
				ValuesRedacted: contract.TenantLDAPRedactedEntryAttributeValuesRedacted(true),
			})
		}
		entries = append(entries, contract.TenantLDAPRedactedEntry{
			Ordinal: entry.Ordinal, DnPresent: entry.DNPresent, GroupValueCount: entry.GroupValueCount,
			ImmutableSubjectRedacted: contract.TenantLDAPRedactedEntryImmutableSubjectRedacted(true),
			Attributes:               attributes,
		})
	}
	return contract.TenantLDAPUserSearchTestResult{
		Diagnostic: diagnostic, MatchedEntryCount: value.MatchedEntryCount,
		Truncated: value.Truncated, Entries: entries,
	}, nil
}

func mapLDAPFilterTestResult(
	value identityprovider.DirectoryTestResult,
	maximumEntries int,
) (contract.TenantLDAPFilterTestResult, error) {
	mapped, err := mapLDAPDirectoryTestResult(value, maximumEntries)
	if err != nil {
		return contract.TenantLDAPFilterTestResult{}, err
	}
	return contract.TenantLDAPFilterTestResult{
		Diagnostic: mapped.Diagnostic, MatchedEntryCount: mapped.MatchedEntryCount,
		Truncated: mapped.Truncated, Entries: mapped.Entries,
	}, nil
}

func mapLDAPMapping(value identityprovider.Mapping) (contract.TenantLDAPMapping, error) {
	if !validLDAPAdministrationID(value.ID) || !validLDAPAdministrationID(value.TenantID) ||
		!validLDAPAdministrationID(value.BindingID) || value.Priority < 0 || value.Priority > 1_000_000 ||
		!validLDAPMappingTarget(value.Target) || !validLDAPReconciliationMode(value.ReconciliationMode) ||
		!validLDAPText(value.Notes, 0, 2000, true) || value.Version < 1 ||
		value.Version > maximumResourceVersion || value.CreatedAt.IsZero() ||
		value.UpdatedAt.Before(value.CreatedAt) || value.Enabled != (value.CurrentSourceEpoch != nil) ||
		value.Enabled && value.ArchivedAt != nil {
		return contract.TenantLDAPMapping{}, errors.New("invalid LDAP mapping projection")
	}
	matcher, err := mapLDAPMatcher(value.Matcher)
	if err != nil {
		return contract.TenantLDAPMapping{}, err
	}
	target := contract.TenantLDAPMappingTarget{
		TenantSecurityGroupId: value.Target.TenantSecurityGroupID,
		RoleIds:               cloneUUIDs(value.Target.RoleIDs),
	}
	if value.Target.OperatorTeamAssignment != nil {
		target.OperatorTeamAssignment = &contract.TenantLDAPOperatorTeamAssignmentTarget{
			OperatorTeamId:    value.Target.OperatorTeamAssignment.OperatorTeamID,
			AssignmentEpochId: value.Target.OperatorTeamAssignment.AssignmentEpochID,
		}
	}
	var epoch *contract.TenantLDAPMappingSourceEpoch
	if value.CurrentSourceEpoch != nil {
		if !validLDAPAdministrationID(value.CurrentSourceEpoch.ID) || value.CurrentSourceEpoch.Sequence < 1 ||
			value.CurrentSourceEpoch.ActivatedAt.IsZero() ||
			!validLDAPReconciliationMode(value.CurrentSourceEpoch.ReconciliationMode) ||
			value.CurrentSourceEpoch.ReconciliationMode != value.ReconciliationMode {
			return contract.TenantLDAPMapping{}, errors.New("invalid LDAP source epoch")
		}
		epoch = &contract.TenantLDAPMappingSourceEpoch{
			Id: value.CurrentSourceEpoch.ID, Sequence: value.CurrentSourceEpoch.Sequence,
			ReconciliationMode: contract.TenantLDAPMappingReconciliationMode(value.CurrentSourceEpoch.ReconciliationMode),
			ActivatedAt:        value.CurrentSourceEpoch.ActivatedAt.UTC(),
		}
	}
	return contract.TenantLDAPMapping{
		Id: value.ID, TenantId: value.TenantID, BindingId: value.BindingID,
		Matcher: matcher, Priority: value.Priority, Target: target,
		ReconciliationMode: contract.TenantLDAPMappingReconciliationMode(value.ReconciliationMode),
		Enabled:            value.Enabled, Notes: value.Notes, CurrentSourceEpoch: epoch,
		LastMatchedAt: utcTimePointer(value.LastMatchedAt), ArchivedAt: utcTimePointer(value.ArchivedAt),
		Version: contract.ResourceVersion(value.Version), CreatedAt: value.CreatedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC(),
	}, nil
}

func mapLDAPMatcher(value identityprovider.MappingMatcher) (contract.TenantLDAPGroupMatcher, error) {
	value, err := validateLDAPMappingMatcher(value)
	if err != nil {
		return contract.TenantLDAPGroupMatcher{}, err
	}
	caseMode := contract.TenantLDAPMappingCaseMode(value.CaseMode)
	if !caseMode.Valid() {
		return contract.TenantLDAPGroupMatcher{}, errors.New("invalid LDAP matcher case mode")
	}
	var result contract.TenantLDAPGroupMatcher
	switch value.Type {
	case identityprovider.MappingMatcherExactDN:
		err = result.FromTenantLDAPExactDNMatcher(contract.TenantLDAPExactDNMatcher{
			Type: contract.TenantLDAPExactDNMatcherType(value.Type), Dn: value.Value, CaseMode: caseMode,
		})
	case identityprovider.MappingMatcherExactCN:
		err = result.FromTenantLDAPExactCNMatcher(contract.TenantLDAPExactCNMatcher{
			Type: contract.TenantLDAPExactCNMatcherType(value.Type), Cn: value.Value, CaseMode: caseMode,
		})
	case identityprovider.MappingMatcherRegex:
		err = result.FromTenantLDAPRegexMatcher(contract.TenantLDAPRegexMatcher{
			Type: contract.TenantLDAPRegexMatcherType(value.Type), Pattern: value.Value, CaseMode: caseMode,
		})
	default:
		err = errors.New("invalid LDAP matcher type")
	}
	return result, err
}

func cloneUUIDPointer(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func validLDAPAdministrationPage[T any](
	input identityprovider.PageInput,
	items []T,
	nextCursor *uuid.UUID,
	id func(T) uuid.UUID,
) bool {
	limit := input.Limit
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 || len(items) > limit {
		return false
	}
	var previous uuid.UUID
	hasPrevious := false
	if input.After != nil {
		if !validLDAPAdministrationID(*input.After) {
			return false
		}
		previous = *input.After
		hasPrevious = true
	}
	for _, item := range items {
		current := id(item)
		if !validLDAPAdministrationID(current) || hasPrevious && uuidCompare(current, previous) <= 0 {
			return false
		}
		previous = current
		hasPrevious = true
	}
	return nextCursor == nil || len(items) > 0 && validLDAPAdministrationID(*nextCursor) &&
		*nextCursor == id(items[len(items)-1])
}

func validLDAPMappingAdministrationPage(
	input identityprovider.ListMappingsInput,
	items []identityprovider.Mapping,
	nextCursor *identityprovider.MappingCursor,
) bool {
	limit := input.Limit
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 || len(items) > limit {
		return false
	}
	var previous identityprovider.MappingCursor
	hasPrevious := false
	if input.After != nil {
		previous = *input.After
		hasPrevious = true
	}
	for _, item := range items {
		current, err := identityprovider.NewMappingCursor(item.Priority, item.ID)
		if err != nil || hasPrevious && compareLDAPMappingCursor(previous, current) >= 0 {
			return false
		}
		previous = current
		hasPrevious = true
	}
	if nextCursor == nil {
		return true
	}
	return len(items) > 0 && *nextCursor == previous
}

func compareLDAPMappingCursor(left, right identityprovider.MappingCursor) int {
	if left.Priority < right.Priority {
		return -1
	}
	if left.Priority > right.Priority {
		return 1
	}
	return uuidCompare(left.ID, right.ID)
}

func uuidCompare(left, right uuid.UUID) int {
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}

func validLDAPTimestampPointer(value *time.Time) bool {
	return value == nil || !value.IsZero()
}

func mapLDAPPinnedSnapshot(
	value identityprovider.PinnedPlannerSnapshot,
) (contract.TenantLDAPPinnedPlannerSnapshot, error) {
	if !validLDAPAdministrationID(value.ProviderID) || !validLDAPAdministrationID(value.BindingID) ||
		!validLDAPAdministrationID(value.AccessEpochID) || value.ProviderVersion < 1 ||
		value.ProviderVersion > maximumResourceVersion || value.BindingVersion < 1 ||
		value.BindingVersion > maximumResourceVersion || value.ConfigurationRevision < 1 ||
		len(value.MappingRevisions) > 1000 {
		return contract.TenantLDAPPinnedPlannerSnapshot{}, errors.New("invalid LDAP pinned snapshot")
	}
	revisions := make([]contract.TenantLDAPPinnedMappingRevision, 0, len(value.MappingRevisions))
	seen := make(map[uuid.UUID]struct{}, len(value.MappingRevisions))
	for _, revision := range value.MappingRevisions {
		if !validLDAPAdministrationID(revision.MappingID) || revision.MappingVersion < 1 ||
			revision.MappingVersion > maximumResourceVersion ||
			(revision.SourceEpochID == nil) != (revision.SourceEpochSequence == nil) ||
			revision.SourceEpochID != nil && (!validLDAPAdministrationID(*revision.SourceEpochID) ||
				revision.SourceEpochSequence == nil || *revision.SourceEpochSequence < 1) {
			return contract.TenantLDAPPinnedPlannerSnapshot{}, errors.New("invalid LDAP pinned mapping revision")
		}
		if _, duplicate := seen[revision.MappingID]; duplicate {
			return contract.TenantLDAPPinnedPlannerSnapshot{}, errors.New("duplicate LDAP pinned mapping revision")
		}
		seen[revision.MappingID] = struct{}{}
		revisions = append(revisions, contract.TenantLDAPPinnedMappingRevision{
			MappingId: revision.MappingID, MappingVersion: contract.ResourceVersion(revision.MappingVersion),
			SourceEpochId:       cloneUUIDPointer(revision.SourceEpochID),
			SourceEpochSequence: cloneIntPointer(revision.SourceEpochSequence),
		})
	}
	return contract.TenantLDAPPinnedPlannerSnapshot{
		ProviderId: value.ProviderID, ProviderVersion: contract.ResourceVersion(value.ProviderVersion),
		BindingId: value.BindingID, BindingVersion: contract.ResourceVersion(value.BindingVersion),
		ConfigurationRevision: value.ConfigurationRevision, AccessEpochId: value.AccessEpochID,
		MappingRevisions: revisions,
	}, nil
}

func mapLDAPDryRunResult(
	value identityprovider.DryRunResult,
) (contract.TenantLDAPMappingDryRunResult, error) {
	outcome := contract.TenantLDAPMappingDryRunResultOutcome(value.Outcome)
	decision := contract.TenantLDAPMappingDryRunResultDecision(value.Decision)
	disposition := contract.TenantLDAPMappingDryRunResultIdentityDisposition(value.IdentityDisposition)
	if !validLDAPAdministrationID(value.ID) || !outcome.Valid() || !decision.Valid() ||
		!disposition.Valid() || value.GeneratedAt.IsZero() || len(value.DenialReasons) > 32 ||
		len(value.MatchedMappingIDs) > 1000 || !validUniqueLDAPAdministrationIDs(value.MatchedMappingIDs) {
		return contract.TenantLDAPMappingDryRunResult{}, errors.New("invalid LDAP dry-run projection")
	}
	snapshot, err := mapLDAPPinnedSnapshot(value.Snapshot)
	if err != nil {
		return contract.TenantLDAPMappingDryRunResult{}, err
	}
	denialReasons := make([]contract.TenantLDAPMappingDryRunResultDenialReasons, 0, len(value.DenialReasons))
	seenDenials := make(map[string]struct{}, len(value.DenialReasons))
	for _, reason := range value.DenialReasons {
		mapped := contract.TenantLDAPMappingDryRunResultDenialReasons(reason)
		if !mapped.Valid() {
			return contract.TenantLDAPMappingDryRunResult{}, errors.New("invalid LDAP dry-run denial reason")
		}
		if _, duplicate := seenDenials[reason]; duplicate {
			return contract.TenantLDAPMappingDryRunResult{}, errors.New("duplicate LDAP dry-run denial reason")
		}
		seenDenials[reason] = struct{}{}
		denialReasons = append(denialReasons, mapped)
	}
	plan, err := mapLDAPDryRunPlan(value.Plan)
	if err != nil {
		return contract.TenantLDAPMappingDryRunResult{}, err
	}
	return contract.TenantLDAPMappingDryRunResult{
		DryRunId: value.ID, Outcome: outcome, Decision: decision,
		IdentityDisposition: disposition, ObservationComplete: value.ObservationComplete,
		DenialReasons: denialReasons, MatchedMappingIds: cloneUUIDs(value.MatchedMappingIDs),
		Snapshot: snapshot, Plan: plan, GeneratedAt: value.GeneratedAt.UTC(),
	}, nil
}

func mapLDAPDryRunPlan(value identityprovider.DryRunPlan) (contract.TenantLDAPMappingDryRunPlan, error) {
	profileAction := contract.TenantLDAPMappingDryRunPlanProfileAction(value.ProfileAction)
	providerAction := contract.TenantLDAPDryRunAction(value.ProviderAccessAction)
	if !profileAction.Valid() || !providerAction.Valid() || len(value.GroupActions) > 1000 ||
		len(value.RoleActions) > 1000 || len(value.OperatorTeamActions) > 1000 {
		return contract.TenantLDAPMappingDryRunPlan{}, errors.New("invalid LDAP dry-run plan")
	}
	groupActions := make([]contract.TenantLDAPDryRunGroupAction, 0, len(value.GroupActions))
	for _, action := range value.GroupActions {
		mappedAction := contract.TenantLDAPDryRunAction(action.Action)
		if !validLDAPAdministrationID(action.TenantSecurityGroupID) || !mappedAction.Valid() ||
			len(action.SourceMappingIDs) < 1 || len(action.SourceMappingIDs) > 1000 ||
			!validUniqueLDAPAdministrationIDs(action.SourceMappingIDs) {
			return contract.TenantLDAPMappingDryRunPlan{}, errors.New("invalid LDAP dry-run group action")
		}
		groupActions = append(groupActions, contract.TenantLDAPDryRunGroupAction{
			TenantSecurityGroupId: action.TenantSecurityGroupID, Action: mappedAction,
			SourceMappingIds: cloneUUIDs(action.SourceMappingIDs),
		})
	}
	roleActions := make([]contract.TenantLDAPDryRunRoleAction, 0, len(value.RoleActions))
	for _, action := range value.RoleActions {
		mappedAction := contract.TenantLDAPDryRunAction(action.Action)
		if !validLDAPAdministrationID(action.RoleID) || !mappedAction.Valid() ||
			len(action.SourceMappingIDs) < 1 || len(action.SourceMappingIDs) > 1000 ||
			!validUniqueLDAPAdministrationIDs(action.SourceMappingIDs) {
			return contract.TenantLDAPMappingDryRunPlan{}, errors.New("invalid LDAP dry-run role action")
		}
		roleActions = append(roleActions, contract.TenantLDAPDryRunRoleAction{
			RoleId: action.RoleID, Action: mappedAction, SourceMappingIds: cloneUUIDs(action.SourceMappingIDs),
		})
	}
	teamActions := make([]contract.TenantLDAPDryRunOperatorTeamAction, 0, len(value.OperatorTeamActions))
	for _, action := range value.OperatorTeamActions {
		mappedAction := contract.TenantLDAPDryRunAction(action.Action)
		if !validLDAPAdministrationID(action.OperatorTeamID) ||
			!validLDAPAdministrationID(action.AssignmentEpochID) || !mappedAction.Valid() ||
			len(action.SourceMappingIDs) < 1 || len(action.SourceMappingIDs) > 1000 ||
			!validUniqueLDAPAdministrationIDs(action.SourceMappingIDs) {
			return contract.TenantLDAPMappingDryRunPlan{}, errors.New("invalid LDAP dry-run team action")
		}
		teamActions = append(teamActions, contract.TenantLDAPDryRunOperatorTeamAction{
			OperatorTeamId: action.OperatorTeamID, AssignmentEpochId: action.AssignmentEpochID,
			Action: mappedAction, SourceMappingIds: cloneUUIDs(action.SourceMappingIDs),
		})
	}
	return contract.TenantLDAPMappingDryRunPlan{
		ProfileAction: profileAction, ProviderAccessAction: providerAction,
		GroupActions: groupActions, RoleActions: roleActions, OperatorTeamActions: teamActions,
	}, nil
}

func mapLDAPSyncStatus(value identityprovider.SyncStatus) (contract.TenantLDAPSyncStatus, error) {
	scheduleState := contract.TenantLDAPSyncStatusScheduleState(value.ScheduleState)
	if !validLDAPAdministrationID(value.BindingID) || !scheduleState.Valid() ||
		value.SyncIntervalSeconds != nil && (*value.SyncIntervalSeconds < 300 || *value.SyncIntervalSeconds > 2_592_000) ||
		value.ActiveRunID != nil && !validLDAPAdministrationID(*value.ActiveRunID) ||
		value.LastRunID != nil && !validLDAPAdministrationID(*value.LastRunID) ||
		(value.LastRunID == nil) != (value.LastRunState == nil) || !validLDAPTimestampPointer(value.LastCompletedAt) ||
		!validLDAPTimestampPointer(value.NextScheduledAt) || value.Version < 1 ||
		value.Version > maximumResourceVersion || value.UpdatedAt.IsZero() {
		return contract.TenantLDAPSyncStatus{}, errors.New("invalid LDAP sync status")
	}
	var lastState *contract.TenantLDAPSyncRunState
	if value.LastRunState != nil {
		mapped := contract.TenantLDAPSyncRunState(*value.LastRunState)
		if !mapped.Valid() {
			return contract.TenantLDAPSyncStatus{}, errors.New("invalid LDAP last sync state")
		}
		lastState = &mapped
	}
	return contract.TenantLDAPSyncStatus{
		BindingId: value.BindingID, ScheduleState: scheduleState,
		SyncIntervalSeconds: cloneIntPointer(value.SyncIntervalSeconds), ActiveRunId: cloneUUIDPointer(value.ActiveRunID),
		LastRunId: cloneUUIDPointer(value.LastRunID), LastRunState: lastState,
		LastCompletedAt: utcTimePointer(value.LastCompletedAt), NextScheduledAt: utcTimePointer(value.NextScheduledAt),
		Version: contract.ResourceVersion(value.Version), UpdatedAt: value.UpdatedAt.UTC(),
	}, nil
}

func mapLDAPSyncRun(value identityprovider.SyncRun) (contract.TenantLDAPSyncRun, error) {
	state := contract.TenantLDAPSyncRunState(value.State)
	trigger := contract.TenantLDAPSyncRunTrigger(value.Trigger)
	if !validLDAPAdministrationID(value.ID) || !validLDAPAdministrationID(value.TenantID) ||
		!validLDAPAdministrationID(value.BindingID) || !validLDAPAdministrationID(value.ProviderID) ||
		!state.Valid() || !trigger.Valid() || value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) ||
		!validLDAPTimestampPointer(value.StartedAt) || !validLDAPTimestampPointer(value.CompletedAt) ||
		value.Version < 1 || value.Version > maximumResourceVersion ||
		(value.Trigger == "manual" && (value.ManualReason == nil || !validLDAPText(*value.ManualReason, 1, 500, false))) ||
		(value.Trigger == "scheduled" && value.ManualReason != nil) {
		return contract.TenantLDAPSyncRun{}, errors.New("invalid LDAP sync run")
	}
	snapshot, err := mapLDAPPinnedSnapshot(value.Snapshot)
	if err != nil || value.Snapshot.ProviderID != value.ProviderID || value.Snapshot.BindingID != value.BindingID {
		return contract.TenantLDAPSyncRun{}, errors.New("inconsistent LDAP sync snapshot")
	}
	enumeration, err := mapLDAPSyncEnumeration(value.Enumeration)
	if err != nil {
		return contract.TenantLDAPSyncRun{}, err
	}
	counters, err := mapLDAPSyncCounters(value.Counters)
	if err != nil {
		return contract.TenantLDAPSyncRun{}, err
	}
	var runError *contract.TenantLDAPSyncRunRunErrorCategory
	if value.RunErrorCategory != nil {
		mapped := contract.TenantLDAPSyncRunRunErrorCategory(*value.RunErrorCategory)
		if !mapped.Valid() {
			return contract.TenantLDAPSyncRun{}, errors.New("invalid LDAP sync error category")
		}
		runError = &mapped
	}
	return contract.TenantLDAPSyncRun{
		Id: value.ID, TenantId: value.TenantID, BindingId: value.BindingID, ProviderId: value.ProviderID,
		Trigger: trigger, ManualReason: cloneStringPointer(value.ManualReason), State: state,
		Snapshot: snapshot, Enumeration: enumeration, Counters: counters, RunErrorCategory: runError,
		CreatedAt: value.CreatedAt.UTC(), StartedAt: utcTimePointer(value.StartedAt),
		CompletedAt: utcTimePointer(value.CompletedAt), Version: contract.ResourceVersion(value.Version),
		UpdatedAt: value.UpdatedAt.UTC(),
	}, nil
}

func mapLDAPSyncEnumeration(
	value identityprovider.SyncEnumeration,
) (contract.TenantLDAPSyncEnumeration, error) {
	state := contract.TenantLDAPSyncEnumerationState(value.State)
	cursorState := contract.TenantLDAPSyncEnumerationCursorState(value.CursorState)
	if !state.Valid() || !cursorState.Valid() || value.EntryCount < 0 || value.EntryCount > 10_000_000 ||
		value.PageCount < 0 || value.PageCount > 100_000 || value.ResponseBytes < 0 ||
		value.ResponseBytes > 1_073_741_824 || !validLDAPSyncEnumerationFlags(value) {
		return contract.TenantLDAPSyncEnumeration{}, errors.New("invalid LDAP sync enumeration")
	}
	var category *contract.TenantLDAPSyncEnumerationErrorCategory
	if value.ErrorCategory != nil {
		mapped := contract.TenantLDAPSyncEnumerationErrorCategory(*value.ErrorCategory)
		if !mapped.Valid() {
			return contract.TenantLDAPSyncEnumeration{}, errors.New("invalid LDAP enumeration error category")
		}
		category = &mapped
	}
	return contract.TenantLDAPSyncEnumeration{
		State: state, Complete: value.Complete, Truncated: value.Truncated,
		AbsenceBasedRevocationAllowed: value.AbsenceBasedRevocationAllowed,
		EntryCount:                    value.EntryCount, PageCount: value.PageCount, ResponseBytes: value.ResponseBytes,
		CursorState: cursorState, ErrorCategory: category,
	}, nil
}

func validLDAPSyncEnumerationFlags(value identityprovider.SyncEnumeration) bool {
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

func mapLDAPSyncCounters(
	value identityprovider.SyncCounters,
) (contract.TenantLDAPSyncCounters, error) {
	values := [...]int{
		value.Observed, value.Staged, value.IdentitiesCreated, value.IdentitiesLinked,
		value.ProviderAccessAdded, value.ProviderAccessSuspended, value.GroupEdgesAdded,
		value.GroupEdgesRefreshed, value.GroupEdgesRevoked, value.RoleEdgesAdded,
		value.RoleEdgesRefreshed, value.RoleEdgesRevoked, value.RosterEdgesAdded,
		value.RosterEdgesRefreshed, value.RosterEdgesRevoked, value.Failed,
	}
	for _, count := range values {
		if count < 0 || count > 10_000_000 {
			return contract.TenantLDAPSyncCounters{}, errors.New("invalid LDAP sync counter")
		}
	}
	return contract.TenantLDAPSyncCounters{
		Observed: value.Observed, Staged: value.Staged,
		IdentitiesCreated: value.IdentitiesCreated, IdentitiesLinked: value.IdentitiesLinked,
		ProviderAccessAdded: value.ProviderAccessAdded, ProviderAccessSuspended: value.ProviderAccessSuspended,
		GroupEdgesAdded: value.GroupEdgesAdded, GroupEdgesRefreshed: value.GroupEdgesRefreshed,
		GroupEdgesRevoked: value.GroupEdgesRevoked, RoleEdgesAdded: value.RoleEdgesAdded,
		RoleEdgesRefreshed: value.RoleEdgesRefreshed, RoleEdgesRevoked: value.RoleEdgesRevoked,
		RosterEdgesAdded: value.RosterEdgesAdded, RosterEdgesRefreshed: value.RosterEdgesRefreshed,
		RosterEdgesRevoked: value.RosterEdgesRevoked, Failed: value.Failed,
	}, nil
}
