package identityprovider

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const mappingDryRunReason = "administrative mapping dry run"

func (s *Service) DryRunMappings(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input DryRunInput,
) (DryRunResult, error) {
	normalized, err := normalizeDryRun(input)
	if err != nil {
		return DryRunResult{}, err
	}
	authority, err := s.resolveAndRequire(
		ctx,
		actor,
		tenantID,
		authorization.TenantPermissionIdentityMappingManage,
	)
	if err != nil {
		return DryRunResult{}, err
	}
	if err := s.evaluator.RequireTenant(
		authority,
		authorization.TenantPermissionIdentityProviderTest,
		authorization.ResourceContext{TenantID: tenantID},
	); err != nil {
		return DryRunResult{}, ErrForbidden
	}
	if s.mappingDryRuns == nil || s.directoryOps == nil || s.observer == nil {
		return DryRunResult{}, ErrUnavailable
	}
	operationRunID, beginAuditEventID, completionAuditEventID, err := s.mappingDryRunIDs()
	if err != nil {
		return DryRunResult{}, err
	}
	startedAt, err := s.currentTime()
	if err != nil {
		return DryRunResult{}, err
	}
	human := HumanParams{
		Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID,
	}
	snapshot, err := s.mappingDryRuns.BeginMappingDryRun(
		ctx,
		BeginMappingDryRunParams{
			HumanParams: human, Audit: normalized.Audit, OccurredAt: startedAt,
			OperationRunID: operationRunID, AuditEventID: beginAuditEventID,
			BindingID:                 normalized.BindingID,
			IncludeDisabledMappingIDs: append([]uuid.UUID(nil), normalized.IncludeDisabledMappingIDs...),
			Reason:                    mappingDryRunReason,
		},
	)
	if err != nil {
		return DryRunResult{}, mapRepositoryError(err)
	}
	defer clear(snapshot.Secret.Envelope.Ciphertext)
	if !validMappingDryRunNetworkSnapshot(
		snapshot,
		tenantID,
		normalized.BindingID,
		operationRunID,
		normalized.IncludeDisabledMappingIDs,
	) {
		return s.failMappingDryRun(
			ctx, human, normalized.Audit, snapshot, operationRunID,
			completionAuditEventID, startedAt, ErrUnavailable,
		)
	}
	plaintext, err := s.keyring.DecryptBindSecret(
		bindSecretContext(tenantID, snapshot.ProviderID, snapshot.Secret.SecretID),
		snapshot.Secret.Envelope,
	)
	if err != nil {
		return s.failMappingDryRun(
			ctx, human, normalized.Audit, snapshot, operationRunID,
			completionAuditEventID, startedAt, ErrUnavailable,
		)
	}
	defer clear(plaintext)
	request, err := directoryObservationRequest(
		snapshot.Configuration,
		snapshot.Endpoints,
		normalized.Username,
	)
	if err != nil {
		clear(plaintext)
		return s.failMappingDryRun(
			ctx, human, normalized.Audit, snapshot, operationRunID,
			completionAuditEventID, startedAt, ErrUnavailable,
		)
	}
	defer clearDirectoryObservationRequest(&request)

	directoryResult, networkErr := s.observer.ObserveDirectory(ctx, request, plaintext)
	clear(plaintext)
	completedAt, err := s.currentTime()
	if err != nil {
		return DryRunResult{}, err
	}
	duration := boundedDirectoryDuration(startedAt, completedAt)
	reported := reportedDirectoryObservation(directoryResult, networkErr, duration)

	if networkErr != nil {
		completion, completionErr := s.completeDirectoryInspection(
			ctx, human, normalized.Audit, operationRunID, completionAuditEventID,
			completedAt, reported, 0, false,
		)
		if completionErr != nil {
			return DryRunResult{}, completionErr
		}
		if ctx.Err() != nil {
			return DryRunResult{}, ctx.Err()
		}
		if staleDirectoryCompletion(completion, operationRunID) {
			return staleMappingDryRunResult(snapshot, operationRunID, completion.Diagnostic.CompletedAt)
		}
		if errors.Is(networkErr, ldapclient.ErrBusy) {
			return DryRunResult{}, ErrRateLimited
		}
		return DryRunResult{}, ErrUnavailable
	}

	if reason, expectedFailure := directoryObservationDenialReason(directoryResult.Category); expectedFailure {
		completion, completionErr := s.completeDirectoryInspection(
			ctx, human, normalized.Audit, operationRunID, completionAuditEventID,
			completedAt, reported, 0, false,
		)
		if completionErr != nil {
			return DryRunResult{}, completionErr
		}
		if ctx.Err() != nil {
			return DryRunResult{}, ctx.Err()
		}
		if staleDirectoryCompletion(completion, operationRunID) {
			return staleMappingDryRunResult(snapshot, operationRunID, completion.Diagnostic.CompletedAt)
		}
		if !validFailedDirectoryCompletion(completion, operationRunID) {
			return DryRunResult{}, ErrUnavailable
		}
		return incompleteMappingDryRunResult(
			snapshot,
			operationRunID,
			completion.Diagnostic.CompletedAt,
			"failure",
			reason,
		), nil
	}
	if directoryResult.Category != ldapclient.DirectoryCategorySuccess ||
		directoryResult.EndpointPriority < 1 || directoryResult.EndpointPriority > 8 {
		completion, completionErr := s.completeDirectoryInspection(
			ctx, human, normalized.Audit, operationRunID, completionAuditEventID,
			completedAt, reported, 0, false,
		)
		if completionErr != nil {
			return DryRunResult{}, completionErr
		}
		if ctx.Err() != nil {
			return DryRunResult{}, ctx.Err()
		}
		if staleDirectoryCompletion(completion, operationRunID) {
			return staleMappingDryRunResult(snapshot, operationRunID, completion.Diagnostic.CompletedAt)
		}
		if !validReportedFailureCompletion(completion, operationRunID, reported) {
			return DryRunResult{}, ErrUnavailable
		}
		return DryRunResult{}, ErrUnavailable
	}

	normalization, err := directoryNormalizationConfiguration(
		snapshot.Configuration,
		normalized.Username,
	)
	if err != nil {
		return s.failMappingDryRunAt(
			ctx, human, normalized.Audit, snapshot, operationRunID,
			completionAuditEventID, completedAt, duration, ErrUnavailable,
		)
	}
	observation, err := ldapclient.NormalizeDirectoryObservation(
		normalization,
		directoryResult.Observation,
	)
	if err != nil {
		return s.failMappingDryRunAt(
			ctx, human, normalized.Audit, snapshot, operationRunID,
			completionAuditEventID, completedAt, duration, ErrUnavailable,
		)
	}
	aliases, err := observation.SubjectAliases(
		s.keyring,
		identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: identity.EntityID(tenantID),
			ProviderID: identity.EntityID(snapshot.ProviderID),
		},
	)
	if err != nil {
		return s.failMappingDryRunAt(
			ctx, human, normalized.Audit, snapshot, operationRunID,
			completionAuditEventID, completedAt, duration, ErrUnavailable,
		)
	}
	defer clearSubjectAliases(aliases)
	lookupAliases := append([]identity.SubjectAlias(nil), aliases...)
	planning, err := s.mappingDryRuns.GetMappingDryRunPlanningSnapshot(
		ctx,
		GetMappingDryRunPlanningSnapshotParams{
			HumanParams: human, OperationRunID: operationRunID,
			SubjectAliases: lookupAliases,
		},
	)
	clearSubjectAliases(lookupAliases)
	if err != nil || !matchingMappingDryRunPins(snapshot, planning) {
		failure := ErrUnavailable
		if err != nil {
			failure = mapRepositoryError(err)
		}
		return s.failMappingDryRunAt(
			ctx, human, normalized.Audit, snapshot, operationRunID,
			completionAuditEventID, completedAt, duration, failure,
		)
	}
	plan, err := identity.PlanLDAPMapping(observation, planning.Planning)
	if err != nil {
		return s.failMappingDryRunAt(
			ctx, human, normalized.Audit, snapshot, operationRunID,
			completionAuditEventID, completedAt, duration, ErrUnavailable,
		)
	}
	projection, err := projectMappingDryRunPlan(plan, planning.Planning)
	if err != nil {
		return s.failMappingDryRunAt(
			ctx, human, normalized.Audit, snapshot, operationRunID,
			completionAuditEventID, completedAt, duration, ErrUnavailable,
		)
	}
	completion, err := s.completeDirectoryInspection(
		ctx, human, normalized.Audit, operationRunID, completionAuditEventID,
		completedAt, reported, 1, false,
	)
	if err != nil {
		return DryRunResult{}, err
	}
	if ctx.Err() != nil {
		return DryRunResult{}, ctx.Err()
	}
	if staleDirectoryCompletion(completion, operationRunID) {
		return staleMappingDryRunResult(snapshot, operationRunID, completion.Diagnostic.CompletedAt)
	}
	if !validSuccessfulDirectoryCompletion(completion, operationRunID) {
		return DryRunResult{}, ErrUnavailable
	}
	return completedMappingDryRunResult(
		snapshot,
		operationRunID,
		completion.Diagnostic.CompletedAt,
		plan,
		planning.Planning,
		projection,
	)
}

func (s *Service) mappingDryRunIDs() (uuid.UUID, uuid.UUID, uuid.UUID, error) {
	runID, err := s.nextID()
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	beginAuditID, err := s.nextID()
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	completionAuditID, err := s.nextID()
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	if runID == beginAuditID || runID == completionAuditID || beginAuditID == completionAuditID {
		return uuid.Nil, uuid.Nil, uuid.Nil, ErrUnavailable
	}
	return runID, beginAuditID, completionAuditID, nil
}

func (s *Service) failMappingDryRun(
	ctx context.Context,
	human HumanParams,
	audit authorization.AuditContext,
	snapshot DirectoryOperationSnapshot,
	operationRunID, completionAuditEventID uuid.UUID,
	startedAt time.Time,
	failure error,
) (DryRunResult, error) {
	completedAt, err := s.currentTime()
	if err != nil {
		return DryRunResult{}, err
	}
	return s.failMappingDryRunAt(
		ctx, human, audit, snapshot, operationRunID, completionAuditEventID,
		completedAt, boundedDirectoryDuration(startedAt, completedAt), failure,
	)
}

func (s *Service) failMappingDryRunAt(
	ctx context.Context,
	human HumanParams,
	audit authorization.AuditContext,
	snapshot DirectoryOperationSnapshot,
	operationRunID, completionAuditEventID uuid.UUID,
	completedAt time.Time,
	duration time.Duration,
	failure error,
) (DryRunResult, error) {
	completion, err := s.completeDirectoryInspection(
		ctx, human, audit, operationRunID, completionAuditEventID, completedAt,
		directoryInspectionReport{
			outcome: TestOutcomeFailure, category: TestCategoryCancelled,
			endpointPriority: nil, duration: duration,
		},
		0,
		false,
	)
	if err != nil {
		return DryRunResult{}, err
	}
	if ctx.Err() != nil {
		return DryRunResult{}, ctx.Err()
	}
	if staleDirectoryCompletion(completion, operationRunID) && validMappingDryRunPublicPins(snapshot) {
		return staleMappingDryRunResult(snapshot, operationRunID, completion.Diagnostic.CompletedAt)
	}
	if failure == nil {
		failure = ErrUnavailable
	}
	return DryRunResult{}, failure
}

func boundedDirectoryDuration(startedAt, completedAt time.Time) time.Duration {
	duration := completedAt.Sub(startedAt).Truncate(time.Millisecond)
	if duration < 0 {
		return 0
	}
	return min(duration, 120*time.Second)
}

func reportedDirectoryObservation(
	result ldapclient.DirectoryResult,
	err error,
	duration time.Duration,
) directoryInspectionReport {
	if err != nil {
		return directoryInspectionReport{
			outcome: TestOutcomeFailure, category: TestCategoryCancelled, duration: duration,
		}
	}
	if result.Category == ldapclient.DirectoryCategoryCancelled ||
		result.EndpointPriority < 1 || result.EndpointPriority > 8 {
		return directoryInspectionReport{
			outcome: TestOutcomeFailure, category: TestCategoryCancelled, duration: duration,
		}
	}
	priority := result.EndpointPriority
	if result.Category == ldapclient.DirectoryCategorySuccess {
		return directoryInspectionReport{
			outcome: TestOutcomeSuccess, category: TestCategorySuccess,
			endpointPriority: &priority, duration: duration,
		}
	}
	return directoryInspectionReport{
		outcome:          TestOutcomeFailure,
		category:         directoryInspectionTestCategory(result.Category),
		endpointPriority: &priority,
		duration:         duration,
	}
}

func directoryObservationDenialReason(category ldapclient.DirectoryCategory) (string, bool) {
	switch category {
	case ldapclient.DirectoryCategoryUserNotFound:
		return "identity_not_found", true
	case ldapclient.DirectoryCategoryUserAmbiguous:
		return "identity_ambiguous", true
	default:
		return "", false
	}
}

func validMappingDryRunNetworkSnapshot(
	value DirectoryOperationSnapshot,
	tenantID, bindingID, operationRunID uuid.UUID,
	requestedDisabled []uuid.UUID,
) bool {
	if value.OperationRunID != operationRunID || value.TenantID != tenantID ||
		value.OperationKind != DirectoryOperationSearchUser ||
		!validUUIDv7(value.OperationRunID) || !validUUIDv7(value.TenantID) ||
		!validUUIDv7(value.ProviderID) || allZeroDigest(value.EndpointSnapshotDigest) ||
		value.ProviderVersion < 1 || value.ProviderVersion > maximumResourceVersion ||
		value.ConfigurationVersion < 1 || value.ConfigurationVersion > maximumResourceVersion ||
		value.SecretVersion < 1 || value.SecretVersion > maximumResourceVersion ||
		!validUUIDv7(value.Secret.SecretID) || value.Secret.Envelope.KeyVersion < 1 ||
		len(value.Secret.Envelope.Ciphertext) < 17 || len(value.Secret.Envelope.Ciphertext) > 8192 ||
		!validInstant(value.StartedAt) || !validInstant(value.ExpiresAt) ||
		!value.ExpiresAt.After(value.StartedAt) || value.ExpiresAt.Sub(value.StartedAt) > 2*time.Minute ||
		value.BindingID == nil || *value.BindingID != bindingID || !validUUIDv7(*value.BindingID) ||
		value.BindingVersion == nil || *value.BindingVersion < 1 ||
		*value.BindingVersion > maximumResourceVersion || value.BindingAuthRevision == nil ||
		*value.BindingAuthRevision < 1 || value.BindingAccessEpochID == nil ||
		!validUUIDv7(*value.BindingAccessEpochID) || value.RuleSetRevision == nil ||
		*value.RuleSetRevision < 1 || value.AuthorizationRevision == nil ||
		*value.AuthorizationRevision < 1 || len(value.MappingRevisions) > 1_000 {
		return false
	}
	requested := make(map[uuid.UUID]struct{}, len(requestedDisabled))
	for _, mappingID := range requestedDisabled {
		if !validUUIDv7(mappingID) {
			return false
		}
		requested[mappingID] = struct{}{}
	}
	seen := make(map[uuid.UUID]struct{}, len(value.MappingRevisions))
	for _, revision := range value.MappingRevisions {
		if !validUUIDv7(revision.MappingID) || revision.MappingVersion < 1 ||
			revision.MappingVersion > maximumResourceVersion ||
			(revision.SourceEpochID == nil) != (revision.SourceEpochSequence == nil) ||
			revision.SourceEpochID != nil && (!validUUIDv7(*revision.SourceEpochID) ||
				revision.SourceEpochSequence == nil || *revision.SourceEpochSequence < 1) {
			return false
		}
		if _, duplicate := seen[revision.MappingID]; duplicate {
			return false
		}
		seen[revision.MappingID] = struct{}{}
		_, explicitlyDisabled := requested[revision.MappingID]
		if explicitlyDisabled != (revision.SourceEpochID == nil) {
			return false
		}
		delete(requested, revision.MappingID)
	}
	if len(requested) != 0 {
		return false
	}
	_, _, err := normalizeConfiguration(value.Configuration, value.Endpoints)
	return err == nil
}

func matchingMappingDryRunPins(
	before DirectoryOperationSnapshot,
	after MappingDryRunPlanningSnapshot,
) bool {
	return before.BindingID != nil && before.BindingVersion != nil &&
		before.BindingAuthRevision != nil && before.BindingAccessEpochID != nil &&
		before.RuleSetRevision != nil && before.AuthorizationRevision != nil &&
		after.OperationRunID == before.OperationRunID &&
		after.ProviderID == before.ProviderID && after.ProviderVersion == before.ProviderVersion &&
		after.BindingID == *before.BindingID && after.BindingVersion == *before.BindingVersion &&
		after.BindingAuthRevision == *before.BindingAuthRevision &&
		after.BindingAccessEpochID == *before.BindingAccessEpochID &&
		after.ConfigurationRevision == before.ConfigurationVersion &&
		after.RuleSetRevision == *before.RuleSetRevision &&
		after.AuthorizationRevision == *before.AuthorizationRevision &&
		after.Planning.TenantID == identity.EntityID(before.TenantID) &&
		after.Planning.Provider == (identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: identity.EntityID(before.TenantID),
			ProviderID: identity.EntityID(before.ProviderID),
		}) && after.Planning.BindingID == identity.EntityID(*before.BindingID) &&
		after.Planning.ConfigurationRevision == before.ConfigurationVersion &&
		after.Planning.RuleSetRevision == *before.RuleSetRevision &&
		after.Planning.AuthorizationRevision == *before.AuthorizationRevision &&
		after.Planning.ProviderAccess.AccessEpochID == identity.EntityID(*before.BindingAccessEpochID)
}

func staleDirectoryCompletion(
	completion DirectoryInspectionCompletion,
	operationRunID uuid.UUID,
) bool {
	return validTestResult(completion.Diagnostic, operationRunID) &&
		completion.Diagnostic.Stale &&
		completion.Diagnostic.Outcome == TestOutcomeInconclusive &&
		completion.Diagnostic.Category == TestCategoryStaleConfiguration &&
		completion.MatchedEntryCount == 0 && !completion.Truncated
}

func validSuccessfulDirectoryCompletion(
	completion DirectoryInspectionCompletion,
	operationRunID uuid.UUID,
) bool {
	return validTestResult(completion.Diagnostic, operationRunID) &&
		!completion.Diagnostic.Stale && completion.Diagnostic.Outcome == TestOutcomeSuccess &&
		completion.Diagnostic.Category == TestCategorySuccess &&
		completion.MatchedEntryCount == 1 && !completion.Truncated
}

func validFailedDirectoryCompletion(
	completion DirectoryInspectionCompletion,
	operationRunID uuid.UUID,
) bool {
	return validTestResult(completion.Diagnostic, operationRunID) &&
		!completion.Diagnostic.Stale && completion.Diagnostic.Outcome == TestOutcomeFailure &&
		completion.Diagnostic.Category == TestCategoryProtocolFailed &&
		completion.MatchedEntryCount == 0 && !completion.Truncated
}

func validReportedFailureCompletion(
	completion DirectoryInspectionCompletion,
	operationRunID uuid.UUID,
	reported directoryInspectionReport,
) bool {
	if !validTestResult(completion.Diagnostic, operationRunID) ||
		completion.Diagnostic.Stale || completion.Diagnostic.Outcome != TestOutcomeFailure ||
		completion.Diagnostic.Category != reported.category ||
		completion.MatchedEntryCount != 0 || completion.Truncated {
		return false
	}
	if (completion.Diagnostic.EndpointPriority == nil) != (reported.endpointPriority == nil) {
		return false
	}
	return reported.endpointPriority == nil ||
		*completion.Diagnostic.EndpointPriority == *reported.endpointPriority
}

func validMappingDryRunPublicPins(value DirectoryOperationSnapshot) bool {
	if !validUUIDv7(value.ProviderID) || value.ProviderVersion < 1 ||
		value.ProviderVersion > maximumResourceVersion || value.BindingID == nil ||
		!validUUIDv7(*value.BindingID) || value.BindingVersion == nil ||
		*value.BindingVersion < 1 || *value.BindingVersion > maximumResourceVersion ||
		value.ConfigurationVersion < 1 || value.ConfigurationVersion > maximumResourceVersion ||
		value.BindingAccessEpochID == nil || !validUUIDv7(*value.BindingAccessEpochID) ||
		len(value.MappingRevisions) > 1_000 {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(value.MappingRevisions))
	for _, revision := range value.MappingRevisions {
		if !validUUIDv7(revision.MappingID) || revision.MappingVersion < 1 ||
			revision.MappingVersion > maximumResourceVersion ||
			(revision.SourceEpochID == nil) != (revision.SourceEpochSequence == nil) ||
			revision.SourceEpochID != nil && (!validUUIDv7(*revision.SourceEpochID) ||
				revision.SourceEpochSequence == nil || *revision.SourceEpochSequence < 1) {
			return false
		}
		if _, duplicate := seen[revision.MappingID]; duplicate {
			return false
		}
		seen[revision.MappingID] = struct{}{}
	}
	return true
}

func pinnedMappingDryRunSnapshot(value DirectoryOperationSnapshot) PinnedPlannerSnapshot {
	revisions := make([]PinnedMappingRevision, 0, len(value.MappingRevisions))
	for _, revision := range value.MappingRevisions {
		mapped := PinnedMappingRevision{
			MappingID: revision.MappingID, MappingVersion: revision.MappingVersion,
		}
		if revision.SourceEpochID != nil {
			id := *revision.SourceEpochID
			sequence := *revision.SourceEpochSequence
			mapped.SourceEpochID = &id
			mapped.SourceEpochSequence = &sequence
		}
		revisions = append(revisions, mapped)
	}
	return PinnedPlannerSnapshot{
		ProviderID: value.ProviderID, ProviderVersion: value.ProviderVersion,
		BindingID: *value.BindingID, BindingVersion: *value.BindingVersion,
		ConfigurationRevision: int(value.ConfigurationVersion),
		AccessEpochID:         *value.BindingAccessEpochID, MappingRevisions: revisions,
	}
}

func incompleteMappingDryRunResult(
	snapshot DirectoryOperationSnapshot,
	operationRunID uuid.UUID,
	generatedAt time.Time,
	outcome, reason string,
) DryRunResult {
	return DryRunResult{
		ID: operationRunID, Outcome: outcome, Decision: "deny",
		IdentityDisposition: "unresolved", ObservationComplete: false,
		DenialReasons: []string{reason}, MatchedMappingIDs: []uuid.UUID{},
		Snapshot: pinnedMappingDryRunSnapshot(snapshot),
		Plan: DryRunPlan{
			ProfileAction: "none", ProviderAccessAction: DryRunActionNone,
			GroupActions: []DryRunGroupAction{}, RoleActions: []DryRunRoleAction{},
			OperatorTeamActions: []DryRunOperatorTeamAction{},
		},
		GeneratedAt: generatedAt,
	}
}

func staleMappingDryRunResult(
	snapshot DirectoryOperationSnapshot,
	operationRunID uuid.UUID,
	generatedAt time.Time,
) (DryRunResult, error) {
	if !validInstant(generatedAt) {
		return DryRunResult{}, ErrUnavailable
	}
	return incompleteMappingDryRunResult(
		snapshot, operationRunID, generatedAt, "inconclusive", "stale_snapshot",
	), nil
}

func completedMappingDryRunResult(
	snapshot DirectoryOperationSnapshot,
	operationRunID uuid.UUID,
	generatedAt time.Time,
	plan identity.LDAPMappingPlan,
	planning identity.LDAPPlanningSnapshot,
	projection DryRunPlan,
) (DryRunResult, error) {
	if !validInstant(generatedAt) {
		return DryRunResult{}, ErrUnavailable
	}
	matched, err := mappingPlanIDs(plan.MatchedRuleIDs())
	if err != nil {
		return DryRunResult{}, err
	}
	result := DryRunResult{
		ID: operationRunID, Outcome: "success", ObservationComplete: true,
		MatchedMappingIDs: matched, Snapshot: pinnedMappingDryRunSnapshot(snapshot),
		Plan: projection, GeneratedAt: generatedAt,
	}
	if plan.Disposition() == identity.LDAPPlanAdmitted {
		result.Decision = "allow"
		if planning.ProviderAccess.ExternalIdentityExists {
			result.IdentityDisposition = "existing_identity"
		} else if plan.IdentityAction() == identity.LDAPIdentityCreateUserAndExternalIdentity {
			result.IdentityDisposition = "create"
		} else {
			return DryRunResult{}, ErrUnavailable
		}
		result.DenialReasons = []string{}
		return result, nil
	}
	if plan.Disposition() != identity.LDAPPlanDenied {
		return DryRunResult{}, ErrUnavailable
	}
	reason, ok := mappingPlanDenialReason(plan.Reason())
	if !ok {
		return DryRunResult{}, ErrUnavailable
	}
	result.Decision = "deny"
	result.IdentityDisposition = "deny"
	result.DenialReasons = []string{reason}
	return result, nil
}

func mappingPlanDenialReason(reason identity.LDAPPlanReason) (string, bool) {
	switch reason {
	case identity.LDAPPlanReasonIncompleteObservation:
		return "incomplete_observation", true
	case identity.LDAPPlanReasonAccountDisabled:
		return "entry_disabled", true
	case identity.LDAPPlanReasonLocalIdentityDisabled:
		return "local_identity_disabled", true
	case identity.LDAPPlanReasonTenantMembershipInactive:
		return "tenant_membership_inactive", true
	case identity.LDAPPlanReasonJITDisabled:
		return "jit_disabled", true
	case identity.LDAPPlanReasonExistingIdentityRequired:
		return "existing_identity_required", true
	case identity.LDAPPlanReasonNoMapping:
		return "no_mapping_match", true
	case identity.LDAPPlanReasonAssignmentInactive:
		return "assignment_epoch_inactive", true
	case identity.LDAPPlanReasonDelegationExceeded:
		return "delegated_authority_denied", true
	default:
		return "", false
	}
}

func projectMappingDryRunPlan(
	plan identity.LDAPMappingPlan,
	snapshot identity.LDAPPlanningSnapshot,
) (DryRunPlan, error) {
	projection := DryRunPlan{
		ProfileAction: "none", ProviderAccessAction: DryRunActionNone,
		GroupActions: []DryRunGroupAction{}, RoleActions: []DryRunRoleAction{},
		OperatorTeamActions: []DryRunOperatorTeamAction{},
	}
	if plan.Disposition() == identity.LDAPPlanAdmitted {
		if plan.IdentityAction() == identity.LDAPIdentityCreateUserAndExternalIdentity {
			projection.ProfileAction = "create"
		} else if snapshot.ProviderAccess.ExternalIdentityExists {
			projection.ProfileAction = "update"
		} else {
			return DryRunPlan{}, ErrUnavailable
		}
		switch plan.ProviderAccessAction() {
		case identity.LDAPProviderAccessEnsure:
			projection.ProviderAccessAction = DryRunActionAdd
		case identity.LDAPProviderAccessNoChange:
			projection.ProviderAccessAction = DryRunActionRetain
		default:
			return DryRunPlan{}, ErrUnavailable
		}
	} else if plan.Disposition() != identity.LDAPPlanDenied {
		return DryRunPlan{}, ErrUnavailable
	}

	sourceMappings := make(map[identity.EntityID]uuid.UUID, len(snapshot.Rules))
	groupRoles := make(map[identity.EntityID][]identity.EntityID, len(snapshot.SecurityGroups))
	for _, group := range snapshot.SecurityGroups {
		groupRoles[group.SecurityGroupID] = append([]identity.EntityID(nil), group.ActiveRoleIDs...)
	}
	for _, rule := range snapshot.Rules {
		mappingID := uuid.UUID(rule.RuleID)
		if !validUUIDv7(mappingID) {
			return DryRunPlan{}, ErrUnavailable
		}
		if _, duplicate := sourceMappings[rule.SourceID]; duplicate {
			return DryRunPlan{}, ErrUnavailable
		}
		sourceMappings[rule.SourceID] = mappingID
	}

	groups := make(map[dryRunResourceAction]map[uuid.UUID]struct{})
	roles := make(map[dryRunResourceAction]map[uuid.UUID]struct{})
	teams := make(map[dryRunTeamResourceAction]map[uuid.UUID]struct{})
	membershipActions := make(map[dryRunSourceResource]DryRunAction)
	for _, change := range plan.Changes() {
		mappingID, exists := sourceMappings[change.SourceID]
		if !exists {
			return DryRunPlan{}, ErrUnavailable
		}
		action, err := mappingChangeAction(change.Operation)
		if err != nil {
			return DryRunPlan{}, err
		}
		primaryID := uuid.UUID(change.Key.PrimaryID)
		if !validUUIDv7(primaryID) {
			return DryRunPlan{}, ErrUnavailable
		}
		switch change.Key.Kind {
		case identity.LDAPSecurityGroupMembershipEdge:
			key := dryRunResourceAction{ID: primaryID, Action: action}
			addDryRunActionSource(groups, key, mappingID)
			membershipActions[dryRunSourceResource{SourceID: change.SourceID, ResourceID: change.Key.PrimaryID}] = action
		case identity.LDAPSecurityGroupRoleGrantEdge:
			roleID := uuid.UUID(change.Key.SecondaryID)
			if !validUUIDv7(roleID) {
				return DryRunPlan{}, ErrUnavailable
			}
			addDryRunActionSource(roles, dryRunResourceAction{ID: roleID, Action: action}, mappingID)
		case identity.LDAPOperatorTeamRosterEdge:
			assignmentID := uuid.UUID(change.Key.SecondaryID)
			if !validUUIDv7(assignmentID) {
				return DryRunPlan{}, ErrUnavailable
			}
			addDryRunTeamActionSource(
				teams,
				dryRunTeamResourceAction{TeamID: primaryID, AssignmentID: assignmentID, Action: action},
				mappingID,
			)
		default:
			return DryRunPlan{}, ErrUnavailable
		}
	}

	matched := make(map[identity.EntityID]struct{}, len(plan.MatchedRuleIDs()))
	for _, mappingID := range plan.MatchedRuleIDs() {
		matched[mappingID] = struct{}{}
	}
	for _, rule := range snapshot.Rules {
		if _, isMatched := matched[rule.RuleID]; !isMatched {
			continue
		}
		action, present := membershipActions[dryRunSourceResource{
			SourceID: rule.SourceID, ResourceID: rule.SecurityGroupID,
		}]
		if !present {
			action = DryRunActionRetain
		} else if action == DryRunActionRefresh {
			action = DryRunActionRetain
		}
		mappingID := uuid.UUID(rule.RuleID)
		for _, roleEntityID := range groupRoles[rule.SecurityGroupID] {
			roleID := uuid.UUID(roleEntityID)
			if !validUUIDv7(roleID) {
				return DryRunPlan{}, ErrUnavailable
			}
			addDryRunActionSource(roles, dryRunResourceAction{ID: roleID, Action: action}, mappingID)
		}
	}
	projection.GroupActions = materializeDryRunGroupActions(groups)
	projection.RoleActions = materializeDryRunRoleActions(roles)
	projection.OperatorTeamActions = materializeDryRunTeamActions(teams)
	return projection, nil
}

type dryRunResourceAction struct {
	ID     uuid.UUID
	Action DryRunAction
}

type dryRunTeamResourceAction struct {
	TeamID       uuid.UUID
	AssignmentID uuid.UUID
	Action       DryRunAction
}

type dryRunSourceResource struct {
	SourceID   identity.EntityID
	ResourceID identity.EntityID
}

func mappingChangeAction(operation identity.LDAPMappingChangeOperation) (DryRunAction, error) {
	switch operation {
	case identity.LDAPMappingEnsure:
		return DryRunActionAdd, nil
	case identity.LDAPMappingRefresh:
		return DryRunActionRefresh, nil
	case identity.LDAPMappingRevoke:
		return DryRunActionRevoke, nil
	default:
		return "", ErrUnavailable
	}
}

func addDryRunActionSource[K comparable](
	destination map[K]map[uuid.UUID]struct{},
	key K,
	mappingID uuid.UUID,
) {
	sources := destination[key]
	if sources == nil {
		sources = make(map[uuid.UUID]struct{})
		destination[key] = sources
	}
	sources[mappingID] = struct{}{}
}

func addDryRunTeamActionSource(
	destination map[dryRunTeamResourceAction]map[uuid.UUID]struct{},
	key dryRunTeamResourceAction,
	mappingID uuid.UUID,
) {
	addDryRunActionSource(destination, key, mappingID)
}

func materializeDryRunGroupActions(
	values map[dryRunResourceAction]map[uuid.UUID]struct{},
) []DryRunGroupAction {
	result := make([]DryRunGroupAction, 0, len(values))
	for key, sources := range values {
		result = append(result, DryRunGroupAction{
			TenantSecurityGroupID: key.ID, Action: key.Action,
			SourceMappingIDs: sortedUUIDSet(sources),
		})
	}
	slices.SortFunc(result, func(left, right DryRunGroupAction) int {
		if comparison := bytes.Compare(left.TenantSecurityGroupID[:], right.TenantSecurityGroupID[:]); comparison != 0 {
			return comparison
		}
		return bytes.Compare([]byte(left.Action), []byte(right.Action))
	})
	return result
}

func materializeDryRunRoleActions(
	values map[dryRunResourceAction]map[uuid.UUID]struct{},
) []DryRunRoleAction {
	result := make([]DryRunRoleAction, 0, len(values))
	for key, sources := range values {
		result = append(result, DryRunRoleAction{
			RoleID: key.ID, Action: key.Action, SourceMappingIDs: sortedUUIDSet(sources),
		})
	}
	slices.SortFunc(result, func(left, right DryRunRoleAction) int {
		if comparison := bytes.Compare(left.RoleID[:], right.RoleID[:]); comparison != 0 {
			return comparison
		}
		return bytes.Compare([]byte(left.Action), []byte(right.Action))
	})
	return result
}

func materializeDryRunTeamActions(
	values map[dryRunTeamResourceAction]map[uuid.UUID]struct{},
) []DryRunOperatorTeamAction {
	result := make([]DryRunOperatorTeamAction, 0, len(values))
	for key, sources := range values {
		result = append(result, DryRunOperatorTeamAction{
			OperatorTeamID: key.TeamID, AssignmentEpochID: key.AssignmentID,
			Action: key.Action, SourceMappingIDs: sortedUUIDSet(sources),
		})
	}
	slices.SortFunc(result, func(left, right DryRunOperatorTeamAction) int {
		if comparison := bytes.Compare(left.OperatorTeamID[:], right.OperatorTeamID[:]); comparison != 0 {
			return comparison
		}
		if comparison := bytes.Compare(left.AssignmentEpochID[:], right.AssignmentEpochID[:]); comparison != 0 {
			return comparison
		}
		return bytes.Compare([]byte(left.Action), []byte(right.Action))
	})
	return result
}

func sortedUUIDSet(values map[uuid.UUID]struct{}) []uuid.UUID {
	result := make([]uuid.UUID, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.SortFunc(result, func(left, right uuid.UUID) int {
		return bytes.Compare(left[:], right[:])
	})
	return result
}

func mappingPlanIDs(values []identity.EntityID) ([]uuid.UUID, error) {
	result := make([]uuid.UUID, 0, len(values))
	seen := make(map[uuid.UUID]struct{}, len(values))
	for _, value := range values {
		identifier := uuid.UUID(value)
		if !validUUIDv7(identifier) {
			return nil, ErrUnavailable
		}
		if _, duplicate := seen[identifier]; duplicate {
			return nil, ErrUnavailable
		}
		seen[identifier] = struct{}{}
		result = append(result, identifier)
	}
	return result, nil
}

func clearSubjectAliases(values []identity.SubjectAlias) {
	for index := range values {
		clear(values[index].Digest[:])
	}
}
