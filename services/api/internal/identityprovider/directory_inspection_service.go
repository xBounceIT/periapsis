package identityprovider

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const (
	directoryUserSearchReason = "administrative user search"
	directoryFilterTestReason = "administrative filter test"
)

type directoryInspectionNetworkResult struct {
	result              ldapclient.DirectoryInspectionResult
	allowedAttributes   []string
	groupCountAttribute string
}

type directoryInspectionExecutor func(
	context.Context,
	DirectoryOperationSnapshot,
	[]byte,
) (directoryInspectionNetworkResult, error)

func (s *Service) SearchUser(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input UserSearchTestInput,
) (DirectoryTestResult, error) {
	normalized, err := normalizeUserSearchTest(providerID, input)
	if err != nil {
		return DirectoryTestResult{}, err
	}
	username, err := identity.NewLDAPUsername(normalized.Username)
	if err != nil {
		return DirectoryTestResult{}, ErrInvalidInput
	}
	return s.runAdministrativeDirectoryInspection(
		ctx, actor, tenantID, providerID, DirectoryOperationSearchUser,
		directoryUserSearchReason, normalized.Audit, 1,
		func(
			operationContext context.Context,
			snapshot DirectoryOperationSnapshot,
			secret []byte,
		) (directoryInspectionNetworkResult, error) {
			configuration, err := directoryInspectionConfiguration(snapshot.Configuration, snapshot.Endpoints)
			if err != nil {
				return directoryInspectionNetworkResult{}, err
			}
			defer clear(configuration.Network.CustomCAPEM)
			filter, err := ldapclient.CompileDirectoryInspectionFilter(
				ldapclient.DirectoryInspectionFilterUser,
				snapshot.Configuration.UserSearchFilter,
			)
			if err != nil {
				return directoryInspectionNetworkResult{}, err
			}
			attributes, groupAttribute, err := directoryUserInspectionAttributes(
				snapshot.Configuration,
				normalized.Username,
			)
			if err != nil {
				return directoryInspectionNetworkResult{}, err
			}
			result, err := s.inspector.SearchDirectoryUser(
				operationContext,
				ldapclient.DirectorySearchUserRequest{
					Configuration:    configuration,
					Username:         username,
					UserBaseDN:       snapshot.Configuration.UserBaseDN,
					UserSearchFilter: filter,
					Attributes:       attributes,
				},
				secret,
			)
			return directoryInspectionNetworkResult{
				result: result, allowedAttributes: attributes,
				groupCountAttribute: groupAttribute,
			}, err
		},
	)
}

func (s *Service) TestFilter(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input FilterTestInput,
) (DirectoryTestResult, error) {
	normalized, err := normalizeFilterTest(providerID, input)
	if err != nil {
		return DirectoryTestResult{}, err
	}
	username, err := identity.NewLDAPUsername(normalized.Username)
	if err != nil {
		return DirectoryTestResult{}, ErrInvalidInput
	}
	operationKind := DirectoryOperationFilterUser
	if normalized.Kind == DirectoryFilterKindGroup {
		operationKind = DirectoryOperationFilterGroup
	}
	return s.runAdministrativeDirectoryInspection(
		ctx, actor, tenantID, providerID, operationKind,
		directoryFilterTestReason, normalized.Audit, normalized.MaxResults,
		func(
			operationContext context.Context,
			snapshot DirectoryOperationSnapshot,
			secret []byte,
		) (directoryInspectionNetworkResult, error) {
			configuration, err := directoryInspectionConfiguration(snapshot.Configuration, snapshot.Endpoints)
			if err != nil {
				return directoryInspectionNetworkResult{}, err
			}
			defer clear(configuration.Network.CustomCAPEM)
			filterKind, values, err := directoryFilterInspectionValues(snapshot.Configuration, normalized, username)
			if err != nil {
				return directoryInspectionNetworkResult{}, err
			}
			filter, err := ldapclient.CompileDirectoryInspectionFilter(filterKind, normalized.FilterTemplate)
			if err != nil {
				return directoryInspectionNetworkResult{}, err
			}
			userAttributes, userGroupAttribute, err := directoryUserInspectionAttributes(
				snapshot.Configuration,
				normalized.Username,
			)
			if err != nil {
				return directoryInspectionNetworkResult{}, err
			}
			groupAttributes, groupCountAttribute, err := directoryGroupInspectionAttributes(snapshot.Configuration)
			if err != nil {
				return directoryInspectionNetworkResult{}, err
			}
			request := ldapclient.DirectoryFilterTestRequest{
				Configuration: configuration,
				Filter:        filter,
				Values:        values,
				MaxResults:    normalized.MaxResults,
			}
			allowedAttributes := userAttributes
			groupAttribute := userGroupAttribute
			if normalized.Kind == DirectoryFilterKindUser {
				request.UserBaseDN = snapshot.Configuration.UserBaseDN
				request.UserAttributes = userAttributes
			} else {
				if snapshot.Configuration.GroupBaseDN == nil {
					return directoryInspectionNetworkResult{}, ErrUnavailable
				}
				request.GroupBaseDN = *snapshot.Configuration.GroupBaseDN
				request.GroupAttributes = groupAttributes
				allowedAttributes = groupAttributes
				groupAttribute = groupCountAttribute
			}
			result, err := s.inspector.TestDirectoryFilter(operationContext, request, secret)
			return directoryInspectionNetworkResult{
				result: result, allowedAttributes: allowedAttributes,
				groupCountAttribute: groupAttribute,
			}, err
		},
	)
}

func (s *Service) runAdministrativeDirectoryInspection(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	kind DirectoryOperationKind,
	reason string,
	audit authorization.AuditContext,
	maximumResults int,
	execute directoryInspectionExecutor,
) (DirectoryTestResult, error) {
	authority, err := s.resolveAndRequire(
		ctx,
		actor,
		tenantID,
		authorization.TenantPermissionIdentityProviderTest,
	)
	if err != nil {
		return DirectoryTestResult{}, err
	}
	if s.directoryOps == nil || s.inspector == nil || execute == nil ||
		maximumResults < 1 || maximumResults > ldapclient.MaximumDirectoryInspectionResults {
		return DirectoryTestResult{}, ErrUnavailable
	}
	operationRunID, err := s.nextID()
	if err != nil {
		return DirectoryTestResult{}, err
	}
	beginAuditEventID, err := s.nextID()
	if err != nil {
		return DirectoryTestResult{}, err
	}
	completionAuditEventID, err := s.nextID()
	if err != nil {
		return DirectoryTestResult{}, err
	}
	if operationRunID == beginAuditEventID || operationRunID == completionAuditEventID ||
		beginAuditEventID == completionAuditEventID {
		return DirectoryTestResult{}, ErrUnavailable
	}
	startedAt, err := s.currentTime()
	if err != nil {
		return DirectoryTestResult{}, err
	}
	human := HumanParams{
		Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID,
	}
	snapshot, err := s.directoryOps.BeginAdministrativeDirectoryInspection(
		ctx,
		BeginAdministrativeDirectoryInspectionParams{
			HumanParams: human, Audit: audit, OccurredAt: startedAt,
			OperationRunID: operationRunID, AuditEventID: beginAuditEventID,
			ProviderID: providerID, OperationKind: kind, Reason: reason,
		},
	)
	if err != nil {
		return DirectoryTestResult{}, mapRepositoryError(err)
	}
	defer clear(snapshot.Secret.Envelope.Ciphertext)
	if !validAdministrativeDirectorySnapshot(snapshot, tenantID, providerID, operationRunID, kind) {
		return s.completeFailedDirectoryInspection(
			ctx, human, audit, operationRunID, completionAuditEventID,
			startedAt, maximumResults, ErrUnavailable,
		)
	}
	plaintext, err := s.keyring.DecryptBindSecret(
		bindSecretContext(tenantID, providerID, snapshot.Secret.SecretID),
		snapshot.Secret.Envelope,
	)
	if err != nil {
		return s.completeFailedDirectoryInspection(
			ctx, human, audit, operationRunID, completionAuditEventID,
			startedAt, maximumResults, ErrUnavailable,
		)
	}
	defer clear(plaintext)
	networkResult, networkErr := execute(ctx, snapshot, plaintext)
	clear(plaintext)
	completedAt, clockErr := s.currentTime()
	if clockErr != nil {
		return DirectoryTestResult{}, clockErr
	}
	duration := completedAt.Sub(startedAt).Truncate(time.Millisecond)
	if duration < 0 {
		duration = 0
	}
	if duration > 120*time.Second {
		duration = 120 * time.Second
	}

	reported := reportedDirectoryInspection(networkResult.result, networkErr, duration)
	entries, projectionErr := redactDirectoryInspectionEntries(
		networkResult.result,
		networkResult.allowedAttributes,
		networkResult.groupCountAttribute,
		maximumResults,
	)
	if projectionErr != nil {
		reported = directoryInspectionReport{
			outcome: TestOutcomeFailure, category: TestCategoryCancelled,
			duration: duration,
		}
	}
	reportedCount := len(entries)
	reportedTruncated := networkResult.result.Truncated
	if reported.outcome != TestOutcomeSuccess {
		reportedCount = 0
		reportedTruncated = false
		entries = nil
	}
	completion, err := s.completeDirectoryInspection(
		ctx, human, audit, operationRunID, completionAuditEventID, completedAt,
		reported, reportedCount, reportedTruncated,
	)
	if err != nil {
		return DirectoryTestResult{}, err
	}
	if ctx.Err() != nil {
		return DirectoryTestResult{}, ctx.Err()
	}
	if networkErr != nil {
		if errors.Is(networkErr, ldapclient.ErrBusy) {
			return DirectoryTestResult{}, ErrRateLimited
		}
		return DirectoryTestResult{}, ErrUnavailable
	}
	if projectionErr != nil {
		return DirectoryTestResult{}, ErrUnavailable
	}
	return completedDirectoryTestResult(completion, operationRunID, entries, maximumResults)
}

func (s *Service) completeFailedDirectoryInspection(
	ctx context.Context,
	human HumanParams,
	audit authorization.AuditContext,
	operationRunID, auditEventID uuid.UUID,
	startedAt time.Time,
	maximumResults int,
	reportedErr error,
) (DirectoryTestResult, error) {
	completedAt, err := s.currentTime()
	if err != nil {
		return DirectoryTestResult{}, err
	}
	duration := completedAt.Sub(startedAt).Truncate(time.Millisecond)
	if duration < 0 {
		duration = 0
	}
	completion, err := s.completeDirectoryInspection(
		ctx, human, audit, operationRunID, auditEventID, completedAt,
		directoryInspectionReport{
			outcome: TestOutcomeFailure, category: TestCategoryCancelled,
			duration: min(duration, 120*time.Second),
		},
		0,
		false,
	)
	if err != nil {
		return DirectoryTestResult{}, err
	}
	if ctx.Err() != nil {
		return DirectoryTestResult{}, ctx.Err()
	}
	if reportedErr != nil {
		return DirectoryTestResult{}, reportedErr
	}
	return completedDirectoryTestResult(completion, operationRunID, nil, maximumResults)
}

type directoryInspectionReport struct {
	outcome          TestOutcome
	category         TestCategory
	endpointPriority *int
	duration         time.Duration
}

func reportedDirectoryInspection(
	result ldapclient.DirectoryInspectionResult,
	err error,
	duration time.Duration,
) directoryInspectionReport {
	if err != nil {
		return directoryInspectionReport{
			outcome: TestOutcomeFailure, category: TestCategoryCancelled,
			duration: duration,
		}
	}
	category := directoryInspectionTestCategory(result.Category)
	priority := result.EndpointPriority
	if result.Category == ldapclient.DirectoryCategorySuccess && priority >= 1 && priority <= 8 {
		return directoryInspectionReport{
			outcome: TestOutcomeSuccess, category: TestCategorySuccess,
			endpointPriority: &priority, duration: duration,
		}
	}
	if result.Category == ldapclient.DirectoryCategoryCancelled || priority < 1 || priority > 8 {
		return directoryInspectionReport{
			outcome: TestOutcomeFailure, category: TestCategoryCancelled,
			duration: duration,
		}
	}
	return directoryInspectionReport{
		outcome: TestOutcomeFailure, category: category,
		endpointPriority: &priority, duration: duration,
	}
}

func directoryInspectionTestCategory(value ldapclient.DirectoryCategory) TestCategory {
	switch value {
	case ldapclient.DirectoryCategoryDNSFailed:
		return TestCategoryDNSFailed
	case ldapclient.DirectoryCategoryDestinationBlocked:
		return TestCategoryDestinationBlocked
	case ldapclient.DirectoryCategoryConnectTimeout:
		return TestCategoryConnectTimeout
	case ldapclient.DirectoryCategoryConnectFailed:
		return TestCategoryConnectFailed
	case ldapclient.DirectoryCategoryTLSFailed:
		return TestCategoryTLSFailed
	case ldapclient.DirectoryCategoryCertificateRejected:
		return TestCategoryCertificateRejected
	case ldapclient.DirectoryCategoryServiceBindRejected,
		ldapclient.DirectoryCategoryCredentialsRejected:
		return TestCategoryBindRejected
	case ldapclient.DirectoryCategoryCancelled:
		return TestCategoryCancelled
	default:
		return TestCategoryProtocolFailed
	}
}

func (s *Service) completeDirectoryInspection(
	parentContext context.Context,
	human HumanParams,
	audit authorization.AuditContext,
	operationRunID, auditEventID uuid.UUID,
	completedAt time.Time,
	reported directoryInspectionReport,
	matchedEntryCount int,
	truncated bool,
) (DirectoryInspectionCompletion, error) {
	completionContext, cancel := context.WithTimeout(
		context.WithoutCancel(parentContext),
		diagnosticCompletionTimeout,
	)
	defer cancel()
	completion, err := s.directoryOps.CompleteDirectoryInspection(
		completionContext,
		CompleteDirectoryInspectionParams{
			HumanParams: human, Audit: audit, OccurredAt: completedAt,
			OperationRunID: operationRunID, AuditEventID: auditEventID,
			ReportedOutcome: reported.outcome, ReportedCategory: reported.category,
			EndpointPriority: reported.endpointPriority, Duration: reported.duration,
			MatchedEntryCount: matchedEntryCount, Truncated: truncated,
		},
	)
	if err != nil {
		return DirectoryInspectionCompletion{}, mapRepositoryError(err)
	}
	return completion, nil
}

func completedDirectoryTestResult(
	completion DirectoryInspectionCompletion,
	operationRunID uuid.UUID,
	entries []RedactedEntry,
	maximumResults int,
) (DirectoryTestResult, error) {
	if !validTestResult(completion.Diagnostic, operationRunID) ||
		completion.MatchedEntryCount < 0 || completion.MatchedEntryCount > maximumResults {
		return DirectoryTestResult{}, ErrUnavailable
	}
	if completion.Diagnostic.Outcome != TestOutcomeSuccess {
		if completion.MatchedEntryCount != 0 || completion.Truncated {
			return DirectoryTestResult{}, ErrUnavailable
		}
		entries = nil
	} else if completion.MatchedEntryCount != len(entries) {
		return DirectoryTestResult{}, ErrUnavailable
	}
	return DirectoryTestResult{
		Diagnostic:        completion.Diagnostic,
		MatchedEntryCount: completion.MatchedEntryCount,
		Truncated:         completion.Truncated,
		Entries:           append([]RedactedEntry(nil), entries...),
	}, nil
}

func validAdministrativeDirectorySnapshot(
	value DirectoryOperationSnapshot,
	tenantID, providerID, operationRunID uuid.UUID,
	kind DirectoryOperationKind,
) bool {
	if value.OperationRunID != operationRunID || value.TenantID != tenantID ||
		value.ProviderID != providerID || value.OperationKind != kind ||
		!validUUIDv7(value.OperationRunID) || !validUUIDv7(value.TenantID) ||
		!validUUIDv7(value.ProviderID) || allZeroDigest(value.EndpointSnapshotDigest) ||
		value.ProviderVersion < 1 || value.ProviderVersion > maximumResourceVersion ||
		value.ConfigurationVersion < 1 || value.ConfigurationVersion > maximumResourceVersion ||
		value.SecretVersion < 1 || value.SecretVersion > maximumResourceVersion ||
		!validUUIDv7(value.Secret.SecretID) || value.Secret.Envelope.KeyVersion < 1 ||
		len(value.Secret.Envelope.Ciphertext) < 17 || len(value.Secret.Envelope.Ciphertext) > 8192 ||
		!validInstant(value.StartedAt) || !validInstant(value.ExpiresAt) ||
		!value.ExpiresAt.After(value.StartedAt) || value.ExpiresAt.Sub(value.StartedAt) > 2*time.Minute ||
		value.BindingID != nil || value.BindingVersion != nil || value.BindingAuthRevision != nil ||
		value.BindingAccessEpochID != nil || value.RuleSetRevision != nil ||
		value.AuthorizationRevision != nil || len(value.MappingRevisions) != 0 {
		return false
	}
	_, _, err := normalizeConfiguration(value.Configuration, value.Endpoints)
	return err == nil
}

func allZeroDigest(value [32]byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func directoryInspectionConfiguration(
	configuration Configuration,
	endpoints []Endpoint,
) (ldapclient.DirectoryInspectionConfiguration, error) {
	network, err := deploymentLDAPConfiguration(configuration, endpoints, true)
	if err != nil {
		return ldapclient.DirectoryInspectionConfiguration{}, ErrUnavailable
	}
	var referrals ldapclient.DirectoryReferralMode
	switch configuration.ReferralMode {
	case ReferralModeDisabled:
		referrals = ldapclient.DirectoryReferralModeDisabled
	case ReferralModeConfiguredEndpoints:
		referrals = ldapclient.DirectoryReferralModeConfiguredEndpoints
	default:
		clear(network.CustomCAPEM)
		return ldapclient.DirectoryInspectionConfiguration{}, ErrUnavailable
	}
	return ldapclient.DirectoryInspectionConfiguration{
		Network:         network,
		BindDN:          configuration.BindDN,
		ReferralMode:    referrals,
		ReferralMaxHops: configuration.MaxReferralHops,
		Limits: ldapclient.DirectoryLimits{
			PageSize:         configuration.PageSize,
			MaxPages:         configuration.MaxPages,
			MaxEntries:       configuration.MaxEntries,
			MaxResponseBytes: configuration.MaxResponseBytes,
		},
	}, nil
}

func directoryFilterInspectionValues(
	configuration Configuration,
	input FilterTestInput,
	username identity.LDAPUsername,
) (ldapclient.DirectoryInspectionFilterKind, identity.LDAPTemplateValues, error) {
	values := identity.LDAPTemplateValues{Username: username}
	if input.Kind == DirectoryFilterKindUser {
		return ldapclient.DirectoryInspectionFilterUser, values, nil
	}
	switch configuration.NestedGroupMode {
	case NestedGroupModeActiveDirectory, NestedGroupModeReverseSearch:
		if input.UserDN == nil || input.GIDNumber != nil {
			return "", identity.LDAPTemplateValues{}, ErrInvalidInput
		}
		userDN, err := identity.ParseLDAPDistinguishedName(*input.UserDN)
		if err != nil {
			return "", identity.LDAPTemplateValues{}, ErrInvalidInput
		}
		values.UserDN = userDN
		return ldapclient.DirectoryInspectionFilterReverseGroup, values, nil
	case NestedGroupModePOSIXMemberUID:
		if input.UserDN != nil {
			return "", identity.LDAPTemplateValues{}, ErrInvalidInput
		}
		if input.GIDNumber != nil {
			gidNumber, err := identity.ParseLDAPGIDNumber(strconv.Itoa(*input.GIDNumber))
			if err != nil {
				return "", identity.LDAPTemplateValues{}, ErrInvalidInput
			}
			values.GIDNumber = gidNumber
		}
		return ldapclient.DirectoryInspectionFilterPOSIXGroup, values, nil
	default:
		return "", identity.LDAPTemplateValues{}, ErrInvalidInput
	}
}

func directoryUserInspectionAttributes(
	configuration Configuration,
	username string,
) ([]string, string, error) {
	normalization, err := directoryNormalizationConfiguration(configuration, username)
	if err != nil {
		return nil, "", ErrUnavailable
	}
	attributes, err := normalization.RequiredUserAttributes()
	if err != nil {
		return nil, "", ErrUnavailable
	}
	groupAttribute := ""
	if configuration.GroupMembershipAttribute != nil {
		groupAttribute = strings.ToLower(*configuration.GroupMembershipAttribute)
		attributes = append(attributes, groupAttribute)
	}
	attributes, ok := normalizedInspectionAttributes(attributes)
	if !ok {
		return nil, "", ErrUnavailable
	}
	return attributes, groupAttribute, nil
}

func directoryGroupInspectionAttributes(configuration Configuration) ([]string, string, error) {
	attributes := []string{"cn"}
	groupAttribute := ""
	if configuration.NestedGroupMode == NestedGroupModePOSIXMemberUID &&
		configuration.POSIXMemberUIDAttribute != nil {
		groupAttribute = strings.ToLower(*configuration.POSIXMemberUIDAttribute)
		attributes = append(attributes, groupAttribute)
	}
	attributes, ok := normalizedInspectionAttributes(attributes)
	if !ok {
		return nil, "", ErrUnavailable
	}
	return attributes, groupAttribute, nil
}

func normalizedInspectionAttributes(values []string) ([]string, bool) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(value)
		if !attributeNamePattern.MatchString(value) {
			return nil, false
		}
		result = append(result, value)
	}
	slices.Sort(result)
	result = slices.Compact(result)
	return result, len(result) > 0 && len(result) <= 64
}

func redactDirectoryInspectionEntries(
	result ldapclient.DirectoryInspectionResult,
	allowedAttributes []string,
	groupCountAttribute string,
	maximumResults int,
) ([]RedactedEntry, error) {
	if result.Category != ldapclient.DirectoryCategorySuccess {
		if len(result.Entries) != 0 || result.Truncated {
			return nil, ErrUnavailable
		}
		return nil, nil
	}
	if result.EndpointPriority < 1 || result.EndpointPriority > 8 ||
		len(result.Entries) > maximumResults {
		return nil, ErrUnavailable
	}
	allowed := make(map[string]struct{}, len(allowedAttributes))
	for _, attribute := range allowedAttributes {
		allowed[strings.ToLower(attribute)] = struct{}{}
	}
	entries := make([]RedactedEntry, 0, len(result.Entries))
	for index, entry := range result.Entries {
		if !validText(entry.DistinguishedName, 1, maximumLDAPExactDNCharacters) ||
			len(entry.DistinguishedName) > maximumLDAPExactDNBytes || len(entry.Attributes) > 64 {
			return nil, ErrUnavailable
		}
		redacted := RedactedEntry{Ordinal: index + 1, DNPresent: true}
		seen := make(map[string]struct{}, len(entry.Attributes))
		for _, attribute := range entry.Attributes {
			name := strings.ToLower(attribute.Name)
			if !attributeNamePattern.MatchString(name) || len(attribute.Values) > 10_000 {
				return nil, ErrUnavailable
			}
			if _, duplicate := seen[name]; duplicate {
				return nil, ErrUnavailable
			}
			seen[name] = struct{}{}
			if _, admitted := allowed[name]; !admitted {
				continue
			}
			if name == groupCountAttribute {
				redacted.GroupValueCount = len(attribute.Values)
				continue
			}
			redacted.Attributes = append(redacted.Attributes, RedactedEntryAttribute{
				Name: name, ValueCount: len(attribute.Values), Truncated: false,
			})
		}
		slices.SortFunc(redacted.Attributes, func(left, right RedactedEntryAttribute) int {
			return strings.Compare(left.Name, right.Name)
		})
		entries = append(entries, redacted)
	}
	return entries, nil
}
