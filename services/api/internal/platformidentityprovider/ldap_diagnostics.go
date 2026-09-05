package platformidentityprovider

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

const platformLDAPDiagnosticCompletionTimeout = 5 * time.Second

// LDAPDiagnosticClient combines only service-bind and connection-test
// capabilities. It has no user-password method, and the shared LDAP client
// applies the same private-egress, TLS, timeout, paging, and concurrency policy
// used by tenant directory diagnostics.
type LDAPDiagnosticClient interface {
	identityprovider.DiagnosticClient
	identityprovider.DirectoryInspectionClient
	identityprovider.DirectoryObservationClient
}

// ConfigureLDAPDiagnostics binds the deployment-owned network client during
// single-threaded startup. Keeping this separate from the historical
// constructor preserves the SAML option ABI while making an omitted LDAP test
// dependency fail closed.
func (service *Service) ConfigureLDAPDiagnostics(client LDAPDiagnosticClient) error {
	if service == nil || interfaceIsNil(client) || service.ldapDiagnostics != nil {
		return errors.New("one platform LDAP diagnostic client is required")
	}
	service.ldapDiagnostics = client
	return nil
}

func (service *Service) TestLDAP(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input LDAPTestInput,
) (LDAPDiagnostic, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderTest); err != nil {
		return LDAPDiagnostic{}, err
	}
	repository, ok := service.repository.(LDAPTestRepository)
	if !ok || !validSession(session) || interfaceIsNil(service.ldapDiagnostics) {
		return LDAPDiagnostic{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return LDAPDiagnostic{}, err
	}
	normalized, err := normalizeLDAPTest(providerID, input)
	if err != nil {
		return LDAPDiagnostic{}, err
	}
	testID, err := service.newID()
	if err != nil || !validUUIDv7(testID) {
		return LDAPDiagnostic{}, authentication.ErrUnavailable
	}
	snapshot, err := repository.BeginLDAPTest(ctx, BeginLDAPTestParams{
		SessionParams: sessionParams(session), ProviderID: providerID, TestID: testID,
		Kind: normalized.Kind, Event: normalized.Event,
	})
	if err != nil {
		return LDAPDiagnostic{}, mapRepositoryError(err)
	}
	defer snapshot.Destroy()
	if !validLDAPTestSnapshot(snapshot, providerID, testID, normalized.Kind) {
		return LDAPDiagnostic{}, authentication.ErrUnavailable
	}

	report, networkErr := service.runLDAPDiagnostic(ctx, snapshot, normalized)
	completedAt := time.Now().UTC().Truncate(time.Millisecond)
	completionContext, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), platformLDAPDiagnosticCompletionTimeout,
	)
	defer cancel()
	stored, err := repository.CompleteLDAPTest(completionContext, CompleteLDAPTestParams{
		SessionParams: sessionParams(session), TestID: testID,
		Outcome: report.outcome, Category: report.category,
		EndpointPriority: report.endpointPriority, Duration: report.duration,
		MatchedEntryCount: report.matchedEntryCount, Attributes: report.attributes,
		CompletedAt: completedAt, Reason: normalized.Reason, Event: normalized.Event,
	})
	if err != nil {
		return LDAPDiagnostic{}, mapRepositoryError(err)
	}
	public, ok := publicLDAPDiagnostic(stored, testID, normalized.Kind)
	if !ok {
		return LDAPDiagnostic{}, authentication.ErrUnavailable
	}
	if ctx.Err() != nil {
		return LDAPDiagnostic{}, ctx.Err()
	}
	if networkErr != nil {
		if errors.Is(networkErr, ldapclient.ErrBusy) {
			return LDAPDiagnostic{}, identityprovider.ErrRateLimited
		}
		return LDAPDiagnostic{}, authentication.ErrUnavailable
	}
	return public, nil
}

type platformLDAPDiagnosticReport struct {
	outcome           string
	category          string
	endpointPriority  *int
	duration          time.Duration
	matchedEntryCount *int
	attributes        []string
}

func (service *Service) runLDAPDiagnostic(
	ctx context.Context,
	snapshot LDAPTestSnapshot,
	input LDAPTestInput,
) (platformLDAPDiagnosticReport, error) {
	endpoints := make([]identityprovider.Endpoint, len(snapshot.Endpoints))
	for index, endpoint := range snapshot.Endpoints {
		endpoints[index] = identityprovider.Endpoint{
			Priority: endpoint.Priority, Host: endpoint.Host, Port: endpoint.Port,
			Transport: ldapclient.Transport(endpoint.Transport), TLSServerName: endpoint.TLSServerName,
			ReferralAllowed: endpoint.ReferralAllowed, Enabled: endpoint.Enabled,
		}
	}
	if input.Kind == LDAPTestConnection || input.Kind == LDAPTestBind {
		configuration, err := identityprovider.BuildDirectoryNetworkConfiguration(
			snapshot.Configuration, endpoints,
		)
		if err != nil {
			identityprovider.ClearDirectoryNetworkConfiguration(&configuration)
			return failedLDAPDiagnostic("configuration_invalid", 0), err
		}
		if err = service.ldapDiagnostics.ValidateConfiguration(configuration); err != nil {
			identityprovider.ClearDirectoryNetworkConfiguration(&configuration)
			return failedLDAPDiagnostic("configuration_invalid", 0), err
		}
		defer identityprovider.ClearDirectoryNetworkConfiguration(&configuration)
		if input.Kind == LDAPTestConnection {
			diagnostic, networkErr := service.ldapDiagnostics.TestConnection(ctx, configuration)
			return diagnosticReport(diagnostic, networkErr)
		}
		secret, err := service.decryptLDAPTestSecret(snapshot)
		if err != nil {
			return failedLDAPDiagnostic("configuration_invalid", 0), err
		}
		defer clear(secret)
		diagnostic, networkErr := service.ldapDiagnostics.TestBind(
			ctx, configuration, snapshot.Configuration.BindDN, secret,
		)
		clear(secret)
		return diagnosticReport(diagnostic, networkErr)
	}

	request, err := identityprovider.BuildDirectoryAuthenticationRequest(
		snapshot.Configuration, endpoints, *input.Username,
	)
	if err != nil {
		return failedLDAPDiagnostic("configuration_invalid", 0), err
	}
	defer identityprovider.ClearDirectoryAuthenticationRequest(&request)
	secret, err := service.decryptLDAPTestSecret(snapshot)
	if err != nil {
		return failedLDAPDiagnostic("configuration_invalid", 0), err
	}
	defer clear(secret)
	startedAt := time.Now()
	if input.Kind == LDAPTestSearchUser {
		filter, compileErr := ldapclient.CompileDirectoryInspectionFilter(
			ldapclient.DirectoryInspectionFilterUser, snapshot.Configuration.UserSearchFilter,
		)
		if compileErr != nil {
			return failedLDAPDiagnostic("configuration_invalid", 0), compileErr
		}
		result, networkErr := service.ldapDiagnostics.SearchDirectoryUser(
			ctx,
			ldapclient.DirectorySearchUserRequest{
				Configuration: ldapclient.DirectoryInspectionConfiguration{
					Network: request.Configuration, BindDN: request.BindDN,
					ReferralMode: request.ReferralMode, ReferralMaxHops: request.ReferralMaxHops,
					Limits: request.Limits,
				},
				Username: request.Username, UserBaseDN: request.UserBaseDN,
				UserSearchFilter: filter, Attributes: request.UserAttributes,
			},
			secret,
		)
		clear(secret)
		return inspectionReport(result, time.Since(startedAt), networkErr)
	}

	result, networkErr := service.ldapDiagnostics.ObserveDirectory(ctx, request, secret)
	clear(secret)
	report := observationReport(result, time.Since(startedAt), networkErr)
	if networkErr != nil || result.Category != ldapclient.DirectoryCategorySuccess || input.Kind != LDAPTestMappingDryRun {
		return report, networkErr
	}
	matched, matchErr := matchLDAPDiagnosticMappings(result.Observation.Groups, snapshot.Mappings)
	if matchErr != nil {
		return failedLDAPDiagnostic("protocol_failed", report.duration), matchErr
	}
	report.matchedEntryCount = intPointer(matched)
	if matched == 0 {
		report.outcome = "failure"
		report.category = "mapping_denied"
	}
	return report, nil
}

func (service *Service) decryptLDAPTestSecret(snapshot LDAPTestSnapshot) ([]byte, error) {
	if snapshot.BindSecret == nil {
		return nil, authentication.ErrUnavailable
	}
	return service.keyring.DecryptBindSecret(identity.BindSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: identity.EntityID(snapshot.ProviderID),
		},
		SecretID: identity.EntityID(snapshot.BindSecret.SecretID),
	}, snapshot.BindSecret.Envelope)
}

func normalizeLDAPTest(providerID uuid.UUID, input LDAPTestInput) (LDAPTestInput, error) {
	input.Reason = strings.TrimSpace(input.Reason)
	if !validUUIDv7(providerID) || !validReason(input.Reason) || !validEvent(input.Event) {
		return LDAPTestInput{}, authentication.ErrInvalidInput
	}
	needsUsername := input.Kind == LDAPTestSearchUser || input.Kind == LDAPTestFilter ||
		input.Kind == LDAPTestMappingDryRun
	if needsUsername {
		if input.Username == nil || len(*input.Username) < 1 || len(*input.Username) > 320 {
			return LDAPTestInput{}, authentication.ErrInvalidInput
		}
		if _, err := identity.NewLDAPUsername(*input.Username); err != nil {
			return LDAPTestInput{}, authentication.ErrInvalidInput
		}
	} else if input.Kind != LDAPTestConnection && input.Kind != LDAPTestBind || input.Username != nil {
		return LDAPTestInput{}, authentication.ErrInvalidInput
	}
	return input, nil
}

func validLDAPTestSnapshot(
	snapshot LDAPTestSnapshot,
	providerID, testID uuid.UUID,
	kind LDAPTestKind,
) bool {
	if snapshot.TestID != testID || snapshot.ProviderID != providerID || snapshot.Kind != kind ||
		snapshot.ProviderVersion < 1 || snapshot.ConfigurationRevision < 1 || snapshot.MappingRevision < 1 ||
		snapshot.Endpoints == nil || snapshot.Mappings == nil {
		return false
	}
	for _, endpoint := range snapshot.Endpoints {
		if !validUUIDv7(endpoint.ID) {
			return false
		}
	}
	if kind == LDAPTestConnection {
		return snapshot.BindSecret == nil && snapshot.SecretRevision == nil
	}
	return snapshot.BindSecret != nil && validUUIDv7(snapshot.BindSecret.SecretID) &&
		snapshot.BindSecret.Envelope.KeyVersion > 0 && len(snapshot.BindSecret.Envelope.Ciphertext) >= 17 &&
		snapshot.SecretRevision != nil && *snapshot.SecretRevision > 0
}

func diagnosticReport(
	diagnostic ldapclient.Diagnostic,
	err error,
) (platformLDAPDiagnosticReport, error) {
	if err != nil {
		return failedLDAPDiagnostic("cancelled", diagnostic.Duration), err
	}
	category := string(diagnostic.Category)
	if !validRawLDAPDiagnosticCategory(category) ||
		(diagnostic.Outcome != ldapclient.OutcomeSuccess && diagnostic.Outcome != ldapclient.OutcomeFailure) {
		return failedLDAPDiagnostic("protocol_failed", diagnostic.Duration), authentication.ErrUnavailable
	}
	report := platformLDAPDiagnosticReport{
		outcome: string(diagnostic.Outcome), category: category,
		duration: boundedLDAPDiagnosticDuration(diagnostic.Duration),
	}
	if diagnostic.EndpointPriority >= 1 && diagnostic.EndpointPriority <= 8 {
		report.endpointPriority = intPointer(diagnostic.EndpointPriority)
	} else if diagnostic.Category != ldapclient.CategoryCancelled {
		return failedLDAPDiagnostic("protocol_failed", diagnostic.Duration), authentication.ErrUnavailable
	}
	return report, nil
}

func inspectionReport(
	result ldapclient.DirectoryInspectionResult,
	duration time.Duration,
	err error,
) (platformLDAPDiagnosticReport, error) {
	report := directoryReport(result.Category, result.EndpointPriority, duration, err)
	if err == nil && result.Category == ldapclient.DirectoryCategorySuccess {
		count := len(result.Entries)
		report.matchedEntryCount = &count
		report.attributes = diagnosticEntryAttributes(result.Entries...)
	}
	return report, err
}

func observationReport(
	result ldapclient.DirectoryResult,
	duration time.Duration,
	err error,
) platformLDAPDiagnosticReport {
	report := directoryReport(result.Category, result.EndpointPriority, duration, err)
	if err == nil && result.Category == ldapclient.DirectoryCategorySuccess {
		count := 1
		report.matchedEntryCount = &count
		entries := make([]ldapclient.DirectoryEntry, 0, len(result.Observation.Groups)+1)
		entries = append(entries, result.Observation.User)
		entries = append(entries, result.Observation.Groups...)
		report.attributes = diagnosticEntryAttributes(entries...)
	}
	return report
}

func directoryReport(
	category ldapclient.DirectoryCategory,
	priority int,
	duration time.Duration,
	err error,
) platformLDAPDiagnosticReport {
	if err != nil {
		return failedLDAPDiagnostic("cancelled", duration)
	}
	mapped := rawDirectoryDiagnosticCategory(category)
	if mapped == "" {
		return failedLDAPDiagnostic("protocol_failed", duration)
	}
	report := platformLDAPDiagnosticReport{
		outcome: "failure", category: mapped, duration: boundedLDAPDiagnosticDuration(duration),
	}
	if category == ldapclient.DirectoryCategorySuccess {
		report.outcome = "success"
	}
	if priority >= 1 && priority <= 8 {
		report.endpointPriority = intPointer(priority)
	} else if category != ldapclient.DirectoryCategoryCancelled {
		report.category = "protocol_failed"
	}
	return report
}

func rawDirectoryDiagnosticCategory(category ldapclient.DirectoryCategory) string {
	switch category {
	case ldapclient.DirectoryCategorySuccess:
		return "success"
	case ldapclient.DirectoryCategoryDNSFailed:
		return "dns_failed"
	case ldapclient.DirectoryCategoryDestinationBlocked:
		return "destination_blocked"
	case ldapclient.DirectoryCategoryConnectTimeout:
		return "connect_timeout"
	case ldapclient.DirectoryCategoryConnectFailed:
		return "connect_failed"
	case ldapclient.DirectoryCategoryTLSFailed:
		return "tls_failed"
	case ldapclient.DirectoryCategoryCertificateRejected:
		return "certificate_rejected"
	case ldapclient.DirectoryCategoryServiceBindRejected, ldapclient.DirectoryCategoryCredentialsRejected:
		return "bind_rejected"
	case ldapclient.DirectoryCategoryUserNotFound:
		return "user_not_found"
	case ldapclient.DirectoryCategoryUserAmbiguous:
		return "user_ambiguous"
	case ldapclient.DirectoryCategoryCancelled:
		return "cancelled"
	case ldapclient.DirectoryCategoryLimitExceeded, ldapclient.DirectoryCategoryReferralRejected,
		ldapclient.DirectoryCategoryInvalidEntry, ldapclient.DirectoryCategoryProtocolFailed:
		return "protocol_failed"
	default:
		return ""
	}
}

func failedLDAPDiagnostic(category string, duration time.Duration) platformLDAPDiagnosticReport {
	return platformLDAPDiagnosticReport{
		outcome: "failure", category: category, duration: boundedLDAPDiagnosticDuration(duration),
		attributes: []string{},
	}
}

func boundedLDAPDiagnosticDuration(value time.Duration) time.Duration {
	value = value.Truncate(time.Millisecond)
	if value < 0 {
		return 0
	}
	if value > 120*time.Second {
		return 120 * time.Second
	}
	return value
}

func matchLDAPDiagnosticMappings(
	groups []ldapclient.DirectoryEntry,
	mappings []LDAPMapping,
) (int, error) {
	parsedGroups := make([]identity.LDAPDistinguishedName, 0, len(groups))
	for _, group := range groups {
		parsed, err := identity.ParseLDAPDistinguishedName(group.DistinguishedName)
		if err != nil {
			return 0, err
		}
		parsedGroups = append(parsedGroups, parsed)
	}
	ordered := append([]LDAPMapping(nil), mappings...)
	slices.SortFunc(ordered, func(left, right LDAPMapping) int {
		if left.Priority != right.Priority {
			return left.Priority - right.Priority
		}
		return slices.Compare(left.ID[:], right.ID[:])
	})
	selectedRoles := make(map[uuid.UUID]struct{}, len(ordered))
	seenMappings := make(map[uuid.UUID]struct{}, len(ordered))
	for _, mapping := range ordered {
		if !mapping.Enabled || mapping.ArchivedAt != nil {
			continue
		}
		if !validUUIDv7(mapping.ID) || !validUUIDv7(mapping.PlatformRoleID) {
			return 0, authentication.ErrUnavailable
		}
		if _, duplicate := seenMappings[mapping.ID]; duplicate {
			return 0, authentication.ErrUnavailable
		}
		seenMappings[mapping.ID] = struct{}{}
		kind, caseMode, ok := ldapMatcherDomain(mapping.MatcherType, mapping.CaseSensitive)
		if !ok {
			return 0, authentication.ErrUnavailable
		}
		matcher, err := identity.CompileLDAPGroupMatcher(identity.LDAPGroupMatcherSpec{
			Kind: kind, CaseMode: caseMode, Pattern: mapping.MatcherValue,
		})
		if err != nil {
			return 0, err
		}
		for _, group := range parsedGroups {
			matched, matchErr := matcher.Match(group)
			if matchErr != nil {
				return 0, matchErr
			}
			if matched {
				selectedRoles[mapping.PlatformRoleID] = struct{}{}
				break
			}
		}
	}
	return len(selectedRoles), nil
}

func diagnosticEntryAttributes(entries ...ldapclient.DirectoryEntry) []string {
	unique := make(map[string]struct{}, 32)
	for _, entry := range entries {
		for _, attribute := range entry.Attributes {
			name := strings.ToLower(attribute.Name)
			if validLDAPDiagnosticAttribute(name) {
				unique[name] = struct{}{}
			}
		}
	}
	result := make([]string, 0, min(len(unique), 128))
	for name := range unique {
		result = append(result, name)
	}
	slices.Sort(result)
	if len(result) > 128 {
		result = result[:128]
	}
	return result
}

func validLDAPDiagnosticAttribute(value string) bool {
	if len(value) < 1 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == ';' || character == '.' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func validRawLDAPDiagnosticCategory(value string) bool {
	switch value {
	case "success", "cancelled", "configuration_invalid", "destination_blocked", "dns_failed",
		"connect_failed", "connect_timeout", "tls_failed", "certificate_rejected", "bind_rejected",
		"user_not_found", "user_ambiguous", "mapping_denied", "stale_configuration", "protocol_failed":
		return true
	default:
		return false
	}
}

func publicLDAPDiagnostic(stored LDAPDiagnostic, testID uuid.UUID, kind LDAPTestKind) (LDAPDiagnostic, bool) {
	if stored.TestID != testID || stored.Kind != kind || stored.Duration < 0 || stored.Duration > 120*time.Second ||
		stored.Attributes == nil || len(stored.Attributes) > 128 || stored.Outcome == "inconclusive" ||
		stored.Category == "stale_configuration" {
		return LDAPDiagnostic{}, false
	}
	for index, attribute := range stored.Attributes {
		if !validLDAPDiagnosticAttribute(attribute) || index > 0 && stored.Attributes[index-1] >= attribute {
			return LDAPDiagnostic{}, false
		}
	}
	category := ""
	switch stored.Category {
	case "success":
		category = "ok"
	case "destination_blocked", "dns_failed", "connect_failed":
		category = "connection_failed"
	case "connect_timeout", "cancelled":
		category = "timeout"
	case "tls_failed", "certificate_rejected":
		category = "tls_rejected"
	case "bind_rejected":
		category = "bind_rejected"
	case "user_not_found":
		category = "no_match"
	case "user_ambiguous":
		category = "ambiguous_match"
	case "mapping_denied":
		category = "mapping_denied"
	case "configuration_invalid", "protocol_failed":
		if kind == LDAPTestConnection || kind == LDAPTestBind {
			category = "connection_failed"
		} else {
			category = "search_rejected"
		}
	default:
		return LDAPDiagnostic{}, false
	}
	outcome := "failure"
	if stored.Category == "success" && stored.Outcome == "success" {
		outcome = "success"
	} else if stored.Outcome != "failure" {
		return LDAPDiagnostic{}, false
	}
	stored.Outcome = outcome
	stored.Category = category
	return stored, true
}

func intPointer(value int) *int { return &value }
