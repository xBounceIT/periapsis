package identityprovider

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const diagnosticCompletionTimeout = 5 * time.Second

type DiagnosticClient interface {
	ValidateConfiguration(ldapclient.Configuration) error
	TestConnection(context.Context, ldapclient.Configuration) (ldapclient.Diagnostic, error)
	TestBind(context.Context, ldapclient.Configuration, string, []byte) (ldapclient.Diagnostic, error)
}

// DirectoryInspectionClient is the service-bind-only LDAP administration
// boundary. Keeping it separate from DiagnosticClient makes the capability
// explicit: these calls can inspect bounded directory projections, but they
// can never accept or exercise a user's password.
type DirectoryInspectionClient interface {
	SearchDirectoryUser(
		context.Context,
		ldapclient.DirectorySearchUserRequest,
		[]byte,
	) (ldapclient.DirectoryInspectionResult, error)
	TestDirectoryFilter(
		context.Context,
		ldapclient.DirectoryFilterTestRequest,
		[]byte,
	) (ldapclient.DirectoryInspectionResult, error)
}

// DirectoryObservationClient is the service-bind-only boundary used by
// mapping dry-runs. It returns the same complete bounded observation as login
// without accepting, testing, or retaining a user password.
type DirectoryObservationClient interface {
	ObserveDirectory(
		context.Context,
		ldapclient.DirectoryRequest,
		[]byte,
	) (ldapclient.DirectoryResult, error)
}

type Service struct {
	repository         Repository
	administration     AdministrationRepository
	syncAdministration SyncAdministrationRepository
	directoryOps       DirectoryInspectionRepository
	mappingDryRuns     MappingDryRunRepository
	diagnostics        DiagnosticClient
	inspector          DirectoryInspectionClient
	observer           DirectoryObservationClient
	evaluator          authorization.Evaluator
	keyring            identity.Keyring
	now                func() time.Time
	newID              func() (uuid.UUID, error)
}

func NewService(repository Repository, keyring identity.Keyring, diagnostics DiagnosticClient) (*Service, error) {
	if repository == nil {
		return nil, errors.New("identity-provider repository is required")
	}
	if keyring.ActiveVersion() < 1 || len(keyring.Versions()) == 0 {
		return nil, errors.New("identity keyring is required")
	}
	if diagnostics == nil {
		return nil, errors.New("LDAP diagnostic client is required")
	}
	administration, _ := repository.(AdministrationRepository)
	syncAdministration, _ := repository.(SyncAdministrationRepository)
	directoryOps, _ := repository.(DirectoryInspectionRepository)
	mappingDryRuns, _ := repository.(MappingDryRunRepository)
	inspector, _ := diagnostics.(DirectoryInspectionClient)
	observer, _ := diagnostics.(DirectoryObservationClient)
	return &Service{
		repository: repository, administration: administration, syncAdministration: syncAdministration,
		directoryOps:   directoryOps,
		mappingDryRuns: mappingDryRuns, diagnostics: diagnostics, inspector: inspector,
		observer: observer, evaluator: authorization.Evaluator{},
		keyring: keyring, now: time.Now, newID: uuid.NewV7,
	}, nil
}

func (s *Service) List(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input ListInput,
) (ProviderPage, error) {
	page, err := normalizePage(input.PageInput)
	if err != nil {
		return ProviderPage{}, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderRead)
	if err != nil {
		return ProviderPage{}, err
	}
	rows, err := s.repository.List(ctx, ListParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		After:       page.After, Limit: int32(page.Limit + 1), IncludeArchived: input.IncludeArchived,
	})
	if err != nil {
		return ProviderPage{}, mapRepositoryError(err)
	}
	for _, row := range rows {
		if !validProviderSummary(row, tenantID) || !input.IncludeArchived && row.ArchivedAt != nil {
			return ProviderPage{}, ErrUnavailable
		}
	}
	items, next, err := boundedPage(rows, page.After, page.Limit)
	if err != nil {
		return ProviderPage{}, err
	}
	return ProviderPage{Items: items, NextCursor: next}, nil
}

func (s *Service) Get(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
) (Provider, error) {
	if !validUUIDv7(providerID) {
		return Provider{}, ErrInvalidInput
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderRead)
	if err != nil {
		return Provider{}, err
	}
	provider, err := s.repository.Get(ctx, GetParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		ProviderID:  providerID,
	})
	if err != nil {
		return Provider{}, mapRepositoryError(err)
	}
	if provider.ID != providerID || !validProvider(provider, tenantID) {
		return Provider{}, ErrUnavailable
	}
	return provider, nil
}

func (s *Service) Create(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input CreateInput,
) (CreateResult, error) {
	normalized, err := normalizeCreate(input)
	if err != nil {
		return CreateResult{}, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return CreateResult{}, err
	}
	if err := s.validateDeploymentConfiguration(normalized.Configuration, normalized.Endpoints); err != nil {
		return CreateResult{}, err
	}
	now, err := s.currentTime()
	if err != nil {
		return CreateResult{}, err
	}
	providerID, err := s.nextID()
	if err != nil {
		return CreateResult{}, err
	}
	digest := sha256.Sum256([]byte(normalized.IdempotencyKey))
	defer clear(digest[:])
	result, err := s.repository.Create(ctx, CreateParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, ProviderID: providerID,
		IdempotencyKeyDigest: digest, Key: normalized.Key, DisplayName: normalized.DisplayName,
		Description: normalized.Description, Configuration: normalized.Configuration,
		Endpoints: normalized.Endpoints,
	})
	if err != nil {
		return CreateResult{}, mapRepositoryError(err)
	}
	if !validUUIDv7(result.ProviderID) || result.Version < 1 || result.Version > maximumResourceVersion ||
		!result.Replayed && (result.ProviderID != providerID || result.Version != 1) {
		return CreateResult{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) Update(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input UpdateInput,
) (int64, error) {
	normalized, version, err := normalizeUpdate(providerID, input)
	if err != nil {
		return 0, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return 0, err
	}
	if err := s.validateDeploymentConfiguration(normalized.Configuration, normalized.Endpoints); err != nil {
		return 0, err
	}
	now, err := s.currentTime()
	if err != nil {
		return 0, err
	}
	updatedVersion, err := s.repository.Update(ctx, UpdateParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, ProviderID: providerID, ExpectedVersion: version,
		Key: normalized.Key, DisplayName: normalized.DisplayName, Description: normalized.Description,
		Enabled: normalized.Enabled, Configuration: normalized.Configuration, Endpoints: normalized.Endpoints,
	})
	if err != nil {
		return 0, mapRepositoryError(err)
	}
	if updatedVersion != version+1 {
		return 0, ErrUnavailable
	}
	return updatedVersion, nil
}

func (s *Service) Archive(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input ArchiveInput,
) (int64, error) {
	normalized, version, err := normalizeArchive(providerID, input)
	if err != nil {
		return 0, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return 0, err
	}
	now, err := s.currentTime()
	if err != nil {
		return 0, err
	}
	updatedVersion, err := s.repository.Archive(ctx, ArchiveParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, ProviderID: providerID,
		ExpectedVersion: version, Reason: normalized.Reason,
	})
	if err != nil {
		return 0, mapRepositoryError(err)
	}
	if updatedVersion != version+1 {
		return 0, ErrUnavailable
	}
	return updatedVersion, nil
}

func (s *Service) RotateBindSecret(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input RotateBindSecretInput,
) (int64, error) {
	defer clear(input.Secret)
	normalized, version, err := normalizeRotateBindSecret(providerID, input)
	if err != nil {
		return 0, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return 0, err
	}
	human := HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID}
	secretID, err := s.repository.GetBindSecretID(ctx, GetBindSecretIDParams{
		HumanParams: human, ProviderID: providerID,
	})
	if err != nil {
		return 0, mapRepositoryError(err)
	}
	if secretID == nil {
		generated, generateErr := s.nextID()
		if generateErr != nil {
			return 0, generateErr
		}
		secretID = &generated
	} else if !validUUIDv7(*secretID) {
		return 0, ErrUnavailable
	}
	envelope, err := s.keyring.EncryptBindSecret(bindSecretContext(tenantID, providerID, *secretID), normalized.Secret)
	if err != nil {
		return 0, ErrUnavailable
	}
	defer clear(envelope.Ciphertext)
	now, err := s.currentTime()
	if err != nil {
		return 0, err
	}
	updatedVersion, err := s.repository.RotateBindSecret(ctx, RotateBindSecretParams{
		HumanParams: human, Audit: normalized.Audit, OccurredAt: now, ProviderID: providerID,
		ExpectedVersion: version, Secret: EncryptedBindSecret{SecretID: *secretID, Envelope: envelope},
	})
	if err != nil {
		return 0, mapRepositoryError(err)
	}
	if updatedVersion != version+1 {
		return 0, ErrUnavailable
	}
	return updatedVersion, nil
}

func (s *Service) ClearBindSecret(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input ClearBindSecretInput,
) (int64, error) {
	normalized, version, err := normalizeClearBindSecret(providerID, input)
	if err != nil {
		return 0, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return 0, err
	}
	now, err := s.currentTime()
	if err != nil {
		return 0, err
	}
	updatedVersion, err := s.repository.ClearBindSecret(ctx, ClearBindSecretParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, ProviderID: providerID,
		ExpectedVersion: version, Reason: normalized.Reason,
	})
	if err != nil {
		return 0, mapRepositoryError(err)
	}
	if updatedVersion != version+1 {
		return 0, ErrUnavailable
	}
	return updatedVersion, nil
}

func (s *Service) TestConnection(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input TestInput,
) (TestResult, error) {
	return s.test(ctx, actor, tenantID, providerID, TestKindConnection, input)
}

func (s *Service) TestBind(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input TestInput,
) (TestResult, error) {
	return s.test(ctx, actor, tenantID, providerID, TestKindBind, input)
}

func (s *Service) test(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	kind TestKind,
	input TestInput,
) (TestResult, error) {
	if !validUUIDv7(providerID) || !validAudit(input.Audit, true) {
		return TestResult{}, ErrInvalidInput
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderTest)
	if err != nil {
		return TestResult{}, err
	}
	testRunID, err := s.nextID()
	if err != nil {
		return TestResult{}, err
	}
	now, err := s.currentTime()
	if err != nil {
		return TestResult{}, err
	}
	human := HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID}
	snapshot, err := s.repository.BeginTest(ctx, BeginTestParams{
		HumanParams: human, Audit: input.Audit, OccurredAt: now,
		TestRunID: testRunID, ProviderID: providerID, Kind: kind,
	})
	if err != nil {
		return TestResult{}, mapRepositoryError(err)
	}
	if snapshot.TestRunID != testRunID || snapshot.ProviderID != providerID {
		return TestResult{}, ErrUnavailable
	}
	if snapshot.Secret != nil {
		defer clear(snapshot.Secret.Envelope.Ciphertext)
	}

	diagnostic, diagnosticErr := s.runDiagnostic(ctx, tenantID, kind, snapshot)
	reported := reportedDiagnostic(diagnostic, diagnosticErr)
	completedAt, clockErr := s.currentTime()
	if clockErr != nil {
		return TestResult{}, clockErr
	}
	completionContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), diagnosticCompletionTimeout)
	defer cancel()
	result, completeErr := s.repository.CompleteTest(completionContext, CompleteTestParams{
		HumanParams: human, Audit: input.Audit, OccurredAt: completedAt, TestRunID: testRunID,
		ReportedOutcome: reported.outcome, ReportedCategory: reported.category,
		EndpointPriority: reported.endpointPriority, Duration: reported.duration,
	})
	if completeErr != nil {
		return TestResult{}, mapRepositoryError(completeErr)
	}
	if result.Stale || result.Category == TestCategoryCancelled {
		result.EndpointPriority = nil
	}
	if !validTestResult(result, testRunID) {
		return TestResult{}, ErrUnavailable
	}
	if ctx.Err() != nil {
		return TestResult{}, ctx.Err()
	}
	if diagnosticErr != nil {
		if errors.Is(diagnosticErr, ldapclient.ErrBusy) {
			return TestResult{}, ErrRateLimited
		}
		return TestResult{}, ErrUnavailable
	}
	return result, nil
}

type diagnosticReport struct {
	outcome          TestOutcome
	category         TestCategory
	endpointPriority *int
	duration         time.Duration
}

func (s *Service) runDiagnostic(
	ctx context.Context,
	tenantID uuid.UUID,
	kind TestKind,
	snapshot TestSnapshot,
) (ldapclient.Diagnostic, error) {
	if !validTestSnapshot(snapshot, tenantID, kind) {
		return ldapclient.Diagnostic{}, ldapclient.ErrInvalidConfiguration
	}
	configuration, endpoints, err := normalizeConfiguration(snapshot.Configuration, snapshot.Endpoints)
	if err != nil {
		return ldapclient.Diagnostic{}, ldapclient.ErrInvalidConfiguration
	}
	networkConfiguration, err := deploymentLDAPConfiguration(configuration, endpoints, true)
	if err != nil {
		return ldapclient.Diagnostic{}, ldapclient.ErrInvalidConfiguration
	}
	defer clear(networkConfiguration.CustomCAPEM)
	if err := s.diagnostics.ValidateConfiguration(networkConfiguration); err != nil {
		return ldapclient.Diagnostic{}, ldapclient.ErrInvalidConfiguration
	}
	if kind == TestKindConnection {
		return s.diagnostics.TestConnection(ctx, networkConfiguration)
	}
	plaintext, err := s.keyring.DecryptBindSecret(
		bindSecretContext(tenantID, snapshot.ProviderID, snapshot.Secret.SecretID),
		snapshot.Secret.Envelope,
	)
	if err != nil {
		return ldapclient.Diagnostic{}, ldapclient.ErrInvalidConfiguration
	}
	defer clear(plaintext)
	return s.diagnostics.TestBind(ctx, networkConfiguration, configuration.BindDN, plaintext)
}

func (s *Service) validateDeploymentConfiguration(configuration Configuration, endpoints []Endpoint) error {
	networkConfiguration, err := deploymentLDAPConfiguration(configuration, endpoints, false)
	if err != nil {
		return ErrInvalidInput
	}
	defer clear(networkConfiguration.CustomCAPEM)
	if err := s.diagnostics.ValidateConfiguration(networkConfiguration); err != nil {
		return ErrInvalidInput
	}
	return nil
}

func deploymentLDAPConfiguration(
	configuration Configuration,
	endpoints []Endpoint,
	enabledOnly bool,
) (ldapclient.Configuration, error) {
	connectTimeout, ok := millisecondsDuration(configuration.ConnectTimeoutMS)
	if !ok {
		return ldapclient.Configuration{}, ErrInvalidInput
	}
	operationTimeout, ok := millisecondsDuration(configuration.OperationTimeoutMS)
	if !ok {
		return ldapclient.Configuration{}, ErrInvalidInput
	}
	result := ldapclient.Configuration{
		Endpoints:        make([]ldapclient.Endpoint, 0, len(endpoints)),
		ConnectTimeout:   connectTimeout,
		OperationTimeout: operationTimeout,
	}
	if configuration.CustomCAPEM != nil {
		result.CustomCAPEM = []byte(*configuration.CustomCAPEM)
	}
	for _, endpoint := range endpoints {
		if enabledOnly && !endpoint.Enabled {
			continue
		}
		result.Endpoints = append(result.Endpoints, ldapclient.Endpoint{
			Priority: endpoint.Priority, Host: endpoint.Host, Port: endpoint.Port,
			Transport: endpoint.Transport, TLSServerName: endpoint.TLSServerName,
			Enabled: endpoint.Enabled, ReferralAllowed: endpoint.ReferralAllowed,
		})
	}
	if len(result.Endpoints) == 0 {
		clear(result.CustomCAPEM)
		return ldapclient.Configuration{}, ErrInvalidInput
	}
	return result, nil
}

func millisecondsDuration(value int) (time.Duration, bool) {
	if value <= 0 || uint64(value) > uint64((1<<63-1)/int64(time.Millisecond)) {
		return 0, false
	}
	return time.Duration(value) * time.Millisecond, true
}

func reportedDiagnostic(value ldapclient.Diagnostic, err error) diagnosticReport {
	if err != nil {
		return diagnosticReport{outcome: TestOutcomeFailure, category: TestCategoryCancelled}
	}
	duration := value.Duration.Truncate(time.Millisecond)
	if duration < 0 {
		duration = 0
	}
	if duration > 120*time.Second {
		duration = 120 * time.Second
	}
	category := TestCategory(value.Category)
	outcome := TestOutcome(value.Outcome)
	priorityIsValid := value.EndpointPriority >= 1 && value.EndpointPriority <= 8
	valid := false
	switch category {
	case TestCategorySuccess:
		valid = outcome == TestOutcomeSuccess && priorityIsValid
	case TestCategoryDNSFailed, TestCategoryDestinationBlocked, TestCategoryConnectTimeout,
		TestCategoryConnectFailed, TestCategoryTLSFailed, TestCategoryCertificateRejected,
		TestCategoryBindRejected, TestCategoryProtocolFailed:
		valid = outcome == TestOutcomeFailure && priorityIsValid
	case TestCategoryCancelled:
		valid = outcome == TestOutcomeFailure
	}
	if !valid {
		return diagnosticReport{outcome: TestOutcomeFailure, category: TestCategoryCancelled, duration: duration}
	}
	var endpointPriority *int
	if category != TestCategoryCancelled {
		priority := value.EndpointPriority
		endpointPriority = &priority
	}
	return diagnosticReport{
		outcome: outcome, category: category, endpointPriority: endpointPriority, duration: duration,
	}
}

func bindSecretContext(tenantID, providerID, secretID uuid.UUID) identity.BindSecretContext {
	return identity.BindSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: identity.EntityID(tenantID),
			ProviderID: identity.EntityID(providerID),
		},
		SecretID: identity.EntityID(secretID),
	}
}

func (s *Service) resolveAndRequire(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	permission authorization.TenantPermission,
) (authorization.TenantAuthority, error) {
	if !validUUIDv7(tenantID) {
		return authorization.TenantAuthority{}, ErrInvalidInput
	}
	if !validUUIDv7(actor.UserID) || !validUUIDv7(actor.SessionID) ||
		actor.ActiveTenantID != tenantID || !validText(actor.AuthenticationMethod, 1, 64) {
		return authorization.TenantAuthority{}, ErrForbidden
	}
	authority, err := s.repository.ResolveHumanAuthority(ctx, authorization.ResolveAuthorityParams{
		Actor: actor, TenantID: tenantID,
	})
	if err != nil {
		return authorization.TenantAuthority{}, mapRepositoryError(err)
	}
	if authority.TenantID != tenantID || authority.Principal.ID != actor.UserID ||
		authority.Principal.Kind != authorization.PrincipalKindHuman || !validUUIDv7(authority.MembershipID) {
		return authorization.TenantAuthority{}, ErrUnavailable
	}
	if err := s.evaluator.RequireTenant(
		authority, permission, authorization.ResourceContext{TenantID: tenantID},
	); err != nil {
		return authorization.TenantAuthority{}, ErrForbidden
	}
	return authority, nil
}

func (s *Service) currentTime() (time.Time, error) {
	value := s.now().UTC().Truncate(time.Microsecond)
	if !validInstant(value) {
		return time.Time{}, ErrUnavailable
	}
	return value, nil
}

func (s *Service) nextID() (uuid.UUID, error) {
	value, err := s.newID()
	if err != nil || !validUUIDv7(value) {
		return uuid.Nil, ErrUnavailable
	}
	return value, nil
}

func validProviderSummary(value ProviderSummary, tenantID uuid.UUID) bool {
	if !validUUIDv7(value.ID) || value.TenantID != tenantID || !providerKeyPattern.MatchString(value.Key) ||
		!validText(value.DisplayName, 1, 120) || !validText(value.Description, 0, 1000) ||
		!knownTemplate(value.Template) || value.EnabledEndpointCount < 0 || value.EnabledEndpointCount > 8 ||
		value.Version < 1 || value.Version > maximumResourceVersion ||
		!validInstant(value.CreatedAt) || !validInstant(value.UpdatedAt) || value.UpdatedAt.Before(value.CreatedAt) {
		return false
	}
	if value.ArchivedAt != nil {
		return !value.Enabled && validInstant(*value.ArchivedAt) && !value.ArchivedAt.Before(value.CreatedAt)
	}
	return true
}

func validProvider(value Provider, tenantID uuid.UUID) bool {
	if !validProviderSummary(value.ProviderSummary, tenantID) || len(value.Endpoints) < 1 || len(value.Endpoints) > 8 {
		return false
	}
	if _, _, err := normalizeConfiguration(value.Configuration, value.Endpoints); err != nil {
		return false
	}
	if value.BindSecretConfigured != (value.BindSecretRotatedAt != nil) ||
		value.BindSecretRotatedAt != nil && (!validInstant(*value.BindSecretRotatedAt) || value.BindSecretRotatedAt.Before(value.CreatedAt)) {
		return false
	}
	if value.ArchivedAt == nil {
		return value.ArchiveReason == nil
	}
	return value.ArchiveReason != nil && validText(*value.ArchiveReason, 1, 500)
}

func validTestSnapshot(value TestSnapshot, tenantID uuid.UUID, kind TestKind) bool {
	if !validUUIDv7(value.TestRunID) || !validUUIDv7(value.ProviderID) ||
		value.ProviderVersion < 1 || value.ProviderVersion > maximumResourceVersion ||
		value.ConfigurationVersion < 1 || value.ConfigurationVersion > maximumResourceVersion ||
		!validInstant(value.StartedAt) {
		return false
	}
	switch kind {
	case TestKindConnection:
		return value.SecretVersion == nil && value.Secret == nil
	case TestKindBind:
		return value.SecretVersion != nil && *value.SecretVersion >= 1 && value.Secret != nil &&
			validUUIDv7(value.Secret.SecretID) && value.Secret.Envelope.KeyVersion >= 1 &&
			len(value.Secret.Envelope.Ciphertext) >= 17 && len(value.Secret.Envelope.Ciphertext) <= 8192
	default:
		return false
	}
}

func validTestResult(value TestResult, testRunID uuid.UUID) bool {
	if value.TestRunID != testRunID || !validInstant(value.CompletedAt) ||
		value.Duration < 0 || value.Duration > 120*time.Second {
		return false
	}
	if value.EndpointPriority != nil && (*value.EndpointPriority < 1 || *value.EndpointPriority > 8) {
		return false
	}
	if value.Category == TestCategoryStaleConfiguration {
		return value.Outcome == TestOutcomeInconclusive && value.Stale && value.EndpointPriority == nil
	}
	if value.Stale {
		return false
	}
	if value.Outcome == TestOutcomeSuccess {
		return value.Category == TestCategorySuccess && value.EndpointPriority != nil
	}
	return value.Outcome == TestOutcomeFailure && value.Category != TestCategorySuccess &&
		value.Category != TestCategoryStaleConfiguration && knownFailureTestCategory(value.Category) &&
		(value.Category == TestCategoryCancelled && value.EndpointPriority == nil ||
			value.Category != TestCategoryCancelled && value.EndpointPriority != nil)
}

func knownFailureTestCategory(value TestCategory) bool {
	switch value {
	case TestCategoryDNSFailed,
		TestCategoryDestinationBlocked,
		TestCategoryConnectTimeout,
		TestCategoryConnectFailed,
		TestCategoryTLSFailed,
		TestCategoryCertificateRejected,
		TestCategoryBindRejected,
		TestCategoryProtocolFailed,
		TestCategoryCancelled:
		return true
	default:
		return false
	}
}

func mapRepositoryError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, authorization.ErrDenied), errors.Is(err, authorization.ErrForbidden), errors.Is(err, ErrForbidden):
		return ErrForbidden
	case errors.Is(err, authorization.ErrInvalidInput), errors.Is(err, ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, authorization.ErrNotFound), errors.Is(err, ErrNotFound):
		return ErrNotFound
	case errors.Is(err, authorization.ErrConflict), errors.Is(err, ErrConflict):
		return ErrConflict
	case errors.Is(err, authorization.ErrPreconditionRequired), errors.Is(err, ErrPreconditionRequired):
		return ErrPreconditionRequired
	case errors.Is(err, authorization.ErrPreconditionFailed), errors.Is(err, ErrPreconditionFailed):
		return ErrPreconditionFailed
	case errors.Is(err, ErrRateLimited):
		return ErrRateLimited
	case errors.Is(err, authorization.ErrUnavailable), errors.Is(err, ErrUnavailable):
		return ErrUnavailable
	default:
		return ErrUnavailable
	}
}
