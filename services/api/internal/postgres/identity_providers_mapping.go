package postgres

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

func mapListedIdentityProvider(
	tenantID uuid.UUID,
	row *dbsql.ListTenantLDAPProvidersRow,
) (identityprovider.ProviderSummary, error) {
	if row == nil {
		return identityprovider.ProviderSummary{}, invalidIdentityProviderProjection("null listed provider")
	}
	return mapIdentityProviderSummary(
		tenantID, row.ProviderID, row.ProviderKey, row.DisplayName, row.Description,
		row.Enabled, row.Template, row.BindSecretConfigured, row.EnabledEndpointCount,
		row.ArchivedAt, row.Version, row.CreatedAt, row.UpdatedAt,
	)
}

func mapGotIdentityProvider(
	tenantID uuid.UUID,
	row *dbsql.GetTenantLDAPProviderRow,
) (identityprovider.Provider, error) {
	if row == nil {
		return identityprovider.Provider{}, invalidIdentityProviderProjection("null provider")
	}
	configuration, err := decodeIdentityProviderJSON[identityprovider.Configuration](row.Configuration)
	if err != nil {
		return identityprovider.Provider{}, err
	}
	endpoints, err := decodeIdentityProviderJSON[[]identityprovider.Endpoint](row.Endpoints)
	if err != nil {
		return identityprovider.Provider{}, err
	}
	summary, err := mapIdentityProviderSummary(
		tenantID, row.ProviderID, row.ProviderKey, row.DisplayName, row.Description,
		row.Enabled, string(configuration.Template), row.BindSecretConfigured,
		countEnabledIdentityProviderEndpoints(endpoints), row.ArchivedAt, row.Version,
		row.CreatedAt, row.UpdatedAt,
	)
	if err != nil {
		return identityprovider.Provider{}, err
	}
	rotatedAt, err := optionalIdentityProviderTime(row.BindSecretRotatedAt)
	if err != nil {
		return identityprovider.Provider{}, err
	}
	var archiveReason *string
	if row.ArchiveReason != "" {
		value := row.ArchiveReason
		archiveReason = &value
	}
	if summary.ArchivedAt == nil && archiveReason != nil ||
		summary.ArchivedAt != nil && archiveReason == nil ||
		summary.BindSecretConfigured != (rotatedAt != nil) {
		return identityprovider.Provider{}, invalidIdentityProviderProjection("inconsistent provider lifecycle metadata")
	}
	return identityprovider.Provider{
		ProviderSummary: summary, Configuration: configuration, Endpoints: endpoints,
		BindSecretRotatedAt: rotatedAt, ArchiveReason: archiveReason,
	}, nil
}

func mapIdentityProviderSummary(
	tenantID uuid.UUID,
	providerID pgtype.UUID,
	key, displayName, description string,
	enabled bool,
	template string,
	bindSecretConfigured bool,
	enabledEndpointCount int32,
	archivedAt pgtype.Timestamptz,
	version int32,
	createdAt, updatedAt pgtype.Timestamptz,
) (identityprovider.ProviderSummary, error) {
	identifier, err := domainUUID(providerID)
	if err != nil || !identityProviderUUIDv7(identifier) {
		return identityprovider.ProviderSummary{}, invalidIdentityProviderProjection("invalid provider ID")
	}
	created, err := domainTime(createdAt)
	if err != nil {
		return identityprovider.ProviderSummary{}, invalidIdentityProviderProjection("invalid provider creation time")
	}
	updated, err := domainTime(updatedAt)
	if err != nil || updated.Before(created) || version < 1 {
		return identityprovider.ProviderSummary{}, invalidIdentityProviderProjection("invalid provider lifecycle")
	}
	archived, err := optionalIdentityProviderTime(archivedAt)
	if err != nil || archived != nil && (archived.Before(created) || enabled) {
		return identityprovider.ProviderSummary{}, invalidIdentityProviderProjection("invalid provider archive state")
	}
	providerTemplate := identityprovider.ProviderTemplate(template)
	switch providerTemplate {
	case identityprovider.ProviderTemplateActiveDirectory,
		identityprovider.ProviderTemplateOpenLDAP,
		identityprovider.ProviderTemplatePOSIX,
		identityprovider.ProviderTemplateCustom:
	default:
		return identityprovider.ProviderSummary{}, invalidIdentityProviderProjection("unknown provider template")
	}
	if enabledEndpointCount < 0 || enabledEndpointCount > 8 {
		return identityprovider.ProviderSummary{}, invalidIdentityProviderProjection("invalid enabled endpoint count")
	}
	return identityprovider.ProviderSummary{
		ID: identifier, TenantID: tenantID, Key: key, DisplayName: displayName,
		Description: description, Enabled: enabled, Template: providerTemplate,
		BindSecretConfigured: bindSecretConfigured, EnabledEndpointCount: int(enabledEndpointCount),
		ArchivedAt: archived, Version: int64(version), CreatedAt: created, UpdatedAt: updated,
	}, nil
}

func mapIdentityProviderTestSnapshot(
	row *dbsql.BeginTenantLDAPProviderTestRow,
	kind identityprovider.TestKind,
) (identityprovider.TestSnapshot, error) {
	if row != nil {
		defer clear(row.SecretCiphertext)
		defer clear(row.SecretNonce)
	}
	if row == nil || row.ProviderVersion < 1 || row.ConfigurationVersion < 1 {
		return identityprovider.TestSnapshot{}, invalidIdentityProviderProjection("invalid provider test snapshot")
	}
	testRunID, err := domainUUID(row.TestRunID)
	if err != nil || !identityProviderUUIDv7(testRunID) {
		return identityprovider.TestSnapshot{}, invalidIdentityProviderProjection("invalid provider test-run ID")
	}
	providerID, err := domainUUID(row.ProviderID)
	if err != nil || !identityProviderUUIDv7(providerID) {
		return identityprovider.TestSnapshot{}, invalidIdentityProviderProjection("invalid tested provider ID")
	}
	configuration, err := decodeIdentityProviderJSON[identityprovider.Configuration](row.Configuration)
	if err != nil {
		return identityprovider.TestSnapshot{}, err
	}
	endpoints, err := decodeIdentityProviderJSON[[]identityprovider.Endpoint](row.Endpoints)
	if err != nil || len(endpoints) < 1 || len(endpoints) > 8 {
		return identityprovider.TestSnapshot{}, invalidIdentityProviderProjection("invalid provider test endpoints")
	}
	startedAt, err := domainTime(row.StartedAt)
	if err != nil {
		return identityprovider.TestSnapshot{}, invalidIdentityProviderProjection("invalid provider test start time")
	}
	snapshot := identityprovider.TestSnapshot{
		TestRunID: testRunID, ProviderID: providerID, ProviderVersion: int64(row.ProviderVersion),
		ConfigurationVersion: int64(row.ConfigurationVersion), Configuration: configuration,
		Endpoints: endpoints, StartedAt: startedAt,
	}
	switch kind {
	case identityprovider.TestKindConnection:
		if row.SecretVersion != 0 || row.SecretID.Valid || len(row.SecretCiphertext) != 0 ||
			len(row.SecretNonce) != 0 || row.SecretKeyVersion != 0 || row.EncryptionAlgorithm != "" {
			return identityprovider.TestSnapshot{}, invalidIdentityProviderProjection("connection test exposed secret material")
		}
	case identityprovider.TestKindBind:
		secretID, secretErr := domainUUID(row.SecretID)
		if secretErr != nil || !identityProviderUUIDv7(secretID) || row.SecretVersion < 1 ||
			len(row.SecretCiphertext) < 17 || len(row.SecretCiphertext) > 8192 ||
			len(row.SecretNonce) != 12 || row.SecretKeyVersion < 1 || row.SecretKeyVersion > 32767 ||
			row.EncryptionAlgorithm != "aes-256-gcm" {
			return identityprovider.TestSnapshot{}, invalidIdentityProviderProjection("invalid bind-test secret envelope")
		}
		var nonce [12]byte
		copy(nonce[:], row.SecretNonce)
		secretVersion := int64(row.SecretVersion)
		snapshot.SecretVersion = &secretVersion
		snapshot.Secret = &identityprovider.EncryptedBindSecret{
			SecretID: secretID,
			Envelope: identity.BindSecretEnvelope{
				KeyVersion: int16(row.SecretKeyVersion), Nonce: nonce,
				Ciphertext: append([]byte(nil), row.SecretCiphertext...),
			},
		}
	default:
		return identityprovider.TestSnapshot{}, identityprovider.ErrInvalidInput
	}
	return snapshot, nil
}

func mapIdentityProviderTestResult(
	row *dbsql.CompleteTenantLDAPProviderTestRow,
) (identityprovider.TestResult, error) {
	if row == nil || row.DurationMs < 0 || row.DurationMs > 120_000 ||
		row.EndpointPriority < 0 || row.EndpointPriority > 8 {
		return identityprovider.TestResult{}, invalidIdentityProviderProjection("invalid provider test result")
	}
	testRunID, err := domainUUID(row.TestRunID)
	if err != nil || !identityProviderUUIDv7(testRunID) {
		return identityprovider.TestResult{}, invalidIdentityProviderProjection("invalid completed test-run ID")
	}
	completedAt, err := domainTime(row.CompletedAt)
	if err != nil {
		return identityprovider.TestResult{}, invalidIdentityProviderProjection("invalid provider test completion time")
	}
	var endpointPriority *int
	if row.EndpointPriority != 0 {
		value := int(row.EndpointPriority)
		endpointPriority = &value
	}
	return identityprovider.TestResult{
		TestRunID: testRunID, Outcome: identityprovider.TestOutcome(row.Outcome),
		Category: identityprovider.TestCategory(row.Category), EndpointPriority: endpointPriority,
		Duration: time.Duration(row.DurationMs) * time.Millisecond, Stale: row.Stale,
		CompletedAt: completedAt,
	}, nil
}

func optionalIdentityProviderTime(value pgtype.Timestamptz) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	result, err := domainTime(value)
	if err != nil {
		return nil, errors.New("database returned an invalid identity-provider timestamp")
	}
	return &result, nil
}

func countEnabledIdentityProviderEndpoints(values []identityprovider.Endpoint) int32 {
	var count int32
	for _, value := range values {
		if value.Enabled {
			count++
		}
	}
	return count
}
