package federatedauth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

// TenantOIDCConfigurationRecord is the exact immutable database projection
// for one ceremony. Authorization contains scalar tenant configuration only;
// Discovery and JWKS are reconstructed from the persisted public documents so
// a database projection can never forge executable endpoint or key objects.
type TenantOIDCConfigurationRecord struct {
	Authorization     federatedoidc.AuthorizationConfiguration
	Issuer            string
	DiscoveryRevision uint64
	DiscoveryDocument []byte `json:"-"`
	DiscoveryDigest   [sha256.Size]byte
	DiscoveryCache    federatedhttp.CacheMetadata
	DiscoveryPolicy   federatedoidc.TrustPolicy
	JWKSDocument      []byte `json:"-"`
	JWKSDigest        [sha256.Size]byte
	JWKSRevision      uint64
	JWKSCache         federatedhttp.CacheMetadata
	IDTokenClaims     federatedoidc.ClaimExtractionPolicy
	UserInfoClaims    federatedoidc.ClaimExtractionPolicy
}

func (record TenantOIDCConfigurationRecord) String() string {
	return fmt.Sprintf(
		"federatedauth.TenantOIDCConfigurationRecord{discovery_bytes:%d,jwks_bytes:%d,material:[REDACTED]}",
		len(record.DiscoveryDocument), len(record.JWKSDocument),
	)
}
func (record TenantOIDCConfigurationRecord) GoString() string { return record.String() }

// TenantSAMLConfigurationRecord persists the bounded public metadata document
// beside scalar policy. Authentication.Metadata must be empty: it is compiled
// afresh and its digest is compared before the configuration is returned.
type TenantSAMLConfigurationRecord struct {
	Authentication            federatedsaml.Configuration
	ExpectedEntityID          string
	MetadataRevision          uint64
	MetadataDocument          []byte `json:"-"`
	MetadataDigest            [sha256.Size]byte
	MetadataRetrievedAt       time.Time
	MetadataMaximumValidUntil time.Time
}

func (record TenantSAMLConfigurationRecord) String() string {
	return fmt.Sprintf(
		"federatedauth.TenantSAMLConfigurationRecord{metadata_bytes:%d,material:[REDACTED]}",
		len(record.MetadataDocument),
	)
}
func (record TenantSAMLConfigurationRecord) GoString() string { return record.String() }

// TenantFederatedConfigurationRecords is the narrow persistence ABI behind
// anonymous start and callback resolution. Implementations must meter Begin
// transactionally and derive callback tenant context exclusively from pins.
type TenantFederatedConfigurationRecords interface {
	BeginTenantOIDCConfigurationRecord(context.Context, OIDCStartLookup) (TenantOIDCConfigurationRecord, error)
	ResolveTenantOIDCConfigurationRecord(context.Context, federatedoidc.CallbackConfigurationLookup) (TenantOIDCConfigurationRecord, error)
	BeginTenantSAMLConfigurationRecord(context.Context, SAMLStartLookup) (TenantSAMLConfigurationRecord, error)
	ResolveTenantSAMLConfigurationRecord(context.Context, federatedsaml.CallbackConfigurationLookup) (TenantSAMLConfigurationRecord, error)
}

// PinnedTenantConfigurationSource reconstructs executable trust snapshots at
// the application boundary. It performs no network I/O and owns no cache; a
// stale or malformed persisted document fails closed.
type PinnedTenantConfigurationSource struct {
	records TenantFederatedConfigurationRecords
	oidc    *federatedoidc.Client
}

func NewPinnedTenantConfigurationSource(
	records TenantFederatedConfigurationRecords,
	oidc *federatedoidc.Client,
) (*PinnedTenantConfigurationSource, error) {
	if records == nil || oidc == nil {
		return nil, ErrInvalidOptions
	}
	return &PinnedTenantConfigurationSource{records: records, oidc: oidc}, nil
}

func (source *PinnedTenantConfigurationSource) String() string {
	return fmt.Sprintf(
		"federatedauth.PinnedTenantConfigurationSource{configured:%t}",
		source != nil && source.records != nil && source.oidc != nil,
	)
}
func (source *PinnedTenantConfigurationSource) GoString() string { return source.String() }

var _ TenantOIDCConfigurationSource = (*PinnedTenantConfigurationSource)(nil)
var _ TenantSAMLConfigurationSource = (*PinnedTenantConfigurationSource)(nil)

func (source *PinnedTenantConfigurationSource) BeginTenantOIDCLogin(
	ctx context.Context,
	lookup OIDCStartLookup,
) (TenantOIDCConfiguration, error) {
	if source == nil || source.records == nil || source.oidc == nil || ctx == nil || ctx.Err() != nil ||
		!validOIDCStartLookup(lookup) {
		return TenantOIDCConfiguration{}, ErrAuthentication
	}
	record, err := source.records.BeginTenantOIDCConfigurationRecord(ctx, lookup)
	if ctx.Err() != nil {
		return TenantOIDCConfiguration{}, ErrAuthentication
	}
	return source.compileOIDCRecord(record, err)
}

func (source *PinnedTenantConfigurationSource) ResolveTenantOIDCCallback(
	ctx context.Context,
	lookup federatedoidc.CallbackConfigurationLookup,
) (TenantOIDCConfiguration, error) {
	if source == nil || source.records == nil || source.oidc == nil || ctx == nil || ctx.Err() != nil ||
		!validOIDCCallbackConfigurationLookup(lookup) {
		return TenantOIDCConfiguration{}, ErrAuthentication
	}
	record, err := source.records.ResolveTenantOIDCConfigurationRecord(ctx, lookup)
	if ctx.Err() != nil {
		return TenantOIDCConfiguration{}, ErrAuthentication
	}
	configuration, compileErr := source.compileOIDCRecord(record, err)
	if compileErr != nil || !sameOIDCConfigurationPins(configuration.Authorization, lookup) {
		return TenantOIDCConfiguration{}, ErrAuthentication
	}
	return configuration, nil
}

func (source *PinnedTenantConfigurationSource) compileOIDCRecord(
	record TenantOIDCConfigurationRecord,
	recordErr error,
) (TenantOIDCConfiguration, error) {
	discoveryDocument := append([]byte(nil), record.DiscoveryDocument...)
	jwksDocument := append([]byte(nil), record.JWKSDocument...)
	defer clear(discoveryDocument)
	defer clear(jwksDocument)
	authorization := record.Authorization
	if recordErr != nil || authorization.Discovery.Revision() != 0 || authorization.JWKS.Revision() != 0 ||
		!validDatabaseRevision(record.DiscoveryRevision) || !validDatabaseRevision(record.JWKSRevision) {
		return TenantOIDCConfiguration{}, ErrAuthentication
	}
	discovery, err := source.oidc.RestoreDiscovery(federatedoidc.DiscoverySnapshotRecord{
		Request: federatedoidc.DiscoveryRequest{
			Issuer: record.Issuer, Revision: record.DiscoveryRevision,
			Policy: record.DiscoveryPolicy,
		},
		Document: discoveryDocument, Digest: record.DiscoveryDigest, Cache: record.DiscoveryCache,
	})
	if err != nil {
		return TenantOIDCConfiguration{}, ErrAuthentication
	}
	keys, err := source.oidc.RestoreJWKS(federatedoidc.JWKSSnapshotRecord{
		Revision: record.JWKSRevision, Document: jwksDocument,
		Digest: record.JWKSDigest, Cache: record.JWKSCache, Discovery: discovery,
	})
	if err != nil {
		return TenantOIDCConfiguration{}, ErrAuthentication
	}
	authorization.Discovery = discovery
	authorization.JWKS = keys
	configuration := TenantOIDCConfiguration{
		Authorization:  authorization,
		IDTokenClaims:  cloneOIDCClaimPolicy(record.IDTokenClaims),
		UserInfoClaims: cloneOIDCClaimPolicy(record.UserInfoClaims),
	}
	if !validTenantOIDCConfiguration(configuration) {
		return TenantOIDCConfiguration{}, ErrAuthentication
	}
	return cloneTenantOIDCConfiguration(configuration), nil
}

func (source *PinnedTenantConfigurationSource) BeginTenantSAMLLogin(
	ctx context.Context,
	lookup SAMLStartLookup,
) (TenantSAMLConfiguration, error) {
	if source == nil || source.records == nil || ctx == nil || ctx.Err() != nil || !validSAMLStartLookup(lookup) {
		return TenantSAMLConfiguration{}, ErrAuthentication
	}
	record, err := source.records.BeginTenantSAMLConfigurationRecord(ctx, lookup)
	if ctx.Err() != nil {
		return TenantSAMLConfiguration{}, ErrAuthentication
	}
	return compileSAMLRecord(record, err)
}

func (source *PinnedTenantConfigurationSource) ResolveTenantSAMLCallback(
	ctx context.Context,
	lookup federatedsaml.CallbackConfigurationLookup,
) (TenantSAMLConfiguration, error) {
	if source == nil || source.records == nil || ctx == nil || ctx.Err() != nil ||
		!validSAMLCallbackConfigurationLookup(lookup) {
		return TenantSAMLConfiguration{}, ErrAuthentication
	}
	record, err := source.records.ResolveTenantSAMLConfigurationRecord(ctx, lookup)
	if ctx.Err() != nil {
		return TenantSAMLConfiguration{}, ErrAuthentication
	}
	configuration, compileErr := compileSAMLRecord(record, err)
	if compileErr != nil || !sameSAMLConfigurationPins(
		configuration.Authentication, lookup, record.MetadataRetrievedAt,
	) {
		return TenantSAMLConfiguration{}, ErrAuthentication
	}
	return configuration, nil
}

func compileSAMLRecord(
	record TenantSAMLConfigurationRecord,
	recordErr error,
) (TenantSAMLConfiguration, error) {
	document := append([]byte(nil), record.MetadataDocument...)
	defer clear(document)
	authentication := record.Authentication
	if recordErr != nil || authentication.Metadata.Revision() != 0 || !validDatabaseRevision(record.MetadataRevision) ||
		record.MetadataDigest == ([sha256.Size]byte{}) {
		return TenantSAMLConfiguration{}, ErrAuthentication
	}
	metadata, err := federatedsaml.CompileMetadata(federatedsaml.MetadataCompilationRequest{
		Document: document, ExpectedEntityID: record.ExpectedEntityID,
		Revision: record.MetadataRevision, RetrievedAt: record.MetadataRetrievedAt,
		MaximumValidUntil: record.MetadataMaximumValidUntil,
	}, federatedsaml.DefaultLimits())
	if err != nil || metadata.Digest() != record.MetadataDigest {
		return TenantSAMLConfiguration{}, ErrAuthentication
	}
	authentication.Metadata = metadata
	configuration := TenantSAMLConfiguration{Authentication: authentication}
	if !validTenantSAMLConfiguration(configuration) {
		return TenantSAMLConfiguration{}, ErrAuthentication
	}
	return cloneTenantSAMLConfiguration(configuration), nil
}

func validOIDCCallbackConfigurationLookup(lookup federatedoidc.CallbackConfigurationLookup) bool {
	pins := lookup.Pins
	admission, validAdmission := pins.TenantAdmission()
	return lookup.TransactionID != (federatedoidc.TransactionID{}) && validDatabaseRevision(lookup.ExpectedVersion) &&
		validAdmission && validTenantAdmission(pins.Provider, admission) &&
		validDatabaseRevision(pins.ProviderRevision) && validDatabaseRevision(pins.BindingRevision) &&
		validDatabaseRevision(pins.ConfigurationRevision) && validDatabaseRevision(pins.SecurityRevision) &&
		validDatabaseRevision(pins.MappingRevision) && validDatabaseRevision(pins.AuthorizationRevision) &&
		validDatabaseRevision(pins.AssurancePolicyRevision) && validDatabaseRevision(pins.ClientSecretRevision) &&
		validDatabaseRevision(pins.DiscoveryRevision) && pins.DiscoveryDigest != ([sha256.Size]byte{}) &&
		validDatabaseRevision(pins.JWKSRevision) && pins.JWKSDigest != ([sha256.Size]byte{})
}

func sameOIDCConfigurationPins(
	configuration federatedoidc.AuthorizationConfiguration,
	lookup federatedoidc.CallbackConfigurationLookup,
) bool {
	pins := lookup.Pins
	return configuration.Provider == pins.Provider && configuration.Admission == pins.Admission &&
		configuration.BindingID == pins.BindingID &&
		configuration.ProviderRevision == pins.ProviderRevision && configuration.BindingRevision == pins.BindingRevision &&
		configuration.ConfigurationRevision == pins.ConfigurationRevision && configuration.SecurityRevision == pins.SecurityRevision &&
		configuration.MappingRevision == pins.MappingRevision && configuration.AuthorizationRevision == pins.AuthorizationRevision &&
		configuration.AssurancePolicyRevision == pins.AssurancePolicyRevision &&
		configuration.ClientSecretRevision == pins.ClientSecretRevision &&
		configuration.Discovery.Revision() == pins.DiscoveryRevision && configuration.Discovery.Digest() == pins.DiscoveryDigest &&
		configuration.JWKS.Revision() == pins.JWKSRevision && configuration.JWKS.Digest() == pins.JWKSDigest
}

func validSAMLCallbackConfigurationLookup(lookup federatedsaml.CallbackConfigurationLookup) bool {
	pins := lookup.Pins
	return lookup.TransactionID != (federatedsaml.TransactionID{}) && validDatabaseRevision(lookup.ExpectedVersion) &&
		validTenantProviderForTenant(pins.Provider, pins.Provider.TenantID) && pins.BindingID != (identity.EntityID{}) &&
		validDatabaseRevision(pins.ProviderRevision) && validDatabaseRevision(pins.BindingRevision) &&
		validDatabaseRevision(pins.ConfigurationRevision) && validDatabaseRevision(pins.SecurityRevision) &&
		validDatabaseRevision(pins.MappingRevision) && validDatabaseRevision(pins.AuthorizationRevision) &&
		validDatabaseRevision(pins.AssurancePolicyRevision) && validDatabaseRevision(pins.MetadataRevision) &&
		pins.MetadataDigest != ([sha256.Size]byte{}) && validDatabaseRevision(pins.SPKeyRevision) &&
		pins.ConfigurationDigest != ([sha256.Size]byte{})
}

func sameSAMLConfigurationPins(
	configuration federatedsaml.Configuration,
	lookup federatedsaml.CallbackConfigurationLookup,
	observedAt time.Time,
) bool {
	pins := lookup.Pins
	return configuration.Provider == pins.Provider && configuration.BindingID == pins.BindingID &&
		configuration.ProviderRevision == pins.ProviderRevision && configuration.BindingRevision == pins.BindingRevision &&
		configuration.ConfigurationRevision == pins.ConfigurationRevision && configuration.SecurityRevision == pins.SecurityRevision &&
		configuration.MappingRevision == pins.MappingRevision && configuration.AuthorizationRevision == pins.AuthorizationRevision &&
		configuration.AssurancePolicyRevision == pins.AssurancePolicyRevision &&
		configuration.Metadata.Revision() == pins.MetadataRevision && configuration.Metadata.Digest() == pins.MetadataDigest &&
		configuration.SPKeyRevision == pins.SPKeyRevision &&
		federatedsaml.ValidatePinnedConfiguration(configuration, pins, observedAt) == nil
}
