package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/origin"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamladapter"
)

const (
	loadPlatformSAMLMetadataSQL                = `select app.load_platform_saml_metadata_projection_v1($1::text)`
	platformSAMLReadinessSQL                   = `select app.platform_saml_direct_runtime_schema_readiness_v57()`
	maximumPlatformSAMLMetadataProjectionBytes = 4 * 1024 * 1024
)

type platformSAMLMetadataCertificateWire struct {
	KeyID                 string `json:"keyId"`
	KeyRevision           uint64 `json:"keyRevision"`
	PlatformLoginRevision uint64 `json:"platformLoginRevision"`
	Signing               bool   `json:"signing"`
	Encryption            bool   `json:"encryption"`
	CertificateDER        []byte `json:"certificateDer"`
}

type platformSAMLMetadataProjectionWire struct {
	directPlatformSAMLConfigurationWire
	Certificates []platformSAMLMetadataCertificateWire `json:"certificates"`
}

// PlatformSAMLRepository is the public projection/readiness boundary. Runtime
// mutation and secret methods remain on FederatedAuthRepository so callers
// cannot obtain private-key envelopes from a metadata-only dependency.
type PlatformSAMLRepository struct {
	queryer      federatedAuthQueryer
	publicOrigin string
}

func NewPlatformSAMLRepository(
	pool *pgxpool.Pool,
	publicOrigin string,
) (*PlatformSAMLRepository, error) {
	canonical, err := canonicalPlatformSAMLPublicOrigin(publicOrigin)
	if pool == nil || err != nil {
		return nil, errPlatformSAMLPersistence
	}
	return &PlatformSAMLRepository{queryer: pool, publicOrigin: canonical}, nil
}

func (repository *PlatformSAMLRepository) LoadDirectPlatformSAMLMetadata(
	ctx context.Context,
	providerKey string,
) (platformsamladapter.DirectSAMLMetadataProjection, bool, error) {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil ||
		!platformSAMLLoginKeyPattern.MatchString(providerKey) {
		return platformsamladapter.DirectSAMLMetadataProjection{}, false, errPlatformSAMLPersistence
	}
	var raw []byte
	if err := repository.queryer.QueryRow(ctx, loadPlatformSAMLMetadataSQL, providerKey).Scan(&raw); err != nil {
		clear(raw)
		return platformsamladapter.DirectSAMLMetadataProjection{}, false, errPlatformSAMLPersistence
	}
	defer clear(raw)
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		return platformsamladapter.DirectSAMLMetadataProjection{}, false, nil
	}
	if len(trimmed) == 0 || len(trimmed) > maximumPlatformSAMLMetadataProjectionBytes {
		return platformsamladapter.DirectSAMLMetadataProjection{}, false, errPlatformSAMLPersistence
	}
	var wire platformSAMLMetadataProjectionWire
	defer clearPlatformSAMLMetadataProjectionWire(&wire)
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return platformsamladapter.DirectSAMLMetadataProjection{}, false, errPlatformSAMLPersistence
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return platformsamladapter.DirectSAMLMetadataProjection{}, false, errPlatformSAMLPersistence
	}
	configuration, projectedKey, err := platformSAMLConfigurationFromWire(wire.directPlatformSAMLConfigurationWire)
	if err != nil || projectedKey != providerKey || len(wire.Certificates) < 1 || len(wire.Certificates) > 8 {
		return platformsamladapter.DirectSAMLMetadataProjection{}, false, errPlatformSAMLPersistence
	}
	certificates := make([]platformsamladapter.DirectSAMLPublicCertificate, len(wire.Certificates))
	type certificateKey struct {
		id       string
		revision uint64
	}
	nextSequence := make(map[certificateKey]uint8, len(wire.Certificates))
	for index, certificate := range wire.Certificates {
		keyID, keyErr := parseEntityIDWire(certificate.KeyID, false)
		key := certificateKey{id: certificate.KeyID, revision: certificate.KeyRevision}
		sequence := nextSequence[key]
		if keyErr != nil || !validPlatformSAMLRevision(certificate.KeyRevision) ||
			certificate.PlatformLoginRevision != configuration.Pins.Protocol.PlatformLoginRevision ||
			sequence >= 8 ||
			len(certificate.CertificateDER) == 0 ||
			len(certificate.CertificateDER) > maximumPlatformSAMLCertificateBytes {
			return platformsamladapter.DirectSAMLMetadataProjection{}, false, errPlatformSAMLPersistence
		}
		certificates[index] = platformsamladapter.DirectSAMLPublicCertificate{
			Context: identity.DirectPlatformSAMLSPKeyContext{
				Provider: configuration.Pins.Protocol.Provider, KeyID: keyID, KeyRevision: certificate.KeyRevision,
			},
			PlatformLoginRevision: certificate.PlatformLoginRevision,
			CertificateSequence:   sequence,
			Signing:               certificate.Signing, Encryption: certificate.Encryption,
			CertificateDER: append([]byte(nil), certificate.CertificateDER...),
		}
		nextSequence[key] = sequence + 1
	}
	return platformsamladapter.DirectSAMLMetadataProjection{
		ProviderKey: providerKey, PublicOrigin: repository.publicOrigin,
		Configuration: configuration, Certificates: certificates,
		ObservedAt: platformSAMLUTC(wire.ObservedAt),
	}, true, nil
}

func (repository *PlatformSAMLRepository) ReadyDirectPlatformSAML(ctx context.Context) error {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errPlatformSAMLPersistence
	}
	if runtimeVerifiedInProbe(ctx, repository.queryer) {
		return nil
	}
	var ready bool
	if err := repository.queryer.QueryRow(ctx, platformSAMLReadinessSQL).Scan(&ready); err != nil ||
		ctx.Err() != nil || !ready {
		return errPlatformSAMLPersistence
	}
	return nil
}

func canonicalPlatformSAMLPublicOrigin(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\\\r\n") {
		return "", errPlatformSAMLPersistence
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.ForceQuery || parsed.Hostname() == "" || strings.Contains(parsed.Host, "%") || strings.HasSuffix(parsed.Host, ":") {
		return "", errPlatformSAMLPersistence
	}
	hostname, err := origin.CanonicalHostname(parsed.Hostname())
	if err != nil || hostname != parsed.Hostname() {
		return "", errPlatformSAMLPersistence
	}
	return value, nil
}

func clearPlatformSAMLMetadataProjectionWire(value *platformSAMLMetadataProjectionWire) {
	if value == nil {
		return
	}
	clearPlatformSAMLConfigurationWire(&value.directPlatformSAMLConfigurationWire)
	for index := range value.Certificates {
		clear(value.Certificates[index].CertificateDER)
	}
	*value = platformSAMLMetadataProjectionWire{}
}
