package postgres

import (
	"context"
	"crypto/sha256"
	"slices"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamladapter"
)

const (
	loadPlatformSAMLSPKeyEnvelopeSQL       = `select app.load_platform_saml_sp_key_envelope_v1($1::jsonb)`
	loadPlatformSAMLLogoutSPKeyEnvelopeSQL = `select app.load_platform_saml_logout_sp_key_envelope_v1($1::jsonb)`
	maximumPlatformSAMLSPKeyWireBytes      = 1024 * 1024
)

type platformSAMLSPKeyLookupWire struct {
	Provider              platformSAMLProviderWire `json:"provider"`
	PlatformLoginRevision uint64                   `json:"platformLoginRevision"`
	KeyRevision           uint64                   `json:"keyRevision"`
	MaterialID            string                   `json:"materialId,omitempty"`
}

type platformSAMLSPKeyContextWire struct {
	Provider    platformSAMLProviderWire `json:"provider"`
	KeyID       string                   `json:"keyId"`
	KeyRevision uint64                   `json:"keyRevision"`
}

type platformSAMLSPKeyEnvelopeWire struct {
	KeyVersion int16  `json:"keyVersion"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type platformSAMLSPKeyProjectionWire struct {
	Request               platformSAMLSPKeyLookupWire   `json:"request"`
	PlatformLoginRevision uint64                        `json:"platformLoginRevision"`
	Context               platformSAMLSPKeyContextWire  `json:"context"`
	Envelope              platformSAMLSPKeyEnvelopeWire `json:"envelope"`
	CertificateDER        [][]byte                      `json:"certificateDer"`
	Live                  bool                          `json:"live"`
}

var _ platformsamladapter.DirectSAMLSPKeyEnvelopeRepository = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) LoadDirectPlatformSAMLSPKeyEnvelope(
	ctx context.Context,
	request federatedsaml.DirectPlatformSPKeyRequest,
) (platformsamladapter.DirectSAMLSPKeyEnvelopeSnapshot, error) {
	provider, err := platformSAMLProviderToWire(request.Provider)
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil || err != nil ||
		!validPlatformSAMLRevision(request.PlatformLoginRevision) || !validPlatformSAMLRevision(request.KeyRevision) {
		return platformsamladapter.DirectSAMLSPKeyEnvelopeSnapshot{}, errPlatformSAMLPersistence
	}
	wire := platformSAMLSPKeyLookupWire{
		Provider: provider, PlatformLoginRevision: request.PlatformLoginRevision, KeyRevision: request.KeyRevision,
	}
	query := loadPlatformSAMLSPKeyEnvelopeSQL
	if request.LogoutMaterialID != (identity.EntityID{}) {
		wire.MaterialID, err = requiredFederatedEntityIDWire(request.LogoutMaterialID)
		if err != nil {
			return platformsamladapter.DirectSAMLSPKeyEnvelopeSnapshot{}, errPlatformSAMLPersistence
		}
		query = loadPlatformSAMLLogoutSPKeyEnvelopeSQL
	}
	var response platformSAMLSPKeyProjectionWire
	defer clearPlatformSAMLSPKeyProjectionWire(&response)
	if err = repository.queryJSONWithResponseLimit(
		ctx, query, wire, &response, maximumPlatformSAMLSPKeyWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformsamladapter.DirectSAMLSPKeyEnvelopeSnapshot{}, errPlatformSAMLPersistence
	}
	projectedProvider, providerErr := platformSAMLProviderFromWire(response.Context.Provider)
	keyID, keyErr := parseEntityIDWire(response.Context.KeyID, false)
	if providerErr != nil || keyErr != nil || response.Request != wire || !response.Live ||
		response.PlatformLoginRevision != request.PlatformLoginRevision || projectedProvider != request.Provider ||
		response.Context.KeyRevision != request.KeyRevision || response.Envelope.KeyVersion < 1 ||
		len(response.Envelope.Nonce) != 12 || slices.Equal(response.Envelope.Nonce, make([]byte, 12)) ||
		len(response.Envelope.Ciphertext) < 17 || len(response.Envelope.Ciphertext) > 131072 ||
		len(response.CertificateDER) < 1 || len(response.CertificateDER) > 8 {
		return platformsamladapter.DirectSAMLSPKeyEnvelopeSnapshot{}, errPlatformSAMLPersistence
	}
	seenCertificates := make(map[[sha256.Size]byte]struct{}, len(response.CertificateDER))
	for _, certificate := range response.CertificateDER {
		if len(certificate) == 0 || len(certificate) > 256*1024 {
			return platformsamladapter.DirectSAMLSPKeyEnvelopeSnapshot{}, errPlatformSAMLPersistence
		}
		digest := sha256.Sum256(certificate)
		if _, duplicate := seenCertificates[digest]; duplicate {
			return platformsamladapter.DirectSAMLSPKeyEnvelopeSnapshot{}, errPlatformSAMLPersistence
		}
		seenCertificates[digest] = struct{}{}
	}
	var nonce [12]byte
	copy(nonce[:], response.Envelope.Nonce)
	return platformsamladapter.DirectSAMLSPKeyEnvelopeSnapshot{
		Request: request, PlatformLoginRevision: response.PlatformLoginRevision,
		Context: identity.DirectPlatformSAMLSPKeyContext{
			Provider: projectedProvider, KeyID: keyID, KeyRevision: response.Context.KeyRevision,
		},
		Envelope: identity.SAMLSPKeyEnvelope{
			KeyVersion: response.Envelope.KeyVersion, Nonce: nonce,
			Ciphertext: append([]byte(nil), response.Envelope.Ciphertext...),
		},
		CertificateDER: clonePlatformSAMLBytes2D(response.CertificateDER), Live: true,
	}, nil
}

func clonePlatformSAMLBytes2D(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = append([]byte(nil), values[index]...)
	}
	return result
}

func clearPlatformSAMLSPKeyProjectionWire(value *platformSAMLSPKeyProjectionWire) {
	if value == nil {
		return
	}
	clear(value.Envelope.Nonce)
	clear(value.Envelope.Ciphertext)
	for index := range value.CertificateDER {
		clear(value.CertificateDER[index])
	}
	*value = platformSAMLSPKeyProjectionWire{}
}
