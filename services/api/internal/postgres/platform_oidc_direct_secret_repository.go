package postgres

import (
	"context"
	"crypto/sha256"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

const (
	loadPlatformOIDCDirectClientSecretSQL          = `select app.load_platform_oidc_client_secret_v1($1::jsonb)`
	maximumPlatformOIDCDirectSecretWireBytes       = 64 * 1024
	maximumPlatformOIDCDirectSecretCiphertextBytes = 8*1024 + 16
)

type platformOIDCDirectSecretLookupWire struct {
	Provider federatedProviderBindingWire `json:"provider"`
	Pins     platformOIDCDirectPinsWire   `json:"pins"`
}

type platformOIDCDirectSecretWire struct {
	Provider   federatedProviderBindingWire `json:"provider"`
	Pins       platformOIDCDirectPinsWire   `json:"pins"`
	SecretID   string                       `json:"secretId"`
	Revision   uint64                       `json:"revision"`
	KeyVersion int16                        `json:"keyVersion"`
	Nonce      []byte                       `json:"nonce"`
	Ciphertext []byte                       `json:"ciphertext"`
}

var _ platformoidcauth.DirectOIDCClientSecretEnvelopeSource = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) LoadDirectOIDCClientSecretEnvelope(
	ctx context.Context,
	lookup platformoidcauth.DirectOIDCClientSecretLookup,
) (platformoidcauth.DirectOIDCClientSecretSnapshot, error) {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil {
		return platformoidcauth.DirectOIDCClientSecretSnapshot{}, errFederatedAuthPersistence
	}
	wire, err := platformOIDCDirectSecretLookupToWire(lookup)
	if err != nil {
		return platformoidcauth.DirectOIDCClientSecretSnapshot{}, errFederatedAuthPersistence
	}
	defer clearPlatformOIDCDirectSecretLookupWire(&wire)
	var response platformOIDCDirectSecretWire
	defer clearPlatformOIDCDirectSecretWire(&response)
	if err = repository.queryJSONWithResponseLimit(
		ctx, loadPlatformOIDCDirectClientSecretSQL, wire, &response,
		maximumPlatformOIDCDirectSecretWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformoidcauth.DirectOIDCClientSecretSnapshot{}, errFederatedAuthPersistence
	}
	snapshot, err := platformOIDCDirectSecretFromWire(response, lookup)
	if err != nil {
		clear(snapshot.Envelope.Nonce[:])
		clear(snapshot.Envelope.Ciphertext)
		return platformoidcauth.DirectOIDCClientSecretSnapshot{}, errFederatedAuthPersistence
	}
	return snapshot, nil
}

func platformOIDCDirectSecretLookupToWire(
	lookup platformoidcauth.DirectOIDCClientSecretLookup,
) (platformOIDCDirectSecretLookupWire, error) {
	pins, err := platformOIDCDirectPinsToWire(lookup.Pins)
	if err != nil {
		return platformOIDCDirectSecretLookupWire{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectSecretLookupWire{Provider: pins.Provider, Pins: pins}, nil
}

func platformOIDCDirectSecretFromWire(
	wire platformOIDCDirectSecretWire,
	lookup platformoidcauth.DirectOIDCClientSecretLookup,
) (platformoidcauth.DirectOIDCClientSecretSnapshot, error) {
	provider, binding, providerErr := providerBindingFromWire(wire.Provider, true)
	pins, pinsErr := platformOIDCDirectPinsFromWire(wire.Pins)
	secretID, secretErr := parseFederatedEntityIDWire(wire.SecretID, false)
	if providerErr != nil || pinsErr != nil || secretErr != nil || binding != (identity.EntityID{}) ||
		provider != lookup.Pins.Provider || pins != lookup.Pins || wire.Revision != lookup.Pins.ClientSecretRevision ||
		!validFederatedRevision(wire.Revision) || wire.KeyVersion < 1 ||
		len(wire.Nonce) != 12 || allZeroFederatedBytes(wire.Nonce) ||
		len(wire.Ciphertext) <= sha256.Size/2 ||
		len(wire.Ciphertext) > maximumPlatformOIDCDirectSecretCiphertextBytes {
		return platformoidcauth.DirectOIDCClientSecretSnapshot{}, errFederatedAuthPersistence
	}
	var nonce [12]byte
	copy(nonce[:], wire.Nonce)
	return platformoidcauth.DirectOIDCClientSecretSnapshot{
		Lookup: lookup, Pins: pins, SecretID: secretID,
		Envelope: identity.OIDCClientSecretEnvelope{
			KeyVersion: wire.KeyVersion, Nonce: nonce,
			Ciphertext: append([]byte(nil), wire.Ciphertext...),
		},
	}, nil
}

func clearPlatformOIDCDirectSecretLookupWire(value *platformOIDCDirectSecretLookupWire) {
	if value == nil {
		return
	}
	clear(value.Pins.DiscoveryDigest)
	clear(value.Pins.JWKSDigest)
	*value = platformOIDCDirectSecretLookupWire{}
}

func clearPlatformOIDCDirectSecretWire(value *platformOIDCDirectSecretWire) {
	if value == nil {
		return
	}
	clear(value.Pins.DiscoveryDigest)
	clear(value.Pins.JWKSDigest)
	clear(value.Nonce)
	clear(value.Ciphertext)
	*value = platformOIDCDirectSecretWire{}
}
