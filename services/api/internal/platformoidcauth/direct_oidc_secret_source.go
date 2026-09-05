package platformoidcauth

import (
	"context"
	"fmt"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

// DirectOIDCClientSecretSnapshot is the exact encrypted secret revision
// selected by the direct post-claim persistence boundary. Lookup and Pins are
// deliberately echoed separately so an adapter cannot silently relabel a
// response to the caller's requested authority. Ownership of
// Envelope.Ciphertext transfers to the caller.
type DirectOIDCClientSecretSnapshot struct {
	Lookup   DirectOIDCClientSecretLookup
	Pins     DirectOIDCConfigurationPins
	SecretID identity.EntityID
	Envelope identity.OIDCClientSecretEnvelope
}

func (snapshot DirectOIDCClientSecretSnapshot) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCClientSecretSnapshot{lookup:%q,pins:%q,secret:%t,envelope:%q,material:[REDACTED]}",
		snapshot.Lookup.String(), snapshot.Pins.String(), validDirectEntityID(snapshot.SecretID),
		snapshot.Envelope.String(),
	)
}

func (snapshot DirectOIDCClientSecretSnapshot) GoString() string { return snapshot.String() }

// DirectOIDCClientSecretEnvelopeSource is implemented by the narrow direct
// platform-login persistence ABI. It returns only one exact encrypted secret
// snapshot and must not retain the transferred ciphertext slice.
type DirectOIDCClientSecretEnvelopeSource interface {
	LoadDirectOIDCClientSecretEnvelope(
		context.Context,
		DirectOIDCClientSecretLookup,
	) (DirectOIDCClientSecretSnapshot, error)
}

// KeyringDirectOIDCClientSecretSource adapts the encrypted direct persistence
// projection to DirectOIDCClientSecretSource. It exposes no general decryption
// operation and always uses the platform provider's zero BindingID AAD.
type KeyringDirectOIDCClientSecretSource struct {
	source  DirectOIDCClientSecretEnvelopeSource
	keyring identity.Keyring
}

func NewKeyringDirectOIDCClientSecretSource(
	source DirectOIDCClientSecretEnvelopeSource,
	keyring identity.Keyring,
) (*KeyringDirectOIDCClientSecretSource, error) {
	if source == nil || keyring.ActiveVersion() < 1 {
		return nil, ErrDirectAuthenticationDenied
	}
	return &KeyringDirectOIDCClientSecretSource{source: source, keyring: keyring}, nil
}

func (source *KeyringDirectOIDCClientSecretSource) String() string {
	return fmt.Sprintf(
		"platformoidcauth.KeyringDirectOIDCClientSecretSource{configured:%t}",
		source != nil && source.source != nil && source.keyring.ActiveVersion() > 0,
	)
}

func (source *KeyringDirectOIDCClientSecretSource) GoString() string { return source.String() }

func (source *KeyringDirectOIDCClientSecretSource) OpenDirectOIDCClientSecret(
	ctx context.Context,
	lookup DirectOIDCClientSecretLookup,
) ([]byte, error) {
	if source == nil || source.source == nil || ctx == nil || ctx.Err() != nil ||
		!validDirectOIDCClientSecretLookup(lookup) {
		return nil, ErrDirectAuthenticationDenied
	}
	snapshot, err := source.source.LoadDirectOIDCClientSecretEnvelope(ctx, lookup)
	defer clear(snapshot.Envelope.Nonce[:])
	defer clear(snapshot.Envelope.Ciphertext)
	if err != nil || ctx.Err() != nil || snapshot.Lookup != lookup || snapshot.Pins != lookup.Pins ||
		!validDirectEntityID(snapshot.SecretID) {
		return nil, ErrDirectAuthenticationDenied
	}
	plaintext, err := source.keyring.DecryptOIDCClientSecret(identity.OIDCClientSecretContext{
		Provider: lookup.Pins.Provider, BindingID: identity.EntityID{}, SecretID: snapshot.SecretID,
	}, snapshot.Envelope)
	if err != nil || ctx.Err() != nil || len(plaintext) == 0 {
		clear(plaintext)
		return nil, ErrDirectAuthenticationDenied
	}
	return plaintext, nil
}

func validDirectOIDCClientSecretLookup(lookup DirectOIDCClientSecretLookup) bool {
	return validDirectOIDCConfigurationPins(lookup.Pins)
}

var _ DirectOIDCClientSecretSource = (*KeyringDirectOIDCClientSecretSource)(nil)
