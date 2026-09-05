package federatedauth

import (
	"bytes"
	"context"
	"errors"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestIdentitySAMLSPKeyEnvelopeOpenerAuthenticatesPersistenceContext(t *testing.T) {
	t.Parallel()
	keyring, err := identity.NewKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{0x51}, 32)})
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	protection := SAMLSPKeyProtectionContext{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: identity.EntityID{1}, ProviderID: identity.EntityID{2},
		},
		BindingID: identity.EntityID{3}, KeyID: identity.EntityID{4}, KeyRevision: 5,
	}
	plaintext := []byte("pkcs8-private-key")
	envelope, err := keyring.EncryptSAMLSPKey(identity.SAMLSPKeyContext{
		Provider: protection.Provider, BindingID: protection.BindingID,
		KeyID: protection.KeyID, KeyRevision: protection.KeyRevision,
	}, plaintext)
	if err != nil {
		t.Fatalf("EncryptSAMLSPKey() error = %v", err)
	}
	serialized := append(append([]byte(nil), envelope.Nonce[:]...), envelope.Ciphertext...)
	clear(envelope.Nonce[:])
	clear(envelope.Ciphertext)
	opener, err := NewIdentitySAMLSPKeyEnvelopeOpener(keyring)
	if err != nil {
		t.Fatalf("NewIdentitySAMLSPKeyEnvelopeOpener() error = %v", err)
	}
	opened, err := opener.OpenSAMLSPKeyEnvelope(context.Background(), protection, ProtectedSAMLSPKey{
		KeyVersion: 1, Ciphertext: serialized,
	})
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("OpenSAMLSPKeyEnvelope() = %q, %v", opened, err)
	}
	clear(opened)

	protection.KeyRevision++
	if opened, err = opener.OpenSAMLSPKeyEnvelope(context.Background(), protection, ProtectedSAMLSPKey{
		KeyVersion: 1, Ciphertext: serialized,
	}); !errors.Is(err, ErrAuthentication) {
		clear(opened)
		t.Fatalf("mutated persistence context accepted: %v", err)
	}
}

func TestIdentitySAMLSPKeyEnvelopeOpenerRejectsInvalidConstructionAndEnvelope(t *testing.T) {
	t.Parallel()
	if _, err := NewIdentitySAMLSPKeyEnvelopeOpener(identity.Keyring{}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("empty keyring error = %v", err)
	}
	keyring, err := identity.NewKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{0x52}, 32)})
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	opener, _ := NewIdentitySAMLSPKeyEnvelopeOpener(keyring)
	if _, err := opener.OpenSAMLSPKeyEnvelope(context.Background(), SAMLSPKeyProtectionContext{}, ProtectedSAMLSPKey{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("empty envelope error = %v", err)
	}
}
