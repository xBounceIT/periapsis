package federatedauth

import (
	"context"
	"fmt"
	"math"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const samlSPKeyNonceBytes = 12

// IdentitySAMLSPKeyEnvelopeOpener adapts the deployment identity keyring to
// the SAML private-key source without exposing a generic decryption primitive.
type IdentitySAMLSPKeyEnvelopeOpener struct {
	keyring identity.Keyring
}

func NewIdentitySAMLSPKeyEnvelopeOpener(
	keyring identity.Keyring,
) (*IdentitySAMLSPKeyEnvelopeOpener, error) {
	if keyring.ActiveVersion() < 1 {
		return nil, ErrInvalidOptions
	}
	return &IdentitySAMLSPKeyEnvelopeOpener{keyring: keyring}, nil
}

func (opener *IdentitySAMLSPKeyEnvelopeOpener) String() string {
	return fmt.Sprintf(
		"federatedauth.IdentitySAMLSPKeyEnvelopeOpener{configured:%t}",
		opener != nil && opener.keyring.ActiveVersion() > 0,
	)
}
func (opener *IdentitySAMLSPKeyEnvelopeOpener) GoString() string { return opener.String() }

var _ SAMLSPKeyEnvelopeOpener = (*IdentitySAMLSPKeyEnvelopeOpener)(nil)

func (opener *IdentitySAMLSPKeyEnvelopeOpener) OpenSAMLSPKeyEnvelope(
	ctx context.Context,
	protection SAMLSPKeyProtectionContext,
	protected ProtectedSAMLSPKey,
) ([]byte, error) {
	if opener == nil || ctx == nil || ctx.Err() != nil || protected.KeyVersion == 0 ||
		protected.KeyVersion > math.MaxInt16 || len(protected.Ciphertext) <= samlSPKeyNonceBytes {
		return nil, ErrAuthentication
	}
	var envelope identity.SAMLSPKeyEnvelope
	envelope.KeyVersion = int16(protected.KeyVersion)
	copy(envelope.Nonce[:], protected.Ciphertext[:samlSPKeyNonceBytes])
	envelope.Ciphertext = append([]byte(nil), protected.Ciphertext[samlSPKeyNonceBytes:]...)
	defer clear(envelope.Nonce[:])
	defer clear(envelope.Ciphertext)
	plaintext, err := opener.keyring.DecryptSAMLSPKey(identity.SAMLSPKeyContext{
		Provider: protection.Provider, BindingID: protection.BindingID,
		KeyID: protection.KeyID, KeyRevision: protection.KeyRevision,
	}, envelope)
	if err != nil || ctx.Err() != nil {
		clear(plaintext)
		return nil, ErrAuthentication
	}
	return plaintext, nil
}
