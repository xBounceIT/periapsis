package federatedauth

import (
	"context"
	"fmt"
	"math"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

const oidcPKCENonceBytes = 12

// IdentityPKCEVerifierProtector adapts the deployment identity keyring to the
// OIDC flow without exposing a generic encryption primitive.
type IdentityPKCEVerifierProtector struct {
	keyring identity.Keyring
}

func NewIdentityPKCEVerifierProtector(keyring identity.Keyring) (*IdentityPKCEVerifierProtector, error) {
	if keyring.ActiveVersion() < 1 {
		return nil, ErrInvalidOptions
	}
	return &IdentityPKCEVerifierProtector{keyring: keyring}, nil
}

func (protector *IdentityPKCEVerifierProtector) String() string {
	return fmt.Sprintf(
		"federatedauth.IdentityPKCEVerifierProtector{configured:%t}",
		protector != nil && protector.keyring.ActiveVersion() > 0,
	)
}
func (protector *IdentityPKCEVerifierProtector) GoString() string { return protector.String() }

var _ federatedoidc.PKCEVerifierProtector = (*IdentityPKCEVerifierProtector)(nil)

func (protector *IdentityPKCEVerifierProtector) SealPKCE(
	ctx context.Context,
	protection federatedoidc.TransactionProtectionContext,
	verifier []byte,
) (federatedoidc.ProtectedVerifier, error) {
	if protector == nil || ctx == nil || ctx.Err() != nil {
		return federatedoidc.ProtectedVerifier{}, federatedoidc.ErrAuthorizationRejected
	}
	var envelope identity.OIDCPKCEVerifierEnvelope
	var err error
	switch protection.Authority {
	case federatedoidc.TenantCeremonyAuthority:
		if _, valid := protection.TenantAdmission(); !valid {
			err = identity.ErrInvalidEncryptedOIDCPKCEVerifier
			break
		}
		switch protection.Provider.Scope {
		case identity.TenantProviderScope:
			envelope, err = protector.keyring.EncryptOIDCPKCEVerifier(identityPKCEContext(protection), verifier)
		case identity.PlatformProviderScope:
			envelope, err = protector.keyring.EncryptPlatformOIDCPKCEVerifier(
				identityPlatformPKCEContext(protection), verifier,
			)
		default:
			err = identity.ErrInvalidEncryptedOIDCPKCEVerifier
		}
	case federatedoidc.DirectPlatformCeremonyAuthority:
		if _, valid := protection.DirectPlatformLogin(); !valid {
			err = identity.ErrInvalidEncryptedOIDCPKCEVerifier
			break
		}
		envelope, err = protector.keyring.EncryptDirectPlatformOIDCPKCEVerifier(
			identityDirectPlatformPKCEContext(protection), verifier,
		)
	default:
		err = identity.ErrInvalidEncryptedOIDCPKCEVerifier
	}
	if err != nil {
		return federatedoidc.ProtectedVerifier{}, federatedoidc.ErrAuthorizationRejected
	}
	serialized := make([]byte, 0, len(envelope.Nonce)+len(envelope.Ciphertext))
	serialized = append(serialized, envelope.Nonce[:]...)
	serialized = append(serialized, envelope.Ciphertext...)
	clear(envelope.Nonce[:])
	clear(envelope.Ciphertext)
	return federatedoidc.ProtectedVerifier{KeyVersion: uint32(envelope.KeyVersion), Ciphertext: serialized}, nil
}

func (protector *IdentityPKCEVerifierProtector) OpenPKCE(
	ctx context.Context,
	protection federatedoidc.TransactionProtectionContext,
	protected federatedoidc.ProtectedVerifier,
) ([]byte, error) {
	if protector == nil || ctx == nil || ctx.Err() != nil || protected.KeyVersion == 0 ||
		protected.KeyVersion > math.MaxInt16 || len(protected.Ciphertext) <= oidcPKCENonceBytes {
		return nil, federatedoidc.ErrCallbackRejected
	}
	var envelope identity.OIDCPKCEVerifierEnvelope
	envelope.KeyVersion = int16(protected.KeyVersion)
	copy(envelope.Nonce[:], protected.Ciphertext[:oidcPKCENonceBytes])
	envelope.Ciphertext = append([]byte(nil), protected.Ciphertext[oidcPKCENonceBytes:]...)
	defer clear(envelope.Nonce[:])
	defer clear(envelope.Ciphertext)
	var plaintext []byte
	var err error
	switch protection.Authority {
	case federatedoidc.TenantCeremonyAuthority:
		if _, valid := protection.TenantAdmission(); !valid {
			err = identity.ErrInvalidEncryptedOIDCPKCEVerifier
			break
		}
		switch protection.Provider.Scope {
		case identity.TenantProviderScope:
			plaintext, err = protector.keyring.DecryptOIDCPKCEVerifier(identityPKCEContext(protection), envelope)
		case identity.PlatformProviderScope:
			plaintext, err = protector.keyring.DecryptPlatformOIDCPKCEVerifier(
				identityPlatformPKCEContext(protection), envelope,
			)
		default:
			err = identity.ErrInvalidEncryptedOIDCPKCEVerifier
		}
	case federatedoidc.DirectPlatformCeremonyAuthority:
		if _, valid := protection.DirectPlatformLogin(); !valid {
			err = identity.ErrInvalidEncryptedOIDCPKCEVerifier
			break
		}
		plaintext, err = protector.keyring.DecryptDirectPlatformOIDCPKCEVerifier(
			identityDirectPlatformPKCEContext(protection), envelope,
		)
	default:
		err = identity.ErrInvalidEncryptedOIDCPKCEVerifier
	}
	if err != nil {
		clear(plaintext)
		return nil, federatedoidc.ErrCallbackRejected
	}
	return plaintext, nil
}

func identityPlatformPKCEContext(
	protection federatedoidc.TransactionProtectionContext,
) identity.PlatformOIDCPKCEVerifierContext {
	return identity.PlatformOIDCPKCEVerifierContext{
		TransactionID: identity.OIDCTransactionID(protection.TransactionID),
		Provider:      protection.Provider,
		Admission:     protection.Admission,
	}
}

func identityDirectPlatformPKCEContext(
	protection federatedoidc.TransactionProtectionContext,
) identity.DirectPlatformOIDCPKCEVerifierContext {
	return identity.DirectPlatformOIDCPKCEVerifierContext{
		TransactionID:         identity.OIDCTransactionID(protection.TransactionID),
		Provider:              protection.Provider,
		PlatformLoginRevision: protection.PlatformLoginRevision,
	}
}

func identityPKCEContext(
	protection federatedoidc.TransactionProtectionContext,
) identity.OIDCPKCEVerifierContext {
	return identity.OIDCPKCEVerifierContext{
		TransactionID: identity.OIDCTransactionID(protection.TransactionID),
		Provider:      protection.Provider,
		BindingID:     protection.BindingID,
	}
}
