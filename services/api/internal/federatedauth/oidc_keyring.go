package federatedauth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const oidcSessionTokenNonceBytes = 12

// OIDCSessionTokenOpener is the narrow logout boundary for encrypted ID-token
// hints. It deliberately does not expose a generic keyring decrypt operation.
type OIDCSessionTokenOpener interface {
	OpenOIDCIDToken(context.Context, OIDCSessionMaterialSealContext, ProtectedToken) ([]byte, error)
}

// IdentityOIDCSessionTokenProtector is shared by initial material sealing,
// refresh rotation, and local-first logout. Each token kind uses its own
// purpose-separated identity-keyring derivative.
type IdentityOIDCSessionTokenProtector struct {
	keyring identity.Keyring
}

func NewIdentityOIDCSessionTokenProtector(
	keyring identity.Keyring,
) (*IdentityOIDCSessionTokenProtector, error) {
	if keyring.ActiveVersion() < 1 {
		return nil, ErrInvalidOptions
	}
	return &IdentityOIDCSessionTokenProtector{keyring: keyring}, nil
}

func (protector *IdentityOIDCSessionTokenProtector) String() string {
	return fmt.Sprintf(
		"federatedauth.IdentityOIDCSessionTokenProtector{configured:%t}",
		protector != nil && protector.keyring.ActiveVersion() > 0,
	)
}

func (protector *IdentityOIDCSessionTokenProtector) GoString() string { return protector.String() }

var _ OIDCSessionMaterialSealer = (*IdentityOIDCSessionTokenProtector)(nil)
var _ TokenProtector = (*IdentityOIDCSessionTokenProtector)(nil)
var _ OIDCSessionTokenOpener = (*IdentityOIDCSessionTokenProtector)(nil)

func (protector *IdentityOIDCSessionTokenProtector) SealOIDCSessionMaterial(
	ctx context.Context,
	protection OIDCSessionMaterialSealContext,
	material OIDCSessionMaterial,
) (ProtectedOIDCSessionMaterial, error) {
	if protector == nil || ctx == nil || ctx.Err() != nil || material == nil ||
		!validOIDCSessionMaterialSealContext(protection) || material.MaterialID() != protection.MaterialID {
		return ProtectedOIDCSessionMaterial{}, ErrAuthentication
	}
	tokens, ok := material.TakeTokens()
	if !ok || tokens == nil {
		return ProtectedOIDCSessionMaterial{}, ErrAuthentication
	}
	defer tokens.Destroy()
	if (len(tokens.IDToken) != 0) != protection.KeepIDToken ||
		(len(tokens.RefreshToken) != 0) != protection.KeepRefreshToken ||
		len(tokens.IDToken) != 0 && !validOIDCSessionToken(tokens.IDToken) ||
		len(tokens.RefreshToken) != 0 && (!validRefreshToken(tokens.RefreshToken) ||
			!validInstant(tokens.AccessExpiresAt)) ||
		len(tokens.RefreshToken) == 0 && !tokens.AccessExpiresAt.IsZero() {
		return ProtectedOIDCSessionMaterial{}, ErrAuthentication
	}
	keyContext := oidcIdentitySessionMaterialContext(protection)
	result := ProtectedOIDCSessionMaterial{MaterialID: protection.MaterialID}
	if len(tokens.IDToken) != 0 {
		envelope, err := protector.keyring.EncryptOIDCIDToken(keyContext, tokens.IDToken)
		if err != nil || ctx.Err() != nil {
			clear(envelope.Nonce[:])
			clear(envelope.Ciphertext)
			return ProtectedOIDCSessionMaterial{}, ErrAuthentication
		}
		protected, valid := oidcEnvelopeToProtected(envelope)
		clear(envelope.Nonce[:])
		clear(envelope.Ciphertext)
		if !valid {
			clear(protected.Ciphertext)
			return ProtectedOIDCSessionMaterial{}, ErrAuthentication
		}
		result.IDToken = &protected
		result.IDTokenDigest = sha256.Sum256(tokens.IDToken)
	}
	if len(tokens.RefreshToken) != 0 {
		envelope, err := protector.keyring.EncryptOIDCRefreshToken(keyContext, tokens.RefreshToken)
		if err != nil || ctx.Err() != nil {
			clear(envelope.Nonce[:])
			clear(envelope.Ciphertext)
			clearProtectedOIDCSessionMaterial(&result)
			return ProtectedOIDCSessionMaterial{}, ErrAuthentication
		}
		protected, valid := oidcEnvelopeToProtected(envelope)
		clear(envelope.Nonce[:])
		clear(envelope.Ciphertext)
		if !valid {
			clear(protected.Ciphertext)
			clearProtectedOIDCSessionMaterial(&result)
			return ProtectedOIDCSessionMaterial{}, ErrAuthentication
		}
		result.RefreshToken = &protected
		result.RefreshTokenDigest = sha256.Sum256(tokens.RefreshToken)
		result.RefreshGeneration = 1
		result.AccessExpiresAt = tokens.AccessExpiresAt
	}
	return result, nil
}

func (protector *IdentityOIDCSessionTokenProtector) OpenOIDCIDToken(
	ctx context.Context,
	protection OIDCSessionMaterialSealContext,
	protected ProtectedToken,
) ([]byte, error) {
	if protector == nil || ctx == nil || ctx.Err() != nil ||
		!validOIDCSessionMaterialSealContext(protection) || !protection.KeepIDToken {
		return nil, ErrAuthentication
	}
	envelope, ok := oidcProtectedToEnvelope(protected)
	if !ok {
		return nil, ErrAuthentication
	}
	defer clear(envelope.Nonce[:])
	defer clear(envelope.Ciphertext)
	plaintext, err := protector.keyring.DecryptOIDCIDToken(
		oidcIdentitySessionMaterialContext(protection), envelope,
	)
	if err != nil || ctx.Err() != nil || !validOIDCSessionToken(plaintext) {
		clear(plaintext)
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

func (protector *IdentityOIDCSessionTokenProtector) OpenRefreshToken(
	ctx context.Context,
	protection RefreshTokenContext,
	protected ProtectedToken,
) ([]byte, error) {
	if protector == nil || ctx == nil || ctx.Err() != nil || !validRefreshTokenContext(protection) {
		return nil, ErrRefreshRejected
	}
	envelope, ok := oidcProtectedToEnvelope(protected)
	if !ok {
		return nil, ErrRefreshRejected
	}
	defer clear(envelope.Nonce[:])
	defer clear(envelope.Ciphertext)
	plaintext, err := protector.keyring.DecryptOIDCRefreshToken(
		identity.OIDCSessionMaterialContext{
			Provider: protection.Provider, TenantID: protection.TenantID,
			BindingID: protection.BindingID, MaterialID: protection.MaterialID,
		},
		envelope,
	)
	if err != nil || ctx.Err() != nil || !validRefreshToken(plaintext) {
		clear(plaintext)
		return nil, ErrRefreshRejected
	}
	return plaintext, nil
}

func (protector *IdentityOIDCSessionTokenProtector) SealRefreshToken(
	ctx context.Context,
	protection RefreshTokenContext,
	plaintext []byte,
) (ProtectedToken, error) {
	if protector == nil || ctx == nil || ctx.Err() != nil || !validRefreshTokenContext(protection) ||
		!validRefreshToken(plaintext) {
		return ProtectedToken{}, ErrRefreshRejected
	}
	envelope, err := protector.keyring.EncryptOIDCRefreshToken(
		identity.OIDCSessionMaterialContext{
			Provider: protection.Provider, TenantID: protection.TenantID,
			BindingID: protection.BindingID, MaterialID: protection.MaterialID,
		},
		plaintext,
	)
	if err != nil || ctx.Err() != nil {
		clear(envelope.Nonce[:])
		clear(envelope.Ciphertext)
		return ProtectedToken{}, ErrRefreshRejected
	}
	protected, ok := oidcEnvelopeToProtected(envelope)
	clear(envelope.Nonce[:])
	clear(envelope.Ciphertext)
	if !ok {
		clear(protected.Ciphertext)
		return ProtectedToken{}, ErrRefreshRejected
	}
	return protected, nil
}

func validOIDCSessionMaterialSealContext(value OIDCSessionMaterialSealContext) bool {
	if !validApplyUUIDv7(value.MaterialID) || value.Provider.ProviderID == (identity.EntityID{}) ||
		value.Provider.TenantID != (identity.EntityID{}) && value.Provider.Scope == identity.PlatformProviderScope ||
		(!value.KeepIDToken && !value.KeepRefreshToken) {
		return false
	}
	tenantAdmission := value.Admission.TenantID != (identity.EntityID{}) &&
		value.Admission.BindingID != (identity.EntityID{})
	directPlatform := value.Admission == (identity.TenantAdmissionContext{})
	return value.Provider.Scope == identity.TenantProviderScope && tenantAdmission &&
		value.Provider.TenantID == value.Admission.TenantID ||
		value.Provider.Scope == identity.PlatformProviderScope && (tenantAdmission || directPlatform)
}

func validRefreshTokenContext(value RefreshTokenContext) bool {
	tenantAdmission := value.TenantID != (identity.EntityID{}) && value.BindingID != (identity.EntityID{})
	directPlatform := value.TenantID == (identity.EntityID{}) && value.BindingID == (identity.EntityID{})
	return validApplyUUIDv7(value.MaterialID) &&
		validApplyUUIDv7(value.SessionFamilyID) && value.Generation > 0 &&
		value.Generation <= maximumPersistentOIDCCounter &&
		value.Provider.ProviderID != (identity.EntityID{}) &&
		(value.Provider.Scope == identity.TenantProviderScope && tenantAdmission && value.Provider.TenantID == value.TenantID ||
			value.Provider.Scope == identity.PlatformProviderScope && value.Provider.TenantID == (identity.EntityID{}) &&
				(tenantAdmission || directPlatform))
}

func oidcIdentitySessionMaterialContext(
	value OIDCSessionMaterialSealContext,
) identity.OIDCSessionMaterialContext {
	return identity.OIDCSessionMaterialContext{
		Provider: value.Provider, TenantID: value.Admission.TenantID,
		BindingID: value.Admission.BindingID, MaterialID: value.MaterialID,
	}
}

func oidcEnvelopeToProtected(envelope identity.OIDCSessionTokenEnvelope) (ProtectedToken, bool) {
	if envelope.KeyVersion < 1 || len(envelope.Ciphertext) < 17 ||
		len(envelope.Ciphertext) > maximumProtectedTokenBytes-oidcSessionTokenNonceBytes {
		return ProtectedToken{}, false
	}
	ciphertext := make([]byte, 0, oidcSessionTokenNonceBytes+len(envelope.Ciphertext))
	ciphertext = append(ciphertext, envelope.Nonce[:]...)
	ciphertext = append(ciphertext, envelope.Ciphertext...)
	return ProtectedToken{KeyVersion: uint32(envelope.KeyVersion), Ciphertext: ciphertext}, true
}

func oidcProtectedToEnvelope(protected ProtectedToken) (identity.OIDCSessionTokenEnvelope, bool) {
	if protected.KeyVersion < 1 || protected.KeyVersion > math.MaxInt16 ||
		len(protected.Ciphertext) < minimumProtectedTokenBytes ||
		len(protected.Ciphertext) > maximumProtectedTokenBytes {
		return identity.OIDCSessionTokenEnvelope{}, false
	}
	envelope := identity.OIDCSessionTokenEnvelope{KeyVersion: int16(protected.KeyVersion)}
	copy(envelope.Nonce[:], protected.Ciphertext[:oidcSessionTokenNonceBytes])
	envelope.Ciphertext = append([]byte(nil), protected.Ciphertext[oidcSessionTokenNonceBytes:]...)
	return envelope, true
}

func validOIDCSessionToken(value []byte) bool {
	if len(value) == 0 || len(value) > maximumRefreshTokenBytes {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}
