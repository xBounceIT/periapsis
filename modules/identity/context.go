package identity

import (
	"encoding/binary"
	"errors"
)

// EntityID is the binary representation of a non-nil UUID. Keeping IDs binary
// prevents textual UUID spellings from changing cryptographic contexts.
type EntityID [16]byte

// ProviderScope distinguishes tenant-owned and platform-owned provider rows.
type ProviderScope uint8

const (
	TenantProviderScope    ProviderScope = 1
	PlatformProviderScope  ProviderScope = 2
	maximumContextRevision               = uint64(9_007_199_254_740_991)
)

// ProviderContext uniquely qualifies cryptographic material to one provider.
// TenantID is mandatory for tenant providers and must be zero for platform
// providers.
type ProviderContext struct {
	Scope      ProviderScope
	TenantID   EntityID
	ProviderID EntityID
}

// TenantAdmissionContext identifies the tenant-local binding that admits an
// otherwise provider-qualified authentication. It is deliberately separate
// from provider cryptographic binding: platform provider secrets remain bound
// with a zero BindingID while every tenant admission has two non-zero IDs.
type TenantAdmissionContext struct {
	TenantID  EntityID
	BindingID EntityID
}

// BindSecretContext additionally binds ciphertext to the exact secret row, so
// swapping ciphertext between rows of one provider fails authentication.
type BindSecretContext struct {
	Provider ProviderContext
	SecretID EntityID
}

// OIDCClientSecretContext binds one versioned client secret to its provider,
// tenant binding, and immutable secret row.
type OIDCClientSecretContext struct {
	Provider  ProviderContext
	BindingID EntityID
	SecretID  EntityID
}

// OIDCSessionMaterialContext binds encrypted ID-token and refresh-token
// material to its immutable database row. Session, continuation, and session-
// family identifiers are mutable ownership references and therefore do not
// participate in the authenticated context.
type OIDCSessionMaterialContext struct {
	Provider   ProviderContext
	TenantID   EntityID
	BindingID  EntityID
	MaterialID EntityID
}

// OIDCTransactionID is the binary 256-bit identifier used as PKCE AAD. The
// protocol package converts its own opaque transaction ID at the adapter edge.
type OIDCTransactionID [32]byte

// OIDCPKCEVerifierContext binds a verifier to one transaction and exact
// provider/binding. It cannot be transplanted between browser ceremonies.
type OIDCPKCEVerifierContext struct {
	TransactionID OIDCTransactionID
	Provider      ProviderContext
	BindingID     EntityID
}

// PlatformOIDCPKCEVerifierContext binds a platform-provider verifier to the
// exact tenant admission selected before redirect. The provider context must
// remain platform-scoped; the tenant and binding exist only in Admission.
type PlatformOIDCPKCEVerifierContext struct {
	TransactionID OIDCTransactionID
	Provider      ProviderContext
	Admission     TenantAdmissionContext
}

// DirectPlatformOIDCPKCEVerifierContext binds a direct platform-login
// verifier to one platform provider, one browser transaction, and the exact
// platform-login policy revision. It deliberately has no tenant or binding
// field: direct platform authentication is a separate authority family.
type DirectPlatformOIDCPKCEVerifierContext struct {
	TransactionID         OIDCTransactionID
	Provider              ProviderContext
	PlatformLoginRevision uint64
}

// SAMLSPKeyContext binds one encrypted PKCS#8 service-provider private key to
// the exact tenant provider, binding, immutable key row, and key revision.
// The revision is part of the authenticated context so ciphertext cannot be
// replayed as a newer retained signing/decryption key.
type SAMLSPKeyContext struct {
	Provider    ProviderContext
	BindingID   EntityID
	KeyID       EntityID
	KeyRevision uint32
}

// DirectPlatformSAMLSPKeyContext binds one platform-owned PKCS#8 key to its
// immutable row and exact platform key revision. It deliberately has no
// tenant or binding field: direct platform authentication is a separate
// authority family.
type DirectPlatformSAMLSPKeyContext struct {
	Provider    ProviderContext
	KeyID       EntityID
	KeyRevision uint64
}

// SAMLSessionMaterialContext binds encrypted logout provenance to its
// immutable database row. Session and continuation identifiers are mutable
// ownership references and therefore deliberately do not participate in the
// authenticated context.
type SAMLSessionMaterialContext struct {
	Provider   ProviderContext
	BindingID  EntityID
	MaterialID EntityID
}

// DirectPlatformSAMLSessionMaterialContext binds platform-login logout
// provenance to its immutable row and the exact direct-login authority
// revision. It cannot be populated with a synthetic tenant or binding.
type DirectPlatformSAMLSessionMaterialContext struct {
	Provider              ProviderContext
	MaterialID            EntityID
	PlatformLoginRevision uint64
}

// ExternalSubjectContext binds encrypted immutable-subject bytes to their
// exact provider and external-identity row. Ciphertext cannot be moved between
// tenants, providers, or identity rows without authentication failure.
type ExternalSubjectContext struct {
	Provider           ProviderContext
	ExternalIdentityID EntityID
}

func validateProviderContext(context ProviderContext) error {
	if isZeroID(context.ProviderID) {
		return errors.New("provider ID is required")
	}
	switch context.Scope {
	case TenantProviderScope:
		if isZeroID(context.TenantID) {
			return errors.New("tenant ID is required")
		}
	case PlatformProviderScope:
		if !isZeroID(context.TenantID) {
			return errors.New("platform provider context cannot contain a tenant ID")
		}
	default:
		return errors.New("provider scope is invalid")
	}
	return nil
}

func validateBindSecretContext(context BindSecretContext) error {
	if err := validateProviderContext(context.Provider); err != nil {
		return err
	}
	if isZeroID(context.SecretID) {
		return errors.New("bind-secret row ID is required")
	}
	return nil
}

func validateOIDCProviderBinding(provider ProviderContext, bindingID EntityID) error {
	if err := validateProviderContext(provider); err != nil {
		return err
	}
	if provider.Scope == TenantProviderScope && isZeroID(bindingID) ||
		provider.Scope == PlatformProviderScope && !isZeroID(bindingID) {
		return errors.New("OIDC binding context is invalid")
	}
	return nil
}

func validateOIDCClientSecretContext(context OIDCClientSecretContext) error {
	if err := validateOIDCProviderBinding(context.Provider, context.BindingID); err != nil {
		return err
	}
	if isZeroID(context.SecretID) {
		return errors.New("OIDC client-secret row ID is required")
	}
	return nil
}

func validateOIDCSessionMaterialContext(context OIDCSessionMaterialContext) error {
	if err := validateProviderContext(context.Provider); err != nil {
		return err
	}
	if isZeroID(context.MaterialID) {
		return errors.New("OIDC session material context is invalid")
	}
	tenantAdmission := !isZeroID(context.TenantID) && !isZeroID(context.BindingID)
	directPlatform := isZeroID(context.TenantID) && isZeroID(context.BindingID)
	if context.Provider.Scope == TenantProviderScope &&
		(!tenantAdmission || context.Provider.TenantID != context.TenantID) ||
		context.Provider.Scope == PlatformProviderScope && !tenantAdmission && !directPlatform {
		return errors.New("OIDC session material context is invalid")
	}
	return nil
}

func validateOIDCPKCEVerifierContext(context OIDCPKCEVerifierContext) error {
	if err := validateOIDCProviderBinding(context.Provider, context.BindingID); err != nil {
		return err
	}
	return validateOIDCTransactionID(context.TransactionID)
}

func validatePlatformOIDCPKCEVerifierContext(context PlatformOIDCPKCEVerifierContext) error {
	if err := validateProviderContext(context.Provider); err != nil {
		return err
	}
	if context.Provider.Scope != PlatformProviderScope ||
		isZeroID(context.Admission.TenantID) || isZeroID(context.Admission.BindingID) {
		return errors.New("platform OIDC PKCE context is invalid")
	}
	return validateOIDCTransactionID(context.TransactionID)
}

func validateDirectPlatformOIDCPKCEVerifierContext(context DirectPlatformOIDCPKCEVerifierContext) error {
	if err := validateProviderContext(context.Provider); err != nil {
		return err
	}
	if context.Provider.Scope != PlatformProviderScope || context.PlatformLoginRevision == 0 ||
		context.PlatformLoginRevision > maximumContextRevision {
		return errors.New("direct platform OIDC PKCE context is invalid")
	}
	return validateOIDCTransactionID(context.TransactionID)
}

func validateOIDCTransactionID(id OIDCTransactionID) error {
	var combined byte
	for _, value := range id {
		combined |= value
	}
	if combined == 0 {
		return errors.New("OIDC transaction ID is required")
	}
	return nil
}

func validateSAMLSPKeyContext(context SAMLSPKeyContext) error {
	if err := validateProviderContext(context.Provider); err != nil {
		return err
	}
	if context.Provider.Scope != TenantProviderScope || isZeroID(context.BindingID) ||
		isZeroID(context.KeyID) || context.KeyRevision == 0 {
		return errors.New("SAML SP key context is invalid")
	}
	return nil
}

func validateDirectPlatformSAMLSPKeyContext(context DirectPlatformSAMLSPKeyContext) error {
	if err := validateProviderContext(context.Provider); err != nil {
		return err
	}
	if context.Provider.Scope != PlatformProviderScope || isZeroID(context.KeyID) ||
		context.KeyRevision == 0 || context.KeyRevision > maximumContextRevision {
		return errors.New("direct platform SAML SP key context is invalid")
	}
	return nil
}

func validateSAMLSessionMaterialContext(context SAMLSessionMaterialContext) error {
	if err := validateProviderContext(context.Provider); err != nil {
		return err
	}
	if context.Provider.Scope != TenantProviderScope || isZeroID(context.BindingID) ||
		isZeroID(context.MaterialID) {
		return errors.New("SAML session material context is invalid")
	}
	return nil
}

func validateDirectPlatformSAMLSessionMaterialContext(context DirectPlatformSAMLSessionMaterialContext) error {
	if err := validateProviderContext(context.Provider); err != nil {
		return err
	}
	if context.Provider.Scope != PlatformProviderScope || isZeroID(context.MaterialID) ||
		context.PlatformLoginRevision == 0 || context.PlatformLoginRevision > maximumContextRevision {
		return errors.New("direct platform SAML session material context is invalid")
	}
	return nil
}

func validateExternalSubjectContext(context ExternalSubjectContext) error {
	if err := validateProviderContext(context.Provider); err != nil {
		return err
	}
	if isZeroID(context.ExternalIdentityID) {
		return errors.New("external-identity row ID is required")
	}
	return nil
}

func isZeroID(id EntityID) bool {
	return id == EntityID{}
}

type aadFieldType uint16

const (
	fieldSchema aadFieldType = iota + 1
	fieldPurpose
	fieldScope
	fieldTenantID
	fieldProviderID
	fieldRowID
	fieldFormat
	fieldKeyVersion
	fieldSubjectFormat
	fieldSubjectValue
	fieldKeyCount
	fieldVerifier
	fieldBindingID
	fieldTransactionID
	fieldUserID
	fieldFactorID
	fieldSetID
	fieldRevision
)

// appendTypedField encodes a field as a two-byte type, a four-byte length, and
// its bytes. Callers use fixed field order in addition to explicit types.
func appendTypedField(destination []byte, fieldType aadFieldType, value []byte) []byte {
	header := [6]byte{}
	binary.BigEndian.PutUint16(header[0:2], uint16(fieldType))
	binary.BigEndian.PutUint32(header[2:6], uint32(len(value)))
	destination = append(destination, header[:]...)
	destination = append(destination, value...)
	return destination
}

func appendProviderContext(destination []byte, context ProviderContext) []byte {
	destination = appendTypedField(destination, fieldScope, []byte{byte(context.Scope)})
	if context.Scope == TenantProviderScope {
		destination = appendTypedField(destination, fieldTenantID, context.TenantID[:])
	} else {
		destination = appendTypedField(destination, fieldTenantID, nil)
	}
	return appendTypedField(destination, fieldProviderID, context.ProviderID[:])
}
