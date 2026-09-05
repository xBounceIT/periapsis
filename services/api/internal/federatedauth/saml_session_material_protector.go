package federatedauth

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

const (
	samlSessionMaterialNonceBytes       = 12
	maximumSAMLSessionMaterialPlaintext = 16*1024 - samlSessionMaterialNonceBytes - 16
	maximumSAMLSessionMaterialEnvelope  = 16 * 1024
	maximumSAMLNameIDBytes              = 16 * 1024
	maximumSAMLSessionIndexBytes        = 2 * 1024
)

var samlSessionMaterialDocumentPrefix = [...]byte{'P', 'S', 'M', 1}

// IdentitySAMLSessionMaterialProtector is the only adapter between SAML
// logout provenance and the purpose-separated identity keyring. Its binary
// document has a fixed field order and exact lengths, so equivalent material
// has one representation and malformed or trailing data fails closed.
type IdentitySAMLSessionMaterialProtector struct {
	keyring identity.Keyring
}

func NewIdentitySAMLSessionMaterialProtector(
	keyring identity.Keyring,
) (*IdentitySAMLSessionMaterialProtector, error) {
	if keyring.ActiveVersion() < 1 {
		return nil, ErrInvalidOptions
	}
	return &IdentitySAMLSessionMaterialProtector{keyring: keyring}, nil
}

func (protector *IdentitySAMLSessionMaterialProtector) String() string {
	return fmt.Sprintf(
		"federatedauth.IdentitySAMLSessionMaterialProtector{configured:%t}",
		protector != nil && protector.keyring.ActiveVersion() > 0,
	)
}

func (protector *IdentitySAMLSessionMaterialProtector) GoString() string {
	return protector.String()
}

var _ SAMLSessionMaterialSealer = (*IdentitySAMLSessionMaterialProtector)(nil)
var _ federatedsaml.SessionMaterialProtector = (*IdentitySAMLSessionMaterialProtector)(nil)

func (protector *IdentitySAMLSessionMaterialProtector) SealSAMLSession(
	ctx context.Context,
	protection SAMLSessionMaterialSealContext,
	material federatedsaml.SessionMaterial,
) (federatedsaml.ProtectedSessionMaterial, error) {
	if protector == nil || ctx == nil || ctx.Err() != nil {
		return federatedsaml.ProtectedSessionMaterial{}, ErrAuthentication
	}
	plaintext, ok := encodeSAMLSessionMaterial(material)
	if !ok {
		return federatedsaml.ProtectedSessionMaterial{}, ErrAuthentication
	}
	defer clear(plaintext)
	envelope, err := protector.keyring.EncryptSAMLSessionMaterial(
		identitySAMLSessionMaterialContext(
			protection.Provider,
			protection.BindingID,
			protection.MaterialID,
		),
		plaintext,
	)
	if err != nil || ctx.Err() != nil {
		clear(envelope.Nonce[:])
		clear(envelope.Ciphertext)
		return federatedsaml.ProtectedSessionMaterial{}, ErrAuthentication
	}
	serialized := make([]byte, 0, len(envelope.Nonce)+len(envelope.Ciphertext))
	serialized = append(serialized, envelope.Nonce[:]...)
	serialized = append(serialized, envelope.Ciphertext...)
	version := envelope.KeyVersion
	clear(envelope.Nonce[:])
	clear(envelope.Ciphertext)
	if version < 1 || len(serialized) <= samlSessionMaterialNonceBytes ||
		len(serialized) > maximumSAMLSessionMaterialEnvelope {
		clear(serialized)
		return federatedsaml.ProtectedSessionMaterial{}, ErrAuthentication
	}
	return federatedsaml.ProtectedSessionMaterial{
		KeyVersion: uint32(version),
		Ciphertext: serialized,
	}, nil
}

func (protector *IdentitySAMLSessionMaterialProtector) OpenSAMLSession(
	ctx context.Context,
	protection federatedsaml.SessionMaterialContext,
	protected federatedsaml.ProtectedSessionMaterial,
) (federatedsaml.SessionMaterial, error) {
	if protector == nil || ctx == nil || ctx.Err() != nil || protected.KeyVersion == 0 ||
		protected.KeyVersion > math.MaxInt16 || len(protected.Ciphertext) <= samlSessionMaterialNonceBytes ||
		len(protected.Ciphertext) > maximumSAMLSessionMaterialEnvelope {
		return federatedsaml.SessionMaterial{}, federatedsaml.ErrLogoutArtifactRejected
	}
	var envelope identity.SAMLSessionMaterialEnvelope
	envelope.KeyVersion = int16(protected.KeyVersion)
	copy(envelope.Nonce[:], protected.Ciphertext[:samlSessionMaterialNonceBytes])
	envelope.Ciphertext = append([]byte(nil), protected.Ciphertext[samlSessionMaterialNonceBytes:]...)
	defer clear(envelope.Nonce[:])
	defer clear(envelope.Ciphertext)
	tenantContext, tenant := protection.TenantProtectionContext()
	directContext, direct := protection.DirectPlatformProtectionContext()
	if tenant == direct {
		return federatedsaml.SessionMaterial{}, federatedsaml.ErrLogoutArtifactRejected
	}
	var plaintext []byte
	var err error
	if tenant {
		plaintext, err = protector.keyring.DecryptSAMLSessionMaterial(tenantContext, envelope)
	} else {
		plaintext, err = protector.keyring.DecryptDirectPlatformSAMLSessionMaterial(directContext, envelope)
	}
	if err != nil || ctx.Err() != nil {
		clear(plaintext)
		return federatedsaml.SessionMaterial{}, federatedsaml.ErrLogoutArtifactRejected
	}
	defer clear(plaintext)
	material, ok := decodeSAMLSessionMaterial(plaintext)
	if !ok {
		return federatedsaml.SessionMaterial{}, federatedsaml.ErrLogoutArtifactRejected
	}
	return material, nil
}

func identitySAMLSessionMaterialContext(
	provider identity.ProviderContext,
	bindingID identity.EntityID,
	materialID identity.EntityID,
) identity.SAMLSessionMaterialContext {
	return identity.SAMLSessionMaterialContext{
		Provider: provider, BindingID: bindingID, MaterialID: materialID,
	}
}

func encodeSAMLSessionMaterial(material federatedsaml.SessionMaterial) ([]byte, bool) {
	if !validSAMLSessionMaterialDocument(material) {
		return nil, false
	}
	encodedLength := len(samlSessionMaterialDocumentPrefix) + 3*4 +
		len(material.NameID) + len(material.NameIDFormat) + len(material.SessionIndex)
	if encodedLength > maximumSAMLSessionMaterialPlaintext {
		return nil, false
	}
	document := make([]byte, 0, encodedLength)
	document = append(document, samlSessionMaterialDocumentPrefix[:]...)
	document = appendSAMLSessionMaterialField(document, material.NameID)
	document = appendSAMLSessionMaterialField(document, material.NameIDFormat)
	document = appendSAMLSessionMaterialField(document, material.SessionIndex)
	return document, true
}

func appendSAMLSessionMaterialField(destination []byte, value string) []byte {
	header := [4]byte{}
	binary.BigEndian.PutUint32(header[:], uint32(len(value)))
	destination = append(destination, header[:]...)
	return append(destination, value...)
}

func decodeSAMLSessionMaterial(document []byte) (federatedsaml.SessionMaterial, bool) {
	if len(document) < len(samlSessionMaterialDocumentPrefix)+3*4 ||
		len(document) > maximumSAMLSessionMaterialPlaintext ||
		!bytes.Equal(document[:len(samlSessionMaterialDocumentPrefix)], samlSessionMaterialDocumentPrefix[:]) {
		return federatedsaml.SessionMaterial{}, false
	}
	offset := len(samlSessionMaterialDocumentPrefix)
	fields := [3]string{}
	for index := range fields {
		if len(document)-offset < 4 {
			return federatedsaml.SessionMaterial{}, false
		}
		length := binary.BigEndian.Uint32(document[offset : offset+4])
		offset += 4
		if uint64(length) > uint64(len(document)-offset) {
			return federatedsaml.SessionMaterial{}, false
		}
		end := offset + int(length)
		fields[index] = string(document[offset:end])
		offset = end
	}
	if offset != len(document) {
		return federatedsaml.SessionMaterial{}, false
	}
	material := federatedsaml.SessionMaterial{
		NameID: fields[0], NameIDFormat: fields[1], SessionIndex: fields[2],
	}
	if !validSAMLSessionMaterialDocument(material) {
		return federatedsaml.SessionMaterial{}, false
	}
	return material, true
}

func validSAMLSessionMaterialDocument(material federatedsaml.SessionMaterial) bool {
	if material == (federatedsaml.SessionMaterial{}) ||
		(material.NameID == "") != (material.NameIDFormat == "") ||
		material.NameID != "" && (material.NameIDFormat != federatedsaml.PersistentNameIDFormat ||
			!validSensitiveText(material.NameID, maximumSAMLNameIDBytes)) ||
		material.SessionIndex != "" && !validSensitiveText(material.SessionIndex, maximumSAMLSessionIndexBytes) {
		return false
	}
	return true
}
