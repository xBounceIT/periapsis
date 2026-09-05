package platformsamladapter

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

const (
	TenantSAMLMetadataPathPrefix = "/api/v1/auth/federated/saml/"
	tenantSAMLACSPath            = "/api/v1/auth/federated/saml/acs"
)

var (
	tenantSAMLSlugPattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	tenantSAMLLoginKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)
)

// TenantSAMLPublicCertificate is one public certificate from the exact
// current tenant/provider/binding key revision. It contains no envelope or
// private-key material.
type TenantSAMLPublicCertificate struct {
	Context             identity.SAMLSPKeyContext
	CertificateSequence uint8
	CertificateDER      []byte
}

func (certificate TenantSAMLPublicCertificate) String() string {
	return fmt.Sprintf(
		"platformsamladapter.TenantSAMLPublicCertificate{revision:%t,sequence:%d,bytes:%d,publicOnly:true}",
		certificate.Context.KeyRevision != 0, certificate.CertificateSequence, len(certificate.CertificateDER),
	)
}

func (certificate TenantSAMLPublicCertificate) GoString() string { return certificate.String() }

// TenantSAMLMetadataProjection is the public-only, provider-qualified
// projection returned by the anonymous SECURITY DEFINER lookup. Live flags
// are explicit so an adapter regression cannot publish a disabled or archived
// boundary merely because its locator happened to resolve.
type TenantSAMLMetadataProjection struct {
	TenantSlug                 string
	LoginKey                   string
	PublicOrigin               string
	TenantID                   identity.EntityID
	ProviderID                 identity.EntityID
	BindingID                  identity.EntityID
	ProviderVersion            uint64
	BindingVersion             uint64
	ConfigurationRevision      uint64
	SecurityRevision           uint64
	PlanRevision               uint64
	AuthorizationRevision      uint64
	SPEntityID                 string
	ACSURL                     string
	SPKeyRevision              uint64
	RedirectSignatureAlgorithm federatedsaml.RedirectSignatureAlgorithm
	SignaturePolicy            federatedsaml.SignaturePolicy
	EncryptionPolicy           federatedsaml.EncryptionPolicy
	SubjectSource              federatedsaml.SubjectSource
	TenantActive               bool
	ProviderEnabled            bool
	BindingEnabled             bool
	PolicyEnabled              bool
	ProviderArchived           bool
	BindingArchived            bool
	AccessEpochLive            bool
	Certificates               []TenantSAMLPublicCertificate
	ObservedAt                 time.Time
}

func (projection TenantSAMLMetadataProjection) String() string {
	return fmt.Sprintf(
		"platformsamladapter.TenantSAMLMetadataProjection{tenant:%t,login:%t,providerRevision:%t,bindingRevision:%t,certificates:%d,publicOnly:true}",
		projection.TenantSlug != "", projection.LoginKey != "", projection.ProviderVersion != 0,
		projection.BindingVersion != 0, len(projection.Certificates),
	)
}

func (projection TenantSAMLMetadataProjection) GoString() string { return projection.String() }

type TenantSAMLMetadataDocument = DirectSAMLMetadataDocument

type TenantSAMLMetadataSource interface {
	LoadTenantSAMLMetadata(context.Context, string, string) (TenantSAMLMetadataProjection, bool, error)
}

// BuildTenantSAMLMetadata emits deterministic unsigned SP metadata from an
// exact live provider projection. Only public certificates are accepted; the
// builder has no private-envelope dependency.
func BuildTenantSAMLMetadata(projection TenantSAMLMetadataProjection) (TenantSAMLMetadataDocument, error) {
	certificates, signing, encryption, ok := validatedTenantMetadataCertificates(projection)
	if !ok {
		return TenantSAMLMetadataDocument{}, ErrProtocolRejected
	}
	var document bytes.Buffer
	document.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	document.WriteString(`<md:EntityDescriptor xmlns:md="` + samlMetadataNamespace + `" xmlns:ds="` + xmlSignatureNamespace + `" entityID="`)
	writeXMLEscaped(&document, projection.SPEntityID)
	document.WriteString(`"><md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="`)
	document.WriteString(strconv.FormatBool(projection.SignaturePolicy != federatedsaml.SignedResponse))
	document.WriteString(`" protocolSupportEnumeration="` + samlProtocolNamespace + `">`)
	encoded := make([]string, len(certificates))
	for index := range certificates {
		encoded[index] = base64.StdEncoding.EncodeToString(certificates[index])
	}
	if signing {
		writeMetadataKeyDescriptor(&document, "signing", encoded)
	}
	if encryption {
		writeMetadataKeyDescriptor(&document, "encryption", encoded)
	}
	if projection.SubjectSource == federatedsaml.SubjectPersistentNameID {
		document.WriteString(`<md:NameIDFormat>` + federatedsaml.PersistentNameIDFormat + `</md:NameIDFormat>`)
	}
	document.WriteString(`<md:AssertionConsumerService Binding="` + samlHTTPPOSTBinding + `" Location="`)
	writeXMLEscaped(&document, projection.ACSURL)
	document.WriteString(`" index="0" isDefault="true"/></md:SPSSODescriptor></md:EntityDescriptor>`)
	if document.Len() == 0 || document.Len() > maximumDirectSAMLMetadataBytes {
		return TenantSAMLMetadataDocument{}, ErrProtocolRejected
	}
	result := append([]byte(nil), document.Bytes()...)
	return TenantSAMLMetadataDocument{
		ContentType: SAMLMetadataContentType, Document: result, Digest: sha256.Sum256(result),
	}, nil
}

func validatedTenantMetadataCertificates(
	projection TenantSAMLMetadataProjection,
) ([][]byte, bool, bool, bool) {
	origin, originOK := canonicalPublicOrigin(projection.PublicOrigin)
	wantEntityID := origin + TenantSAMLMetadataPathPrefix + projection.TenantSlug + "/" + projection.LoginKey + DirectSAMLMetadataPathSuffix
	if !originOK || !tenantSAMLSlugPattern.MatchString(projection.TenantSlug) ||
		!tenantSAMLLoginKeyPattern.MatchString(projection.LoginKey) ||
		!validTenantMetadataEntity(projection.TenantID) || !validTenantMetadataEntity(projection.ProviderID) ||
		!validTenantMetadataEntity(projection.BindingID) || !validRevision(projection.ProviderVersion) ||
		!validRevision(projection.BindingVersion) || !validRevision(projection.ConfigurationRevision) ||
		!validRevision(projection.SecurityRevision) || !validRevision(projection.PlanRevision) ||
		!validRevision(projection.AuthorizationRevision) || !validRevision(projection.SPKeyRevision) ||
		projection.SPEntityID != wantEntityID || projection.ACSURL != origin+tenantSAMLACSPath ||
		!validInstant(projection.ObservedAt) || !validTenantMetadataPolicy(projection) ||
		!projection.TenantActive || !projection.ProviderEnabled || !projection.BindingEnabled ||
		!projection.PolicyEnabled || projection.ProviderArchived || projection.BindingArchived ||
		!projection.AccessEpochLive || len(projection.Certificates) == 0 ||
		len(projection.Certificates) > maximumCertificatesPerKey {
		return nil, false, false, false
	}
	certificates := make([][]byte, len(projection.Certificates))
	seen := make(map[[sha256.Size]byte]struct{}, len(projection.Certificates))
	var publicKeyDigest [sha256.Size]byte
	var keyID identity.EntityID
	for _, value := range projection.Certificates {
		if value.Context.Provider.Scope != identity.TenantProviderScope ||
			value.Context.Provider.TenantID != projection.TenantID ||
			value.Context.Provider.ProviderID != projection.ProviderID ||
			value.Context.BindingID != projection.BindingID ||
			!validTenantMetadataEntity(value.Context.KeyID) ||
			uint64(value.Context.KeyRevision) != projection.SPKeyRevision ||
			int(value.CertificateSequence) >= len(certificates) || len(value.CertificateDER) == 0 ||
			len(value.CertificateDER) > maximumCertificateBytes || certificates[value.CertificateSequence] != nil {
			return nil, false, false, false
		}
		certificate, err := x509.ParseCertificate(value.CertificateDER)
		if err != nil || projection.ObservedAt.Before(certificate.NotBefore.UTC()) ||
			!projection.ObservedAt.Before(certificate.NotAfter.UTC()) ||
			!tenantMetadataPublicKeyMatchesAlgorithm(certificate.PublicKey, projection.RedirectSignatureAlgorithm) {
			return nil, false, false, false
		}
		publicDER, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
		if err != nil {
			return nil, false, false, false
		}
		digest := sha256.Sum256(publicDER)
		clear(publicDER)
		certificateDigest := sha256.Sum256(value.CertificateDER)
		if _, duplicate := seen[certificateDigest]; duplicate {
			return nil, false, false, false
		}
		seen[certificateDigest] = struct{}{}
		if keyID == (identity.EntityID{}) {
			keyID = value.Context.KeyID
			publicKeyDigest = digest
		} else if keyID != value.Context.KeyID || publicKeyDigest != digest {
			return nil, false, false, false
		}
		certificates[value.CertificateSequence] = append([]byte(nil), value.CertificateDER...)
	}
	for _, certificate := range certificates {
		if certificate == nil {
			return nil, false, false, false
		}
	}
	return certificates, true, projection.EncryptionPolicy != federatedsaml.EncryptionDisabled, true
}

func validTenantMetadataEntity(value identity.EntityID) bool {
	return validUUIDv7(value)
}

func validTenantMetadataPolicy(projection TenantSAMLMetadataProjection) bool {
	if projection.SignaturePolicy != federatedsaml.SignedAssertion &&
		projection.SignaturePolicy != federatedsaml.SignedResponse && projection.SignaturePolicy != federatedsaml.SignedBoth {
		return false
	}
	switch projection.EncryptionPolicy {
	case federatedsaml.EncryptionDisabled, federatedsaml.EncryptionOptional, federatedsaml.EncryptionRequired:
	default:
		return false
	}
	return projection.SubjectSource == federatedsaml.SubjectPersistentNameID ||
		projection.SubjectSource == federatedsaml.SubjectImmutableAttribute
}

func tenantMetadataPublicKeyMatchesAlgorithm(publicKey any, algorithm federatedsaml.RedirectSignatureAlgorithm) bool {
	switch algorithm {
	case federatedsaml.RedirectRSASHA256, federatedsaml.RedirectRSASHA384, federatedsaml.RedirectRSASHA512:
		key, ok := publicKey.(*rsa.PublicKey)
		return ok && key != nil && key.N != nil && key.N.BitLen() == federationSAMLRSAKeyBitsForMetadata && key.E == 65537
	case federatedsaml.RedirectECDSASHA256:
		return tenantMetadataECDSACurve(publicKey, "P-256")
	case federatedsaml.RedirectECDSASHA384:
		return tenantMetadataECDSACurve(publicKey, "P-384")
	case federatedsaml.RedirectECDSASHA512:
		return tenantMetadataECDSACurve(publicKey, "P-521")
	default:
		return false
	}
}

const federationSAMLRSAKeyBitsForMetadata = 3072

func tenantMetadataECDSACurve(publicKey any, name string) bool {
	key, ok := publicKey.(*ecdsa.PublicKey)
	return ok && key != nil && key.Curve != nil && key.X != nil && key.Y != nil &&
		key.Curve.Params().Name == name && key.Curve.IsOnCurve(key.X, key.Y)
}
