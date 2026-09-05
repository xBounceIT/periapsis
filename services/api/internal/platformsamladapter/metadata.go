package platformsamladapter

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/origin"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

const (
	DirectSAMLMetadataPathPrefix = "/api/v1/auth/platform/saml/"
	DirectSAMLMetadataPathSuffix = "/metadata"
	SAMLMetadataContentType      = "application/samlmetadata+xml"

	samlMetadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata"
	xmlSignatureNamespace = "http://www.w3.org/2000/09/xmldsig#"
	samlProtocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlHTTPPOSTBinding   = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

	maximumDirectSAMLMetadataBytes = 512 * 1024
	maximumMetadataKeys            = 9
	maximumCertificatesPerKey      = 8
)

// DirectSAMLPublicCertificate contains public material only. KeyID and
// KeyRevision prove which immutable key row supplied the certificate;
// PlatformLoginRevision prevents a live-key projection from being replayed
// across direct-login authority revisions.
type DirectSAMLPublicCertificate struct {
	Context               identity.DirectPlatformSAMLSPKeyContext
	PlatformLoginRevision uint64
	// CertificateSequence is the zero-based, gap-free order within one
	// immutable SP-key bundle. Every certificate in that bundle carries the
	// same public key and is emitted in one KeyDescriptor.
	CertificateSequence uint8
	Signing             bool
	Encryption          bool
	CertificateDER      []byte
}

func (certificate DirectSAMLPublicCertificate) String() string {
	return fmt.Sprintf(
		"platformsamladapter.DirectSAMLPublicCertificate{keyRevision:%t,loginRevision:%t,certificateSequence:%d,signing:%t,encryption:%t,certificateBytes:%d,publicOnly:true}",
		certificate.Context.KeyRevision != 0, certificate.PlatformLoginRevision != 0,
		certificate.CertificateSequence, certificate.Signing, certificate.Encryption, len(certificate.CertificateDER),
	)
}

func (certificate DirectSAMLPublicCertificate) GoString() string { return certificate.String() }

// DirectSAMLMetadataProjection must come from a provider-qualified read-only
// projection. PublicOrigin is deployment configuration, ProviderKey is the
// already-resolved canonical provider key, and SPEntityID/ACSURL are exact
// echoes of the stored projection. The builder verifies, but never infers,
// authentication authority from an HTTP route.
type DirectSAMLMetadataProjection struct {
	ProviderKey   string
	PublicOrigin  string
	Configuration platformsamlauth.ConfigurationSnapshot
	Certificates  []DirectSAMLPublicCertificate
	ObservedAt    time.Time
}

func (projection DirectSAMLMetadataProjection) String() string {
	return fmt.Sprintf(
		"platformsamladapter.DirectSAMLMetadataProjection{providerKey:%t,origin:%t,configuration:%q,certificates:%d,observed:%t,publicOnly:true}",
		projection.ProviderKey != "", projection.PublicOrigin != "", projection.Configuration.String(),
		len(projection.Certificates),
		!projection.ObservedAt.IsZero(),
	)
}

func (projection DirectSAMLMetadataProjection) GoString() string { return projection.String() }

type DirectSAMLMetadataDocument struct {
	ContentType string
	Document    []byte
	Digest      [sha256.Size]byte
}

func (document DirectSAMLMetadataDocument) String() string {
	return fmt.Sprintf(
		"platformsamladapter.DirectSAMLMetadataDocument{contentType:%q,bytes:%d,digest:[REDACTED],publicOnly:true}",
		document.ContentType, len(document.Document),
	)
}

func (document DirectSAMLMetadataDocument) GoString() string { return document.String() }

// BuildDirectSAMLMetadata emits deterministic unsigned SP metadata from an
// exact, already-authorized projection. Signing metadata itself is a separate
// policy decision; this builder never opens an envelope or accepts a private
// key. The public HTTP route is intentionally not implemented here.
func BuildDirectSAMLMetadata(projection DirectSAMLMetadataProjection) (DirectSAMLMetadataDocument, error) {
	keys, ok := validatedMetadataCertificates(projection)
	if !ok {
		return DirectSAMLMetadataDocument{}, ErrProtocolRejected
	}
	configuration := projection.Configuration.Authentication
	var document bytes.Buffer
	document.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	document.WriteString(`<md:EntityDescriptor xmlns:md="` + samlMetadataNamespace + `" xmlns:ds="` + xmlSignatureNamespace + `" entityID="`)
	writeXMLEscaped(&document, configuration.SPEntityID)
	document.WriteString(`"><md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="`)
	document.WriteString(strconv.FormatBool(configuration.SignaturePolicy != federatedsaml.SignedResponse))
	document.WriteString(`" protocolSupportEnumeration="` + samlProtocolNamespace + `">`)
	for _, key := range keys {
		encodedCertificates := make([]string, len(key.Certificates))
		for index, certificate := range key.Certificates {
			encodedCertificates[index] = base64.StdEncoding.EncodeToString(certificate)
		}
		if key.Signing {
			writeMetadataKeyDescriptor(&document, "signing", encodedCertificates)
		}
		if key.Encryption {
			writeMetadataKeyDescriptor(&document, "encryption", encodedCertificates)
		}
	}
	if configuration.Subject.Source == federatedsaml.SubjectPersistentNameID {
		document.WriteString(`<md:NameIDFormat>` + federatedsaml.PersistentNameIDFormat + `</md:NameIDFormat>`)
	}
	document.WriteString(`<md:AssertionConsumerService Binding="` + samlHTTPPOSTBinding + `" Location="`)
	writeXMLEscaped(&document, configuration.ACSURL)
	document.WriteString(`" index="0" isDefault="true"/></md:SPSSODescriptor></md:EntityDescriptor>`)
	if document.Len() > maximumDirectSAMLMetadataBytes {
		return DirectSAMLMetadataDocument{}, ErrProtocolRejected
	}
	encoded := append([]byte(nil), document.Bytes()...)
	return DirectSAMLMetadataDocument{
		ContentType: SAMLMetadataContentType, Document: encoded, Digest: sha256.Sum256(encoded),
	}, nil
}

func validatedMetadataCertificates(
	projection DirectSAMLMetadataProjection,
) ([]directSAMLMetadataKey, bool) {
	origin, ok := canonicalPublicOrigin(projection.PublicOrigin)
	configuration := projection.Configuration.Authentication
	pins := projection.Configuration.Pins
	if !ok || !providerKeyPattern.MatchString(projection.ProviderKey) ||
		projection.Configuration.ProviderKind != platformsamlauth.ProviderKindSAML ||
		!validDirectPins(pins) || !validInstant(projection.ObservedAt) ||
		federatedsaml.ValidatePinnedConfiguration(configuration, pins.Protocol, projection.ObservedAt) != nil ||
		configuration.SPEntityID != origin+DirectSAMLMetadataPathPrefix+projection.ProviderKey+DirectSAMLMetadataPathSuffix ||
		configuration.ACSURL != origin+platformsamlauth.DirectSAMLACSURL ||
		len(configuration.Mapping.Scalars) != 0 || len(configuration.Mapping.Profiles) != 0 ||
		configuration.Mapping.Groups != nil || len(configuration.DirectPlatformDecryptionKeyRevisions) > 8 {
		return nil, false
	}
	wanted := map[uint64]struct{}{
		pins.Protocol.SPKeyRevision: {},
	}
	decryption := make(map[uint64]struct{}, len(configuration.DirectPlatformDecryptionKeyRevisions))
	for _, revision := range configuration.DirectPlatformDecryptionKeyRevisions {
		wanted[revision] = struct{}{}
		decryption[revision] = struct{}{}
	}
	if len(wanted) > maximumMetadataKeys || len(projection.Certificates) < len(wanted) ||
		len(projection.Certificates) > len(wanted)*maximumCertificatesPerKey {
		return nil, false
	}
	type certificateGroup struct {
		keyID           identity.EntityID
		signing         bool
		encryption      bool
		publicKeyDigest [sha256.Size]byte
		sequences       map[uint8][]byte
		certificates    map[[sha256.Size]byte]struct{}
	}
	groups := make(map[uint64]*certificateGroup, len(wanted))
	seenKeyIDs := make(map[identity.EntityID]uint64, len(wanted))
	for _, value := range projection.Certificates {
		revision := value.Context.KeyRevision
		if _, expected := wanted[revision]; !expected {
			return nil, false
		}
		_, mustEncrypt := decryption[revision]
		mustSign := revision == pins.Protocol.SPKeyRevision
		if value.Signing != mustSign || value.Encryption != mustEncrypt ||
			value.Context.Provider != pins.Protocol.Provider || !validUUIDv7(value.Context.KeyID) ||
			!validRevision(value.Context.KeyRevision) ||
			int(value.CertificateSequence) >= maximumCertificatesPerKey ||
			value.PlatformLoginRevision != pins.Protocol.PlatformLoginRevision ||
			len(value.CertificateDER) == 0 || len(value.CertificateDER) > maximumCertificateBytes {
			return nil, false
		}
		certificate, err := x509.ParseCertificate(value.CertificateDER)
		if err != nil || projection.ObservedAt.Before(certificate.NotBefore.UTC()) ||
			!projection.ObservedAt.Before(certificate.NotAfter.UTC()) ||
			!validMetadataPublicKey(certificate.PublicKey, mustEncrypt) {
			return nil, false
		}
		publicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
		if err != nil {
			return nil, false
		}
		publicKeyDigest := sha256.Sum256(publicKey)
		certificateDigest := sha256.Sum256(value.CertificateDER)
		group := groups[revision]
		if group == nil {
			if previousRevision, duplicate := seenKeyIDs[value.Context.KeyID]; duplicate && previousRevision != revision {
				return nil, false
			}
			seenKeyIDs[value.Context.KeyID] = revision
			group = &certificateGroup{
				keyID: value.Context.KeyID, signing: mustSign, encryption: mustEncrypt,
				publicKeyDigest: publicKeyDigest,
				sequences:       make(map[uint8][]byte, maximumCertificatesPerKey),
				certificates:    make(map[[sha256.Size]byte]struct{}, maximumCertificatesPerKey),
			}
			groups[revision] = group
		}
		if group.keyID != value.Context.KeyID || group.publicKeyDigest != publicKeyDigest {
			return nil, false
		}
		if _, duplicate := group.sequences[value.CertificateSequence]; duplicate {
			return nil, false
		}
		if _, duplicate := group.certificates[certificateDigest]; duplicate {
			return nil, false
		}
		group.sequences[value.CertificateSequence] = append([]byte(nil), value.CertificateDER...)
		group.certificates[certificateDigest] = struct{}{}
	}
	if len(groups) != len(wanted) {
		return nil, false
	}
	result := make([]directSAMLMetadataKey, 0, len(groups))
	for revision, group := range groups {
		if len(group.sequences) == 0 || len(group.sequences) > maximumCertificatesPerKey {
			return nil, false
		}
		certificates := make([][]byte, len(group.sequences))
		for index := range certificates {
			certificate, present := group.sequences[uint8(index)]
			if !present {
				return nil, false
			}
			certificates[index] = certificate
		}
		result = append(result, directSAMLMetadataKey{
			KeyID: group.keyID, KeyRevision: revision, Signing: group.signing,
			Encryption: group.encryption, Certificates: certificates,
		})
	}
	slices.SortFunc(result, func(left, right directSAMLMetadataKey) int {
		if left.KeyRevision < right.KeyRevision {
			return -1
		}
		if left.KeyRevision > right.KeyRevision {
			return 1
		}
		return bytes.Compare(left.KeyID[:], right.KeyID[:])
	})
	return result, true
}

type directSAMLMetadataKey struct {
	KeyID        identity.EntityID
	KeyRevision  uint64
	Signing      bool
	Encryption   bool
	Certificates [][]byte
}

func canonicalPublicOrigin(raw string) (string, bool) {
	if !validText(raw, 2048, false) || strings.ContainsAny(raw, "\\\r\n") {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Hostname() == "" || parsed.ForceQuery || strings.Contains(parsed.Host, "%") ||
		strings.HasSuffix(parsed.Host, ":") {
		return "", false
	}
	hostname, err := origin.CanonicalHostname(parsed.Hostname())
	if err != nil {
		return "", false
	}
	port := parsed.Port()
	if port != "" {
		numericPort, portErr := strconv.Atoi(port)
		if portErr != nil || numericPort < 1 || numericPort > 65535 || numericPort == 443 {
			return "", false
		}
		port = strconv.Itoa(numericPort)
	}
	canonicalHost := hostname
	if strings.Contains(hostname, ":") {
		canonicalHost = "[" + hostname + "]"
	}
	if port != "" {
		canonicalHost = net.JoinHostPort(hostname, port)
	}
	canonical := "https://" + canonicalHost
	if canonical != raw || parsed.String() != raw {
		return "", false
	}
	return canonical, true
}

func validMetadataPublicKey(public any, encryption bool) bool {
	switch key := public.(type) {
	case *rsa.PublicKey:
		return key != nil && key.N != nil && key.N.BitLen() >= 2048 && key.E >= 65537
	case *ecdsa.PublicKey:
		return !encryption && key != nil && key.Curve != nil && key.X != nil && key.Y != nil &&
			key.Curve.Params() != nil && key.Curve.Params().BitSize >= 256 && key.Curve.IsOnCurve(key.X, key.Y)
	default:
		return false
	}
}

func writeMetadataKeyDescriptor(destination *bytes.Buffer, usage string, encodedCertificates []string) {
	destination.WriteString(`<md:KeyDescriptor use="` + usage + `"><ds:KeyInfo><ds:X509Data>`)
	for _, encodedCertificate := range encodedCertificates {
		destination.WriteString(`<ds:X509Certificate>`)
		destination.WriteString(encodedCertificate)
		destination.WriteString(`</ds:X509Certificate>`)
	}
	destination.WriteString(`</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`)
}

func writeXMLEscaped(destination *bytes.Buffer, value string) {
	_ = xml.EscapeText(destination, []byte(value))
}
