package federatedsaml

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml/xmlenc"
	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
	dsig "github.com/russellhaering/goxmldsig"
)

var (
	ErrInvalidAdapterOptions = errors.New("invalid SAML adapter options")
	ErrMetadataFetchFailed   = errors.New("SAML metadata fetch failed")
	ErrSPKeyUnavailable      = errors.New("SAML SP key unavailable")
)

// MetadataLocation is an immutable provider-bound URL projection. The
// resolver must return the exact provider, binding, and requested revision.
type MetadataLocation struct {
	Provider  identity.ProviderContext
	BindingID identity.EntityID
	Revision  uint64
	URL       string
}

// MetadataLocationResolver performs only the short configuration lookup. It
// must not keep a database transaction open after returning.
type MetadataLocationResolver interface {
	ResolveSAMLMetadataLocation(context.Context, MetadataLoadRequest) (MetadataLocation, error)
}

// HTTPMetadataSourceOptions freezes the concrete SSRF boundary and a bounded
// non-authoritative raw-document cache. Immutable compiled snapshots remain
// the authority boundary.
type HTTPMetadataSourceOptions struct {
	HTTP       *federatedhttp.Client
	Locations  MetadataLocationResolver
	MaxEntries int
	Now        func() time.Time
}

type metadataCacheKey struct {
	Provider  identity.ProviderContext
	BindingID identity.EntityID
	Revision  uint64
}

type metadataCacheEntry struct {
	document   []byte
	retrieved  time.Time
	freshUntil time.Time
}

// HTTPMetadataSource implements MetadataSource using the single hardened
// federated HTTP client. Cache hits return defensive copies.
type HTTPMetadataSource struct {
	http       *federatedhttp.Client
	locations  MetadataLocationResolver
	maxEntries int
	now        func() time.Time
	mu         sync.Mutex
	cache      map[metadataCacheKey]metadataCacheEntry
}

func NewHTTPMetadataSource(options HTTPMetadataSourceOptions) (*HTTPMetadataSource, error) {
	if options.HTTP == nil || options.Locations == nil || options.MaxEntries < 1 || options.MaxEntries > 1024 {
		return nil, ErrInvalidAdapterOptions
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &HTTPMetadataSource{
		http: options.HTTP, locations: options.Locations, maxEntries: options.MaxEntries,
		now: options.Now, cache: make(map[metadataCacheKey]metadataCacheEntry),
	}, nil
}

func (source *HTTPMetadataSource) LoadSAMLMetadata(
	ctx context.Context,
	request MetadataLoadRequest,
	maximumBytes int,
) (MetadataDocument, error) {
	if source == nil || source.http == nil || source.locations == nil || ctx == nil ||
		maximumBytes < 1 || maximumBytes > maximumMetadataAdapterBytes || !validProvider(request.Provider) ||
		!validEntityID(request.BindingID) || request.Revision == 0 ||
		!validBoundedString(request.ExpectedEntityID, maximumEntityIDBytes) || !validInstant(request.MaximumValidUntil) {
		return MetadataDocument{}, ErrMetadataFetchFailed
	}
	key := metadataCacheKey{Provider: request.Provider, BindingID: request.BindingID, Revision: request.Revision}
	if cached, ok := source.loadFresh(key, maximumBytes); ok {
		return MetadataDocument{Document: cached.document, RetrievedAt: cached.retrieved}, nil
	}
	location, err := source.locations.ResolveSAMLMetadataLocation(ctx, request)
	if err != nil || location.Provider != request.Provider || location.BindingID != request.BindingID ||
		location.Revision != request.Revision {
		return MetadataDocument{}, ErrMetadataFetchFailed
	}
	target, err := source.http.CompileTarget(federatedhttp.DocumentSAMLMetadata, location.URL)
	if err != nil {
		return MetadataDocument{}, ErrMetadataFetchFailed
	}
	result, err := source.http.Fetch(ctx, target, nil)
	defer clear(result.Body)
	if err != nil || result.Category != federatedhttp.CategorySuccess || result.Kind != federatedhttp.DocumentSAMLMetadata ||
		len(result.Body) == 0 || len(result.Body) > maximumBytes || result.Digest != sha256.Sum256(result.Body) ||
		result.Cache.RetrievedAt.IsZero() || result.Cache.FreshUntil.Before(result.Cache.RetrievedAt) {
		return MetadataDocument{}, ErrMetadataFetchFailed
	}
	document := append([]byte(nil), result.Body...)
	cacheNow := source.now().UTC()
	if result.Cache.Cacheable && !cacheNow.IsZero() && result.Cache.FreshUntil.After(cacheNow) {
		source.store(key, metadataCacheEntry{
			document: append([]byte(nil), document...), retrieved: result.Cache.RetrievedAt,
			freshUntil: result.Cache.FreshUntil,
		})
	}
	return MetadataDocument{Document: document, RetrievedAt: result.Cache.RetrievedAt}, nil
}

const (
	maximumMetadataAdapterBytes           = 512 * 1024
	maximumCryptoAdapterXMLBytes          = 768 * 1024
	maximumDecryptedAssertionAdapterBytes = 512 * 1024
)

func (source *HTTPMetadataSource) loadFresh(key metadataCacheKey, maximumBytes int) (metadataCacheEntry, bool) {
	now := source.now().UTC()
	if now.IsZero() {
		return metadataCacheEntry{}, false
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	entry, ok := source.cache[key]
	if !ok {
		return metadataCacheEntry{}, false
	}
	if !entry.freshUntil.After(now) {
		clear(entry.document)
		delete(source.cache, key)
		return metadataCacheEntry{}, false
	}
	if len(entry.document) > maximumBytes {
		return metadataCacheEntry{}, false
	}
	entry.document = append([]byte(nil), entry.document...)
	return entry, true
}

func (source *HTTPMetadataSource) store(key metadataCacheKey, entry metadataCacheEntry) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if previous, found := source.cache[key]; found {
		clear(previous.document)
		source.cache[key] = entry
		return
	}
	if len(source.cache) >= source.maxEntries {
		var oldestKey metadataCacheKey
		var oldest time.Time
		for candidate, cached := range source.cache {
			if oldest.IsZero() || cached.freshUntil.Before(oldest) {
				oldestKey, oldest = candidate, cached.freshUntil
			}
		}
		removed := source.cache[oldestKey]
		clear(removed.document)
		delete(source.cache, oldestKey)
	}
	source.cache[key] = entry
}

// SPKeyRequest binds private-key access to one exact provider, binding, and
// immutable key revision.
type SPKeyRequest struct {
	Provider         identity.ProviderContext
	BindingID        identity.EntityID
	KeyRevision      uint32
	LogoutMaterialID identity.EntityID
}

// SPKeyMaterial never formats its signer or private key.
type SPKeyMaterial struct {
	Provider       identity.ProviderContext
	BindingID      identity.EntityID
	KeyRevision    uint32
	Signer         crypto.Signer   `json:"-"`
	RSADecrypter   *rsa.PrivateKey `json:"-"`
	CertificateDER [][]byte
}

func (material SPKeyMaterial) String() string {
	return fmt.Sprintf("federatedsaml.SPKeyMaterial{revision:%d,certificates:%d,material:[REDACTED]}",
		material.KeyRevision, len(material.CertificateDER))
}
func (material SPKeyMaterial) GoString() string { return material.String() }

// SPKeySource owns protected private-key loading and exact revision lookup.
type SPKeySource interface {
	LoadSAMLSPKey(context.Context, SPKeyRequest) (SPKeyMaterial, error)
}

// DirectPlatformSPKeyRequest is the separate platform key lookup family. Its
// uint64 revision matches the platform SP-key table and cannot be truncated
// into the legacy tenant key source.
type DirectPlatformSPKeyRequest struct {
	Provider              identity.ProviderContext
	PlatformLoginRevision uint64
	KeyRevision           uint64
	LogoutMaterialID      identity.EntityID
}

func (request DirectPlatformSPKeyRequest) String() string {
	return fmt.Sprintf(
		"federatedsaml.DirectPlatformSPKeyRequest{provider_present:%t,platform_login:%t,key_revision:%t,logout_material:%t}",
		validProvider(request.Provider), request.PlatformLoginRevision != 0, request.KeyRevision != 0,
		validEntityID(request.LogoutMaterialID),
	)
}
func (request DirectPlatformSPKeyRequest) GoString() string { return request.String() }

// DirectPlatformSPKeyMaterial carries the exact keyring context used to open
// one platform-owned SP key. Signer and decrypter material never format.
type DirectPlatformSPKeyMaterial struct {
	Context        identity.DirectPlatformSAMLSPKeyContext
	Signer         crypto.Signer   `json:"-"`
	RSADecrypter   *rsa.PrivateKey `json:"-"`
	CertificateDER [][]byte
}

func (material DirectPlatformSPKeyMaterial) String() string {
	return fmt.Sprintf(
		"federatedsaml.DirectPlatformSPKeyMaterial{revision:%d,certificates:%d,material:[REDACTED]}",
		material.Context.KeyRevision, len(material.CertificateDER),
	)
}
func (material DirectPlatformSPKeyMaterial) GoString() string { return material.String() }

// DirectPlatformSPKeySource cannot fall back to tenant key lookup. It resolves
// the immutable platform key row and opens it with the direct-platform AAD
// context before returning private material.
type DirectPlatformSPKeySource interface {
	LoadDirectPlatformSAMLSPKey(context.Context, DirectPlatformSPKeyRequest) (DirectPlatformSPKeyMaterial, error)
}

// LibraryCryptoAdapter implements all SAML crypto ports using goxmldsig and
// crewjam/saml's XML Encryption implementation behind exact key access.
type LibraryCryptoAdapter struct {
	keys               SPKeySource
	directPlatformKeys DirectPlatformSPKeySource
}

var registerModernXMLDecrypter sync.Once

type xmlEncryptionSHA256Digest struct{}

func (xmlEncryptionSHA256Digest) Algorithm() string { return digestSHA256 }
func (xmlEncryptionSHA256Digest) Hash() hash.Hash   { return sha256.New() }

func NewLibraryCryptoAdapter(keys SPKeySource) (*LibraryCryptoAdapter, error) {
	if keys == nil {
		return nil, ErrInvalidAdapterOptions
	}
	// crewjam/saml registers the legacy 2001 RSA-OAEP URI by default. ADR-0010
	// admits only the XML Encryption 1.1 RSA-OAEP URI with SHA-256, so register
	// that maintained implementation exactly once before any concurrent use.
	registerSAMLXMLDecrypters()
	return &LibraryCryptoAdapter{keys: keys}, nil
}

// NewDirectPlatformLibraryCryptoAdapter constructs a crypto adapter that can
// access only the direct-platform SP-key family.
func NewDirectPlatformLibraryCryptoAdapter(keys DirectPlatformSPKeySource) (*LibraryCryptoAdapter, error) {
	if keys == nil {
		return nil, ErrInvalidAdapterOptions
	}
	registerSAMLXMLDecrypters()
	return &LibraryCryptoAdapter{directPlatformKeys: keys}, nil
}

func registerSAMLXMLDecrypters() {
	registerModernXMLDecrypter.Do(func() {
		xmlenc.RegisterDigestMethod(xmlEncryptionSHA256Digest{})
		xmlenc.RegisterDecrypter(xmlenc.OAEP_SHA256())
	})
}

func (adapter *LibraryCryptoAdapter) SignRedirect(
	ctx context.Context,
	request RedirectSignRequest,
) ([]byte, error) {
	if adapter == nil || ctx == nil || ctx.Err() != nil ||
		!validCeremonyContext(
			request.Authority, request.Provider, request.BindingID, request.PlatformLoginRevision,
		) || !validPersistentRevision(request.KeyRevision) ||
		!validRedirectAlgorithm(request.Algorithm) || len(request.Payload) == 0 || len(request.Payload) > maximumSignedPayloadBytes {
		return nil, ErrSPKeyUnavailable
	}
	var signer crypto.Signer
	var certificates [][]byte
	switch request.Authority {
	case TenantCeremonyAuthority:
		if adapter.keys == nil || request.KeyRevision > math.MaxUint32 {
			return nil, ErrSPKeyUnavailable
		}
		material, err := adapter.keys.LoadSAMLSPKey(ctx, SPKeyRequest{
			Provider: request.Provider, BindingID: request.BindingID, KeyRevision: uint32(request.KeyRevision),
			LogoutMaterialID: request.LogoutMaterialID,
		})
		if err != nil || !validSPKeyMaterial(
			material, request.Provider, request.BindingID, uint32(request.KeyRevision), true,
		) {
			return nil, ErrSPKeyUnavailable
		}
		signer, certificates = material.Signer, material.CertificateDER
	case DirectPlatformCeremonyAuthority:
		if adapter.directPlatformKeys == nil {
			return nil, ErrSPKeyUnavailable
		}
		material, err := adapter.directPlatformKeys.LoadDirectPlatformSAMLSPKey(ctx, DirectPlatformSPKeyRequest{
			Provider: request.Provider, PlatformLoginRevision: request.PlatformLoginRevision,
			KeyRevision: request.KeyRevision, LogoutMaterialID: request.LogoutMaterialID,
		})
		if err != nil || !validDirectPlatformSPKeyMaterial(material, request.Provider, request.KeyRevision, true) {
			return nil, ErrSPKeyUnavailable
		}
		signer, certificates = material.Signer, material.CertificateDER
	default:
		return nil, ErrSPKeyUnavailable
	}
	if ctx.Err() != nil {
		return nil, ErrSPKeyUnavailable
	}
	signing, err := dsig.NewSigningContext(signer, cloneBytes2DAdapter(certificates))
	if err != nil || signing.SetSignatureMethod(string(request.Algorithm)) != nil {
		return nil, ErrSPKeyUnavailable
	}
	signature, err := signing.SignString(string(request.Payload))
	if err != nil || len(signature) == 0 || len(signature) > maximumSignatureBytes || ctx.Err() != nil {
		clear(signature)
		return nil, ErrSPKeyUnavailable
	}
	return signature, nil
}

func (adapter *LibraryCryptoAdapter) VerifyXMLSignature(
	ctx context.Context,
	request SignatureVerificationRequest,
) (SignatureVerificationResult, error) {
	if adapter == nil || ctx == nil || ctx.Err() != nil || !request.Metadata.valid ||
		!validSignatureVerificationAuthority(request) ||
		!validXMLID(request.ObjectID) ||
		request.ObjectKind != SignedObjectResponse && request.ObjectKind != SignedObjectAssertion {
		return SignatureVerificationResult{}, ErrSignatureRejected
	}
	if _, err := parseBoundedXML(request.Document, maximumCryptoAdapterXMLBytes, DefaultLimits()); err != nil {
		return SignatureVerificationResult{}, ErrSignatureRejected
	}
	document := etree.NewDocument()
	document.ReadSettings = etree.ReadSettings{Permissive: false}
	if err := document.ReadFromBytes(request.Document); err != nil || document.Root() == nil {
		return SignatureVerificationResult{}, ErrSignatureRejected
	}
	object, count := findObjectByID(document.Root(), request.ObjectID)
	if count != 1 || !objectMatchesKind(object, request.ObjectKind) {
		return SignatureVerificationResult{}, ErrSignatureRejected
	}
	shape, err := inspectSignatureShape(object, request.ObjectID)
	if err != nil || shape.referenceURI != "#"+request.ObjectID || shape.referenceCount != 1 ||
		shape.keyInfoCertificateCount < 0 || shape.keyInfoCertificateCount > 1 ||
		shape.canonicalizationParameterCount != 0 || shape.transformParameterCount != 0 ||
		shape.externalDereferenceCount != 0 || !validXMLSignatureAlgorithm(shape.signatureAlgorithm) ||
		!validDigestAlgorithm(shape.digestAlgorithm) || shape.canonicalizationAlgorithm != exclusiveCanonicalization ||
		!slices.Equal(shape.transforms, []string{envelopedSignatureTransform, exclusiveCanonicalization}) {
		return SignatureVerificationResult{}, ErrSignatureRejected
	}
	matching := 0
	var fingerprint [sha256.Size]byte
	for _, der := range request.Metadata.CertificateDER() {
		certificate, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			continue
		}
		validation := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{certificate}})
		validation.IdAttribute = "ID"
		validated, validationErr := validation.Validate(object.Copy())
		if validationErr == nil && validated != nil && validated.SelectAttrValue("ID", "") == request.ObjectID {
			matching++
			fingerprint = sha256.Sum256(der)
		}
	}
	if matching != 1 || ctx.Err() != nil {
		return SignatureVerificationResult{}, ErrSignatureRejected
	}
	return SignatureVerificationResult{
		Authority: request.Authority, Provider: request.Provider, BindingID: request.BindingID,
		PlatformLoginRevision: request.PlatformLoginRevision,
		ObjectKind:            request.ObjectKind, ObjectID: request.ObjectID, ReferenceURI: shape.referenceURI,
		CertificateFingerprintSHA256: fingerprint, SignatureAlgorithm: shape.signatureAlgorithm,
		DigestAlgorithm: shape.digestAlgorithm, CanonicalizationAlgorithm: shape.canonicalizationAlgorithm,
		Transforms: shape.transforms, DocumentDigest: sha256.Sum256(request.Document),
		ReferenceCount: shape.referenceCount, KeyInfoCertificateCount: shape.keyInfoCertificateCount,
		MatchingCertificateCount: matching, CanonicalizationParameterCount: shape.canonicalizationParameterCount,
		TransformParameterCount: shape.transformParameterCount, ExternalDereferenceCount: shape.externalDereferenceCount,
	}, nil
}

func validSignatureVerificationAuthority(request SignatureVerificationRequest) bool {
	if request.Authority == DirectPlatformCeremonyAuthority {
		return validCeremonyContext(
			request.Authority, request.Provider, request.BindingID, request.PlatformLoginRevision,
		)
	}
	if request.Authority != TenantCeremonyAuthority || request.PlatformLoginRevision != 0 {
		return false
	}
	// Provider and binding were added to bind direct-platform verification.
	// Preserve the legacy tenant adapter call shape while requiring new tenant
	// callers that provide either field to provide the complete exact context.
	zeroProvider := identity.ProviderContext{}
	zeroBinding := identity.EntityID{}
	if request.Provider == zeroProvider && request.BindingID == zeroBinding {
		return true
	}
	return validCeremonyContext(
		request.Authority, request.Provider, request.BindingID, request.PlatformLoginRevision,
	)
}

func (adapter *LibraryCryptoAdapter) DecryptAssertion(
	ctx context.Context,
	request DecryptionRequest,
) (DecryptionResult, error) {
	if adapter == nil || ctx == nil || ctx.Err() != nil || !validDecryptionRequestAuthority(adapter, request) ||
		!validXMLID(request.ResponseID) || !validXMLID(request.EncryptedObjectID) {
		return DecryptionResult{}, ErrEncryptionRejected
	}
	parsed, err := parseBoundedXML(request.Response, maximumCryptoAdapterXMLBytes, DefaultLimits())
	if err != nil || parsed.name != (expandedName{space: samlProtocolNamespace, local: "Response"}) {
		return DecryptionResult{}, ErrEncryptionRejected
	}
	envelope, envelopeCount := findValidatedEncryptedEnvelope(parsed, request.EncryptedObjectID)
	if envelopeCount != 1 {
		return DecryptionResult{}, ErrEncryptionRejected
	}
	document := etree.NewDocument()
	document.ReadSettings = etree.ReadSettings{Permissive: false}
	if err := document.ReadFromBytes(request.Response); err != nil || document.Root() == nil ||
		document.Root().SelectAttrValue("ID", "") != request.ResponseID {
		return DecryptionResult{}, ErrEncryptionRejected
	}
	encrypted, count := findObjectByID(document.Root(), request.EncryptedObjectID)
	if count != 1 || encrypted == nil || encrypted.Tag != "EncryptedData" || encrypted.NamespaceURI() != xmlEncryptionNamespace {
		return DecryptionResult{}, ErrEncryptionRejected
	}
	algorithms, err := inspectEncryptionAlgorithms(encrypted)
	if err != nil || !validContentEncryption(algorithms.content) ||
		algorithms.content != envelope.contentAlgorithm || algorithms.transport != envelope.keyAlgorithm ||
		algorithms.digest != envelope.keyDigest || algorithms.mgf != envelope.keyMGF ||
		algorithms.transport != rsaOAEP11 || algorithms.digest != digestSHA256 || algorithms.mgf != mgf1SHA256 {
		return DecryptionResult{}, ErrEncryptionRejected
	}
	if request.Authority == TenantCeremonyAuthority {
		for _, revision := range request.AllowedKeyVersions {
			material, loadErr := adapter.keys.LoadSAMLSPKey(ctx, SPKeyRequest{
				Provider: request.Provider, BindingID: request.BindingID, KeyRevision: revision,
			})
			if loadErr != nil || !validSPKeyMaterial(
				material, request.Provider, request.BindingID, revision, false,
			) {
				continue
			}
			plaintext, decrypted, valid := decryptSAMLAssertionCandidate(ctx, material.RSADecrypter, encrypted)
			if !decrypted {
				continue
			}
			if !valid {
				return DecryptionResult{}, ErrEncryptionRejected
			}
			return decryptionResult(request, algorithms, plaintext, revision, 0), nil
		}
		return DecryptionResult{}, ErrEncryptionRejected
	}
	for _, revision := range request.DirectPlatformKeyRevisions {
		material, loadErr := adapter.directPlatformKeys.LoadDirectPlatformSAMLSPKey(ctx, DirectPlatformSPKeyRequest{
			Provider: request.Provider, PlatformLoginRevision: request.PlatformLoginRevision, KeyRevision: revision,
		})
		if loadErr != nil || !validDirectPlatformSPKeyMaterial(material, request.Provider, revision, false) {
			continue
		}
		plaintext, decrypted, valid := decryptSAMLAssertionCandidate(ctx, material.RSADecrypter, encrypted)
		if !decrypted {
			continue
		}
		if !valid {
			return DecryptionResult{}, ErrEncryptionRejected
		}
		return decryptionResult(request, algorithms, plaintext, 0, revision), nil
	}
	return DecryptionResult{}, ErrEncryptionRejected
}

func decryptSAMLAssertionCandidate(
	ctx context.Context,
	decrypter *rsa.PrivateKey,
	encrypted *etree.Element,
) ([]byte, bool, bool) {
	plaintext, err := xmlenc.Decrypt(decrypter, encrypted.Copy())
	if err != nil {
		clear(plaintext)
		return nil, false, false
	}
	assertion, parseErr := parseBoundedXML(plaintext, maximumDecryptedAssertionAdapterBytes, DefaultLimits())
	if ctx.Err() != nil || parseErr != nil ||
		assertion.name != (expandedName{space: samlAssertionNamespace, local: "Assertion"}) {
		clear(plaintext)
		return nil, true, false
	}
	return plaintext, true, true
}

func decryptionResult(
	request DecryptionRequest,
	algorithms encryptionAlgorithms,
	plaintext []byte,
	tenantRevision uint32,
	directRevision uint64,
) DecryptionResult {
	return DecryptionResult{
		Authority: request.Authority, Provider: request.Provider, BindingID: request.BindingID,
		PlatformLoginRevision: request.PlatformLoginRevision,
		Assertion:             plaintext, KeyVersion: tenantRevision, DirectPlatformKeyRevision: directRevision,
		ContentEncryptionAlgorithm: algorithms.content, KeyTransportAlgorithm: algorithms.transport,
		KeyDigestAlgorithm: algorithms.digest, MaskGenerationAlgorithm: algorithms.mgf,
		EncryptedObjectID: request.EncryptedObjectID, ExternalDereferenceCount: 0,
	}
}

func validDecryptionRequestAuthority(adapter *LibraryCryptoAdapter, request DecryptionRequest) bool {
	if !validCeremonyContext(
		request.Authority, request.Provider, request.BindingID, request.PlatformLoginRevision,
	) {
		return false
	}
	switch request.Authority {
	case TenantCeremonyAuthority:
		return adapter.keys != nil && len(request.DirectPlatformKeyRevisions) == 0 &&
			len(request.AllowedKeyVersions) > 0 && len(request.AllowedKeyVersions) <= 8 &&
			strictSortedUniqueUint32(request.AllowedKeyVersions)
	case DirectPlatformCeremonyAuthority:
		return adapter.directPlatformKeys != nil && len(request.AllowedKeyVersions) == 0 &&
			len(request.DirectPlatformKeyRevisions) > 0 && len(request.DirectPlatformKeyRevisions) <= 8 &&
			strictSortedUniqueUint64(request.DirectPlatformKeyRevisions)
	default:
		return false
	}
}

func findValidatedEncryptedEnvelope(root *xmlNode, objectID string) (encryptedEnvelope, int) {
	var result encryptedEnvelope
	count := 0
	if root == nil {
		return result, 0
	}
	for _, node := range root.children {
		if node.name == (expandedName{space: samlAssertionNamespace, local: "EncryptedAssertion"}) {
			if envelope, err := validateEncryptedAssertionEnvelope(node); err == nil && envelope.id == objectID {
				result, count = envelope, count+1
			}
		}
	}
	return result, count
}

type signatureShape struct {
	referenceURI, signatureAlgorithm, digestAlgorithm, canonicalizationAlgorithm      string
	transforms                                                                        []string
	referenceCount, keyInfoCertificateCount                                           int
	canonicalizationParameterCount, transformParameterCount, externalDereferenceCount int
}

func inspectSignatureShape(object *etree.Element, objectID string) (signatureShape, error) {
	var signature *etree.Element
	for _, child := range object.ChildElements() {
		if child.Tag == "Signature" && child.NamespaceURI() == xmlSignatureNamespace {
			if signature != nil {
				return signatureShape{}, ErrSignatureRejected
			}
			signature = child
		}
	}
	if signature == nil {
		return signatureShape{}, ErrSignatureRejected
	}
	signatureChildren := []expandedName{
		{space: xmlSignatureNamespace, local: "SignedInfo"},
		{space: xmlSignatureNamespace, local: "SignatureValue"},
	}
	if len(directChildren(signature, xmlSignatureNamespace, "KeyInfo")) == 1 {
		signatureChildren = append(signatureChildren, expandedName{space: xmlSignatureNamespace, local: "KeyInfo"})
	}
	if !exactElementChildren(signature, signatureChildren...) {
		return signatureShape{}, ErrSignatureRejected
	}
	signedInfo := directChild(signature, xmlSignatureNamespace, "SignedInfo")
	canonicalization := directChild(signedInfo, xmlSignatureNamespace, "CanonicalizationMethod")
	signatureMethod := directChild(signedInfo, xmlSignatureNamespace, "SignatureMethod")
	signatureValue := directChild(signature, xmlSignatureNamespace, "SignatureValue")
	if signedInfo == nil || canonicalization == nil || signatureMethod == nil ||
		signatureValue == nil || len(signatureMethod.ChildElements()) != 0 ||
		len(signatureValue.ChildElements()) != 0 || strings.TrimSpace(signatureValue.Text()) == "" ||
		!exactElementChildren(signedInfo,
			expandedName{space: xmlSignatureNamespace, local: "CanonicalizationMethod"},
			expandedName{space: xmlSignatureNamespace, local: "SignatureMethod"},
			expandedName{space: xmlSignatureNamespace, local: "Reference"},
		) {
		return signatureShape{}, ErrSignatureRejected
	}
	references := directChildren(signedInfo, xmlSignatureNamespace, "Reference")
	if len(references) != 1 {
		return signatureShape{}, ErrSignatureRejected
	}
	reference := references[0]
	transformsNode := directChild(reference, xmlSignatureNamespace, "Transforms")
	digestMethod := directChild(reference, xmlSignatureNamespace, "DigestMethod")
	digestValue := directChild(reference, xmlSignatureNamespace, "DigestValue")
	if transformsNode == nil || digestMethod == nil || digestValue == nil ||
		len(digestMethod.ChildElements()) != 0 || len(digestValue.ChildElements()) != 0 ||
		strings.TrimSpace(digestValue.Text()) == "" ||
		!exactElementChildren(reference,
			expandedName{space: xmlSignatureNamespace, local: "Transforms"},
			expandedName{space: xmlSignatureNamespace, local: "DigestMethod"},
			expandedName{space: xmlSignatureNamespace, local: "DigestValue"},
		) {
		return signatureShape{}, ErrSignatureRejected
	}
	transforms := directChildren(transformsNode, xmlSignatureNamespace, "Transform")
	if len(transforms) != 2 || !exactElementChildren(transformsNode,
		expandedName{space: xmlSignatureNamespace, local: "Transform"},
		expandedName{space: xmlSignatureNamespace, local: "Transform"},
	) {
		return signatureShape{}, ErrSignatureRejected
	}
	result := signatureShape{
		referenceURI:                   reference.SelectAttrValue("URI", ""),
		signatureAlgorithm:             signatureMethod.SelectAttrValue("Algorithm", ""),
		digestAlgorithm:                digestMethod.SelectAttrValue("Algorithm", ""),
		canonicalizationAlgorithm:      canonicalization.SelectAttrValue("Algorithm", ""),
		referenceCount:                 len(references),
		canonicalizationParameterCount: len(canonicalization.ChildElements()),
	}
	if result.referenceURI != "#"+objectID {
		result.externalDereferenceCount = 1
	}
	for _, transform := range transforms {
		result.transforms = append(result.transforms, transform.SelectAttrValue("Algorithm", ""))
		result.transformParameterCount += len(transform.ChildElements())
	}
	keyInfo := directChild(signature, xmlSignatureNamespace, "KeyInfo")
	if keyInfo != nil {
		x509Data := directChild(keyInfo, xmlSignatureNamespace, "X509Data")
		if x509Data == nil || !exactElementChildren(keyInfo,
			expandedName{space: xmlSignatureNamespace, local: "X509Data"},
		) || !exactElementChildren(x509Data,
			expandedName{space: xmlSignatureNamespace, local: "X509Certificate"},
		) {
			return signatureShape{}, ErrSignatureRejected
		}
		result.keyInfoCertificateCount = 1
	}
	return result, nil
}

func exactElementChildren(parent *etree.Element, expected ...expandedName) bool {
	if parent == nil {
		return false
	}
	children := parent.ChildElements()
	if len(children) != len(expected) {
		return false
	}
	for index, child := range children {
		if child.Tag != expected[index].local || child.NamespaceURI() != expected[index].space {
			return false
		}
	}
	return true
}

type encryptionAlgorithms struct{ content, transport, digest, mgf string }

func inspectEncryptionAlgorithms(encrypted *etree.Element) (encryptionAlgorithms, error) {
	contentMethod := directChild(encrypted, xmlEncryptionNamespace, "EncryptionMethod")
	keyInfo := directChild(encrypted, xmlSignatureNamespace, "KeyInfo")
	encryptedKey := directChild(keyInfo, xmlEncryptionNamespace, "EncryptedKey")
	transportMethod := directChild(encryptedKey, xmlEncryptionNamespace, "EncryptionMethod")
	if contentMethod == nil || transportMethod == nil {
		return encryptionAlgorithms{}, ErrEncryptionRejected
	}
	digest := directChild(transportMethod, xmlSignatureNamespace, "DigestMethod")
	mgf := directChild(transportMethod, xmlEncryption11NS, "MGF")
	if digest == nil || mgf == nil {
		return encryptionAlgorithms{}, ErrEncryptionRejected
	}
	return encryptionAlgorithms{
		content:   contentMethod.SelectAttrValue("Algorithm", ""),
		transport: transportMethod.SelectAttrValue("Algorithm", ""),
		digest:    digest.SelectAttrValue("Algorithm", ""), mgf: mgf.SelectAttrValue("Algorithm", ""),
	}, nil
}

func validSPKeyMaterial(
	material SPKeyMaterial,
	provider identity.ProviderContext,
	binding identity.EntityID,
	revision uint32,
	needSigner bool,
) bool {
	if material.Provider != provider || material.BindingID != binding || material.KeyRevision != revision ||
		needSigner && material.Signer == nil || !needSigner && material.RSADecrypter == nil {
		return false
	}
	if needSigner {
		return compatibleSignerPublicKey(material.Signer.Public()) &&
			validSignerCertificates(material.Signer.Public(), material.CertificateDER)
	}
	return material.RSADecrypter.N != nil && material.RSADecrypter.N.BitLen() >= 2048 &&
		material.RSADecrypter.E >= 65537 && material.RSADecrypter.D != nil &&
		len(material.RSADecrypter.Primes) >= 2 && material.RSADecrypter.Validate() == nil
}

func validDirectPlatformSPKeyMaterial(
	material DirectPlatformSPKeyMaterial,
	provider identity.ProviderContext,
	revision uint64,
	needSigner bool,
) bool {
	if material.Context.Provider != provider || !validEntityID(material.Context.KeyID) ||
		material.Context.KeyRevision != revision || !validPersistentRevision(revision) ||
		provider.Scope != identity.PlatformProviderScope || !validProvider(provider) ||
		needSigner && material.Signer == nil || !needSigner && material.RSADecrypter == nil {
		return false
	}
	if needSigner {
		return compatibleSignerPublicKey(material.Signer.Public()) &&
			validSignerCertificates(material.Signer.Public(), material.CertificateDER)
	}
	return material.RSADecrypter.N != nil && material.RSADecrypter.N.BitLen() >= 2048 &&
		material.RSADecrypter.E >= 65537 && material.RSADecrypter.D != nil &&
		len(material.RSADecrypter.Primes) >= 2 && material.RSADecrypter.Validate() == nil
}

// compatibleSignerPublicKey avoids accepting opaque signer implementations
// whose algorithm goxmldsig cannot bind to an admitted SignatureMethod.
func compatibleSignerPublicKey(public any) bool {
	switch key := public.(type) {
	case *rsa.PublicKey:
		return key.N != nil && key.N.BitLen() >= 2048 && key.E >= 65537
	case *ecdsa.PublicKey:
		return key.Curve != nil && key.X != nil && key.Y != nil && key.Curve.Params() != nil &&
			key.Curve.Params().BitSize >= 256 && key.Curve.IsOnCurve(key.X, key.Y)
	default:
		return false
	}
}

func validSignerCertificates(public any, certificates [][]byte) bool {
	if len(certificates) > 8 {
		return false
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return false
	}
	for index, der := range certificates {
		if len(der) == 0 || len(der) > maximumCertificateBytes {
			return false
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return false
		}
		if index == 0 && !bytes.Equal(certificate.RawSubjectPublicKeyInfo, publicDER) {
			return false
		}
	}
	return true
}

func findObjectByID(root *etree.Element, id string) (*etree.Element, int) {
	if root == nil {
		return nil, 0
	}
	var found *etree.Element
	count := 0
	var visit func(*etree.Element)
	visit = func(element *etree.Element) {
		if element.SelectAttrValue("ID", "") == id || element.SelectAttrValue("Id", "") == id {
			found, count = element, count+1
		}
		for _, child := range element.ChildElements() {
			visit(child)
		}
	}
	visit(root)
	return found, count
}

func objectMatchesKind(object *etree.Element, kind SignedObjectKind) bool {
	if object == nil {
		return false
	}
	return kind == SignedObjectResponse && object.Tag == "Response" && object.NamespaceURI() == samlProtocolNamespace ||
		kind == SignedObjectAssertion && object.Tag == "Assertion" && object.NamespaceURI() == samlAssertionNamespace
}

func directChild(parent *etree.Element, namespace, tag string) *etree.Element {
	if parent == nil {
		return nil
	}
	for _, child := range parent.ChildElements() {
		if child.Tag == tag && child.NamespaceURI() == namespace {
			return child
		}
	}
	return nil
}

func directChildren(parent *etree.Element, namespace, tag string) []*etree.Element {
	if parent == nil {
		return nil
	}
	result := make([]*etree.Element, 0, 2)
	for _, child := range parent.ChildElements() {
		if child.Tag == tag && child.NamespaceURI() == namespace {
			result = append(result, child)
		}
	}
	return result
}

func cloneBytes2DAdapter(source [][]byte) [][]byte {
	result := make([][]byte, len(source))
	for index := range source {
		result[index] = append([]byte(nil), source[index]...)
	}
	return result
}
