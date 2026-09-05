package federatedsaml

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"
)

// LoadMetadata invokes only the injected provider-bound source, then compiles
// its bounded result. No ambient resolver, proxy, or HTTP client is used.
func LoadMetadata(
	ctx context.Context,
	source MetadataSource,
	request MetadataLoadRequest,
	limits Limits,
	operationTimeout time.Duration,
) (MetadataSnapshot, error) {
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	if source == nil || !validProvider(request.Provider) || !validEntityID(request.BindingID) ||
		!validBoundedString(request.ExpectedEntityID, maximumEntityIDBytes) || request.Revision == 0 ||
		!validInstant(request.MaximumValidUntil) || !validLimits(limits) ||
		operationTimeout < 100*time.Millisecond || operationTimeout > 2*time.Minute || !alignedDuration(operationTimeout) {
		return MetadataSnapshot{}, ErrInvalidMetadata
	}
	bounded, cancel, err := operationContext(ctx, operationTimeout)
	if err != nil {
		return MetadataSnapshot{}, errors.Join(ErrInvalidMetadata, err)
	}
	defer cancel()
	document, err := source.LoadSAMLMetadata(bounded, request, limits.MaxMetadataBytes)
	if err != nil || len(document.Document) > limits.MaxMetadataBytes {
		return MetadataSnapshot{}, ErrInvalidMetadata
	}
	return CompileMetadata(MetadataCompilationRequest{
		Document: append([]byte(nil), document.Document...), ExpectedEntityID: request.ExpectedEntityID,
		Revision: request.Revision, RetrievedAt: document.RetrievedAt,
		MaximumValidUntil: request.MaximumValidUntil,
	}, limits)
}

// CompileMetadata turns one already-fetched metadata document into an
// immutable trust snapshot. It performs no discovery or network I/O.
func CompileMetadata(request MetadataCompilationRequest, limits Limits) (MetadataSnapshot, error) {
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	if !validLimits(limits) || request.Revision == 0 ||
		!validBoundedString(request.ExpectedEntityID, maximumEntityIDBytes) ||
		!validInstant(request.RetrievedAt) || !validInstant(request.MaximumValidUntil) ||
		!request.MaximumValidUntil.After(request.RetrievedAt) ||
		request.MaximumValidUntil.Sub(request.RetrievedAt) > 31*24*time.Hour {
		return MetadataSnapshot{}, ErrInvalidMetadata
	}
	root, err := parseBoundedXML(request.Document, limits.MaxMetadataBytes, limits)
	if err != nil || root.name != (expandedName{space: samlMetadataNamespace, local: "EntityDescriptor"}) {
		return MetadataSnapshot{}, ErrInvalidMetadata
	}
	entityID, _, err := attribute(root, "", "entityID", true, maximumEntityIDBytes)
	if err != nil || entityID != request.ExpectedEntityID {
		return MetadataSnapshot{}, ErrInvalidMetadata
	}
	validUntilRaw, _, err := attribute(root, "", "validUntil", true, 64)
	if err != nil || !allowedAttributes(root,
		expandedName{local: "entityID"}, expandedName{local: "validUntil"}, expandedName{local: "ID"}) ||
		len(root.children) != 1 || strings.TrimSpace(root.text) != "" {
		return MetadataSnapshot{}, ErrInvalidMetadata
	}
	validUntil, err := parseSAMLInstant(validUntilRaw)
	if err != nil || !validUntil.After(request.RetrievedAt) || validUntil.After(request.MaximumValidUntil) {
		return MetadataSnapshot{}, ErrInvalidMetadata
	}
	idp := root.children[0]
	if idp.name != (expandedName{space: samlMetadataNamespace, local: "IDPSSODescriptor"}) {
		return MetadataSnapshot{}, ErrInvalidMetadata
	}
	protocols, _, err := attribute(idp, "", "protocolSupportEnumeration", true, 1024)
	if err != nil || protocols != samlProtocolEnumeration || !allowedAttributes(idp,
		expandedName{local: "protocolSupportEnumeration"}, expandedName{local: "ID"},
		expandedName{local: "WantAuthnRequestsSigned"}) || strings.TrimSpace(idp.text) != "" {
		return MetadataSnapshot{}, ErrInvalidMetadata
	}
	if value, present, attributeErr := attribute(idp, "", "WantAuthnRequestsSigned", false, 5); attributeErr != nil ||
		present && value != "true" {
		return MetadataSnapshot{}, ErrInvalidMetadata
	}

	var ssoURL, sloURL string
	certificates := make([][]byte, 0, limits.MaxCertificates)
	for _, child := range idp.children {
		switch child.name {
		case expandedName{space: samlMetadataNamespace, local: "KeyDescriptor"}:
			certificate, parseErr := parseSigningKeyDescriptor(child)
			if parseErr != nil {
				return MetadataSnapshot{}, ErrInvalidMetadata
			}
			certificates = append(certificates, certificate)
			if len(certificates) > limits.MaxCertificates {
				return MetadataSnapshot{}, ErrInvalidMetadata
			}
		case expandedName{space: samlMetadataNamespace, local: "SingleSignOnService"}:
			endpoint, endpointErr := parseMetadataEndpoint(child, "SingleSignOnService")
			if endpointErr != nil || ssoURL != "" {
				return MetadataSnapshot{}, ErrInvalidMetadata
			}
			ssoURL = endpoint
		case expandedName{space: samlMetadataNamespace, local: "SingleLogoutService"}:
			endpoint, endpointErr := parseMetadataEndpoint(child, "SingleLogoutService")
			if endpointErr != nil || sloURL != "" {
				return MetadataSnapshot{}, ErrInvalidMetadata
			}
			sloURL = endpoint
		default:
			return MetadataSnapshot{}, ErrInvalidMetadata
		}
	}
	if ssoURL == "" || len(certificates) == 0 {
		return MetadataSnapshot{}, ErrInvalidMetadata
	}

	summaries := make([]CertificateSummary, 0, len(certificates))
	derByFingerprint := make(map[[sha256.Size]byte][]byte, len(certificates))
	currentCertificates := 0
	for _, der := range certificates {
		certificate, parseErr := x509.ParseCertificate(der)
		if parseErr != nil || certificate.IsCA || !request.RetrievedAt.Before(certificate.NotAfter.UTC()) ||
			!certificate.NotBefore.UTC().Before(validUntil) ||
			certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return MetadataSnapshot{}, ErrInvalidMetadata
		}
		bits, keyValid := publicKeyBits(certificate.PublicKey)
		if !keyValid {
			return MetadataSnapshot{}, ErrInvalidMetadata
		}
		if !request.RetrievedAt.Before(certificate.NotBefore.UTC()) && request.RetrievedAt.Before(certificate.NotAfter.UTC()) {
			currentCertificates++
		}
		fingerprint := sha256.Sum256(der)
		if _, duplicate := derByFingerprint[fingerprint]; duplicate {
			return MetadataSnapshot{}, ErrInvalidMetadata
		}
		derByFingerprint[fingerprint] = append([]byte(nil), der...)
		summaries = append(summaries, CertificateSummary{
			FingerprintSHA256: fingerprint, NotBefore: certificate.NotBefore.UTC(),
			NotAfter: certificate.NotAfter.UTC(), PublicKeyAlgorithm: certificate.PublicKeyAlgorithm,
			Bits: bits,
		})
	}
	if currentCertificates == 0 {
		return MetadataSnapshot{}, ErrInvalidMetadata
	}
	slices.SortFunc(summaries, func(left, right CertificateSummary) int {
		return bytes.Compare(left.FingerprintSHA256[:], right.FingerprintSHA256[:])
	})
	orderedDER := make([][]byte, len(summaries))
	for index, summary := range summaries {
		orderedDER[index] = derByFingerprint[summary.FingerprintSHA256]
	}
	return MetadataSnapshot{
		revision: request.Revision, digest: sha256.Sum256(request.Document),
		retrievedAt: request.RetrievedAt.UTC(), validUntil: validUntil,
		entityID: entityID, ssoRedirectURL: ssoURL, sloRedirectURL: sloURL,
		certificateSummaries: summaries, certificateDER: orderedDER, valid: true,
	}, nil
}

func parseSigningKeyDescriptor(node *xmlNode) ([]byte, error) {
	if !allowedAttributes(node, expandedName{local: "use"}) || strings.TrimSpace(node.text) != "" {
		return nil, errors.New("key descriptor rejected")
	}
	use, present, err := attribute(node, "", "use", false, 32)
	if err != nil || present && use != "signing" {
		return nil, errors.New("key descriptor rejected")
	}
	if len(node.children) != 1 || node.children[0].name != (expandedName{space: xmlSignatureNamespace, local: "KeyInfo"}) {
		return nil, errors.New("key descriptor rejected")
	}
	keyInfo := node.children[0]
	if !allowedAttributes(keyInfo, expandedName{local: "ID"}) || len(keyInfo.children) != 1 ||
		strings.TrimSpace(keyInfo.text) != "" || keyInfo.children[0].name != (expandedName{space: xmlSignatureNamespace, local: "X509Data"}) {
		return nil, errors.New("key descriptor rejected")
	}
	x509Data := keyInfo.children[0]
	if !allowedAttributes(x509Data) || len(x509Data.children) != 1 || strings.TrimSpace(x509Data.text) != "" ||
		x509Data.children[0].name != (expandedName{space: xmlSignatureNamespace, local: "X509Certificate"}) {
		return nil, errors.New("key descriptor rejected")
	}
	encoded, err := simpleElementText(x509Data.children[0], base64.StdEncoding.EncodedLen(maximumCertificateBytes))
	if err != nil {
		return nil, errors.New("key descriptor rejected")
	}
	der, err := decodeCanonicalBase64(encoded, base64.StdEncoding.EncodedLen(maximumCertificateBytes))
	if err != nil || len(der) > maximumCertificateBytes {
		return nil, errors.New("key descriptor rejected")
	}
	return der, nil
}

func parseMetadataEndpoint(node *xmlNode, expected string) (string, error) {
	if node.name != (expandedName{space: samlMetadataNamespace, local: expected}) ||
		!allowedAttributes(node, expandedName{local: "Binding"}, expandedName{local: "Location"}) ||
		len(node.children) != 0 || strings.TrimSpace(node.text) != "" {
		return "", errors.New("endpoint rejected")
	}
	binding, _, err := attribute(node, "", "Binding", true, 512)
	if err != nil || binding != samlHTTPRedirectBinding {
		return "", errors.New("endpoint rejected")
	}
	location, _, err := attribute(node, "", "Location", true, maximumEndpointBytes)
	if err != nil {
		return "", errors.New("endpoint rejected")
	}
	canonical, valid := canonicalHTTPSURL(location, maximumEndpointBytes)
	if !valid || canonical != location {
		return "", errors.New("endpoint rejected")
	}
	return canonical, nil
}

func publicKeyBits(publicKey any) (int, bool) {
	switch value := publicKey.(type) {
	case *rsa.PublicKey:
		bits := value.N.BitLen()
		return bits, bits >= 2048 && bits <= 8192 && value.E >= 65537 && value.E%2 == 1
	case *ecdsa.PublicKey:
		if value.Curve == nil {
			return 0, false
		}
		bits := value.Curve.Params().BitSize
		return bits, bits == 256 || bits == 384 || bits == 521
	default:
		return 0, false
	}
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
}

func parseSAMLInstant(value string) (time.Time, error) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New("instant rejected")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Nanosecond()%1_000 != 0 {
		return time.Time{}, errors.New("instant rejected")
	}
	return parsed.UTC(), nil
}

// AssessMetadataRollover requires protected approval when the new trust set
// has no certificate overlap or changes a browser-facing endpoint.
func AssessMetadataRollover(previous, next MetadataSnapshot) (RolloverAssessment, error) {
	if !previous.valid || !next.valid || next.revision <= previous.revision ||
		previous.entityID != next.entityID || compareDigest(previous.digest, next.digest) {
		return RolloverAssessment{}, ErrMetadataRolloverRejected
	}
	oldSet := make(map[[sha256.Size]byte]struct{}, len(previous.certificateSummaries))
	for _, summary := range previous.certificateSummaries {
		oldSet[summary.FingerprintSHA256] = struct{}{}
	}
	newSet := make(map[[sha256.Size]byte]struct{}, len(next.certificateSummaries))
	overlap := 0
	for _, summary := range next.certificateSummaries {
		newSet[summary.FingerprintSHA256] = struct{}{}
		if _, found := oldSet[summary.FingerprintSHA256]; found {
			overlap++
		}
	}
	added, removed := 0, 0
	for fingerprint := range newSet {
		if _, found := oldSet[fingerprint]; !found {
			added++
		}
	}
	for fingerprint := range oldSet {
		if _, found := newSet[fingerprint]; !found {
			removed++
		}
	}
	decision := RolloverAutomatic
	if overlap == 0 || previous.ssoRedirectURL != next.ssoRedirectURL || previous.sloRedirectURL != next.sloRedirectURL {
		decision = RolloverProtectedApproval
	}
	return RolloverAssessment{Decision: decision, OverlappingFingerprints: overlap, AddedFingerprints: added, RemovedFingerprints: removed}, nil
}
