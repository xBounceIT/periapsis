package federatedsaml

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"slices"
	"strings"
	"time"
)

func validEncryptionShape(policy EncryptionPolicy, encrypted bool) bool {
	switch policy {
	case EncryptionDisabled:
		return !encrypted
	case EncryptionOptional:
		return true
	case EncryptionRequired:
		return encrypted
	default:
		return false
	}
}

func (kernel *Kernel) verifyResponseSignature(
	ctx context.Context,
	configuration Configuration,
	document []byte,
	response parsedResponse,
	now time.Time,
) error {
	required := configuration.SignaturePolicy == SignedResponse || configuration.SignaturePolicy == SignedBoth
	if response.hasSignature != required {
		return ErrSignatureRejected
	}
	count := countSignatureDocuments(response.assertion, response.hasSignature)
	if response.encrypted {
		count = boolInt(response.hasSignature)
	}
	if count > 2 || response.encrypted && count != boolInt(response.hasSignature) {
		return ErrSignatureRejected
	}
	if !required {
		return nil
	}
	return kernel.verifyOneSignature(ctx, configuration, document, SignedObjectResponse, response.id, now)
}

func (kernel *Kernel) verifyAssertionSignature(
	ctx context.Context,
	configuration Configuration,
	responseDocument []byte,
	response parsedResponse,
	assertionDocument []byte,
	assertion parsedAssertion,
	now time.Time,
) error {
	required := configuration.SignaturePolicy == SignedAssertion || configuration.SignaturePolicy == SignedBoth
	if assertion.hasSignature != required {
		return ErrSignatureRejected
	}
	expectedCount := boolInt(response.hasSignature) + boolInt(assertion.hasSignature)
	if response.encrypted {
		if countNamedXMLSignature(assertionDocument, kernel.limits) != boolInt(assertion.hasSignature) {
			return ErrSignatureRejected
		}
	} else if countNamedXMLSignature(responseDocument, kernel.limits) != expectedCount {
		return ErrSignatureRejected
	}
	if !required {
		return nil
	}
	return kernel.verifyOneSignature(ctx, configuration, assertionDocument, SignedObjectAssertion, assertion.id, now)
}

func (kernel *Kernel) verifyOneSignature(
	ctx context.Context,
	configuration Configuration,
	document []byte,
	kind SignedObjectKind,
	objectID string,
	now time.Time,
) error {
	request := SignatureVerificationRequest{
		Authority: configuration.Authority, Provider: configuration.Provider, BindingID: configuration.BindingID,
		PlatformLoginRevision: configuration.PlatformLoginRevision,
		Document:              append([]byte(nil), document...), ObjectKind: kind, ObjectID: objectID,
		Metadata: configuration.Metadata,
	}
	proof, err := kernel.signatureVerifier.VerifyXMLSignature(ctx, request)
	clear(request.Document)
	if err != nil || proof.ObjectKind != kind || proof.ObjectID != objectID ||
		!validDirectSignatureProofAuthority(proof, configuration) ||
		proof.ReferenceURI != "#"+objectID || proof.DocumentDigest != sha256.Sum256(document) ||
		proof.ReferenceCount != 1 || proof.KeyInfoCertificateCount < 0 || proof.KeyInfoCertificateCount > 1 ||
		proof.MatchingCertificateCount != 1 ||
		proof.CanonicalizationParameterCount != 0 || proof.TransformParameterCount != 0 ||
		proof.ExternalDereferenceCount != 0 ||
		!validXMLSignatureAlgorithm(proof.SignatureAlgorithm) || !validDigestAlgorithm(proof.DigestAlgorithm) ||
		proof.CanonicalizationAlgorithm != exclusiveCanonicalization ||
		!slices.Equal(proof.Transforms, []string{envelopedSignatureTransform, exclusiveCanonicalization}) ||
		!trustedCertificateAt(configuration.Metadata, proof.CertificateFingerprintSHA256, proof.SignatureAlgorithm, now) {
		return ErrSignatureRejected
	}
	return nil
}

func validDirectSignatureProofAuthority(proof SignatureVerificationResult, configuration Configuration) bool {
	if configuration.Authority == TenantCeremonyAuthority {
		return true
	}
	return configuration.Authority == DirectPlatformCeremonyAuthority &&
		proof.Authority == configuration.Authority && proof.Provider == configuration.Provider &&
		proof.BindingID == configuration.BindingID &&
		proof.PlatformLoginRevision == configuration.PlatformLoginRevision
}

func validXMLSignatureAlgorithm(value string) bool {
	switch RedirectSignatureAlgorithm(value) {
	case RedirectRSASHA256, RedirectRSASHA384, RedirectRSASHA512,
		RedirectECDSASHA256, RedirectECDSASHA384, RedirectECDSASHA512:
		return true
	default:
		return false
	}
}

func trustedCertificateAt(metadata MetadataSnapshot, fingerprint [sha256.Size]byte, signatureAlgorithm string, now time.Time) bool {
	for _, summary := range metadata.certificateSummaries {
		if summary.FingerprintSHA256 == fingerprint && !now.Before(summary.NotBefore) && now.Before(summary.NotAfter) &&
			compatibleSignatureKey(summary.PublicKeyAlgorithm, signatureAlgorithm) {
			return true
		}
	}
	return false
}

func compatibleSignatureKey(algorithm x509.PublicKeyAlgorithm, signatureAlgorithm string) bool {
	if strings.Contains(signatureAlgorithm, "rsa-sha") {
		return algorithm == x509.RSA
	}
	if strings.Contains(signatureAlgorithm, "ecdsa-sha") {
		return algorithm == x509.ECDSA
	}
	return false
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func countSignatureDocuments(assertion *xmlNode, responseSignature bool) int {
	count := boolInt(responseSignature)
	if assertion != nil {
		count += countNamed(assertion, expandedName{space: xmlSignatureNamespace, local: "Signature"})
	}
	return count
}

func countNamedXMLSignature(document []byte, limits Limits) int {
	root, err := parseBoundedXML(document, max(limits.MaxDecodedResponseBytes, limits.MaxDecryptedAssertionBytes), limits)
	if err != nil {
		return -1
	}
	return countNamed(root, expandedName{space: xmlSignatureNamespace, local: "Signature"})
}
