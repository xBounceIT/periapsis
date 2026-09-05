package federatedsaml

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const (
	exclusiveCanonicalization   = "http://www.w3.org/2001/10/xml-exc-c14n#"
	envelopedSignatureTransform = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	digestSHA256                = "http://www.w3.org/2001/04/xmlenc#sha256"
	digestSHA384                = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	digestSHA512                = "http://www.w3.org/2001/04/xmlenc#sha512"
	aes128GCM                   = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	aes192GCM                   = "http://www.w3.org/2009/xmlenc11#aes192-gcm"
	aes256GCM                   = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	rsaOAEP11                   = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
	mgf1SHA256                  = "http://www.w3.org/2009/xmlenc11#mgf1sha256"
	mgf1SHA384                  = "http://www.w3.org/2009/xmlenc11#mgf1sha384"
	mgf1SHA512                  = "http://www.w3.org/2009/xmlenc11#mgf1sha512"
	maximumReturnPathBytes      = 2048
	maximumPersistentRevision   = uint64(9_007_199_254_740_991)
)

func New(options Options) (*Kernel, error) {
	return newKernel(options, rand.Reader, time.Now)
}

func newKernel(options Options, random io.Reader, now func() time.Time) (*Kernel, error) {
	limits := options.Limits
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	if options.Transactions == nil || options.RedirectSigner == nil ||
		options.SignatureVerifier == nil || options.AssertionDecrypter == nil ||
		options.SessionProtector == nil || random == nil || now == nil ||
		!validLimits(limits) || options.TransactionTTL < time.Minute ||
		options.TransactionTTL > 15*time.Minute || options.OperationTimeout < 100*time.Millisecond ||
		options.OperationTimeout > 2*time.Minute || !alignedDuration(options.TransactionTTL) ||
		!alignedDuration(options.OperationTimeout) || !validAuthorityValue(options.Authority) {
		return nil, ErrInvalidOptions
	}
	return &Kernel{
		authority:    options.Authority,
		transactions: options.Transactions, redirectSigner: options.RedirectSigner,
		signatureVerifier: options.SignatureVerifier, assertionDecrypter: options.AssertionDecrypter,
		sessionProtector: options.SessionProtector, limits: limits,
		transactionTTL: options.TransactionTTL, operationTimeout: options.OperationTimeout,
		random: random, now: now,
	}, nil
}

func alignedDuration(value time.Duration) bool { return value%time.Microsecond == 0 }

func validLimits(value Limits) bool {
	defaults := DefaultLimits()
	return value.MaxMetadataBytes >= 16*1024 && value.MaxMetadataBytes <= defaults.MaxMetadataBytes &&
		value.MaxEncodedResponseBytes >= 64*1024 && value.MaxEncodedResponseBytes <= defaults.MaxEncodedResponseBytes &&
		value.MaxDecodedResponseBytes >= 64*1024 && value.MaxDecodedResponseBytes <= defaults.MaxDecodedResponseBytes &&
		value.MaxDecryptedAssertionBytes >= 32*1024 && value.MaxDecryptedAssertionBytes <= defaults.MaxDecryptedAssertionBytes &&
		value.MaxXMLDepth >= 8 && value.MaxXMLDepth <= defaults.MaxXMLDepth &&
		value.MaxXMLNodes >= 128 && value.MaxXMLNodes <= defaults.MaxXMLNodes &&
		value.MaxXMLAttributes >= 256 && value.MaxXMLAttributes <= defaults.MaxXMLAttributes &&
		value.MaxXMLTextBytes >= 32*1024 && value.MaxXMLTextBytes <= defaults.MaxXMLTextBytes &&
		value.MaxCertificates >= 1 && value.MaxCertificates <= defaults.MaxCertificates &&
		value.MaxAttributes >= 1 && value.MaxAttributes <= defaults.MaxAttributes &&
		value.MaxValuesPerAttribute >= 1 && value.MaxValuesPerAttribute <= defaults.MaxValuesPerAttribute &&
		value.MaxMappedScalars >= 1 && value.MaxMappedScalars <= defaults.MaxMappedScalars &&
		value.MaxMappedProfiles >= 1 && value.MaxMappedProfiles <= defaults.MaxMappedProfiles &&
		value.MaxGroups >= 1 && value.MaxGroups <= defaults.MaxGroups
}

func operationContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	return bounded, cancel, nil
}

func canonicalNow(now func() time.Time) (time.Time, error) {
	value := now()
	if value.IsZero() {
		return time.Time{}, errors.New("invalid clock")
	}
	return value.UTC().Truncate(time.Microsecond), nil
}

func validProvider(value identity.ProviderContext) bool {
	zero := identity.EntityID{}
	if value.ProviderID == zero {
		return false
	}
	switch value.Scope {
	case identity.TenantProviderScope:
		return value.TenantID != zero
	case identity.PlatformProviderScope:
		return value.TenantID == zero
	default:
		return false
	}
}

func validAuthorityValue(value CeremonyAuthority) bool {
	return value == TenantCeremonyAuthority || value == DirectPlatformCeremonyAuthority
}

func validCeremonyContext(
	authority CeremonyAuthority,
	provider identity.ProviderContext,
	bindingID identity.EntityID,
	platformLoginRevision uint64,
) bool {
	zeroID := identity.EntityID{}
	switch authority {
	case TenantCeremonyAuthority:
		return provider.Scope == identity.TenantProviderScope && provider.TenantID != zeroID &&
			provider.ProviderID != zeroID && bindingID != zeroID && platformLoginRevision == 0
	case DirectPlatformCeremonyAuthority:
		return provider.Scope == identity.PlatformProviderScope && provider.TenantID == zeroID &&
			provider.ProviderID != zeroID && bindingID == zeroID && validPersistentRevision(platformLoginRevision)
	default:
		return false
	}
}

func validCeremonyAuthority(
	authority CeremonyAuthority,
	provider identity.ProviderContext,
	bindingID identity.EntityID,
	bindingRevision uint64,
	mappingRevision uint64,
	authorizationRevision uint64,
	platformLoginRevision uint64,
	planRevision uint64,
) bool {
	if !validCeremonyContext(authority, provider, bindingID, platformLoginRevision) {
		return false
	}
	switch authority {
	case TenantCeremonyAuthority:
		return validPersistentRevision(bindingRevision) && validPersistentRevision(mappingRevision) &&
			validPersistentRevision(authorizationRevision) && planRevision == 0
	case DirectPlatformCeremonyAuthority:
		return bindingRevision == 0 && mappingRevision == 0 && authorizationRevision == 0 &&
			validPersistentRevision(planRevision)
	default:
		return false
	}
}

func validEntityID(value identity.EntityID) bool { return value != (identity.EntityID{}) }

func validUUIDv7(value identity.EntityID) bool {
	return value != (identity.EntityID{}) && value[6]>>4 == 7 && value[8]&0xc0 == 0x80
}

func validPersistentRevision(value uint64) bool {
	return value > 0 && value <= maximumPersistentRevision
}

func validPersistentSuccessorRevision(value uint64) bool {
	return value > 0 && value < maximumPersistentRevision
}

func validAuthenticationBegin(value AuthenticationBegin) bool {
	operationID := value.OperationRunID
	receipt := [sha256.Size]byte(value.ReceiptDigest)
	network := [sha256.Size]byte(value.NetworkDigest)
	account := [sha256.Size]byte(value.AccountDigest)
	provider := [sha256.Size]byte(value.ProviderDigest)
	return validUUIDv7(operationID) &&
		receipt != ([sha256.Size]byte{}) && network != ([sha256.Size]byte{}) &&
		account != ([sha256.Size]byte{}) && provider != ([sha256.Size]byte{}) &&
		receipt != network && receipt != account && receipt != provider &&
		network != account && network != provider && account != provider
}

func validOpaque(value []byte) bool {
	return len(value) == minimumOpaqueBytes && !allZero(value)
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func randomOpaque(reader io.Reader) ([]byte, error) {
	value := make([]byte, minimumOpaqueBytes)
	if _, err := io.ReadFull(reader, value); err != nil || allZero(value) {
		return nil, errors.New("opaque value generation failed")
	}
	return value, nil
}

func digestOpaque(value []byte) [sha256.Size]byte { return sha256.Sum256(value) }

func digestFields(fields ...[]byte) [sha256.Size]byte {
	hash := sha256.New()
	var size [8]byte
	for _, field := range fields {
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write(field)
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func validBoundedString(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		validXMLText(value) && noControlCharacters(value)
}

func validReturnPath(value string) bool {
	if value == "" || len(value) > maximumReturnPathBytes || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\\") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || strings.ContainsRune(parsed.Path, '\\') || !noControlCharacters(parsed.Path) {
		return false
	}
	decodedQuery, err := url.QueryUnescape(parsed.RawQuery)
	return err == nil && noControlCharacters(decodedQuery) && parsed.IsAbs() == false && parsed.Host == "" && parsed.User == nil &&
		strings.HasPrefix(parsed.Path, "/") && !strings.HasPrefix(parsed.Path, "//") &&
		path.Clean(parsed.Path) == parsed.Path && parsed.Fragment == ""
}

func noControlCharacters(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func canonicalHTTPSURL(raw string, maximum int) (string, bool) {
	if !validBoundedString(raw, maximum) {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawQuery != "" || parsed.Opaque != "" || parsed.RawPath != "" {
		return "", false
	}
	if parsed.Hostname() == "" || strings.Contains(parsed.Host, "%") || strings.HasSuffix(parsed.Host, ".") {
		return "", false
	}
	parsed.Scheme = "https"
	parsed.Host = strings.ToLower(parsed.Host)
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	if path.Clean(parsed.Path) != parsed.Path || strings.Contains(parsed.EscapedPath(), "%2f") || strings.Contains(parsed.EscapedPath(), "%2F") {
		return "", false
	}
	return parsed.String(), true
}

func canonicalACSURL(value string, authority CeremonyAuthority) bool {
	canonical, valid := canonicalHTTPSURL(value, maximumEndpointBytes)
	if !valid || canonical != value {
		return false
	}
	parsed, _ := url.Parse(value)
	switch authority {
	case TenantCeremonyAuthority:
		return parsed.Path == samlACSPath
	case DirectPlatformCeremonyAuthority:
		return parsed.Path == directPlatformSAMLACSPath
	default:
		return false
	}
}

func cloneJITAuthentication(value JITAuthentication) JITAuthentication {
	result := value
	result.scalars = append([]NamedScalar(nil), value.scalars...)
	result.profiles = append([]ProfileValue(nil), value.profiles...)
	result.groups = append([]string(nil), value.groups...)
	if value.assurance != nil {
		result.assurance = value.AssuranceEvidence()
	}
	return result
}

func decodeCanonicalBase64(value string, maximum int) ([]byte, error) {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return nil, errors.New("base64 rejected")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || base64.StdEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, errors.New("base64 rejected")
	}
	return decoded, nil
}

func compareDigest(left, right [sha256.Size]byte) bool {
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}
