package federatedauth

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/netip"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const (
	samlNetworkRatePurpose    = "periapsis/federated-auth/saml-start/network/v1"
	samlAccountRatePurpose    = "periapsis/federated-auth/saml-start/account/v1"
	samlProviderRatePurpose   = "periapsis/federated-auth/saml-start/provider/v1"
	samlStartDigestKeyPurpose = "periapsis/federated-auth/saml-start/hmac-sha256/key/v1"
)

// SAMLStartDigester derives the anonymous start receipt and independently
// purpose-separated database throttle keys. Construction retains only an
// HKDF-derived SAML key; the deployment-owned source key is never retained,
// formatted, or returned.
type SAMLStartDigester struct {
	key []byte
}

func NewSAMLStartDigester(sourceKey []byte) (*SAMLStartDigester, error) {
	if len(sourceKey) < minimumOIDCStartDigestKeyBytes || len(sourceKey) > maximumOIDCStartDigestKeyBytes ||
		allZeroOIDCStartBytes(sourceKey) {
		return nil, ErrInvalidOptions
	}
	derived, err := hkdf.Key(
		sha256.New,
		sourceKey,
		[]byte(startDigestHKDFSalt),
		samlStartDigestKeyPurpose,
		startDigestDerivedKeyBytes,
	)
	if err != nil || len(derived) != startDigestDerivedKeyBytes || allZeroOIDCStartBytes(derived) {
		clear(derived)
		return nil, ErrInvalidOptions
	}
	return &SAMLStartDigester{key: derived}, nil
}

func (digester *SAMLStartDigester) String() string {
	return fmt.Sprintf("federatedauth.SAMLStartDigester{configured:%t}", digester != nil && len(digester.key) != 0)
}
func (digester *SAMLStartDigester) GoString() string { return digester.String() }

func (digester *SAMLStartDigester) BuildLookup(
	operationRunID identity.EntityID,
	receipt []byte,
	tenantSlug string,
	loginKey string,
	network string,
) (SAMLStartLookup, error) {
	address, err := netip.ParseAddr(network)
	if digester == nil || len(digester.key) < minimumOIDCStartDigestKeyBytes ||
		len(receipt) != oidcStartReceiptBytes || allZeroOIDCStartBytes(receipt) ||
		operationRunID == (identity.EntityID{}) || operationRunID[6]>>4 != 7 || operationRunID[8]&0xc0 != 0x80 ||
		!tenantOIDCSlugPattern.MatchString(tenantSlug) || !tenantOIDCLoginKeyPattern.MatchString(loginKey) ||
		err != nil || address.Zone() != "" || address.String() != network {
		return SAMLStartLookup{}, ErrInvalidInput
	}
	receiptDigest := sha256.Sum256(receipt)
	lookup := SAMLStartLookup{
		OperationRunID: operationRunID,
		ReceiptDigest:  SAMLStartReceiptDigest(receiptDigest),
		TenantSlug:     tenantSlug,
		LoginKey:       loginKey,
		NetworkDigest: SAMLNetworkRateDigest(
			digester.digest(samlNetworkRatePurpose, []byte(network)),
		),
		AccountDigest: SAMLAccountRateDigest(
			digester.digest(samlAccountRatePurpose, []byte(tenantSlug)),
		),
		ProviderDigest: SAMLProviderRateDigest(
			digester.digest(samlProviderRatePurpose, []byte(tenantSlug), []byte(loginKey)),
		),
	}
	if !validSAMLStartLookup(lookup) {
		return SAMLStartLookup{}, ErrInvalidInput
	}
	return lookup, nil
}

func (digester *SAMLStartDigester) digest(purpose string, fields ...[]byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, digester.key)
	writeOIDCDigestField(mac, []byte(purpose))
	for _, field := range fields {
		writeOIDCDigestField(mac, field)
	}
	bytes := mac.Sum(nil)
	defer clear(bytes)
	var result [sha256.Size]byte
	copy(result[:], bytes)
	return result
}
