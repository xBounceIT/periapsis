package federatedauth

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const (
	minimumOIDCStartDigestKeyBytes = 32
	maximumOIDCStartDigestKeyBytes = 128
	oidcStartReceiptBytes          = 32
	startDigestDerivedKeyBytes     = sha256.Size
	startDigestHKDFSalt            = "periapsis/federated-auth/start-digest/hkdf-sha256/v1"
	oidcStartDigestKeyPurpose      = "periapsis/federated-auth/oidc-start/hmac-sha256/key/v1"

	oidcNetworkRatePurpose  = "periapsis/federated-auth/oidc-start/network/v1"
	oidcAccountRatePurpose  = "periapsis/federated-auth/oidc-start/account/v1"
	oidcProviderRatePurpose = "periapsis/federated-auth/oidc-start/provider/v1"
)

// OIDCStartDigester derives the public-start receipt and independently
// purpose-separated database throttle keys. Construction retains only an
// HKDF-derived OIDC key; the deployment-owned source key is never retained,
// formatted, or returned.
type OIDCStartDigester struct {
	key []byte
}

func NewOIDCStartDigester(sourceKey []byte) (*OIDCStartDigester, error) {
	if len(sourceKey) < minimumOIDCStartDigestKeyBytes || len(sourceKey) > maximumOIDCStartDigestKeyBytes ||
		allZeroOIDCStartBytes(sourceKey) {
		return nil, ErrInvalidOptions
	}
	derived, err := hkdf.Key(
		sha256.New,
		sourceKey,
		[]byte(startDigestHKDFSalt),
		oidcStartDigestKeyPurpose,
		startDigestDerivedKeyBytes,
	)
	if err != nil || len(derived) != startDigestDerivedKeyBytes || allZeroOIDCStartBytes(derived) {
		clear(derived)
		return nil, ErrInvalidOptions
	}
	return &OIDCStartDigester{key: derived}, nil
}

func (digester *OIDCStartDigester) String() string {
	return fmt.Sprintf("federatedauth.OIDCStartDigester{configured:%t}", digester != nil && len(digester.key) != 0)
}
func (digester *OIDCStartDigester) GoString() string { return digester.String() }

// BuildLookup treats the canonical tenant slug as the non-oracular account
// throttle dimension and (tenant slug, login key) as the provider dimension.
// Network must be a canonical unzoned IP string established by the trusted
// request boundary. Receipt is the raw 256-bit browser secret; only SHA-256 is
// returned to persistence.
func (digester *OIDCStartDigester) BuildLookup(
	operationRunID identity.EntityID,
	receipt []byte,
	tenantSlug string,
	loginKey string,
	network string,
) (OIDCStartLookup, error) {
	address, err := netip.ParseAddr(network)
	if digester == nil || len(digester.key) < minimumOIDCStartDigestKeyBytes ||
		len(receipt) != oidcStartReceiptBytes || allZeroOIDCStartBytes(receipt) ||
		operationRunID == (identity.EntityID{}) || operationRunID[6]>>4 != 7 || operationRunID[8]&0xc0 != 0x80 ||
		!tenantOIDCSlugPattern.MatchString(tenantSlug) || !tenantOIDCLoginKeyPattern.MatchString(loginKey) ||
		err != nil || address.Zone() != "" || address.String() != network {
		return OIDCStartLookup{}, ErrInvalidInput
	}
	receiptDigest := sha256.Sum256(receipt)
	lookup := OIDCStartLookup{
		OperationRunID: operationRunID,
		ReceiptDigest:  OIDCStartReceiptDigest(receiptDigest),
		TenantSlug:     tenantSlug,
		LoginKey:       loginKey,
		NetworkDigest: OIDCNetworkRateDigest(
			digester.digest(oidcNetworkRatePurpose, []byte(network)),
		),
		AccountDigest: OIDCAccountRateDigest(
			digester.digest(oidcAccountRatePurpose, []byte(tenantSlug)),
		),
		ProviderDigest: OIDCProviderRateDigest(
			digester.digest(oidcProviderRatePurpose, []byte(tenantSlug), []byte(loginKey)),
		),
	}
	if !validOIDCStartLookup(lookup) {
		return OIDCStartLookup{}, ErrInvalidInput
	}
	return lookup, nil
}

func allZeroOIDCStartBytes(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func (digester *OIDCStartDigester) digest(purpose string, fields ...[]byte) [sha256.Size]byte {
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

type oidcDigestWriter interface {
	Write([]byte) (int, error)
}

func writeOIDCDigestField(writer oidcDigestWriter, value []byte) {
	length := [4]byte{}
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}
