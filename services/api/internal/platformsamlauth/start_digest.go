package platformsamlauth

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

const (
	minimumStartDigestKeyBytes = 32
	maximumStartDigestKeyBytes = 128
	startReceiptBytes          = sha256.Size

	startDigestHKDFSalt   = "periapsis/platform-saml-auth/direct-start/hkdf-sha256/v1"
	startDigestKeyPurpose = "periapsis/platform-saml-auth/direct-start/hmac-sha256/key/v1"
	startReceiptPurpose   = "periapsis/platform-saml-auth/direct-start/receipt/v1"
	startNetworkPurpose   = "periapsis/platform-saml-auth/direct-start/network/v1"
	startAccountPurpose   = "periapsis/platform-saml-auth/direct-start/browser-account/v1"
	startProviderPurpose  = "periapsis/platform-saml-auth/direct-start/provider/v1"
)

// StartDigester derives purpose-separated, direct-platform SAML admission
// digests. The public provider key remains only a locator. The account bucket
// is scoped to the random browser receipt because no account identity exists
// before the IdP response and deriving it from a claimed subject would create
// an account-existence oracle.
type StartDigester struct {
	key []byte
}

func NewStartDigester(sourceKey []byte) (*StartDigester, error) {
	if len(sourceKey) < minimumStartDigestKeyBytes || len(sourceKey) > maximumStartDigestKeyBytes ||
		allZeroStartBytes(sourceKey) {
		return nil, ErrInvalidOptions
	}
	derived, err := hkdf.Key(
		sha256.New,
		sourceKey,
		[]byte(startDigestHKDFSalt),
		startDigestKeyPurpose,
		sha256.Size,
	)
	if err != nil || len(derived) != sha256.Size || allZeroStartBytes(derived) {
		clear(derived)
		return nil, ErrInvalidOptions
	}
	return &StartDigester{key: derived}, nil
}

func (digester *StartDigester) String() string {
	return fmt.Sprintf(
		"platformsamlauth.StartDigester{configured:%t,material:[REDACTED]}",
		digester != nil && len(digester.key) == sha256.Size,
	)
}

func (digester *StartDigester) GoString() string { return digester.String() }

func (digester *StartDigester) BuildLookup(
	operationRunID identity.EntityID,
	receipt []byte,
	providerKey string,
	network string,
) (StartLookup, error) {
	address, addressErr := netip.ParseAddr(network)
	if digester == nil || len(digester.key) != sha256.Size || !validUUIDv7(operationRunID) ||
		len(receipt) != startReceiptBytes || allZeroStartBytes(receipt) ||
		!loginKeyPattern.MatchString(providerKey) || addressErr != nil || address.Zone() != "" ||
		address != address.Unmap() || address.String() != network {
		return StartLookup{}, ErrAuthenticationDenied
	}
	lookup := StartLookup{
		Begin: federatedsaml.AuthenticationBegin{
			OperationRunID: operationRunID,
			ReceiptDigest: federatedsaml.StartReceiptDigest(
				digester.digest(startReceiptPurpose, receipt),
			),
			NetworkDigest: federatedsaml.NetworkThrottleDigest(
				digester.digest(startNetworkPurpose, []byte(network)),
			),
			AccountDigest: federatedsaml.AccountThrottleDigest(
				digester.digest(startAccountPurpose, receipt),
			),
			ProviderDigest: federatedsaml.ProviderThrottleDigest(
				digester.digest(startProviderPurpose, []byte(providerKey)),
			),
		},
		LoginKey: providerKey,
	}
	if !validStartLookup(lookup) {
		return StartLookup{}, ErrAuthenticationDenied
	}
	return lookup, nil
}

func (digester *StartDigester) digest(purpose string, fields ...[]byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, digester.key)
	writeStartDigestField(mac, []byte(purpose))
	for _, field := range fields {
		writeStartDigestField(mac, field)
	}
	material := mac.Sum(nil)
	defer clear(material)
	var result [sha256.Size]byte
	copy(result[:], material)
	return result
}

type startDigestWriter interface {
	Write([]byte) (int, error)
}

func writeStartDigestField(writer startDigestWriter, value []byte) {
	length := [4]byte{}
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func allZeroStartBytes(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
