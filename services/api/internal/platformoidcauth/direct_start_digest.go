package platformoidcauth

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"regexp"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const (
	minimumDirectStartKeyBytes = 32
	maximumDirectStartKeyBytes = 128
	directStartSecretBytes     = sha256.Size
	directStartHKDFSalt        = "periapsis/platform-oidc-auth/direct-start/hkdf-sha256/v1"
	directStartKeyPurpose      = "periapsis/platform-oidc-auth/direct-start/hmac-sha256/key/v1"
	directReceiptPurpose       = "periapsis/platform-oidc-auth/direct-start/receipt/v1"
	directNetworkPurpose       = "periapsis/platform-oidc-auth/direct-start/network/v1"
	directAccountPurpose       = "periapsis/platform-oidc-auth/direct-start/browser-account/v1"
	directProviderPurpose      = "periapsis/platform-oidc-auth/direct-start/provider/v1"
	directBrowserPurpose       = "periapsis/platform-oidc-auth/direct-start/browser-capability/v1"
)

var directOIDCLoginKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)

type DirectStartReceiptDigest [sha256.Size]byte
type DirectNetworkRateDigest [sha256.Size]byte
type DirectAccountRateDigest [sha256.Size]byte
type DirectProviderRateDigest [sha256.Size]byte
type DirectBrowserCapabilityDigest [sha256.Size]byte

// DirectOIDCStartLookup is the only public locator admitted by direct login.
// It has no tenant, username, email, subject, or account identifier. The
// account throttle dimension is browser-capability scoped, preventing an
// account-existence oracle before provider authentication.
type DirectOIDCStartLookup struct {
	OperationRunID          identity.EntityID
	ReceiptDigest           DirectStartReceiptDigest
	LoginKey                string
	NetworkDigest           DirectNetworkRateDigest
	AccountDigest           DirectAccountRateDigest
	ProviderDigest          DirectProviderRateDigest
	BrowserCapabilityDigest DirectBrowserCapabilityDigest
}

func (lookup DirectOIDCStartLookup) String() string {
	return "platformoidcauth.DirectOIDCStartLookup{locator:[REDACTED],digests:true}"
}

func (lookup DirectOIDCStartLookup) GoString() string { return lookup.String() }

// DirectOIDCStartDigester retains only a direct-family HKDF derivative. Every
// persistence key, including the receipt and browser capability, has its own
// HMAC purpose and therefore cannot be transplanted into tenant OIDC starts.
type DirectOIDCStartDigester struct {
	key []byte
}

func NewDirectOIDCStartDigester(sourceKey []byte) (*DirectOIDCStartDigester, error) {
	if len(sourceKey) < minimumDirectStartKeyBytes || len(sourceKey) > maximumDirectStartKeyBytes ||
		allZeroDirectStartBytes(sourceKey) {
		return nil, ErrDirectAuthenticationDenied
	}
	derived, err := hkdf.Key(
		sha256.New, sourceKey, []byte(directStartHKDFSalt), directStartKeyPurpose, sha256.Size,
	)
	if err != nil || len(derived) != sha256.Size || allZeroDirectStartBytes(derived) {
		clear(derived)
		return nil, ErrDirectAuthenticationDenied
	}
	return &DirectOIDCStartDigester{key: derived}, nil
}

func (digester *DirectOIDCStartDigester) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCStartDigester{configured:%t}",
		digester != nil && len(digester.key) == sha256.Size,
	)
}

func (digester *DirectOIDCStartDigester) GoString() string { return digester.String() }

func (digester *DirectOIDCStartDigester) BuildLookup(
	operationRunID identity.EntityID,
	receipt []byte,
	browserCapability []byte,
	loginKey string,
	network string,
) (DirectOIDCStartLookup, error) {
	address, addressErr := netip.ParseAddr(network)
	if digester == nil || len(digester.key) != sha256.Size || !validDirectEntityID(operationRunID) ||
		len(receipt) != directStartSecretBytes || allZeroDirectStartBytes(receipt) ||
		len(browserCapability) != directStartSecretBytes || allZeroDirectStartBytes(browserCapability) ||
		!directOIDCLoginKeyPattern.MatchString(loginKey) || addressErr != nil || address.Zone() != "" ||
		address.String() != network {
		return DirectOIDCStartLookup{}, ErrDirectAuthenticationDenied
	}
	browserDigest := digester.digest(directBrowserPurpose, browserCapability)
	lookup := DirectOIDCStartLookup{
		OperationRunID:          operationRunID,
		ReceiptDigest:           DirectStartReceiptDigest(digester.digest(directReceiptPurpose, receipt)),
		LoginKey:                loginKey,
		NetworkDigest:           DirectNetworkRateDigest(digester.digest(directNetworkPurpose, []byte(network))),
		AccountDigest:           DirectAccountRateDigest(digester.digest(directAccountPurpose, browserCapability)),
		ProviderDigest:          DirectProviderRateDigest(digester.digest(directProviderPurpose, []byte(loginKey))),
		BrowserCapabilityDigest: DirectBrowserCapabilityDigest(browserDigest),
	}
	if !validDirectOIDCStartLookup(lookup) {
		return DirectOIDCStartLookup{}, ErrDirectAuthenticationDenied
	}
	return lookup, nil
}

func (digester *DirectOIDCStartDigester) BrowserCapabilityDigest(
	browserCapability []byte,
) (DirectBrowserCapabilityDigest, error) {
	if digester == nil || len(digester.key) != sha256.Size ||
		len(browserCapability) != directStartSecretBytes || allZeroDirectStartBytes(browserCapability) {
		return DirectBrowserCapabilityDigest{}, ErrDirectAuthenticationDenied
	}
	return DirectBrowserCapabilityDigest(digester.digest(directBrowserPurpose, browserCapability)), nil
}

func (digester *DirectOIDCStartDigester) digest(purpose string, fields ...[]byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, digester.key)
	writeDirectDigestField(mac, []byte(purpose))
	for _, field := range fields {
		writeDirectDigestField(mac, field)
	}
	material := mac.Sum(nil)
	defer clear(material)
	result := [sha256.Size]byte{}
	copy(result[:], material)
	return result
}

type directDigestWriter interface {
	Write([]byte) (int, error)
}

func writeDirectDigestField(writer directDigestWriter, value []byte) {
	length := [4]byte{}
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func validDirectOIDCStartLookup(lookup DirectOIDCStartLookup) bool {
	digests := [][sha256.Size]byte{
		lookup.ReceiptDigest, lookup.NetworkDigest, lookup.AccountDigest,
		lookup.ProviderDigest, lookup.BrowserCapabilityDigest,
	}
	if !validDirectEntityID(lookup.OperationRunID) || !directOIDCLoginKeyPattern.MatchString(lookup.LoginKey) {
		return false
	}
	for index, digest := range digests {
		if digest == ([sha256.Size]byte{}) {
			return false
		}
		for previous := 0; previous < index; previous++ {
			if hmac.Equal(digest[:], digests[previous][:]) {
				return false
			}
		}
	}
	return true
}

func allZeroDirectStartBytes(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
