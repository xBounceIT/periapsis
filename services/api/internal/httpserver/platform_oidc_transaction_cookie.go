package httpserver

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

const (
	platformOIDCTransactionCookieVersionV1 byte = 1
	platformOIDCTransactionSecretBytes          = 32
	platformOIDCTransactionCookieV1Bytes        = 1 + 2*platformOIDCTransactionSecretBytes
)

// platformOIDCTransactionCapability carries two independently generated,
// purpose-separated browser secrets. TransactionHandle is understood only by
// the OIDC protocol kernel; BrowserCapability is reduced to the direct-login
// HMAC digest before it reaches persistence. Neither value is authority on its
// own and both are destroyed by the HTTP adapter after every use.
type platformOIDCTransactionCapability struct {
	transactionHandle []byte
	browserCapability []byte
}

func (capability platformOIDCTransactionCapability) String() string {
	return fmt.Sprintf(
		"httpserver.platformOIDCTransactionCapability{transaction:%t,browser:%t,material:[REDACTED]}",
		len(capability.transactionHandle) != 0, len(capability.browserCapability) != 0,
	)
}

func (capability platformOIDCTransactionCapability) GoString() string { return capability.String() }

func (capability platformOIDCTransactionCapability) transaction() []byte {
	return append([]byte(nil), capability.transactionHandle...)
}

func (capability platformOIDCTransactionCapability) browser() []byte {
	return append([]byte(nil), capability.browserCapability...)
}

func (capability platformOIDCTransactionCapability) isZero() bool {
	return len(capability.transactionHandle) == 0 && len(capability.browserCapability) == 0
}

func (capability *platformOIDCTransactionCapability) destroy() {
	if capability == nil {
		return
	}
	clear(capability.transactionHandle)
	clear(capability.browserCapability)
	*capability = platformOIDCTransactionCapability{}
}

func setPlatformOIDCTransactionCookie(
	w http.ResponseWriter,
	policy federatedTransactionCookiePolicy,
	transactionHandle []byte,
	browserCapability []byte,
	expiresAt time.Time,
	now time.Time,
) error {
	if !validPlatformOIDCTransactionCookiePolicy(policy) ||
		!validMFABrowserHandle(string(transactionHandle)) ||
		!validPlatformOIDCBrowserCapability(browserCapability) ||
		!validFederatedExpiry(expiresAt, now) {
		return errFederatedTransportUnavailable
	}
	transactionRaw := make([]byte, platformOIDCTransactionSecretBytes)
	decoded, err := base64.RawURLEncoding.Strict().Decode(transactionRaw, transactionHandle)
	if err != nil || decoded != len(transactionRaw) ||
		base64.RawURLEncoding.EncodeToString(transactionRaw) != string(transactionHandle) ||
		subtle.ConstantTimeCompare(transactionRaw, browserCapability) == 1 {
		clear(transactionRaw)
		return errFederatedTransportUnavailable
	}
	defer clear(transactionRaw)
	payload := make([]byte, platformOIDCTransactionCookieV1Bytes)
	defer clear(payload)
	payload[0] = platformOIDCTransactionCookieVersionV1
	copy(payload[1:1+platformOIDCTransactionSecretBytes], transactionRaw)
	copy(payload[1+platformOIDCTransactionSecretBytes:], browserCapability)
	value := base64.RawURLEncoding.EncodeToString(payload)
	maxAge := int(math.Ceil(expiresAt.Sub(now).Seconds()))
	if maxAge < 1 {
		return errFederatedTransportUnavailable
	}
	http.SetCookie(w, &http.Cookie{
		Name: policy.name, Value: value, Path: "/", Expires: expiresAt,
		MaxAge: maxAge, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func platformOIDCTransactionCookie(
	r *http.Request,
	policy federatedTransactionCookiePolicy,
	required bool,
) (platformOIDCTransactionCapability, error) {
	if r == nil || !validPlatformOIDCTransactionCookiePolicy(policy) {
		return platformOIDCTransactionCapability{}, authentication.ErrInvalidAuthentication
	}
	value := ""
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == policy.name {
			count++
			value = cookie.Value
		}
	}
	if count == 0 && !required {
		return platformOIDCTransactionCapability{}, nil
	}
	if count != 1 || len(value) != base64.RawURLEncoding.EncodedLen(platformOIDCTransactionCookieV1Bytes) {
		return platformOIDCTransactionCapability{}, authentication.ErrInvalidAuthentication
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(payload) != platformOIDCTransactionCookieV1Bytes ||
		payload[0] != platformOIDCTransactionCookieVersionV1 ||
		base64.RawURLEncoding.EncodeToString(payload) != value {
		clear(payload)
		return platformOIDCTransactionCapability{}, authentication.ErrInvalidAuthentication
	}
	defer clear(payload)
	transactionRaw := payload[1 : 1+platformOIDCTransactionSecretBytes]
	browserCapability := payload[1+platformOIDCTransactionSecretBytes:]
	transactionHandle := []byte(base64.RawURLEncoding.EncodeToString(transactionRaw))
	if !validMFABrowserHandle(string(transactionHandle)) ||
		!validPlatformOIDCBrowserCapability(browserCapability) ||
		subtle.ConstantTimeCompare(transactionRaw, browserCapability) == 1 {
		clear(transactionHandle)
		return platformOIDCTransactionCapability{}, authentication.ErrInvalidAuthentication
	}
	return platformOIDCTransactionCapability{
		transactionHandle: transactionHandle,
		browserCapability: append([]byte(nil), browserCapability...),
	}, nil
}

func validPlatformOIDCTransactionCookiePolicy(policy federatedTransactionCookiePolicy) bool {
	return policy.sameSite == http.SameSiteLaxMode &&
		(policy.name == developmentPlatformOIDCTransactionCookie ||
			policy.name == productionPlatformOIDCTransactionCookie)
}

func validPlatformOIDCBrowserCapability(value []byte) bool {
	if len(value) != platformOIDCTransactionSecretBytes {
		return false
	}
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined != 0
}
