package httpserver

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPlatformOIDCTransactionCookieRoundTripKeepsBothSecretsSeparated(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	expiresAt := now.Add(7 * time.Minute)
	transactionRaw := repeatedPlatformOIDCSecret(0x31)
	transactionHandle := []byte(base64.RawURLEncoding.EncodeToString(transactionRaw))
	browserCapability := repeatedPlatformOIDCSecret(0x72)
	policy := federatedTransactionCookiePolicy{
		name: productionPlatformOIDCTransactionCookie, sameSite: http.SameSiteLaxMode,
	}
	recorder := httptest.NewRecorder()
	if err := setPlatformOIDCTransactionCookie(
		recorder, policy, transactionHandle, browserCapability, expiresAt, now,
	); err != nil {
		t.Fatalf("setPlatformOIDCTransactionCookie() error = %v", err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != policy.name || cookies[0].Path != "/" ||
		!cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode ||
		cookies[0].MaxAge != 7*60 || cookies[0].Value == string(transactionHandle) ||
		cookies[0].Value == base64.RawURLEncoding.EncodeToString(browserCapability) {
		t.Fatalf("cookie = %#v", cookies)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/platform/oidc/callback", nil)
	request.AddCookie(cookies[0])
	decoded, err := platformOIDCTransactionCookie(request, policy, true)
	if err != nil {
		t.Fatalf("platformOIDCTransactionCookie() error = %v", err)
	}
	defer decoded.destroy()
	if string(decoded.transactionHandle) != string(transactionHandle) ||
		string(decoded.browserCapability) != string(browserCapability) {
		t.Fatalf("decoded capability did not preserve both exact inputs: %#v", decoded)
	}
	transactionCopy := decoded.transaction()
	browserCopy := decoded.browser()
	decoded.destroy()
	if string(transactionCopy) != string(transactionHandle) || string(browserCopy) != string(browserCapability) {
		t.Fatal("accessors did not return owned copies")
	}
	clear(transactionCopy)
	clear(browserCopy)
}

func TestPlatformOIDCTransactionCapabilityFormattingRedactsBothSecrets(t *testing.T) {
	transaction := []byte("transaction-formatting-canary")
	browser := []byte("browser-formatting-canary")
	capability := platformOIDCTransactionCapability{
		transactionHandle: transaction, browserCapability: browser,
	}
	for _, formatted := range []string{
		fmt.Sprint(capability), fmt.Sprintf("%+v", capability), fmt.Sprintf("%#v", capability),
	} {
		if strings.Contains(formatted, string(transaction)) || strings.Contains(formatted, string(browser)) ||
			!strings.Contains(formatted, "[REDACTED]") {
			t.Fatalf("formatting leaked capability material: %q", formatted)
		}
	}
}

func TestPlatformOIDCTransactionCookieOptionalAbsenceAndStrictRejections(t *testing.T) {
	platformPolicy := federatedTransactionCookiePolicy{
		name: developmentPlatformOIDCTransactionCookie, sameSite: http.SameSiteLaxMode,
	}
	emptyRequest := httptest.NewRequest(http.MethodPost, "/", nil)
	capability, err := platformOIDCTransactionCookie(emptyRequest, platformPolicy, false)
	if err != nil || !capability.isZero() {
		t.Fatalf("optional absence = %#v, %v", capability, err)
	}
	if _, err = platformOIDCTransactionCookie(emptyRequest, platformPolicy, true); err == nil {
		t.Fatal("required absence was accepted")
	}

	validPayload := make([]byte, platformOIDCTransactionCookieV1Bytes)
	validPayload[0] = platformOIDCTransactionCookieVersionV1
	copy(validPayload[1:33], repeatedPlatformOIDCSecret(0x11))
	copy(validPayload[33:], repeatedPlatformOIDCSecret(0x22))
	validValue := base64.RawURLEncoding.EncodeToString(validPayload)
	clear(validPayload)
	tests := []struct {
		name    string
		policy  federatedTransactionCookiePolicy
		cookies []*http.Cookie
	}{
		{
			name: "tenant cookie policy transplant",
			policy: federatedTransactionCookiePolicy{
				name: developmentOIDCTransactionCookie, sameSite: http.SameSiteLaxMode,
			},
			cookies: []*http.Cookie{{Name: developmentOIDCTransactionCookie, Value: validValue}},
		},
		{
			name:   "duplicate",
			policy: platformPolicy,
			cookies: []*http.Cookie{
				{Name: platformPolicy.name, Value: validValue},
				{Name: platformPolicy.name, Value: validValue},
			},
		},
		{
			name: "legacy single handle", policy: platformPolicy,
			cookies: []*http.Cookie{{Name: platformPolicy.name, Value: string(federatedOpaque(0x33))}},
		},
		{
			name: "unknown version", policy: platformPolicy,
			cookies: []*http.Cookie{{Name: platformPolicy.name, Value: platformOIDCCookieValue(9, 0x11, 0x22)}},
		},
		{
			name: "zero browser capability", policy: platformPolicy,
			cookies: []*http.Cookie{{Name: platformPolicy.name, Value: platformOIDCCookieValue(1, 0x11, 0x00)}},
		},
		{
			name: "aliased secrets", policy: platformPolicy,
			cookies: []*http.Cookie{{Name: platformPolicy.name, Value: platformOIDCCookieValue(1, 0x44, 0x44)}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, cookie := range test.cookies {
				request.AddCookie(cookie)
			}
			if decoded, err := platformOIDCTransactionCookie(request, test.policy, true); err == nil {
				decoded.destroy()
				t.Fatal("malformed or cross-family cookie was accepted")
			}
		})
	}
}

func TestSetPlatformOIDCTransactionCookieRejectsAliasedAndWrongFamilyInputs(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	secret := repeatedPlatformOIDCSecret(0x51)
	handle := []byte(base64.RawURLEncoding.EncodeToString(secret))
	tenantPolicy := federatedTransactionCookiePolicy{
		name: developmentOIDCTransactionCookie, sameSite: http.SameSiteLaxMode,
	}
	if err := setPlatformOIDCTransactionCookie(
		httptest.NewRecorder(), tenantPolicy, handle, repeatedPlatformOIDCSecret(0x61), now.Add(time.Minute), now,
	); err == nil {
		t.Fatal("tenant cookie policy was accepted")
	}
	platformPolicy := federatedTransactionCookiePolicy{
		name: developmentPlatformOIDCTransactionCookie, sameSite: http.SameSiteLaxMode,
	}
	if err := setPlatformOIDCTransactionCookie(
		httptest.NewRecorder(), platformPolicy, handle, secret, now.Add(time.Minute), now,
	); err == nil {
		t.Fatal("aliased transaction and browser secrets were accepted")
	}
}

func repeatedPlatformOIDCSecret(value byte) []byte {
	result := make([]byte, platformOIDCTransactionSecretBytes)
	for index := range result {
		result[index] = value
	}
	return result
}

func platformOIDCCookieValue(version, transaction, browser byte) string {
	payload := make([]byte, platformOIDCTransactionCookieV1Bytes)
	payload[0] = version
	copy(payload[1:33], repeatedPlatformOIDCSecret(transaction))
	copy(payload[33:], repeatedPlatformOIDCSecret(browser))
	value := base64.RawURLEncoding.EncodeToString(payload)
	clear(payload)
	return value
}
