package federatedoidc

import (
	"testing"
	"time"
)

func FuzzStrictOIDCParsersNeverPanic(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("state=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA&code=code"),
		[]byte(`{"id_token":"a.b.c","access_token":"token","token_type":"Bearer","expires_in":600}`),
		[]byte("eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS1lZDI1NTE5LXByaW1hcnkifQ.e30.AQ"),
		[]byte(`{"duplicate":1,"duplicate":2}`),
		{0xff, 0x00, '&', '='},
	} {
		f.Add(seed)
	}
	flow := &Flow{
		policy: DefaultFlowPolicy(),
		trust:  &Client{limits: DefaultLimits()},
	}
	record := ClaimedTransaction{PendingTransaction: PendingTransaction{
		ID: TransactionID{1}, Scopes: []string{RequiredScopeOpenID},
	}}
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, input []byte) {
		callback, callbackErr := flow.parseCallback(string(input))
		if callbackErr == nil {
			if !validOpaque(callback.state) || callback.providerError == (len(callback.code) != 0) {
				t.Fatal("callback parser returned an invalid success shape")
			}
			clear(callback.state)
			clear(callback.code)
		}
		bundle, tokenErr := flow.parseTokenResponse(input, record, now)
		if tokenErr == nil {
			if bundle == nil || !bundle.HasAccessToken() {
				t.Fatal("token parser returned an invalid success shape")
			}
			bundle.Destroy()
		}
		parsed, compactErr := flow.parseCompactToken(input)
		if compactErr == nil {
			if len(parsed.payloadRaw) == 0 || parsed.keyID == "" || !supportedSigningAlgorithm(parsed.algorithm) {
				t.Fatal("compact parser returned an invalid success shape")
			}
			clear(parsed.payloadRaw)
		}
	})
}

func FuzzReturnPathRemainsSameOriginRelative(f *testing.F) {
	for _, seed := range []string{"/", "/alerts", "/cases?sort=oldest", "//evil.example", "/../admin"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if !validReturnPath(value) {
			return
		}
		if value == "" || value[0] != '/' || len(value) > 1 && value[1] == '/' {
			t.Fatalf("unsafe return path accepted: %q", value)
		}
	})
}
