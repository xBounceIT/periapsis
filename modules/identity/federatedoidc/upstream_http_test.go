package federatedoidc

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

func TestEncodeFormPinsClientSecretPlacementAndRedaction(t *testing.T) {
	clientID := "client!id"
	secret := []byte("s e/c+r?et")
	fieldValue := []byte("v a/l+ue")
	for _, mode := range []ClientAuthenticationMode{ClientSecretBasic, ClientSecretPost} {
		t.Run(string(mode), func(t *testing.T) {
			form := encodeForm([]formField{{name: "grant_type", value: fieldValue}}, mode, clientID, secret)
			defer clear(form.body)
			defer clear(form.authorization)
			values, err := url.ParseQuery(string(form.body))
			if err != nil || values.Get("grant_type") != string(fieldValue) {
				t.Fatalf("form shape rejected: %v", err)
			}
			switch mode {
			case ClientSecretBasic:
				if values.Has("client_id") || values.Has("client_secret") || !bytes.HasPrefix(form.authorization, []byte("Basic ")) {
					t.Fatal("basic client authentication was placed in the request body")
				}
				decoded, err := base64.StdEncoding.Strict().DecodeString(string(bytes.TrimPrefix(form.authorization, []byte("Basic "))))
				if err != nil || string(decoded) != url.QueryEscape(clientID)+":"+url.QueryEscape(string(secret)) {
					t.Fatal("basic client authentication encoding mismatch")
				}
				clear(decoded)
			case ClientSecretPost:
				if len(form.authorization) != 0 || values.Get("client_id") != clientID || values.Get("client_secret") != string(secret) {
					t.Fatal("post client authentication placement mismatch")
				}
			}
			request := RefreshExchangeRequest{ClientSecret: secret, RefreshToken: fieldValue}
			if strings.Contains(request.String(), string(secret)) || strings.Contains(request.GoString(), string(fieldValue)) {
				t.Fatal("refresh request formatting disclosed material")
			}
		})
	}
}

func TestAppendFormEscapeMatchesStandardForEveryByte(t *testing.T) {
	input := make([]byte, 256)
	for index := range input {
		input[index] = byte(index)
	}
	encoded := appendFormEscape(nil, input)
	defer clear(encoded)
	if string(encoded) != url.QueryEscape(string(input)) {
		t.Fatal("byte-wise form encoder diverged from net/url")
	}
}

func TestParseRefreshedTokensRequiresRotationAndDuplicateSafeBounds(t *testing.T) {
	adapter := &UpstreamHTTP{
		jsonLimits: DefaultLimits(), maxRefreshBytes: 16 * 1024,
	}
	now := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	presented := []byte(randomProtocolText(t))
	access := randomProtocolText(t)
	successor := randomProtocolText(t)
	document, err := json.Marshal(map[string]any{
		"access_token": access, "refresh_token": successor, "token_type": "Bearer", "expires_in": 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := adapter.parseRefreshedTokens(document, presented, now)
	if err != nil {
		t.Fatalf("parseRefreshedTokens() error = %v", err)
	}
	if got := tokens.RefreshToken(); !bytes.Equal(got, []byte(successor)) {
		clear(got)
		t.Fatal("rotated refresh token mismatch")
	} else {
		clear(got)
	}
	if tokens.ExpiresAt() != now.Add(5*time.Minute) || strings.Contains(tokens.String(), access) ||
		strings.Contains(tokens.GoString(), successor) {
		t.Fatal("refreshed token result mismatch or disclosure")
	}
	tokens.Destroy()

	hostile := [][]byte{
		mustJSON(t, map[string]any{
			"access_token": access, "refresh_token": string(presented), "token_type": "Bearer", "expires_in": 300,
		}),
		[]byte(`{"access_token":"` + access + `","access_token":"` + randomProtocolText(t) +
			`","refresh_token":"` + successor + `","token_type":"Bearer","expires_in":300}`),
		mustJSON(t, map[string]any{
			"access_token": access, "refresh_token": successor, "token_type": "Bearer", "expires_in": 86401,
		}),
		mustJSON(t, map[string]any{
			"access_token": access, "refresh_token": successor, "token_type": "MAC", "expires_in": 300,
		}),
	}
	for index, candidate := range hostile {
		if rejected, err := adapter.parseRefreshedTokens(candidate, presented, now); err == nil || rejected != nil {
			t.Fatalf("hostile refresh response %d unexpectedly accepted", index)
		}
	}
}

func TestCredentialRetryClassificationRequiresDispatchProof(t *testing.T) {
	if !credentialRequestSafeToRetry(federatedhttp.OperationResult{
		Category: federatedhttp.CategoryCancelled, RequestNotDispatched: true,
	}, nil) || credentialRequestSafeToRetry(federatedhttp.OperationResult{
		Category: federatedhttp.CategoryCancelled,
	}, nil) {
		t.Fatal("shared refresh/revocation retry classifier ignored dispatch proof")
	}

	preDispatch := refreshExecutionError(federatedhttp.OperationResult{
		Category: federatedhttp.CategoryCancelled, RequestNotDispatched: true,
	}, nil)
	if !errors.Is(preDispatch, ErrRefreshSafeToRetry) || errors.Is(preDispatch, ErrRefreshAmbiguous) {
		t.Fatalf("pre-dispatch cancellation = %v", preDispatch)
	}

	postDispatch := refreshExecutionError(federatedhttp.OperationResult{
		Category: federatedhttp.CategoryCancelled,
	}, nil)
	if !errors.Is(postDispatch, ErrRefreshAmbiguous) || errors.Is(postDispatch, ErrRefreshSafeToRetry) {
		t.Fatalf("post-dispatch cancellation = %v", postDispatch)
	}

	busy := refreshExecutionError(federatedhttp.OperationResult{}, federatedhttp.ErrBusy)
	if !errors.Is(busy, ErrRefreshSafeToRetry) || errors.Is(busy, ErrRefreshAmbiguous) {
		t.Fatalf("concurrency rejection = %v", busy)
	}
}

func TestMergeUserInfoCannotOverrideSecurityOrExistingClaims(t *testing.T) {
	flow := &Flow{policy: FlowPolicy{Limits: DefaultFlowPolicy().Limits}}
	subject := randomProtocolText(t)
	proof := VerifiedAuthentication{
		subject: subject, valid: true,
		claims: ClaimSet{scalars: []NamedScalar{{Name: "employee_id", Value: randomProtocolText(t)}}},
	}
	document := UserInfoDocument{subject: subject, valid: true, claims: map[string]json.RawMessage{
		"department": json.RawMessage(`"operations"`),
	}}
	merged, err := flow.MergeUserInfo(proof, document, ClaimExtractionPolicy{
		Scalars: []ScalarClaimRule{{Claim: "department", Required: true}},
	})
	if err != nil {
		t.Fatalf("MergeUserInfo() error = %v", err)
	}
	if value, ok := merged.Claims().Scalar("department"); !ok || value != "operations" {
		t.Fatal("UserInfo claim was not added")
	}

	document.claims["employee_id"] = json.RawMessage(`"replacement"`)
	if _, err := flow.MergeUserInfo(proof, document, ClaimExtractionPolicy{
		Scalars: []ScalarClaimRule{{Claim: "employee_id", Required: true}},
	}); err == nil {
		t.Fatal("UserInfo replaced an ID token claim")
	}
	if _, err := flow.MergeUserInfo(proof, document, ClaimExtractionPolicy{AMR: &StringArrayClaimRule{Claim: "amr"}}); err == nil {
		t.Fatal("UserInfo supplied assurance claims")
	}
	if _, err := flow.MergeUserInfo(proof, document, ClaimExtractionPolicy{ACR: &ScalarClaimRule{Claim: "acr"}}); err == nil {
		t.Fatal("UserInfo supplied ACR assurance")
	}
	document.subject = randomProtocolText(t)
	if _, err := flow.MergeUserInfo(proof, document, ClaimExtractionPolicy{}); err == nil {
		t.Fatal("UserInfo subject mismatch was accepted")
	}
}

func randomProtocolText(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	result := base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	return result
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
}
