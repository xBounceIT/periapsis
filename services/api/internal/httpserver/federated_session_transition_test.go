package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

type sessionTransitionDeliveryStub struct {
	confirmed   int
	compensated int
}

func (stub *sessionTransitionDeliveryStub) ConfirmBrowserDelivery() error {
	stub.confirmed++
	return nil
}

func (stub *sessionTransitionDeliveryStub) CompensateBrowserDelivery(context.Context) error {
	stub.compensated++
	return nil
}

func TestFederatedSessionRotationReplacesCookieWithoutReplayingRequest(t *testing.T) {
	t.Parallel()
	lookup := transitionAuthorityLookup("passkey")
	expiresAt := time.Now().UTC().Add(8 * time.Hour).Truncate(time.Millisecond)
	token := federatedOpaque(0xa1)
	transition, err := authentication.NewFederatedSessionRotationTransition(
		lookup, uuid.Must(uuid.NewV7()), expiresAt, token, federatedOpaque(0xa2),
	)
	if err != nil {
		t.Fatalf("rotation transition: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/tickets", nil)
	response := httptest.NewRecorder()
	transitionWriter(response, request, transition)

	assertProblem(t, response, http.StatusUnauthorized, "session_rotated")
	if response.Header().Get(sessionTransitionHeader) != "rotated" {
		t.Fatalf("transition header = %q", response.Header().Get(sessionTransitionHeader))
	}
	assertSessionCookie(t, response.Result().Cookies(), developmentCookie, string(token))
	assertClearedStrictCookie(t, response.Result().Cookies(), developmentMFACookie)
	assertClearedStrictCookie(t, response.Result().Cookies(), developmentFederatedContinuationCookie)
	if _, consumed := transition.Consume(); consumed {
		t.Fatal("HTTP response left rotation material consumable")
	}
}

func TestFederatedSessionStepUpReplacesSessionWithPossessionBoundCookie(t *testing.T) {
	t.Parallel()
	lookup := transitionAuthorityLookup("saml")
	continuationID := uuid.Must(uuid.NewV7())
	receipt := federatedOpaque(0xb1)
	transition, err := authentication.NewFederatedSessionStepUpTransition(
		lookup, continuationID, time.Now().UTC().Add(5*time.Minute).Truncate(time.Millisecond), receipt,
	)
	if err != nil {
		t.Fatalf("step-up transition: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	response := httptest.NewRecorder()
	transitionWriter(response, request, transition)

	assertProblem(t, response, http.StatusUnauthorized, "mfa_step_up_required")
	if response.Header().Get(sessionTransitionHeader) != "step_up" ||
		response.Header().Get("Location") != federatedContinuationPath {
		t.Fatalf("transition headers = %#v", response.Header())
	}
	assertClearedStrictCookie(t, response.Result().Cookies(), developmentCookie)
	cookie := findPositiveResponseCookie(response.Result().Cookies(), developmentFederatedContinuationCookie)
	if cookie == nil || cookie.Value == string(receipt) {
		t.Fatalf("continuation cookie = %#v", cookie)
	}
	decode := httptest.NewRequest(http.MethodGet, federatedContinuationPath, nil)
	decode.AddCookie(cookie)
	decodedID, decodedReceipt, err := federatedContinuationCookie(
		decode, sessionCookiePolicy{name: developmentFederatedContinuationCookie},
	)
	if err != nil || decodedID != continuationID || string(decodedReceipt) != string(receipt) {
		t.Fatalf("decoded continuation = %s receipt_match=%t error=%v", decodedID, string(decodedReceipt) == string(receipt), err)
	}
	clear(decodedReceipt)
	if _, consumed := transition.Consume(); consumed {
		t.Fatal("HTTP response left continuation material consumable")
	}
}

func TestDirectSAMLSessionStepUpEmitsPurposeSeparatedCookieAndConfirmsDelivery(t *testing.T) {
	t.Parallel()
	lookup := authentication.DirectPlatformSessionAuthorityLookup{
		SessionID: uuid.Must(uuid.NewV7()), UserID: uuid.Must(uuid.NewV7()),
		AuthenticationMethod: "saml", Audience: "api",
	}
	continuationID := uuid.Must(uuid.NewV7())
	receipt := federatedOpaque(0xb2)
	delivery := &sessionTransitionDeliveryStub{}
	transition, err := authentication.NewDirectPlatformSessionStepUpTransition(
		lookup, continuationID, time.Now().UTC().Add(5*time.Minute).Truncate(time.Millisecond),
		receipt, delivery,
	)
	if err != nil {
		t.Fatalf("direct SAML step-up transition: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	response := httptest.NewRecorder()
	transitionWriter(response, request, transition)

	assertProblem(t, response, http.StatusUnauthorized, "mfa_step_up_required")
	cookie := findPositiveResponseCookie(response.Result().Cookies(), developmentFederatedContinuationCookie)
	if cookie == nil {
		t.Fatal("missing direct SAML continuation cookie")
	}
	decode := httptest.NewRequest(http.MethodGet, federatedContinuationPath, nil)
	decode.AddCookie(cookie)
	capability, decodeErr := federatedContinuationCapabilityCookie(
		decode, sessionCookiePolicy{name: developmentFederatedContinuationCookie},
	)
	if decodeErr != nil {
		t.Fatalf("decode direct SAML continuation: %v", decodeErr)
	}
	defer capability.destroy()
	if capability.authority != federatedauth.ContinuationAuthorityDirectPlatformSAML ||
		capability.continuationID != continuationID || string(capability.receipt) != string(receipt) {
		t.Fatalf("direct SAML capability = %#v", capability)
	}
	if delivery.confirmed != 1 || delivery.compensated != 0 {
		t.Fatalf("delivery finalization = confirmed %d, compensated %d", delivery.confirmed, delivery.compensated)
	}
}

func TestDirectSessionTransitionCompensatesWhenCookiePoliciesAreUnavailable(t *testing.T) {
	t.Parallel()
	lookup := authentication.DirectPlatformSessionAuthorityLookup{
		SessionID: uuid.Must(uuid.NewV7()), UserID: uuid.Must(uuid.NewV7()),
		AuthenticationMethod: "saml", Audience: "api",
	}
	delivery := &sessionTransitionDeliveryStub{}
	transition, err := authentication.NewDirectPlatformSessionRotationTransition(
		lookup, uuid.Must(uuid.NewV7()), time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond),
		federatedOpaque(0xb3), federatedOpaque(0xb4), delivery,
	)
	if err != nil {
		t.Fatalf("direct rotation transition: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	response := httptest.NewRecorder()
	writeDomainError(response, request, authentication.NewFederatedSessionTransitionError(transition))
	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if delivery.confirmed != 0 || delivery.compensated != 1 {
		t.Fatalf("delivery finalization = confirmed %d, compensated %d", delivery.confirmed, delivery.compensated)
	}
}

func TestFederatedContinuationCookieRejectsUUIDOnlyTamperingAndDuplicates(t *testing.T) {
	t.Parallel()
	policy := sessionCookiePolicy{name: developmentFederatedContinuationCookie}
	now := time.Now().UTC().Truncate(time.Millisecond)
	response := httptest.NewRecorder()
	if err := setFederatedContinuationCookieWithPolicy(
		response, policy, uuid.Must(uuid.NewV7()), federatedOpaque(0xc1), now.Add(5*time.Minute), now,
	); err != nil {
		t.Fatalf("setFederatedContinuationCookieWithPolicy() error = %v", err)
	}
	cookie := findPositiveResponseCookie(response.Result().Cookies(), developmentFederatedContinuationCookie)
	if cookie == nil {
		t.Fatal("missing continuation cookie")
	}
	tamperedPrefix := "A"
	if cookie.Value[0] == 'A' {
		tamperedPrefix = "B"
	}
	for _, testCase := range []struct {
		name    string
		cookies []*http.Cookie
	}{
		{name: "UUID only", cookies: []*http.Cookie{{Name: developmentFederatedContinuationCookie, Value: uuid.Must(uuid.NewV7()).String()}}},
		{name: "legacy receipt only", cookies: []*http.Cookie{{Name: developmentFederatedContinuationCookie, Value: string(federatedOpaque(0xc1))}}},
		{name: "tampered", cookies: []*http.Cookie{{Name: developmentFederatedContinuationCookie, Value: tamperedPrefix + cookie.Value[1:]}}},
		{name: "duplicate", cookies: []*http.Cookie{cookie, cookie}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, item := range testCase.cookies {
				request.AddCookie(item)
			}
			if _, receipt, err := federatedContinuationCookie(request, policy); err == nil || receipt != nil {
				clear(receipt)
				t.Fatalf("federatedContinuationCookie() error = %v", err)
			}
		})
	}
}

func TestFederatedContinuationCookieV2CarriesPurposeSeparatedDirectPlatformAuthority(t *testing.T) {
	t.Parallel()
	policy := sessionCookiePolicy{name: developmentFederatedContinuationCookie}
	now := time.Now().UTC().Truncate(time.Millisecond)
	for _, testCase := range []struct {
		name      string
		family    federatedContinuationFamily
		authority federatedauth.ContinuationAuthority
		seed      byte
	}{
		{name: "OIDC", family: federatedContinuationDirectPlatformOIDC, authority: federatedauth.ContinuationAuthorityDirectPlatformOIDC, seed: 0xd2},
		{name: "SAML", family: federatedContinuationDirectPlatformSAML, authority: federatedauth.ContinuationAuthorityDirectPlatformSAML, seed: 0xd3},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			continuationID := uuid.Must(uuid.NewV7())
			receipt := federatedOpaque(testCase.seed)
			response := httptest.NewRecorder()
			if err := setFederatedContinuationCookieForFamilyWithPolicy(
				response, policy, testCase.family,
				continuationID, receipt, now.Add(5*time.Minute), now,
			); err != nil {
				t.Fatalf("set direct continuation cookie: %v", err)
			}
			cookie := findPositiveResponseCookie(response.Result().Cookies(), developmentFederatedContinuationCookie)
			if cookie == nil {
				t.Fatal("missing direct continuation cookie")
			}
			request := httptest.NewRequest(http.MethodGet, federatedContinuationPath, nil)
			request.AddCookie(cookie)
			capability, err := federatedContinuationCapabilityCookie(request, policy)
			if err != nil {
				t.Fatalf("decode direct continuation cookie: %v", err)
			}
			defer capability.destroy()
			if capability.authority != testCase.authority ||
				capability.continuationID != continuationID || string(capability.receipt) != string(receipt) {
				t.Fatalf("decoded capability = %#v", capability)
			}
			decodedID, decodedReceipt, legacyErr := federatedContinuationCookie(request, policy)
			defer clear(decodedReceipt)
			if legacyErr == nil || decodedID != uuid.Nil || decodedReceipt != nil {
				t.Fatalf("direct capability crossed tenant decoder = %s/%x/%v", decodedID, decodedReceipt, legacyErr)
			}
		})
	}
	continuationID := uuid.Must(uuid.NewV7())
	receipt := federatedOpaque(0xd4)
	if err := setFederatedContinuationCookieForFamilyWithPolicy(
		httptest.NewRecorder(), policy, federatedContinuationTenant,
		continuationID, receipt, now.Add(5*time.Minute), now,
	); err == nil {
		t.Fatal("tenant continuation was emitted with the v2 wire format")
	}
}

func TestFederatedContinuationCookieV2RejectsRelabeledAndUnknownFamily(t *testing.T) {
	t.Parallel()
	policy := sessionCookiePolicy{name: developmentFederatedContinuationCookie}
	now := time.Now().UTC().Truncate(time.Millisecond)
	response := httptest.NewRecorder()
	if err := setFederatedContinuationCookieForFamilyWithPolicy(
		response, policy, federatedContinuationDirectPlatformOIDC,
		uuid.Must(uuid.NewV7()), federatedOpaque(0xd3), now.Add(5*time.Minute), now,
	); err != nil {
		t.Fatalf("set family continuation cookie: %v", err)
	}
	cookie := findPositiveResponseCookie(response.Result().Cookies(), developmentFederatedContinuationCookie)
	if cookie == nil {
		t.Fatal("missing family continuation cookie")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(cookie.Value)
	if err != nil || len(payload) != federatedContinuationCookieV2Bytes {
		t.Fatalf("decode test cookie = %d/%v", len(payload), err)
	}
	for _, family := range []byte{byte(federatedContinuationTenant), 0xff} {
		tampered := append([]byte(nil), payload...)
		tampered[1] = family
		request := httptest.NewRequest(http.MethodGet, federatedContinuationPath, nil)
		request.AddCookie(&http.Cookie{
			Name: cookie.Name, Value: base64.RawURLEncoding.EncodeToString(tampered),
		})
		clear(tampered)
		capability, decodeErr := federatedContinuationCapabilityCookie(request, policy)
		capability.destroy()
		if decodeErr == nil {
			t.Fatalf("continuation family %x was accepted", family)
		}
	}
	clear(payload)
}

func TestFederatedContinuationCookieV1RejectsRelabeledAndUnknownFamily(t *testing.T) {
	t.Parallel()
	policy := sessionCookiePolicy{name: developmentFederatedContinuationCookie}
	now := time.Now().UTC().Truncate(time.Millisecond)
	for _, family := range []federatedContinuationFamily{
		federatedContinuationDirectPlatformOIDC,
		federatedContinuationDirectPlatformSAML,
		federatedContinuationFamily(0xff),
	} {
		response := httptest.NewRecorder()
		if err := setFederatedContinuationCookiePayloadWithPolicy(
			response, policy, federatedContinuationCookieVersionV1, family,
			uuid.Must(uuid.NewV7()), federatedOpaque(0xd5), now.Add(5*time.Minute), now,
		); err == nil {
			t.Fatalf("v1 family %x was silently encoded as tenant authority", family)
		}
		if len(response.Result().Cookies()) != 0 {
			t.Fatalf("v1 family %x emitted a cookie", family)
		}
	}
}

func TestFederatedContinuationDigestRejectsV1V2AuthorityRelabeling(t *testing.T) {
	t.Parallel()
	continuationID := uuid.Must(uuid.NewV7())
	receipt := federatedOpaque(0xd4)
	tenantDigest, err := federatedauth.ContinuationReceiptDigest(
		federatedauth.ContinuationAuthorityTenant, identity.EntityID(continuationID), receipt,
	)
	if err != nil || tenantDigest != sha256.Sum256(receipt) {
		t.Fatalf("tenant digest = %x, %v", tenantDigest, err)
	}
	directDigest, err := federatedauth.ContinuationReceiptDigest(
		federatedauth.ContinuationAuthorityDirectPlatformOIDC,
		identity.EntityID(continuationID), receipt,
	)
	if err != nil || directDigest == tenantDigest {
		t.Fatalf("direct digest was not authority bound: %x, %v", directDigest, err)
	}
	samlDigest, err := federatedauth.ContinuationReceiptDigest(
		federatedauth.ContinuationAuthorityDirectPlatformSAML,
		identity.EntityID(continuationID), receipt,
	)
	if err != nil || samlDigest == tenantDigest || samlDigest == directDigest {
		t.Fatalf("SAML digest was not authority bound: %x, %v", samlDigest, err)
	}
}

func transitionWriter(
	response *httptest.ResponseRecorder,
	request *http.Request,
	transition *authentication.FederatedSessionTransition,
) {
	err := authentication.NewFederatedSessionTransitionError(transition)
	handler := federatedSessionCookiePolicyMiddleware(
		sessionCookiePolicy{name: developmentCookie},
		sessionCookiePolicy{name: developmentMFACookie},
		sessionCookiePolicy{name: developmentFederatedContinuationCookie},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeDomainError(w, r, err) }),
	)
	handler.ServeHTTP(response, request)
}

func transitionAuthorityLookup(method string) authentication.FederatedSessionAuthorityLookup {
	return authentication.FederatedSessionAuthorityLookup{
		SessionID: uuid.Must(uuid.NewV7()), TenantID: uuid.Must(uuid.NewV7()), UserID: uuid.Must(uuid.NewV7()),
		AuthenticationMethod: method, Audience: "api",
	}
}
