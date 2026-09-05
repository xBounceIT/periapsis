package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/platformlocalaccount"
)

type platformLocalAccountHTTPStub struct {
	listInput       platformlocalaccount.ListInput
	listResult      platformlocalaccount.Page
	listError       error
	listCalls       int
	getResult       platformlocalaccount.Account
	getError        error
	getCalls        int
	inviteResult    platformlocalaccount.MutationResult
	inviteError     error
	inviteCalls     int
	activationInput platformlocalaccount.ActivationInput
	activation      platformlocalaccount.MutationResult
	activationError error
	activationCalls int
	disableResult   platformlocalaccount.MutationResult
	enableResult    platformlocalaccount.MutationResult
	recoverResult   platformlocalaccount.MutationResult
	rotationInput   platformlocalaccount.PasswordTransitionInput
	rotationResult  platformlocalaccount.MutationResult
}

func (stub *platformLocalAccountHTTPStub) List(
	_ context.Context,
	_ authentication.Session,
	input platformlocalaccount.ListInput,
) (platformlocalaccount.Page, error) {
	stub.listCalls++
	stub.listInput = input
	return stub.listResult, stub.listError
}

func (stub *platformLocalAccountHTTPStub) Get(
	_ context.Context,
	_ authentication.Session,
	_ uuid.UUID,
) (platformlocalaccount.Account, error) {
	stub.getCalls++
	return stub.getResult, stub.getError
}

func (stub *platformLocalAccountHTTPStub) Invite(
	_ context.Context,
	_ authentication.Session,
	_ platformlocalaccount.InviteInput,
) (platformlocalaccount.MutationResult, error) {
	stub.inviteCalls++
	return stub.inviteResult, stub.inviteError
}

func (stub *platformLocalAccountHTTPStub) Activate(
	_ context.Context,
	_ authentication.Session,
	_ uuid.UUID,
	input platformlocalaccount.ActivationInput,
) (platformlocalaccount.MutationResult, error) {
	stub.activationCalls++
	stub.activationInput = input
	return stub.activation, stub.activationError
}

func (stub *platformLocalAccountHTTPStub) Disable(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformlocalaccount.TransitionInput,
) (platformlocalaccount.MutationResult, error) {
	return stub.disableResult, nil
}

func (stub *platformLocalAccountHTTPStub) Enable(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformlocalaccount.TransitionInput,
) (platformlocalaccount.MutationResult, error) {
	return stub.enableResult, nil
}

func (stub *platformLocalAccountHTTPStub) Recover(
	context.Context,
	authentication.Session,
	uuid.UUID,
	platformlocalaccount.TransitionInput,
) (platformlocalaccount.MutationResult, error) {
	return stub.recoverResult, nil
}

func (stub *platformLocalAccountHTTPStub) RotatePassword(
	_ context.Context,
	_ authentication.Session,
	_ uuid.UUID,
	input platformlocalaccount.PasswordTransitionInput,
) (platformlocalaccount.MutationResult, error) {
	stub.rotationInput = input
	return stub.rotationResult, nil
}

func TestPlatformLocalAccountListAndGetExposeOnlySafeNoStoreProjection(t *testing.T) {
	first := platformLocalAccountHTTPFixture(t, platformlocalaccount.StatusActive, 2)
	second := platformLocalAccountHTTPFixture(t, platformlocalaccount.StatusDisabled, 3)
	if bytes.Compare(first.ID[:], second.ID[:]) > 0 {
		first.ID, second.ID = second.ID, first.ID
	}
	service := &platformLocalAccountHTTPStub{
		listResult: platformlocalaccount.Page{
			Items: []platformlocalaccount.Account{first, second}, NextCursor: &second.ID,
		},
		getResult: second,
	}
	router := newPlatformLocalAccountTestRouter(t, service)

	listResponse := httptest.NewRecorder()
	router.ServeHTTP(listResponse, platformLocalAccountReadRequest("/api/v1/platform/local-accounts?limit=2&includeDisabled=true"))
	if listResponse.Code != http.StatusOK || service.listCalls != 1 || service.listInput.Limit != 2 ||
		!service.listInput.IncludeDisabled || !strings.Contains(listResponse.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("list response=%d input=%#v headers=%#v body=%s", listResponse.Code, service.listInput, listResponse.Header(), listResponse.Body.String())
	}
	assertPlatformLocalAccountResponseSafe(t, listResponse.Body.Bytes())
	if strings.Contains(listResponse.Body.String(), "ceremonyToken") ||
		strings.Contains(listResponse.Body.String(), "totpEnrollment") {
		t.Fatalf("list response exposed enrollment material: %s", listResponse.Body.String())
	}

	getResponse := httptest.NewRecorder()
	router.ServeHTTP(getResponse, platformLocalAccountReadRequest(platformLocalAccountLocation(second.ID)))
	if getResponse.Code != http.StatusOK || getResponse.Header().Get("ETag") != `"v3"` || service.getCalls != 1 {
		t.Fatalf("get response=%d headers=%#v body=%s", getResponse.Code, getResponse.Header(), getResponse.Body.String())
	}
	assertPlatformLocalAccountResponseSafe(t, getResponse.Body.Bytes())
	if strings.Contains(getResponse.Body.String(), "ceremonyToken") ||
		strings.Contains(getResponse.Body.String(), "totpEnrollment") {
		t.Fatalf("detail response exposed enrollment material: %s", getResponse.Body.String())
	}
	var mapped contract.PlatformLocalAccount
	if err := json.Unmarshal(getResponse.Body.Bytes(), &mapped); err != nil || mapped.Id != second.ID ||
		mapped.Status != contract.PlatformLocalAccountStatusDisabled || mapped.CredentialVersion != 2 {
		t.Fatalf("mapped=%#v err=%v", mapped, err)
	}
}

func TestPlatformLocalAccountInvitationTokenIsEmittedOnceAndReplayIsRedacted(t *testing.T) {
	repository := &platformLocalAccountInviteRepository{}
	ids := []uuid.UUID{
		mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t),
		mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t),
	}
	nextID := func() (uuid.UUID, error) {
		value := ids[0]
		ids = ids[1:]
		return value, nil
	}
	service, err := platformlocalaccount.NewService(platformlocalaccount.Options{
		Repository: repository, PasswordHasher: platformLocalAccountHTTPHasher{},
		TOTPEnrollment:   platformLocalAccountHTTPEnrollmentSecurity(t),
		CommandDigestKey: bytes.Repeat([]byte{0x42}, 32), Random: bytes.NewReader(bytes.Repeat([]byte{0x24}, 64)),
		Now: func() time.Time { return time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC) }, NewID: nextID,
	})
	if err != nil {
		t.Fatal(err)
	}
	router := newPlatformLocalAccountTestRouter(t, service)
	requestBody := `{"displayName":"Emergency Operator","loginIdentifier":"emergency@example.test","protectedRecoveryPrincipal":true}`

	first := platformLocalAccountMutationRequest(http.MethodPost, "/api/v1/platform/local-accounts", requestBody)
	first.Header.Set(idempotencyKeyHeader, "local-account-invite-0001")
	first.Header.Set("X-Audit-Reason", "Provision reviewed recovery operator")
	firstResponse := httptest.NewRecorder()
	router.ServeHTTP(firstResponse, first)
	if firstResponse.Code != http.StatusCreated || firstResponse.Header().Get("ETag") != `"v1"` ||
		firstResponse.Header().Get("Location") != platformLocalAccountLocation(repository.account.ID) {
		t.Fatalf("first response=%d headers=%#v body=%s", firstResponse.Code, firstResponse.Header(), firstResponse.Body.String())
	}
	var firstResult contract.PlatformLocalAccountMutationResult
	if err := json.Unmarshal(firstResponse.Body.Bytes(), &firstResult); err != nil || firstResult.Replayed ||
		firstResult.CeremonyToken == nil || len(*firstResult.CeremonyToken) != 43 ||
		firstResult.TotpEnrollment == nil || len(firstResult.TotpEnrollment.Secret) < 16 ||
		!strings.HasPrefix(firstResult.TotpEnrollment.ProvisioningUri, "otpauth://totp/Periapsis:"+repository.account.ID.String()+"?") ||
		!strings.Contains(firstResult.TotpEnrollment.ProvisioningUri, "secret="+firstResult.TotpEnrollment.Secret) {
		t.Fatalf("first result=%#v err=%v", firstResult, err)
	}
	assertPlatformLocalAccountResponseSafe(t, firstResponse.Body.Bytes())

	replay := platformLocalAccountMutationRequest(http.MethodPost, "/api/v1/platform/local-accounts", requestBody)
	replay.Header.Set(idempotencyKeyHeader, "local-account-invite-0001")
	replay.Header.Set("X-Audit-Reason", "Provision reviewed recovery operator")
	replayResponse := httptest.NewRecorder()
	router.ServeHTTP(replayResponse, replay)
	var replayResult contract.PlatformLocalAccountMutationResult
	if replayResponse.Code != http.StatusCreated || json.Unmarshal(replayResponse.Body.Bytes(), &replayResult) != nil ||
		!replayResult.Replayed || replayResult.CeremonyToken != nil || replayResult.TotpEnrollment != nil ||
		strings.Contains(replayResponse.Body.String(), *firstResult.CeremonyToken) ||
		strings.Contains(replayResponse.Body.String(), firstResult.TotpEnrollment.Secret) ||
		strings.Contains(replayResponse.Body.String(), firstResult.TotpEnrollment.ProvisioningUri) {
		t.Fatalf("replay response=%d result=%#v body=%s", replayResponse.Code, replayResult, replayResponse.Body.String())
	}
	if repository.calls != 2 {
		t.Fatalf("repository calls=%d", repository.calls)
	}
}

func TestPlatformLocalAccountActivationBindsCASAndClearsSecretBuffers(t *testing.T) {
	account := platformLocalAccountHTTPFixture(t, platformlocalaccount.StatusActive, 2)
	service := &platformLocalAccountHTTPStub{activation: platformlocalaccount.MutationResult{Account: account}}
	router := newPlatformLocalAccountTestRouter(t, service)
	token := strings.Repeat("B", 42) + "A"
	password := "correct horse battery staple"
	request := platformLocalAccountMutationRequest(
		http.MethodPost,
		platformLocalAccountLocation(account.ID)+"/activate",
		`{"expectedRevision":1,"ceremonyToken":"`+token+`","newPassword":"`+password+`","factorProof":"123456"}`,
	)
	request.Header.Set(ifMatchHeader, `"v1"`)
	request.Header.Set(idempotencyKeyHeader, "local-activation-0001")
	request.Header.Set("X-Audit-Reason", "Complete reviewed emergency enrollment")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v2"` || service.activationCalls != 1 ||
		service.activationInput.ExpectedEntityTag == nil || *service.activationInput.ExpectedEntityTag != `"v1"` ||
		service.activationInput.IdempotencyKey != "local-activation-0001" || service.activationInput.Reason != "Complete reviewed emergency enrollment" {
		t.Fatalf("response=%d headers=%#v input=%#v body=%s", response.Code, response.Header(), service.activationInput, response.Body.String())
	}
	if !allPlatformLocalAccountBytesCleared(service.activationInput.CeremonyToken) ||
		!allPlatformLocalAccountBytesCleared(service.activationInput.NewPassword) ||
		!allPlatformLocalAccountBytesCleared(service.activationInput.FactorProof) {
		t.Fatal("HTTP transport retained activation secrets after the service call")
	}
	if strings.Contains(response.Body.String(), token) || strings.Contains(response.Body.String(), password) || strings.Contains(response.Body.String(), "123456") {
		t.Fatalf("activation response leaked protected material: %s", response.Body.String())
	}
	assertPlatformLocalAccountResponseSafe(t, response.Body.Bytes())
}

func TestPlatformLocalAccountRejectsUnexpectedArtifactBeforeSettingValidatorHeaders(t *testing.T) {
	repository := &platformLocalAccountInviteRepository{}
	ids := []uuid.UUID{
		mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t),
	}
	service, err := platformlocalaccount.NewService(platformlocalaccount.Options{
		Repository: repository, PasswordHasher: platformLocalAccountHTTPHasher{},
		TOTPEnrollment:   platformLocalAccountHTTPEnrollmentSecurity(t),
		CommandDigestKey: bytes.Repeat([]byte{0x42}, 32), Random: bytes.NewReader(bytes.Repeat([]byte{0x24}, 64)),
		Now: func() time.Time { return time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC) },
		NewID: func() (uuid.UUID, error) {
			value := ids[0]
			ids = ids[1:]
			return value, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	session := authentication.Session{
		ID: mustTransportUUIDv7(t), User: authentication.User{ID: mustTransportUUIDv7(t)},
		Permissions: []authorization.Permission{
			authorization.PermissionPlatformIdentityAccountRead,
			authorization.PermissionPlatformIdentityAccountManage,
		},
		AuthenticationMethod: "totp",
	}
	result, err := service.Invite(context.Background(), session, platformlocalaccount.InviteInput{
		DisplayName: "Emergency Operator", LoginIdentifier: "emergency@example.test",
		ProtectedRecoveryPrincipal: true, Reason: "Provision reviewed recovery operator",
		IdempotencyKey: "local-account-invite-0001",
		Event: authentication.EventContext{
			RequestID: mustTransportUUIDv7(t), CorrelationID: mustTransportUUIDv7(t),
			RemoteAddress: netip.MustParseAddr("192.0.2.10"), UserAgent: "local-account-handler-test",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	stub := &platformLocalAccountHTTPStub{activation: result}
	request := platformLocalAccountMutationRequest(
		http.MethodPost,
		platformLocalAccountLocation(result.Account.ID)+"/activate",
		`{"expectedRevision":1,"ceremonyToken":"`+strings.Repeat("B", 42)+`A","newPassword":"correct horse battery staple","factorProof":"123456"}`,
	)
	request.Header.Set(ifMatchHeader, `"v1"`)
	request.Header.Set(idempotencyKeyHeader, "local-activation-0001")
	request.Header.Set("X-Audit-Reason", "Complete reviewed emergency enrollment")
	response := httptest.NewRecorder()
	newPlatformLocalAccountTestRouter(t, stub).ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable || response.Header().Get("ETag") != "" ||
		response.Header().Get("Location") != "" || strings.Contains(response.Body.String(), "ceremonyToken") ||
		strings.Contains(response.Body.String(), "totpEnrollment") {
		t.Fatalf("unexpected-artifact response=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if material, ok := result.Artifact.Consume(); ok || len(material.CeremonyToken) != 0 ||
		len(material.TOTPSecret) != 0 || len(material.ProvisioningURI) != 0 {
		t.Fatalf("unexpected artifact remained consumable: %#v, %t", material, ok)
	}
}

func TestPlatformLocalAccountTransportRejectsAmbiguousOrUnboundedInput(t *testing.T) {
	account := platformLocalAccountHTTPFixture(t, platformlocalaccount.StatusActive, 2)
	path := platformLocalAccountLocation(account.ID) + "/activate"
	valid := `{"expectedRevision":1,"ceremonyToken":"` + strings.Repeat("B", 42) + `A","newPassword":"correct horse battery staple","factorProof":"123456"}`
	tests := []struct {
		name       string
		body       string
		configure  func(*http.Request)
		wantStatus int
	}{
		{name: "unknown", body: strings.TrimSuffix(valid, "}") + `,"role":"admin"}`, wantStatus: http.StatusBadRequest},
		{name: "duplicate", body: strings.Replace(valid, `"factorProof":"123456"`, `"factorProof":"123456","factorProof":"654321"`, 1), wantStatus: http.StatusBadRequest},
		{name: "oversized", body: `{"expectedRevision":1,"ceremonyToken":"` + strings.Repeat("B", 42) + `A","newPassword":"` + strings.Repeat("p", maximumPlatformLocalAccountBodyBytes) + `","factorProof":"123456"}`, wantStatus: http.StatusBadRequest},
		{name: "missing if match", body: valid, configure: func(request *http.Request) { request.Header.Del(ifMatchHeader) }, wantStatus: http.StatusPreconditionRequired},
		{name: "body mismatch", body: valid, configure: func(request *http.Request) { request.Header.Set(ifMatchHeader, `"v2"`) }, wantStatus: http.StatusBadRequest},
		{name: "duplicate reason", body: valid, configure: func(request *http.Request) { request.Header.Add("X-Audit-Reason", "another reason") }, wantStatus: http.StatusBadRequest},
		{name: "folded idempotency", body: valid, configure: func(request *http.Request) { request.Header.Add(idempotencyKeyHeader, "local-activation-0002") }, wantStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &platformLocalAccountHTTPStub{activation: platformlocalaccount.MutationResult{Account: account}}
			request := platformLocalAccountMutationRequest(http.MethodPost, path, test.body)
			request.Header.Set(ifMatchHeader, `"v1"`)
			request.Header.Set(idempotencyKeyHeader, "local-activation-0001")
			request.Header.Set("X-Audit-Reason", "Complete reviewed emergency enrollment")
			if test.configure != nil {
				test.configure(request)
			}
			response := httptest.NewRecorder()
			newPlatformLocalAccountTestRouter(t, service).ServeHTTP(response, request)
			if response.Code != test.wantStatus || service.activationCalls != 0 {
				t.Fatalf("response=%d calls=%d body=%s", response.Code, service.activationCalls, response.Body.String())
			}
		})
	}

	service := &platformLocalAccountHTTPStub{}
	request := platformLocalAccountMutationRequest(http.MethodPost, path, valid)
	request.Header.Set(ifMatchHeader, `"v1"`)
	request.Header.Set(idempotencyKeyHeader, "local-activation-0001")
	request.Header.Set("X-Audit-Reason", "Complete reviewed emergency enrollment")
	request.Body = noProgressReadCloser{}
	response := httptest.NewRecorder()
	newPlatformLocalAccountTestRouter(t, service).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || service.activationCalls != 0 {
		t.Fatalf("no-progress response=%d calls=%d", response.Code, service.activationCalls)
	}
}

func TestPlatformLocalAccountErrorsAreFailClosedAndNonOracular(t *testing.T) {
	accountID := mustTransportUUIDv7(t)
	for _, test := range []struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		{authentication.ErrNotFound, http.StatusNotFound, "not_found"},
		{authentication.ErrForbidden, http.StatusForbidden, "forbidden"},
		{authentication.ErrUnavailable, http.StatusServiceUnavailable, "service_unavailable"},
	} {
		service := &platformLocalAccountHTTPStub{getError: test.err}
		response := httptest.NewRecorder()
		newPlatformLocalAccountTestRouter(t, service).ServeHTTP(response, platformLocalAccountReadRequest(platformLocalAccountLocation(accountID)))
		if response.Code != test.wantStatus || test.err == authentication.ErrNotFound && strings.Contains(strings.ToLower(response.Body.String()), "local account") {
			t.Fatalf("error=%v response=%d body=%s", test.err, response.Code, response.Body.String())
		}
		assertPlatformIdentityProviderProblem(t, response, test.wantCode)
	}

	response := httptest.NewRecorder()
	newPlatformLocalAccountTestRouter(t, nil).ServeHTTP(response, platformLocalAccountReadRequest("/api/v1/platform/local-accounts"))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured response=%d body=%s", response.Code, response.Body.String())
	}

	malformed := platformLocalAccountHTTPFixture(t, platformlocalaccount.StatusActive, 2)
	malformed.DisplayName = ""
	response = httptest.NewRecorder()
	newPlatformLocalAccountTestRouter(t, &platformLocalAccountHTTPStub{getResult: malformed}).ServeHTTP(
		response,
		platformLocalAccountReadRequest(platformLocalAccountLocation(malformed.ID)),
	)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), malformed.LoginIdentifier) {
		t.Fatalf("malformed projection response=%d body=%s", response.Code, response.Body.String())
	}
}

func TestReadPlatformLocalAccountBodyRejectsNilRequestWithoutPanic(t *testing.T) {
	if document, err := readPlatformLocalAccountBody(nil); err == nil || document != nil {
		t.Fatalf("readPlatformLocalAccountBody(nil) = %q, %v", document, err)
	}
}

type platformLocalAccountInviteRepository struct {
	account platformlocalaccount.Account
	calls   int
}

func (*platformLocalAccountInviteRepository) List(context.Context, platformlocalaccount.ListParams) ([]platformlocalaccount.Account, error) {
	return nil, authentication.ErrUnavailable
}

func (*platformLocalAccountInviteRepository) Get(context.Context, platformlocalaccount.GetParams) (platformlocalaccount.Account, error) {
	return platformlocalaccount.Account{}, authentication.ErrUnavailable
}

func (repository *platformLocalAccountInviteRepository) Apply(
	_ context.Context,
	params platformlocalaccount.ApplyParams,
) (platformlocalaccount.ApplyResult, error) {
	repository.calls++
	if repository.calls > 1 {
		return params.ValidateResult(platformlocalaccount.ApplyResult{Account: repository.account, Replayed: true})
	}
	plan, err := params.Plan(platformlocalaccount.PlanningState{FreshLocalMFA: true, ProtectedWorkflow: true})
	if err != nil {
		return platformlocalaccount.ApplyResult{}, err
	}
	repository.account = platformlocalaccount.Account{
		ID: uuid.UUID(plan.AccountID), UserID: uuid.UUID(plan.UserID), DisplayName: params.DisplayName,
		LoginIdentifier: params.CanonicalLoginIdentifier, Status: platformlocalaccount.StatusInvited,
		LoginIdentifierStatus:      platformlocalaccount.LoginIdentifierPending,
		CredentialStatus:           platformlocalaccount.CredentialPending,
		ProtectedRecoveryPrincipal: params.ProtectedRecoveryPrincipal,
		Revision:                   plan.NextRevision, IdentityEpoch: plan.NextIdentityEpoch,
		InvitedAt: params.At, UpdatedAt: params.At,
	}
	return params.ValidateResult(platformlocalaccount.ApplyResult{Account: repository.account, ArtifactIssued: true})
}

type platformLocalAccountHTTPHasher struct{}

func (platformLocalAccountHTTPHasher) Hash(value []byte) ([]byte, error) {
	return []byte("$argon2id$v=19$m=65536,t=3,p=1$AQIDBAUGBwgJCgsMDQ4PEA$AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"), nil
}
func (platformLocalAccountHTTPHasher) Verify(value, encoded []byte) bool {
	return bytes.HasSuffix(encoded, value)
}

type platformLocalAccountHTTPTOTPEngine struct{}

func (platformLocalAccountHTTPTOTPEngine) Generate(account string) (string, string, error) {
	secret := "JBSWY3DPEHPK3PXP"
	return secret, "otpauth://totp/Periapsis:" + account + "?issuer=Periapsis&secret=" + secret, nil
}

func (platformLocalAccountHTTPTOTPEngine) Validate(string, string, time.Time, int64) (int64, error) {
	return 123, nil
}

type platformLocalAccountHTTPTOTPCipher struct{}

func (platformLocalAccountHTTPTOTPCipher) EncryptTOTP(context, _ string) (authentication.EncryptedSecret, error) {
	return authentication.EncryptedSecret{
		Ciphertext: bytes.Repeat([]byte{0x42}, 32), Nonce: bytes.Repeat([]byte{0x24}, 12),
		AAD: []byte(context), KeyVersion: 1,
	}, nil
}

func (platformLocalAccountHTTPTOTPCipher) DecryptTOTP(_ string, _ authentication.EncryptedSecret) (string, error) {
	return "JBSWY3DPEHPK3PXP", nil
}

func platformLocalAccountHTTPEnrollmentSecurity(t *testing.T) platformlocalaccount.TOTPEnrollmentSecurity {
	t.Helper()
	security, err := platformlocalaccount.NewEncryptedTOTPEnrollmentSecurity(
		platformLocalAccountHTTPTOTPEngine{}, platformLocalAccountHTTPTOTPCipher{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return security
}

type noProgressReadCloser struct{}

func (noProgressReadCloser) Read([]byte) (int, error) { return 0, nil }
func (noProgressReadCloser) Close() error             { return nil }

func newPlatformLocalAccountTestRouter(t *testing.T, service PlatformLocalAccountService) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auth := groupTransportAuthentication(mustTransportUUIDv7(t), mustTransportUUIDv7(t))
	auth.authenticateResult.ActiveTenantID = nil
	auth.authenticateResult.Permissions = []authorization.Permission{
		authorization.PermissionPlatformIdentityAccountRead,
		authorization.PermissionPlatformIdentityAccountManage,
	}
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
			PlatformLocalAccounts: service, PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return Router(handler, logger, false)
}

func platformLocalAccountReadRequest(path string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	return request
}

func platformLocalAccountMutationRequest(method, path, body string) *http.Request {
	return platformIdentityProviderMutationRequest(method, path, body)
}

func platformLocalAccountHTTPFixture(t *testing.T, status platformlocalaccount.Status, revision uint64) platformlocalaccount.Account {
	t.Helper()
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	account := platformlocalaccount.Account{
		ID: mustTransportUUIDv7(t), UserID: mustTransportUUIDv7(t), DisplayName: "Emergency Operator",
		LoginIdentifier: "emergency@example.test", Status: status,
		LoginIdentifierStatus: platformlocalaccount.LoginIdentifierVerified,
		CredentialStatus:      platformlocalaccount.CredentialActive,
		CredentialVersion:     2, ConfirmedAcceptableFactors: 1,
		ProtectedRecoveryPrincipal: true, Revision: revision, IdentityEpoch: revision,
		InvitedAt: now.Add(-2 * time.Hour), ActivatedAt: &now, UpdatedAt: now,
	}
	if status == platformlocalaccount.StatusDisabled {
		account.LoginIdentifierStatus = platformlocalaccount.LoginIdentifierDisabled
		account.CredentialStatus = platformlocalaccount.CredentialDisabled
		account.DisabledAt = &now
	}
	return account
}

func assertPlatformLocalAccountResponseSafe(t *testing.T, body []byte) {
	t.Helper()
	lower := strings.ToLower(string(body))
	for _, forbidden := range []string{"password", "phc", "digest", "factorproof", "factorsecret", "recoverycode", "sessionprovenance", "permissions", "roles", "tenantmemberships"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("response contains forbidden field %q: %s", forbidden, body)
		}
	}
}

func allPlatformLocalAccountBytesCleared(value []byte) bool {
	for _, item := range value[:cap(value)] {
		if item != 0 {
			return false
		}
	}
	return true
}
