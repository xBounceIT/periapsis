package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/mfapolicy"
)

type mfaPolicyHTTPStub struct {
	publishPlatform func(context.Context, authentication.Session, mfapolicy.PublishInput) (mfapolicy.MutationResult, error)
}

func (stub *mfaPolicyHTTPStub) ListPlatform(context.Context, authentication.Session, mfapolicy.ListInput) (mfapolicy.Page, error) {
	return mfapolicy.Page{}, mfapolicy.ErrUnavailable
}

func (stub *mfaPolicyHTTPStub) ListTenant(context.Context, authentication.Session, uuid.UUID, mfapolicy.ListInput) (mfapolicy.Page, error) {
	return mfapolicy.Page{}, mfapolicy.ErrUnavailable
}

func (stub *mfaPolicyHTTPStub) GetPlatform(context.Context, authentication.Session, uuid.UUID, int64) (mfa.PolicyDocument, error) {
	return mfa.PolicyDocument{}, mfapolicy.ErrUnavailable
}

func (stub *mfaPolicyHTTPStub) GetTenant(context.Context, authentication.Session, uuid.UUID, uuid.UUID, int64) (mfa.PolicyDocument, error) {
	return mfa.PolicyDocument{}, mfapolicy.ErrUnavailable
}

func (stub *mfaPolicyHTTPStub) SimulatePlatform(context.Context, authentication.Session, mfapolicy.SimulationInput) (mfa.PolicySimulation, error) {
	return mfa.PolicySimulation{}, mfapolicy.ErrUnavailable
}

func (stub *mfaPolicyHTTPStub) SimulateTenant(context.Context, authentication.Session, uuid.UUID, mfapolicy.SimulationInput) (mfa.PolicySimulation, error) {
	return mfa.PolicySimulation{}, mfapolicy.ErrUnavailable
}

func (stub *mfaPolicyHTTPStub) PublishPlatform(
	ctx context.Context,
	session authentication.Session,
	input mfapolicy.PublishInput,
) (mfapolicy.MutationResult, error) {
	if stub.publishPlatform == nil {
		return mfapolicy.MutationResult{}, mfapolicy.ErrUnavailable
	}
	return stub.publishPlatform(ctx, session, input)
}

func (stub *mfaPolicyHTTPStub) PublishTenant(context.Context, authentication.Session, uuid.UUID, mfapolicy.PublishInput) (mfapolicy.MutationResult, error) {
	return mfapolicy.MutationResult{}, mfapolicy.ErrUnavailable
}

func (stub *mfaPolicyHTTPStub) RetirePlatform(context.Context, authentication.Session, mfapolicy.RetireInput) (mfapolicy.MutationResult, error) {
	return mfapolicy.MutationResult{}, mfapolicy.ErrUnavailable
}

func (stub *mfaPolicyHTTPStub) RetireTenant(context.Context, authentication.Session, uuid.UUID, mfapolicy.RetireInput) (mfapolicy.MutationResult, error) {
	return mfapolicy.MutationResult{}, mfapolicy.ErrUnavailable
}

func TestPublishPlatformMFAPolicyMapsExactCommandAndReceipt(t *testing.T) {
	commandID := uuid.Must(uuid.NewV7())
	policyID := uuid.Must(uuid.NewV7())
	createdAt := time.Date(2026, time.August, 30, 12, 0, 0, 123_000_000, time.UTC)
	service := &mfaPolicyHTTPStub{publishPlatform: func(
		_ context.Context,
		_ authentication.Session,
		input mfapolicy.PublishInput,
	) (mfapolicy.MutationResult, error) {
		if input.CommandID != commandID || input.Reason != "Publish explicit platform floor" ||
			input.ExpectedRevision != 0 || input.ExpectedPolicyID != nil ||
			input.Target.Scope != mfa.PolicyPlatformFloor || input.Requirement.Level != identity.AssuranceMFA ||
			!input.Requirement.LocalRequired || input.Requirement.Freshness != 5*time.Minute ||
			input.Event.RequestID == uuid.Nil || input.Event.CorrelationID == uuid.Nil {
			t.Fatalf("input = %#v", input)
		}
		return mfapolicy.MutationResult{Policy: mfa.PolicyDocument{
			ID: identity.EntityID(policyID), Revision: 1,
			Target: input.Target, Requirement: input.Requirement,
			Status: mfa.PolicyLive, CreatedAt: createdAt,
		}}, nil
	}}
	router := newMFAPolicyTestRouter(t, service)
	request := mfaPolicyMutationRequest(
		http.MethodPost,
		"/api/v1/platform/mfa-policies",
		`{"target":{"scope":"platform_floor"},"expectedRevision":0,"requirement":{"level":"mfa","localRequired":true,"freshnessSeconds":300,"enrollmentDeadline":null}}`,
	)
	request.Header.Set(idempotencyKeyHeader, commandID.String())
	request.Header.Set("X-Audit-Reason", "Publish explicit platform floor")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"v1"` ||
		response.Header().Get("Location") != fmt.Sprintf("/api/v1/platform/mfa-policies/%s/revisions/1", policyID) ||
		!strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("response = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var result contract.MfaPolicyMutationResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || uuid.UUID(result.Policy.Id) != policyID || result.Replayed {
		t.Fatalf("result = %#v, %v", result, err)
	}
}

func TestMFAPolicyTransportRejectsNonExactBodiesAndPreconditions(t *testing.T) {
	commandID := uuid.Must(uuid.NewV7())
	policyID := uuid.Must(uuid.NewV7())
	calls := 0
	service := &mfaPolicyHTTPStub{publishPlatform: func(
		context.Context,
		authentication.Session,
		mfapolicy.PublishInput,
	) (mfapolicy.MutationResult, error) {
		calls++
		return mfapolicy.MutationResult{}, mfapolicy.ErrUnavailable
	}}
	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		ifMatch    string
		wantStatus int
	}{
		{
			name: "missing nullable deadline remains missing", method: http.MethodPost,
			path:       "/api/v1/platform/mfa-policies",
			body:       `{"target":{"scope":"platform_floor"},"expectedRevision":0,"requirement":{"level":"mfa","localRequired":true,"freshnessSeconds":300}}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "wrong freshness type", method: http.MethodPost,
			path:       "/api/v1/platform/mfa-policies",
			body:       `{"target":{"scope":"platform_floor"},"expectedRevision":0,"requirement":{"level":"mfa","localRequired":true,"freshnessSeconds":"300","enrollmentDeadline":null}}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "freshness multiplication overflow", method: http.MethodPost,
			path:       "/api/v1/platform/mfa-policies",
			body:       `{"target":{"scope":"platform_floor"},"expectedRevision":0,"requirement":{"level":"mfa","localRequired":true,"freshnessSeconds":36028797018963968,"enrollmentDeadline":null}}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "tenant id body smuggling", method: http.MethodPost,
			path:       "/api/v1/tenants/" + uuid.Must(uuid.NewV7()).String() + "/mfa-policies/simulate",
			body:       `{"operation":"publish","target":{"scope":"tenant_baseline","tenantId":"018f0000-0000-7000-8000-000000000001"},"expectedRevision":0,"requirement":{"level":"mfa","localRequired":true,"freshnessSeconds":300,"enrollmentDeadline":null},"context":{"roleIds":[],"securityGroupIds":[],"action":"case.export"}}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "duplicate member", method: http.MethodPost,
			path:       "/api/v1/platform/mfa-policies",
			body:       `{"target":{"scope":"platform_floor"},"expectedRevision":0,"expectedRevision":0,"requirement":{"level":"mfa","localRequired":true,"freshnessSeconds":300,"enrollmentDeadline":null}}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "missing if match", method: http.MethodPut,
			path:       "/api/v1/platform/mfa-policies/" + policyID.String(),
			body:       `{"target":{"scope":"platform_floor"},"expectedRevision":1,"requirement":{"level":"mfa","localRequired":true,"freshnessSeconds":300,"enrollmentDeadline":null}}`,
			wantStatus: http.StatusPreconditionRequired,
		},
		{
			name: "mismatched if match", method: http.MethodPut,
			path:    "/api/v1/platform/mfa-policies/" + policyID.String(),
			body:    `{"target":{"scope":"platform_floor"},"expectedRevision":2,"requirement":{"level":"mfa","localRequired":true,"freshnessSeconds":300,"enrollmentDeadline":null}}`,
			ifMatch: `"v1"`, wantStatus: http.StatusBadRequest,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := mfaPolicyMutationRequest(test.method, test.path, test.body)
			request.Header.Set(idempotencyKeyHeader, commandID.String())
			request.Header.Set("X-Audit-Reason", "Bounded policy change")
			if test.ifMatch != "" {
				request.Header.Set(ifMatchHeader, test.ifMatch)
			}
			response := httptest.NewRecorder()
			newMFAPolicyTestRouter(t, service).ServeHTTP(response, request)
			if response.Code != test.wantStatus || !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
				t.Fatalf("response = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
		})
	}
	if calls != 0 {
		t.Fatalf("service calls = %d", calls)
	}
}

func TestMFAPolicyRecoveryUnsafeUsesSpecificConflict(t *testing.T) {
	commandID := uuid.Must(uuid.NewV7())
	service := &mfaPolicyHTTPStub{publishPlatform: func(
		context.Context,
		authentication.Session,
		mfapolicy.PublishInput,
	) (mfapolicy.MutationResult, error) {
		return mfapolicy.MutationResult{}, mfapolicy.ErrRecoveryUnsafe
	}}
	request := mfaPolicyMutationRequest(
		http.MethodPost,
		"/api/v1/platform/mfa-policies",
		`{"target":{"scope":"platform_floor"},"expectedRevision":0,"requirement":{"level":"phishing_resistant","localRequired":true,"freshnessSeconds":300,"enrollmentDeadline":null}}`,
	)
	request.Header.Set(idempotencyKeyHeader, commandID.String())
	request.Header.Set("X-Audit-Reason", "Test recovery safety")
	response := httptest.NewRecorder()
	newMFAPolicyTestRouter(t, service).ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	assertPlatformIdentityProviderProblem(t, response, "mfa_policy_recovery_unsafe")
}

func TestMFAPolicyETagSupportsJavaScriptSafeRevisionCeiling(t *testing.T) {
	response := httptest.NewRecorder()
	if !setMFAPolicyETag(response, mfapolicy.MaximumSafeRevision) ||
		response.Header().Get("ETag") != `"v9007199254740991"` {
		t.Fatalf("ETag = %q", response.Header().Get("ETag"))
	}
	if setMFAPolicyETag(response, mfapolicy.MaximumSafeRevision+1) {
		t.Fatal("overflowing ETag was accepted")
	}
}

func newMFAPolicyTestRouter(t *testing.T, service MFAPolicyService) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	userID := uuid.Must(uuid.NewV7())
	auth := groupTransportAuthentication(uuid.Must(uuid.NewV7()), userID)
	auth.authenticateResult.ActiveTenantID = nil
	auth.authenticateResult.Permissions = []authorization.Permission{
		authorization.PermissionPlatformIdentityPolicyRead,
		authorization.PermissionPlatformIdentityPolicyManage,
	}
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, MFAPolicies: service, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
			PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func mfaPolicyMutationRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, "csrf-value")
	request.Header.Set("User-Agent", "periapsis-mfa-policy-test")
	return request
}

var _ MFAPolicyService = (*mfaPolicyHTTPStub)(nil)
