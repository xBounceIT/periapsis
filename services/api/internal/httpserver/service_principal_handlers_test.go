package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/alert"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/serviceaccount"
)

type transportServiceAccountStub struct {
	*serviceaccount.Service
	createAccountCalls   int
	createAccountFunc    func(context.Context, authorization.Actor, uuid.UUID, serviceaccount.CreateAccountInput) (serviceaccount.Account, error)
	getCredentialFunc    func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID) (serviceaccount.CredentialMetadata, error)
	issueCredentialCalls int
	issueCredentialFunc  func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, serviceaccount.IssueCredentialInput) (serviceaccount.CredentialSecret, error)
	listAccountsCalls    int
	listAccountsFunc     func(context.Context, authorization.Actor, uuid.UUID, serviceaccount.ListAccountsInput) (serviceaccount.AccountPage, error)
	listCredentialsFunc  func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, serviceaccount.ListCredentialsInput) (serviceaccount.CredentialPage, error)
}

func (s *transportServiceAccountStub) CreateAccount(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input serviceaccount.CreateAccountInput,
) (serviceaccount.Account, error) {
	s.createAccountCalls++
	if s.createAccountFunc == nil {
		return serviceaccount.Account{}, serviceaccount.ErrUnavailable
	}
	return s.createAccountFunc(ctx, actor, tenantID, input)
}

func (s *transportServiceAccountStub) ListAccounts(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input serviceaccount.ListAccountsInput,
) (serviceaccount.AccountPage, error) {
	s.listAccountsCalls++
	if s.listAccountsFunc == nil {
		return serviceaccount.AccountPage{}, serviceaccount.ErrUnavailable
	}
	return s.listAccountsFunc(ctx, actor, tenantID, input)
}

func (s *transportServiceAccountStub) ListCredentials(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	serviceAccountID uuid.UUID,
	input serviceaccount.ListCredentialsInput,
) (serviceaccount.CredentialPage, error) {
	if s.listCredentialsFunc == nil {
		return serviceaccount.CredentialPage{}, serviceaccount.ErrUnavailable
	}
	return s.listCredentialsFunc(ctx, actor, tenantID, serviceAccountID, input)
}

func (s *transportServiceAccountStub) GetCredential(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	serviceAccountID uuid.UUID,
	credentialID uuid.UUID,
) (serviceaccount.CredentialMetadata, error) {
	if s.getCredentialFunc == nil {
		return serviceaccount.CredentialMetadata{}, serviceaccount.ErrUnavailable
	}
	return s.getCredentialFunc(ctx, actor, tenantID, serviceAccountID, credentialID)
}

func (s *transportServiceAccountStub) IssueCredential(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	serviceAccountID uuid.UUID,
	input serviceaccount.IssueCredentialInput,
) (serviceaccount.CredentialSecret, error) {
	s.issueCredentialCalls++
	if s.issueCredentialFunc == nil {
		return serviceaccount.CredentialSecret{}, serviceaccount.ErrUnavailable
	}
	return s.issueCredentialFunc(ctx, actor, tenantID, serviceAccountID, input)
}

type transportAlertStub struct {
	*alert.Service
	bearerCalls int
	bearerFunc  func(context.Context, uuid.UUID, alert.BearerCreateInput) (alert.Alert, error)
	humanCalls  int
	humanFunc   func(context.Context, authorization.Actor, uuid.UUID, alert.CreateInput) (alert.Alert, error)
}

func (s *transportAlertStub) CreateAsHuman(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input alert.CreateInput,
) (alert.Alert, error) {
	s.humanCalls++
	if s.humanFunc == nil {
		return alert.Alert{}, alert.ErrUnavailable
	}
	return s.humanFunc(ctx, actor, tenantID, input)
}

func (s *transportAlertStub) CreateAsBearer(
	ctx context.Context,
	tenantID uuid.UUID,
	input alert.BearerCreateInput,
) (alert.Alert, error) {
	s.bearerCalls++
	if s.bearerFunc == nil {
		return alert.Alert{}, alert.ErrUnavailable
	}
	return s.bearerFunc(ctx, tenantID, input)
}

func TestCreateTenantAlertRejectsMixedAuthenticationWithoutFallback(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	service := &transportAlertStub{}
	request := alertCreateRequest(t, tenantID)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	response := httptest.NewRecorder()

	newServicePrincipalTestRouter(t, groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())), nil, service, nil).
		ServeHTTP(response, request)

	assertProblem(t, response, http.StatusUnauthorized, "authentication_failed")
	assertServiceAccountBearerChallenge(t, response)
	if service.humanCalls != 0 || service.bearerCalls != 0 {
		t.Fatalf("Alert service calls = human %d, bearer %d", service.humanCalls, service.bearerCalls)
	}
}

func TestCreateTenantAlertRejectsAmbiguousBearerHeaders(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	for _, test := range []struct {
		name   string
		values []string
	}{
		{name: "comma folded", values: []string{"Bearer " + strings.Repeat("a", 64) + ",Bearer " + strings.Repeat("b", 64)}},
		{name: "multiple fields", values: []string{"Bearer " + strings.Repeat("a", 64), "Bearer " + strings.Repeat("b", 64)}},
		{name: "folded whitespace", values: []string{"Bearer  " + strings.Repeat("a", 64)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &transportAlertStub{}
			request := alertCreateRequest(t, tenantID)
			for _, value := range test.values {
				request.Header.Add("Authorization", value)
			}
			response := httptest.NewRecorder()

			newServicePrincipalTestRouter(t, groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())), nil, service, nil).
				ServeHTTP(response, request)

			assertProblem(t, response, http.StatusUnauthorized, "authentication_failed")
			assertServiceAccountBearerChallenge(t, response)
			if service.bearerCalls != 0 || service.humanCalls != 0 {
				t.Fatal("ambiguous bearer request reached the Alert service")
			}
		})
	}
}

func TestCreateTenantAlertMissingAuthenticationIncludesBearerChallenge(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	service := &transportAlertStub{}
	request := alertCreateRequest(t, tenantID)
	response := httptest.NewRecorder()

	newServicePrincipalTestRouter(t, groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())), nil, service, nil).
		ServeHTTP(response, request)

	assertProblem(t, response, http.StatusUnauthorized, "authentication_failed")
	assertServiceAccountBearerChallenge(t, response)
	if service.humanCalls != 0 || service.bearerCalls != 0 {
		t.Fatalf("Alert service calls = human %d, bearer %d", service.humanCalls, service.bearerCalls)
	}
}

func TestCreateTenantAlertInvalidCookieIncludesBearerChallenge(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	service := &transportAlertStub{}
	authenticationService := groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7()))
	authenticationService.authenticateError = authentication.ErrInvalidAuthentication
	request := alertCreateRequest(t, tenantID)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "expired-session"})
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, "csrf-value")
	response := httptest.NewRecorder()

	newServicePrincipalTestRouter(t, authenticationService, nil, service, nil).ServeHTTP(response, request)

	assertProblem(t, response, http.StatusUnauthorized, "authentication_failed")
	assertServiceAccountBearerChallenge(t, response)
	if service.humanCalls != 0 || service.bearerCalls != 0 {
		t.Fatalf("Alert service calls = human %d, bearer %d", service.humanCalls, service.bearerCalls)
	}
}

func TestCreateTenantAlertRejectsDuplicateOrFoldedIdempotencyKey(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	for _, test := range []struct {
		name   string
		values []string
	}{
		{name: "multiple fields", values: []string{"retry-key-00000001", "retry-key-00000002"}},
		{name: "comma folded", values: []string{"retry-key-00000001,retry-key-00000002"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &transportAlertStub{}
			request := alertCreateRequest(t, tenantID)
			request.Header.Del(idempotencyKeyHeader)
			for _, value := range test.values {
				request.Header.Add(idempotencyKeyHeader, value)
			}
			request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
			response := httptest.NewRecorder()

			newServicePrincipalTestRouter(t, groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())), nil, service, nil).
				ServeHTTP(response, request)

			assertProblem(t, response, http.StatusBadRequest, "invalid_request")
			if service.bearerCalls != 0 {
				t.Fatal("ambiguous idempotency request reached the Alert service")
			}
		})
	}
}

func TestCreateTenantAlertRejectsDuplicateContentType(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	service := &transportAlertStub{}
	request := alertCreateRequest(t, tenantID)
	request.Header.Add("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	response := httptest.NewRecorder()

	newServicePrincipalTestRouter(t, groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())), nil, service, nil).
		ServeHTTP(response, request)

	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	if service.bearerCalls != 0 || service.humanCalls != 0 {
		t.Fatal("ambiguous Content-Type request reached the Alert service")
	}
}

func TestServiceAccountMutationRequiresCSRF(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	service := &transportServiceAccountStub{}
	request := servicePrincipalMutationRequest(
		http.MethodPost,
		fmt.Sprintf("/api/v1/tenants/%s/service-accounts", tenantID),
		`{"key":"alert_ingest","displayName":"Alert ingest"}`,
	)
	request.Header.Del(csrfTokenHeader)
	response := httptest.NewRecorder()

	newServicePrincipalTestRouter(t, groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())), service, nil, nil).
		ServeHTTP(response, request)

	assertProblem(t, response, http.StatusForbidden, "forbidden")
	if service.createAccountCalls != 0 {
		t.Fatal("mutation without CSRF reached the service-account service")
	}
}

func TestServiceAccountHandlerRejectsCrossTenantActorBeforeService(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	activeTenantID := uuid.Must(uuid.NewV7())
	service := &transportServiceAccountStub{}
	request := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/tenants/%s/service-accounts", tenantID), nil)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	response := httptest.NewRecorder()

	newServicePrincipalTestRouter(t, groupTransportAuthentication(activeTenantID, uuid.Must(uuid.NewV7())), service, nil, nil).
		ServeHTTP(response, request)

	assertProblem(t, response, http.StatusForbidden, "forbidden")
	if service.listAccountsCalls != 0 {
		t.Fatal("cross-tenant actor reached the service-account service")
	}
}

func TestCredentialReplayIsRedactedAndNeverCacheable(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	serviceAccountID := uuid.Must(uuid.NewV7())
	credentialID := uuid.Must(uuid.NewV7())
	service := &transportServiceAccountStub{issueCredentialFunc: func(
		context.Context,
		authorization.Actor,
		uuid.UUID,
		uuid.UUID,
		serviceaccount.IssueCredentialInput,
	) (serviceaccount.CredentialSecret, error) {
		return serviceaccount.CredentialSecret{}, &serviceaccount.OneTimeSecretAlreadyIssuedError{
			ServiceAccountID: serviceAccountID, CredentialID: credentialID, Version: 3,
		}
	}}
	request := servicePrincipalMutationRequest(
		http.MethodPost,
		fmt.Sprintf("/api/v1/tenants/%s/service-accounts/%s/credentials", tenantID, serviceAccountID),
		credentialWriteBody(),
	)
	request.Header.Set(idempotencyKeyHeader, "retry-key-00000001")
	response := httptest.NewRecorder()

	newServicePrincipalTestRouter(t, groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())), service, nil, nil).
		ServeHTTP(response, request)

	body := response.Body.String()
	assertProblem(t, response, http.StatusConflict, "one_time_secret_already_issued")
	wantLocation := serviceAccountCredentialLocation(tenantID, serviceAccountID, credentialID)
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Location") != wantLocation {
		t.Fatalf("replay headers = %#v", response.Header())
	}
	if strings.Contains(strings.ToLower(body), "bearertoken") || strings.Contains(body, strings.Repeat("a", 64)) {
		t.Fatalf("replay response exposed a token: %s", body)
	}
	var problem struct {
		CredentialID uuid.UUID `json:"credentialId"`
		Location     string    `json:"location"`
	}
	if err := json.Unmarshal([]byte(body), &problem); err != nil || problem.CredentialID != credentialID || problem.Location != wantLocation {
		t.Fatalf("replay problem = %#v, error = %v", problem, err)
	}
}

func TestCredentialMetadataResponsesAreStructurallyRedacted(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	serviceAccountID := uuid.Must(uuid.NewV7())
	credential := credentialHTTPFixture(tenantID, serviceAccountID)
	service := &transportServiceAccountStub{
		listCredentialsFunc: func(
			context.Context,
			authorization.Actor,
			uuid.UUID,
			uuid.UUID,
			serviceaccount.ListCredentialsInput,
		) (serviceaccount.CredentialPage, error) {
			return serviceaccount.CredentialPage{Items: []serviceaccount.CredentialMetadata{credential}}, nil
		},
		getCredentialFunc: func(
			context.Context,
			authorization.Actor,
			uuid.UUID,
			uuid.UUID,
			uuid.UUID,
		) (serviceaccount.CredentialMetadata, error) {
			return credential, nil
		},
	}
	router := newServicePrincipalTestRouter(t, groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())), service, nil, nil)
	paths := []string{
		fmt.Sprintf("/api/v1/tenants/%s/service-accounts/%s/credentials", tenantID, serviceAccountID),
		fmt.Sprintf("/api/v1/tenants/%s/service-accounts/%s/credentials/%s", tenantID, serviceAccountID, credential.ID),
	}
	for _, path := range paths {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		if response.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d: %s", path, response.Code, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("GET %s lacks no-store", path)
		}
		lower := strings.ToLower(response.Body.String())
		for _, forbidden := range []string{"bearertoken", "locator", "digest", "keyversion", "formatversion"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("GET %s exposed %q: %s", path, forbidden, response.Body.String())
			}
		}
	}
}

func TestServiceAccountBodyRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	service := &transportServiceAccountStub{}
	request := servicePrincipalMutationRequest(
		http.MethodPost,
		fmt.Sprintf("/api/v1/tenants/%s/service-accounts", tenantID),
		`{"key":"alert_ingest","displayName":"Alert ingest","principalType":"service_account"}`,
	)
	response := httptest.NewRecorder()

	newServicePrincipalTestRouter(t, groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())), service, nil, nil).
		ServeHTTP(response, request)

	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	if service.createAccountCalls != 0 {
		t.Fatal("body with an unknown field reached the service-account service")
	}
}

func TestServiceAccountRoleGrantMapsGenericInactiveDependencyAsExpired(t *testing.T) {
	t.Parallel()

	tenantID, accountID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	grantedAt := time.Date(2026, time.August, 25, 10, 0, 0, 0, time.UTC)
	retiredAt := grantedAt.Add(time.Hour)
	value := serviceaccount.RoleGrant{
		ID: uuid.Must(uuid.NewV7()), TenantID: tenantID, ServiceAccountID: accountID,
		Role: serviceaccount.RoleSummary{
			ID: uuid.Must(uuid.NewV7()), Key: "alert_ingest", DisplayName: "Alert ingest", System: true,
		},
		SourceID: uuid.Must(uuid.NewV7()), SourceKind: authorization.AuthorizationSourceIdentityMapping,
		SourceKey: "idp:collector", SourceAuthoritative: true, SourceRetiredAt: &retiredAt,
		GrantedByMembershipID: uuid.Must(uuid.NewV7()), GrantedByUserID: uuid.Must(uuid.NewV7()),
		GrantReason: "Collector mapping", GrantedAt: grantedAt, State: serviceaccount.RoleGrantStateExpired,
		Version: 2, UpdatedAt: grantedAt,
	}

	mapped, err := mapServiceAccountRoleGrant(value, tenantID, accountID)
	if err != nil {
		t.Fatalf("mapServiceAccountRoleGrant() error = %v", err)
	}
	if mapped.State != contract.AuthorizationEdgeStateExpired || mapped.ManagedByServiceAccountApi || mapped.Provenance.ExpiresAt != nil ||
		mapped.Provenance.RetiredAt == nil || *mapped.Provenance.RetiredAt != retiredAt {
		t.Fatalf("mapped generic expiry = %#v", mapped)
	}

	value.State = serviceaccount.RoleGrantStateActive
	if _, err := mapServiceAccountRoleGrant(value, tenantID, accountID); err == nil {
		t.Fatal("mapServiceAccountRoleGrant() accepted an active grant with a retired source")
	}

	value.SourceKind = authorization.AuthorizationSourceManual
	value.SourceKey = "manual"
	value.SourceAuthoritative = false
	value.SourceRetiredAt = nil
	value.State = serviceaccount.RoleGrantStateActive
	value.ManagedByServiceAccountAPI = true
	mapped, err = mapServiceAccountRoleGrant(value, tenantID, accountID)
	if err != nil {
		t.Fatalf("mapServiceAccountRoleGrant(managed) error = %v", err)
	}
	if !mapped.ManagedByServiceAccountApi {
		t.Fatalf("mapped managed grant = %#v", mapped)
	}
}

func TestCreatedAlertMapperPreservesPresentEmptyDescription(t *testing.T) {
	t.Parallel()

	tenantID, serviceAccountID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	value := createdAlertHTTPFixture(tenantID, nil, &serviceAccountID)
	empty := ""
	value.Description = &empty

	mapped, err := mapCreatedAlert(value, tenantID)
	if err != nil {
		t.Fatalf("mapCreatedAlert() error = %v", err)
	}
	if mapped.Description == nil || *mapped.Description != "" {
		t.Fatalf("mapped description = %#v", mapped.Description)
	}
}

func TestCreatedAlertMapperAcceptsCurrentReplayStatus(t *testing.T) {
	t.Parallel()

	tenantID, serviceAccountID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	value := createdAlertHTTPFixture(tenantID, nil, &serviceAccountID)
	value.Status = alert.StatusInProgress
	value.Version = 2
	value.UpdatedAt = value.CreatedAt.Add(time.Minute)

	mapped, err := mapCreatedAlert(value, tenantID)
	if err != nil {
		t.Fatalf("mapCreatedAlert() error = %v", err)
	}
	if mapped.Status != contract.AlertStatusInProgress || mapped.Version != 2 {
		t.Fatalf("mapped current replay = %#v", mapped)
	}
}

func TestCredentialMapperRejectsLastUseAfterExpiryOrProjectionUpdate(t *testing.T) {
	t.Parallel()

	tenantID, serviceAccountID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, test := range []struct {
		name     string
		lastUsed func(serviceaccount.CredentialMetadata) time.Time
		updated  func(serviceaccount.CredentialMetadata) time.Time
	}{
		{
			name:     "after expiry",
			lastUsed: func(value serviceaccount.CredentialMetadata) time.Time { return value.ExpiresAt.Add(time.Microsecond) },
			updated:  func(value serviceaccount.CredentialMetadata) time.Time { return value.ExpiresAt.Add(time.Minute) },
		},
		{
			name:     "after projection update",
			lastUsed: func(value serviceaccount.CredentialMetadata) time.Time { return value.IssuedAt.Add(time.Minute) },
			updated:  func(value serviceaccount.CredentialMetadata) time.Time { return value.IssuedAt },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := credentialHTTPFixture(tenantID, serviceAccountID)
			lastUsedAt := test.lastUsed(value)
			lastUsedIP := netip.MustParseAddr("198.51.100.20")
			value.LastUsedAt, value.LastUsedIP = &lastUsedAt, &lastUsedIP
			value.UpdatedAt = test.updated(value)
			if _, err := mapServiceAccountCredential(value, tenantID, serviceAccountID); err == nil {
				t.Fatal("mapServiceAccountCredential() accepted impossible usage timestamps")
			}
		})
	}
}

func TestCredentialMapperPreservesPostgreSQLCIDROrder(t *testing.T) {
	t.Parallel()

	tenantID, serviceAccountID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	value := credentialHTTPFixture(tenantID, serviceAccountID)
	value.Networks = []netip.Prefix{
		netip.MustParsePrefix("2.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/9"),
		netip.MustParsePrefix("10.128.0.0/9"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2001:db8::/48"),
		netip.MustParsePrefix("2001:db8:1::/48"),
	}

	mapped, err := mapServiceAccountCredential(value, tenantID, serviceAccountID)
	if err != nil {
		t.Fatalf("mapServiceAccountCredential() error = %v", err)
	}
	want := []contract.ServiceAccountCredentialCidr{
		"2.0.0.0/8", "10.0.0.0/8", "10.0.0.0/9", "10.128.0.0/9",
		"2001:db8::/32", "2001:db8::/48", "2001:db8:1::/48",
	}
	if !reflect.DeepEqual(mapped.AllowedNetworks, want) {
		t.Fatalf("AllowedNetworks = %v, want PostgreSQL cidr order %v", mapped.AllowedNetworks, want)
	}
}

func TestCredentialMapperRejectsLastUseAfterRevocation(t *testing.T) {
	t.Parallel()

	tenantID, serviceAccountID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	value := credentialHTTPFixture(tenantID, serviceAccountID)
	revokedAt := value.IssuedAt.Add(20 * time.Minute)
	lastUsedAt := value.IssuedAt.Add(30 * time.Minute)
	lastUsedIP := netip.MustParseAddr("198.51.100.20")
	revokedMembershipID, revokedUserID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	reason := "credential replaced"
	value.State = serviceaccount.CredentialStateRevoked
	value.RevokedAt = &revokedAt
	value.RevokedByMembershipID = &revokedMembershipID
	value.RevokedByUserID = &revokedUserID
	value.RevokeReason = &reason
	value.LastUsedAt, value.LastUsedIP = &lastUsedAt, &lastUsedIP
	value.UpdatedAt = value.IssuedAt.Add(40 * time.Minute)

	if _, err := mapServiceAccountCredential(value, tenantID, serviceAccountID); err == nil {
		t.Fatal("mapServiceAccountCredential() accepted use after revocation")
	}
}

func TestBearerAlertUsesCanonicalTrustedProxyAddress(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	serviceAccountID := uuid.Must(uuid.NewV7())
	clientAddress := netip.MustParseAddr("203.0.113.50")
	token := strings.Repeat("a", 64)
	service := &transportAlertStub{bearerFunc: func(
		_ context.Context,
		actualTenantID uuid.UUID,
		input alert.BearerCreateInput,
	) (alert.Alert, error) {
		if actualTenantID != tenantID || input.Token != token || input.Audit.RemoteAddress != clientAddress {
			t.Fatalf("bearer input = tenant %s, token length %d, address %s", actualTenantID, len(input.Token), input.Audit.RemoteAddress)
		}
		return createdAlertHTTPFixture(tenantID, nil, &serviceAccountID), nil
	}}
	request := alertCreateRequest(t, tenantID)
	request.Header.Set("Authorization", "Bearer "+token)
	request.RemoteAddr = "172.30.240.3:40000"
	request.Header.Set("X-Forwarded-For", clientAddress.String())
	response := httptest.NewRecorder()

	newServicePrincipalTestRouter(
		t, groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())), nil, service,
		[]netip.Prefix{netip.MustParsePrefix("172.30.240.3/32")},
	).ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if service.bearerCalls != 1 || service.humanCalls != 0 {
		t.Fatalf("Alert calls = bearer %d, human %d", service.bearerCalls, service.humanCalls)
	}
	if response.Header().Get("ETag") != `"v1"` || response.Header().Get("Location") == "" {
		t.Fatalf("response headers = %#v", response.Header())
	}
}

func TestServicePrincipalDomainErrorsUseProblemMappings(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "invalid", err: serviceaccount.ErrInvalidInput, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "forbidden", err: serviceaccount.ErrForbidden, status: http.StatusForbidden, code: "forbidden"},
		{name: "not found", err: serviceaccount.ErrNotFound, status: http.StatusNotFound, code: "not_found"},
		{name: "conflict", err: serviceaccount.ErrConflict, status: http.StatusConflict, code: "conflict"},
		{name: "precondition failed", err: serviceaccount.ErrPreconditionFailed, status: http.StatusPreconditionFailed, code: "precondition_failed"},
		{name: "precondition required", err: serviceaccount.ErrPreconditionRequired, status: http.StatusPreconditionRequired, code: "precondition_required"},
		{name: "unavailable", err: serviceaccount.ErrUnavailable, status: http.StatusServiceUnavailable, code: "service_unavailable"},
		{name: "deadline", err: context.DeadlineExceeded, status: http.StatusServiceUnavailable, code: "service_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := requestWithTestID()
			response := httptest.NewRecorder()
			(&Handler{}).writeServiceAccountError(response, request, test.err)
			assertProblem(t, response, test.status, test.code)
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("problem response is cacheable")
			}
		})
	}
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{alert.ErrInvalidInput, http.StatusBadRequest, "invalid_request"},
		{alert.ErrUnauthenticated, http.StatusUnauthorized, "authentication_failed"},
		{alert.ErrForbidden, http.StatusForbidden, "forbidden"},
		{alert.ErrConflict, http.StatusConflict, "conflict"},
		{alert.ErrUnavailable, http.StatusServiceUnavailable, "service_unavailable"},
	} {
		request := requestWithTestID()
		response := httptest.NewRecorder()
		(&Handler{}).writeAlertError(response, request, test.err)
		assertProblem(t, response, test.status, test.code)
		if errors.Is(test.err, alert.ErrUnauthenticated) {
			assertServiceAccountBearerChallenge(t, response)
		} else if response.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("non-authentication Alert error emitted a bearer challenge: %#v", response.Header())
		}
	}
}

func assertServiceAccountBearerChallenge(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if challenge := response.Header().Get("WWW-Authenticate"); challenge != `Bearer realm="periapsis"` {
		t.Fatalf("WWW-Authenticate = %q, want generic service-account bearer challenge", challenge)
	}
}

func TestApplicationHandlerRequiresServicePrincipalBoundaries(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, ApplicationOptions{
		Authentication: &transportAuthStub{}, Authorization: &transportAuthorizationStub{}, Environment: "test",
		LDAPAdministration: &transportLDAPAdministrationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{}, PublicOrigin: "http://localhost:8081",
	})
	if err == nil {
		t.Fatal("NewApplicationHandler accepted missing service-principal boundaries")
	}
}

func TestApplicationHandlerRequiresTicketingBoundary(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, ApplicationOptions{
		Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: &transportAuthStub{}, Authorization: &transportAuthorizationStub{},
		Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{}, Environment: "test",
		IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{},
		Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
		PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{},
	})
	if err == nil || !strings.Contains(err.Error(), "ticketing") {
		t.Fatalf("NewApplicationHandler() error = %v, want missing ticketing boundary", err)
	}
}

func newServicePrincipalTestRouter(
	t *testing.T,
	auth AuthenticationService,
	serviceAccounts ServiceAccountService,
	alerts AlertService,
	trusted []netip.Prefix,
) http.Handler {
	t.Helper()
	if serviceAccounts == nil {
		serviceAccounts = &transportServiceAccountStub{}
	}
	if alerts == nil {
		alerts = &transportAlertStub{}
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, ApplicationOptions{
		Alerts: alerts, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{}, Environment: "test",
		Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
		IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{}, PublicOrigin: "http://localhost:8081",
		ServiceAccounts: serviceAccounts, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{}, TrustedProxyCIDRs: trusted,
	})
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func servicePrincipalMutationRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, "csrf-value")
	return request
}

func alertCreateRequest(t *testing.T, tenantID uuid.UUID) *http.Request {
	t.Helper()
	request := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/v1/tenants/%s/alerts", tenantID),
		strings.NewReader(`{"title":"Suspicious process","severity":"high"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(idempotencyKeyHeader, "retry-key-00000001")
	return request
}

func credentialWriteBody() string {
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)
	return fmt.Sprintf(
		`{"label":"Alert integration","expiresAt":%q,"permissions":[{"permissionKey":"alert.create","scope":"tenant"}],"allowedNetworks":[]}`,
		expiresAt,
	)
}

func credentialHTTPFixture(tenantID, serviceAccountID uuid.UUID) serviceaccount.CredentialMetadata {
	issuedAt := time.Date(2026, time.August, 25, 10, 0, 0, 0, time.UTC)
	return serviceaccount.CredentialMetadata{
		ID: uuid.Must(uuid.NewV7()), TenantID: tenantID, ServiceAccountID: serviceAccountID,
		Label: "Alert integration", FormatVersion: 1, KeyVersion: 2,
		Permissions:          []authorization.ScopedPermission{{Permission: authorization.TenantPermissionAlertCreate, Scope: authorization.ScopeTenant}},
		Networks:             []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		IssuedByMembershipID: uuid.Must(uuid.NewV7()), IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(24 * time.Hour),
		State: serviceaccount.CredentialStateActive, Version: 2, UpdatedAt: issuedAt,
	}
}

func createdAlertHTTPFixture(tenantID uuid.UUID, membershipID, serviceAccountID *uuid.UUID) alert.Alert {
	createdAt := time.Date(2026, time.August, 25, 10, 0, 0, 0, time.UTC)
	value := alert.Alert{
		ID: uuid.Must(uuid.NewV7()), TenantID: tenantID, Title: "Suspicious process",
		Status: alert.StatusNew, Severity: alert.SeverityHigh, CreatedAt: createdAt, UpdatedAt: createdAt, Version: 1,
		CreatedByMembershipID: membershipID, CreatedByServiceAccountID: serviceAccountID,
	}
	if membershipID != nil {
		userID := uuid.Must(uuid.NewV7())
		value.CreatedByUserID = &userID
	}
	return value
}

func requestWithTestID() *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	return request.WithContext(context.WithValue(request.Context(), requestIDKey{}, uuid.Must(uuid.NewV7()).String()))
}

var _ ServiceAccountService = (*transportServiceAccountStub)(nil)
var _ AlertService = (*transportAlertStub)(nil)
