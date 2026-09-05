package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/sla"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationsla "github.com/periapsis-im/periapsis/services/api/internal/sla"
)

type transportSLAAuthorizationStub struct {
	*authorization.Service
	authority authorization.TenantAuthority
	err       error
	calls     int
}

func (s *transportSLAAuthorizationStub) GetTenantAuthority(
	context.Context,
	authorization.Actor,
	uuid.UUID,
) (authorization.TenantAuthority, error) {
	s.calls++
	return s.authority, s.err
}

func TestSLACalendarCreateUsesLiveActorAndReturnsCanonicalRepresentation(t *testing.T) {
	fixture := newSLATransportFixture(t, authorization.LegacyMembershipRoleAnalyst)
	var captured applicationsla.CalendarPublishCommand
	service := &transportSLAStub{publishCalendar: func(
		_ context.Context,
		actor applicationsla.Actor,
		tenantID uuid.UUID,
		command applicationsla.CalendarPublishCommand,
	) (applicationsla.PublicationResult[kernel.BusinessCalendar], error) {
		if actor.Kind != applicationsla.PrincipalOperator || actor.TenantID != fixture.tenantID ||
			actor.PrincipalID != fixture.userID || tenantID != fixture.tenantID {
			t.Fatalf("unexpected actor=%#v tenant=%s", actor, tenantID)
		}
		captured = command
		calendar, err := kernel.NewBusinessCalendar(command.Input)
		if err != nil {
			t.Fatalf("NewBusinessCalendar() error = %v", err)
		}
		return applicationsla.PublicationResult[kernel.BusinessCalendar]{
			Value: calendar, ResourceVersion: 1, CreatedAt: fixture.now, UpdatedAt: fixture.now,
		}, nil
	}}
	router := newSLATestRouter(t, fixture, service)
	body := calendarCreateBody(fixture.calendarID)
	request := fixture.mutationRequest(http.MethodPost, fixture.calendarCollectionPath(), body)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if captured.ExpectedActiveVersion != 0 || captured.Input.ID.String() != fixture.calendarID.String() ||
		captured.Envelope.IdempotencyKey != "sla-calendar-create-0001" {
		t.Fatalf("captured command = %#v", captured)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
	wantLocation := fixture.calendarCollectionPath() + "/" + fixture.calendarID.String()
	if response.Header().Get("Location") != wantLocation {
		t.Fatalf("Location = %q, want %q", response.Header().Get("Location"), wantLocation)
	}
	entityID := mustSLAEntityID(t, fixture.calendarID)
	wantETag := applicationsla.StrongConfigurationETag(applicationsla.ArchiveCalendar, entityID, 1)
	if response.Header().Get("ETag") != wantETag {
		t.Fatalf("ETag = %q, want %q", response.Header().Get("ETag"), wantETag)
	}
	var representation contract.SLABusinessCalendar
	if err := json.Unmarshal(response.Body.Bytes(), &representation); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if uuid.UUID(representation.TenantId) != fixture.tenantID || uuid.UUID(representation.Id) != fixture.calendarID ||
		representation.ResourceVersion != 1 || representation.Version != 1 || len(representation.WeeklySchedules) != 1 {
		t.Fatalf("representation = %#v", representation)
	}
}

func TestSLATransportRejectsHostileBodiesPreconditionsAndCrossTenantBeforeUseCase(t *testing.T) {
	fixture := newSLATransportFixture(t, authorization.LegacyMembershipRoleAnalyst)
	calls := 0
	service := &transportSLAStub{publishCalendar: func(
		context.Context, applicationsla.Actor, uuid.UUID, applicationsla.CalendarPublishCommand,
	) (applicationsla.PublicationResult[kernel.BusinessCalendar], error) {
		calls++
		return applicationsla.PublicationResult[kernel.BusinessCalendar]{}, applicationsla.ErrUnavailable
	}}
	router := newSLATestRouter(t, fixture, service)
	valid := calendarCreateBody(fixture.calendarID)
	hostile := strings.Replace(valid, `"startMinute":540`, `"startMinute":540,"startMinute":541`, 1)
	request := fixture.mutationRequest(http.MethodPost, fixture.calendarCollectionPath(), hostile)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	if calls != 0 {
		t.Fatalf("service calls after duplicate member = %d", calls)
	}

	request = fixture.mutationRequest(
		http.MethodPut,
		fixture.calendarCollectionPath()+"/"+fixture.calendarID.String(),
		calendarReplaceBody(),
	)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusPreconditionRequired, "precondition_required")
	if calls != 0 {
		t.Fatalf("service calls after missing If-Match = %d", calls)
	}

	foreignTenant := uuid.Must(uuid.NewV7())
	request = fixture.mutationRequest(
		http.MethodPost,
		"/api/v1/tenants/"+foreignTenant.String()+"/business-calendars",
		strings.Replace(valid, `"timezone":"UTC"`, `"timezone":"ldap://bind-secret.example"`, 1),
	)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusForbidden, "forbidden")
	if strings.Contains(response.Body.String(), "bind-secret") || calls != 0 {
		t.Fatalf("cross-tenant response leaked payload or called service: calls=%d body=%s", calls, response.Body.String())
	}
}

func TestSLATransportForwardsExactPreconditionAndMapsServiceErrors(t *testing.T) {
	fixture := newSLATransportFixture(t, authorization.LegacyMembershipRoleAnalyst)
	entityID := mustSLAEntityID(t, fixture.calendarID)
	wantETag := applicationsla.StrongConfigurationETag(applicationsla.ArchiveCalendar, entityID, 7)
	calls := 0
	service := &transportSLAStub{publishCalendar: func(
		_ context.Context,
		_ applicationsla.Actor,
		_ uuid.UUID,
		command applicationsla.CalendarPublishCommand,
	) (applicationsla.PublicationResult[kernel.BusinessCalendar], error) {
		calls++
		if command.ExpectedActiveVersion != 7 || command.Input.Version != 8 {
			t.Fatalf("version binding = expected %d input %d", command.ExpectedActiveVersion, command.Input.Version)
		}
		return applicationsla.PublicationResult[kernel.BusinessCalendar]{}, applicationsla.ErrPreconditionFailed
	}}
	router := newSLATestRouter(t, fixture, service)
	request := fixture.mutationRequest(
		http.MethodPut,
		fixture.calendarCollectionPath()+"/"+fixture.calendarID.String(),
		calendarReplaceBody(),
	)
	request.Header.Set("If-Match", wantETag)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusPreconditionFailed, "precondition_failed")
	if calls != 1 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("calls=%d Cache-Control=%q", calls, response.Header().Get("Cache-Control"))
	}

	for _, invalid := range []string{"*", "W/" + wantETag, wantETag + "," + wantETag} {
		request = fixture.mutationRequest(
			http.MethodPut,
			fixture.calendarCollectionPath()+"/"+fixture.calendarID.String(),
			calendarReplaceBody(),
		)
		request.Header.Set("If-Match", invalid)
		response = httptest.NewRecorder()
		router.ServeHTTP(response, request)
		assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	}
	if calls != 1 {
		t.Fatalf("service calls after malformed validators = %d", calls)
	}
}

func TestSLAObjectRoutesBindAudienceToRouteIntentInsteadOfLegacyRole(t *testing.T) {
	tests := []struct {
		name       string
		role       authorization.LegacyMembershipRole
		portal     bool
		objectType kernel.ObjectType
		wantKind   applicationsla.PrincipalKind
		serviceErr error
	}{
		{
			name: "read only operator remains operator", role: authorization.LegacyMembershipRoleReadOnly,
			objectType: kernel.ObjectCase, wantKind: applicationsla.PrincipalOperator,
		},
		{
			name: "customer compatibility role gets no operator fallback", role: authorization.LegacyMembershipRoleCustomerUser,
			objectType: kernel.ObjectAlert, wantKind: applicationsla.PrincipalOperator, serviceErr: applicationsla.ErrForbidden,
		},
		{
			name: "custom JIT role can use customer route", role: authorization.LegacyMembershipRole("jit_customer_custom"),
			portal: true, objectType: kernel.ObjectCase, wantKind: applicationsla.PrincipalCustomer,
		},
		{
			name: "read only operator gets no customer fallback", role: authorization.LegacyMembershipRoleReadOnly,
			portal: true, objectType: kernel.ObjectAlert, wantKind: applicationsla.PrincipalCustomer, serviceErr: applicationsla.ErrForbidden,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSLATransportFixture(t, test.role)
			objectUUID := uuid.Must(uuid.NewV7())
			calls := 0
			service := &transportSLAStub{projectObject: func(
				_ context.Context,
				actor applicationsla.Actor,
				tenantID uuid.UUID,
				command applicationsla.ObjectProjectionCommand,
			) (applicationsla.ObjectProjection, error) {
				calls++
				if actor.Kind != test.wantKind || tenantID != fixture.tenantID || command.ObjectType != test.objectType ||
					command.ObjectID.String() != objectUUID.String() {
					t.Fatalf("route intent drifted: actor=%#v tenant=%s command=%#v", actor, tenantID, command)
				}
				if test.serviceErr != nil {
					return applicationsla.ObjectProjection{}, test.serviceErr
				}
				return slaObjectProjectionFixture(t, fixture, objectUUID, test.objectType, test.wantKind), nil
			}}
			router := newSLATestRouter(t, fixture, service)
			resource := "cases"
			if test.objectType == kernel.ObjectAlert {
				resource = "alerts"
			}
			prefix := "/api/v1/tenants/" + fixture.tenantID.String() + "/"
			if test.portal {
				prefix += "portal/"
			}
			request := fixture.readRequest(prefix + resource + "/" + objectUUID.String() + "/sla")
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if calls != 1 || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("calls=%d Cache-Control=%q", calls, response.Header().Get("Cache-Control"))
			}
			if test.serviceErr != nil {
				assertProblem(t, response, http.StatusForbidden, "forbidden")
				return
			}
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			wantAudience := string(applicationsla.AudienceOperator)
			if test.portal {
				wantAudience = string(applicationsla.AudienceCustomer)
			}
			if body["audience"] != wantAudience {
				t.Fatalf("audience=%v want=%s", body["audience"], wantAudience)
			}
			_, hasInternalID := body["slaInstanceId"]
			if hasInternalID == test.portal {
				t.Fatalf("customer/operator projection shape drifted: %s", response.Body.String())
			}
			if test.portal {
				const customerETagPrefix = `"sla-customer-`
				etag := response.Header().Get("ETag")
				if !strings.HasPrefix(etag, customerETagPrefix) || !strings.HasSuffix(etag, `"`) ||
					len(etag) != len(customerETagPrefix)+22+1 {
					t.Fatalf("customer ETag was not an opaque fixed-width validator: %q", etag)
				}
			}
			if test.portal {
				for _, privateKey := range []string{
					"slaInstanceId", "aggregateVersion", "policyId", "policyVersion",
					"metricDefinitionId", "metricInstanceId", "metricVersion", "customerVisible", "pausedAt",
				} {
					if strings.Contains(response.Body.String(), `"`+privateKey+`"`) {
						t.Fatalf("customer SLA projection leaked %s: %s", privateKey, response.Body.String())
					}
				}
			}
		})
	}
}

func TestSLAObjectRoutesRejectOppositeAudienceProjection(t *testing.T) {
	for _, portal := range []bool{false, true} {
		name := "operator"
		intent := applicationsla.PrincipalOperator
		returned := applicationsla.PrincipalCustomer
		if portal {
			name, intent, returned = "customer", applicationsla.PrincipalCustomer, applicationsla.PrincipalOperator
		}
		t.Run(name, func(t *testing.T) {
			fixture := newSLATransportFixture(t, authorization.LegacyMembershipRoleReadOnly)
			objectUUID := uuid.Must(uuid.NewV7())
			service := &transportSLAStub{projectObject: func(
				_ context.Context,
				actor applicationsla.Actor,
				_ uuid.UUID,
				_ applicationsla.ObjectProjectionCommand,
			) (applicationsla.ObjectProjection, error) {
				if actor.Kind != intent {
					t.Fatalf("actor kind = %q, want %q", actor.Kind, intent)
				}
				return slaObjectProjectionFixture(t, fixture, objectUUID, kernel.ObjectCase, returned), nil
			}}
			path := "/api/v1/tenants/" + fixture.tenantID.String() + "/"
			if portal {
				path += "portal/"
			}
			path += "cases/" + objectUUID.String() + "/sla"
			response := httptest.NewRecorder()

			newSLATestRouter(t, fixture, service).ServeHTTP(response, fixture.readRequest(path))

			assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestCustomerSLAProjectionFailsClosedOnPrivateOrPausedItems(t *testing.T) {
	fixture := newSLATransportFixture(t, authorization.LegacyMembershipRoleCustomerUser)
	base := slaObjectProjectionFixture(
		t, fixture, uuid.Must(uuid.NewV7()), kernel.ObjectCase, applicationsla.PrincipalCustomer,
	)
	if _, err := mapSLACustomerObject(base); err != nil {
		t.Fatalf("valid customer projection error = %v", err)
	}
	pausedAt := fixture.now
	tests := []struct {
		name   string
		mutate func(*applicationsla.ObjectProjection)
	}{
		{"private metric", func(value *applicationsla.ObjectProjection) { value.Metrics[0].CustomerVisible = false }},
		{"paused metric state", func(value *applicationsla.ObjectProjection) { value.Metrics[0].State = kernel.StatePaused }},
		{"paused metric timestamp", func(value *applicationsla.ObjectProjection) { value.Metrics[0].PausedAt = &pausedAt }},
		{"private column", func(value *applicationsla.ObjectProjection) {
			value.Columns = []applicationsla.ColumnProjection{{CustomerVisible: false}}
		}},
		{"paused column", func(value *applicationsla.ObjectProjection) {
			value.Columns = []applicationsla.ColumnProjection{{CustomerVisible: true, State: kernel.StatePaused}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			projection := base
			projection.Metrics = append([]applicationsla.MetricProjection(nil), base.Metrics...)
			projection.Columns = append([]applicationsla.ColumnProjection(nil), base.Columns...)
			test.mutate(&projection)
			if _, err := mapSLACustomerObject(projection); !errors.Is(err, applicationsla.ErrUnavailable) {
				t.Fatalf("private customer projection error = %v, want unavailable", err)
			}
		})
	}
}

func TestSLAObjectRouteRejectsCrossTenantProjection(t *testing.T) {
	fixture := newSLATransportFixture(t, authorization.LegacyMembershipRoleReadOnly)
	objectUUID := uuid.Must(uuid.NewV7())
	service := &transportSLAStub{projectObject: func(
		_ context.Context,
		_ applicationsla.Actor,
		_ uuid.UUID,
		_ applicationsla.ObjectProjectionCommand,
	) (applicationsla.ObjectProjection, error) {
		projection := slaObjectProjectionFixture(t, fixture, objectUUID, kernel.ObjectCase, applicationsla.PrincipalCustomer)
		projection.TenantID = uuid.Must(uuid.NewV7())
		return projection, nil
	}}
	path := "/api/v1/tenants/" + fixture.tenantID.String() + "/portal/cases/" + objectUUID.String() + "/sla"
	response := httptest.NewRecorder()

	newSLATestRouter(t, fixture, service).ServeHTTP(response, fixture.readRequest(path))

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
}

func TestApplicationHandlerRequiresSLABoundary(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, ApplicationOptions{
		Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: &transportAuthStub{}, Authorization: &transportAuthorizationStub{},
		Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{}, Environment: "test",
		IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{},
		OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{}, PublicOrigin: "http://localhost:8081",
		ServiceAccounts: &transportServiceAccountStub{}, Ticketing: &transportTicketingStub{},
	})
	if err == nil || !strings.Contains(err.Error(), "SLA") {
		t.Fatalf("NewApplicationHandler() error = %v, want missing SLA boundary", err)
	}
}

type slaTransportFixture struct {
	tenantID      uuid.UUID
	userID        uuid.UUID
	membershipID  uuid.UUID
	calendarID    uuid.UUID
	now           time.Time
	auth          *transportAuthStub
	authorization *transportSLAAuthorizationStub
}

func newSLATransportFixture(t *testing.T, role authorization.LegacyMembershipRole) slaTransportFixture {
	t.Helper()
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	membershipID := uuid.Must(uuid.NewV7())
	return slaTransportFixture{
		tenantID: tenantID, userID: userID, membershipID: membershipID,
		calendarID: uuid.Must(uuid.NewV7()), now: time.Now().UTC().Truncate(time.Microsecond),
		auth: tenantLDAPTransportAuthentication(tenantID, userID),
		authorization: &transportSLAAuthorizationStub{authority: authorization.TenantAuthority{
			TenantID: tenantID, Principal: authorization.TenantPrincipal{ID: userID, Kind: authorization.PrincipalKindHuman},
			MembershipID: membershipID, MembershipStatus: authorization.MembershipStatusActive, LegacyRole: role,
		}},
	}
}

func newSLATestRouter(t *testing.T, fixture slaTransportFixture, service SLAService) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, ApplicationOptions{
		Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: fixture.auth, Authorization: fixture.authorization,
		Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{}, Environment: "test",
		IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, Notifications: &transportNotificationStub{},
		OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{}, PublicOrigin: "http://localhost:8081",
		MFA: &transportMFAStub{}, ServiceAccounts: &transportServiceAccountStub{}, SLA: service, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
	})
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func (fixture slaTransportFixture) calendarCollectionPath() string {
	return "/api/v1/tenants/" + fixture.tenantID.String() + "/business-calendars"
}

func (fixture slaTransportFixture) mutationRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.RemoteAddr = "198.51.100.42:4123"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, "csrf-value")
	request.Header.Set(idempotencyKeyHeader, "sla-calendar-create-0001")
	return request
}

func (fixture slaTransportFixture) readRequest(path string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.RemoteAddr = "198.51.100.42:4123"
	return request
}

func slaObjectProjectionFixture(
	t *testing.T,
	fixture slaTransportFixture,
	objectUUID uuid.UUID,
	objectType kernel.ObjectType,
	kind applicationsla.PrincipalKind,
) applicationsla.ObjectProjection {
	t.Helper()
	audience := applicationsla.AudienceOperator
	if kind == applicationsla.PrincipalCustomer {
		audience = applicationsla.AudienceCustomer
	}
	metricKey, err := kernel.NewKey("first_response")
	if err != nil {
		t.Fatal(err)
	}
	return applicationsla.ObjectProjection{
		TenantID: fixture.tenantID, Audience: audience, ObjectType: objectType,
		ObjectID: mustSLAEntityID(t, objectUUID), SLAInstanceID: mustSLAEntityID(t, uuid.Must(uuid.NewV7())),
		AggregateVersion: 3, PolicyID: mustSLAEntityID(t, uuid.Must(uuid.NewV7())), PolicyVersion: 2,
		Metrics: []applicationsla.MetricProjection{{
			MetricID: mustSLAEntityID(t, uuid.Must(uuid.NewV7())), MetricInstanceID: mustSLAEntityID(t, uuid.Must(uuid.NewV7())),
			MetricVersion: 4, Key: metricKey, Label: "First response", CustomerVisible: true,
			State: kernel.StateOnTrack, RemainingSeconds: 600, ConsumedPercentage: 50,
		}},
		Columns: []applicationsla.ColumnProjection{}, ProjectedAt: fixture.now,
	}
}

func calendarCreateBody(id uuid.UUID) string {
	return `{"id":"` + id.String() + `","key":"support_hours","label":"Support hours","timezone":"UTC","weeklySchedules":[{"weekday":"monday","intervals":[{"startMinute":540,"endMinute":1020}]}],"exceptions":[]}`
}

func calendarReplaceBody() string {
	return `{"key":"support_hours","label":"Support hours","timezone":"UTC","weeklySchedules":[{"weekday":"monday","intervals":[{"startMinute":540,"endMinute":1020}]}],"exceptions":[]}`
}

func mustSLAEntityID(t *testing.T, id uuid.UUID) kernel.EntityID {
	t.Helper()
	result, err := kernel.NewEntityID([16]byte(id))
	if err != nil {
		t.Fatalf("NewEntityID() error = %v", err)
	}
	return result
}
