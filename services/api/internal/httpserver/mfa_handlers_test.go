package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
)

type mfaTransportStub struct {
	*mfaauth.PublicService
	admissionCalls        int
	admissionPrincipal    identity.EntityID
	admissionResource     string
	prepareCalls          int
	prepareRequest        mfaauth.CompletionTicketRequest
	prepareError          error
	prepareResultMethod   string
	prepareSourceVersion  uint64
	prepareSourceSession  identity.EntityID
	prepareSourceFamily   identity.EntityID
	prepareSourceAbsolute time.Time
	prepareTenantID       identity.EntityID
	prepareUserID         identity.EntityID
	prepareResolvedFactor []byte
	startLocalCalls       int
	startLocalCommand     mfaauth.StartLocalStepUpCommand
	startLocalError       error
	stepUpTOTPCalls       int
	stepUpTOTPCommand     mfaauth.CompleteTOTPCommand
	stepUpTOTPError       error
	stepUpRecoveryCalls   int
	stepUpRecoveryCommand mfaauth.CompleteRecoveryCommand
	stepUpRecoveryError   error
	completeCalls         int
	completeCommand       mfaauth.FinishTOTPEnrollmentCommand
	completeResult        mfaauth.TOTPEnrollmentApplyResult
	completeError         error
	devicePage            mfaauth.DevicePage
	deviceError           error
	deviceInput           mfaauth.DeviceListInput
	deviceAuthority       mfaauth.DeviceAuthority
	renameCalls           int
	revokeCalls           int
	mutationResult        mfaauth.DeviceMutationResult
	mutationError         error
}

func (stub *mfaTransportStub) Admission(
	_ netip.Addr,
	principal identity.EntityID,
	resource string,
) (mfaauth.AdmissionContext, error) {
	stub.admissionCalls++
	stub.admissionPrincipal = principal
	stub.admissionResource = resource
	return mfaauth.AdmissionContext{
		OperationID:   identity.EntityID(uuid.Must(uuid.NewV7())),
		NetworkDigest: mfaauth.AdmissionDigest{1}, PrincipalDigest: mfaauth.AdmissionDigest{2},
		ResourceDigest: mfaauth.AdmissionDigest{3},
	}, nil
}

type mfaTransportCompletionGate struct{}

func (mfaTransportCompletionGate) Admit(
	context.Context,
	mfaauth.AdmissionContext,
	time.Time,
) (mfaauth.AdmissionDecision, error) {
	return mfaauth.AdmissionDecision{Outcome: mfaauth.AdmissionAllowed}, nil
}

type mfaTransportCompletionSource struct {
	resolve func(mfaauth.CompletionTicketLookup) (mfaauth.CompletionTicketResolutionInput, error)
}

func (source mfaTransportCompletionSource) ResolveMFACompletion(
	_ context.Context,
	lookup mfaauth.CompletionTicketLookup,
) (mfaauth.CompletionTicketResolutionInput, error) {
	return source.resolve(lookup)
}

func (stub *mfaTransportStub) PrepareCompletion(
	ctx context.Context,
	request mfaauth.CompletionTicketRequest,
) (mfaauth.CompletionTicket, error) {
	stub.prepareCalls++
	request.ArtifactID = append([]byte(nil), request.ArtifactID...)
	request.BrowserHandle = append([]byte(nil), request.BrowserHandle...)
	request.FactorID = append([]byte(nil), request.FactorID...)
	stub.prepareRequest = request
	if stub.prepareError != nil {
		return mfaauth.CompletionTicket{}, stub.prepareError
	}
	issuer, err := mfaauth.NewCompletionTicketIssuer(mfaauth.CompletionTicketOptions{
		Source: mfaTransportCompletionSource{resolve: func(lookup mfaauth.CompletionTicketLookup) (
			mfaauth.CompletionTicketResolutionInput,
			error,
		) {
			return stub.completionResolution(lookup), nil
		}},
		Admissions: mfaTransportCompletionGate{}, OperationTimeout: time.Second,
	})
	if err != nil {
		return mfaauth.CompletionTicket{}, err
	}
	return issuer.Prepare(ctx, request)
}

func (stub *mfaTransportStub) completionResolution(
	lookup mfaauth.CompletionTicketLookup,
) mfaauth.CompletionTicketResolutionInput {
	tenantID, userID := stub.prepareTenantID, stub.prepareUserID
	if tenantID == (identity.EntityID{}) {
		tenantID = identity.EntityID(uuid.Must(uuid.NewV7()))
	}
	if userID == (identity.EntityID{}) {
		userID = identity.EntityID(uuid.Must(uuid.NewV7()))
	}
	factorID := append([]byte(nil), lookup.FactorID...)
	if len(factorID) == 0 {
		factorID = append([]byte(nil), stub.prepareResolvedFactor...)
		if len(factorID) == 0 {
			resolved := identity.EntityID(uuid.Must(uuid.NewV7()))
			factorID = append(factorID, resolved[:]...)
		}
	}
	version := stub.prepareSourceVersion
	if version == 0 {
		version = 4
	}
	loadedAt := lookup.RequestedAt
	anchorExpiresAt := loadedAt.Add(time.Hour).Truncate(time.Millisecond)
	resolution := mfaauth.CompletionTicketResolutionInput{
		LoadedAt: loadedAt, ArtifactKind: lookup.ArtifactKind,
		ArtifactID: append([]byte(nil), lookup.ArtifactID...), BrowserDigest: lookup.BrowserDigest,
		FactorKind: lookup.FactorKind, FactorID: factorID,
		TenantID: tenantID, UserID: userID, IdentityEpoch: 7,
		ResolvedUserID: userID, ResolvedIdentityEpoch: 7,
		AnchorVersion: version, AnchorExpiresAt: anchorExpiresAt,
		Action: "session.create", Audience: "api",
		ContinuationReceiptDigest: lookup.ContinuationReceiptDigest,
	}
	method := mfa.SessionAuthenticationTOTP
	switch lookup.FactorKind {
	case mfaauth.CompletionFactorRecovery:
		method = mfa.SessionAuthenticationRecovery
	case mfaauth.CompletionFactorPasskey:
		method = mfa.SessionAuthenticationPasskey
	}
	resolution.ReservationAuthenticationMethod = method
	resolution.ResultAuthenticationMethod = string(method)
	if stub.prepareResultMethod != "" {
		resolution.ResultAuthenticationMethod = stub.prepareResultMethod
	}
	switch {
	case lookup.SessionSource != nil:
		resolution.Flow = mfaauth.CompletionFlowSession
		resolution.TenantID = lookup.SessionSource.TenantID
		resolution.UserID = lookup.SessionSource.UserID
		resolution.ResolvedUserID = lookup.SessionSource.UserID
		resolution.SessionID = lookup.SessionSource.SessionID
		resolution.SessionFamilyID = lookup.SessionSource.SessionFamilyID
		resolution.SourceSessionID = lookup.SessionSource.SessionID
		resolution.SourceSessionFamilyID = lookup.SessionSource.SessionFamilyID
		resolution.SourceSessionVersion = version
		resolution.SourceAbsoluteExpiresAt = lookup.SessionSource.AbsoluteExpiresAt
		resolution.ReservationDisposition = mfaauth.CompletionReservationRotate
		resolution.ResultAuthenticationMethod = lookup.SessionSource.AuthenticationMethod
	case lookup.ContinuationID != (identity.EntityID{}):
		resolution.Flow = mfaauth.CompletionFlowContinuation
		resolution.ContinuationID = lookup.ContinuationID
		if lookup.ArtifactKind == mfaauth.CompletionArtifactTOTPEnrollment ||
			lookup.ArtifactKind == mfaauth.CompletionArtifactWebAuthnRegistration {
			resolution.ReservationDisposition = mfaauth.CompletionReservationNone
			resolution.ReservationAuthenticationMethod = ""
			resolution.ResultAuthenticationMethod = ""
		} else {
			resolution.ReservationDisposition = mfaauth.CompletionReservationCreate
			if stub.prepareSourceSession != (identity.EntityID{}) {
				resolution.ReservationDisposition = mfaauth.CompletionReservationRotate
				resolution.SourceSessionID = stub.prepareSourceSession
				resolution.SourceSessionFamilyID = stub.prepareSourceFamily
				resolution.SourceSessionVersion = version
				resolution.SourceAbsoluteExpiresAt = stub.prepareSourceAbsolute
			}
		}
	default:
		resolution.Flow = mfaauth.CompletionFlowPrimary
		resolution.AnchorVersion = 0
		resolution.AnchorExpiresAt = time.Time{}
		resolution.ReservationDisposition = mfaauth.CompletionReservationCreate
		resolution.ReservationAuthenticationMethod = mfa.SessionAuthenticationPasskey
		resolution.ResultAuthenticationMethod = string(mfa.SessionAuthenticationPasskey)
	}
	return resolution
}

func (stub *mfaTransportStub) StartLocalStepUp(
	_ context.Context,
	command mfaauth.StartLocalStepUpCommand,
) (mfaauth.LocalStepUpStartArtifact, error) {
	stub.startLocalCalls++
	stub.startLocalCommand = command
	return mfaauth.LocalStepUpStartArtifact{}, stub.startLocalError
}

func (stub *mfaTransportStub) CompleteTOTP(
	_ context.Context,
	command mfaauth.CompleteTOTPCommand,
) (mfa.StepUpArtifact, error) {
	stub.stepUpTOTPCalls++
	command.Code = append([]byte(nil), command.Code...)
	stub.stepUpTOTPCommand = command
	return mfa.StepUpArtifact{}, stub.stepUpTOTPError
}

func (stub *mfaTransportStub) CompleteRecovery(
	_ context.Context,
	command mfaauth.CompleteRecoveryCommand,
) (mfa.StepUpArtifact, error) {
	stub.stepUpRecoveryCalls++
	command.Code = append([]byte(nil), command.Code...)
	stub.stepUpRecoveryCommand = command
	return mfa.StepUpArtifact{}, stub.stepUpRecoveryError
}

func (stub *mfaTransportStub) FinishTOTP(
	_ context.Context,
	command mfaauth.FinishTOTPEnrollmentCommand,
) (mfaauth.TOTPEnrollmentApplyResult, error) {
	stub.completeCalls++
	command.Code = append([]byte(nil), command.Code...)
	stub.completeCommand = command
	return stub.completeResult, stub.completeError
}

func (stub *mfaTransportStub) ListDevices(
	_ context.Context,
	authority mfaauth.DeviceAuthority,
	input mfaauth.DeviceListInput,
) (mfaauth.DevicePage, error) {
	stub.deviceAuthority = authority
	stub.deviceInput = input
	return stub.devicePage, stub.deviceError
}

func (stub *mfaTransportStub) RenamePasskey(
	_ context.Context,
	authority mfaauth.DeviceAuthority,
	_ identity.EntityID,
	_ string,
	_ uint64,
) (mfaauth.DeviceMutationResult, error) {
	stub.renameCalls++
	stub.deviceAuthority = authority
	return stub.mutationResult, stub.mutationError
}

func (stub *mfaTransportStub) RevokeDevice(
	_ context.Context,
	authority mfaauth.DeviceAuthority,
	_ identity.EntityID,
	_ mfaauth.DeviceKind,
	_ uint64,
) (mfaauth.DeviceMutationResult, error) {
	stub.revokeCalls++
	stub.deviceAuthority = authority
	return stub.mutationResult, stub.mutationError
}

func TestFederatedMFACeremonyCancellationRetainsOnlyExactContinuation(t *testing.T) {
	continuationID := uuid.Must(uuid.NewV7())
	continuationCookie, _ := testFederatedContinuationCookie(t, continuationID)
	service := &mfaTransportStub{}
	router := newMFATestRouter(t, &transportAuthStub{}, service)
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/federated/mfa/ceremony", nil)
	request.Header.Set("Origin", "http://localhost:8081")
	request.AddCookie(continuationCookie)
	request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: testMFABrowserHandle()})
	request.RemoteAddr = "198.51.100.42:4242"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || response.Body.Len() != 0 ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response = status %d cache %q body %q", response.Code,
			response.Header().Get("Cache-Control"), response.Body.String())
	}
	if service.admissionCalls != 1 || service.admissionPrincipal != identity.EntityID(continuationID) ||
		service.admissionResource != federatedMFACancelResource {
		t.Fatalf("admission = calls %d principal %s resource %q", service.admissionCalls,
			uuid.UUID(service.admissionPrincipal), service.admissionResource)
	}
	setCookies := response.Header().Values("Set-Cookie")
	if len(setCookies) != 1 || !strings.Contains(setCookies[0], developmentMFACookie+"=; ") ||
		strings.Contains(setCookies[0], developmentFederatedContinuationCookie) {
		t.Fatalf("Set-Cookie = %#v, want only terminal MFA ceremony deletion", setCookies)
	}
}

func TestFederatedMFACeremonyCancellationRejectsMixedOrMalformedAuthority(t *testing.T) {
	continuationID := uuid.Must(uuid.NewV7())
	validContinuation, _ := testFederatedContinuationCookie(t, continuationID)
	tests := []struct {
		name   string
		mutate func(*http.Request)
		status int
		code   string
	}{
		{
			name: "missing continuation",
			mutate: func(request *http.Request) {
				request.Header.Del("Cookie")
				request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: testMFABrowserHandle()})
			},
			status: http.StatusUnauthorized, code: "authentication_failed",
		},
		{
			name: "duplicate ceremony",
			mutate: func(request *http.Request) {
				request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: testMFABrowserHandle()})
			},
			status: http.StatusUnauthorized, code: "authentication_failed",
		},
		{
			name: "session authority",
			mutate: func(request *http.Request) {
				request.AddCookie(&http.Cookie{Name: developmentCookie, Value: testMFABrowserHandle()})
			},
			status: http.StatusUnauthorized, code: "authentication_failed",
		},
		{
			name: "csrf authority",
			mutate: func(request *http.Request) {
				request.Header.Set(csrfTokenHeader, testMFABrowserHandle())
			},
			status: http.StatusUnauthorized, code: "authentication_failed",
		},
		{
			name: "unexpected body",
			mutate: func(request *http.Request) {
				request.Body = io.NopCloser(strings.NewReader(`{}`))
				request.ContentLength = 2
				request.Header.Set("Content-Type", "application/json")
			},
			status: http.StatusBadRequest, code: "invalid_request",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &mfaTransportStub{}
			router := newMFATestRouter(t, &transportAuthStub{}, service)
			request := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/federated/mfa/ceremony", nil)
			request.Header.Set("Origin", "http://localhost:8081")
			request.AddCookie(validContinuation)
			request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: testMFABrowserHandle()})
			request.RemoteAddr = "198.51.100.42:4242"
			test.mutate(request)
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			assertProblem(t, response, test.status, test.code)
			if len(response.Header().Values("Set-Cookie")) != 0 {
				t.Fatalf("rejected request cleared cookies: %#v", response.Header().Values("Set-Cookie"))
			}
		})
	}
}

func TestFederatedMFAContinuationAbandonmentIsIdempotentAndNonOracular(t *testing.T) {
	service := &mfaTransportStub{}
	router := newMFATestRouter(t, &transportAuthStub{}, service)
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/federated/mfa/continuation", nil)
	request.Header.Set("Origin", "http://localhost:8081")
	for _, cookie := range []http.Cookie{
		{Name: developmentOIDCTransactionCookie, Value: "stale-oidc"},
		{Name: developmentSAMLTransactionCookie, Value: "stale-saml"},
		{Name: developmentPlatformOIDCTransactionCookie, Value: "stale-platform-oidc"},
		{Name: developmentPlatformSAMLTransactionCookie, Value: "stale-platform-saml"},
		{Name: developmentMFACookie, Value: "stale-mfa"},
		{Name: developmentFederatedContinuationCookie, Value: "stale-continuation"},
	} {
		request.AddCookie(&cookie)
	}
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || response.Body.Len() != 0 ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response = status %d cache %q body %q", response.Code,
			response.Header().Get("Cache-Control"), response.Body.String())
	}
	setCookies := strings.Join(response.Header().Values("Set-Cookie"), "\n")
	if len(response.Header().Values("Set-Cookie")) != 6 {
		t.Fatalf("Set-Cookie = %q, want six browser capability deletions", setCookies)
	}
	for _, name := range []string{
		developmentOIDCTransactionCookie,
		developmentSAMLTransactionCookie,
		developmentPlatformOIDCTransactionCookie,
		developmentPlatformSAMLTransactionCookie,
		developmentMFACookie,
		developmentFederatedContinuationCookie,
	} {
		if !strings.Contains(setCookies, name+"=; ") {
			t.Fatalf("Set-Cookie = %q, missing deletion for %q", setCookies, name)
		}
	}
	if service.admissionCalls != 0 {
		t.Fatalf("admission calls = %d, want zero", service.admissionCalls)
	}
}

func TestFederatedMFAContinuationAbandonmentRejectsMixedAuthorityBeforeClearing(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
		status int
		code   string
	}{
		{
			name: "session cookie",
			mutate: func(request *http.Request) {
				request.AddCookie(&http.Cookie{Name: developmentCookie, Value: testMFABrowserHandle()})
			},
			status: http.StatusUnauthorized, code: "authentication_failed",
		},
		{
			name: "bearer authority",
			mutate: func(request *http.Request) {
				request.Header.Set("Authorization", "Bearer "+testMFABrowserHandle())
			},
			status: http.StatusUnauthorized, code: "authentication_failed",
		},
		{
			name: "csrf authority",
			mutate: func(request *http.Request) {
				request.Header.Set(csrfTokenHeader, testMFABrowserHandle())
			},
			status: http.StatusUnauthorized, code: "authentication_failed",
		},
		{
			name:   "wrong origin",
			mutate: func(request *http.Request) { request.Header.Set("Origin", "https://evil.example") },
			status: http.StatusForbidden, code: "forbidden",
		},
		{
			name: "unexpected body",
			mutate: func(request *http.Request) {
				request.Body = io.NopCloser(strings.NewReader(`{}`))
				request.ContentLength = 2
				request.Header.Set("Content-Type", "application/json")
			},
			status: http.StatusBadRequest, code: "invalid_request",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router := newMFATestRouter(t, &transportAuthStub{}, &mfaTransportStub{})
			request := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/federated/mfa/continuation", nil)
			request.Header.Set("Origin", "http://localhost:8081")
			test.mutate(request)
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			assertProblem(t, response, test.status, test.code)
			if len(response.Header().Values("Set-Cookie")) != 0 {
				t.Fatalf("rejected request cleared cookies: %#v", response.Header().Values("Set-Cookie"))
			}
		})
	}
}

func TestFederatedMFAStartBindsExactContinuationReceiptDigest(t *testing.T) {
	continuationID := uuid.Must(uuid.NewV7())
	continuationCookie, receipt := testFederatedContinuationCookie(t, continuationID)
	service := &mfaTransportStub{startLocalError: mfaauth.ErrDenied}
	router := newMFATestRouter(t, &transportAuthStub{}, service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/federated/mfa/step-up", nil)
	request.Header.Set("Origin", "http://localhost:8081")
	request.AddCookie(continuationCookie)
	request.RemoteAddr = "198.51.100.42:4242"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusForbidden, "forbidden")
	wantDigest := sha256.Sum256([]byte(receipt))
	lookup := service.startLocalCommand.Lookup
	if service.startLocalCalls != 1 || service.admissionCalls != 1 ||
		service.admissionPrincipal != identity.EntityID(continuationID) ||
		service.admissionResource != federatedMFAStartResource ||
		lookup.Flow != mfa.FlowPostPrimaryContinuation ||
		lookup.AnchorID != identity.EntityID(continuationID) ||
		lookup.Action != federatedContinuationAction || lookup.Audience != federatedContinuationAudience ||
		lookup.ContinuationReceiptDigest != wantDigest {
		t.Fatalf("federated lookup/admission = %#v / principal %s resource %q", lookup,
			uuid.UUID(service.admissionPrincipal), service.admissionResource)
	}
}

func TestFederatedMFAStartRejectsMixedOrMalformedAuthorityBeforeAdmission(t *testing.T) {
	continuationID := uuid.Must(uuid.NewV7())
	validCookie, receipt := testFederatedContinuationCookie(t, continuationID)
	tests := []struct {
		name   string
		mutate func(*http.Request)
		status int
		code   string
	}{
		{
			name: "session cookie",
			mutate: func(request *http.Request) {
				request.AddCookie(&http.Cookie{Name: developmentCookie, Value: testMFABrowserHandle()})
			},
			status: http.StatusUnauthorized, code: "authentication_failed",
		},
		{
			name: "bearer authority",
			mutate: func(request *http.Request) {
				request.Header.Set("Authorization", "Bearer "+testMFABrowserHandle())
			},
			status: http.StatusUnauthorized, code: "authentication_failed",
		},
		{
			name: "csrf authority",
			mutate: func(request *http.Request) {
				request.Header.Set(csrfTokenHeader, testMFABrowserHandle())
			},
			status: http.StatusUnauthorized, code: "authentication_failed",
		},
		{
			name: "existing MFA ceremony",
			mutate: func(request *http.Request) {
				request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: testMFABrowserHandle()})
			},
			status: http.StatusUnauthorized, code: "authentication_failed",
		},
		{
			name: "duplicate continuation",
			mutate: func(request *http.Request) {
				request.AddCookie(validCookie)
			},
			status: http.StatusUnauthorized, code: "authentication_failed",
		},
		{
			name: "uuid only",
			mutate: func(request *http.Request) {
				request.Header.Set("Cookie", developmentFederatedContinuationCookie+"="+
					base64.RawURLEncoding.EncodeToString(continuationID[:]))
			},
			status: http.StatusUnauthorized, code: "authentication_failed",
		},
		{
			name: "receipt only",
			mutate: func(request *http.Request) {
				request.Header.Set("Cookie", developmentFederatedContinuationCookie+"="+receipt)
			},
			status: http.StatusUnauthorized, code: "authentication_failed",
		},
		{
			name: "unexpected body",
			mutate: func(request *http.Request) {
				request.Body = io.NopCloser(strings.NewReader(`{}`))
				request.ContentLength = 2
				request.Header.Set("Content-Type", "application/json")
			},
			status: http.StatusBadRequest, code: "invalid_request",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &mfaTransportStub{startLocalError: mfaauth.ErrDenied}
			router := newMFATestRouter(t, &transportAuthStub{}, service)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/federated/mfa/step-up", nil)
			request.Header.Set("Origin", "http://localhost:8081")
			request.AddCookie(validCookie)
			request.RemoteAddr = "198.51.100.42:4242"
			test.mutate(request)
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			assertProblem(t, response, test.status, test.code)
			if service.admissionCalls != 0 || service.startLocalCalls != 0 {
				t.Fatalf("calls = admission %d start %d, want zero", service.admissionCalls, service.startLocalCalls)
			}
		})
	}
}

func TestFederatedTotpCompletionConsumesContinuationIntoNewSession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	continuationID := uuid.Must(uuid.NewV7())
	factorID := uuid.Must(uuid.NewV7())
	sessionID := uuid.Must(uuid.NewV7())
	familyID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	continuationCookie, _ := testFederatedContinuationCookie(t, continuationID)
	reservation := testMFASessionReservation(t, sessionID, familyID, now)
	auth := &transportAuthStub{
		reserveResult: reservation,
		currentResult: authentication.SessionCredential{
			SessionToken: testReservedSessionToken(), CSRFToken: testReservedCSRFToken(),
			Session: authentication.Session{
				ID: sessionID, RotationFamilyID: familyID, User: authentication.User{ID: userID, DisplayName: "Responder"},
				ActiveTenantID: &tenantID, CreatedAt: now, LastSeenAt: now,
				IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
				AuthenticationMethod: "oidc",
			},
		},
	}
	service := &mfaTransportStub{prepareResultMethod: "oidc"}
	router := newMFATestRouter(t, auth, service)
	challengeRaw := sha256.Sum256([]byte("federated TOTP challenge"))
	challengeID := base64.RawURLEncoding.EncodeToString(challengeRaw[:])
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/federated/mfa/step-up/"+challengeID+"/totp",
		strings.NewReader(`{"factorId":"`+factorID.String()+`","code":"123456"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.AddCookie(continuationCookie)
	request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: testMFABrowserHandle()})
	request.RemoteAddr = "198.51.100.42:4242"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	command := service.stepUpTOTPCommand
	prepared := service.prepareRequest
	if auth.reserveCalls != 1 || auth.reserveCurrent != nil ||
		auth.reserveMethod != mfa.SessionAuthenticationTOTP || service.stepUpTOTPCalls != 1 ||
		service.prepareCalls != 1 ||
		service.admissionPrincipal != identity.EntityID(continuationID) ||
		service.admissionResource != federatedMFATOTPResource ||
		!bytes.Equal(prepared.FactorID, factorID[:]) || !bytes.Equal(prepared.ArtifactID, challengeRaw[:]) ||
		string(prepared.BrowserHandle) != testMFABrowserHandle() || string(command.Code) != "123456" ||
		prepared.ContinuationID != identity.EntityID(continuationID) ||
		prepared.ContinuationReceiptDigest == ([32]byte{}) {
		t.Fatalf("completion authority/command = reserve %d current %v method %q calls %d command %#v",
			auth.reserveCalls, auth.reserveCurrent, auth.reserveMethod, service.stepUpTOTPCalls, command)
	}
	if command.Session.SessionID() != identity.EntityID(sessionID) ||
		command.Session.FamilyID() != identity.EntityID(familyID) {
		t.Fatalf("session reservation = %#v", command.Session)
	}
	setCookies := strings.Join(response.Header().Values("Set-Cookie"), "\n")
	for _, fragment := range []string{
		developmentMFACookie + "=; ",
		developmentFederatedContinuationCookie + "=; ",
		developmentCookie + "=" + testReservedSessionToken(),
	} {
		if !strings.Contains(setCookies, fragment) {
			t.Fatalf("Set-Cookie = %q, missing %q", setCookies, fragment)
		}
	}
	if auth.authenticateCalls != 0 || auth.currentToken != testReservedSessionToken() {
		t.Fatalf("session checks = Authenticate %d CurrentSession token %q", auth.authenticateCalls, auth.currentToken)
	}
	if !strings.Contains(response.Body.String(), `"authenticationMethod":"oidc"`) {
		t.Fatalf("response did not preserve the primary method: %s", response.Body.String())
	}
}

func TestFederatedTotpRevalidationRotatesExactSourceAndPreservesPrimaryMethod(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	continuationID := uuid.Must(uuid.NewV7())
	factorID := uuid.Must(uuid.NewV7())
	sourceSessionID := uuid.Must(uuid.NewV7())
	newSessionID := uuid.Must(uuid.NewV7())
	familyID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	absoluteExpiresAt := now.Add(8 * time.Hour)
	continuationCookie, _ := testFederatedContinuationCookie(t, continuationID)
	reservation := testMFASessionReservation(t, newSessionID, familyID, now)
	auth := &transportAuthStub{
		reserveResult: reservation,
		currentResult: authentication.SessionCredential{
			SessionToken: testReservedSessionToken(), CSRFToken: testReservedCSRFToken(),
			Session: authentication.Session{
				ID: newSessionID, RotationFamilyID: familyID,
				User: authentication.User{ID: userID, DisplayName: "Responder"}, ActiveTenantID: &tenantID,
				CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(time.Hour),
				AbsoluteExpiresAt: absoluteExpiresAt, AuthenticationMethod: "oidc",
			},
		},
	}
	service := &mfaTransportStub{
		prepareResultMethod: "oidc", prepareSourceVersion: 9,
		prepareSourceSession:  identity.EntityID(sourceSessionID),
		prepareSourceFamily:   identity.EntityID(familyID),
		prepareSourceAbsolute: absoluteExpiresAt,
		prepareTenantID:       identity.EntityID(tenantID), prepareUserID: identity.EntityID(userID),
	}
	router := newMFATestRouter(t, auth, service)
	challengeRaw := sha256.Sum256([]byte("federated session-revalidation TOTP challenge"))
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/federated/mfa/step-up/"+base64.RawURLEncoding.EncodeToString(challengeRaw[:])+"/totp",
		strings.NewReader(`{"factorId":"`+factorID.String()+`","code":"123456"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.AddCookie(continuationCookie)
	request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: testMFABrowserHandle()})
	request.RemoteAddr = "198.51.100.42:4242"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if auth.reserveCalls != 1 || auth.reserveCurrent == nil ||
		auth.reserveCurrent.ID != sourceSessionID || auth.reserveCurrent.RotationFamilyID != familyID ||
		!auth.reserveCurrent.AbsoluteExpiresAt.Equal(absoluteExpiresAt) ||
		auth.reserveMethod != mfa.SessionAuthenticationTOTP || auth.reserveIssuedAt.IsZero() ||
		auth.reserveIssuedAt.Location() != time.UTC || auth.reserveIssuedAt.Nanosecond()%int(time.Microsecond) != 0 {
		t.Fatalf("rotation reservation = calls %d current %#v method %q issued %s",
			auth.reserveCalls, auth.reserveCurrent, auth.reserveMethod, auth.reserveIssuedAt)
	}
	command := service.stepUpTOTPCommand
	if command.Session.SessionID() != identity.EntityID(newSessionID) ||
		command.Session.FamilyID() != identity.EntityID(familyID) ||
		!command.Session.AbsoluteExpiresAt().Equal(absoluteExpiresAt) {
		t.Fatalf("completion reservation = %#v", command.Session)
	}
	if !strings.Contains(response.Body.String(), `"authenticationMethod":"oidc"`) {
		t.Fatalf("response did not preserve source primary method: %s", response.Body.String())
	}
	cookies := strings.Join(response.Header().Values("Set-Cookie"), "\n")
	for _, fragment := range []string{
		developmentMFACookie + "=; ",
		developmentFederatedContinuationCookie + "=; ",
		developmentCookie + "=" + testReservedSessionToken(),
	} {
		if !strings.Contains(cookies, fragment) {
			t.Fatalf("Set-Cookie = %q, missing %q", cookies, fragment)
		}
	}
}

func TestFederatedCompletionResolverFailurePreservesBothBrowserCapabilities(t *testing.T) {
	continuationID := uuid.Must(uuid.NewV7())
	factorID := uuid.Must(uuid.NewV7())
	continuationCookie, _ := testFederatedContinuationCookie(t, continuationID)
	service := &mfaTransportStub{prepareError: mfaauth.ErrAuthentication}
	auth := &transportAuthStub{}
	router := newMFATestRouter(t, auth, service)
	challengeRaw := sha256.Sum256([]byte("wrong-receipt challenge"))
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/federated/mfa/step-up/"+base64.RawURLEncoding.EncodeToString(challengeRaw[:])+"/totp",
		strings.NewReader(`{"factorId":"`+factorID.String()+`","code":"123456"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.AddCookie(continuationCookie)
	request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: testMFABrowserHandle()})
	request.RemoteAddr = "198.51.100.42:4242"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusUnauthorized, "authentication_failed")
	if service.prepareCalls != 1 || service.stepUpTOTPCalls != 0 || auth.reserveCalls != 0 {
		t.Fatalf("calls = prepare %d finish %d reserve %d", service.prepareCalls, service.stepUpTOTPCalls, auth.reserveCalls)
	}
	if cookies := response.Header().Values("Set-Cookie"); len(cookies) != 0 {
		t.Fatalf("resolver failure cleared retryable browser capabilities: %#v", cookies)
	}
}

func TestFederatedCompletionClaimFailureClearsMFAOnlyAndDestroysReservation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	continuationID := uuid.Must(uuid.NewV7())
	factorID := uuid.Must(uuid.NewV7())
	continuationCookie, _ := testFederatedContinuationCookie(t, continuationID)
	reservation := testMFASessionReservation(t, uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), now)
	auth := &transportAuthStub{reserveResult: reservation}
	service := &mfaTransportStub{stepUpTOTPError: mfaauth.ErrDenied}
	router := newMFATestRouter(t, auth, service)
	challengeRaw := sha256.Sum256([]byte("claimed failure challenge"))
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/federated/mfa/step-up/"+base64.RawURLEncoding.EncodeToString(challengeRaw[:])+"/totp",
		strings.NewReader(`{"factorId":"`+factorID.String()+`","code":"123456"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.AddCookie(continuationCookie)
	request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: testMFABrowserHandle()})
	request.RemoteAddr = "198.51.100.42:4242"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusForbidden, "forbidden")
	if service.prepareCalls != 1 || service.stepUpTOTPCalls != 1 || auth.reserveCalls != 1 {
		t.Fatalf("calls = prepare %d finish %d reserve %d", service.prepareCalls, service.stepUpTOTPCalls, auth.reserveCalls)
	}
	if _, ok := reservation.Consume(); ok {
		t.Fatal("claim failure left reserved browser material consumable")
	}
	cookies := strings.Join(response.Header().Values("Set-Cookie"), "\n")
	if !strings.Contains(cookies, developmentMFACookie+"=; ") ||
		strings.Contains(cookies, developmentFederatedContinuationCookie+"=; ") ||
		strings.Contains(cookies, developmentCookie+"=") {
		t.Fatalf("Set-Cookie = %q, want MFA deletion while continuation stays retryable", cookies)
	}
}

func TestFederatedTotpEnrollmentRetainsExactContinuationWithoutSession(t *testing.T) {
	continuationID := uuid.Must(uuid.NewV7())
	enrollmentID := uuid.Must(uuid.NewV7())
	factorID := uuid.Must(uuid.NewV7())
	continuationCookie, _ := testFederatedContinuationCookie(t, continuationID)
	auth := &transportAuthStub{}
	service := &mfaTransportStub{completeResult: mfaauth.TOTPEnrollmentApplyResult{
		FactorID: identity.EntityID(factorID), Mutation: mfaauth.SessionRetainContinuation,
		RetainedContinuationID: identity.EntityID(continuationID), SessionVersion: 2,
	}}
	router := newMFATestRouter(t, auth, service)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/federated/mfa/totp/enrollments/"+enrollmentID.String(),
		strings.NewReader(`{"code":"123456"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.AddCookie(continuationCookie)
	request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: testMFABrowserHandle()})
	request.RemoteAddr = "198.51.100.42:4242"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	command := service.completeCommand
	prepared := service.prepareRequest
	if auth.reserveCalls != 0 || service.completeCalls != 1 || !command.Session.IsZero() ||
		service.prepareCalls != 1 || !bytes.Equal(prepared.ArtifactID, enrollmentID[:]) ||
		string(prepared.BrowserHandle) != testMFABrowserHandle() || string(command.Code) != "123456" ||
		prepared.ContinuationID != identity.EntityID(continuationID) ||
		prepared.ContinuationReceiptDigest == ([32]byte{}) ||
		service.admissionPrincipal != identity.EntityID(continuationID) ||
		service.admissionResource != federatedMFATOTPEnrollmentCompleteResource {
		t.Fatalf("enrollment completion = reservation %d calls %d command %#v", auth.reserveCalls, service.completeCalls, command)
	}
	setCookies := response.Header().Values("Set-Cookie")
	if len(setCookies) != 1 || !strings.Contains(setCookies[0], developmentMFACookie+"=; ") ||
		strings.Contains(setCookies[0], developmentFederatedContinuationCookie) ||
		strings.Contains(setCookies[0], developmentCookie+"=") {
		t.Fatalf("Set-Cookie = %#v, want only terminal MFA ceremony deletion", setCookies)
	}
	if !strings.Contains(response.Body.String(), `"factorId":"`+factorID.String()+`"`) ||
		!strings.Contains(response.Body.String(), `"next":"step_up"`) {
		t.Fatalf("response = %s", response.Body.String())
	}
}

func TestCompleteTOTPEnrollmentRotatesSessionAndClearsCeremonyCookie(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	oldSessionID := uuid.Must(uuid.NewV7())
	familyID := uuid.Must(uuid.NewV7())
	newSessionID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	factorID := uuid.Must(uuid.NewV7())
	reservation := testMFASessionReservation(t, newSessionID, familyID, now)
	auth := &transportAuthStub{
		authenticateResult: authentication.Session{
			ID: oldSessionID, RotationFamilyID: familyID, User: authentication.User{ID: userID},
			ActiveTenantID: &tenantID, AbsoluteExpiresAt: now.Add(8 * time.Hour), AuthenticationMethod: "oidc",
		},
		reserveResult: reservation,
		currentResult: authentication.SessionCredential{
			SessionToken: testReservedSessionToken(), CSRFToken: testReservedCSRFToken(),
			Session: authentication.Session{
				ID: newSessionID, RotationFamilyID: familyID,
				User: authentication.User{ID: userID, DisplayName: "Responder"}, ActiveTenantID: &tenantID,
				CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(time.Hour),
				AbsoluteExpiresAt: now.Add(8 * time.Hour), AuthenticationMethod: "oidc",
			}},
	}
	mfaService := &mfaTransportStub{completeResult: mfaauth.TOTPEnrollmentApplyResult{FactorID: identity.EntityID(factorID)}}
	router := newMFATestRouter(t, auth, mfaService)
	enrollmentID := uuid.Must(uuid.NewV7())
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/mfa/totp/enrollments/"+enrollmentID.String(),
		strings.NewReader(`{"code":"123456"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, strings.Repeat("C", 43))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: strings.Repeat("A", 43)})
	request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: testMFABrowserHandle()})
	request.RemoteAddr = "198.51.100.42:4242"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if auth.reserveCalls != 1 || auth.reserveCurrent == nil || auth.reserveCurrent.ID != oldSessionID ||
		auth.reserveMethod != mfa.SessionAuthenticationTOTP ||
		!auth.reserveCurrent.AbsoluteExpiresAt.Equal(now.Add(8*time.Hour)) ||
		auth.reserveIssuedAt.IsZero() || mfaService.completeCalls != 1 {
		t.Fatalf("reservation/complete = calls %d current %v method %q completes %d",
			auth.reserveCalls, auth.reserveCurrent, auth.reserveMethod, mfaService.completeCalls)
	}
	if auth.currentToken != testReservedSessionToken() {
		t.Fatalf("CurrentSession token = %q, want reserved browser token", auth.currentToken)
	}
	if _, ok := reservation.Consume(); ok {
		t.Fatal("the HTTP boundary exposed reserved browser material twice")
	}
	setCookies := response.Header().Values("Set-Cookie")
	if len(setCookies) != 2 || !strings.Contains(strings.Join(setCookies, "\n"), developmentCookie+"=") ||
		!strings.Contains(strings.Join(setCookies, "\n"), developmentMFACookie+"=; ") {
		t.Fatalf("Set-Cookie = %#v, want rotated session and cleared ceremony", setCookies)
	}
	if !strings.Contains(response.Body.String(), `"authenticationMethod":"oidc"`) ||
		!strings.Contains(response.Body.String(), `"factorId":"`+factorID.String()+`"`) {
		t.Fatalf("response = %s", response.Body.String())
	}
}

func TestCompleteTOTPEnrollmentDestroysReservedBrowserMaterialOnKernelFailure(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	oldSessionID := uuid.Must(uuid.NewV7())
	familyID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	reservation := testMFASessionReservation(t, uuid.Must(uuid.NewV7()), familyID, now)
	auth := &transportAuthStub{
		authenticateResult: authentication.Session{
			ID: oldSessionID, RotationFamilyID: familyID,
			User:           authentication.User{ID: uuid.Must(uuid.NewV7())},
			ActiveTenantID: &tenantID, AbsoluteExpiresAt: now.Add(8 * time.Hour),
			AuthenticationMethod: "totp",
		},
		reserveResult: reservation,
	}
	router := newMFATestRouter(t, auth, &mfaTransportStub{completeError: mfaauth.ErrDenied})
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/mfa/totp/enrollments/"+uuid.Must(uuid.NewV7()).String(),
		strings.NewReader(`{"code":"123456"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, strings.Repeat("C", 43))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: strings.Repeat("A", 43)})
	request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: testMFABrowserHandle()})
	request.RemoteAddr = "198.51.100.42:4242"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusForbidden, "forbidden")
	if _, ok := reservation.Consume(); ok {
		t.Fatal("kernel failure left reserved browser material consumable")
	}
	if auth.currentToken != "" {
		t.Fatal("kernel failure delivered a reserved browser token to CurrentSession")
	}
	setCookies := strings.Join(response.Header().Values("Set-Cookie"), "\n")
	if !strings.Contains(setCookies, developmentMFACookie+"=; ") ||
		strings.Contains(setCookies, developmentCookie+"=") {
		t.Fatalf("Set-Cookie = %q, want only terminal MFA ceremony deletion", setCookies)
	}
}

func TestCompleteReservedSessionRejectsRehydratedCredentialMaterialMismatch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	sessionID := uuid.Must(uuid.NewV7())
	familyID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	reservation := testMFASessionReservation(t, sessionID, familyID, now)
	auth := &transportAuthStub{currentResult: authentication.SessionCredential{
		SessionToken: strings.Repeat("B", 43), CSRFToken: testReservedCSRFToken(),
		Session: authentication.Session{
			ID: sessionID, RotationFamilyID: familyID, User: authentication.User{ID: userID},
			ActiveTenantID: &tenantID, AbsoluteExpiresAt: now.Add(8 * time.Hour),
			AuthenticationMethod: "totp",
		},
	}}
	handler := &Handler{authentication: auth}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/test", nil)
	response := httptest.NewRecorder()

	if _, ok := handler.completeReservedSession(response, request, reservation, "totp"); ok {
		t.Fatal("credential material mismatch was accepted")
	}

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if _, ok := reservation.Consume(); ok {
		t.Fatal("credential material mismatch left reserved browser material consumable")
	}
}

func TestAnonymousPasskeyStartRequiresSameOriginAndNoSessionAuthority(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	for _, test := range []struct {
		name       string
		origin     string
		withCookie bool
		status     int
		code       string
	}{
		{name: "cross origin", origin: "https://attacker.example", status: http.StatusForbidden, code: "forbidden"},
		{name: "mixed session authority", origin: "http://localhost:8081", withCookie: true, status: http.StatusUnauthorized, code: "authentication_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			mfaService := &mfaTransportStub{}
			router := newMFATestRouter(t, &transportAuthStub{}, mfaService)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkeys/options",
				strings.NewReader(`{"tenantId":"`+tenantID.String()+`"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", test.origin)
			request.RemoteAddr = "198.51.100.42:4242"
			if test.withCookie {
				request.AddCookie(&http.Cookie{Name: developmentCookie, Value: strings.Repeat("A", 43)})
			}
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			assertProblem(t, response, test.status, test.code)
			if mfaService.admissionCalls != 0 {
				t.Fatalf("Admission calls = %d, want zero", mfaService.admissionCalls)
			}
		})
	}
}

func TestTenantBoundMfaStartRejectsSessionWithoutActiveTenantBeforeAdmission(t *testing.T) {
	auth := &transportAuthStub{authenticateResult: authentication.Session{
		ID: uuid.Must(uuid.NewV7()), User: authentication.User{ID: uuid.Must(uuid.NewV7())},
		AbsoluteExpiresAt: time.Now().UTC().Add(time.Hour), AuthenticationMethod: "totp",
	}}
	mfaService := &mfaTransportStub{}
	router := newMFATestRouter(t, auth, mfaService)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/totp/enrollments", nil)
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, strings.Repeat("C", 43))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: strings.Repeat("A", 43)})
	request.RemoteAddr = "198.51.100.42:4242"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusForbidden, "forbidden")
	if mfaService.admissionCalls != 0 {
		t.Fatalf("Admission calls = %d, want zero without active tenant", mfaService.admissionCalls)
	}
}

func TestMalformedPasskeyCompletionPreservesCookieBeforeAuthoritativePreparation(t *testing.T) {
	mfaService := &mfaTransportStub{}
	router := newMFATestRouter(t, &transportAuthStub{}, mfaService)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkeys/verify", strings.NewReader(`{
        "ceremonyId":"***",
        "credential":{"id":"AQ","type":"public-key","response":{
          "clientDataJSON":"AQ","authenticatorData":"AQ","signature":"AQ"
        }}
      }`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: testMFABrowserHandle()})
	request.RemoteAddr = "198.51.100.42:4242"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	if setCookie := response.Header().Get("Set-Cookie"); setCookie != "" {
		t.Fatalf("Set-Cookie = %q, want retryable ceremony cookie", setCookie)
	}
	if mfaService.admissionCalls != 0 {
		t.Fatalf("Admission calls = %d, want zero before canonical decoding", mfaService.admissionCalls)
	}
}

func TestListMfaDevicesReturnsOnlySafeProjectionAndCanonicalCursor(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	sessionID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	totp := mustMFADevice(t, mfaauth.DeviceProjection{
		ID: identity.EntityID(uuid.Must(uuid.NewV7())), Kind: mfaauth.DeviceTOTP,
		Status: mfaauth.DeviceActive, Version: 1, CreatedAt: now,
	})
	passkey := mustMFADevice(t, mfaauth.DeviceProjection{
		ID: identity.EntityID(uuid.Must(uuid.NewV7())), Kind: mfaauth.DevicePasskey,
		Status: mfaauth.DeviceActive, DisplayName: "Platform key", Version: 7,
		Discoverable: true, BackupEligible: true, BackedUp: true,
		Transports: []webauthn.CredentialTransport{webauthn.TransportInternal},
		CreatedAt:  now.Add(-time.Minute), LastUsedAt: timePointer(now),
	})
	next := mfaauth.DeviceCursor{Kind: passkey.Kind(), ID: passkey.ID()}
	service := &mfaTransportStub{devicePage: mfaauth.DevicePage{
		Items: []mfaauth.Device{totp, passkey}, NextCursor: &next,
	}}
	auth := &transportAuthStub{authenticateResult: authentication.Session{
		ID: sessionID, User: authentication.User{ID: userID}, ActiveTenantID: &tenantID,
	}}
	router := newMFATestRouter(t, auth, service)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/mfa/devices?limit=2", nil)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: strings.Repeat("A", 43)})
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
	var page struct {
		Items      []map[string]any `json:"items"`
		NextCursor string           `json:"nextCursor"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("device page = %#v", page)
	}
	for _, forbidden := range []string{
		"credentialId", "publicKey", "aaguid", "signCount", "secretEnvelope", "keyVersion",
	} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, response.Body.String())
		}
	}
	if service.deviceAuthority.SessionID != identity.EntityID(sessionID) ||
		service.deviceAuthority.TenantID != identity.EntityID(tenantID) ||
		service.deviceAuthority.UserID != identity.EntityID(userID) || service.deviceInput.Limit != 2 {
		t.Fatalf("authority/input = %#v / %#v", service.deviceAuthority, service.deviceInput)
	}

	service.devicePage = mfaauth.DevicePage{Items: []mfaauth.Device{}}
	request = httptest.NewRequest(
		http.MethodGet,
		"/api/v1/auth/mfa/devices?limit=1&includeRevoked=true&after="+page.NextCursor,
		nil,
	)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: strings.Repeat("A", 43)})
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || service.deviceInput.After == nil ||
		*service.deviceInput.After != next || !service.deviceInput.IncludeRevoked {
		t.Fatalf("cursor request = status %d input %#v", response.Code, service.deviceInput)
	}
}

func TestMfaDeviceMutationsEnforceOriginCsrfAndStrongVersion(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	deviceID := uuid.Must(uuid.NewV7())
	sessionID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	active := mustMFADevice(t, mfaauth.DeviceProjection{
		ID: identity.EntityID(deviceID), Kind: mfaauth.DevicePasskey,
		Status: mfaauth.DeviceActive, DisplayName: "Security key", Version: 2,
		Transports: []webauthn.CredentialTransport{}, CreatedAt: now,
	})
	baseAuth := func() *transportAuthStub {
		return &transportAuthStub{authenticateResult: authentication.Session{
			ID: sessionID, User: authentication.User{ID: userID}, ActiveTenantID: &tenantID,
		}}
	}
	for _, test := range []struct {
		name       string
		origin     string
		csrf       string
		ifMatch    string
		body       string
		result     mfaauth.DeviceMutationResult
		resultErr  error
		wantStatus int
		wantCalls  int
	}{
		{name: "cross origin", origin: "https://attacker.invalid", csrf: strings.Repeat("C", 43), ifMatch: `"v1"`, body: `{"expectedVersion":1,"displayName":"Security key"}`, wantStatus: http.StatusForbidden},
		{name: "missing csrf", origin: "http://localhost:8081", ifMatch: `"v1"`, body: `{"expectedVersion":1,"displayName":"Security key"}`, wantStatus: http.StatusForbidden},
		{name: "missing precondition", origin: "http://localhost:8081", csrf: strings.Repeat("C", 43), body: `{"expectedVersion":1,"displayName":"Security key"}`, wantStatus: http.StatusPreconditionRequired},
		{name: "header body mismatch", origin: "http://localhost:8081", csrf: strings.Repeat("C", 43), ifMatch: `"v2"`, body: `{"expectedVersion":1,"displayName":"Security key"}`, wantStatus: http.StatusBadRequest},
		{name: "stale cas", origin: "http://localhost:8081", csrf: strings.Repeat("C", 43), ifMatch: `"v1"`, body: `{"expectedVersion":1,"displayName":"Security key"}`, resultErr: mfaauth.ErrPrecondition, wantStatus: http.StatusPreconditionFailed, wantCalls: 1},
		{name: "success", origin: "http://localhost:8081", csrf: strings.Repeat("C", 43), ifMatch: `"v1"`, body: `{"expectedVersion":1,"displayName":"Security key"}`, result: mfaauth.DeviceMutationResult{Device: active}, wantStatus: http.StatusOK, wantCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &mfaTransportStub{mutationResult: test.result, mutationError: test.resultErr}
			router := newMFATestRouter(t, baseAuth(), service)
			request := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/mfa/devices/"+deviceID.String(), strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.csrf != "" {
				request.Header.Set(csrfTokenHeader, test.csrf)
			}
			if test.ifMatch != "" {
				request.Header.Set(ifMatchHeader, test.ifMatch)
			}
			request.AddCookie(&http.Cookie{Name: developmentCookie, Value: strings.Repeat("A", 43)})
			request.RemoteAddr = "198.51.100.42:4242"
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != test.wantStatus || service.renameCalls != test.wantCalls {
				t.Fatalf("status/calls = %d/%d: %s", response.Code, service.renameCalls, response.Body.String())
			}
			if test.wantStatus == http.StatusOK && response.Header().Get("ETag") != `"v2"` {
				t.Fatalf("ETag = %q", response.Header().Get("ETag"))
			}
		})
	}
}

func TestRevokeMfaDeviceClearsCurrentSessionCookie(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	deviceID := uuid.Must(uuid.NewV7())
	sessionID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	revokedAt := now.Add(time.Second)
	device := mustMFADevice(t, mfaauth.DeviceProjection{
		ID: identity.EntityID(deviceID), Kind: mfaauth.DeviceTOTP,
		Status: mfaauth.DeviceRevoked, Version: 2, CreatedAt: now, RevokedAt: &revokedAt,
	})
	service := &mfaTransportStub{mutationResult: mfaauth.DeviceMutationResult{
		Device: device, CurrentSessionRevoked: true,
	}}
	auth := &transportAuthStub{authenticateResult: authentication.Session{
		ID: sessionID, User: authentication.User{ID: userID}, ActiveTenantID: &tenantID,
	}}
	router := newMFATestRouter(t, auth, service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/devices/"+deviceID.String()+"/revoke", strings.NewReader(`{"kind":"totp","expectedVersion":1}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, strings.Repeat("C", 43))
	request.Header.Set(ifMatchHeader, `"v1"`)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: strings.Repeat("A", 43)})
	request.RemoteAddr = "198.51.100.42:4242"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK || service.revokeCalls != 1 || response.Header().Get("ETag") != `"v2"` {
		t.Fatalf("status/calls/etag = %d/%d/%q: %s", response.Code, service.revokeCalls, response.Header().Get("ETag"), response.Body.String())
	}
	if cookie := response.Header().Get("Set-Cookie"); !strings.Contains(cookie, developmentCookie+"=;") || !strings.Contains(cookie, "Max-Age=0") {
		t.Fatalf("Set-Cookie = %q, want current-session deletion", cookie)
	}
}

func FuzzMfaDeviceCursorIsCanonical(f *testing.F) {
	id := identity.EntityID(uuid.MustParse("019d2f44-9000-7000-8000-000000000001"))
	seed, err := encodeMFADeviceCursor(mfaauth.DeviceCursor{Kind: mfaauth.DevicePasskey, ID: id})
	if err != nil {
		f.Fatalf("encode seed: %v", err)
	}
	f.Add(seed)
	f.Add("***")
	f.Fuzz(func(t *testing.T, value string) {
		cursor, decodeErr := decodeMFADeviceCursor(value)
		if decodeErr != nil {
			return
		}
		encoded, encodeErr := encodeMFADeviceCursor(cursor)
		if encodeErr != nil || encoded != value {
			t.Fatalf("accepted non-canonical cursor %q: encoded %q error %v", value, encoded, encodeErr)
		}
	})
}

func FuzzDecodeWebAuthnBinaryRejectsNonCanonicalInputs(f *testing.F) {
	f.Add("AQ")
	f.Add("AQ==")
	f.Add("***")
	f.Fuzz(func(t *testing.T, value string) {
		decoded, err := decodeWebAuthnBinary(value, 1, 64)
		if err != nil {
			return
		}
		if len(decoded) < 1 || len(decoded) > 64 || base64.RawURLEncoding.EncodeToString(decoded) != value {
			t.Fatalf("accepted non-canonical value %q", value)
		}
	})
}

func TestWebAuthnMaterialSizeEnforcesAggregateBound(t *testing.T) {
	t.Parallel()

	if got := webAuthnMaterialSize(make([]byte, maximumWebAuthnBinaryBytes)); got != maximumWebAuthnBinaryBytes {
		t.Fatalf("exact aggregate = %d", got)
	}
	if got := webAuthnMaterialSize(make([]byte, maximumWebAuthnBinaryBytes), []byte{1}); got <= maximumWebAuthnBinaryBytes {
		t.Fatalf("oversized aggregate = %d", got)
	}
}

func TestOpaqueMFAIdentifiersRejectZeroEntropy(t *testing.T) {
	zero := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, err := decodeCeremonyID(zero); err == nil {
		t.Fatal("decodeCeremonyID() accepted an all-zero identifier")
	}
	if _, err := decodeChallengeID(zero); err == nil {
		t.Fatal("decodeChallengeID() accepted an all-zero identifier")
	}
	nonzero := make([]byte, 32)
	nonzero[0] = 1
	encoded := base64.RawURLEncoding.EncodeToString(nonzero)
	if _, err := decodeCeremonyID(encoded); err != nil {
		t.Fatalf("decodeCeremonyID() rejected canonical identifier: %v", err)
	}
	if _, err := decodeChallengeID(encoded); err != nil {
		t.Fatalf("decodeChallengeID() rejected canonical identifier: %v", err)
	}
}

func mustMFADevice(t *testing.T, projection mfaauth.DeviceProjection) mfaauth.Device {
	t.Helper()
	device, err := mfaauth.NewDevice(projection)
	if err != nil {
		t.Fatalf("NewDevice() error = %v", err)
	}
	return device
}

func timePointer(value time.Time) *time.Time { return &value }

func testMFABrowserHandle() string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("\x01", 32)))
}

func testFederatedContinuationCookie(t *testing.T, continuationID uuid.UUID) (*http.Cookie, string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	receiptRaw := sha256.Sum256(append([]byte("federated continuation receipt:"), continuationID[:]...))
	receipt := base64.RawURLEncoding.EncodeToString(receiptRaw[:])
	response := httptest.NewRecorder()
	if err := setFederatedContinuationCookieWithPolicy(
		response,
		sessionCookiePolicy{name: developmentFederatedContinuationCookie, secure: false},
		continuationID,
		[]byte(receipt),
		now.Add(5*time.Minute),
		now,
	); err != nil {
		t.Fatalf("setFederatedContinuationCookieWithPolicy() error = %v", err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("continuation cookies = %#v", cookies)
	}
	return cookies[0], receipt
}

func newMFATestRouter(t *testing.T, auth AuthenticationService, service MFAService) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth,
			Authorization: &transportAuthorizationStub{}, Contacts: &transportContactStub{},
			CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{}, Environment: "test",
			IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{},
			MFA: service, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{},
			Platform: &transportPlatformStub{}, PublicOrigin: "http://localhost:8081",
			ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{},
			Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func testMFASessionReservation(
	t *testing.T,
	sessionID uuid.UUID,
	familyID uuid.UUID,
	now time.Time,
) authentication.MFASessionReservation {
	t.Helper()
	sessionToken := []byte(testReservedSessionToken())
	csrfToken := []byte(testReservedCSRFToken())
	tokenDigest := sha256.Sum256(sessionToken)
	csrfDigest := sha256.Sum256(csrfToken)
	reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID: identity.EntityID(sessionID), FamilyID: identity.EntityID(familyID),
		TokenDigest: tokenDigest, CSRFDigest: csrfDigest, AuthenticationMethod: mfa.SessionAuthenticationTOTP,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewSessionReservation() error = %v", err)
	}
	result, err := authentication.NewMFASessionReservation(reservation, sessionToken, csrfToken)
	if err != nil {
		t.Fatalf("NewMFASessionReservation() error = %v", err)
	}
	return result
}

func testReservedSessionToken() string {
	value := sha256.Sum256([]byte("reserved MFA browser session token"))
	return base64.RawURLEncoding.EncodeToString(value[:])
}

func testReservedCSRFToken() string {
	value := sha256.Sum256([]byte("reserved MFA browser CSRF token"))
	return base64.RawURLEncoding.EncodeToString(value[:])
}
