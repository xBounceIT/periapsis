package httpserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformldapauth"
)

type unavailablePlatformLDAPAuthenticationService struct{}

func (unavailablePlatformLDAPAuthenticationService) Authenticate(
	context.Context,
	platformldapauth.Command,
) (platformldapauth.Result, error) {
	return platformldapauth.Result{}, platformldapauth.ErrUnavailable
}

func platformLDAPAuthenticationServiceIsNil(service PlatformLDAPAuthenticationService) bool {
	if service == nil {
		return true
	}
	value := reflect.ValueOf(service)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (h *Handler) LoginPlatformLDAP(
	w http.ResponseWriter,
	r *http.Request,
	providerKey contract.PlatformLDAPProviderKey,
) {
	prepareFederatedResponse(w)
	if h.rejectLDAPBrowserAuthority(r) != nil || h.requireSameOrigin(r) != nil ||
		r.URL.RawQuery != "" || r.URL.ForceQuery {
		writePlatformLDAPFailure(w, r, platformldapauth.ErrAuthentication)
		return
	}
	command, err := h.decodePlatformLDAPLogin(w, r, string(providerKey))
	if err != nil {
		writePlatformLDAPFailure(w, r, platformldapauth.ErrAuthentication)
		return
	}
	defer clear(command.Password)
	defer clear(command.TOTPCode)
	result, err := h.platformLDAPAuthentication.Authenticate(r.Context(), command)
	clear(command.Password)
	clear(command.TOTPCode)
	if err != nil {
		if result.Credential != nil {
			result.Credential.Destroy()
		}
		writePlatformLDAPFailure(w, r, err)
		return
	}
	federatedResult := federatedauth.ApplyResult{
		Category: federatedauth.ApplySuccess,
		UserID:   identity.EntityID(result.UserID), SessionID: result.SessionID,
		ReturnPath: result.ReturnPath, Credential: result.Credential,
	}
	if !h.completeFederatedBrowserCredential(w, r, federatedProtocolPlatformLDAP, federatedResult) {
		writePlatformLDAPFailure(w, r, platformldapauth.ErrAuthentication)
	}
}

func (h *Handler) decodePlatformLDAPLogin(
	w http.ResponseWriter,
	r *http.Request,
	providerKey string,
) (platformldapauth.Command, error) {
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return platformldapauth.Command{}, platformldapauth.ErrInvalidInput
	}
	r.Body = http.MaxBytesReader(w, r.Body, maximumLDAPLoginBodyBytes)
	raw, readErr := io.ReadAll(r.Body)
	closeErr := r.Body.Close()
	if readErr != nil || closeErr != nil || len(raw) == 0 {
		clear(raw)
		return platformldapauth.Command{}, platformldapauth.ErrInvalidInput
	}
	defer clear(raw)
	fields := make(map[string][]byte, 4)
	for _, item := range bytes.Split(raw, []byte{'&'}) {
		namePart, valuePart, found := bytes.Cut(item, []byte{'='})
		if !found {
			clearFormFields(fields)
			return platformldapauth.Command{}, platformldapauth.ErrInvalidInput
		}
		nameBytes, decodeErr := decodeLDAPFormComponent(namePart)
		if decodeErr != nil {
			clearFormFields(fields)
			return platformldapauth.Command{}, platformldapauth.ErrInvalidInput
		}
		name := string(nameBytes)
		clear(nameBytes)
		if name != "username" && name != "password" && name != "totpCode" && name != "returnPath" {
			clearFormFields(fields)
			return platformldapauth.Command{}, platformldapauth.ErrInvalidInput
		}
		if _, duplicate := fields[name]; duplicate {
			clearFormFields(fields)
			return platformldapauth.Command{}, platformldapauth.ErrInvalidInput
		}
		value, decodeErr := decodeLDAPFormComponent(valuePart)
		if decodeErr != nil {
			clearFormFields(fields)
			return platformldapauth.Command{}, platformldapauth.ErrInvalidInput
		}
		fields[name] = value
	}
	if len(fields) != 4 || !utf8.Valid(fields["username"]) || !utf8.Valid(fields["returnPath"]) {
		clearFormFields(fields)
		return platformldapauth.Command{}, platformldapauth.ErrInvalidInput
	}
	event, err := h.eventContext(r)
	if err != nil {
		clearFormFields(fields)
		return platformldapauth.Command{}, platformldapauth.ErrInvalidInput
	}
	password := fields["password"]
	totpCode := fields["totpCode"]
	fields["password"] = nil
	fields["totpCode"] = nil
	command := platformldapauth.Command{
		ProviderKey: providerKey, Username: string(fields["username"]),
		Password: password, TOTPCode: totpCode, ReturnPath: string(fields["returnPath"]),
		ClientIP: event.RemoteAddress, UserAgent: event.UserAgent,
		RequestID: event.RequestID, CorrelationID: event.CorrelationID,
	}
	clearFormFields(fields)
	return command, nil
}

func writePlatformLDAPFailure(w http.ResponseWriter, r *http.Request, err error) {
	prepareFederatedResponse(w)
	if errors.Is(err, platformldapauth.ErrRateLimited) {
		w.Header().Set("Retry-After", "5")
		writeProblem(w, r, http.StatusTooManyRequests, "authentication_rate_limited", "Authentication unavailable", "Directory authentication could not be completed.")
		return
	}
	if errors.Is(err, platformldapauth.ErrUnavailable) {
		w.Header().Set("Retry-After", "5")
		writeProblem(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable", "Directory authentication is temporarily unavailable.")
		return
	}
	writeProblem(w, r, http.StatusUnauthorized, "authentication_failed", "Authentication failed", "Directory authentication could not be completed.")
}

var _ PlatformLDAPAuthenticationService = unavailablePlatformLDAPAuthenticationService{}
