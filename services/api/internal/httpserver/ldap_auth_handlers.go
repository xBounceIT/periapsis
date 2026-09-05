package httpserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/ldapauth"
)

const maximumLDAPLoginBodyBytes = 16 * 1024

type LDAPAuthenticationService interface {
	Authenticate(context.Context, ldapauth.Command) (ldapauth.Result, error)
}

type unavailableLDAPAuthenticationService struct{}

func (unavailableLDAPAuthenticationService) Authenticate(context.Context, ldapauth.Command) (ldapauth.Result, error) {
	return ldapauth.Result{}, ldapauth.ErrUnavailable
}

func (h *Handler) LoginTenantLDAP(
	w http.ResponseWriter,
	r *http.Request,
	tenantSlug contract.FederatedTenantSlug,
	loginKey contract.FederatedLoginKey,
) {
	prepareFederatedResponse(w)
	if h.rejectLDAPBrowserAuthority(r) != nil || h.requireSameOrigin(r) != nil ||
		r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeLDAPFailure(w, r, ldapauth.ErrAuthentication)
		return
	}
	command, err := h.decodeLDAPLogin(w, r, string(tenantSlug), string(loginKey))
	if err != nil {
		writeLDAPFailure(w, r, ldapauth.ErrAuthentication)
		return
	}
	defer clear(command.Password)
	result, err := h.ldapAuthentication.Authenticate(r.Context(), command)
	clear(command.Password)
	if err != nil {
		if result.Credential != nil {
			result.Credential.Destroy()
		}
		writeLDAPFailure(w, r, err)
		return
	}
	federatedResult := federatedauth.ApplyResult{
		Category: federatedauth.ApplySuccess,
		UserID:   identity.EntityID(result.UserID), SessionID: result.SessionID,
		ContinuationID: result.ContinuationID, ReturnPath: result.ReturnPath,
		Credential: result.Credential,
	}
	if !h.completeFederatedBrowserCredential(w, r, federatedProtocolLDAP, federatedResult) {
		writeLDAPFailure(w, r, ldapauth.ErrAuthentication)
	}
}

func (h *Handler) decodeLDAPLogin(
	w http.ResponseWriter,
	r *http.Request,
	tenantSlug string,
	loginKey string,
) (ldapauth.Command, error) {
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return ldapauth.Command{}, ldapauth.ErrInvalidInput
	}
	r.Body = http.MaxBytesReader(w, r.Body, maximumLDAPLoginBodyBytes)
	raw, readErr := io.ReadAll(r.Body)
	closeErr := r.Body.Close()
	if readErr != nil || closeErr != nil || len(raw) == 0 {
		clear(raw)
		return ldapauth.Command{}, ldapauth.ErrInvalidInput
	}
	defer clear(raw)
	fields := make(map[string][]byte, 3)
	for _, item := range bytes.Split(raw, []byte{'&'}) {
		namePart, valuePart, found := bytes.Cut(item, []byte{'='})
		if !found {
			clearFormFields(fields)
			return ldapauth.Command{}, ldapauth.ErrInvalidInput
		}
		nameBytes, decodeErr := decodeLDAPFormComponent(namePart)
		if decodeErr != nil {
			clearFormFields(fields)
			return ldapauth.Command{}, ldapauth.ErrInvalidInput
		}
		name := string(nameBytes)
		clear(nameBytes)
		if name != "username" && name != "password" && name != "returnPath" {
			clearFormFields(fields)
			return ldapauth.Command{}, ldapauth.ErrInvalidInput
		}
		if _, duplicate := fields[name]; duplicate {
			clearFormFields(fields)
			return ldapauth.Command{}, ldapauth.ErrInvalidInput
		}
		value, decodeErr := decodeLDAPFormComponent(valuePart)
		if decodeErr != nil {
			clearFormFields(fields)
			return ldapauth.Command{}, ldapauth.ErrInvalidInput
		}
		fields[name] = value
	}
	if len(fields) != 3 || !utf8.Valid(fields["username"]) || !utf8.Valid(fields["returnPath"]) {
		clearFormFields(fields)
		return ldapauth.Command{}, ldapauth.ErrInvalidInput
	}
	event, err := h.eventContext(r)
	if err != nil {
		clearFormFields(fields)
		return ldapauth.Command{}, ldapauth.ErrInvalidInput
	}
	password := fields["password"]
	fields["password"] = nil
	command := ldapauth.Command{
		TenantSlug: tenantSlug, LoginKey: loginKey,
		Username: string(fields["username"]), Password: password,
		ReturnPath: string(fields["returnPath"]), ClientIP: event.RemoteAddress,
		UserAgent: event.UserAgent, RequestID: event.RequestID, CorrelationID: event.CorrelationID,
	}
	clearFormFields(fields)
	return command, nil
}

func decodeLDAPFormComponent(value []byte) ([]byte, error) {
	decoded := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '+':
			decoded = append(decoded, ' ')
		case '%':
			if index+2 >= len(value) {
				clear(decoded)
				return nil, ldapauth.ErrInvalidInput
			}
			high, highOK := hexadecimalFormNibble(value[index+1])
			low, lowOK := hexadecimalFormNibble(value[index+2])
			if !highOK || !lowOK {
				clear(decoded)
				return nil, ldapauth.ErrInvalidInput
			}
			decoded = append(decoded, high<<4|low)
			index += 2
		default:
			decoded = append(decoded, value[index])
		}
	}
	return decoded, nil
}

func hexadecimalFormNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func clearFormFields(fields map[string][]byte) {
	for key, value := range fields {
		clear(value)
		delete(fields, key)
	}
}

func (h *Handler) rejectLDAPBrowserAuthority(r *http.Request) error {
	if err := h.rejectFederatedBrowserAuthority(r); err != nil {
		return err
	}
	for _, cookie := range r.Cookies() {
		switch cookie.Name {
		case h.federated.oidcCookie.name, h.federated.samlCookie.name,
			h.federated.platformOIDCCookie.name, h.federated.platformSAMLCookie.name:
			return ldapauth.ErrAuthentication
		}
	}
	return nil
}

func writeLDAPFailure(w http.ResponseWriter, r *http.Request, err error) {
	prepareFederatedResponse(w)
	if errors.Is(err, ldapauth.ErrRateLimited) {
		w.Header().Set("Retry-After", "5")
		writeProblem(w, r, http.StatusTooManyRequests, "authentication_rate_limited", "Authentication unavailable", "Directory authentication could not be completed.")
		return
	}
	if errors.Is(err, ldapauth.ErrUnavailable) {
		w.Header().Set("Retry-After", "5")
		writeProblem(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable", "Directory authentication is temporarily unavailable.")
		return
	}
	writeProblem(w, r, http.StatusUnauthorized, "authentication_failed", "Authentication failed", "Directory authentication could not be completed.")
}
