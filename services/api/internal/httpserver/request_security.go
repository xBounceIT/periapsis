package httpserver

import (
	"encoding/base64"
	"errors"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/origin"
)

const (
	bootstrapTokenHeader                         = "X-Periapsis-Bootstrap-Token"
	correlationIDHeader                          = "X-Correlation-ID"
	csrfTokenHeader                              = "X-CSRF-Token"
	developmentCookie                            = "periapsis_session"
	developmentMFACookie                         = "periapsis_mfa"
	developmentFederatedContinuationCookie       = "periapsis_federated_continuation"
	developmentLogoutContinuationCookie          = "periapsis_logout_continuation"
	idempotencyKeyHeader                         = "Idempotency-Key"
	ifMatchHeader                                = "If-Match"
	unknownUserAgent                             = "unknown"
	productionCookie                             = "__Host-periapsis_session"
	productionMFACookie                          = "__Host-periapsis_mfa"
	productionFederatedContinuationCookie        = "__Host-periapsis_federated_continuation"
	productionLogoutContinuationCookie           = "__Secure-periapsis_logout_continuation"
	maximumUserAgentSize                         = 512
	maximumResourceVersion                 int64 = 2_147_483_647
	maximumIncrementableResourceVersion          = maximumResourceVersion - 1
	maximumExactJSONResourceVersion        int64 = 9_007_199_254_740_991
	maximumForwardedForSize                      = 2048
	maximumForwardedHops                         = 32
	maximumBearerTokenSize                       = 256
)

type sessionCookiePolicy struct {
	name   string
	secure bool
}

func newSessionCookiePolicy(environment, publicOrigin string) (sessionCookiePolicy, error) {
	return newBrowserCapabilityCookiePolicy(environment, publicOrigin, developmentCookie, productionCookie)
}

func newMFACookiePolicy(environment, publicOrigin string) (sessionCookiePolicy, error) {
	return newBrowserCapabilityCookiePolicy(environment, publicOrigin, developmentMFACookie, productionMFACookie)
}

func newFederatedContinuationCookiePolicy(environment, publicOrigin string) (sessionCookiePolicy, error) {
	return newBrowserCapabilityCookiePolicy(
		environment,
		publicOrigin,
		developmentFederatedContinuationCookie,
		productionFederatedContinuationCookie,
	)
}

func newLogoutContinuationCookiePolicy(environment, publicOrigin string) (sessionCookiePolicy, error) {
	return newBrowserCapabilityCookiePolicy(
		environment,
		publicOrigin,
		developmentLogoutContinuationCookie,
		productionLogoutContinuationCookie,
	)
}

func setLogoutContinuationCookie(
	w http.ResponseWriter,
	policy sessionCookiePolicy,
	continuationID identity.EntityID,
	credential []byte,
	expiresAt time.Time,
	databaseLifetime time.Duration,
	now time.Time,
) error {
	path := logoutContinuationPath(continuationID)
	lifetime := databaseLifetime
	if lifetime == 0 {
		lifetime = expiresAt.Sub(now)
	}
	if !validLogoutContinuationCookiePolicy(policy) || path == "" ||
		!validMFABrowserHandle(string(credential)) || !validInstantForLogoutCookie(expiresAt) ||
		!validInstantForLogoutCookie(now) || lifetime <= 0 ||
		lifetime > maximumLogoutContinuationTTL {
		return authentication.ErrUnavailable
	}
	localExpiresAt := now.Add(lifetime)
	maxAge := int(math.Ceil(lifetime.Seconds()))
	if maxAge < 1 {
		return authentication.ErrUnavailable
	}
	http.SetCookie(w, &http.Cookie{
		Name: policy.name, Value: string(credential), Path: path, Expires: localExpiresAt,
		MaxAge: maxAge, HttpOnly: true, Secure: policy.secure, SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func logoutContinuationCredential(
	r *http.Request,
	policy sessionCookiePolicy,
	continuationID identity.EntityID,
) ([]byte, error) {
	if r == nil || !validLogoutContinuationCookiePolicy(policy) || logoutContinuationPath(continuationID) == "" {
		return nil, authentication.ErrInvalidAuthentication
	}
	value := ""
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == policy.name {
			count++
			value = cookie.Value
		}
	}
	if count != 1 || !validMFABrowserHandle(value) {
		return nil, authentication.ErrInvalidAuthentication
	}
	return []byte(value), nil
}

func clearLogoutContinuationCookie(
	w http.ResponseWriter,
	policy sessionCookiePolicy,
	continuationID identity.EntityID,
) {
	path := logoutContinuationPath(continuationID)
	if !validLogoutContinuationCookiePolicy(policy) || path == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: policy.name, Value: "", Path: path, Expires: time.Unix(1, 0).UTC(),
		MaxAge: -1, HttpOnly: true, Secure: policy.secure, SameSite: http.SameSiteStrictMode,
	})
}

func validLogoutContinuationCookiePolicy(policy sessionCookiePolicy) bool {
	return policy == (sessionCookiePolicy{name: productionLogoutContinuationCookie, secure: true}) ||
		policy == (sessionCookiePolicy{name: developmentLogoutContinuationCookie, secure: false})
}

func validInstantForLogoutCookie(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
}

func newBrowserCapabilityCookiePolicy(
	environment, publicOrigin, developmentName, secureName string,
) (sessionCookiePolicy, error) {
	secure, err := browserOriginUsesSecureCookies(environment, publicOrigin)
	if err != nil {
		return sessionCookiePolicy{}, err
	}
	if secure {
		return sessionCookiePolicy{name: secureName, secure: true}, nil
	}
	return sessionCookiePolicy{name: developmentName, secure: false}, nil
}

// browserOriginUsesSecureCookies keeps the cookie boundary aligned with the
// actual browser origin. Development deployments behind a TLS edge exercise
// the same __Host-/Secure contract as production; only an explicit local HTTP
// origin may use the deliberately separate development cookie namespace.
func browserOriginUsesSecureCookies(environment, publicOrigin string) (bool, error) {
	switch environment {
	case "production", "development", "test":
	default:
		return false, errors.New("unsupported HTTP environment")
	}
	parsed, err := url.Parse(publicOrigin)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" || parsed.ForceQuery {
		return false, errors.New("canonical public origin is required for browser cookies")
	}
	switch parsed.Scheme {
	case "https":
		return true, nil
	case "http":
		if environment == "production" {
			return false, errors.New("production browser cookies require an HTTPS public origin")
		}
		return false, nil
	default:
		return false, errors.New("canonical public origin is required for browser cookies")
	}
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, token string, absoluteExpiry time.Time) {
	maxAge := int(time.Until(absoluteExpiry).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name: h.cookie.name, Value: token, Path: "/", Expires: absoluteExpiry,
		MaxAge: maxAge, HttpOnly: true, Secure: h.cookie.secure, SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: h.cookie.name, Value: "", Path: "/", Expires: time.Unix(1, 0).UTC(),
		MaxAge: -1, HttpOnly: true, Secure: h.cookie.secure, SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) setMFACookie(w http.ResponseWriter, browserHandle []byte, absoluteExpiry time.Time) error {
	value := string(browserHandle)
	if !validMFABrowserHandle(value) {
		return authentication.ErrUnavailable
	}
	maxAge := int(time.Until(absoluteExpiry).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name: h.mfaCookie.name, Value: value, Path: "/", Expires: absoluteExpiry,
		MaxAge: maxAge, HttpOnly: true, Secure: h.mfaCookie.secure, SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func (h *Handler) clearMFACookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: h.mfaCookie.name, Value: "", Path: "/", Expires: time.Unix(1, 0).UTC(),
		MaxAge: -1, HttpOnly: true, Secure: h.mfaCookie.secure, SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) clearFederatedContinuationCookie(w http.ResponseWriter) {
	clearCookieWithPolicy(w, h.federatedContinuationCookie)
}

func (h *Handler) mfaBrowserHandle(r *http.Request) ([]byte, error) {
	var value string
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == h.mfaCookie.name {
			count++
			value = cookie.Value
		}
	}
	if count != 1 || !validMFABrowserHandle(value) {
		return nil, authentication.ErrInvalidAuthentication
	}
	return []byte(value), nil
}

func validMFABrowserHandle(value string) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(32) || strings.TrimSpace(value) != value {
		return false
	}
	decoded := make([]byte, 32)
	count, err := base64.RawURLEncoding.Strict().Decode(decoded, []byte(value))
	var combined byte
	for _, item := range decoded {
		combined |= item
	}
	valid := err == nil && count == len(decoded) && combined != 0 &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
	clear(decoded)
	return valid
}

func (h *Handler) rejectSessionAuthority(r *http.Request) error {
	if len(r.Header.Values("Authorization")) != 0 {
		return authentication.ErrInvalidAuthentication
	}
	for _, cookie := range r.Cookies() {
		if cookie.Name == h.cookie.name {
			return authentication.ErrInvalidAuthentication
		}
	}
	return nil
}

func (h *Handler) sessionToken(r *http.Request) (string, error) {
	if len(r.Header.Values("Authorization")) != 0 {
		return "", authentication.ErrInvalidAuthentication
	}
	var token string
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == h.cookie.name {
			count++
			token = cookie.Value
		}
	}
	if count != 1 || token == "" || len(token) > 128 {
		return "", authentication.ErrInvalidAuthentication
	}
	return token, nil
}

func (h *Handler) bearerToken(r *http.Request) (string, error) {
	for _, cookie := range r.Cookies() {
		if cookie.Name == h.cookie.name {
			return "", authentication.ErrInvalidAuthentication
		}
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", authentication.ErrInvalidAuthentication
	}
	value := values[0]
	if value != strings.TrimSpace(value) || len(value) > len("Bearer ")+maximumBearerTokenSize || strings.Contains(value, ",") {
		return "", authentication.ErrInvalidAuthentication
	}
	separator := strings.IndexByte(value, ' ')
	if separator < 1 || !strings.EqualFold(value[:separator], "Bearer") {
		return "", authentication.ErrInvalidAuthentication
	}
	token := value[separator+1:]
	if token == "" || len(token) > maximumBearerTokenSize || strings.ContainsAny(token, " \t\r\n") {
		return "", authentication.ErrInvalidAuthentication
	}
	return token, nil
}

func singleHeader(r *http.Request, name string, maximumLength int) (string, error) {
	values := r.Header.Values(name)
	if len(values) != 1 {
		return "", errors.New("header must occur exactly once")
	}
	value := strings.TrimSpace(values[0])
	if value == "" || len(value) > maximumLength || strings.Contains(value, ",") {
		return "", errors.New("header value is invalid")
	}
	return value, nil
}

// strongVersionPrecondition parses the deliberately narrow strong ETag shape
// used by mutable authorization resources. The boolean distinguishes a missing
// precondition (HTTP 428) from a malformed one (HTTP 400).
func strongVersionPrecondition(r *http.Request) (int64, bool, error) {
	return strongVersionPreconditionUpTo(r, maximumResourceVersion)
}

func strongVersionPreconditionUpTo(r *http.Request, maximum int64) (int64, bool, error) {
	values := r.Header.Values(ifMatchHeader)
	if len(values) == 0 {
		return 0, false, nil
	}
	value, err := singleHeader(r, ifMatchHeader, 32)
	if err != nil || len(value) < len("\"v1\"") ||
		!strings.HasPrefix(value, "\"v") || !strings.HasSuffix(value, "\"") {
		return 0, true, errors.New("If-Match must contain one strong version ETag")
	}
	digits := value[2 : len(value)-1]
	if digits == "" || digits[0] == '0' {
		return 0, true, errors.New("If-Match version is invalid")
	}
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return 0, true, errors.New("If-Match version is invalid")
		}
	}
	version, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || version < 1 || version > maximum {
		return 0, true, errors.New("If-Match version is invalid")
	}
	return version, true, nil
}

func strongVersionETag(version int64) (string, error) {
	return strongVersionETagUpTo(version, maximumResourceVersion)
}

func strongVersionETagUpTo(version int64, maximum int64) (string, error) {
	if version < 1 || version > maximum {
		return "", errors.New("resource version must be positive")
	}
	return "\"v" + strconv.FormatInt(version, 10) + "\"", nil
}

func requestIdempotencyKey(r *http.Request) (string, error) {
	value, err := singleHeader(r, idempotencyKeyHeader, 128)
	if err != nil || len(value) < 16 {
		return "", errors.New("idempotency key is invalid")
	}
	for _, character := range value {
		if character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("._~-", character) {
			continue
		}
		return "", errors.New("idempotency key is invalid")
	}
	return value, nil
}

func (h *Handler) requireSameOrigin(r *http.Request) error {
	origins := r.Header.Values("Origin")
	if len(origins) > 1 {
		return authentication.ErrForbidden
	}
	if len(origins) == 1 {
		origin, err := canonicalHeaderOrigin(origins[0], false)
		if err != nil || origin != h.publicOrigin {
			return authentication.ErrForbidden
		}
		return nil
	}
	referers := r.Header.Values("Referer")
	if len(referers) != 1 {
		return authentication.ErrForbidden
	}
	refererOrigin, err := canonicalHeaderOrigin(referers[0], true)
	if err != nil || refererOrigin != h.publicOrigin {
		return authentication.ErrForbidden
	}
	return nil
}

func canonicalHeaderOrigin(value string, allowPath bool) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Fragment != "" {
		return "", errors.New("invalid origin URL")
	}
	if !allowPath && (parsed.Path != "" || parsed.RawQuery != "") {
		return "", errors.New("origin header must contain only an origin")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("origin scheme is not HTTP")
	}
	hostname, err := origin.CanonicalHostname(parsed.Hostname())
	if err != nil {
		return "", errors.New("origin host is invalid")
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return "", errors.New("origin contains an empty port")
	}
	port := parsed.Port()
	if port != "" {
		parsedPort, portErr := strconv.Atoi(port)
		if portErr != nil || parsedPort < 1 || parsedPort > 65535 {
			return "", errors.New("origin port is invalid")
		}
		if parsedPort == 443 && scheme == "https" || parsedPort == 80 && scheme == "http" {
			port = ""
		} else {
			port = strconv.Itoa(parsedPort)
		}
	}
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	}
	return scheme + "://" + host, nil
}

func requireJSON(r *http.Request) error {
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != "application/json" {
		return authentication.ErrInvalidInput
	}
	return nil
}

func requestMediaType(r *http.Request) (string, error) {
	values := r.Header.Values("Content-Type")
	if len(values) != 1 {
		return "", errors.New("Content-Type must occur exactly once")
	}
	mediaType, _, err := mime.ParseMediaType(values[0])
	if err != nil {
		return "", errors.New("Content-Type is invalid")
	}
	return mediaType, nil
}

func (h *Handler) eventContext(r *http.Request) (authentication.EventContext, error) {
	requestID, err := uuid.Parse(requestIDFromContext(r.Context()))
	if err != nil || requestID.Version() != 7 || requestID.Variant() != uuid.RFC4122 {
		return authentication.EventContext{}, errors.New("request ID is unavailable")
	}
	correlationID := requestID
	if values := r.Header.Values(correlationIDHeader); len(values) == 1 {
		if parsed, parseErr := uuid.Parse(values[0]); parseErr == nil &&
			parsed.Version() == 7 && parsed.Variant() == uuid.RFC4122 {
			correlationID = parsed
		}
	} else if len(values) > 1 {
		return authentication.EventContext{}, errors.New("duplicate correlation ID")
	}
	remoteAddress, err := resolveClientAddress(r, h.trustedProxies)
	if err != nil {
		return authentication.EventContext{}, err
	}
	userAgent := strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return -1
		}
		return character
	}, strings.ToValidUTF8(r.UserAgent(), ""))
	if len(userAgent) > maximumUserAgentSize {
		userAgent = userAgent[:maximumUserAgentSize]
		for !utf8.ValidString(userAgent) {
			userAgent = userAgent[:len(userAgent)-1]
		}
	}
	if strings.Trim(userAgent, " ") == "" {
		userAgent = unknownUserAgent
	}
	return authentication.EventContext{
		RequestID: requestID, CorrelationID: correlationID,
		RemoteAddress: remoteAddress, UserAgent: userAgent,
	}, nil
}

func (h *Handler) authenticateRequest(r *http.Request, token string) (authentication.Session, error) {
	if h == nil || h.authentication == nil || r == nil {
		return authentication.Session{}, authentication.ErrInvalidAuthentication
	}
	event, err := h.eventContext(r)
	if err != nil {
		return authentication.Session{}, authentication.ErrInvalidAuthentication
	}
	ctx, err := authentication.WithEventContext(r.Context(), event)
	if err != nil {
		return authentication.Session{}, authentication.ErrInvalidAuthentication
	}
	return h.authentication.Authenticate(ctx, token)
}

func resolveClientAddress(r *http.Request, trustedProxies []netip.Prefix) (netip.Addr, error) {
	peer, err := parseRemoteAddress(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, errors.New("invalid remote address")
	}
	if !prefixContains(trustedProxies, peer) {
		return peer, nil
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > maximumForwardedForSize {
		return netip.Addr{}, errors.New("trusted proxy did not provide one client address")
	}
	parts := strings.Split(values[0], ",")
	if len(parts) == 0 || len(parts) > maximumForwardedHops {
		return netip.Addr{}, errors.New("trusted proxy provided an invalid forwarding chain")
	}
	chain := make([]netip.Addr, 0, len(parts)+1)
	for _, part := range parts {
		address, parseErr := netip.ParseAddr(strings.TrimSpace(part))
		if parseErr != nil || address.Zone() != "" {
			return netip.Addr{}, errors.New("trusted proxy provided an invalid forwarding chain")
		}
		chain = append(chain, address.Unmap())
	}
	chain = append(chain, peer)
	for index := len(chain) - 1; index >= 0; index-- {
		if !prefixContains(trustedProxies, chain[index]) {
			return chain[index], nil
		}
	}
	return chain[0], nil
}

func parseRemoteAddress(value string) (netip.Addr, error) {
	if addressPort, err := netip.ParseAddrPort(value); err == nil {
		return addressPort.Addr().Unmap(), nil
	}
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		address, parseErr := netip.ParseAddr(host)
		if parseErr == nil {
			return address.Unmap(), nil
		}
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, err
	}
	return address.Unmap(), nil
}

func prefixContains(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
