package federatedhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// New freezes one deployment-owned resolver, literal-IP dialer, egress policy,
// trust pool, concurrency budget, and set of resource limits.
func New(options Options) (*Client, error) {
	if options.Resolver == nil || options.Dialer == nil || !options.EgressPolicy.valid ||
		options.MaxConcurrent < 1 || options.MaxConcurrent > maximumConcurrent ||
		validateLimits(options.Limits) != nil {
		return nil, ErrInvalidOptions
	}
	policy, err := cloneDeploymentPolicy(options.EgressPolicy)
	if err != nil {
		return nil, ErrInvalidOptions
	}
	var roots *x509.CertPool
	if options.RootCAs == nil {
		roots, err = x509.SystemCertPool()
		if err != nil || roots == nil {
			return nil, ErrInvalidOptions
		}
	} else {
		roots = options.RootCAs.Clone()
	}
	client := &Client{
		resolver: options.Resolver,
		dialer:   options.Dialer,
		policy:   policy,
		roots:    roots,
		limits:   options.Limits,
		slots:    make(chan struct{}, options.MaxConcurrent),
	}
	client.transport = &http.Transport{
		Proxy:                  nil,
		DialContext:            client.rejectPlaintextDial,
		DialTLSContext:         client.dialTLSContext,
		ForceAttemptHTTP2:      false,
		DisableKeepAlives:      true,
		MaxIdleConns:           0,
		MaxIdleConnsPerHost:    0,
		MaxConnsPerHost:        options.MaxConcurrent,
		IdleConnTimeout:        time.Second,
		TLSHandshakeTimeout:    options.Limits.TLSHandshakeTimeout,
		ResponseHeaderTimeout:  options.Limits.ResponseHeaderTimeout,
		ExpectContinueTimeout:  minimumPhaseTimeout,
		MaxResponseHeaderBytes: options.Limits.MaxResponseHeaderBytes,
		DisableCompression:     true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
			NextProtos: []string{"http/1.1"},
		},
	}
	return client, nil
}

// Fetch performs one GET for a compiled public document target. authorization
// is optional and ownership transfers to this call; its backing array is
// cleared on every return. A credential-bearing request never follows a
// redirect.
func (client *Client) Fetch(
	ctx context.Context,
	target Target,
	authorization []byte,
) (Result, error) {
	defer clear(authorization)
	if client == nil || ctx == nil {
		return Result{}, ErrInvalidTarget
	}
	if !validAuthorization(authorization) {
		return Result{}, ErrInvalidAuthorization
	}
	validated, targetURL, err := client.validatedTarget(target)
	if err != nil {
		return Result{}, ErrInvalidTarget
	}
	if contextEnded(ctx) {
		return Result{Category: categoryFromContexts(ctx, ctx, CategoryOperationTimeout), Kind: validated.kind}, nil
	}
	select {
	case client.slots <- struct{}{}:
		defer func() { <-client.slots }()
	default:
		return Result{}, ErrBusy
	}

	operationCtx, cancel := context.WithTimeout(ctx, client.limits.OperationTimeout)
	defer cancel()
	current := validated
	currentURL := targetURL
	redirects := 0
	visited := map[string]struct{}{current.canonicalURL: {}}
	credentialBearing := len(authorization) != 0
	for {
		response, category := client.roundTrip(operationCtx, current, currentURL, authorization)
		if response == nil {
			return sanitizeResult(Result{
				Category: category, Kind: validated.kind, Redirects: redirects,
			}), nil
		}
		if isRedirectStatus(response.StatusCode) {
			_ = response.Body.Close()
			if credentialBearing || redirects >= client.limits.MaxRedirects {
				return Result{
					Category: CategoryRedirectRejected, Kind: validated.kind, Redirects: redirects,
				}, nil
			}
			locations := response.Header.Values("Location")
			if len(locations) != 1 {
				return Result{
					Category: CategoryRedirectRejected, Kind: validated.kind, Redirects: redirects,
				}, nil
			}
			next, redirectErr := client.redirectTarget(current, locations[0])
			if redirectErr != nil {
				return Result{
					Category: CategoryRedirectRejected, Kind: validated.kind, Redirects: redirects,
				}, nil
			}
			if _, loop := visited[next.canonicalURL]; loop {
				return Result{
					Category: CategoryRedirectRejected, Kind: validated.kind, Redirects: redirects,
				}, nil
			}
			nextURL, parseErr := urlForTarget(next)
			if parseErr != nil {
				return Result{
					Category: CategoryRedirectRejected, Kind: validated.kind, Redirects: redirects,
				}, nil
			}
			redirects++
			visited[next.canonicalURL] = struct{}{}
			current, currentURL = next, nextURL
			continue
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return Result{
				Category: CategoryHTTPStatusRejected, Kind: validated.kind, Redirects: redirects,
			}, nil
		}
		result := client.readDocument(operationCtx, validated.kind, response, redirects, credentialBearing)
		return sanitizeResult(result), nil
	}
}

func validateLimits(limits Limits) error {
	phaseTimeouts := []time.Duration{
		limits.ConnectTimeout,
		limits.TLSHandshakeTimeout,
		limits.ResponseHeaderTimeout,
	}
	for _, timeout := range phaseTimeouts {
		if timeout < minimumPhaseTimeout || timeout > maximumPhaseTimeout ||
			timeout > limits.OperationTimeout {
			return ErrInvalidOptions
		}
	}
	if limits.OperationTimeout < minimumTotalTimeout || limits.OperationTimeout > maximumTotalTimeout ||
		limits.MaxResponseHeaderBytes < minimumHeaderBytes ||
		limits.MaxResponseHeaderBytes > maximumHeaderBytes ||
		limits.MaxWireBytes < minimumDocumentBytes || limits.MaxWireBytes > maximumWireBytes ||
		limits.MaxDocumentBytes < minimumDocumentBytes ||
		limits.MaxDocumentBytes > maximumDocumentBytes ||
		limits.MaxRedirects < 0 || limits.MaxRedirects > maximumRedirects ||
		limits.DefaultCacheAge < 0 || limits.DefaultCacheAge > limits.MaxCacheAge ||
		limits.MaxCacheAge < 0 || limits.MaxCacheAge > maximumCacheAge {
		return ErrInvalidOptions
	}
	return nil
}

func cloneDeploymentPolicy(source DeploymentEgressPolicy) (DeploymentEgressPolicy, error) {
	ports := make([]uint16, 0, len(source.ports))
	for port := range source.ports {
		ports = append(ports, port)
	}
	privateCIDRs, err := normalizePrivateCIDRs(source.privateCIDRs)
	if err != nil {
		return DeploymentEgressPolicy{}, err
	}
	normalizedPorts, err := normalizeHTTPSPorts(ports)
	if err != nil || len(normalizedPorts) != len(source.ports) {
		return DeploymentEgressPolicy{}, ErrInvalidOptions
	}
	return DeploymentEgressPolicy{privateCIDRs: privateCIDRs, ports: normalizedPorts, valid: true}, nil
}

func validAuthorization(value []byte) bool {
	if len(value) == 0 {
		return true
	}
	if len(value) > maximumAuthorizationBytes || value[0] == ' ' || value[len(value)-1] == ' ' {
		return false
	}
	space := bytes.IndexByte(value, ' ')
	if space < 1 || space == len(value)-1 {
		return false
	}
	for index, character := range value {
		if character < 0x20 || character > 0x7e {
			return false
		}
		if index < space && !authorizationTokenByte(character) {
			return false
		}
	}
	return true
}

func authorizationTokenByte(character byte) bool {
	if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' {
		return true
	}
	switch character {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

func (client *Client) roundTrip(
	ctx context.Context,
	target Target,
	targetURL *url.URL,
	authorization []byte,
) (*http.Response, Category) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL.String(), nil)
	if err != nil {
		return nil, CategoryResponseFailed
	}
	request.Header.Set("Accept", acceptForKind(target.kind))
	request.Header.Set("Accept-Encoding", "gzip")
	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("User-Agent", "Periapsis-Federated-Metadata/1")
	if len(authorization) != 0 {
		request.Header.Set("Authorization", string(authorization))
	}
	response, requestErr := client.transport.RoundTrip(request)
	request.Header.Del("Authorization")
	if requestErr != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, categoryFromRoundTripError(ctx, requestErr)
	}
	if response == nil || response.Body == nil {
		return nil, CategoryResponseFailed
	}
	return response, CategorySuccess
}

func (client *Client) rejectPlaintextDial(context.Context, string, string) (net.Conn, error) {
	return nil, categorizedError{category: CategoryDestinationBlocked}
}

func (client *Client) dialTLSContext(ctx context.Context, network, address string) (net.Conn, error) {
	dispatchEvidence := dispatchEvidenceFromContext(ctx)
	if network != "tcp" {
		return nil, categorizedError{category: CategoryDestinationBlocked}
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil || !validCanonicalHost(host) {
		return nil, categorizedError{category: CategoryDestinationBlocked}
	}
	parsedPort, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || parsedPort == 0 || strconv.FormatUint(parsedPort, 10) != portText {
		return nil, categorizedError{category: CategoryDestinationBlocked}
	}
	port := uint16(parsedPort)
	if _, allowed := client.policy.ports[port]; !allowed {
		return nil, categorizedError{category: CategoryDestinationBlocked}
	}

	connectCtx, cancelConnect := context.WithTimeout(ctx, client.limits.ConnectTimeout)
	addresses, category := client.resolve(connectCtx, host)
	if category != CategorySuccess {
		if contextEnded(connectCtx) {
			category = categoryFromContexts(ctx, connectCtx, CategoryConnectTimeout)
		}
		cancelConnect()
		return nil, categorizedError{category: category}
	}

	if contextEnded(ctx) {
		cancelConnect()
		return nil, categorizedError{
			category: categoryFromContexts(ctx, ctx, CategoryOperationTimeout),
		}
	}
	raw, dialErr := client.dialer.DialContext(
		connectCtx,
		"tcp",
		net.JoinHostPort(addresses[0].String(), portText),
	)
	if dialErr != nil || raw == nil {
		if raw != nil {
			_ = raw.Close()
		}
		if contextEnded(connectCtx) {
			category := categoryFromContexts(ctx, connectCtx, CategoryConnectTimeout)
			cancelConnect()
			return nil, categorizedError{category: category}
		}
		cancelConnect()
		return nil, categorizedError{category: CategoryConnectFailed}
	}
	cancelConnect()

	tlsCtx, cancelTLS := context.WithTimeout(ctx, client.limits.TLSHandshakeTimeout)
	tlsConnection := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: host,
		RootCAs:    client.roots,
		NextProtos: []string{"http/1.1"},
	})
	stopClose := context.AfterFunc(tlsCtx, func() { _ = raw.Close() })
	handshakeErr := tlsConnection.HandshakeContext(tlsCtx)
	stopClose()
	tlsContextEnded := contextEnded(tlsCtx)
	cancelTLS()
	if handshakeErr == nil && !tlsContextEnded {
		state := tlsConnection.ConnectionState()
		if state.HandshakeComplete && state.Version >= tls.VersionTLS12 && len(state.VerifiedChains) != 0 {
			if dispatchEvidence != nil {
				dispatchEvidence.connectionReturned.Store(true)
			}
			return tlsConnection, nil
		}
		handshakeErr = errors.New("invalid TLS state")
	}
	_ = raw.Close()
	switch {
	case contextEnded(ctx):
		return nil, categorizedError{
			category: categoryFromContexts(ctx, ctx, CategoryTLSTimeout),
		}
	case tlsContextEnded:
		return nil, categorizedError{category: CategoryTLSTimeout}
	case isCertificateError(handshakeErr):
		return nil, categorizedError{category: CategoryCertificateRejected}
	default:
		return nil, categorizedError{category: CategoryTLSFailed}
	}
}

type categorizedError struct {
	category Category
}

func (err categorizedError) Error() string { return "federated HTTP request failed" }

func categoryFromRoundTripError(ctx context.Context, err error) Category {
	if contextEnded(ctx) {
		return categoryFromContexts(ctx, ctx, CategoryOperationTimeout)
	}
	var categorized categorizedError
	if errors.As(err, &categorized) && safeCategory(categorized.category) != "unknown" {
		return categorized.category
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return CategoryResponseHeaderTimeout
	}
	return CategoryResponseFailed
}

// operationRoundTripFailure preserves the stronger phase evidence carried by
// errors from the private dial/TLS boundary. Once that boundary has returned a
// connection, any later transport error is intentionally treated as possibly
// post-dispatch, even when the caller context is also cancelled.
func operationRoundTripFailure(ctx context.Context, err error) (Category, bool) {
	// This transport disables keep-alives, proxies, alternate protocols, and
	// HTTP/2, so every operation must obtain its connection through
	// dialTLSContext. A RoundTrip failure before that boundary returns a
	// connection therefore proves that request bytes were never dispatched,
	// including cancellation while net/http is still scheduling the dial.
	if evidence := dispatchEvidenceFromContext(ctx); evidence != nil &&
		!evidence.connectionReturned.Load() {
		return categoryFromRoundTripError(ctx, err), true
	}
	var categorized categorizedError
	if errors.As(err, &categorized) && safeCategory(categorized.category) != "unknown" {
		return categorized.category, true
	}
	return categoryFromRoundTripError(ctx, err), false
}

func categoryFromContexts(parent, phase context.Context, phaseTimeout Category) Category {
	if (parent != nil && errors.Is(parent.Err(), context.Canceled)) ||
		(phase != nil && errors.Is(phase.Err(), context.Canceled)) {
		return CategoryCancelled
	}
	if parent != nil && errors.Is(parent.Err(), context.DeadlineExceeded) {
		return CategoryOperationTimeout
	}
	return phaseTimeout
}

func contextEnded(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return true
	}
	deadline, ok := ctx.Deadline()
	return ok && !time.Now().Before(deadline)
}

func isCertificateError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var roots x509.SystemRootsError
	return errors.As(err, &unknownAuthority) || errors.As(err, &hostname) ||
		errors.As(err, &invalid) || errors.As(err, &roots)
}

func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func acceptForKind(kind DocumentKind) string {
	switch kind {
	case DocumentOIDCDiscovery:
		return "application/json"
	case DocumentOIDCJWKS:
		return "application/jwk-set+json, application/json;q=0.9"
	case DocumentSAMLMetadata:
		return "application/samlmetadata+xml, application/xml;q=0.9, text/xml;q=0.8"
	default:
		return "application/octet-stream"
	}
}

func urlForTarget(target Target) (*url.URL, error) {
	parsed, err := url.Parse(target.canonicalURL)
	if err != nil {
		return nil, ErrInvalidTarget
	}
	return parsed, nil
}

func sanitizeResult(result Result) Result {
	if result.Category != CategorySuccess {
		result.Body = nil
		result.Digest = [sha256.Size]byte{}
		result.Cache = CacheMetadata{}
	}
	return result
}
