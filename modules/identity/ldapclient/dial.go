package ldapclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

const maximumDiagnosticReadBytes = 256 * 1024

var errDiagnosticReadLimit = errors.New("LDAP diagnostic inbound byte limit exceeded")

type boundedReadConn struct {
	net.Conn
	remaining int64
	budget    *inboundReadBudget
}

func (connection *boundedReadConn) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return connection.Conn.Read(buffer)
	}
	if connection.budget != nil {
		return connection.budget.read(connection.Conn, buffer)
	}
	if connection.remaining <= 0 {
		return 0, errDiagnosticReadLimit
	}
	if int64(len(buffer)) > connection.remaining {
		buffer = buffer[:connection.remaining]
	}
	read, err := connection.Conn.Read(buffer)
	connection.remaining -= int64(read)
	return read, err
}

type inboundReadBudget struct {
	mu        sync.Mutex
	remaining int64
	exhausted bool
}

func newInboundReadBudget(limit int64) *inboundReadBudget {
	return &inboundReadBudget{remaining: limit}
}

func (budget *inboundReadBudget) read(connection net.Conn, buffer []byte) (int, error) {
	budget.mu.Lock()
	if budget.remaining <= 0 {
		budget.exhausted = true
		budget.mu.Unlock()
		return 0, errDiagnosticReadLimit
	}
	allowed := int64(len(buffer))
	if allowed > budget.remaining {
		allowed = budget.remaining
		buffer = buffer[:allowed]
	}
	budget.remaining -= allowed
	budget.mu.Unlock()

	read, err := connection.Read(buffer)
	budget.mu.Lock()
	budget.remaining += allowed - int64(read)
	budget.mu.Unlock()
	return read, err
}

func (budget *inboundReadBudget) isExhausted() bool {
	if budget == nil {
		return true
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budget.exhausted
}

type secureConnection struct {
	ldap *ldap.Conn
	raw  net.Conn
}

func (connection *secureConnection) close() {
	if connection == nil {
		return
	}
	if connection.ldap != nil {
		_ = connection.ldap.Close()
	} else if connection.raw != nil {
		_ = connection.raw.Close()
	}
}

func (c *Client) attemptEndpoint(
	ctx context.Context,
	configuration validatedConfiguration,
	endpoint Endpoint,
	bindDN string,
	bindSecret []byte,
	bind bool,
) Category {
	connection, category := c.connect(ctx, configuration, endpoint)
	if connection == nil {
		return category
	}
	defer connection.close()
	if !bind {
		if contextEnded(ctx) {
			return contextCategory(ctx, ctx)
		}
		return CategorySuccess
	}

	stopClose := context.AfterFunc(ctx, func() { _ = connection.raw.Close() })
	defer stopClose()
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return contextCategory(ctx, ctx)
		}
		connection.ldap.SetTimeout(remaining)
	}
	// go-ldap's API requires a string. Keep the unavoidable copy scoped to
	// this call and never attach it or the upstream error to a diagnostic.
	err := connection.ldap.Bind(bindDN, string(bindSecret))
	if err == nil {
		if contextEnded(ctx) {
			return contextCategory(ctx, ctx)
		}
		return CategorySuccess
	}
	if contextEnded(ctx) {
		return contextCategory(ctx, ctx)
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		return CategoryBindRejected
	}
	if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
		return CategoryConnectFailed
	}
	return CategoryProtocolFailed
}

func (c *Client) connect(
	ctx context.Context,
	configuration validatedConfiguration,
	endpoint Endpoint,
) (*secureConnection, Category) {
	return c.connectWithReadBudget(
		ctx,
		configuration,
		endpoint,
		newInboundReadBudget(maximumDiagnosticReadBytes),
	)
}

func (c *Client) connectWithReadBudget(
	ctx context.Context,
	configuration validatedConfiguration,
	endpoint Endpoint,
	budget *inboundReadBudget,
) (*secureConnection, Category) {
	if budget == nil {
		return nil, CategoryProtocolFailed
	}
	connectCtx, cancel := context.WithTimeout(ctx, configuration.connectTimeout)
	defer cancel()
	addresses, category := c.resolve(connectCtx, endpoint.Host)
	if category != CategorySuccess {
		return nil, category
	}

	var firstSecureFailure Category
	for _, address := range addresses {
		if contextEnded(connectCtx) {
			return nil, contextCategory(ctx, connectCtx)
		}
		target := net.JoinHostPort(address.String(), strconv.Itoa(int(endpoint.Port)))
		raw, err := c.dialer.DialContext(connectCtx, "tcp", target)
		if err != nil {
			if raw != nil {
				_ = raw.Close()
			}
			if contextEnded(connectCtx) {
				return nil, contextCategory(ctx, connectCtx)
			}
			continue
		}
		if raw == nil {
			continue
		}
		raw = &boundedReadConn{Conn: raw, budget: budget}
		connection, secureCategory := secureLDAPConnection(
			connectCtx,
			raw,
			endpoint,
			configuration.rootCAs,
			configuration.connectTimeout,
		)
		if connection != nil {
			return connection, CategorySuccess
		}
		if firstSecureFailure == "" {
			firstSecureFailure = secureCategory
		}
	}
	if contextEnded(connectCtx) {
		return nil, contextCategory(ctx, connectCtx)
	}
	if firstSecureFailure != "" {
		return nil, firstSecureFailure
	}
	return nil, CategoryConnectFailed
}

func (c *Client) resolve(ctx context.Context, host string) ([]netip.Addr, Category) {
	if literal, err := netip.ParseAddr(host); err == nil {
		literal = literal.Unmap()
		if !c.addressAllowed(literal) {
			return nil, CategoryDestinationBlocked
		}
		return []netip.Addr{literal}, CategorySuccess
	}
	addresses, err := c.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		if contextEnded(ctx) {
			return nil, contextCategory(ctx, ctx)
		}
		return nil, CategoryDNSFailed
	}
	if len(addresses) < 1 {
		return nil, CategoryDNSFailed
	}
	if len(addresses) > maximumResolvedAddresses {
		return nil, CategoryDestinationBlocked
	}

	validated := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !c.addressAllowed(address) {
			return nil, CategoryDestinationBlocked
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		validated = append(validated, address)
	}
	if len(validated) < 1 {
		return nil, CategoryDNSFailed
	}
	return validated, CategorySuccess
}

func secureLDAPConnection(
	ctx context.Context,
	raw net.Conn,
	endpoint Endpoint,
	roots *x509.CertPool,
	requestTimeout time.Duration,
) (*secureConnection, Category) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: endpoint.TLSServerName,
		RootCAs:    roots,
	}
	if endpoint.Transport == TransportLDAPS {
		tlsConnection := tls.Client(raw, tlsConfig)
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			if contextEnded(ctx) {
				return nil, contextCategory(ctx, ctx)
			}
			if isCertificateError(err) {
				return nil, CategoryCertificateRejected
			}
			return nil, CategoryTLSFailed
		}
		state := tlsConnection.ConnectionState()
		if !state.HandshakeComplete || state.Version < tls.VersionTLS12 || len(state.VerifiedChains) == 0 {
			_ = raw.Close()
			return nil, CategoryTLSFailed
		}
		ldapConnection := ldap.NewConn(tlsConnection, true)
		ldapConnection.SetTimeout(requestTimeout)
		ldapConnection.Start()
		return &secureConnection{ldap: ldapConnection, raw: raw}, CategorySuccess
	}

	ldapConnection := ldap.NewConn(raw, false)
	ldapConnection.SetTimeout(requestTimeout)
	ldapConnection.Start()
	connection := &secureConnection{ldap: ldapConnection, raw: raw}
	stopClose := context.AfterFunc(ctx, func() { _ = raw.Close() })
	err := ldapConnection.StartTLS(tlsConfig)
	stopClose()
	if err != nil {
		connection.close()
		if contextEnded(ctx) {
			return nil, contextCategory(ctx, ctx)
		}
		if isCertificateError(err) {
			return nil, CategoryCertificateRejected
		}
		// go-ldap v3.4.14 flattens the typed tls/x509 cause with %v in
		// StartTLS. Do not parse its error text or weaken standard certificate
		// verification to recover a finer category; these failures remain the
		// safe, intentionally coarse tls_failed category.
		if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
			return nil, CategoryTLSFailed
		}
		return nil, CategoryProtocolFailed
	}
	state, ok := ldapConnection.TLSConnectionState()
	if !ok || !state.HandshakeComplete || state.Version < tls.VersionTLS12 || len(state.VerifiedChains) == 0 {
		connection.close()
		return nil, CategoryTLSFailed
	}
	return connection, CategorySuccess
}

func isCertificateError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalidCertificate x509.CertificateInvalidError
	var verificationError *tls.CertificateVerificationError
	return errors.As(err, &unknownAuthority) || errors.As(err, &hostname) ||
		errors.As(err, &invalidCertificate) || errors.As(err, &verificationError)
}
