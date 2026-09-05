package ldapclient

import (
	"context"
	"crypto/x509"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"
)

// Client owns one deployment-level egress policy and global concurrency
// budget. Every test still creates a dedicated network connection.
type Client struct {
	resolver             Resolver
	dialer               Dialer
	privateEgressCIDRs   []netip.Prefix
	allowedStartTLSPorts map[uint16]struct{}
	allowedLDAPSPorts    map[uint16]struct{}
	systemRoots          *x509.CertPool
	slots                chan struct{}
}

// New constructs a client from deployment-owned policy. Resolver and Dialer
// are required explicitly so DNS and dialing cannot bypass validation.
func New(options Options) (*Client, error) {
	if options.Resolver == nil || options.Dialer == nil || options.MaxConcurrent < 1 ||
		options.MaxConcurrent > maximumConcurrent {
		return nil, ErrInvalidOptions
	}
	privateCIDRs, err := normalizePrivateEgressCIDRs(options.PrivateEgressCIDRs)
	if err != nil {
		return nil, ErrInvalidOptions
	}
	startTLSPorts, err := normalizeAllowedPorts(options.AllowedStartTLSPorts, 389)
	if err != nil {
		return nil, ErrInvalidOptions
	}
	ldapsPorts, err := normalizeAllowedPorts(options.AllowedLDAPSPorts, 636)
	if err != nil {
		return nil, ErrInvalidOptions
	}
	systemRoots, err := loadSystemRoots()
	if err != nil {
		return nil, ErrInvalidOptions
	}
	return &Client{
		resolver:             options.Resolver,
		dialer:               options.Dialer,
		privateEgressCIDRs:   privateCIDRs,
		allowedStartTLSPorts: startTLSPorts,
		allowedLDAPSPorts:    ldapsPorts,
		systemRoots:          systemRoots,
		slots:                make(chan struct{}, options.MaxConcurrent),
	}, nil
}

// ValidateConfiguration applies the client's deployment-owned port and trust
// policy without resolving DNS or opening a connection. Callers use this at
// provider write boundaries so persisted configuration is accepted by the
// exact same validator used immediately before network access.
func (c *Client) ValidateConfiguration(configuration Configuration) error {
	_, err := c.validateConfiguration(configuration)
	return err
}

// TestConnection proves DNS, egress, TCP, and mandatory TLS using ordered
// endpoint failover. Apart from the required StartTLS upgrade, it sends no
// LDAP operation: connection tests never bind or search.
func (c *Client) TestConnection(ctx context.Context, configuration Configuration) (Diagnostic, error) {
	return c.test(ctx, configuration, "", nil, false)
}

// TestBind performs the same encrypted connection proof followed by one simple
// bind. bindSecret ownership transfers to this call and its backing bytes are
// always cleared before return, including local validation or capacity errors.
func (c *Client) TestBind(
	ctx context.Context,
	configuration Configuration,
	bindDN string,
	bindSecret []byte,
) (Diagnostic, error) {
	defer clear(bindSecret)
	if !utf8.ValidString(bindDN) || strings.TrimSpace(bindDN) == "" ||
		utf8.RuneCountInString(bindDN) > maximumBindDNCharacters || len(bindDN) > maximumBindDNBytes ||
		len(bindSecret) < 1 ||
		len(bindSecret) > maximumBindSecretBytes {
		return Diagnostic{}, ErrInvalidConfiguration
	}
	if _, err := ldap.ParseDN(bindDN); err != nil {
		return Diagnostic{}, ErrInvalidConfiguration
	}
	return c.test(ctx, configuration, bindDN, bindSecret, true)
}

func (c *Client) test(
	ctx context.Context,
	configuration Configuration,
	bindDN string,
	bindSecret []byte,
	bind bool,
) (Diagnostic, error) {
	if ctx == nil || c == nil {
		return Diagnostic{}, ErrInvalidConfiguration
	}
	if contextEnded(ctx) {
		return newDiagnostic(contextCategory(ctx, ctx), 0, 0), nil
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return Diagnostic{}, ErrBusy
	}
	validated, err := c.validateConfiguration(configuration)
	if err != nil {
		return Diagnostic{}, ErrInvalidConfiguration
	}
	if contextEnded(ctx) {
		return newDiagnostic(contextCategory(ctx, ctx), validated.endpoints[0].Priority, 0), nil
	}

	startedAt := time.Now()
	operationCtx, cancel := context.WithTimeout(ctx, validated.operationTimeout)
	defer cancel()
	var firstFailure *Diagnostic
	for _, endpoint := range validated.endpoints {
		category := c.attemptEndpoint(operationCtx, validated, endpoint, bindDN, bindSecret, bind)
		diagnostic := newDiagnostic(category, endpoint.Priority, time.Since(startedAt))
		if category == CategorySuccess || category == CategoryCancelled || contextEnded(operationCtx) ||
			bind && category == CategoryBindRejected {
			return diagnostic, nil
		}
		if firstFailure == nil {
			firstFailure = &diagnostic
		}
	}
	if firstFailure != nil {
		firstFailure.Duration = time.Since(startedAt)
		return *firstFailure, nil
	}
	return newDiagnostic(CategoryProtocolFailed, 0, time.Since(startedAt)), nil
}

func contextEnded(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	deadline, ok := ctx.Deadline()
	return ok && !time.Now().Before(deadline)
}

func contextCategory(parent, phase context.Context) Category {
	if errors.Is(parent.Err(), context.Canceled) {
		return CategoryCancelled
	}
	if errors.Is(parent.Err(), context.DeadlineExceeded) || errors.Is(phase.Err(), context.DeadlineExceeded) {
		return CategoryConnectTimeout
	}
	if contextEnded(parent) || contextEnded(phase) {
		return CategoryConnectTimeout
	}
	if errors.Is(phase.Err(), context.Canceled) {
		return CategoryCancelled
	}
	return CategoryConnectFailed
}
