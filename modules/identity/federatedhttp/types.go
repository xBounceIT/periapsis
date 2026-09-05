// Package federatedhttp provides the single bounded outbound HTTP boundary
// used to retrieve OIDC discovery/JWKS documents and SAML metadata. It does
// not parse or verify either protocol.
package federatedhttp

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"
)

const (
	maximumAllowedHTTPSPorts  = 16
	maximumPrivateCIDRs       = 64
	maximumResolvedAddresses  = 16
	maximumConcurrent         = 256
	maximumTargetBytes        = 4 * 1024
	maximumPathBytes          = 2 * 1024
	maximumAuthorizationBytes = 8 * 1024
	maximumRedirects          = 3

	minimumPhaseTimeout = 50 * time.Millisecond
	maximumPhaseTimeout = 30 * time.Second
	minimumTotalTimeout = 100 * time.Millisecond
	maximumTotalTimeout = 2 * time.Minute

	minimumHeaderBytes   = 1024
	maximumHeaderBytes   = 256 * 1024
	minimumDocumentBytes = 1024
	maximumWireBytes     = 8 * 1024 * 1024
	maximumDocumentBytes = 16 * 1024 * 1024
	maximumCacheAge      = 7 * 24 * time.Hour
)

var (
	// ErrInvalidOptions contains no deployment policy, trust, or network data.
	ErrInvalidOptions = errors.New("invalid federated HTTP options")
	// ErrInvalidTarget deliberately omits the rejected URL and parser details.
	ErrInvalidTarget = errors.New("invalid federated HTTP target")
	// ErrInvalidAuthorization deliberately omits credential bytes.
	ErrInvalidAuthorization = errors.New("invalid federated HTTP authorization")
	// ErrBusy is returned without queueing when the deployment concurrency
	// budget is exhausted.
	ErrBusy = errors.New("federated HTTP client is busy")
)

// Resolver is the only DNS boundary used by Client. Implementations must
// honor ctx and return literal addresses without opening a connection.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer receives only an already validated literal IP and port.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DeploymentEgressPolicy is constructed only from deployment-owned private
// CIDRs and HTTPS ports. Its private representation prevents a per-request or
// tenant-provided value from widening the policy after Client construction.
type DeploymentEgressPolicy struct {
	privateCIDRs []netip.Prefix
	ports        map[uint16]struct{}
	valid        bool
}

// NewDeploymentEgressPolicy validates exact private-network subprefixes and
// canonical HTTPS ports. An empty port list selects only 443.
func NewDeploymentEgressPolicy(
	privateCIDRs []netip.Prefix,
	allowedHTTPSPorts []uint16,
) (DeploymentEgressPolicy, error) {
	normalizedCIDRs, err := normalizePrivateCIDRs(privateCIDRs)
	if err != nil {
		return DeploymentEgressPolicy{}, ErrInvalidOptions
	}
	ports, err := normalizeHTTPSPorts(allowedHTTPSPorts)
	if err != nil {
		return DeploymentEgressPolicy{}, ErrInvalidOptions
	}
	return DeploymentEgressPolicy{privateCIDRs: normalizedCIDRs, ports: ports, valid: true}, nil
}

// Limits are deployment-owned hard ceilings applied again at every fetch.
type Limits struct {
	ConnectTimeout         time.Duration
	TLSHandshakeTimeout    time.Duration
	ResponseHeaderTimeout  time.Duration
	OperationTimeout       time.Duration
	MaxResponseHeaderBytes int64
	MaxWireBytes           int64
	MaxDocumentBytes       int64
	MaxRedirects           int
	DefaultCacheAge        time.Duration
	MaxCacheAge            time.Duration
}

// DefaultLimits returns conservative bounded defaults suitable for discovery,
// JWKS, and metadata documents.
func DefaultLimits() Limits {
	return Limits{
		ConnectTimeout:         5 * time.Second,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		OperationTimeout:       20 * time.Second,
		MaxResponseHeaderBytes: 64 * 1024,
		MaxWireBytes:           2 * 1024 * 1024,
		MaxDocumentBytes:       4 * 1024 * 1024,
		MaxRedirects:           maximumRedirects,
		DefaultCacheAge:        5 * time.Minute,
		MaxCacheAge:            24 * time.Hour,
	}
}

// Options contains deployment-owned network, trust, concurrency, and resource
// policy. Environment-derived HTTP proxies are never consulted.
type Options struct {
	Resolver      Resolver
	Dialer        Dialer
	EgressPolicy  DeploymentEgressPolicy
	RootCAs       *x509.CertPool
	Limits        Limits
	MaxConcurrent int
}

// DocumentKind is the closed set of public, cacheable protocol documents this
// adapter can retrieve.
type DocumentKind string

const (
	DocumentOIDCDiscovery DocumentKind = "oidc_discovery"
	DocumentOIDCJWKS      DocumentKind = "oidc_jwks"
	DocumentSAMLMetadata  DocumentKind = "saml_metadata"
)

// Target is a privately represented canonical HTTPS destination. Construct it
// with Client.CompileTarget; its zero value is invalid.
type Target struct {
	kind         DocumentKind
	canonicalURL string
	host         string
	port         uint16
	valid        bool
}

// Category is a stable sanitized fetch outcome. It never contains a URL,
// response body, certificate detail, resolver error, or credential value.
type Category string

const (
	CategorySuccess               Category = "success"
	CategoryDNSFailed             Category = "dns_failed"
	CategoryDestinationBlocked    Category = "destination_blocked"
	CategoryConnectTimeout        Category = "connect_timeout"
	CategoryConnectFailed         Category = "connect_failed"
	CategoryTLSTimeout            Category = "tls_timeout"
	CategoryTLSFailed             Category = "tls_failed"
	CategoryCertificateRejected   Category = "certificate_rejected"
	CategoryResponseHeaderTimeout Category = "response_header_timeout"
	CategoryOperationTimeout      Category = "operation_timeout"
	CategoryRedirectRejected      Category = "redirect_rejected"
	CategoryHTTPStatusRejected    Category = "http_status_rejected"
	CategoryMediaTypeRejected     Category = "media_type_rejected"
	CategoryEncodingRejected      Category = "encoding_rejected"
	CategoryLimitExceeded         Category = "limit_exceeded"
	CategoryResponseFailed        Category = "response_failed"
	CategoryCancelled             Category = "cancelled"
)

// CacheMetadata is a sanitized cache decision. Raw Cache-Control, ETag,
// Expires, Date, and Last-Modified values never cross this boundary.
type CacheMetadata struct {
	RetrievedAt    time.Time
	FreshUntil     time.Time
	Cacheable      bool
	MustRevalidate bool
}

// Result owns a bounded document on success. Body, Digest, and Cache are zero
// for every non-success category.
type Result struct {
	Category  Category
	Kind      DocumentKind
	Redirects int
	Body      []byte
	Digest    [sha256.Size]byte
	Cache     CacheMetadata
}

// Client owns one immutable deployment policy and an HTTP transport with
// proxies and connection reuse disabled.
type Client struct {
	resolver  Resolver
	dialer    Dialer
	policy    DeploymentEgressPolicy
	roots     *x509.CertPool
	limits    Limits
	slots     chan struct{}
	transport *http.Transport
}
