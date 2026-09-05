package oidcmaintenance

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

const (
	maximumFederatedCABundleBytes = 1024 * 1024
	defaultOIDCResponseBytes      = 64 * 1024
)

type UpstreamOptions struct {
	Resolver           federatedhttp.Resolver
	Dialer             federatedhttp.Dialer
	PrivateEgressCIDRs []netip.Prefix
	AllowedHTTPSPorts  []uint16
	CABundleFile       string
	OperationTimeout   time.Duration
	MaxConcurrent      int
}

// PinnedUpstream narrows the shared OIDC client to the maintenance worker's
// two operations. Its refresh result can contain only the successor refresh
// token and expiry; access and ID tokens are destroyed inside the adapter.
type PinnedUpstream struct {
	upstream *federatedoidc.UpstreamHTTP
}

var _ Upstream = (*PinnedUpstream)(nil)

// NewUpstream constructs the worker's sole outbound HTTP boundary. It ignores
// ambient proxy settings, recompiles every stored endpoint through the pinned
// deployment policy, disables redirects, and owns a bounded concurrency pool.
func NewUpstream(options UpstreamOptions) (*PinnedUpstream, error) {
	if options.Resolver == nil || options.Dialer == nil ||
		options.OperationTimeout < MinimumOperation || options.OperationTimeout > MaximumOperation ||
		options.OperationTimeout%time.Microsecond != 0 || options.MaxConcurrent < 1 ||
		options.MaxConcurrent > 256 {
		return nil, ErrInvalidConfiguration
	}
	policy, err := federatedhttp.NewDeploymentEgressPolicy(
		options.PrivateEgressCIDRs, options.AllowedHTTPSPorts,
	)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	roots, err := loadFederatedRootCAs(options.CABundleFile)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	limits := federatedhttp.DefaultLimits()
	limits.OperationTimeout = options.OperationTimeout
	limits.ConnectTimeout = min(limits.ConnectTimeout, options.OperationTimeout)
	limits.TLSHandshakeTimeout = min(limits.TLSHandshakeTimeout, options.OperationTimeout)
	limits.ResponseHeaderTimeout = min(limits.ResponseHeaderTimeout, options.OperationTimeout)
	client, err := federatedhttp.New(federatedhttp.Options{
		Resolver: options.Resolver, Dialer: options.Dialer, EgressPolicy: policy,
		RootCAs: roots, Limits: limits, MaxConcurrent: options.MaxConcurrent,
	})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	upstream, err := federatedoidc.NewUpstreamHTTP(federatedoidc.UpstreamOptions{
		HTTP: client, JSONLimits: federatedoidc.DefaultLimits(),
		MaxUserInfoBytes: defaultOIDCResponseBytes, MaxRefreshBytes: defaultOIDCResponseBytes,
	})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return &PinnedUpstream{upstream: upstream}, nil
}

func (adapter *PinnedUpstream) Refresh(
	ctx context.Context,
	request federatedoidc.StoredRefreshExchangeRequest,
	now time.Time,
) (RefreshResult, error) {
	if adapter == nil || adapter.upstream == nil {
		clear(request.ClientSecret)
		clear(request.RefreshToken)
		return RefreshResult{}, federatedoidc.ErrRefreshRejected
	}
	tokens, err := adapter.upstream.RefreshStored(ctx, request, now)
	if tokens != nil {
		defer tokens.Destroy()
	}
	if err != nil {
		return RefreshResult{}, err
	}
	if tokens == nil {
		return RefreshResult{}, federatedoidc.ErrRefreshRejected
	}
	refreshToken := tokens.RefreshToken()
	defer clear(refreshToken)
	return RefreshResult{
		RefreshToken:    append([]byte(nil), refreshToken...),
		AccessExpiresAt: tokens.ExpiresAt(),
	}, nil
}

func (adapter *PinnedUpstream) Revoke(
	ctx context.Context,
	material federatedoidc.StoredRevocationMaterial,
) error {
	if adapter == nil || adapter.upstream == nil {
		clear(material.Token)
		clear(material.ClientSecret)
		return federatedoidc.ErrRevocationFailed
	}
	return adapter.upstream.RevokeStored(ctx, material)
}

func loadFederatedRootCAs(bundleFile string) (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return nil, ErrInvalidConfiguration
	}
	roots = roots.Clone()
	bundleFile = strings.TrimSpace(bundleFile)
	if bundleFile == "" {
		return roots, nil
	}
	file, err := os.Open(bundleFile)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumFederatedCABundleBytes {
		return nil, ErrInvalidConfiguration
	}
	document, err := io.ReadAll(io.LimitReader(file, maximumFederatedCABundleBytes+1))
	if err != nil || len(document) == 0 || len(document) > maximumFederatedCABundleBytes {
		clear(document)
		return nil, ErrInvalidConfiguration
	}
	defer clear(document)
	if !validCertificatePEM(document) || !roots.AppendCertsFromPEM(document) {
		return nil, ErrInvalidConfiguration
	}
	return roots, nil
}

func validCertificatePEM(document []byte) bool {
	rest := document
	parsed := false
	for len(bytes.TrimSpace(rest)) > 0 {
		block, remainder := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		parsed = true
		rest = remainder
	}
	return parsed
}
