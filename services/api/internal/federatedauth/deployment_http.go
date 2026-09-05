package federatedauth

import (
	"crypto/x509"
	"net/netip"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

// DeploymentHTTPOptions is the deployment-owned network policy used by every
// OIDC and SAML outbound operation. Tenant configuration can provide exact
// HTTPS URLs, but it cannot replace or widen any option in this structure.
type DeploymentHTTPOptions struct {
	Resolver           federatedhttp.Resolver
	Dialer             federatedhttp.Dialer
	PrivateEgressCIDRs []netip.Prefix
	AllowedHTTPSPorts  []uint16
	RootCAs            *x509.CertPool
	OperationTimeout   time.Duration
	MaxConcurrent      int
}

// NewDeploymentHTTPClient freezes one SSRF-safe network boundary. Phase
// deadlines are capped by the total operation deadline so every configuration
// accepted by the application (including the 100 ms minimum) is internally
// coherent and still governed by the client's shared overall context.
func NewDeploymentHTTPClient(options DeploymentHTTPOptions) (*federatedhttp.Client, error) {
	if options.Resolver == nil || options.Dialer == nil || options.RootCAs == nil ||
		options.OperationTimeout < minimumOperationTimeout ||
		options.OperationTimeout > maximumOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 ||
		options.MaxConcurrent < 1 || options.MaxConcurrent > 256 {
		return nil, ErrInvalidOptions
	}
	policy, err := federatedhttp.NewDeploymentEgressPolicy(
		options.PrivateEgressCIDRs, options.AllowedHTTPSPorts,
	)
	if err != nil {
		return nil, ErrInvalidOptions
	}
	limits := federatedhttp.DefaultLimits()
	limits.OperationTimeout = options.OperationTimeout
	limits.ConnectTimeout = cappedFederatedPhaseTimeout(limits.ConnectTimeout, options.OperationTimeout)
	limits.TLSHandshakeTimeout = cappedFederatedPhaseTimeout(limits.TLSHandshakeTimeout, options.OperationTimeout)
	limits.ResponseHeaderTimeout = cappedFederatedPhaseTimeout(limits.ResponseHeaderTimeout, options.OperationTimeout)
	client, err := federatedhttp.New(federatedhttp.Options{
		Resolver: options.Resolver, Dialer: options.Dialer, EgressPolicy: policy,
		RootCAs: options.RootCAs, Limits: limits, MaxConcurrent: options.MaxConcurrent,
	})
	if err != nil {
		return nil, ErrInvalidOptions
	}
	return client, nil
}

func cappedFederatedPhaseTimeout(preferred, total time.Duration) time.Duration {
	if preferred > total {
		return total
	}
	return preferred
}
