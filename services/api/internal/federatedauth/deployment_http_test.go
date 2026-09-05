package federatedauth

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

type deploymentResolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (function deploymentResolverFunc) LookupNetIP(
	ctx context.Context,
	network string,
	host string,
) ([]netip.Addr, error) {
	return function(ctx, network, host)
}

type deploymentDialerFunc func(context.Context, string, string) (net.Conn, error)

func (function deploymentDialerFunc) DialContext(
	ctx context.Context,
	network string,
	address string,
) (net.Conn, error) {
	return function(ctx, network, address)
}

func TestNewDeploymentHTTPClientFreezesPortsCIDRsAndMinimumTimeout(t *testing.T) {
	privateCIDRs := []netip.Prefix{netip.MustParsePrefix("10.40.0.0/16")}
	ports := []uint16{443, 8443}
	dialCalls := 0
	client, err := NewDeploymentHTTPClient(DeploymentHTTPOptions{
		Resolver: deploymentResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("10.40.1.7")}, nil
		}),
		Dialer: deploymentDialerFunc(func(context.Context, string, string) (net.Conn, error) {
			dialCalls++
			return nil, errors.New("not invoked")
		}),
		PrivateEgressCIDRs: privateCIDRs, AllowedHTTPSPorts: ports,
		RootCAs: x509.NewCertPool(), OperationTimeout: 100 * time.Millisecond, MaxConcurrent: 1,
	})
	if err != nil || client == nil {
		t.Fatalf("NewDeploymentHTTPClient() = %v, %v", client, err)
	}
	privateCIDRs[0] = netip.MustParsePrefix("192.168.0.0/16")
	ports[1] = 9443
	if _, err = client.CompileTarget(federatedhttp.DocumentOIDCDiscovery, "https://idp.example:8443/discovery"); err != nil {
		t.Fatalf("frozen allowed port rejected: %v", err)
	}
	if _, err = client.CompileTarget(federatedhttp.DocumentOIDCDiscovery, "https://idp.example:9443/discovery"); !errors.Is(err, federatedhttp.ErrInvalidTarget) {
		t.Fatalf("mutated caller port widened client: %v", err)
	}
	target, err := client.CompileTarget(federatedhttp.DocumentOIDCDiscovery, "https://idp.example/discovery")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Fetch(context.Background(), target, nil)
	if err != nil || result.Category != federatedhttp.CategoryConnectFailed || dialCalls != 1 {
		t.Fatalf("frozen private CIDR result = %#v, %v, dial calls=%d", result, err, dialCalls)
	}
}

func TestNewDeploymentHTTPClientRejectsIncompleteOrUnboundedPolicy(t *testing.T) {
	valid := DeploymentHTTPOptions{
		Resolver: deploymentResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("not invoked")
		}),
		Dialer: deploymentDialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("not invoked")
		}),
		RootCAs: x509.NewCertPool(), OperationTimeout: time.Second, MaxConcurrent: 1,
	}
	tests := map[string]func(*DeploymentHTTPOptions){
		"resolver":    func(value *DeploymentHTTPOptions) { value.Resolver = nil },
		"dialer":      func(value *DeploymentHTTPOptions) { value.Dialer = nil },
		"roots":       func(value *DeploymentHTTPOptions) { value.RootCAs = nil },
		"short total": func(value *DeploymentHTTPOptions) { value.OperationTimeout = 99 * time.Millisecond },
		"unaligned":   func(value *DeploymentHTTPOptions) { value.OperationTimeout = time.Second + time.Nanosecond },
		"concurrency": func(value *DeploymentHTTPOptions) { value.MaxConcurrent = 257 },
		"duplicate port": func(value *DeploymentHTTPOptions) {
			value.AllowedHTTPSPorts = []uint16{443, 443}
		},
		"noncanonical CIDR": func(value *DeploymentHTTPOptions) {
			value.PrivateEgressCIDRs = []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr("10.1.2.3"), 8)}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			options := valid
			mutate(&options)
			if client, err := NewDeploymentHTTPClient(options); !errors.Is(err, ErrInvalidOptions) || client != nil {
				t.Fatalf("NewDeploymentHTTPClient() = %v, %v", client, err)
			}
		})
	}
}
