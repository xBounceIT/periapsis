package oidcmaintenance

import (
	"context"
	"encoding/pem"
	"errors"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewUpstreamUsesClosedDeploymentEgressPolicyAndCustomTrust(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	certificate := server.TLS.Certificates[0].Certificate[0]
	server.Close()
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	path := filepath.Join(t.TempDir(), "federated-ca.pem")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(bundle)

	upstream, err := NewUpstream(UpstreamOptions{
		Resolver: oidcMaintenanceTestResolver{}, Dialer: oidcMaintenanceTestDialer{},
		PrivateEgressCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		AllowedHTTPSPorts:  []uint16{8443}, CABundleFile: path,
		OperationTimeout: 20 * time.Second, MaxConcurrent: 4,
	})
	if err != nil || upstream == nil || upstream.upstream == nil {
		t.Fatalf("NewUpstream() = %v, %v", upstream, err)
	}
}

func TestNewUpstreamRejectsAmbientOrUnsafeConfiguration(t *testing.T) {
	valid := UpstreamOptions{
		Resolver: oidcMaintenanceTestResolver{}, Dialer: oidcMaintenanceTestDialer{},
		OperationTimeout: 20 * time.Second, MaxConcurrent: 4,
	}
	tests := []struct {
		name   string
		mutate func(*UpstreamOptions)
	}{
		{name: "missing resolver", mutate: func(options *UpstreamOptions) { options.Resolver = nil }},
		{name: "missing literal dialer", mutate: func(options *UpstreamOptions) { options.Dialer = nil }},
		{name: "public egress widening", mutate: func(options *UpstreamOptions) {
			options.PrivateEgressCIDRs = []netip.Prefix{netip.MustParsePrefix("8.8.0.0/16")}
		}},
		{name: "duplicate port", mutate: func(options *UpstreamOptions) {
			options.AllowedHTTPSPorts = []uint16{443, 443}
		}},
		{name: "unbounded concurrency", mutate: func(options *UpstreamOptions) { options.MaxConcurrent = 257 }},
		{name: "unbounded timeout", mutate: func(options *UpstreamOptions) { options.OperationTimeout = 99 * time.Millisecond }},
		{name: "invalid trust bundle", mutate: func(options *UpstreamOptions) {
			path := filepath.Join(t.TempDir(), "not-a-ca.pem")
			if err := os.WriteFile(path, []byte("customer-secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			options.CABundleFile = path
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := valid
			test.mutate(&options)
			if _, err := NewUpstream(options); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("NewUpstream() error = %v", err)
			}
		})
	}
}

type oidcMaintenanceTestResolver struct{}

func (oidcMaintenanceTestResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errors.New("unused")
}

type oidcMaintenanceTestDialer struct{}

func (oidcMaintenanceTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unused")
}
