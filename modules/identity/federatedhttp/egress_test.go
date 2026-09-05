package federatedhttp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestFetchBlocksSSRFAddressesBeforeDial(t *testing.T) {
	blocked := []netip.Addr{
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("100.64.0.1"),
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("168.63.129.16"),
		netip.MustParseAddr("169.254.169.254"),
		netip.MustParseAddr("172.16.0.1"),
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.168.0.1"),
		netip.MustParseAddr("198.18.0.1"),
		netip.MustParseAddr("198.51.100.1"),
		netip.MustParseAddr("203.0.113.1"),
		netip.MustParseAddr("224.0.0.1"),
		netip.MustParseAddr("255.255.255.255"),
		netip.MustParseAddr("::"),
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("::ffff:127.0.0.1"),
		netip.MustParseAddr("::7f00:1"),
		netip.MustParseAddr("64:ff9b::7f00:1"),
		netip.MustParseAddr("100::1"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("fd00:ec2::254"),
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("ff02::1"),
	}
	for _, address := range blocked {
		address := address
		t.Run(address.String(), func(t *testing.T) {
			var dialed bool
			client := newTestClient(
				t,
				staticResolver(map[string][]netip.Addr{"provider.example": {address}}),
				dialerFunc(func(context.Context, string, string) (net.Conn, error) {
					dialed = true
					return nil, errors.New("must not dial")
				}),
				nil,
			)
			target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example")
			result, err := client.Fetch(context.Background(), target, nil)
			if err != nil {
				t.Fatal(err)
			}
			if result.Category != CategoryDestinationBlocked || dialed {
				t.Fatalf("result = %v, dialed = %t", result, dialed)
			}
		})
	}
}

func TestFetchValidatesEveryDNSAddressBeforeDial(t *testing.T) {
	dialed := false
	client := newTestClient(
		t,
		staticResolver(map[string][]netip.Addr{
			"provider.example": {
				netip.MustParseAddr("93.184.216.34"),
				netip.MustParseAddr("169.254.169.254"),
			},
		}),
		dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("must not dial")
		}),
		nil,
	)
	target := compileTestTarget(t, client, DocumentOIDCJWKS, "https://provider.example/keys")
	result, err := client.Fetch(context.Background(), target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Category != CategoryDestinationBlocked || dialed {
		t.Fatalf("result = %v, dialed = %t", result, dialed)
	}
}

func TestFetchRejectsUnboundedDNSAnswersBeforeDial(t *testing.T) {
	addresses := make([]netip.Addr, maximumResolvedAddresses+1)
	for index := range addresses {
		addresses[index] = netip.AddrFrom4([4]byte{93, 184, 216, byte(index + 1)})
	}
	dialed := false
	client := newTestClient(
		t,
		staticResolver(map[string][]netip.Addr{"provider.example": addresses}),
		dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("must not dial")
		}),
		nil,
	)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example")
	result, err := client.Fetch(context.Background(), target, nil)
	if err != nil || result.Category != CategoryDestinationBlocked || dialed {
		t.Fatalf("Fetch() = %v, %v; dialed = %t", result, err, dialed)
	}
}

func TestFetchDialsOneDeterministicApprovedAddress(t *testing.T) {
	server := startTestTLSServer(t, documentHandler("application/json", `{}`))
	dialer := &routingDialer{routes: map[string]string{
		"93.184.216.34:443": server.Listener.Addr().String(),
		"93.184.216.35:443": server.Listener.Addr().String(),
	}}
	client := newTestClient(
		t,
		staticResolver(map[string][]netip.Addr{
			"provider.example": {
				netip.MustParseAddr("93.184.216.35"),
				netip.MustParseAddr("93.184.216.34"),
			},
		}),
		dialer,
		nil,
	)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example")
	result, err := client.Fetch(context.Background(), target, nil)
	if err != nil || result.Category != CategorySuccess {
		t.Fatalf("Fetch() = %v, %v", result, err)
	}
	if calls := dialer.callSnapshot(); !slices.Equal(calls, []string{"93.184.216.34:443"}) {
		t.Fatalf("dial calls = %v", calls)
	}
}

func TestPrivateAllowlistCannotOverrideMetadataBlock(t *testing.T) {
	policy, err := NewDeploymentEgressPolicy(
		[]netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("fd00::/8"),
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, roots := testCertificate(t)
	var mu sync.Mutex
	var calls []string
	client, err := New(Options{
		Resolver: staticResolver(map[string][]netip.Addr{
			"private.example":  {netip.MustParseAddr("10.20.30.40")},
			"metadata.example": {netip.MustParseAddr("fd00:ec2::254")},
		}),
		Dialer: dialerFunc(func(_ context.Context, _, address string) (net.Conn, error) {
			mu.Lock()
			calls = append(calls, address)
			mu.Unlock()
			return nil, errors.New("expected test failure")
		}),
		EgressPolicy:  policy,
		RootCAs:       roots,
		Limits:        testLimits(),
		MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	privateTarget := compileTestTarget(t, client, DocumentSAMLMetadata, "https://private.example")
	result, err := client.Fetch(context.Background(), privateTarget, nil)
	if err != nil || result.Category != CategoryConnectFailed {
		t.Fatalf("private result = %v, %v", result, err)
	}
	metadataTarget := compileTestTarget(t, client, DocumentSAMLMetadata, "https://metadata.example")
	result, err = client.Fetch(context.Background(), metadataTarget, nil)
	if err != nil || result.Category != CategoryDestinationBlocked {
		t.Fatalf("metadata result = %v, %v", result, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(calls, []string{"10.20.30.40:443"}) {
		t.Fatalf("dial calls = %v", calls)
	}
}

func TestFetchRevalidatesDNSOnEveryConnection(t *testing.T) {
	server := startTestTLSServer(t, documentHandler("application/json", `{}`))
	var mu sync.Mutex
	lookup := 0
	resolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		lookup++
		if lookup == 1 {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	})
	dialer := &routingDialer{routes: map[string]string{
		"93.184.216.34:443": server.Listener.Addr().String(),
	}}
	client := newTestClient(t, resolver, dialer, nil)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example")
	first, err := client.Fetch(context.Background(), target, nil)
	if err != nil || first.Category != CategorySuccess {
		t.Fatalf("first Fetch() = %v, %v", first, err)
	}
	second, err := client.Fetch(context.Background(), target, nil)
	if err != nil || second.Category != CategoryDestinationBlocked {
		t.Fatalf("second Fetch() = %v, %v", second, err)
	}
	if calls := dialer.callSnapshot(); len(calls) != 1 {
		t.Fatalf("DNS rebinding caused %d dials: %v", len(calls), calls)
	}
}

func TestResolverFailuresAreRedacted(t *testing.T) {
	secret := "resolver-secret-canary"
	client := newTestClient(
		t,
		resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New(secret)
		}),
		dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unused")
		}),
		nil,
	)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example/"+secret)
	result, err := client.Fetch(context.Background(), target, nil)
	if err != nil || result.Category != CategoryDNSFailed {
		t.Fatalf("Fetch() = %v, %v", result, err)
	}
	if strings.Contains(result.String(), secret) {
		t.Fatalf("resolver or URL secret leaked: %v", result)
	}
}
