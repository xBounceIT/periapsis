package federatedhttp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCompileTargetAcceptsOnlyCanonicalHTTPS(t *testing.T) {
	client := newTestClient(
		t,
		staticResolver(nil),
		dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unused")
		}),
		nil,
	)
	for _, rawURL := range []string{
		"https://provider.example",
		"https://provider.example/.well-known/openid-configuration",
		"https://2606:4700:4700::1111/metadata",
	} {
		if strings.Contains(rawURL, "2606:") {
			rawURL = "https://[2606:4700:4700::1111]/metadata"
		}
		target, err := client.CompileTarget(DocumentOIDCDiscovery, rawURL)
		if err != nil {
			t.Fatalf("CompileTarget(%q): %v", rawURL, err)
		}
		if !target.valid || target.canonicalURL != rawURL {
			t.Fatalf("target was not frozen canonically: %v", target)
		}
	}
}

func TestCompileTargetRejectsAmbiguityAndSecretURLComponents(t *testing.T) {
	client := newTestClient(
		t,
		staticResolver(nil),
		dialerFunc(func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unused") }),
		nil,
	)
	secret := "url-secret-canary"
	cases := []string{
		"",
		"http://provider.example/metadata",
		"HTTPS://provider.example/metadata",
		"https://user:" + secret + "@provider.example/metadata",
		"https://provider.example/metadata?token=" + secret,
		"https://provider.example/metadata#" + secret,
		"https://provider.example:443/metadata",
		"https://provider.example:8443/metadata",
		"https://Provider.example/metadata",
		"https://provider.example./metadata",
		"https://2130706433/metadata",
		"https://127.1/metadata",
		"https://0x7f.0x0.0x0.0x1/metadata",
		"https://[::ffff:127.0.0.1]/metadata",
		"https://provider.example/%2e%2e/metadata",
		"https://provider.example/a//b",
		"https://provider.example/a/../b",
		"https://provider.example/a\\b",
		" https://provider.example/metadata",
		"https://provider.example/m\u00e9tadata",
	}
	for _, rawURL := range cases {
		_, err := client.CompileTarget(DocumentSAMLMetadata, rawURL)
		if !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("CompileTarget(%q) error = %v", rawURL, err)
		}
		if err != nil && strings.Contains(err.Error(), secret) {
			t.Fatalf("secret leaked in target error: %v", err)
		}
	}
	if _, err := client.CompileTarget(DocumentKind(secret), "https://provider.example"); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("invalid document kind error = %v", err)
	}
}

func TestRedirectTargetRepeatsCanonicalURLValidation(t *testing.T) {
	client := newTestClient(
		t,
		staticResolver(nil),
		dialerFunc(func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unused") }),
		nil,
	)
	current := compileTestTarget(t, client, DocumentOIDCJWKS, "https://provider.example/keys")
	for _, location := range []string{
		"//redirect.example/keys",
		"relative/keys",
		"http://redirect.example/keys",
		"https://user:secret@redirect.example/keys",
		"https://redirect.example/keys?token=secret",
		"https://redirect.example/keys#secret",
		"https://redirect.example:443/keys",
		"https://Redirect.example/keys",
		"/a/../keys",
	} {
		if _, err := client.redirectTarget(current, location); !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("redirect location %q accepted: %v", location, err)
		}
	}
	for _, location := range []string{
		"/next",
		"https://redirect.example/next",
	} {
		if _, err := client.redirectTarget(current, location); err != nil {
			t.Errorf("redirect location %q rejected: %v", location, err)
		}
	}
}

func TestDeploymentEgressPolicyIsClosedAndCopied(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
	ports := []uint16{8443}
	policy, err := NewDeploymentEgressPolicy(prefixes, ports)
	if err != nil {
		t.Fatal(err)
	}
	prefixes[0] = netip.MustParsePrefix("10.30.0.0/16")
	ports[0] = 9443
	if !policy.privateCIDRs[0].Contains(netip.MustParseAddr("10.20.1.1")) {
		t.Fatal("policy retained caller-owned CIDR storage")
	}
	if _, ok := policy.ports[8443]; !ok {
		t.Fatal("policy retained caller-owned port storage")
	}

	_, roots := testCertificate(t)
	client, err := New(Options{
		Resolver: staticResolver(nil),
		Dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unused")
		}),
		EgressPolicy:  policy,
		RootCAs:       roots,
		Limits:        testLimits(),
		MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	delete(policy.ports, 8443)
	policy.privateCIDRs[0] = netip.MustParsePrefix("10.30.0.0/16")
	if _, err := client.CompileTarget(DocumentOIDCJWKS, "https://provider.example:8443/keys"); err != nil {
		t.Fatalf("client did not freeze deployment policy: %v", err)
	}
	if !client.addressAllowed(netip.MustParseAddr("10.20.1.1")) ||
		client.addressAllowed(netip.MustParseAddr("10.30.1.1")) {
		t.Fatal("client deployment CIDR policy changed after construction")
	}
}

func TestDeploymentEgressPolicyRejectsUnsafeValues(t *testing.T) {
	cases := [][]netip.Prefix{
		{netip.MustParsePrefix("127.0.0.0/8")},
		{netip.MustParsePrefix("169.254.0.0/16")},
		{netip.MustParsePrefix("10.0.0.1/8")},
		{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8")},
	}
	for _, prefixes := range cases {
		if _, err := NewDeploymentEgressPolicy(prefixes, nil); !errors.Is(err, ErrInvalidOptions) {
			t.Errorf("unsafe CIDRs %v accepted: %v", prefixes, err)
		}
	}
	tooMany := make([]netip.Prefix, maximumPrivateCIDRs+1)
	for index := range tooMany {
		tooMany[index] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(index), 0, 0}), 24)
	}
	if _, err := NewDeploymentEgressPolicy(tooMany, nil); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("too many CIDRs accepted: %v", err)
	}
	if _, err := NewDeploymentEgressPolicy(nil, []uint16{0}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("zero port accepted: %v", err)
	}
	if _, err := NewDeploymentEgressPolicy(nil, []uint16{443, 443}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("duplicate port accepted: %v", err)
	}
}

func TestNewRejectsIncompleteOrUnboundedOptions(t *testing.T) {
	policy, err := NewDeploymentEgressPolicy(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	valid := Options{
		Resolver: staticResolver(nil),
		Dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unused")
		}),
		EgressPolicy:  policy,
		Limits:        testLimits(),
		MaxConcurrent: 1,
	}
	cases := []Options{valid, valid, valid, valid, valid}
	cases[0].Resolver = nil
	cases[1].Dialer = nil
	cases[2].EgressPolicy = DeploymentEgressPolicy{}
	cases[3].MaxConcurrent = 0
	cases[4].Limits.OperationTimeout = 0
	for index, options := range cases {
		if _, err := New(options); !errors.Is(err, ErrInvalidOptions) {
			t.Errorf("case %d error = %v", index, err)
		}
	}

	limits := testLimits()
	limits.ConnectTimeout = limits.OperationTimeout + time.Second
	valid.Limits = limits
	if _, err := New(valid); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("phase timeout beyond total accepted: %v", err)
	}
}
