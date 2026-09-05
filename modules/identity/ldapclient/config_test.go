package ldapclient

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestNewRejectsInvalidDeploymentPolicy(t *testing.T) {
	t.Parallel()

	resolver := publicResolver("93.184.216.34")
	dialer := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial failed")
	})
	valid := testOptions(resolver, dialer)
	tooManyPorts := make([]uint16, maximumAllowedPorts+1)
	for index := range tooManyPorts {
		tooManyPorts[index] = uint16(index + 1)
	}
	tooManyCIDRs := make([]netip.Prefix, maximumPrivateCIDRs+1)
	for index := range tooManyCIDRs {
		tooManyCIDRs[index] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(index), 0, 0}), 16)
	}

	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{name: "nil resolver", mutate: func(options *Options) { options.Resolver = nil }},
		{name: "nil dialer", mutate: func(options *Options) { options.Dialer = nil }},
		{name: "zero concurrency", mutate: func(options *Options) { options.MaxConcurrent = 0 }},
		{name: "excessive concurrency", mutate: func(options *Options) { options.MaxConcurrent = maximumConcurrent + 1 }},
		{name: "public allowlist", mutate: func(options *Options) {
			options.PrivateEgressCIDRs = []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")}
		}},
		{name: "loopback allowlist", mutate: func(options *Options) {
			options.PrivateEgressCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
		}},
		{name: "unmasked allowlist", mutate: func(options *Options) {
			options.PrivateEgressCIDRs = []netip.Prefix{netip.MustParsePrefix("10.1.2.0/8")}
		}},
		{name: "duplicate allowlist", mutate: func(options *Options) {
			options.PrivateEgressCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8")}
		}},
		{name: "too many allowlists", mutate: func(options *Options) { options.PrivateEgressCIDRs = tooManyCIDRs }},
		{name: "zero StartTLS port", mutate: func(options *Options) { options.AllowedStartTLSPorts = []uint16{0} }},
		{name: "duplicate LDAPS port", mutate: func(options *Options) { options.AllowedLDAPSPorts = []uint16{636, 636} }},
		{name: "too many ports", mutate: func(options *Options) { options.AllowedLDAPSPorts = tooManyPorts }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := valid
			test.mutate(&options)
			if _, err := New(options); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("New() error = %v", err)
			}
		})
	}
}

func TestConfigurationValidationIsStrictAndBounded(t *testing.T) {
	t.Parallel()

	options := testOptions(publicResolver("93.184.216.34"), &recordingDialer{})
	options.MaxConcurrent = maximumConcurrent
	client, err := New(options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	valid := testConfiguration()
	tooManyEndpoints := make([]Endpoint, maximumEndpoints+1)
	for index := range tooManyEndpoints {
		tooManyEndpoints[index] = valid.Endpoints[0]
		tooManyEndpoints[index].Priority = index + 1
	}

	tests := []struct {
		name   string
		mutate func(*Configuration)
	}{
		{name: "no endpoints", mutate: func(configuration *Configuration) { configuration.Endpoints = nil }},
		{name: "too many endpoints", mutate: func(configuration *Configuration) { configuration.Endpoints = tooManyEndpoints }},
		{name: "connect too short", mutate: func(configuration *Configuration) {
			configuration.ConnectTimeout = minimumConnectTimeout - time.Millisecond
		}},
		{name: "connect too long", mutate: func(configuration *Configuration) {
			configuration.ConnectTimeout = maximumConnectTimeout + time.Millisecond
		}},
		{name: "operation too short", mutate: func(configuration *Configuration) {
			configuration.OperationTimeout = minimumOperationTimeout - time.Millisecond
		}},
		{name: "operation too long", mutate: func(configuration *Configuration) {
			configuration.OperationTimeout = maximumOperationTimeout + time.Millisecond
		}},
		{name: "connect exceeds operation", mutate: func(configuration *Configuration) {
			configuration.ConnectTimeout = time.Second
			configuration.OperationTimeout = 500 * time.Millisecond
		}},
		{name: "zero priority", mutate: func(configuration *Configuration) { configuration.Endpoints[0].Priority = 0 }},
		{name: "duplicate priority", mutate: func(configuration *Configuration) {
			configuration.Endpoints = append(configuration.Endpoints, configuration.Endpoints[0])
		}},
		{name: "zero port", mutate: func(configuration *Configuration) { configuration.Endpoints[0].Port = 0 }},
		{name: "unexpected port", mutate: func(configuration *Configuration) { configuration.Endpoints[0].Port = 389 }},
		{name: "unknown transport", mutate: func(configuration *Configuration) { configuration.Endpoints[0].Transport = "ldap" }},
		{name: "uppercase host", mutate: func(configuration *Configuration) { configuration.Endpoints[0].Host = "LDAP.example.com" }},
		{name: "trailing dot", mutate: func(configuration *Configuration) { configuration.Endpoints[0].Host = "ldap.example.com." }},
		{name: "ambiguous decimal address", mutate: func(configuration *Configuration) { configuration.Endpoints[0].Host = "2130706433" }},
		{name: "ambiguous octal address", mutate: func(configuration *Configuration) { configuration.Endpoints[0].Host = "0177.0.0.1" }},
		{name: "ambiguous hexadecimal address", mutate: func(configuration *Configuration) { configuration.Endpoints[0].Host = "0x7f.0x0.0x0.0x1" }},
		{name: "noncanonical IPv6", mutate: func(configuration *Configuration) { configuration.Endpoints[0].Host = "2001:0db8::1" }},
		{name: "TLS name with wildcard", mutate: func(configuration *Configuration) { configuration.Endpoints[0].TLSServerName = "*.example.com" }},
		{name: "TLS name with whitespace", mutate: func(configuration *Configuration) { configuration.Endpoints[0].TLSServerName = "ldap .example.com" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			configuration := valid
			configuration.Endpoints = append([]Endpoint(nil), valid.Endpoints...)
			test.mutate(&configuration)
			if _, err := client.TestConnection(context.Background(), configuration); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("TestConnection() error = %v", err)
			}
		})
	}
}

func TestConfigurationSortsEndpointsAndSupportsDeploymentPorts(t *testing.T) {
	t.Parallel()

	client, err := New(Options{
		Resolver:             publicResolver("93.184.216.34"),
		Dialer:               &recordingDialer{},
		AllowedStartTLSPorts: []uint16{389, 3268},
		AllowedLDAPSPorts:    []uint16{636, 3269},
		MaxConcurrent:        1,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	configuration := testConfiguration()
	configuration.Endpoints = []Endpoint{
		{Priority: 2, Enabled: true, Host: "second.example.com", Port: 3269, Transport: TransportLDAPS, TLSServerName: "second.example.com"},
		{Priority: 1, Enabled: true, Host: "first.example.com", Port: 3268, Transport: TransportStartTLS, TLSServerName: "first.example.com"},
	}
	validated, err := client.validateConfiguration(configuration)
	if err != nil {
		t.Fatalf("validateConfiguration() error = %v", err)
	}
	if validated.endpoints[0].Priority != 1 || validated.endpoints[1].Priority != 2 {
		t.Fatalf("endpoint order = %#v", validated.endpoints)
	}
}

func TestValidateConfigurationUsesDeploymentPolicyWithoutNetworkIO(t *testing.T) {
	t.Parallel()

	resolverCalls := 0
	dialCalls := 0
	client, err := New(Options{
		Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			resolverCalls++
			return nil, errors.New("resolver must not be called")
		}),
		Dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			dialCalls++
			return nil, errors.New("dialer must not be called")
		}),
		AllowedStartTLSPorts: []uint16{389, 3268},
		AllowedLDAPSPorts:    []uint16{636, 3269},
		MaxConcurrent:        1,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	configuration := testConfiguration()
	configuration.Endpoints[0].Port = 3269
	if err := client.ValidateConfiguration(configuration); err != nil {
		t.Fatalf("ValidateConfiguration() error = %v", err)
	}
	configuration.Endpoints[0].Port = 1636
	if err := client.ValidateConfiguration(configuration); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("ValidateConfiguration() unsupported port error = %v", err)
	}
	if resolverCalls != 0 || dialCalls != 0 {
		t.Fatalf("ValidateConfiguration() performed network I/O: resolver=%d dialer=%d", resolverCalls, dialCalls)
	}
}

func TestCustomCAsStrictlyExtendAnIsolatedTrustPool(t *testing.T) {
	t.Parallel()

	base := newTestPKI(t, "base.example.com")
	customOne := newTestPKI(t, "one.example.com")
	customTwo := newTestPKI(t, "two.example.com")
	customPEM := append(append([]byte(" \r\n"), customOne.caPEM...), customTwo.caPEM...)
	customPEM = append(customPEM, '\n')
	pool, err := trustPoolWithCustomCAs(base.roots, customPEM)
	if err != nil {
		t.Fatalf("trustPoolWithCustomCAs() error = %v", err)
	}
	if got, want := len(pool.Subjects()), len(base.roots.Subjects())+2; got != want {
		t.Fatalf("trust subjects = %d, want %d", got, want)
	}
	if got := len(base.roots.Subjects()); got != 1 {
		t.Fatalf("base trust pool was mutated, subjects = %d", got)
	}
}

func TestCustomCAMaterialIsStrictAndBounded(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	leafPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: pki.serverCertificate.Certificate[0],
	})
	withHeaders := pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE",
		Headers: map[string]string{"tenant": "untrusted"},
		Bytes:   pki.serverCertificate.Certificate[1],
	})
	duplicate := append(append([]byte(nil), pki.caPEM...), pki.caPEM...)
	tests := []struct {
		name  string
		value []byte
	}{
		{name: "whitespace only", value: []byte(" \r\n\t")},
		{name: "leading junk", value: append([]byte("junk"), pki.caPEM...)},
		{name: "trailing junk", value: append(append([]byte(nil), pki.caPEM...), []byte("junk")...)},
		{name: "wrong PEM type", value: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}})},
		{name: "PEM headers", value: withHeaders},
		{name: "malformed DER", value: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})},
		{name: "leaf trust anchor", value: leafPEM},
		{name: "duplicate certificate", value: duplicate},
		{name: "oversized", value: bytes.Repeat([]byte{'x'}, maximumCustomCABytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := trustPoolWithCustomCAs(pki.roots, test.value); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("trustPoolWithCustomCAs() error = %v", err)
			}
		})
	}
	if _, err := trustPoolWithCustomCAs(nil, nil); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("nil system roots error = %v", err)
	}
}

func TestBindValidationClearsCallerSecret(t *testing.T) {
	t.Parallel()

	client, err := New(testOptions(publicResolver("93.184.216.34"), &recordingDialer{}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, test := range []struct {
		name   string
		dn     string
		secret []byte
	}{
		{name: "empty DN", secret: []byte("secret")},
		{name: "whitespace DN", dn: "   ", secret: []byte("secret")},
		{name: "invalid UTF-8 DN", dn: string([]byte{'c', 'n', '=', 0xff}), secret: []byte("secret")},
		{name: "invalid DN", dn: "not=a,valid=dn,", secret: []byte("secret")},
		{name: "oversized DN", dn: "cn=" + strings.Repeat("a", maximumBindDNCharacters), secret: []byte("secret")},
		{name: "empty secret", dn: "cn=svc,dc=example,dc=com"},
		{name: "oversized secret", dn: "cn=svc,dc=example,dc=com", secret: bytes.Repeat([]byte{1}, maximumBindSecretBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			secret := append([]byte(nil), test.secret...)
			if _, err := client.TestBind(context.Background(), testConfiguration(), test.dn, secret); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("TestBind() error = %v", err)
			}
			if !allZeroBytes(secret) {
				t.Fatal("TestBind() did not clear a rejected secret")
			}
		})
	}
}

func TestBindAcceptsDatabaseBoundedMultibyteDN(t *testing.T) {
	t.Parallel()

	client, err := New(testOptions(publicResolver("93.184.216.34"), &recordingDialer{}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	bindDN := "cn=" + strings.Repeat("é", maximumBindDNCharacters-3)
	if utf8.RuneCountInString(bindDN) != maximumBindDNCharacters || len(bindDN) <= 2048 {
		t.Fatal("test DN does not exercise the character-vs-byte boundary")
	}
	secret := []byte("secret")
	diagnostic, err := client.TestBind(context.Background(), testConfiguration(), bindDN, secret)
	if err != nil || diagnostic.Category != CategoryConnectFailed {
		t.Fatalf("diagnostic = %#v, error = %v", diagnostic, err)
	}
	if !allZeroBytes(secret) {
		t.Fatal("TestBind() did not clear the accepted secret")
	}
}

func allZeroBytes(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
