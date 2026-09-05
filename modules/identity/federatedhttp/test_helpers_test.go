package federatedhttp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"
)

var (
	testPKIOnce sync.Once
	testCert    tls.Certificate
	testRoots   *x509.CertPool
	testPKIErr  error
)

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (resolver resolverFunc) LookupNetIP(
	ctx context.Context,
	network string,
	host string,
) ([]netip.Addr, error) {
	return resolver(ctx, network, host)
}

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (dialer dialerFunc) DialContext(
	ctx context.Context,
	network string,
	address string,
) (net.Conn, error) {
	return dialer(ctx, network, address)
}

type routingDialer struct {
	mu     sync.Mutex
	routes map[string]string
	calls  []string
}

func (dialer *routingDialer) DialContext(
	ctx context.Context,
	network string,
	address string,
) (net.Conn, error) {
	dialer.mu.Lock()
	dialer.calls = append(dialer.calls, address)
	destination := dialer.routes[address]
	dialer.mu.Unlock()
	if destination == "" {
		return nil, &net.DNSError{Err: "unroutable test destination", Name: "redacted.invalid"}
	}
	var networkDialer net.Dialer
	return networkDialer.DialContext(ctx, network, destination)
}

func (dialer *routingDialer) callSnapshot() []string {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	return append([]string(nil), dialer.calls...)
}

func staticResolver(values map[string][]netip.Addr) Resolver {
	return resolverFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" {
			return nil, &net.DNSError{Err: "unexpected network", Name: "redacted.invalid"}
		}
		return append([]netip.Addr(nil), values[host]...), nil
	})
}

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	testPKIOnce.Do(func() {
		_, rootKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			testPKIErr = err
			return
		}
		now := time.Now().UTC()
		rootTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "federatedhttp test root"},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
		if err != nil {
			testPKIErr = err
			return
		}
		root, err := x509.ParseCertificate(rootDER)
		if err != nil {
			testPKIErr = err
			return
		}

		_, leafKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			testPKIErr = err
			return
		}
		leafTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "provider.example"},
			DNSNames: []string{
				"provider.example",
				"redirect.example",
				"third.example",
			},
			NotBefore:   now.Add(-time.Hour),
			NotAfter:    now.Add(time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, leafKey.Public(), rootKey)
		if err != nil {
			testPKIErr = err
			return
		}
		testCert = tls.Certificate{
			Certificate: [][]byte{leafDER, rootDER},
			PrivateKey:  leafKey,
		}
		testRoots = x509.NewCertPool()
		testRoots.AddCert(root)
	})
	if testPKIErr != nil {
		t.Fatal(testPKIErr)
	}
	return testCert, testRoots.Clone()
}

func startTestTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	certificate, _ := testCertificate(t)
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.EnableHTTP2 = false
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func testLimits() Limits {
	limits := DefaultLimits()
	limits.ConnectTimeout = 500 * time.Millisecond
	limits.TLSHandshakeTimeout = 500 * time.Millisecond
	limits.ResponseHeaderTimeout = 500 * time.Millisecond
	limits.OperationTimeout = 2 * time.Second
	limits.MaxResponseHeaderBytes = 8 * 1024
	limits.MaxWireBytes = 8 * 1024
	limits.MaxDocumentBytes = 16 * 1024
	limits.DefaultCacheAge = time.Minute
	limits.MaxCacheAge = time.Hour
	return limits
}

func newTestClient(
	t *testing.T,
	resolver Resolver,
	dialer Dialer,
	mutateLimits func(*Limits),
) *Client {
	t.Helper()
	policy, err := NewDeploymentEgressPolicy(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, roots := testCertificate(t)
	limits := testLimits()
	if mutateLimits != nil {
		mutateLimits(&limits)
	}
	client, err := New(Options{
		Resolver:      resolver,
		Dialer:        dialer,
		EgressPolicy:  policy,
		RootCAs:       roots,
		Limits:        limits,
		MaxConcurrent: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func compileTestTarget(t *testing.T, client *Client, kind DocumentKind, rawURL string) Target {
	t.Helper()
	target, err := client.CompileTarget(kind, rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func documentHandler(contentType, body string) http.HandlerFunc {
	return func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", contentType)
		_, _ = response.Write([]byte(body))
	}
}
