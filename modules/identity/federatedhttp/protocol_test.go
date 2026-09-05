package federatedhttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

func TestFetchPreservesHostnameForTLSAndUsesNoEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy-secret-canary.invalid:8080")
	t.Setenv("https_proxy", "http://proxy-secret-canary.invalid:8080")
	seenSNI := make(chan string, 1)
	server := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		seenSNI <- request.TLS.ServerName
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{}`)
	}))
	dialer := &routingDialer{routes: map[string]string{
		"93.184.216.34:443": server.Listener.Addr().String(),
	}}
	client := newTestClient(
		t,
		staticResolver(map[string][]netip.Addr{
			"provider.example": {netip.MustParseAddr("93.184.216.34")},
		}),
		dialer,
		nil,
	)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example")
	result, err := client.Fetch(context.Background(), target, nil)
	if err != nil || result.Category != CategorySuccess {
		t.Fatalf("Fetch() = %v, %v", result, err)
	}
	if got := <-seenSNI; got != "provider.example" {
		t.Fatalf("TLS SNI = %q", got)
	}
	if calls := dialer.callSnapshot(); !slices.Equal(calls, []string{"93.184.216.34:443"}) {
		t.Fatalf("proxy or hostname was dialed: %v", calls)
	}
}

func TestFetchRejectsUntrustedCertificateWithoutDetails(t *testing.T) {
	secret := "certificate-secret-canary"
	server := startTestTLSServer(t, documentHandler("application/json", `{}`))
	client := newTestClient(
		t,
		staticResolver(map[string][]netip.Addr{
			"untrusted.example": {netip.MustParseAddr("93.184.216.34")},
		}),
		&routingDialer{routes: map[string]string{
			"93.184.216.34:443": server.Listener.Addr().String(),
		}},
		nil,
	)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://untrusted.example/"+secret)
	result, err := client.Fetch(context.Background(), target, nil)
	if err != nil || result.Category != CategoryCertificateRejected {
		t.Fatalf("Fetch() = %v, %v", result, err)
	}
	if strings.Contains(result.String(), secret) {
		t.Fatalf("certificate failure leaked target details: %v", result)
	}
}

func TestFetchFollowsBoundedRevalidatedDocumentRedirect(t *testing.T) {
	finalServer := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/final" || request.Header.Get("Authorization") != "" {
			t.Errorf("unexpected redirected request path or authorization")
		}
		response.Header().Set("Content-Type", "application/jwk-set+json; charset=utf-8")
		response.Header().Set("Cache-Control", "max-age=60, must-revalidate")
		_, _ = io.WriteString(response, `{"keys":[]}`)
	}))
	firstServer := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", "https://redirect.example/final")
		response.WriteHeader(http.StatusFound)
	}))
	dialer := &routingDialer{routes: map[string]string{
		"93.184.216.34:443": firstServer.Listener.Addr().String(),
		"93.184.216.35:443": finalServer.Listener.Addr().String(),
	}}
	client := newTestClient(
		t,
		staticResolver(map[string][]netip.Addr{
			"provider.example": {netip.MustParseAddr("93.184.216.34")},
			"redirect.example": {netip.MustParseAddr("93.184.216.35")},
		}),
		dialer,
		nil,
	)
	target := compileTestTarget(t, client, DocumentOIDCJWKS, "https://provider.example/keys")
	result, err := client.Fetch(context.Background(), target, nil)
	if err != nil || result.Category != CategorySuccess || result.Redirects != 1 ||
		string(result.Body) != `{"keys":[]}` || !result.Cache.MustRevalidate {
		t.Fatalf("Fetch() = %v, %v", result, err)
	}
	if calls := dialer.callSnapshot(); !slices.Equal(calls, []string{
		"93.184.216.34:443", "93.184.216.35:443",
	}) {
		t.Fatalf("redirect dial calls = %v", calls)
	}
}

func TestFetchRejectsRedirectLoopAndHopOverflow(t *testing.T) {
	server := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/loop-a":
			response.Header().Set("Location", "/loop-b")
		case "/loop-b":
			response.Header().Set("Location", "/loop-a")
		default:
			step := int(request.URL.Path[len("/hop-")] - '0')
			response.Header().Set("Location", fmt.Sprintf("/hop-%d", step+1))
		}
		response.WriteHeader(http.StatusTemporaryRedirect)
	}))
	dialer := &routingDialer{routes: map[string]string{
		"93.184.216.34:443": server.Listener.Addr().String(),
	}}
	client := newTestClient(
		t,
		staticResolver(map[string][]netip.Addr{
			"provider.example": {netip.MustParseAddr("93.184.216.34")},
		}),
		dialer,
		nil,
	)
	loop := compileTestTarget(t, client, DocumentSAMLMetadata, "https://provider.example/loop-a")
	result, err := client.Fetch(context.Background(), loop, nil)
	if err != nil || result.Category != CategoryRedirectRejected || result.Redirects != 1 {
		t.Fatalf("loop Fetch() = %v, %v", result, err)
	}
	hops := compileTestTarget(t, client, DocumentSAMLMetadata, "https://provider.example/hop-0")
	result, err = client.Fetch(context.Background(), hops, nil)
	if err != nil || result.Category != CategoryRedirectRejected || result.Redirects != maximumRedirects {
		t.Fatalf("hop Fetch() = %v, %v", result, err)
	}
}

func TestFetchRevalidatesRedirectDestinationEgress(t *testing.T) {
	server := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", "https://redirect.example/final")
		response.WriteHeader(http.StatusFound)
	}))
	dialer := &routingDialer{routes: map[string]string{
		"93.184.216.34:443": server.Listener.Addr().String(),
	}}
	client := newTestClient(
		t,
		staticResolver(map[string][]netip.Addr{
			"provider.example": {netip.MustParseAddr("93.184.216.34")},
			"redirect.example": {netip.MustParseAddr("169.254.169.254")},
		}),
		dialer,
		nil,
	)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example")
	result, err := client.Fetch(context.Background(), target, nil)
	if err != nil || result.Category != CategoryDestinationBlocked || result.Redirects != 1 {
		t.Fatalf("Fetch() = %v, %v", result, err)
	}
	if calls := dialer.callSnapshot(); len(calls) != 1 {
		t.Fatalf("blocked redirect was dialed: %v", calls)
	}
}

func TestCredentialBearingFetchNeverRedirectsOrForwards(t *testing.T) {
	secret := []byte("Bearer credential-secret-canary")
	secondRequests := atomic.Int32{}
	secondServer := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		secondRequests.Add(1)
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{}`)
	}))
	firstServer := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer credential-secret-canary" {
			t.Errorf("credential was not sent exactly to the initial origin")
		}
		response.Header().Set("Location", "https://redirect.example/final")
		response.WriteHeader(http.StatusFound)
	}))
	dialer := &routingDialer{routes: map[string]string{
		"93.184.216.34:443": firstServer.Listener.Addr().String(),
		"93.184.216.35:443": secondServer.Listener.Addr().String(),
	}}
	client := newTestClient(
		t,
		staticResolver(map[string][]netip.Addr{
			"provider.example": {netip.MustParseAddr("93.184.216.34")},
			"redirect.example": {netip.MustParseAddr("93.184.216.35")},
		}),
		dialer,
		nil,
	)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example")
	result, err := client.Fetch(context.Background(), target, secret)
	if err != nil || result.Category != CategoryRedirectRejected || result.Redirects != 0 {
		t.Fatalf("Fetch() = %v, %v", result, err)
	}
	if secondRequests.Load() != 0 || len(dialer.callSnapshot()) != 1 {
		t.Fatal("credential-bearing redirect reached another origin")
	}
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatalf("authorization ownership was not cleared: %q", secret)
	}
}

func TestCredentialBearingSuccessIsNeverCacheable(t *testing.T) {
	server := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = io.WriteString(response, `{}`)
	}))
	dialer := &routingDialer{routes: map[string]string{
		"93.184.216.34:443": server.Listener.Addr().String(),
	}}
	client := newTestClient(t, staticResolver(map[string][]netip.Addr{
		"provider.example": {netip.MustParseAddr("93.184.216.34")},
	}), dialer, nil)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example")
	authorization := []byte("Bearer credential-secret-canary")
	result, err := client.Fetch(context.Background(), target, authorization)
	if err != nil || result.Category != CategorySuccess || result.Cache.Cacheable ||
		!result.Cache.MustRevalidate || !result.Cache.FreshUntil.Equal(result.Cache.RetrievedAt) {
		t.Fatalf("Fetch() = %v, %v", result, err)
	}
}

func TestInvalidAuthorizationIsClearedAndRedacted(t *testing.T) {
	client := newTestClient(
		t,
		staticResolver(nil),
		dialerFunc(func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unused") }),
		nil,
	)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example")
	for _, raw := range [][]byte{
		[]byte("credential-secret-canary"),
		[]byte("Bad: credential-secret-canary"),
		{'B', 'e', 'a', 'r', 'e', 'r', ' ', 0x7f},
	} {
		secret := append([]byte(nil), raw...)
		_, err := client.Fetch(context.Background(), target, secret)
		if !errors.Is(err, ErrInvalidAuthorization) || strings.Contains(err.Error(), "canary") {
			t.Fatalf("invalid authorization error = %v", err)
		}
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatalf("invalid authorization was not cleared: %q", secret)
		}
	}
}
