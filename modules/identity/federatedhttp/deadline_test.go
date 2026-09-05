package federatedhttp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
)

func TestFetchHonorsCallerCancellationDuringResolution(t *testing.T) {
	entered := make(chan struct{})
	resolver := resolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		close(entered)
		<-ctx.Done()
		return nil, errors.New("resolver-secret-canary")
	})
	client := newTestClient(
		t,
		resolver,
		dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("must not dial")
		}),
		nil,
	)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example")
	ctx, cancel := context.WithCancel(context.Background())
	resultChannel := make(chan Result, 1)
	errorChannel := make(chan error, 1)
	go func() {
		result, err := client.Fetch(ctx, target, nil)
		resultChannel <- result
		errorChannel <- err
	}()
	<-entered
	cancel()
	result := <-resultChannel
	if err := <-errorChannel; err != nil || result.Category != CategoryCancelled {
		t.Fatalf("Fetch() = %v, %v", result, err)
	}
}

func TestFetchAppliesConnectTimeout(t *testing.T) {
	client := newTestClient(
		t,
		staticResolver(map[string][]netip.Addr{
			"provider.example": {netip.MustParseAddr("93.184.216.34")},
		}),
		dialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}),
		func(limits *Limits) { limits.ConnectTimeout = minimumPhaseTimeout },
	)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example")
	result, err := client.Fetch(context.Background(), target, nil)
	if err != nil || result.Category != CategoryConnectTimeout {
		t.Fatalf("Fetch() = %v, %v", result, err)
	}
}

func TestFetchAppliesTLSHandshakeTimeout(t *testing.T) {
	dialer := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		clientSide, serverSide := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, serverSide)
			_ = serverSide.Close()
		}()
		return clientSide, nil
	})
	client := newTestClient(
		t,
		staticResolver(map[string][]netip.Addr{
			"provider.example": {netip.MustParseAddr("93.184.216.34")},
		}),
		dialer,
		func(limits *Limits) { limits.TLSHandshakeTimeout = minimumPhaseTimeout },
	)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example")
	result, err := client.Fetch(context.Background(), target, nil)
	if err != nil || result.Category != CategoryTLSTimeout {
		t.Fatalf("Fetch() = %v, %v", result, err)
	}
}

func TestFetchAppliesResponseHeaderTimeout(t *testing.T) {
	server := startTestTLSServer(t, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	dialer := &routingDialer{routes: map[string]string{
		"93.184.216.34:443": server.Listener.Addr().String(),
	}}
	client := newTestClient(t, staticResolver(map[string][]netip.Addr{
		"provider.example": {netip.MustParseAddr("93.184.216.34")},
	}), dialer, func(limits *Limits) {
		limits.ResponseHeaderTimeout = minimumPhaseTimeout
	})
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example")
	result, err := client.Fetch(context.Background(), target, nil)
	if err != nil || result.Category != CategoryResponseHeaderTimeout {
		t.Fatalf("Fetch() = %v, %v", result, err)
	}
}

func TestFetchAppliesSharedOperationDeadlineWhileReading(t *testing.T) {
	server := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		response.(http.Flusher).Flush()
		<-request.Context().Done()
	}))
	dialer := &routingDialer{routes: map[string]string{
		"93.184.216.34:443": server.Listener.Addr().String(),
	}}
	client := newTestClient(t, staticResolver(map[string][]netip.Addr{
		"provider.example": {netip.MustParseAddr("93.184.216.34")},
	}), dialer, func(limits *Limits) {
		limits.ConnectTimeout = minimumPhaseTimeout
		limits.TLSHandshakeTimeout = minimumPhaseTimeout
		limits.ResponseHeaderTimeout = minimumPhaseTimeout
		limits.OperationTimeout = minimumTotalTimeout
	})
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example")
	result, err := client.Fetch(context.Background(), target, nil)
	if err != nil || result.Category != CategoryOperationTimeout {
		t.Fatalf("Fetch() = %v, %v", result, err)
	}
}

func TestFetchCancelsDedicatedConnectionDuringBodyRead(t *testing.T) {
	started := make(chan struct{})
	server := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		response.(http.Flusher).Flush()
		close(started)
		<-request.Context().Done()
	}))
	dialer := &routingDialer{routes: map[string]string{
		"93.184.216.34:443": server.Listener.Addr().String(),
	}}
	client := newTestClient(t, staticResolver(map[string][]netip.Addr{
		"provider.example": {netip.MustParseAddr("93.184.216.34")},
	}), dialer, nil)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example")
	ctx, cancel := context.WithCancel(context.Background())
	resultChannel := make(chan Result, 1)
	go func() {
		result, _ := client.Fetch(ctx, target, nil)
		resultChannel <- result
	}()
	<-started
	cancel()
	result := <-resultChannel
	if result.Category != CategoryCancelled {
		t.Fatalf("Fetch() = %v", result)
	}
}

func TestFetchConcurrencyBudgetFailsWithoutQueueing(t *testing.T) {
	entered := make(chan struct{})
	resolver := resolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	policy, err := NewDeploymentEgressPolicy(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, roots := testCertificate(t)
	client, err := New(Options{
		Resolver: resolver,
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
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = client.Fetch(ctx, target, nil)
		close(done)
	}()
	<-entered
	result, err := client.Fetch(context.Background(), target, nil)
	if !errors.Is(err, ErrBusy) || result.Category != "" || result.Kind != "" ||
		result.Redirects != 0 || result.Body != nil || result.Cache != (CacheMetadata{}) {
		t.Fatalf("concurrent Fetch() = %v, %v", result, err)
	}
	cancel()
	<-done
}
