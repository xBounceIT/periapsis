package federatedhttp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestExecuteUsesPinnedTransportAndClearsOwnedMaterial(t *testing.T) {
	var receivedMethod, receivedAuthorization, receivedBody string
	server := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		receivedMethod = request.Method
		receivedAuthorization = request.Header.Get("Authorization")
		body, _ := io.ReadAll(request.Body)
		receivedBody = string(body)
		response.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(response, `{"ok":true}`)
	}))
	dialer := &routingDialer{routes: map[string]string{
		"93.184.216.34:443": server.Listener.Addr().String(),
	}}
	client := newTestClient(t, staticResolver(map[string][]netip.Addr{
		"provider.example": {netip.MustParseAddr("93.184.216.34")},
	}), dialer, nil)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example/token")
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	authorization := append([]byte("Basic "), []byte(base64.StdEncoding.EncodeToString(random))...)
	body := []byte("grant_type=authorization_code")
	wantAuthorization, wantBody := string(authorization), string(body)
	result, err := client.Execute(context.Background(), OperationRequest{
		Kind: OperationOIDCToken, Target: target, Authorization: authorization,
		Body: body, MaxResponseBytes: 1024,
	})
	if err != nil || result.Category != CategorySuccess || result.StatusCode != http.StatusOK ||
		string(result.Body) != `{"ok":true}` {
		t.Fatalf("Execute() = %v, %v", result, err)
	}
	if receivedMethod != http.MethodPost || receivedAuthorization != wantAuthorization || receivedBody != wantBody {
		t.Fatalf("request shape = method %q authorization match %t body match %t",
			receivedMethod, receivedAuthorization == wantAuthorization, receivedBody == wantBody)
	}
	if !allZeroBytes(authorization) || !allZeroBytes(body) {
		t.Fatal("owned credential-bearing slices were not cleared")
	}
	if strings.Contains(result.String(), string(result.Body)) {
		t.Fatal("operation result formatting exposed body")
	}
}

func TestExecuteNeverFollowsCredentialBearingRedirect(t *testing.T) {
	var calls atomic.Int32
	server := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		response.Header().Set("Location", "/second")
		response.WriteHeader(http.StatusFound)
	}))
	dialer := &routingDialer{routes: map[string]string{
		"93.184.216.34:443": server.Listener.Addr().String(),
	}}
	client := newTestClient(t, staticResolver(map[string][]netip.Addr{
		"provider.example": {netip.MustParseAddr("93.184.216.34")},
	}), dialer, nil)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example/token")
	result, err := client.Execute(context.Background(), OperationRequest{
		Kind: OperationOIDCToken, Target: target, Body: []byte("x=y"), MaxResponseBytes: 1024,
	})
	if err != nil || result.Category != CategoryHTTPStatusRejected || result.StatusCode != http.StatusFound || calls.Load() != 1 {
		t.Fatalf("Execute() = %v, %v, calls=%d", result, err, calls.Load())
	}
}

func TestExecuteRejectsMediaEncodingAndResponseOverflow(t *testing.T) {
	tests := map[string]struct {
		headers  http.Header
		body     string
		maximum  int64
		expected Category
	}{
		"non JSON": {
			headers: http.Header{"Content-Type": {"text/html"}}, body: "x", maximum: 1024,
			expected: CategoryMediaTypeRejected,
		},
		"profile parameter": {
			headers: http.Header{"Content-Type": {"application/json; profile=unsafe"}}, body: `{}`, maximum: 1024,
			expected: CategoryMediaTypeRejected,
		},
		"content encoding": {
			headers: http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"gzip"}}, body: `{}`, maximum: 1024,
			expected: CategoryMediaTypeRejected,
		},
		"stream overflow": {
			headers: http.Header{"Content-Type": {"application/json"}}, body: strings.Repeat("x", 1025), maximum: 1024,
			expected: CategoryLimitExceeded,
		},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			server := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				for key, values := range testCase.headers {
					for _, value := range values {
						response.Header().Add(key, value)
					}
				}
				_, _ = io.WriteString(response, testCase.body)
			}))
			dialer := &routingDialer{routes: map[string]string{
				"93.184.216.34:443": server.Listener.Addr().String(),
			}}
			client := newTestClient(t, staticResolver(map[string][]netip.Addr{
				"provider.example": {netip.MustParseAddr("93.184.216.34")},
			}), dialer, nil)
			target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example/userinfo")
			random := make([]byte, 24)
			if _, err := rand.Read(random); err != nil {
				t.Fatal(err)
			}
			authorization := append([]byte("Bearer "), []byte(base64.RawURLEncoding.EncodeToString(random))...)
			result, err := client.Execute(context.Background(), OperationRequest{
				Kind: OperationOIDCUserInfo, Target: target,
				Authorization: authorization, MaxResponseBytes: testCase.maximum,
			})
			if err != nil || result.Category != testCase.expected || len(result.Body) != 0 {
				t.Fatalf("Execute() = %v, %v", result, err)
			}
		})
	}
}

func TestExecuteProvesCancellationDuringResolutionWasNotDispatched(t *testing.T) {
	entered := make(chan struct{})
	var once sync.Once
	client := newTestClient(t, resolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		return nil, ctx.Err()
	}), dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("must not dial")
	}), nil)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example/token")
	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan OperationResult, 1)
	go func() {
		result, _ := client.Execute(ctx, OperationRequest{
			Kind: OperationOIDCToken, Target: target, Body: []byte("x=y"), MaxResponseBytes: 1024,
		})
		results <- result
	}()
	<-entered
	cancel()
	result := <-results
	if result.Category != CategoryCancelled || !result.RequestNotDispatched {
		t.Fatalf("Execute() = %v", result)
	}
}

func TestOperationFailureBeforeDialSchedulingIsNotDispatched(t *testing.T) {
	evidence := &operationDispatchEvidence{}
	ctx, cancel := context.WithCancel(context.WithValue(
		context.Background(), operationDispatchEvidenceKey{}, evidence,
	))
	cancel()
	category, requestNotDispatched := operationRoundTripFailure(ctx, context.Canceled)
	if category != CategoryCancelled || !requestNotDispatched {
		t.Fatalf("operationRoundTripFailure() = %s, %t", category, requestNotDispatched)
	}
}

func TestExecuteDoesNotClaimPostDispatchCancellationIsSafe(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := startTestTLSServer(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
	}))
	dialer := &routingDialer{routes: map[string]string{
		"93.184.216.34:443": server.Listener.Addr().String(),
	}}
	client := newTestClient(t, staticResolver(map[string][]netip.Addr{
		"provider.example": {netip.MustParseAddr("93.184.216.34")},
	}), dialer, nil)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example/token")
	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan OperationResult, 1)
	go func() {
		result, _ := client.Execute(ctx, OperationRequest{
			Kind: OperationOIDCToken, Target: target, Body: []byte("x=y"), MaxResponseBytes: 1024,
		})
		results <- result
	}()
	<-started
	cancel()
	result := <-results
	close(release)
	if result.Category != CategoryCancelled || result.RequestNotDispatched {
		t.Fatalf("Execute() = %v", result)
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
