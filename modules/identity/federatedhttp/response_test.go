package federatedhttp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestFetchAcceptsOnlyKindSpecificMediaTypes(t *testing.T) {
	cases := []struct {
		kind        DocumentKind
		contentType string
		want        Category
	}{
		{DocumentOIDCDiscovery, "application/json", CategorySuccess},
		{DocumentOIDCDiscovery, "application/jwk-set+json", CategoryMediaTypeRejected},
		{DocumentOIDCJWKS, "application/jwk-set+json; charset=UTF-8", CategorySuccess},
		{DocumentOIDCJWKS, "application/json", CategorySuccess},
		{DocumentSAMLMetadata, "application/samlmetadata+xml", CategorySuccess},
		{DocumentSAMLMetadata, "application/xml; charset=utf-8", CategorySuccess},
		{DocumentSAMLMetadata, "text/xml", CategorySuccess},
		{DocumentSAMLMetadata, "text/html", CategoryMediaTypeRejected},
		{DocumentOIDCDiscovery, "application/json; profile=secret", CategoryMediaTypeRejected},
		{DocumentOIDCDiscovery, "", CategoryMediaTypeRejected},
	}
	for _, testCase := range cases {
		t.Run(testCase.kind.String()+"/"+testCase.contentType, func(t *testing.T) {
			server := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				if testCase.contentType != "" {
					response.Header().Set("Content-Type", testCase.contentType)
				}
				_, _ = io.WriteString(response, `{}`)
			}))
			dialer := &routingDialer{routes: map[string]string{
				"93.184.216.34:443": server.Listener.Addr().String(),
			}}
			client := newTestClient(t, staticResolver(map[string][]netip.Addr{
				"provider.example": {netip.MustParseAddr("93.184.216.34")},
			}), dialer, nil)
			target := compileTestTarget(t, client, testCase.kind, "https://provider.example/document")
			result, err := client.Fetch(context.Background(), target, nil)
			if err != nil || result.Category != testCase.want {
				t.Fatalf("Fetch() = %v, %v", result, err)
			}
			assertSanitizedFailure(t, result)
		})
	}
}

func TestFetchEnforcesWireAndDocumentBounds(t *testing.T) {
	gzipBomb := gzipBytes(t, bytes.Repeat([]byte("x"), minimumDocumentBytes+1))
	concatenated := append(gzipBytes(t, []byte(`{"first":true}`)), gzipBytes(t, []byte(`{"second":true}`))...)
	cases := []struct {
		name     string
		headers  http.Header
		body     []byte
		mutate   func(*Limits)
		category Category
	}{
		{
			name: "declared length",
			headers: http.Header{
				"Content-Type":   {"application/json"},
				"Content-Length": {"2048"},
			},
			body: bytes.Repeat([]byte("x"), 2048),
			mutate: func(limits *Limits) {
				limits.MaxWireBytes = minimumDocumentBytes
				limits.MaxDocumentBytes = minimumDocumentBytes
			},
			category: CategoryLimitExceeded,
		},
		{
			name: "streamed wire",
			headers: http.Header{
				"Content-Type": {"application/json"},
			},
			body: bytes.Repeat([]byte("x"), minimumDocumentBytes+1),
			mutate: func(limits *Limits) {
				limits.MaxWireBytes = minimumDocumentBytes
				limits.MaxDocumentBytes = minimumDocumentBytes
			},
			category: CategoryLimitExceeded,
		},
		{
			name: "gzip bomb",
			headers: http.Header{
				"Content-Type":     {"application/json"},
				"Content-Encoding": {"gzip"},
			},
			body: gzipBomb,
			mutate: func(limits *Limits) {
				limits.MaxWireBytes = minimumDocumentBytes
				limits.MaxDocumentBytes = minimumDocumentBytes
			},
			category: CategoryLimitExceeded,
		},
		{
			name: "concatenated gzip",
			headers: http.Header{
				"Content-Type":     {"application/json"},
				"Content-Encoding": {"gzip"},
			},
			body:     concatenated,
			category: CategoryEncodingRejected,
		},
		{
			name: "unsupported encoding",
			headers: http.Header{
				"Content-Type":     {"application/json"},
				"Content-Encoding": {"br"},
			},
			body:     []byte(`{}`),
			category: CategoryEncodingRejected,
		},
		{
			name: "multiple encodings",
			headers: http.Header{
				"Content-Type":     {"application/json"},
				"Content-Encoding": {"gzip, identity"},
			},
			body:     []byte(`{}`),
			category: CategoryEncodingRejected,
		},
		{
			name: "empty encoding",
			headers: http.Header{
				"Content-Type":     {"application/json"},
				"Content-Encoding": {""},
			},
			body:     []byte(`{}`),
			category: CategoryEncodingRejected,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				for name, values := range testCase.headers {
					for _, value := range values {
						response.Header().Add(name, value)
					}
				}
				if testCase.name == "streamed wire" {
					response.Header().Set("Transfer-Encoding", "chunked")
				}
				response.WriteHeader(http.StatusOK)
				_, _ = response.Write(testCase.body)
			}))
			dialer := &routingDialer{routes: map[string]string{
				"93.184.216.34:443": server.Listener.Addr().String(),
			}}
			client := newTestClient(t, staticResolver(map[string][]netip.Addr{
				"provider.example": {netip.MustParseAddr("93.184.216.34")},
			}), dialer, testCase.mutate)
			target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example/document")
			result, err := client.Fetch(context.Background(), target, nil)
			if err != nil || result.Category != testCase.category {
				t.Fatalf("Fetch() = %v, %v", result, err)
			}
			assertSanitizedFailure(t, result)
		})
	}
}

func TestFetchReturnsOwnedBodyDigestAndBoundedCacheDecision(t *testing.T) {
	source := []byte(`{"issuer":"https://provider.example"}`)
	want := append([]byte(nil), source...)
	server := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "max-age=999999999")
		_, _ = response.Write(source)
		clear(source)
	}))
	dialer := &routingDialer{routes: map[string]string{
		"93.184.216.34:443": server.Listener.Addr().String(),
	}}
	client := newTestClient(t, staticResolver(map[string][]netip.Addr{
		"provider.example": {netip.MustParseAddr("93.184.216.34")},
	}), dialer, nil)
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example/document")
	result, err := client.Fetch(context.Background(), target, nil)
	if err != nil || result.Category != CategorySuccess {
		t.Fatalf("Fetch() = %v, %v", result, err)
	}
	if !bytes.Equal(result.Body, want) || result.Digest != sha256.Sum256(want) {
		t.Fatalf("body/digest mismatch: %v", result)
	}
	if !result.Cache.Cacheable || result.Cache.MustRevalidate ||
		result.Cache.FreshUntil.Sub(result.Cache.RetrievedAt) != time.Hour ||
		result.Cache.RetrievedAt.Location() != time.UTC || result.Cache.RetrievedAt.Nanosecond()%1_000 != 0 {
		t.Fatalf("cache metadata was not capped: %v", result.Cache)
	}
	result.Body[0] = 'X'
	if bytes.Equal(result.Body, want) {
		t.Fatal("result body test did not mutate its owned copy")
	}
}

func TestFetchCacheFailClosedCases(t *testing.T) {
	cases := []struct {
		name      string
		headers   http.Header
		cacheable bool
	}{
		{
			name:      "no store",
			headers:   http.Header{"Cache-Control": {"no-store, max-age=60"}},
			cacheable: false,
		},
		{
			name:      "malformed max age",
			headers:   http.Header{"Cache-Control": {"max-age=01"}},
			cacheable: true,
		},
		{
			name:      "pragma no cache",
			headers:   http.Header{"Pragma": {"no-cache"}},
			cacheable: true,
		},
		{
			name: "conflicting age",
			headers: http.Header{
				"Cache-Control": {"max-age=60"},
				"Age":           {"1", "2"},
			},
			cacheable: true,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				for name, values := range testCase.headers {
					for _, value := range values {
						response.Header().Add(name, value)
					}
				}
				_, _ = io.WriteString(response, `{}`)
			}))
			dialer := &routingDialer{routes: map[string]string{
				"93.184.216.34:443": server.Listener.Addr().String(),
			}}
			client := newTestClient(t, staticResolver(map[string][]netip.Addr{
				"provider.example": {netip.MustParseAddr("93.184.216.34")},
			}), dialer, nil)
			target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example/document")
			result, err := client.Fetch(context.Background(), target, nil)
			if err != nil || result.Category != CategorySuccess {
				t.Fatalf("Fetch() = %v, %v", result, err)
			}
			if result.Cache.Cacheable != testCase.cacheable || !result.Cache.MustRevalidate ||
				!result.Cache.FreshUntil.Equal(result.Cache.RetrievedAt) {
				t.Fatalf("cache did not fail closed: %v", result.Cache)
			}
		})
	}
}

func TestFetchRejectsStatusAndMultipleContentTypesWithoutBodyProjection(t *testing.T) {
	secret := "response-body-secret-canary"
	cases := []http.Handler{
		http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "text/plain")
			response.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(response, secret)
		}),
		http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Add("Content-Type", "application/json")
			response.Header().Add("Content-Type", "text/plain")
			_, _ = io.WriteString(response, secret)
		}),
	}
	wants := []Category{CategoryHTTPStatusRejected, CategoryMediaTypeRejected}
	for index, handler := range cases {
		server := startTestTLSServer(t, handler)
		dialer := &routingDialer{routes: map[string]string{
			"93.184.216.34:443": server.Listener.Addr().String(),
		}}
		client := newTestClient(t, staticResolver(map[string][]netip.Addr{
			"provider.example": {netip.MustParseAddr("93.184.216.34")},
		}), dialer, nil)
		target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example/document")
		result, err := client.Fetch(context.Background(), target, nil)
		if err != nil || result.Category != wants[index] {
			t.Fatalf("case %d Fetch() = %v, %v", index, result, err)
		}
		assertSanitizedFailure(t, result)
		if bytes.Contains([]byte(result.String()), []byte(secret)) {
			t.Fatalf("response body leaked through result formatting: %v", result)
		}
	}
}

func TestFetchBoundsResponseHeaders(t *testing.T) {
	server := startTestTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("X-Untrusted", string(bytes.Repeat([]byte("x"), 2*minimumHeaderBytes)))
		_, _ = io.WriteString(response, `{}`)
	}))
	dialer := &routingDialer{routes: map[string]string{
		"93.184.216.34:443": server.Listener.Addr().String(),
	}}
	client := newTestClient(t, staticResolver(map[string][]netip.Addr{
		"provider.example": {netip.MustParseAddr("93.184.216.34")},
	}), dialer, func(limits *Limits) {
		limits.MaxResponseHeaderBytes = minimumHeaderBytes
	})
	target := compileTestTarget(t, client, DocumentOIDCDiscovery, "https://provider.example/document")
	result, err := client.Fetch(context.Background(), target, nil)
	if err != nil || result.Category == CategorySuccess {
		t.Fatalf("Fetch() = %v, %v", result, err)
	}
	assertSanitizedFailure(t, result)
}

func gzipBytes(t *testing.T, value []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	if _, err := writer.Write(value); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func assertSanitizedFailure(t *testing.T, result Result) {
	t.Helper()
	if result.Category == CategorySuccess {
		return
	}
	if result.Body != nil || result.Digest != ([sha256.Size]byte{}) || result.Cache != (CacheMetadata{}) {
		t.Fatalf("failure retained document state: %v", result)
	}
}
