package dfiradapter

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	dfir "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

const (
	testTenantID  = "018f0000-0000-7000-8000-000000000001"
	testStorageID = "018f0000-0000-7000-8000-000000000002"
)

func TestS3PresignBindsCanonicalLocationHeadersAndExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 25, 18, 0, 0, 0, time.UTC)
	config := testS3Config(t, "https://storage.example")
	config.publicEndpoint = mustEndpoint(t, "https://uploads.example")
	storage, err := newS3WithHTTPClient(config, &http.Client{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	location := testLocation()
	upload, err := storage.PrepareUpload(
		context.Background(),
		location,
		4_096,
		"application/octet-stream",
		now.Add(10*time.Minute),
	)
	if err != nil {
		t.Fatalf("PrepareUpload() error = %v", err)
	}
	if upload.Method != http.MethodPut || upload.ExpiresAt != now.Add(10*time.Minute) ||
		!strings.HasPrefix(upload.TargetURL, "https://uploads.example/") ||
		!headerEquals(upload.Headers, "Content-Length", "4096") ||
		!headerEquals(upload.Headers, "Content-Type", "application/octet-stream") ||
		!headerEquals(upload.Headers, "If-None-Match", "*") ||
		!headerEquals(upload.Headers, "X-Amz-Meta-Periapsis-Declared-Mime", "application/octet-stream") ||
		!headerEquals(upload.Headers, "X-Amz-Meta-Periapsis-Expected-Size", "4096") {
		t.Fatalf("upload grant lost signed invariants: %v", upload)
	}
	parsedUpload, err := url.Parse(upload.TargetURL)
	if err != nil {
		t.Fatal(err)
	}
	signedHeaders := ";" + parsedUpload.Query().Get("X-Amz-SignedHeaders") + ";"
	if !strings.Contains(signedHeaders, ";content-length;") ||
		!strings.Contains(signedHeaders, ";if-none-match;") ||
		!strings.Contains(signedHeaders, ";x-amz-meta-periapsis-declared-mime;") ||
		!strings.Contains(signedHeaders, ";x-amz-meta-periapsis-expected-size;") {
		t.Fatalf("presigned request omitted create-only or exact-size signed headers: %q", signedHeaders)
	}
	if strings.Contains(upload.String(), "X-Amz-Credential") || strings.Contains(upload.String(), testStorageID) {
		t.Fatal("upload formatter exposed its signed capability")
	}

	download, err := storage.PrepareDownload(
		context.Background(),
		location,
		now.Add(4*time.Minute),
	)
	if err != nil {
		t.Fatalf("PrepareDownload() error = %v", err)
	}
	if download.ExpiresAt != now.Add(4*time.Minute) ||
		strings.Contains(download.String(), "X-Amz-Credential") ||
		!strings.Contains(download.TargetURL, "response-content-disposition=attachment") {
		t.Fatalf("download grant invariants failed: %v", download)
	}
}

func TestS3RejectsOversizeBeforeCallingPresigner(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	storage := &S3Storage{
		objects: &fakeS3Objects{},
		presigner: &fakeS3Presigner{put: func(
			context.Context,
			*s3.PutObjectInput,
			...func(*s3.PresignOptions),
		) (*v4.PresignedHTTPRequest, error) {
			calls.Add(1)
			return nil, nil
		}},
		endpoint: mustEndpoint(t, "https://storage.example"),
		bucket:   "periapsis-evidence",
		maximum:  8 * 1024 * 1024,
		clock:    time.Now,
	}
	if _, err := storage.PrepareUpload(
		context.Background(),
		testLocation(),
		storage.maximum+1,
		"application/octet-stream",
		time.Now().Add(time.Minute),
	); err == nil {
		t.Fatal("PrepareUpload accepted a size above the configured bound")
	}
	if calls.Load() != 0 {
		t.Fatal("oversize request reached the signer")
	}
}

func TestPresignedExpiryAndHostValidationIsExactAndBounded(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"https://storage.example/bucket/key?X-Amz-Expires=0",
		"https://storage.example/bucket/key?X-Amz-Expires=901",
		"https://storage.example/bucket/key?X-Amz-Expires=090",
		"https://storage.example/bucket/key?X-Amz-Expires=90&X-Amz-Expires=90",
	} {
		if validPresignedExpiry(raw, 90*time.Second, uploadExpiryLimit) {
			t.Fatalf("invalid presigned expiry %q succeeded", raw)
		}
	}
	if !validPresignedExpiry(
		"https://storage.example/bucket/key?X-Amz-Expires=90",
		90*time.Second,
		uploadExpiryLimit,
	) {
		t.Fatal("canonical presigned expiry was rejected")
	}
	if signedHostEquals(http.Header{"Host": {"attacker.example"}}, "storage.example") ||
		signedHostEquals(http.Header{"Host": {"storage.example", "attacker.example"}}, "storage.example") {
		t.Fatal("ambiguous signed host was accepted")
	}
}

func TestS3OpenRequiresExactPayloadBoundSize(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		actual       int64
		expectedText string
	}{
		{name: "oversized", actual: 10, expectedText: "9"},
		{name: "truncated", actual: 8, expectedText: "9"},
		{name: "missing", actual: 9, expectedText: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &trackedBody{Reader: bytes.NewReader(make([]byte, test.actual))}
			contentType := "application/octet-stream"
			metadata := map[string]string{declaredMIMEMetadata: contentType}
			if test.expectedText != "" {
				metadata[expectedSizeMetadata] = test.expectedText
			}
			objects := &fakeS3Objects{get: func(
				context.Context,
				*s3.GetObjectInput,
				...func(*s3.Options),
			) (*s3.GetObjectOutput, error) {
				return &s3.GetObjectOutput{
					Body: body, ContentLength: &test.actual, ContentType: &contentType,
					Metadata: metadata,
				}, nil
			}}
			storage := testStorageWithObjects(t, objects)
			if _, err := storage.Open(context.Background(), testLocation()); err == nil {
				t.Fatal("Open accepted an object whose length did not equal the signed expected size")
			}
			if !body.closed.Load() {
				t.Fatal("Open did not close a rejected object body")
			}
		})
	}
}

func TestS3OpenRequiresSignedDeclaredMIME(t *testing.T) {
	t.Parallel()
	actual := int64(9)
	actualContentType := "application/octet-stream"
	for _, test := range []struct {
		name         string
		declaredMIME string
		wantError    bool
	}{
		{name: "missing", wantError: true},
		{name: "malformed", declaredMIME: "not a media type", wantError: true},
		{name: "signed declaration differs from untrusted content type", declaredMIME: "text/plain"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &trackedBody{Reader: bytes.NewReader(make([]byte, actual))}
			metadata := map[string]string{expectedSizeMetadata: "9"}
			if test.declaredMIME != "" {
				metadata[declaredMIMEMetadata] = test.declaredMIME
			}
			objects := &fakeS3Objects{get: func(
				context.Context,
				*s3.GetObjectInput,
				...func(*s3.Options),
			) (*s3.GetObjectOutput, error) {
				return &s3.GetObjectOutput{
					Body: body, ContentLength: &actual, ContentType: &actualContentType,
					Metadata: metadata,
				}, nil
			}}
			reader, err := testStorageWithObjects(t, objects).Open(context.Background(), testLocation())
			if test.wantError {
				if err == nil || !body.closed.Load() {
					t.Fatalf("Open() = (%v, %v), body closed = %t", reader, err, body.closed.Load())
				}
				return
			}
			if err != nil || reader.DeclaredMIME != test.declaredMIME || reader.ContentType != actualContentType {
				t.Fatalf("Open() = (%v, %v), want declared MIME %q", reader, err, test.declaredMIME)
			}
			_ = reader.Body.Close()
		})
	}
}

func TestS3UsesPinnedTLSHTTPBoundaryForReadinessOpenAndDelete(t *testing.T) {
	t.Parallel()
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Header.Get("Authorization") == "" {
			http.Error(response, "missing signature", http.StatusForbidden)
			return
		}
		switch request.Method {
		case http.MethodHead:
			response.WriteHeader(http.StatusOK)
		case http.MethodGet:
			response.Header().Set("Content-Type", "application/octet-stream")
			response.Header().Set("X-Amz-Meta-Periapsis-Expected-Size", "15")
			response.Header().Set("X-Amz-Meta-Periapsis-Declared-Mime", "application/octet-stream")
			_, _ = response.Write([]byte("forensic-object"))
		case http.MethodDelete:
			response.WriteHeader(http.StatusNoContent)
		default:
			http.Error(response, "method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	endpoint := mustEndpoint(t, "https://example.com:"+port)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	httpClient, err := newHTTPClientWithNetwork(
		endpoint,
		egressPolicy{},
		roots,
		4,
		staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}},
		routingDialer{target: server.Listener.Addr().String()},
	)
	if err != nil {
		t.Fatal(err)
	}
	config := testS3Config(t, endpoint.canonical)
	storage, err := newS3WithHTTPClient(config, httpClient, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := storage.Check(ctx); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	reader, err := storage.Open(ctx, testLocation())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	value, err := io.ReadAll(reader.Body)
	_ = reader.Body.Close()
	if err != nil || string(value) != "forensic-object" {
		t.Fatalf("object = %q, %v", value, err)
	}
	if reader.DeclaredMIME != "application/octet-stream" {
		t.Fatalf("declared MIME = %q", reader.DeclaredMIME)
	}
	if err := storage.Delete(ctx, testLocation()); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if requests.Load() != 3 {
		t.Fatalf("requests = %d, want 3", requests.Load())
	}
}

func TestEgressRejectsMixedDNSAnswersBeforeDial(t *testing.T) {
	t.Parallel()
	endpoint := mustEndpoint(t, "https://storage.example")
	var dials atomic.Int64
	boundary := endpointDialer{
		endpoint: endpoint,
		policy:   egressPolicy{},
		resolver: staticResolver{addresses: []netip.Addr{
			netip.MustParseAddr("93.184.216.34"),
			netip.MustParseAddr("169.254.169.254"),
		}},
		dialer:         countingDialer{calls: &dials},
		connectTimeout: time.Second,
	}
	if _, err := boundary.DialContext(context.Background(), "tcp", "storage.example:443"); err == nil {
		t.Fatal("mixed allowed/metadata DNS answer reached the dialer")
	}
	if dials.Load() != 0 {
		t.Fatal("blocked DNS response opened a connection")
	}
}

func testS3Config(t *testing.T, rawEndpoint string) S3Config {
	t.Helper()
	endpoint := mustEndpoint(t, rawEndpoint)
	roots, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	return S3Config{
		endpoint:          endpoint,
		publicEndpoint:    endpoint,
		region:            "eu-south-1",
		bucket:            "periapsis-evidence",
		accessKeyID:       "ACCESS-CANARY",
		secretAccessKey:   "SECRET-CANARY-0123456789",
		rootCAs:           roots,
		policy:            egressPolicy{},
		maximumObjectSize: 32 * 1024 * 1024,
		maxConcurrent:     4,
	}
}

func testStorageWithObjects(t *testing.T, objects s3ObjectAPI) *S3Storage {
	t.Helper()
	return &S3Storage{
		objects:   objects,
		presigner: &fakeS3Presigner{},
		endpoint:  mustEndpoint(t, "https://storage.example"),
		bucket:    "periapsis-evidence",
		maximum:   32 * 1024 * 1024,
		clock:     time.Now,
	}
}

func mustEndpoint(t *testing.T, value string) compiledEndpoint {
	t.Helper()
	endpoint, err := compileHTTPEndpoint(value, false)
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}

func testLocation() dfir.ObjectLocation {
	return dfir.ObjectLocation{
		Bucket: "periapsis-evidence",
		Key:    testTenantID + "/" + testStorageID,
	}
}

type fakeS3Objects struct {
	get        func(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	headObject func(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	head       func(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	delete     func(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

func (fake *fakeS3Objects) GetObject(ctx context.Context, input *s3.GetObjectInput, options ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if fake.get == nil {
		return nil, ErrStorageUnavailable
	}
	return fake.get(ctx, input, options...)
}
func (fake *fakeS3Objects) HeadObject(ctx context.Context, input *s3.HeadObjectInput, options ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if fake.headObject == nil {
		return nil, ErrStorageUnavailable
	}
	return fake.headObject(ctx, input, options...)
}
func (fake *fakeS3Objects) HeadBucket(ctx context.Context, input *s3.HeadBucketInput, options ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	if fake.head == nil {
		return nil, ErrStorageUnavailable
	}
	return fake.head(ctx, input, options...)
}
func (fake *fakeS3Objects) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput, options ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	if fake.delete == nil {
		return nil, ErrStorageUnavailable
	}
	return fake.delete(ctx, input, options...)
}

type fakeS3Presigner struct {
	put func(context.Context, *s3.PutObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
	get func(context.Context, *s3.GetObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

func (fake *fakeS3Presigner) PresignPutObject(ctx context.Context, input *s3.PutObjectInput, options ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	if fake.put == nil {
		return nil, ErrStorageUnavailable
	}
	return fake.put(ctx, input, options...)
}
func (fake *fakeS3Presigner) PresignGetObject(ctx context.Context, input *s3.GetObjectInput, options ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	if fake.get == nil {
		return nil, ErrStorageUnavailable
	}
	return fake.get(ctx, input, options...)
}

type trackedBody struct {
	*bytes.Reader
	closed atomic.Bool
}

func (body *trackedBody) Close() error {
	body.closed.Store(true)
	return nil
}

type staticResolver struct {
	addresses []netip.Addr
	err       error
}

func (resolver staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), resolver.addresses...), resolver.err
}

type routingDialer struct {
	target string
}

func (dialer routingDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	var networkDialer net.Dialer
	return networkDialer.DialContext(ctx, network, dialer.target)
}

type countingDialer struct {
	calls *atomic.Int64
}

func (dialer countingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	dialer.calls.Add(1)
	return nil, ErrEgressRejected
}
