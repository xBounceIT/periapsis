package dfiradapter

import (
	"context"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	dfir "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

const (
	uploadExpiryLimit    = 15 * time.Minute
	downloadExpiryLimit  = 5 * time.Minute
	maximumGrantBytes    = 16 * 1024
	maximumMediaBytes    = 512
	maximumObjectKey     = 1_024
	expectedSizeMetadata = "periapsis-expected-size"
	declaredMIMEMetadata = "periapsis-declared-mime"
	createOnlyCondition  = "*"
)

type s3ObjectAPI interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

type s3PresignAPI interface {
	PresignPutObject(context.Context, *s3.PutObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
	PresignGetObject(context.Context, *s3.GetObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

// S3Storage is the production S3-compatible object adapter. Its client has no
// ambient credentials/proxy, redirects are rejected, and every connection is
// revalidated against the immutable deployment egress policy.
type S3Storage struct {
	objects             s3ObjectAPI
	presigner           s3PresignAPI
	endpoint            compiledEndpoint
	bucket              string
	maximum             int64
	clock               func() time.Time
	expectedBucketOwner *string
}

var (
	_ dfir.ObjectStorage = (*S3Storage)(nil)
	_ dfir.ObjectDeleter = (*S3Storage)(nil)
)

func (*S3Storage) String() string {
	return "dfiradapter.S3Storage{endpoint:[REDACTED],credentials:[REDACTED]}"
}
func (storage *S3Storage) GoString() string { return storage.String() }

func NewS3(config S3Config) (*S3Storage, error) {
	httpClient, err := newHTTPClient(
		config.endpoint,
		config.policy,
		config.rootCAs,
		config.maxConcurrent,
	)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return newS3WithHTTPClient(config, httpClient, time.Now)
}

func newS3WithHTTPClient(config S3Config, httpClient *http.Client, clock func() time.Time) (*S3Storage, error) {
	if httpClient == nil || clock == nil || config.endpoint.canonical == "" || config.publicEndpoint.canonical == "" ||
		!validBucket(config.bucket) || !regionPattern.MatchString(config.region) ||
		!validVisibleASCII(config.accessKeyID) || !validVisibleASCII(config.secretAccessKey) ||
		config.maximumObjectSize < minimumConfiguredObjectBytes || config.maximumObjectSize > SinglePutMaximumBytes {
		return nil, ErrInvalidConfig
	}
	baseEndpoint := config.endpoint.canonical
	awsConfig := aws.Config{
		Region: config.region,
		Credentials: credentials.NewStaticCredentialsProvider(
			config.accessKeyID,
			config.secretAccessKey,
			config.sessionToken,
		),
		HTTPClient:                 httpClient,
		RetryMaxAttempts:           3,
		RetryMode:                  aws.RetryModeStandard,
		BaseEndpoint:               &baseEndpoint,
		AppID:                      "periapsis-dfir",
		ClientLogMode:              0,
		DisableRequestCompression:  true,
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}
	clientOptions := func(endpoint string) func(*s3.Options) {
		return func(options *s3.Options) {
			options.BaseEndpoint = &endpoint
			options.UsePathStyle = true
			options.UseAccelerate = false
			options.UseARNRegion = false
			options.DisableMultiRegionAccessPoints = true
			options.DisableS3ExpressSessionAuth = aws.Bool(true)
			options.RetryMaxAttempts = 3
			options.RetryMode = aws.RetryModeStandard
		}
	}
	client := s3.NewFromConfig(awsConfig, clientOptions(baseEndpoint))
	publicEndpoint := config.publicEndpoint.canonical
	presignClient := s3.NewFromConfig(awsConfig, clientOptions(publicEndpoint))
	var expectedBucketOwner *string
	if config.expectedOwner != "" {
		expectedBucketOwner = aws.String(config.expectedOwner)
	}
	return &S3Storage{
		objects: client, presigner: s3.NewPresignClient(presignClient), endpoint: config.publicEndpoint,
		bucket: config.bucket, maximum: config.maximumObjectSize, clock: clock,
		expectedBucketOwner: expectedBucketOwner,
	}, nil
}

func (storage *S3Storage) PrepareUpload(
	ctx context.Context,
	location dfir.ObjectLocation,
	sizeBytes int64,
	contentType string,
	expiresAt time.Time,
) (dfir.UploadGrant, error) {
	if !storage.valid() || ctx == nil || ctx.Err() != nil || !storage.validLocation(location) ||
		sizeBytes <= 0 || sizeBytes > storage.maximum || !validMediaType(contentType) {
		return dfir.UploadGrant{}, ErrStorageUnavailable
	}
	now := storage.clock().UTC()
	lifetime := expiresAt.Sub(now)
	if lifetime <= 0 || lifetime > uploadExpiryLimit {
		return dfir.UploadGrant{}, ErrStorageUnavailable
	}
	sizeText := strconv.FormatInt(sizeBytes, 10)
	request, err := storage.presigner.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket:             aws.String(location.Bucket),
		Key:                aws.String(location.Key),
		ContentLength:      aws.Int64(sizeBytes),
		ContentType:        aws.String(contentType),
		CacheControl:       aws.String("no-store"),
		ContentDisposition: aws.String("attachment"),
		IfNoneMatch:        aws.String(createOnlyCondition),
		Metadata: map[string]string{
			expectedSizeMetadata: sizeText,
			declaredMIMEMetadata: contentType,
		},
	}, func(options *s3.PresignOptions) {
		options.Expires = lifetime
	})
	if err != nil || request == nil || request.Method != http.MethodPut ||
		!signedHostEquals(request.SignedHeader, endpointAuthority(storage.endpoint)) ||
		!validPresignedExpiry(request.URL, lifetime, uploadExpiryLimit) ||
		!storage.validPresignedTarget(request.URL, location) {
		return dfir.UploadGrant{}, ErrStorageUnavailable
	}
	headers, err := uploadHeaders(request.SignedHeader, contentType, sizeText)
	if err != nil {
		return dfir.UploadGrant{}, ErrStorageUnavailable
	}
	return dfir.UploadGrant{
		TargetURL: request.URL,
		Method:    http.MethodPut,
		Headers:   headers,
		ExpiresAt: expiresAt.UTC(),
	}, nil
}

func (storage *S3Storage) PrepareDownload(
	ctx context.Context,
	location dfir.ObjectLocation,
	expiresAt time.Time,
) (dfir.DownloadGrant, error) {
	if !storage.valid() || ctx == nil || ctx.Err() != nil || !storage.validLocation(location) {
		return dfir.DownloadGrant{}, ErrStorageUnavailable
	}
	now := storage.clock().UTC()
	lifetime := expiresAt.Sub(now)
	if lifetime <= 0 || lifetime > downloadExpiryLimit {
		return dfir.DownloadGrant{}, ErrStorageUnavailable
	}
	request, err := storage.presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket:                     aws.String(location.Bucket),
		Key:                        aws.String(location.Key),
		ResponseCacheControl:       aws.String("no-store"),
		ResponseContentDisposition: aws.String("attachment"),
		ResponseContentType:        aws.String("application/octet-stream"),
	}, func(options *s3.PresignOptions) {
		options.Expires = lifetime
	})
	if err != nil || request == nil || request.Method != http.MethodGet ||
		!onlyHostHeader(request.SignedHeader, endpointAuthority(storage.endpoint)) ||
		!validPresignedExpiry(request.URL, lifetime, downloadExpiryLimit) ||
		!storage.validPresignedTarget(request.URL, location) {
		return dfir.DownloadGrant{}, ErrStorageUnavailable
	}
	return dfir.DownloadGrant{TargetURL: request.URL, ExpiresAt: expiresAt.UTC()}, nil
}

func onlyHostHeader(headers http.Header, expected string) bool {
	if len(headers) != 1 {
		return false
	}
	return signedHostEquals(headers, expected)
}

func signedHostEquals(headers http.Header, expected string) bool {
	values, present := headers["Host"]
	return present && len(values) == 1 && values[0] == expected
}

func validPresignedExpiry(raw string, requested, maximum time.Duration) bool {
	parsed, err := url.Parse(raw)
	if err != nil || requested <= 0 || maximum <= 0 || requested > maximum {
		return false
	}
	values := parsed.Query()["X-Amz-Expires"]
	if len(values) != 1 {
		return false
	}
	seconds, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || seconds < 1 || strconv.FormatInt(seconds, 10) != values[0] {
		return false
	}
	requestedCeiling := int64((requested + time.Second - 1) / time.Second)
	maximumSeconds := int64(maximum / time.Second)
	return seconds <= requestedCeiling && seconds <= maximumSeconds
}

func (storage *S3Storage) Open(ctx context.Context, location dfir.ObjectLocation) (dfir.ObjectReader, error) {
	if !storage.valid() || ctx == nil || ctx.Err() != nil || !storage.validLocation(location) {
		return dfir.ObjectReader{}, ErrStorageUnavailable
	}
	result, err := storage.objects.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(location.Bucket),
		Key:    aws.String(location.Key),
	})
	if err != nil || result == nil || result.Body == nil || result.ContentLength == nil ||
		*result.ContentLength < 0 || *result.ContentLength > storage.maximum || result.ContentEncoding != nil {
		if result != nil && result.Body != nil {
			_ = result.Body.Close()
		}
		return dfir.ObjectReader{}, ErrStorageUnavailable
	}
	expectedText, present := result.Metadata[expectedSizeMetadata]
	expectedSize, parseErr := strconv.ParseInt(expectedText, 10, 64)
	if !present || parseErr != nil || expectedSize <= 0 || expectedSize > storage.maximum ||
		*result.ContentLength != expectedSize {
		_ = result.Body.Close()
		return dfir.ObjectReader{}, ErrStorageUnavailable
	}
	declaredMIME, present := result.Metadata[declaredMIMEMetadata]
	if !present || !validMediaType(declaredMIME) {
		_ = result.Body.Close()
		return dfir.ObjectReader{}, ErrStorageUnavailable
	}
	contentType := ""
	if result.ContentType != nil {
		contentType = *result.ContentType
		if !validMediaType(contentType) {
			_ = result.Body.Close()
			return dfir.ObjectReader{}, ErrStorageUnavailable
		}
	}
	return dfir.ObjectReader{
		Body: result.Body, SizeBytes: *result.ContentLength,
		ContentType: contentType, DeclaredMIME: declaredMIME,
	}, nil
}

// Check performs a bounded authenticated bucket probe for startup/readiness.
func (storage *S3Storage) Check(ctx context.Context) error {
	if !storage.valid() || ctx == nil || ctx.Err() != nil {
		return ErrStorageUnavailable
	}
	result, err := storage.objects.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(storage.bucket)})
	if err != nil || result == nil {
		return ErrStorageUnavailable
	}
	return nil
}

// Delete is idempotent at the S3 protocol boundary and is intended only for a
// fenced orphan-cleanup worker.
func (storage *S3Storage) Delete(ctx context.Context, location dfir.ObjectLocation) error {
	if !storage.valid() || ctx == nil || ctx.Err() != nil || !storage.validLocation(location) {
		return ErrStorageUnavailable
	}
	result, err := storage.objects.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(location.Bucket),
		Key:    aws.String(location.Key),
	})
	if err != nil || result == nil {
		return ErrStorageUnavailable
	}
	return nil
}

func (storage *S3Storage) valid() bool {
	return storage != nil && storage.objects != nil && storage.presigner != nil && storage.clock != nil &&
		storage.endpoint.canonical != "" && validBucket(storage.bucket) &&
		storage.maximum >= minimumConfiguredObjectBytes && storage.maximum <= SinglePutMaximumBytes
}

func (storage *S3Storage) validLocation(location dfir.ObjectLocation) bool {
	if !storage.valid() || location.Bucket != storage.bucket || len(location.Key) == 0 ||
		len(location.Key) > maximumObjectKey || strings.TrimSpace(location.Key) != location.Key {
		return false
	}
	parts := strings.Split(location.Key, "/")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		parsed, err := uuid.Parse(part)
		if err != nil || parsed.String() != part {
			return false
		}
	}
	return true
}

func (storage *S3Storage) validPresignedTarget(raw string, location dfir.ObjectLocation) bool {
	if !storage.validLocation(location) {
		return false
	}
	return storage.validPresignedObjectTarget(raw, location.Bucket, location.Key)
}

func (storage *S3Storage) validPresignedObjectTarget(raw, bucket, key string) bool {
	if len(raw) == 0 || len(raw) > maximumGrantBytes || !utf8.ValidString(raw) {
		return false
	}
	for _, character := range raw {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != storage.endpoint.scheme || parsed.Host != endpointAuthority(storage.endpoint) ||
		parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery == "" {
		return false
	}
	wantPath := "/" + bucket + "/" + key
	return parsed.Path == wantPath && parsed.EscapedPath() == wantPath
}

func endpointAuthority(endpoint compiledEndpoint) string {
	authority := endpoint.host
	defaultPort := uint16(443)
	if endpoint.scheme == "http" {
		defaultPort = 80
	}
	if address, err := netip.ParseAddr(endpoint.host); err == nil && address.Is6() {
		authority = "[" + endpoint.host + "]"
	}
	if endpoint.port != defaultPort {
		authority = net.JoinHostPort(endpoint.host, strconv.Itoa(int(endpoint.port)))
	}
	return authority
}

func uploadHeaders(values http.Header, contentType, sizeText string) ([]dfir.UploadHeader, error) {
	if len(values) == 0 || len(values) > 16 {
		return nil, ErrStorageUnavailable
	}
	result := make([]dfir.UploadHeader, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for rawName, rawValues := range values {
		name := http.CanonicalHeaderKey(rawName)
		if name == "Host" {
			continue
		}
		if _, duplicate := seen[name]; duplicate || len(rawValues) != 1 || !allowedUploadHeader(name) ||
			!validHeaderValue(rawValues[0]) {
			return nil, ErrStorageUnavailable
		}
		seen[name] = struct{}{}
		result = append(result, dfir.UploadHeader{Name: name, Value: rawValues[0]})
	}
	if !headerEquals(result, "X-Amz-Meta-Periapsis-Expected-Size", sizeText) {
		return nil, ErrStorageUnavailable
	}
	if !headerEquals(result, "X-Amz-Meta-Periapsis-Declared-Mime", contentType) {
		return nil, ErrStorageUnavailable
	}
	if !headerEquals(result, "Content-Length", sizeText) {
		return nil, ErrStorageUnavailable
	}
	if !headerEquals(result, "If-None-Match", createOnlyCondition) {
		return nil, ErrStorageUnavailable
	}
	if headerValue, present := findHeader(result, "Content-Type"); present {
		if headerValue != contentType {
			return nil, ErrStorageUnavailable
		}
	} else {
		// The current AWS v2 presigner does not include Content-Type in
		// SignedHeader for PutObject. It remains an explicit browser hint;
		// the worker compares the signed declared-MIME metadata with the bytes
		// it independently detects from the exact object stream.
		result = append(result, dfir.UploadHeader{Name: "Content-Type", Value: contentType})
	}
	slices.SortFunc(result, func(left, right dfir.UploadHeader) int {
		return strings.Compare(left.Name, right.Name)
	})
	return result, nil
}

func allowedUploadHeader(name string) bool {
	switch name {
	case "Cache-Control", "Content-Disposition", "Content-Length", "Content-Type", "If-None-Match", "X-Amz-Meta-Periapsis-Declared-Mime", "X-Amz-Meta-Periapsis-Expected-Size":
		return true
	default:
		return false
	}
}

func headerEquals(headers []dfir.UploadHeader, name, value string) bool {
	actual, present := findHeader(headers, name)
	return present && actual == value
}

func findHeader(headers []dfir.UploadHeader, name string) (string, bool) {
	for _, header := range headers {
		if header.Name == name {
			return header.Value, true
		}
	}
	return "", false
}

func validHeaderValue(value string) bool {
	if len(value) > 4_096 || strings.TrimSpace(value) != value {
		return false
	}
	for index := range value {
		if value[index] < 0x20 || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func validMediaType(value string) bool {
	if value == "" || len(value) > maximumMediaBytes || strings.TrimSpace(value) != value {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(value)
	return err == nil && mediaType == strings.ToLower(mediaType) && len(parameters) <= 8
}
