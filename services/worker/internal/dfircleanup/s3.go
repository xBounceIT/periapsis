package dfircleanup

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

type s3DeleteAPI interface {
	ListObjectVersions(context.Context, *s3.ListObjectVersionsInput, ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

type S3Config struct {
	endpoint      compiledEndpoint
	region        string
	bucket        string
	accessKey     string
	secretKey     string
	sessionToken  string
	rootCAs       *x509.CertPool
	privateCIDRs  []netip.Prefix
	maxConcurrent int
	expectedOwner string
}

func (S3Config) String() string          { return "dfircleanup.S3Config{[REDACTED]}" }
func (config S3Config) GoString() string { return config.String() }

// ClearSecrets releases the source credential strings after client
// construction. The AWS credentials provider owns the only remaining copy
// needed for signed requests.
func (config *S3Config) ClearSecrets() {
	if config == nil {
		return
	}
	config.accessKey = ""
	config.secretKey = ""
	config.sessionToken = ""
}

type S3Deleter struct {
	api           s3DeleteAPI
	bucket        string
	expectedOwner *string
}

func (*S3Deleter) String() string           { return "dfircleanup.S3Deleter{[REDACTED]}" }
func (deleter *S3Deleter) GoString() string { return deleter.String() }

func LoadS3Config(environment string) (S3Config, error) {
	return loadS3Config(environment, os.LookupEnv, os.ReadFile)
}

func loadS3Config(
	environment string,
	lookup func(string) (string, bool),
	readFile func(string) ([]byte, error),
) (S3Config, error) {
	if lookup == nil || readFile == nil ||
		(environment != "production" && environment != "development" && environment != "test") {
		return S3Config{}, ErrInvalidConfiguration
	}
	production := environment == "production"
	allowPlaintext, err := readStrictBool(lookup, "PERIAPSIS_S3_ALLOW_PLAINTEXT_LOCAL", false)
	if err != nil || production && allowPlaintext {
		return S3Config{}, ErrInvalidConfiguration
	}
	endpointText, ok := readValue(lookup, "PERIAPSIS_S3_ENDPOINT")
	if !ok {
		return S3Config{}, ErrInvalidConfiguration
	}
	endpoint, err := compileEndpoint(endpointText, allowPlaintext)
	if err != nil || production && endpoint.scheme != "https" {
		return S3Config{}, ErrInvalidConfiguration
	}
	region, regionOK := readValue(lookup, "PERIAPSIS_S3_REGION")
	bucket, bucketOK := readValue(lookup, "PERIAPSIS_S3_BUCKET")
	if !regionOK || !validRegion(region) || !bucketOK || !validBucket(bucket) {
		return S3Config{}, ErrInvalidConfiguration
	}
	accessKey, err := readSecret(lookup, readFile, "PERIAPSIS_S3_ACCESS_KEY", production, true, 3, 128)
	if err != nil {
		return S3Config{}, ErrInvalidConfiguration
	}
	secretKey, err := readSecret(lookup, readFile, "PERIAPSIS_S3_SECRET_KEY", production, true, 16, 512)
	if err != nil {
		return S3Config{}, ErrInvalidConfiguration
	}
	sessionToken, err := readSecret(lookup, readFile, "PERIAPSIS_S3_SESSION_TOKEN", production, false, 0, 4096)
	if err != nil || !visibleASCII(accessKey) || !visibleASCII(secretKey) ||
		sessionToken != "" && !visibleASCII(sessionToken) {
		return S3Config{}, ErrInvalidConfiguration
	}
	privateCIDRs, err := readPrivateCIDRs(lookup)
	if err != nil {
		return S3Config{}, ErrInvalidConfiguration
	}
	if literal, parseErr := netip.ParseAddr(endpoint.host); parseErr == nil &&
		!addressAllowed(literal, privateCIDRs) {
		return S3Config{}, ErrInvalidConfiguration
	}
	rootCAs, err := readRootCAs(lookup, readFile)
	if err != nil {
		return S3Config{}, ErrInvalidConfiguration
	}
	maximum, err := readStrictInt(lookup, "PERIAPSIS_S3_MAX_CONCURRENT", 16, 1, 128)
	if err != nil {
		return S3Config{}, ErrInvalidConfiguration
	}
	expectedOwner := ""
	if value, present := lookup("PERIAPSIS_TICKET_EXPORT_EXPECTED_BUCKET_OWNER"); present && value != "" {
		if len(value) != 12 || strings.Trim(value, "0123456789") != "" {
			return S3Config{}, ErrInvalidConfiguration
		}
		expectedOwner = value
	}
	return S3Config{
		endpoint: endpoint, region: region, bucket: bucket,
		accessKey: accessKey, secretKey: secretKey, sessionToken: sessionToken,
		rootCAs: rootCAs, privateCIDRs: privateCIDRs, maxConcurrent: maximum,
		expectedOwner: expectedOwner,
	}, nil
}

func NewS3Deleter(config S3Config) (*S3Deleter, error) {
	api, err := NewS3Client(config)
	if err != nil {
		return nil, err
	}
	return newS3Deleter(api, config.bucket, config.expectedOwner)
}

// NewS3DeleterFromClient shares one endpoint-pinned S3 client with the scan
// runtime while keeping cleanup's key and bucket validation intact.
func NewS3DeleterFromClient(api *s3.Client, bucket, expectedOwner string) (*S3Deleter, error) {
	return newS3Deleter(api, bucket, expectedOwner)
}

// NewS3Client builds the single bounded, endpoint-pinned S3 client shared by
// storage runtimes. Callers cannot override endpoint routing, redirects,
// retries, request logging, or checksum policy after construction.
func NewS3Client(config S3Config) (*s3.Client, error) {
	defer config.ClearSecrets()
	client, err := newBoundedS3HTTPClient(config)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	endpoint := config.endpoint.canonical
	awsConfig := aws.Config{
		Region: config.region,
		Credentials: credentials.NewStaticCredentialsProvider(
			config.accessKey, config.secretKey, config.sessionToken,
		),
		HTTPClient: client, RetryMaxAttempts: 3, RetryMode: aws.RetryModeStandard,
		BaseEndpoint: &endpoint, AppID: "periapsis-worker-storage", ClientLogMode: 0,
		DisableRequestCompression:  true,
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}
	api := s3.NewFromConfig(awsConfig, func(options *s3.Options) {
		options.BaseEndpoint = &endpoint
		options.UsePathStyle = true
		options.UseAccelerate = false
		options.UseARNRegion = false
		options.DisableMultiRegionAccessPoints = true
		options.DisableS3ExpressSessionAuth = aws.Bool(true)
		options.RetryMaxAttempts = 3
		options.RetryMode = aws.RetryModeStandard
	})
	return api, nil
}

// Bucket returns the validated configured bucket without exposing credentials
// or endpoint policy.
func (config S3Config) Bucket() string { return config.bucket }

// CloseS3Client releases idle transport connections during graceful process
// shutdown. In-flight requests remain governed by their cancelled contexts.
func CloseS3Client(client *s3.Client) {
	if client == nil {
		return
	}
	if closer, ok := client.Options().HTTPClient.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func newS3Deleter(api s3DeleteAPI, bucket, expectedOwner string) (*S3Deleter, error) {
	if api == nil || !validBucket(bucket) ||
		expectedOwner != "" && (len(expectedOwner) != 12 || strings.Trim(expectedOwner, "0123456789") != "") {
		return nil, ErrInvalidConfiguration
	}
	var owner *string
	if expectedOwner != "" {
		owner = aws.String(expectedOwner)
	}
	return &S3Deleter{api: api, bucket: bucket, expectedOwner: owner}, nil
}

const (
	maximumVersionPages = 16
	versionsPerPage     = int32(1000)
)

type objectVersion struct {
	key       string
	versionID string
}

func (deleter *S3Deleter) Check(ctx context.Context) error {
	if deleter == nil || deleter.api == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	readinessKey := "019d0200-0001-7001-8001-000000000001/019d0200-0002-7002-8002-000000000002"
	result, err := deleter.api.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
		Bucket: aws.String(deleter.bucket), Prefix: aws.String(readinessKey),
		MaxKeys: aws.Int32(1), ExpectedBucketOwner: deleter.expectedOwner,
	})
	if err != nil || result == nil {
		return ErrUnavailable
	}
	return nil
}

func (deleter *S3Deleter) Delete(ctx context.Context, location ObjectLocation) error {
	if deleter == nil || deleter.api == nil || ctx == nil || ctx.Err() != nil ||
		location.Bucket != deleter.bucket || !validObjectKey(location.Key) {
		return ErrUnavailable
	}
	versions, err := deleter.listExactVersions(ctx, location)
	if err != nil {
		return ErrUnavailable
	}
	for _, version := range versions {
		result, deleteErr := deleter.api.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(location.Bucket), Key: aws.String(version.key),
			VersionId: aws.String(version.versionID), ExpectedBucketOwner: deleter.expectedOwner,
		})
		if deleteErr != nil || result == nil {
			return ErrUnavailable
		}
	}
	remaining, err := deleter.listExactVersions(ctx, location)
	if err != nil || len(remaining) != 0 {
		return ErrUnavailable
	}
	return nil
}

func (deleter *S3Deleter) listExactVersions(ctx context.Context, location ObjectLocation) ([]objectVersion, error) {
	versions := make([]objectVersion, 0, 4)
	var keyMarker, versionMarker *string
	seenMarkers := make(map[string]struct{}, maximumVersionPages)
	for page := 0; page < maximumVersionPages; page++ {
		result, err := deleter.api.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: aws.String(location.Bucket), Prefix: aws.String(location.Key),
			KeyMarker: keyMarker, VersionIdMarker: versionMarker,
			MaxKeys: aws.Int32(versionsPerPage), ExpectedBucketOwner: deleter.expectedOwner,
		})
		if err != nil || result == nil || result.IsTruncated == nil {
			return nil, ErrUnavailable
		}
		for _, version := range result.Versions {
			if err := appendExactVersion(&versions, location.Key, version.Key, version.VersionId); err != nil {
				return nil, err
			}
		}
		for _, marker := range result.DeleteMarkers {
			if err := appendExactVersion(&versions, location.Key, marker.Key, marker.VersionId); err != nil {
				return nil, err
			}
		}
		if !*result.IsTruncated {
			return versions, nil
		}
		if result.NextKeyMarker == nil || result.NextVersionIdMarker == nil ||
			*result.NextKeyMarker == "" || *result.NextVersionIdMarker == "" {
			return nil, ErrUnavailable
		}
		marker := *result.NextKeyMarker + "\x00" + *result.NextVersionIdMarker
		if _, duplicate := seenMarkers[marker]; duplicate {
			return nil, ErrUnavailable
		}
		seenMarkers[marker] = struct{}{}
		keyMarker = result.NextKeyMarker
		versionMarker = result.NextVersionIdMarker
	}
	return nil, ErrUnavailable
}

func appendExactVersion(result *[]objectVersion, expectedKey string, key, versionID *string) error {
	if key == nil || versionID == nil || !safeVersionID(*versionID) {
		return ErrUnavailable
	}
	if *key == expectedKey {
		*result = append(*result, objectVersion{key: *key, versionID: *versionID})
	}
	return nil
}

func safeVersionID(value string) bool {
	return value != "" && len(value) <= 1024 && utf8.ValidString(value) &&
		!strings.ContainsAny(value, "\r\n\x00")
}

func validObjectKey(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || len(value) > 1024 {
		return false
	}
	for _, part := range parts {
		parsed, err := uuid.Parse(part)
		if err != nil || parsed.Version() != 7 || parsed.String() != part {
			return false
		}
	}
	return true
}

type compiledEndpoint struct {
	scheme    string
	host      string
	port      uint16
	canonical string
}

func compileEndpoint(raw string, allowPlaintext bool) (compiledEndpoint, error) {
	if !safeText(raw, 2048) {
		return compiledEndpoint{}, ErrInvalidConfiguration
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || (parsed.Scheme != "https" && !(allowPlaintext && parsed.Scheme == "http")) {
		return compiledEndpoint{}, ErrInvalidConfiguration
	}
	host := parsed.Hostname()
	if !validHost(host) {
		return compiledEndpoint{}, ErrInvalidConfiguration
	}
	defaultPort := uint16(443)
	if parsed.Scheme == "http" {
		defaultPort = 80
	}
	port := defaultPort
	if portText := parsed.Port(); portText != "" {
		value, parseErr := strconv.ParseUint(portText, 10, 16)
		if parseErr != nil || value == 0 || uint16(value) == defaultPort || strconv.FormatUint(value, 10) != portText {
			return compiledEndpoint{}, ErrInvalidConfiguration
		}
		port = uint16(value)
	}
	authority := host
	if address, parseErr := netip.ParseAddr(host); parseErr == nil && address.Is6() {
		authority = "[" + host + "]"
	}
	if port != defaultPort {
		authority = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	if parsed.Host != authority || raw != parsed.Scheme+"://"+authority {
		return compiledEndpoint{}, ErrInvalidConfiguration
	}
	return compiledEndpoint{scheme: parsed.Scheme, host: host, port: port, canonical: raw}, nil
}

func newBoundedS3HTTPClient(config S3Config) (*http.Client, error) {
	if config.endpoint.canonical == "" || config.rootCAs == nil ||
		config.maxConcurrent < 1 || config.maxConcurrent > 128 {
		return nil, ErrInvalidConfiguration
	}
	boundary := &endpointDialer{
		endpoint: config.endpoint, privateCIDRs: slices.Clone(config.privateCIDRs),
		resolver: net.DefaultResolver,
		dialer:   &net.Dialer{KeepAlive: 30 * time.Second},
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: boundary.DialContext, ForceAttemptHTTP2: false,
		DisableCompression: true, MaxIdleConns: config.maxConcurrent,
		MaxIdleConnsPerHost: config.maxConcurrent, MaxConnsPerHost: config.maxConcurrent,
		IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second, ExpectContinueTimeout: time.Second,
		MaxResponseHeaderBytes: 64 * 1024,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: config.rootCAs.Clone(),
			NextProtos: []string{"http/1.1"},
		},
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrUnavailable },
	}, nil
}

type endpointDialer struct {
	endpoint     compiledEndpoint
	privateCIDRs []netip.Prefix
	resolver     interface {
		LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
	}
	dialer interface {
		DialContext(context.Context, string, string) (net.Conn, error)
	}
}

func (boundary *endpointDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if boundary == nil || ctx == nil || network != "tcp" || boundary.resolver == nil || boundary.dialer == nil {
		return nil, ErrUnavailable
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != boundary.endpoint.host || port != strconv.Itoa(int(boundary.endpoint.port)) {
		return nil, ErrUnavailable
	}
	connectContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := boundary.resolve(connectContext)
	if err != nil {
		return nil, ErrUnavailable
	}
	for _, candidate := range addresses {
		connection, dialErr := boundary.dialer.DialContext(
			connectContext, "tcp", net.JoinHostPort(candidate.String(), port),
		)
		if dialErr == nil && connection != nil {
			return connection, nil
		}
		if connection != nil {
			_ = connection.Close()
		}
	}
	return nil, ErrUnavailable
}

func (boundary *endpointDialer) resolve(ctx context.Context) ([]netip.Addr, error) {
	addresses := []netip.Addr(nil)
	if literal, err := netip.ParseAddr(boundary.endpoint.host); err == nil {
		addresses = []netip.Addr{literal}
	} else {
		resolved, lookupErr := boundary.resolver.LookupNetIP(ctx, "ip", boundary.endpoint.host)
		if lookupErr != nil || len(resolved) == 0 || len(resolved) > 16 {
			return nil, ErrUnavailable
		}
		addresses = resolved
	}
	validated := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if !addressAllowed(address, boundary.privateCIDRs) ||
			boundary.endpoint.scheme == "http" && !address.IsPrivate() {
			return nil, ErrUnavailable
		}
		if _, duplicate := seen[address]; !duplicate {
			seen[address] = struct{}{}
			validated = append(validated, address)
		}
	}
	slices.SortFunc(validated, netip.Addr.Compare)
	return validated, nil
}

var privateNetworks = [...]netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7"),
}

var blockedNetworks = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("168.63.129.16/32"), netip.MustParsePrefix("169.254.169.254/32"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
}

func addressAllowed(address netip.Addr, privateCIDRs []netip.Prefix) bool {
	if !address.IsValid() || address.Zone() != "" || address.Is4In6() {
		return false
	}
	for _, blocked := range blockedNetworks {
		if blocked.Contains(address) {
			return false
		}
	}
	if address.IsPrivate() {
		for _, allowed := range privateCIDRs {
			if allowed.Contains(address) {
				return true
			}
		}
		return false
	}
	return address.IsGlobalUnicast()
}

func readPrivateCIDRs(lookup func(string) (string, bool)) ([]netip.Prefix, error) {
	raw, present := lookup("PERIAPSIS_DFIR_PRIVATE_EGRESS_CIDRS")
	if !present || raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 64 {
		return nil, ErrInvalidConfiguration
	}
	result := make([]netip.Prefix, 0, len(parts))
	seen := make(map[netip.Prefix]struct{}, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(part)
		if err != nil || part != prefix.String() || prefix != prefix.Masked() || !privateSubprefix(prefix) {
			return nil, ErrInvalidConfiguration
		}
		if _, duplicate := seen[prefix]; duplicate {
			return nil, ErrInvalidConfiguration
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	slices.SortFunc(result, func(left, right netip.Prefix) int {
		if compared := left.Addr().Compare(right.Addr()); compared != 0 {
			return compared
		}
		return left.Bits() - right.Bits()
	})
	return result, nil
}

func privateSubprefix(candidate netip.Prefix) bool {
	for _, network := range privateNetworks {
		if candidate.Addr().BitLen() == network.Addr().BitLen() &&
			candidate.Bits() >= network.Bits() && network.Contains(candidate.Addr()) {
			return true
		}
	}
	return false
}

func validHost(value string) bool {
	if value == "" || len(value) > 253 || strings.ToLower(value) != value || strings.HasSuffix(value, ".") {
		return false
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == "" && !address.Is4In6() && address.String() == value
	}
	if looksLikeAmbiguousAddress(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range label {
			character := label[index]
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

// looksLikeAmbiguousAddress rejects legacy numeric forms that some resolvers
// interpret as IP literals even though netip does not. The compiled target and
// the address ultimately dialed must have identical meaning.
func looksLikeAmbiguousAddress(value string) bool {
	decimalOrDot := true
	for index := range value {
		if value[index] != '.' && (value[index] < '0' || value[index] > '9') {
			decimalOrDot = false
			break
		}
	}
	if decimalOrDot {
		return true
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) <= 2 || !strings.HasPrefix(label, "0x") {
			continue
		}
		hexadecimal := true
		for index := 2; index < len(label); index++ {
			character := label[index]
			if (character < '0' || character > '9') &&
				(character < 'a' || character > 'f') {
				hexadecimal = false
				break
			}
		}
		if hexadecimal {
			return true
		}
	}
	return false
}

func validRegion(value string) bool {
	if value == "" || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := range value {
		if character := value[index]; (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func readValue(lookup func(string) (string, bool), name string) (string, bool) {
	value, present := lookup(name)
	return value, present && safeText(value, 4096)
}

func safeText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func visibleASCII(value string) bool {
	for index := range value {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func readSecret(
	lookup func(string) (string, bool),
	readFile func(string) ([]byte, error),
	name string,
	production bool,
	required bool,
	minimum int,
	maximum int,
) (string, error) {
	direct, directSet := lookup(name)
	fileName, fileSet := lookup(name + "_FILE")
	directSet = directSet && direct != ""
	fileSet = fileSet && fileName != ""
	if directSet && fileSet || production && directSet || production && required && !fileSet ||
		fileSet && !validSecretFile(fileName) {
		return "", ErrInvalidConfiguration
	}
	var value []byte
	if fileSet {
		contents, err := readFile(fileName)
		if err != nil || len(contents) > 64*1024 {
			clear(contents)
			return "", ErrInvalidConfiguration
		}
		defer clear(contents)
		value = bytes.TrimSuffix(contents, []byte{'\n'})
		value = bytes.TrimSuffix(value, []byte{'\r'})
	} else if directSet {
		value = []byte(direct)
	}
	if len(value) == 0 && !required {
		return "", nil
	}
	if len(value) < minimum || len(value) > maximum || !utf8.Valid(value) {
		return "", ErrInvalidConfiguration
	}
	return string(value), nil
}

func validSecretFile(value string) bool {
	if value == "" || len(value) > 1024 || value[0] != '/' || strings.Contains(value, "//") ||
		strings.ContainsRune(value, '\\') || strings.TrimSpace(value) != value {
		return false
	}
	for _, segment := range strings.Split(value[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func readRootCAs(
	lookup func(string) (string, bool),
	readFile func(string) ([]byte, error),
) (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return nil, ErrInvalidConfiguration
	}
	fileName, present := lookup("PERIAPSIS_S3_CA_BUNDLE_FILE")
	if !present || fileName == "" {
		return roots, nil
	}
	if !validSecretFile(fileName) {
		return nil, ErrInvalidConfiguration
	}
	document, err := readFile(fileName)
	if err != nil || len(document) == 0 || len(document) > 1024*1024 || !roots.AppendCertsFromPEM(document) {
		clear(document)
		return nil, ErrInvalidConfiguration
	}
	clear(document)
	return roots, nil
}

func readStrictBool(lookup func(string) (string, bool), name string, fallback bool) (bool, error) {
	value, present := lookup(name)
	if !present || value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil || strconv.FormatBool(parsed) != value {
		return false, ErrInvalidConfiguration
	}
	return parsed, nil
}

func readStrictInt(lookup func(string) (string, bool), name string, fallback, minimum, maximum int) (int, error) {
	value, present := lookup(name)
	if !present || value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum || strconv.Itoa(parsed) != value {
		return 0, ErrInvalidConfiguration
	}
	return parsed, nil
}

var _ ObjectDeleter = (*S3Deleter)(nil)
