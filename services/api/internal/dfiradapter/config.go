package dfiradapter

import (
	"bytes"
	"crypto/x509"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const SinglePutMaximumBytes int64 = 5_000_000_000

const minimumConfiguredObjectBytes int64 = 1024 * 1024

var (
	bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	regionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// Config contains the immutable deployment-owned storage and scanner
// configuration. Credential fields remain private and every formatter is
// redacted.
type Config struct {
	Storage S3Config
	Scanner ClamAVConfig
}

func (Config) String() string          { return "dfiradapter.Config{storage:[REDACTED],scanner:[REDACTED]}" }
func (config Config) GoString() string { return config.String() }

type S3Config struct {
	endpoint          compiledEndpoint
	publicEndpoint    compiledEndpoint
	region            string
	bucket            string
	expectedOwner     string
	accessKeyID       string
	secretAccessKey   string
	sessionToken      string
	rootCAs           *x509.CertPool
	policy            egressPolicy
	maximumObjectSize int64
	maxConcurrent     int
}

func (S3Config) String() string {
	return "dfiradapter.S3Config{endpoint:[REDACTED],credentials:[REDACTED]}"
}
func (config S3Config) GoString() string { return config.String() }
func (config S3Config) Bucket() string   { return config.bucket }
func (config S3Config) MaximumObjectBytes() int64 {
	return config.maximumObjectSize
}

type ClamAVConfig struct {
	endpoint          compiledEndpoint
	unixSocket        string
	rootCAs           *x509.CertPool
	policy            egressPolicy
	maximumObjectSize int64
	operationTimeout  time.Duration
}

func (ClamAVConfig) String() string          { return "dfiradapter.ClamAVConfig{endpoint:[REDACTED]}" }
func (config ClamAVConfig) GoString() string { return config.String() }

type configSource struct {
	lookup   func(string) (string, bool)
	readFile func(string) ([]byte, error)
}

// LoadConfig reads a closed set of PERIAPSIS_S3_* and PERIAPSIS_DFIR_* values.
// Production credentials must be supplied through *_FILE values; ambient AWS
// credential, proxy, endpoint, and trust configuration is never consulted.
func LoadConfig(environment string) (Config, error) {
	return loadConfigFrom(environment, configSource{lookup: os.LookupEnv, readFile: os.ReadFile})
}

func loadConfigFrom(environment string, source configSource) (Config, error) {
	if source.lookup == nil || source.readFile == nil ||
		(environment != "production" && environment != "development" && environment != "test") {
		return Config{}, ErrInvalidConfig
	}
	production := environment == "production"
	allowPlainStorage, err := source.boolean("PERIAPSIS_S3_ALLOW_PLAINTEXT_LOCAL", false)
	if err != nil || production && allowPlainStorage {
		return Config{}, ErrInvalidConfig
	}
	allowPlainScanner, err := source.boolean("PERIAPSIS_DFIR_SCANNER_ALLOW_PLAINTEXT_LOCAL", false)
	if err != nil || production && allowPlainScanner {
		return Config{}, ErrInvalidConfig
	}
	privateCIDRs, err := source.privateCIDRs("PERIAPSIS_DFIR_PRIVATE_EGRESS_CIDRS")
	if err != nil {
		return Config{}, ErrInvalidConfig
	}
	policy, err := newEgressPolicy(privateCIDRs)
	if err != nil {
		return Config{}, ErrInvalidConfig
	}
	maximumObjectSize, err := source.int64Value(
		"PERIAPSIS_DFIR_MAX_OBJECT_BYTES",
		SinglePutMaximumBytes,
		minimumConfiguredObjectBytes,
		SinglePutMaximumBytes,
	)
	if err != nil {
		return Config{}, ErrInvalidConfig
	}
	maxConcurrent, err := source.intValue("PERIAPSIS_S3_MAX_CONCURRENT", 16, 1, 128)
	if err != nil {
		return Config{}, ErrInvalidConfig
	}
	expectedOwner := ""
	if raw, present := source.lookup("PERIAPSIS_TICKET_EXPORT_EXPECTED_BUCKET_OWNER"); present {
		if !validExpectedBucketOwner(raw) {
			return Config{}, ErrInvalidConfig
		}
		expectedOwner = raw
	}

	storageEndpointText, ok := source.value("PERIAPSIS_S3_ENDPOINT")
	if !ok {
		return Config{}, ErrInvalidConfig
	}
	storageEndpoint, err := compileHTTPEndpoint(storageEndpointText, allowPlainStorage)
	if err != nil || production && storageEndpoint.scheme != "https" ||
		!literalEndpointAllowed(storageEndpoint, policy, storageEndpoint.scheme == "http") {
		return Config{}, ErrInvalidConfig
	}
	publicEndpointText, publicEndpointSet := source.value("PERIAPSIS_S3_PUBLIC_ENDPOINT")
	if !publicEndpointSet {
		publicEndpointText = storageEndpointText
	}
	publicEndpoint, err := compileHTTPEndpoint(publicEndpointText, allowPlainStorage)
	if err != nil || production && publicEndpoint.scheme != "https" {
		return Config{}, ErrInvalidConfig
	}
	region, regionOK := source.value("PERIAPSIS_S3_REGION")
	bucket, bucketOK := source.value("PERIAPSIS_S3_BUCKET")
	if !regionOK || !regionPattern.MatchString(region) || !bucketOK || !validBucket(bucket) {
		return Config{}, ErrInvalidConfig
	}
	accessKeyID, err := source.secret("PERIAPSIS_S3_ACCESS_KEY", production, true, 3, 128)
	if err != nil || !validVisibleASCII(accessKeyID) {
		return Config{}, ErrInvalidConfig
	}
	secretAccessKey, err := source.secret("PERIAPSIS_S3_SECRET_KEY", production, true, 16, 512)
	if err != nil || !validVisibleASCII(secretAccessKey) {
		return Config{}, ErrInvalidConfig
	}
	sessionToken, err := source.secret("PERIAPSIS_S3_SESSION_TOKEN", production, false, 0, 4_096)
	if err != nil || sessionToken != "" && !validVisibleASCII(sessionToken) {
		return Config{}, ErrInvalidConfig
	}
	storageRoots, err := source.rootCAs("PERIAPSIS_S3_CA_BUNDLE_FILE")
	if err != nil {
		return Config{}, ErrInvalidConfig
	}

	scannerText, scannerOK := source.value("PERIAPSIS_DFIR_SCANNER_ENDPOINT")
	if !scannerOK {
		return Config{}, ErrInvalidConfig
	}
	var scannerEndpoint compiledEndpoint
	var unixSocket string
	if strings.HasPrefix(scannerText, "unix://") {
		unixSocket, err = canonicalUnixSocket(scannerText)
	} else {
		scannerEndpoint, err = compileTCPScannerEndpoint(scannerText, allowPlainScanner)
		if err == nil && production && scannerEndpoint.scheme != "tls" {
			err = ErrInvalidConfig
		}
		if err == nil && !literalEndpointAllowed(scannerEndpoint, policy, scannerEndpoint.scheme == "tcp") {
			err = ErrInvalidConfig
		}
	}
	if err != nil {
		return Config{}, ErrInvalidConfig
	}
	scannerRoots, err := source.rootCAs("PERIAPSIS_DFIR_SCANNER_CA_BUNDLE_FILE")
	if err != nil {
		return Config{}, ErrInvalidConfig
	}
	scannerTimeout, err := source.durationValue(
		"PERIAPSIS_DFIR_SCANNER_TIMEOUT",
		5*time.Minute,
		10*time.Second,
		15*time.Minute,
	)
	if err != nil {
		return Config{}, ErrInvalidConfig
	}

	return Config{
		Storage: S3Config{
			endpoint: storageEndpoint, publicEndpoint: publicEndpoint, region: region, bucket: bucket,
			expectedOwner: expectedOwner,
			accessKeyID:   accessKeyID, secretAccessKey: secretAccessKey, sessionToken: sessionToken,
			rootCAs: storageRoots, policy: policy, maximumObjectSize: maximumObjectSize,
			maxConcurrent: maxConcurrent,
		},
		Scanner: ClamAVConfig{
			endpoint: scannerEndpoint, unixSocket: unixSocket, rootCAs: scannerRoots,
			policy: policy, maximumObjectSize: maximumObjectSize, operationTimeout: scannerTimeout,
		},
	}, nil
}

func literalEndpointAllowed(endpoint compiledEndpoint, policy egressPolicy, privateOnly bool) bool {
	address, err := netip.ParseAddr(endpoint.host)
	if err != nil {
		return true
	}
	return policy.addressAllowed(address) && (!privateOnly || address.IsPrivate())
}

func validBucket(value string) bool {
	if !bucketPattern.MatchString(value) || strings.Contains(value, "..") ||
		strings.Contains(value, ".-") || strings.Contains(value, "-.") ||
		looksLikeAmbiguousAddress(value) {
		return false
	}
	return true
}

func validExpectedBucketOwner(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func canonicalUnixSocket(raw string) (string, error) {
	const prefix = "unix://"
	if !validEndpointText(raw) || !strings.HasPrefix(raw, prefix) {
		return "", ErrInvalidConfig
	}
	socket := strings.TrimPrefix(raw, prefix)
	if len(socket) < 2 || len(socket) > 1_024 || socket[0] != '/' || strings.Contains(socket, "//") ||
		strings.ContainsRune(socket, '\\') {
		return "", ErrInvalidConfig
	}
	for _, segment := range strings.Split(socket[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", ErrInvalidConfig
		}
	}
	return socket, nil
}

func validVisibleASCII(value string) bool {
	for index := range value {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func (source configSource) value(name string) (string, bool) {
	raw, present := source.lookup(name)
	if !present || raw == "" || strings.TrimSpace(raw) != raw || !utf8.ValidString(raw) {
		return "", false
	}
	for _, character := range raw {
		if unicode.IsControl(character) {
			return "", false
		}
	}
	return raw, true
}

func (source configSource) secret(
	name string,
	production bool,
	required bool,
	minimum int,
	maximum int,
) (string, error) {
	direct, directSet := source.lookup(name)
	fileName, fileSet := source.lookup(name + "_FILE")
	directSet = directSet && direct != ""
	fileSet = fileSet && fileName != ""
	if directSet && fileSet || production && directSet || production && required && !fileSet ||
		fileSet && !validSecretFileName(fileName) {
		return "", ErrInvalidConfig
	}
	var value []byte
	if fileSet {
		contents, err := source.readFile(fileName)
		if err != nil || len(contents) > 64*1024 {
			clear(contents)
			return "", ErrInvalidConfig
		}
		defer clear(contents)
		value = trimSecretLineEnding(contents)
	} else if directSet {
		value = []byte(direct)
	}
	if len(value) == 0 {
		if required {
			return "", ErrInvalidConfig
		}
		return "", nil
	}
	if len(value) < minimum || len(value) > maximum || !utf8.Valid(value) {
		return "", ErrInvalidConfig
	}
	return string(value), nil
}

func validSecretFileName(value string) bool {
	if value == "" || len(value) > 1_024 || value[0] != '/' || strings.TrimSpace(value) != value ||
		strings.Contains(value, "//") || strings.ContainsRune(value, '\\') {
		return false
	}
	for _, segment := range strings.Split(value[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func trimSecretLineEnding(value []byte) []byte {
	if bytes.HasSuffix(value, []byte{'\r', '\n'}) {
		return value[:len(value)-2]
	}
	if bytes.HasSuffix(value, []byte{'\n'}) {
		return value[:len(value)-1]
	}
	return value
}

func (source configSource) boolean(name string, fallback bool) (bool, error) {
	value, present := source.lookup(name)
	if !present || value == "" {
		return fallback, nil
	}
	if strings.TrimSpace(value) != value {
		return false, ErrInvalidConfig
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, ErrInvalidConfig
	}
	return parsed, nil
}

func (source configSource) intValue(name string, fallback, minimum, maximum int) (int, error) {
	value, present := source.lookup(name)
	if !present || value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum || strconv.Itoa(parsed) != value {
		return 0, ErrInvalidConfig
	}
	return parsed, nil
}

func (source configSource) int64Value(name string, fallback, minimum, maximum int64) (int64, error) {
	value, present := source.lookup(name)
	if !present || value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < minimum || parsed > maximum || strconv.FormatInt(parsed, 10) != value {
		return 0, ErrInvalidConfig
	}
	return parsed, nil
}

func (source configSource) durationValue(
	name string,
	fallback time.Duration,
	minimum time.Duration,
	maximum time.Duration,
) (time.Duration, error) {
	value, present := source.lookup(name)
	if !present || value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, ErrInvalidConfig
	}
	return parsed, nil
}

func (source configSource) privateCIDRs(name string) ([]netip.Prefix, error) {
	value, present := source.lookup(name)
	if !present || value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > 64 {
		return nil, ErrInvalidConfig
	}
	result := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		if part == "" || strings.TrimSpace(part) != part {
			return nil, ErrInvalidConfig
		}
		prefix, err := netip.ParsePrefix(part)
		if err != nil || prefix.String() != part {
			return nil, ErrInvalidConfig
		}
		result = append(result, prefix)
	}
	return result, nil
}

func (source configSource) rootCAs(name string) (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return nil, ErrInvalidConfig
	}
	fileName, present := source.lookup(name)
	if !present || fileName == "" {
		return roots, nil
	}
	if strings.TrimSpace(fileName) != fileName {
		return nil, ErrInvalidConfig
	}
	document, err := source.readFile(fileName)
	if err != nil || len(document) == 0 || len(document) > 1024*1024 || !roots.AppendCertsFromPEM(document) {
		clear(document)
		return nil, ErrInvalidConfig
	}
	clear(document)
	return roots, nil
}
