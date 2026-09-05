package dfirscan

import (
	"crypto/x509"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type scannerEndpoint struct {
	scheme string
	host   string
	port   uint16
}

type ClamAVConfig struct {
	endpoint          scannerEndpoint
	unixSocket        string
	rootCAs           *x509.CertPool
	privateCIDRs      []netip.Prefix
	maximumObjectSize int64
	operationTimeout  time.Duration
}

func (ClamAVConfig) String() string          { return "dfirscan.ClamAVConfig{[REDACTED]}" }
func (config ClamAVConfig) GoString() string { return config.String() }

func LoadClamAVConfig(environment string) (ClamAVConfig, error) {
	return loadClamAVConfig(environment, os.LookupEnv, os.ReadFile)
}

func loadClamAVConfig(
	environment string,
	lookup func(string) (string, bool),
	readFile func(string) ([]byte, error),
) (ClamAVConfig, error) {
	if lookup == nil || readFile == nil ||
		(environment != "production" && environment != "development" && environment != "test") {
		return ClamAVConfig{}, ErrInvalidConfiguration
	}
	production := environment == "production"
	allowPlaintext, err := scannerStrictBool(lookup, "PERIAPSIS_DFIR_SCANNER_ALLOW_PLAINTEXT_LOCAL", false)
	if err != nil || production && allowPlaintext {
		return ClamAVConfig{}, ErrInvalidConfiguration
	}
	maximum, err := scannerInt64(
		lookup, "PERIAPSIS_DFIR_MAX_OBJECT_BYTES", 5_000_000_000, 1_024*1_024, 5_000_000_000,
	)
	if err != nil {
		return ClamAVConfig{}, err
	}
	timeout, err := scannerDuration(
		lookup, "PERIAPSIS_DFIR_SCANNER_TIMEOUT", 5*time.Minute, 10*time.Second, 15*time.Minute,
	)
	if err != nil {
		return ClamAVConfig{}, err
	}
	privateCIDRs, err := scannerPrivateCIDRs(lookup)
	if err != nil {
		return ClamAVConfig{}, err
	}
	raw, present := lookup("PERIAPSIS_DFIR_SCANNER_ENDPOINT")
	if !present || !scannerSafeText(raw, 2_048) {
		return ClamAVConfig{}, ErrInvalidConfiguration
	}
	config := ClamAVConfig{
		privateCIDRs: privateCIDRs, maximumObjectSize: maximum, operationTimeout: timeout,
	}
	if strings.HasPrefix(raw, "unix://") {
		path := strings.TrimPrefix(raw, "unix://")
		if path == "" || len(path) > 1_024 || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
			strings.ContainsRune(path, 0) {
			return ClamAVConfig{}, ErrInvalidConfiguration
		}
		config.unixSocket = path
	} else {
		endpoint, parseErr := parseScannerEndpoint(raw, allowPlaintext)
		if parseErr != nil || production && endpoint.scheme != "tls" {
			return ClamAVConfig{}, ErrInvalidConfiguration
		}
		if literal, literalErr := netip.ParseAddr(endpoint.host); literalErr == nil &&
			!scannerAddressAllowed(literal, privateCIDRs, endpoint.scheme == "tcp") {
			return ClamAVConfig{}, ErrInvalidConfiguration
		}
		config.endpoint = endpoint
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return ClamAVConfig{}, ErrInvalidConfiguration
	}
	if fileName, set := lookup("PERIAPSIS_DFIR_SCANNER_CA_BUNDLE_FILE"); set && fileName != "" {
		if !scannerSecretPath(fileName) {
			return ClamAVConfig{}, ErrInvalidConfiguration
		}
		document, readErr := readFile(fileName)
		if readErr != nil || len(document) == 0 || len(document) > 1_048_576 || !roots.AppendCertsFromPEM(document) {
			clear(document)
			return ClamAVConfig{}, ErrInvalidConfiguration
		}
		clear(document)
	}
	config.rootCAs = roots
	if !validClamAVConfig(config) {
		return ClamAVConfig{}, ErrInvalidConfiguration
	}
	return config, nil
}

func parseScannerEndpoint(raw string, allowPlaintext bool) (scannerEndpoint, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.Port() == "" ||
		(parsed.Scheme != "tls" && !(allowPlaintext && parsed.Scheme == "tcp")) {
		return scannerEndpoint{}, ErrInvalidConfiguration
	}
	host := parsed.Hostname()
	if !scannerValidHost(host) {
		return scannerEndpoint{}, ErrInvalidConfiguration
	}
	portValue, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || portValue == 0 || strconv.FormatUint(portValue, 10) != parsed.Port() {
		return scannerEndpoint{}, ErrInvalidConfiguration
	}
	authority := net.JoinHostPort(host, parsed.Port())
	if parsed.Host != authority || raw != parsed.Scheme+"://"+authority {
		return scannerEndpoint{}, ErrInvalidConfiguration
	}
	return scannerEndpoint{scheme: parsed.Scheme, host: host, port: uint16(portValue)}, nil
}

func scannerPrivateCIDRs(lookup func(string) (string, bool)) ([]netip.Prefix, error) {
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
		if err != nil || prefix.String() != part || prefix != prefix.Masked() || !scannerPrivateSubprefix(prefix) {
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

var scannerPrivateNetworks = [...]netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7"),
}

var scannerBlockedNetworks = [...]netip.Prefix{
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

func scannerAddressAllowed(address netip.Addr, privateCIDRs []netip.Prefix, privateOnly bool) bool {
	if !address.IsValid() || address.Zone() != "" || address.Is4In6() {
		return false
	}
	for _, blocked := range scannerBlockedNetworks {
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
	return !privateOnly && address.IsGlobalUnicast()
}

func scannerPrivateSubprefix(candidate netip.Prefix) bool {
	for _, network := range scannerPrivateNetworks {
		if candidate.Addr().BitLen() == network.Addr().BitLen() && candidate.Bits() >= network.Bits() &&
			network.Contains(candidate.Addr()) {
			return true
		}
	}
	return false
}

func scannerValidHost(value string) bool {
	if value == "" || len(value) > 253 || strings.ToLower(value) != value || strings.HasSuffix(value, ".") {
		return false
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == "" && !address.Is4In6() && address.String() == value
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

func scannerStrictBool(lookup func(string) (string, bool), name string, fallback bool) (bool, error) {
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

func scannerInt64(lookup func(string) (string, bool), name string, fallback, minimum, maximum int64) (int64, error) {
	value, present := lookup(name)
	if !present || value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < minimum || parsed > maximum || strconv.FormatInt(parsed, 10) != value {
		return 0, ErrInvalidConfiguration
	}
	return parsed, nil
}

func scannerDuration(lookup func(string) (string, bool), name string, fallback, minimum, maximum time.Duration) (time.Duration, error) {
	value, present := lookup(name)
	if !present || value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < minimum || parsed > maximum || parsed%time.Microsecond != 0 {
		return 0, ErrInvalidConfiguration
	}
	return parsed, nil
}

func scannerSafeText(value string, maximum int) bool {
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

func scannerSecretPath(value string) bool {
	if value == "" || len(value) > 1_024 || value[0] != '/' || strings.Contains(value, "//") ||
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
