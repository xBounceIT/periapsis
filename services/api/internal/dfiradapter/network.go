package dfiradapter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
)

var (
	ErrInvalidConfig      = errors.New("invalid DFIR adapter configuration")
	ErrEgressRejected     = errors.New("DFIR adapter destination rejected")
	ErrStorageUnavailable = errors.New("DFIR object storage unavailable")
	ErrScannerUnavailable = errors.New("DFIR malware scanner unavailable")
)

type resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type compiledEndpoint struct {
	scheme    string
	host      string
	port      uint16
	canonical string
}

type egressPolicy struct {
	privateCIDRs []netip.Prefix
}

type endpointDialer struct {
	endpoint       compiledEndpoint
	policy         egressPolicy
	resolver       resolver
	dialer         dialer
	connectTimeout time.Duration
	privateOnly    bool
}

var privateNetworkRanges = [...]netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

var metadataServiceRanges = [...]netip.Prefix{
	netip.MustParsePrefix("168.63.129.16/32"),
	netip.MustParsePrefix("169.254.169.254/32"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
}

var blockedSpecialRanges = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func compileHTTPEndpoint(raw string, allowPlaintext bool) (compiledEndpoint, error) {
	if !validEndpointText(raw) {
		return compiledEndpoint{}, ErrInvalidConfig
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.RawFragment != "" ||
		(parsed.Scheme != "https" && !(allowPlaintext && parsed.Scheme == "http")) {
		return compiledEndpoint{}, ErrInvalidConfig
	}
	host := parsed.Hostname()
	if !validCanonicalHost(host) {
		return compiledEndpoint{}, ErrInvalidConfig
	}
	defaultPort := uint16(443)
	if parsed.Scheme == "http" {
		defaultPort = 80
	}
	port, authority, err := canonicalAuthority(host, parsed.Port(), defaultPort, false)
	if err != nil || parsed.Host != authority || raw != parsed.Scheme+"://"+authority {
		return compiledEndpoint{}, ErrInvalidConfig
	}
	return compiledEndpoint{scheme: parsed.Scheme, host: host, port: port, canonical: raw}, nil
}

func compileTCPScannerEndpoint(raw string, allowPlaintext bool) (compiledEndpoint, error) {
	if !validEndpointText(raw) {
		return compiledEndpoint{}, ErrInvalidConfig
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.RawFragment != "" ||
		(parsed.Scheme != "tls" && !(allowPlaintext && parsed.Scheme == "tcp")) {
		return compiledEndpoint{}, ErrInvalidConfig
	}
	host := parsed.Hostname()
	if !validCanonicalHost(host) {
		return compiledEndpoint{}, ErrInvalidConfig
	}
	port, authority, err := canonicalAuthority(host, parsed.Port(), 0, true)
	if err != nil || parsed.Host != authority || raw != parsed.Scheme+"://"+authority {
		return compiledEndpoint{}, ErrInvalidConfig
	}
	return compiledEndpoint{scheme: parsed.Scheme, host: host, port: port, canonical: raw}, nil
}

func canonicalAuthority(host, portText string, defaultPort uint16, requirePort bool) (uint16, string, error) {
	port := defaultPort
	if portText == "" {
		if requirePort || defaultPort == 0 {
			return 0, "", ErrInvalidConfig
		}
	} else {
		parsed, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != portText ||
			!requirePort && uint16(parsed) == defaultPort {
			return 0, "", ErrInvalidConfig
		}
		port = uint16(parsed)
	}
	authority := host
	if address, err := netip.ParseAddr(host); err == nil && address.Is6() {
		authority = "[" + host + "]"
	}
	if requirePort || port != defaultPort {
		authority = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	return port, authority, nil
}

func validEndpointText(value string) bool {
	if value == "" || len(value) > 2_048 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func validCanonicalHost(value string) bool {
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

// looksLikeAmbiguousAddress rejects legacy numeric host forms that some
// resolvers interpret as IP literals even though netip does not. Accepting one
// would make the compiled target differ from the address ultimately dialed.
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
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
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

func newEgressPolicy(privateCIDRs []netip.Prefix) (egressPolicy, error) {
	if len(privateCIDRs) > 64 {
		return egressPolicy{}, ErrInvalidConfig
	}
	result := make([]netip.Prefix, 0, len(privateCIDRs))
	seen := make(map[netip.Prefix]struct{}, len(privateCIDRs))
	for _, prefix := range privateCIDRs {
		if !prefix.IsValid() || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() ||
			prefix != prefix.Masked() || !isPrivateSubprefix(prefix) {
			return egressPolicy{}, ErrInvalidConfig
		}
		if _, duplicate := seen[prefix]; duplicate {
			return egressPolicy{}, ErrInvalidConfig
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
	return egressPolicy{privateCIDRs: result}, nil
}

func isPrivateSubprefix(candidate netip.Prefix) bool {
	for _, privateRange := range privateNetworkRanges {
		if candidate.Addr().BitLen() == privateRange.Addr().BitLen() &&
			candidate.Bits() >= privateRange.Bits() && privateRange.Contains(candidate.Addr()) {
			return true
		}
	}
	return false
}

func (policy egressPolicy) addressAllowed(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" || address.Is4In6() {
		return false
	}
	for _, blocked := range metadataServiceRanges {
		if blocked.Contains(address) {
			return false
		}
	}
	if address.IsPrivate() {
		for _, allowed := range policy.privateCIDRs {
			if allowed.Contains(address) {
				return true
			}
		}
		return false
	}
	if !address.IsGlobalUnicast() {
		return false
	}
	for _, blocked := range blockedSpecialRanges {
		if blocked.Contains(address) {
			return false
		}
	}
	return true
}

func (boundary endpointDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil || network != "tcp" || boundary.resolver == nil || boundary.dialer == nil ||
		boundary.connectTimeout < 50*time.Millisecond || boundary.connectTimeout > 30*time.Second {
		return nil, ErrEgressRejected
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host != boundary.endpoint.host || portText != strconv.Itoa(int(boundary.endpoint.port)) {
		return nil, ErrEgressRejected
	}
	connectContext, cancel := context.WithTimeout(ctx, boundary.connectTimeout)
	defer cancel()
	addresses, err := boundary.resolve(connectContext)
	if err != nil {
		return nil, ErrEgressRejected
	}
	for _, candidate := range addresses {
		connection, dialErr := boundary.dialer.DialContext(
			connectContext,
			"tcp",
			net.JoinHostPort(candidate.String(), portText),
		)
		if dialErr == nil && connection != nil {
			return connection, nil
		}
		if connection != nil {
			_ = connection.Close()
		}
	}
	return nil, ErrEgressRejected
}

func (boundary endpointDialer) resolve(ctx context.Context) ([]netip.Addr, error) {
	var addresses []netip.Addr
	if literal, err := netip.ParseAddr(boundary.endpoint.host); err == nil {
		addresses = []netip.Addr{literal}
	} else {
		resolved, lookupErr := boundary.resolver.LookupNetIP(ctx, "ip", boundary.endpoint.host)
		if lookupErr != nil || len(resolved) == 0 || len(resolved) > 16 {
			return nil, ErrEgressRejected
		}
		addresses = resolved
	}
	validated := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if !boundary.policy.addressAllowed(address) || boundary.privateOnly && !address.IsPrivate() {
			return nil, ErrEgressRejected
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		validated = append(validated, address)
	}
	if len(validated) == 0 {
		return nil, ErrEgressRejected
	}
	slices.SortFunc(validated, netip.Addr.Compare)
	return validated, nil
}

func newHTTPClient(endpoint compiledEndpoint, policy egressPolicy, roots *x509.CertPool, maxConcurrent int) (*http.Client, error) {
	return newHTTPClientWithNetwork(
		endpoint,
		policy,
		roots,
		maxConcurrent,
		net.DefaultResolver,
		&net.Dialer{KeepAlive: 30 * time.Second},
	)
}

func newHTTPClientWithNetwork(
	endpoint compiledEndpoint,
	policy egressPolicy,
	roots *x509.CertPool,
	maxConcurrent int,
	nameResolver resolver,
	networkDialer dialer,
) (*http.Client, error) {
	if endpoint.canonical == "" || roots == nil || maxConcurrent < 1 || maxConcurrent > 128 ||
		nameResolver == nil || networkDialer == nil {
		return nil, ErrInvalidConfig
	}
	boundary := endpointDialer{
		endpoint: endpoint, policy: policy, resolver: nameResolver, dialer: networkDialer,
		connectTimeout: 5 * time.Second, privateOnly: endpoint.scheme == "http",
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            boundary.DialContext,
		ForceAttemptHTTP2:      false,
		DisableCompression:     true,
		MaxIdleConns:           maxConcurrent,
		MaxIdleConnsPerHost:    maxConcurrent,
		MaxConnsPerHost:        maxConcurrent,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 64 * 1024,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots.Clone(),
			NextProtos: []string{"http/1.1"},
		},
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrEgressRejected
		},
	}, nil
}
