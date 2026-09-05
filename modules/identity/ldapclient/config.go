package ldapclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	minimumConnectTimeout    = 100 * time.Millisecond
	maximumConnectTimeout    = 30 * time.Second
	minimumOperationTimeout  = 100 * time.Millisecond
	maximumOperationTimeout  = 60 * time.Second
	maximumEndpoints         = 8
	maximumResolvedAddresses = 16
	maximumConcurrent        = 256
	maximumAllowedPorts      = 16
	maximumPrivateCIDRs      = 64
	maximumBindDNCharacters  = 2 * 1024
	maximumBindDNBytes       = maximumBindDNCharacters * utf8.UTFMax
	maximumBindSecretBytes   = 8*1024 - 16
	maximumCustomCABytes     = 128 * 1024
)

// Resolver is the only DNS boundary used by Client. Implementations must honor
// ctx and return literal addresses without initiating a connection.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer establishes only the already validated IP literal selected by Client.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Options contains deployment-owned egress and resource policy. Tenant data
// cannot mutate these values.
type Options struct {
	Resolver             Resolver
	Dialer               Dialer
	PrivateEgressCIDRs   []netip.Prefix
	AllowedStartTLSPorts []uint16
	AllowedLDAPSPorts    []uint16
	MaxConcurrent        int
}

// Transport is an encrypted LDAP transport. Plaintext bind is not modeled.
type Transport string

const (
	TransportLDAPS    Transport = "ldaps"
	TransportStartTLS Transport = "starttls"
)

// Endpoint is one enabled provider endpoint from an immutable snapshot.
type Endpoint struct {
	Priority        int
	Enabled         bool
	ReferralAllowed bool
	Host            string
	Port            uint16
	Transport       Transport
	TLSServerName   string
}

// Configuration is the immutable network portion of a provider test snapshot.
// CustomCAPEM, when present, extends an operation-isolated clone of the system
// trust roots. It cannot replace system trust or disable verification.
type Configuration struct {
	Endpoints        []Endpoint
	ConnectTimeout   time.Duration
	OperationTimeout time.Duration
	CustomCAPEM      []byte
}

type validatedConfiguration struct {
	endpoints        []Endpoint
	connectTimeout   time.Duration
	operationTimeout time.Duration
	rootCAs          *x509.CertPool
}

func (c *Client) validateConfiguration(configuration Configuration) (validatedConfiguration, error) {
	if c == nil || len(configuration.Endpoints) < 1 || len(configuration.Endpoints) > maximumEndpoints ||
		configuration.ConnectTimeout < minimumConnectTimeout ||
		configuration.ConnectTimeout > maximumConnectTimeout ||
		configuration.OperationTimeout < minimumOperationTimeout ||
		configuration.OperationTimeout > maximumOperationTimeout ||
		configuration.ConnectTimeout > configuration.OperationTimeout {
		return validatedConfiguration{}, ErrInvalidConfiguration
	}

	configuredEndpoints := append([]Endpoint(nil), configuration.Endpoints...)
	endpoints := make([]Endpoint, 0, len(configuredEndpoints))
	priorities := make(map[int]struct{}, len(endpoints))
	origins := make(map[directoryEndpointOrigin]struct{}, len(configuredEndpoints))
	for _, endpoint := range configuredEndpoints {
		if endpoint.Priority < 1 || endpoint.Priority > maximumEndpoints || endpoint.Port == 0 {
			return validatedConfiguration{}, ErrInvalidConfiguration
		}
		if _, duplicate := priorities[endpoint.Priority]; duplicate {
			return validatedConfiguration{}, ErrInvalidConfiguration
		}
		priorities[endpoint.Priority] = struct{}{}
		if !endpoint.Enabled && endpoint.ReferralAllowed {
			return validatedConfiguration{}, ErrInvalidConfiguration
		}
		if !validCanonicalNetworkName(endpoint.Host) || !validCanonicalNetworkName(endpoint.TLSServerName) {
			return validatedConfiguration{}, ErrInvalidConfiguration
		}
		switch endpoint.Transport {
		case TransportLDAPS:
			if _, allowed := c.allowedLDAPSPorts[endpoint.Port]; !allowed {
				return validatedConfiguration{}, ErrInvalidConfiguration
			}
		case TransportStartTLS:
			if _, allowed := c.allowedStartTLSPorts[endpoint.Port]; !allowed {
				return validatedConfiguration{}, ErrInvalidConfiguration
			}
		default:
			return validatedConfiguration{}, ErrInvalidConfiguration
		}
		origin := directoryOriginForEndpoint(endpoint)
		if _, duplicate := origins[origin]; duplicate {
			return validatedConfiguration{}, ErrInvalidConfiguration
		}
		origins[origin] = struct{}{}
		if endpoint.Enabled {
			endpoints = append(endpoints, endpoint)
		}
	}
	if len(endpoints) == 0 {
		return validatedConfiguration{}, ErrInvalidConfiguration
	}
	slices.SortFunc(endpoints, func(left, right Endpoint) int {
		return left.Priority - right.Priority
	})

	roots, err := trustPoolWithCustomCAs(c.systemRoots, configuration.CustomCAPEM)
	if err != nil {
		return validatedConfiguration{}, ErrInvalidConfiguration
	}
	return validatedConfiguration{
		endpoints:        endpoints,
		connectTimeout:   configuration.ConnectTimeout,
		operationTimeout: configuration.OperationTimeout,
		rootCAs:          roots,
	}, nil
}

func trustPoolWithCustomCAs(systemRoots *x509.CertPool, customPEM []byte) (*x509.CertPool, error) {
	if systemRoots == nil || len(customPEM) > maximumCustomCABytes {
		return nil, ErrInvalidConfiguration
	}
	roots := systemRoots.Clone()
	if len(customPEM) == 0 {
		return roots, nil
	}

	rest := customPEM
	certificates := 0
	seen := make(map[[sha256.Size]byte]struct{})
	for {
		rest = bytes.TrimSpace(rest)
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrInvalidConfiguration
		}
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrInvalidConfiguration
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA ||
			certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, ErrInvalidConfiguration
		}
		digest := sha256.Sum256(certificate.Raw)
		if _, duplicate := seen[digest]; duplicate {
			return nil, ErrInvalidConfiguration
		}
		seen[digest] = struct{}{}
		roots.AddCert(certificate)
		certificates++
		rest = remaining
	}
	if certificates == 0 {
		return nil, ErrInvalidConfiguration
	}
	return roots, nil
}

func loadSystemRoots() (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return nil, errors.New("system trust roots unavailable")
	}
	return roots, nil
}

func validCanonicalNetworkName(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character > unicode.MaxASCII || unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == "" && !address.Is4In6() && address.String() == value
	}
	if looksLikeAmbiguousAddress(value) {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range label {
			character := label[index]
			if character < 'a' || character > 'z' {
				if character < '0' || character > '9' {
					if character != '-' {
						return false
					}
				}
			}
		}
	}
	return true
}

func looksLikeAmbiguousAddress(value string) bool {
	allDecimalOrDot := true
	for index := range value {
		if value[index] != '.' && (value[index] < '0' || value[index] > '9') {
			allDecimalOrDot = false
			break
		}
	}
	if allDecimalOrDot {
		return true
	}
	for _, label := range strings.Split(value, ".") {
		if !strings.HasPrefix(label, "0x") || len(label) <= 2 {
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

func normalizeAllowedPorts(values []uint16, defaultPort uint16) (map[uint16]struct{}, error) {
	if len(values) == 0 {
		values = []uint16{defaultPort}
	}
	if len(values) > maximumAllowedPorts {
		return nil, ErrInvalidOptions
	}
	ports := make(map[uint16]struct{}, len(values))
	for _, port := range values {
		if port == 0 {
			return nil, ErrInvalidOptions
		}
		if _, duplicate := ports[port]; duplicate {
			return nil, ErrInvalidOptions
		}
		ports[port] = struct{}{}
	}
	return ports, nil
}
