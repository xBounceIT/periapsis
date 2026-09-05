package dfirscan

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	clamdChunkBytes   = 64 * 1024
	clamdResponseMax  = 4 * 1024
	clamdConnectLimit = 5 * time.Second
)

type scannerResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type scannerDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// ClamAVScanner streams the exact object body using clamd INSTREAM. It never
// sends an object key or returns daemon text/signatures to callers.
type ClamAVScanner struct {
	config ClamAVConfig
	dial   func(context.Context) (net.Conn, error)
}

func (*ClamAVScanner) String() string           { return "dfirscan.ClamAVScanner{[REDACTED]}" }
func (scanner *ClamAVScanner) GoString() string { return scanner.String() }

func NewClamAV(config ClamAVConfig) (*ClamAVScanner, error) {
	return newClamAV(config, net.DefaultResolver, &net.Dialer{KeepAlive: -1})
}

func newClamAV(config ClamAVConfig, resolver scannerResolver, networkDialer scannerDialer) (*ClamAVScanner, error) {
	if !validClamAVConfig(config) || resolver == nil || networkDialer == nil {
		return nil, ErrInvalidConfiguration
	}
	var connect func(context.Context) (net.Conn, error)
	if config.unixSocket != "" {
		socket := config.unixSocket
		connect = func(ctx context.Context) (net.Conn, error) {
			connectContext, cancel := context.WithTimeout(ctx, clamdConnectLimit)
			defer cancel()
			connection, err := networkDialer.DialContext(connectContext, "unix", socket)
			if err != nil || connection == nil {
				if connection != nil {
					_ = connection.Close()
				}
				return nil, ErrUnavailable
			}
			return connection, nil
		}
	} else {
		connect = scannerNetworkConnector(config, resolver, networkDialer)
	}
	return &ClamAVScanner{config: config, dial: connect}, nil
}

func newClamAVWithDialer(config ClamAVConfig, dial func(context.Context) (net.Conn, error)) (*ClamAVScanner, error) {
	if !validClamAVConfig(config) || dial == nil {
		return nil, ErrInvalidConfiguration
	}
	return &ClamAVScanner{config: config, dial: dial}, nil
}

func scannerNetworkConnector(
	config ClamAVConfig,
	resolver scannerResolver,
	networkDialer scannerDialer,
) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		connectContext, cancel := context.WithTimeout(ctx, clamdConnectLimit)
		defer cancel()
		addresses, err := resolveScannerAddresses(connectContext, config, resolver)
		if err != nil {
			return nil, ErrUnavailable
		}
		port := strconv.Itoa(int(config.endpoint.port))
		for _, address := range addresses {
			raw, dialErr := networkDialer.DialContext(connectContext, "tcp", net.JoinHostPort(address.String(), port))
			if dialErr != nil || raw == nil {
				if raw != nil {
					_ = raw.Close()
				}
				continue
			}
			if config.endpoint.scheme == "tcp" {
				return raw, nil
			}
			connection := tls.Client(raw, &tls.Config{
				MinVersion: tls.VersionTLS12, ServerName: config.endpoint.host, RootCAs: config.rootCAs.Clone(),
			})
			if handshakeErr := connection.HandshakeContext(connectContext); handshakeErr != nil {
				_ = raw.Close()
				continue
			}
			state := connection.ConnectionState()
			if !state.HandshakeComplete || state.Version < tls.VersionTLS12 || len(state.VerifiedChains) == 0 {
				_ = raw.Close()
				continue
			}
			return connection, nil
		}
		return nil, ErrUnavailable
	}
}

func resolveScannerAddresses(ctx context.Context, config ClamAVConfig, resolver scannerResolver) ([]netip.Addr, error) {
	var addresses []netip.Addr
	if literal, err := netip.ParseAddr(config.endpoint.host); err == nil {
		addresses = []netip.Addr{literal}
	} else {
		resolved, err := resolver.LookupNetIP(ctx, "ip", config.endpoint.host)
		if err != nil || len(resolved) == 0 || len(resolved) > 16 {
			return nil, ErrUnavailable
		}
		addresses = resolved
	}
	result := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if !scannerAddressAllowed(address, config.privateCIDRs, config.endpoint.scheme == "tcp") {
			return nil, ErrUnavailable
		}
		if _, duplicate := seen[address]; !duplicate {
			seen[address] = struct{}{}
			result = append(result, address)
		}
	}
	slices.SortFunc(result, netip.Addr.Compare)
	return result, nil
}

func (scanner *ClamAVScanner) Scan(ctx context.Context, reader io.Reader, maximumBytes int64) (ScanVerdict, error) {
	if !scanner.valid() || ctx == nil || ctx.Err() != nil || reader == nil ||
		maximumBytes <= 0 || maximumBytes > scanner.config.maximumObjectSize {
		return "", ErrUnavailable
	}
	operationContext, cancel := context.WithTimeout(ctx, scanner.config.operationTimeout)
	defer cancel()
	connection, err := scanner.dial(operationContext)
	if err != nil || connection == nil {
		if connection != nil {
			_ = connection.Close()
		}
		return "", ErrUnavailable
	}
	defer connection.Close()
	stopDeadline, err := bindScannerDeadline(operationContext, connection)
	if err != nil {
		return "", ErrUnavailable
	}
	defer stopDeadline()
	if err := scannerWriteAll(connection, []byte{'z', 'I', 'N', 'S', 'T', 'R', 'E', 'A', 'M', 0}); err != nil {
		return "", err
	}
	buffer := make([]byte, clamdChunkBytes)
	var total int64
	for {
		read, readErr := reader.Read(buffer)
		if read < 0 || read > len(buffer) || read == 0 && readErr == nil {
			return "", ErrUnavailable
		}
		if read > 0 {
			total += int64(read)
			if total > maximumBytes || total > scanner.config.maximumObjectSize {
				return "", ErrUnavailable
			}
			var prefix [4]byte
			binary.BigEndian.PutUint32(prefix[:], uint32(read))
			if scannerWriteAll(connection, prefix[:]) != nil || scannerWriteAll(connection, buffer[:read]) != nil {
				return "", ErrUnavailable
			}
		}
		switch readErr {
		case nil:
			continue
		case io.EOF:
			if scannerWriteAll(connection, []byte{0, 0, 0, 0}) != nil {
				return "", ErrUnavailable
			}
			response, responseErr := readClamdResponse(connection)
			if responseErr != nil {
				return "", responseErr
			}
			return parseClamdResponse(response)
		default:
			return "", ErrUnavailable
		}
	}
}

func (scanner *ClamAVScanner) Check(ctx context.Context) error {
	if !scanner.valid() || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	checkContext, cancel := context.WithTimeout(ctx, min(scanner.config.operationTimeout, 10*time.Second))
	defer cancel()
	connection, err := scanner.dial(checkContext)
	if err != nil || connection == nil {
		if connection != nil {
			_ = connection.Close()
		}
		return ErrUnavailable
	}
	defer connection.Close()
	stopDeadline, err := bindScannerDeadline(checkContext, connection)
	if err != nil {
		return ErrUnavailable
	}
	defer stopDeadline()
	if scannerWriteAll(connection, []byte{'z', 'P', 'I', 'N', 'G', 0}) != nil {
		return ErrUnavailable
	}
	response, err := readClamdResponse(connection)
	if err != nil || response != "PONG" {
		return ErrUnavailable
	}
	return nil
}

func validClamAVConfig(config ClamAVConfig) bool {
	endpointSet := config.endpoint.scheme != ""
	socketSet := config.unixSocket != ""
	return endpointSet != socketSet && config.rootCAs != nil &&
		config.maximumObjectSize >= 1_024*1_024 && config.maximumObjectSize <= 5_000_000_000 &&
		config.operationTimeout >= 10*time.Second && config.operationTimeout <= 15*time.Minute
}

func (scanner *ClamAVScanner) valid() bool {
	return scanner != nil && scanner.dial != nil && validClamAVConfig(scanner.config)
}

func bindScannerDeadline(ctx context.Context, connection net.Conn) (func(), error) {
	deadline, present := ctx.Deadline()
	if !present || !deadline.After(time.Now()) || connection.SetDeadline(deadline) != nil {
		return func() {}, ErrUnavailable
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	return func() {
		stop()
		_ = connection.SetDeadline(time.Time{})
	}, nil
}

func scannerWriteAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if written < 0 || written > len(value) || written == 0 && err == nil {
			return ErrUnavailable
		}
		value = value[written:]
		if err != nil {
			return ErrUnavailable
		}
	}
	return nil
}

func readClamdResponse(reader io.Reader) (string, error) {
	response, err := bufio.NewReaderSize(io.LimitReader(reader, clamdResponseMax+1), clamdResponseMax+1).ReadBytes(0)
	if err != nil || len(response) < 2 || len(response) > clamdResponseMax || response[len(response)-1] != 0 {
		return "", ErrUnavailable
	}
	response = response[:len(response)-1]
	if !utf8.Valid(response) {
		return "", ErrUnavailable
	}
	for _, character := range string(response) {
		if unicode.IsControl(character) {
			return "", ErrUnavailable
		}
	}
	return string(response), nil
}

func parseClamdResponse(response string) (ScanVerdict, error) {
	if response == "stream: OK" {
		return ScanClean, nil
	}
	if strings.HasPrefix(response, "stream: ") && strings.HasSuffix(response, " FOUND") {
		signature := strings.TrimSuffix(strings.TrimPrefix(response, "stream: "), " FOUND")
		if signature != "" && len(signature) <= 512 && strings.TrimSpace(signature) == signature {
			return ScanMalicious, nil
		}
	}
	return "", ErrUnavailable
}

var _ MalwareScanner = (*ClamAVScanner)(nil)
