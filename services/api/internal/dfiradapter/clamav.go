package dfiradapter

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	dfir "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

const (
	clamdChunkBytes   = 64 * 1024
	clamdResponseMax  = 4 * 1024
	clamdConnectLimit = 5 * time.Second
)

// ClamAVScanner streams bytes with clamd's framed INSTREAM protocol. It never
// sends an object path or exposes a signature/daemon response to callers.
type ClamAVScanner struct {
	config ClamAVConfig
	dial   func(context.Context) (net.Conn, error)
}

var _ dfir.MalwareScanner = (*ClamAVScanner)(nil)

func (*ClamAVScanner) String() string           { return "dfiradapter.ClamAVScanner{endpoint:[REDACTED]}" }
func (scanner *ClamAVScanner) GoString() string { return scanner.String() }

func NewClamAV(config ClamAVConfig) (*ClamAVScanner, error) {
	if !validClamAVConfig(config) {
		return nil, ErrInvalidConfig
	}
	networkDialer := &net.Dialer{KeepAlive: -1}
	var connect func(context.Context) (net.Conn, error)
	switch {
	case config.unixSocket != "":
		socket := config.unixSocket
		connect = func(ctx context.Context) (net.Conn, error) {
			connectContext, cancel := context.WithTimeout(ctx, clamdConnectLimit)
			defer cancel()
			connection, err := networkDialer.DialContext(connectContext, "unix", socket)
			if err != nil || connection == nil {
				if connection != nil {
					_ = connection.Close()
				}
				return nil, ErrScannerUnavailable
			}
			return connection, nil
		}
	default:
		boundary := endpointDialer{
			endpoint: config.endpoint, policy: config.policy,
			resolver: net.DefaultResolver, dialer: networkDialer,
			connectTimeout: clamdConnectLimit, privateOnly: config.endpoint.scheme == "tcp",
		}
		connect = func(ctx context.Context) (net.Conn, error) {
			raw, err := boundary.DialContext(
				ctx,
				"tcp",
				net.JoinHostPort(config.endpoint.host, strconv.Itoa(int(config.endpoint.port))),
			)
			if err != nil || raw == nil {
				if raw != nil {
					_ = raw.Close()
				}
				return nil, ErrScannerUnavailable
			}
			if config.endpoint.scheme == "tcp" {
				return raw, nil
			}
			tlsConfig := &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: config.endpoint.host,
				RootCAs:    config.rootCAs.Clone(),
			}
			connection := tls.Client(raw, tlsConfig)
			handshakeContext, cancel := context.WithTimeout(ctx, clamdConnectLimit)
			defer cancel()
			if err := connection.HandshakeContext(handshakeContext); err != nil {
				_ = raw.Close()
				return nil, ErrScannerUnavailable
			}
			state := connection.ConnectionState()
			if !state.HandshakeComplete || state.Version < tls.VersionTLS12 || len(state.VerifiedChains) == 0 {
				_ = raw.Close()
				return nil, ErrScannerUnavailable
			}
			return connection, nil
		}
	}
	return &ClamAVScanner{config: config, dial: connect}, nil
}

func newClamAVWithDialer(config ClamAVConfig, connect func(context.Context) (net.Conn, error)) (*ClamAVScanner, error) {
	if !validClamAVConfig(config) || connect == nil {
		return nil, ErrInvalidConfig
	}
	return &ClamAVScanner{config: config, dial: connect}, nil
}

func (scanner *ClamAVScanner) Scan(
	ctx context.Context,
	reader io.Reader,
	maximumBytes int64,
) (dfir.ScanVerdict, error) {
	if !scanner.valid() || ctx == nil || ctx.Err() != nil || reader == nil ||
		maximumBytes <= 0 || maximumBytes > scanner.config.maximumObjectSize {
		return "", ErrScannerUnavailable
	}
	operationContext, cancel := context.WithTimeout(ctx, scanner.config.operationTimeout)
	defer cancel()
	connection, err := scanner.dial(operationContext)
	if err != nil || connection == nil {
		if connection != nil {
			_ = connection.Close()
		}
		return "", ErrScannerUnavailable
	}
	defer connection.Close()
	stopCancellation, err := bindConnectionDeadline(operationContext, connection)
	if err != nil {
		return "", ErrScannerUnavailable
	}
	defer stopCancellation()

	if err := writeAll(connection, []byte{'z', 'I', 'N', 'S', 'T', 'R', 'E', 'A', 'M', 0}); err != nil {
		return "", ErrScannerUnavailable
	}
	buffer := make([]byte, clamdChunkBytes)
	var total int64
	for {
		read, readErr := reader.Read(buffer)
		if read < 0 || read > len(buffer) {
			return "", ErrScannerUnavailable
		}
		if read > 0 {
			total += int64(read)
			if total > maximumBytes || total > scanner.config.maximumObjectSize {
				return "", ErrScannerUnavailable
			}
			var prefix [4]byte
			binary.BigEndian.PutUint32(prefix[:], uint32(read))
			if err := writeAll(connection, prefix[:]); err != nil {
				return "", ErrScannerUnavailable
			}
			if err := writeAll(connection, buffer[:read]); err != nil {
				return "", ErrScannerUnavailable
			}
		}
		switch readErr {
		case nil:
			if read == 0 {
				return "", ErrScannerUnavailable
			}
		case io.EOF:
			if err := writeAll(connection, []byte{0, 0, 0, 0}); err != nil {
				return "", ErrScannerUnavailable
			}
			response, responseErr := readClamdResponse(connection)
			if responseErr != nil {
				return "", ErrScannerUnavailable
			}
			return parseScanResponse(response)
		default:
			return "", ErrScannerUnavailable
		}
	}
}

// Check performs a bounded clamd PING for startup/readiness.
func (scanner *ClamAVScanner) Check(ctx context.Context) error {
	if !scanner.valid() || ctx == nil || ctx.Err() != nil {
		return ErrScannerUnavailable
	}
	checkContext, cancel := context.WithTimeout(ctx, min(scanner.config.operationTimeout, 10*time.Second))
	defer cancel()
	connection, err := scanner.dial(checkContext)
	if err != nil || connection == nil {
		if connection != nil {
			_ = connection.Close()
		}
		return ErrScannerUnavailable
	}
	defer connection.Close()
	stopCancellation, err := bindConnectionDeadline(checkContext, connection)
	if err != nil {
		return ErrScannerUnavailable
	}
	defer stopCancellation()
	if err := writeAll(connection, []byte{'z', 'P', 'I', 'N', 'G', 0}); err != nil {
		return ErrScannerUnavailable
	}
	response, err := readClamdResponse(connection)
	if err != nil || response != "PONG" {
		return ErrScannerUnavailable
	}
	return nil
}

func validClamAVConfig(config ClamAVConfig) bool {
	endpointSet := config.endpoint.canonical != ""
	socketSet := config.unixSocket != ""
	return endpointSet != socketSet && config.rootCAs != nil &&
		config.maximumObjectSize >= minimumConfiguredObjectBytes &&
		config.maximumObjectSize <= SinglePutMaximumBytes &&
		config.operationTimeout >= 10*time.Second && config.operationTimeout <= 15*time.Minute
}

func (scanner *ClamAVScanner) valid() bool {
	return scanner != nil && scanner.dial != nil && validClamAVConfig(scanner.config)
}

func bindConnectionDeadline(ctx context.Context, connection net.Conn) (func(), error) {
	deadline, present := ctx.Deadline()
	if !present || !deadline.After(time.Now()) || connection.SetDeadline(deadline) != nil {
		return func() {}, ErrScannerUnavailable
	}
	stop := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
	})
	return func() {
		stop()
		_ = connection.SetDeadline(time.Time{})
	}, nil
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if written < 0 || written > len(value) || written == 0 && err == nil {
			return ErrScannerUnavailable
		}
		value = value[written:]
		if err != nil {
			return ErrScannerUnavailable
		}
	}
	return nil
}

func readClamdResponse(reader io.Reader) (string, error) {
	bounded := io.LimitReader(reader, clamdResponseMax+1)
	response, err := bufio.NewReaderSize(bounded, clamdResponseMax+1).ReadBytes(0)
	if err != nil || len(response) < 2 || len(response) > clamdResponseMax || response[len(response)-1] != 0 {
		return "", ErrScannerUnavailable
	}
	response = response[:len(response)-1]
	if !utf8.Valid(response) {
		return "", ErrScannerUnavailable
	}
	for _, character := range string(response) {
		if unicode.IsControl(character) {
			return "", ErrScannerUnavailable
		}
	}
	return string(response), nil
}

func parseScanResponse(response string) (dfir.ScanVerdict, error) {
	if response == "stream: OK" {
		return dfir.ScanVerdictClean, nil
	}
	const prefix = "stream: "
	const suffix = " FOUND"
	if strings.HasPrefix(response, prefix) && strings.HasSuffix(response, suffix) {
		signature := strings.TrimSuffix(strings.TrimPrefix(response, prefix), suffix)
		if signature != "" && len(signature) <= 512 && strings.TrimSpace(signature) == signature {
			return dfir.ScanVerdictMalicious, nil
		}
	}
	return "", ErrScannerUnavailable
}
