package dfiradapter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	dfir "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func TestClamAVScanUsesBoundedInstreamAndMapsClosedVerdicts(t *testing.T) {
	t.Parallel()
	for name, response := range map[string]struct {
		wire string
		want dfir.ScanVerdict
	}{
		"clean":     {wire: "stream: OK\x00", want: dfir.ScanVerdictClean},
		"malicious": {wire: "stream: Unit.Test.Signature FOUND\x00", want: dfir.ScanVerdictMalicious},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			serverErrors := make(chan error, 1)
			scanner := testClamAVScanner(t, func(ctx context.Context) (net.Conn, error) {
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					value, err := readInstream(server)
					if err == nil && string(value) != "forensic-payload" {
						err = fmt.Errorf("payload = %q", value)
					}
					if err == nil {
						err = writeAll(server, []byte(response.wire))
					}
					serverErrors <- err
				}()
				return client, nil
			})
			verdict, err := scanner.Scan(
				context.Background(),
				strings.NewReader("forensic-payload"),
				1024,
			)
			if err != nil || verdict != response.want {
				t.Fatalf("Scan() = %q, %v", verdict, err)
			}
			if err := <-serverErrors; err != nil {
				t.Fatal(err)
			}
			if strings.Contains(fmt.Sprint(scanner), "scanner.example") ||
				strings.Contains(fmt.Sprintf("%#v", scanner), "scanner.example") {
				t.Fatal("scanner formatter exposed its endpoint")
			}
		})
	}
}

func TestClamAVFailsClosedAndRedactsHostileDaemonResponse(t *testing.T) {
	t.Parallel()
	const canary = "HOSTILE-DAEMON-CANARY"
	scanner := testClamAVScanner(t, func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_, _ = readInstream(server)
			_ = writeAll(server, []byte("stream: "+canary+" ERROR\x00"))
		}()
		return client, nil
	})
	verdict, err := scanner.Scan(context.Background(), strings.NewReader("payload"), 1024)
	if err == nil || verdict != "" || strings.Contains(err.Error(), canary) {
		t.Fatalf("Scan() = %q, %v; hostile daemon detail escaped", verdict, err)
	}
}

func TestClamAVRejectsOversizeAndHonorsCancellation(t *testing.T) {
	t.Parallel()
	t.Run("oversize", func(t *testing.T) {
		t.Parallel()
		scanner := testClamAVScanner(t, func(context.Context) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				_, _ = bufio.NewReader(server).ReadBytes(0)
				_, _ = io.Copy(io.Discard, server)
			}()
			return client, nil
		})
		if verdict, err := scanner.Scan(context.Background(), strings.NewReader("12345"), 4); err == nil || verdict != "" {
			t.Fatalf("oversize Scan() = %q, %v", verdict, err)
		}
	})

	t.Run("cancel", func(t *testing.T) {
		t.Parallel()
		commandRead := make(chan struct{})
		scanner := testClamAVScanner(t, func(context.Context) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				_, _ = readInstreamCommand(server)
				close(commandRead)
				_, _ = io.Copy(io.Discard, server)
			}()
			return client, nil
		})
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, err := scanner.Scan(ctx, strings.NewReader("payload"), 1024)
			result <- err
		}()
		<-commandRead
		cancel()
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("cancelled scan succeeded")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("cancelled scan did not unblock")
		}
	})
}

func TestClamAVReadinessAndConcurrentScans(t *testing.T) {
	t.Parallel()
	scanner := testClamAVScanner(t, func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			command, err := readInstreamCommand(server)
			switch {
			case err != nil:
				return
			case bytes.Equal(command, []byte("zPING\x00")):
				_ = writeAll(server, []byte("PONG\x00"))
			case bytes.Equal(command, []byte("zINSTREAM\x00")):
				if _, err := readInstreamChunks(server); err == nil {
					_ = writeAll(server, []byte("stream: OK\x00"))
				}
			}
		}()
		return client, nil
	})
	if err := scanner.Check(context.Background()); err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	var wait sync.WaitGroup
	errorsFound := make(chan error, 32)
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			verdict, err := scanner.Scan(context.Background(), strings.NewReader("payload"), 1024)
			if err != nil || verdict != dfir.ScanVerdictClean {
				errorsFound <- fmt.Errorf("Scan() = %q, %v", verdict, err)
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
}

func testClamAVScanner(
	t *testing.T,
	connect func(context.Context) (net.Conn, error),
) *ClamAVScanner {
	t.Helper()
	endpoint, err := compileTCPScannerEndpoint("tls://scanner.example:3310", false)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	scanner, err := newClamAVWithDialer(ClamAVConfig{
		endpoint:          endpoint,
		rootCAs:           roots,
		policy:            egressPolicy{},
		maximumObjectSize: 1024 * 1024,
		operationTimeout:  10 * time.Second,
	}, connect)
	if err != nil {
		t.Fatal(err)
	}
	return scanner
}

func readInstream(reader io.Reader) ([]byte, error) {
	command, err := readInstreamCommand(reader)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(command, []byte("zINSTREAM\x00")) {
		return nil, fmt.Errorf("command = %q", command)
	}
	return readInstreamChunks(reader)
}

func readInstreamCommand(reader io.Reader) ([]byte, error) {
	result := make([]byte, 0, 16)
	var current [1]byte
	for len(result) < 32 {
		if _, err := io.ReadFull(reader, current[:]); err != nil {
			return nil, err
		}
		result = append(result, current[0])
		if current[0] == 0 {
			return result, nil
		}
	}
	return nil, ErrScannerUnavailable
}

func readInstreamChunks(reader io.Reader) ([]byte, error) {
	var result bytes.Buffer
	var prefix [4]byte
	for {
		if _, err := io.ReadFull(reader, prefix[:]); err != nil {
			return nil, err
		}
		size := binary.BigEndian.Uint32(prefix[:])
		if size == 0 {
			return result.Bytes(), nil
		}
		if size > clamdChunkBytes {
			return nil, fmt.Errorf("chunk = %d", size)
		}
		if _, err := io.CopyN(&result, reader, int64(size)); err != nil {
			return nil, err
		}
	}
}
