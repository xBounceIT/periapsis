package dfirscan

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestClamAVScannerStreamsINSTREAMAndRedactsSignature(t *testing.T) {
	t.Parallel()
	content := bytes.Repeat([]byte("forensic evidence\n"), 8_000)
	server, client := net.Pipe()
	readContent := make(chan []byte, 1)
	go func() {
		defer server.Close()
		command := make([]byte, 10)
		if _, err := io.ReadFull(server, command); err != nil || string(command) != "zINSTREAM\x00" {
			readContent <- nil
			return
		}
		var received bytes.Buffer
		for {
			var size [4]byte
			if _, err := io.ReadFull(server, size[:]); err != nil {
				readContent <- nil
				return
			}
			length := binary.BigEndian.Uint32(size[:])
			if length == 0 {
				break
			}
			chunk := make([]byte, length)
			if _, err := io.ReadFull(server, chunk); err != nil {
				readContent <- nil
				return
			}
			received.Write(chunk)
		}
		readContent <- received.Bytes()
		_, _ = server.Write([]byte("stream: sensitive-signature FOUND\x00"))
	}()
	config := testClamAVConfig()
	scanner, err := newClamAVWithDialer(config, func(context.Context) (net.Conn, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := scanner.Scan(context.Background(), bytes.NewReader(content), int64(len(content)))
	if err != nil || verdict != ScanMalicious {
		t.Fatalf("Scan() = %q, %v", verdict, err)
	}
	if got := <-readContent; !bytes.Equal(got, content) {
		t.Fatal("clamd did not receive the exact stream")
	}
	if scanner.String() != "dfirscan.ClamAVScanner{[REDACTED]}" {
		t.Fatalf("String() = %q", scanner.String())
	}
}

func TestClamAVCheckRequiresExactPONG(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	go func() {
		defer server.Close()
		command := make([]byte, 6)
		_, _ = io.ReadFull(server, command)
		_, _ = server.Write([]byte("PONG\x00"))
	}()
	scanner, err := newClamAVWithDialer(testClamAVConfig(), func(context.Context) (net.Conn, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := scanner.Check(context.Background()); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}

func TestClamAVConfigRejectsProductionPlaintextAndUnlistedPrivateTarget(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"PERIAPSIS_DFIR_SCANNER_ENDPOINT":              "tcp://clamav:3310",
		"PERIAPSIS_DFIR_SCANNER_ALLOW_PLAINTEXT_LOCAL": "true",
		"PERIAPSIS_DFIR_PRIVATE_EGRESS_CIDRS":          "172.16.0.0/12",
	}
	lookup := func(name string) (string, bool) { value, ok := base[name]; return value, ok }
	if _, err := loadClamAVConfig("production", lookup, func(string) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("production accepted plaintext scanner")
	}
	base["PERIAPSIS_DFIR_SCANNER_ENDPOINT"] = "tcp://10.0.0.7:3310"
	if _, err := loadClamAVConfig("development", lookup, func(string) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("development accepted an unlisted private scanner")
	}
	base["PERIAPSIS_DFIR_PRIVATE_EGRESS_CIDRS"] = "10.0.0.7/32"
	if _, err := loadClamAVConfig("development", lookup, func(string) ([]byte, error) { return nil, nil }); err != nil {
		t.Fatalf("development rejected explicitly allowed scanner: %v", err)
	}
}

func testClamAVConfig() ClamAVConfig {
	return ClamAVConfig{
		unixSocket: "/run/clamav/clamd.sock", rootCAs: x509.NewCertPool(),
		maximumObjectSize: 10 * 1024 * 1024, operationTimeout: time.Minute,
	}
}
