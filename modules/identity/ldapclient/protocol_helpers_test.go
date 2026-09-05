package ldapclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

const maximumTestPacketBytes = 64 * 1024

type testPKI struct {
	serverCertificate tls.Certificate
	roots             *x509.CertPool
	caPEM             []byte
}

func newTestPKI(t *testing.T, dnsNames ...string) testPKI {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "LDAP diagnostic test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "LDAP diagnostic test server"},
		DNSNames:     dnsNames,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	return testPKI{
		serverCertificate: tls.Certificate{
			Certificate: [][]byte{leafDER, caDER},
			PrivateKey:  leafKey,
		},
		roots: roots,
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
	}
}

func (pki testPKI) serverTLSConfig(onHello func(string)) *tls.Config {
	configuration := &tls.Config{
		Certificates: []tls.Certificate{pki.serverCertificate},
		MinVersion:   tls.VersionTLS12,
	}
	if onHello != nil {
		configuration.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			onHello(info.ServerName)
			return nil, nil
		}
	}
	return configuration
}

type pipeScriptDialer struct {
	handler func(net.Conn) error
	done    chan error

	mu      sync.Mutex
	targets []string
}

func newPipeScriptDialer(handler func(net.Conn) error) *pipeScriptDialer {
	return &pipeScriptDialer{handler: handler, done: make(chan error, 16)}
}

func (dialer *pipeScriptDialer) DialContext(
	ctx context.Context,
	network string,
	address string,
) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dialer.mu.Lock()
	dialer.targets = append(dialer.targets, address)
	dialer.mu.Unlock()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		dialer.done <- dialer.handler(server)
	}()
	return client, nil
}

func (dialer *pipeScriptDialer) wait(t *testing.T) {
	t.Helper()
	select {
	case err := <-dialer.done:
		if err != nil {
			t.Fatalf("LDAP test server: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("LDAP test server did not stop")
	}
}

func (dialer *pipeScriptDialer) dialTargets() []string {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	return append([]string(nil), dialer.targets...)
}

func readBERPacket(reader io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	lengthBytes := []byte{header[1]}
	length := int(header[1])
	if header[1]&0x80 != 0 {
		lengthWidth := int(header[1] & 0x7f)
		if lengthWidth < 1 || lengthWidth > 4 {
			return nil, errors.New("invalid BER length width")
		}
		extra := make([]byte, lengthWidth)
		if _, err := io.ReadFull(reader, extra); err != nil {
			return nil, err
		}
		lengthBytes = append(lengthBytes, extra...)
		length = 0
		for _, value := range extra {
			length = length<<8 | int(value)
		}
	}
	if length < 0 || length > maximumTestPacketBytes {
		return nil, errors.New("invalid BER packet length")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	packet := make([]byte, 0, 1+len(lengthBytes)+len(body))
	packet = append(packet, header[0])
	packet = append(packet, lengthBytes...)
	packet = append(packet, body...)
	return packet, nil
}

func ldapMessageIDAndOperation(packet []byte) (int, byte, error) {
	if len(packet) < 5 || packet[0] != 0x30 {
		return 0, 0, errors.New("invalid LDAP message sequence")
	}
	index, _, err := skipBERLength(packet, 1)
	if err != nil || index >= len(packet) || packet[index] != 0x02 {
		return 0, 0, errors.New("invalid LDAP message ID")
	}
	index++
	valueStart, valueLength, err := skipBERLength(packet, index)
	if err != nil || valueLength < 1 || valueLength > 4 || valueStart+valueLength >= len(packet) {
		return 0, 0, errors.New("invalid LDAP message ID value")
	}
	messageID := 0
	for _, value := range packet[valueStart : valueStart+valueLength] {
		messageID = messageID<<8 | int(value)
	}
	return messageID, packet[valueStart+valueLength], nil
}

func skipBERLength(packet []byte, index int) (valueStart, valueLength int, err error) {
	if index >= len(packet) {
		return 0, 0, io.ErrUnexpectedEOF
	}
	first := packet[index]
	index++
	if first&0x80 == 0 {
		return index, int(first), nil
	}
	width := int(first & 0x7f)
	if width < 1 || width > 4 || index+width > len(packet) {
		return 0, 0, errors.New("invalid BER length")
	}
	length := 0
	for _, value := range packet[index : index+width] {
		length = length<<8 | int(value)
	}
	return index + width, length, nil
}

func ldapResultPacket(messageID int, operation byte, resultCode byte) []byte {
	result := []byte{0x0a, 0x01, resultCode, 0x04, 0x00, 0x04, 0x00}
	operationPacket := encodeTestTLV(operation, result)
	message := append(encodeTestInteger(messageID), operationPacket...)
	return encodeTestTLV(0x30, message)
}

type testLDAPAttribute struct {
	name   string
	values [][]byte
}

func ldapSearchEntryPacket(messageID int, distinguishedName string, attributes []testLDAPAttribute) []byte {
	encodedAttributes := make([]byte, 0)
	for _, attribute := range attributes {
		values := make([]byte, 0)
		for _, value := range attribute.values {
			values = append(values, encodeTestTLV(0x04, value)...)
		}
		partialAttribute := append(
			encodeTestTLV(0x04, []byte(attribute.name)),
			encodeTestTLV(0x31, values)...,
		)
		encodedAttributes = append(encodedAttributes, encodeTestTLV(0x30, partialAttribute)...)
	}
	entry := append(
		encodeTestTLV(0x04, []byte(distinguishedName)),
		encodeTestTLV(0x30, encodedAttributes)...,
	)
	message := append(encodeTestInteger(messageID), encodeTestTLV(0x64, entry)...)
	return encodeTestTLV(0x30, message)
}

func ldapSearchReferencePacket(messageID int, referralURLs ...string) []byte {
	referrals := make([]byte, 0)
	for _, referralURL := range referralURLs {
		referrals = append(referrals, encodeTestTLV(0x04, []byte(referralURL))...)
	}
	message := append(encodeTestInteger(messageID), encodeTestTLV(0x73, referrals)...)
	return encodeTestTLV(0x30, message)
}

func ldapSearchDoneReferralPacket(messageID int, referralURLs ...string) []byte {
	referrals := make([]byte, 0)
	for _, referralURL := range referralURLs {
		referrals = append(referrals, encodeTestTLV(0x04, []byte(referralURL))...)
	}
	result := []byte{0x0a, 0x01, 0x0a, 0x04, 0x00, 0x04, 0x00}
	result = append(result, encodeTestTLV(0xa3, referrals)...)
	message := append(encodeTestInteger(messageID), encodeTestTLV(0x65, result)...)
	return encodeTestTLV(0x30, message)
}

func ldapSearchDonePagingPacket(messageID int, resultCode byte, cookie []byte) []byte {
	result := []byte{0x0a, 0x01, resultCode, 0x04, 0x00, 0x04, 0x00}
	message := append(encodeTestInteger(messageID), encodeTestTLV(0x65, result)...)
	pagingValue := append(encodeTestInteger(0), encodeTestTLV(0x04, cookie)...)
	control := append(
		encodeTestTLV(0x04, []byte("1.2.840.113556.1.4.319")),
		encodeTestTLV(0x04, encodeTestTLV(0x30, pagingValue))...,
	)
	message = append(message, encodeTestTLV(0xa0, encodeTestTLV(0x30, control))...)
	return encodeTestTLV(0x30, message)
}

func encodeTestInteger(value int) []byte {
	if value < 0 {
		panic("negative test integer")
	}
	encoded := []byte{byte(value)}
	for remaining := value >> 8; remaining > 0; remaining >>= 8 {
		encoded = append([]byte{byte(remaining)}, encoded...)
	}
	if encoded[0]&0x80 != 0 {
		encoded = append([]byte{0}, encoded...)
	}
	return encodeTestTLV(0x02, encoded)
}

func encodeTestTLV(tag byte, value []byte) []byte {
	packet := []byte{tag}
	switch {
	case len(value) < 0x80:
		packet = append(packet, byte(len(value)))
	case len(value) <= 0xff:
		packet = append(packet, 0x81, byte(len(value)))
	default:
		packet = append(packet, 0x82, byte(len(value)>>8), byte(len(value)))
	}
	return append(packet, value...)
}

func serveLDAPSBind(
	connection net.Conn,
	configuration *tls.Config,
	resultCode byte,
	onBind func([]byte) error,
) error {
	tlsConnection := tls.Server(connection, configuration)
	if err := tlsConnection.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake: %w", err)
	}
	packet, err := readBERPacket(tlsConnection)
	if err != nil {
		return fmt.Errorf("read bind: %w", err)
	}
	messageID, operation, err := ldapMessageIDAndOperation(packet)
	if err != nil {
		return err
	}
	if operation != 0x60 {
		return fmt.Errorf("first encrypted LDAP operation = %#x, want bind", operation)
	}
	if onBind != nil {
		if err := onBind(packet); err != nil {
			return err
		}
	}
	_, err = tlsConnection.Write(ldapResultPacket(messageID, 0x61, resultCode))
	return err
}

func serveStartTLSBind(
	connection net.Conn,
	configuration *tls.Config,
	startTLSResult byte,
	bindResult byte,
	onPlaintext func([]byte) error,
) error {
	packet, err := readBERPacket(connection)
	if err != nil {
		return fmt.Errorf("read StartTLS: %w", err)
	}
	messageID, operation, err := ldapMessageIDAndOperation(packet)
	if err != nil {
		return err
	}
	if operation != 0x77 {
		return fmt.Errorf("first plaintext LDAP operation = %#x, want StartTLS", operation)
	}
	if onPlaintext != nil {
		if err := onPlaintext(packet); err != nil {
			return err
		}
	}
	if _, err := connection.Write(ldapResultPacket(messageID, 0x78, startTLSResult)); err != nil {
		return err
	}
	if startTLSResult != 0 {
		return nil
	}
	return serveLDAPSBind(connection, configuration, bindResult, nil)
}
