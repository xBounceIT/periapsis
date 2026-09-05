package ldapclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestLDAPSUsesValidatedIPAndOriginalTLSServerName(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	serverName := make(chan string, 1)
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		tlsConnection := tls.Server(connection, pki.serverTLSConfig(func(value string) { serverName <- value }))
		if err := tlsConnection.Handshake(); err != nil {
			return err
		}
		buffer := make([]byte, 1)
		read, err := tlsConnection.Read(buffer)
		if read != 0 || err == nil {
			return errors.New("TestConnection sent an LDAP operation")
		}
		return nil
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	configuration := testConfiguration()
	configuration.CustomCAPEM = pki.caPEM
	diagnostic, err := client.TestConnection(context.Background(), configuration)
	if err != nil || diagnostic.Category != CategorySuccess || diagnostic.Outcome != OutcomeSuccess {
		t.Fatalf("diagnostic = %#v, error = %v", diagnostic, err)
	}
	if targets := dialer.dialTargets(); len(targets) != 1 || targets[0] != "93.184.216.34:636" {
		t.Fatalf("dial targets = %v", targets)
	}
	select {
	case got := <-serverName:
		if got != "ldap.example.com" {
			t.Fatalf("TLS ServerName = %q", got)
		}
	default:
		t.Fatal("server did not receive a TLS ServerName")
	}
	dialer.wait(t)
}

func TestStartTLSConnectionSendsNoBindOrSearch(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	serverName := make(chan string, 1)
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		request, err := readBERPacket(connection)
		if err != nil {
			return err
		}
		messageID, operation, err := ldapMessageIDAndOperation(request)
		if err != nil || operation != 0x77 {
			return errors.New("expected only a StartTLS request")
		}
		if _, err := connection.Write(ldapResultPacket(messageID, 0x78, 0)); err != nil {
			return err
		}
		tlsConnection := tls.Server(connection, pki.serverTLSConfig(func(value string) { serverName <- value }))
		if err := tlsConnection.Handshake(); err != nil {
			return err
		}
		buffer := make([]byte, 1)
		read, err := tlsConnection.Read(buffer)
		if read != 0 || err == nil {
			return errors.New("TestConnection sent an encrypted LDAP operation")
		}
		return nil
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	configuration := testConfiguration()
	configuration.Endpoints[0].Port = 389
	configuration.Endpoints[0].Transport = TransportStartTLS
	configuration.CustomCAPEM = pki.caPEM
	diagnostic, err := client.TestConnection(context.Background(), configuration)
	if err != nil || diagnostic.Category != CategorySuccess {
		t.Fatalf("diagnostic = %#v, error = %v", diagnostic, err)
	}
	select {
	case got := <-serverName:
		if got != "ldap.example.com" {
			t.Fatalf("TLS ServerName = %q", got)
		}
	default:
		t.Fatal("server did not receive a TLS ServerName")
	}
	dialer.wait(t)
}

func TestTLSCertificateAndVersionFailuresAreSanitized(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		serverName string
		serverTLS  func(testPKI) *tls.Config
		category   Category
	}{
		{
			name:       "hostname mismatch",
			serverName: "wrong.example.com",
			serverTLS:  func(pki testPKI) *tls.Config { return pki.serverTLSConfig(nil) },
			category:   CategoryCertificateRejected,
		},
		{
			name:       "TLS below 1.2",
			serverName: "ldap.example.com",
			serverTLS: func(pki testPKI) *tls.Config {
				configuration := pki.serverTLSConfig(nil)
				configuration.MinVersion = tls.VersionTLS10
				configuration.MaxVersion = tls.VersionTLS11
				return configuration
			},
			category: CategoryTLSFailed,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			pki := newTestPKI(t, "ldap.example.com")
			dialer := newPipeScriptDialer(func(connection net.Conn) error {
				// The server side is expected to observe the peer rejecting this
				// handshake, so its error is not asserted separately.
				_ = tls.Server(connection, test.serverTLS(pki)).Handshake()
				return nil
			})
			client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			configuration := testConfiguration()
			configuration.CustomCAPEM = pki.caPEM
			configuration.Endpoints[0].TLSServerName = test.serverName
			diagnostic, err := client.TestConnection(context.Background(), configuration)
			if err != nil || diagnostic.Category != test.category {
				t.Fatalf("diagnostic = %#v, error = %v", diagnostic, err)
			}
			dialer.wait(t)
		})
	}
}

func TestStartTLSCompletesBeforeBind(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	secretCanary := []byte("starttls-secret-canary")
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		return serveStartTLSBind(connection, pki.serverTLSConfig(nil), 0, 0, func(plaintext []byte) error {
			if bytes.Contains(plaintext, secretCanary) {
				return errors.New("bind secret appeared before TLS")
			}
			return nil
		})
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	configuration := testConfiguration()
	configuration.Endpoints[0].Port = 389
	configuration.Endpoints[0].Transport = TransportStartTLS
	configuration.CustomCAPEM = pki.caPEM
	secret := append([]byte(nil), secretCanary...)
	diagnostic, err := client.TestBind(
		context.Background(),
		configuration,
		"cn=svc,dc=example,dc=com",
		secret,
	)
	if err != nil || diagnostic.Category != CategorySuccess {
		t.Fatalf("diagnostic = %#v, error = %v", diagnostic, err)
	}
	if !allZeroBytes(secret) {
		t.Fatal("TestBind() did not clear the caller-owned secret")
	}
	dialer.wait(t)
}

func TestStartTLSDowngradeAndHandshakeFailureNeverBind(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name           string
		handler        func(net.Conn) error
		category       Category
		serverMayError bool
	}{
		{
			name: "upgrade rejected",
			handler: func(connection net.Conn) error {
				return serveStartTLSBind(connection, nil, 52, 0, nil)
			},
			category: CategoryProtocolFailed,
		},
		{
			name: "connection closes after upgrade success",
			handler: func(connection net.Conn) error {
				request, err := readBERPacket(connection)
				if err != nil {
					return err
				}
				messageID, operation, err := ldapMessageIDAndOperation(request)
				if err != nil || operation != 0x77 {
					return errors.New("expected StartTLS request")
				}
				if _, err := connection.Write(ldapResultPacket(messageID, 0x78, 0)); err != nil {
					return err
				}
				// Closing instead of beginning TLS must not induce a
				// plaintext bind after the accepted upgrade.
				return nil
			},
			category: CategoryTLSFailed,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dialer := newPipeScriptDialer(test.handler)
			client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			configuration := testConfiguration()
			configuration.Endpoints[0].Port = 389
			configuration.Endpoints[0].Transport = TransportStartTLS
			secret := []byte("must-never-cross-plaintext")
			diagnostic, err := client.TestBind(context.Background(), configuration, "cn=svc,dc=example,dc=com", secret)
			if err != nil || diagnostic.Category != test.category {
				t.Fatalf("diagnostic = %#v, error = %v", diagnostic, err)
			}
			if !allZeroBytes(secret) {
				t.Fatal("TestBind() did not clear the secret after StartTLS failure")
			}
			dialer.wait(t)
		})
	}
}

func TestStartTLSUnknownAuthorityFailsWithoutBind(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	secretCanary := []byte("unknown-ca-bind-secret")
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		request, err := readBERPacket(connection)
		if err != nil {
			return err
		}
		messageID, operation, err := ldapMessageIDAndOperation(request)
		if err != nil || operation != 0x77 {
			return errors.New("expected StartTLS before any bind")
		}
		if bytes.Contains(request, secretCanary) {
			return errors.New("bind secret appeared before TLS")
		}
		if _, err := connection.Write(ldapResultPacket(messageID, 0x78, 0)); err != nil {
			return err
		}
		// The client must reject this random CA through Go's standard
		// verification path. go-ldap loses the typed cause but never proceeds
		// to a bind on the failed TLS session.
		if err := tls.Server(connection, pki.serverTLSConfig(nil)).Handshake(); err == nil {
			return errors.New("untrusted StartTLS certificate was accepted")
		}
		return nil
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	configuration := testConfiguration()
	configuration.Endpoints[0].Port = 389
	configuration.Endpoints[0].Transport = TransportStartTLS
	secret := append([]byte(nil), secretCanary...)
	diagnostic, err := client.TestBind(
		context.Background(),
		configuration,
		"cn=svc,dc=example,dc=com",
		secret,
	)
	if err != nil || diagnostic.Category != CategoryTLSFailed {
		t.Fatalf("diagnostic = %#v, error = %v", diagnostic, err)
	}
	if !allZeroBytes(secret) {
		t.Fatal("TestBind() did not clear the secret after certificate rejection")
	}
	dialer.wait(t)
}

func TestBindResultClassificationAndNoReferralFollowing(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		resultCode byte
		category   Category
	}{
		{name: "invalid credentials", resultCode: 49, category: CategoryBindRejected},
		{name: "referral", resultCode: 10, category: CategoryProtocolFailed},
		{name: "protocol failure", resultCode: 2, category: CategoryProtocolFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			pki := newTestPKI(t, "ldap.example.com")
			dialer := newPipeScriptDialer(func(connection net.Conn) error {
				return serveLDAPSBind(connection, pki.serverTLSConfig(nil), test.resultCode, nil)
			})
			client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			configuration := testConfiguration()
			configuration.CustomCAPEM = pki.caPEM
			secret := []byte("invalid-credential-canary")
			diagnostic, err := client.TestBind(context.Background(), configuration, "cn=svc,dc=example,dc=com", secret)
			if err != nil || diagnostic.Category != test.category {
				t.Fatalf("diagnostic = %#v, error = %v", diagnostic, err)
			}
			if len(dialer.dialTargets()) != 1 {
				t.Fatalf("unexpected referral/failover dial targets = %v", dialer.dialTargets())
			}
			if !allZeroBytes(secret) {
				t.Fatal("TestBind() did not clear the caller-owned secret")
			}
			dialer.wait(t)
		})
	}
}

func TestInvalidCredentialsStopEndpointFailover(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		return serveLDAPSBind(connection, pki.serverTLSConfig(nil), 49, nil)
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	configuration := testConfiguration()
	configuration.CustomCAPEM = pki.caPEM
	configuration.Endpoints = append(configuration.Endpoints, Endpoint{
		Priority:      2,
		Enabled:       true,
		Host:          "second.example.com",
		Port:          636,
		Transport:     TransportLDAPS,
		TLSServerName: "ldap.example.com",
	})
	secret := []byte("invalid-credential-canary")
	diagnostic, err := client.TestBind(context.Background(), configuration, "cn=svc,dc=example,dc=com", secret)
	if err != nil || diagnostic.Category != CategoryBindRejected || diagnostic.EndpointPriority != 1 {
		t.Fatalf("diagnostic = %#v, error = %v", diagnostic, err)
	}
	if len(dialer.dialTargets()) != 1 {
		t.Fatalf("invalid credentials triggered failover: %v", dialer.dialTargets())
	}
	dialer.wait(t)
}

func TestCancellationClosesDedicatedBindConnection(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	bindReceived := make(chan struct{})
	connectionClosed := make(chan struct{})
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		defer close(connectionClosed)
		tlsConnection := tls.Server(connection, pki.serverTLSConfig(nil))
		if err := tlsConnection.Handshake(); err != nil {
			return err
		}
		packet, err := readBERPacket(tlsConnection)
		if err != nil {
			return err
		}
		_, operation, err := ldapMessageIDAndOperation(packet)
		if err != nil || operation != 0x60 {
			return errors.New("expected bind")
		}
		close(bindReceived)
		buffer := make([]byte, 1)
		_, err = tlsConnection.Read(buffer)
		if err == nil {
			return errors.New("connection remained open after cancellation")
		}
		return nil
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	configuration := testConfiguration()
	configuration.CustomCAPEM = pki.caPEM
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan Diagnostic, 1)
	secret := []byte("cancelled-bind-secret")
	go func() {
		diagnostic, _ := client.TestBind(ctx, configuration, "cn=svc,dc=example,dc=com", secret)
		result <- diagnostic
	}()
	select {
	case <-bindReceived:
	case <-time.After(time.Second):
		t.Fatal("server did not receive bind")
	}
	cancel()
	select {
	case diagnostic := <-result:
		if diagnostic.Category != CategoryCancelled || diagnostic.Outcome != OutcomeFailure {
			t.Fatalf("diagnostic = %#v", diagnostic)
		}
	case <-time.After(time.Second):
		t.Fatal("TestBind() did not stop on cancellation")
	}
	select {
	case <-connectionClosed:
	case <-time.After(time.Second):
		t.Fatal("dedicated connection was not closed on cancellation")
	}
	if !allZeroBytes(secret) {
		t.Fatal("cancelled TestBind() did not clear the secret")
	}
	dialer.wait(t)
}

func TestOperationDeadlineClosesBlockedBind(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		tlsConnection := tls.Server(connection, pki.serverTLSConfig(nil))
		if err := tlsConnection.Handshake(); err != nil {
			return err
		}
		if _, err := readBERPacket(tlsConnection); err != nil {
			return err
		}
		_, err := io.Copy(io.Discard, tlsConnection)
		return err
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	configuration := testConfiguration()
	configuration.ConnectTimeout = minimumConnectTimeout
	configuration.OperationTimeout = minimumOperationTimeout
	configuration.CustomCAPEM = pki.caPEM
	secret := []byte("timed-out-bind-secret")
	startedAt := time.Now()
	diagnostic, err := client.TestBind(context.Background(), configuration, "cn=svc,dc=example,dc=com", secret)
	if err != nil || diagnostic.Category != CategoryConnectTimeout {
		t.Fatalf("diagnostic = %#v, error = %v", diagnostic, err)
	}
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("operation timeout took %v", elapsed)
	}
	if !allZeroBytes(secret) {
		t.Fatal("timed-out TestBind() did not clear the secret")
	}
	dialer.wait(t)
}

func TestEndpointFailoverIsOrderedAndBounded(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	var mu sync.Mutex
	targets := make([]string, 0, 2)
	done := make(chan error, 1)
	dialer := dialerFunc(func(_ context.Context, _ string, address string) (net.Conn, error) {
		mu.Lock()
		targets = append(targets, address)
		attempt := len(targets)
		mu.Unlock()
		if attempt == 1 {
			return nil, errors.New("first endpoint unavailable")
		}
		clientConnection, serverConnection := net.Pipe()
		go func() {
			defer serverConnection.Close()
			done <- tls.Server(serverConnection, pki.serverTLSConfig(nil)).Handshake()
		}()
		return clientConnection, nil
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	configuration := testConfiguration()
	configuration.CustomCAPEM = pki.caPEM
	configuration.Endpoints = []Endpoint{
		{Priority: 2, Enabled: true, Host: "second.example.com", Port: 636, Transport: TransportLDAPS, TLSServerName: "ldap.example.com"},
		{Priority: 1, Enabled: true, Host: "first.example.com", Port: 636, Transport: TransportLDAPS, TLSServerName: "ldap.example.com"},
	}
	diagnostic, err := client.TestConnection(context.Background(), configuration)
	if err != nil || diagnostic.Category != CategorySuccess || diagnostic.EndpointPriority != 2 {
		t.Fatalf("diagnostic = %#v, error = %v", diagnostic, err)
	}
	mu.Lock()
	gotTargets := append([]string(nil), targets...)
	mu.Unlock()
	if len(gotTargets) != 2 {
		t.Fatalf("dial targets = %v", gotTargets)
	}
	select {
	case serverErr := <-done:
		if serverErr != nil {
			t.Fatalf("TLS server error = %v", serverErr)
		}
	case <-time.After(time.Second):
		t.Fatal("TLS server did not stop")
	}
}

func TestInboundConnectionBytesAreHardBounded(t *testing.T) {
	t.Parallel()

	clientConnection, serverConnection := net.Pipe()
	writeDone := make(chan error, 1)
	go func() {
		_, err := serverConnection.Write(make([]byte, maximumDiagnosticReadBytes+1))
		writeDone <- err
	}()
	connection := &boundedReadConn{
		Conn:      clientConnection,
		remaining: maximumDiagnosticReadBytes,
	}
	buffer := make([]byte, 32*1024)
	total := 0
	var readErr error
	for readErr == nil {
		read := 0
		read, readErr = connection.Read(buffer)
		total += read
	}
	if !errors.Is(readErr, errDiagnosticReadLimit) {
		t.Fatalf("read error = %v", readErr)
	}
	if total != maximumDiagnosticReadBytes {
		t.Fatalf("read bytes = %d", total)
	}
	_ = connection.Close()
	_ = serverConnection.Close()
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("bounded writer did not stop")
	}
}

func TestInboundReadBudgetIsSharedAcrossDedicatedConnections(t *testing.T) {
	t.Parallel()

	firstClient, firstServer := net.Pipe()
	secondClient, secondServer := net.Pipe()
	defer firstClient.Close()
	defer firstServer.Close()
	defer secondClient.Close()
	defer secondServer.Close()
	budget := newInboundReadBudget(10)
	first := &boundedReadConn{Conn: firstClient, budget: budget}
	second := &boundedReadConn{Conn: secondClient, budget: budget}
	firstWrite := make(chan error, 1)
	secondWrite := make(chan error, 1)
	go func() {
		_, err := firstServer.Write([]byte("123456"))
		firstWrite <- err
	}()
	firstBuffer := make([]byte, 6)
	if count, err := first.Read(firstBuffer); err != nil || count != 6 {
		t.Fatalf("first shared read = %d, %v", count, err)
	}
	go func() {
		_, err := secondServer.Write([]byte("abcdef"))
		secondWrite <- err
	}()
	secondBuffer := make([]byte, 6)
	if count, err := second.Read(secondBuffer); err != nil || count != 4 {
		t.Fatalf("second shared read = %d, %v", count, err)
	}
	if count, err := second.Read(secondBuffer); count != 0 || !errors.Is(err, errDiagnosticReadLimit) {
		t.Fatalf("exhausted shared read = %d, %v", count, err)
	}
	if !budget.isExhausted() {
		t.Fatal("shared budget did not record exhaustion")
	}
	_ = secondServer.Close()
	select {
	case <-firstWrite:
	case <-time.After(time.Second):
		t.Fatal("first shared-budget writer did not stop")
	}
	select {
	case <-secondWrite:
	case <-time.After(time.Second):
		t.Fatal("second shared-budget writer did not stop")
	}
}
