package ldapclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func serveTestLDAPSRequest(
	connection net.Conn,
	configuration *tls.Config,
) (*tls.Conn, []byte, int, byte, error) {
	tlsConnection := tls.Server(connection, configuration)
	if err := tlsConnection.Handshake(); err != nil {
		return nil, nil, 0, 0, err
	}
	packet, err := readBERPacket(tlsConnection)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	messageID, operation, err := ldapMessageIDAndOperation(packet)
	return tlsConnection, packet, messageID, operation, err
}

func readTestLDAPRequest(connection net.Conn, wanted byte) ([]byte, int, error) {
	packet, err := readBERPacket(connection)
	if err != nil {
		return nil, 0, err
	}
	messageID, operation, err := ldapMessageIDAndOperation(packet)
	if err != nil {
		return nil, 0, err
	}
	if operation != wanted {
		return nil, 0, errors.New("unexpected LDAP operation")
	}
	return packet, messageID, nil
}

func writeTestLDAPPackets(connection net.Conn, packets ...[]byte) error {
	for _, packet := range packets {
		if _, err := connection.Write(packet); err != nil {
			return err
		}
	}
	return nil
}

func TestAuthenticateDirectoryUsesManualPagingAndSeparateSameEndpointUserBind(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	serviceSecretCanary := []byte("service-secret-canary")
	userPasswordCanary := []byte("user-password-canary")
	var connectionNumber atomic.Int32
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		switch connectionNumber.Add(1) {
		case 1:
			tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(
				connection,
				pki.serverTLSConfig(nil),
			)
			if err != nil || operation != 0x60 {
				return errors.New("service connection did not bind first")
			}
			if !bytes.Contains(bindPacket, serviceSecretCanary) || bytes.Contains(bindPacket, userPasswordCanary) {
				return errors.New("service bind used the wrong credential")
			}
			if err := writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 0)); err != nil {
				return err
			}

			_, searchID, err := readTestLDAPRequest(tlsConnection, 0x63)
			if err != nil {
				return err
			}
			if err := writeTestLDAPPackets(
				tlsConnection,
				ldapSearchEntryPacket(searchID, "uid=alice,ou=people,dc=example,dc=com", nil),
				ldapSearchDonePagingPacket(searchID, 0, []byte("user-page-two")),
			); err != nil {
				return err
			}
			secondSearch, secondSearchID, err := readTestLDAPRequest(tlsConnection, 0x63)
			if err != nil {
				return err
			}
			if !bytes.Contains(secondSearch, []byte("user-page-two")) {
				return errors.New("second search omitted the RFC2696 cookie")
			}
			if err := writeTestLDAPPackets(
				tlsConnection,
				ldapSearchDonePagingPacket(secondSearchID, 0, nil),
			); err != nil {
				return err
			}

			_, attributeSearchID, err := readTestLDAPRequest(tlsConnection, 0x63)
			if err != nil {
				return err
			}
			return writeTestLDAPPackets(
				tlsConnection,
				ldapSearchEntryPacket(
					attributeSearchID,
					"uid=alice,ou=people,dc=example,dc=com",
					[]testLDAPAttribute{
						{name: "uid", values: [][]byte{[]byte("alice")}},
						{name: "memberOf", values: [][]byte{[]byte("cn=responders,ou=groups,dc=example,dc=com")}},
					},
				),
				ldapSearchDonePagingPacket(attributeSearchID, 0, nil),
			)
		case 2:
			tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(
				connection,
				pki.serverTLSConfig(nil),
			)
			if err != nil || operation != 0x60 {
				return errors.New("user connection did not bind first")
			}
			if !bytes.Contains(bindPacket, userPasswordCanary) || bytes.Contains(bindPacket, serviceSecretCanary) {
				return errors.New("user bind used the wrong credential")
			}
			return writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 0))
		default:
			return errors.New("authentication opened an unexpected connection")
		}
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := validDirectoryRequest(t)
	request.Configuration.CustomCAPEM = pki.caPEM
	bindSecret := append([]byte(nil), serviceSecretCanary...)
	userPassword := append([]byte(nil), userPasswordCanary...)
	result, err := client.AuthenticateDirectory(context.Background(), request, bindSecret, userPassword)
	if err != nil || result.Category != DirectoryCategorySuccess || result.EndpointPriority != 1 {
		t.Fatalf("AuthenticateDirectory() result = %#v, error = %v", result, err)
	}
	if got := len(result.Observation.Groups); got != 1 ||
		result.Observation.Groups[0].DistinguishedName != "cn=responders,ou=groups,dc=example,dc=com" {
		t.Fatalf("group observation = %#v", result.Observation.Groups)
	}
	if !allZeroBytes(bindSecret) || !allZeroBytes(userPassword) {
		t.Fatal("AuthenticateDirectory() retained caller-owned credentials")
	}
	if got := connectionNumber.Load(); got != 2 {
		t.Fatalf("connection count = %d, want service plus user", got)
	}
	dialer.wait(t)
	dialer.wait(t)
}

func TestAuthenticateDirectoryInvalidCredentialsAreAttemptedExactlyOnceWithoutFailover(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	userPasswordCanary := []byte("single-attempt-password")
	var connectionNumber atomic.Int32
	var userBindAttempts atomic.Int32
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		switch connectionNumber.Add(1) {
		case 1:
			tlsConnection, _, bindID, operation, err := serveTestLDAPSRequest(connection, pki.serverTLSConfig(nil))
			if err != nil || operation != 0x60 {
				return errors.New("service bind missing")
			}
			if err := writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 0)); err != nil {
				return err
			}
			_, searchID, err := readTestLDAPRequest(tlsConnection, 0x63)
			if err != nil {
				return err
			}
			if err := writeTestLDAPPackets(
				tlsConnection,
				ldapSearchEntryPacket(searchID, "uid=alice,ou=people,dc=example,dc=com", nil),
				ldapSearchDonePagingPacket(searchID, 0, nil),
			); err != nil {
				return err
			}
			_, err = io.Copy(io.Discard, tlsConnection)
			return err
		case 2:
			tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(connection, pki.serverTLSConfig(nil))
			if err != nil || operation != 0x60 || !bytes.Contains(bindPacket, userPasswordCanary) {
				return errors.New("user credential bind missing")
			}
			userBindAttempts.Add(1)
			return writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 49))
		default:
			return errors.New("invalid credential was failed over")
		}
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := validDirectoryRequest(t)
	request.Configuration.CustomCAPEM = pki.caPEM
	request.Configuration.Endpoints = []Endpoint{
		{Priority: 1, Enabled: true, Host: "first.example.com", Port: 636, Transport: TransportLDAPS, TLSServerName: "ldap.example.com"},
		{Priority: 2, Enabled: true, Host: "second.example.com", Port: 636, Transport: TransportLDAPS, TLSServerName: "ldap.example.com"},
	}
	bindSecret := []byte("service-secret")
	userPassword := append([]byte(nil), userPasswordCanary...)
	result, err := client.AuthenticateDirectory(context.Background(), request, bindSecret, userPassword)
	if err != nil || result.Category != DirectoryCategoryCredentialsRejected || result.EndpointPriority != 1 {
		t.Fatalf("AuthenticateDirectory() result = %#v, error = %v", result, err)
	}
	if userBindAttempts.Load() != 1 || connectionNumber.Load() != 2 {
		t.Fatalf("user binds = %d, connections = %d", userBindAttempts.Load(), connectionNumber.Load())
	}
	if !allZeroBytes(bindSecret) || !allZeroBytes(userPassword) {
		t.Fatal("invalid-credential path retained credentials")
	}
	dialer.wait(t)
	dialer.wait(t)
}

func TestAuthenticateDirectoryRequiresExactlyOneLocatedUserBeforeCredentialProof(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		entries  []string
		category DirectoryCategory
	}{
		{name: "zero", category: DirectoryCategoryUserNotFound},
		{
			name: "ambiguous",
			entries: []string{
				"uid=alice,ou=people,dc=example,dc=com",
				"uid=alice-copy,ou=people,dc=example,dc=com",
			},
			category: DirectoryCategoryUserAmbiguous,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			pki := newTestPKI(t, "ldap.example.com")
			userPasswordCanary := []byte("must-not-be-sent")
			var connections atomic.Int32
			dialer := newPipeScriptDialer(func(connection net.Conn) error {
				connections.Add(1)
				tlsConnection, _, bindID, operation, err := serveTestLDAPSRequest(connection, pki.serverTLSConfig(nil))
				if err != nil || operation != 0x60 {
					return errors.New("service bind missing")
				}
				if err := writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 0)); err != nil {
					return err
				}
				searchPacket, searchID, err := readTestLDAPRequest(tlsConnection, 0x63)
				if err != nil || bytes.Contains(searchPacket, userPasswordCanary) {
					return errors.New("user credential crossed the locate query")
				}
				packets := make([][]byte, 0, len(test.entries)+1)
				for _, distinguishedName := range test.entries {
					packets = append(packets, ldapSearchEntryPacket(searchID, distinguishedName, nil))
				}
				packets = append(packets, ldapSearchDonePagingPacket(searchID, 0, nil))
				if err := writeTestLDAPPackets(tlsConnection, packets...); err != nil {
					return err
				}
				_, err = io.Copy(io.Discard, tlsConnection)
				return err
			})
			client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			request := validDirectoryRequest(t)
			request.Configuration.CustomCAPEM = pki.caPEM
			bindSecret := []byte("service-secret")
			userPassword := append([]byte(nil), userPasswordCanary...)
			result, err := client.AuthenticateDirectory(context.Background(), request, bindSecret, userPassword)
			if err != nil || result.Category != test.category {
				t.Fatalf("AuthenticateDirectory() result = %#v, error = %v", result, err)
			}
			if connections.Load() != 1 {
				t.Fatalf("connection count = %d; user bind must not start", connections.Load())
			}
			if !allZeroBytes(bindSecret) || !allZeroBytes(userPassword) {
				t.Fatal("cardinality failure retained credentials")
			}
			dialer.wait(t)
		})
	}
}

func TestAuthenticateDirectoryCancellationClosesBlockedSearchAndClearsCredentials(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	searchReceived := make(chan struct{})
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		tlsConnection, _, bindID, operation, err := serveTestLDAPSRequest(connection, pki.serverTLSConfig(nil))
		if err != nil || operation != 0x60 {
			return errors.New("service bind missing")
		}
		if err := writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 0)); err != nil {
			return err
		}
		if _, _, err := readTestLDAPRequest(tlsConnection, 0x63); err != nil {
			return err
		}
		close(searchReceived)
		buffer := make([]byte, 1)
		_, err = tlsConnection.Read(buffer)
		if err == nil {
			return errors.New("cancelled search connection remained open")
		}
		return nil
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := validDirectoryRequest(t)
	request.Configuration.CustomCAPEM = pki.caPEM
	ctx, cancel := context.WithCancel(context.Background())
	bindSecret := []byte("cancelled-service-secret")
	userPassword := []byte("cancelled-user-password")
	resultChannel := make(chan DirectoryResult, 1)
	go func() {
		result, _ := client.AuthenticateDirectory(ctx, request, bindSecret, userPassword)
		resultChannel <- result
	}()
	select {
	case <-searchReceived:
	case <-time.After(time.Second):
		t.Fatal("server did not receive search")
	}
	cancel()
	select {
	case result := <-resultChannel:
		if result.Category != DirectoryCategoryCancelled {
			t.Fatalf("cancelled result = %#v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("AuthenticateDirectory() did not stop after cancellation")
	}
	if !allZeroBytes(bindSecret) || !allZeroBytes(userPassword) {
		t.Fatal("cancelled authentication retained credentials")
	}
	dialer.wait(t)
}

func TestAuthenticateDirectoryTotalDeadlineClosesBlockedSearch(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		tlsConnection, _, bindID, operation, err := serveTestLDAPSRequest(connection, pki.serverTLSConfig(nil))
		if err != nil || operation != 0x60 {
			return errors.New("service bind missing")
		}
		if err := writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 0)); err != nil {
			return err
		}
		if _, _, err := readTestLDAPRequest(tlsConnection, 0x63); err != nil {
			return err
		}
		buffer := make([]byte, 1)
		_, err = tlsConnection.Read(buffer)
		if err == nil {
			return errors.New("deadline-expired search connection remained open")
		}
		return nil
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := validDirectoryRequest(t)
	request.Configuration.CustomCAPEM = pki.caPEM
	// Leave enough headroom for the in-memory TLS handshake when the full Go
	// suite is CPU-saturated. The assertion is about the total operation
	// deadline closing an already-blocked search, not the minimum timeout.
	request.Configuration.ConnectTimeout = 5 * minimumConnectTimeout
	request.Configuration.OperationTimeout = 5 * minimumOperationTimeout
	bindSecret := []byte("deadline-service-secret")
	userPassword := []byte("deadline-user-password")
	startedAt := time.Now()
	result, err := client.AuthenticateDirectory(context.Background(), request, bindSecret, userPassword)
	if err != nil || result.Category != DirectoryCategoryConnectTimeout {
		t.Fatalf("AuthenticateDirectory() result = %#v, error = %v", result, err)
	}
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("directory deadline took %v", elapsed)
	}
	if !allZeroBytes(bindSecret) || !allZeroBytes(userPassword) {
		t.Fatal("deadline path retained credentials")
	}
	dialer.wait(t)
}
