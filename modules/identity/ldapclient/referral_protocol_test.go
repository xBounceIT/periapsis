package ldapclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthenticateDirectoryFollowsAllowedReferralWithServiceCredentialOnly(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	serviceSecretCanary := []byte("referral-service-secret")
	userPasswordCanary := []byte("referral-user-password")
	var connectionNumber atomic.Int32
	var userBinds atomic.Int32
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		switch connectionNumber.Add(1) {
		case 1:
			tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(connection, pki.serverTLSConfig(nil))
			if err != nil || operation != 0x60 || !bytes.Contains(bindPacket, serviceSecretCanary) ||
				bytes.Contains(bindPacket, userPasswordCanary) {
				return errors.New("primary service bind used the wrong credential")
			}
			if err := writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 0)); err != nil {
				return err
			}
			_, locateID, err := readTestLDAPRequest(tlsConnection, 0x63)
			if err != nil {
				return err
			}
			if err := writeTestLDAPPackets(
				tlsConnection,
				ldapSearchReferencePacket(locateID, "ldaps://referral.example.com:636"),
				ldapSearchDonePagingPacket(locateID, 0, nil),
			); err != nil {
				return err
			}
			_, attributeID, err := readTestLDAPRequest(tlsConnection, 0x63)
			if err != nil {
				return err
			}
			return writeTestLDAPPackets(
				tlsConnection,
				ldapSearchEntryPacket(attributeID, "uid=alice,ou=people,dc=example,dc=com", nil),
				ldapSearchDonePagingPacket(attributeID, 0, nil),
			)
		case 2:
			tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(connection, pki.serverTLSConfig(nil))
			if err != nil || operation != 0x60 || !bytes.Contains(bindPacket, serviceSecretCanary) ||
				bytes.Contains(bindPacket, userPasswordCanary) {
				return errors.New("referral did not use the isolated service credential")
			}
			if err := writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 0)); err != nil {
				return err
			}
			_, searchID, err := readTestLDAPRequest(tlsConnection, 0x63)
			if err != nil {
				return err
			}
			return writeTestLDAPPackets(
				tlsConnection,
				ldapSearchEntryPacket(searchID, "uid=alice,ou=people,dc=example,dc=com", nil),
				ldapSearchDonePagingPacket(searchID, 0, nil),
			)
		case 3:
			tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(connection, pki.serverTLSConfig(nil))
			if err != nil || operation != 0x60 || !bytes.Contains(bindPacket, userPasswordCanary) ||
				bytes.Contains(bindPacket, serviceSecretCanary) {
				return errors.New("user credential was not isolated to the original endpoint")
			}
			userBinds.Add(1)
			return writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 0))
		default:
			return errors.New("unexpected referral authentication connection")
		}
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := configuredReferralDirectoryRequest(t, pki.caPEM)
	bindSecret := append([]byte(nil), serviceSecretCanary...)
	userPassword := append([]byte(nil), userPasswordCanary...)
	result, err := client.AuthenticateDirectory(context.Background(), request, bindSecret, userPassword)
	if err != nil || result.Category != DirectoryCategorySuccess || result.EndpointPriority != 1 {
		t.Fatalf("AuthenticateDirectory() = %s, %v", result, err)
	}
	if connectionNumber.Load() != 3 || userBinds.Load() != 1 {
		t.Fatalf("connections = %d, user binds = %d", connectionNumber.Load(), userBinds.Load())
	}
	if !allZeroBytes(bindSecret) || !allZeroBytes(userPassword) {
		t.Fatal("referral authentication retained credentials")
	}
	for range 3 {
		dialer.wait(t)
	}
}

func TestAuthenticateDirectoryRejectsCrossOriginReferralBeforeCredentialForwarding(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	userPasswordCanary := []byte("cross-origin-user-password")
	var connections atomic.Int32
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		connections.Add(1)
		tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(connection, pki.serverTLSConfig(nil))
		if err != nil || operation != 0x60 || bytes.Contains(bindPacket, userPasswordCanary) {
			return errors.New("unexpected credential on primary service connection")
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
			ldapSearchDoneReferralPacket(searchID, "ldaps://foreign.example.com:636"),
		); err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, tlsConnection)
		return nil
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := configuredReferralDirectoryRequest(t, pki.caPEM)
	bindSecret := []byte("cross-origin-service-secret")
	userPassword := append([]byte(nil), userPasswordCanary...)
	result, err := client.AuthenticateDirectory(context.Background(), request, bindSecret, userPassword)
	if err != nil || result.Category != DirectoryCategoryReferralRejected || connections.Load() != 1 {
		t.Fatalf("AuthenticateDirectory() = %s, %v, connections=%d", result, err, connections.Load())
	}
	if !allZeroBytes(bindSecret) || !allZeroBytes(userPassword) {
		t.Fatal("cross-origin rejection retained credentials")
	}
	dialer.wait(t)
}

func TestAuthenticateDirectoryNeverFollowsUserBindReferral(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	userPasswordCanary := []byte("single-user-referral-password")
	var connectionNumber atomic.Int32
	var userBinds atomic.Int32
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		switch connectionNumber.Add(1) {
		case 1:
			tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(connection, pki.serverTLSConfig(nil))
			if err != nil || operation != 0x60 || bytes.Contains(bindPacket, userPasswordCanary) {
				return errors.New("service connection received the user credential")
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
			_, _ = io.Copy(io.Discard, tlsConnection)
			return nil
		case 2:
			tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(connection, pki.serverTLSConfig(nil))
			if err != nil || operation != 0x60 || !bytes.Contains(bindPacket, userPasswordCanary) {
				return errors.New("user bind credential missing")
			}
			userBinds.Add(1)
			return writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 10))
		default:
			return errors.New("user-bind referral opened another connection")
		}
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := configuredReferralDirectoryRequest(t, pki.caPEM)
	bindSecret := []byte("user-referral-service-secret")
	userPassword := append([]byte(nil), userPasswordCanary...)
	result, err := client.AuthenticateDirectory(context.Background(), request, bindSecret, userPassword)
	if err != nil || result.Category != DirectoryCategoryReferralRejected ||
		connectionNumber.Load() != 2 || userBinds.Load() != 1 {
		t.Fatalf("AuthenticateDirectory() = %s, %v, connections=%d userBinds=%d",
			result, err, connectionNumber.Load(), userBinds.Load())
	}
	if !allZeroBytes(bindSecret) || !allZeroBytes(userPassword) {
		t.Fatal("user-bind referral retained credentials")
	}
	for range 2 {
		dialer.wait(t)
	}
}

func TestAuthenticateDirectoryRevalidatesReferralDNSAndEgress(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	var referralResolutions atomic.Int32
	resolver := resolverFunc(func(_ context.Context, _ string, host string) ([]netip.Addr, error) {
		if host == "referral.example.com" {
			referralResolutions.Add(1)
			return []netip.Addr{netip.MustParseAddr("10.0.0.7")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	var connections atomic.Int32
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		connections.Add(1)
		tlsConnection, _, bindID, operation, err := serveTestLDAPSRequest(connection, pki.serverTLSConfig(nil))
		if err != nil || operation != 0x60 {
			return errors.New("primary service bind missing")
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
			ldapSearchReferencePacket(searchID, "ldaps://referral.example.com:636"),
			ldapSearchDonePagingPacket(searchID, 0, nil),
		); err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, tlsConnection)
		return nil
	})
	client, err := New(testOptions(resolver, dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := configuredReferralDirectoryRequest(t, pki.caPEM)
	bindSecret := []byte("egress-service-secret")
	userPassword := []byte("egress-user-password")
	result, err := client.AuthenticateDirectory(context.Background(), request, bindSecret, userPassword)
	if err != nil || result.Category != DirectoryCategoryDestinationBlocked ||
		connections.Load() != 1 || referralResolutions.Load() != 1 {
		t.Fatalf("AuthenticateDirectory() = %s, %v, connections=%d resolutions=%d",
			result, err, connections.Load(), referralResolutions.Load())
	}
	if !allZeroBytes(bindSecret) || !allZeroBytes(userPassword) {
		t.Fatal("egress rejection retained credentials")
	}
	dialer.wait(t)
}

func TestAuthenticateDirectoryCancellationClosesReferralSearch(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	referralSearchStarted := make(chan struct{})
	var connectionNumber atomic.Int32
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		switch connectionNumber.Add(1) {
		case 1:
			tlsConnection, _, bindID, operation, err := serveTestLDAPSRequest(connection, pki.serverTLSConfig(nil))
			if err != nil || operation != 0x60 {
				return errors.New("primary service bind missing")
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
				ldapSearchReferencePacket(searchID, "ldaps://referral.example.com:636"),
				ldapSearchDonePagingPacket(searchID, 0, nil),
			); err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, tlsConnection)
			return nil
		case 2:
			tlsConnection, _, bindID, operation, err := serveTestLDAPSRequest(connection, pki.serverTLSConfig(nil))
			if err != nil || operation != 0x60 {
				return errors.New("referral service bind missing")
			}
			if err := writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 0)); err != nil {
				return err
			}
			if _, _, err := readTestLDAPRequest(tlsConnection, 0x63); err != nil {
				return err
			}
			close(referralSearchStarted)
			buffer := make([]byte, 1)
			if _, err := tlsConnection.Read(buffer); err == nil {
				return errors.New("cancelled referral connection remained open")
			}
			return nil
		default:
			return errors.New("unexpected connection after referral cancellation")
		}
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := configuredReferralDirectoryRequest(t, pki.caPEM)
	ctx, cancel := context.WithCancel(context.Background())
	bindSecret := []byte("cancel-referral-service")
	userPassword := []byte("cancel-referral-user")
	resultChannel := make(chan DirectoryResult, 1)
	go func() {
		result, _ := client.AuthenticateDirectory(ctx, request, bindSecret, userPassword)
		resultChannel <- result
	}()
	select {
	case <-referralSearchStarted:
	case <-time.After(time.Second):
		t.Fatal("referral search did not start")
	}
	cancel()
	select {
	case result := <-resultChannel:
		if result.Category != DirectoryCategoryCancelled {
			t.Fatalf("cancelled referral result = %s", result)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled referral search did not stop")
	}
	if !allZeroBytes(bindSecret) || !allZeroBytes(userPassword) {
		t.Fatal("cancelled referral search retained credentials")
	}
	for range 2 {
		dialer.wait(t)
	}
}

func TestAuthenticateDirectoryRejectsReferralLoopWithoutUserBind(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	serviceSecretCanary := []byte("loop-service-secret")
	userPasswordCanary := []byte("loop-user-password")
	var connectionNumber atomic.Int32
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		targetURL := "ldaps://referral.example.com:636"
		if connectionNumber.Add(1) == 2 {
			targetURL = "ldaps://primary.example.com:636"
		}
		tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(connection, pki.serverTLSConfig(nil))
		if err != nil || operation != 0x60 || !bytes.Contains(bindPacket, serviceSecretCanary) ||
			bytes.Contains(bindPacket, userPasswordCanary) {
			return errors.New("referral loop forwarded the wrong credential")
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
			ldapSearchReferencePacket(searchID, targetURL),
			ldapSearchDonePagingPacket(searchID, 0, nil),
		); err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, tlsConnection)
		return nil
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := configuredReferralDirectoryRequest(t, pki.caPEM)
	request.Configuration.Endpoints[0].ReferralAllowed = true
	bindSecret := append([]byte(nil), serviceSecretCanary...)
	userPassword := append([]byte(nil), userPasswordCanary...)
	result, err := client.AuthenticateDirectory(context.Background(), request, bindSecret, userPassword)
	if err != nil || result.Category != DirectoryCategoryReferralRejected || connectionNumber.Load() != 2 {
		t.Fatalf("AuthenticateDirectory() = %s, %v, connections=%d", result, err, connectionNumber.Load())
	}
	if !allZeroBytes(bindSecret) || !allZeroBytes(userPassword) {
		t.Fatal("referral-loop rejection retained credentials")
	}
	for range 2 {
		dialer.wait(t)
	}
}

func TestAuthenticateDirectoryReferralURLsShareDecodedResponseBudget(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	longLabel := strings.Repeat("a", 60)
	referralURLs := make([]string, 0, 5)
	referralEndpoints := make([]Endpoint, 0, 5)
	for index := range 5 {
		host := fmt.Sprintf("r%d.%s.%s.%s.example.com", index, longLabel, longLabel, longLabel)
		referralURLs = append(referralURLs, "ldaps://"+host+":636")
		referralEndpoints = append(referralEndpoints, Endpoint{
			Priority: index + 2, Enabled: true, ReferralAllowed: true,
			Host: host, Port: 636, Transport: TransportLDAPS, TLSServerName: "ldap.example.com",
		})
	}
	var connections atomic.Int32
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		connections.Add(1)
		tlsConnection, _, bindID, operation, err := serveTestLDAPSRequest(connection, pki.serverTLSConfig(nil))
		if err != nil || operation != 0x60 {
			return errors.New("primary service bind missing")
		}
		if err := writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 0)); err != nil {
			return err
		}
		_, searchID, err := readTestLDAPRequest(tlsConnection, 0x63)
		if err != nil {
			return err
		}
		packets := make([][]byte, 0, len(referralURLs)+1)
		for _, referralURL := range referralURLs {
			packets = append(packets, ldapSearchReferencePacket(searchID, referralURL))
		}
		packets = append(packets, ldapSearchDonePagingPacket(searchID, 0, nil))
		if err := writeTestLDAPPackets(tlsConnection, packets...); err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, tlsConnection)
		return nil
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := configuredReferralDirectoryRequest(t, pki.caPEM)
	request.Configuration.Endpoints = append(request.Configuration.Endpoints[:1], referralEndpoints...)
	request.Limits.MaxResponseBytes = minimumDirectoryResponseBytes
	bindSecret := []byte("budget-service-secret")
	userPassword := []byte("budget-user-password")
	result, err := client.AuthenticateDirectory(context.Background(), request, bindSecret, userPassword)
	if err != nil || result.Category != DirectoryCategoryLimitExceeded || connections.Load() != 1 {
		t.Fatalf("AuthenticateDirectory() = %s, %v, connections=%d", result, err, connections.Load())
	}
	if !allZeroBytes(bindSecret) || !allZeroBytes(userPassword) {
		t.Fatal("referral-budget rejection retained credentials")
	}
	dialer.wait(t)
}

func configuredReferralDirectoryRequest(t *testing.T, customCA []byte) DirectoryRequest {
	t.Helper()
	request := validDirectoryRequest(t)
	request.Configuration.CustomCAPEM = customCA
	request.Configuration.Endpoints = []Endpoint{
		{
			Priority: 1, Enabled: true,
			Host: "primary.example.com", Port: 636, Transport: TransportLDAPS,
			TLSServerName: "ldap.example.com",
		},
		{
			Priority: 2, Enabled: true, ReferralAllowed: true,
			Host: "referral.example.com", Port: 636, Transport: TransportLDAPS,
			TLSServerName: "ldap.example.com",
		},
	}
	request.ReferralMode = DirectoryReferralModeConfiguredEndpoints
	request.ReferralMaxHops = 2
	return request
}
