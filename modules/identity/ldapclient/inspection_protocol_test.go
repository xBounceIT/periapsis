package ldapclient

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestSearchDirectoryUserUsesOneServiceBindAndReportsAmbiguityWithoutUserBind(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	serviceSecretCanary := []byte("inspection-service-secret-canary")
	userPasswordCanary := []byte("inspection-user-password-must-never-cross")
	firstValue := []byte("alice")
	var connections atomic.Int32
	var binds atomic.Int32
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		connections.Add(1)
		tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(
			connection,
			pki.serverTLSConfig(nil),
		)
		if err != nil || operation != 0x60 {
			return errors.New("inspection connection did not service-bind first")
		}
		binds.Add(1)
		if !bytes.Contains(bindPacket, serviceSecretCanary) || bytes.Contains(bindPacket, userPasswordCanary) {
			return errors.New("inspection bind used a non-service credential")
		}
		if err := writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 0)); err != nil {
			return err
		}
		searchPacket, searchID, err := readTestLDAPRequest(tlsConnection, 0x63)
		if err != nil || !bytes.Contains(searchPacket, []byte("alice")) ||
			bytes.Contains(searchPacket, userPasswordCanary) {
			return errors.New("inspection search omitted the typed user or carried a credential")
		}
		return writeTestLDAPPackets(
			tlsConnection,
			ldapSearchEntryPacket(
				searchID,
				"uid=alice,ou=people,dc=example,dc=com",
				[]testLDAPAttribute{{name: "uid", values: [][]byte{firstValue}}},
			),
			ldapSearchEntryPacket(
				searchID,
				"uid=alice-copy,ou=people,dc=example,dc=com",
				[]testLDAPAttribute{{name: "uid", values: [][]byte{[]byte("alice-copy")}}},
			),
			ldapSearchDonePagingPacket(searchID, 0, nil),
		)
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := validDirectorySearchUserRequest(t)
	request.Configuration.Network.CustomCAPEM = pki.caPEM
	request.Attributes = []string{"uid"}
	bindSecret := append([]byte(nil), serviceSecretCanary...)
	result, err := client.SearchDirectoryUser(context.Background(), request, bindSecret)
	if err != nil || result.Category != DirectoryCategorySuccess || result.EndpointPriority != 1 ||
		!result.Truncated || len(result.Entries) != 1 {
		t.Fatalf("SearchDirectoryUser() result = %#v, error = %v", result, err)
	}
	if cap(result.Entries) != len(result.Entries) {
		t.Fatalf("projected entry slice exposes hidden capacity: len = %d, cap = %d", len(result.Entries), cap(result.Entries))
	}
	if got := string(result.Entries[0].Attributes[0].Values[0]); got != "alice" {
		t.Fatalf("projected value = %q", got)
	}
	firstValue[0] = 'X'
	if got := string(result.Entries[0].Attributes[0].Values[0]); got != "alice" {
		t.Fatalf("projected entry aliases caller/server memory: %q", got)
	}
	if !allZeroBytes(bindSecret) {
		t.Fatal("SearchDirectoryUser() retained the service secret")
	}
	if connections.Load() != 1 || binds.Load() != 1 {
		t.Fatalf("connections = %d, binds = %d; inspection must not open a user-bind connection", connections.Load(), binds.Load())
	}
	dialer.wait(t)
}

func TestDirectoryFilterInspectionUsesManualPagingAndHardProjectionLimit(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	serviceSecretCanary := []byte("paged-inspection-service-secret")
	var binds atomic.Int32
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(
			connection,
			pki.serverTLSConfig(nil),
		)
		if err != nil || operation != 0x60 || !bytes.Contains(bindPacket, serviceSecretCanary) {
			return errors.New("paged inspection service bind missing")
		}
		binds.Add(1)
		if err := writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 0)); err != nil {
			return err
		}
		_, firstSearchID, err := readTestLDAPRequest(tlsConnection, 0x63)
		if err != nil {
			return err
		}
		if err := writeTestLDAPPackets(
			tlsConnection,
			ldapSearchEntryPacket(firstSearchID, "uid=one,ou=people,dc=example,dc=com", nil),
			ldapSearchEntryPacket(firstSearchID, "uid=two,ou=people,dc=example,dc=com", nil),
			ldapSearchDonePagingPacket(firstSearchID, 0, []byte("inspection-next-page")),
		); err != nil {
			return err
		}
		secondSearch, secondSearchID, err := readTestLDAPRequest(tlsConnection, 0x63)
		if err != nil || !bytes.Contains(secondSearch, []byte("inspection-next-page")) {
			return errors.New("inspection did not continue RFC2696 paging")
		}
		return writeTestLDAPPackets(
			tlsConnection,
			ldapSearchEntryPacket(secondSearchID, "uid=three,ou=people,dc=example,dc=com", nil),
			ldapSearchDonePagingPacket(secondSearchID, 0, nil),
		)
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := validDirectoryFilterTestRequest(t)
	request.Configuration.Network.CustomCAPEM = pki.caPEM
	request.Configuration.Limits.PageSize = 2
	request.MaxResults = 2
	request.UserAttributes = nil
	bindSecret := append([]byte(nil), serviceSecretCanary...)
	result, err := client.TestDirectoryFilter(context.Background(), request, bindSecret)
	if err != nil || result.Category != DirectoryCategorySuccess || !result.Truncated ||
		len(result.Entries) != 2 {
		t.Fatalf("TestDirectoryFilter() result = %#v, error = %v", result, err)
	}
	if cap(result.Entries) != len(result.Entries) {
		t.Fatalf("bounded entry slice exposes hidden capacity: len = %d, cap = %d", len(result.Entries), cap(result.Entries))
	}
	if result.Entries[0].DistinguishedName != "uid=one,ou=people,dc=example,dc=com" ||
		result.Entries[1].DistinguishedName != "uid=two,ou=people,dc=example,dc=com" {
		t.Fatalf("bounded entries = %#v", result.Entries)
	}
	if binds.Load() != 1 || !allZeroBytes(bindSecret) {
		t.Fatalf("binds = %d, secret cleared = %t", binds.Load(), allZeroBytes(bindSecret))
	}
	dialer.wait(t)
}

func TestDirectoryInspectionCancellationClosesBlockedSearchAndClearsServiceSecret(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	searchReceived := make(chan struct{})
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		tlsConnection, _, bindID, operation, err := serveTestLDAPSRequest(
			connection,
			pki.serverTLSConfig(nil),
		)
		if err != nil || operation != 0x60 {
			return errors.New("inspection service bind missing")
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
			return errors.New("cancelled inspection connection remained open")
		}
		return nil
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := validDirectoryFilterTestRequest(t)
	request.Configuration.Network.CustomCAPEM = pki.caPEM
	ctx, cancel := context.WithCancel(context.Background())
	bindSecret := []byte("cancelled-inspection-service-secret")
	resultChannel := make(chan DirectoryInspectionResult, 1)
	go func() {
		result, _ := client.TestDirectoryFilter(ctx, request, bindSecret)
		resultChannel <- result
	}()
	select {
	case <-searchReceived:
	case <-time.After(time.Second):
		t.Fatal("server did not receive inspection search")
	}
	cancel()
	select {
	case result := <-resultChannel:
		if result.Category != DirectoryCategoryCancelled {
			t.Fatalf("cancelled inspection result = %#v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("TestDirectoryFilter() did not stop after cancellation")
	}
	if !allZeroBytes(bindSecret) {
		t.Fatal("cancelled inspection retained the service secret")
	}
	dialer.wait(t)
}

func TestDirectoryInspectionReferralRevalidatesAndForwardsOnlyServiceIdentity(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "origin.example.com", "referral.example.com")
	serviceSecretCanary := []byte("referral-inspection-service-secret")
	userPasswordCanary := []byte("referral-user-password-must-never-cross")
	var connections atomic.Int32
	var originResolutions atomic.Int32
	var referralResolutions atomic.Int32
	resolver := resolverFunc(func(_ context.Context, _ string, host string) ([]netip.Addr, error) {
		switch host {
		case "origin.example.com":
			originResolutions.Add(1)
		case "referral.example.com":
			referralResolutions.Add(1)
		default:
			return nil, errors.New("unexpected host")
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		switch connections.Add(1) {
		case 1:
			tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(
				connection,
				pki.serverTLSConfig(nil),
			)
			if err != nil || operation != 0x60 || !bytes.Contains(bindPacket, serviceSecretCanary) ||
				bytes.Contains(bindPacket, userPasswordCanary) {
				return errors.New("origin inspection bind was not service-only")
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
				ldapSearchReferencePacket(searchID, "ldaps://referral.example.com:636"),
				ldapSearchDonePagingPacket(searchID, 0, nil),
			)
		case 2:
			tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(
				connection,
				pki.serverTLSConfig(nil),
			)
			if err != nil || operation != 0x60 || !bytes.Contains(bindPacket, serviceSecretCanary) ||
				bytes.Contains(bindPacket, userPasswordCanary) {
				return errors.New("referral inspection bind was not service-only")
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
		default:
			return errors.New("inspection opened an unexpected connection")
		}
	})
	client, err := New(testOptions(resolver, dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := validDirectorySearchUserRequest(t)
	request.Attributes = nil
	request.Configuration.Network = Configuration{
		Endpoints: []Endpoint{
			{Priority: 1, Enabled: true, Host: "origin.example.com", Port: 636, Transport: TransportLDAPS, TLSServerName: "origin.example.com"},
			{Priority: 2, Enabled: true, ReferralAllowed: true, Host: "referral.example.com", Port: 636, Transport: TransportLDAPS, TLSServerName: "referral.example.com"},
		},
		ConnectTimeout: 200 * time.Millisecond, OperationTimeout: time.Second,
		CustomCAPEM: pki.caPEM,
	}
	request.Configuration.ReferralMode = DirectoryReferralModeConfiguredEndpoints
	request.Configuration.ReferralMaxHops = 1
	bindSecret := append([]byte(nil), serviceSecretCanary...)
	result, err := client.SearchDirectoryUser(context.Background(), request, bindSecret)
	if err != nil || result.Category != DirectoryCategorySuccess || result.EndpointPriority != 1 ||
		result.Truncated || len(result.Entries) != 1 {
		t.Fatalf("SearchDirectoryUser() referral result = %#v, error = %v", result, err)
	}
	if connections.Load() != 2 || originResolutions.Load() != 1 || referralResolutions.Load() != 1 {
		t.Fatalf(
			"connections = %d, origin resolutions = %d, referral resolutions = %d",
			connections.Load(), originResolutions.Load(), referralResolutions.Load(),
		)
	}
	if !allZeroBytes(bindSecret) {
		t.Fatal("referral inspection retained the service secret")
	}
	dialer.wait(t)
	dialer.wait(t)
}

func TestDirectoryInspectionPreservesLastRetryableEndpointPriority(t *testing.T) {
	t.Parallel()

	var dials atomic.Int32
	client, err := New(testOptions(
		publicResolver("93.184.216.34"),
		dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("retryable dial failure with hostile details")
		}),
	))
	if err != nil {
		t.Fatal(err)
	}
	request := validDirectorySearchUserRequest(t)
	request.Configuration.Network.Endpoints = []Endpoint{
		{
			Priority: 1, Enabled: true, Host: "first.example.com", Port: 636,
			Transport: TransportLDAPS, TLSServerName: "first.example.com",
		},
		{
			Priority: 2, Enabled: true, Host: "second.example.com", Port: 636,
			Transport: TransportLDAPS, TLSServerName: "second.example.com",
		},
	}
	bindSecret := []byte("last-priority-service-secret")
	result, err := client.SearchDirectoryUser(context.Background(), request, bindSecret)
	if err != nil || result.Category != DirectoryCategoryConnectFailed || result.EndpointPriority != 2 {
		t.Fatalf("SearchDirectoryUser() result = %#v, error = %v", result, err)
	}
	if dials.Load() != 2 || !allZeroBytes(bindSecret) {
		t.Fatalf("dials = %d, secret cleared = %t", dials.Load(), allZeroBytes(bindSecret))
	}
}
