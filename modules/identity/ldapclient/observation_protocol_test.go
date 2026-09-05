package ldapclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestObserveDirectoryUsesOneServiceBindAndReturnsCompletePOSIXGroups(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	serviceSecret := []byte("observation-service-secret-canary")
	forbiddenUserPassword := []byte("observation-user-password-must-never-cross")
	var connections atomic.Int32
	var binds atomic.Int32
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		if connections.Add(1) != 1 {
			return errors.New("observation opened a user-bind connection")
		}
		tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(
			connection,
			pki.serverTLSConfig(nil),
		)
		if err != nil || operation != 0x60 || !bytes.Contains(bindPacket, serviceSecret) ||
			bytes.Contains(bindPacket, forbiddenUserPassword) {
			return errors.New("observation did not service-bind exactly once")
		}
		binds.Add(1)
		if err := writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 0)); err != nil {
			return err
		}

		locatePacket, locateID, err := readTestLDAPRequest(tlsConnection, 0x63)
		if err != nil || bytes.Contains(locatePacket, forbiddenUserPassword) {
			return errors.New("located-user search carried a user credential")
		}
		if err := writeTestLDAPPackets(
			tlsConnection,
			ldapSearchEntryPacket(locateID, "uid=alice,ou=people,dc=example,dc=com", nil),
			ldapSearchDonePagingPacket(locateID, 0, nil),
		); err != nil {
			return err
		}

		attributePacket, attributeID, err := readTestLDAPRequest(tlsConnection, 0x63)
		if err != nil || bytes.Contains(attributePacket, forbiddenUserPassword) {
			return errors.New("attribute search carried a user credential")
		}
		if err := writeTestLDAPPackets(
			tlsConnection,
			ldapSearchEntryPacket(
				attributeID,
				"uid=alice,ou=people,dc=example,dc=com",
				[]testLDAPAttribute{{name: "uid", values: [][]byte{[]byte("alice")}}},
			),
			ldapSearchDonePagingPacket(attributeID, 0, nil),
		); err != nil {
			return err
		}

		groupPacket, groupID, err := readTestLDAPRequest(tlsConnection, 0x63)
		if err != nil || !bytes.Contains(groupPacket, []byte("alice")) ||
			bytes.Contains(groupPacket, forbiddenUserPassword) {
			return errors.New("POSIX group search was not service-bound and typed")
		}
		return writeTestLDAPPackets(
			tlsConnection,
			ldapSearchEntryPacket(
				groupID,
				"cn=responders,ou=groups,dc=example,dc=com",
				[]testLDAPAttribute{{name: "cn", values: [][]byte{[]byte("responders")}}},
			),
			ldapSearchDonePagingPacket(groupID, 0, nil),
		)
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatal(err)
	}
	request := posixObservationRequest(t)
	request.Configuration.CustomCAPEM = pki.caPEM
	bindSecret := append([]byte(nil), serviceSecret...)
	result, err := client.ObserveDirectory(context.Background(), request, bindSecret)
	if err != nil || result.Category != DirectoryCategorySuccess || result.EndpointPriority != 1 {
		t.Fatalf("ObserveDirectory() result = %#v, error = %v", result, err)
	}
	if result.Observation.User.DistinguishedName != "uid=alice,ou=people,dc=example,dc=com" ||
		len(result.Observation.Groups) != 1 ||
		result.Observation.Groups[0].DistinguishedName != "cn=responders,ou=groups,dc=example,dc=com" {
		t.Fatalf("observation = %#v", result.Observation)
	}
	if connections.Load() != 1 || binds.Load() != 1 || !allZeroBytes(bindSecret) {
		t.Fatalf(
			"connections = %d, binds = %d, secret cleared = %t",
			connections.Load(),
			binds.Load(),
			allZeroBytes(bindSecret),
		)
	}
	dialer.wait(t)
}

func TestObserveDirectoryRequiresExactlyOneLocatedUser(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name     string
		entries  []string
		category DirectoryCategory
	}{
		{name: "not found", category: DirectoryCategoryUserNotFound},
		{
			name: "ambiguous",
			entries: []string{
				"uid=alice,ou=people,dc=example,dc=com",
				"uid=alice-copy,ou=people,dc=example,dc=com",
			},
			category: DirectoryCategoryUserAmbiguous,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			pki := newTestPKI(t, "ldap.example.com")
			var connections atomic.Int32
			dialer := newPipeScriptDialer(func(connection net.Conn) error {
				connections.Add(1)
				tlsConnection, _, bindID, operation, err := serveTestLDAPSRequest(
					connection,
					pki.serverTLSConfig(nil),
				)
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
				packets := make([][]byte, 0, len(testCase.entries)+1)
				for _, distinguishedName := range testCase.entries {
					packets = append(
						packets,
						ldapSearchEntryPacket(searchID, distinguishedName, nil),
					)
				}
				packets = append(packets, ldapSearchDonePagingPacket(searchID, 0, nil))
				return writeTestLDAPPackets(tlsConnection, packets...)
			})
			client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
			if err != nil {
				t.Fatal(err)
			}
			request := validDirectoryRequest(t)
			request.Configuration.CustomCAPEM = pki.caPEM
			bindSecret := []byte("cardinality-service-secret")
			result, err := client.ObserveDirectory(context.Background(), request, bindSecret)
			if err != nil || result.Category != testCase.category || result.EndpointPriority != 1 {
				t.Fatalf("ObserveDirectory() result = %#v, error = %v", result, err)
			}
			assertZeroDirectoryObservation(t, result.Observation)
			if connections.Load() != 1 || !allZeroBytes(bindSecret) {
				t.Fatalf("connections = %d, secret cleared = %t", connections.Load(), allZeroBytes(bindSecret))
			}
			dialer.wait(t)
		})
	}
}

func TestObserveDirectoryFailsClosedWhenGroupBudgetCannotComplete(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		tlsConnection, _, bindID, operation, err := serveTestLDAPSRequest(
			connection,
			pki.serverTLSConfig(nil),
		)
		if err != nil || operation != 0x60 {
			return errors.New("service bind missing")
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
			ldapSearchEntryPacket(locateID, "uid=alice,ou=people,dc=example,dc=com", nil),
			ldapSearchDonePagingPacket(locateID, 0, nil),
		); err != nil {
			return err
		}
		_, attributeID, err := readTestLDAPRequest(tlsConnection, 0x63)
		if err != nil {
			return err
		}
		if err := writeTestLDAPPackets(
			tlsConnection,
			ldapSearchEntryPacket(
				attributeID,
				"uid=alice,ou=people,dc=example,dc=com",
				[]testLDAPAttribute{{name: "uid", values: [][]byte{[]byte("alice")}}},
			),
			ldapSearchDonePagingPacket(attributeID, 0, nil),
		); err != nil {
			return err
		}
		_, err = io.Copy(io.Discard, tlsConnection)
		return err
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatal(err)
	}
	request := posixObservationRequest(t)
	request.Configuration.CustomCAPEM = pki.caPEM
	request.Limits.MaxPages = 2
	bindSecret := []byte("budget-service-secret")
	result, err := client.ObserveDirectory(context.Background(), request, bindSecret)
	if err != nil || result.Category != DirectoryCategoryLimitExceeded || result.EndpointPriority != 1 {
		t.Fatalf("ObserveDirectory() result = %#v, error = %v", result, err)
	}
	assertZeroDirectoryObservation(t, result.Observation)
	if !allZeroBytes(bindSecret) {
		t.Fatal("budget failure retained service secret")
	}
	dialer.wait(t)
}

func TestObserveDirectoryCancellationClosesSearchAndClearsServiceSecret(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	searchReceived := make(chan struct{})
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		tlsConnection, _, bindID, operation, err := serveTestLDAPSRequest(
			connection,
			pki.serverTLSConfig(nil),
		)
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
			return errors.New("cancelled observation connection remained open")
		}
		return nil
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatal(err)
	}
	request := validDirectoryRequest(t)
	request.Configuration.CustomCAPEM = pki.caPEM
	ctx, cancel := context.WithCancel(context.Background())
	bindSecret := []byte("cancelled-observation-service-secret")
	resultChannel := make(chan DirectoryResult, 1)
	go func() {
		result, _ := client.ObserveDirectory(ctx, request, bindSecret)
		resultChannel <- result
	}()
	select {
	case <-searchReceived:
	case <-time.After(time.Second):
		t.Fatal("server did not receive observation search")
	}
	cancel()
	select {
	case result := <-resultChannel:
		if result.Category != DirectoryCategoryCancelled {
			t.Fatalf("ObserveDirectory() result = %#v", result)
		}
		assertZeroDirectoryObservation(t, result.Observation)
	case <-time.After(time.Second):
		t.Fatal("ObserveDirectory() did not stop after cancellation")
	}
	if !allZeroBytes(bindSecret) {
		t.Fatal("cancelled observation retained service secret")
	}
	dialer.wait(t)
}

func TestObserveDirectoryFollowsConfiguredReferralWithServiceIdentityOnly(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	serviceSecret := []byte("observation-referral-service-secret")
	var connections atomic.Int32
	var resolutions atomic.Int32
	resolver := resolverFunc(func(_ context.Context, _ string, host string) ([]netip.Addr, error) {
		if host != "primary.example.com" && host != "referral.example.com" {
			return nil, errors.New("unexpected referral host")
		}
		resolutions.Add(1)
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		switch connections.Add(1) {
		case 1:
			tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(
				connection,
				pki.serverTLSConfig(nil),
			)
			if err != nil || operation != 0x60 || !bytes.Contains(bindPacket, serviceSecret) {
				return errors.New("origin did not receive the service bind")
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
				ldapSearchEntryPacket(
					attributeID,
					"uid=alice,ou=people,dc=example,dc=com",
					[]testLDAPAttribute{
						{name: "uid", values: [][]byte{[]byte("alice")}},
						{name: "memberOf", values: [][]byte{[]byte("cn=responders,ou=groups,dc=example,dc=com")}},
					},
				),
				ldapSearchDonePagingPacket(attributeID, 0, nil),
			)
		case 2:
			tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(
				connection,
				pki.serverTLSConfig(nil),
			)
			if err != nil || operation != 0x60 || !bytes.Contains(bindPacket, serviceSecret) {
				return errors.New("referral did not receive only the service bind")
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
			return errors.New("observation referral opened an unexpected connection")
		}
	})
	client, err := New(testOptions(resolver, dialer))
	if err != nil {
		t.Fatal(err)
	}
	request := configuredReferralDirectoryRequest(t, pki.caPEM)
	bindSecret := append([]byte(nil), serviceSecret...)
	result, err := client.ObserveDirectory(context.Background(), request, bindSecret)
	if err != nil || result.Category != DirectoryCategorySuccess || result.EndpointPriority != 1 ||
		len(result.Observation.Groups) != 1 {
		t.Fatalf("ObserveDirectory() referral result = %#v, error = %v", result, err)
	}
	if connections.Load() != 2 || resolutions.Load() != 2 || !allZeroBytes(bindSecret) {
		t.Fatalf(
			"connections = %d, resolutions = %d, secret cleared = %t",
			connections.Load(),
			resolutions.Load(),
			allZeroBytes(bindSecret),
		)
	}
	dialer.wait(t)
	dialer.wait(t)
}

func TestObserveDirectoryClearsServiceSecretOnRejectedInput(t *testing.T) {
	t.Parallel()

	client := newValidationOnlyDirectoryClient(t)
	request := validDirectoryRequest(t)
	request.Limits.MaxPages = 0
	bindSecret := []byte("rejected-observation-service-secret")
	result, err := client.ObserveDirectory(context.Background(), request, bindSecret)
	if !errors.Is(err, ErrInvalidConfiguration) || result.Category != "" || !allZeroBytes(bindSecret) {
		t.Fatalf("ObserveDirectory() result = %#v, error = %v, secret cleared = %t", result, err, allZeroBytes(bindSecret))
	}

	oversized := bytes.Repeat([]byte{'s'}, maximumBindSecretBytes+1)
	result, err = client.ObserveDirectory(context.Background(), validDirectoryRequest(t), oversized)
	if !errors.Is(err, ErrInvalidConfiguration) || result.Category != "" || !allZeroBytes(oversized) {
		t.Fatalf("oversized secret result = %#v, error = %v, secret cleared = %t", result, err, allZeroBytes(oversized))
	}
}

func TestObserveDirectoryPreservesLastRetryableEndpointPriority(t *testing.T) {
	t.Parallel()

	var dials atomic.Int32
	client, err := New(testOptions(
		publicResolver("93.184.216.34"),
		dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("retryable observation dial failure")
		}),
	))
	if err != nil {
		t.Fatal(err)
	}
	request := validDirectoryRequest(t)
	request.Configuration.Endpoints = []Endpoint{
		{
			Priority: 1, Enabled: true, Host: "first.example.com", Port: 636,
			Transport: TransportLDAPS, TLSServerName: "first.example.com",
		},
		{
			Priority: 2, Enabled: true, Host: "second.example.com", Port: 636,
			Transport: TransportLDAPS, TLSServerName: "second.example.com",
		},
	}
	bindSecret := []byte("retry-observation-service-secret")
	result, err := client.ObserveDirectory(context.Background(), request, bindSecret)
	if err != nil || result.Category != DirectoryCategoryConnectFailed || result.EndpointPriority != 2 {
		t.Fatalf("ObserveDirectory() result = %#v, error = %v", result, err)
	}
	assertZeroDirectoryObservation(t, result.Observation)
	if dials.Load() != 2 || !allZeroBytes(bindSecret) {
		t.Fatalf("dials = %d, secret cleared = %t", dials.Load(), allZeroBytes(bindSecret))
	}
}

func posixObservationRequest(t *testing.T) DirectoryRequest {
	t.Helper()
	request := validDirectoryRequest(t)
	filter, err := identity.CompileLDAPTemplate(
		identity.LDAPTemplateContextPOSIXGroupSearchFilter,
		"(&(objectClass=posixGroup)(memberUid={username}))",
	)
	if err != nil {
		t.Fatal(err)
	}
	request.UserAttributes = []string{"uid"}
	request.Groups = DirectoryGroupConfiguration{
		Mode:         DirectoryGroupModePOSIXMemberUID,
		BaseDN:       "ou=groups,dc=example,dc=com",
		SearchFilter: &filter,
		Attributes:   []string{"cn"},
		MaxDepth:     1,
		MaxGroups:    10,
	}
	return request
}

func assertZeroDirectoryObservation(t *testing.T, observation DirectoryObservation) {
	t.Helper()
	if observation.User.DistinguishedName != "" || observation.User.Attributes != nil ||
		observation.Groups != nil {
		t.Fatalf("non-success retained observation: %#v", observation)
	}
}
