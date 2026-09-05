package ldapclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func validDirectoryEnumerationRequest(t *testing.T) DirectoryEnumerationRequest {
	t.Helper()
	filter, err := identity.CompileLDAPTemplate(
		identity.LDAPTemplateContextUserSearchFilter,
		"(&(objectClass=person)(uid={username}))",
	)
	if err != nil {
		t.Fatalf("CompileLDAPTemplate() error = %v", err)
	}
	return DirectoryEnumerationRequest{
		Configuration:    testConfiguration(),
		BindDN:           "cn=service,dc=example,dc=com",
		UserBaseDN:       "ou=people,dc=example,dc=com",
		UserSearchFilter: filter,
		UserAttributes:   []string{"uid", "mail", "entryUUID"},
		ReferralMode:     DirectoryReferralModeDisabled,
		Limits: DirectoryLimits{
			PageSize: 2, MaxPages: 10, MaxEntries: 10, MaxResponseBytes: 1024 * 1024,
		},
	}
}

func TestEnumerateDirectoryUsersRequiresCompletePagingAndSortsUsers(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, "ldap.example.com")
	serviceSecret := []byte("enumeration-service-secret-canary")
	forbiddenUsername := []byte("alice-login-value-must-not-cross")
	var connections atomic.Int32
	dialer := newPipeScriptDialer(func(connection net.Conn) error {
		if connections.Add(1) != 1 {
			return errors.New("enumeration opened more than one connection")
		}
		tlsConnection, bindPacket, bindID, operation, err := serveTestLDAPSRequest(
			connection,
			pki.serverTLSConfig(nil),
		)
		if err != nil || operation != 0x60 || !bytes.Contains(bindPacket, serviceSecret) {
			return errors.New("enumeration did not service-bind")
		}
		if err := writeTestLDAPPackets(tlsConnection, ldapResultPacket(bindID, 0x61, 0)); err != nil {
			return err
		}

		firstSearch, firstID, err := readTestLDAPRequest(tlsConnection, 0x63)
		if err != nil || bytes.Contains(firstSearch, forbiddenUsername) ||
			bytes.Contains(firstSearch, []byte("{username}")) || !bytes.Contains(firstSearch, []byte("uid")) {
			return errors.New("first enumeration request did not use the derived population filter")
		}
		if err := writeTestLDAPPackets(
			tlsConnection,
			ldapSearchEntryPacket(
				firstID,
				"uid=bob,ou=people,dc=example,dc=com",
				[]testLDAPAttribute{{name: "uid", values: [][]byte{[]byte("bob")}}},
			),
			ldapSearchDonePagingPacket(firstID, 0, []byte("page-two")),
		); err != nil {
			return err
		}

		secondSearch, secondID, err := readTestLDAPRequest(tlsConnection, 0x63)
		if err != nil || !bytes.Contains(secondSearch, []byte("page-two")) {
			return errors.New("second enumeration request omitted the paging cookie")
		}
		return writeTestLDAPPackets(
			tlsConnection,
			ldapSearchEntryPacket(
				secondID,
				"uid=alice,ou=people,dc=example,dc=com",
				[]testLDAPAttribute{{name: "uid", values: [][]byte{[]byte("alice")}}},
			),
			ldapSearchDonePagingPacket(secondID, 0, nil),
		)
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatal(err)
	}
	request := validDirectoryEnumerationRequest(t)
	request.Configuration.CustomCAPEM = pki.caPEM
	secret := append([]byte(nil), serviceSecret...)
	result, err := client.EnumerateDirectoryUsers(context.Background(), request, secret)
	if err != nil || result.Category != DirectoryCategorySuccess || !result.Complete ||
		result.Truncated || result.EndpointPriority != 1 || len(result.Users) != 2 {
		t.Fatalf("EnumerateDirectoryUsers() result = %#v, error = %v", result, err)
	}
	if result.Users[0].DistinguishedName != "uid=alice,ou=people,dc=example,dc=com" ||
		result.Users[1].DistinguishedName != "uid=bob,ou=people,dc=example,dc=com" {
		t.Fatalf("users were not deterministically sorted: %#v", result)
	}
	if connections.Load() != 1 || !allZeroBytes(secret) {
		t.Fatalf("connections = %d, secret cleared = %t", connections.Load(), allZeroBytes(secret))
	}
	if formatted := fmt.Sprintf("%#v", result); strings.Contains(formatted, "alice") ||
		!strings.Contains(formatted, "users:[REDACTED]") {
		t.Fatalf("enumeration formatting leaked users: %s", formatted)
	}
	dialer.wait(t)
}

func TestEnumerateDirectoryUsersDiscardsPartialResultsWhenLimitTruncatesPaging(t *testing.T) {
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
		_, searchID, err := readTestLDAPRequest(tlsConnection, 0x63)
		if err != nil {
			return err
		}
		return writeTestLDAPPackets(
			tlsConnection,
			ldapSearchEntryPacket(
				searchID,
				"uid=partial,ou=people,dc=example,dc=com",
				[]testLDAPAttribute{{name: "uid", values: [][]byte{[]byte("partial")}}},
			),
			ldapSearchDonePagingPacket(searchID, 0, []byte("more-results")),
		)
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatal(err)
	}
	request := validDirectoryEnumerationRequest(t)
	request.Configuration.CustomCAPEM = pki.caPEM
	request.Limits.MaxEntries = 1
	request.Limits.PageSize = 1
	secret := []byte("truncated-enumeration-secret")
	result, err := client.EnumerateDirectoryUsers(context.Background(), request, secret)
	if err != nil || result.Category != DirectoryCategoryLimitExceeded || result.Complete ||
		!result.Truncated || result.Users != nil {
		t.Fatalf("EnumerateDirectoryUsers() result = %#v, error = %v", result, err)
	}
	if !allZeroBytes(secret) {
		t.Fatal("enumeration retained the service secret")
	}
	dialer.wait(t)
}

func TestEnumerateDirectoryUsersRejectsDuplicateCanonicalDNsAndInvalidRequests(t *testing.T) {
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
		_, searchID, err := readTestLDAPRequest(tlsConnection, 0x63)
		if err != nil {
			return err
		}
		return writeTestLDAPPackets(
			tlsConnection,
			ldapSearchEntryPacket(searchID, "cn=Alice+uid=42,ou=people,dc=example,dc=com", nil),
			ldapSearchEntryPacket(searchID, "UID=42+CN=alice,OU=people,DC=example,DC=com", nil),
			ldapSearchDonePagingPacket(searchID, 0, nil),
		)
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatal(err)
	}
	request := validDirectoryEnumerationRequest(t)
	request.Configuration.CustomCAPEM = pki.caPEM
	secret := []byte("duplicate-enumeration-secret")
	result, err := client.EnumerateDirectoryUsers(context.Background(), request, secret)
	if err != nil || result.Category != DirectoryCategoryInvalidEntry || result.Complete ||
		result.Truncated || result.Users != nil {
		t.Fatalf("EnumerateDirectoryUsers() result = %#v, error = %v", result, err)
	}
	if !allZeroBytes(secret) {
		t.Fatal("enumeration retained the service secret")
	}
	dialer.wait(t)

	invalid := validDirectoryEnumerationRequest(t)
	invalid.UserAttributes = nil
	invalidSecret := []byte("invalid-enumeration-secret")
	result, err = client.EnumerateDirectoryUsers(context.Background(), invalid, invalidSecret)
	if !errors.Is(err, ErrInvalidConfiguration) || result.Category != "" ||
		result.EndpointPriority != 0 || result.Complete || result.Truncated || result.Users != nil ||
		!allZeroBytes(invalidSecret) {
		t.Fatalf("invalid request result = %#v, error = %v, secret cleared = %t", result, err, allZeroBytes(invalidSecret))
	}
}
