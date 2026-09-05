package ldapauth

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
)

func TestAuthenticateAlwaysDestroysOwnedPasswordBeforeValidationReturns(t *testing.T) {
	password := []byte("directory password that must disappear")
	var service *Service
	_, err := service.Authenticate(nil, Command{Password: password})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Authenticate() error = %v; want ErrInvalidInput", err)
	}
	if !bytes.Equal(password, make([]byte, len(password))) {
		t.Fatal("Authenticate() retained password bytes on validation failure")
	}
}

func TestCommandAndResultFormattingAreRedacted(t *testing.T) {
	secret := "correct horse battery staple"
	command := Command{
		TenantSlug: "tenant", LoginKey: "directory", Username: "alice@example.test",
		Password: []byte(secret), ReturnPath: "/incidents",
	}
	for _, formatted := range []string{command.String(), fmt.Sprintf("%v", command), fmt.Sprintf("%#v", command), Result{}.String()} {
		if strings.Contains(formatted, secret) || strings.Contains(formatted, command.Username) {
			t.Fatalf("redacted formatter disclosed authentication material: %q", formatted)
		}
	}
}

func TestRateKeysAreDomainSeparatedAndContainNoRawLocatorDigest(t *testing.T) {
	service := &Service{}
	copy(service.rateDigestKey[:], bytes.Repeat([]byte{0x5a}, sha256.Size))
	command := Command{
		TenantSlug: "tenant", LoginKey: "directory", Username: "Alice",
		ClientIP: netip.MustParseAddr("192.0.2.18"), RequestID: uuid.Must(uuid.NewV7()),
		CorrelationID: uuid.Must(uuid.NewV7()),
	}
	keys := service.rateKeys(command)
	if keys[0] == keys[1] || keys[0] == keys[2] || keys[1] == keys[2] {
		t.Fatal("rate-limit domains produced the same digest")
	}
	raw := sha256.Sum256([]byte(command.Username))
	for _, key := range keys {
		if key == raw {
			t.Fatal("rate-limit key is an unhashed-domain raw locator digest")
		}
	}
}

func TestDirectoryFailuresPreserveUniformCredentialEnumeration(t *testing.T) {
	for _, category := range []ldapclient.DirectoryCategory{
		ldapclient.DirectoryCategoryCredentialsRejected,
		ldapclient.DirectoryCategoryUserNotFound,
		ldapclient.DirectoryCategoryUserAmbiguous,
	} {
		failure, publicErr := directoryFailure(category, nil)
		if failure != FailureCredentials || !errors.Is(publicErr, ErrAuthentication) {
			t.Fatalf("directoryFailure(%q) = (%q, %v)", category, failure, publicErr)
		}
	}
}
