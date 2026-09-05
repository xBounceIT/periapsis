package serviceaccount

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

type partialSecretEntropyReader struct {
	reads  int
	secret []byte
}

func TestNormalizeCredentialNetworksUsesPostgreSQLCIDROrder(t *testing.T) {
	t.Parallel()

	got, err := normalizeCredentialNetworks([]netip.Prefix{
		netip.MustParsePrefix("10.128.0.0/9"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("10.0.0.1/9"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2.0.0.0/8"),
	})
	if err != nil {
		t.Fatalf("normalizeCredentialNetworks() error = %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("2.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/9"),
		netip.MustParsePrefix("10.128.0.0/9"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeCredentialNetworks() = %v, want PostgreSQL cidr order %v", got, want)
	}
}

func (r *partialSecretEntropyReader) Read(destination []byte) (int, error) {
	r.reads++
	if r.reads == 1 {
		for index := range destination {
			destination[index] = 0xA1
		}
		return len(destination), nil
	}
	r.secret = destination
	for index := 0; index < 7; index++ {
		destination[index] = 0xB2
	}
	return 7, errors.New("entropy source failed")
}

func TestCredentialIssueAndVerificationRoundTrip(t *testing.T) {
	t.Parallel()

	randomMaterial := append(bytes.Repeat([]byte{0x11}, credentialLocatorBytes), bytes.Repeat([]byte{0x22}, credentialSecretBytes)...)
	keyring, err := newCredentialKeyring(7, map[int16][]byte{7: bytes.Repeat([]byte{0xA7}, 32)}, bytes.NewReader(randomMaterial))
	if err != nil {
		t.Fatalf("newCredentialKeyring() error = %v", err)
	}
	issued, err := keyring.Issue()
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if !strings.HasPrefix(issued.Token, "periapsis_api_v1.7.") || strings.ContainsAny(issued.Token, "= \t\r\n") {
		t.Fatalf("Token = %q, want canonical raw-url envelope", issued.Token)
	}
	presented, err := keyring.ParseAndDigest(issued.Token)
	if err != nil {
		t.Fatalf("ParseAndDigest() error = %v", err)
	}
	if presented != issued.PresentedCredential {
		t.Fatalf("presented = %#v, want %#v", presented, issued.PresentedCredential)
	}
}

func TestCredentialEnvelopeRejectsAmbiguity(t *testing.T) {
	t.Parallel()

	keyring, err := newCredentialKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{0x31}, 32)}, bytes.NewReader(bytes.Repeat([]byte{0x41}, 48)))
	if err != nil {
		t.Fatalf("newCredentialKeyring() error = %v", err)
	}
	issued, err := keyring.Issue()
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	parts := strings.Split(issued.Token, ".")
	for _, token := range []string{
		" " + issued.Token,
		issued.Token + ",other",
		strings.Repeat("x", maximumCredentialTokenBytes+1),
		strings.Replace(issued.Token, ".1.", ".01.", 1),
		strings.Replace(issued.Token, credentialFormatPrefix, "PERIAPSIS_API_V1", 1),
		issued.Token + ".extra",
		strings.Join([]string{parts[0], parts[1], base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 16)), parts[3]}, "."),
		strings.Join([]string{parts[0], "2", parts[2], parts[3]}, "."),
	} {
		if _, err := keyring.ParseAndDigest(token); !errors.Is(err, ErrInvalidCredential) {
			t.Fatalf("ParseAndDigest(%q) error = %v, want ErrInvalidCredential", token, err)
		}
	}
}

func TestCredentialEnvelopeHasExactStructuralBounds(t *testing.T) {
	t.Parallel()

	for version, expectedLength := range map[int16]int{
		1:                 minimumCredentialTokenBytes,
		maximumKeyVersion: maximumCredentialTokenBytes,
	} {
		keyring, err := newCredentialKeyring(
			version,
			map[int16][]byte{version: bytes.Repeat([]byte{0x35}, credentialSourceKeyBytes)},
			bytes.NewReader(bytes.Repeat([]byte{0x45}, credentialLocatorBytes+credentialSecretBytes)),
		)
		if err != nil {
			t.Fatalf("newCredentialKeyring(%d) error = %v", version, err)
		}
		issued, err := keyring.Issue()
		if err != nil {
			t.Fatalf("Issue(%d) error = %v", version, err)
		}
		if len(issued.Token) != expectedLength {
			t.Fatalf("len(Issue(%d).Token) = %d, want %d", version, len(issued.Token), expectedLength)
		}
		if _, err := keyring.ParseAndDigest(issued.Token); err != nil {
			t.Fatalf("ParseAndDigest(Issue(%d).Token) error = %v", version, err)
		}
	}
}

func TestCredentialDigestBindsEveryEnvelopeFieldAndSourceKey(t *testing.T) {
	t.Parallel()

	randomMaterial := append(bytes.Repeat([]byte{0x51}, 16), bytes.Repeat([]byte{0x61}, 32)...)
	first, err := newCredentialKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{0x71}, 32)}, bytes.NewReader(randomMaterial))
	if err != nil {
		t.Fatalf("newCredentialKeyring(first) error = %v", err)
	}
	issued, err := first.Issue()
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	second, err := NewCredentialKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{0x72}, 32)})
	if err != nil {
		t.Fatalf("NewCredentialKeyring(second) error = %v", err)
	}
	presented, err := second.ParseAndDigest(issued.Token)
	if err != nil {
		t.Fatalf("ParseAndDigest() error = %v", err)
	}
	if bytes.Equal(presented.Digest[:], issued.Digest[:]) {
		t.Fatal("different source keys produced the same digest")
	}

	parts := strings.Split(issued.Token, ".")
	secret, decodeErr := credentialEncoding.DecodeString(parts[3])
	if decodeErr != nil {
		t.Fatalf("decode test secret: %v", decodeErr)
	}
	secret[0] ^= 0xFF
	parts[3] = credentialEncoding.EncodeToString(secret)
	changed, parseErr := first.ParseAndDigest(strings.Join(parts, "."))
	if parseErr != nil {
		t.Fatalf("ParseAndDigest(changed secret) error = %v", parseErr)
	}
	if bytes.Equal(changed.Digest[:], issued.Digest[:]) {
		t.Fatal("changed secret produced the same digest")
	}
}

func TestCredentialKeyringValidationAndReadiness(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x81}, 32)
	keyring, err := NewCredentialKeyring(2, map[int16][]byte{1: key, 2: bytes.Repeat([]byte{0x82}, 32)})
	if err != nil {
		t.Fatalf("NewCredentialKeyring() error = %v", err)
	}
	clear(key)
	if keyring.ActiveVersion() != 2 || !slicesEqual(keyring.VerificationVersions(), []int16{1, 2}) {
		t.Fatalf("keyring versions = active %d, verify %v", keyring.ActiveVersion(), keyring.VerificationVersions())
	}
	if missing := keyring.MissingVersions([]int16{2, 3, 3, -1}); !slicesEqual(missing, []int16{-1, 3}) {
		t.Fatalf("MissingVersions() = %v", missing)
	}

	for _, test := range []struct {
		name   string
		active int16
		keys   map[int16][]byte
	}{
		{name: "missing keys", active: 1},
		{name: "zero active", keys: map[int16][]byte{1: bytes.Repeat([]byte{1}, 32)}},
		{name: "active absent", active: 2, keys: map[int16][]byte{1: bytes.Repeat([]byte{1}, 32)}},
		{name: "short source", active: 1, keys: map[int16][]byte{1: bytes.Repeat([]byte{1}, 31)}},
		{name: "invalid version", active: 1, keys: map[int16][]byte{-1: bytes.Repeat([]byte{1}, 32), 1: bytes.Repeat([]byte{2}, 32)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewCredentialKeyring(test.active, test.keys); err == nil {
				t.Fatal("NewCredentialKeyring() unexpectedly succeeded")
			}
		})
	}
}

func TestClearCredentialVerificationKeysOverwritesEveryEntry(t *testing.T) {
	t.Parallel()

	keys := map[int16][credentialDigestBytes]byte{
		1: bytesToCredentialDigest(bytes.Repeat([]byte{0xA1}, credentialDigestBytes)),
		2: bytesToCredentialDigest(bytes.Repeat([]byte{0xB2}, credentialDigestBytes)),
	}
	clearCredentialVerificationKeys(keys)
	for version, key := range keys {
		if key != [credentialDigestBytes]byte{} {
			t.Fatalf("credential verification key %d was not cleared: %x", version, key)
		}
	}
}

func TestCredentialIssueFailsClosedWhenEntropyIsUnavailable(t *testing.T) {
	t.Parallel()

	keyring, err := newCredentialKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{0x91}, 32)}, bytes.NewReader(make([]byte, 15)))
	if err != nil {
		t.Fatalf("newCredentialKeyring() error = %v", err)
	}
	if _, err := keyring.Issue(); err == nil {
		t.Fatal("Issue() succeeded with insufficient entropy")
	}
}

func TestCredentialIssueClearsPartiallyReadSecretOnEntropyFailure(t *testing.T) {
	t.Parallel()

	random := &partialSecretEntropyReader{}
	keyring, err := newCredentialKeyring(
		1,
		map[int16][]byte{1: bytes.Repeat([]byte{0x92}, credentialSourceKeyBytes)},
		random,
	)
	if err != nil {
		t.Fatalf("newCredentialKeyring() error = %v", err)
	}
	if _, err := keyring.Issue(); err == nil {
		t.Fatal("Issue() succeeded after a partial secret read")
	}
	if len(random.secret) != credentialSecretBytes || !bytes.Equal(random.secret, make([]byte, credentialSecretBytes)) {
		t.Fatalf("partially read secret was not cleared: %x", random.secret)
	}
}

func slicesEqual(left, right []int16) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func bytesToCredentialDigest(value []byte) [credentialDigestBytes]byte {
	var digest [credentialDigestBytes]byte
	copy(digest[:], value)
	return digest
}
