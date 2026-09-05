package identity

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestNewKeyringCopiesSourcesAndReportsVersions(t *testing.T) {
	t.Parallel()

	first := bytes.Repeat([]byte{0x11}, sourceKeyBytes)
	second := bytes.Repeat([]byte{0x22}, sourceKeyBytes)
	keyring, err := NewKeyring(2, map[int16][]byte{2: second, 1: first})
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	before, err := keyring.ReadinessVerifier()
	if err != nil {
		t.Fatalf("ReadinessVerifier() error = %v", err)
	}
	clear(first)
	clear(second)
	after, err := keyring.ReadinessVerifier()
	if err != nil {
		t.Fatalf("ReadinessVerifier() after source clear error = %v", err)
	}
	if before != after {
		t.Fatal("caller mutation changed the constructed keyring")
	}
	if keyring.ActiveVersion() != 2 || !equalVersions(keyring.Versions(), []int16{1, 2}) {
		t.Fatalf("versions = active %d, retained %v", keyring.ActiveVersion(), keyring.Versions())
	}
	if missing := keyring.MissingVersions([]int16{2, 3, 3, 0, -1}); !equalVersions(missing, []int16{-1, 0, 3}) {
		t.Fatalf("MissingVersions() = %v", missing)
	}
	versions := keyring.Versions()
	versions[0] = 99
	if !equalVersions(keyring.Versions(), []int16{1, 2}) {
		t.Fatal("caller mutation changed the retained version inventory")
	}
}

func TestNewKeyringRejectsInvalidShape(t *testing.T) {
	t.Parallel()

	valid := bytes.Repeat([]byte{0x31}, sourceKeyBytes)
	tooMany := make(map[int16][]byte, maximumKeyCount+1)
	for version := int16(1); version <= maximumKeyCount+1; version++ {
		tooMany[version] = valid
	}
	for _, test := range []struct {
		name   string
		active int16
		keys   map[int16][]byte
	}{
		{name: "zero active", keys: map[int16][]byte{1: valid}},
		{name: "negative active", active: -1, keys: map[int16][]byte{1: valid}},
		{name: "active absent", active: 2, keys: map[int16][]byte{1: valid}},
		{name: "empty", active: 1},
		{name: "zero version", active: 1, keys: map[int16][]byte{0: valid, 1: valid}},
		{name: "negative version", active: 1, keys: map[int16][]byte{-1: valid, 1: valid}},
		{name: "short root", active: 1, keys: map[int16][]byte{1: valid[:len(valid)-1]}},
		{name: "long root", active: 1, keys: map[int16][]byte{1: append(append([]byte(nil), valid...), 1)}},
		{name: "too many", active: 1, keys: tooMany},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewKeyring(test.active, test.keys); !errors.Is(err, ErrInvalidKeyring) {
				t.Fatalf("NewKeyring() error = %v, want ErrInvalidKeyring", err)
			}
		})
	}
	if _, err := newKeyring(1, map[int16][]byte{1: valid}, nil); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("newKeyring(nil random) error = %v", err)
	}
}

func TestReadinessVerifierBindsExactKeyring(t *testing.T) {
	t.Parallel()

	first := bytes.Repeat([]byte{0x41}, sourceKeyBytes)
	second := bytes.Repeat([]byte{0x42}, sourceKeyBytes)
	baseline := mustKeyring(t, 1, map[int16][]byte{2: second, 1: first})
	reordered := mustKeyring(t, 1, map[int16][]byte{1: first, 2: second})
	activeChanged := mustKeyring(t, 2, map[int16][]byte{1: first, 2: second})
	rootChanged := mustKeyring(t, 1, map[int16][]byte{1: first, 2: bytes.Repeat([]byte{0x43}, sourceKeyBytes)})
	inventoryChanged := mustKeyring(t, 1, map[int16][]byte{1: first})

	want, err := baseline.ReadinessVerifier()
	if err != nil {
		t.Fatalf("ReadinessVerifier() error = %v", err)
	}
	if want == ([32]byte{}) {
		t.Fatal("ReadinessVerifier() returned an empty verifier")
	}
	if got := hex.EncodeToString(want[:]); got != "f31b7a0b89beb38adf4b85f347e7f1ab57e4308f89092b4b6e7db306593366e3" {
		t.Fatalf("readiness verifier vector = %s", got)
	}
	for name, candidate := range map[string]Keyring{
		"same roots in another map order": reordered,
	} {
		got, candidateErr := candidate.ReadinessVerifier()
		if candidateErr != nil || got != want {
			t.Fatalf("%s verifier = %x, %v; want %x", name, got, candidateErr, want)
		}
	}
	for name, candidate := range map[string]Keyring{
		"active version": activeChanged,
		"root material":  rootChanged,
		"inventory":      inventoryChanged,
	} {
		got, candidateErr := candidate.ReadinessVerifier()
		if candidateErr != nil {
			t.Fatalf("%s ReadinessVerifier() error = %v", name, candidateErr)
		}
		if got == want {
			t.Fatalf("changing %s did not change the readiness verifier", name)
		}
	}
	if _, err := (Keyring{}).ReadinessVerifier(); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("zero keyring verifier error = %v", err)
	}
}

func TestReadinessEvidenceIsSortedStableAndIndependentlyBound(t *testing.T) {
	t.Parallel()

	first := bytes.Repeat([]byte{0x41}, sourceKeyBytes)
	second := bytes.Repeat([]byte{0x42}, sourceKeyBytes)
	baseline := mustKeyring(t, 1, map[int16][]byte{2: second, 1: first})
	evidence, err := baseline.ReadinessEvidence()
	if err != nil {
		t.Fatalf("ReadinessEvidence() error = %v", err)
	}
	if evidence.ActiveVersion != 1 || len(evidence.Versions) != 2 ||
		evidence.Versions[0].KeyVersion != 1 || evidence.Versions[1].KeyVersion != 2 {
		t.Fatalf("ReadinessEvidence() = %#v", evidence)
	}
	if got := hex.EncodeToString(evidence.Versions[0].Verifier[:]); got != "94673b6b1d9f3e7e20f44c4aaf8fa2fef749ed9c85e27011f34fb9d8caa3436e" {
		t.Fatalf("version 1 readiness vector = %s", got)
	}

	activeChanged := mustKeyring(t, 2, map[int16][]byte{1: first, 2: second})
	activeEvidence, err := activeChanged.ReadinessEvidence()
	if err != nil {
		t.Fatalf("active ReadinessEvidence() error = %v", err)
	}
	if activeEvidence.ActiveVersion != 2 || activeEvidence.Versions[0].Verifier != evidence.Versions[0].Verifier ||
		activeEvidence.Versions[1].Verifier != evidence.Versions[1].Verifier {
		t.Fatal("changing only the active version changed per-version evidence")
	}

	rootChanged := mustKeyring(t, 1, map[int16][]byte{1: first, 2: bytes.Repeat([]byte{0x43}, sourceKeyBytes)})
	rootEvidence, err := rootChanged.ReadinessEvidence()
	if err != nil {
		t.Fatalf("changed-root ReadinessEvidence() error = %v", err)
	}
	if rootEvidence.Versions[0].Verifier != evidence.Versions[0].Verifier ||
		rootEvidence.Versions[1].Verifier == evidence.Versions[1].Verifier {
		t.Fatal("per-version evidence did not isolate the changed root")
	}

	withAddedVersion := mustKeyring(t, 1, map[int16][]byte{
		1: first, 2: second, 3: bytes.Repeat([]byte{0x44}, sourceKeyBytes),
	})
	addedEvidence, err := withAddedVersion.ReadinessEvidence()
	if err != nil {
		t.Fatalf("added-version ReadinessEvidence() error = %v", err)
	}
	if len(addedEvidence.Versions) != 3 || addedEvidence.Versions[0].Verifier != evidence.Versions[0].Verifier ||
		addedEvidence.Versions[1].Verifier != evidence.Versions[1].Verifier {
		t.Fatal("adding a version changed retained version evidence")
	}

	evidence.Versions[0] = VersionVerifier{}
	freshEvidence, err := baseline.ReadinessEvidence()
	if err != nil || freshEvidence.Versions[0].KeyVersion != 1 || freshEvidence.Versions[0].Verifier == ([32]byte{}) {
		t.Fatal("caller mutation changed keyring readiness evidence")
	}
	if _, err := (Keyring{}).ReadinessEvidence(); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("zero keyring evidence error = %v", err)
	}
}

func TestKeyDerivationIsDomainAndVersionSeparated(t *testing.T) {
	t.Parallel()

	root := bytes.Repeat([]byte{0xD1}, sourceKeyBytes)
	keyring := mustKeyring(t, 1, map[int16][]byte{1: root, 2: root})
	first := keyring.keys[1]
	second := keyring.keys[2]
	for name, key := range map[string][derivedKeyBytes]byte{
		"bind secret":      first.bindSecret,
		"SAML SP key":      first.samlSPKey,
		"SAML session":     first.samlSession,
		"external subject": first.externalSubject,
		"subject alias":    first.subjectAlias,
		"readiness":        first.readiness,
	} {
		if bytes.Equal(key[:], root) {
			t.Fatalf("%s derivation retained the root key", name)
		}
	}
	if first.bindSecret == first.samlSPKey || first.bindSecret == first.samlSession ||
		first.samlSPKey == first.samlSession || first.samlSession == first.externalSubject ||
		first.bindSecret == first.externalSubject || first.bindSecret == first.subjectAlias ||
		first.bindSecret == first.readiness || first.externalSubject == first.subjectAlias ||
		first.externalSubject == first.readiness || first.subjectAlias == first.readiness {
		t.Fatal("different purposes produced the same derived key")
	}
	if first.bindSecret == second.bindSecret || first.samlSPKey == second.samlSPKey ||
		first.samlSession == second.samlSession || first.externalSubject == second.externalSubject ||
		first.subjectAlias == second.subjectAlias || first.readiness == second.readiness {
		t.Fatal("different versions produced the same derived key")
	}
	clearVersionKey(&first)
	clearVersionKey(&second)
}

func TestKeyringFormattingNeverExposesDerivedKeys(t *testing.T) {
	t.Parallel()

	keyring := mustKeyring(t, 7, map[int16][]byte{7: bytes.Repeat([]byte{0xE1}, sourceKeyBytes)})
	keysForVersion := keyring.keys[7]
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", keyring, keyring, keyring, keyring, keyring, keyring)
	for name, key := range map[string][derivedKeyBytes]byte{
		"bind secret":      keysForVersion.bindSecret,
		"SAML SP key":      keysForVersion.samlSPKey,
		"SAML session":     keysForVersion.samlSession,
		"external subject": keysForVersion.externalSubject,
		"subject alias":    keysForVersion.subjectAlias,
		"readiness":        keysForVersion.readiness,
	} {
		if strings.Contains(formatted, hex.EncodeToString(key[:])) {
			t.Fatalf("formatted keyring exposed the %s key", name)
		}
	}
	if strings.Contains(formatted, "bindSecret") || strings.Contains(formatted, "samlSPKey") ||
		strings.Contains(formatted, "samlSession") || strings.Contains(formatted, "externalSubject") ||
		strings.Contains(formatted, "subjectAlias") || strings.Contains(formatted, "readiness") {
		t.Fatalf("formatted keyring exposed private field names: %s", formatted)
	}
	clearVersionKey(&keysForVersion)
}

func mustKeyring(t *testing.T, active int16, roots map[int16][]byte) Keyring {
	t.Helper()
	keyring, err := NewKeyring(active, roots)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	return keyring
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
