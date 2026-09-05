package identity

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestCanonicalBinarySubjects(t *testing.T) {
	t.Parallel()

	guidBytes := testID(0x21)
	guid, err := CanonicalADObjectGUID(guidBytes[:])
	if err != nil || guid.Format() != ADObjectGUIDSubject {
		t.Fatalf("CanonicalADObjectGUID() = %#v, %v", guid, err)
	}
	original := append([]byte(nil), guid.value...)
	clear(guidBytes[:])
	if !bytes.Equal(guid.value, original) {
		t.Fatal("caller mutation changed the canonical objectGUID")
	}

	lower, err := CanonicalEntryUUID("550e8400-e29b-41d4-a716-446655440000")
	if err != nil || lower.Format() != EntryUUIDSubject {
		t.Fatalf("CanonicalEntryUUID(lower) = %#v, %v", lower, err)
	}
	upper, err := CanonicalEntryUUID("550E8400-E29B-41D4-A716-446655440000")
	if err != nil || !bytes.Equal(lower.value, upper.value) {
		t.Fatalf("CanonicalEntryUUID(upper) = %#v, %v", upper, err)
	}
}

func TestCanonicalBinarySubjectsRejectInvalidValues(t *testing.T) {
	t.Parallel()

	for _, value := range [][]byte{nil, make([]byte, 15), make([]byte, 16), make([]byte, 17)} {
		if _, err := CanonicalADObjectGUID(value); !errors.Is(err, ErrInvalidSubject) {
			t.Fatalf("CanonicalADObjectGUID(%d bytes) error = %v", len(value), err)
		}
	}
	for _, value := range []string{
		"",
		"00000000-0000-0000-0000-000000000000",
		"550e8400e29b41d4a716446655440000",
		"550e8400-e29b-41d4-a716-44665544000z",
		"550e8400-e29b-01d4-a716-446655440000",
		"550e8400-e29b-61d4-a716-446655440000",
		"550e8400-e29b-41d4-0716-446655440000",
		"{550e8400-e29b-41d4-a716-446655440000}",
	} {
		if _, err := CanonicalEntryUUID(value); !errors.Is(err, ErrInvalidSubject) {
			t.Fatalf("CanonicalEntryUUID(%q) error = %v", value, err)
		}
	}
}

func TestCanonicalCustomSubjects(t *testing.T) {
	t.Parallel()

	exactSource := []byte("Straße")
	exact, err := CanonicalUTF8Exact(exactSource)
	if err != nil || exact.Format() != UTF8ExactSubject || string(exact.value) != "Straße" {
		t.Fatalf("CanonicalUTF8Exact() = %#v, %v", exact, err)
	}
	clear(exactSource)
	if string(exact.value) != "Straße" {
		t.Fatal("caller mutation changed the exact subject")
	}
	folded, err := CanonicalUTF8CaseFold([]byte("Straße"))
	if err != nil || folded.Format() != UTF8CaseFoldSubject || string(folded.value) != "strasse" {
		t.Fatalf("CanonicalUTF8CaseFold() = %q, %v", folded.value, err)
	}
	foldedUpper, err := CanonicalUTF8CaseFold([]byte("STRASSE"))
	if err != nil || !bytes.Equal(folded.value, foldedUpper.value) {
		t.Fatalf("folded uppercase = %q, %v", foldedUpper.value, err)
	}
}

func TestCanonicalCustomSubjectsRejectInvalidOrOversizedValues(t *testing.T) {
	t.Parallel()

	invalidUTF8 := []byte{0xff, 0xfe}
	oversized := bytes.Repeat([]byte("a"), maximumCanonicalSubjectBytes+1)
	for _, value := range [][]byte{nil, invalidUTF8, oversized} {
		if _, err := CanonicalUTF8Exact(value); !errors.Is(err, ErrInvalidSubject) {
			t.Fatalf("CanonicalUTF8Exact(%d bytes) error = %v", len(value), err)
		}
		if _, err := CanonicalUTF8CaseFold(value); !errors.Is(err, ErrInvalidSubject) {
			t.Fatalf("CanonicalUTF8CaseFold(%d bytes) error = %v", len(value), err)
		}
	}
	expandsPastLimit := []byte(strings.Repeat("İ", maximumCanonicalSubjectBytes/2))
	if len(expandsPastLimit) != maximumCanonicalSubjectBytes {
		t.Fatalf("expansion fixture = %d bytes", len(expandsPastLimit))
	}
	if _, err := CanonicalUTF8CaseFold(expandsPastLimit); !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("post-fold oversized subject error = %v", err)
	}
}

func TestCanonicalOIDCIssuerSubjectBindsExactTupleWithoutNormalization(t *testing.T) {
	left, err := CanonicalOIDCIssuerSubject("https://issuer.example/Tenant", "Subject")
	if err != nil {
		t.Fatal(err)
	}
	defer left.Clear()
	right, err := CanonicalOIDCIssuerSubject("https://issuer.example/tenant", "subject")
	if err != nil {
		t.Fatal(err)
	}
	defer right.Clear()
	if left.Format() != UTF8ExactSubject || bytes.Equal(left.value, right.value) ||
		!bytes.HasPrefix(left.value, []byte(oidcSubjectPrefix)) {
		t.Fatal("OIDC subject tuple was normalized or lost its domain separator")
	}
	keyring := mustKeyring(t, 1, map[int16][]byte{1: bytes.Repeat([]byte{0x75}, sourceKeyBytes)})
	provider := ProviderContext{Scope: TenantProviderScope, TenantID: testID(70), ProviderID: testID(71)}
	leftAliases, err := keyring.SubjectAliases(provider, left)
	if err != nil {
		t.Fatal(err)
	}
	rightAliases, err := keyring.SubjectAliases(provider, right)
	if err != nil {
		t.Fatal(err)
	}
	if leftAliases[0].Digest == rightAliases[0].Digest {
		t.Fatal("distinct exact OIDC tuples produced the same alias")
	}
}

func TestCanonicalOIDCIssuerSubjectRejectsAmbiguousOrHostileComponents(t *testing.T) {
	for name, tuple := range map[string][2]string{
		"empty issuer":       {"", "subject"},
		"empty subject":      {"https://issuer.example", ""},
		"issuer control":     {"https://issuer.example\x00evil", "subject"},
		"subject control":    {"https://issuer.example", "subject\nnext"},
		"unicode control":    {"https://issuer.example", "subject\u0085next"},
		"arabic letter mark": {"https://issuer.example", "subject\u061cnext"},
		"directional":        {"https://issuer.example", "subject\u202e"},
		"issuer oversized":   {strings.Repeat("i", maximumOIDCIssuerBytes+1), "subject"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CanonicalOIDCIssuerSubject(tuple[0], tuple[1]); !errors.Is(err, ErrInvalidSubject) {
				t.Fatalf("CanonicalOIDCIssuerSubject() error = %v", err)
			}
		})
	}
}

func TestCanonicalSAMLSubjectTuplePreservesLegacyEncodingAndExactBoundaries(t *testing.T) {
	t.Parallel()
	const (
		issuer = "https://idp.example/entity"
		source = "persistent_nameid"
		name   = "NameID"
		format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
		value  = "ExactSubject"
	)
	subject, err := CanonicalSAMLSubjectTuple(issuer, source, name, format, value)
	if err != nil {
		t.Fatalf("CanonicalSAMLSubjectTuple() error = %v", err)
	}
	defer subject.Clear()
	legacy := []byte(samlSubjectPrefix)
	for _, field := range []string{issuer, source, name, format, value} {
		legacy = strconv.AppendInt(legacy, int64(len(field)), 10)
		legacy = append(legacy, ':')
		legacy = append(legacy, field...)
	}
	defer clear(legacy)
	if subject.Format() != UTF8ExactSubject || !bytes.Equal(subject.value, legacy) {
		t.Fatalf("canonical SAML subject changed legacy encoding: %x", subject.value)
	}
	repeat, err := CanonicalSAMLSubjectTuple(issuer, source, name, format, value)
	if err != nil {
		t.Fatal(err)
	}
	defer repeat.Clear()
	if !bytes.Equal(subject.value, repeat.value) {
		t.Fatal("equivalent exact SAML tuples produced different subjects")
	}

	base := [5]string{issuer, source, name, format, value}
	for index := range base {
		changed := base
		changed[index] += "-changed"
		candidate, candidateErr := CanonicalSAMLSubjectTuple(
			changed[0], changed[1], changed[2], changed[3], changed[4],
		)
		if candidateErr != nil {
			t.Fatalf("changed component %d error = %v", index, candidateErr)
		}
		if bytes.Equal(subject.value, candidate.value) {
			candidate.Clear()
			t.Fatalf("component %d was not tuple-bound", index)
		}
		candidate.Clear()
	}

	left, err := CanonicalSAMLSubjectTuple("a", "bc", name, format, value)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Clear()
	right, err := CanonicalSAMLSubjectTuple("ab", "c", name, format, value)
	if err != nil {
		t.Fatal(err)
	}
	defer right.Clear()
	if bytes.Equal(left.value, right.value) {
		t.Fatal("length framing conflated adjacent tuple boundaries")
	}
}

func TestCanonicalSAMLSubjectTupleRejectsInvalidComponentsAndComposite(t *testing.T) {
	t.Parallel()
	valid := [5]string{
		"https://idp.example/entity", "persistent_nameid", "NameID",
		"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", "subject",
	}
	tests := map[string]func(*[5]string){
		"empty issuer": func(value *[5]string) { value[0] = "" },
		"empty source": func(value *[5]string) { value[1] = "" },
		"empty name":   func(value *[5]string) { value[2] = "" },
		"empty format": func(value *[5]string) { value[3] = "" },
		"empty value":  func(value *[5]string) { value[4] = "" },
		"leading space": func(value *[5]string) {
			value[4] = " subject"
		},
		"control":      func(value *[5]string) { value[4] = "subject\nnext" },
		"invalid UTF8": func(value *[5]string) { value[4] = string([]byte{0xff}) },
		"issuer oversized": func(value *[5]string) {
			value[0] = strings.Repeat("i", maximumOIDCIssuerBytes+1)
		},
		"source oversized": func(value *[5]string) {
			value[1] = strings.Repeat("s", maximumSAMLSubjectSourceBytes+1)
		},
		"name oversized": func(value *[5]string) {
			value[2] = strings.Repeat("n", maximumSAMLSubjectNameBytes+1)
		},
		"format oversized": func(value *[5]string) {
			value[3] = strings.Repeat("f", maximumSAMLSubjectFormatBytes+1)
		},
		"value oversized": func(value *[5]string) {
			value[4] = strings.Repeat("v", maximumSAMLSubjectValueBytes+1)
		},
		"composite oversized": func(value *[5]string) {
			value[4] = strings.Repeat("v", maximumSAMLSubjectValueBytes)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			tuple := valid
			mutate(&tuple)
			if _, err := CanonicalSAMLSubjectTuple(tuple[0], tuple[1], tuple[2], tuple[3], tuple[4]); !errors.Is(err, ErrInvalidSubject) {
				t.Fatalf("CanonicalSAMLSubjectTuple() error = %v", err)
			}
		})
	}
}

func TestSubjectAliasesCoverRetainedKeysAndBindContextAndFormat(t *testing.T) {
	t.Parallel()

	root := bytes.Repeat([]byte{0x81}, sourceKeyBytes)
	keyring := mustKeyring(t, 2, map[int16][]byte{3: root, 1: root, 2: root})
	context := ProviderContext{Scope: TenantProviderScope, TenantID: testID(30), ProviderID: testID(31)}
	exact, _ := CanonicalUTF8Exact([]byte("Alice"))
	aliases, err := keyring.SubjectAliases(context, exact)
	if err != nil {
		t.Fatalf("SubjectAliases() error = %v", err)
	}
	if len(aliases) != 3 || aliases[0].KeyVersion != 1 || aliases[1].KeyVersion != 2 || aliases[2].KeyVersion != 3 {
		t.Fatalf("aliases versions = %#v", aliases)
	}
	if aliases[0].Digest == aliases[1].Digest || aliases[1].Digest == aliases[2].Digest {
		t.Fatal("separate key versions produced the same alias")
	}
	if got := hex.EncodeToString(aliases[0].Digest[:]); got != "b016673a8ff8d0b01d7622ada611ca5fd9d4518d57c3212c0ec4522c87e34676" {
		t.Fatalf("subject alias vector = %s", got)
	}
	repeat, err := keyring.SubjectAliases(context, exact)
	if err != nil || repeat[0].Digest != aliases[0].Digest {
		t.Fatal("subject aliases are not deterministic")
	}

	changedTenant := context
	changedTenant.TenantID = testID(32)
	changedProvider := context
	changedProvider.ProviderID = testID(33)
	platform := ProviderContext{Scope: PlatformProviderScope, ProviderID: context.ProviderID}
	folded, _ := CanonicalUTF8CaseFold([]byte("Alice"))
	for name, candidate := range map[string]struct {
		context ProviderContext
		subject Subject
	}{
		"tenant":   {context: changedTenant, subject: exact},
		"provider": {context: changedProvider, subject: exact},
		"scope":    {context: platform, subject: exact},
		"format":   {context: context, subject: folded},
	} {
		candidateAliases, candidateErr := keyring.SubjectAliases(candidate.context, candidate.subject)
		if candidateErr != nil {
			t.Fatalf("%s SubjectAliases() error = %v", name, candidateErr)
		}
		if candidateAliases[0].Digest == aliases[0].Digest {
			t.Fatalf("changing %s did not change the alias", name)
		}
	}
}

func TestCaseFoldAliasesEquivalentStringsAndRejectInvalidInputs(t *testing.T) {
	t.Parallel()

	keyring := mustKeyring(t, 1, map[int16][]byte{1: bytes.Repeat([]byte{0x91}, sourceKeyBytes)})
	context := ProviderContext{Scope: TenantProviderScope, TenantID: testID(40), ProviderID: testID(41)}
	first, _ := CanonicalUTF8CaseFold([]byte("Straße"))
	second, _ := CanonicalUTF8CaseFold([]byte("STRASSE"))
	firstAliases, err := keyring.SubjectAliases(context, first)
	if err != nil {
		t.Fatalf("SubjectAliases(first) error = %v", err)
	}
	secondAliases, err := keyring.SubjectAliases(context, second)
	if err != nil || firstAliases[0].Digest != secondAliases[0].Digest {
		t.Fatalf("case-fold aliases differ: %x and %x, %v", firstAliases[0].Digest, secondAliases[0].Digest, err)
	}
	if _, err := keyring.SubjectAliases(ProviderContext{}, first); !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("invalid context error = %v", err)
	}
	if _, err := keyring.SubjectAliases(context, Subject{}); !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("invalid subject error = %v", err)
	}
	if _, err := (Keyring{}).SubjectAliases(context, first); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("zero keyring error = %v", err)
	}
}

func TestSubjectFormattingRedactsCanonicalValue(t *testing.T) {
	t.Parallel()

	subject, err := CanonicalUTF8Exact([]byte("private-directory-identifier"))
	if err != nil {
		t.Fatalf("CanonicalUTF8Exact() error = %v", err)
	}
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", subject, subject, subject, subject, subject, subject)
	if strings.Contains(formatted, "private-directory-identifier") || strings.Contains(formatted, "112 114 105") {
		t.Fatalf("formatted subject exposed canonical bytes: %s", formatted)
	}
}

func TestSubjectClearInvalidatesCanonicalBytesAndCopies(t *testing.T) {
	subject, err := CanonicalUTF8Exact([]byte("clear-me"))
	if err != nil {
		t.Fatalf("CanonicalUTF8Exact() error = %v", err)
	}
	copyOfSubject := subject
	subject.Clear()
	if subject.Format() != 0 || len(subject.value) != 0 || !allZero(copyOfSubject.value) {
		t.Fatalf("cleared subject = %#v, copy bytes = %x", subject, copyOfSubject.value)
	}
	var nilSubject *Subject
	nilSubject.Clear()
}
