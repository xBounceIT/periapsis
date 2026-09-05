package identity

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNewLDAPObservationSortsDeduplicatesAndCopiesValues(t *testing.T) {
	firstName := "Alice"
	email := "alice@example.com"
	subject, _ := CanonicalUTF8Exact([]byte("subject-1"))
	username, _ := NewLDAPUsername("alice")
	userDN, _ := ParseLDAPDistinguishedName("uid=alice,ou=people,dc=example,dc=com")
	groupB, _ := ParseLDAPDistinguishedName("cn=Blue,ou=groups,dc=example,dc=com")
	groupA, _ := ParseLDAPDistinguishedName("cn=Amber,ou=groups,dc=example,dc=com")
	gid, _ := ParseLDAPGIDNumber("0")
	observation, err := NewLDAPObservation(LDAPObservationInput{
		Subject: subject, UserDN: userDN, LoginUsername: username,
		Profile: LDAPProfileValues{FirstName: &firstName, Email: &email},
		Groups:  []LDAPDistinguishedName{groupB, groupA, groupB}, GIDNumber: &gid,
		AccountState: LDAPAccountActive, Complete: true,
	})
	if err != nil {
		t.Fatalf("NewLDAPObservation() error = %v", err)
	}
	firstName = "mutated"
	email = "mutated@example.com"
	subject.Clear()
	if observation.GroupCount() != 2 || !observation.Complete() ||
		observation.AccountState() != LDAPAccountActive || observation.SubjectFormat() != UTF8ExactSubject {
		t.Fatalf("observation metadata = %s", observation)
	}
	if got, present, revealErr := observation.RevealProfileField(LDAPProfileFirstName); revealErr != nil || !present || got != "Alice" {
		t.Fatalf("RevealProfileField() = %q, %t, %v", got, present, revealErr)
	}
	groups := observation.mappingGroups()
	if groups[0].value != groupA.value || groups[1].value != groupB.value {
		t.Fatalf("groups = %q, %q", groups[0].value, groups[1].value)
	}
}

func TestLDAPObservationProtectsSubjectWithoutExposingIt(t *testing.T) {
	subject, _ := CanonicalUTF8CaseFold([]byte("Private-Subject"))
	username, _ := NewLDAPUsername("alice")
	userDN, _ := ParseLDAPDistinguishedName("uid=alice,dc=example,dc=com")
	observation, err := NewLDAPObservation(LDAPObservationInput{
		Subject: subject, UserDN: userDN, LoginUsername: username,
		AccountState: LDAPAccountActive, Complete: true,
	})
	if err != nil {
		t.Fatalf("NewLDAPObservation() error = %v", err)
	}
	keyring := mustKeyring(t, 1, map[int16][]byte{1: bytes.Repeat([]byte{0x81}, sourceKeyBytes)})
	context := testExternalSubjectContext(0x82)
	envelope, aliases, err := observation.ProtectSubject(keyring, context)
	if err != nil || len(aliases) != 1 || len(envelope.Ciphertext) <= externalSubjectTagBytes {
		t.Fatalf("ProtectSubject() = %#v, %#v, %v", envelope, aliases, err)
	}
	decrypted, err := keyring.DecryptExternalSubject(context, envelope)
	if err != nil || string(decrypted.value) != "private-subject" {
		t.Fatalf("DecryptExternalSubject() = %#v, %v", decrypted, err)
	}
	decrypted.Clear()
	clear(envelope.Ciphertext)
}

func TestLDAPObservationSubjectAliasesAreDeterministicAndDoNotExposeSubject(t *testing.T) {
	subject, _ := CanonicalUTF8CaseFold([]byte("Private-Dry-Run-Subject"))
	username, _ := NewLDAPUsername("alice")
	userDN, _ := ParseLDAPDistinguishedName("uid=alice,dc=example,dc=com")
	observation, err := NewLDAPObservation(LDAPObservationInput{
		Subject: subject, UserDN: userDN, LoginUsername: username,
		AccountState: LDAPAccountActive, Complete: true,
	})
	if err != nil {
		t.Fatalf("NewLDAPObservation() error = %v", err)
	}
	keyring := mustKeyring(t, 2, map[int16][]byte{
		1: bytes.Repeat([]byte{0x83}, sourceKeyBytes),
		2: bytes.Repeat([]byte{0x84}, sourceKeyBytes),
	})
	provider := ProviderContext{
		Scope: TenantProviderScope, TenantID: testID(0x85), ProviderID: testID(0x86),
	}

	aliases, err := observation.SubjectAliases(keyring, provider)
	if err != nil || len(aliases) != 2 || aliases[0].KeyVersion != 1 || aliases[1].KeyVersion != 2 {
		t.Fatalf("SubjectAliases() = %#v, %v", aliases, err)
	}
	if aliases[0].Digest == ([32]byte{}) || aliases[0].Digest == aliases[1].Digest {
		t.Fatal("subject aliases must be nonzero and independently keyed")
	}
	expectedFirst := aliases[0].Digest
	aliases[0].Digest[0] ^= 0xff
	repeat, err := observation.SubjectAliases(keyring, provider)
	if err != nil || repeat[0].Digest != expectedFirst {
		t.Fatalf("repeated SubjectAliases() = %#v, %v", repeat, err)
	}
	formatted := fmt.Sprintf("%v|%+v|%#v", repeat, repeat, repeat)
	if strings.Contains(strings.ToLower(formatted), "private-dry-run-subject") {
		t.Fatalf("formatted aliases exposed subject: %s", formatted)
	}

	if _, err := observation.SubjectAliases(keyring, ProviderContext{}); !errors.Is(err, ErrInvalidLDAPObservation) {
		t.Fatalf("invalid provider error = %v", err)
	}
	if _, err := (LDAPObservation{}).SubjectAliases(keyring, provider); !errors.Is(err, ErrInvalidLDAPObservation) {
		t.Fatalf("zero observation error = %v", err)
	}
}

func TestNewLDAPObservationRejectsMalformedOrOversizedShapes(t *testing.T) {
	valid := validLDAPObservationInput(t)
	tests := []LDAPObservationInput{
		{},
		func() LDAPObservationInput { value := valid; value.Subject = Subject{}; return value }(),
		func() LDAPObservationInput { value := valid; value.UserDN = LDAPDistinguishedName{}; return value }(),
		func() LDAPObservationInput { value := valid; value.LoginUsername = LDAPUsername{}; return value }(),
		func() LDAPObservationInput { value := valid; value.AccountState = 0; return value }(),
		func() LDAPObservationInput {
			value := valid
			invalid := "bad\nvalue"
			value.Profile.FirstName = &invalid
			return value
		}(),
		func() LDAPObservationInput {
			value := valid
			value.Groups = make([]LDAPDistinguishedName, maximumLDAPObservationGroups+1)
			return value
		}(),
		func() LDAPObservationInput { value := valid; value.Groups = []LDAPDistinguishedName{{}}; return value }(),
		func() LDAPObservationInput { value := valid; value.GIDNumber = &LDAPGIDNumber{}; return value }(),
	}
	for index, input := range tests {
		if _, err := NewLDAPObservation(input); !errors.Is(err, ErrInvalidLDAPObservation) {
			t.Fatalf("case %d error = %v", index, err)
		}
	}
}

func TestLDAPObservationFormattingAndPresenceAreRedacted(t *testing.T) {
	input := validLDAPObservationInput(t)
	privateSubject := "private-observation-subject"
	input.Subject, _ = CanonicalUTF8Exact([]byte(privateSubject))
	secretName := "Sensitive Name"
	secretEmail := "sensitive@example.com"
	input.Profile = LDAPProfileValues{DisplayName: &secretName, Email: &secretEmail}
	observation, err := NewLDAPObservation(input)
	if err != nil {
		t.Fatalf("NewLDAPObservation() error = %v", err)
	}
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q", observation, observation, observation, observation, observation)
	if strings.Contains(formatted, secretName) || strings.Contains(formatted, secretEmail) || strings.Contains(formatted, privateSubject) {
		t.Fatalf("formatted observation exposed values: %s", formatted)
	}
	presence := observation.ProfilePresence()
	if !presence[LDAPProfileDisplayName] || !presence[LDAPProfileEmail] || presence[LDAPProfileFirstName] {
		t.Fatalf("presence = %#v", presence)
	}
	if _, _, err := observation.RevealProfileField(0); !errors.Is(err, ErrInvalidLDAPObservation) {
		t.Fatalf("unknown profile field error = %v", err)
	}
}

func validLDAPObservationInput(t *testing.T) LDAPObservationInput {
	t.Helper()
	subject, _ := CanonicalUTF8Exact([]byte("subject"))
	username, _ := NewLDAPUsername("alice")
	userDN, _ := ParseLDAPDistinguishedName("uid=alice,dc=example,dc=com")
	return LDAPObservationInput{
		Subject: subject, UserDN: userDN, LoginUsername: username,
		AccountState: LDAPAccountActive, Complete: true,
	}
}
