package identity

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestLDAPBoundaryValueFormattingIsRedacted(t *testing.T) {
	username, _ := NewLDAPUsername("private-format-username")
	dn, _ := ParseLDAPDistinguishedName("uid=private-format-username,dc=example,dc=com")
	gid, _ := ParseLDAPGIDNumber("42424242")
	template, _ := CompileLDAPTemplate(
		LDAPTemplateContextUserSearchFilter,
		"(&(objectClass=privateFormatClass)(uid={username}))",
	)
	matcherSpec := LDAPGroupMatcherSpec{
		Kind: LDAPGroupMatcherExactCN, CaseMode: LDAPGroupCaseSensitive,
		Pattern: "private-format-group",
	}
	matcher, _ := CompileLDAPGroupMatcher(matcherSpec)
	subject, _ := CanonicalUTF8Exact([]byte("private-format-subject"))
	profileValue := "private-format-profile"
	input := LDAPObservationInput{
		Subject: subject, UserDN: dn, LoginUsername: username,
		Profile: LDAPProfileValues{DisplayName: &profileValue}, Groups: []LDAPDistinguishedName{dn},
		AccountState: LDAPAccountActive, Complete: true,
	}
	bindCiphertext := []byte("private-bind-ciphertext")
	externalCiphertext := []byte("private-external-ciphertext")
	bindEnvelope := BindSecretEnvelope{KeyVersion: 1, Ciphertext: bindCiphertext}
	externalEnvelope := ExternalSubjectEnvelope{
		KeyVersion: 1, Format: UTF8ExactSubject, Ciphertext: externalCiphertext,
	}
	alias := SubjectAlias{KeyVersion: 1}
	for index := range alias.Digest {
		alias.Digest[index] = 0xa7
	}
	snapshot := minimalMappingSnapshot()
	snapshot.Rules = []LDAPMappingRule{{
		Revision: 1, Matcher: matcher, AdministrativeNote: "private-format-note",
	}}

	values := []any{
		username,
		dn,
		gid,
		LDAPTemplateValues{Username: username, UserDN: dn, GIDNumber: gid},
		template,
		matcherSpec,
		matcher,
		input,
		bindEnvelope,
		externalEnvelope,
		alias,
		snapshot,
	}
	var formatted strings.Builder
	for _, value := range values {
		fmt.Fprintf(&formatted, "%v|%+v|%#v|%s|%q|%x\n", value, value, value, value, value, value)
	}
	result := formatted.String()
	secrets := [][]byte{
		[]byte("private-format-username"),
		[]byte("privateFormatClass"),
		[]byte("private-format-group"),
		[]byte("private-format-subject"),
		[]byte("private-format-profile"),
		[]byte("private-format-note"),
		bindCiphertext,
		externalCiphertext,
		alias.Digest[:],
	}
	for _, secret := range secrets {
		if strings.Contains(result, string(secret)) || strings.Contains(result, hex.EncodeToString(secret)) {
			t.Fatalf("formatted LDAP boundary value exposed secret %q: %s", secret, result)
		}
	}
}
