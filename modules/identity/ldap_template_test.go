package identity

import (
	"errors"
	"strings"
	"testing"
)

func TestCompileLDAPTemplateAcceptsClosedContextGrammar(t *testing.T) {
	tests := []struct {
		name    string
		context LDAPTemplateContext
		value   string
	}{
		{name: "user lookup", context: LDAPTemplateContextUserSearchFilter, value: "(&(objectClass=person)(uid={username}))"},
		{name: "user DN", context: LDAPTemplateContextUserDN, value: "uid={username},ou=people,dc=example,dc=invalid"},
		{name: "reverse group required only", context: LDAPTemplateContextReverseGroupSearchFilter, value: "(member={userDn})"},
		{name: "reverse group optional username", context: LDAPTemplateContextReverseGroupSearchFilter, value: "(|(member={userDn})(memberUid={username}))"},
		{name: "POSIX required only", context: LDAPTemplateContextPOSIXGroupSearchFilter, value: "(&(objectClass=posixGroup)(memberUid={username}))"},
		{name: "POSIX optional gid", context: LDAPTemplateContextPOSIXGroupSearchFilter, value: "(&(memberUid={username})(gidNumber={gidNumber}))"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := CompileLDAPTemplate(test.context, test.value); err != nil {
				t.Fatalf("CompileLDAPTemplate() error = %v", err)
			}
		})
	}
}

func TestCompileLDAPTemplateRejectsAmbiguousOrInvalidSurfaces(t *testing.T) {
	tests := []struct {
		name    string
		context LDAPTemplateContext
		value   string
	}{
		{name: "unknown context", context: 0, value: "(uid={username})"},
		{name: "unknown", context: LDAPTemplateContextUserSearchFilter, value: "(uid={user})"},
		{name: "duplicate", context: LDAPTemplateContextUserSearchFilter, value: "(|(uid={username})(mail={username}))"},
		{name: "missing required", context: LDAPTemplateContextUserSearchFilter, value: "(objectClass=person)"},
		{name: "unclosed placeholder", context: LDAPTemplateContextUserSearchFilter, value: "(uid={username)"},
		{name: "stray closing brace", context: LDAPTemplateContextUserSearchFilter, value: "(uid=username})"},
		{name: "nested placeholder", context: LDAPTemplateContextUserSearchFilter, value: "(uid={{username}})"},
		{name: "unclosed LDAP filter", context: LDAPTemplateContextUserSearchFilter, value: "(&(uid={username})"},
		{name: "inapplicable placeholder", context: LDAPTemplateContextUserSearchFilter, value: "(gidNumber={gidNumber})"},
		{name: "DN context userDn", context: LDAPTemplateContextUserDN, value: "uid={userDn},dc=example,dc=invalid"},
		{name: "reverse missing userDn", context: LDAPTemplateContextReverseGroupSearchFilter, value: "(uid={username})"},
		{name: "POSIX missing username", context: LDAPTemplateContextPOSIXGroupSearchFilter, value: "(gidNumber={gidNumber})"},
		{name: "raw control", context: LDAPTemplateContextUserSearchFilter, value: "(uid={username}\n)"},
		{name: "negated username population", context: LDAPTemplateContextUserSearchFilter, value: "(!(uid={username}))"},
		{name: "ordered username assertion", context: LDAPTemplateContextUserSearchFilter, value: "(uid>={username})"},
		{name: "approximate username assertion", context: LDAPTemplateContextUserSearchFilter, value: "(uid~={username})"},
		{name: "extensible username assertion", context: LDAPTemplateContextUserSearchFilter, value: "(uid:caseExactMatch:={username})"},
		{name: "oversized", context: LDAPTemplateContextUserSearchFilter, value: "(uid={username}" + strings.Repeat("x", maximumLDAPFilterTemplateCharacters) + ")"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CompileLDAPTemplate(test.context, test.value)
			if !errors.Is(err, ErrInvalidLDAPTemplate) {
				t.Fatalf("CompileLDAPTemplate() error = %v, want ErrInvalidLDAPTemplate", err)
			}
		})
	}
}

func TestCompileLDAPTemplateAcceptsPositiveUsernameAssertionBesideIndependentNegation(t *testing.T) {
	template, err := CompileLDAPTemplate(
		LDAPTemplateContextUserSearchFilter,
		"(&(!(disabled=TRUE))(uid=prefix-{username}-suffix))",
	)
	if err != nil {
		t.Fatalf("CompileLDAPTemplate() error = %v", err)
	}
	rendered, err := template.RenderUserEnumerationFilter()
	if err != nil || rendered != "(&(!(disabled=TRUE))(uid=prefix-*-suffix))" {
		t.Fatalf("RenderUserEnumerationFilter() = %q, %v", rendered, err)
	}
}

func TestCompiledLDAPTemplateRendersTypedEscapedValues(t *testing.T) {
	username, err := NewLDAPUsername(" *(admin)\\ ")
	if err != nil {
		t.Fatalf("NewLDAPUsername() error = %v", err)
	}
	userDN, err := ParseLDAPDistinguishedName("cn=Smith\\, Alice,ou=People,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseLDAPDistinguishedName() error = %v", err)
	}
	gidNumber, err := ParseLDAPGIDNumber("4294967295")
	if err != nil {
		t.Fatalf("ParseLDAPGIDNumber() error = %v", err)
	}

	userFilter, _ := CompileLDAPTemplate(LDAPTemplateContextUserSearchFilter, "(uid={username})")
	rendered, err := userFilter.Render(LDAPTemplateValues{Username: username})
	if err != nil || rendered != `(uid= \2a\28admin\29\5c )` {
		t.Fatalf("user filter = %q, error = %v", rendered, err)
	}

	userDNTemplate, _ := CompileLDAPTemplate(LDAPTemplateContextUserDN, "uid={username},ou=people,dc=example,dc=com")
	rendered, err = userDNTemplate.Render(LDAPTemplateValues{Username: username})
	if err != nil || rendered != `uid=\ *(admin)\\\ ,ou=people,dc=example,dc=com` {
		t.Fatalf("user DN = %q, error = %v", rendered, err)
	}

	groupFilter, _ := CompileLDAPTemplate(LDAPTemplateContextReverseGroupSearchFilter, "(|(member={userDn})(memberUid={username}))")
	rendered, err = groupFilter.Render(LDAPTemplateValues{Username: username, UserDN: userDN})
	if err != nil || !strings.Contains(rendered, `member=cn=Smith\5c, Alice,ou=People,dc=example,dc=com`) ||
		!strings.Contains(rendered, `memberUid= \2a\28admin\29\5c `) {
		t.Fatalf("group filter = %q, error = %v", rendered, err)
	}

	posixFilter, _ := CompileLDAPTemplate(LDAPTemplateContextPOSIXGroupSearchFilter, "(&(memberUid={username})(gidNumber={gidNumber}))")
	rendered, err = posixFilter.Render(LDAPTemplateValues{Username: username, GIDNumber: gidNumber})
	if err != nil || !strings.Contains(rendered, "(gidNumber=4294967295)") {
		t.Fatalf("POSIX filter = %q, error = %v", rendered, err)
	}
}

func TestCompiledLDAPTemplateDerivesClosedUserEnumerationFilter(t *testing.T) {
	template, err := CompileLDAPTemplate(
		LDAPTemplateContextUserSearchFilter,
		"(&(objectClass=person)(uid={username}))",
	)
	if err != nil {
		t.Fatalf("CompileLDAPTemplate() error = %v", err)
	}

	rendered, err := template.RenderUserEnumerationFilter()
	if err != nil || rendered != "(&(objectClass=person)(uid=*))" {
		t.Fatalf("RenderUserEnumerationFilter() = %q, %v", rendered, err)
	}

	hostile, err := NewLDAPUsername("*")
	if err != nil {
		t.Fatalf("NewLDAPUsername() error = %v", err)
	}
	lookup, err := template.Render(LDAPTemplateValues{Username: hostile})
	if err != nil || lookup != `(&(objectClass=person)(uid=\2a))` {
		t.Fatalf("lookup filter = %q, %v", lookup, err)
	}
}

func TestCompiledLDAPTemplateRejectsEnumerationFromAnyOtherContext(t *testing.T) {
	reverse, err := CompileLDAPTemplate(
		LDAPTemplateContextReverseGroupSearchFilter,
		"(member={userDn})",
	)
	if err != nil {
		t.Fatalf("CompileLDAPTemplate() error = %v", err)
	}
	for name, template := range map[string]CompiledLDAPTemplate{
		"zero":    {},
		"reverse": reverse,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := template.RenderUserEnumerationFilter(); !errors.Is(err, ErrInvalidLDAPTemplate) {
				t.Fatalf("RenderUserEnumerationFilter() error = %v", err)
			}
		})
	}
}

func TestCompiledLDAPTemplateFailsWhenOptionalRuntimeValueIsMissing(t *testing.T) {
	username, _ := NewLDAPUsername("alice")
	userDN, _ := ParseLDAPDistinguishedName("uid=alice,dc=example,dc=com")
	tests := []struct {
		name     string
		context  LDAPTemplateContext
		value    string
		rendered LDAPTemplateValues
	}{
		{name: "optional reverse username", context: LDAPTemplateContextReverseGroupSearchFilter, value: "(|(member={userDn})(memberUid={username}))", rendered: LDAPTemplateValues{UserDN: userDN}},
		{name: "optional POSIX gid", context: LDAPTemplateContextPOSIXGroupSearchFilter, value: "(&(memberUid={username})(gidNumber={gidNumber}))", rendered: LDAPTemplateValues{Username: username}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			template, err := CompileLDAPTemplate(test.context, test.value)
			if err != nil {
				t.Fatalf("CompileLDAPTemplate() error = %v", err)
			}
			if _, err := template.Render(test.rendered); !errors.Is(err, ErrInvalidLDAPTemplate) {
				t.Fatalf("Render() error = %v, want ErrInvalidLDAPTemplate", err)
			}
		})
	}
}

func TestCompiledLDAPTemplateRequirementsReflectOptionalTokenPresence(t *testing.T) {
	tests := []struct {
		name    string
		context LDAPTemplateContext
		value   string
		want    LDAPTemplateRequirements
	}{
		{
			name: "reverse required only", context: LDAPTemplateContextReverseGroupSearchFilter,
			value: "(member={userDn})", want: LDAPTemplateRequirements{UserDN: true},
		},
		{
			name: "reverse username present", context: LDAPTemplateContextReverseGroupSearchFilter,
			value: "(|(member={userDn})(memberUid={username}))",
			want:  LDAPTemplateRequirements{Username: true, UserDN: true},
		},
		{
			name: "POSIX gid omitted", context: LDAPTemplateContextPOSIXGroupSearchFilter,
			value: "(memberUid={username})", want: LDAPTemplateRequirements{Username: true},
		},
		{
			name: "POSIX gid present", context: LDAPTemplateContextPOSIXGroupSearchFilter,
			value: "(&(memberUid={username})(gidNumber={gidNumber}))",
			want:  LDAPTemplateRequirements{Username: true, GIDNumber: true},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			template, err := CompileLDAPTemplate(test.context, test.value)
			if err != nil {
				t.Fatalf("CompileLDAPTemplate() error = %v", err)
			}
			got, err := template.Requirements()
			if err != nil || got != test.want {
				t.Fatalf("Requirements() = %#v, %v, want %#v", got, err, test.want)
			}
		})
	}
}

func TestLDAPRuntimeValueTypesRejectNonCanonicalOrInvalidInput(t *testing.T) {
	for _, value := range []string{"", "alice\n", strings.Repeat("x", maximumLDAPUsernameCharacters+1)} {
		if _, err := NewLDAPUsername(value); !errors.Is(err, ErrInvalidLDAPTemplate) {
			t.Fatalf("NewLDAPUsername(%q) error = %v", value, err)
		}
	}
	for _, value := range []string{"", "not a dn", "cn=alice,dc=example,dc=com,"} {
		if _, err := ParseLDAPDistinguishedName(value); !errors.Is(err, ErrInvalidLDAPTemplate) {
			t.Fatalf("ParseLDAPDistinguishedName(%q) error = %v", value, err)
		}
	}
	for _, value := range []string{"", "-1", "+1", "01", "4294967296", "1 "} {
		if _, err := ParseLDAPGIDNumber(value); !errors.Is(err, ErrInvalidLDAPTemplate) {
			t.Fatalf("ParseLDAPGIDNumber(%q) error = %v", value, err)
		}
	}
}

func TestCompiledLDAPTemplateZeroValueFailsClosed(t *testing.T) {
	if _, err := (CompiledLDAPTemplate{}).Render(LDAPTemplateValues{}); !errors.Is(err, ErrInvalidLDAPTemplate) {
		t.Fatalf("zero-value Render() error = %v, want ErrInvalidLDAPTemplate", err)
	}
	if _, err := (CompiledLDAPTemplate{}).Requirements(); !errors.Is(err, ErrInvalidLDAPTemplate) {
		t.Fatalf("zero-value Requirements() error = %v, want ErrInvalidLDAPTemplate", err)
	}
}
