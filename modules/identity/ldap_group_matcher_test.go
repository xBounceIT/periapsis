package identity

import (
	"errors"
	"strings"
	"testing"
)

func TestLDAPExactDNMatcherUsesParsedCanonicalEquality(t *testing.T) {
	group, err := ParseLDAPDistinguishedName("UID=42+CN=Blue\\, Team,OU=Groups,DC=example,DC=com")
	if err != nil {
		t.Fatalf("ParseLDAPDistinguishedName() error = %v", err)
	}
	caseSensitive, err := CompileLDAPGroupMatcher(LDAPGroupMatcherSpec{
		Kind: LDAPGroupMatcherExactDN, CaseMode: LDAPGroupCaseSensitive,
		Pattern: "cn=Blue\\, Team+uid=42,ou=Groups,dc=example,dc=com",
	})
	if err != nil {
		t.Fatalf("CompileLDAPGroupMatcher() error = %v", err)
	}
	matched, err := caseSensitive.Match(group)
	if err != nil || !matched {
		t.Fatalf("case-sensitive Match() = %t, %v", matched, err)
	}

	differentCase, _ := ParseLDAPDistinguishedName("cn=blue\\, team+uid=42,ou=groups,dc=example,dc=com")
	matched, err = caseSensitive.Match(differentCase)
	if err != nil || matched {
		t.Fatalf("case-sensitive changed-case Match() = %t, %v", matched, err)
	}
	caseInsensitive, err := CompileLDAPGroupMatcher(LDAPGroupMatcherSpec{
		Kind: LDAPGroupMatcherExactDN, CaseMode: LDAPGroupCaseInsensitive,
		Pattern: "cn=Blue\\, Team+uid=42,ou=Groups,dc=example,dc=com",
	})
	if err != nil {
		t.Fatalf("Compile case-insensitive matcher: %v", err)
	}
	matched, err = caseInsensitive.Match(differentCase)
	if err != nil || !matched {
		t.Fatalf("case-insensitive Match() = %t, %v", matched, err)
	}
}

func TestLDAPExactCNMatcherUsesExactlyOneLeafCN(t *testing.T) {
	matcher, err := CompileLDAPGroupMatcher(LDAPGroupMatcherSpec{
		Kind: LDAPGroupMatcherExactCN, CaseMode: LDAPGroupCaseInsensitive, Pattern: "Incident Response",
	})
	if err != nil {
		t.Fatalf("CompileLDAPGroupMatcher() error = %v", err)
	}
	group, _ := ParseLDAPDistinguishedName("cn=incident response,ou=Groups,dc=example,dc=com")
	matched, err := matcher.Match(group)
	if err != nil || !matched {
		t.Fatalf("Match() = %t, %v", matched, err)
	}
	parentOnly, _ := ParseLDAPDistinguishedName("uid=team,cn=Incident Response,dc=example,dc=com")
	matched, err = matcher.Match(parentOnly)
	if err != nil || matched {
		t.Fatalf("parent CN Match() = %t, %v", matched, err)
	}
	ambiguous, _ := ParseLDAPDistinguishedName("cn=Incident Response+cn=Other,dc=example,dc=com")
	if _, err := matcher.Match(ambiguous); !errors.Is(err, ErrInvalidLDAPGroupMatcher) {
		t.Fatalf("ambiguous leaf Match() error = %v", err)
	}
}

func TestLDAPRegexMatcherIsFullStringAndCasePolicyIsExplicit(t *testing.T) {
	group, _ := ParseLDAPDistinguishedName("cn=Blue Team,ou=Groups,dc=example,dc=com")
	caseSensitive, err := CompileLDAPGroupMatcher(LDAPGroupMatcherSpec{
		Kind: LDAPGroupMatcherRegex, CaseMode: LDAPGroupCaseSensitive,
		Pattern: `cn=Blue Team,ou=Groups,dc=example,dc=com`,
	})
	if err != nil {
		t.Fatalf("CompileLDAPGroupMatcher() error = %v", err)
	}
	matched, err := caseSensitive.Match(group)
	if err != nil || !matched {
		t.Fatalf("exact regex Match() = %t, %v", matched, err)
	}
	partial, _ := CompileLDAPGroupMatcher(LDAPGroupMatcherSpec{
		Kind: LDAPGroupMatcherRegex, CaseMode: LDAPGroupCaseSensitive, Pattern: `Blue Team`,
	})
	matched, err = partial.Match(group)
	if err != nil || matched {
		t.Fatalf("partial regex Match() = %t, %v", matched, err)
	}
	caseInsensitive, _ := CompileLDAPGroupMatcher(LDAPGroupMatcherSpec{
		Kind: LDAPGroupMatcherRegex, CaseMode: LDAPGroupCaseInsensitive,
		Pattern: `CN=BLUE TEAM,OU=GROUPS,DC=EXAMPLE,DC=COM`,
	})
	matched, err = caseInsensitive.Match(group)
	if err != nil || !matched {
		t.Fatalf("case-insensitive regex Match() = %t, %v", matched, err)
	}
}

func TestCompileLDAPGroupMatcherRejectsUnsafeOrAmbiguousRules(t *testing.T) {
	tests := []LDAPGroupMatcherSpec{
		{},
		{Kind: LDAPGroupMatcherExactCN, CaseMode: 0, Pattern: "team"},
		{Kind: LDAPGroupMatcherExactCN, CaseMode: LDAPGroupCaseSensitive, Pattern: ""},
		{Kind: LDAPGroupMatcherExactCN, CaseMode: LDAPGroupCaseSensitive, Pattern: "team\n"},
		{Kind: LDAPGroupMatcherExactDN, CaseMode: LDAPGroupCaseSensitive, Pattern: "not a DN"},
		{Kind: LDAPGroupMatcherRegex, CaseMode: LDAPGroupCaseSensitive, Pattern: "("},
		{Kind: LDAPGroupMatcherRegex, CaseMode: LDAPGroupCaseSensitive, Pattern: `(?i)team`},
		{Kind: LDAPGroupMatcherRegex, CaseMode: LDAPGroupCaseInsensitive, Pattern: `(?-i:team)`},
		{Kind: LDAPGroupMatcherRegex, CaseMode: LDAPGroupCaseSensitive, Pattern: strings.Repeat("a", maximumLDAPGroupMatcherPatternBytes+1)},
	}
	for index, spec := range tests {
		if _, err := CompileLDAPGroupMatcher(spec); !errors.Is(err, ErrInvalidLDAPGroupMatcher) {
			t.Fatalf("case %d CompileLDAPGroupMatcher() error = %v", index, err)
		}
	}
}

func TestLDAPGroupMatcherAcceptsTheCompleteCanonicalDNContract(t *testing.T) {
	matcher, _ := CompileLDAPGroupMatcher(LDAPGroupMatcherSpec{
		Kind: LDAPGroupMatcherRegex, CaseMode: LDAPGroupCaseSensitive, Pattern: `.*`,
	})
	if _, err := matcher.Match(LDAPDistinguishedName{}); !errors.Is(err, ErrInvalidLDAPGroupMatcher) {
		t.Fatalf("zero group Match() error = %v", err)
	}
	if _, err := (CompiledLDAPGroupMatcher{}).Match(LDAPDistinguishedName{}); !errors.Is(err, ErrInvalidLDAPGroupMatcher) {
		t.Fatalf("zero matcher Match() error = %v", err)
	}
	longSource := "cn=" + strings.Repeat("é", 900) + ",dc=example,dc=com"
	longDN, err := ParseLDAPDistinguishedName(longSource)
	if err != nil {
		t.Fatalf("long fixture parse = %v", err)
	}
	if len(longDN.value) <= 4096 || len(longDN.value) > maximumLDAPGroupCanonicalDNBytes {
		t.Fatalf("long fixture canonical bytes = %d", len(longDN.value))
	}
	matched, err := matcher.Match(longDN)
	if err != nil || !matched {
		t.Fatalf("long Match() = %t, %v", matched, err)
	}
	exact, err := CompileLDAPGroupMatcher(LDAPGroupMatcherSpec{
		Kind: LDAPGroupMatcherExactDN, CaseMode: LDAPGroupCaseSensitive, Pattern: longSource,
	})
	if err != nil {
		t.Fatalf("long exact CompileLDAPGroupMatcher() error = %v", err)
	}
	matched, err = exact.Match(longDN)
	if err != nil || !matched {
		t.Fatalf("long exact Match() = %t, %v", matched, err)
	}
	if _, err := ParseLDAPDistinguishedName("cn=" + strings.Repeat("é", 1400) + ",dc=example,dc=com"); !errors.Is(err, ErrInvalidLDAPTemplate) {
		t.Fatalf("over-contract ParseLDAPDistinguishedName() error = %v", err)
	}
}
