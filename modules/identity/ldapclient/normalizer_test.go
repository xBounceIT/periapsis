package ldapclient

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestNormalizeDirectoryObservationActiveDirectory(t *testing.T) {
	t.Parallel()

	objectGUID := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
	}
	configuration := mustADNormalizationConfiguration(t)
	raw := DirectoryObservation{
		User: DirectoryEntry{
			DistinguishedName: "CN=Alice Smith,OU=People,DC=example,DC=com",
			Attributes: []DirectoryAttribute{
				{Name: "mail", Values: [][]byte{[]byte("alice@example.com")}},
				{Name: "objectGUID", Values: [][]byte{append([]byte(nil), objectGUID...)}},
				{Name: "givenName", Values: [][]byte{[]byte("Alice")}},
				{Name: "sn", Values: [][]byte{[]byte("Smith")}},
				{Name: "displayName", Values: [][]byte{[]byte("Alice Smith")}},
				{Name: "sAMAccountName", Values: [][]byte{[]byte("alice")}},
				{Name: "userPrincipalName", Values: [][]byte{[]byte("alice@example.com")}},
				{Name: "accountFlags", Values: [][]byte{[]byte("512")}},
			},
		},
		Groups: []DirectoryEntry{
			{DistinguishedName: "CN=Responders,OU=Groups,DC=example,DC=com"},
			{DistinguishedName: "cn=responders,ou=groups,dc=EXAMPLE,dc=COM"},
			{DistinguishedName: "CN=Operators,OU=Groups,DC=example,DC=com"},
		},
	}

	observation, err := NormalizeDirectoryObservation(configuration, raw)
	if err != nil {
		t.Fatalf("NormalizeDirectoryObservation() error = %v", err)
	}
	if observation.SubjectFormat() != identity.ADObjectGUIDSubject ||
		observation.AccountState() != identity.LDAPAccountActive ||
		!observation.Complete() || observation.GroupCount() != 2 {
		t.Fatalf("observation metadata = %s", observation)
	}
	assertProfileField(t, observation, identity.LDAPProfileFirstName, "Alice")
	assertProfileField(t, observation, identity.LDAPProfileLastName, "Smith")
	assertProfileField(t, observation, identity.LDAPProfileDisplayName, "Alice Smith")
	assertProfileField(t, observation, identity.LDAPProfileUsername, "alice")
	assertProfileField(t, observation, identity.LDAPProfileAlternateUsername, "alice@example.com")
	assertProfileField(t, observation, identity.LDAPProfileEmail, "alice@example.com")

	expected, subjectErr := identity.CanonicalADObjectGUID(objectGUID)
	if subjectErr != nil {
		t.Fatalf("CanonicalADObjectGUID() error = %v", subjectErr)
	}
	defer expected.Clear()
	if got, want := observationSubjectAlias(t, observation), canonicalSubjectAlias(t, expected); got != want {
		t.Fatal("binary objectGUID was not preserved exactly")
	}
	disabledRaw := cloneNormalizationObservation(raw)
	disabledRaw.User.Attributes[7].Values[0] = []byte("514")
	disabled, err := NormalizeDirectoryObservation(configuration, disabledRaw)
	if err != nil || disabled.AccountState() != identity.LDAPAccountDisabled {
		t.Fatalf("disabled AD observation = %s, %v", disabled, err)
	}

	attributes, err := configuration.RequiredUserAttributes()
	if err != nil {
		t.Fatalf("RequiredUserAttributes() error = %v", err)
	}
	wantAttributes := []string{
		"accountflags", "displayname", "givenname", "mail", "objectguid",
		"samaccountname", "sn", "userprincipalname",
	}
	if !slices.Equal(attributes, wantAttributes) {
		t.Fatalf("RequiredUserAttributes() = %v, want %v", attributes, wantAttributes)
	}
	attributes[0] = "mutated"
	again, _ := configuration.RequiredUserAttributes()
	if !slices.Equal(again, wantAttributes) {
		t.Fatalf("RequiredUserAttributes() did not return an owned copy: %v", again)
	}
}

func TestDirectoryUsernameFromEntryBridgesEnumerationToTypedLookup(t *testing.T) {
	t.Parallel()

	attribute := mustDirectoryAttributeName(t, "uid")
	entry := DirectoryEntry{
		DistinguishedName: "uid=alice,ou=people,dc=example,dc=com",
		Attributes: []DirectoryAttribute{
			{Name: "mail", Values: [][]byte{[]byte("alice@example.com")}},
			{Name: "UID", Values: [][]byte{[]byte(` *(alice)\ `)}},
		},
	}
	username, err := DirectoryUsernameFromEntry(attribute, entry)
	if err != nil {
		t.Fatalf("DirectoryUsernameFromEntry() error = %v", err)
	}
	filter, err := identity.CompileLDAPTemplate(
		identity.LDAPTemplateContextUserSearchFilter,
		"(uid={username})",
	)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := filter.Render(identity.LDAPTemplateValues{Username: username})
	if err != nil || rendered != `(uid= \2a\28alice\29\5c )` {
		t.Fatalf("typed lookup filter = %q, %v", rendered, err)
	}
	if formatted := fmt.Sprintf("%#v", username); strings.Contains(formatted, "alice") ||
		!strings.Contains(formatted, "[REDACTED]") {
		t.Fatalf("username formatting leaked the value: %s", formatted)
	}
}

func TestDirectoryUsernameFromEntryRejectsMalformedEnumerationEntries(t *testing.T) {
	t.Parallel()

	attribute := mustDirectoryAttributeName(t, "uid")
	valid := DirectoryEntry{
		DistinguishedName: "uid=alice,ou=people,dc=example,dc=com",
		Attributes:        []DirectoryAttribute{{Name: "uid", Values: [][]byte{[]byte("alice")}}},
	}
	for name, mutate := range map[string]func(*DirectoryEntry){
		"missing": func(entry *DirectoryEntry) {
			entry.Attributes = nil
		},
		"multi-valued": func(entry *DirectoryEntry) {
			entry.Attributes[0].Values = append(entry.Attributes[0].Values, []byte("alias"))
		},
		"invalid utf8": func(entry *DirectoryEntry) {
			entry.Attributes[0].Values[0] = []byte{0xff}
		},
		"duplicate attribute": func(entry *DirectoryEntry) {
			entry.Attributes = append(entry.Attributes, DirectoryAttribute{Name: "UID", Values: [][]byte{[]byte("alice")}})
		},
		"malformed dn": func(entry *DirectoryEntry) {
			entry.DistinguishedName = "not a dn"
		},
	} {
		t.Run(name, func(t *testing.T) {
			entry := cloneNormalizationEntry(valid)
			mutate(&entry)
			if _, err := DirectoryUsernameFromEntry(attribute, entry); !errors.Is(err, ErrInvalidDirectoryNormalization) {
				t.Fatalf("DirectoryUsernameFromEntry() error = %v", err)
			}
		})
	}
	if _, err := DirectoryUsernameFromEntry(DirectoryAttributeName{}, valid); !errors.Is(err, ErrInvalidDirectoryNormalization) {
		t.Fatalf("zero attribute error = %v", err)
	}
}

func TestNormalizeDirectoryObservationOpenLDAPModes(t *testing.T) {
	t.Parallel()

	username := mustNormalizationUsername(t, "alice")
	uuidAttribute := mustDirectoryAttributeName(t, "entryUUID")
	lockAttribute := mustDirectoryAttributeName(t, "customLockFlag")
	subject := mustDirectorySubjectMapping(t, DirectorySubjectEntryUUID, uuidAttribute)
	marker := []byte("LOCKED")
	account, err := NewDirectoryOpenLDAPValueAccountState(
		lockAttribute,
		marker,
		DirectoryValueCaseFold,
	)
	if err != nil {
		t.Fatalf("NewDirectoryOpenLDAPValueAccountState() error = %v", err)
	}
	marker[0] = 'X'
	configuration := DirectoryNormalizationConfiguration{
		LoginUsername: username,
		Subject:       subject,
		AccountState:  account,
	}
	raw := DirectoryObservation{User: DirectoryEntry{
		DistinguishedName: "uid=alice,ou=people,dc=example,dc=com",
		Attributes: []DirectoryAttribute{
			{Name: "entryUUID", Values: [][]byte{[]byte("550e8400-e29b-41d4-a716-446655440000")}},
			{Name: "customLockFlag", Values: [][]byte{[]byte("locked")}},
		},
	}}
	observation, err := NormalizeDirectoryObservation(configuration, raw)
	if err != nil {
		t.Fatalf("NormalizeDirectoryObservation() error = %v", err)
	}
	if observation.SubjectFormat() != identity.EntryUUIDSubject ||
		observation.AccountState() != identity.LDAPAccountDisabled {
		t.Fatalf("OpenLDAP observation = %s", observation)
	}

	withoutMarker := cloneNormalizationObservation(raw)
	withoutMarker.User.Attributes = withoutMarker.User.Attributes[:1]
	active, err := NormalizeDirectoryObservation(configuration, withoutMarker)
	if err != nil || active.AccountState() != identity.LDAPAccountActive {
		t.Fatalf("absent OpenLDAP marker = %s, %v", active, err)
	}

	presenceAccount, err := NewDirectoryOpenLDAPPresenceAccountState(lockAttribute)
	if err != nil {
		t.Fatalf("NewDirectoryOpenLDAPPresenceAccountState() error = %v", err)
	}
	configuration.AccountState = presenceAccount
	present, err := NormalizeDirectoryObservation(configuration, raw)
	if err != nil || present.AccountState() != identity.LDAPAccountDisabled {
		t.Fatalf("present OpenLDAP marker = %s, %v", present, err)
	}
}

func TestNormalizeDirectoryObservationPOSIXGIDAndExpiry(t *testing.T) {
	t.Parallel()

	entryUUID := mustDirectoryAttributeName(t, "stableUUID")
	uid := mustDirectoryAttributeName(t, "loginName")
	gid := mustDirectoryAttributeName(t, "unixPrimaryGroup")
	expiry := mustDirectoryAttributeName(t, "accountExpiryDay")
	account, err := NewDirectoryPOSIXShadowExpireAccountState(expiry, 20_000)
	if err != nil {
		t.Fatalf("NewDirectoryPOSIXShadowExpireAccountState() error = %v", err)
	}
	configuration := DirectoryNormalizationConfiguration{
		LoginUsername:      mustNormalizationUsername(t, "alice"),
		Profile:            DirectoryProfileAttributeMapping{Username: uid},
		Subject:            mustDirectorySubjectMapping(t, DirectorySubjectEntryUUID, entryUUID),
		AccountState:       account,
		GIDNumberAttribute: gid,
	}
	raw := DirectoryObservation{User: DirectoryEntry{
		DistinguishedName: "uid=alice,ou=posix,dc=example,dc=com",
		Attributes: []DirectoryAttribute{
			{Name: "stableUUID", Values: [][]byte{[]byte("550e8400-e29b-41d4-a716-446655440000")}},
			{Name: "loginName", Values: [][]byte{[]byte("alice")}},
			{Name: "unixPrimaryGroup", Values: [][]byte{[]byte("42")}},
			{Name: "accountExpiryDay", Values: [][]byte{[]byte("19999")}},
		},
	}}
	observation, err := NormalizeDirectoryObservation(configuration, raw)
	if err != nil {
		t.Fatalf("NormalizeDirectoryObservation() error = %v", err)
	}
	if observation.AccountState() != identity.LDAPAccountDisabled ||
		observation.SubjectFormat() != identity.EntryUUIDSubject {
		t.Fatalf("POSIX observation = %s", observation)
	}
	assertProfileField(t, observation, identity.LDAPProfileUsername, "alice")

	for name, value := range map[string][]byte{
		"no expiry":     []byte("-1"),
		"future expiry": []byte("20001"),
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneNormalizationObservation(raw)
			candidate.User.Attributes[3].Values[0] = value
			active, normalizeErr := NormalizeDirectoryObservation(configuration, candidate)
			if normalizeErr != nil || active.AccountState() != identity.LDAPAccountActive {
				t.Fatalf("NormalizeDirectoryObservation() = %s, %v", active, normalizeErr)
			}
		})
	}
}

func TestNormalizeDirectoryObservationCustomSubjectModes(t *testing.T) {
	t.Parallel()

	attribute := mustDirectoryAttributeName(t, "tenantStableID")
	raw := DirectoryObservation{User: DirectoryEntry{
		DistinguishedName: "uid=alice,dc=example,dc=com",
		Attributes: []DirectoryAttribute{
			{Name: "tenantStableID", Values: [][]byte{[]byte("Straße-ABC")}},
		},
	}}
	for _, test := range []struct {
		name     string
		mode     DirectorySubjectMode
		expected func([]byte) (identity.Subject, error)
	}{
		{name: "exact", mode: DirectorySubjectUTF8Exact, expected: identity.CanonicalUTF8Exact},
		{name: "casefold", mode: DirectorySubjectUTF8CaseFold, expected: identity.CanonicalUTF8CaseFold},
	} {
		t.Run(test.name, func(t *testing.T) {
			configuration := DirectoryNormalizationConfiguration{
				LoginUsername: mustNormalizationUsername(t, "alice"),
				Subject:       mustDirectorySubjectMapping(t, test.mode, attribute),
				AccountState:  DirectoryAlwaysActiveAccountState(),
			}
			observation, err := NormalizeDirectoryObservation(configuration, raw)
			if err != nil {
				t.Fatalf("NormalizeDirectoryObservation() error = %v", err)
			}
			expected, expectedErr := test.expected([]byte("Straße-ABC"))
			if expectedErr != nil {
				t.Fatalf("canonical subject error = %v", expectedErr)
			}
			defer expected.Clear()
			if got, want := observationSubjectAlias(t, observation), canonicalSubjectAlias(t, expected); got != want {
				t.Fatal("custom subject canonicalization mismatch")
			}
		})
	}
}

func TestNormalizeDirectoryObservationRejectsCardinalityMalformedAndOversizedInputs(t *testing.T) {
	t.Parallel()

	configuration, valid := validCustomNormalizationFixture(t)
	tests := []struct {
		name   string
		mutate func(*DirectoryNormalizationConfiguration, *DirectoryObservation)
	}{
		{name: "subject missing no profile auto link", mutate: func(_ *DirectoryNormalizationConfiguration, raw *DirectoryObservation) {
			raw.User.Attributes = raw.User.Attributes[1:]
		}},
		{name: "subject multivalue", mutate: func(_ *DirectoryNormalizationConfiguration, raw *DirectoryObservation) {
			raw.User.Attributes[0].Values = append(raw.User.Attributes[0].Values, []byte("other"))
		}},
		{name: "duplicate subject attribute", mutate: func(_ *DirectoryNormalizationConfiguration, raw *DirectoryObservation) {
			raw.User.Attributes = append(raw.User.Attributes, cloneDirectoryAttribute(raw.User.Attributes[0]))
		}},
		{name: "case-insensitive attribute collision", mutate: func(_ *DirectoryNormalizationConfiguration, raw *DirectoryObservation) {
			duplicate := cloneDirectoryAttribute(raw.User.Attributes[0])
			duplicate.Name = "STABLEID"
			raw.User.Attributes = append(raw.User.Attributes, duplicate)
		}},
		{name: "subject malformed utf8", mutate: func(_ *DirectoryNormalizationConfiguration, raw *DirectoryObservation) {
			raw.User.Attributes[0].Values[0] = []byte{0xff, 0xfe}
		}},
		{name: "subject oversized", mutate: func(_ *DirectoryNormalizationConfiguration, raw *DirectoryObservation) {
			raw.User.Attributes[0].Values[0] = bytes.Repeat([]byte("x"), 4*1024+1)
		}},
		{name: "profile multivalue", mutate: func(_ *DirectoryNormalizationConfiguration, raw *DirectoryObservation) {
			raw.User.Attributes[1].Values = append(raw.User.Attributes[1].Values, []byte("alias"))
		}},
		{name: "profile malformed utf8", mutate: func(_ *DirectoryNormalizationConfiguration, raw *DirectoryObservation) {
			raw.User.Attributes[2].Values[0] = []byte{0xff}
		}},
		{name: "profile oversized", mutate: func(_ *DirectoryNormalizationConfiguration, raw *DirectoryObservation) {
			raw.User.Attributes[2].Values[0] = bytes.Repeat([]byte("x"), 4*1024+1)
		}},
		{name: "attribute value hard limit", mutate: func(_ *DirectoryNormalizationConfiguration, raw *DirectoryObservation) {
			raw.User.Attributes[2].Values[0] = bytes.Repeat([]byte("x"), maximumDirectoryAttributeValueBytes+1)
		}},
		{name: "total response budget", mutate: func(_ *DirectoryNormalizationConfiguration, raw *DirectoryObservation) {
			shared := bytes.Repeat([]byte("x"), maximumDirectoryAttributeValueBytes)
			values := make([][]byte, maximumDirectoryResponseBytes/len(shared)+1)
			for index := range values {
				values[index] = shared
			}
			raw.Groups = []DirectoryEntry{{
				DistinguishedName: "cn=oversized,dc=example,dc=com",
				Attributes:        []DirectoryAttribute{{Name: "description", Values: values}},
			}}
		}},
		{name: "total value count", mutate: func(_ *DirectoryNormalizationConfiguration, raw *DirectoryObservation) {
			values := make([][]byte, maximumDirectoryValuesPerAttribute)
			raw.Groups = make([]DirectoryEntry, maximumDirectoryNormalizationValues/len(values)+1)
			for index := range raw.Groups {
				raw.Groups[index] = DirectoryEntry{
					DistinguishedName: "cn=values,dc=example,dc=com",
					Attributes:        []DirectoryAttribute{{Name: "description", Values: values}},
				}
			}
		}},
		{name: "invalid user dn", mutate: func(_ *DirectoryNormalizationConfiguration, raw *DirectoryObservation) {
			raw.User.DistinguishedName = "not a dn"
		}},
		{name: "invalid group dn", mutate: func(_ *DirectoryNormalizationConfiguration, raw *DirectoryObservation) {
			raw.Groups = []DirectoryEntry{{DistinguishedName: "not a dn"}}
		}},
		{name: "too many groups", mutate: func(_ *DirectoryNormalizationConfiguration, raw *DirectoryObservation) {
			raw.Groups = make([]DirectoryEntry, maximumDirectoryGroups+1)
		}},
		{name: "zero account configuration", mutate: func(configuration *DirectoryNormalizationConfiguration, _ *DirectoryObservation) {
			configuration.AccountState = DirectoryAccountStateMapping{}
		}},
		{name: "zero subject configuration", mutate: func(configuration *DirectoryNormalizationConfiguration, _ *DirectoryObservation) {
			configuration.Subject = DirectorySubjectMapping{}
		}},
		{name: "invalid login username", mutate: func(configuration *DirectoryNormalizationConfiguration, _ *DirectoryObservation) {
			configuration.LoginUsername = identity.LDAPUsername{}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateConfiguration := configuration
			candidate := cloneNormalizationObservation(valid)
			test.mutate(&candidateConfiguration, &candidate)
			observation, err := NormalizeDirectoryObservation(candidateConfiguration, candidate)
			if !errors.Is(err, ErrInvalidDirectoryNormalization) ||
				!zeroNormalizationObservation(observation) {
				t.Fatalf("NormalizeDirectoryObservation() = %s, %v", observation, err)
			}
		})
	}
}

func TestNormalizeDirectoryObservationRejectsSubjectAndAccountProviderFailures(t *testing.T) {
	t.Parallel()

	username := mustNormalizationUsername(t, "alice")
	tests := []struct {
		name        string
		subjectMode DirectorySubjectMode
		subject     []byte
		account     func(*testing.T, DirectoryAttributeName) DirectoryAccountStateMapping
		status      [][]byte
	}{
		{
			name: "AD objectGUID wrong length", subjectMode: DirectorySubjectADObjectGUID,
			subject: []byte("not-sixteen"), account: mustADAccountMapping, status: [][]byte{[]byte("512")},
		},
		{
			name: "AD all-zero objectGUID", subjectMode: DirectorySubjectADObjectGUID,
			subject: make([]byte, 16), account: mustADAccountMapping, status: [][]byte{[]byte("512")},
		},
		{
			name: "entryUUID malformed", subjectMode: DirectorySubjectEntryUUID,
			subject: []byte("550e8400-e29b-01d4-a716-446655440000"),
			account: mustADAccountMapping, status: [][]byte{[]byte("512")},
		},
		{
			name: "AD status missing", subjectMode: DirectorySubjectUTF8Exact,
			subject: []byte("subject"), account: mustADAccountMapping, status: nil,
		},
		{
			name: "AD status multivalue", subjectMode: DirectorySubjectUTF8Exact,
			subject: []byte("subject"), account: mustADAccountMapping,
			status: [][]byte{[]byte("512"), []byte("514")},
		},
		{
			name: "AD status noncanonical", subjectMode: DirectorySubjectUTF8Exact,
			subject: []byte("subject"), account: mustADAccountMapping, status: [][]byte{[]byte("0512")},
		},
		{
			name: "OpenLDAP status malformed UTF8", subjectMode: DirectorySubjectUTF8Exact,
			subject: []byte("subject"), account: func(t *testing.T, attribute DirectoryAttributeName) DirectoryAccountStateMapping {
				value, err := NewDirectoryOpenLDAPValueAccountState(
					attribute,
					[]byte("locked"),
					DirectoryValueExact,
				)
				if err != nil {
					t.Fatalf("NewDirectoryOpenLDAPValueAccountState() error = %v", err)
				}
				return value
			}, status: [][]byte{{0xff}},
		},
		{
			name: "POSIX expiry invalid", subjectMode: DirectorySubjectUTF8Exact,
			subject: []byte("subject"), account: func(t *testing.T, attribute DirectoryAttributeName) DirectoryAccountStateMapping {
				value, err := NewDirectoryPOSIXShadowExpireAccountState(attribute, 20_000)
				if err != nil {
					t.Fatalf("NewDirectoryPOSIXShadowExpireAccountState() error = %v", err)
				}
				return value
			}, status: [][]byte{[]byte("-2")},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			subjectAttribute := mustDirectoryAttributeName(t, "immutableValue")
			statusAttribute := mustDirectoryAttributeName(t, "accountStatusValue")
			configuration := DirectoryNormalizationConfiguration{
				LoginUsername: username,
				Subject:       mustDirectorySubjectMapping(t, test.subjectMode, subjectAttribute),
				AccountState:  test.account(t, statusAttribute),
			}
			attributes := []DirectoryAttribute{{Name: "immutableValue", Values: [][]byte{test.subject}}}
			if test.status != nil {
				attributes = append(attributes, DirectoryAttribute{Name: "accountStatusValue", Values: test.status})
			}
			raw := DirectoryObservation{User: DirectoryEntry{
				DistinguishedName: "uid=alice,dc=example,dc=com",
				Attributes:        attributes,
			}}
			if _, err := NormalizeDirectoryObservation(configuration, raw); !errors.Is(err, ErrInvalidDirectoryNormalization) {
				t.Fatalf("NormalizeDirectoryObservation() error = %v", err)
			}
		})
	}
}

func TestNormalizeDirectoryObservationRequiresCanonicalGIDNumber(t *testing.T) {
	t.Parallel()

	configuration, valid := validCustomNormalizationFixture(t)
	configuration.GIDNumberAttribute = mustDirectoryAttributeName(t, "gidNumber")
	for _, values := range [][][]byte{
		nil,
		{[]byte("01")},
		{[]byte("1"), []byte("2")},
		{{0xff}},
	} {
		candidate := cloneNormalizationObservation(valid)
		if values != nil {
			candidate.User.Attributes = append(candidate.User.Attributes, DirectoryAttribute{
				Name: "gidNumber", Values: values,
			})
		}
		if _, err := NormalizeDirectoryObservation(configuration, candidate); !errors.Is(err, ErrInvalidDirectoryNormalization) {
			t.Fatalf("values %v error = %v", values, err)
		}
	}
}

func TestNormalizeDirectoryObservationIsDeterministicAndOwnsValues(t *testing.T) {
	t.Parallel()

	configuration, firstRaw := validCustomNormalizationFixture(t)
	firstRaw.Groups = []DirectoryEntry{
		{DistinguishedName: "cn=Zulu,ou=groups,dc=example,dc=com"},
		{DistinguishedName: "cn=Alpha,ou=groups,dc=example,dc=com"},
	}
	secondRaw := cloneNormalizationObservation(firstRaw)
	slices.Reverse(secondRaw.User.Attributes)
	slices.Reverse(secondRaw.Groups)

	first, err := NormalizeDirectoryObservation(configuration, firstRaw)
	if err != nil {
		t.Fatalf("first NormalizeDirectoryObservation() error = %v", err)
	}
	second, err := NormalizeDirectoryObservation(configuration, secondRaw)
	if err != nil {
		t.Fatalf("second NormalizeDirectoryObservation() error = %v", err)
	}
	if first.String() != second.String() || observationSubjectAlias(t, first) != observationSubjectAlias(t, second) {
		t.Fatalf("normalization is nondeterministic: %s, %s", first, second)
	}
	for _, field := range []identity.LDAPProfileField{
		identity.LDAPProfileUsername,
		identity.LDAPProfileEmail,
	} {
		left, leftPresent, leftErr := first.RevealProfileField(field)
		right, rightPresent, rightErr := second.RevealProfileField(field)
		if leftErr != nil || rightErr != nil || leftPresent != rightPresent || left != right {
			t.Fatalf("field %d differs: %q/%t/%v, %q/%t/%v", field, left, leftPresent, leftErr, right, rightPresent, rightErr)
		}
	}

	for _, attribute := range firstRaw.User.Attributes {
		for _, value := range attribute.Values {
			clear(value)
		}
	}
	firstRaw.User.DistinguishedName = "mutated"
	firstRaw.Groups = nil
	assertProfileField(t, first, identity.LDAPProfileUsername, "alice")
	assertProfileField(t, first, identity.LDAPProfileEmail, "alice@example.com")
	if first.GroupCount() != 2 || observationSubjectAlias(t, first) != observationSubjectAlias(t, second) {
		t.Fatalf("normalized observation retained caller-owned values: %s", first)
	}
}

func TestDirectoryNormalizerFormattingAndErrorsAreRedacted(t *testing.T) {
	t.Parallel()

	attributeCanary := "privateStableAttribute"
	markerCanary := "private-disabled-marker"
	usernameCanary := "private-login-name"
	attribute := mustDirectoryAttributeName(t, attributeCanary)
	subject := mustDirectorySubjectMapping(t, DirectorySubjectUTF8Exact, attribute)
	accountAttribute := mustDirectoryAttributeName(t, "privateStatusAttribute")
	account, err := NewDirectoryOpenLDAPValueAccountState(
		accountAttribute,
		[]byte(markerCanary),
		DirectoryValueExact,
	)
	if err != nil {
		t.Fatalf("NewDirectoryOpenLDAPValueAccountState() error = %v", err)
	}
	configuration := DirectoryNormalizationConfiguration{
		LoginUsername: mustNormalizationUsername(t, usernameCanary),
		Profile: DirectoryProfileAttributeMapping{
			Email: mustDirectoryAttributeName(t, "privateMailAttribute"),
		},
		Subject:      subject,
		AccountState: account,
	}
	values := []any{
		attribute, &attribute,
		configuration.Profile, &configuration.Profile,
		subject, &subject,
		account, &account,
		configuration, &configuration,
	}
	canaries := []string{
		attributeCanary,
		strings.ToLower(attributeCanary),
		"privateStatusAttribute",
		"privatestatusattribute",
		"privateMailAttribute",
		"privatemailattribute",
		markerCanary,
		usernameCanary,
	}
	for _, value := range values {
		formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", value, value, value, value, value, value)
		lower := strings.ToLower(formatted)
		for _, canary := range canaries {
			if strings.Contains(formatted, canary) || strings.Contains(lower, strings.ToLower(canary)) ||
				strings.Contains(lower, fmt.Sprintf("%x", []byte(canary))) {
				t.Fatalf("format %T exposed %q: %s", value, canary, formatted)
			}
		}
	}

	raw := DirectoryObservation{User: DirectoryEntry{
		DistinguishedName: "uid=" + usernameCanary + ",dc=example,dc=com",
		Attributes: []DirectoryAttribute{
			{Name: attributeCanary, Values: [][]byte{[]byte("private-subject-value"), []byte("duplicate")}},
		},
	}}
	_, normalizationErr := NormalizeDirectoryObservation(configuration, raw)
	if !errors.Is(normalizationErr, ErrInvalidDirectoryNormalization) {
		t.Fatalf("NormalizeDirectoryObservation() error = %v", normalizationErr)
	}
	formattedError := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", normalizationErr, normalizationErr, normalizationErr, normalizationErr, normalizationErr, normalizationErr)
	for _, canary := range append(canaries, "private-subject-value", "duplicate") {
		if strings.Contains(strings.ToLower(formattedError), strings.ToLower(canary)) ||
			strings.Contains(strings.ToLower(formattedError), fmt.Sprintf("%x", []byte(canary))) {
			t.Fatalf("error exposed %q: %s", canary, formattedError)
		}
	}
}

func TestDirectoryNormalizerConstructorsRejectUnknownOrMalformedConfiguration(t *testing.T) {
	t.Parallel()

	validAttribute := mustDirectoryAttributeName(t, "validAttribute")
	if _, err := NewDirectoryAttributeName(" bad attribute "); !errors.Is(err, ErrInvalidDirectoryNormalization) {
		t.Fatalf("NewDirectoryAttributeName() error = %v", err)
	}
	if _, err := NewDirectorySubjectMapping(0, validAttribute); !errors.Is(err, ErrInvalidDirectoryNormalization) {
		t.Fatalf("NewDirectorySubjectMapping() error = %v", err)
	}
	if _, err := NewDirectoryADAccountState(DirectoryAttributeName{}); !errors.Is(err, ErrInvalidDirectoryNormalization) {
		t.Fatalf("NewDirectoryADAccountState() error = %v", err)
	}
	if _, err := NewDirectoryOpenLDAPValueAccountState(validAttribute, nil, DirectoryValueExact); !errors.Is(err, ErrInvalidDirectoryNormalization) {
		t.Fatalf("empty marker error = %v", err)
	}
	if _, err := NewDirectoryOpenLDAPValueAccountState(validAttribute, []byte{0xff}, DirectoryValueCaseFold); !errors.Is(err, ErrInvalidDirectoryNormalization) {
		t.Fatalf("invalid marker error = %v", err)
	}
	if _, err := NewDirectoryOpenLDAPValueAccountState(validAttribute, []byte("locked"), 99); !errors.Is(err, ErrInvalidDirectoryNormalization) {
		t.Fatalf("unknown comparison error = %v", err)
	}
	if _, err := (DirectoryNormalizationConfiguration{}).RequiredUserAttributes(); !errors.Is(err, ErrInvalidDirectoryNormalization) {
		t.Fatalf("zero configuration error = %v", err)
	}
}

func mustADNormalizationConfiguration(t *testing.T) DirectoryNormalizationConfiguration {
	t.Helper()
	objectGUID := mustDirectoryAttributeName(t, "objectGUID")
	accountAttribute := mustDirectoryAttributeName(t, "accountFlags")
	account, err := NewDirectoryADAccountState(accountAttribute)
	if err != nil {
		t.Fatalf("NewDirectoryADAccountState() error = %v", err)
	}
	return DirectoryNormalizationConfiguration{
		LoginUsername: mustNormalizationUsername(t, "alice"),
		Profile: DirectoryProfileAttributeMapping{
			FirstName:         mustDirectoryAttributeName(t, "givenName"),
			LastName:          mustDirectoryAttributeName(t, "sn"),
			DisplayName:       mustDirectoryAttributeName(t, "displayName"),
			Username:          mustDirectoryAttributeName(t, "sAMAccountName"),
			AlternateUsername: mustDirectoryAttributeName(t, "userPrincipalName"),
			Email:             mustDirectoryAttributeName(t, "mail"),
		},
		Subject:      mustDirectorySubjectMapping(t, DirectorySubjectADObjectGUID, objectGUID),
		AccountState: account,
	}
}

func validCustomNormalizationFixture(t *testing.T) (DirectoryNormalizationConfiguration, DirectoryObservation) {
	t.Helper()
	subjectAttribute := mustDirectoryAttributeName(t, "stableID")
	configuration := DirectoryNormalizationConfiguration{
		LoginUsername: mustNormalizationUsername(t, "alice"),
		Profile: DirectoryProfileAttributeMapping{
			Username: mustDirectoryAttributeName(t, "uid"),
			Email:    mustDirectoryAttributeName(t, "mail"),
		},
		Subject:      mustDirectorySubjectMapping(t, DirectorySubjectUTF8Exact, subjectAttribute),
		AccountState: DirectoryAlwaysActiveAccountState(),
	}
	raw := DirectoryObservation{User: DirectoryEntry{
		DistinguishedName: "uid=alice,ou=people,dc=example,dc=com",
		Attributes: []DirectoryAttribute{
			{Name: "stableID", Values: [][]byte{[]byte("immutable-subject")}},
			{Name: "uid", Values: [][]byte{[]byte("alice")}},
			{Name: "mail", Values: [][]byte{[]byte("alice@example.com")}},
		},
	}}
	return configuration, raw
}

func mustADAccountMapping(t *testing.T, attribute DirectoryAttributeName) DirectoryAccountStateMapping {
	t.Helper()
	value, err := NewDirectoryADAccountState(attribute)
	if err != nil {
		t.Fatalf("NewDirectoryADAccountState() error = %v", err)
	}
	return value
}

func mustDirectoryAttributeName(t *testing.T, value string) DirectoryAttributeName {
	t.Helper()
	attribute, err := NewDirectoryAttributeName(value)
	if err != nil {
		t.Fatalf("NewDirectoryAttributeName(%q) error = %v", value, err)
	}
	return attribute
}

func mustDirectorySubjectMapping(
	t *testing.T,
	mode DirectorySubjectMode,
	attribute DirectoryAttributeName,
) DirectorySubjectMapping {
	t.Helper()
	mapping, err := NewDirectorySubjectMapping(mode, attribute)
	if err != nil {
		t.Fatalf("NewDirectorySubjectMapping() error = %v", err)
	}
	return mapping
}

func mustNormalizationUsername(t *testing.T, value string) identity.LDAPUsername {
	t.Helper()
	username, err := identity.NewLDAPUsername(value)
	if err != nil {
		t.Fatalf("NewLDAPUsername() error = %v", err)
	}
	return username
}

func assertProfileField(
	t *testing.T,
	observation identity.LDAPObservation,
	field identity.LDAPProfileField,
	want string,
) {
	t.Helper()
	got, present, err := observation.RevealProfileField(field)
	if err != nil || !present || got != want {
		t.Fatalf("RevealProfileField(%d) = %q, %t, %v; want %q", field, got, present, err, want)
	}
}

func observationSubjectAlias(t *testing.T, observation identity.LDAPObservation) [32]byte {
	t.Helper()
	keyring := normalizationTestKeyring(t)
	context := normalizationExternalSubjectContext()
	envelope, aliases, err := observation.ProtectSubject(keyring, context)
	if err != nil || len(aliases) != 1 {
		t.Fatalf("ProtectSubject() = %s, %v", observation, err)
	}
	clear(envelope.Ciphertext)
	return aliases[0].Digest
}

func canonicalSubjectAlias(t *testing.T, subject identity.Subject) [32]byte {
	t.Helper()
	aliases, err := normalizationTestKeyring(t).SubjectAliases(
		normalizationExternalSubjectContext().Provider,
		subject,
	)
	if err != nil || len(aliases) != 1 {
		t.Fatalf("SubjectAliases() = %v", err)
	}
	return aliases[0].Digest
}

func normalizationTestKeyring(t *testing.T) identity.Keyring {
	t.Helper()
	keyring, err := identity.NewKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{0x81}, 32)})
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	return keyring
}

func normalizationExternalSubjectContext() identity.ExternalSubjectContext {
	return identity.ExternalSubjectContext{
		Provider: identity.ProviderContext{
			Scope:      identity.TenantProviderScope,
			TenantID:   normalizationEntityID(0x11),
			ProviderID: normalizationEntityID(0x22),
		},
		ExternalIdentityID: normalizationEntityID(0x33),
	}
}

func normalizationEntityID(seed byte) identity.EntityID {
	var value identity.EntityID
	value[0] = seed
	return value
}

func cloneNormalizationObservation(source DirectoryObservation) DirectoryObservation {
	return DirectoryObservation{
		User:   cloneNormalizationEntry(source.User),
		Groups: cloneNormalizationEntries(source.Groups),
	}
}

func cloneNormalizationEntries(source []DirectoryEntry) []DirectoryEntry {
	result := make([]DirectoryEntry, len(source))
	for index := range source {
		result[index] = cloneNormalizationEntry(source[index])
	}
	return result
}

func cloneNormalizationEntry(source DirectoryEntry) DirectoryEntry {
	result := DirectoryEntry{DistinguishedName: source.DistinguishedName}
	result.Attributes = make([]DirectoryAttribute, len(source.Attributes))
	for index := range source.Attributes {
		result.Attributes[index] = cloneDirectoryAttribute(source.Attributes[index])
	}
	return result
}

func cloneDirectoryAttribute(source DirectoryAttribute) DirectoryAttribute {
	result := DirectoryAttribute{Name: source.Name, Values: make([][]byte, len(source.Values))}
	for index := range source.Values {
		result.Values[index] = append([]byte(nil), source.Values[index]...)
	}
	return result
}

func zeroNormalizationObservation(observation identity.LDAPObservation) bool {
	if observation.SubjectFormat() != 0 || observation.AccountState() != 0 ||
		observation.GroupCount() != 0 || observation.Complete() {
		return false
	}
	for _, present := range observation.ProfilePresence() {
		if present {
			return false
		}
	}
	return true
}
