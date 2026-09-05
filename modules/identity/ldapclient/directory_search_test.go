package ldapclient

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type queuedDirectorySearch struct {
	result *ldap.SearchResult
	err    error
}

type queuedDirectoryConnection struct {
	searches []queuedDirectorySearch
	requests []*ldap.SearchRequest
	binds    int
	bindErr  error
	timeout  time.Duration
}

func (connection *queuedDirectoryConnection) Bind(string, string) error {
	connection.binds++
	return connection.bindErr
}

func (connection *queuedDirectoryConnection) Search(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	connection.requests = append(connection.requests, request)
	if len(connection.searches) == 0 {
		return nil, errors.New("unexpected search")
	}
	response := connection.searches[0]
	connection.searches = connection.searches[1:]
	return response.result, response.err
}

func (connection *queuedDirectoryConnection) SetTimeout(timeout time.Duration) {
	connection.timeout = timeout
}

func testDirectoryLimits() DirectoryLimits {
	return DirectoryLimits{
		PageSize:         2,
		MaxPages:         20,
		MaxEntries:       100,
		MaxResponseBytes: 64 * 1024,
	}
}

func testLDAPEntry(dn string, attributes map[string][][]byte) *ldap.Entry {
	entry := &ldap.Entry{DN: dn}
	for name, values := range attributes {
		attribute := &ldap.EntryAttribute{
			Name:       name,
			Values:     make([]string, len(values)),
			ByteValues: make([][]byte, len(values)),
		}
		for index, value := range values {
			attribute.Values[index] = string(value)
			attribute.ByteValues[index] = value
		}
		entry.Attributes = append(entry.Attributes, attribute)
	}
	return entry
}

func testPagingControl(cookie []byte) ldap.Control {
	control := ldap.NewControlPaging(2)
	control.SetCookie(append([]byte(nil), cookie...))
	return control
}

func testDirectorySearchState(t *testing.T, connection directoryLDAPConnection) *directorySearchState {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return &directorySearchState{
		ctx:        ctx,
		connection: connection,
		limits:     testDirectoryLimits(),
	}
}

func mustTestDN(t *testing.T, value string) *ldap.DN {
	t.Helper()
	dn, err := parseBoundedDN(value)
	if err != nil {
		t.Fatalf("parseBoundedDN() error = %v", err)
	}
	return dn
}

func TestDirectorySearchManuallyPagesAndOwnsReturnedValues(t *testing.T) {
	t.Parallel()

	firstValue := []byte("Alice")
	connection := &queuedDirectoryConnection{searches: []queuedDirectorySearch{
		{result: &ldap.SearchResult{
			Entries:  []*ldap.Entry{testLDAPEntry("uid=alice,ou=people,dc=example,dc=com", map[string][][]byte{"cn": {firstValue}})},
			Controls: []ldap.Control{testPagingControl([]byte("next-page"))},
		}},
		{result: &ldap.SearchResult{
			Entries:  []*ldap.Entry{testLDAPEntry("uid=bob,ou=people,dc=example,dc=com", map[string][][]byte{"cn": {[]byte("Bob")}})},
			Controls: []ldap.Control{testPagingControl(nil)},
		}},
	}}
	state := testDirectorySearchState(t, connection)
	entries, err := state.search(directorySearchSpec{
		baseDN:     mustTestDN(t, "ou=people,dc=example,dc=com"),
		scope:      ldap.ScopeWholeSubtree,
		filter:     "(objectClass=person)",
		attributes: []string{"cn"},
		maxResults: 10,
	})
	if err != nil || len(entries) != 2 {
		t.Fatalf("search() entries = %#v, error = %v", entries, err)
	}
	if len(connection.requests) != 2 {
		t.Fatalf("search request count = %d", len(connection.requests))
	}
	secondPaging, ok := connection.requests[1].Controls[0].(*ldap.ControlPaging)
	if !ok || !bytes.Equal(secondPaging.Cookie, []byte("next-page")) {
		t.Fatalf("second paging control = %#v", connection.requests[1].Controls)
	}
	firstValue[0] = 'X'
	if got := string(entries[0].Attributes[0].Values[0]); got != "Alice" {
		t.Fatalf("returned value aliases LDAP response memory: %q", got)
	}
}

func TestDirectorySearchPagingTerminationFailsClosed(t *testing.T) {
	t.Parallel()

	entry := testLDAPEntry("cn=one,ou=groups,dc=example,dc=com", nil)
	oversizedCookie := bytes.Repeat([]byte{'c'}, maximumDirectoryPagingCookieBytes+1)
	tests := []struct {
		name      string
		responses []queuedDirectorySearch
		mutate    func(*directorySearchState)
		want      error
	}{
		{
			name: "repeated cookie",
			responses: []queuedDirectorySearch{
				{result: &ldap.SearchResult{Entries: []*ldap.Entry{entry}, Controls: []ldap.Control{testPagingControl([]byte("same"))}}},
				{result: &ldap.SearchResult{Controls: []ldap.Control{testPagingControl([]byte("same"))}}},
			},
			want: errDirectoryProtocol,
		},
		{
			name:      "oversized cookie",
			responses: []queuedDirectorySearch{{result: &ldap.SearchResult{Controls: []ldap.Control{testPagingControl(oversizedCookie)}}}},
			want:      errDirectoryLimit,
		},
		{
			name: "paging disappears",
			responses: []queuedDirectorySearch{
				{result: &ldap.SearchResult{Entries: []*ldap.Entry{entry}, Controls: []ldap.Control{testPagingControl([]byte("next"))}}},
				{result: &ldap.SearchResult{}},
			},
			want: errDirectoryProtocol,
		},
		{
			name: "unexpected response control",
			responses: []queuedDirectorySearch{{result: &ldap.SearchResult{Controls: []ldap.Control{
				ldap.NewControlString("1.2.3.4.5", false, ""),
			}}}},
			want: errDirectoryProtocol,
		},
		{
			name:      "referral",
			responses: []queuedDirectorySearch{{result: &ldap.SearchResult{Referrals: []string{"ldaps://attacker.invalid"}}}},
			want:      errDirectoryReferral,
		},
		{
			name:      "page ceiling",
			responses: []queuedDirectorySearch{{result: &ldap.SearchResult{Controls: []ldap.Control{testPagingControl([]byte("next"))}}}},
			mutate:    func(state *directorySearchState) { state.limits.MaxPages = 1 },
			want:      errDirectoryLimit,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			connection := &queuedDirectoryConnection{searches: test.responses}
			state := testDirectorySearchState(t, connection)
			if test.mutate != nil {
				test.mutate(state)
			}
			_, err := state.search(directorySearchSpec{
				baseDN:     mustTestDN(t, "ou=groups,dc=example,dc=com"),
				scope:      ldap.ScopeWholeSubtree,
				filter:     "(objectClass=groupOfNames)",
				maxResults: 10,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("search() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestDirectorySearchEnforcesEntryAttributeValueAndByteLimits(t *testing.T) {
	t.Parallel()

	tooManyAttributes := make(map[string][][]byte, maximumDirectoryAttributes+1)
	tooManyAttributeNames := make([]string, 0, maximumDirectoryAttributes+1)
	for index := 0; index <= maximumDirectoryAttributes; index++ {
		name := "attr" + strconv.Itoa(index)
		tooManyAttributes[name] = [][]byte{[]byte("x")}
		tooManyAttributeNames = append(tooManyAttributeNames, name)
	}
	tooManyValues := make([][]byte, maximumDirectoryValuesPerAttribute+1)
	for index := range tooManyValues {
		tooManyValues[index] = []byte("x")
	}
	tests := []struct {
		name       string
		entry      *ldap.Entry
		attributes []string
		mutate     func(*directorySearchState)
		want       error
	}{
		{
			name:       "unexpected attribute",
			entry:      testLDAPEntry("uid=alice,ou=people,dc=example,dc=com", map[string][][]byte{"mail": {[]byte("a@example.com")}}),
			attributes: []string{"cn"},
			want:       errDirectoryInvalidEntry,
		},
		{
			name:       "entry outside base",
			entry:      testLDAPEntry("uid=alice,ou=other,dc=example,dc=com", nil),
			attributes: nil,
			want:       errDirectoryInvalidEntry,
		},
		{
			name:       "too many attributes",
			entry:      testLDAPEntry("uid=alice,ou=people,dc=example,dc=com", tooManyAttributes),
			attributes: tooManyAttributeNames,
			want:       errDirectoryInvalidEntry,
		},
		{
			name:       "too many values",
			entry:      testLDAPEntry("uid=alice,ou=people,dc=example,dc=com", map[string][][]byte{"memberOf": tooManyValues}),
			attributes: []string{"memberof"},
			want:       errDirectoryInvalidEntry,
		},
		{
			name:       "oversized value",
			entry:      testLDAPEntry("uid=alice,ou=people,dc=example,dc=com", map[string][][]byte{"jpegPhoto": {bytes.Repeat([]byte{'x'}, maximumDirectoryAttributeValueBytes+1)}}),
			attributes: []string{"jpegphoto"},
			want:       errDirectoryLimit,
		},
		{
			name:       "response byte budget",
			entry:      testLDAPEntry("uid=alice,ou=people,dc=example,dc=com", map[string][][]byte{"cn": {bytes.Repeat([]byte{'x'}, 1_024)}}),
			attributes: []string{"cn"},
			mutate:     func(state *directorySearchState) { state.limits.MaxResponseBytes = 1_024 },
			want:       errDirectoryLimit,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			connection := &queuedDirectoryConnection{searches: []queuedDirectorySearch{{result: &ldap.SearchResult{
				Entries: []*ldap.Entry{test.entry},
			}}}}
			state := testDirectorySearchState(t, connection)
			if test.mutate != nil {
				test.mutate(state)
			}
			_, err := state.search(directorySearchSpec{
				baseDN:     mustTestDN(t, "ou=people,dc=example,dc=com"),
				scope:      ldap.ScopeWholeSubtree,
				filter:     "(objectClass=person)",
				attributes: test.attributes,
				maxResults: 10,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("search() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestDirectoryGroupResolutionSupportsDirectReverseAndPOSIX(t *testing.T) {
	t.Parallel()

	username, _ := identity.NewLDAPUsername("alice")
	userDN := mustTestDN(t, "uid=alice,ou=people,dc=example,dc=com")
	user := DirectoryEntry{
		DistinguishedName: userDN.String(),
		Attributes: []DirectoryAttribute{
			{Name: "gidnumber", Values: [][]byte{[]byte("42")}},
			{Name: "memberof", Values: [][]byte{
				[]byte("cn=direct,ou=groups,dc=example,dc=com"),
			}},
		},
	}

	t.Run("direct attribute", func(t *testing.T) {
		t.Parallel()
		state := testDirectorySearchState(t, &queuedDirectoryConnection{})
		groups, err := state.resolveGroups(validatedDirectoryRequest{
			username: username,
			groups: validatedDirectoryGroups{
				mode: DirectoryGroupModeDisabled, directMembershipAttribute: "memberof", maxGroups: 10,
			},
		}, userDN, user)
		if err != nil || len(groups) != 1 || groups[0].DistinguishedName != "cn=direct,ou=groups,dc=example,dc=com" {
			t.Fatalf("direct groups = %#v, error = %v", groups, err)
		}
	})

	t.Run("direct attribute outside configured group base", func(t *testing.T) {
		t.Parallel()
		state := testDirectorySearchState(t, &queuedDirectoryConnection{})
		_, err := state.resolveGroups(validatedDirectoryRequest{
			username: username,
			groups: validatedDirectoryGroups{
				mode: DirectoryGroupModeDisabled, baseDN: mustTestDN(t, "ou=other-groups,dc=example,dc=com"),
				directMembershipAttribute: "memberof", maxGroups: 10,
			},
		}, userDN, user)
		if !errors.Is(err, errDirectoryInvalidEntry) {
			t.Fatalf("resolveGroups() error = %v, want invalid out-of-base group", err)
		}
	})

	t.Run("reverse nested breadth first", func(t *testing.T) {
		t.Parallel()
		filter, _ := identity.CompileLDAPTemplate(
			identity.LDAPTemplateContextReverseGroupSearchFilter,
			"(member={userDn})",
		)
		connection := &queuedDirectoryConnection{searches: []queuedDirectorySearch{
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{testLDAPEntry(
				"cn=direct,ou=groups,dc=example,dc=com", map[string][][]byte{"cn": {[]byte("direct")}},
			)}}},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{testLDAPEntry(
				"cn=parent,ou=groups,dc=example,dc=com", map[string][][]byte{"cn": {[]byte("parent")}},
			)}}},
			// Boundary probe proves there is no third level.
			{result: &ldap.SearchResult{}},
		}}
		state := testDirectorySearchState(t, connection)
		groups, err := state.resolveGroups(validatedDirectoryRequest{
			username: username,
			groups: validatedDirectoryGroups{
				mode: DirectoryGroupModeReverseSearch, baseDN: mustTestDN(t, "ou=groups,dc=example,dc=com"),
				searchFilter: &filter, directMembershipAttribute: "memberof", attributes: []string{"cn"},
				maxDepth: 2, maxGroups: 10,
			},
		}, userDN, user)
		if err != nil || len(groups) != 2 || len(connection.requests) != 3 {
			t.Fatalf("reverse groups = %#v, requests = %d, error = %v", groups, len(connection.requests), err)
		}
		if !strings.Contains(connection.requests[1].Filter, "cn=direct") {
			t.Fatalf("nested filter = %q", connection.requests[1].Filter)
		}
	})

	t.Run("POSIX memberUid and gid fallback", func(t *testing.T) {
		t.Parallel()
		filter, _ := identity.CompileLDAPTemplate(
			identity.LDAPTemplateContextPOSIXGroupSearchFilter,
			"(|(memberUid={username})(gidNumber={gidNumber}))",
		)
		connection := &queuedDirectoryConnection{searches: []queuedDirectorySearch{{result: &ldap.SearchResult{
			Entries: []*ldap.Entry{testLDAPEntry(
				"cn=primary,ou=groups,dc=example,dc=com", map[string][][]byte{"cn": {[]byte("primary")}},
			)},
		}}}}
		state := testDirectorySearchState(t, connection)
		groups, err := state.resolveGroups(validatedDirectoryRequest{
			username: username,
			groups: validatedDirectoryGroups{
				mode: DirectoryGroupModePOSIXMemberUID, baseDN: mustTestDN(t, "ou=groups,dc=example,dc=com"),
				searchFilter: &filter, directMembershipAttribute: "memberof",
				posixGIDNumberAttribute: "gidnumber", attributes: []string{"cn"},
				maxDepth: 1, maxGroups: 10,
			},
		}, userDN, user)
		if err != nil || len(groups) != 2 {
			t.Fatalf("POSIX groups = %#v, error = %v", groups, err)
		}
		if got := connection.requests[0].Filter; got != "(|(memberUid=alice)(gidNumber=42))" {
			t.Fatalf("POSIX filter = %q", got)
		}
	})
}

func TestReverseGroupDepthAndGroupCountTruncationFailClosed(t *testing.T) {
	t.Parallel()

	username, _ := identity.NewLDAPUsername("alice")
	filter, _ := identity.CompileLDAPTemplate(
		identity.LDAPTemplateContextReverseGroupSearchFilter,
		"(member={userDn})",
	)
	userDN := mustTestDN(t, "uid=alice,ou=people,dc=example,dc=com")
	connection := &queuedDirectoryConnection{searches: []queuedDirectorySearch{
		{result: &ldap.SearchResult{Entries: []*ldap.Entry{testLDAPEntry("cn=level1,ou=groups,dc=example,dc=com", nil)}}},
		// The boundary probe discovers a previously unseen second level.
		{result: &ldap.SearchResult{Entries: []*ldap.Entry{testLDAPEntry("cn=level2,ou=groups,dc=example,dc=com", nil)}}},
	}}
	state := testDirectorySearchState(t, connection)
	_, err := state.resolveGroups(validatedDirectoryRequest{
		username: username,
		groups: validatedDirectoryGroups{
			mode: DirectoryGroupModeActiveDirectory, baseDN: mustTestDN(t, "ou=groups,dc=example,dc=com"),
			searchFilter: &filter, maxDepth: 1, maxGroups: 10,
		},
	}, userDN, DirectoryEntry{DistinguishedName: userDN.String()})
	if !errors.Is(err, errDirectoryLimit) {
		t.Fatalf("resolveGroups() error = %v, want depth limit", err)
	}
}
