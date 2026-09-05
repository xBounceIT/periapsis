package ldapclient

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func validDirectoryInspectionConfiguration() DirectoryInspectionConfiguration {
	return DirectoryInspectionConfiguration{
		Network:      testConfiguration(),
		BindDN:       "cn=service,dc=example,dc=com",
		ReferralMode: DirectoryReferralModeDisabled,
		Limits: DirectoryLimits{
			PageSize: 100, MaxPages: 10, MaxEntries: 1_000, MaxResponseBytes: 1024 * 1024,
		},
	}
}

func mustDirectoryInspectionFilter(
	t *testing.T,
	kind DirectoryInspectionFilterKind,
	source string,
) CompiledDirectoryInspectionFilter {
	t.Helper()
	filter, err := CompileDirectoryInspectionFilter(kind, source)
	if err != nil {
		t.Fatalf("CompileDirectoryInspectionFilter() error = %v", err)
	}
	return filter
}

func validDirectorySearchUserRequest(t *testing.T) DirectorySearchUserRequest {
	t.Helper()
	username, err := identity.NewLDAPUsername("alice")
	if err != nil {
		t.Fatalf("NewLDAPUsername() error = %v", err)
	}
	return DirectorySearchUserRequest{
		Configuration:    validDirectoryInspectionConfiguration(),
		Username:         username,
		UserBaseDN:       "ou=people,dc=example,dc=com",
		UserSearchFilter: mustDirectoryInspectionFilter(t, DirectoryInspectionFilterUser, "(uid={username})"),
		Attributes:       []string{"uid", "cn", "mail"},
	}
}

func validDirectoryFilterTestRequest(t *testing.T) DirectoryFilterTestRequest {
	t.Helper()
	username, err := identity.NewLDAPUsername("alice")
	if err != nil {
		t.Fatalf("NewLDAPUsername() error = %v", err)
	}
	return DirectoryFilterTestRequest{
		Configuration:  validDirectoryInspectionConfiguration(),
		UserBaseDN:     "ou=people,dc=example,dc=com",
		Filter:         mustDirectoryInspectionFilter(t, DirectoryInspectionFilterUser, "(uid={username})"),
		Values:         identity.LDAPTemplateValues{Username: username},
		UserAttributes: []string{"uid", "cn", "mail"},
		MaxResults:     MaximumDirectoryInspectionResults,
	}
}

func TestCompileDirectoryInspectionFilterEnforcesClosedContext(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		kind   DirectoryInspectionFilterKind
		source string
	}{
		{name: "user", kind: DirectoryInspectionFilterUser, source: "(uid={username})"},
		{name: "reverse", kind: DirectoryInspectionFilterReverseGroup, source: "(|(member={userDn})(memberUid={username}))"},
		{name: "posix", kind: DirectoryInspectionFilterPOSIXGroup, source: "(|(memberUid={username})(gidNumber={gidNumber}))"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := CompileDirectoryInspectionFilter(test.kind, test.source); err != nil {
				t.Fatalf("CompileDirectoryInspectionFilter() error = %v", err)
			}
		})
	}

	for _, test := range []struct {
		name   string
		kind   DirectoryInspectionFilterKind
		source string
	}{
		{name: "unknown kind", kind: DirectoryInspectionFilterKind("private-kind"), source: "(uid={username})"},
		{name: "user relabeled reverse", kind: DirectoryInspectionFilterReverseGroup, source: "(uid={username})"},
		{name: "reverse relabeled posix", kind: DirectoryInspectionFilterPOSIXGroup, source: "(member={userDn})"},
		{name: "raw rendered user", kind: DirectoryInspectionFilterUser, source: "(uid=alice)"},
		{name: "duplicate placeholder", kind: DirectoryInspectionFilterUser, source: "(|(uid={username})(mail={username}))"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := CompileDirectoryInspectionFilter(test.kind, test.source); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("CompileDirectoryInspectionFilter() error = %v", err)
			}
		})
	}
}

func TestDirectoryInspectionFiltersRenderTypedADOpenLDAPPOSIXContexts(t *testing.T) {
	t.Parallel()

	username, err := identity.NewLDAPUsername(" *(alice)\\ ")
	if err != nil {
		t.Fatalf("NewLDAPUsername() error = %v", err)
	}
	userDN, err := identity.ParseLDAPDistinguishedName("cn=Smith\\, Alice,ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseLDAPDistinguishedName() error = %v", err)
	}
	gidNumber, err := identity.ParseLDAPGIDNumber("4294967295")
	if err != nil {
		t.Fatalf("ParseLDAPGIDNumber() error = %v", err)
	}
	for _, test := range []struct {
		name   string
		kind   DirectoryInspectionFilterKind
		source string
		values identity.LDAPTemplateValues
	}{
		{
			name: "OpenLDAP user", kind: DirectoryInspectionFilterUser,
			source: "(&(objectClass=inetOrgPerson)(uid={username}))",
			values: identity.LDAPTemplateValues{Username: username},
		},
		{
			name: "Active Directory reverse membership", kind: DirectoryInspectionFilterReverseGroup,
			source: "(&(objectClass=group)(member={userDn})(memberUid={username}))",
			values: identity.LDAPTemplateValues{Username: username, UserDN: userDN},
		},
		{
			name: "POSIX memberUid and gid", kind: DirectoryInspectionFilterPOSIXGroup,
			source: "(&(objectClass=posixGroup)(memberUid={username})(gidNumber={gidNumber}))",
			values: identity.LDAPTemplateValues{Username: username, GIDNumber: gidNumber},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			filter := mustDirectoryInspectionFilter(t, test.kind, test.source)
			rendered, err := filter.render(test.values)
			if err != nil {
				t.Fatalf("render() error = %v", err)
			}
			if _, err := ldap.CompileFilter(rendered); err != nil {
				t.Fatalf("rendered filter did not compile: %v", err)
			}
			if strings.Contains(rendered, " *(alice)\\ ") || strings.Contains(rendered, "Smith\\, Alice") {
				t.Fatalf("rendered filter contains an unescaped runtime value: %q", rendered)
			}
		})
	}
}

func TestDirectoryInspectionRejectsEveryUnboundedOrMismatchedSurfaceAndClearsSecret(t *testing.T) {
	t.Parallel()

	client := newValidationOnlyDirectoryClient(t)
	validSearch := validDirectorySearchUserRequest(t)
	validFilter := validDirectoryFilterTestRequest(t)
	reverseFilter := mustDirectoryInspectionFilter(
		t,
		DirectoryInspectionFilterReverseGroup,
		"(member={userDn})",
	)
	posixFilter := mustDirectoryInspectionFilter(
		t,
		DirectoryInspectionFilterPOSIXGroup,
		"(|(memberUid={username})(gidNumber={gidNumber}))",
	)

	searchTests := []struct {
		name   string
		mutate func(*DirectorySearchUserRequest)
	}{
		{name: "zero filter", mutate: func(value *DirectorySearchUserRequest) { value.UserSearchFilter = CompiledDirectoryInspectionFilter{} }},
		{name: "group filter", mutate: func(value *DirectorySearchUserRequest) { value.UserSearchFilter = reverseFilter }},
		{name: "zero username", mutate: func(value *DirectorySearchUserRequest) { value.Username = identity.LDAPUsername{} }},
		{name: "invalid base", mutate: func(value *DirectorySearchUserRequest) { value.UserBaseDN = "" }},
		{name: "entry budget cannot prove ambiguity", mutate: func(value *DirectorySearchUserRequest) { value.Configuration.Limits.MaxEntries = 1 }},
		{name: "latent referral", mutate: func(value *DirectorySearchUserRequest) {
			value.Configuration.Network.Endpoints[0].ReferralAllowed = true
		}},
		{name: "too many attributes", mutate: func(value *DirectorySearchUserRequest) {
			value.Attributes = make([]string, maximumDirectoryInspectionAttributes+1)
			for index := range value.Attributes {
				value.Attributes[index] = "attr" + strconv.Itoa(index)
			}
		}},
	}
	for _, test := range searchTests {
		t.Run("search user/"+test.name, func(t *testing.T) {
			request := validSearch
			request.Configuration.Network.Endpoints = append([]Endpoint(nil), validSearch.Configuration.Network.Endpoints...)
			test.mutate(&request)
			secret := []byte("private-service-secret")
			if _, err := client.SearchDirectoryUser(context.Background(), request, secret); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("SearchDirectoryUser() error = %v", err)
			}
			if !allZeroBytes(secret) {
				t.Fatal("SearchDirectoryUser() retained bind secret")
			}
		})
	}

	filterTests := []struct {
		name   string
		mutate func(*DirectoryFilterTestRequest)
	}{
		{name: "zero filter", mutate: func(value *DirectoryFilterTestRequest) { value.Filter = CompiledDirectoryInspectionFilter{} }},
		{name: "zero max results", mutate: func(value *DirectoryFilterTestRequest) { value.MaxResults = 0 }},
		{name: "above public max results", mutate: func(value *DirectoryFilterTestRequest) { value.MaxResults = MaximumDirectoryInspectionResults + 1 }},
		{name: "entry budget cannot prove truncation", mutate: func(value *DirectoryFilterTestRequest) { value.Configuration.Limits.MaxEntries = value.MaxResults }},
		{name: "reverse missing DN", mutate: func(value *DirectoryFilterTestRequest) {
			value.Filter = reverseFilter
			value.GroupBaseDN = "ou=groups,dc=example,dc=com"
			value.GroupAttributes = []string{"cn"}
			value.UserBaseDN = ""
			value.UserAttributes = nil
		}},
		{name: "POSIX missing gid", mutate: func(value *DirectoryFilterTestRequest) {
			value.Filter = posixFilter
			value.GroupBaseDN = "ou=groups,dc=example,dc=com"
			value.GroupAttributes = []string{"cn"}
			value.UserBaseDN = ""
			value.UserAttributes = nil
		}},
		{name: "mixed user and group context", mutate: func(value *DirectoryFilterTestRequest) {
			value.GroupBaseDN = "ou=groups,dc=example,dc=com"
		}},
		{name: "invalid base", mutate: func(value *DirectoryFilterTestRequest) { value.UserBaseDN = "dc=example,dc=com\n" }},
	}
	for _, test := range filterTests {
		t.Run("filter/"+test.name, func(t *testing.T) {
			request := validFilter
			request.Configuration.Network.Endpoints = append([]Endpoint(nil), validFilter.Configuration.Network.Endpoints...)
			test.mutate(&request)
			secret := []byte("private-service-secret")
			if _, err := client.TestDirectoryFilter(context.Background(), request, secret); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("TestDirectoryFilter() error = %v", err)
			}
			if !allZeroBytes(secret) {
				t.Fatal("TestDirectoryFilter() retained bind secret")
			}
		})
	}
}

func TestDirectoryInspectionCancellationAndBusyPathsClearSecretWithoutDialing(t *testing.T) {
	t.Parallel()

	var dials int
	client, err := New(testOptions(
		publicResolver("93.184.216.34"),
		dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			dials++
			return nil, errors.New("must not dial")
		}),
	))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := validDirectorySearchUserRequest(t)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	cancelledSecret := []byte("cancelled-secret")
	result, err := client.SearchDirectoryUser(cancelled, request, cancelledSecret)
	if err != nil || result.Category != DirectoryCategoryCancelled || !allZeroBytes(cancelledSecret) {
		t.Fatalf("cancelled result = %#v, error = %v, secret cleared = %t", result, err, allZeroBytes(cancelledSecret))
	}

	for index := 0; index < cap(client.slots); index++ {
		client.slots <- struct{}{}
	}
	busySecret := []byte("busy-secret")
	_, err = client.SearchDirectoryUser(context.Background(), request, busySecret)
	for index := 0; index < cap(client.slots); index++ {
		<-client.slots
	}
	if !errors.Is(err, ErrBusy) || !allZeroBytes(busySecret) {
		t.Fatalf("busy error = %v, secret cleared = %t", err, allZeroBytes(busySecret))
	}
	if dials != 0 {
		t.Fatalf("pre-network paths dialed %d times", dials)
	}
}

func TestDirectoryInspectionFailureSanitizerAlwaysClearsEntries(t *testing.T) {
	t.Parallel()

	sensitive := []DirectoryEntry{{
		DistinguishedName: "uid=private,dc=example,dc=com",
		Attributes: []DirectoryAttribute{{
			Name: "privateAttribute", Values: [][]byte{[]byte("private-value")},
		}},
	}}
	for _, category := range []DirectoryCategory{
		DirectoryCategoryDNSFailed,
		DirectoryCategoryDestinationBlocked,
		DirectoryCategoryConnectTimeout,
		DirectoryCategoryConnectFailed,
		DirectoryCategoryTLSFailed,
		DirectoryCategoryCertificateRejected,
		DirectoryCategoryServiceBindRejected,
		DirectoryCategoryLimitExceeded,
		DirectoryCategoryReferralRejected,
		DirectoryCategoryInvalidEntry,
		DirectoryCategoryProtocolFailed,
		DirectoryCategoryCancelled,
		DirectoryCategory("private-category"),
	} {
		result := sanitizeDirectoryInspectionResult(DirectoryInspectionResult{
			Category: category, EndpointPriority: 2, Truncated: true, Entries: sensitive,
		})
		if result.Truncated || len(result.Entries) != 0 {
			t.Fatalf("category %q retained inspection data: %#v", category, result)
		}
	}
}
