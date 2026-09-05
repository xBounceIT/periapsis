package identityprovider

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
)

func TestDirectoryObservationRequestDoesNotInferTemplateDefaults(t *testing.T) {
	t.Parallel()

	for _, template := range []ProviderTemplate{
		ProviderTemplateActiveDirectory,
		ProviderTemplateOpenLDAP,
		ProviderTemplatePOSIX,
		ProviderTemplateCustom,
	} {
		t.Run(string(template), func(t *testing.T) {
			t.Parallel()
			configuration := testConfiguration()
			configuration.Template = template
			configuration.AlternateUsernameAttribute = stringPointer("loginAlias")
			configuration.EmailAttribute = stringPointer("mail")
			request, err := directoryObservationRequest(configuration, testEndpoints(), "alice")
			if err != nil {
				t.Fatalf("directoryObservationRequest() error = %v", err)
			}
			defer clearDirectoryObservationRequest(&request)
			wantAttributes := []string{
				"displayname", "entryuuid", "givenname", "loginalias", "mail", "sn", "uid",
			}
			if !slices.Equal(request.UserAttributes, wantAttributes) ||
				request.Groups.Mode != ldapclient.DirectoryGroupModeDisabled ||
				request.Groups.SearchFilter != nil || request.Groups.BaseDN != "" ||
				request.Groups.DirectMembershipAttribute != "" || len(request.Groups.Attributes) != 0 ||
				request.UserDNTemplate != nil {
				t.Fatalf("template %q inferred request defaults: %#v", template, request)
			}
			requirements, err := request.UserSearchFilter.Requirements()
			if err != nil || requirements != (identity.LDAPTemplateRequirements{Username: true}) {
				t.Fatalf("user filter requirements = %#v, %v", requirements, err)
			}
		})
	}
}

func TestDirectoryObservationRequestUsesTypedUsernameAndExactRequiredAttributes(t *testing.T) {
	t.Parallel()

	configuration := testConfiguration()
	configuration.UserDNTemplate = stringPointer("uid={username},ou=users,dc=example,dc=com")
	configuration.AlternateUsernameAttribute = stringPointer("loginAlias")
	configuration.EmailAttribute = stringPointer("mail")
	configuration.GroupMembershipAttribute = stringPointer("memberOf")
	configuration.AccountStatusMode = AccountStatusModeActiveDirectoryUAC
	configuration.AccountStatusAttribute = stringPointer("userAccountControl")
	request, err := directoryObservationRequest(configuration, testEndpoints(), ` *(alice)\ `)
	if err != nil {
		t.Fatalf("directoryObservationRequest() error = %v", err)
	}
	defer clearDirectoryObservationRequest(&request)

	wantAttributes := []string{
		"displayname", "entryuuid", "givenname", "loginalias", "mail", "memberof",
		"sn", "uid", "useraccountcontrol",
	}
	if !slices.Equal(request.UserAttributes, wantAttributes) {
		t.Fatalf("required user attributes = %v, want %v", request.UserAttributes, wantAttributes)
	}
	renderedFilter, err := request.UserSearchFilter.Render(identity.LDAPTemplateValues{Username: request.Username})
	if err != nil || renderedFilter != `(uid= \2a\28alice\29\5c )` {
		t.Fatalf("typed user filter = %q, %v", renderedFilter, err)
	}
	if request.UserDNTemplate == nil {
		t.Fatal("typed user DN template was omitted")
	}
	renderedDN, err := request.UserDNTemplate.Render(identity.LDAPTemplateValues{Username: request.Username})
	if err != nil || renderedDN != `uid=\ *(alice)\\\ ,ou=users,dc=example,dc=com` {
		t.Fatalf("typed user DN = %q, %v", renderedDN, err)
	}
}

func TestDirectoryObservationRequestMapsEveryNestedGroupModeExactly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		mode                NestedGroupMode
		filter              *string
		memberUIDAttribute  *string
		gidAttribute        *string
		wantMode            ldapclient.DirectoryGroupMode
		wantRequirements    identity.LDAPTemplateRequirements
		wantUserAttributes  []string
		wantGroupAttributes []string
	}{
		{
			name:               "disabled direct membership only",
			mode:               NestedGroupModeDisabled,
			wantMode:           ldapclient.DirectoryGroupModeDisabled,
			wantUserAttributes: observationAttributes("memberof"),
		},
		{
			name:                "active directory",
			mode:                NestedGroupModeActiveDirectory,
			filter:              stringPointer("(&(objectClass=group)(member={userDn})(ownerName={username}))"),
			wantMode:            ldapclient.DirectoryGroupModeActiveDirectory,
			wantRequirements:    identity.LDAPTemplateRequirements{Username: true, UserDN: true},
			wantUserAttributes:  observationAttributes("memberof"),
			wantGroupAttributes: []string{"cn"},
		},
		{
			name:                "generic reverse",
			mode:                NestedGroupModeReverseSearch,
			filter:              stringPointer("(&(objectClass=groupOfNames)(member={userDn}))"),
			wantMode:            ldapclient.DirectoryGroupModeReverseSearch,
			wantRequirements:    identity.LDAPTemplateRequirements{UserDN: true},
			wantUserAttributes:  observationAttributes("memberof"),
			wantGroupAttributes: []string{"cn"},
		},
		{
			name:                "POSIX username",
			mode:                NestedGroupModePOSIXMemberUID,
			filter:              stringPointer("(&(objectClass=posixGroup)(memberUid={username}))"),
			memberUIDAttribute:  stringPointer("memberUid"),
			wantMode:            ldapclient.DirectoryGroupModePOSIXMemberUID,
			wantRequirements:    identity.LDAPTemplateRequirements{Username: true},
			wantUserAttributes:  observationAttributes("memberof"),
			wantGroupAttributes: []string{"cn", "memberuid"},
		},
		{
			name:                "POSIX username and primary gid",
			mode:                NestedGroupModePOSIXMemberUID,
			filter:              stringPointer("(|(memberUid={username})(gidNumber={gidNumber}))"),
			memberUIDAttribute:  stringPointer("memberUid"),
			gidAttribute:        stringPointer("gidNumber"),
			wantMode:            ldapclient.DirectoryGroupModePOSIXMemberUID,
			wantRequirements:    identity.LDAPTemplateRequirements{Username: true, GIDNumber: true},
			wantUserAttributes:  observationAttributes("gidnumber", "memberof"),
			wantGroupAttributes: []string{"cn", "memberuid"},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			configuration := testConfiguration()
			configuration.NestedGroupMode = testCase.mode
			configuration.GroupMembershipAttribute = stringPointer("memberOf")
			configuration.MaxNestedGroupDepth = 0
			configuration.GroupSearchFilter = testCase.filter
			configuration.POSIXMemberUIDAttribute = testCase.memberUIDAttribute
			configuration.POSIXGIDNumberAttribute = testCase.gidAttribute
			if testCase.mode != NestedGroupModeDisabled {
				configuration.GroupBaseDN = stringPointer("ou=groups,dc=example,dc=com")
				configuration.MaxNestedGroupDepth = 3
			}
			configuration.MaxGroups = 77

			request, err := directoryObservationRequest(configuration, testEndpoints(), "alice")
			if err != nil {
				t.Fatalf("directoryObservationRequest() error = %v", err)
			}
			defer clearDirectoryObservationRequest(&request)
			if request.Groups.Mode != testCase.wantMode || request.Groups.MaxDepth != configuration.MaxNestedGroupDepth ||
				request.Groups.MaxGroups != 77 || request.Groups.DirectMembershipAttribute != "memberof" ||
				!slices.Equal(request.UserAttributes, testCase.wantUserAttributes) ||
				!slices.Equal(request.Groups.Attributes, testCase.wantGroupAttributes) {
				t.Fatalf("group mapping = %#v; user attrs = %v", request.Groups, request.UserAttributes)
			}
			if testCase.mode == NestedGroupModeDisabled {
				if request.Groups.SearchFilter != nil || request.Groups.BaseDN != "" {
					t.Fatalf("disabled mode inferred nested search: %#v", request.Groups)
				}
				return
			}
			if request.Groups.BaseDN != "ou=groups,dc=example,dc=com" || request.Groups.SearchFilter == nil {
				t.Fatalf("nested group search shape = %#v", request.Groups)
			}
			requirements, err := request.Groups.SearchFilter.Requirements()
			if err != nil || requirements != testCase.wantRequirements {
				t.Fatalf("group requirements = %#v, %v", requirements, err)
			}
			wantGIDAttribute := ""
			if testCase.gidAttribute != nil {
				wantGIDAttribute = "gidnumber"
			}
			if request.Groups.POSIXGIDNumberAttribute != wantGIDAttribute {
				t.Fatalf("gidNumber attribute = %q", request.Groups.POSIXGIDNumberAttribute)
			}
		})
	}
}

func TestDirectoryObservationRequestMapsUserDNReferralLimitsAndEveryEndpointFlag(t *testing.T) {
	t.Parallel()

	configuration := testConfiguration()
	configuration.UserDNTemplate = stringPointer("uid={username},ou=users,dc=example,dc=com")
	configuration.GroupBaseDN = stringPointer("ou=groups,dc=example,dc=com")
	configuration.GroupMembershipAttribute = stringPointer("memberOf")
	configuration.ReferralMode = ReferralModeConfiguredEndpoints
	configuration.MaxReferralHops = 3
	caSource := "owned-custom-ca-canary"
	configuration.CustomCAPEM = &caSource
	endpoints := []Endpoint{
		{
			Priority: 2, Enabled: false, Host: "disabled.example.com", Port: 636,
			Transport: ldapclient.TransportLDAPS, TLSServerName: "disabled.example.com",
		},
		{
			Priority: 1, Enabled: true, ReferralAllowed: true,
			Host: "primary.example.com", Port: 636,
			Transport: ldapclient.TransportLDAPS, TLSServerName: "primary.example.com",
		},
	}
	request, err := directoryObservationRequest(configuration, endpoints, "alice")
	if err != nil {
		t.Fatalf("directoryObservationRequest() error = %v", err)
	}
	if request.ReferralMode != ldapclient.DirectoryReferralModeConfiguredEndpoints ||
		request.ReferralMaxHops != 3 || len(request.Configuration.Endpoints) != 2 ||
		request.Configuration.Endpoints[0].Priority != 1 ||
		!request.Configuration.Endpoints[0].Enabled ||
		!request.Configuration.Endpoints[0].ReferralAllowed ||
		request.Configuration.Endpoints[1].Priority != 2 ||
		request.Configuration.Endpoints[1].Enabled ||
		request.Configuration.Endpoints[1].ReferralAllowed {
		t.Fatalf("referral/endpoint mapping = %#v", request)
	}
	if request.Configuration.ConnectTimeout != time.Second ||
		request.Configuration.OperationTimeout != 5*time.Second ||
		request.Limits != (ldapclient.DirectoryLimits{
			PageSize: 100, MaxPages: 10, MaxEntries: 1_000, MaxResponseBytes: 1_048_576,
		}) {
		t.Fatalf("timeout/limit mapping = %#v, %#v", request.Configuration, request.Limits)
	}
	if request.Groups.Mode != ldapclient.DirectoryGroupModeDisabled ||
		request.Groups.BaseDN != "ou=groups,dc=example,dc=com" ||
		request.Groups.DirectMembershipAttribute != "memberof" ||
		request.Groups.SearchFilter != nil || len(request.Groups.Attributes) != 0 {
		t.Fatalf("direct-membership-only mapping = %#v", request.Groups)
	}
	if request.UserDNTemplate == nil {
		t.Fatal("configured user DN template was omitted")
	}
	requirements, err := request.UserDNTemplate.Requirements()
	if err != nil || requirements != (identity.LDAPTemplateRequirements{Username: true}) {
		t.Fatalf("user DN requirements = %#v, %v", requirements, err)
	}
	if string(request.Configuration.CustomCAPEM) != "owned-custom-ca-canary" {
		t.Fatalf("custom CA was not copied exactly")
	}
	ownedCA := request.Configuration.CustomCAPEM
	caSource = "caller-mutated"
	endpoints[0].Host = "caller-mutated.example.com"
	if string(request.Configuration.CustomCAPEM) != "owned-custom-ca-canary" ||
		request.Configuration.Endpoints[1].Host != "disabled.example.com" {
		t.Fatal("mapped request aliases caller-owned input")
	}
	clearDirectoryObservationRequest(&request)
	if request.Configuration.CustomCAPEM != nil || !allBytesCleared(ownedCA) {
		t.Fatal("owned custom CA was not cleared")
	}
	clearDirectoryObservationRequest(&request)
	clearDirectoryObservationRequest(nil)
}

func TestDirectoryObservationRequestRejectsModePlaceholderAndConfigurationMismatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mutate    func(*Configuration, *[]Endpoint, *string)
		secretTag string
	}{
		{
			name: "invalid username",
			mutate: func(_ *Configuration, _ *[]Endpoint, username *string) {
				*username = "invalid-user-secret\n"
			},
			secretTag: "invalid-user-secret",
		},
		{
			name: "user filter missing typed username",
			mutate: func(configuration *Configuration, _ *[]Endpoint, _ *string) {
				configuration.UserSearchFilter = "(objectClass=user-filter-secret)"
			},
			secretTag: "user-filter-secret",
		},
		{
			name: "user DN wrong placeholder context",
			mutate: func(configuration *Configuration, _ *[]Endpoint, _ *string) {
				configuration.UserDNTemplate = stringPointer("uid={userDn},dc=user-dn-secret")
			},
			secretTag: "user-dn-secret",
		},
		{
			name: "nested group missing base DN",
			mutate: func(configuration *Configuration, _ *[]Endpoint, _ *string) {
				configuration.NestedGroupMode = NestedGroupModeReverseSearch
				configuration.MaxNestedGroupDepth = 1
				configuration.GroupSearchFilter = stringPointer("(member={userDn})")
			},
		},
		{
			name: "reverse filter uses POSIX context",
			mutate: func(configuration *Configuration, _ *[]Endpoint, _ *string) {
				configuration.NestedGroupMode = NestedGroupModeReverseSearch
				configuration.MaxNestedGroupDepth = 1
				configuration.GroupBaseDN = stringPointer("ou=groups,dc=example,dc=com")
				configuration.GroupSearchFilter = stringPointer("(memberUid={username})")
			},
		},
		{
			name: "POSIX gid placeholder missing attribute",
			mutate: func(configuration *Configuration, _ *[]Endpoint, _ *string) {
				configurePOSIXObservation(configuration, "(|(memberUid={username})(gidNumber={gidNumber}))")
			},
		},
		{
			name: "POSIX gid attribute without placeholder",
			mutate: func(configuration *Configuration, _ *[]Endpoint, _ *string) {
				configurePOSIXObservation(configuration, "(memberUid={username})")
				configuration.POSIXGIDNumberAttribute = stringPointer("gidNumber")
			},
		},
		{
			name: "disabled mode retains POSIX field",
			mutate: func(configuration *Configuration, _ *[]Endpoint, _ *string) {
				configuration.POSIXMemberUIDAttribute = stringPointer("memberUid")
			},
		},
		{
			name: "reverse mode retains POSIX field",
			mutate: func(configuration *Configuration, _ *[]Endpoint, _ *string) {
				configuration.NestedGroupMode = NestedGroupModeActiveDirectory
				configuration.MaxNestedGroupDepth = 1
				configuration.GroupBaseDN = stringPointer("ou=groups,dc=example,dc=com")
				configuration.GroupSearchFilter = stringPointer("(member={userDn})")
				configuration.POSIXMemberUIDAttribute = stringPointer("memberUid")
			},
		},
		{
			name: "all endpoints disabled",
			mutate: func(_ *Configuration, endpoints *[]Endpoint, _ *string) {
				(*endpoints)[0].Enabled = false
			},
		},
		{
			name: "configured referrals without allowed endpoint",
			mutate: func(configuration *Configuration, _ *[]Endpoint, _ *string) {
				configuration.ReferralMode = ReferralModeConfiguredEndpoints
				configuration.MaxReferralHops = 1
			},
		},
		{
			name: "disabled referrals with latent allowed endpoint",
			mutate: func(_ *Configuration, endpoints *[]Endpoint, _ *string) {
				(*endpoints)[0].ReferralAllowed = true
			},
		},
		{
			name: "disabled endpoint cannot be referral allowed",
			mutate: func(_ *Configuration, endpoints *[]Endpoint, _ *string) {
				*endpoints = append(*endpoints, Endpoint{
					Priority: 2, Host: "disabled.example.com", Port: 636,
					Transport: ldapclient.TransportLDAPS, TLSServerName: "disabled.example.com",
					Enabled: false, ReferralAllowed: true,
				})
			},
		},
		{
			name: "unknown referral mode",
			mutate: func(configuration *Configuration, _ *[]Endpoint, _ *string) {
				configuration.ReferralMode = "future-referral-secret"
			},
			secretTag: "future-referral-secret",
		},
		{
			name: "invalid bounded limit",
			mutate: func(configuration *Configuration, _ *[]Endpoint, _ *string) {
				configuration.MaxPages = 0
			},
		},
		{
			name: "unknown nested mode",
			mutate: func(configuration *Configuration, _ *[]Endpoint, _ *string) {
				configuration.NestedGroupMode = "future-group-secret"
			},
			secretTag: "future-group-secret",
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			configuration := testConfiguration()
			endpoints := testEndpoints()
			username := "alice"
			testCase.mutate(&configuration, &endpoints, &username)
			request, err := directoryObservationRequest(configuration, endpoints, username)
			if !errors.Is(err, ErrInvalidInput) {
				clearDirectoryObservationRequest(&request)
				t.Fatalf("directoryObservationRequest() error = %v", err)
			}
			if testCase.secretTag != "" && strings.Contains(err.Error(), testCase.secretTag) {
				t.Fatalf("mapping error leaked hostile configuration: %v", err)
			}
			if request.Configuration.CustomCAPEM != nil || len(request.UserAttributes) != 0 ||
				request.Groups.SearchFilter != nil {
				t.Fatalf("failure returned partial request: %#v", request)
			}
		})
	}
}

func baseObservationAttributes() []string {
	return []string{"displayname", "entryuuid", "givenname", "sn", "uid"}
}

func observationAttributes(attributes ...string) []string {
	result := append(baseObservationAttributes(), attributes...)
	slices.Sort(result)
	return result
}

func configurePOSIXObservation(configuration *Configuration, filter string) {
	configuration.NestedGroupMode = NestedGroupModePOSIXMemberUID
	configuration.MaxNestedGroupDepth = 1
	configuration.GroupBaseDN = stringPointer("ou=groups,dc=example,dc=com")
	configuration.GroupSearchFilter = stringPointer(filter)
}
