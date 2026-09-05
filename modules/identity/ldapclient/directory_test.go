package ldapclient

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func validDirectoryRequest(t *testing.T) DirectoryRequest {
	t.Helper()
	username, err := identity.NewLDAPUsername("alice")
	if err != nil {
		t.Fatalf("NewLDAPUsername() error = %v", err)
	}
	userFilter, err := identity.CompileLDAPTemplate(
		identity.LDAPTemplateContextUserSearchFilter,
		"(&(objectClass=person)(uid={username}))",
	)
	if err != nil {
		t.Fatalf("CompileLDAPTemplate() error = %v", err)
	}
	return DirectoryRequest{
		Configuration:    testConfiguration(),
		BindDN:           "cn=service,dc=example,dc=com",
		Username:         username,
		UserBaseDN:       "ou=people,dc=example,dc=com",
		UserSearchFilter: userFilter,
		UserAttributes:   []string{"givenName", "sn", "cn", "uid", "mail", "entryUUID"},
		ReferralMode:     DirectoryReferralModeDisabled,
		Groups: DirectoryGroupConfiguration{
			Mode: DirectoryGroupModeDisabled, BaseDN: "ou=groups,dc=example,dc=com",
			DirectMembershipAttribute: "memberOf", MaxGroups: 100,
		},
		Limits: DirectoryLimits{
			PageSize: 100, MaxPages: 10, MaxEntries: 1_000, MaxResponseBytes: 1024 * 1024,
		},
	}
}

func newValidationOnlyDirectoryClient(t *testing.T) *Client {
	t.Helper()
	client, err := New(testOptions(
		publicResolver("93.184.216.34"),
		dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("validation must not dial")
		}),
	))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client
}

func TestDirectoryRequestValidationAcceptsClosedTypedModes(t *testing.T) {
	t.Parallel()

	client := newValidationOnlyDirectoryClient(t)
	request := validDirectoryRequest(t)
	if _, err := client.validateDirectoryRequest(request); err != nil {
		t.Fatalf("disabled/direct validation error = %v", err)
	}

	reverseFilter, _ := identity.CompileLDAPTemplate(
		identity.LDAPTemplateContextReverseGroupSearchFilter,
		"(|(member={userDn})(memberUid={username}))",
	)
	reverse := request
	reverse.Groups = DirectoryGroupConfiguration{
		Mode: DirectoryGroupModeActiveDirectory, BaseDN: "ou=groups,dc=example,dc=com",
		SearchFilter: &reverseFilter, DirectMembershipAttribute: "memberOf",
		Attributes: []string{"cn"}, MaxDepth: 5, MaxGroups: 100,
	}
	if _, err := client.validateDirectoryRequest(reverse); err != nil {
		t.Fatalf("reverse validation error = %v", err)
	}

	posixFilter, _ := identity.CompileLDAPTemplate(
		identity.LDAPTemplateContextPOSIXGroupSearchFilter,
		"(|(memberUid={username})(gidNumber={gidNumber}))",
	)
	posix := request
	posix.Groups = DirectoryGroupConfiguration{
		Mode: DirectoryGroupModePOSIXMemberUID, BaseDN: "ou=groups,dc=example,dc=com",
		SearchFilter: &posixFilter, POSIXGIDNumberAttribute: "gidNumber",
		Attributes: []string{"cn"}, MaxDepth: 1, MaxGroups: 100,
	}
	if _, err := client.validateDirectoryRequest(posix); err != nil {
		t.Fatalf("POSIX validation error = %v", err)
	}
}

func TestDirectoryRequestValidationRejectsEveryUnboundedOrMismatchedSurface(t *testing.T) {
	t.Parallel()

	client := newValidationOnlyDirectoryClient(t)
	valid := validDirectoryRequest(t)
	reverseFilter, _ := identity.CompileLDAPTemplate(
		identity.LDAPTemplateContextReverseGroupSearchFilter,
		"(member={userDn})",
	)
	posixGIDFilter, _ := identity.CompileLDAPTemplate(
		identity.LDAPTemplateContextPOSIXGroupSearchFilter,
		"(|(memberUid={username})(gidNumber={gidNumber}))",
	)
	userDNTemplate, _ := identity.CompileLDAPTemplate(
		identity.LDAPTemplateContextUserDN,
		"uid={username},ou=people,dc=example,dc=com",
	)
	tests := []struct {
		name   string
		mutate func(*DirectoryRequest)
	}{
		{name: "configured referrals without target policy", mutate: func(value *DirectoryRequest) {
			value.ReferralMode = "configured_endpoints"
		}},
		{name: "zero page size", mutate: func(value *DirectoryRequest) { value.Limits.PageSize = 0 }},
		{name: "excessive page count", mutate: func(value *DirectoryRequest) {
			value.Limits.MaxPages = maximumDirectoryPages + 1
		}},
		{name: "zero entry bound", mutate: func(value *DirectoryRequest) { value.Limits.MaxEntries = 0 }},
		{name: "small response bound", mutate: func(value *DirectoryRequest) {
			value.Limits.MaxResponseBytes = minimumDirectoryResponseBytes - 1
		}},
		{name: "empty service bind DN", mutate: func(value *DirectoryRequest) { value.BindDN = "" }},
		{name: "invalid user base DN", mutate: func(value *DirectoryRequest) { value.UserBaseDN = "not-a-dn" }},
		{name: "wildcard attribute", mutate: func(value *DirectoryRequest) { value.UserAttributes = []string{"*"} }},
		{name: "DN template used as search filter", mutate: func(value *DirectoryRequest) {
			value.UserSearchFilter = userDNTemplate
		}},
		{name: "filter template used as user DN", mutate: func(value *DirectoryRequest) {
			value.UserDNTemplate = &value.UserSearchFilter
		}},
		{name: "disabled mode with a group search", mutate: func(value *DirectoryRequest) {
			value.Groups.BaseDN = "ou=groups,dc=example,dc=com"
			value.Groups.SearchFilter = &reverseFilter
			value.Groups.MaxDepth = 1
		}},
		{name: "reverse mode with POSIX filter", mutate: func(value *DirectoryRequest) {
			value.Groups = DirectoryGroupConfiguration{
				Mode: DirectoryGroupModeReverseSearch, BaseDN: "ou=groups,dc=example,dc=com",
				SearchFilter: &posixGIDFilter, MaxDepth: 1, MaxGroups: 10,
			}
		}},
		{name: "POSIX gid placeholder without attribute", mutate: func(value *DirectoryRequest) {
			value.Groups = DirectoryGroupConfiguration{
				Mode: DirectoryGroupModePOSIXMemberUID, BaseDN: "ou=groups,dc=example,dc=com",
				SearchFilter: &posixGIDFilter, MaxDepth: 1, MaxGroups: 10,
			}
		}},
		{name: "reverse depth zero", mutate: func(value *DirectoryRequest) {
			value.Groups = DirectoryGroupConfiguration{
				Mode: DirectoryGroupModeReverseSearch, BaseDN: "ou=groups,dc=example,dc=com",
				SearchFilter: &reverseFilter, MaxGroups: 10,
			}
		}},
		{name: "zero group bound", mutate: func(value *DirectoryRequest) { value.Groups.MaxGroups = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := valid
			request.Configuration.Endpoints = append([]Endpoint(nil), valid.Configuration.Endpoints...)
			request.UserAttributes = append([]string(nil), valid.UserAttributes...)
			test.mutate(&request)
			if _, err := client.validateDirectoryRequest(request); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("validateDirectoryRequest() error = %v", err)
			}
		})
	}
}

func TestAuthenticateDirectoryClearsBothSecretsBeforeAnyRejectedInputReturns(t *testing.T) {
	t.Parallel()

	client := newValidationOnlyDirectoryClient(t)
	request := validDirectoryRequest(t)
	request.ReferralMode = "configured_endpoints"
	bindSecret := []byte("service-secret-canary")
	userPassword := []byte("user-password-canary")
	_, err := client.AuthenticateDirectory(context.Background(), request, bindSecret, userPassword)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("AuthenticateDirectory() error = %v", err)
	}
	if !allZeroBytes(bindSecret) || !allZeroBytes(userPassword) {
		t.Fatalf("rejected request retained secret bytes: bind=%v user=%v", bindSecret, userPassword)
	}

	oversizedBind := bytes.Repeat([]byte{'s'}, maximumBindSecretBytes+1)
	secondUserPassword := []byte("another-user-password")
	_, err = client.AuthenticateDirectory(context.Background(), validDirectoryRequest(t), oversizedBind, secondUserPassword)
	if !errors.Is(err, ErrInvalidConfiguration) || !allZeroBytes(oversizedBind) || !allZeroBytes(secondUserPassword) {
		t.Fatalf("oversized secret path error = %v, bind cleared=%t, user cleared=%t",
			err, allZeroBytes(oversizedBind), allZeroBytes(secondUserPassword))
	}
}
