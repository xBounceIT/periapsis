package ldapclient

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestDirectoryBoundaryFormattingRedactsRawConfigurationAndObservations(t *testing.T) {
	t.Parallel()

	const (
		usernameCanary  = "fmt-user-canary-918273"
		bindDNCanary    = "cn=fmt-bind-canary-918273,dc=example,dc=com"
		baseDNCanary    = "ou=fmt-user-base-canary-918273,dc=example,dc=com"
		groupDNCanary   = "cn=fmt-group-canary-918273,ou=groups,dc=example,dc=com"
		attributeCanary = "fmtAttributeCanary918273"
		valueCanary     = "fmt-value-canary-918273"
		caCanary        = "fmt-ca-canary-918273"
		hostCanary      = "fmt-host-canary-918273.example.com"
	)
	username, _ := identity.NewLDAPUsername(usernameCanary)
	userFilter, _ := identity.CompileLDAPTemplate(
		identity.LDAPTemplateContextUserSearchFilter,
		"(&(fmtLiteralCanary918273=1)(uid={username}))",
	)
	groupFilter, _ := identity.CompileLDAPTemplate(
		identity.LDAPTemplateContextReverseGroupSearchFilter,
		"(&(fmtGroupFilterCanary918273=1)(member={userDn}))",
	)
	attribute := DirectoryAttribute{Name: attributeCanary, Values: [][]byte{[]byte(valueCanary)}}
	entry := DirectoryEntry{DistinguishedName: groupDNCanary, Attributes: []DirectoryAttribute{attribute}}
	observation := DirectoryObservation{User: entry, Groups: []DirectoryEntry{entry, entry}}
	request := DirectoryRequest{
		Configuration: Configuration{
			Endpoints:   []Endpoint{{Host: hostCanary, TLSServerName: hostCanary}},
			CustomCAPEM: []byte(caCanary),
		},
		BindDN:           bindDNCanary,
		Username:         username,
		UserBaseDN:       baseDNCanary,
		UserSearchFilter: userFilter,
		UserAttributes:   []string{attributeCanary},
		Groups: DirectoryGroupConfiguration{
			BaseDN:                    groupDNCanary,
			SearchFilter:              &groupFilter,
			DirectMembershipAttribute: attributeCanary,
			POSIXGIDNumberAttribute:   "fmtGidCanary918273",
			Attributes:                []string{attributeCanary},
		},
	}
	result := DirectoryResult{
		Category: DirectoryCategorySuccess, EndpointPriority: 7, Observation: observation,
	}
	values := []any{
		request.Configuration, &request.Configuration,
		request.Configuration.Endpoints[0], &request.Configuration.Endpoints[0],
		request, &request,
		request.Groups, &request.Groups,
		attribute, &attribute,
		entry, &entry,
		observation, &observation,
		result, &result,
	}
	canaries := []string{
		usernameCanary, bindDNCanary, baseDNCanary, groupDNCanary, attributeCanary,
		valueCanary, caCanary, hostCanary, "fmtLiteralCanary918273", "fmtGroupFilterCanary918273",
		"fmtGidCanary918273",
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		for _, value := range values {
			formatted := fmt.Sprintf(format, value)
			for _, canary := range canaries {
				if strings.Contains(formatted, canary) ||
					strings.Contains(strings.ToLower(formatted), hex.EncodeToString([]byte(canary))) {
					t.Fatalf("format %q exposed a canary in %q", format, formatted)
				}
			}
		}
	}
	formattedResult := fmt.Sprintf("%v", result)
	for _, expected := range []string{
		"category=success", "endpoint_priority=7", "user_present=true", "groups=2",
	} {
		if !strings.Contains(formattedResult, expected) {
			t.Fatalf("sanitized result %q omitted %q", formattedResult, expected)
		}
	}
}

func TestDirectoryFailureResultsAlwaysZeroObservation(t *testing.T) {
	t.Parallel()

	sensitive := DirectoryObservation{
		User: DirectoryEntry{
			DistinguishedName: "cn=must-be-cleared,dc=example,dc=com",
			Attributes:        []DirectoryAttribute{{Name: "secretAttribute", Values: [][]byte{[]byte("secret-value")}}},
		},
		Groups: []DirectoryEntry{{DistinguishedName: "cn=also-cleared,dc=example,dc=com"}},
	}
	for _, category := range []DirectoryCategory{
		DirectoryCategoryDNSFailed,
		DirectoryCategoryDestinationBlocked,
		DirectoryCategoryConnectTimeout,
		DirectoryCategoryConnectFailed,
		DirectoryCategoryTLSFailed,
		DirectoryCategoryCertificateRejected,
		DirectoryCategoryServiceBindRejected,
		DirectoryCategoryCredentialsRejected,
		DirectoryCategoryUserNotFound,
		DirectoryCategoryUserAmbiguous,
		DirectoryCategoryLimitExceeded,
		DirectoryCategoryReferralRejected,
		DirectoryCategoryInvalidEntry,
		DirectoryCategoryProtocolFailed,
		DirectoryCategoryCancelled,
		DirectoryCategory("unrecognized-category"),
	} {
		result := sanitizeDirectoryResult(DirectoryResult{
			Category: category, EndpointPriority: 3, Observation: sensitive,
		})
		if directoryEntryPresent(result.Observation.User) || len(result.Observation.Groups) != 0 {
			t.Fatalf("category %q retained observation: %#v", category, result)
		}
		formatted := fmt.Sprintf("%+v", DirectoryResult{
			Category: category, EndpointPriority: 3, Observation: sensitive,
		})
		if !strings.Contains(formatted, "user_present=false") || !strings.Contains(formatted, "groups=0") ||
			strings.Contains(formatted, "must-be-cleared") || strings.Contains(formatted, "secret-value") {
			t.Fatalf("category %q formatted unsafe failure %q", category, formatted)
		}
	}
}
