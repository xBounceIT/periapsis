package ldapclient

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestDirectoryInspectionBoundaryFormattingRedactsEveryValueSurface(t *testing.T) {
	t.Parallel()

	const (
		usernameCanary  = "inspection-user-canary-918273"
		bindDNCanary    = "cn=inspection-bind-canary-918273,dc=example,dc=com"
		baseDNCanary    = "ou=inspection-base-canary-918273,dc=example,dc=com"
		hostCanary      = "inspection-host-canary-918273.example.com"
		attributeCanary = "inspectionAttributeCanary918273"
		valueCanary     = "inspection-value-canary-918273"
		filterCanary    = "inspectionFilterCanary918273"
		caCanary        = "inspection-ca-canary-918273"
	)
	username, _ := identity.NewLDAPUsername(usernameCanary)
	filter := mustDirectoryInspectionFilter(
		t,
		DirectoryInspectionFilterUser,
		"(&("+filterCanary+"=1)(uid={username}))",
	)
	configuration := DirectoryInspectionConfiguration{
		Network: Configuration{
			Endpoints:   []Endpoint{{Host: hostCanary, TLSServerName: hostCanary}},
			CustomCAPEM: []byte(caCanary),
		},
		BindDN: bindDNCanary,
	}
	searchRequest := DirectorySearchUserRequest{
		Configuration: configuration, Username: username, UserBaseDN: baseDNCanary,
		UserSearchFilter: filter, Attributes: []string{attributeCanary},
	}
	filterRequest := DirectoryFilterTestRequest{
		Configuration: configuration, UserBaseDN: baseDNCanary, Filter: filter,
		Values:         identity.LDAPTemplateValues{Username: username},
		UserAttributes: []string{attributeCanary}, MaxResults: 7,
	}
	entry := DirectoryEntry{
		DistinguishedName: baseDNCanary,
		Attributes:        []DirectoryAttribute{{Name: attributeCanary, Values: [][]byte{[]byte(valueCanary)}}},
	}
	result := DirectoryInspectionResult{
		Category: DirectoryCategorySuccess, EndpointPriority: 4, Truncated: true,
		Entries: []DirectoryEntry{entry},
	}
	values := []any{
		filter, &filter,
		configuration, &configuration,
		searchRequest, &searchRequest,
		filterRequest, &filterRequest,
		result, &result,
		DirectoryInspectionFilterKind("private-kind-918273"),
	}
	canaries := []string{
		usernameCanary, bindDNCanary, baseDNCanary, hostCanary, attributeCanary,
		valueCanary, filterCanary, caCanary, "private-kind-918273",
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

	formatted := fmt.Sprintf("%v", result)
	for _, expected := range []string{
		"category=success", "endpoint_priority=4", "truncated=true", "entries=1",
	} {
		if !strings.Contains(formatted, expected) {
			t.Fatalf("sanitized result %q omitted %q", formatted, expected)
		}
	}
}

func TestDirectoryInspectionFailureFormattingReportsZeroProjection(t *testing.T) {
	t.Parallel()

	result := DirectoryInspectionResult{
		Category: DirectoryCategoryProtocolFailed, EndpointPriority: 5, Truncated: true,
		Entries: []DirectoryEntry{{
			DistinguishedName: "uid=must-not-format,dc=example,dc=com",
			Attributes: []DirectoryAttribute{{
				Name: "privateAttribute", Values: [][]byte{[]byte("private-value")},
			}},
		}},
	}
	formatted := fmt.Sprintf("%+v", result)
	if !strings.Contains(formatted, "truncated=false") || !strings.Contains(formatted, "entries=0") ||
		strings.Contains(formatted, "must-not-format") || strings.Contains(formatted, "private-value") {
		t.Fatalf("failed inspection formatted unsafe data: %q", formatted)
	}
}
