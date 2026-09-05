package identityprovider

import (
	"strings"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
)

// directoryObservationRequest converts one canonical provider snapshot into
// the complete service-bind-only ObserveDirectory request. The returned
// request owns Configuration.CustomCAPEM; callers must defer
// clearDirectoryObservationRequest immediately after a successful mapping.
// No bind secret or user-password value crosses this pure boundary.
func directoryObservationRequest(
	configuration Configuration,
	endpoints []Endpoint,
	username string,
) (ldapclient.DirectoryRequest, error) {
	canonical, canonicalEndpoints, err := normalizeConfiguration(configuration, endpoints)
	if err != nil || !hasEnabledDirectoryEndpoint(canonicalEndpoints) {
		return ldapclient.DirectoryRequest{}, ErrInvalidInput
	}

	typedUsername, err := identity.NewLDAPUsername(username)
	if err != nil {
		return ldapclient.DirectoryRequest{}, ErrInvalidInput
	}
	userFilter, err := identity.CompileLDAPTemplate(
		identity.LDAPTemplateContextUserSearchFilter,
		canonical.UserSearchFilter,
	)
	if err != nil {
		return ldapclient.DirectoryRequest{}, ErrInvalidInput
	}
	var userDNTemplate *identity.CompiledLDAPTemplate
	if canonical.UserDNTemplate != nil {
		compiled, compileErr := identity.CompileLDAPTemplate(
			identity.LDAPTemplateContextUserDN,
			*canonical.UserDNTemplate,
		)
		if compileErr != nil {
			return ldapclient.DirectoryRequest{}, ErrInvalidInput
		}
		userDNTemplate = &compiled
	}

	userAttributes, err := directoryObservationUserAttributes(canonical, username)
	if err != nil {
		return ldapclient.DirectoryRequest{}, err
	}
	groups, err := directoryObservationGroups(canonical)
	if err != nil {
		return ldapclient.DirectoryRequest{}, err
	}
	referrals, err := directoryObservationReferralMode(canonical.ReferralMode)
	if err != nil {
		return ldapclient.DirectoryRequest{}, err
	}
	network, err := deploymentLDAPConfiguration(canonical, canonicalEndpoints, false)
	if err != nil {
		return ldapclient.DirectoryRequest{}, ErrInvalidInput
	}

	return ldapclient.DirectoryRequest{
		Configuration:    network,
		BindDN:           canonical.BindDN,
		Username:         typedUsername,
		UserBaseDN:       canonical.UserBaseDN,
		UserSearchFilter: userFilter,
		UserDNTemplate:   userDNTemplate,
		UserAttributes:   userAttributes,
		ReferralMode:     referrals,
		ReferralMaxHops:  canonical.MaxReferralHops,
		Groups:           groups,
		Limits: ldapclient.DirectoryLimits{
			PageSize:         canonical.PageSize,
			MaxPages:         canonical.MaxPages,
			MaxEntries:       canonical.MaxEntries,
			MaxResponseBytes: canonical.MaxResponseBytes,
		},
	}, nil
}

func directoryObservationUserAttributes(
	configuration Configuration,
	username string,
) ([]string, error) {
	normalization, err := directoryNormalizationConfiguration(configuration, username)
	if err != nil {
		return nil, ErrInvalidInput
	}
	attributes, err := normalization.RequiredUserAttributes()
	if err != nil {
		return nil, ErrInvalidInput
	}
	if configuration.GroupMembershipAttribute != nil {
		attributes = append(attributes, strings.ToLower(*configuration.GroupMembershipAttribute))
	}
	normalized, ok := normalizedInspectionAttributes(attributes)
	if !ok {
		return nil, ErrInvalidInput
	}
	return normalized, nil
}

func directoryObservationGroups(
	configuration Configuration,
) (ldapclient.DirectoryGroupConfiguration, error) {
	directMembershipAttribute := ""
	if configuration.GroupMembershipAttribute != nil {
		directMembershipAttribute = strings.ToLower(*configuration.GroupMembershipAttribute)
	}
	baseDN := ""
	if configuration.GroupBaseDN != nil {
		baseDN = *configuration.GroupBaseDN
	}
	result := ldapclient.DirectoryGroupConfiguration{
		BaseDN:                    baseDN,
		DirectMembershipAttribute: directMembershipAttribute,
		MaxDepth:                  configuration.MaxNestedGroupDepth,
		MaxGroups:                 configuration.MaxGroups,
	}

	switch configuration.NestedGroupMode {
	case NestedGroupModeDisabled:
		if configuration.GroupSearchFilter != nil || configuration.MaxNestedGroupDepth != 0 ||
			configuration.POSIXMemberUIDAttribute != nil || configuration.POSIXGIDNumberAttribute != nil {
			return ldapclient.DirectoryGroupConfiguration{}, ErrInvalidInput
		}
		result.Mode = ldapclient.DirectoryGroupModeDisabled
		return result, nil
	case NestedGroupModeActiveDirectory, NestedGroupModeReverseSearch:
		if configuration.GroupBaseDN == nil || configuration.GroupSearchFilter == nil ||
			configuration.POSIXMemberUIDAttribute != nil || configuration.POSIXGIDNumberAttribute != nil {
			return ldapclient.DirectoryGroupConfiguration{}, ErrInvalidInput
		}
		compiled, err := identity.CompileLDAPTemplate(
			identity.LDAPTemplateContextReverseGroupSearchFilter,
			*configuration.GroupSearchFilter,
		)
		if err != nil {
			return ldapclient.DirectoryGroupConfiguration{}, ErrInvalidInput
		}
		attributes, _, err := directoryGroupInspectionAttributes(configuration)
		if err != nil {
			return ldapclient.DirectoryGroupConfiguration{}, ErrInvalidInput
		}
		if configuration.NestedGroupMode == NestedGroupModeActiveDirectory {
			result.Mode = ldapclient.DirectoryGroupModeActiveDirectory
		} else {
			result.Mode = ldapclient.DirectoryGroupModeReverseSearch
		}
		result.SearchFilter = &compiled
		result.Attributes = attributes
		return result, nil
	case NestedGroupModePOSIXMemberUID:
		if configuration.GroupBaseDN == nil || configuration.GroupSearchFilter == nil {
			return ldapclient.DirectoryGroupConfiguration{}, ErrInvalidInput
		}
		compiled, err := identity.CompileLDAPTemplate(
			identity.LDAPTemplateContextPOSIXGroupSearchFilter,
			*configuration.GroupSearchFilter,
		)
		if err != nil {
			return ldapclient.DirectoryGroupConfiguration{}, ErrInvalidInput
		}
		requirements, err := compiled.Requirements()
		if err != nil || requirements.GIDNumber != (configuration.POSIXGIDNumberAttribute != nil) {
			return ldapclient.DirectoryGroupConfiguration{}, ErrInvalidInput
		}
		attributes, _, err := directoryGroupInspectionAttributes(configuration)
		if err != nil {
			return ldapclient.DirectoryGroupConfiguration{}, ErrInvalidInput
		}
		result.Mode = ldapclient.DirectoryGroupModePOSIXMemberUID
		result.SearchFilter = &compiled
		result.Attributes = attributes
		if configuration.POSIXGIDNumberAttribute != nil {
			result.POSIXGIDNumberAttribute = strings.ToLower(*configuration.POSIXGIDNumberAttribute)
		}
		return result, nil
	default:
		return ldapclient.DirectoryGroupConfiguration{}, ErrInvalidInput
	}
}

func directoryObservationReferralMode(
	mode ReferralMode,
) (ldapclient.DirectoryReferralMode, error) {
	switch mode {
	case ReferralModeDisabled:
		return ldapclient.DirectoryReferralModeDisabled, nil
	case ReferralModeConfiguredEndpoints:
		return ldapclient.DirectoryReferralModeConfiguredEndpoints, nil
	default:
		return "", ErrInvalidInput
	}
}

func hasEnabledDirectoryEndpoint(endpoints []Endpoint) bool {
	for _, endpoint := range endpoints {
		if endpoint.Enabled {
			return true
		}
	}
	return false
}

// clearDirectoryObservationRequest destroys only owned trust bytes. Other
// request fields contain provider configuration but no secret material.
func clearDirectoryObservationRequest(request *ldapclient.DirectoryRequest) {
	if request == nil {
		return
	}
	clear(request.Configuration.CustomCAPEM)
	request.Configuration.CustomCAPEM = nil
}

// BuildDirectoryAuthenticationRequest exposes the canonical LDAP provider
// mapping to the interactive-login boundary. The caller owns the returned CA
// bytes and must call ClearDirectoryAuthenticationRequest on every path.
func BuildDirectoryAuthenticationRequest(
	configuration Configuration,
	endpoints []Endpoint,
	username string,
) (ldapclient.DirectoryRequest, error) {
	return directoryObservationRequest(configuration, endpoints, username)
}

// ClearDirectoryAuthenticationRequest destroys the trust bytes owned by a
// request returned from BuildDirectoryAuthenticationRequest.
func ClearDirectoryAuthenticationRequest(request *ldapclient.DirectoryRequest) {
	clearDirectoryObservationRequest(request)
}

// BuildDirectoryNetworkConfiguration exposes only the ordered, enabled,
// deny-by-default egress/TLS projection needed by connection and service-bind
// diagnostics. The returned configuration owns CustomCAPEM and must be
// cleared with ClearDirectoryNetworkConfiguration.
func BuildDirectoryNetworkConfiguration(
	configuration Configuration,
	endpoints []Endpoint,
) (ldapclient.Configuration, error) {
	canonical, canonicalEndpoints, err := normalizeConfiguration(configuration, endpoints)
	if err != nil || !hasEnabledDirectoryEndpoint(canonicalEndpoints) {
		return ldapclient.Configuration{}, ErrInvalidInput
	}
	return deploymentLDAPConfiguration(canonical, canonicalEndpoints, true)
}

func ClearDirectoryNetworkConfiguration(configuration *ldapclient.Configuration) {
	if configuration == nil {
		return
	}
	clear(configuration.CustomCAPEM)
	configuration.CustomCAPEM = nil
}
