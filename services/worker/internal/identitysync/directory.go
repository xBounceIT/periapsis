package identitysync

import (
	"errors"
	"slices"
	"strings"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
)

func providerContext(claim Claim) identity.ProviderContext {
	return identity.ProviderContext{
		Scope:      identity.TenantProviderScope,
		TenantID:   identity.EntityID(claim.TenantID),
		ProviderID: identity.EntityID(claim.ProviderID),
	}
}

func decryptBindSecret(keyring identity.Keyring, claim Claim) ([]byte, error) {
	if claim.SecretAlgorithm != "aes-256-gcm" || claim.SecretKeyVersion < 1 ||
		len(claim.SecretCiphertext) < 17 || len(claim.SecretCiphertext) > 8_192 {
		return nil, ErrInvalidSnapshot
	}
	envelope := identity.BindSecretEnvelope{
		KeyVersion: claim.SecretKeyVersion,
		Nonce:      claim.SecretNonce,
		Ciphertext: claim.SecretCiphertext,
	}
	plaintext, err := keyring.DecryptBindSecret(identity.BindSecretContext{
		Provider: providerContext(claim), SecretID: identity.EntityID(claim.SecretID),
	}, envelope)
	if err != nil {
		return nil, errors.Join(ErrInvalidSnapshot, err)
	}
	return plaintext, nil
}

func networkConfiguration(claim Claim) (ldapclient.Configuration, error) {
	configuration := claim.Configuration
	if !configuration.VerifyCertificate || configuration.ConnectTimeoutMS <= 0 ||
		configuration.OperationTimeoutMS <= 0 || len(claim.Endpoints) < 1 || len(claim.Endpoints) > 8 {
		return ldapclient.Configuration{}, ErrInvalidSnapshot
	}
	network := ldapclient.Configuration{
		ConnectTimeout:   time.Duration(configuration.ConnectTimeoutMS) * time.Millisecond,
		OperationTimeout: time.Duration(configuration.OperationTimeoutMS) * time.Millisecond,
		Endpoints:        make([]ldapclient.Endpoint, 0, len(claim.Endpoints)),
	}
	if configuration.CustomCAPEM != nil {
		network.CustomCAPEM = []byte(*configuration.CustomCAPEM)
	}
	for _, endpoint := range claim.Endpoints {
		network.Endpoints = append(network.Endpoints, ldapclient.Endpoint{
			Priority: endpoint.Priority, Enabled: endpoint.Enabled,
			ReferralAllowed: endpoint.ReferralAllowed, Host: endpoint.Host,
			Port: endpoint.Port, Transport: endpoint.Transport,
			TLSServerName: endpoint.TLSServerName,
		})
	}
	return network, nil
}

func referralMode(value string) (ldapclient.DirectoryReferralMode, error) {
	switch value {
	case "disabled":
		return ldapclient.DirectoryReferralModeDisabled, nil
	case "configured_endpoints":
		return ldapclient.DirectoryReferralModeConfiguredEndpoints, nil
	default:
		return "", ErrInvalidSnapshot
	}
}

func enumerationRequest(claim Claim) (ldapclient.DirectoryEnumerationRequest, ldapclient.DirectoryAttributeName, error) {
	network, err := networkConfiguration(claim)
	if err != nil {
		return ldapclient.DirectoryEnumerationRequest{}, ldapclient.DirectoryAttributeName{}, err
	}
	fail := func() (ldapclient.DirectoryEnumerationRequest, ldapclient.DirectoryAttributeName, error) {
		clear(network.CustomCAPEM)
		return ldapclient.DirectoryEnumerationRequest{}, ldapclient.DirectoryAttributeName{}, ErrInvalidSnapshot
	}
	usernameAttribute, err := ldapclient.NewDirectoryAttributeName(claim.Configuration.UsernameAttribute)
	if err != nil {
		return fail()
	}
	filter, err := identity.CompileLDAPTemplate(
		identity.LDAPTemplateContextUserSearchFilter,
		claim.Configuration.UserSearchFilter,
	)
	if err != nil {
		return fail()
	}
	referrals, err := referralMode(claim.Configuration.ReferralMode)
	if err != nil {
		return fail()
	}
	maxEntries := min(claim.Configuration.MaxEntries, maximumStagedObservations)
	if maxEntries < 1 {
		return fail()
	}
	return ldapclient.DirectoryEnumerationRequest{
		Configuration:    network,
		BindDN:           claim.Configuration.BindDN,
		UserBaseDN:       claim.Configuration.UserBaseDN,
		UserSearchFilter: filter,
		UserAttributes:   []string{strings.ToLower(claim.Configuration.UsernameAttribute)},
		ReferralMode:     referrals,
		ReferralMaxHops:  claim.Configuration.MaxReferralHops,
		Limits: ldapclient.DirectoryLimits{
			PageSize: claim.Configuration.PageSize, MaxPages: claim.Configuration.MaxPages,
			MaxEntries: maxEntries, MaxResponseBytes: claim.Configuration.MaxResponseBytes,
		},
	}, usernameAttribute, nil
}

func observationRequest(
	claim Claim,
	username identity.LDAPUsername,
) (ldapclient.DirectoryRequest, ldapclient.DirectoryNormalizationConfiguration, error) {
	network, err := networkConfiguration(claim)
	if err != nil {
		return ldapclient.DirectoryRequest{}, ldapclient.DirectoryNormalizationConfiguration{}, err
	}
	fail := func() (ldapclient.DirectoryRequest, ldapclient.DirectoryNormalizationConfiguration, error) {
		clear(network.CustomCAPEM)
		return ldapclient.DirectoryRequest{}, ldapclient.DirectoryNormalizationConfiguration{}, ErrInvalidSnapshot
	}
	normalization, err := normalizationConfiguration(claim.Configuration, username)
	if err != nil {
		return fail()
	}
	userAttributes, err := normalization.RequiredUserAttributes()
	if err != nil {
		return fail()
	}
	filter, err := identity.CompileLDAPTemplate(
		identity.LDAPTemplateContextUserSearchFilter,
		claim.Configuration.UserSearchFilter,
	)
	if err != nil {
		return fail()
	}
	groups, err := groupConfiguration(claim.Configuration)
	if err != nil {
		return fail()
	}
	referrals, err := referralMode(claim.Configuration.ReferralMode)
	if err != nil {
		return fail()
	}
	return ldapclient.DirectoryRequest{
		Configuration: network, BindDN: claim.Configuration.BindDN,
		Username: username, UserBaseDN: claim.Configuration.UserBaseDN,
		UserSearchFilter: filter, UserAttributes: userAttributes,
		ReferralMode: referrals, ReferralMaxHops: claim.Configuration.MaxReferralHops,
		Groups: groups,
		Limits: ldapclient.DirectoryLimits{
			PageSize: claim.Configuration.PageSize, MaxPages: claim.Configuration.MaxPages,
			MaxEntries:       claim.Configuration.MaxEntries,
			MaxResponseBytes: claim.Configuration.MaxResponseBytes,
		},
	}, normalization, nil
}

func normalizationConfiguration(
	configuration SnapshotConfiguration,
	username identity.LDAPUsername,
) (ldapclient.DirectoryNormalizationConfiguration, error) {
	firstName, err := requiredAttribute(configuration.FirstNameAttribute)
	if err != nil {
		return ldapclient.DirectoryNormalizationConfiguration{}, err
	}
	lastName, err := requiredAttribute(configuration.LastNameAttribute)
	if err != nil {
		return ldapclient.DirectoryNormalizationConfiguration{}, err
	}
	displayName, err := requiredAttribute(configuration.DisplayNameAttribute)
	if err != nil {
		return ldapclient.DirectoryNormalizationConfiguration{}, err
	}
	usernameAttribute, err := requiredAttribute(configuration.UsernameAttribute)
	if err != nil {
		return ldapclient.DirectoryNormalizationConfiguration{}, err
	}
	alternate, err := optionalAttribute(configuration.AlternateUsernameAttribute)
	if err != nil {
		return ldapclient.DirectoryNormalizationConfiguration{}, err
	}
	email, err := optionalAttribute(configuration.EmailAttribute)
	if err != nil {
		return ldapclient.DirectoryNormalizationConfiguration{}, err
	}
	subjectAttribute, err := requiredAttribute(configuration.ImmutableSubjectAttribute)
	if err != nil {
		return ldapclient.DirectoryNormalizationConfiguration{}, err
	}
	var subjectMode ldapclient.DirectorySubjectMode
	switch configuration.ImmutableSubjectFormat {
	case "ad_object_guid":
		subjectMode = ldapclient.DirectorySubjectADObjectGUID
	case "entry_uuid":
		subjectMode = ldapclient.DirectorySubjectEntryUUID
	case "utf8_exact":
		subjectMode = ldapclient.DirectorySubjectUTF8Exact
	case "utf8_casefold":
		subjectMode = ldapclient.DirectorySubjectUTF8CaseFold
	default:
		return ldapclient.DirectoryNormalizationConfiguration{}, ErrInvalidSnapshot
	}
	subject, err := ldapclient.NewDirectorySubjectMapping(subjectMode, subjectAttribute)
	if err != nil {
		return ldapclient.DirectoryNormalizationConfiguration{}, ErrInvalidSnapshot
	}
	account, err := accountStateMapping(configuration)
	if err != nil {
		return ldapclient.DirectoryNormalizationConfiguration{}, err
	}
	var gid ldapclient.DirectoryAttributeName
	if configuration.NestedGroupMode == "posix_member_uid" && configuration.POSIXGIDNumberAttribute != nil {
		gid, err = requiredAttribute(*configuration.POSIXGIDNumberAttribute)
		if err != nil {
			return ldapclient.DirectoryNormalizationConfiguration{}, err
		}
	}
	result := ldapclient.DirectoryNormalizationConfiguration{
		LoginUsername: username,
		Profile: ldapclient.DirectoryProfileAttributeMapping{
			FirstName: firstName, LastName: lastName, DisplayName: displayName,
			Username: usernameAttribute, AlternateUsername: alternate, Email: email,
		},
		Subject: subject, AccountState: account, GIDNumberAttribute: gid,
	}
	if _, err := result.RequiredUserAttributes(); err != nil {
		return ldapclient.DirectoryNormalizationConfiguration{}, ErrInvalidSnapshot
	}
	return result, nil
}

func accountStateMapping(configuration SnapshotConfiguration) (ldapclient.DirectoryAccountStateMapping, error) {
	switch configuration.AccountStatusMode {
	case "none":
		if configuration.AccountStatusAttribute != nil || configuration.AccountDisabledValue != nil {
			return ldapclient.DirectoryAccountStateMapping{}, ErrInvalidSnapshot
		}
		return ldapclient.DirectoryAlwaysActiveAccountState(), nil
	case "active_directory_uac":
		if configuration.AccountStatusAttribute == nil || configuration.AccountDisabledValue != nil {
			return ldapclient.DirectoryAccountStateMapping{}, ErrInvalidSnapshot
		}
		attribute, err := requiredAttribute(*configuration.AccountStatusAttribute)
		if err != nil {
			return ldapclient.DirectoryAccountStateMapping{}, err
		}
		mapped, err := ldapclient.NewDirectoryADAccountState(attribute)
		if err != nil {
			return ldapclient.DirectoryAccountStateMapping{}, ErrInvalidSnapshot
		}
		return mapped, nil
	case "attribute_equals":
		if configuration.AccountStatusAttribute == nil || configuration.AccountDisabledValue == nil {
			return ldapclient.DirectoryAccountStateMapping{}, ErrInvalidSnapshot
		}
		attribute, err := requiredAttribute(*configuration.AccountStatusAttribute)
		if err != nil {
			return ldapclient.DirectoryAccountStateMapping{}, err
		}
		mapped, err := ldapclient.NewDirectoryOpenLDAPValueAccountState(
			attribute, []byte(*configuration.AccountDisabledValue), ldapclient.DirectoryValueExact,
		)
		if err != nil {
			return ldapclient.DirectoryAccountStateMapping{}, ErrInvalidSnapshot
		}
		return mapped, nil
	default:
		return ldapclient.DirectoryAccountStateMapping{}, ErrInvalidSnapshot
	}
}

func groupConfiguration(configuration SnapshotConfiguration) (ldapclient.DirectoryGroupConfiguration, error) {
	result := ldapclient.DirectoryGroupConfiguration{MaxGroups: configuration.MaxGroups}
	if configuration.GroupBaseDN != nil {
		result.BaseDN = *configuration.GroupBaseDN
	}
	if configuration.GroupMembershipAttribute != nil {
		result.DirectMembershipAttribute = strings.ToLower(*configuration.GroupMembershipAttribute)
	}
	result.MaxDepth = configuration.MaxNestedGroupDepth
	switch configuration.NestedGroupMode {
	case "disabled":
		result.Mode = ldapclient.DirectoryGroupModeDisabled
		return result, nil
	case "active_directory", "reverse_search":
		if configuration.GroupSearchFilter == nil || configuration.GroupBaseDN == nil {
			return ldapclient.DirectoryGroupConfiguration{}, ErrInvalidSnapshot
		}
		compiled, err := identity.CompileLDAPTemplate(
			identity.LDAPTemplateContextReverseGroupSearchFilter,
			*configuration.GroupSearchFilter,
		)
		if err != nil {
			return ldapclient.DirectoryGroupConfiguration{}, ErrInvalidSnapshot
		}
		if configuration.NestedGroupMode == "active_directory" {
			result.Mode = ldapclient.DirectoryGroupModeActiveDirectory
		} else {
			result.Mode = ldapclient.DirectoryGroupModeReverseSearch
		}
		result.SearchFilter = &compiled
		result.Attributes = []string{"cn"}
		return result, nil
	case "posix_member_uid":
		if configuration.GroupSearchFilter == nil || configuration.GroupBaseDN == nil {
			return ldapclient.DirectoryGroupConfiguration{}, ErrInvalidSnapshot
		}
		compiled, err := identity.CompileLDAPTemplate(
			identity.LDAPTemplateContextPOSIXGroupSearchFilter,
			*configuration.GroupSearchFilter,
		)
		if err != nil {
			return ldapclient.DirectoryGroupConfiguration{}, ErrInvalidSnapshot
		}
		result.Mode = ldapclient.DirectoryGroupModePOSIXMemberUID
		result.SearchFilter = &compiled
		result.Attributes = []string{"cn"}
		if configuration.POSIXMemberUIDAttribute != nil {
			result.Attributes = append(result.Attributes, strings.ToLower(*configuration.POSIXMemberUIDAttribute))
		}
		if configuration.POSIXGIDNumberAttribute != nil {
			result.POSIXGIDNumberAttribute = strings.ToLower(*configuration.POSIXGIDNumberAttribute)
		}
		slices.Sort(result.Attributes)
		result.Attributes = slices.Compact(result.Attributes)
		return result, nil
	default:
		return ldapclient.DirectoryGroupConfiguration{}, ErrInvalidSnapshot
	}
}

func requiredAttribute(value string) (ldapclient.DirectoryAttributeName, error) {
	attribute, err := ldapclient.NewDirectoryAttributeName(value)
	if err != nil {
		return ldapclient.DirectoryAttributeName{}, ErrInvalidSnapshot
	}
	return attribute, nil
}

func optionalAttribute(value *string) (ldapclient.DirectoryAttributeName, error) {
	if value == nil {
		return ldapclient.DirectoryAttributeName{}, nil
	}
	return requiredAttribute(*value)
}
