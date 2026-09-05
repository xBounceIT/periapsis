package identityprovider

import (
	"errors"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
)

// directoryNormalizationConfiguration converts the canonical provider
// document into the one shared raw-directory normalizer. It never infers
// attribute defaults from the provider template.
func directoryNormalizationConfiguration(
	configuration Configuration,
	username string,
) (ldapclient.DirectoryNormalizationConfiguration, error) {
	loginUsername, err := identity.NewLDAPUsername(username)
	if err != nil {
		return ldapclient.DirectoryNormalizationConfiguration{}, ErrInvalidInput
	}
	profile, err := directoryProfileMapping(configuration)
	if err != nil {
		return ldapclient.DirectoryNormalizationConfiguration{}, err
	}
	subject, err := directorySubjectMapping(configuration)
	if err != nil {
		return ldapclient.DirectoryNormalizationConfiguration{}, err
	}
	account, err := directoryAccountStateMapping(configuration)
	if err != nil {
		return ldapclient.DirectoryNormalizationConfiguration{}, err
	}
	gidNumber, err := directoryGIDNumberMapping(configuration)
	if err != nil {
		return ldapclient.DirectoryNormalizationConfiguration{}, err
	}
	result := ldapclient.DirectoryNormalizationConfiguration{
		LoginUsername:      loginUsername,
		Profile:            profile,
		Subject:            subject,
		AccountState:       account,
		GIDNumberAttribute: gidNumber,
	}
	if _, err := result.RequiredUserAttributes(); err != nil {
		return ldapclient.DirectoryNormalizationConfiguration{}, ErrInvalidInput
	}
	return result, nil
}

func directoryProfileMapping(
	configuration Configuration,
) (ldapclient.DirectoryProfileAttributeMapping, error) {
	firstName, err := requiredDirectoryAttribute(configuration.FirstNameAttribute)
	if err != nil {
		return ldapclient.DirectoryProfileAttributeMapping{}, err
	}
	lastName, err := requiredDirectoryAttribute(configuration.LastNameAttribute)
	if err != nil {
		return ldapclient.DirectoryProfileAttributeMapping{}, err
	}
	displayName, err := requiredDirectoryAttribute(configuration.DisplayNameAttribute)
	if err != nil {
		return ldapclient.DirectoryProfileAttributeMapping{}, err
	}
	username, err := requiredDirectoryAttribute(configuration.UsernameAttribute)
	if err != nil {
		return ldapclient.DirectoryProfileAttributeMapping{}, err
	}
	alternateUsername, err := optionalDirectoryAttribute(configuration.AlternateUsernameAttribute)
	if err != nil {
		return ldapclient.DirectoryProfileAttributeMapping{}, err
	}
	email, err := optionalDirectoryAttribute(configuration.EmailAttribute)
	if err != nil {
		return ldapclient.DirectoryProfileAttributeMapping{}, err
	}
	return ldapclient.DirectoryProfileAttributeMapping{
		FirstName: firstName, LastName: lastName, DisplayName: displayName,
		Username: username, AlternateUsername: alternateUsername, Email: email,
	}, nil
}

func directorySubjectMapping(configuration Configuration) (ldapclient.DirectorySubjectMapping, error) {
	attribute, err := requiredDirectoryAttribute(configuration.ImmutableSubjectAttribute)
	if err != nil {
		return ldapclient.DirectorySubjectMapping{}, err
	}
	var mode ldapclient.DirectorySubjectMode
	switch configuration.ImmutableSubjectFormat {
	case SubjectFormatADObjectGUID:
		mode = ldapclient.DirectorySubjectADObjectGUID
	case SubjectFormatEntryUUID:
		mode = ldapclient.DirectorySubjectEntryUUID
	case SubjectFormatUTF8Exact:
		mode = ldapclient.DirectorySubjectUTF8Exact
	case SubjectFormatUTF8Casefold:
		mode = ldapclient.DirectorySubjectUTF8CaseFold
	default:
		return ldapclient.DirectorySubjectMapping{}, ErrInvalidInput
	}
	mapping, err := ldapclient.NewDirectorySubjectMapping(mode, attribute)
	if err != nil {
		return ldapclient.DirectorySubjectMapping{}, ErrInvalidInput
	}
	return mapping, nil
}

func directoryAccountStateMapping(
	configuration Configuration,
) (ldapclient.DirectoryAccountStateMapping, error) {
	switch configuration.AccountStatusMode {
	case AccountStatusModeNone:
		if configuration.AccountStatusAttribute != nil || configuration.AccountDisabledValue != nil {
			return ldapclient.DirectoryAccountStateMapping{}, ErrInvalidInput
		}
		return ldapclient.DirectoryAlwaysActiveAccountState(), nil
	case AccountStatusModeActiveDirectoryUAC:
		if configuration.AccountStatusAttribute == nil || configuration.AccountDisabledValue != nil {
			return ldapclient.DirectoryAccountStateMapping{}, ErrInvalidInput
		}
		attribute, err := requiredDirectoryAttribute(*configuration.AccountStatusAttribute)
		if err != nil {
			return ldapclient.DirectoryAccountStateMapping{}, err
		}
		mapping, err := ldapclient.NewDirectoryADAccountState(attribute)
		if err != nil {
			return ldapclient.DirectoryAccountStateMapping{}, ErrInvalidInput
		}
		return mapping, nil
	case AccountStatusModeAttributeEquals:
		if configuration.AccountStatusAttribute == nil || configuration.AccountDisabledValue == nil {
			return ldapclient.DirectoryAccountStateMapping{}, ErrInvalidInput
		}
		attribute, err := requiredDirectoryAttribute(*configuration.AccountStatusAttribute)
		if err != nil {
			return ldapclient.DirectoryAccountStateMapping{}, err
		}
		mapping, err := ldapclient.NewDirectoryOpenLDAPValueAccountState(
			attribute,
			[]byte(*configuration.AccountDisabledValue),
			ldapclient.DirectoryValueExact,
		)
		if err != nil {
			return ldapclient.DirectoryAccountStateMapping{}, ErrInvalidInput
		}
		return mapping, nil
	default:
		return ldapclient.DirectoryAccountStateMapping{}, ErrInvalidInput
	}
}

func directoryGIDNumberMapping(configuration Configuration) (ldapclient.DirectoryAttributeName, error) {
	if configuration.NestedGroupMode != NestedGroupModePOSIXMemberUID ||
		configuration.GroupSearchFilter == nil {
		return ldapclient.DirectoryAttributeName{}, nil
	}
	compiled, err := identity.CompileLDAPTemplate(
		identity.LDAPTemplateContextPOSIXGroupSearchFilter,
		*configuration.GroupSearchFilter,
	)
	if err != nil {
		return ldapclient.DirectoryAttributeName{}, ErrInvalidInput
	}
	requirements, err := compiled.Requirements()
	if err != nil || !requirements.Username {
		return ldapclient.DirectoryAttributeName{}, ErrInvalidInput
	}
	if !requirements.GIDNumber {
		return ldapclient.DirectoryAttributeName{}, nil
	}
	if configuration.POSIXGIDNumberAttribute == nil {
		return ldapclient.DirectoryAttributeName{}, ErrInvalidInput
	}
	return requiredDirectoryAttribute(*configuration.POSIXGIDNumberAttribute)
}

func requiredDirectoryAttribute(value string) (ldapclient.DirectoryAttributeName, error) {
	attribute, err := ldapclient.NewDirectoryAttributeName(value)
	if err != nil {
		return ldapclient.DirectoryAttributeName{}, ErrInvalidInput
	}
	return attribute, nil
}

func optionalDirectoryAttribute(value *string) (ldapclient.DirectoryAttributeName, error) {
	if value == nil {
		return ldapclient.DirectoryAttributeName{}, nil
	}
	return requiredDirectoryAttribute(*value)
}

func mapDirectoryNormalizationError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ldapclient.ErrInvalidDirectoryNormalization) {
		return ErrUnavailable
	}
	return mapRepositoryError(err)
}

// BuildDirectoryNormalizationConfiguration exposes the same canonical
// normalizer used by LDAP dry-runs and synchronization to interactive login.
func BuildDirectoryNormalizationConfiguration(
	configuration Configuration,
	username string,
) (ldapclient.DirectoryNormalizationConfiguration, error) {
	return directoryNormalizationConfiguration(configuration, username)
}
