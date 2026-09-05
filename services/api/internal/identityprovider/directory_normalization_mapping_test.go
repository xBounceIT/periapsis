package identityprovider

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestDirectoryNormalizationConfigurationUsesExactCanonicalAttributes(t *testing.T) {
	t.Parallel()

	configuration := testConfiguration()
	configuration.AlternateUsernameAttribute = stringPointer("mailAlias")
	configuration.EmailAttribute = stringPointer("mail")
	configuration.AccountStatusMode = AccountStatusModeActiveDirectoryUAC
	configuration.AccountStatusAttribute = stringPointer("userAccountControl")
	configuration.ImmutableSubjectFormat = SubjectFormatADObjectGUID
	configuration.ImmutableSubjectAttribute = "objectGUID"

	mapped, err := directoryNormalizationConfiguration(configuration, "alice")
	if err != nil {
		t.Fatalf("directoryNormalizationConfiguration() error = %v", err)
	}
	attributes, err := mapped.RequiredUserAttributes()
	if err != nil {
		t.Fatalf("RequiredUserAttributes() error = %v", err)
	}
	want := []string{
		"displayname", "givenname", "mail", "mailalias", "objectguid", "sn", "uid", "useraccountcontrol",
	}
	if !slices.Equal(attributes, want) {
		t.Fatalf("attributes = %v, want %v", attributes, want)
	}
}

func TestDirectoryNormalizationConfigurationMapsCanonicalAttributeEqualsExactly(t *testing.T) {
	t.Parallel()

	configuration := testConfiguration()
	configuration.AccountStatusMode = AccountStatusModeAttributeEquals
	configuration.AccountStatusAttribute = stringPointer("pwdAccountLockedTime")
	configuration.AccountDisabledValue = stringPointer("LOCKED")
	if _, err := directoryNormalizationConfiguration(configuration, "alice"); err != nil {
		t.Fatalf("attribute-equals mapping error = %v", err)
	}

	configuration.AccountDisabledValue = nil
	if _, err := directoryNormalizationConfiguration(configuration, "alice"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing disabled marker error = %v", err)
	}
}

func TestDirectoryNormalizationConfigurationRequiresConfiguredPOSIXGIDAttribute(t *testing.T) {
	t.Parallel()

	configuration := testConfiguration()
	configuration.NestedGroupMode = NestedGroupModePOSIXMemberUID
	configuration.MaxNestedGroupDepth = 1
	configuration.GroupSearchFilter = stringPointer(
		"(|(memberUid={username})(gidNumber={gidNumber}))",
	)
	if _, err := directoryNormalizationConfiguration(configuration, "alice"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing gidNumber attribute error = %v", err)
	}
	configuration.POSIXGIDNumberAttribute = stringPointer("gidNumber")
	mapped, err := directoryNormalizationConfiguration(configuration, "alice")
	if err != nil {
		t.Fatalf("POSIX mapping error = %v", err)
	}
	attributes, err := mapped.RequiredUserAttributes()
	if err != nil || !slices.Contains(attributes, "gidnumber") {
		t.Fatalf("POSIX attributes = %v, %v", attributes, err)
	}
}

func TestDirectoryNormalizationConfigurationRejectsUnknownModesWithoutReflectingValues(t *testing.T) {
	t.Parallel()

	configuration := testConfiguration()
	configuration.ImmutableSubjectAttribute = "sensitiveImmutableAttribute"
	configuration.ImmutableSubjectFormat = "future-subject-mode"
	_, err := directoryNormalizationConfiguration(configuration, "sensitive-login")
	if !errors.Is(err, ErrInvalidInput) ||
		containsAny(err.Error(), "sensitiveImmutableAttribute", "sensitive-login") {
		t.Fatalf("unredacted mapping error = %v", err)
	}
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if candidate != "" && strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}
