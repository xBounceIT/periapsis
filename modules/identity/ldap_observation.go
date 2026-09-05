package identity

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrInvalidLDAPObservation deliberately does not identify an attribute or
// value. Administrative diagnostics expose only bounded presence metadata.
var ErrInvalidLDAPObservation = errors.New("invalid LDAP observation")

const (
	maximumLDAPObservationGroups      = 10_000
	maximumLDAPProfileFieldCharacters = 1024
	maximumLDAPProfileFieldBytes      = 4096
	maximumLDAPProfileEmailCharacters = 320
	maximumLDAPProfileEmailBytes      = 1280
)

// LDAPAccountState is the normalized admission state, not a raw directory
// status value.
type LDAPAccountState uint8

const (
	LDAPAccountActive LDAPAccountState = iota + 1
	LDAPAccountDisabled
)

// LDAPProfileField is the closed set of provider-owned tenant-profile fields.
type LDAPProfileField uint8

const (
	LDAPProfileFirstName LDAPProfileField = iota + 1
	LDAPProfileLastName
	LDAPProfileDisplayName
	LDAPProfileUsername
	LDAPProfileAlternateUsername
	LDAPProfileEmail
)

// LDAPProfileValues contains already cardinality-checked scalar attributes.
// Nil means the configured attribute was absent, not an empty string.
type LDAPProfileValues struct {
	FirstName         *string
	LastName          *string
	DisplayName       *string
	Username          *string
	AlternateUsername *string
	Email             *string
}

// String redacts every directory value while retaining safe presence bits.
func (values LDAPProfileValues) String() string {
	return fmt.Sprintf(
		"identity.LDAPProfileValues{firstName:%t,lastName:%t,displayName:%t,username:%t,alternateUsername:%t,email:%t}",
		values.FirstName != nil,
		values.LastName != nil,
		values.DisplayName != nil,
		values.Username != nil,
		values.AlternateUsername != nil,
		values.Email != nil,
	)
}

// GoString uses the same redacted representation for %#v formatting.
func (values LDAPProfileValues) GoString() string { return values.String() }

// LDAPObservationInput is the provider-neutral result of bounded LDAP
// attribute cardinality handling. Complete is true only when every configured
// lookup/group traversal finished without truncation.
type LDAPObservationInput struct {
	Subject       Subject
	UserDN        LDAPDistinguishedName
	LoginUsername LDAPUsername
	Profile       LDAPProfileValues
	Groups        []LDAPDistinguishedName
	GIDNumber     *LDAPGIDNumber
	AccountState  LDAPAccountState
	Complete      bool
}

func (input LDAPObservationInput) String() string {
	return fmt.Sprintf(
		"identity.LDAPObservationInput{subjectFormat:%d,profile:%s,groupCount:%d,accountState:%d,complete:%t,values:[REDACTED]}",
		input.Subject.Format(), input.Profile, len(input.Groups), input.AccountState, input.Complete,
	)
}
func (input LDAPObservationInput) GoString() string { return input.String() }

// LDAPObservation owns a deterministic, sorted, duplicate-free snapshot. Its
// customer values are private and formatting is redacted.
type LDAPObservation struct {
	subject       Subject
	userDN        LDAPDistinguishedName
	loginUsername LDAPUsername
	profile       LDAPProfileValues
	groups        []LDAPDistinguishedName
	gidNumber     *LDAPGIDNumber
	accountState  LDAPAccountState
	complete      bool
}

// NewLDAPObservation validates the normalized shape and takes copies of all
// slice- and pointer-backed input owned by the caller.
func NewLDAPObservation(input LDAPObservationInput) (LDAPObservation, error) {
	if !validCanonicalSubject(input.Subject) || !input.UserDN.valid || input.UserDN.dn == nil ||
		input.UserDN.dn.String() != input.UserDN.value || !validLDAPCanonicalDN(input.UserDN.value) ||
		!input.LoginUsername.valid || !validLDAPRuntimeText(
		input.LoginUsername.value,
		maximumLDAPUsernameCharacters,
		maximumLDAPUsernameBytes,
	) || (input.AccountState != LDAPAccountActive && input.AccountState != LDAPAccountDisabled) ||
		len(input.Groups) > maximumLDAPObservationGroups {
		return LDAPObservation{}, ErrInvalidLDAPObservation
	}
	profile, err := normalizeLDAPProfile(input.Profile)
	if err != nil {
		return LDAPObservation{}, err
	}
	groups := append([]LDAPDistinguishedName(nil), input.Groups...)
	for _, group := range groups {
		if !group.valid || group.dn == nil || group.dn.String() != group.value ||
			len(group.value) > maximumLDAPGroupCanonicalDNBytes {
			return LDAPObservation{}, ErrInvalidLDAPObservation
		}
	}
	slices.SortFunc(groups, func(left, right LDAPDistinguishedName) int {
		return strings.Compare(left.value, right.value)
	})
	groups = slices.CompactFunc(groups, func(left, right LDAPDistinguishedName) bool {
		return left.value == right.value
	})
	var gidNumber *LDAPGIDNumber
	if input.GIDNumber != nil {
		if !input.GIDNumber.valid {
			return LDAPObservation{}, ErrInvalidLDAPObservation
		}
		copyOfGID := *input.GIDNumber
		gidNumber = &copyOfGID
	}
	subject := Subject{
		format: input.Subject.format,
		value:  append([]byte(nil), input.Subject.value...),
	}
	return LDAPObservation{
		subject: subject, userDN: input.UserDN, loginUsername: input.LoginUsername,
		profile: profile, groups: groups, gidNumber: gidNumber,
		accountState: input.AccountState, complete: input.Complete,
	}, nil
}

// String exposes only safe counts/state.
func (observation LDAPObservation) String() string {
	return "identity.LDAPObservation{subjectFormat:" + strconv.Itoa(int(observation.subject.format)) +
		",groupCount:" + strconv.Itoa(len(observation.groups)) +
		",accountState:" + strconv.Itoa(int(observation.accountState)) +
		",complete:" + strconv.FormatBool(observation.complete) + "}"
}

// GoString uses the same redacted representation for %#v formatting.
func (observation LDAPObservation) GoString() string { return observation.String() }

// Complete reports whether the entire configured directory observation was
// obtained without a bound being hit.
func (observation LDAPObservation) Complete() bool { return observation.complete }

// AccountState returns only the normalized admission state.
func (observation LDAPObservation) AccountState() LDAPAccountState {
	return observation.accountState
}

// SubjectFormat returns metadata without subject bytes.
func (observation LDAPObservation) SubjectFormat() SubjectFormat {
	return observation.subject.format
}

// GroupCount is safe diagnostic metadata.
func (observation LDAPObservation) GroupCount() int { return len(observation.groups) }

// ProfilePresence returns safe configured-field presence metadata.
func (observation LDAPObservation) ProfilePresence() map[LDAPProfileField]bool {
	return map[LDAPProfileField]bool{
		LDAPProfileFirstName:         observation.profile.FirstName != nil,
		LDAPProfileLastName:          observation.profile.LastName != nil,
		LDAPProfileDisplayName:       observation.profile.DisplayName != nil,
		LDAPProfileUsername:          observation.profile.Username != nil,
		LDAPProfileAlternateUsername: observation.profile.AlternateUsername != nil,
		LDAPProfileEmail:             observation.profile.Email != nil,
	}
}

// RevealProfileField is an explicit application boundary for the short
// transactional profile write. Callers must not log or put the returned value
// in a dry-run/audit payload.
func (observation LDAPObservation) RevealProfileField(field LDAPProfileField) (string, bool, error) {
	var value *string
	switch field {
	case LDAPProfileFirstName:
		value = observation.profile.FirstName
	case LDAPProfileLastName:
		value = observation.profile.LastName
	case LDAPProfileDisplayName:
		value = observation.profile.DisplayName
	case LDAPProfileUsername:
		value = observation.profile.Username
	case LDAPProfileAlternateUsername:
		value = observation.profile.AlternateUsername
	case LDAPProfileEmail:
		value = observation.profile.Email
	default:
		return "", false, ErrInvalidLDAPObservation
	}
	if value == nil {
		return "", false, nil
	}
	return *value, true, nil
}

// ProtectSubject creates ciphertext and retained-key lookup aliases without
// exposing canonical subject bytes outside this package.
func (observation LDAPObservation) ProtectSubject(
	keyring Keyring,
	context ExternalSubjectContext,
) (ExternalSubjectEnvelope, []SubjectAlias, error) {
	if !validCanonicalSubject(observation.subject) || validateExternalSubjectContext(context) != nil {
		return ExternalSubjectEnvelope{}, nil, ErrInvalidLDAPObservation
	}
	envelope, err := keyring.EncryptExternalSubject(context, observation.subject)
	if err != nil {
		return ExternalSubjectEnvelope{}, nil, err
	}
	aliases, err := keyring.SubjectAliases(context.Provider, observation.subject)
	if err != nil {
		clear(envelope.Ciphertext)
		return ExternalSubjectEnvelope{}, nil, err
	}
	return envelope, aliases, nil
}

// SubjectAliases returns only provider-qualified, versioned lookup digests for
// a normalized immutable subject. Dry-run and pre-link planning use this
// boundary to find an existing external identity without manufacturing an
// external-identity row ID or exposing canonical subject bytes.
func (observation LDAPObservation) SubjectAliases(
	keyring Keyring,
	provider ProviderContext,
) ([]SubjectAlias, error) {
	if !validCanonicalSubject(observation.subject) || validateProviderContext(provider) != nil {
		return nil, ErrInvalidLDAPObservation
	}
	aliases, err := keyring.SubjectAliases(provider, observation.subject)
	if err != nil {
		return nil, err
	}
	return aliases, nil
}

func (observation LDAPObservation) mappingGroups() []LDAPDistinguishedName {
	return observation.groups
}

func normalizeLDAPProfile(values LDAPProfileValues) (LDAPProfileValues, error) {
	result := LDAPProfileValues{}
	fields := []struct {
		source      *string
		destination **string
		characters  int
		bytes       int
	}{
		{values.FirstName, &result.FirstName, maximumLDAPProfileFieldCharacters, maximumLDAPProfileFieldBytes},
		{values.LastName, &result.LastName, maximumLDAPProfileFieldCharacters, maximumLDAPProfileFieldBytes},
		{values.DisplayName, &result.DisplayName, maximumLDAPProfileFieldCharacters, maximumLDAPProfileFieldBytes},
		{values.Username, &result.Username, maximumLDAPProfileFieldCharacters, maximumLDAPProfileFieldBytes},
		{values.AlternateUsername, &result.AlternateUsername, maximumLDAPProfileFieldCharacters, maximumLDAPProfileFieldBytes},
		{values.Email, &result.Email, maximumLDAPProfileEmailCharacters, maximumLDAPProfileEmailBytes},
	}
	for _, field := range fields {
		if field.source == nil {
			continue
		}
		if !validLDAPProfileText(*field.source, field.characters, field.bytes) {
			return LDAPProfileValues{}, ErrInvalidLDAPObservation
		}
		copyOfValue := *field.source
		*field.destination = &copyOfValue
	}
	return result, nil
}

func validLDAPProfileText(value string, maximumCharacters, maximumBytes int) bool {
	if value == "" || len(value) > maximumBytes || !utf8.ValidString(value) ||
		utf8.RuneCountInString(value) > maximumCharacters {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
