package ldapclient

import (
	"bytes"
	"errors"
	"slices"
	"strconv"
	"unicode"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"
	"golang.org/x/text/cases"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

// ErrInvalidDirectoryNormalization combines invalid configuration, malformed
// directory values, cardinality violations, and exceeded bounds. It never
// identifies the responsible attribute or reflects a directory value.
var ErrInvalidDirectoryNormalization = errors.New("invalid LDAP directory normalization")

const (
	maximumDirectoryNormalizationAttributes = maximumDirectoryAttributes * (maximumDirectoryGroups + 1)
	maximumDirectoryNormalizationValues     = 1_000_000
)

// DirectoryAttributeName is a parsed, canonical LDAP attribute description.
// Its value remains private so configuration cannot be accidentally logged.
type DirectoryAttributeName struct {
	value string
	valid bool
}

// NewDirectoryAttributeName validates and canonicalizes an LDAP attribute
// description. Attribute names are matched case-insensitively by their ASCII
// lowercase form.
func NewDirectoryAttributeName(value string) (DirectoryAttributeName, error) {
	normalized, err := normalizeOptionalDirectoryAttribute(value)
	if err != nil || normalized == "" {
		return DirectoryAttributeName{}, ErrInvalidDirectoryNormalization
	}
	return DirectoryAttributeName{value: normalized, valid: true}, nil
}

// String exposes presence only, never the configured schema attribute.
func (name DirectoryAttributeName) String() string {
	return "ldapclient.DirectoryAttributeName{configured=" + strconv.FormatBool(name.valid) + "}"
}

// GoString applies the same redaction to %#v.
func (name DirectoryAttributeName) GoString() string { return name.String() }

// DirectoryProfileAttributeMapping is the closed profile projection. A zero
// attribute name means that field is not mapped. Profile fields are never
// considered immutable identity aliases.
type DirectoryProfileAttributeMapping struct {
	FirstName         DirectoryAttributeName
	LastName          DirectoryAttributeName
	DisplayName       DirectoryAttributeName
	Username          DirectoryAttributeName
	AlternateUsername DirectoryAttributeName
	Email             DirectoryAttributeName
}

// String exposes only the number of configured profile projections.
func (mapping DirectoryProfileAttributeMapping) String() string {
	return "ldapclient.DirectoryProfileAttributeMapping{configured=" +
		strconv.Itoa(mapping.configuredCount()) + "}"
}

// GoString applies the same redaction to %#v.
func (mapping DirectoryProfileAttributeMapping) GoString() string { return mapping.String() }

// DirectorySubjectMode is the closed set of immutable-subject
// canonicalization profiles supported by the identity domain.
type DirectorySubjectMode uint8

const (
	DirectorySubjectADObjectGUID DirectorySubjectMode = iota + 1
	DirectorySubjectEntryUUID
	DirectorySubjectUTF8Exact
	DirectorySubjectUTF8CaseFold
)

// DirectorySubjectMapping binds exactly one configured attribute to one
// immutable-subject canonicalization profile. Its fields are private so only
// the validating constructor can create a usable mapping.
type DirectorySubjectMapping struct {
	mode      DirectorySubjectMode
	attribute DirectoryAttributeName
}

// NewDirectorySubjectMapping creates a closed immutable-subject mapping.
func NewDirectorySubjectMapping(
	mode DirectorySubjectMode,
	attribute DirectoryAttributeName,
) (DirectorySubjectMapping, error) {
	if !knownDirectorySubjectMode(mode) || !attribute.validValue() {
		return DirectorySubjectMapping{}, ErrInvalidDirectoryNormalization
	}
	return DirectorySubjectMapping{mode: mode, attribute: attribute}, nil
}

// String exposes only the safe canonicalization category and presence.
func (mapping DirectorySubjectMapping) String() string {
	return "ldapclient.DirectorySubjectMapping{mode=" + safeDirectorySubjectMode(mapping.mode) +
		",attribute=" + strconv.FormatBool(mapping.attribute.validValue()) + "}"
}

// GoString applies the same redaction to %#v.
func (mapping DirectorySubjectMapping) GoString() string { return mapping.String() }

// DirectoryValueComparison is the closed text comparison used by a
// configured OpenLDAP lock marker.
type DirectoryValueComparison uint8

const (
	DirectoryValueExact DirectoryValueComparison = iota + 1
	DirectoryValueCaseFold
)

// DirectoryAccountStateMode is the closed set of directory account-state
// interpretations. Schema attribute names and OpenLDAP marker values always
// come from validated configuration rather than provider-template defaults.
type DirectoryAccountStateMode uint8

const (
	directoryAccountAlwaysActive DirectoryAccountStateMode = iota + 1
	directoryAccountADUserAccountControl
	directoryAccountOpenLDAPPresence
	directoryAccountOpenLDAPValue
	directoryAccountPOSIXShadowExpire
)

// DirectoryAccountStateMapping is constructor-only. Marker bytes are copied
// and never exposed by formatting.
type DirectoryAccountStateMapping struct {
	mode          DirectoryAccountStateMode
	attribute     DirectoryAttributeName
	comparison    DirectoryValueComparison
	disabledValue []byte
	evaluationDay uint32
	valid         bool
}

// DirectoryAlwaysActiveAccountState explicitly disables directory account
// state evaluation. The explicit constructor distinguishes this policy from a
// missing or corrupted zero-value configuration.
func DirectoryAlwaysActiveAccountState() DirectoryAccountStateMapping {
	return DirectoryAccountStateMapping{mode: directoryAccountAlwaysActive, valid: true}
}

// NewDirectoryADAccountState configures the Active Directory
// userAccountControl-compatible bit-field evaluator. The configured attribute
// must contain exactly one canonical unsigned 32-bit decimal value; bit 0x2
// denotes a disabled account.
func NewDirectoryADAccountState(
	attribute DirectoryAttributeName,
) (DirectoryAccountStateMapping, error) {
	if !attribute.validValue() {
		return DirectoryAccountStateMapping{}, ErrInvalidDirectoryNormalization
	}
	return DirectoryAccountStateMapping{
		mode: directoryAccountADUserAccountControl, attribute: attribute, valid: true,
	}, nil
}

// NewDirectoryOpenLDAPPresenceAccountState configures a lock attribute whose
// presence means disabled and whose absence means active. A present attribute
// must have exactly one value.
func NewDirectoryOpenLDAPPresenceAccountState(
	attribute DirectoryAttributeName,
) (DirectoryAccountStateMapping, error) {
	if !attribute.validValue() {
		return DirectoryAccountStateMapping{}, ErrInvalidDirectoryNormalization
	}
	return DirectoryAccountStateMapping{
		mode: directoryAccountOpenLDAPPresence, attribute: attribute, valid: true,
	}, nil
}

// NewDirectoryOpenLDAPValueAccountState configures an exact or Unicode
// case-folded lock-marker comparison. The constructor takes a private copy of
// disabledValue. Absence means active; a present attribute must be scalar.
func NewDirectoryOpenLDAPValueAccountState(
	attribute DirectoryAttributeName,
	disabledValue []byte,
	comparison DirectoryValueComparison,
) (DirectoryAccountStateMapping, error) {
	if !attribute.validValue() || !validDirectoryAccountMarker(disabledValue) ||
		comparison != DirectoryValueExact && comparison != DirectoryValueCaseFold {
		return DirectoryAccountStateMapping{}, ErrInvalidDirectoryNormalization
	}
	return DirectoryAccountStateMapping{
		mode:          directoryAccountOpenLDAPValue,
		attribute:     attribute,
		comparison:    comparison,
		disabledValue: append([]byte(nil), disabledValue...),
		valid:         true,
	}, nil
}

// NewDirectoryPOSIXShadowExpireAccountState configures the RFC 2307
// shadowExpire evaluator. evaluationDay is supplied by the caller for a
// deterministic snapshot. Absent and -1 mean no expiry; a non-negative value
// at or before evaluationDay means disabled.
func NewDirectoryPOSIXShadowExpireAccountState(
	attribute DirectoryAttributeName,
	evaluationDay uint32,
) (DirectoryAccountStateMapping, error) {
	if !attribute.validValue() {
		return DirectoryAccountStateMapping{}, ErrInvalidDirectoryNormalization
	}
	return DirectoryAccountStateMapping{
		mode: directoryAccountPOSIXShadowExpire, attribute: attribute,
		evaluationDay: evaluationDay, valid: true,
	}, nil
}

// String exposes only the closed evaluator category and safe presence bits.
func (mapping DirectoryAccountStateMapping) String() string {
	return "ldapclient.DirectoryAccountStateMapping{mode=" + safeDirectoryAccountStateMode(mapping.mode) +
		",attribute=" + strconv.FormatBool(mapping.attribute.validValue()) +
		",marker=" + strconv.FormatBool(len(mapping.disabledValue) != 0) + "}"
}

// GoString applies the same redaction to %#v.
func (mapping DirectoryAccountStateMapping) GoString() string { return mapping.String() }

// DirectoryNormalizationConfiguration is the complete, typed projection from
// one value-owning raw directory observation to the identity-domain snapshot.
// GIDNumberAttribute is zero unless a configured POSIX group template
// requires gidNumber.
type DirectoryNormalizationConfiguration struct {
	LoginUsername      identity.LDAPUsername
	Profile            DirectoryProfileAttributeMapping
	Subject            DirectorySubjectMapping
	AccountState       DirectoryAccountStateMapping
	GIDNumberAttribute DirectoryAttributeName
}

// String exposes configuration shape only.
func (configuration DirectoryNormalizationConfiguration) String() string {
	return "ldapclient.DirectoryNormalizationConfiguration{profile_attributes=" +
		strconv.Itoa(configuration.Profile.configuredCount()) +
		",subject_mode=" + safeDirectorySubjectMode(configuration.Subject.mode) +
		",subject_attribute=" + strconv.FormatBool(configuration.Subject.attribute.validValue()) +
		",account_mode=" + safeDirectoryAccountStateMode(configuration.AccountState.mode) +
		",account_attribute=" + strconv.FormatBool(configuration.AccountState.attribute.validValue()) +
		",gid_required=" + strconv.FormatBool(configuration.GIDNumberAttribute.validValue()) + "}"
}

// GoString applies the same redaction to %#v.
func (configuration DirectoryNormalizationConfiguration) GoString() string {
	return configuration.String()
}

// RequiredUserAttributes returns a sorted, duplicate-free copy of the exact
// schema attributes that the bounded directory search must request. Callers
// must not log the returned configuration values.
func (configuration DirectoryNormalizationConfiguration) RequiredUserAttributes() ([]string, error) {
	if !configuration.valid() {
		return nil, ErrInvalidDirectoryNormalization
	}
	attributes := make([]string, 0, 10)
	for _, attribute := range configuration.allAttributes() {
		if attribute.validValue() {
			attributes = append(attributes, attribute.value)
		}
	}
	slices.Sort(attributes)
	return slices.Compact(attributes), nil
}

// DirectoryUsernameFromEntry extracts the configured scalar username from one
// already enumerated user entry and returns it through the typed escaping
// boundary used by ObserveDirectory. The complete entry shape and bounds are
// revalidated; no raw attribute value is returned or formatted.
func DirectoryUsernameFromEntry(
	attribute DirectoryAttributeName,
	entry DirectoryEntry,
) (identity.LDAPUsername, error) {
	if !attribute.validValue() {
		return identity.LDAPUsername{}, ErrInvalidDirectoryNormalization
	}
	budget := directoryNormalizationBudget{
		remainingBytes:      maximumDirectoryResponseBytes,
		remainingAttributes: maximumDirectoryNormalizationAttributes,
		remainingValues:     maximumDirectoryNormalizationValues,
	}
	_, attributes, err := normalizeDirectoryEntryShape(entry, &budget)
	if err != nil {
		return identity.LDAPUsername{}, ErrInvalidDirectoryNormalization
	}
	values, present := attributes[attribute.value]
	if !present || len(values) != 1 || !utf8.Valid(values[0]) {
		return identity.LDAPUsername{}, ErrInvalidDirectoryNormalization
	}
	username, err := identity.NewLDAPUsername(string(values[0]))
	if err != nil {
		return identity.LDAPUsername{}, ErrInvalidDirectoryNormalization
	}
	return username, nil
}

// NormalizeDirectoryObservation is the only raw-directory to identity-domain
// conversion. It validates bounds again, enforces scalar cardinality, parses
// and canonicalizes every DN, and makes the returned observation independent
// of all caller-owned slices. Email, usernames, and DNs are profile/runtime
// inputs only and are never substituted for the configured immutable subject.
func NormalizeDirectoryObservation(
	configuration DirectoryNormalizationConfiguration,
	raw DirectoryObservation,
) (identity.LDAPObservation, error) {
	if !configuration.valid() || len(raw.Groups) > maximumDirectoryGroups {
		return identity.LDAPObservation{}, ErrInvalidDirectoryNormalization
	}

	budget := directoryNormalizationBudget{
		remainingBytes:      maximumDirectoryResponseBytes,
		remainingAttributes: maximumDirectoryNormalizationAttributes,
		remainingValues:     maximumDirectoryNormalizationValues,
	}
	parsedUserDN, attributes, err := normalizeDirectoryEntryShape(raw.User, &budget)
	if err != nil {
		return identity.LDAPObservation{}, ErrInvalidDirectoryNormalization
	}
	userDN, err := identity.ParseLDAPDistinguishedName(parsedUserDN.String())
	if err != nil {
		return identity.LDAPObservation{}, ErrInvalidDirectoryNormalization
	}

	subjectValues, found := attributes[configuration.Subject.attribute.value]
	if !found || len(subjectValues) != 1 {
		return identity.LDAPObservation{}, ErrInvalidDirectoryNormalization
	}
	subject, err := normalizeDirectorySubject(configuration.Subject.mode, subjectValues[0])
	if err != nil {
		return identity.LDAPObservation{}, ErrInvalidDirectoryNormalization
	}
	defer subject.Clear()

	profile, err := normalizeDirectoryProfile(configuration.Profile, attributes)
	if err != nil {
		return identity.LDAPObservation{}, ErrInvalidDirectoryNormalization
	}
	accountState, err := normalizeDirectoryAccountState(configuration.AccountState, attributes)
	if err != nil {
		return identity.LDAPObservation{}, ErrInvalidDirectoryNormalization
	}

	var gidNumber *identity.LDAPGIDNumber
	if configuration.GIDNumberAttribute.validValue() {
		values, present := attributes[configuration.GIDNumberAttribute.value]
		if !present || len(values) != 1 || !utf8.Valid(values[0]) {
			return identity.LDAPObservation{}, ErrInvalidDirectoryNormalization
		}
		parsed, parseErr := identity.ParseLDAPGIDNumber(string(values[0]))
		if parseErr != nil {
			return identity.LDAPObservation{}, ErrInvalidDirectoryNormalization
		}
		gidNumber = &parsed
	}

	groups, err := normalizeDirectoryGroupDNs(raw.Groups, &budget)
	if err != nil {
		return identity.LDAPObservation{}, ErrInvalidDirectoryNormalization
	}
	observation, err := identity.NewLDAPObservation(identity.LDAPObservationInput{
		Subject:       subject,
		UserDN:        userDN,
		LoginUsername: configuration.LoginUsername,
		Profile:       profile,
		Groups:        groups,
		GIDNumber:     gidNumber,
		AccountState:  accountState,
		Complete:      true,
	})
	if err != nil {
		return identity.LDAPObservation{}, ErrInvalidDirectoryNormalization
	}
	return observation, nil
}

type directoryNormalizationBudget struct {
	remainingBytes      int
	remainingAttributes int
	remainingValues     int
}

func (budget *directoryNormalizationBudget) consumeBytes(count int) bool {
	if budget == nil || count < 0 || count > budget.remainingBytes {
		return false
	}
	budget.remainingBytes -= count
	return true
}

func (budget *directoryNormalizationBudget) consumeShape(attributes, values int) bool {
	if budget == nil || attributes < 0 || values < 0 ||
		attributes > budget.remainingAttributes || values > budget.remainingValues {
		return false
	}
	budget.remainingAttributes -= attributes
	budget.remainingValues -= values
	return true
}

func normalizeDirectoryEntryShape(
	entry DirectoryEntry,
	budget *directoryNormalizationBudget,
) (*ldap.DN, map[string][][]byte, error) {
	if len(entry.Attributes) > maximumDirectoryAttributes ||
		!budget.consumeShape(len(entry.Attributes), 0) ||
		!budget.consumeBytes(len(entry.DistinguishedName)) {
		return nil, nil, ErrInvalidDirectoryNormalization
	}
	parsed, err := parseBoundedDN(entry.DistinguishedName)
	if err != nil {
		return nil, nil, ErrInvalidDirectoryNormalization
	}
	if len(entry.Attributes) == 0 {
		return parsed, nil, nil
	}

	attributes := make(map[string][][]byte, len(entry.Attributes))
	for _, attribute := range entry.Attributes {
		name, nameErr := normalizeOptionalDirectoryAttribute(attribute.Name)
		if nameErr != nil || name == "" || len(attribute.Values) > maximumDirectoryValuesPerAttribute ||
			!budget.consumeShape(0, len(attribute.Values)) ||
			!budget.consumeBytes(len(name)) {
			return nil, nil, ErrInvalidDirectoryNormalization
		}
		if _, collision := attributes[name]; collision {
			return nil, nil, ErrInvalidDirectoryNormalization
		}
		for _, value := range attribute.Values {
			if len(value) > maximumDirectoryAttributeValueBytes || !budget.consumeBytes(len(value)) {
				return nil, nil, ErrInvalidDirectoryNormalization
			}
		}
		attributes[name] = attribute.Values
	}
	return parsed, attributes, nil
}

func normalizeDirectoryGroupDNs(
	entries []DirectoryEntry,
	budget *directoryNormalizationBudget,
) ([]identity.LDAPDistinguishedName, error) {
	canonicalByKey := make(map[string]string, len(entries))
	for _, entry := range entries {
		parsed, _, err := normalizeDirectoryEntryShape(entry, budget)
		if err != nil {
			return nil, ErrInvalidDirectoryNormalization
		}
		// The package-local fold key collapses semantically equal case variants
		// deterministically before the identity constructor.
		canonical := parsed.String()
		key := directoryDNKey(parsed)
		if existing, duplicate := canonicalByKey[key]; !duplicate || canonical < existing {
			canonicalByKey[key] = canonical
		}
	}
	keys := make([]string, 0, len(canonicalByKey))
	for key := range canonicalByKey {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	groups := make([]identity.LDAPDistinguishedName, 0, len(keys))
	for _, key := range keys {
		dn, err := identity.ParseLDAPDistinguishedName(canonicalByKey[key])
		if err != nil {
			return nil, ErrInvalidDirectoryNormalization
		}
		groups = append(groups, dn)
	}
	return groups, nil
}

func normalizeDirectorySubject(mode DirectorySubjectMode, value []byte) (identity.Subject, error) {
	switch mode {
	case DirectorySubjectADObjectGUID:
		return identity.CanonicalADObjectGUID(value)
	case DirectorySubjectEntryUUID:
		if !utf8.Valid(value) {
			return identity.Subject{}, ErrInvalidDirectoryNormalization
		}
		return identity.CanonicalEntryUUID(string(value))
	case DirectorySubjectUTF8Exact:
		return identity.CanonicalUTF8Exact(value)
	case DirectorySubjectUTF8CaseFold:
		return identity.CanonicalUTF8CaseFold(value)
	default:
		return identity.Subject{}, ErrInvalidDirectoryNormalization
	}
}

func normalizeDirectoryProfile(
	mapping DirectoryProfileAttributeMapping,
	attributes map[string][][]byte,
) (identity.LDAPProfileValues, error) {
	result := identity.LDAPProfileValues{}
	fields := []struct {
		attribute   DirectoryAttributeName
		destination **string
	}{
		{mapping.FirstName, &result.FirstName},
		{mapping.LastName, &result.LastName},
		{mapping.DisplayName, &result.DisplayName},
		{mapping.Username, &result.Username},
		{mapping.AlternateUsername, &result.AlternateUsername},
		{mapping.Email, &result.Email},
	}
	for _, field := range fields {
		if !field.attribute.validValue() {
			continue
		}
		values, present := attributes[field.attribute.value]
		if !present {
			continue
		}
		if len(values) != 1 || !utf8.Valid(values[0]) {
			return identity.LDAPProfileValues{}, ErrInvalidDirectoryNormalization
		}
		value := string(values[0])
		*field.destination = &value
	}
	return result, nil
}

func normalizeDirectoryAccountState(
	mapping DirectoryAccountStateMapping,
	attributes map[string][][]byte,
) (identity.LDAPAccountState, error) {
	if mapping.mode == directoryAccountAlwaysActive {
		return identity.LDAPAccountActive, nil
	}
	values, present := attributes[mapping.attribute.value]
	if !present {
		switch mapping.mode {
		case directoryAccountOpenLDAPPresence,
			directoryAccountOpenLDAPValue,
			directoryAccountPOSIXShadowExpire:
			return identity.LDAPAccountActive, nil
		default:
			return 0, ErrInvalidDirectoryNormalization
		}
	}
	if len(values) != 1 {
		return 0, ErrInvalidDirectoryNormalization
	}
	value := values[0]
	switch mapping.mode {
	case directoryAccountADUserAccountControl:
		if !utf8.Valid(value) {
			return 0, ErrInvalidDirectoryNormalization
		}
		flags, err := strconv.ParseUint(string(value), 10, 32)
		if err != nil || strconv.FormatUint(flags, 10) != string(value) {
			return 0, ErrInvalidDirectoryNormalization
		}
		if flags&0x2 != 0 {
			return identity.LDAPAccountDisabled, nil
		}
		return identity.LDAPAccountActive, nil
	case directoryAccountOpenLDAPPresence:
		if !utf8.Valid(value) {
			return 0, ErrInvalidDirectoryNormalization
		}
		return identity.LDAPAccountDisabled, nil
	case directoryAccountOpenLDAPValue:
		if !utf8.Valid(value) {
			return 0, ErrInvalidDirectoryNormalization
		}
		matched := bytes.Equal(value, mapping.disabledValue)
		if mapping.comparison == DirectoryValueCaseFold {
			matched = cases.Fold().String(string(value)) ==
				cases.Fold().String(string(mapping.disabledValue))
		}
		if matched {
			return identity.LDAPAccountDisabled, nil
		}
		return identity.LDAPAccountActive, nil
	case directoryAccountPOSIXShadowExpire:
		if !utf8.Valid(value) {
			return 0, ErrInvalidDirectoryNormalization
		}
		text := string(value)
		if text == "-1" {
			return identity.LDAPAccountActive, nil
		}
		day, err := strconv.ParseUint(text, 10, 32)
		if err != nil || strconv.FormatUint(day, 10) != text {
			return 0, ErrInvalidDirectoryNormalization
		}
		if day <= uint64(mapping.evaluationDay) {
			return identity.LDAPAccountDisabled, nil
		}
		return identity.LDAPAccountActive, nil
	default:
		return 0, ErrInvalidDirectoryNormalization
	}
}

func (configuration DirectoryNormalizationConfiguration) valid() bool {
	if !configuration.Subject.attribute.validValue() ||
		!knownDirectorySubjectMode(configuration.Subject.mode) ||
		!configuration.AccountState.validValue() ||
		!configuration.GIDNumberAttribute.zeroOrValid() {
		return false
	}
	for _, attribute := range configuration.Profile.attributes() {
		if !attribute.zeroOrValid() {
			return false
		}
	}
	return true
}

func (configuration DirectoryNormalizationConfiguration) allAttributes() []DirectoryAttributeName {
	attributes := configuration.Profile.attributes()
	attributes = append(attributes, configuration.Subject.attribute)
	if configuration.AccountState.attribute.validValue() {
		attributes = append(attributes, configuration.AccountState.attribute)
	}
	if configuration.GIDNumberAttribute.validValue() {
		attributes = append(attributes, configuration.GIDNumberAttribute)
	}
	return attributes
}

func (mapping DirectoryProfileAttributeMapping) attributes() []DirectoryAttributeName {
	return []DirectoryAttributeName{
		mapping.FirstName,
		mapping.LastName,
		mapping.DisplayName,
		mapping.Username,
		mapping.AlternateUsername,
		mapping.Email,
	}
}

func (mapping DirectoryProfileAttributeMapping) configuredCount() int {
	count := 0
	for _, attribute := range mapping.attributes() {
		if attribute.validValue() {
			count++
		}
	}
	return count
}

func (name DirectoryAttributeName) validValue() bool {
	if !name.valid {
		return false
	}
	normalized, err := normalizeOptionalDirectoryAttribute(name.value)
	return err == nil && normalized == name.value
}

func (name DirectoryAttributeName) zeroOrValid() bool {
	return !name.valid && name.value == "" || name.validValue()
}

func (mapping DirectoryAccountStateMapping) validValue() bool {
	if !mapping.valid {
		return false
	}
	switch mapping.mode {
	case directoryAccountAlwaysActive:
		return !mapping.attribute.valid && mapping.attribute.value == "" &&
			mapping.comparison == 0 && len(mapping.disabledValue) == 0 && mapping.evaluationDay == 0
	case directoryAccountADUserAccountControl,
		directoryAccountOpenLDAPPresence:
		return mapping.attribute.validValue() && mapping.comparison == 0 &&
			len(mapping.disabledValue) == 0 && mapping.evaluationDay == 0
	case directoryAccountPOSIXShadowExpire:
		return mapping.attribute.validValue() && mapping.comparison == 0 && len(mapping.disabledValue) == 0
	case directoryAccountOpenLDAPValue:
		return mapping.attribute.validValue() && validDirectoryAccountMarker(mapping.disabledValue) &&
			(mapping.comparison == DirectoryValueExact || mapping.comparison == DirectoryValueCaseFold) &&
			mapping.evaluationDay == 0
	default:
		return false
	}
}

func validDirectoryAccountMarker(value []byte) bool {
	if len(value) == 0 || len(value) > maximumDirectoryAttributeValueBytes || !utf8.Valid(value) {
		return false
	}
	for _, character := range string(value) {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func knownDirectorySubjectMode(mode DirectorySubjectMode) bool {
	switch mode {
	case DirectorySubjectADObjectGUID,
		DirectorySubjectEntryUUID,
		DirectorySubjectUTF8Exact,
		DirectorySubjectUTF8CaseFold:
		return true
	default:
		return false
	}
}

func safeDirectorySubjectMode(mode DirectorySubjectMode) string {
	switch mode {
	case DirectorySubjectADObjectGUID:
		return "ad_object_guid"
	case DirectorySubjectEntryUUID:
		return "entry_uuid"
	case DirectorySubjectUTF8Exact:
		return "utf8_exact"
	case DirectorySubjectUTF8CaseFold:
		return "utf8_casefold"
	default:
		return "unknown"
	}
}

func safeDirectoryAccountStateMode(mode DirectoryAccountStateMode) string {
	switch mode {
	case directoryAccountAlwaysActive:
		return "always_active"
	case directoryAccountADUserAccountControl:
		return "ad_user_account_control"
	case directoryAccountOpenLDAPPresence:
		return "openldap_presence"
	case directoryAccountOpenLDAPValue:
		return "openldap_value"
	case directoryAccountPOSIXShadowExpire:
		return "posix_shadow_expire"
	default:
		return "unknown"
	}
}
