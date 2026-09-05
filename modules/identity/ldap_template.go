package identity

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

// ErrInvalidLDAPTemplate deliberately hides parser positions and directory
// syntax details from callers. Configuration and authentication paths must not
// turn the LDAP parser into an oracle.
var ErrInvalidLDAPTemplate = errors.New("invalid LDAP template")

// LDAPTemplateContext is the closed set of places where v1 permits LDAP
// interpolation. Each context owns its placeholder policy and escaping mode;
// callers cannot supply their own allowlist.
type LDAPTemplateContext uint8

const (
	LDAPTemplateContextUserSearchFilter LDAPTemplateContext = iota + 1
	LDAPTemplateContextUserDN
	LDAPTemplateContextReverseGroupSearchFilter
	LDAPTemplateContextPOSIXGroupSearchFilter
)

type ldapTemplatePlaceholder uint8

const (
	ldapTemplateUsername ldapTemplatePlaceholder = iota + 1
	ldapTemplateUserDN
	ldapTemplateGIDNumber
)

const (
	maximumLDAPFilterTemplateCharacters = 4096
	maximumLDAPDNTemplateCharacters     = 2048
	maximumLDAPUsernameCharacters       = 1024
	maximumLDAPUsernameBytes            = maximumLDAPUsernameCharacters * utf8.UTFMax
	maximumLDAPDNCharacters             = 2048
	maximumLDAPDNBytes                  = maximumLDAPDNCharacters * utf8.UTFMax
)

// LDAPUsername is an exact, bounded external username. It is intentionally not
// a string alias, so a renderer cannot receive an unvalidated raw value.
type LDAPUsername struct {
	value string
	valid bool
}

func (username LDAPUsername) String() string {
	return fmt.Sprintf("identity.LDAPUsername{valid:%t,value:[REDACTED]}", username.valid)
}
func (username LDAPUsername) GoString() string { return username.String() }

// NewLDAPUsername validates without trimming or case-folding. Those operations
// would change directory identity semantics and belong to an explicit provider
// normalizer, not the escaping boundary.
func NewLDAPUsername(value string) (LDAPUsername, error) {
	if !validLDAPRuntimeText(value, maximumLDAPUsernameCharacters, maximumLDAPUsernameBytes) {
		return LDAPUsername{}, ErrInvalidLDAPTemplate
	}
	return LDAPUsername{value: value, valid: true}, nil
}

// LDAPDistinguishedName contains the library-rendered form of a parsed DN.
// Runtime filter interpolation therefore never accepts an unparsed DN string.
type LDAPDistinguishedName struct {
	value string
	dn    *ldap.DN
	valid bool
}

func (dn LDAPDistinguishedName) String() string {
	return fmt.Sprintf("identity.LDAPDistinguishedName{valid:%t,value:[REDACTED]}", dn.valid)
}
func (dn LDAPDistinguishedName) GoString() string { return dn.String() }

// ParseLDAPDistinguishedName parses and re-renders a bounded RFC 4514 DN.
func ParseLDAPDistinguishedName(value string) (LDAPDistinguishedName, error) {
	if !validLDAPRuntimeText(value, maximumLDAPDNCharacters, maximumLDAPDNBytes) {
		return LDAPDistinguishedName{}, ErrInvalidLDAPTemplate
	}
	parsed, err := ldap.ParseDN(value)
	if err != nil {
		return LDAPDistinguishedName{}, ErrInvalidLDAPTemplate
	}
	canonical := parsed.String()
	if !validLDAPCanonicalDN(canonical) {
		return LDAPDistinguishedName{}, ErrInvalidLDAPTemplate
	}
	return LDAPDistinguishedName{value: canonical, dn: parsed, valid: true}, nil
}

// LDAPGIDNumber is a canonical unsigned POSIX gidNumber value. The explicit
// presence bit keeps the valid value zero distinct from an omitted optional
// placeholder input.
type LDAPGIDNumber struct {
	value uint32
	valid bool
}

func (gid LDAPGIDNumber) String() string {
	return fmt.Sprintf("identity.LDAPGIDNumber{valid:%t,value:[REDACTED]}", gid.valid)
}
func (gid LDAPGIDNumber) GoString() string { return gid.String() }

// ParseLDAPGIDNumber rejects signs, whitespace, leading zeroes, and overflow.
func ParseLDAPGIDNumber(value string) (LDAPGIDNumber, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return LDAPGIDNumber{}, ErrInvalidLDAPTemplate
	}
	return LDAPGIDNumber{value: uint32(parsed), valid: true}, nil
}

// LDAPTemplateValues is the typed runtime substitution set. A compiled
// template asks only for placeholders it actually contains; if an optional
// placeholder occurs in the source and its typed value is absent, Render fails
// closed.
type LDAPTemplateValues struct {
	Username  LDAPUsername
	UserDN    LDAPDistinguishedName
	GIDNumber LDAPGIDNumber
}

func (values LDAPTemplateValues) String() string {
	return fmt.Sprintf(
		"identity.LDAPTemplateValues{username:%t,userDN:%t,gidNumber:%t,values:[REDACTED]}",
		values.Username.valid, values.UserDN.valid, values.GIDNumber.valid,
	)
}
func (values LDAPTemplateValues) GoString() string { return values.String() }

// CompiledLDAPTemplate is immutable after construction. Literal fragments and
// typed placeholder tokens are stored separately, so runtime rendering never
// uses raw string replacement.
type CompiledLDAPTemplate struct {
	context      LDAPTemplateContext
	fragments    []string
	placeholders []ldapTemplatePlaceholder
}

func (template CompiledLDAPTemplate) String() string {
	return fmt.Sprintf(
		"identity.CompiledLDAPTemplate{context:%d,placeholders:%d,source:[REDACTED]}",
		template.context, len(template.placeholders),
	)
}
func (template CompiledLDAPTemplate) GoString() string { return template.String() }

// LDAPTemplateRequirements tells the normalizer which typed runtime values a
// compiled template actually consumes. Optional grammar placeholders become
// requirements only when they occur in that exact compiled source.
type LDAPTemplateRequirements struct {
	Username  bool
	UserDN    bool
	GIDNumber bool
}

// CompileLDAPTemplate validates the closed context grammar, substitutes hostile
// sentinel values using the context's RFC escaping, and asks go-ldap to compile
// or parse the complete result.
func CompileLDAPTemplate(context LDAPTemplateContext, value string) (CompiledLDAPTemplate, error) {
	spec, ok := ldapTemplateSpecFor(context)
	if !ok || !validLDAPTemplateSource(value, spec.maximumCharacters) {
		return CompiledLDAPTemplate{}, ErrInvalidLDAPTemplate
	}
	fragments, placeholders, counts, err := parseLDAPTemplate(value, spec)
	if err != nil {
		return CompiledLDAPTemplate{}, ErrInvalidLDAPTemplate
	}
	for _, required := range spec.required {
		if counts[required] != 1 {
			return CompiledLDAPTemplate{}, ErrInvalidLDAPTemplate
		}
	}
	compiled := CompiledLDAPTemplate{
		context:      context,
		fragments:    fragments,
		placeholders: placeholders,
	}
	rendered, err := compiled.renderSentinels()
	if err != nil || !compiled.validRenderedValue(rendered) ||
		context == LDAPTemplateContextUserSearchFilter && !validUserPopulationAssertion(rendered) {
		return CompiledLDAPTemplate{}, ErrInvalidLDAPTemplate
	}
	return compiled, nil
}

// validUserPopulationAssertion proves that the username token participates in
// one positive equality/substring assertion. Replacing that token with a
// presence wildcard therefore broadens the lookup population. Negated,
// ordering, approximate, and extensible matches are rejected because their
// wildcard form is not a safe complete-enumeration superset.
func validUserPopulationAssertion(rendered string) bool {
	packet, err := ldap.CompileFilter(rendered)
	if err != nil || packet == nil {
		return false
	}
	sentinel := []byte("periapsis*(username)\\\x00")
	matches := 0
	valid := true
	var visit func(*ber.Packet, bool, ber.Tag)
	visit = func(current *ber.Packet, negated bool, assertion ber.Tag) {
		if current == nil || !valid {
			valid = false
			return
		}
		if current.ClassType == ber.ClassContext && current.TagType == ber.TypeConstructed {
			switch uint64(current.Tag) {
			case ldap.FilterNot:
				negated = true
			case ldap.FilterEqualityMatch, ldap.FilterSubstrings:
				assertion = current.Tag
			}
		}
		if current.TagType == ber.TypePrimitive && current.Data != nil &&
			bytes.Contains(current.Data.Bytes(), sentinel) {
			matches++
			if negated || uint64(assertion) != ldap.FilterEqualityMatch &&
				uint64(assertion) != ldap.FilterSubstrings {
				valid = false
			}
		}
		for _, child := range current.Children {
			visit(child, negated, assertion)
		}
	}
	visit(packet, false, 0)
	return valid && matches == 1
}

// Render performs exactly one RFC-appropriate escape for each typed value and
// validates the completed LDAP value again. Missing values and a zero-value or
// corrupted compiled template fail closed.
func (template CompiledLDAPTemplate) Render(values LDAPTemplateValues) (string, error) {
	if len(template.fragments) != len(template.placeholders)+1 {
		return "", ErrInvalidLDAPTemplate
	}
	var rendered strings.Builder
	rendered.Grow(template.renderedCapacity())
	for index, placeholder := range template.placeholders {
		rendered.WriteString(template.fragments[index])
		value, err := template.renderPlaceholder(placeholder, values)
		if err != nil {
			return "", ErrInvalidLDAPTemplate
		}
		rendered.WriteString(value)
	}
	rendered.WriteString(template.fragments[len(template.fragments)-1])
	result := rendered.String()
	if !template.validRenderedValue(result) {
		return "", ErrInvalidLDAPTemplate
	}
	return result, nil
}

// RenderUserEnumerationFilter derives the closed population filter used by a
// complete LDAP synchronization from the configured user-lookup template. It
// replaces the one compiled {username} token with an LDAP presence wildcard;
// no caller-controlled value participates in the transformation. This keeps
// login and synchronization scoped to the same configured population without
// weakening Render's escaping boundary or accepting a second raw filter.
func (template CompiledLDAPTemplate) RenderUserEnumerationFilter() (string, error) {
	requirements, err := template.Requirements()
	if err != nil || template.context != LDAPTemplateContextUserSearchFilter ||
		requirements != (LDAPTemplateRequirements{Username: true}) ||
		len(template.fragments) != 2 || len(template.placeholders) != 1 ||
		template.placeholders[0] != ldapTemplateUsername {
		return "", ErrInvalidLDAPTemplate
	}
	result := template.fragments[0] + "*" + template.fragments[1]
	if !template.validRenderedValue(result) {
		return "", ErrInvalidLDAPTemplate
	}
	return result, nil
}

// Requirements is derived only from private compiled tokens. A zero-value or
// inconsistent template returns ErrInvalidLDAPTemplate instead of looking like
// a template with no requirements.
func (template CompiledLDAPTemplate) Requirements() (LDAPTemplateRequirements, error) {
	if len(template.fragments) != len(template.placeholders)+1 {
		return LDAPTemplateRequirements{}, ErrInvalidLDAPTemplate
	}
	spec, ok := ldapTemplateSpecFor(template.context)
	if !ok {
		return LDAPTemplateRequirements{}, ErrInvalidLDAPTemplate
	}
	var requirements LDAPTemplateRequirements
	counts := make(map[ldapTemplatePlaceholder]int, len(template.placeholders))
	for _, placeholder := range template.placeholders {
		allowed := false
		for _, candidate := range spec.allowed {
			if candidate == placeholder {
				allowed = true
				break
			}
		}
		if !allowed {
			return LDAPTemplateRequirements{}, ErrInvalidLDAPTemplate
		}
		counts[placeholder]++
		if counts[placeholder] != 1 {
			return LDAPTemplateRequirements{}, ErrInvalidLDAPTemplate
		}
		switch placeholder {
		case ldapTemplateUsername:
			requirements.Username = true
		case ldapTemplateUserDN:
			requirements.UserDN = true
		case ldapTemplateGIDNumber:
			requirements.GIDNumber = true
		default:
			return LDAPTemplateRequirements{}, ErrInvalidLDAPTemplate
		}
	}
	for _, required := range spec.required {
		if counts[required] != 1 {
			return LDAPTemplateRequirements{}, ErrInvalidLDAPTemplate
		}
	}
	return requirements, nil
}

type ldapTemplateSpec struct {
	allowed           []ldapTemplatePlaceholder
	required          []ldapTemplatePlaceholder
	maximumCharacters int
}

func ldapTemplateSpecFor(context LDAPTemplateContext) (ldapTemplateSpec, bool) {
	switch context {
	case LDAPTemplateContextUserSearchFilter:
		return ldapTemplateSpec{
			allowed: []ldapTemplatePlaceholder{ldapTemplateUsername}, required: []ldapTemplatePlaceholder{ldapTemplateUsername},
			maximumCharacters: maximumLDAPFilterTemplateCharacters,
		}, true
	case LDAPTemplateContextUserDN:
		return ldapTemplateSpec{
			allowed: []ldapTemplatePlaceholder{ldapTemplateUsername}, required: []ldapTemplatePlaceholder{ldapTemplateUsername},
			maximumCharacters: maximumLDAPDNTemplateCharacters,
		}, true
	case LDAPTemplateContextReverseGroupSearchFilter:
		return ldapTemplateSpec{
			allowed:  []ldapTemplatePlaceholder{ldapTemplateUserDN, ldapTemplateUsername},
			required: []ldapTemplatePlaceholder{ldapTemplateUserDN}, maximumCharacters: maximumLDAPFilterTemplateCharacters,
		}, true
	case LDAPTemplateContextPOSIXGroupSearchFilter:
		return ldapTemplateSpec{
			allowed:  []ldapTemplatePlaceholder{ldapTemplateUsername, ldapTemplateGIDNumber},
			required: []ldapTemplatePlaceholder{ldapTemplateUsername}, maximumCharacters: maximumLDAPFilterTemplateCharacters,
		}, true
	default:
		return ldapTemplateSpec{}, false
	}
}

func parseLDAPTemplate(
	value string,
	spec ldapTemplateSpec,
) ([]string, []ldapTemplatePlaceholder, map[ldapTemplatePlaceholder]int, error) {
	allowed := make(map[string]ldapTemplatePlaceholder, len(spec.allowed))
	for _, placeholder := range spec.allowed {
		name := ldapTemplatePlaceholderName(placeholder)
		if name == "" {
			return nil, nil, nil, ErrInvalidLDAPTemplate
		}
		allowed[name] = placeholder
	}
	counts := make(map[ldapTemplatePlaceholder]int, len(spec.allowed))
	fragments := make([]string, 0, len(spec.allowed)+1)
	placeholders := make([]ldapTemplatePlaceholder, 0, len(spec.allowed))
	fragmentStart := 0
	for index := 0; index < len(value); {
		switch value[index] {
		case '}':
			return nil, nil, nil, ErrInvalidLDAPTemplate
		case '{':
			closingOffset := strings.IndexByte(value[index+1:], '}')
			if closingOffset < 0 {
				return nil, nil, nil, ErrInvalidLDAPTemplate
			}
			closingIndex := index + 1 + closingOffset
			name := value[index+1 : closingIndex]
			if name == "" || strings.ContainsAny(name, "{}") {
				return nil, nil, nil, ErrInvalidLDAPTemplate
			}
			placeholder, known := allowed[name]
			if !known {
				return nil, nil, nil, ErrInvalidLDAPTemplate
			}
			counts[placeholder]++
			if counts[placeholder] != 1 {
				return nil, nil, nil, ErrInvalidLDAPTemplate
			}
			fragments = append(fragments, value[fragmentStart:index])
			placeholders = append(placeholders, placeholder)
			index = closingIndex + 1
			fragmentStart = index
		default:
			index++
		}
	}
	fragments = append(fragments, value[fragmentStart:])
	return fragments, placeholders, counts, nil
}

func (template CompiledLDAPTemplate) renderPlaceholder(
	placeholder ldapTemplatePlaceholder,
	values LDAPTemplateValues,
) (string, error) {
	switch placeholder {
	case ldapTemplateUsername:
		if !values.Username.valid || !validLDAPRuntimeText(
			values.Username.value,
			maximumLDAPUsernameCharacters,
			maximumLDAPUsernameBytes,
		) {
			return "", ErrInvalidLDAPTemplate
		}
		if template.context == LDAPTemplateContextUserDN {
			return ldap.EscapeDN(values.Username.value), nil
		}
		return ldap.EscapeFilter(values.Username.value), nil
	case ldapTemplateUserDN:
		if !values.UserDN.valid || values.UserDN.dn == nil || !validLDAPCanonicalDN(values.UserDN.value) {
			return "", ErrInvalidLDAPTemplate
		}
		if values.UserDN.dn.String() != values.UserDN.value {
			return "", ErrInvalidLDAPTemplate
		}
		return ldap.EscapeFilter(values.UserDN.value), nil
	case ldapTemplateGIDNumber:
		if !values.GIDNumber.valid {
			return "", ErrInvalidLDAPTemplate
		}
		return strconv.FormatUint(uint64(values.GIDNumber.value), 10), nil
	default:
		return "", ErrInvalidLDAPTemplate
	}
}

func (template CompiledLDAPTemplate) renderSentinels() (string, error) {
	if len(template.fragments) != len(template.placeholders)+1 {
		return "", ErrInvalidLDAPTemplate
	}
	filterUsername := ldap.EscapeFilter("periapsis*(username)\\\x00")
	dnUsername := ldap.EscapeDN(" periapsis,sentinel=+<>#;\"\\ \x00")
	userDN := ldap.EscapeFilter(
		"uid=" + ldap.EscapeDN(" periapsis,sentinel=+<>#;\"\\ ") +
			",ou=people,dc=example,dc=invalid",
	)
	var rendered strings.Builder
	rendered.Grow(template.renderedCapacity())
	for index, placeholder := range template.placeholders {
		rendered.WriteString(template.fragments[index])
		switch placeholder {
		case ldapTemplateUsername:
			if template.context == LDAPTemplateContextUserDN {
				rendered.WriteString(dnUsername)
			} else {
				rendered.WriteString(filterUsername)
			}
		case ldapTemplateUserDN:
			rendered.WriteString(userDN)
		case ldapTemplateGIDNumber:
			rendered.WriteString("4294967295")
		default:
			return "", ErrInvalidLDAPTemplate
		}
	}
	rendered.WriteString(template.fragments[len(template.fragments)-1])
	return rendered.String(), nil
}

func (template CompiledLDAPTemplate) validRenderedValue(value string) bool {
	switch template.context {
	case LDAPTemplateContextUserDN:
		_, err := ldap.ParseDN(value)
		return err == nil
	case LDAPTemplateContextUserSearchFilter,
		LDAPTemplateContextReverseGroupSearchFilter,
		LDAPTemplateContextPOSIXGroupSearchFilter:
		_, err := ldap.CompileFilter(value)
		return err == nil
	default:
		return false
	}
}

func (template CompiledLDAPTemplate) renderedCapacity() int {
	capacity := 64 * len(template.placeholders)
	for _, fragment := range template.fragments {
		capacity += len(fragment)
	}
	return capacity
}

func ldapTemplatePlaceholderName(value ldapTemplatePlaceholder) string {
	switch value {
	case ldapTemplateUsername:
		return "username"
	case ldapTemplateUserDN:
		return "userDn"
	case ldapTemplateGIDNumber:
		return "gidNumber"
	default:
		return ""
	}
}

func validLDAPTemplateSource(value string, maximumCharacters int) bool {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > maximumCharacters {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validLDAPRuntimeText(value string, maximumCharacters, maximumBytes int) bool {
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

func validLDAPCanonicalDN(value string) bool {
	// RFC 4514 rendering may expand one input byte to a three-byte hex escape,
	// so the parsed input character bound and the canonical output byte bound
	// are intentionally distinct.
	return validLDAPRuntimeText(value, maximumLDAPDNBytes, maximumLDAPDNBytes)
}
