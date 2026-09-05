package federatedoidc

import (
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ProfileField is the closed non-authorizing profile projection.
type ProfileField string

const (
	ProfileUsername    ProfileField = "username"
	ProfileEmail       ProfileField = "email"
	ProfileDisplayName ProfileField = "display_name"
)

type ScalarClaimRule struct {
	Claim    string
	Required bool
}

type ProfileClaimRule struct {
	Claim    string
	Field    ProfileField
	Required bool
}

type StringArrayClaimRule struct {
	Claim    string
	Required bool
}

// ClaimExtractionPolicy maps only exact top-level names with closed types.
type ClaimExtractionPolicy struct {
	Scalars  []ScalarClaimRule
	Profiles []ProfileClaimRule
	Groups   *StringArrayClaimRule
	// ACR and AMR are optional trust evidence only. Their claim names are
	// fixed to the standard names and Required must remain false.
	ACR *ScalarClaimRule
	AMR *StringArrayClaimRule
}

type NamedScalar struct {
	Name  string
	Value string `json:"-"`
}

type ProfileValue struct {
	Field ProfileField
	Value string `json:"-"`
}

// ClaimSet is immutable; accessors return defensive copies.
type ClaimSet struct {
	scalars  []NamedScalar
	profiles []ProfileValue
	groups   []string
	acr      string
	amr      []string
}

func (claims ClaimSet) Scalars() []NamedScalar {
	return append([]NamedScalar(nil), claims.scalars...)
}

func (claims ClaimSet) Profiles() []ProfileValue {
	return append([]ProfileValue(nil), claims.profiles...)
}

func (claims ClaimSet) Groups() []string { return append([]string(nil), claims.groups...) }
func (claims ClaimSet) ACR() string      { return claims.acr }
func (claims ClaimSet) AMR() []string    { return append([]string(nil), claims.amr...) }

func (claims ClaimSet) Scalar(name string) (string, bool) {
	for _, value := range claims.scalars {
		if value.Name == name {
			return value.Value, true
		}
	}
	return "", false
}

func (claims ClaimSet) Profile(field ProfileField) (string, bool) {
	for _, value := range claims.profiles {
		if value.Field == field {
			return value.Value, true
		}
	}
	return "", false
}

// VerifiedAuthentication contains exact proof facts, never permissions.
type VerifiedAuthentication struct {
	issuer          string
	subject         string
	audience        []string
	issuedAt        time.Time
	expiresAt       time.Time
	authenticatedAt time.Time
	claims          ClaimSet
	completion      TransactionCompletion
	valid           bool
}

func (proof VerifiedAuthentication) Issuer() string  { return proof.issuer }
func (proof VerifiedAuthentication) Subject() string { return proof.subject }
func (proof VerifiedAuthentication) Audience() []string {
	return append([]string(nil), proof.audience...)
}
func (proof VerifiedAuthentication) IssuedAt() time.Time        { return proof.issuedAt }
func (proof VerifiedAuthentication) ExpiresAt() time.Time       { return proof.expiresAt }
func (proof VerifiedAuthentication) AuthenticatedAt() time.Time { return proof.authenticatedAt }
func (proof VerifiedAuthentication) Claims() ClaimSet {
	return ClaimSet{
		scalars:  append([]NamedScalar(nil), proof.claims.scalars...),
		profiles: append([]ProfileValue(nil), proof.claims.profiles...),
		groups:   append([]string(nil), proof.claims.groups...),
		acr:      proof.claims.acr,
		amr:      append([]string(nil), proof.claims.amr...),
	}
}
func (proof VerifiedAuthentication) Completion() TransactionCompletion { return proof.completion }

func (flow *Flow) extractClaims(
	object map[string]json.RawMessage,
	policy ClaimExtractionPolicy,
) (ClaimSet, error) {
	normalized, err := flow.normalizeClaimPolicy(policy)
	if err != nil {
		return ClaimSet{}, ErrClaimExtractionRejected
	}
	result := ClaimSet{}
	trustEvidenceValid := true
	for _, rule := range normalized.Scalars {
		value, present, decodeErr := decodeStringMember(
			object, rule.Claim, rule.Required, flow.policy.Limits.MaxClaimValueBytes,
		)
		if decodeErr != nil || present && !validClaimValue(value, flow.policy.Limits.MaxClaimValueBytes) {
			return ClaimSet{}, ErrClaimExtractionRejected
		}
		if present {
			result.scalars = append(result.scalars, NamedScalar{Name: rule.Claim, Value: value})
		}
	}
	for _, rule := range normalized.Profiles {
		value, present, decodeErr := decodeStringMember(
			object, rule.Claim, rule.Required, flow.policy.Limits.MaxClaimValueBytes,
		)
		if decodeErr != nil || present && !validClaimValue(value, flow.policy.Limits.MaxClaimValueBytes) {
			return ClaimSet{}, ErrClaimExtractionRejected
		}
		if present {
			result.profiles = append(result.profiles, ProfileValue{Field: rule.Field, Value: value})
		}
	}
	if normalized.Groups != nil {
		values, present, decodeErr := decodeStringArrayMember(
			object, normalized.Groups.Claim, normalized.Groups.Required,
			flow.policy.Limits.MaxGroups, flow.policy.Limits.MaxClaimValueBytes,
		)
		if decodeErr != nil || present && !validClaimValues(values, flow.policy.Limits.MaxClaimValueBytes) {
			return ClaimSet{}, ErrClaimExtractionRejected
		}
		result.groups = append(result.groups, values...)
	}
	if normalized.ACR != nil {
		_, rawPresent := object[normalized.ACR.Claim]
		value, present, decodeErr := decodeStringMember(
			object, normalized.ACR.Claim, false,
			flow.policy.Limits.MaxClaimValueBytes,
		)
		// Assurance claims are never admission requirements. Missing, malformed,
		// duplicated, or over-limit evidence yields primary assurance only.
		if rawPresent && (decodeErr != nil || !present || !validClaimValue(value, flow.policy.Limits.MaxClaimValueBytes)) {
			trustEvidenceValid = false
		} else if present {
			result.acr = value
		}
	}
	if normalized.AMR != nil {
		_, rawPresent := object[normalized.AMR.Claim]
		values, present, decodeErr := decodeStringArrayMember(
			object, normalized.AMR.Claim, false,
			flow.policy.Limits.MaxAMRValues, flow.policy.Limits.MaxClaimValueBytes,
		)
		if rawPresent && (decodeErr != nil || !present || !validClaimValues(values, flow.policy.Limits.MaxClaimValueBytes)) {
			trustEvidenceValid = false
		} else if present {
			result.amr = append(result.amr, values...)
		}
	}
	if !trustEvidenceValid {
		result.acr = ""
		clear(result.amr)
		result.amr = nil
	}
	slices.SortFunc(result.scalars, func(left, right NamedScalar) int {
		return strings.Compare(left.Name, right.Name)
	})
	slices.SortFunc(result.profiles, func(left, right ProfileValue) int {
		return strings.Compare(string(left.Field), string(right.Field))
	})
	slices.Sort(result.groups)
	slices.Sort(result.amr)
	return result, nil
}

func (flow *Flow) normalizeClaimPolicy(policy ClaimExtractionPolicy) (ClaimExtractionPolicy, error) {
	if flow == nil || len(policy.Scalars) > flow.policy.Limits.MaxScalarClaims ||
		len(policy.Profiles) > flow.policy.Limits.MaxProfileClaims {
		return ClaimExtractionPolicy{}, ErrClaimExtractionRejected
	}
	result := ClaimExtractionPolicy{
		Scalars:  append([]ScalarClaimRule(nil), policy.Scalars...),
		Profiles: append([]ProfileClaimRule(nil), policy.Profiles...),
	}
	seenClaims := make(map[string]struct{}, len(result.Scalars)+len(result.Profiles)+3)
	seenFields := make(map[ProfileField]struct{}, len(result.Profiles))
	for _, rule := range result.Scalars {
		if !validClaimName(rule.Claim) || reservedSecurityClaim(rule.Claim) {
			return ClaimExtractionPolicy{}, ErrClaimExtractionRejected
		}
		if _, duplicate := seenClaims[rule.Claim]; duplicate {
			return ClaimExtractionPolicy{}, ErrClaimExtractionRejected
		}
		seenClaims[rule.Claim] = struct{}{}
	}
	for _, rule := range result.Profiles {
		if !validClaimName(rule.Claim) || !validProfileField(rule.Field) || reservedSecurityClaim(rule.Claim) {
			return ClaimExtractionPolicy{}, ErrClaimExtractionRejected
		}
		if _, duplicate := seenClaims[rule.Claim]; duplicate {
			return ClaimExtractionPolicy{}, ErrClaimExtractionRejected
		}
		if _, duplicate := seenFields[rule.Field]; duplicate {
			return ClaimExtractionPolicy{}, ErrClaimExtractionRejected
		}
		seenClaims[rule.Claim] = struct{}{}
		seenFields[rule.Field] = struct{}{}
	}
	if policy.Groups != nil {
		if !validClaimName(policy.Groups.Claim) || reservedSecurityClaim(policy.Groups.Claim) {
			return ClaimExtractionPolicy{}, ErrClaimExtractionRejected
		}
		if _, duplicate := seenClaims[policy.Groups.Claim]; duplicate {
			return ClaimExtractionPolicy{}, ErrClaimExtractionRejected
		}
		copyRule := *policy.Groups
		result.Groups = &copyRule
		seenClaims[policy.Groups.Claim] = struct{}{}
	}
	if policy.ACR != nil {
		if policy.ACR.Claim != "acr" || policy.ACR.Required {
			return ClaimExtractionPolicy{}, ErrClaimExtractionRejected
		}
		if _, duplicate := seenClaims[policy.ACR.Claim]; duplicate {
			return ClaimExtractionPolicy{}, ErrClaimExtractionRejected
		}
		copyRule := *policy.ACR
		result.ACR = &copyRule
		seenClaims[policy.ACR.Claim] = struct{}{}
	}
	if policy.AMR != nil {
		if policy.AMR.Claim != "amr" || policy.AMR.Required {
			return ClaimExtractionPolicy{}, ErrClaimExtractionRejected
		}
		if _, duplicate := seenClaims[policy.AMR.Claim]; duplicate {
			return ClaimExtractionPolicy{}, ErrClaimExtractionRejected
		}
		copyRule := *policy.AMR
		result.AMR = &copyRule
		seenClaims[policy.AMR.Claim] = struct{}{}
	}
	return result, nil
}

func validClaimName(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || character == '"' || character == '\\' {
			return false
		}
	}
	return true
}

func reservedSecurityClaim(value string) bool {
	switch value {
	case "iss", "sub", "aud", "azp", "exp", "iat", "nbf", "auth_time", "nonce", "at_hash", "acr", "amr":
		return true
	default:
		return false
	}
}

func validProfileField(value ProfileField) bool {
	return value == ProfileUsername || value == ProfileEmail || value == ProfileDisplayName
}

func validClaimValue(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || isDirectionalControl(character) {
			return false
		}
	}
	return true
}

func isDirectionalControl(character rune) bool {
	return character == '\u200e' || character == '\u200f' ||
		character >= '\u202a' && character <= '\u202e' ||
		character >= '\u2066' && character <= '\u2069'
}

func validClaimValues(values []string, maximum int) bool {
	for _, value := range values {
		if !validClaimValue(value, maximum) {
			return false
		}
	}
	return true
}
