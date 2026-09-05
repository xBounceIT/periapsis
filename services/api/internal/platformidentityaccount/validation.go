package platformidentityaccount

import (
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

const (
	defaultPageSize                      = 50
	maximumPageSize                      = 100
	maximumReasonBytes                   = 2 * 1024
	maximumAccountVersion          int64 = 2_147_483_647
	maximumExpectedMutationVersion int64 = maximumAccountVersion - 1
	maximumProviderRevision        int64 = 9_007_199_254_740_991
	maximumSubjectAliases                = 16
	maximumSubjectCiphertextBytes        = 4*1024 + 16
)

var (
	idempotencyKeyPattern   = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)
	canonicalDNSHostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	canonicalPortPattern    = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)
	numericIPv4HostPattern  = regexp.MustCompile(`^[0-9.]+$`)
)

func normalizeList(providerID uuid.UUID, input ListInput) (ListInput, error) {
	if input.Limit == 0 {
		input.Limit = defaultPageSize
	}
	if !validUUIDv7(providerID) || input.Limit < 1 || input.Limit > maximumPageSize ||
		input.After != nil && !validUUIDv7(*input.After) {
		return ListInput{}, authentication.ErrInvalidInput
	}
	if input.After != nil {
		cursor := *input.After
		input.After = &cursor
	}
	return input, nil
}

func normalizePrelink(
	providerID uuid.UUID,
	input PrelinkInput,
) (PrelinkInput, identity.Subject, [sha256.Size]byte, error) {
	input.Reason = strings.TrimSpace(input.Reason)
	if !validUUIDv7(providerID) || !validUUIDv7(input.UserID) ||
		!validOIDCIssuer(input.Issuer) || !validReason(input.Reason) ||
		!idempotencyKeyPattern.MatchString(input.IdempotencyKey) || !validEvent(input.Event) {
		return PrelinkInput{}, identity.Subject{}, [sha256.Size]byte{}, authentication.ErrInvalidInput
	}
	subject, err := identity.CanonicalOIDCIssuerSubject(input.Issuer, input.Subject)
	if err != nil {
		return PrelinkInput{}, identity.Subject{}, [sha256.Size]byte{}, authentication.ErrInvalidInput
	}
	digest, err := prelinkPublicRequestDigest(providerID, input)
	if err != nil {
		subject.Clear()
		return PrelinkInput{}, identity.Subject{}, [sha256.Size]byte{}, authentication.ErrInvalidInput
	}
	return input, subject, digest, nil
}

func normalizeRetire(
	providerID, accountID uuid.UUID,
	input RetireInput,
) (RetireInput, int64, int64, error) {
	if !validUUIDv7(providerID) || !validUUIDv7(accountID) ||
		input.ExpectedEntityTag == nil || !validEvent(input.Event) {
		return RetireInput{}, 0, 0, authentication.ErrInvalidInput
	}
	version, userVersion, err := ParseEntityTag(*input.ExpectedEntityTag)
	if err != nil || version > maximumExpectedMutationVersion {
		return RetireInput{}, 0, 0, authentication.ErrInvalidInput
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validReason(input.Reason) {
		return RetireInput{}, 0, 0, authentication.ErrInvalidInput
	}
	return input, version, userVersion, nil
}

// prelinkPublicRequestDigest binds only the normalized, non-secret portion of
// the command. The exact OIDC subject is intentionally excluded: hashing a
// low-entropy subject with an unkeyed digest would create an offline dictionary
// oracle for a database reader. Repository replay logic binds subject equality
// through the protected, provider-scoped alias vector instead.
func prelinkPublicRequestDigest(providerID uuid.UUID, input PrelinkInput) ([sha256.Size]byte, error) {
	document := struct {
		Schema     string    `json:"schema"`
		ProviderID uuid.UUID `json:"providerId"`
		UserID     uuid.UUID `json:"userId"`
		Issuer     string    `json:"issuer"`
		Reason     string    `json:"reason"`
	}{
		Schema: "periapsis/platform-identity-account-prelink-public/v1", ProviderID: providerID,
		UserID: input.UserID, Issuer: input.Issuer, Reason: input.Reason,
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) < 1 || len(encoded) > 16*1024 {
		clear(encoded)
		return [sha256.Size]byte{}, authentication.ErrInvalidInput
	}
	digest := sha256.Sum256(encoded)
	clear(encoded)
	return digest, nil
}

func validAccount(value Account) bool {
	if !validUUIDv7(value.ID) || !validUUIDv7(value.ProviderID) || !validUserSummary(value.User) ||
		(value.State != AccountStateActive && value.State != AccountStateRetired) ||
		(value.State == AccountStateActive) != (value.RetiredAt == nil) ||
		!validProviderRevision(value.AdmittedConfigurationRevision) ||
		!validProviderRevision(value.AdmittedSecurityRevision) ||
		!validResourceVersion(value.Version) || !validInstant(value.CreatedAt) ||
		!validInstant(value.UpdatedAt) || value.UpdatedAt.Before(value.CreatedAt) {
		return false
	}
	switch value.LastObservationState {
	case LastObservationStateKnown:
		if value.LastObservedAt == nil || !validInstant(*value.LastObservedAt) ||
			value.LastObservedAt.Before(value.CreatedAt) || value.LastObservedAt.After(value.UpdatedAt) {
			return false
		}
	case LastObservationStateLegacyUnknown:
		if value.State != AccountStateRetired || value.RetiredAt == nil ||
			value.LastObservedAt != nil || value.Version != 1 {
			return false
		}
	default:
		return false
	}
	if value.RetiredAt != nil && (!validInstant(*value.RetiredAt) ||
		value.RetiredAt.Before(value.CreatedAt) ||
		(value.LastObservedAt != nil && value.RetiredAt.Before(*value.LastObservedAt)) ||
		value.RetiredAt.After(value.UpdatedAt)) {
		return false
	}
	return true
}

func initialAccountProjection(value Account) bool {
	return value.State == AccountStateActive && value.RetiredAt == nil && value.User.Active &&
		value.LastObservationState == LastObservationStateKnown && value.LastObservedAt != nil &&
		value.Version == 1 && value.CreatedAt.Equal(value.UpdatedAt) &&
		value.LastObservedAt.Equal(value.CreatedAt)
}

func validUserSummary(value UserSummary) bool {
	if !validUUIDv7(value.ID) || !validText(value.DisplayName, 1, 160) ||
		!validResourceVersion(value.Version) {
		return false
	}
	if value.Email == nil {
		return true
	}
	email := *value.Email
	return len(email) <= 320 && strings.TrimSpace(email) == email && strings.ToLower(email) == email &&
		strings.IndexByte(email, '@') > 0 && validText(email, 3, 320)
}

func validRetirementTransition(previous, next Account) bool {
	if !validAccount(previous) || !validAccount(next) ||
		previous.State != AccountStateActive || previous.RetiredAt != nil ||
		next.State != AccountStateRetired || next.RetiredAt == nil ||
		previous.ID != next.ID || previous.ProviderID != next.ProviderID ||
		previous.User.ID != next.User.ID || previous.User.Version != next.User.Version ||
		previous.User.Active != next.User.Active || previous.User.DisplayName != next.User.DisplayName ||
		!equalOptionalString(previous.User.Email, next.User.Email) ||
		previous.AdmittedConfigurationRevision != next.AdmittedConfigurationRevision ||
		previous.AdmittedSecurityRevision != next.AdmittedSecurityRevision ||
		previous.LastObservationState != LastObservationStateKnown ||
		next.LastObservationState != previous.LastObservationState ||
		previous.Version >= maximumAccountVersion || next.Version != previous.Version+1 ||
		!previous.CreatedAt.Equal(next.CreatedAt) ||
		!equalOptionalInstant(previous.LastObservedAt, next.LastObservedAt) ||
		next.RetiredAt.Before(previous.UpdatedAt) ||
		next.RetiredAt.Before(*previous.LastObservedAt) ||
		!next.UpdatedAt.Equal(*next.RetiredAt) {
		return false
	}
	return true
}

func equalOptionalInstant(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func equalOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func validProtectedSubject(value ProtectedSubject) bool {
	if len(value.Aliases) < 1 || len(value.Aliases) > maximumSubjectAliases ||
		value.Envelope.KeyVersion < 1 || value.Envelope.Format != identity.UTF8ExactSubject ||
		len(value.Envelope.Ciphertext) < 17 || len(value.Envelope.Ciphertext) > maximumSubjectCiphertextBytes {
		return false
	}
	hasEnvelopeVersion := false
	for index, alias := range value.Aliases {
		if alias.KeyVersion < 1 || index > 0 && value.Aliases[index-1].KeyVersion >= alias.KeyVersion {
			return false
		}
		var combined byte
		for _, item := range alias.Digest {
			combined |= item
		}
		if combined == 0 {
			return false
		}
		if alias.KeyVersion == value.Envelope.KeyVersion {
			hasEnvelopeVersion = true
		}
	}
	return hasEnvelopeVersion
}

func validSession(session authentication.Session) bool {
	return validUUIDv7(session.User.ID) && validUUIDv7(session.ID) &&
		validAuthenticationMethod(session.AuthenticationMethod)
}

func validAuthenticationMethod(value string) bool {
	switch value {
	case "bootstrap_totp", "oidc", "passkey", "recovery_code", "saml", "totp":
		return true
	default:
		return false
	}
}

func validEvent(value authentication.EventContext) bool {
	if !validUUIDv7(value.RequestID) || !validUUIDv7(value.CorrelationID) ||
		!value.RemoteAddress.IsValid() || value.RemoteAddress.Zone() != "" ||
		len(value.UserAgent) < 1 || len(value.UserAgent) > 512 || !utf8.ValidString(value.UserAgent) {
		return false
	}
	for _, character := range value.UserAgent {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validOIDCIssuer(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.Fragment == "" && parsed.RawQuery == "" && parsed.String() == value &&
		validURIText(value, 2*1024) && validCanonicalHTTPSAuthority(parsed.Host)
}

func validURIText(value string, maximumBytes int) bool {
	return len(value) > 0 && len(value) <= maximumBytes && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && !strings.Contains(value, `\`) &&
		strings.IndexFunc(value, unicode.IsSpace) < 0
}

func validCanonicalHTTPSAuthority(authority string) bool {
	var hostValue, portValue string
	if strings.HasPrefix(authority, "[") {
		closingBracket := strings.IndexByte(authority, ']')
		if closingBracket <= 1 {
			return false
		}
		hostValue = authority[1:closingBracket]
		tail := authority[closingBracket+1:]
		if tail != "" {
			if !strings.HasPrefix(tail, ":") {
				return false
			}
			portValue = tail[1:]
		}
		address, err := netip.ParseAddr(hostValue)
		if err != nil || !address.Is6() || address.String() != hostValue {
			return false
		}
	} else {
		if strings.Count(authority, ":") > 1 {
			return false
		}
		hostValue = authority
		if separator := strings.LastIndexByte(authority, ':'); separator >= 0 {
			hostValue, portValue = authority[:separator], authority[separator+1:]
		}
		if hostValue != strings.ToLower(hostValue) || len(hostValue) > 253 {
			return false
		}
		if numericIPv4HostPattern.MatchString(hostValue) {
			address, err := netip.ParseAddr(hostValue)
			if err != nil || !address.Is4() || address.String() != hostValue {
				return false
			}
		} else if !canonicalDNSHostPattern.MatchString(hostValue) {
			return false
		}
	}
	if portValue == "" {
		return !strings.HasSuffix(authority, ":")
	}
	port, err := strconv.Atoi(portValue)
	return err == nil && canonicalPortPattern.MatchString(portValue) && port <= 65_535
}

func validReason(value string) bool {
	return len(value) >= 1 && len(value) <= maximumReasonBytes && validText(value, 1, maximumReasonBytes)
}

func validText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) < minimum ||
		utf8.RuneCountInString(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validResourceVersion(value int64) bool {
	return value > 0 && value <= maximumAccountVersion
}

func validProviderRevision(value int64) bool {
	return value > 0 && value <= maximumProviderRevision
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1970 && value.Year() <= 9999 &&
		value.Nanosecond()%1_000 == 0
}

func cloneAccount(value Account) Account {
	if value.User.Email != nil {
		email := *value.User.Email
		value.User.Email = &email
	}
	if value.RetiredAt != nil {
		retiredAt := *value.RetiredAt
		value.RetiredAt = &retiredAt
	}
	if value.LastObservedAt != nil {
		lastObservedAt := *value.LastObservedAt
		value.LastObservedAt = &lastObservedAt
	}
	return value
}

func clearProtectedSubject(value *ProtectedSubject) {
	if value == nil {
		return
	}
	for index := range value.Aliases {
		clear(value.Aliases[index].Digest[:])
	}
	clear(value.Aliases)
	clear(value.Envelope.Nonce[:])
	clear(value.Envelope.Ciphertext)
	*value = ProtectedSubject{}
}
