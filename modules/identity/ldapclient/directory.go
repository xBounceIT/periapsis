package ldapclient

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const (
	maximumDirectoryPageSize             = 1_000
	maximumDirectoryPages                = 1_000
	maximumDirectoryEntries              = 100_000
	minimumDirectoryResponseBytes        = 1_024
	maximumDirectoryResponseBytes        = 50 * 1024 * 1024
	maximumDirectoryGroups               = 10_000
	maximumDirectoryNestedGroupDepth     = 20
	maximumDirectoryAttributes           = 128
	maximumDirectoryValuesPerAttribute   = 10_000
	maximumDirectoryAttributeValueBytes  = 64 * 1024
	maximumDirectoryPagingCookieBytes    = 4 * 1024
	maximumDirectoryResponseControls     = 16
	maximumDirectoryTransportOverhead    = 512 * 1024
	maximumDirectoryReferralHops         = 3
	maximumDirectoryReferralURLBytes     = 2 * 1024
	maximumDirectoryReferralsPerResponse = maximumEndpoints
)

var directoryAttributeNamePattern = regexp.MustCompile(
	`^(?:[A-Za-z][A-Za-z0-9-]{0,127}|[0-9]+(?:\.[0-9]+)+)$`,
)

// DirectoryReferralMode is closed to fail-closed disabled behavior or a
// preconfigured endpoint allowlist. Arbitrary server destinations are never
// followed.
type DirectoryReferralMode string

const (
	DirectoryReferralModeDisabled            DirectoryReferralMode = "disabled"
	DirectoryReferralModeConfiguredEndpoints DirectoryReferralMode = "configured_endpoints"
)

// DirectoryGroupMode selects one typed group-discovery strategy. Disabled
// still permits the bounded direct-membership attribute projection.
type DirectoryGroupMode string

const (
	DirectoryGroupModeDisabled        DirectoryGroupMode = "disabled"
	DirectoryGroupModeActiveDirectory DirectoryGroupMode = "active_directory"
	DirectoryGroupModeReverseSearch   DirectoryGroupMode = "reverse_search"
	DirectoryGroupModePOSIXMemberUID  DirectoryGroupMode = "posix_member_uid"
)

// DirectoryLimits are provider-owned ceilings that are validated against
// process hard limits again immediately before each network operation.
type DirectoryLimits struct {
	PageSize         int
	MaxPages         int
	MaxEntries       int
	MaxResponseBytes int
}

// DirectoryGroupConfiguration contains no raw filter substitution surface.
// SearchFilter must have been compiled in the corresponding closed identity
// template context. For POSIX, an optional {gidNumber} token expresses the
// configured primary-gid fallback in the same bounded group query.
type DirectoryGroupConfiguration struct {
	Mode                      DirectoryGroupMode
	BaseDN                    string
	SearchFilter              *identity.CompiledLDAPTemplate
	DirectMembershipAttribute string
	POSIXGIDNumberAttribute   string
	Attributes                []string
	MaxDepth                  int
	MaxGroups                 int
}

// DirectoryRequest is an immutable provider/configuration snapshot for one
// authentication proof and observation. Username and filters cross the LDAP
// boundary only through the identity package's typed compiled renderer.
type DirectoryRequest struct {
	Configuration    Configuration
	BindDN           string
	Username         identity.LDAPUsername
	UserBaseDN       string
	UserSearchFilter identity.CompiledLDAPTemplate
	UserDNTemplate   *identity.CompiledLDAPTemplate
	UserAttributes   []string
	ReferralMode     DirectoryReferralMode
	ReferralMaxHops  int
	Groups           DirectoryGroupConfiguration
	Limits           DirectoryLimits
}

// DirectoryAttribute is a bounded, value-owning LDAP attribute projection.
// Binary values are preserved exactly and never formatted or logged here.
type DirectoryAttribute struct {
	Name   string
	Values [][]byte
}

// DirectoryEntry is a provider-neutral bounded raw entry. DistinguishedName
// is parsed and library-rendered before it reaches this boundary.
type DirectoryEntry struct {
	DistinguishedName string
	Attributes        []DirectoryAttribute
}

// DirectoryObservation is emitted only after exactly one user was located and
// all configured group searches ended without truncation or referral
// ambiguity. AuthenticateDirectory additionally requires one separate user
// bind; ObserveDirectory is service-bound administrative evidence only.
type DirectoryObservation struct {
	User   DirectoryEntry
	Groups []DirectoryEntry
}

// DirectoryCategory is a stable sanitized result class. It deliberately does
// not carry LDAP errors, DNs, filters, attributes, or credential material.
type DirectoryCategory string

const (
	DirectoryCategorySuccess             DirectoryCategory = "success"
	DirectoryCategoryDNSFailed           DirectoryCategory = "dns_failed"
	DirectoryCategoryDestinationBlocked  DirectoryCategory = "destination_blocked"
	DirectoryCategoryConnectTimeout      DirectoryCategory = "connect_timeout"
	DirectoryCategoryConnectFailed       DirectoryCategory = "connect_failed"
	DirectoryCategoryTLSFailed           DirectoryCategory = "tls_failed"
	DirectoryCategoryCertificateRejected DirectoryCategory = "certificate_rejected"
	DirectoryCategoryServiceBindRejected DirectoryCategory = "service_bind_rejected"
	DirectoryCategoryCredentialsRejected DirectoryCategory = "credentials_rejected"
	DirectoryCategoryUserNotFound        DirectoryCategory = "user_not_found"
	DirectoryCategoryUserAmbiguous       DirectoryCategory = "user_ambiguous"
	DirectoryCategoryLimitExceeded       DirectoryCategory = "limit_exceeded"
	DirectoryCategoryReferralRejected    DirectoryCategory = "referral_rejected"
	DirectoryCategoryInvalidEntry        DirectoryCategory = "invalid_entry"
	DirectoryCategoryProtocolFailed      DirectoryCategory = "protocol_failed"
	DirectoryCategoryCancelled           DirectoryCategory = "cancelled"
)

// DirectoryResult identifies only the selected configured endpoint and a
// sanitized category. Observation is zero unless Category is success.
type DirectoryResult struct {
	Category         DirectoryCategory
	EndpointPriority int
	Observation      DirectoryObservation
}

type validatedDirectoryRequest struct {
	network        validatedConfiguration
	bindDN         string
	username       identity.LDAPUsername
	userBaseDN     *ldap.DN
	userFilter     identity.CompiledLDAPTemplate
	userDNTemplate *identity.CompiledLDAPTemplate
	userAttributes []string
	referrals      validatedDirectoryReferrals
	groups         validatedDirectoryGroups
	limits         DirectoryLimits
}

type validatedDirectoryGroups struct {
	mode                      DirectoryGroupMode
	baseDN                    *ldap.DN
	searchFilter              *identity.CompiledLDAPTemplate
	directMembershipAttribute string
	posixGIDNumberAttribute   string
	attributes                []string
	maxDepth                  int
	maxGroups                 int
}

type validatedDirectoryReferrals struct {
	enabled   bool
	maxHops   int
	endpoints map[directoryEndpointOrigin]Endpoint
}

// AuthenticateDirectory locates exactly one user with the service identity,
// performs exactly one user-password Bind on a separate connection to the
// same selected endpoint, then retrieves a bounded observation. Ownership of
// both secret slices transfers to this call; both backing arrays are cleared
// on every return path.
func (c *Client) AuthenticateDirectory(
	ctx context.Context,
	request DirectoryRequest,
	bindSecret []byte,
	userPassword []byte,
) (DirectoryResult, error) {
	defer clear(bindSecret)
	defer clear(userPassword)
	if ctx == nil || c == nil {
		return DirectoryResult{}, ErrInvalidConfiguration
	}
	if len(bindSecret) < 1 || len(bindSecret) > maximumBindSecretBytes ||
		len(userPassword) < 1 || len(userPassword) > maximumBindSecretBytes {
		return DirectoryResult{}, ErrInvalidConfiguration
	}
	if contextEnded(ctx) {
		return DirectoryResult{Category: directoryContextCategory(ctx, ctx)}, nil
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return DirectoryResult{}, ErrBusy
	}

	validated, err := c.validateDirectoryRequest(request)
	if err != nil {
		return DirectoryResult{}, ErrInvalidConfiguration
	}
	operationCtx, cancel := context.WithTimeout(ctx, validated.network.operationTimeout)
	defer cancel()
	budget := newInboundReadBudget(int64(validated.limits.MaxResponseBytes + maximumDirectoryTransportOverhead))
	lastResult := DirectoryResult{}

	for _, endpoint := range validated.network.endpoints {
		result, retry := c.authenticateDirectoryEndpoint(
			operationCtx,
			validated,
			endpoint,
			bindSecret,
			userPassword,
			budget,
		)
		if !retry {
			return sanitizeDirectoryResult(result), nil
		}
		lastResult = result
	}
	return finalDirectoryRetryResult(ctx, operationCtx, lastResult), nil
}

// ObserveDirectory locates exactly one user and retrieves the same complete
// bounded user/group observation as AuthenticateDirectory using only the
// service identity. It is an administrative dry-run boundary, not an
// authentication proof, and has no user-password input. Ownership of
// bindSecret transfers to this call and its backing array is cleared on every
// return path.
func (c *Client) ObserveDirectory(
	ctx context.Context,
	request DirectoryRequest,
	bindSecret []byte,
) (DirectoryResult, error) {
	defer clear(bindSecret)
	if ctx == nil || c == nil || len(bindSecret) < 1 || len(bindSecret) > maximumBindSecretBytes {
		return DirectoryResult{}, ErrInvalidConfiguration
	}
	if contextEnded(ctx) {
		return DirectoryResult{Category: directoryContextCategory(ctx, ctx)}, nil
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return DirectoryResult{}, ErrBusy
	}

	validated, err := c.validateDirectoryRequest(request)
	if err != nil {
		return DirectoryResult{}, ErrInvalidConfiguration
	}
	operationCtx, cancel := context.WithTimeout(ctx, validated.network.operationTimeout)
	defer cancel()
	budget := newInboundReadBudget(int64(validated.limits.MaxResponseBytes + maximumDirectoryTransportOverhead))
	lastResult := DirectoryResult{}
	for _, endpoint := range validated.network.endpoints {
		result, retry := c.observeDirectoryEndpoint(
			operationCtx,
			validated,
			endpoint,
			bindSecret,
			budget,
		)
		if !retry {
			return sanitizeDirectoryResult(result), nil
		}
		lastResult = result
	}
	return finalDirectoryRetryResult(ctx, operationCtx, lastResult), nil
}

func finalDirectoryRetryResult(
	parent context.Context,
	operation context.Context,
	last DirectoryResult,
) DirectoryResult {
	if contextEnded(operation) {
		last.Category = directoryContextCategory(parent, operation)
	}
	return sanitizeDirectoryResult(last)
}

func sanitizeDirectoryResult(result DirectoryResult) DirectoryResult {
	if result.Category != DirectoryCategorySuccess {
		result.Observation = DirectoryObservation{}
	}
	return result
}

func (c *Client) validateDirectoryRequest(request DirectoryRequest) (validatedDirectoryRequest, error) {
	network, err := c.validateConfiguration(request.Configuration)
	if err != nil || validateDirectoryLimits(request.Limits) != nil {
		return validatedDirectoryRequest{}, ErrInvalidConfiguration
	}
	referrals, err := validateDirectoryReferralConfiguration(request, network)
	if err != nil {
		return validatedDirectoryRequest{}, ErrInvalidConfiguration
	}
	bindDN, err := parseBoundedDN(request.BindDN)
	if err != nil {
		return validatedDirectoryRequest{}, ErrInvalidConfiguration
	}
	userBaseDN, err := parseBoundedDN(request.UserBaseDN)
	if err != nil {
		return validatedDirectoryRequest{}, ErrInvalidConfiguration
	}
	userRequirements, err := request.UserSearchFilter.Requirements()
	if err != nil || userRequirements != (identity.LDAPTemplateRequirements{Username: true}) {
		return validatedDirectoryRequest{}, ErrInvalidConfiguration
	}
	renderedUserFilter, err := request.UserSearchFilter.Render(identity.LDAPTemplateValues{Username: request.Username})
	if err != nil {
		return validatedDirectoryRequest{}, ErrInvalidConfiguration
	}
	if _, err := ldap.CompileFilter(renderedUserFilter); err != nil {
		return validatedDirectoryRequest{}, ErrInvalidConfiguration
	}

	var userDNTemplate *identity.CompiledLDAPTemplate
	if request.UserDNTemplate != nil {
		value := *request.UserDNTemplate
		requirements, requirementErr := value.Requirements()
		if requirementErr != nil || requirements != (identity.LDAPTemplateRequirements{Username: true}) {
			return validatedDirectoryRequest{}, ErrInvalidConfiguration
		}
		rendered, renderErr := value.Render(identity.LDAPTemplateValues{Username: request.Username})
		if renderErr != nil {
			return validatedDirectoryRequest{}, ErrInvalidConfiguration
		}
		renderedDN, parseErr := parseBoundedDN(rendered)
		if parseErr != nil || !dnWithin(userBaseDN, renderedDN) {
			return validatedDirectoryRequest{}, ErrInvalidConfiguration
		}
		userDNTemplate = &value
	}

	groups, err := validateDirectoryGroups(request.Groups, request.Username)
	if err != nil {
		return validatedDirectoryRequest{}, ErrInvalidConfiguration
	}
	requestedUserAttributes := append([]string(nil), request.UserAttributes...)
	if groups.directMembershipAttribute != "" {
		requestedUserAttributes = append(requestedUserAttributes, groups.directMembershipAttribute)
	}
	if groups.posixGIDNumberAttribute != "" {
		requestedUserAttributes = append(requestedUserAttributes, groups.posixGIDNumberAttribute)
	}
	userAttributes, err := normalizeDirectoryAttributes(requestedUserAttributes)
	if err != nil {
		return validatedDirectoryRequest{}, ErrInvalidConfiguration
	}

	return validatedDirectoryRequest{
		network:        network,
		bindDN:         bindDN.String(),
		username:       request.Username,
		userBaseDN:     userBaseDN,
		userFilter:     request.UserSearchFilter,
		userDNTemplate: userDNTemplate,
		userAttributes: userAttributes,
		referrals:      referrals,
		groups:         groups,
		limits:         request.Limits,
	}, nil
}

func validateDirectoryLimits(limits DirectoryLimits) error {
	if limits.PageSize < 1 || limits.PageSize > maximumDirectoryPageSize ||
		limits.MaxPages < 1 || limits.MaxPages > maximumDirectoryPages ||
		limits.MaxEntries < 1 || limits.MaxEntries > maximumDirectoryEntries ||
		limits.MaxResponseBytes < minimumDirectoryResponseBytes ||
		limits.MaxResponseBytes > maximumDirectoryResponseBytes {
		return ErrInvalidConfiguration
	}
	return nil
}

func validateDirectoryReferralConfiguration(
	request DirectoryRequest,
	network validatedConfiguration,
) (validatedDirectoryReferrals, error) {
	return validateDirectoryReferralPolicy(
		request.Configuration,
		request.ReferralMode,
		request.ReferralMaxHops,
		network,
	)
}

func validateDirectoryReferralPolicy(
	configuration Configuration,
	mode DirectoryReferralMode,
	maxHops int,
	network validatedConfiguration,
) (validatedDirectoryReferrals, error) {
	allowed := make(map[directoryEndpointOrigin]Endpoint)
	latentAllowed := 0
	for _, endpoint := range configuration.Endpoints {
		if endpoint.ReferralAllowed {
			latentAllowed++
		}
	}
	switch mode {
	case DirectoryReferralModeDisabled:
		if maxHops != 0 || latentAllowed != 0 {
			return validatedDirectoryReferrals{}, ErrInvalidConfiguration
		}
		return validatedDirectoryReferrals{}, nil
	case DirectoryReferralModeConfiguredEndpoints:
		if maxHops < 1 || maxHops > maximumDirectoryReferralHops {
			return validatedDirectoryReferrals{}, ErrInvalidConfiguration
		}
		for _, endpoint := range network.endpoints {
			if endpoint.ReferralAllowed {
				allowed[directoryOriginForEndpoint(endpoint)] = endpoint
			}
		}
		if len(allowed) == 0 || len(allowed) != latentAllowed {
			return validatedDirectoryReferrals{}, ErrInvalidConfiguration
		}
		return validatedDirectoryReferrals{
			enabled: true, maxHops: maxHops, endpoints: allowed,
		}, nil
	default:
		return validatedDirectoryReferrals{}, ErrInvalidConfiguration
	}
}

func validateDirectoryGroups(
	configuration DirectoryGroupConfiguration,
	username identity.LDAPUsername,
) (validatedDirectoryGroups, error) {
	if configuration.MaxGroups < 1 || configuration.MaxGroups > maximumDirectoryGroups ||
		configuration.MaxDepth < 0 || configuration.MaxDepth > maximumDirectoryNestedGroupDepth {
		return validatedDirectoryGroups{}, ErrInvalidConfiguration
	}
	directAttribute, err := normalizeOptionalDirectoryAttribute(configuration.DirectMembershipAttribute)
	if err != nil {
		return validatedDirectoryGroups{}, err
	}
	posixGIDAttribute, err := normalizeOptionalDirectoryAttribute(configuration.POSIXGIDNumberAttribute)
	if err != nil {
		return validatedDirectoryGroups{}, err
	}
	groupAttributes, err := normalizeDirectoryAttributes(configuration.Attributes)
	if err != nil {
		return validatedDirectoryGroups{}, err
	}

	result := validatedDirectoryGroups{
		mode:                      configuration.Mode,
		directMembershipAttribute: directAttribute,
		posixGIDNumberAttribute:   posixGIDAttribute,
		attributes:                groupAttributes,
		maxDepth:                  configuration.MaxDepth,
		maxGroups:                 configuration.MaxGroups,
	}
	if configuration.Mode == DirectoryGroupModeDisabled {
		if configuration.SearchFilter != nil || configuration.MaxDepth != 0 ||
			posixGIDAttribute != "" || len(groupAttributes) != 0 {
			return validatedDirectoryGroups{}, ErrInvalidConfiguration
		}
		if configuration.BaseDN != "" {
			baseDN, parseErr := parseBoundedDN(configuration.BaseDN)
			if parseErr != nil {
				return validatedDirectoryGroups{}, ErrInvalidConfiguration
			}
			result.baseDN = baseDN
		}
		return result, nil
	}
	if configuration.SearchFilter == nil || configuration.MaxDepth < 1 {
		return validatedDirectoryGroups{}, ErrInvalidConfiguration
	}
	baseDN, err := parseBoundedDN(configuration.BaseDN)
	if err != nil {
		return validatedDirectoryGroups{}, err
	}
	filter := *configuration.SearchFilter
	requirements, err := filter.Requirements()
	if err != nil {
		return validatedDirectoryGroups{}, err
	}

	switch configuration.Mode {
	case DirectoryGroupModeActiveDirectory, DirectoryGroupModeReverseSearch:
		if !requirements.UserDN || requirements.GIDNumber || posixGIDAttribute != "" {
			return validatedDirectoryGroups{}, ErrInvalidConfiguration
		}
		testDN, parseErr := identity.ParseLDAPDistinguishedName("cn=periapsis,dc=example,dc=invalid")
		if parseErr != nil {
			return validatedDirectoryGroups{}, ErrInvalidConfiguration
		}
		rendered, renderErr := filter.Render(identity.LDAPTemplateValues{Username: username, UserDN: testDN})
		if renderErr != nil {
			return validatedDirectoryGroups{}, ErrInvalidConfiguration
		}
		if _, compileErr := ldap.CompileFilter(rendered); compileErr != nil {
			return validatedDirectoryGroups{}, ErrInvalidConfiguration
		}
	case DirectoryGroupModePOSIXMemberUID:
		if !requirements.Username || requirements.UserDN ||
			requirements.GIDNumber && posixGIDAttribute == "" ||
			!requirements.GIDNumber && posixGIDAttribute != "" {
			return validatedDirectoryGroups{}, ErrInvalidConfiguration
		}
		values := identity.LDAPTemplateValues{Username: username}
		if requirements.GIDNumber {
			gid, parseErr := identity.ParseLDAPGIDNumber("1")
			if parseErr != nil {
				return validatedDirectoryGroups{}, ErrInvalidConfiguration
			}
			values.GIDNumber = gid
		}
		rendered, renderErr := filter.Render(values)
		if renderErr != nil {
			return validatedDirectoryGroups{}, ErrInvalidConfiguration
		}
		if _, compileErr := ldap.CompileFilter(rendered); compileErr != nil {
			return validatedDirectoryGroups{}, ErrInvalidConfiguration
		}
	default:
		return validatedDirectoryGroups{}, ErrInvalidConfiguration
	}
	result.baseDN = baseDN
	result.searchFilter = &filter
	return result, nil
}

func normalizeDirectoryAttributes(values ...[]string) ([]string, error) {
	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, list := range values {
		for _, value := range list {
			normalized, err := normalizeOptionalDirectoryAttribute(value)
			if err != nil || normalized == "" {
				return nil, ErrInvalidConfiguration
			}
			if _, duplicate := seen[normalized]; duplicate {
				continue
			}
			seen[normalized] = struct{}{}
			result = append(result, normalized)
		}
	}
	slices.Sort(result)
	if len(result) > maximumDirectoryAttributes {
		return nil, ErrInvalidConfiguration
	}
	return result, nil
}

func normalizeOptionalDirectoryAttribute(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if strings.TrimSpace(value) != value || !utf8.ValidString(value) ||
		!directoryAttributeNamePattern.MatchString(value) {
		return "", ErrInvalidConfiguration
	}
	return strings.ToLower(value), nil
}

func parseBoundedDN(value string) (*ldap.DN, error) {
	if !validDirectoryDNText(value) {
		return nil, ErrInvalidConfiguration
	}
	parsed, err := ldap.ParseDN(value)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	canonical := parsed.String()
	if !validDirectoryDNText(canonical) {
		return nil, ErrInvalidConfiguration
	}
	return parsed, nil
}

func validDirectoryDNText(value string) bool {
	if value == "" || len(value) > maximumBindDNBytes || !utf8.ValidString(value) ||
		utf8.RuneCountInString(value) > maximumBindDNCharacters || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func directoryCategoryFromConnection(category Category) DirectoryCategory {
	switch category {
	case CategoryDNSFailed:
		return DirectoryCategoryDNSFailed
	case CategoryDestinationBlocked:
		return DirectoryCategoryDestinationBlocked
	case CategoryConnectTimeout:
		return DirectoryCategoryConnectTimeout
	case CategoryConnectFailed:
		return DirectoryCategoryConnectFailed
	case CategoryTLSFailed:
		return DirectoryCategoryTLSFailed
	case CategoryCertificateRejected:
		return DirectoryCategoryCertificateRejected
	case CategoryCancelled:
		return DirectoryCategoryCancelled
	default:
		return DirectoryCategoryProtocolFailed
	}
}

func directoryContextCategory(parent, phase context.Context) DirectoryCategory {
	if errors.Is(parent.Err(), context.Canceled) || errors.Is(phase.Err(), context.Canceled) {
		return DirectoryCategoryCancelled
	}
	return DirectoryCategoryConnectTimeout
}

func directoryRemainingSeconds(ctx context.Context) (int, bool) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0, false
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, false
	}
	seconds := int((remaining + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return seconds, true
}
