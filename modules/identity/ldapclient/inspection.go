package ldapclient

import (
	"context"

	ldap "github.com/go-ldap/ldap/v3"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const (
	// MaximumDirectoryInspectionResults is the hard result projection ceiling
	// for an administrative filter test. SearchDirectoryUser has the stricter
	// fixed ceiling of one projected entry.
	MaximumDirectoryInspectionResults = 10

	maximumDirectoryInspectionAttributes = 64
)

// DirectoryInspectionFilterKind is the closed set of filter grammars admitted
// by administrative directory inspection. Active Directory nested searches
// and generic reverse membership searches share the reverse-group grammar.
type DirectoryInspectionFilterKind string

const (
	DirectoryInspectionFilterUser         DirectoryInspectionFilterKind = "user"
	DirectoryInspectionFilterReverseGroup DirectoryInspectionFilterKind = "reverse_group"
	DirectoryInspectionFilterPOSIXGroup   DirectoryInspectionFilterKind = "posix_group"
)

// CompiledDirectoryInspectionFilter retains a context-bound compiled LDAP
// template. Its fields are private so callers cannot relabel a user filter as
// a group filter or inject a pre-rendered filter into an inspection request.
type CompiledDirectoryInspectionFilter struct {
	kind         DirectoryInspectionFilterKind
	template     identity.CompiledLDAPTemplate
	requirements identity.LDAPTemplateRequirements
	valid        bool
}

// CompileDirectoryInspectionFilter compiles one source template in the exact
// closed identity grammar selected by kind. Errors deliberately expose no
// template text, parser position, or rendered value.
func CompileDirectoryInspectionFilter(
	kind DirectoryInspectionFilterKind,
	source string,
) (CompiledDirectoryInspectionFilter, error) {
	contextKind, ok := directoryInspectionTemplateContext(kind)
	if !ok {
		return CompiledDirectoryInspectionFilter{}, ErrInvalidConfiguration
	}
	compiled, err := identity.CompileLDAPTemplate(contextKind, source)
	if err != nil {
		return CompiledDirectoryInspectionFilter{}, ErrInvalidConfiguration
	}
	requirements, err := compiled.Requirements()
	if err != nil || !validDirectoryInspectionRequirements(kind, requirements) {
		return CompiledDirectoryInspectionFilter{}, ErrInvalidConfiguration
	}
	return CompiledDirectoryInspectionFilter{
		kind: kind, template: compiled, requirements: requirements, valid: true,
	}, nil
}

// DirectoryInspectionConfiguration is one immutable provider connection and
// resource-policy snapshot. BindDN is always used as a service identity; no
// user-password field exists anywhere in the inspection API.
type DirectoryInspectionConfiguration struct {
	Network         Configuration
	BindDN          string
	ReferralMode    DirectoryReferralMode
	ReferralMaxHops int
	Limits          DirectoryLimits
}

// DirectorySearchUserRequest tests the provider's configured user lookup.
// UserSearchFilter must have been compiled as DirectoryInspectionFilterUser.
// Search scope is always the complete subtree under UserBaseDN.
type DirectorySearchUserRequest struct {
	Configuration    DirectoryInspectionConfiguration
	Username         identity.LDAPUsername
	UserBaseDN       string
	UserSearchFilter CompiledDirectoryInspectionFilter
	Attributes       []string
}

// DirectoryFilterTestRequest executes one context-bound candidate filter. The
// base DN and projected attributes must come from the provider snapshot; scope
// is fixed to the complete subtree and callers cannot supply LDAP controls.
type DirectoryFilterTestRequest struct {
	Configuration   DirectoryInspectionConfiguration
	UserBaseDN      string
	GroupBaseDN     string
	Filter          CompiledDirectoryInspectionFilter
	Values          identity.LDAPTemplateValues
	UserAttributes  []string
	GroupAttributes []string
	MaxResults      int
}

// DirectoryInspectionResult contains only bounded, value-owning projections
// and sanitized operation metadata. Truncated means at least one additional
// entry was observed beyond the public projection ceiling.
type DirectoryInspectionResult struct {
	Category         DirectoryCategory
	EndpointPriority int
	Truncated        bool
	Entries          []DirectoryEntry
}

type validatedDirectoryInspectionConfiguration struct {
	network   validatedConfiguration
	bindDN    string
	referrals validatedDirectoryReferrals
	limits    DirectoryLimits
}

type validatedDirectoryInspectionRequest struct {
	configuration validatedDirectoryInspectionConfiguration
	baseDN        *ldap.DN
	filter        string
	attributes    []string
	resultLimit   int
}

// SearchDirectoryUser service-binds and runs only the configured typed user
// search. It projects at most one owned entry and reports Truncated when the
// directory proves the lookup ambiguous. Ownership of bindSecret transfers to
// this call and its backing array is cleared on every return path.
func (c *Client) SearchDirectoryUser(
	ctx context.Context,
	request DirectorySearchUserRequest,
	bindSecret []byte,
) (DirectoryInspectionResult, error) {
	defer clear(bindSecret)
	if ctx == nil || c == nil || len(bindSecret) < 1 || len(bindSecret) > maximumBindSecretBytes {
		return DirectoryInspectionResult{}, ErrInvalidConfiguration
	}
	if contextEnded(ctx) {
		return DirectoryInspectionResult{Category: directoryContextCategory(ctx, ctx)}, nil
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return DirectoryInspectionResult{}, ErrBusy
	}
	validatedConfiguration, err := c.validateDirectoryInspectionConfiguration(request.Configuration)
	if err != nil || validatedConfiguration.limits.MaxEntries < 2 {
		return DirectoryInspectionResult{}, ErrInvalidConfiguration
	}
	if request.UserSearchFilter.kind != DirectoryInspectionFilterUser {
		return DirectoryInspectionResult{}, ErrInvalidConfiguration
	}
	filter, err := request.UserSearchFilter.render(identity.LDAPTemplateValues{Username: request.Username})
	if err != nil {
		return DirectoryInspectionResult{}, ErrInvalidConfiguration
	}
	baseDN, attributes, err := validateDirectoryInspectionSearchShape(
		request.UserBaseDN,
		request.Attributes,
	)
	if err != nil {
		return DirectoryInspectionResult{}, ErrInvalidConfiguration
	}
	return c.inspectDirectory(ctx, validatedDirectoryInspectionRequest{
		configuration: validatedConfiguration,
		baseDN:        baseDN,
		filter:        filter,
		attributes:    attributes,
		resultLimit:   1,
	}, bindSecret)
}

// TestDirectoryFilter service-binds and executes one context-bound candidate
// using the same manual paging, deadline, referral, TLS, DNS, and egress path
// as authentication. It returns at most MaximumDirectoryInspectionResults
// owned entries. Ownership of bindSecret transfers to this call.
func (c *Client) TestDirectoryFilter(
	ctx context.Context,
	request DirectoryFilterTestRequest,
	bindSecret []byte,
) (DirectoryInspectionResult, error) {
	defer clear(bindSecret)
	if ctx == nil || c == nil || len(bindSecret) < 1 || len(bindSecret) > maximumBindSecretBytes ||
		request.MaxResults < 1 || request.MaxResults > MaximumDirectoryInspectionResults {
		return DirectoryInspectionResult{}, ErrInvalidConfiguration
	}
	if contextEnded(ctx) {
		return DirectoryInspectionResult{Category: directoryContextCategory(ctx, ctx)}, nil
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return DirectoryInspectionResult{}, ErrBusy
	}
	validatedConfiguration, err := c.validateDirectoryInspectionConfiguration(request.Configuration)
	if err != nil || validatedConfiguration.limits.MaxEntries < request.MaxResults+1 {
		return DirectoryInspectionResult{}, ErrInvalidConfiguration
	}
	filter, err := request.Filter.render(request.Values)
	if err != nil {
		return DirectoryInspectionResult{}, ErrInvalidConfiguration
	}
	baseDNText, requestedAttributes, err := request.contextSearchShape()
	if err != nil {
		return DirectoryInspectionResult{}, ErrInvalidConfiguration
	}
	baseDN, attributes, err := validateDirectoryInspectionSearchShape(baseDNText, requestedAttributes)
	if err != nil {
		return DirectoryInspectionResult{}, ErrInvalidConfiguration
	}
	return c.inspectDirectory(ctx, validatedDirectoryInspectionRequest{
		configuration: validatedConfiguration,
		baseDN:        baseDN,
		filter:        filter,
		attributes:    attributes,
		resultLimit:   request.MaxResults,
	}, bindSecret)
}

func (request DirectoryFilterTestRequest) contextSearchShape() (string, []string, error) {
	switch request.Filter.kind {
	case DirectoryInspectionFilterUser:
		if request.GroupBaseDN != "" || len(request.GroupAttributes) != 0 {
			return "", nil, ErrInvalidConfiguration
		}
		return request.UserBaseDN, request.UserAttributes, nil
	case DirectoryInspectionFilterReverseGroup, DirectoryInspectionFilterPOSIXGroup:
		if request.UserBaseDN != "" || len(request.UserAttributes) != 0 {
			return "", nil, ErrInvalidConfiguration
		}
		return request.GroupBaseDN, request.GroupAttributes, nil
	default:
		return "", nil, ErrInvalidConfiguration
	}
}

func (c *Client) validateDirectoryInspectionConfiguration(
	configuration DirectoryInspectionConfiguration,
) (validatedDirectoryInspectionConfiguration, error) {
	network, err := c.validateConfiguration(configuration.Network)
	if err != nil || validateDirectoryLimits(configuration.Limits) != nil {
		return validatedDirectoryInspectionConfiguration{}, ErrInvalidConfiguration
	}
	bindDN, err := parseBoundedDN(configuration.BindDN)
	if err != nil {
		return validatedDirectoryInspectionConfiguration{}, ErrInvalidConfiguration
	}
	referrals, err := validateDirectoryReferralPolicy(
		configuration.Network,
		configuration.ReferralMode,
		configuration.ReferralMaxHops,
		network,
	)
	if err != nil {
		return validatedDirectoryInspectionConfiguration{}, ErrInvalidConfiguration
	}
	return validatedDirectoryInspectionConfiguration{
		network: network, bindDN: bindDN.String(), referrals: referrals, limits: configuration.Limits,
	}, nil
}

func validateDirectoryInspectionSearchShape(
	baseDNText string,
	attributes []string,
) (*ldap.DN, []string, error) {
	baseDN, err := parseBoundedDN(baseDNText)
	if err != nil {
		return nil, nil, ErrInvalidConfiguration
	}
	normalized, err := normalizeDirectoryAttributes(attributes)
	if err != nil || len(normalized) > maximumDirectoryInspectionAttributes {
		return nil, nil, ErrInvalidConfiguration
	}
	return baseDN, normalized, nil
}

func (filter CompiledDirectoryInspectionFilter) render(
	values identity.LDAPTemplateValues,
) (string, error) {
	if !filter.valid || !validDirectoryInspectionRequirements(filter.kind, filter.requirements) {
		return "", ErrInvalidConfiguration
	}
	requirements, err := filter.template.Requirements()
	if err != nil || requirements != filter.requirements {
		return "", ErrInvalidConfiguration
	}
	rendered, err := filter.template.Render(values)
	if err != nil {
		return "", ErrInvalidConfiguration
	}
	if _, err := ldap.CompileFilter(rendered); err != nil {
		return "", ErrInvalidConfiguration
	}
	return rendered, nil
}

func directoryInspectionTemplateContext(
	kind DirectoryInspectionFilterKind,
) (identity.LDAPTemplateContext, bool) {
	switch kind {
	case DirectoryInspectionFilterUser:
		return identity.LDAPTemplateContextUserSearchFilter, true
	case DirectoryInspectionFilterReverseGroup:
		return identity.LDAPTemplateContextReverseGroupSearchFilter, true
	case DirectoryInspectionFilterPOSIXGroup:
		return identity.LDAPTemplateContextPOSIXGroupSearchFilter, true
	default:
		return 0, false
	}
}

func validDirectoryInspectionRequirements(
	kind DirectoryInspectionFilterKind,
	requirements identity.LDAPTemplateRequirements,
) bool {
	switch kind {
	case DirectoryInspectionFilterUser:
		return requirements == (identity.LDAPTemplateRequirements{Username: true})
	case DirectoryInspectionFilterReverseGroup:
		return requirements.UserDN && !requirements.GIDNumber
	case DirectoryInspectionFilterPOSIXGroup:
		return requirements.Username && !requirements.UserDN
	default:
		return false
	}
}

func (c *Client) inspectDirectory(
	ctx context.Context,
	request validatedDirectoryInspectionRequest,
	bindSecret []byte,
) (DirectoryInspectionResult, error) {
	if contextEnded(ctx) {
		return DirectoryInspectionResult{Category: directoryContextCategory(ctx, ctx)}, nil
	}
	operationCtx, cancel := context.WithTimeout(ctx, request.configuration.network.operationTimeout)
	defer cancel()
	budget := newInboundReadBudget(int64(
		request.configuration.limits.MaxResponseBytes + maximumDirectoryTransportOverhead,
	))
	lastResult := DirectoryInspectionResult{}
	for _, endpoint := range request.configuration.network.endpoints {
		result, retry := c.inspectDirectoryEndpoint(operationCtx, request, endpoint, bindSecret, budget)
		if !retry {
			return sanitizeDirectoryInspectionResult(result), nil
		}
		lastResult = result
	}
	if contextEnded(operationCtx) {
		lastResult.Category = directoryContextCategory(ctx, operationCtx)
	}
	return sanitizeDirectoryInspectionResult(lastResult), nil
}

func (c *Client) inspectDirectoryEndpoint(
	ctx context.Context,
	request validatedDirectoryInspectionRequest,
	endpoint Endpoint,
	bindSecret []byte,
	budget *inboundReadBudget,
) (DirectoryInspectionResult, bool) {
	priority := endpoint.Priority
	connection, connectionCategory := c.connectWithReadBudget(
		ctx,
		request.configuration.network,
		endpoint,
		budget,
	)
	if connection == nil {
		if budget.isExhausted() {
			return DirectoryInspectionResult{
				Category: DirectoryCategoryLimitExceeded, EndpointPriority: priority,
			}, false
		}
		return DirectoryInspectionResult{
			Category: directoryCategoryFromConnection(connectionCategory), EndpointPriority: priority,
		}, directoryConnectionFailureRetryable(ctx, connectionCategory)
	}
	defer connection.close()
	stopClose := context.AfterFunc(ctx, func() { _ = connection.raw.Close() })
	defer stopClose()

	bindCategory := bindDirectoryConnection(
		ctx,
		connection.ldap,
		request.configuration.bindDN,
		bindSecret,
	)
	if bindCategory != DirectoryCategorySuccess {
		return DirectoryInspectionResult{Category: bindCategory, EndpointPriority: priority},
			directoryServiceFailureRetryable(ctx, bindCategory)
	}

	state := &directorySearchState{
		ctx: ctx, connection: connection.ldap, endpoint: endpoint, limits: request.configuration.limits,
		referrals: &directoryReferralPolicy{
			client: c, network: request.configuration.network, configuration: request.configuration.referrals,
			bindDN: request.configuration.bindDN, bindSecret: bindSecret, budget: budget,
		},
	}
	entries, searchErr := state.search(directorySearchSpec{
		baseDN:           request.baseDN,
		scope:            ldap.ScopeWholeSubtree,
		filter:           request.filter,
		attributes:       request.attributes,
		maxResults:       request.resultLimit + 1,
		stopAtMaxResults: true,
	})
	if searchErr != nil {
		category := directorySearchErrorCategory(ctx, searchErr)
		return DirectoryInspectionResult{Category: category, EndpointPriority: priority},
			category == DirectoryCategoryConnectFailed && !contextEnded(ctx)
	}
	truncated := len(entries) > request.resultLimit
	projectedCount := min(len(entries), request.resultLimit)
	projected := make([]DirectoryEntry, projectedCount)
	copy(projected, entries[:projectedCount])
	return DirectoryInspectionResult{
		Category: DirectoryCategorySuccess, EndpointPriority: priority,
		Truncated: truncated, Entries: projected,
	}, false
}

func sanitizeDirectoryInspectionResult(result DirectoryInspectionResult) DirectoryInspectionResult {
	if result.Category != DirectoryCategorySuccess {
		result.Truncated = false
		result.Entries = nil
	}
	return result
}
