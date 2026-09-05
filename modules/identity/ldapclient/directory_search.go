package ldapclient

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"
	"golang.org/x/text/cases"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

var (
	errDirectoryLimit        = errors.New("LDAP directory limit exceeded")
	errDirectoryReferral     = errors.New("LDAP directory referral rejected")
	errDirectoryInvalidEntry = errors.New("LDAP directory entry is invalid")
	errDirectoryProtocol     = errors.New("LDAP directory protocol is invalid")
)

type directoryLDAPConnection interface {
	Bind(username, password string) error
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	SetTimeout(timeout time.Duration)
}

type directorySearchState struct {
	ctx           context.Context
	connection    directoryLDAPConnection
	endpoint      Endpoint
	referrals     *directoryReferralPolicy
	limits        DirectoryLimits
	pages         int
	entries       int
	responseBytes int
}

type directoryReferralPolicy struct {
	client        *Client
	network       validatedConfiguration
	configuration validatedDirectoryReferrals
	bindDN        string
	bindSecret    []byte
	budget        *inboundReadBudget
}

type directorySearchSpec struct {
	baseDN           *ldap.DN
	scope            int
	filter           string
	attributes       []string
	maxResults       int
	stopAtMaxResults bool
}

func (c *Client) authenticateDirectoryEndpoint(
	ctx context.Context,
	request validatedDirectoryRequest,
	endpoint Endpoint,
	bindSecret []byte,
	userPassword []byte,
	budget *inboundReadBudget,
) (DirectoryResult, bool) {
	priority := endpoint.Priority
	serviceConnection, connectionCategory := c.connectWithReadBudget(ctx, request.network, endpoint, budget)
	if serviceConnection == nil {
		if budget.isExhausted() {
			return DirectoryResult{
				Category: DirectoryCategoryLimitExceeded, EndpointPriority: priority,
			}, false
		}
		return DirectoryResult{
			Category:         directoryCategoryFromConnection(connectionCategory),
			EndpointPriority: priority,
		}, directoryConnectionFailureRetryable(ctx, connectionCategory)
	}
	defer serviceConnection.close()
	stopServiceClose := context.AfterFunc(ctx, func() { _ = serviceConnection.raw.Close() })
	defer stopServiceClose()

	serviceBindCategory := bindDirectoryConnection(ctx, serviceConnection.ldap, request.bindDN, bindSecret)
	if serviceBindCategory != DirectoryCategorySuccess {
		return DirectoryResult{Category: serviceBindCategory, EndpointPriority: priority},
			directoryServiceFailureRetryable(ctx, serviceBindCategory)
	}

	state := &directorySearchState{
		ctx: ctx, connection: serviceConnection.ldap, endpoint: endpoint, limits: request.limits,
		referrals: &directoryReferralPolicy{
			client: c, network: request.network, configuration: request.referrals,
			bindDN: request.bindDN, bindSecret: bindSecret, budget: budget,
		},
	}
	userDN, locateCategory := locateDirectoryUser(state, request)
	if locateCategory != DirectoryCategorySuccess {
		return DirectoryResult{Category: locateCategory, EndpointPriority: priority},
			locateCategory == DirectoryCategoryConnectFailed && !contextEnded(ctx)
	}

	// The user password is never sent over the service-bound connection. A
	// second TLS connection to this exact selected endpoint is established and
	// Bind is invoked at most once for the entire operation.
	userConnection, userConnectionCategory := c.connectWithReadBudget(ctx, request.network, endpoint, budget)
	if userConnection == nil {
		if budget.isExhausted() {
			return DirectoryResult{
				Category: DirectoryCategoryLimitExceeded, EndpointPriority: priority,
			}, false
		}
		return DirectoryResult{
			Category:         directoryCategoryFromConnection(userConnectionCategory),
			EndpointPriority: priority,
		}, directoryConnectionFailureRetryable(ctx, userConnectionCategory)
	}
	stopUserClose := context.AfterFunc(ctx, func() { _ = userConnection.raw.Close() })
	userBindCategory := bindDirectoryConnection(ctx, userConnection.ldap, userDN.String(), userPassword)
	stopUserClose()
	userConnection.close()
	if userBindCategory == DirectoryCategoryServiceBindRejected {
		userBindCategory = DirectoryCategoryCredentialsRejected
	}
	if userBindCategory != DirectoryCategorySuccess {
		// Never fail over after Bind was invoked: a network failure may have
		// occurred after the credential reached the selected directory.
		return DirectoryResult{Category: userBindCategory, EndpointPriority: priority}, false
	}

	observation, observationCategory := observeDirectoryUser(state, request, userDN)
	if observationCategory != DirectoryCategorySuccess {
		return DirectoryResult{Category: observationCategory, EndpointPriority: priority}, false
	}
	return DirectoryResult{
		Category:         DirectoryCategorySuccess,
		EndpointPriority: priority,
		Observation:      observation,
	}, false
}

func (c *Client) observeDirectoryEndpoint(
	ctx context.Context,
	request validatedDirectoryRequest,
	endpoint Endpoint,
	bindSecret []byte,
	budget *inboundReadBudget,
) (DirectoryResult, bool) {
	priority := endpoint.Priority
	serviceConnection, connectionCategory := c.connectWithReadBudget(ctx, request.network, endpoint, budget)
	if serviceConnection == nil {
		if budget.isExhausted() {
			return DirectoryResult{
				Category: DirectoryCategoryLimitExceeded, EndpointPriority: priority,
			}, false
		}
		return DirectoryResult{
			Category:         directoryCategoryFromConnection(connectionCategory),
			EndpointPriority: priority,
		}, directoryConnectionFailureRetryable(ctx, connectionCategory)
	}
	defer serviceConnection.close()
	stopServiceClose := context.AfterFunc(ctx, func() { _ = serviceConnection.raw.Close() })
	defer stopServiceClose()

	serviceBindCategory := bindDirectoryConnection(ctx, serviceConnection.ldap, request.bindDN, bindSecret)
	if serviceBindCategory != DirectoryCategorySuccess {
		return DirectoryResult{Category: serviceBindCategory, EndpointPriority: priority},
			directoryServiceFailureRetryable(ctx, serviceBindCategory)
	}

	state := &directorySearchState{
		ctx: ctx, connection: serviceConnection.ldap, endpoint: endpoint, limits: request.limits,
		referrals: &directoryReferralPolicy{
			client: c, network: request.network, configuration: request.referrals,
			bindDN: request.bindDN, bindSecret: bindSecret, budget: budget,
		},
	}
	userDN, locateCategory := locateDirectoryUser(state, request)
	if locateCategory != DirectoryCategorySuccess {
		return DirectoryResult{Category: locateCategory, EndpointPriority: priority},
			locateCategory == DirectoryCategoryConnectFailed && !contextEnded(ctx)
	}
	observation, observationCategory := observeDirectoryUser(state, request, userDN)
	if observationCategory != DirectoryCategorySuccess {
		return DirectoryResult{Category: observationCategory, EndpointPriority: priority},
			observationCategory == DirectoryCategoryConnectFailed && !contextEnded(ctx)
	}
	return DirectoryResult{
		Category:         DirectoryCategorySuccess,
		EndpointPriority: priority,
		Observation:      observation,
	}, false
}

func locateDirectoryUser(
	state *directorySearchState,
	request validatedDirectoryRequest,
) (*ldap.DN, DirectoryCategory) {
	userFilter, err := request.userFilter.Render(identity.LDAPTemplateValues{Username: request.username})
	if err != nil {
		return nil, DirectoryCategoryProtocolFailed
	}
	located, searchErr := state.search(directorySearchSpec{
		baseDN:           request.userBaseDN,
		scope:            ldap.ScopeWholeSubtree,
		filter:           userFilter,
		maxResults:       2,
		stopAtMaxResults: true,
	})
	if len(located) > 1 {
		return nil, DirectoryCategoryUserAmbiguous
	}
	if searchErr != nil {
		return nil, directorySearchErrorCategory(state.ctx, searchErr)
	}
	if len(located) == 0 {
		return nil, DirectoryCategoryUserNotFound
	}
	userDN, err := parseBoundedDN(located[0].DistinguishedName)
	if err != nil || !dnWithin(request.userBaseDN, userDN) {
		return nil, DirectoryCategoryInvalidEntry
	}
	if request.userDNTemplate == nil {
		return userDN, DirectoryCategorySuccess
	}
	rendered, renderErr := request.userDNTemplate.Render(
		identity.LDAPTemplateValues{Username: request.username},
	)
	templateDN, parseErr := parseBoundedDN(rendered)
	if renderErr != nil || parseErr != nil || !templateDN.EqualFold(userDN) {
		return nil, DirectoryCategoryInvalidEntry
	}
	return templateDN, DirectoryCategorySuccess
}

func observeDirectoryUser(
	state *directorySearchState,
	request validatedDirectoryRequest,
	userDN *ldap.DN,
) (DirectoryObservation, DirectoryCategory) {
	userEntries, searchErr := state.search(directorySearchSpec{
		baseDN:           userDN,
		scope:            ldap.ScopeBaseObject,
		filter:           "(objectClass=*)",
		attributes:       request.userAttributes,
		maxResults:       2,
		stopAtMaxResults: true,
	})
	if len(userEntries) > 1 {
		return DirectoryObservation{}, DirectoryCategoryUserAmbiguous
	}
	if searchErr != nil {
		return DirectoryObservation{}, directorySearchErrorCategory(state.ctx, searchErr)
	}
	if len(userEntries) != 1 {
		return DirectoryObservation{}, DirectoryCategoryUserNotFound
	}
	observedDN, err := parseBoundedDN(userEntries[0].DistinguishedName)
	if err != nil || !observedDN.EqualFold(userDN) {
		return DirectoryObservation{}, DirectoryCategoryInvalidEntry
	}

	groups, groupErr := state.resolveGroups(request, userDN, userEntries[0])
	if groupErr != nil {
		return DirectoryObservation{}, directorySearchErrorCategory(state.ctx, groupErr)
	}
	return DirectoryObservation{User: userEntries[0], Groups: groups}, DirectoryCategorySuccess
}

func directoryServiceFailureRetryable(ctx context.Context, category DirectoryCategory) bool {
	if contextEnded(ctx) {
		return false
	}
	return category == DirectoryCategoryConnectFailed || category == DirectoryCategoryProtocolFailed
}

func bindDirectoryConnection(
	ctx context.Context,
	connection directoryLDAPConnection,
	dn string,
	secret []byte,
) DirectoryCategory {
	if contextEnded(ctx) {
		return directoryContextCategory(ctx, ctx)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return DirectoryCategoryProtocolFailed
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return directoryContextCategory(ctx, ctx)
	}
	connection.SetTimeout(remaining)
	// go-ldap requires a string. The copy exists only for this synchronous call
	// and is never returned, formatted, audited, or attached to an error.
	err := connection.Bind(dn, string(secret))
	if err == nil {
		if contextEnded(ctx) {
			return directoryContextCategory(ctx, ctx)
		}
		return DirectoryCategorySuccess
	}
	if contextEnded(ctx) {
		return directoryContextCategory(ctx, ctx)
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		return DirectoryCategoryServiceBindRejected
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultReferral) {
		return DirectoryCategoryReferralRejected
	}
	if errors.Is(err, errDiagnosticReadLimit) {
		return DirectoryCategoryLimitExceeded
	}
	if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
		return DirectoryCategoryConnectFailed
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultTimeLimitExceeded) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultTimeout) {
		return DirectoryCategoryConnectTimeout
	}
	return DirectoryCategoryProtocolFailed
}

func directoryConnectionFailureRetryable(ctx context.Context, category Category) bool {
	if contextEnded(ctx) {
		return false
	}
	switch category {
	case CategoryDNSFailed, CategoryConnectFailed, CategoryTLSFailed, CategoryCertificateRejected:
		return true
	default:
		return false
	}
}

type directoryReferralTraversal struct {
	completed map[directoryEndpointOrigin]struct{}
}

func (state *directorySearchState) search(spec directorySearchSpec) ([]DirectoryEntry, error) {
	if state == nil {
		return nil, errDirectoryProtocol
	}
	traversal := &directoryReferralTraversal{
		completed: make(map[directoryEndpointOrigin]struct{}),
	}
	path := make(map[directoryEndpointOrigin]struct{})
	if state != nil && state.endpoint.Enabled {
		origin := directoryOriginForEndpoint(state.endpoint)
		path[origin] = struct{}{}
		traversal.completed[origin] = struct{}{}
	}
	return state.searchOnConnection(spec, state.connection, state.endpoint, traversal, 0, path)
}

func (state *directorySearchState) searchOnConnection(
	spec directorySearchSpec,
	connection directoryLDAPConnection,
	endpoint Endpoint,
	traversal *directoryReferralTraversal,
	depth int,
	path map[directoryEndpointOrigin]struct{},
) ([]DirectoryEntry, error) {
	if state == nil || connection == nil || traversal == nil || traversal.completed == nil ||
		spec.baseDN == nil || spec.maxResults < 1 ||
		spec.scope != ldap.ScopeBaseObject && spec.scope != ldap.ScopeWholeSubtree {
		return nil, errDirectoryProtocol
	}
	attributes := append([]string(nil), spec.attributes...)
	allowedAttributes := make(map[string]struct{}, len(attributes))
	for _, attribute := range attributes {
		allowedAttributes[attribute] = struct{}{}
	}
	if len(attributes) == 0 {
		// LDAP's empty attribute list means all user attributes. 1.1 is the
		// standard no-attributes selector and keeps locate queries value-free.
		attributes = []string{"1.1"}
	}

	entries := make([]DirectoryEntry, 0, min(spec.maxResults, state.limits.PageSize))
	seenCookies := make(map[string]struct{})
	var cookie []byte
	hadPagingCookie := false
	for {
		if contextEnded(state.ctx) {
			return entries, directoryEndedError(state.ctx)
		}
		if state.pages >= state.limits.MaxPages || state.entries >= state.limits.MaxEntries {
			return entries, errDirectoryLimit
		}
		state.pages++
		remainingEntries := state.limits.MaxEntries - state.entries
		remainingResults := spec.maxResults - len(entries)
		if remainingResults < 1 {
			return entries, nil
		}
		requestLimit := min(remainingEntries, remainingResults)
		if requestLimit < 1 {
			return entries, errDirectoryLimit
		}
		paging := ldap.NewControlPaging(uint32(state.limits.PageSize))
		paging.SetCookie(append([]byte(nil), cookie...))
		timeLimit, ok := directoryRemainingSeconds(state.ctx)
		if !ok {
			if state.ctx.Err() != nil {
				return entries, state.ctx.Err()
			}
			return entries, errDirectoryProtocol
		}
		request := ldap.NewSearchRequest(
			spec.baseDN.String(),
			spec.scope,
			ldap.NeverDerefAliases,
			requestLimit,
			timeLimit,
			false,
			spec.filter,
			attributes,
			[]ldap.Control{paging},
		)
		request.EnforceSizeLimit = true
		if deadline, deadlineOK := state.ctx.Deadline(); deadlineOK {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return entries, state.ctx.Err()
			}
			connection.SetTimeout(remaining)
		}
		result, searchErr := connection.Search(request)
		if contextEnded(state.ctx) {
			return entries, directoryEndedError(state.ctx)
		}
		originEntryCount := 0
		if result != nil {
			if len(result.Entries) > state.limits.PageSize {
				return entries, errDirectoryLimit
			}
			originEntryCount = len(result.Entries)
			for _, raw := range result.Entries {
				entry, copyErr := state.copyEntry(raw, allowedAttributes, spec.baseDN, spec.scope)
				if copyErr != nil {
					return entries, copyErr
				}
				state.entries++
				entries = append(entries, entry)
				if state.entries > state.limits.MaxEntries {
					return entries, errDirectoryLimit
				}
				if spec.stopAtMaxResults && len(entries) >= spec.maxResults {
					return entries, nil
				}
				if len(entries) > spec.maxResults {
					return entries, errDirectoryLimit
				}
			}
		}

		doneReferrals, referralResult, referralExtractErr := directoryLDAPErrorReferrals(searchErr)
		if referralExtractErr != nil {
			return entries, referralExtractErr
		}
		if searchErr != nil && !referralResult {
			return entries, normalizeDirectorySearchError(state.ctx, searchErr)
		}
		if result == nil {
			return entries, errDirectoryProtocol
		}
		if len(result.Referrals) != 0 {
			remaining := spec.maxResults - len(entries)
			if remaining < 1 {
				if spec.stopAtMaxResults {
					return entries, nil
				}
				return entries, errDirectoryLimit
			}
			referralSpec := spec
			referralSpec.maxResults = remaining
			referred, referralErr := state.followReferralReferences(
				referralSpec,
				result.Referrals,
				traversal,
				depth,
				path,
			)
			entries = append(entries, referred...)
			if referralErr != nil {
				return entries, referralErr
			}
			if len(entries) >= spec.maxResults {
				if spec.stopAtMaxResults {
					return entries, nil
				}
				if len(entries) > spec.maxResults {
					return entries, errDirectoryLimit
				}
			}
		}
		if referralResult {
			remaining := spec.maxResults - len(entries)
			if remaining < 1 {
				if spec.stopAtMaxResults {
					return entries, nil
				}
				return entries, errDirectoryLimit
			}
			referralSpec := spec
			referralSpec.maxResults = remaining
			referred, referralErr := state.followReferralAlternatives(
				referralSpec,
				doneReferrals,
				traversal,
				depth,
				path,
			)
			entries = append(entries, referred...)
			if referralErr != nil {
				return entries, referralErr
			}
			if len(entries) > spec.maxResults {
				return entries, errDirectoryLimit
			}
			return entries, nil
		}

		nextCookie, present, controlErr := directoryPagingCookie(result.Controls)
		if controlErr != nil {
			return entries, controlErr
		}
		if !present {
			if hadPagingCookie {
				return entries, errDirectoryProtocol
			}
			if originEntryCount >= requestLimit {
				return entries, errDirectoryLimit
			}
			return entries, nil
		}
		if len(nextCookie) == 0 {
			return entries, nil
		}
		if len(entries) >= spec.maxResults {
			return entries, errDirectoryLimit
		}
		hadPagingCookie = true
		if len(nextCookie) > maximumDirectoryPagingCookieBytes {
			return entries, errDirectoryLimit
		}
		key := string(nextCookie)
		if _, repeated := seenCookies[key]; repeated {
			return entries, errDirectoryProtocol
		}
		seenCookies[key] = struct{}{}
		cookie = append(cookie[:0], nextCookie...)
	}
}

func (state *directorySearchState) followReferralReferences(
	spec directorySearchSpec,
	referralURLs []string,
	traversal *directoryReferralTraversal,
	depth int,
	path map[directoryEndpointOrigin]struct{},
) ([]DirectoryEntry, error) {
	targets, err := state.validatedReferralTargets(referralURLs, depth, path)
	if err != nil {
		return nil, err
	}
	entries := make([]DirectoryEntry, 0)
	for _, target := range targets {
		origin := directoryOriginForEndpoint(target)
		if _, alreadyCompleted := traversal.completed[origin]; alreadyCompleted {
			continue
		}
		remaining := spec.maxResults - len(entries)
		if remaining < 1 {
			if spec.stopAtMaxResults {
				return entries, nil
			}
			return entries, errDirectoryLimit
		}
		targetSpec := spec
		targetSpec.maxResults = remaining
		referred, referralErr, _ := state.searchReferralEndpoint(
			targetSpec,
			target,
			traversal,
			depth,
			path,
		)
		entries = append(entries, referred...)
		if referralErr != nil {
			return entries, referralErr
		}
		traversal.completed[origin] = struct{}{}
	}
	return entries, nil
}

func (state *directorySearchState) followReferralAlternatives(
	spec directorySearchSpec,
	referralURLs []string,
	traversal *directoryReferralTraversal,
	depth int,
	path map[directoryEndpointOrigin]struct{},
) ([]DirectoryEntry, error) {
	targets, err := state.validatedReferralTargets(referralURLs, depth, path)
	if err != nil {
		return nil, err
	}
	var lastError error
	for index, target := range targets {
		origin := directoryOriginForEndpoint(target)
		if _, alreadyCompleted := traversal.completed[origin]; alreadyCompleted {
			return nil, nil
		}
		entries, referralErr, searchStarted := state.searchReferralEndpoint(
			spec,
			target,
			traversal,
			depth,
			path,
		)
		if referralErr == nil {
			traversal.completed[origin] = struct{}{}
			return entries, nil
		}
		lastError = referralErr
		if searchStarted || !directoryReferralAlternativeRetryable(referralErr) || index == len(targets)-1 {
			return entries, referralErr
		}
	}
	if lastError != nil {
		return nil, lastError
	}
	return nil, errDirectoryReferral
}

func (state *directorySearchState) validatedReferralTargets(
	referralURLs []string,
	depth int,
	path map[directoryEndpointOrigin]struct{},
) ([]Endpoint, error) {
	if state == nil || state.referrals == nil || !state.referrals.configuration.enabled ||
		len(referralURLs) < 1 || len(referralURLs) > maximumDirectoryReferralsPerResponse ||
		depth >= state.referrals.configuration.maxHops {
		return nil, errDirectoryReferral
	}
	targets := make([]Endpoint, 0, len(referralURLs))
	seen := make(map[directoryEndpointOrigin]struct{}, len(referralURLs))
	for _, rawURL := range referralURLs {
		if err := state.consumeResponseBytes(len(rawURL)); err != nil {
			return nil, err
		}
		endpoint, err := directoryReferralEndpoint(rawURL, state.referrals.configuration.endpoints)
		if err != nil {
			return nil, errDirectoryReferral
		}
		origin := directoryOriginForEndpoint(endpoint)
		if _, loop := path[origin]; loop {
			return nil, errDirectoryReferral
		}
		if _, duplicate := seen[origin]; duplicate {
			continue
		}
		seen[origin] = struct{}{}
		targets = append(targets, endpoint)
	}
	if len(targets) == 0 {
		return nil, errDirectoryReferral
	}
	return targets, nil
}

func (state *directorySearchState) searchReferralEndpoint(
	spec directorySearchSpec,
	target Endpoint,
	traversal *directoryReferralTraversal,
	depth int,
	path map[directoryEndpointOrigin]struct{},
) ([]DirectoryEntry, error, bool) {
	policy := state.referrals
	if policy == nil || policy.client == nil || policy.budget == nil {
		return nil, errDirectoryReferral, false
	}
	connection, category := policy.client.connectWithReadBudget(
		state.ctx,
		policy.network,
		target,
		policy.budget,
	)
	if connection == nil {
		if policy.budget.isExhausted() {
			return nil, newDirectoryCategorizedError(DirectoryCategoryLimitExceeded), false
		}
		return nil, newDirectoryCategorizedError(directoryCategoryFromConnection(category)), false
	}
	defer connection.close()
	stopClose := context.AfterFunc(state.ctx, func() { _ = connection.raw.Close() })
	defer stopClose()

	bindCategory := bindDirectoryConnection(state.ctx, connection.ldap, policy.bindDN, policy.bindSecret)
	if bindCategory != DirectoryCategorySuccess {
		return nil, newDirectoryCategorizedError(bindCategory), false
	}
	nextPath := cloneDirectoryReferralPath(path)
	nextPath[directoryOriginForEndpoint(target)] = struct{}{}
	entries, err := state.searchOnConnection(
		spec,
		connection.ldap,
		target,
		traversal,
		depth+1,
		nextPath,
	)
	return entries, err, true
}

func cloneDirectoryReferralPath(
	source map[directoryEndpointOrigin]struct{},
) map[directoryEndpointOrigin]struct{} {
	result := make(map[directoryEndpointOrigin]struct{}, len(source)+1)
	for origin := range source {
		result[origin] = struct{}{}
	}
	return result
}

func directoryReferralAlternativeRetryable(err error) bool {
	var categorized directoryCategorizedError
	if !errors.As(err, &categorized) {
		return false
	}
	switch categorized.category {
	case DirectoryCategoryDNSFailed,
		DirectoryCategoryConnectFailed,
		DirectoryCategoryTLSFailed,
		DirectoryCategoryCertificateRejected:
		return true
	default:
		return false
	}
}

func (state *directorySearchState) copyEntry(
	entry *ldap.Entry,
	allowedAttributes map[string]struct{},
	baseDN *ldap.DN,
	scope int,
) (DirectoryEntry, error) {
	if entry == nil || len(entry.Attributes) > maximumDirectoryAttributes {
		return DirectoryEntry{}, errDirectoryInvalidEntry
	}
	dn, err := parseBoundedDN(entry.DN)
	if err != nil || scope == ldap.ScopeBaseObject && !baseDN.EqualFold(dn) ||
		scope == ldap.ScopeWholeSubtree && !dnWithin(baseDN, dn) {
		return DirectoryEntry{}, errDirectoryInvalidEntry
	}
	result := DirectoryEntry{DistinguishedName: dn.String()}
	if err := state.consumeResponseBytes(len(result.DistinguishedName)); err != nil {
		return DirectoryEntry{}, err
	}
	seen := make(map[string]struct{}, len(entry.Attributes))
	for _, attribute := range entry.Attributes {
		if attribute == nil || len(attribute.Values) != len(attribute.ByteValues) ||
			len(attribute.ByteValues) > maximumDirectoryValuesPerAttribute {
			return DirectoryEntry{}, errDirectoryInvalidEntry
		}
		name, nameErr := normalizeOptionalDirectoryAttribute(attribute.Name)
		if nameErr != nil || name == "" {
			return DirectoryEntry{}, errDirectoryInvalidEntry
		}
		if _, allowed := allowedAttributes[name]; !allowed {
			return DirectoryEntry{}, errDirectoryInvalidEntry
		}
		if _, duplicate := seen[name]; duplicate {
			return DirectoryEntry{}, errDirectoryInvalidEntry
		}
		seen[name] = struct{}{}
		if err := state.consumeResponseBytes(len(name)); err != nil {
			return DirectoryEntry{}, err
		}
		copied := DirectoryAttribute{Name: name, Values: make([][]byte, len(attribute.ByteValues))}
		for index, value := range attribute.ByteValues {
			if len(value) > maximumDirectoryAttributeValueBytes {
				return DirectoryEntry{}, errDirectoryLimit
			}
			if err := state.consumeResponseBytes(len(value)); err != nil {
				return DirectoryEntry{}, err
			}
			copied.Values[index] = append([]byte(nil), value...)
		}
		slices.SortFunc(copied.Values, bytes.Compare)
		for index := 1; index < len(copied.Values); index++ {
			if bytes.Equal(copied.Values[index-1], copied.Values[index]) {
				return DirectoryEntry{}, errDirectoryInvalidEntry
			}
		}
		result.Attributes = append(result.Attributes, copied)
	}
	slices.SortFunc(result.Attributes, func(left, right DirectoryAttribute) int {
		return strings.Compare(left.Name, right.Name)
	})
	return result, nil
}

func (state *directorySearchState) consumeResponseBytes(count int) error {
	if count < 0 || count > state.limits.MaxResponseBytes-state.responseBytes {
		return errDirectoryLimit
	}
	state.responseBytes += count
	return nil
}

func directoryPagingCookie(controls []ldap.Control) ([]byte, bool, error) {
	if len(controls) > maximumDirectoryResponseControls {
		return nil, false, errDirectoryLimit
	}
	var paging *ldap.ControlPaging
	for _, control := range controls {
		if control == nil || control.GetControlType() != ldap.ControlTypePaging {
			return nil, false, errDirectoryProtocol
		}
		value, ok := control.(*ldap.ControlPaging)
		if !ok || paging != nil {
			return nil, false, errDirectoryProtocol
		}
		paging = value
	}
	if paging == nil {
		return nil, false, nil
	}
	return append([]byte(nil), paging.Cookie...), true, nil
}

func normalizeDirectorySearchError(ctx context.Context, err error) error {
	if contextEnded(ctx) {
		return directoryEndedError(ctx)
	}
	if errors.Is(err, errDiagnosticReadLimit) || errors.Is(err, ldap.ErrSizeLimitExceeded) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultAdminLimitExceeded) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultReferralLimitExceeded) {
		return errDirectoryLimit
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultReferral) {
		return errDirectoryReferral
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultTimeLimitExceeded) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultTimeout) {
		return context.DeadlineExceeded
	}
	if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
		return err
	}
	return errDirectoryProtocol
}

func directoryEndedError(ctx context.Context) error {
	if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		return context.Canceled
	}
	return context.DeadlineExceeded
}

func directorySearchErrorCategory(ctx context.Context, err error) DirectoryCategory {
	if contextEnded(ctx) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return directoryContextCategory(ctx, ctx)
	}
	var categorized directoryCategorizedError
	if errors.As(err, &categorized) {
		return categorized.category
	}
	switch {
	case errors.Is(err, errDirectoryLimit):
		return DirectoryCategoryLimitExceeded
	case errors.Is(err, errDirectoryReferral):
		return DirectoryCategoryReferralRejected
	case errors.Is(err, errDirectoryInvalidEntry):
		return DirectoryCategoryInvalidEntry
	case ldap.IsErrorWithCode(err, ldap.ErrorNetwork):
		return DirectoryCategoryConnectFailed
	default:
		return DirectoryCategoryProtocolFailed
	}
}

func dnWithin(base, candidate *ldap.DN) bool {
	return base != nil && candidate != nil && (base.EqualFold(candidate) || base.AncestorOfFold(candidate))
}

func (state *directorySearchState) resolveGroups(
	request validatedDirectoryRequest,
	userDN *ldap.DN,
	user DirectoryEntry,
) ([]DirectoryEntry, error) {
	groups := newDirectoryGroupSet(request.groups.maxGroups)
	if attribute := directoryEntryAttribute(user, request.groups.directMembershipAttribute); attribute != nil {
		for _, value := range attribute.Values {
			if !utf8BoundedDirectoryValue(value) {
				return nil, errDirectoryInvalidEntry
			}
			dn, err := parseBoundedDN(string(value))
			if err != nil || request.groups.baseDN != nil && !dnWithin(request.groups.baseDN, dn) {
				return nil, errDirectoryInvalidEntry
			}
			if err := groups.add(DirectoryEntry{DistinguishedName: dn.String()}); err != nil {
				return nil, err
			}
		}
	}

	switch request.groups.mode {
	case DirectoryGroupModeDisabled:
		return groups.sorted(), nil
	case DirectoryGroupModePOSIXMemberUID:
		values := identity.LDAPTemplateValues{Username: request.username}
		requirements, err := request.groups.searchFilter.Requirements()
		if err != nil {
			return nil, errDirectoryProtocol
		}
		if requirements.GIDNumber {
			attribute := directoryEntryAttribute(user, request.groups.posixGIDNumberAttribute)
			if attribute == nil || len(attribute.Values) != 1 || !utf8BoundedDirectoryValue(attribute.Values[0]) {
				return nil, errDirectoryInvalidEntry
			}
			gid, parseErr := identity.ParseLDAPGIDNumber(string(attribute.Values[0]))
			if parseErr != nil {
				return nil, errDirectoryInvalidEntry
			}
			values.GIDNumber = gid
		}
		filter, err := request.groups.searchFilter.Render(values)
		if err != nil {
			return nil, errDirectoryProtocol
		}
		entries, err := state.search(directorySearchSpec{
			baseDN:     request.groups.baseDN,
			scope:      ldap.ScopeWholeSubtree,
			filter:     filter,
			attributes: request.groups.attributes,
			maxResults: request.groups.maxGroups,
		})
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if err := groups.add(entry); err != nil {
				return nil, err
			}
		}
		return groups.sorted(), nil
	case DirectoryGroupModeActiveDirectory, DirectoryGroupModeReverseSearch:
		return state.resolveReverseGroups(request, userDN, groups)
	default:
		return nil, errDirectoryProtocol
	}
}

func (state *directorySearchState) resolveReverseGroups(
	request validatedDirectoryRequest,
	userDN *ldap.DN,
	groups *directoryGroupSet,
) ([]DirectoryEntry, error) {
	frontier := []*ldap.DN{userDN}
	boundary := make([]*ldap.DN, 0)
	queued := map[string]struct{}{directoryDNKey(userDN): {}}
	for depth := 1; depth <= request.groups.maxDepth && len(frontier) != 0; depth++ {
		next := make([]*ldap.DN, 0)
		for _, memberDN := range frontier {
			typedDN, err := identity.ParseLDAPDistinguishedName(memberDN.String())
			if err != nil {
				return nil, errDirectoryInvalidEntry
			}
			filter, err := request.groups.searchFilter.Render(identity.LDAPTemplateValues{
				Username: request.username,
				UserDN:   typedDN,
			})
			if err != nil {
				return nil, errDirectoryProtocol
			}
			remaining := request.groups.maxGroups - groups.len()
			if remaining < 1 {
				return nil, errDirectoryLimit
			}
			entries, err := state.search(directorySearchSpec{
				baseDN:     request.groups.baseDN,
				scope:      ldap.ScopeWholeSubtree,
				filter:     filter,
				attributes: request.groups.attributes,
				maxResults: remaining,
			})
			if err != nil {
				return nil, err
			}
			for _, entry := range entries {
				_, addErr := groups.addNew(entry)
				if addErr != nil {
					return nil, addErr
				}
				dn, parseErr := parseBoundedDN(entry.DistinguishedName)
				if parseErr != nil {
					return nil, errDirectoryInvalidEntry
				}
				key := directoryDNKey(dn)
				if _, alreadyQueued := queued[key]; alreadyQueued {
					continue
				}
				queued[key] = struct{}{}
				if depth < request.groups.maxDepth {
					next = append(next, dn)
				} else {
					boundary = append(boundary, dn)
				}
			}
		}
		frontier = next
	}
	// A depth ceiling is not a truncation license. Probe the boundary and fail
	// closed if any previously unseen parent exists beyond the configured
	// maximum. Cycles and duplicate paths that resolve only to known groups are
	// harmless and remain deduplicated.
	for _, memberDN := range boundary {
		typedDN, err := identity.ParseLDAPDistinguishedName(memberDN.String())
		if err != nil {
			return nil, errDirectoryInvalidEntry
		}
		filter, err := request.groups.searchFilter.Render(identity.LDAPTemplateValues{
			Username: request.username,
			UserDN:   typedDN,
		})
		if err != nil {
			return nil, errDirectoryProtocol
		}
		entries, err := state.search(directorySearchSpec{
			baseDN:     request.groups.baseDN,
			scope:      ldap.ScopeWholeSubtree,
			filter:     filter,
			attributes: request.groups.attributes,
			maxResults: request.groups.maxGroups,
		})
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if !groups.contains(entry.DistinguishedName) {
				return nil, errDirectoryLimit
			}
		}
	}
	return groups.sorted(), nil
}

type directoryGroupSet struct {
	maximum int
	entries map[string]DirectoryEntry
}

func newDirectoryGroupSet(maximum int) *directoryGroupSet {
	return &directoryGroupSet{maximum: maximum, entries: make(map[string]DirectoryEntry)}
}

func (groups *directoryGroupSet) len() int {
	return len(groups.entries)
}

func (groups *directoryGroupSet) contains(distinguishedName string) bool {
	dn, err := parseBoundedDN(distinguishedName)
	if err != nil {
		return false
	}
	_, found := groups.entries[directoryDNKey(dn)]
	return found
}

func (groups *directoryGroupSet) add(entry DirectoryEntry) error {
	_, err := groups.addNew(entry)
	return err
}

func (groups *directoryGroupSet) addNew(entry DirectoryEntry) (bool, error) {
	dn, err := parseBoundedDN(entry.DistinguishedName)
	if err != nil {
		return false, errDirectoryInvalidEntry
	}
	entry.DistinguishedName = dn.String()
	key := directoryDNKey(dn)
	if existing, found := groups.entries[key]; found {
		switch {
		case len(existing.Attributes) == 0 && len(entry.Attributes) != 0:
			groups.entries[key] = entry
			return true, nil
		case len(entry.Attributes) == 0:
		case directoryEntriesEqual(existing, entry):
		default:
			return false, errDirectoryInvalidEntry
		}
		return false, nil
	}
	if len(groups.entries) >= groups.maximum {
		return false, errDirectoryLimit
	}
	groups.entries[key] = entry
	return true, nil
}

func (groups *directoryGroupSet) sorted() []DirectoryEntry {
	result := make([]DirectoryEntry, 0, len(groups.entries))
	for _, entry := range groups.entries {
		result = append(result, entry)
	}
	slices.SortFunc(result, func(left, right DirectoryEntry) int {
		leftDN, _ := parseBoundedDN(left.DistinguishedName)
		rightDN, _ := parseBoundedDN(right.DistinguishedName)
		return strings.Compare(directoryDNKey(leftDN), directoryDNKey(rightDN))
	})
	return result
}

func directoryEntriesEqual(left, right DirectoryEntry) bool {
	leftDN, leftErr := parseBoundedDN(left.DistinguishedName)
	rightDN, rightErr := parseBoundedDN(right.DistinguishedName)
	if leftErr != nil || rightErr != nil || !leftDN.EqualFold(rightDN) ||
		len(left.Attributes) != len(right.Attributes) {
		return false
	}
	for index := range left.Attributes {
		if left.Attributes[index].Name != right.Attributes[index].Name ||
			len(left.Attributes[index].Values) != len(right.Attributes[index].Values) {
			return false
		}
		for valueIndex := range left.Attributes[index].Values {
			if !bytes.Equal(left.Attributes[index].Values[valueIndex], right.Attributes[index].Values[valueIndex]) {
				return false
			}
		}
	}
	return true
}

func directoryDNKey(dn *ldap.DN) string {
	if dn == nil {
		return ""
	}
	return cases.Fold().String(dn.String())
}

func directoryEntryAttribute(entry DirectoryEntry, name string) *DirectoryAttribute {
	if name == "" {
		return nil
	}
	index, found := slices.BinarySearchFunc(entry.Attributes, name, func(attribute DirectoryAttribute, target string) int {
		return strings.Compare(attribute.Name, target)
	})
	if !found {
		return nil
	}
	return &entry.Attributes[index]
}

func utf8BoundedDirectoryValue(value []byte) bool {
	return len(value) > 0 && len(value) <= maximumDirectoryAttributeValueBytes &&
		utf8.Valid(value) && strings.TrimSpace(string(value)) == string(value)
}
