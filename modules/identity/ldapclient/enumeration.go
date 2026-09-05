package ldapclient

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	"golang.org/x/text/cases"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

// DirectoryEnumerationRequest is an immutable configuration snapshot for one
// complete user-population scan. UserSearchFilter is the same closed lookup
// template used by login; the identity package derives its fixed presence
// filter without accepting a raw runtime substitution.
type DirectoryEnumerationRequest struct {
	Configuration    Configuration
	BindDN           string
	UserBaseDN       string
	UserSearchFilter identity.CompiledLDAPTemplate
	UserAttributes   []string
	ReferralMode     DirectoryReferralMode
	ReferralMaxHops  int
	Limits           DirectoryLimits
}

// DirectoryEnumerationResult never exposes partial observations as usable
// data. Complete is true only after validated paging termination. Truncated is
// true only when a configured or process hard limit prevented completion.
type DirectoryEnumerationResult struct {
	Category         DirectoryCategory
	EndpointPriority int
	Complete         bool
	Truncated        bool
	Users            []DirectoryEntry
}

func (result DirectoryEnumerationResult) String() string {
	return fmt.Sprintf(
		"ldapclient.DirectoryEnumerationResult{category:%s,endpointPriority:%d,complete:%t,truncated:%t,userCount:%d,users:[REDACTED]}",
		result.Category,
		result.EndpointPriority,
		result.Complete,
		result.Truncated,
		len(result.Users),
	)
}

func (result DirectoryEnumerationResult) GoString() string { return result.String() }

type validatedDirectoryEnumerationRequest struct {
	network        validatedConfiguration
	bindDN         string
	userBaseDN     *ldap.DN
	userFilter     string
	userAttributes []string
	referrals      validatedDirectoryReferrals
	limits         DirectoryLimits
}

// EnumerateDirectoryUsers returns users only after the server proves complete
// paging termination across the bounded search and any configured referrals.
// Ownership of bindSecret transfers to this call and its backing array is
// cleared on every return path. A timeout, cancellation, malformed response,
// duplicate DN, or limit breach discards every partial entry.
func (c *Client) EnumerateDirectoryUsers(
	ctx context.Context,
	request DirectoryEnumerationRequest,
	bindSecret []byte,
) (DirectoryEnumerationResult, error) {
	defer clear(bindSecret)
	if ctx == nil || c == nil || len(bindSecret) < 1 || len(bindSecret) > maximumBindSecretBytes {
		return DirectoryEnumerationResult{}, ErrInvalidConfiguration
	}
	if contextEnded(ctx) {
		return sanitizeDirectoryEnumerationResult(DirectoryEnumerationResult{
			Category: directoryContextCategory(ctx, ctx),
		}), nil
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return DirectoryEnumerationResult{}, ErrBusy
	}

	validated, err := c.validateDirectoryEnumerationRequest(request)
	if err != nil {
		return DirectoryEnumerationResult{}, ErrInvalidConfiguration
	}
	operationCtx, cancel := context.WithTimeout(ctx, validated.network.operationTimeout)
	defer cancel()
	budget := newInboundReadBudget(int64(validated.limits.MaxResponseBytes + maximumDirectoryTransportOverhead))
	lastResult := DirectoryEnumerationResult{}
	for _, endpoint := range validated.network.endpoints {
		result, retry := c.enumerateDirectoryUsersEndpoint(
			operationCtx,
			validated,
			endpoint,
			bindSecret,
			budget,
		)
		if !retry {
			return sanitizeDirectoryEnumerationResult(result), nil
		}
		lastResult = result
	}
	if contextEnded(operationCtx) {
		lastResult.Category = directoryContextCategory(ctx, operationCtx)
	}
	return sanitizeDirectoryEnumerationResult(lastResult), nil
}

func (c *Client) validateDirectoryEnumerationRequest(
	request DirectoryEnumerationRequest,
) (validatedDirectoryEnumerationRequest, error) {
	network, err := c.validateConfiguration(request.Configuration)
	if err != nil || validateDirectoryLimits(request.Limits) != nil {
		return validatedDirectoryEnumerationRequest{}, ErrInvalidConfiguration
	}
	referrals, err := validateDirectoryReferralPolicy(
		request.Configuration,
		request.ReferralMode,
		request.ReferralMaxHops,
		network,
	)
	if err != nil {
		return validatedDirectoryEnumerationRequest{}, ErrInvalidConfiguration
	}
	bindDN, err := parseBoundedDN(request.BindDN)
	if err != nil {
		return validatedDirectoryEnumerationRequest{}, ErrInvalidConfiguration
	}
	userBaseDN, err := parseBoundedDN(request.UserBaseDN)
	if err != nil {
		return validatedDirectoryEnumerationRequest{}, ErrInvalidConfiguration
	}
	userFilter, err := request.UserSearchFilter.RenderUserEnumerationFilter()
	if err != nil {
		return validatedDirectoryEnumerationRequest{}, ErrInvalidConfiguration
	}
	userAttributes, err := normalizeDirectoryAttributes(request.UserAttributes)
	if err != nil || len(userAttributes) == 0 {
		return validatedDirectoryEnumerationRequest{}, ErrInvalidConfiguration
	}
	return validatedDirectoryEnumerationRequest{
		network:        network,
		bindDN:         bindDN.String(),
		userBaseDN:     userBaseDN,
		userFilter:     userFilter,
		userAttributes: userAttributes,
		referrals:      referrals,
		limits:         request.Limits,
	}, nil
}

func (c *Client) enumerateDirectoryUsersEndpoint(
	ctx context.Context,
	request validatedDirectoryEnumerationRequest,
	endpoint Endpoint,
	bindSecret []byte,
	budget *inboundReadBudget,
) (DirectoryEnumerationResult, bool) {
	priority := endpoint.Priority
	connection, connectionCategory := c.connectWithReadBudget(ctx, request.network, endpoint, budget)
	if connection == nil {
		if budget.isExhausted() {
			return DirectoryEnumerationResult{
				Category: DirectoryCategoryLimitExceeded, EndpointPriority: priority,
			}, false
		}
		return DirectoryEnumerationResult{
			Category:         directoryCategoryFromConnection(connectionCategory),
			EndpointPriority: priority,
		}, directoryConnectionFailureRetryable(ctx, connectionCategory)
	}
	defer connection.close()
	stopClose := context.AfterFunc(ctx, func() { _ = connection.raw.Close() })
	defer stopClose()

	bindCategory := bindDirectoryConnection(ctx, connection.ldap, request.bindDN, bindSecret)
	if bindCategory != DirectoryCategorySuccess {
		return DirectoryEnumerationResult{Category: bindCategory, EndpointPriority: priority},
			directoryServiceFailureRetryable(ctx, bindCategory)
	}

	state := &directorySearchState{
		ctx: ctx, connection: connection.ldap, endpoint: endpoint, limits: request.limits,
		referrals: &directoryReferralPolicy{
			client: c, network: request.network, configuration: request.referrals,
			bindDN: request.bindDN, bindSecret: bindSecret, budget: budget,
		},
	}
	users, searchErr := state.search(directorySearchSpec{
		baseDN:           request.userBaseDN,
		scope:            ldap.ScopeWholeSubtree,
		filter:           request.userFilter,
		attributes:       request.userAttributes,
		maxResults:       request.limits.MaxEntries,
		stopAtMaxResults: false,
	})
	if searchErr != nil {
		category := directorySearchErrorCategory(ctx, searchErr)
		return DirectoryEnumerationResult{Category: category, EndpointPriority: priority},
			directoryServiceFailureRetryable(ctx, category)
	}
	if !sortAndValidateEnumeratedUsers(users) {
		return DirectoryEnumerationResult{
			Category: DirectoryCategoryInvalidEntry, EndpointPriority: priority,
		}, false
	}
	return DirectoryEnumerationResult{
		Category:         DirectoryCategorySuccess,
		EndpointPriority: priority,
		Complete:         true,
		Users:            users,
	}, false
}

func sortAndValidateEnumeratedUsers(users []DirectoryEntry) bool {
	type keyedUser struct {
		entry   DirectoryEntry
		sortKey string
	}
	keyed := make([]keyedUser, len(users))
	seen := make(map[string][]*ldap.DN, len(users))
	fold := cases.Fold()
	for index, user := range users {
		dn, err := parseBoundedDN(user.DistinguishedName)
		if err != nil {
			return false
		}
		key, ok := foldedDirectoryDNKey(dn)
		if !ok {
			return false
		}
		for _, prior := range seen[key] {
			if prior.EqualFold(dn) {
				return false
			}
		}
		seen[key] = append(seen[key], dn)
		keyed[index] = keyedUser{entry: user, sortKey: fold.String(user.DistinguishedName)}
	}
	slices.SortFunc(keyed, func(left, right keyedUser) int {
		if order := strings.Compare(left.sortKey, right.sortKey); order != 0 {
			return order
		}
		return strings.Compare(left.entry.DistinguishedName, right.entry.DistinguishedName)
	})
	for index := range keyed {
		users[index] = keyed[index].entry
	}
	return true
}

func foldedDirectoryDNKey(dn *ldap.DN) (string, bool) {
	if dn == nil {
		return "", false
	}
	fold := cases.Fold()
	var key strings.Builder
	writeFoldedDNPart(&key, strconv.Itoa(len(dn.RDNs)))
	for _, rdn := range dn.RDNs {
		if rdn == nil {
			return "", false
		}
		attributes := make([]string, len(rdn.Attributes))
		for index, attribute := range rdn.Attributes {
			if attribute == nil {
				return "", false
			}
			var encoded strings.Builder
			writeFoldedDNPart(&encoded, fold.String(attribute.Type))
			writeFoldedDNPart(&encoded, fold.String(attribute.Value))
			attributes[index] = encoded.String()
		}
		slices.Sort(attributes)
		writeFoldedDNPart(&key, strconv.Itoa(len(attributes)))
		for _, attribute := range attributes {
			writeFoldedDNPart(&key, attribute)
		}
	}
	return key.String(), true
}

func writeFoldedDNPart(target *strings.Builder, value string) {
	target.WriteString(strconv.Itoa(len(value)))
	target.WriteByte(':')
	target.WriteString(value)
}

func sanitizeDirectoryEnumerationResult(result DirectoryEnumerationResult) DirectoryEnumerationResult {
	if result.Category == DirectoryCategorySuccess && result.Complete && !result.Truncated {
		return result
	}
	result.Complete = false
	result.Truncated = result.Category == DirectoryCategoryLimitExceeded
	result.Users = nil
	return result
}
