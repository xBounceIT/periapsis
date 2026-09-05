package ticketing

import (
	"fmt"
	"slices"
	"strings"
)

// RosterPair is one exact team/user eligibility fact resolved by the backend.
// It is not inferred from a role name or from browser state.
type RosterPair struct {
	team EntityID
	user EntityID
}

func NewRosterPair(team, user EntityID) (RosterPair, error) {
	if !validEntityID(team) || !validEntityID(user) {
		return RosterPair{}, ErrInvalidAuthority
	}
	return RosterPair{team: team, user: user}, nil
}

func (pair RosterPair) Team() EntityID { return pair.team }
func (pair RosterPair) User() EntityID { return pair.user }

// AuthorizationSnapshot is an immutable, tenant-bound projection produced by
// backend authorization. UI capability state must never be used to construct it.
// ClaimableTeams already incorporates either an exact live roster or a validated
// override; ManageableTeams and AssignableRoster are separate on purpose.
type AuthorizationSnapshot struct {
	tenant           EntityID
	actor            EntityID
	principal        PrincipalKind
	tenantAccess     bool
	roles            []Key
	permissions      []Permission
	claimableTeams   []EntityID
	manageableTeams  []EntityID
	assignableRoster []RosterPair
}

func NewAuthorizationSnapshot(
	tenant EntityID,
	actor EntityID,
	principal PrincipalKind,
	tenantAccess bool,
	roles []Key,
	permissions []Permission,
	claimableTeams []EntityID,
	manageableTeams []EntityID,
	assignableRoster []RosterPair,
) (AuthorizationSnapshot, error) {
	canonicalRoles, rolesOK := canonicalKeys(roles, maxAuthorityItems)
	canonicalPermissions, permissionsOK := canonicalPermissions(permissions, maxAuthorityItems)
	canonicalClaimTeams, claimTeamsOK := canonicalIDs(claimableTeams, maxAuthorityItems)
	canonicalManageTeams, manageTeamsOK := canonicalIDs(manageableTeams, maxAuthorityItems)
	canonicalRoster, rosterOK := canonicalRoster(assignableRoster)
	if !validEntityID(tenant) || !validEntityID(actor) || !validPrincipalKind(principal) ||
		!rolesOK || !permissionsOK || !claimTeamsOK || !manageTeamsOK || !rosterOK {
		return AuthorizationSnapshot{}, ErrInvalidAuthority
	}
	return AuthorizationSnapshot{
		tenant:           tenant,
		actor:            actor,
		principal:        principal,
		tenantAccess:     tenantAccess,
		roles:            canonicalRoles,
		permissions:      canonicalPermissions,
		claimableTeams:   canonicalClaimTeams,
		manageableTeams:  canonicalManageTeams,
		assignableRoster: canonicalRoster,
	}, nil
}

func (authority AuthorizationSnapshot) Tenant() EntityID         { return authority.tenant }
func (authority AuthorizationSnapshot) Actor() EntityID          { return authority.actor }
func (authority AuthorizationSnapshot) Principal() PrincipalKind { return authority.principal }
func (authority AuthorizationSnapshot) TenantAccess() bool       { return authority.tenantAccess }
func (authority AuthorizationSnapshot) Roles() []Key             { return slices.Clone(authority.roles) }
func (authority AuthorizationSnapshot) Permissions() []Permission {
	return slices.Clone(authority.permissions)
}
func (authority AuthorizationSnapshot) ClaimableTeams() []EntityID {
	return slices.Clone(authority.claimableTeams)
}
func (authority AuthorizationSnapshot) ManageableTeams() []EntityID {
	return slices.Clone(authority.manageableTeams)
}
func (authority AuthorizationSnapshot) AssignableRoster() []RosterPair {
	return slices.Clone(authority.assignableRoster)
}

func (authority AuthorizationSnapshot) String() string {
	return fmt.Sprintf(
		"AuthorizationSnapshot{principal:%s,tenant_access:%t,roles:%d,permissions:%d,claim_teams:%d,manage_teams:%d,roster:%d}",
		authority.principal,
		authority.tenantAccess,
		len(authority.roles),
		len(authority.permissions),
		len(authority.claimableTeams),
		len(authority.manageableTeams),
		len(authority.assignableRoster),
	)
}

func validAuthorizationSnapshot(authority AuthorizationSnapshot) bool {
	roles, rolesOK := canonicalKeys(authority.roles, maxAuthorityItems)
	permissions, permissionsOK := canonicalPermissions(authority.permissions, maxAuthorityItems)
	claimTeams, claimTeamsOK := canonicalIDs(authority.claimableTeams, maxAuthorityItems)
	manageTeams, manageTeamsOK := canonicalIDs(authority.manageableTeams, maxAuthorityItems)
	roster, rosterOK := canonicalRoster(authority.assignableRoster)
	return validEntityID(authority.tenant) && validEntityID(authority.actor) &&
		validPrincipalKind(authority.principal) && rolesOK && slices.Equal(roles, authority.roles) &&
		permissionsOK && slices.Equal(permissions, authority.permissions) &&
		claimTeamsOK && slices.Equal(claimTeams, authority.claimableTeams) &&
		manageTeamsOK && slices.Equal(manageTeams, authority.manageableTeams) &&
		rosterOK && slices.Equal(roster, authority.assignableRoster)
}

func (authority AuthorizationSnapshot) hasPermission(permission Permission) bool {
	_, found := slices.BinarySearchFunc(authority.permissions, permission, func(candidate, target Permission) int {
		return int(candidate) - int(target)
	})
	return found
}

func (authority AuthorizationSnapshot) hasAllPermissions(required []Permission) bool {
	for _, permission := range required {
		if !authority.hasPermission(permission) {
			return false
		}
	}
	return true
}

func (authority AuthorizationSnapshot) hasAnyRole(required []Key) bool {
	if len(required) == 0 {
		return true
	}
	for _, role := range required {
		if _, found := slices.BinarySearchFunc(authority.roles, role, func(candidate, target Key) int {
			return strings.Compare(candidate.value, target.value)
		}); found {
			return true
		}
	}
	return false
}

func (authority AuthorizationSnapshot) mayClaimTeam(team EntityID) bool {
	_, found := slices.BinarySearchFunc(authority.claimableTeams, team, compareEntityID)
	return found
}

func (authority AuthorizationSnapshot) mayManageTeam(team EntityID) bool {
	_, found := slices.BinarySearchFunc(authority.manageableTeams, team, compareEntityID)
	return found
}

func (authority AuthorizationSnapshot) mayAssign(team, user EntityID) bool {
	target := RosterPair{team: team, user: user}
	_, found := slices.BinarySearchFunc(authority.assignableRoster, target, compareRoster)
	return found
}

func canonicalRoster(values []RosterPair) ([]RosterPair, bool) {
	if len(values) > maxAuthorityItems {
		return nil, false
	}
	result := slices.Clone(values)
	for _, pair := range result {
		if !validEntityID(pair.team) || !validEntityID(pair.user) {
			return nil, false
		}
	}
	slices.SortFunc(result, compareRoster)
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, false
		}
	}
	return result, true
}

func compareRoster(left, right RosterPair) int {
	if result := compareEntityID(left.team, right.team); result != 0 {
		return result
	}
	return compareEntityID(left.user, right.user)
}
