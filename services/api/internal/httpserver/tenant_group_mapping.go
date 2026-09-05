package httpserver

import (
	"errors"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

func mapTenantSecurityGroup(value authorization.TenantSecurityGroup) contract.TenantSecurityGroup {
	var description *string
	if value.Description != "" {
		descriptionValue := value.Description
		description = &descriptionValue
	}
	return contract.TenantSecurityGroup{
		Id: value.ID, TenantId: value.TenantID, Key: value.Key, Name: value.Name,
		Description: description, Archived: value.Archived, ArchivedAt: value.ArchivedAt,
		Version: value.Version, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
}

func mapTenantSecurityGroupMembership(
	value authorization.TenantSecurityGroupMembership,
) (contract.TenantSecurityGroupMembership, error) {
	state := contract.AuthorizationEdgeState(value.State)
	if !state.Valid() {
		return contract.TenantSecurityGroupMembership{}, errors.New("unsupported membership edge state")
	}
	member, err := mapTenantUser(value.Member)
	if err != nil {
		return contract.TenantSecurityGroupMembership{}, err
	}
	provenance, err := mapAuthorizationEdgeProvenance(value.Provenance)
	if err != nil {
		return contract.TenantSecurityGroupMembership{}, err
	}
	entityTag, err := authorization.TenantSecurityGroupMembershipEntityTag(value)
	if err != nil {
		return contract.TenantSecurityGroupMembership{}, err
	}
	return contract.TenantSecurityGroupMembership{
		Id: value.ID, TenantId: value.TenantID, Group: mapTenantSecurityGroup(value.Group), Etag: entityTag,
		ManagedByAuthorizationApi: authorizationAPIOwnershipPointer(value.ManagedByAuthorizationAPI),
		Member:                    member, Provenance: provenance, State: state,
		RevokedAt: value.RevokedAt, RevokedByUserId: value.RevokedByUserID, RevokeReason: value.RevokeReason,
		Version: value.Version, UpdatedAt: value.UpdatedAt,
	}, nil
}

func mapTenantSecurityGroupRoleGrant(
	value authorization.TenantSecurityGroupRoleGrant,
) (contract.TenantSecurityGroupRoleGrant, error) {
	state := contract.AuthorizationEdgeState(value.State)
	if !state.Valid() {
		return contract.TenantSecurityGroupRoleGrant{}, errors.New("unsupported role-grant edge state")
	}
	provenance, err := mapAuthorizationEdgeProvenance(value.Provenance)
	if err != nil {
		return contract.TenantSecurityGroupRoleGrant{}, err
	}
	entityTag, err := authorization.TenantSecurityGroupRoleGrantEntityTag(value)
	if err != nil {
		return contract.TenantSecurityGroupRoleGrant{}, err
	}
	return contract.TenantSecurityGroupRoleGrant{
		Id: value.ID, TenantId: value.TenantID, Group: mapTenantSecurityGroup(value.Group), Etag: entityTag,
		ManagedByAuthorizationApi: authorizationAPIOwnershipPointer(value.ManagedByAuthorizationAPI),
		Role:                      mapTenantRoleSummary(value.Role), Provenance: provenance, State: state,
		RevokedAt: value.RevokedAt, RevokedByUserId: value.RevokedByUserID, RevokeReason: value.RevokeReason,
		Version: value.Version, UpdatedAt: value.UpdatedAt,
	}, nil
}
