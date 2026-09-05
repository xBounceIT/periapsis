package authorization

import (
	"strings"
	"testing"
	"time"
)

func TestEdgeEntityTagsAreDeterministicAndRepresentationBound(t *testing.T) {
	role := serviceTestRole(serviceTestID(150), false, validRolePolicy())
	userID := serviceTestID(151)
	direct := serviceTestDirectGrant(serviceTestID(152), userID, role, "Direct grant", nil)
	group := serviceTestGroup(serviceTestID(153), "incident_commanders")
	membership := serviceTestGroupMembership(serviceTestID(154), userID, group)
	groupGrant := TenantSecurityGroupRoleGrant{
		ID: serviceTestID(155), TenantID: testTenantID, Group: group,
		Role: role.TenantRoleSummary,
		Provenance: AuthorizationEdgeProvenance{
			SourceKind: AuthorizationSourceManual, SourceID: uuidPointer(serviceTestID(156)),
			GrantedByUserID: uuidPointer(testPrincipalID), GrantedAt: serviceTestNow.Add(-time.Hour),
			Reason: "Group role grant",
		},
		State: AuthorizationEdgeStateActive, Version: 1, UpdatedAt: serviceTestNow,
	}

	tests := []struct {
		name    string
		current func() (string, error)
		mutate  func()
	}{
		{
			name: "direct live role rename",
			current: func() (string, error) {
				return DirectUserRoleGrantEntityTag(direct)
			},
			mutate: func() { direct.Role.Name = "Renamed responder" },
		},
		{
			name: "membership user deactivation",
			current: func() (string, error) {
				return TenantSecurityGroupMembershipEntityTag(membership)
			},
			mutate: func() { membership.Member.User.Active = false },
		},
		{
			name: "group grant source retirement",
			current: func() (string, error) {
				return TenantSecurityGroupRoleGrantEntityTag(groupGrant)
			},
			mutate: func() {
				retiredAt := serviceTestNow
				groupGrant.Provenance.RetiredAt = &retiredAt
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			before, err := test.current()
			if err != nil {
				t.Fatalf("entity tag before mutation: %v", err)
			}
			repeated, err := test.current()
			if err != nil || repeated != before {
				t.Fatalf("repeated entity tag = (%q, %v), want (%q, nil)", repeated, err, before)
			}
			version, err := ParseEdgeEntityTag(before)
			if err != nil || version != 1 {
				t.Fatalf("ParseEdgeEntityTag(%q) = (%d, %v), want (1, nil)", before, version, err)
			}

			test.mutate()
			after, err := test.current()
			if err != nil {
				t.Fatalf("entity tag after mutation: %v", err)
			}
			if after == before {
				t.Fatalf("entity tag did not change after the selected representation changed: %q", after)
			}
		})
	}
}

func TestDirectRoleGrantEntityTagIncludesRevocationReason(t *testing.T) {
	role := serviceTestRole(serviceTestID(157), false, validRolePolicy())
	grant := serviceTestDirectGrant(
		serviceTestID(158), serviceTestID(159), role, "Direct grant", nil,
	)
	revokedAt := serviceTestNow.Add(time.Minute)
	revokerID := serviceTestID(160)
	reason := "Removed after access review"
	grant.State = DirectRoleGrantStateRevoked
	grant.RevokedAt = &revokedAt
	grant.RevokedByUserID = &revokerID
	grant.RevokeReason = &reason
	grant.Version = 2
	grant.UpdatedAt = revokedAt

	before, err := DirectUserRoleGrantEntityTag(grant)
	if err != nil {
		t.Fatalf("entity tag before revoke-reason change: %v", err)
	}
	updatedReason := "Removed after quarterly access review"
	grant.RevokeReason = &updatedReason
	after, err := DirectUserRoleGrantEntityTag(grant)
	if err != nil {
		t.Fatalf("entity tag after revoke-reason change: %v", err)
	}
	if before == after {
		t.Fatalf("entity tag did not change with revocation reason: %q", before)
	}
}

func TestDirectRoleGrantEntityTagIgnoresRepositoryOwnershipMetadata(t *testing.T) {
	role := serviceTestRole(serviceTestID(161), false, validRolePolicy())
	grant := serviceTestDirectGrant(
		serviceTestID(162), serviceTestID(163), role, "Direct grant", nil,
	)
	grant.ManagedByAuthorizationAPI = false
	unmanaged, err := DirectUserRoleGrantEntityTag(grant)
	if err != nil {
		t.Fatalf("unmanaged entity tag: %v", err)
	}
	grant.ManagedByAuthorizationAPI = true
	managed, err := DirectUserRoleGrantEntityTag(grant)
	if err != nil {
		t.Fatalf("managed entity tag: %v", err)
	}
	if managed != unmanaged {
		t.Fatalf("repository ownership changed public validator: %q != %q", managed, unmanaged)
	}
}

func TestSecurityGroupEntityTagsIgnoreRepositoryOwnershipMetadata(t *testing.T) {
	group := serviceTestGroup(serviceTestID(164), "incident_responders")
	membership := serviceTestGroupMembership(
		serviceTestID(165), serviceTestID(166), group,
	)
	role := serviceTestRole(serviceTestID(167), false, validRolePolicy())
	roleGrant := TenantSecurityGroupRoleGrant{
		ID: serviceTestID(168), TenantID: testTenantID, Group: group,
		Role: role.TenantRoleSummary,
		Provenance: AuthorizationEdgeProvenance{
			SourceKind: AuthorizationSourceManual, SourceID: uuidPointer(serviceTestID(169)),
			GrantedByUserID: uuidPointer(testPrincipalID), GrantedAt: serviceTestNow.Add(-time.Hour),
			Reason: "Group role grant",
		},
		State: AuthorizationEdgeStateActive, Version: 1, UpdatedAt: serviceTestNow,
	}

	membership.ManagedByAuthorizationAPI = false
	unmanagedMembership, err := TenantSecurityGroupMembershipEntityTag(membership)
	if err != nil {
		t.Fatalf("unmanaged membership entity tag: %v", err)
	}
	membership.ManagedByAuthorizationAPI = true
	managedMembership, err := TenantSecurityGroupMembershipEntityTag(membership)
	if err != nil {
		t.Fatalf("managed membership entity tag: %v", err)
	}
	if managedMembership != unmanagedMembership {
		t.Fatalf("membership ownership changed public validator: %q != %q", managedMembership, unmanagedMembership)
	}

	roleGrant.ManagedByAuthorizationAPI = false
	unmanagedRoleGrant, err := TenantSecurityGroupRoleGrantEntityTag(roleGrant)
	if err != nil {
		t.Fatalf("unmanaged group role-grant entity tag: %v", err)
	}
	roleGrant.ManagedByAuthorizationAPI = true
	managedRoleGrant, err := TenantSecurityGroupRoleGrantEntityTag(roleGrant)
	if err != nil {
		t.Fatalf("managed group role-grant entity tag: %v", err)
	}
	if managedRoleGrant != unmanagedRoleGrant {
		t.Fatalf("group role-grant ownership changed public validator: %q != %q", managedRoleGrant, unmanagedRoleGrant)
	}
}

func TestParseEdgeEntityTagRejectsNonCanonicalValidators(t *testing.T) {
	validDigest := strings.Repeat("A", 43)
	tests := []string{
		"", "v1-" + validDigest, "W/\"v1-" + validDigest + "\"",
		"\"v0-" + validDigest + "\"", "\"v01-" + validDigest + "\"",
		"\"v2147483648-" + validDigest + "\"", "\"v1-short\"",
		"\"v1-" + strings.Repeat("A", 42) + "B\"",
		"\"v1-" + strings.Repeat("+", 43) + "\"",
		"\"v1-" + validDigest + "\", \"v2-" + validDigest + "\"",
	}
	for _, value := range tests {
		if _, err := ParseEdgeEntityTag(value); err == nil {
			t.Fatalf("ParseEdgeEntityTag(%q) unexpectedly succeeded", value)
		}
	}
}
