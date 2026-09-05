package serviceaccount

import (
	"testing"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func TestRoleGrantEntityTagBindsPublicRepresentationOnly(t *testing.T) {
	t.Parallel()

	grant := storedRoleGrant(
		serviceTestID(70), serviceTestID(71), serviceTestID(72),
		serviceTestID(73), serviceTestID(74), serviceTestID(75),
	)
	first, err := RoleGrantEntityTag(grant)
	if err != nil {
		t.Fatalf("RoleGrantEntityTag() error = %v", err)
	}
	second, err := RoleGrantEntityTag(grant)
	if err != nil || first != second {
		t.Fatalf("RoleGrantEntityTag() = (%q, %v), want %q", second, err, first)
	}
	version, err := authorization.ParseEdgeEntityTag(first)
	if err != nil || version != grant.Version {
		t.Fatalf("ParseEdgeEntityTag(%q) = (%d, %v)", first, version, err)
	}

	changedOwnership := grant
	changedOwnership.SourceKind = authorization.AuthorizationSourceIdentityMapping
	changedOwnership.SourceKey = "identity:ldap"
	changedOwnership.SourceAuthoritative = true
	changedOwnership.ManagedByServiceAccountAPI = false
	if !validRoleGrant(changedOwnership, changedOwnership.TenantID, changedOwnership.ServiceAccountID) {
		t.Fatal("changed ownership fixture is not a valid public role-grant representation")
	}
	changedOwnershipTag, err := RoleGrantEntityTag(changedOwnership)
	if err != nil || changedOwnershipTag == first {
		t.Fatalf("changed-ownership tag = (%q, %v), original %q", changedOwnershipTag, err, first)
	}

	changed := grant
	changed.Role.DisplayName = "Renamed ingest role"
	changedTag, err := RoleGrantEntityTag(changed)
	if err != nil || changedTag == first {
		t.Fatalf("changed public tag = (%q, %v), original %q", changedTag, err, first)
	}
}
