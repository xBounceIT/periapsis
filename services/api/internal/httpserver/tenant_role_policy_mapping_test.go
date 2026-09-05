package httpserver

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

func TestTenantRoleReadPolicyPreservesTuplesAboveCustomWriteLimit(t *testing.T) {
	// Use distinct contract-valid tuples to exercise transport hydration without
	// duplicating the authorization evaluator's permission catalog here.
	specification, err := contract.GetSpecJSON()
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]struct {
				Enum []string `json:"enum"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(specification, &document); err != nil {
		t.Fatal(err)
	}
	tuples := make([]authorization.ScopedPermission, 0, 176)
	for _, key := range document.Components.Schemas["TenantPermissionKey"].Enum {
		for _, scope := range document.Components.Schemas["TenantAuthorizationScope"].Enum {
			if len(tuples) < cap(tuples) {
				tuples = append(tuples, authorization.ScopedPermission{
					Permission: authorization.TenantPermission(key), Scope: authorization.Scope(scope),
				})
			}
		}
	}
	if len(tuples) != 176 {
		t.Fatalf("fixture has %d distinct tuples, want 176", len(tuples))
	}
	role, err := mapTenantRole(authorization.TenantRole{
		Policy: authorization.TenantRolePolicy{Permissions: tuples, DelegationCeiling: tuples},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(role)
	if err != nil {
		t.Fatal(err)
	}
	var decoded contract.TenantRole
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Policy.Permissions) != len(tuples) || len(decoded.Policy.DelegationCeiling) != len(tuples) {
		t.Fatal("stored role transport truncated permission or delegation tuples")
	}
	if !reflect.DeepEqual(role.Policy, decoded.Policy) {
		t.Fatal("stored role policy changed during JSON transport")
	}
}
