package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func inputs(t *testing.T) (string, []byte, []byte, []byte) {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../.."))
	read := func(path string) []byte {
		value, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	return root, read("services/api/internal/authorization/model.go"), read("services/api/internal/authorization/evaluator.go"), read("services/api/internal/contract/openapi.json")
}

func TestPermissionCatalogCurrentSources(t *testing.T) {
	_, model, evaluator, contract := inputs(t)
	value, err := derive(model, evaluator, contract)
	if err != nil {
		t.Fatal(err)
	}
	if len(value.platform) != 25 || len(value.tenant) != 85 {
		t.Fatalf("unexpected current catalog size: %d platform, %d tenant", len(value.platform), len(value.tenant))
	}
	for _, test := range []struct {
		key        string
		scopes     []string
		principals []string
	}{
		{"alert.create", []string{"tenant"}, []string{"human", "service_account"}},
		{"role.manage", []string{"tenant"}, []string{"human"}},
		{"operator_team.read", []string{"tenant", "operator_team"}, []string{"human"}},
		{"alert.update", []string{"own", "assigned", "operator_team", "tenant"}, []string{"human"}},
		{"case.update", []string{"assigned", "operator_team", "tenant"}, []string{"human"}},
		{"dfir.evidence.manage", []string{"assigned", "operator_team", "tenant"}, []string{"human"}},
		{"portal.case.read", []string{"own"}, []string{"human"}},
	} {
		actual := value.tenant[test.key]
		if sameSet(actual.scopes, test.scopes) != nil || sameSet(actual.principals, test.principals) != nil {
			t.Fatalf("%s has unexpected metadata: %+v", test.key, actual)
		}
	}
}

func TestPermissionCatalogRejectsUnclosedGoMetadata(t *testing.T) {
	_, model, evaluator, contract := inputs(t)
	for _, test := range []struct{ name, before, after string }{
		{"missing map", "var initialTenantPermissions =", "var missingCatalog ="},
		{"wrong map type", "var initialTenantPermissions = map[TenantPermission]tenantPermissionMetadata", "var initialTenantPermissions = map[Permission]tenantPermissionMetadata"},
		{"unresolved metadata", "TenantPermissionPermissionRead:                 tenantAdministrativePermission", "TenantPermissionPermissionRead:                 missingMetadata"},
		{"computed metadata", "setOf(PrincipalKindHuman)", "loadPrincipals()"},
		{"unknown field", "principalKinds: setOf(PrincipalKindHuman)", "futureKinds: setOf(PrincipalKindHuman)"},
		{"unknown scope", "scopes:         setOf(ScopeTenant)", "scopes:         setOf(UnknownScope)"},
		{"duplicate scope", "scopes:         setOf(ScopeTenant)", "scopes:         setOf(ScopeTenant, ScopeTenant)"},
		{"platform scope in tenant", "scopes:         setOf(ScopeTenant)", "scopes:         setOf(ScopePlatform)"},
		{"platform marker call", "PermissionPlatformTenantRead:             {}", "PermissionPlatformTenantRead:             makeMarker()"},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := bytes.Replace(evaluator, []byte(test.before), []byte(test.after), 1)
			if bytes.Equal(changed, evaluator) {
				t.Fatal("mutant did not change source")
			}
			if _, err := derive(model, changed, contract); err == nil {
				t.Fatal("unclosed metadata was accepted")
			}
		})
	}
}

func TestPermissionCatalogRejectsContractDrift(t *testing.T) {
	_, model, evaluator, contract := inputs(t)
	for _, name := range []string{"tenant key", "platform key", "scope vocabulary", "principal vocabulary", "principal conditional", "null principal conditional", "machine key", "machine scope", "session surface"} {
		t.Run(name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(contract, &document); err != nil {
				t.Fatal(err)
			}
			schemas := document["components"].(map[string]any)["schemas"].(map[string]any)
			get := func(key string) map[string]any { return schemas[key].(map[string]any) }
			switch name {
			case "tenant key":
				get("TenantPermissionKey")["enum"] = []string{"role.read"}
			case "platform key":
				get("PlatformPermission")["enum"] = []string{"platform.tenant.read"}
			case "scope vocabulary":
				get("TenantAuthorizationScope")["enum"] = []string{"tenant", "platform"}
			case "principal vocabulary":
				get("TenantPrincipalType")["enum"] = []string{"human", "service_account", "worker"}
			case "principal conditional":
				get("TenantPermission")["allOf"] = []any{}
			case "null principal conditional":
				get("TenantPermission")["allOf"] = []any{nil}
			case "machine key":
				get("ServiceAccountCredentialPermissionKey")["const"] = "role.manage"
			case "machine scope":
				get("ServiceAccountCredentialScope")["const"] = "own"
			case "session surface":
				get("Session")["properties"] = map[string]any{}
			}
			changed, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := derive(model, evaluator, changed); err == nil {
				t.Fatal("contract drift was accepted")
			}
		})
	}
}

func TestPermissionCatalogDeterministicAndRoleIndependent(t *testing.T) {
	_, model, evaluator, contract := inputs(t)
	value, err := derive(model, evaluator, contract)
	if err != nil {
		t.Fatal(err)
	}
	first := render(value)
	reversed := map[string]metadata{}
	keys := sortedKeys(value.tenant)
	slices.Reverse(keys)
	for _, key := range keys {
		metadata := value.tenant[key]
		metadata.scopes = slices.Clone(metadata.scopes)
		slices.Reverse(metadata.scopes)
		reversed[key] = metadata
	}
	value.tenant = reversed
	if render(value) != first {
		t.Fatal("output depends on map or scope iteration order")
	}
	for _, forbidden := range []string{"tenant_admin", "platform_super_admin", "soc_analyst"} {
		if strings.Contains(first, forbidden) {
			t.Fatalf("catalog inferred a role assignment: %s", forbidden)
		}
	}
}

func TestPermissionCatalogCommittedDocument(t *testing.T) {
	root, _, _, _ := inputs(t)
	expected, err := generate(root)
	if err != nil {
		t.Fatal(err)
	}
	existing, err := os.ReadFile(filepath.Join(root, "docs/permission-catalog.md"))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkDocument(existing, expected); err != nil {
		t.Fatal(err)
	}
	if checkDocument(append(slices.Clone(existing), []byte("manual drift\n")...), expected) == nil {
		t.Fatal("document drift was accepted")
	}
	if err := checkDocument(bytes.ReplaceAll(expected, []byte("\n"), []byte("\r\n")), expected); err != nil {
		t.Fatalf("Windows checkout line endings rejected: %v", err)
	}
}
