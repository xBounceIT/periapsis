// Command permission-catalog derives documentation from the checked OpenAPI bundle
// and the authorization evaluator's Go AST. It never executes application policy.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type symbol struct{ kind, value string }
type metadata struct{ scopes, principals []string }
type catalog struct {
	platform []string
	tenant   map[string]metadata
}
type schema struct {
	Ref        string             `json:"$ref"`
	Enum       []json.RawMessage  `json:"enum"`
	Const      json.RawMessage    `json:"const"`
	Properties map[string]*schema `json:"properties"`
	Items      *schema            `json:"items"`
	AllOf      []*schema          `json:"allOf"`
	If         *schema            `json:"if"`
	Then       *schema            `json:"then"`
	Else       *schema            `json:"else"`
}

func main() {
	write := flag.Bool("write", false, "regenerate docs/permission-catalog.md (default: check only)")
	check := flag.Bool("check", false, "check documentation without writing (also the default)")
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	if flag.NArg() != 0 || *write && *check {
		fatal(fmt.Errorf("use --write or --check, without positional arguments"))
	}
	content, err := generate(*root)
	if err != nil {
		fatal(err)
	}
	path := filepath.Join(*root, "docs/permission-catalog.md")
	if *write {
		err = os.WriteFile(path, content, 0644)
	} else {
		var existing []byte
		existing, err = os.ReadFile(path)
		if err == nil {
			err = checkDocument(existing, content)
		}
	}
	if err != nil {
		fatal(err)
	}
}

func checkDocument(existing, expected []byte) error {
	if !bytes.Equal(bytes.ReplaceAll(existing, []byte("\r\n"), []byte("\n")), expected) {
		return fmt.Errorf("permission catalog drift: run go run scripts/docs/permission-catalog.go --write")
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func generate(root string) ([]byte, error) {
	read := func(path string) ([]byte, error) { return os.ReadFile(filepath.Join(root, path)) }
	model, err := read("services/api/internal/authorization/model.go")
	if err != nil {
		return nil, err
	}
	evaluator, err := read("services/api/internal/authorization/evaluator.go")
	if err != nil {
		return nil, err
	}
	contract, err := read("services/api/internal/contract/openapi.json")
	if err != nil {
		return nil, err
	}
	value, err := derive(model, evaluator, contract)
	if err != nil {
		return nil, err
	}
	return []byte(render(value)), nil
}

func derive(model, evaluator, contract []byte) (catalog, error) {
	result := catalog{tenant: map[string]metadata{}}
	symbols := map[string]symbol{}
	variables := map[string]ast.Expr{}
	for index, source := range [][]byte{model, evaluator} {
		file, err := parser.ParseFile(token.NewFileSet(), fmt.Sprintf("source%d.go", index), source, 0)
		if err != nil {
			return result, err
		}
		for _, declaration := range file.Decls {
			group, ok := declaration.(*ast.GenDecl)
			if !ok || group.Tok != token.CONST && group.Tok != token.VAR {
				continue
			}
			for _, specification := range group.Specs {
				value := specification.(*ast.ValueSpec)
				kind := identifier(value.Type)
				if group.Tok == token.CONST && slices.Contains([]string{"Permission", "TenantPermission", "Scope", "PrincipalKind"}, kind) {
					if len(value.Names) != 1 || len(value.Values) != 1 {
						return result, fmt.Errorf("unsupported %s constant declaration", kind)
					}
					literal, ok := value.Values[0].(*ast.BasicLit)
					if !ok || literal.Kind != token.STRING {
						return result, fmt.Errorf("%s must be a string literal", value.Names[0].Name)
					}
					text, err := strconv.Unquote(literal.Value)
					if err != nil || text == "" {
						return result, fmt.Errorf("invalid permission symbol %s", value.Names[0].Name)
					}
					name := value.Names[0].Name
					if _, exists := symbols[name]; exists {
						return result, fmt.Errorf("duplicate symbol %s", name)
					}
					symbols[name] = symbol{kind, text}
				}
				if group.Tok == token.VAR && len(value.Names) == 1 && len(value.Values) == 1 {
					name := value.Names[0].Name
					if _, exists := variables[name]; exists {
						return result, fmt.Errorf("duplicate variable %s", name)
					}
					variables[name] = value.Values[0]
				}
			}
		}
	}
	resolve := func(expression ast.Expr, kind string) (string, error) {
		value, exists := symbols[identifier(expression)]
		if !exists || value.kind != kind {
			return "", fmt.Errorf("unresolved %s symbol %s", kind, identifier(expression))
		}
		return value.value, nil
	}
	for _, name := range []string{"knownPermissions", "initialTenantPermissions"} {
		literal, ok := variables[name].(*ast.CompositeLit)
		if !ok {
			return result, fmt.Errorf("missing literal catalog %s", name)
		}
		mapType, ok := literal.Type.(*ast.MapType)
		if !ok || name == "initialTenantPermissions" && (identifier(mapType.Key) != "TenantPermission" || identifier(mapType.Value) != "tenantPermissionMetadata") || name == "knownPermissions" && identifier(mapType.Key) != "Permission" {
			return result, fmt.Errorf("unsupported map type for %s", name)
		}
		for _, entry := range literal.Elts {
			pair, ok := entry.(*ast.KeyValueExpr)
			if !ok {
				return result, fmt.Errorf("unsupported entry in %s", name)
			}
			kind := "TenantPermission"
			if name == "knownPermissions" {
				kind = "Permission"
			}
			key, err := resolve(pair.Key, kind)
			if err != nil {
				return result, err
			}
			if kind == "Permission" {
				marker, ok := pair.Value.(*ast.CompositeLit)
				if !ok || len(marker.Elts) != 0 {
					return result, fmt.Errorf("unsupported platform marker for %s", key)
				}
				result.platform = append(result.platform, key)
				continue
			}
			if _, exists := result.tenant[key]; exists {
				return result, fmt.Errorf("duplicate tenant key %s", key)
			}
			definition, ok := variables[identifier(pair.Value)].(*ast.CompositeLit)
			if !ok || identifier(definition.Type) != "tenantPermissionMetadata" || len(definition.Elts) != 2 {
				return result, fmt.Errorf("unsupported metadata for %s", key)
			}
			fields := map[string][]string{}
			for _, field := range definition.Elts {
				pair, ok := field.(*ast.KeyValueExpr)
				if !ok {
					return result, fmt.Errorf("unsupported metadata field for %s", key)
				}
				name := identifier(pair.Key)
				kind := map[string]string{"scopes": "Scope", "principalKinds": "PrincipalKind"}[name]
				call, ok := pair.Value.(*ast.CallExpr)
				if kind == "" || fields[name] != nil || !ok || identifier(call.Fun) != "setOf" || len(call.Args) == 0 || call.Ellipsis.IsValid() {
					return result, fmt.Errorf("unsupported %s metadata for %s", name, key)
				}
				for _, argument := range call.Args {
					value, err := resolve(argument, kind)
					if err != nil {
						return result, err
					}
					fields[name] = append(fields[name], value)
				}
				if err := unique(fields[name]); err != nil {
					return result, fmt.Errorf("%s: %w", key, err)
				}
			}
			result.tenant[key] = metadata{fields["scopes"], fields["principalKinds"]}
		}
	}
	var document struct {
		Components struct{ Schemas map[string]*schema } `json:"components"`
	}
	if err := json.Unmarshal(contract, &document); err != nil {
		return result, err
	}
	schemas := document.Components.Schemas
	for _, name := range []string{"PlatformPermission", "TenantPermissionKey", "TenantAuthorizationScope", "TenantPrincipalType", "TenantPermission", "ServiceAccountCredentialPermissionKey", "ServiceAccountCredentialScope", "Session"} {
		if schemas[name] == nil {
			return result, fmt.Errorf("missing contract schema %s", name)
		}
	}
	enums := map[string][]string{}
	for _, name := range []string{"PlatformPermission", "TenantPermissionKey", "TenantAuthorizationScope", "TenantPrincipalType"} {
		for _, raw := range schemas[name].Enum {
			var value string
			if err := json.Unmarshal(raw, &value); err != nil {
				return result, fmt.Errorf("%s enum must contain strings", name)
			}
			enums[name] = append(enums[name], value)
		}
	}
	if err := sameSet(result.platform, enums["PlatformPermission"]); err != nil {
		return result, fmt.Errorf("platform catalog: %w", err)
	}
	keys := sortedKeys(result.tenant)
	if err := sameSet(keys, enums["TenantPermissionKey"]); err != nil {
		return result, fmt.Errorf("tenant catalog: %w", err)
	}
	for name, values := range map[string][]string{"TenantAuthorizationScope": {"own", "assigned", "operator_team", "tenant"}, "TenantPrincipalType": {"human", "service_account"}} {
		if err := sameSet(values, enums[name]); err != nil {
			return result, fmt.Errorf("%s vocabulary: %w", name, err)
		}
	}
	sessionPermissions := schemas["Session"].Properties["permissions"]
	if sessionPermissions == nil || sessionPermissions.Items == nil || sessionPermissions.Items.Ref != "#/components/schemas/PlatformPermission" {
		return result, fmt.Errorf("platform Session.permissions reference changed")
	}
	var credentialKey, credentialScope string
	if json.Unmarshal(schemas["ServiceAccountCredentialPermissionKey"].Const, &credentialKey) != nil || json.Unmarshal(schemas["ServiceAccountCredentialScope"].Const, &credentialScope) != nil {
		return result, fmt.Errorf("unsupported machine credential allowlist")
	}
	conditional := schemas["TenantPermission"].AllOf
	if len(conditional) != 1 || conditional[0] == nil || conditional[0].If == nil || conditional[0].Then == nil || conditional[0].Else == nil {
		return result, fmt.Errorf("unsupported TenantPermission principal conditional")
	}
	rule := conditional[0]
	keyCondition := rule.If.Properties["key"]
	if keyCondition == nil {
		return result, fmt.Errorf("missing TenantPermission key condition")
	}
	var conditionalKey string
	if json.Unmarshal(keyCondition.Const, &conditionalKey) != nil {
		return result, fmt.Errorf("unsupported TenantPermission key condition")
	}
	for _, key := range keys {
		metadata := result.tenant[key]
		for _, principal := range metadata.principals {
			if !slices.Contains(enums["TenantPrincipalType"], principal) {
				return result, fmt.Errorf("unknown principal %s for %s", principal, key)
			}
		}
		for _, scope := range metadata.scopes {
			if !slices.Contains(enums["TenantAuthorizationScope"], scope) {
				return result, fmt.Errorf("unknown scope %s for %s", scope, key)
			}
		}
		branch := rule.Else
		if key == conditionalKey {
			branch = rule.Then
		}
		principalSchema := branch.Properties["principalTypes"]
		var principals []string
		if principalSchema == nil || json.Unmarshal(principalSchema.Const, &principals) != nil {
			return result, fmt.Errorf("unsupported principal types for %s", key)
		}
		if err := sameSet(metadata.principals, principals); err != nil {
			return result, fmt.Errorf("principal types for %s: %w", key, err)
		}
		machine := slices.Contains(metadata.principals, "service_account")
		if machine != (key == credentialKey) || machine && (len(metadata.scopes) != 1 || metadata.scopes[0] != credentialScope) {
			return result, fmt.Errorf("machine credential tuple mismatch for %s", key)
		}
	}
	slices.Sort(result.platform)
	return result, nil
}

func identifier(expression ast.Expr) string {
	if value, ok := expression.(*ast.Ident); ok {
		return value.Name
	}
	return ""
}

func unique(values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("empty catalog/set")
	}
	seen := map[string]bool{}
	for _, value := range values {
		if value == "" || seen[value] {
			return fmt.Errorf("empty or duplicate value %q", value)
		}
		seen[value] = true
	}
	return nil
}

func sameSet(actual, expected []string) error {
	for _, values := range [][]string{actual, expected} {
		if err := unique(values); err != nil {
			return err
		}
	}
	left, right := slices.Clone(actual), slices.Clone(expected)
	slices.Sort(left)
	slices.Sort(right)
	if !slices.Equal(left, right) {
		return fmt.Errorf("set mismatch: got %v, expected %v", left, right)
	}
	return nil
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func render(value catalog) string {
	var output strings.Builder
	output.WriteString("# Current permission catalog\n\n<!-- Generated by scripts/docs/permission-catalog.go; do not edit manually. -->\n\n")
	output.WriteString("This is a source-derived capability catalog, not a list of role assignments or a\nruntime authority snapshot. A row never grants access. Built-in/custom role policies,\nlive grants, delegation ceilings, membership, account/credential state, resource\nrelationships, and operation-specific checks still determine an actual decision.\nDo not infer a built-in role's permissions from its name or from this table.\nWorker/notifier database privileges and public authentication ceremonies are not\nprincipal-grantable HTTP permission keys and are outside this catalog.\n\n")
	output.WriteString("## Sources and reproduction\n\n")
	output.WriteString("- [Canonical OpenAPI](../packages/contracts/openapi/openapi.yaml):\n  `PlatformPermission.enum`, `TenantPermissionKey.enum`, `TenantAuthorizationScope.enum`,\n  `TenantPrincipalType.enum`, `TenantPermission` principal-type conditions,\n  `ServiceAccountCredentialPermissionKey.const`, and `ServiceAccountCredentialScope.const`.\n- [Evaluator](../services/api/internal/authorization/evaluator.go):\n  `knownPermissions`, `initialTenantPermissions`, and each referenced\n  `tenantPermissionMetadata.scopes` / `.principalKinds` declaration.\n- [Go symbols](../services/api/internal/authorization/model.go): exact scope, principal,\n  and tenant-permission literals. The generator reads Go syntax, not role names.\n\n")
	output.WriteString("The generator consumes the generated OpenAPI JSON bundle; run the existing drift\ngate first to prove that bundle matches canonical YAML. It rejects mismatched key\nsets, unknown metadata forms, principal-type drift, and machine-credential tuple drift.\nNo database, secrets, network, or application service is needed. From the repository root:\n\n```bash\ncorepack pnpm verify:generated\ngo run scripts/docs/permission-catalog.go --write\ngo run scripts/docs/permission-catalog.go --check\ngo test scripts/docs/permission-catalog.go scripts/docs/permission-catalog_test.go\n```\n\n")
	output.WriteString("`--check` (also the default) checks committed documentation without writing. Generation\ncontains no timestamp or environment-specific data. See the [authorization model](permissions.md)\nfor scope/delegation semantics and the historical rollout tables.\n\n")
	fmt.Fprintf(&output, "## Platform capabilities (%d)\n\n", len(value.platform))
	output.WriteString("These exact keys belong to `Session.permissions` (human-session platform authority),\nnot tenant role-policy tuples. The machine credential allowlist contains no platform\nkey. `platform` below describes the authority domain, not an inferred role grant.\n\n")
	platformRows := [][]string{{"Permission", "Authority domain", "Principal surface"}}
	for _, key := range value.platform {
		platformRows = append(platformRows, []string{"`" + key + "`", "`platform`", "Human session"})
	}
	writeTable(&output, platformRows)
	fmt.Fprintf(&output, "\n## Tenant capabilities (%d)\n\n", len(value.tenant))
	output.WriteString("Scopes are exact catalog-admitted tuples, not automatic delegation rights. `human`\nincludes customer-portal users where their live policy and resource relationship\npermit it; it does not mean every human or operator may use the capability.\n`service_account` means the evaluator admits that principal kind, still constrained\nby live machine authority and the exact credential allowlist.\n\n")
	tenantRows := [][]string{{"Permission", "Allowed scopes", "Admitted principal types"}}
	quote := func(values []string) string {
		items := slices.Clone(values)
		slices.Sort(items)
		for index, value := range items {
			items[index] = "`" + value + "`"
		}
		return strings.Join(items, ", ")
	}
	for _, key := range sortedKeys(value.tenant) {
		metadata := value.tenant[key]
		tenantRows = append(tenantRows, []string{"`" + key + "`", quote(metadata.scopes), quote(metadata.principals)})
	}
	writeTable(&output, tenantRows)
	return output.String()
}

func writeTable(output *strings.Builder, rows [][]string) {
	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for index, cell := range row {
			widths[index] = max(widths[index], len(cell), 3)
		}
	}
	for index, row := range rows {
		for column, cell := range row {
			fmt.Fprintf(output, "| %-*s ", widths[column], cell)
		}
		output.WriteString("|\n")
		if index == 0 {
			for _, width := range widths {
				fmt.Fprintf(output, "| %s ", strings.Repeat("-", width))
			}
			output.WriteString("|\n")
		}
	}
}
