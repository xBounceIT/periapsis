package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Maintenance OIDC claims and historical-secret access belong exclusively to
// the worker. The API binary composes an interactive secret source for browser
// login, but must not accidentally acquire refresh/logout maintenance powers.
func TestFederatedRuntimeCompositionKeepsOIDCMaintenanceWorkerOnly(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "federated.go", nil, 0)
	if err != nil {
		t.Fatalf("parse federated.go: %v", err)
	}

	interactiveConstructors := 0
	maintenanceConstructors := 0
	applicationOptions := 0
	interactiveRuntimeWire := false
	forbiddenOptions := map[string]struct{}{
		"Refreshes": {}, "TokenProtector": {}, "ClientSecrets": {},
		"OIDCRefresh": {}, "LogoutRetries": {}, "LogoutExecutor": {},
	}

	ast.Inspect(file, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.SelectorExpr:
			switch value.Sel.Name {
			case "NewKeyringOIDCClientSecretSource":
				interactiveConstructors++
			case "NewKeyringOIDCMaintenanceClientSecretSource":
				maintenanceConstructors++
			}
		case *ast.CompositeLit:
			selector, ok := value.Type.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Options" && selector.Sel.Name != "RuntimeOptions" {
				return true
			}
			packageName, ok := selector.X.(*ast.Ident)
			if !ok || packageName.Name != "federatedauth" {
				return true
			}
			if selector.Sel.Name == "Options" {
				applicationOptions++
				for _, element := range value.Elts {
					field, fieldOK := element.(*ast.KeyValueExpr)
					if !fieldOK {
						continue
					}
					name, nameOK := field.Key.(*ast.Ident)
					if nameOK {
						if _, forbidden := forbiddenOptions[name.Name]; forbidden {
							t.Fatalf("API federatedauth.Options unexpectedly wires worker-only %s", name.Name)
						}
					}
				}
				return true
			}
			for _, element := range value.Elts {
				field, fieldOK := element.(*ast.KeyValueExpr)
				if !fieldOK {
					continue
				}
				name, nameOK := field.Key.(*ast.Ident)
				identifier, valueOK := field.Value.(*ast.Ident)
				if nameOK && valueOK && name.Name == "OIDCClientSecrets" &&
					identifier.Name == "interactiveClientSecrets" {
					interactiveRuntimeWire = true
				}
			}
		}
		return true
	})

	if interactiveConstructors != 1 || maintenanceConstructors != 0 ||
		applicationOptions != 1 || !interactiveRuntimeWire {
		t.Fatalf(
			"OIDC secret composition drifted: interactive=%d maintenance=%d application_options=%d runtime_wire=%t",
			interactiveConstructors, maintenanceConstructors, applicationOptions, interactiveRuntimeWire,
		)
	}
}
