package federatedauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The old Service.SAMLConsumer path could not carry exact subject identity or
// protected logout provenance. Keep SAML composition on SAMLApplication's
// typed transaction port instead of silently reviving that parallel surface.
func TestServiceCannotExposeLegacySAMLConsumer(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	directory := filepath.Dir(current)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	files := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		parsed, parseErr := parser.ParseFile(files, path, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", entry.Name(), parseErr)
		}
		for _, declaration := range parsed.Decls {
			switch value := declaration.(type) {
			case *ast.GenDecl:
				for _, specification := range value.Specs {
					if typeSpec, isType := specification.(*ast.TypeSpec); isType && typeSpec.Name.Name == "SAMLConsumer" {
						t.Fatalf("%s reintroduces the unsafe exported SAMLConsumer type", entry.Name())
					}
				}
			case *ast.FuncDecl:
				if value.Name.Name == "SAMLConsumer" && receiverName(value.Recv) == "Service" {
					t.Fatalf("%s reintroduces Service.SAMLConsumer", entry.Name())
				}
			}
		}
	}
}

func receiverName(fields *ast.FieldList) string {
	if fields == nil || len(fields.List) != 1 {
		return ""
	}
	switch receiver := fields.List[0].Type.(type) {
	case *ast.Ident:
		return receiver.Name
	case *ast.StarExpr:
		if identifier, ok := receiver.X.(*ast.Ident); ok {
			return identifier.Name
		}
	}
	return ""
}
