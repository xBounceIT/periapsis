package contract

import (
	_ "embed"
	"io"
)

//go:embed openapi.json
var documentationJSON []byte

// WriteDocumentation writes the generated OpenAPI bundle served by Swagger UI.
// It includes deterministic examples that are intentionally derived after the
// structural Go and TypeScript contract generation steps.
func WriteDocumentation(destination io.Writer) (int, error) {
	return destination.Write(documentationJSON)
}
