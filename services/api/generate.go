// Package api owns generation hooks for the Periapsis HTTP contract.
package api

//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 --config oapi-codegen.yaml ../../packages/contracts/openapi/openapi.yaml
//go:generate node ../../scripts/generate-sqlc.mjs
