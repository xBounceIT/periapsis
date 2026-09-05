// Package customfields contains the deterministic, tenant-bound custom-field
// definition and value-validation kernel shared by Alert and Case write paths.
//
// The package deliberately keeps missing, explicit null, and present values
// distinct. Callers must still enforce authorization and PostgreSQL RLS; the
// visibility and edit-policy checks here are an additional domain boundary,
// never the sole authorization boundary.
package customfields
