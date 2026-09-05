-- name: GetTenant :one
SELECT
  id,
  slug,
  name,
  status,
  timezone,
  locale,
  created_at,
  updated_at
FROM tenants
WHERE id = sqlc.arg(id)::uuid;

-- name: ListTenants :many
SELECT
  id,
  slug,
  name,
  status,
  timezone,
  locale,
  created_at,
  updated_at
FROM tenants
WHERE sqlc.narg(after_id)::uuid IS NULL OR id > sqlc.narg(after_id)::uuid
ORDER BY id ASC
LIMIT sqlc.arg(page_size);

