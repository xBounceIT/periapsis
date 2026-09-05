-- name: SetTenantContext :one
SELECT
  set_config('app.tenant_id', sqlc.arg(tenant_id)::uuid::text, true)::text AS tenant_id,
  set_config('app.user_id', sqlc.arg(user_id)::uuid::text, true)::text AS user_id;

