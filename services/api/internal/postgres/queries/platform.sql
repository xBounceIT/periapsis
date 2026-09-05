-- name: ListPlatformTenants :many
SELECT tenant.id::uuid AS id, tenant.slug::text AS slug,
       tenant.name::text AS name, tenant.status::text AS status,
       tenant.timezone::text AS timezone, tenant.locale::text AS locale,
	   tenant.version::integer AS version,
       tenant.created_at::timestamptz AS created_at,
       tenant.updated_at::timestamptz AS updated_at
FROM app.list_platform_tenants(
  sqlc.narg(after_id)::uuid,
  sqlc.arg(page_size)::integer
) AS tenant(id, slug, name, status, timezone, locale, version, created_at, updated_at);

-- name: CreatePlatformTenant :one
SELECT tenant.id::uuid AS id, tenant.slug::text AS slug,
       tenant.name::text AS name, tenant.status::text AS status,
       tenant.timezone::text AS timezone, tenant.locale::text AS locale,
	   tenant.version::integer AS version,
       tenant.created_at::timestamptz AS created_at,
       tenant.updated_at::timestamptz AS updated_at
FROM app.create_platform_tenant(
  sqlc.arg(tenant_id)::uuid,
  sqlc.arg(membership_id)::uuid,
  sqlc.arg(slug)::text,
  sqlc.arg(name)::text,
  sqlc.arg(timezone)::text,
  sqlc.arg(locale)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text
) AS tenant(id, slug, name, status, timezone, locale, version, created_at, updated_at);

-- name: ChangePlatformTenantLifecycle :one
SELECT lifecycle.tenant_id::uuid AS tenant_id,
       lifecycle.previous_status::text AS previous_status,
       lifecycle.status::text AS status,
       lifecycle.version::integer AS version,
       lifecycle.updated_at::timestamptz AS updated_at,
       lifecycle.replayed::boolean AS replayed
FROM app.change_platform_tenant_lifecycle(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(tenant_id)::uuid,
  sqlc.arg(target)::public.tenant_status,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text
) AS lifecycle(tenant_id, previous_status, status, version, updated_at, replayed);

-- name: AuthorizePlatformTenantAccess :one
SELECT access.tenant_id::uuid AS tenant_id,
       access.membership_id::uuid AS membership_id,
       access.user_id::uuid AS user_id,
       access.tenant_version::integer AS tenant_version,
       access.membership_revision::integer AS membership_revision,
       access.authorization_revision::bigint AS authorization_revision,
       access.authorized_at::timestamptz AS authorized_at,
       access.replayed::boolean AS replayed
FROM app.authorize_platform_tenant_access_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(tenant_id)::uuid,
  sqlc.arg(membership_id)::uuid,
  sqlc.arg(role_grant_id)::uuid,
  sqlc.arg(expected_tenant_version)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(idempotency_key_digest)::bytea,
  sqlc.arg(platform_audit_event_id)::uuid,
  sqlc.arg(tenant_audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text
) AS access(
  tenant_id, membership_id, user_id, tenant_version, membership_revision,
  authorization_revision, authorized_at, replayed
);
