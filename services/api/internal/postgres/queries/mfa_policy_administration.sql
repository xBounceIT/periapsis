-- name: ListPlatformMFAPolicies :many
SELECT policy.document::jsonb AS document
FROM app.list_platform_mfa_policies_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.narg(after_policy_id)::uuid,
  sqlc.narg(after_revision)::bigint,
  sqlc.arg(page_size)::integer,
  sqlc.arg(include_retired)::boolean
) AS policy(document);

-- name: ListTenantMFAPolicies :many
SELECT policy.document::jsonb AS document
FROM app.list_tenant_mfa_policies_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(tenant_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.narg(after_policy_id)::uuid,
  sqlc.narg(after_revision)::bigint,
  sqlc.arg(page_size)::integer,
  sqlc.arg(include_retired)::boolean
) AS policy(document);

-- name: GetPlatformMFAPolicy :one
SELECT app.get_platform_mfa_policy_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(policy_id)::uuid,
  sqlc.narg(revision)::bigint
)::jsonb AS document;

-- name: GetTenantMFAPolicy :one
SELECT app.get_tenant_mfa_policy_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(tenant_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(policy_id)::uuid,
  sqlc.narg(revision)::bigint
)::jsonb AS document;

-- name: SimulatePlatformMFAPolicyChange :one
SELECT app.simulate_platform_mfa_policy_change_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(request)::jsonb
)::jsonb AS document;

-- name: SimulateTenantMFAPolicyChange :one
SELECT app.simulate_tenant_mfa_policy_change_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(tenant_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(request)::jsonb
)::jsonb AS document;

-- name: PublishPlatformMFAPolicy :one
SELECT app.publish_platform_mfa_policy_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(command)::jsonb
)::jsonb AS document;

-- name: RetirePlatformMFAPolicy :one
SELECT app.retire_platform_mfa_policy_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(command)::jsonb
)::jsonb AS document;

-- name: PublishTenantMFAPolicy :one
SELECT app.publish_tenant_mfa_policy_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(tenant_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(command)::jsonb
)::jsonb AS document;

-- name: RetireTenantMFAPolicy :one
SELECT app.retire_tenant_mfa_policy_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(tenant_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(command)::jsonb
)::jsonb AS document;
