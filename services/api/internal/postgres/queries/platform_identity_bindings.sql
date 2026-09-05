-- name: ListTenantPlatformAuthProviderBindings :many
SELECT binding.document::jsonb AS document
FROM app.list_tenant_platform_auth_provider_bindings_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(platform_provider_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.narg(after_binding_id)::uuid,
  sqlc.arg(page_size)::integer,
  sqlc.arg(include_archived)::boolean
) AS binding(document);

-- name: GetTenantPlatformAuthProviderBinding :one
SELECT app.get_tenant_platform_auth_provider_binding_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(platform_provider_id)::uuid,
  sqlc.arg(binding_id)::uuid,
  sqlc.arg(authentication_method)::text
)::jsonb AS document;

-- name: CreateTenantPlatformAuthProviderBinding :one
SELECT result.binding_id::uuid AS binding_id,
       result.version::bigint AS version,
       result.replayed::boolean AS replayed,
       result.document::jsonb AS document
FROM app.create_tenant_platform_auth_provider_binding_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(command_id)::uuid,
  sqlc.arg(binding_id)::uuid,
  sqlc.arg(platform_provider_id)::uuid,
  sqlc.arg(tenant_id)::uuid,
  sqlc.arg(login_key)::text,
  sqlc.arg(profile_priority)::integer,
  sqlc.arg(key_digest)::bytea,
  sqlc.arg(request_digest)::bytea,
  sqlc.arg(tenant_audit_event_id)::uuid,
  sqlc.arg(platform_audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(binding_id, version, replayed, document);

-- name: UpdateTenantPlatformAuthProviderBinding :one
SELECT result.version::bigint AS version,
       result.document::jsonb AS document
FROM app.update_tenant_platform_auth_provider_binding_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(platform_provider_id)::uuid,
  sqlc.arg(binding_id)::uuid,
  sqlc.arg(expected_version)::bigint,
  sqlc.arg(expected_tenant_version)::integer,
  sqlc.arg(login_key)::text,
  sqlc.arg(profile_priority)::integer,
  sqlc.arg(tenant_audit_event_id)::uuid,
  sqlc.arg(platform_audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(version, document);

-- name: ArchiveTenantPlatformAuthProviderBinding :one
SELECT result.version::bigint AS version,
       result.tenant_version::integer AS tenant_version
FROM app.archive_tenant_platform_auth_provider_binding_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(platform_provider_id)::uuid,
  sqlc.arg(binding_id)::uuid,
  sqlc.arg(expected_version)::bigint,
  sqlc.arg(expected_tenant_version)::integer,
  sqlc.arg(tenant_audit_event_id)::uuid,
  sqlc.arg(platform_audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(version, tenant_version);

-- name: ActivateTenantPlatformAuthProviderBinding :one
SELECT result.version::bigint AS version,
       result.document::jsonb AS document
FROM app.activate_tenant_platform_auth_provider_binding_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(platform_provider_id)::uuid,
  sqlc.arg(binding_id)::uuid,
  sqlc.arg(expected_version)::bigint,
  sqlc.arg(expected_tenant_version)::integer,
  sqlc.arg(jit_mode)::text,
  sqlc.arg(no_match_policy)::text,
  sqlc.arg(tenant_audit_event_id)::uuid,
  sqlc.arg(platform_audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(version, document);

-- name: DeactivateTenantPlatformAuthProviderBinding :one
SELECT result.version::bigint AS version,
       result.document::jsonb AS document
FROM app.deactivate_tenant_platform_auth_provider_binding_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(platform_provider_id)::uuid,
  sqlc.arg(binding_id)::uuid,
  sqlc.arg(expected_version)::bigint,
  sqlc.arg(expected_tenant_version)::integer,
  sqlc.arg(tenant_audit_event_id)::uuid,
  sqlc.arg(platform_audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(version, document);
