-- name: GetCurrentTenantAuthorizationContext :one
SELECT authority.tenant_id::uuid AS tenant_id,
       authority.membership_id::uuid AS membership_id,
       authority.authorization_revision::bigint AS authorization_revision,
       authority.membership_status::text AS membership_status,
       authority.compatibility_role::text AS compatibility_role,
       authority.evaluated_at::timestamptz AS evaluated_at
FROM app.get_current_tenant_authorization_context() AS authority(
  tenant_id, membership_id, authorization_revision, membership_status,
  compatibility_role, evaluated_at
);

-- name: ResolveCurrentTenantHumanAuthority :many
SELECT authority.permission_key::text AS permission_key,
       authority.scope::text AS scope,
       authority.delegable::boolean AS delegable,
       authority.delegation_expires_at::timestamptz AS delegation_expires_at
FROM app.resolve_current_tenant_human_authority_v3(
  sqlc.arg(page_size)::integer
) AS authority(permission_key, scope, delegable, delegation_expires_at);

-- name: ResolveCurrentTenantHumanRoleGrantPaths :many
SELECT role_path.path_type::text AS path_type,
       role_path.source_type::text AS source_type,
       role_path.effective_expires_at::timestamptz AS effective_expires_at,
       role_path.role_id::uuid AS role_id,
       role_path.role_key::text AS role_key,
       role_path.role_name::text AS role_name,
       role_path.role_grant_id::uuid AS role_grant_id,
       role_path.role_source_id::uuid AS role_source_id,
       role_path.role_source_kind::text AS role_source_kind,
       role_path.role_source_authoritative::boolean AS role_source_authoritative,
       role_path.role_source_retired_at::timestamptz AS role_source_retired_at,
       role_path.role_granted_by_user_id::uuid AS role_granted_by_user_id,
       role_path.role_grant_reason::text AS role_grant_reason,
       role_path.role_granted_at::timestamptz AS role_granted_at,
       role_path.role_grant_expires_at::timestamptz AS role_grant_expires_at,
       role_path.role_grant_version::integer AS role_grant_version,
       role_path.group_id::uuid AS group_id,
       coalesce(role_path.group_key::text, '')::text AS group_key,
       coalesce(role_path.group_name::text, '')::text AS group_name,
       role_path.group_membership_id::uuid AS group_membership_id,
       role_path.membership_source_id::uuid AS membership_source_id,
       coalesce(role_path.membership_source_kind::text, '')::text AS membership_source_kind,
       coalesce(role_path.membership_source_authoritative::boolean, false)::boolean AS membership_source_authoritative,
       role_path.membership_source_retired_at::timestamptz AS membership_source_retired_at,
       role_path.membership_granted_by_user_id::uuid AS membership_granted_by_user_id,
       coalesce(role_path.membership_grant_reason::text, '')::text AS membership_grant_reason,
       role_path.membership_granted_at::timestamptz AS membership_granted_at,
       role_path.membership_expires_at::timestamptz AS membership_expires_at,
       coalesce(role_path.membership_version::integer, 0)::integer AS membership_version
FROM app.resolve_current_tenant_human_role_grant_paths(
  sqlc.arg(page_size)::integer
) AS role_path(
  path_type, source_type, effective_expires_at, role_id, role_key, role_name,
  role_grant_id, role_source_id, role_source_kind, role_source_authoritative,
  role_source_retired_at, role_granted_by_user_id, role_grant_reason,
  role_granted_at, role_grant_expires_at, role_grant_version, group_id,
  group_key, group_name, group_membership_id, membership_source_id,
  membership_source_kind, membership_source_authoritative,
  membership_source_retired_at, membership_granted_by_user_id,
  membership_grant_reason, membership_granted_at, membership_expires_at,
  membership_version
);

-- name: ListTenantPermissionCatalog :many
SELECT permission.permission_id::uuid AS permission_id,
       permission.permission_key::text AS permission_key,
       permission.display_name::text AS display_name,
       permission.description::text AS description,
       permission.allowed_scopes::text[] AS allowed_scopes,
       permission.principal_kinds::text[] AS principal_kinds
FROM app.list_tenant_permission_catalog_v3(
  sqlc.narg(after_id)::uuid,
  sqlc.arg(page_size)::integer
) AS permission(
  permission_id, permission_key, display_name, description, allowed_scopes,
  principal_kinds
);

-- name: ListTenantAuthorizationRoles :many
SELECT role.role_id::uuid AS role_id,
       role.role_key::text AS role_key,
       role.display_name::text AS display_name,
       role.description::text AS description,
       role.principal_kind::text AS principal_kind,
       role.system_role::boolean AS system_role,
       role.protected_role::boolean AS protected_role,
       role.version::integer AS version,
       role.archived_at::timestamptz AS archived_at,
       role.created_at::timestamptz AS created_at,
       role.updated_at::timestamptz AS updated_at
FROM app.list_tenant_roles_v3(
  sqlc.narg(after_id)::uuid,
  sqlc.arg(include_archived)::boolean,
  sqlc.arg(page_size)::integer
) AS role(
  role_id, role_key, display_name, description, principal_kind, system_role, protected_role,
  version, archived_at, created_at, updated_at
);

-- name: GetTenantAuthorizationRole :one
SELECT role.role_id::uuid AS role_id,
       role.role_key::text AS role_key,
       role.display_name::text AS display_name,
       role.description::text AS description,
       role.principal_kind::text AS principal_kind,
       role.system_role::boolean AS system_role,
       role.protected_role::boolean AS protected_role,
       role.version::integer AS version,
       role.archived_at::timestamptz AS archived_at,
       role.created_at::timestamptz AS created_at,
       role.updated_at::timestamptz AS updated_at
FROM app.get_tenant_role_v3(sqlc.arg(role_id)::uuid) AS role(
  role_id, role_key, display_name, description, principal_kind, system_role, protected_role,
  version, archived_at, created_at, updated_at
);

-- name: GetTenantAuthorizationRolePolicy :many
SELECT policy.permission_key::text AS permission_key,
       policy.scope::text AS scope,
       policy.delegable::boolean AS delegable
FROM app.get_tenant_role_policy_v3(
  sqlc.arg(role_id)::uuid
) AS policy(permission_key, scope, delegable);

-- name: ListTenantAuthorizationUsers :many
SELECT tenant_user.membership_id::uuid AS membership_id,
       tenant_user.user_id::uuid AS user_id,
       tenant_user.email::text AS email,
       tenant_user.display_name::text AS display_name,
       tenant_user.membership_status::text AS membership_status,
       tenant_user.compatibility_role::text AS compatibility_role,
       tenant_user.user_active::boolean AS user_active,
       tenant_user.lifecycle_revision::integer AS lifecycle_revision,
       tenant_user.created_at::timestamptz AS created_at,
       tenant_user.updated_at::timestamptz AS updated_at
FROM app.list_tenant_users_v2(
  sqlc.narg(after_membership_id)::uuid,
  sqlc.arg(page_size)::integer
) AS tenant_user(
  membership_id, user_id, email, display_name, membership_status,
  compatibility_role, user_active, lifecycle_revision, created_at, updated_at
);

-- name: ChangeTenantMembershipLifecycle :one
SELECT result.tenant_id::uuid AS tenant_id,
       result.membership_id::uuid AS membership_id,
       result.target_user_id::uuid AS target_user_id,
       result.previous_status::text AS previous_status,
       result.status::text AS status,
       result.lifecycle_revision::integer AS lifecycle_revision,
       result.updated_at::timestamptz AS updated_at,
       result.revoked_session_count::integer AS revoked_session_count,
       result.revoked_continuation_count::integer AS revoked_continuation_count,
       result.replayed::boolean AS replayed
FROM app.change_tenant_membership_lifecycle_v1(
  sqlc.arg(actor_session_id)::uuid,
  sqlc.arg(target_user_id)::uuid,
  sqlc.arg(target_status)::text::membership_status,
  sqlc.arg(expected_revision)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(idempotency_key_digest)::bytea,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(
  tenant_id, membership_id, target_user_id, previous_status, status,
  lifecycle_revision, updated_at, revoked_session_count,
  revoked_continuation_count, replayed
);

-- name: ListTenantMembershipRoleGrants :many
SELECT role_grant.grant_id::uuid AS grant_id,
       role_grant.membership_id::uuid AS membership_id,
       role_grant.role_id::uuid AS role_id,
       role_grant.role_key::text AS role_key,
       role_grant.role_name::text AS role_name,
       role_grant.role_description::text AS role_description,
       role_grant.role_system::boolean AS role_system,
       role_grant.role_archived_at::timestamptz AS role_archived_at,
       role_grant.role_version::integer AS role_version,
       role_grant.role_created_at::timestamptz AS role_created_at,
       role_grant.role_updated_at::timestamptz AS role_updated_at,
       role_grant.source_id::uuid AS source_id,
       role_grant.source_kind::text AS source_kind,
       role_grant.source_authoritative::boolean AS source_authoritative,
       role_grant.source_retired_at::timestamptz AS source_retired_at,
       role_grant.managed_by_authorization_api::boolean AS managed_by_authorization_api,
       role_grant.source_type::text AS source_type,
       role_grant.granted_by_membership_id::uuid AS granted_by_membership_id,
       role_grant.granted_by_user_id::uuid AS granted_by_user_id,
       role_grant.grant_reason::text AS grant_reason,
       role_grant.granted_at::timestamptz AS granted_at,
       role_grant.expires_at::timestamptz AS expires_at,
       role_grant.revoked_at::timestamptz AS revoked_at,
       role_grant.revoked_by_membership_id::uuid AS revoked_by_membership_id,
       role_grant.revoked_by_user_id::uuid AS revoked_by_user_id,
       coalesce(role_grant.revoke_reason::text, '')::text AS revoke_reason,
       role_grant.grant_state::text AS grant_state,
       role_grant.version::integer AS version,
       role_grant.updated_at::timestamptz AS updated_at
FROM app.list_tenant_membership_role_grants_v2(
  sqlc.arg(target_user_id)::uuid,
  sqlc.narg(after_grant_id)::uuid,
  sqlc.arg(include_revoked)::boolean,
  sqlc.arg(page_size)::integer
) AS role_grant(
  grant_id, membership_id, role_id, role_key, role_name, role_description,
  role_system, role_archived_at, role_version, role_created_at, role_updated_at,
  source_id, source_kind, source_authoritative, source_retired_at,
  managed_by_authorization_api, source_type,
  granted_by_membership_id,
  granted_by_user_id, grant_reason, granted_at, expires_at, revoked_at,
  revoked_by_membership_id, revoked_by_user_id, revoke_reason, grant_state,
  version, updated_at
);

-- name: GetTenantMembershipRoleGrant :one
SELECT role_grant.grant_id::uuid AS grant_id,
       role_grant.membership_id::uuid AS membership_id,
       role_grant.target_user_id::uuid AS target_user_id,
       role_grant.role_id::uuid AS role_id,
       role_grant.role_key::text AS role_key,
       role_grant.role_name::text AS role_name,
       role_grant.role_description::text AS role_description,
       role_grant.role_system::boolean AS role_system,
       role_grant.role_archived_at::timestamptz AS role_archived_at,
       role_grant.role_version::integer AS role_version,
       role_grant.role_created_at::timestamptz AS role_created_at,
       role_grant.role_updated_at::timestamptz AS role_updated_at,
       role_grant.source_id::uuid AS source_id,
       role_grant.source_kind::text AS source_kind,
       role_grant.source_authoritative::boolean AS source_authoritative,
       role_grant.source_retired_at::timestamptz AS source_retired_at,
       role_grant.managed_by_authorization_api::boolean AS managed_by_authorization_api,
       role_grant.source_type::text AS source_type,
       role_grant.granted_by_membership_id::uuid AS granted_by_membership_id,
       role_grant.granted_by_user_id::uuid AS granted_by_user_id,
       role_grant.grant_reason::text AS grant_reason,
       role_grant.granted_at::timestamptz AS granted_at,
       role_grant.expires_at::timestamptz AS expires_at,
       role_grant.revoked_at::timestamptz AS revoked_at,
       role_grant.revoked_by_membership_id::uuid AS revoked_by_membership_id,
       role_grant.revoked_by_user_id::uuid AS revoked_by_user_id,
       coalesce(role_grant.revoke_reason::text, '')::text AS revoke_reason,
       role_grant.grant_state::text AS grant_state,
       role_grant.version::integer AS version,
       role_grant.updated_at::timestamptz AS updated_at
FROM app.get_tenant_membership_role_grant_v2(
  sqlc.arg(grant_id)::uuid
) AS role_grant(
  grant_id, membership_id, target_user_id, role_id, role_key, role_name,
  role_description, role_system, role_archived_at, role_version,
  role_created_at, role_updated_at, source_id, source_kind,
  source_authoritative, source_retired_at, managed_by_authorization_api,
  source_type,
  granted_by_membership_id, granted_by_user_id, grant_reason, granted_at,
  expires_at, revoked_at, revoked_by_membership_id, revoked_by_user_id,
  revoke_reason, grant_state, version, updated_at
);

-- name: CreateTenantAuthorizationRole :one
SELECT result.result_resource_id::uuid AS result_resource_id,
       result.result_version::integer AS result_version,
       result.replayed::boolean AS replayed
FROM app.create_tenant_role(
  sqlc.arg(role_id)::uuid,
  sqlc.arg(idempotency_key_digest)::bytea,
  sqlc.arg(role_key)::text,
  sqlc.arg(role_name)::text,
  sqlc.arg(role_description)::text,
  sqlc.arg(permission_keys)::text[],
  sqlc.arg(permission_scopes)::text[]::authorization_scope[],
  sqlc.arg(delegation_permission_keys)::text[],
  sqlc.arg(delegation_scopes)::text[]::authorization_scope[],
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(result_resource_id, result_version, replayed);

-- name: UpdateTenantAuthorizationRoleMetadata :one
SELECT app.update_tenant_role_metadata(
  sqlc.arg(role_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.narg(role_name)::text,
  sqlc.narg(role_description)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: ReplaceTenantAuthorizationRolePolicy :one
SELECT result.role_id::uuid AS role_id,
       result.role_key::text AS role_key,
       result.display_name::text AS display_name,
       result.description::text AS description,
       result.system_role::boolean AS system_role,
       result.protected_role::boolean AS protected_role,
       result.version::integer AS version,
       result.archived_at::timestamptz AS archived_at,
       result.created_at::timestamptz AS created_at,
       result.updated_at::timestamptz AS updated_at,
       result.permission_keys::text[] AS permission_keys,
       result.permission_scopes::text[] AS permission_scopes,
       result.delegation_permission_keys::text[] AS delegation_permission_keys,
       result.delegation_scopes::text[] AS delegation_scopes
FROM app.replace_tenant_role_policy_with_result_v2(
  sqlc.arg(role_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(permission_keys)::text[],
  sqlc.arg(permission_scopes)::text[]::authorization_scope[],
  sqlc.arg(delegation_permission_keys)::text[],
  sqlc.arg(delegation_scopes)::text[]::authorization_scope[],
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(
  role_id, role_key, display_name, description, system_role, protected_role,
  version, archived_at, created_at, updated_at, permission_keys,
  permission_scopes, delegation_permission_keys, delegation_scopes
);

-- name: ArchiveTenantAuthorizationRole :one
SELECT app.archive_tenant_role(
  sqlc.arg(role_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: GrantTenantUserRole :one
SELECT result.result_resource_id::uuid AS result_resource_id,
       result.result_version::integer AS result_version,
       result.replayed::boolean AS replayed
FROM app.grant_tenant_human_user_role_v1(
  sqlc.arg(grant_id)::uuid,
  sqlc.arg(idempotency_key_digest)::bytea,
  sqlc.arg(target_user_id)::uuid,
  sqlc.arg(role_id)::uuid,
  sqlc.arg(reason)::text,
  sqlc.narg(expires_at)::timestamptz,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(result_resource_id, result_version, replayed);

-- name: RevokeTenantUserRoleGrant :one
SELECT app.revoke_tenant_human_user_role_grant_v1(
  sqlc.arg(grant_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: ListTenantAuthorizationSecurityGroups :many
SELECT security_group.group_id::uuid AS group_id,
       security_group.group_key::text AS group_key,
       security_group.group_name::text AS group_name,
       security_group.group_description::text AS group_description,
       security_group.archived_at::timestamptz AS archived_at,
       security_group.version::integer AS version,
       security_group.created_at::timestamptz AS created_at,
       security_group.updated_at::timestamptz AS updated_at
FROM app.list_tenant_security_groups(
  sqlc.narg(after_group_id)::uuid,
  sqlc.arg(include_archived)::boolean,
  sqlc.arg(page_size)::integer
) AS security_group(
  group_id, group_key, group_name, group_description,
  created_by_membership_id, created_by_user_id, archived_at, version,
  created_at, updated_at
);

-- name: GetTenantAuthorizationSecurityGroup :one
SELECT security_group.group_id::uuid AS group_id,
       security_group.group_key::text AS group_key,
       security_group.group_name::text AS group_name,
       security_group.group_description::text AS group_description,
       security_group.archived_at::timestamptz AS archived_at,
       security_group.version::integer AS version,
       security_group.created_at::timestamptz AS created_at,
       security_group.updated_at::timestamptz AS updated_at
FROM app.get_tenant_security_group(
  sqlc.arg(group_id)::uuid
) AS security_group(
  group_id, group_key, group_name, group_description,
  created_by_membership_id, created_by_user_id, archived_at, version,
  created_at, updated_at
);

-- name: CreateTenantAuthorizationSecurityGroup :one
SELECT result.result_resource_id::uuid AS result_resource_id,
       result.result_version::integer AS result_version,
       result.replayed::boolean AS replayed
FROM app.create_tenant_security_group(
  sqlc.arg(group_id)::uuid,
  sqlc.arg(idempotency_key_digest)::bytea,
  sqlc.arg(group_key)::text,
  sqlc.arg(group_name)::text,
  sqlc.arg(group_description)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(result_resource_id, result_version, replayed);

-- name: UpdateTenantAuthorizationSecurityGroupMetadata :one
SELECT app.update_tenant_security_group_metadata(
  sqlc.arg(group_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.narg(group_name)::text,
  sqlc.narg(group_description)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: ArchiveTenantAuthorizationSecurityGroup :one
SELECT app.archive_tenant_security_group(
  sqlc.arg(group_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: ListTenantAuthorizationSecurityGroupMemberships :many
SELECT edge.group_membership_id::uuid AS group_membership_id,
       edge.group_id::uuid AS group_id,
       edge.group_key::text AS group_key,
       edge.group_name::text AS group_name,
       edge.group_description::text AS group_description,
       edge.group_archived_at::timestamptz AS group_archived_at,
       edge.group_version::integer AS group_version,
       edge.group_created_at::timestamptz AS group_created_at,
       edge.group_updated_at::timestamptz AS group_updated_at,
       edge.membership_id::uuid AS membership_id,
       edge.target_user_id::uuid AS target_user_id,
       edge.email::text AS email,
       edge.display_name::text AS display_name,
       edge.membership_status::text AS membership_status,
       edge.compatibility_role::text AS compatibility_role,
       edge.user_active::boolean AS user_active,
       edge.membership_created_at::timestamptz AS membership_created_at,
       edge.membership_updated_at::timestamptz AS membership_updated_at,
       edge.source_id::uuid AS source_id,
       edge.source_kind::text AS source_kind,
       edge.source_authoritative::boolean AS source_authoritative,
       edge.source_retired_at::timestamptz AS source_retired_at,
       edge.granted_by_user_id::uuid AS granted_by_user_id,
       edge.grant_reason::text AS grant_reason,
       edge.granted_at::timestamptz AS granted_at,
       edge.expires_at::timestamptz AS expires_at,
       edge.revoked_at::timestamptz AS revoked_at,
       edge.revoked_by_user_id::uuid AS revoked_by_user_id,
       coalesce(edge.revoke_reason::text, '')::text AS revoke_reason,
       edge.grant_state::text AS grant_state,
       edge.version::integer AS version,
       edge.updated_at::timestamptz AS updated_at,
       edge.managed_by_authorization_api::boolean AS managed_by_authorization_api,
       edge.membership_lifecycle_revision::integer AS membership_lifecycle_revision
FROM app.list_tenant_security_group_memberships_v3(
  sqlc.arg(group_id)::uuid,
  sqlc.narg(after_group_membership_id)::uuid,
  sqlc.arg(include_revoked)::boolean,
  sqlc.arg(page_size)::integer
) AS edge(
  group_membership_id, group_id, group_key, group_name, group_description,
  group_archived_at, group_version, group_created_at, group_updated_at,
  membership_id, target_user_id, email, display_name, membership_status,
  compatibility_role, user_active, membership_created_at,
  membership_updated_at, source_id, source_kind, source_authoritative,
  source_retired_at, granted_by_membership_id, granted_by_user_id,
  grant_reason, granted_at, expires_at, revoked_at,
  revoked_by_membership_id, revoked_by_user_id, revoke_reason, grant_state,
  version, updated_at, managed_by_authorization_api, membership_lifecycle_revision
);

-- name: GetTenantAuthorizationSecurityGroupMembership :one
SELECT edge.group_membership_id::uuid AS group_membership_id,
       edge.group_id::uuid AS group_id,
       edge.group_key::text AS group_key,
       edge.group_name::text AS group_name,
       edge.group_description::text AS group_description,
       edge.group_archived_at::timestamptz AS group_archived_at,
       edge.group_version::integer AS group_version,
       edge.group_created_at::timestamptz AS group_created_at,
       edge.group_updated_at::timestamptz AS group_updated_at,
       edge.membership_id::uuid AS membership_id,
       edge.target_user_id::uuid AS target_user_id,
       edge.email::text AS email,
       edge.display_name::text AS display_name,
       edge.membership_status::text AS membership_status,
       edge.compatibility_role::text AS compatibility_role,
       edge.user_active::boolean AS user_active,
       edge.membership_created_at::timestamptz AS membership_created_at,
       edge.membership_updated_at::timestamptz AS membership_updated_at,
       edge.source_id::uuid AS source_id,
       edge.source_kind::text AS source_kind,
       edge.source_authoritative::boolean AS source_authoritative,
       edge.source_retired_at::timestamptz AS source_retired_at,
       edge.granted_by_user_id::uuid AS granted_by_user_id,
       edge.grant_reason::text AS grant_reason,
       edge.granted_at::timestamptz AS granted_at,
       edge.expires_at::timestamptz AS expires_at,
       edge.revoked_at::timestamptz AS revoked_at,
       edge.revoked_by_user_id::uuid AS revoked_by_user_id,
       coalesce(edge.revoke_reason::text, '')::text AS revoke_reason,
       edge.grant_state::text AS grant_state,
       edge.version::integer AS version,
       edge.updated_at::timestamptz AS updated_at,
       edge.managed_by_authorization_api::boolean AS managed_by_authorization_api,
       edge.membership_lifecycle_revision::integer AS membership_lifecycle_revision
FROM app.get_tenant_security_group_membership_v3(
  sqlc.arg(group_id)::uuid,
  sqlc.arg(group_membership_id)::uuid
) AS edge(
  group_membership_id, group_id, group_key, group_name, group_description,
  group_archived_at, group_version, group_created_at, group_updated_at,
  membership_id, target_user_id, email, display_name, membership_status,
  compatibility_role, user_active, membership_created_at,
  membership_updated_at, source_id, source_kind, source_authoritative,
  source_retired_at, granted_by_membership_id, granted_by_user_id,
  grant_reason, granted_at, expires_at, revoked_at,
  revoked_by_membership_id, revoked_by_user_id, revoke_reason, grant_state,
  version, updated_at, managed_by_authorization_api, membership_lifecycle_revision
);

-- name: AddTenantAuthorizationSecurityGroupMember :one
SELECT result.result_resource_id::uuid AS result_resource_id,
       result.result_version::integer AS result_version,
       result.replayed::boolean AS replayed
FROM app.add_tenant_security_group_member(
  sqlc.arg(group_membership_id)::uuid,
  sqlc.arg(idempotency_key_digest)::bytea,
  sqlc.arg(group_id)::uuid,
  sqlc.arg(target_user_id)::uuid,
  sqlc.arg(reason)::text,
  sqlc.narg(expires_at)::timestamptz,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(result_resource_id, result_version, replayed);

-- name: RevokeTenantAuthorizationSecurityGroupMembership :one
SELECT app.revoke_tenant_security_group_membership(
  sqlc.arg(group_id)::uuid,
  sqlc.arg(group_membership_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: ListTenantAuthorizationSecurityGroupRoleGrants :many
SELECT edge.group_role_grant_id::uuid AS group_role_grant_id,
       edge.group_id::uuid AS group_id,
       edge.group_key::text AS group_key,
       edge.group_name::text AS group_name,
       edge.group_description::text AS group_description,
       edge.group_archived_at::timestamptz AS group_archived_at,
       edge.group_version::integer AS group_version,
       edge.group_created_at::timestamptz AS group_created_at,
       edge.group_updated_at::timestamptz AS group_updated_at,
       edge.role_id::uuid AS role_id,
       edge.role_key::text AS role_key,
       edge.role_name::text AS role_name,
       edge.role_description::text AS role_description,
       edge.role_system::boolean AS role_system,
       edge.role_protected::boolean AS role_protected,
       edge.role_archived_at::timestamptz AS role_archived_at,
       edge.role_version::integer AS role_version,
       edge.role_created_at::timestamptz AS role_created_at,
       edge.role_updated_at::timestamptz AS role_updated_at,
       edge.source_id::uuid AS source_id,
       edge.source_kind::text AS source_kind,
       edge.source_authoritative::boolean AS source_authoritative,
       edge.source_retired_at::timestamptz AS source_retired_at,
       edge.granted_by_user_id::uuid AS granted_by_user_id,
       edge.grant_reason::text AS grant_reason,
       edge.granted_at::timestamptz AS granted_at,
       edge.expires_at::timestamptz AS expires_at,
       edge.revoked_at::timestamptz AS revoked_at,
       edge.revoked_by_user_id::uuid AS revoked_by_user_id,
       coalesce(edge.revoke_reason::text, '')::text AS revoke_reason,
       edge.grant_state::text AS grant_state,
       edge.version::integer AS version,
       edge.updated_at::timestamptz AS updated_at,
       edge.managed_by_authorization_api::boolean AS managed_by_authorization_api
FROM app.list_tenant_security_group_role_grants_v2(
  sqlc.arg(group_id)::uuid,
  sqlc.narg(after_group_role_grant_id)::uuid,
  sqlc.arg(include_revoked)::boolean,
  sqlc.arg(page_size)::integer
) AS edge(
  group_role_grant_id, group_id, group_key, group_name, group_description,
  group_archived_at, group_version, group_created_at, group_updated_at,
  role_id, role_key, role_name, role_description, role_system,
  role_protected, role_archived_at, role_version, role_created_at,
  role_updated_at, source_id, source_kind, source_authoritative,
  source_retired_at, granted_by_membership_id, granted_by_user_id,
  grant_reason, granted_at, expires_at, revoked_at,
  revoked_by_membership_id, revoked_by_user_id, revoke_reason, grant_state,
  version, updated_at, managed_by_authorization_api
);

-- name: GetTenantAuthorizationSecurityGroupRoleGrant :one
SELECT edge.group_role_grant_id::uuid AS group_role_grant_id,
       edge.group_id::uuid AS group_id,
       edge.group_key::text AS group_key,
       edge.group_name::text AS group_name,
       edge.group_description::text AS group_description,
       edge.group_archived_at::timestamptz AS group_archived_at,
       edge.group_version::integer AS group_version,
       edge.group_created_at::timestamptz AS group_created_at,
       edge.group_updated_at::timestamptz AS group_updated_at,
       edge.role_id::uuid AS role_id,
       edge.role_key::text AS role_key,
       edge.role_name::text AS role_name,
       edge.role_description::text AS role_description,
       edge.role_system::boolean AS role_system,
       edge.role_protected::boolean AS role_protected,
       edge.role_archived_at::timestamptz AS role_archived_at,
       edge.role_version::integer AS role_version,
       edge.role_created_at::timestamptz AS role_created_at,
       edge.role_updated_at::timestamptz AS role_updated_at,
       edge.source_id::uuid AS source_id,
       edge.source_kind::text AS source_kind,
       edge.source_authoritative::boolean AS source_authoritative,
       edge.source_retired_at::timestamptz AS source_retired_at,
       edge.granted_by_user_id::uuid AS granted_by_user_id,
       edge.grant_reason::text AS grant_reason,
       edge.granted_at::timestamptz AS granted_at,
       edge.expires_at::timestamptz AS expires_at,
       edge.revoked_at::timestamptz AS revoked_at,
       edge.revoked_by_user_id::uuid AS revoked_by_user_id,
       coalesce(edge.revoke_reason::text, '')::text AS revoke_reason,
       edge.grant_state::text AS grant_state,
       edge.version::integer AS version,
       edge.updated_at::timestamptz AS updated_at,
       edge.managed_by_authorization_api::boolean AS managed_by_authorization_api
FROM app.get_tenant_security_group_role_grant_v2(
  sqlc.arg(group_id)::uuid,
  sqlc.arg(group_role_grant_id)::uuid
) AS edge(
  group_role_grant_id, group_id, group_key, group_name, group_description,
  group_archived_at, group_version, group_created_at, group_updated_at,
  role_id, role_key, role_name, role_description, role_system,
  role_protected, role_archived_at, role_version, role_created_at,
  role_updated_at, source_id, source_kind, source_authoritative,
  source_retired_at, granted_by_membership_id, granted_by_user_id,
  grant_reason, granted_at, expires_at, revoked_at,
  revoked_by_membership_id, revoked_by_user_id, revoke_reason, grant_state,
  version, updated_at, managed_by_authorization_api
);

-- name: GrantTenantAuthorizationSecurityGroupRole :one
SELECT result.result_resource_id::uuid AS result_resource_id,
       result.result_version::integer AS result_version,
       result.replayed::boolean AS replayed
FROM app.grant_tenant_human_security_group_role_v1(
  sqlc.arg(group_role_grant_id)::uuid,
  sqlc.arg(idempotency_key_digest)::bytea,
  sqlc.arg(group_id)::uuid,
  sqlc.arg(role_id)::uuid,
  sqlc.arg(reason)::text,
  sqlc.narg(expires_at)::timestamptz,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(result_resource_id, result_version, replayed);

-- name: RevokeTenantAuthorizationSecurityGroupRoleGrant :one
SELECT app.revoke_tenant_human_security_group_role_grant_v1(
  sqlc.arg(group_id)::uuid,
  sqlc.arg(group_role_grant_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(audit_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;
