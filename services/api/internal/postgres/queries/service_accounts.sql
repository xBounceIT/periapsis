-- name: ResolveTenantServiceAccountAuthority :many
SELECT authority.permission_key::text AS permission_key,
       authority.scope::text AS scope,
       authority.effective_expires_at::timestamptz AS effective_expires_at
FROM app.resolve_tenant_service_account_authority_v1(
  sqlc.arg(service_account_id)::uuid,
  sqlc.arg(page_size)::integer
) AS authority(permission_key, scope, effective_expires_at);

-- name: ListLiveAPICredentialKeyVersions :many
SELECT inventory.key_version::integer AS key_version
FROM app.list_live_api_credential_key_versions_v1(
  sqlc.arg(page_size)::integer
) AS inventory(key_version);

-- name: ListTenantServiceAccounts :many
SELECT account.service_account_id::uuid AS service_account_id,
       account.account_key::text AS account_key,
       account.display_name::text AS display_name,
       account.description::text AS description,
       account.created_by_membership_id::uuid AS created_by_membership_id,
       account.created_by_user_id::uuid AS created_by_user_id,
       account.archived_at::timestamptz AS archived_at,
       account.archived_by_membership_id::uuid AS archived_by_membership_id,
       account.archived_by_user_id::uuid AS archived_by_user_id,
       coalesce(account.archive_reason::text, '')::text AS archive_reason,
       account.version::integer AS version,
       account.created_at::timestamptz AS created_at,
       account.updated_at::timestamptz AS updated_at
FROM app.list_tenant_service_accounts_v1(
  sqlc.narg(after_id)::uuid,
  sqlc.arg(include_archived)::boolean,
  sqlc.arg(page_size)::integer
) AS account(
  service_account_id, account_key, display_name, description,
  created_by_membership_id, created_by_user_id, archived_at,
  archived_by_membership_id, archived_by_user_id, archive_reason, version,
  created_at, updated_at
);

-- name: GetTenantServiceAccount :one
SELECT account.service_account_id::uuid AS service_account_id,
       account.account_key::text AS account_key,
       account.display_name::text AS display_name,
       account.description::text AS description,
       account.created_by_membership_id::uuid AS created_by_membership_id,
       account.created_by_user_id::uuid AS created_by_user_id,
       account.archived_at::timestamptz AS archived_at,
       account.archived_by_membership_id::uuid AS archived_by_membership_id,
       account.archived_by_user_id::uuid AS archived_by_user_id,
       coalesce(account.archive_reason::text, '')::text AS archive_reason,
       account.version::integer AS version,
       account.created_at::timestamptz AS created_at,
       account.updated_at::timestamptz AS updated_at
FROM app.get_tenant_service_account_v1(
  sqlc.arg(service_account_id)::uuid
) AS account(
  service_account_id, account_key, display_name, description,
  created_by_membership_id, created_by_user_id, archived_at,
  archived_by_membership_id, archived_by_user_id, archive_reason, version,
  created_at, updated_at
);

-- name: CreateTenantServiceAccount :one
SELECT result.result_resource_id::uuid AS result_resource_id,
       result.result_version::integer AS result_version
FROM app.create_tenant_service_account_v1(
  sqlc.arg(service_account_id)::uuid,
  sqlc.arg(account_key)::text,
  sqlc.arg(display_name)::text,
  sqlc.arg(description)::text,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(result_resource_id, result_version);

-- name: UpdateTenantServiceAccount :one
SELECT app.update_tenant_service_account_v1(
  sqlc.arg(service_account_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.narg(display_name)::text,
  sqlc.narg(description)::text,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: ArchiveTenantServiceAccount :one
SELECT app.archive_tenant_service_account_v1(
  sqlc.arg(service_account_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: ListTenantServiceAccountRoleGrants :many
SELECT role_grant.grant_id::uuid AS grant_id,
       role_grant.service_account_id::uuid AS service_account_id,
       role_grant.role_id::uuid AS role_id,
       role_grant.role_key::text AS role_key,
       role_grant.role_display_name::text AS role_display_name,
       role_grant.role_system::boolean AS role_system,
       role_grant.source_id::uuid AS source_id,
       role_grant.source_kind::text AS source_kind,
       role_grant.source_key::text AS source_key,
       role_grant.source_authoritative::boolean AS source_authoritative,
       role_grant.source_retired_at::timestamptz AS source_retired_at,
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
FROM app.list_tenant_service_account_role_grants_v1(
  sqlc.arg(service_account_id)::uuid,
  sqlc.narg(after_id)::uuid,
  sqlc.arg(include_revoked)::boolean,
  sqlc.arg(page_size)::integer
) AS role_grant(
  grant_id, service_account_id, role_id, role_key, role_display_name,
  role_system, source_id, source_kind, source_key, source_authoritative,
  source_retired_at, granted_by_membership_id, granted_by_user_id,
  grant_reason, granted_at, expires_at, revoked_at,
  revoked_by_membership_id, revoked_by_user_id, revoke_reason, grant_state,
  version, updated_at
);

-- name: GetTenantServiceAccountRoleGrant :one
SELECT role_grant.grant_id::uuid AS grant_id,
       role_grant.service_account_id::uuid AS service_account_id,
       role_grant.role_id::uuid AS role_id,
       role_grant.role_key::text AS role_key,
       role_grant.role_display_name::text AS role_display_name,
       role_grant.role_system::boolean AS role_system,
       role_grant.source_id::uuid AS source_id,
       role_grant.source_kind::text AS source_kind,
       role_grant.source_key::text AS source_key,
       role_grant.source_authoritative::boolean AS source_authoritative,
       role_grant.source_retired_at::timestamptz AS source_retired_at,
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
FROM app.get_tenant_service_account_role_grant_v1(
  sqlc.arg(service_account_id)::uuid,
  sqlc.arg(grant_id)::uuid
) AS role_grant(
  grant_id, service_account_id, role_id, role_key, role_display_name,
  role_system, source_id, source_kind, source_key, source_authoritative,
  source_retired_at, granted_by_membership_id, granted_by_user_id,
  grant_reason, granted_at, expires_at, revoked_at,
  revoked_by_membership_id, revoked_by_user_id, revoke_reason, grant_state,
  version, updated_at
);

-- name: GrantTenantServiceAccountRole :one
SELECT result.result_resource_id::uuid AS result_resource_id,
       result.result_version::integer AS result_version
FROM app.grant_tenant_service_account_role_v1(
  sqlc.arg(grant_id)::uuid,
  sqlc.arg(service_account_id)::uuid,
  sqlc.arg(role_id)::uuid,
  sqlc.arg(reason)::text,
  sqlc.narg(expires_at)::timestamptz,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(result_resource_id, result_version);

-- name: RevokeTenantServiceAccountRoleGrant :one
SELECT app.revoke_tenant_service_account_role_grant_v1(
  sqlc.arg(service_account_id)::uuid,
  sqlc.arg(grant_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: ListTenantAPICredentials :many
SELECT credential.credential_id::uuid AS credential_id,
       credential.service_account_id::uuid AS service_account_id,
       credential.label::text AS label,
       credential.format_version::integer AS format_version,
       credential.key_version::integer AS key_version,
       credential.issued_by_membership_id::uuid AS issued_by_membership_id,
       credential.issued_by_user_id::uuid AS issued_by_user_id,
       credential.issued_at::timestamptz AS issued_at,
       credential.expires_at::timestamptz AS expires_at,
       credential.rotated_from_credential_id::uuid AS rotated_from_credential_id,
       credential.revoked_at::timestamptz AS revoked_at,
       credential.revoked_by_membership_id::uuid AS revoked_by_membership_id,
       credential.revoked_by_user_id::uuid AS revoked_by_user_id,
       coalesce(credential.revoke_reason::text, '')::text AS revoke_reason,
       credential.last_used_at::timestamptz AS last_used_at,
       credential.last_used_ip::inet AS last_used_ip,
       CASE
         WHEN credential.revoked_at IS NOT NULL THEN 'revoked'
         WHEN credential.expires_at <= transaction_timestamp() THEN 'expired'
         ELSE 'active'
       END::text AS credential_state,
       credential.version::integer AS version,
       credential.updated_at::timestamptz AS updated_at,
       credential.permission_keys::text[] AS permission_keys,
       credential.permission_scopes::text[] AS permission_scopes,
       credential.networks::cidr[] AS networks
FROM app.list_tenant_api_credentials_v1(
  sqlc.arg(service_account_id)::uuid,
  sqlc.narg(after_id)::uuid,
  sqlc.arg(include_revoked)::boolean,
  sqlc.arg(page_size)::integer
) AS credential(
  credential_id, service_account_id, label, format_version, key_version,
  issued_by_membership_id, issued_by_user_id, issued_at, expires_at,
  rotated_from_credential_id, revoked_at, revoked_by_membership_id,
  revoked_by_user_id, revoke_reason, last_used_at, last_used_ip, version,
  updated_at, permission_keys, permission_scopes, networks
);

-- name: GetTenantAPICredential :one
SELECT credential.credential_id::uuid AS credential_id,
       credential.service_account_id::uuid AS service_account_id,
       credential.label::text AS label,
       credential.format_version::integer AS format_version,
       credential.key_version::integer AS key_version,
       credential.issued_by_membership_id::uuid AS issued_by_membership_id,
       credential.issued_by_user_id::uuid AS issued_by_user_id,
       credential.issued_at::timestamptz AS issued_at,
       credential.expires_at::timestamptz AS expires_at,
       credential.rotated_from_credential_id::uuid AS rotated_from_credential_id,
       credential.revoked_at::timestamptz AS revoked_at,
       credential.revoked_by_membership_id::uuid AS revoked_by_membership_id,
       credential.revoked_by_user_id::uuid AS revoked_by_user_id,
       coalesce(credential.revoke_reason::text, '')::text AS revoke_reason,
       credential.last_used_at::timestamptz AS last_used_at,
       credential.last_used_ip::inet AS last_used_ip,
       CASE
         WHEN credential.revoked_at IS NOT NULL THEN 'revoked'
         WHEN credential.expires_at <= transaction_timestamp() THEN 'expired'
         ELSE 'active'
       END::text AS credential_state,
       credential.version::integer AS version,
       credential.updated_at::timestamptz AS updated_at,
       credential.permission_keys::text[] AS permission_keys,
       credential.permission_scopes::text[] AS permission_scopes,
       credential.networks::cidr[] AS networks
FROM app.get_tenant_api_credential_v1(
  sqlc.arg(service_account_id)::uuid,
  sqlc.arg(credential_id)::uuid
) AS credential(
  credential_id, service_account_id, label, format_version, key_version,
  issued_by_membership_id, issued_by_user_id, issued_at, expires_at,
  rotated_from_credential_id, revoked_at, revoked_by_membership_id,
  revoked_by_user_id, revoke_reason, last_used_at, last_used_ip, version,
  updated_at, permission_keys, permission_scopes, networks
);

-- name: IssueTenantAPICredential :one
SELECT result.result_credential_id::uuid AS result_credential_id,
       result.result_version::integer AS result_version,
       result.replayed::boolean AS replayed
FROM app.issue_tenant_api_credential_v1(
  sqlc.arg(credential_id)::uuid,
  sqlc.arg(service_account_id)::uuid,
  sqlc.arg(key_digest)::bytea,
  sqlc.arg(request_digest)::bytea,
  sqlc.arg(label)::text,
  sqlc.arg(format_version)::integer,
  sqlc.arg(locator)::bytea,
  sqlc.arg(key_version)::integer,
  sqlc.arg(secret_digest)::bytea,
  sqlc.arg(expires_at)::timestamptz,
  sqlc.arg(permission_keys)::text[],
  sqlc.arg(permission_scopes)::text[]::authorization_scope[],
  sqlc.arg(networks)::cidr[],
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(result_credential_id, result_version, replayed);

-- name: RotateTenantAPICredential :one
SELECT result.result_credential_id::uuid AS result_credential_id,
       result.result_version::integer AS result_version,
       result.replayed::boolean AS replayed
FROM app.rotate_tenant_api_credential_v1(
  sqlc.arg(replacement_credential_id)::uuid,
  sqlc.arg(service_account_id)::uuid,
  sqlc.arg(rotated_from_credential_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(key_digest)::bytea,
  sqlc.arg(request_digest)::bytea,
  sqlc.arg(label)::text,
  sqlc.arg(format_version)::integer,
  sqlc.arg(locator)::bytea,
  sqlc.arg(key_version)::integer,
  sqlc.arg(secret_digest)::bytea,
  sqlc.arg(expires_at)::timestamptz,
  sqlc.arg(permission_keys)::text[],
  sqlc.arg(permission_scopes)::text[]::authorization_scope[],
  sqlc.arg(networks)::cidr[],
  sqlc.arg(rotation_reason)::text,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(result_credential_id, result_version, replayed);

-- name: RevokeTenantAPICredential :one
SELECT app.revoke_tenant_api_credential_v1(
  sqlc.arg(service_account_id)::uuid,
  sqlc.arg(credential_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;
