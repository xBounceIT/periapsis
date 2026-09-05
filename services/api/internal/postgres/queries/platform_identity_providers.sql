-- name: ListPlatformAuthProviders :many
SELECT provider.document::jsonb AS document
FROM app.list_platform_auth_providers_v2(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.narg(after_provider_id)::uuid,
  sqlc.arg(page_size)::integer,
  sqlc.arg(include_archived)::boolean
) AS provider(document);

-- name: GetPlatformAuthProvider :one
SELECT app.get_platform_auth_provider_v2(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(authentication_method)::text
)::jsonb AS document;

-- name: CreatePlatformLDAPAuthProvider :one
SELECT app.create_platform_ldap_provider_v1(
  sqlc.arg(request)::jsonb
)::jsonb AS result;

-- name: UpdatePlatformLDAPAuthProvider :one
SELECT app.update_platform_ldap_provider_v1(
  sqlc.arg(request)::jsonb
)::jsonb AS document;

-- name: ReplacePlatformLDAPBindSecret :one
SELECT app.rotate_platform_ldap_bind_secret_v1(
  sqlc.arg(request)::jsonb
)::jsonb AS result;

-- name: PutPlatformLDAPMapping :one
SELECT app.put_platform_ldap_mapping_rule_v1(
  sqlc.arg(request)::jsonb
)::jsonb AS document;

-- name: SetPlatformLDAPLoginState :one
SELECT app.set_platform_ldap_provider_enabled_v1(
  sqlc.arg(request)::jsonb
)::jsonb AS document;

-- name: BeginPlatformLDAPTest :one
SELECT app.begin_platform_ldap_test_v1(
  sqlc.arg(request)::jsonb
)::jsonb AS snapshot;

-- name: CompletePlatformLDAPTest :one
SELECT app.complete_platform_ldap_test_v1(
  sqlc.arg(request)::jsonb
)::jsonb AS result;

-- name: CreatePlatformOIDCAuthProvider :one
SELECT result.provider_id::uuid AS provider_id,
       result.version::bigint AS version,
       result.replayed::boolean AS replayed,
       result.document::jsonb AS document
FROM app.create_platform_oidc_auth_provider_v2(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(command_id)::uuid,
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(provider_key)::text,
  sqlc.arg(display_name)::text,
  sqlc.arg(description)::text,
  sqlc.arg(configuration)::jsonb,
  sqlc.arg(tenant_redirect_uri)::text,
  sqlc.arg(key_digest)::bytea,
  sqlc.arg(request_digest)::bytea,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(provider_id, version, replayed, document);

-- name: CreatePlatformSAMLAuthProvider :one
SELECT result.provider_id::uuid AS provider_id,
       result.version::bigint AS version,
       result.replayed::boolean AS replayed,
       result.document::jsonb AS document
FROM app.create_platform_saml_auth_provider_v2(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(command_id)::uuid,
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(provider_key)::text,
  sqlc.arg(display_name)::text,
  sqlc.arg(description)::text,
  sqlc.arg(configuration)::jsonb,
  sqlc.arg(key_digest)::bytea,
  sqlc.arg(request_digest)::bytea,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(provider_id, version, replayed, document);

-- name: UpdatePlatformAuthProvider :one
SELECT result.version::bigint AS version,
       result.document::jsonb AS document
FROM app.update_platform_auth_provider_v2(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(expected_version)::bigint,
  sqlc.arg(provider_key)::text,
  sqlc.arg(display_name)::text,
  sqlc.arg(description)::text,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(version, document);

-- name: ArchivePlatformAuthProvider :one
SELECT app.archive_platform_auth_provider_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(expected_version)::bigint,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
)::bigint AS version;

-- name: ReplacePlatformOIDCAuthProviderClientSecret :one
SELECT result.version::bigint AS version,
       result.secret_revision::bigint AS secret_revision
FROM app.replace_platform_oidc_client_secret_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(secret_id)::uuid,
  sqlc.arg(expected_version)::bigint,
  sqlc.arg(key_version)::integer,
  sqlc.arg(nonce)::bytea,
  sqlc.arg(ciphertext)::bytea,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(version, secret_revision);

-- name: ActivatePlatformAuthProviderTenantExecution :one
SELECT result.version::bigint AS version,
       result.document::jsonb AS document
FROM app.activate_platform_auth_provider_tenant_execution_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(expected_version)::bigint,
  sqlc.arg(account_mode)::text,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(version, document);

-- name: DeactivatePlatformAuthProviderTenantExecution :one
SELECT result.version::bigint AS version,
       result.document::jsonb AS document
FROM app.deactivate_platform_auth_provider_tenant_execution_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(expected_version)::bigint,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(version, document);

-- name: ActivatePlatformOIDCDirectLogin :one
SELECT result.version::bigint AS version,
       result.document::jsonb AS document
FROM app.activate_platform_direct_login_v2(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(expected_version)::bigint,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(version, document);

-- name: DeactivatePlatformOIDCDirectLogin :one
SELECT result.version::bigint AS version,
       result.document::jsonb AS document
FROM app.deactivate_platform_direct_login_v2(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(expected_version)::bigint,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(version, document);
