-- name: ListTenantLDAPProviders :many
SELECT provider.provider_id::uuid AS provider_id,
       provider.provider_key::text AS provider_key,
       provider.display_name::text AS display_name,
       provider.description::text AS description,
       provider.enabled::boolean AS enabled,
       provider.template::text AS template,
       provider.bind_secret_configured::boolean AS bind_secret_configured,
       provider.enabled_endpoint_count::integer AS enabled_endpoint_count,
       provider.archived_at::timestamptz AS archived_at,
       provider.version::integer AS version,
       provider.created_at::timestamptz AS created_at,
       provider.updated_at::timestamptz AS updated_at
FROM app.list_tenant_ldap_providers_v1(
  sqlc.narg(after_provider_id)::uuid,
  sqlc.arg(include_archived)::boolean,
  sqlc.arg(page_size)::integer
) AS provider(
  provider_id, provider_key, display_name, description, enabled, template,
  bind_secret_configured, enabled_endpoint_count, archived_at, version,
  created_at, updated_at
);

-- name: GetTenantLDAPProvider :one
SELECT provider.provider_id::uuid AS provider_id,
       provider.provider_key::text AS provider_key,
       provider.display_name::text AS display_name,
       provider.description::text AS description,
       provider.enabled::boolean AS enabled,
       provider.configuration::jsonb AS configuration,
       provider.endpoints::jsonb AS endpoints,
       provider.bind_secret_configured::boolean AS bind_secret_configured,
       provider.bind_secret_rotated_at::timestamptz AS bind_secret_rotated_at,
       provider.archived_at::timestamptz AS archived_at,
       coalesce(provider.archive_reason::text, '')::text AS archive_reason,
       provider.version::integer AS version,
       provider.created_at::timestamptz AS created_at,
       provider.updated_at::timestamptz AS updated_at
FROM app.get_tenant_ldap_provider_v1(
  sqlc.arg(provider_id)::uuid
) AS provider(
  provider_id, provider_key, display_name, description, enabled,
  configuration, endpoints, bind_secret_configured,
  bind_secret_rotated_at, archived_at, archive_reason, version,
  created_at, updated_at
);

-- name: CreateTenantLDAPProvider :one
SELECT result.provider_id::uuid AS provider_id,
       result.result_version::integer AS result_version,
       result.replayed::boolean AS replayed
FROM app.create_tenant_ldap_provider_v1(
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(idempotency_key_digest)::bytea,
  sqlc.arg(provider_key)::text,
  sqlc.arg(display_name)::text,
  sqlc.arg(description)::text,
  sqlc.arg(configuration)::jsonb,
  sqlc.arg(endpoints)::jsonb,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(provider_id, result_version, replayed);

-- name: UpdateTenantLDAPProvider :one
SELECT app.update_tenant_ldap_provider_v1(
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(provider_key)::text,
  sqlc.arg(display_name)::text,
  sqlc.arg(description)::text,
  sqlc.arg(enabled)::boolean,
  sqlc.arg(configuration)::jsonb,
  sqlc.arg(endpoints)::jsonb,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: GetTenantLDAPBindSecretID :one
SELECT app.get_tenant_ldap_bind_secret_id_v1(
  sqlc.arg(provider_id)::uuid
) AS secret_id;

-- name: RotateTenantLDAPBindSecret :one
SELECT app.rotate_tenant_ldap_bind_secret_v1(
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(secret_id)::uuid,
  sqlc.arg(secret_ciphertext)::bytea,
  sqlc.arg(secret_nonce)::bytea,
  sqlc.arg(key_version)::integer,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: ClearTenantLDAPBindSecret :one
SELECT app.clear_tenant_ldap_bind_secret_v1(
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: ArchiveTenantLDAPProvider :one
SELECT app.archive_tenant_ldap_provider_v1(
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(expected_version)::integer,
  sqlc.arg(reason)::text,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS version;

-- name: BeginTenantLDAPProviderTest :one
SELECT snapshot.test_run_id::uuid AS test_run_id,
       snapshot.provider_id::uuid AS provider_id,
       snapshot.provider_version::integer AS provider_version,
       snapshot.configuration_version::integer AS configuration_version,
       coalesce(snapshot.secret_version, 0)::integer AS secret_version,
       snapshot.configuration::jsonb AS configuration,
       snapshot.endpoints::jsonb AS endpoints,
       snapshot.secret_id::uuid AS secret_id,
       snapshot.secret_ciphertext::bytea AS secret_ciphertext,
       snapshot.secret_nonce::bytea AS secret_nonce,
       coalesce(snapshot.secret_key_version, 0)::integer AS secret_key_version,
       coalesce(snapshot.encryption_algorithm, '')::text AS encryption_algorithm,
       snapshot.started_at::timestamptz AS started_at
FROM app.begin_tenant_ldap_provider_test_v1(
  sqlc.arg(test_run_id)::uuid,
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(test_kind)::text::ldap_provider_test_kind,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS snapshot(
  test_run_id, provider_id, provider_version, configuration_version,
  secret_version, configuration, endpoints, secret_id, secret_ciphertext,
  secret_nonce, secret_key_version, encryption_algorithm, started_at
);

-- name: CompleteTenantLDAPProviderTest :one
SELECT result.test_run_id::uuid AS test_run_id,
       result.outcome::text AS outcome,
       result.category::text AS category,
       coalesce(result.endpoint_priority, 0)::integer AS endpoint_priority,
       result.duration_ms::integer AS duration_ms,
       result.stale::boolean AS stale,
       result.completed_at::timestamptz AS completed_at
FROM app.complete_tenant_ldap_provider_test_v1(
  sqlc.arg(test_run_id)::uuid,
  sqlc.arg(reported_outcome)::text::ldap_provider_test_outcome,
  sqlc.arg(reported_category)::text::ldap_provider_test_category,
  sqlc.narg(endpoint_priority)::integer,
  sqlc.arg(duration_ms)::integer,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  nullif(sqlc.arg(user_agent)::text, ''),
  sqlc.arg(authentication_method)::text
) AS result(
  test_run_id, outcome, category, endpoint_priority, duration_ms, stale,
  completed_at
);

-- name: VerifyIdentityKeyring :one
SELECT app.verify_identity_keyring_v3(
  sqlc.arg(key_versions)::integer[],
  sqlc.arg(verifiers)::bytea[],
  sqlc.arg(active_version)::integer
) AS verified;
