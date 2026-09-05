-- name: ListPlatformIdentityAccounts :many
SELECT account.document::jsonb AS document
FROM app.list_platform_identity_accounts_v2(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(platform_provider_id)::uuid,
  sqlc.narg(after_account_id)::uuid,
  sqlc.arg(page_size)::integer,
  sqlc.arg(include_retired)::boolean
) AS account(document);

-- name: GetPlatformIdentityAccount :one
SELECT app.get_platform_identity_account_v2(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(platform_provider_id)::uuid,
  sqlc.arg(account_id)::uuid,
  sqlc.arg(authentication_method)::text
)::jsonb AS document;

-- name: PrelinkPlatformIdentityAccount :one
SELECT result.account_id::uuid AS account_id,
       result.version::bigint AS version,
       result.replayed::boolean AS replayed,
       result.document::jsonb AS document
FROM app.prelink_platform_identity_account_v2(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(command_id)::uuid,
  sqlc.arg(account_id)::uuid,
  sqlc.arg(platform_provider_id)::uuid,
  sqlc.arg(user_id)::uuid,
  sqlc.arg(issuer)::text,
  sqlc.arg(subject_format)::public.identity_subject_format,
  sqlc.arg(subject_ciphertext)::bytea,
  sqlc.arg(subject_nonce)::bytea,
  sqlc.arg(subject_key_version)::integer,
  sqlc.arg(alias_key_versions)::integer[],
  sqlc.arg(alias_subject_digests)::bytea[],
  sqlc.arg(key_digest)::bytea,
  sqlc.arg(public_request_digest)::bytea,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(account_id, version, replayed, document);

-- name: RetirePlatformIdentityAccountV3 :one
SELECT result.account_id::uuid AS account_id,
       result.version::bigint AS version,
       result.document::jsonb AS document
FROM app.retire_platform_identity_account_v3(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(platform_provider_id)::uuid,
  sqlc.arg(account_id)::uuid,
  sqlc.arg(expected_version)::bigint,
  sqlc.arg(expected_user_version)::bigint,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(account_id, version, document);
