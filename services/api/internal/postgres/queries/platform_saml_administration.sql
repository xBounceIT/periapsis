-- name: LoadPlatformSAMLMetadataAdmin :one
SELECT app.load_platform_saml_metadata_admin_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(authentication_method)::text
)::jsonb AS document;

-- name: ReplacePlatformSAMLMetadata :one
SELECT result.version::bigint AS version,
       result.metadata_revision::bigint AS material_revision
FROM app.replace_platform_saml_metadata_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(expected_version)::bigint,
  sqlc.arg(document)::bytea,
  sqlc.arg(document_digest)::bytea,
  sqlc.arg(retrieved_at)::timestamptz,
  sqlc.arg(maximum_valid_until)::timestamptz,
  sqlc.arg(protected_approval)::boolean,
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(version, metadata_revision);

-- name: ReplacePlatformSAMLSPKey :one
SELECT result.version::bigint AS version,
       result.key_revision::bigint AS material_revision
FROM app.replace_platform_saml_sp_key_v1(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(provider_id)::uuid,
  sqlc.arg(key_id)::uuid,
  sqlc.arg(expected_version)::bigint,
  sqlc.arg(key_version)::integer,
  sqlc.arg(nonce)::bytea,
  sqlc.arg(ciphertext)::bytea,
  sqlc.arg(certificates)::bytea[],
  sqlc.arg(audit_event_id)::uuid,
  sqlc.arg(request_id)::uuid,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(ip_address)::inet,
  sqlc.arg(user_agent)::text,
  sqlc.arg(authentication_method)::text,
  sqlc.arg(reason)::text
) AS result(version, key_revision);

-- name: ClearPlatformSAMLSPKey :one
SELECT result.version::bigint AS version,
       result.key_revision::bigint AS material_revision
FROM app.clear_platform_saml_sp_key_v1(
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
) AS result(version, key_revision);
