-- V33 adds the expand-only platform federation administration boundary. V32
-- remains the exact rolling predecessor at migration 0154; V31 is retired.
CREATE FUNCTION app.schema_compatibility_v33()
RETURNS TABLE(
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  latest_rows bigint;
  forward_count bigint;
  forward_latest_created_at bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787929625096
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, latest_rows;
  IF journal_count = 159
     AND journal_latest_created_at = 1787929625096
     AND latest_rows = 1
     AND to_regprocedure('app.schema_compatibility_v34()') IS NULL THEN
    RETURN QUERY EXECUTE $query$
      SELECT count(*)::bigint, max(migration.created_at)::bigint,
             (SELECT lower(latest.hash::text)
              FROM drizzle.__drizzle_migrations AS latest
              ORDER BY latest.created_at DESC, latest.id DESC LIMIT 1),
             string_agg(
               migration.created_at::text || '@' || lower(migration.hash::text),
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM drizzle.__drizzle_migrations AS migration
    $query$;
    RETURN;
  END IF;

  -- This is the immutable rolling-predecessor ABI for the planned 9B
  -- expansion.  A suffix is visible only after the versioned current
  -- projection has been sealed successfully; an applied-but-unsealed or
  -- partially failed upgrade therefore remains unavailable to old replicas.
  IF journal_count = 163
     AND journal_latest_created_at = 1787936037593
     AND latest_rows = 1
     AND to_regprocedure('app.schema_compatibility_v34()') IS NOT NULL THEN
    EXECUTE $query$
      SELECT compatibility.applied_count,
             compatibility.latest_created_at
      FROM app.schema_compatibility_v34() AS compatibility
    $query$ INTO forward_count, forward_latest_created_at;
    IF forward_count = 163
       AND forward_latest_created_at = 1787936037593 THEN
      RETURN QUERY EXECUTE $query$
        WITH ordered_migrations AS (
          SELECT migration.id, migration.created_at,
                 lower(migration.hash::text) AS migration_hash,
                 row_number() OVER (
                   ORDER BY migration.created_at, migration.id
                 ) AS migration_ordinal
          FROM drizzle.__drizzle_migrations AS migration
        )
        SELECT count(*)::bigint, max(migration.created_at)::bigint,
               (SELECT prefix.migration_hash
                FROM ordered_migrations AS prefix
                WHERE prefix.migration_ordinal = 159),
               string_agg(
                 migration.created_at::text || '@' || migration.migration_hash,
                 ':' ORDER BY migration.created_at, migration.id
               )
        FROM ordered_migrations AS migration
        WHERE migration.migration_ordinal <= 159
      $query$;
      RETURN;
    END IF;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v33()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v33()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v33()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v32()
RETURNS TABLE(
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
SET app.schema_compatibility_fingerprint = 'UNSEALED'
AS $function$
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  latest_rows bigint;
  full_count bigint;
  full_latest_created_at bigint;
  full_fingerprint text;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787929625096
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, latest_rows;
  IF journal_count IS DISTINCT FROM 159
     OR journal_latest_created_at IS DISTINCT FROM 1787929625096
     OR latest_rows IS DISTINCT FROM 1 THEN
    RETURN QUERY SELECT 0::bigint, 0::bigint,
                        'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
    RETURN;
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.migration_fingerprint
  INTO full_count, full_latest_created_at, full_fingerprint
  FROM app.schema_compatibility_v33() AS compatibility;
  IF full_count = 159
     AND full_latest_created_at = 1787929625096
     AND full_fingerprint = current_setting(
       'app.schema_compatibility_fingerprint', true
     ) THEN
    RETURN QUERY EXECUTE $query$
      WITH ordered_migrations AS (
        SELECT migration.id, migration.created_at,
               lower(migration.hash::text) AS migration_hash,
               row_number() OVER (
                 ORDER BY migration.created_at, migration.id
               ) AS migration_ordinal
        FROM drizzle.__drizzle_migrations AS migration
      )
      SELECT count(*)::bigint, max(migration.created_at)::bigint,
             (SELECT prefix.migration_hash
              FROM ordered_migrations AS prefix
              WHERE prefix.migration_ordinal = 155),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 155
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v32()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v32()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v32()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v31()
RETURNS TABLE(
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v31()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v31()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

-- Migration 0119 inherited the applying superuser as owner for three
-- runtime-visible MFA helpers.  Normalize them before the first platform
-- runtime-catalog seal so both the predecessor and its 9B successor are
-- independent of the bootstrap role.
ALTER FUNCTION app.private_complete_mfa_factor_v1(jsonb, text)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_webauthn_ceremony_projection_v1(bytea)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_webauthn_credential_projection_v1(uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint

-- A schema-local default-privilege revoke cannot remove PostgreSQL's global
-- PUBLIC EXECUTE default for routines. Seal the actual creator-role default
-- globally so any future function is private until explicitly granted.
ALTER DEFAULT PRIVILEGES FOR ROLE periapsis_migrator
REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
--> statement-breakpoint

-- PostgreSQL 15+ assigns public to the dynamic pg_database_owner role by
-- default. A later database-owner transfer must not grant a new principal the
-- ability to inject operators, casts, views, or routines into a trusted
-- SECURITY DEFINER search path.
ALTER SCHEMA public OWNER TO periapsis_migrator;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
--> statement-breakpoint

-- These statements are generated from the canonical Drizzle model. Fold them
-- into the unreleased compatibility slice so persistence rejects values that
-- Go cannot project exactly, instead of relying on readiness alone.
ALTER TABLE "platform_auth_providers" DROP CONSTRAINT "platform_auth_providers_display_name_check";
ALTER TABLE "platform_auth_providers" DROP CONSTRAINT "platform_auth_providers_description_check";
ALTER TABLE "platform_auth_providers" DROP CONSTRAINT "platform_auth_providers_archive_check";
ALTER TABLE "platform_auth_providers" DROP CONSTRAINT "platform_auth_providers_lifecycle_check";
ALTER TABLE "platform_federated_provider_policies" DROP CONSTRAINT "platform_federated_provider_policies_revision_check";
ALTER TABLE "platform_federated_trust_rules" DROP CONSTRAINT "platform_federated_trust_rules_value_check";
ALTER TABLE "platform_identity_provider_commands" DROP CONSTRAINT "platform_identity_provider_commands_result_check";
ALTER TABLE "platform_identity_provider_test_runs" DROP CONSTRAINT "platform_identity_provider_test_runs_revision_check";
ALTER TABLE "platform_oidc_client_secrets" DROP CONSTRAINT "platform_oidc_client_secrets_envelope_check";
ALTER TABLE "platform_oidc_discovery_snapshots" DROP CONSTRAINT "platform_oidc_discovery_snapshots_value_check";
ALTER TABLE "platform_oidc_jwks_snapshots" DROP CONSTRAINT "platform_oidc_jwks_snapshots_value_check";
ALTER TABLE "platform_oidc_provider_configurations" DROP CONSTRAINT "platform_oidc_provider_configurations_revision_check";
ALTER TABLE "platform_oidc_provider_configurations" DROP CONSTRAINT "platform_oidc_provider_configurations_text_check";
ALTER TABLE "platform_oidc_provider_configurations" DROP CONSTRAINT "platform_oidc_provider_configurations_scope_check";
ALTER TABLE "platform_saml_metadata_snapshots" DROP CONSTRAINT "platform_saml_metadata_snapshots_value_check";
ALTER TABLE "platform_saml_provider_configurations" DROP CONSTRAINT "platform_saml_provider_configurations_revision_check";
ALTER TABLE "platform_saml_provider_configurations" DROP CONSTRAINT "platform_saml_provider_configurations_text_check";
ALTER TABLE "platform_saml_sp_keys" DROP CONSTRAINT "platform_saml_sp_keys_envelope_check";
--> statement-breakpoint

ALTER TABLE "platform_auth_providers" ADD CONSTRAINT "platform_auth_providers_display_name_check" CHECK ("platform_auth_providers"."display_name" = btrim("platform_auth_providers"."display_name")
        and "platform_auth_providers"."display_name" <> ''
        and char_length("platform_auth_providers"."display_name") <= 120
        and "platform_auth_providers"."display_name" !~ '[[:cntrl:]]');
ALTER TABLE "platform_auth_providers" ADD CONSTRAINT "platform_auth_providers_description_check" CHECK ("platform_auth_providers"."description" = btrim("platform_auth_providers"."description")
        and char_length("platform_auth_providers"."description") <= 1000
        and "platform_auth_providers"."description" !~ '[[:cntrl:]]');
ALTER TABLE "platform_auth_providers" ADD CONSTRAINT "platform_auth_providers_archive_check" CHECK (("platform_auth_providers"."archived_at" is null
          and "platform_auth_providers"."archived_by_user_id" is null
          and "platform_auth_providers"."archive_reason" is null)
        or ("platform_auth_providers"."archived_at" is not null
          and "platform_auth_providers"."archived_by_user_id" is not null
          and "platform_auth_providers"."archive_reason" is not null
          and not "platform_auth_providers"."enabled"
          and "platform_auth_providers"."archived_at" >= "platform_auth_providers"."created_at"
          and "platform_auth_providers"."archive_reason" = btrim("platform_auth_providers"."archive_reason")
          and "platform_auth_providers"."archive_reason" <> ''
          and octet_length(convert_to("platform_auth_providers"."archive_reason", 'UTF8')) <= 2048
          and "platform_auth_providers"."archive_reason" !~ '[[:cntrl:]]'));
ALTER TABLE "platform_auth_providers" ADD CONSTRAINT "platform_auth_providers_lifecycle_check" CHECK ("platform_auth_providers"."version" between 1 and 2147483647
        and isfinite("platform_auth_providers"."created_at") and isfinite("platform_auth_providers"."updated_at")
        and extract(year from "platform_auth_providers"."created_at" at time zone 'UTC') between 1970 and 9999
        and extract(year from "platform_auth_providers"."updated_at" at time zone 'UTC') between 1970 and 9999
        and "platform_auth_providers"."updated_at" >= "platform_auth_providers"."created_at"
        and ("platform_auth_providers"."archived_at" is null or (
          isfinite("platform_auth_providers"."archived_at")
          and extract(year from "platform_auth_providers"."archived_at" at time zone 'UTC') between 1970 and 9999
          and "platform_auth_providers"."updated_at" >= "platform_auth_providers"."archived_at")));
ALTER TABLE "platform_federated_provider_policies" ADD CONSTRAINT "platform_federated_provider_policies_revision_check" CHECK ("platform_federated_provider_policies"."configuration_revision" between 1 and 9007199254740991
        and "platform_federated_provider_policies"."security_revision" between 1 and 9007199254740991
        and "platform_federated_provider_policies"."plan_revision" between 1 and 9007199254740991
        and "platform_federated_provider_policies"."assurance_policy_revision" between 1 and 9007199254740991);
ALTER TABLE "platform_federated_trust_rules" ADD CONSTRAINT "platform_federated_trust_rules_value_check" CHECK ("platform_federated_trust_rules"."provider_kind" in ('oidc','saml')
        and "platform_federated_trust_rules"."revision" between 1 and 9007199254740991
        and "platform_federated_trust_rules"."level" in ('mfa','phishing_resistant')
        and "platform_federated_trust_rules"."maximum_authentication_age_seconds" between 60 and 2592000
        and cardinality("platform_federated_trust_rules"."required_values") <= 128
        and array_position("platform_federated_trust_rules"."required_values", null) is null
        and (("platform_federated_trust_rules"."provider_kind" = 'oidc'
            and ("platform_federated_trust_rules"."exact_value" is not null or cardinality("platform_federated_trust_rules"."required_values") > 0))
          or ("platform_federated_trust_rules"."provider_kind" = 'saml'
            and "platform_federated_trust_rules"."exact_value" is not null
            and cardinality("platform_federated_trust_rules"."required_values") = 0)));
ALTER TABLE "platform_identity_provider_commands" ADD CONSTRAINT "platform_identity_provider_commands_result_check" CHECK ("platform_identity_provider_commands"."result_version" = 1);
ALTER TABLE "platform_identity_provider_test_runs" ADD CONSTRAINT "platform_identity_provider_test_runs_revision_check" CHECK ("platform_identity_provider_test_runs"."provider_version" between 1 and 2147483647
        and "platform_identity_provider_test_runs"."configuration_revision" between 1 and 9007199254740991);
ALTER TABLE "platform_oidc_client_secrets" ADD CONSTRAINT "platform_oidc_client_secrets_envelope_check" CHECK ("platform_oidc_client_secrets"."revision" between 1 and 9007199254740991
        and "platform_oidc_client_secrets"."key_version" between 1 and 32767
        and octet_length("platform_oidc_client_secrets"."nonce") = 12
        and octet_length("platform_oidc_client_secrets"."ciphertext") between 17 and 8208);
ALTER TABLE "platform_oidc_discovery_snapshots" ADD CONSTRAINT "platform_oidc_discovery_snapshots_value_check" CHECK ("platform_oidc_discovery_snapshots"."revision" between 1 and 9007199254740991
        and octet_length("platform_oidc_discovery_snapshots"."document") between 2 and 1048576
        and octet_length("platform_oidc_discovery_snapshots"."document_digest") = 32
        and "platform_oidc_discovery_snapshots"."fresh_until" between "platform_oidc_discovery_snapshots"."retrieved_at" and "platform_oidc_discovery_snapshots"."retrieved_at" + interval '7 days'
        and ("platform_oidc_discovery_snapshots"."cacheable" or ("platform_oidc_discovery_snapshots"."must_revalidate" and "platform_oidc_discovery_snapshots"."fresh_until" = "platform_oidc_discovery_snapshots"."retrieved_at"))
        and "platform_oidc_discovery_snapshots"."client_authentication" in ('client_secret_basic', 'client_secret_post')
        and cardinality("platform_oidc_discovery_snapshots"."signing_algorithms") between 1 and 16
        and array_position("platform_oidc_discovery_snapshots"."signing_algorithms", null) is null);
ALTER TABLE "platform_oidc_jwks_snapshots" ADD CONSTRAINT "platform_oidc_jwks_snapshots_value_check" CHECK ("platform_oidc_jwks_snapshots"."revision" between 1 and 9007199254740991
        and octet_length("platform_oidc_jwks_snapshots"."document") between 2 and 1048576
        and octet_length("platform_oidc_jwks_snapshots"."document_digest") = 32
        and "platform_oidc_jwks_snapshots"."fresh_until" between "platform_oidc_jwks_snapshots"."retrieved_at" and "platform_oidc_jwks_snapshots"."retrieved_at" + interval '7 days'
        and ("platform_oidc_jwks_snapshots"."cacheable" or ("platform_oidc_jwks_snapshots"."must_revalidate" and "platform_oidc_jwks_snapshots"."fresh_until" = "platform_oidc_jwks_snapshots"."retrieved_at")));
ALTER TABLE "platform_oidc_provider_configurations" ADD CONSTRAINT "platform_oidc_provider_configurations_revision_check" CHECK ("platform_oidc_provider_configurations"."client_secret_revision" between 1 and 9007199254740991
        and "platform_oidc_provider_configurations"."discovery_revision" between 1 and 9007199254740991
        and "platform_oidc_provider_configurations"."jwks_revision" between 1 and 9007199254740991
        and "platform_oidc_provider_configurations"."version" between 1 and 9007199254740991);
ALTER TABLE "platform_oidc_provider_configurations" ADD CONSTRAINT "platform_oidc_provider_configurations_text_check" CHECK ("platform_oidc_provider_configurations"."issuer" = btrim("platform_oidc_provider_configurations"."issuer")
        and "platform_oidc_provider_configurations"."issuer" ~ '^https://[^/?#@]+[^#?]*$'
        and char_length("platform_oidc_provider_configurations"."issuer") between 1 and 4096
        and octet_length(convert_to("platform_oidc_provider_configurations"."client_id", 'UTF8')) between 1 and 512
        and "platform_oidc_provider_configurations"."client_id" = btrim("platform_oidc_provider_configurations"."client_id")
        and "platform_oidc_provider_configurations"."redirect_uri" ~ '^https://[^/?#@]+'
        and "platform_oidc_provider_configurations"."post_logout_redirect_uri" ~ '^https://[^/?#@]+'
        and char_length("platform_oidc_provider_configurations"."redirect_uri") between 1 and 4096
        and char_length("platform_oidc_provider_configurations"."post_logout_redirect_uri") between 1 and 4096
        and "platform_oidc_provider_configurations"."issuer" !~ '[[:cntrl:]]'
        and "platform_oidc_provider_configurations"."client_id" !~ '[[:cntrl:]]'
        and "platform_oidc_provider_configurations"."redirect_uri" !~ '[[:cntrl:]]'
        and "platform_oidc_provider_configurations"."post_logout_redirect_uri" !~ '[[:cntrl:]]');
ALTER TABLE "platform_oidc_provider_configurations" ADD CONSTRAINT "platform_oidc_provider_configurations_scope_check" CHECK (cardinality("platform_oidc_provider_configurations"."extra_scopes") <= 32
        and array_position("platform_oidc_provider_configurations"."extra_scopes", null) is null
        and array_position("platform_oidc_provider_configurations"."extra_scopes", 'openid') is null
        and array_to_string("platform_oidc_provider_configurations"."extra_scopes", ' ') ~
          '^$|^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}( [A-Za-z0-9][A-Za-z0-9._:/-]{0,127})*$');
ALTER TABLE "platform_saml_metadata_snapshots" ADD CONSTRAINT "platform_saml_metadata_snapshots_value_check" CHECK ("platform_saml_metadata_snapshots"."revision" between 1 and 9007199254740991
        and octet_length("platform_saml_metadata_snapshots"."document") between 1 and 524288
        and octet_length("platform_saml_metadata_snapshots"."document_digest") = 32
        and "platform_saml_metadata_snapshots"."maximum_valid_until" > "platform_saml_metadata_snapshots"."retrieved_at");
ALTER TABLE "platform_saml_provider_configurations" ADD CONSTRAINT "platform_saml_provider_configurations_revision_check" CHECK ("platform_saml_provider_configurations"."sp_key_revision" between 1 and 9007199254740991
        and "platform_saml_provider_configurations"."metadata_revision" between 1 and 9007199254740991
        and "platform_saml_provider_configurations"."version" between 1 and 9007199254740991);
ALTER TABLE "platform_saml_provider_configurations" ADD CONSTRAINT "platform_saml_provider_configurations_text_check" CHECK ("platform_saml_provider_configurations"."expected_entity_id" = btrim("platform_saml_provider_configurations"."expected_entity_id")
        and "platform_saml_provider_configurations"."expected_entity_id" ~ '^[a-z][a-z0-9+.-]*:'
        and "platform_saml_provider_configurations"."sp_entity_id" ~ '^https://[^/?#@]+'
        and "platform_saml_provider_configurations"."acs_url" ~ '^https://[^/?#@]+'
        and octet_length(convert_to("platform_saml_provider_configurations"."expected_entity_id", 'UTF8')) between 1 and 2048
        and octet_length(convert_to("platform_saml_provider_configurations"."sp_entity_id", 'UTF8')) between 1 and 2048
        and octet_length(convert_to("platform_saml_provider_configurations"."acs_url", 'UTF8')) between 1 and 4096
        and "platform_saml_provider_configurations"."expected_entity_id" !~ '[[:cntrl:]]'
        and "platform_saml_provider_configurations"."sp_entity_id" !~ '[[:cntrl:]]'
        and "platform_saml_provider_configurations"."acs_url" !~ '[[:cntrl:]]');
ALTER TABLE "platform_saml_sp_keys" ADD CONSTRAINT "platform_saml_sp_keys_envelope_check" CHECK ("platform_saml_sp_keys"."revision" between 1 and 9007199254740991
        and "platform_saml_sp_keys"."key_version" between 1 and 32767
        and octet_length("platform_saml_sp_keys"."ciphertext") between 17 and 131072);
--> statement-breakpoint

-- Canonicalize every relation, sequence, routine, and effective privilege in
-- app/public that any deployed runtime group can reach. The readiness function
-- compares this digest with a build-reviewed value, so an additional view or
-- SECURITY DEFINER routine cannot become a covert secret-reading ABI.
CREATE FUNCTION app.private_runtime_accessible_surface_hash_v1()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
WITH runtime_role(role_name) AS (
  VALUES
    ('periapsis_api'), ('periapsis_worker'), ('periapsis_notifier'),
    ('periapsis_auditor'), ('periapsis_audit_reader_owner'),
    ('periapsis_ldap_administration_owner'),
    ('periapsis_notification_admin_owner'),
    ('periapsis_notification_dispatch_owner'), ('periapsis_sla_api_owner'),
    ('periapsis_notification_readiness_owner'),
    ('periapsis_sla_worker_owner'), ('periapsis_sla_readiness_owner'),
    ('periapsis_ticket_saved_view_owner'),
    ('periapsis_ticket_attribution_owner'),
    ('periapsis_ticket_sla_projection_owner')
),
externally_attested_routine(signature) AS (
  VALUES
    ('app.append_platform_audit_event(uuid,public.audit_actor_type,uuid,text,text,uuid,uuid,uuid,inet,text,text,public.audit_outcome,text,jsonb)'),
    ('app.archive_platform_auth_provider_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)'),
    ('app.audit_json_document_safe_v1(jsonb,integer,boolean)'),
    ('app.audit_json_key_value_safe_v1(text,jsonb)'),
    ('app.calculate_platform_audit_event_hash(public.platform_audit_events,character)'),
    ('app.context_user_id()'),
    ('app.create_platform_auth_provider_v1(uuid,uuid,uuid,public.auth_provider_kind,text,text,text,jsonb,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'),
    ('app.get_platform_auth_provider_v1(uuid,uuid,text)'),
    ('app.guard_audit_json_documents_v1()'),
    ('app.list_platform_auth_providers_v1(uuid,text,uuid,integer,boolean)'),
    ('app.platform_audit_event_payload(public.platform_audit_events)'),
    ('app.platform_user_has_permission(uuid,text)'),
    ('app.private_platform_audit_reason_is_safe_v1(text)'),
    ('app.private_platform_auth_provider_document_v1(uuid)'),
    ('app.private_platform_identity_text_is_safe_v1(text,boolean)'),
    ('app.private_platform_identity_uri_is_canonical_v1(text,boolean,boolean,integer)'),
    ('app.private_platform_lifecycle_reason_is_valid_v1(text)'),
    ('app.private_require_platform_identity_permission_v1(uuid,text,text)'),
    ('app.reject_platform_audit_event_mutation()'),
    ('app.replace_platform_oidc_client_secret_v1(uuid,uuid,uuid,bigint,integer,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'),
    ('app.seal_platform_audit_event()'),
    ('app.update_platform_auth_provider_v1(uuid,uuid,bigint,text,text,text,uuid,uuid,uuid,inet,text,text,text)'),
    ('app.verify_identity_keyring_v1(integer[],bytea[],integer)'),
    ('app.verify_identity_keyring_v2(integer[],bytea[],integer)'),
    ('app.verify_identity_keyring_v3(integer[],bytea[],integer)'),
    ('app.schema_compatibility_v33()'),
    ('app.platform_tenant_lifecycle_schema_readiness_v1()'),
    ('app.platform_identity_provider_schema_readiness_v1()')
),
relation_object AS (
  SELECT class.oid, namespace.nspname, class.relname, class.relkind,
         class.relpersistence, class.relrowsecurity, class.relforcerowsecurity,
         class.relreplident, class.relispartition, owner.rolname AS owner_name,
         CASE WHEN class.relkind IN ('v', 'm')
              THEN pg_get_viewdef(class.oid, true) ELSE '' END AS definition
  FROM pg_class AS class
  JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
  JOIN pg_roles AS owner ON owner.oid = class.relowner
  WHERE namespace.nspname IN ('app', 'public')
    AND class.relkind IN ('r', 'p', 'v', 'm', 'f')
    AND EXISTS (
      SELECT 1
      FROM runtime_role AS role
      WHERE has_table_privilege(role.role_name, class.oid, 'SELECT')
         OR has_table_privilege(role.role_name, class.oid, 'INSERT')
         OR has_table_privilege(role.role_name, class.oid, 'UPDATE')
         OR has_table_privilege(role.role_name, class.oid, 'DELETE')
         OR has_table_privilege(role.role_name, class.oid, 'TRUNCATE')
         OR has_table_privilege(role.role_name, class.oid, 'REFERENCES')
         OR has_table_privilege(role.role_name, class.oid, 'TRIGGER')
         OR has_any_column_privilege(role.role_name, class.oid, 'SELECT')
         OR has_any_column_privilege(role.role_name, class.oid, 'INSERT')
         OR has_any_column_privilege(role.role_name, class.oid, 'UPDATE')
         OR has_any_column_privilege(role.role_name, class.oid, 'REFERENCES')
    )
),
relation_object_entry(entry) AS (
  SELECT concat_ws(
    '|', 'relation', nspname || '.' || relname, relkind, relpersistence,
    relrowsecurity, relforcerowsecurity, relreplident, relispartition,
    owner_name, encode(sha256(convert_to(definition, 'UTF8')), 'hex')
  )
  FROM relation_object
),
relation_privilege_entry(entry) AS (
  SELECT concat_ws(
    '|', 'relation-privilege',
    relation.nspname || '.' || relation.relname,
    role.role_name, privilege.privilege_name
  )
  FROM relation_object AS relation
  CROSS JOIN runtime_role AS role
  CROSS JOIN (VALUES
    ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'),
    ('REFERENCES'), ('TRIGGER')
  ) AS privilege(privilege_name)
  WHERE has_table_privilege(
    role.role_name, relation.oid, privilege.privilege_name
  )
),
column_privilege_entry(entry) AS (
  SELECT concat_ws(
    '|', 'column-privilege', relation.nspname || '.' || relation.relname,
    attribute.attname, role.role_name, privilege.privilege_name
  )
  FROM relation_object AS relation
  JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid
  CROSS JOIN runtime_role AS role
  CROSS JOIN (VALUES
    ('SELECT'), ('INSERT'), ('UPDATE'), ('REFERENCES')
  ) AS privilege(privilege_name)
  WHERE attribute.attnum > 0
    AND NOT attribute.attisdropped
    AND has_column_privilege(
      role.role_name, relation.oid, attribute.attnum,
      privilege.privilege_name
    )
),
sequence_object AS (
  SELECT class.oid, namespace.nspname, class.relname,
         class.relpersistence, owner.rolname AS owner_name
  FROM pg_class AS class
  JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
  JOIN pg_roles AS owner ON owner.oid = class.relowner
  WHERE namespace.nspname IN ('app', 'public')
    AND class.relkind = 'S'
    AND EXISTS (
      SELECT 1
      FROM runtime_role AS role
      WHERE has_sequence_privilege(role.role_name, class.oid, 'USAGE')
         OR has_sequence_privilege(role.role_name, class.oid, 'SELECT')
         OR has_sequence_privilege(role.role_name, class.oid, 'UPDATE')
    )
),
sequence_object_entry(entry) AS (
  SELECT concat_ws(
    '|', 'sequence', nspname || '.' || relname,
    relpersistence, owner_name
  )
  FROM sequence_object
),
sequence_privilege_entry(entry) AS (
  SELECT concat_ws(
    '|', 'sequence-privilege', sequence.nspname || '.' || sequence.relname,
    role.role_name, privilege.privilege_name
  )
  FROM sequence_object AS sequence
  CROSS JOIN runtime_role AS role
  CROSS JOIN (VALUES
    ('USAGE'), ('SELECT'), ('UPDATE')
  ) AS privilege(privilege_name)
  WHERE has_sequence_privilege(
    role.role_name, sequence.oid, privilege.privilege_name
  )
),
routine_object AS (
  SELECT function.oid,
         namespace.nspname || '.' || function.proname || '(' ||
           pg_get_function_identity_arguments(function.oid) ||
           ')' AS signature,
         owner.rolname AS owner_name,
         language.lanname,
         function.prokind,
         function.provolatile,
         function.prosecdef,
         function.proleakproof,
         function.proisstrict,
         function.proparallel,
         CASE WHEN function.proname LIKE 'schema_compatibility_v%'
              THEN ARRAY['<sealed-compatibility-config>']::text[]
              ELSE function.proconfig END AS normalized_config,
         pg_get_function_result(function.oid) AS result_type,
         function.prosrc
  FROM pg_proc AS function
  JOIN pg_namespace AS namespace ON namespace.oid = function.pronamespace
  JOIN pg_roles AS owner ON owner.oid = function.proowner
  JOIN pg_language AS language ON language.oid = function.prolang
  WHERE namespace.nspname IN ('app', 'public')
    AND EXISTS (
      SELECT 1
      FROM runtime_role AS role
      WHERE has_function_privilege(
        role.role_name, function.oid, 'EXECUTE'
      )
    )
),
routine_object_entry(entry) AS (
  SELECT concat_ws(
    '|', 'routine', signature, owner_name, lanname, prokind, provolatile,
    prosecdef, proleakproof, proisstrict, proparallel,
    coalesce(array_to_string(normalized_config, ','), '<null>'),
    result_type,
    CASE WHEN EXISTS (
      SELECT 1
      FROM externally_attested_routine AS attested
      WHERE attested.signature = routine.signature
    ) THEN '<externally-attested>'
    ELSE encode(sha256(convert_to(prosrc, 'UTF8')), 'hex') END
  )
  FROM routine_object AS routine
),
routine_privilege_entry(entry) AS (
  SELECT concat_ws(
    '|', 'routine-privilege', routine.signature,
    role.role_name, 'EXECUTE'
  )
  FROM routine_object AS routine
  CROSS JOIN runtime_role AS role
  WHERE has_function_privilege(role.role_name, routine.oid, 'EXECUTE')
),
catalog_entry(entry) AS (
  SELECT entry FROM relation_object_entry
  UNION ALL SELECT entry FROM relation_privilege_entry
  UNION ALL SELECT entry FROM column_privilege_entry
  UNION ALL SELECT entry FROM sequence_object_entry
  UNION ALL SELECT entry FROM sequence_privilege_entry
  UNION ALL SELECT entry FROM routine_object_entry
  UNION ALL SELECT entry FROM routine_privilege_entry
)
SELECT encode(
  sha256(convert_to(string_agg(entry, E'\n' ORDER BY entry), 'UTF8')),
  'hex'
)
FROM catalog_entry;
$function$;
ALTER FUNCTION app.private_runtime_accessible_surface_hash_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_runtime_accessible_surface_hash_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ldap_administration_owner,
  periapsis_notification_admin_owner, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_notification_readiness_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

CREATE FUNCTION app.platform_identity_provider_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
DECLARE
  current_count bigint;
  predecessor_count bigint;
  protected_table_count integer;
  protected_trigger_count integer;
  protected_rule_count integer;
  protected_policy_count integer;
  protected_inheritance_count integer;
  protected_toast_mismatch_count integer;
  custom_operator_count integer;
  provider_cast_count integer;
  protected_function_count integer;
  private_function_count integer;
  permission_function_definition text;
  private_projection_function_count integer;
  private_validator_function_count integer;
  runtime_surface_function_count integer;
  runtime_accessible_surface_hash text;
  protected_acl_mismatch_count integer;
  private_acl_mismatch_count integer;
  protected_owner_function_count integer;
  private_owner_function_count integer;
  protected_owner_table_count integer;
  keyring_function_count integer;
  keyring_acl_mismatch_count integer;
  keyring_runtime_acl_mismatch_count integer;
  keyring_acl_entry_count integer;
  keyring_owner_function_count integer;
  legacy_keyring_acl_mismatch_count integer;
  security_role_mismatch_count integer;
  security_role_membership_mismatch_count integer;
  runtime_login_role_mismatch_count integer;
  schema_acl_mismatch_count integer;
  schema_effective_create_mismatch_count integer;
  database_effective_create_mismatch_count integer;
  default_acl_mismatch_count integer;
  default_acl_row_count integer;
  provider_kind_type_count integer;
  provider_kind_acl_mismatch_count integer;
  provider_kind_enum_mismatch_count integer;
  trusted_function_definition_mismatch_count integer;
  platform_audit_trigger_mismatch_count integer;
  catalog_column_mismatch_count integer;
  catalog_constraint_mismatch_count integer;
  catalog_index_mismatch_count integer;
  binding_extension_function_present boolean;
  binding_extension_ready boolean := false;
  rolling_catalog_state_ready boolean;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v33() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v32() AS compatibility;

  -- All principals in this slice's trust boundary retain their canonical
  -- non-login, non-privileged posture. The migrator alone may bypass RLS,
  -- solely so it can own the sealed SECURITY DEFINER surface.
  WITH expected_security_role(
    role_name, inherits_privileges, bypasses_rls
  ) AS (
    VALUES
      ('periapsis_migrator', true, true),
      ('periapsis_api', true, false),
      ('periapsis_worker', true, false),
      ('periapsis_notifier', true, false),
      ('periapsis_auditor', true, false),
      ('periapsis_ldap_administration_owner', false, false),
      ('periapsis_notification_admin_owner', false, false),
      ('periapsis_audit_reader_owner', false, false),
      ('periapsis_notification_dispatch_owner', false, false),
      ('periapsis_notification_readiness_owner', false, false),
      ('periapsis_sla_api_owner', false, false),
      ('periapsis_sla_worker_owner', false, false),
      ('periapsis_sla_readiness_owner', false, false),
      ('periapsis_ticket_saved_view_owner', false, false),
      ('periapsis_ticket_attribution_owner', false, false),
      ('periapsis_ticket_sla_projection_owner', false, false)
  )
  SELECT count(*)::integer INTO security_role_mismatch_count
  FROM expected_security_role AS expected
  LEFT JOIN pg_catalog.pg_roles AS role
    ON role.rolname = expected.role_name
  WHERE role.oid IS NULL
     OR role.rolsuper
     OR role.rolcreaterole
     OR role.rolcreatedb
     OR role.rolcanlogin
     OR role.rolreplication
     OR role.rolinherit IS DISTINCT FROM expected.inherits_privileges
     OR role.rolbypassrls IS DISTINCT FROM expected.bypasses_rls;

  -- A trust-boundary role is never allowed to SET ROLE into another
  -- principal. The only admitted inbound edges are the four deployment-owned
  -- runtime logins to their exact group roles, with no administration option.
  WITH boundary_role(role_name) AS (
    VALUES
      ('periapsis_migrator'),
      ('periapsis_api'),
      ('periapsis_worker'),
      ('periapsis_notifier'),
      ('periapsis_auditor'),
      ('periapsis_ldap_administration_owner'),
      ('periapsis_notification_admin_owner'),
      ('periapsis_audit_reader_owner'),
      ('periapsis_notification_dispatch_owner'),
      ('periapsis_notification_readiness_owner'),
      ('periapsis_sla_api_owner'),
      ('periapsis_sla_worker_owner'),
      ('periapsis_sla_readiness_owner'),
      ('periapsis_ticket_saved_view_owner'),
      ('periapsis_ticket_attribution_owner'),
      ('periapsis_ticket_sla_projection_owner')
  ),
  runtime_login(role_name, group_role_name) AS (
    VALUES
      ('periapsis_api_login', 'periapsis_api'),
      ('periapsis_worker_login', 'periapsis_worker'),
      ('periapsis_notifier_login', 'periapsis_notifier'),
      ('periapsis_auditor_login', 'periapsis_auditor')
  )
  SELECT count(*)::integer INTO security_role_membership_mismatch_count
  FROM pg_catalog.pg_auth_members AS membership
  JOIN pg_catalog.pg_roles AS granted_role
    ON granted_role.oid = membership.roleid
  JOIN pg_catalog.pg_roles AS member_role
    ON member_role.oid = membership.member
  WHERE (
      granted_role.rolname IN (SELECT role_name FROM boundary_role)
      OR member_role.rolname IN (SELECT role_name FROM boundary_role)
      OR granted_role.rolname IN (SELECT role_name FROM runtime_login)
      OR member_role.rolname IN (SELECT role_name FROM runtime_login)
    )
    AND NOT EXISTS (
      SELECT 1
      FROM runtime_login AS allowed
      WHERE allowed.group_role_name = granted_role.rolname
        AND allowed.role_name = member_role.rolname
        AND NOT membership.admin_option
        AND membership.inherit_option
        AND membership.set_option
    );

  -- Provisioning is intentionally a separate deployment step, so an absent
  -- runtime login is allowed during migration. Once present, it must be an
  -- exact unprivileged LOGIN with exactly its canonical group membership.
  WITH runtime_login(role_name, group_role_name) AS (
    VALUES
      ('periapsis_api_login', 'periapsis_api'),
      ('periapsis_worker_login', 'periapsis_worker'),
      ('periapsis_notifier_login', 'periapsis_notifier'),
      ('periapsis_auditor_login', 'periapsis_auditor')
  )
  SELECT count(*)::integer INTO runtime_login_role_mismatch_count
  FROM runtime_login AS expected
  JOIN pg_catalog.pg_roles AS login_role
    ON login_role.rolname = expected.role_name
  WHERE login_role.rolsuper
     OR NOT login_role.rolinherit
     OR login_role.rolcreaterole
     OR login_role.rolcreatedb
     OR NOT login_role.rolcanlogin
     OR login_role.rolreplication
     OR login_role.rolbypassrls
     OR NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_auth_members AS membership
       JOIN pg_catalog.pg_roles AS granted_role
         ON granted_role.oid = membership.roleid
       WHERE membership.member = login_role.oid
         AND granted_role.rolname = expected.group_role_name
         AND NOT membership.admin_option
         AND membership.inherit_option
         AND membership.set_option
     );

  -- SECURITY DEFINER routines resolve through public and app, so both schema
  -- namespaces are part of the trust boundary. Keep their owners and direct
  -- ACLs exact: runtime and helper roles may resolve objects, but only the
  -- canonical schema owners may create or replace them.
  WITH expected_schema_usage_role(role_name) AS (
    VALUES
      ('periapsis_api'),
      ('periapsis_worker'),
      ('periapsis_notifier'),
      ('periapsis_auditor'),
      ('periapsis_ldap_administration_owner'),
      ('periapsis_notification_admin_owner'),
      ('periapsis_notification_dispatch_owner'),
      ('periapsis_notification_readiness_owner'),
      ('periapsis_audit_reader_owner'),
      ('periapsis_sla_api_owner'),
      ('periapsis_sla_worker_owner'),
      ('periapsis_sla_readiness_owner'),
      ('periapsis_ticket_saved_view_owner'),
      ('periapsis_ticket_attribution_owner'),
      ('periapsis_ticket_sla_projection_owner')
  ),
  expected_schema_acl(
    schema_name, owner_name, grantee_name, privilege_type, is_grantable
  ) AS (
    VALUES
      ('app', 'periapsis_migrator', 'periapsis_migrator', 'CREATE', false),
      ('app', 'periapsis_migrator', 'periapsis_migrator', 'USAGE', false),
      ('public', 'periapsis_migrator', 'periapsis_migrator', 'CREATE', false),
      ('public', 'periapsis_migrator', 'periapsis_migrator', 'USAGE', false),
      ('public', 'periapsis_migrator', 'PUBLIC', 'USAGE', false)
    UNION ALL
    SELECT 'app', 'periapsis_migrator', role_name, 'USAGE', false
    FROM expected_schema_usage_role
    UNION ALL
    SELECT 'public', 'periapsis_migrator', role_name, 'USAGE', false
    FROM expected_schema_usage_role
  ),
  actual_schema_acl(
    schema_name, owner_name, grantee_name, privilege_type, is_grantable
  ) AS (
    SELECT namespace.nspname,
           owner.rolname,
           CASE schema_acl.grantee
             WHEN 0 THEN 'PUBLIC'
             ELSE grantee.rolname::text
           END,
           schema_acl.privilege_type,
           schema_acl.is_grantable
    FROM pg_catalog.pg_namespace AS namespace
    JOIN pg_catalog.pg_roles AS owner
      ON owner.oid = namespace.nspowner
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      coalesce(
        namespace.nspacl,
        pg_catalog.acldefault('n', namespace.nspowner)
      )
    ) AS schema_acl
    LEFT JOIN pg_catalog.pg_roles AS grantee
      ON grantee.oid = schema_acl.grantee
    WHERE namespace.nspname IN ('app', 'public')
  ),
  protected_schema_principal(
    role_name, may_create_app, may_create_public
  ) AS (
    SELECT role_name, false, false
    FROM expected_schema_usage_role
    UNION ALL
    SELECT 'periapsis_migrator', true, true
    UNION ALL
    SELECT role.rolname, false, false
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname IN (
      'periapsis_api_login',
      'periapsis_worker_login',
      'periapsis_notifier_login',
      'periapsis_auditor_login'
    )
  ),
  schema_acl_mismatch AS (
    (SELECT * FROM expected_schema_acl
     EXCEPT
     SELECT * FROM actual_schema_acl)
    UNION ALL
    (SELECT * FROM actual_schema_acl
     EXCEPT
     SELECT * FROM expected_schema_acl)
  ),
  schema_effective_create_mismatch AS (
    SELECT principal.role_name
    FROM protected_schema_principal AS principal
    WHERE has_schema_privilege(
            principal.role_name, 'public', 'CREATE'
          ) IS DISTINCT FROM principal.may_create_public
       OR has_schema_privilege(
            principal.role_name, 'app', 'CREATE'
          ) IS DISTINCT FROM principal.may_create_app
  ),
  database_effective_create_mismatch AS (
    SELECT principal.role_name
    FROM protected_schema_principal AS principal
    WHERE has_database_privilege(
            principal.role_name, current_database(), 'CREATE'
          ) IS DISTINCT FROM false
  )
  SELECT (SELECT count(*)::integer FROM schema_acl_mismatch),
         (SELECT count(*)::integer FROM schema_effective_create_mismatch),
         (SELECT count(*)::integer FROM database_effective_create_mismatch)
  INTO schema_acl_mismatch_count, schema_effective_create_mismatch_count,
       database_effective_create_mismatch_count;

  WITH expected_default_acl(
    owner_name, schema_name, object_type, grantee_name,
    privilege_type, is_grantable
  ) AS (
    VALUES (
      'periapsis_migrator', '<global>', 'f',
      'periapsis_migrator', 'EXECUTE', false
    )
  ),
  actual_default_acl(
    owner_name, schema_name, object_type, grantee_name,
    privilege_type, is_grantable
  ) AS (
    SELECT owner.rolname,
           coalesce(namespace.nspname, '<global>'),
           default_acl.defaclobjtype::text,
           CASE acl.grantee
             WHEN 0 THEN 'PUBLIC'
             ELSE grantee.rolname::text
           END,
           acl.privilege_type,
           acl.is_grantable
    FROM pg_catalog.pg_default_acl AS default_acl
    JOIN pg_catalog.pg_roles AS owner
      ON owner.oid = default_acl.defaclrole
    LEFT JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = default_acl.defaclnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(default_acl.defaclacl) AS acl
    LEFT JOIN pg_catalog.pg_roles AS grantee
      ON grantee.oid = acl.grantee
    WHERE owner.rolname = 'periapsis_migrator'
  )
  SELECT count(*)::integer INTO default_acl_mismatch_count
  FROM (
    (SELECT * FROM expected_default_acl
     EXCEPT
     SELECT * FROM actual_default_acl)
    UNION ALL
    (SELECT * FROM actual_default_acl
     EXCEPT
     SELECT * FROM expected_default_acl)
  ) AS mismatch;

  SELECT count(*)::integer INTO default_acl_row_count
  FROM pg_catalog.pg_default_acl AS default_acl
  JOIN pg_catalog.pg_roles AS owner
    ON owner.oid = default_acl.defaclrole
  WHERE owner.rolname = 'periapsis_migrator';

  SELECT count(*)::integer INTO provider_kind_type_count
  FROM pg_catalog.pg_type AS provider_kind
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = provider_kind.typnamespace
  JOIN pg_catalog.pg_roles AS owner
    ON owner.oid = provider_kind.typowner
  JOIN pg_catalog.pg_type AS array_type
    ON array_type.oid = provider_kind.typarray
  JOIN pg_catalog.pg_roles AS array_owner
    ON array_owner.oid = array_type.typowner
  WHERE namespace.nspname = 'public'
    AND provider_kind.typname = 'auth_provider_kind'
    AND provider_kind.typtype = 'e'
    AND provider_kind.typcategory = 'E'
    AND NOT provider_kind.typispreferred
    AND provider_kind.typdelim = ','
    AND provider_kind.typrelid = 0
    AND provider_kind.typelem = 0
    AND NOT provider_kind.typnotnull
    AND provider_kind.typbasetype = 0
    AND provider_kind.typtypmod = -1
    AND provider_kind.typndims = 0
    AND provider_kind.typcollation = 0
    AND owner.rolname = 'periapsis_migrator'
    AND array_type.typname = '_auth_provider_kind'
    AND array_type.typelem = provider_kind.oid
    AND array_owner.rolname = 'periapsis_migrator';

  WITH expected_provider_kind_acl(
    grantee_name, privilege_type, is_grantable
  ) AS (
    VALUES
      ('PUBLIC', 'USAGE', false),
      ('periapsis_migrator', 'USAGE', false)
  ),
  actual_provider_kind_acl(
    grantee_name, privilege_type, is_grantable
  ) AS (
    SELECT CASE type_acl.grantee
             WHEN 0 THEN 'PUBLIC'
             ELSE grantee.rolname::text
           END,
           type_acl.privilege_type,
           type_acl.is_grantable
    FROM pg_catalog.pg_type AS provider_kind
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = provider_kind.typnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      coalesce(
        provider_kind.typacl,
        pg_catalog.acldefault('T', provider_kind.typowner)
      )
    ) AS type_acl
    LEFT JOIN pg_catalog.pg_roles AS grantee
      ON grantee.oid = type_acl.grantee
    WHERE namespace.nspname = 'public'
      AND provider_kind.typname = 'auth_provider_kind'
  )
  SELECT count(*)::integer INTO provider_kind_acl_mismatch_count
  FROM (
    (SELECT * FROM expected_provider_kind_acl
     EXCEPT
     SELECT * FROM actual_provider_kind_acl)
    UNION ALL
    (SELECT * FROM actual_provider_kind_acl
     EXCEPT
     SELECT * FROM expected_provider_kind_acl)
  ) AS mismatch;

  WITH expected_provider_kind_enum(enum_label, sort_order) AS (
    VALUES
      ('ldap', 1::real),
      ('oidc', 2::real),
      ('saml', 3::real)
  ),
  actual_provider_kind_enum(enum_label, sort_order) AS (
    SELECT enum.enumlabel::text, enum.enumsortorder
    FROM pg_catalog.pg_enum AS enum
    JOIN pg_catalog.pg_type AS provider_kind
      ON provider_kind.oid = enum.enumtypid
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = provider_kind.typnamespace
    WHERE namespace.nspname = 'public'
      AND provider_kind.typname = 'auth_provider_kind'
  )
  SELECT count(*)::integer INTO provider_kind_enum_mismatch_count
  FROM (
    (SELECT * FROM expected_provider_kind_enum
     EXCEPT
     SELECT * FROM actual_provider_kind_enum)
    UNION ALL
    (SELECT * FROM actual_provider_kind_enum
     EXCEPT
     SELECT * FROM expected_provider_kind_enum)
  ) AS mismatch;

  SELECT count(*)::integer INTO protected_table_count
  FROM pg_catalog.pg_class AS table_row
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = table_row.relnamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = table_row.relowner
  WHERE namespace.nspname = 'public'
    AND table_row.relname = ANY (ARRAY[
      'platform_auth_providers',
      'platform_federated_provider_policies',
      'platform_federated_trust_rules',
      'platform_identity_provider_commands',
      'platform_identity_provider_test_runs',
      'platform_oidc_claim_rules',
      'platform_oidc_client_secrets',
      'platform_oidc_discovery_snapshots',
      'platform_oidc_jwks_snapshots',
      'platform_oidc_provider_configurations',
      'platform_saml_attribute_rules',
      'platform_saml_metadata_snapshots',
      'platform_saml_provider_configurations',
      'platform_saml_sp_certificates',
      'platform_saml_sp_keys'
    ]::name[])
    AND table_row.relkind = 'r'
    AND table_row.relpersistence = 'p'
    AND table_row.relreplident = 'd'
    AND NOT table_row.relispartition
    AND table_row.relpartbound IS NULL
    AND table_row.reloptions IS NULL
    AND table_row.relam = (
      SELECT access_method.oid
      FROM pg_catalog.pg_am AS access_method
      WHERE access_method.amname = 'heap'
    )
    AND table_row.relrowsecurity
    AND table_row.relforcerowsecurity
    AND owner.rolname = 'periapsis_migrator';

  SELECT count(*)::integer INTO protected_trigger_count
  FROM pg_catalog.pg_trigger AS trigger
  JOIN pg_catalog.pg_class AS table_row
    ON table_row.oid = trigger.tgrelid
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = table_row.relnamespace
  WHERE namespace.nspname = 'public'
    AND table_row.relname = ANY (ARRAY[
      'platform_auth_providers',
      'platform_federated_provider_policies',
      'platform_federated_trust_rules',
      'platform_identity_provider_commands',
      'platform_identity_provider_test_runs',
      'platform_oidc_claim_rules',
      'platform_oidc_client_secrets',
      'platform_oidc_discovery_snapshots',
      'platform_oidc_jwks_snapshots',
      'platform_oidc_provider_configurations',
      'platform_saml_attribute_rules',
      'platform_saml_metadata_snapshots',
      'platform_saml_provider_configurations',
      'platform_saml_sp_certificates',
      'platform_saml_sp_keys'
    ]::name[])
    AND NOT trigger.tgisinternal;

  SELECT count(*)::integer INTO protected_rule_count
  FROM pg_catalog.pg_rewrite AS rule
  JOIN pg_catalog.pg_class AS table_row
    ON table_row.oid = rule.ev_class
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = table_row.relnamespace
  WHERE namespace.nspname = 'public'
    AND table_row.relname = ANY (ARRAY[
      'platform_auth_providers',
      'platform_federated_provider_policies',
      'platform_federated_trust_rules',
      'platform_identity_provider_commands',
      'platform_identity_provider_test_runs',
      'platform_oidc_claim_rules',
      'platform_oidc_client_secrets',
      'platform_oidc_discovery_snapshots',
      'platform_oidc_jwks_snapshots',
      'platform_oidc_provider_configurations',
      'platform_saml_attribute_rules',
      'platform_saml_metadata_snapshots',
      'platform_saml_provider_configurations',
      'platform_saml_sp_certificates',
      'platform_saml_sp_keys'
    ]::name[])
    AND rule.rulename <> '_RETURN';

  SELECT count(*)::integer INTO protected_policy_count
  FROM pg_catalog.pg_policy AS policy
  JOIN pg_catalog.pg_class AS table_row
    ON table_row.oid = policy.polrelid
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = table_row.relnamespace
  WHERE namespace.nspname = 'public'
    AND table_row.relname = ANY (ARRAY[
      'platform_auth_providers',
      'platform_federated_provider_policies',
      'platform_federated_trust_rules',
      'platform_identity_provider_commands',
      'platform_identity_provider_test_runs',
      'platform_oidc_claim_rules',
      'platform_oidc_client_secrets',
      'platform_oidc_discovery_snapshots',
      'platform_oidc_jwks_snapshots',
      'platform_oidc_provider_configurations',
      'platform_saml_attribute_rules',
      'platform_saml_metadata_snapshots',
      'platform_saml_provider_configurations',
      'platform_saml_sp_certificates',
      'platform_saml_sp_keys'
    ]::name[]);

  SELECT count(*)::integer INTO protected_inheritance_count
  FROM pg_catalog.pg_inherits AS inheritance
  JOIN pg_catalog.pg_class AS child
    ON child.oid = inheritance.inhrelid
  JOIN pg_catalog.pg_namespace AS child_namespace
    ON child_namespace.oid = child.relnamespace
  JOIN pg_catalog.pg_class AS parent
    ON parent.oid = inheritance.inhparent
  JOIN pg_catalog.pg_namespace AS parent_namespace
    ON parent_namespace.oid = parent.relnamespace
  WHERE (
    child_namespace.nspname = 'public'
    AND child.relname = ANY (ARRAY[
      'platform_auth_providers',
      'platform_federated_provider_policies',
      'platform_federated_trust_rules',
      'platform_identity_provider_commands',
      'platform_identity_provider_test_runs',
      'platform_oidc_claim_rules',
      'platform_oidc_client_secrets',
      'platform_oidc_discovery_snapshots',
      'platform_oidc_jwks_snapshots',
      'platform_oidc_provider_configurations',
      'platform_saml_attribute_rules',
      'platform_saml_metadata_snapshots',
      'platform_saml_provider_configurations',
      'platform_saml_sp_certificates',
      'platform_saml_sp_keys'
    ]::name[])
  ) OR (
    parent_namespace.nspname = 'public'
    AND parent.relname = ANY (ARRAY[
      'platform_auth_providers',
      'platform_federated_provider_policies',
      'platform_federated_trust_rules',
      'platform_identity_provider_commands',
      'platform_identity_provider_test_runs',
      'platform_oidc_claim_rules',
      'platform_oidc_client_secrets',
      'platform_oidc_discovery_snapshots',
      'platform_oidc_jwks_snapshots',
      'platform_oidc_provider_configurations',
      'platform_saml_attribute_rules',
      'platform_saml_metadata_snapshots',
      'platform_saml_provider_configurations',
      'platform_saml_sp_certificates',
      'platform_saml_sp_keys'
    ]::name[])
  );

  SELECT count(*)::integer INTO protected_toast_mismatch_count
  FROM pg_catalog.pg_class AS table_row
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = table_row.relnamespace
  LEFT JOIN pg_catalog.pg_class AS toast_row
    ON toast_row.oid = table_row.reltoastrelid
  LEFT JOIN pg_catalog.pg_roles AS toast_owner
    ON toast_owner.oid = toast_row.relowner
  WHERE namespace.nspname = 'public'
    AND table_row.relname = ANY (ARRAY[
      'platform_auth_providers',
      'platform_federated_provider_policies',
      'platform_federated_trust_rules',
      'platform_identity_provider_commands',
      'platform_identity_provider_test_runs',
      'platform_oidc_claim_rules',
      'platform_oidc_client_secrets',
      'platform_oidc_discovery_snapshots',
      'platform_oidc_jwks_snapshots',
      'platform_oidc_provider_configurations',
      'platform_saml_attribute_rules',
      'platform_saml_metadata_snapshots',
      'platform_saml_provider_configurations',
      'platform_saml_sp_certificates',
      'platform_saml_sp_keys'
    ]::name[])
    AND (
      toast_row.oid IS NULL
      OR toast_row.relkind <> 't'
      OR toast_row.relpersistence <> 'p'
      OR toast_row.reloptions IS NOT NULL
      OR toast_owner.rolname <> 'periapsis_migrator'
    );

  -- No application-defined operator or cast participates in this slice. This
  -- blocks operator/cast shadowing even if a privileged principal mutates the
  -- catalog between deployment checks.
  SELECT count(*)::integer INTO custom_operator_count
  FROM pg_catalog.pg_operator AS operator
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = operator.oprnamespace
  WHERE namespace.nspname IN ('app', 'public');

  SELECT count(*)::integer INTO provider_cast_count
  FROM pg_catalog.pg_cast AS cast_row
  JOIN pg_catalog.pg_type AS source_type
    ON source_type.oid = cast_row.castsource
  JOIN pg_catalog.pg_namespace AS source_namespace
    ON source_namespace.oid = source_type.typnamespace
  JOIN pg_catalog.pg_type AS target_type
    ON target_type.oid = cast_row.casttarget
  JOIN pg_catalog.pg_namespace AS target_namespace
    ON target_namespace.oid = target_type.typnamespace
  WHERE source_namespace.nspname IN ('app', 'public')
     OR target_namespace.nspname IN ('app', 'public');

  SELECT count(*)::integer INTO protected_function_count
  FROM pg_catalog.pg_proc AS function
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = function.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
  WHERE namespace.nspname = 'app'
    AND function.proname = ANY (ARRAY[
      'list_platform_auth_providers_v1',
      'get_platform_auth_provider_v1',
      'create_platform_auth_provider_v1',
      'update_platform_auth_provider_v1',
      'archive_platform_auth_provider_v1',
      'replace_platform_oidc_client_secret_v1'
    ]::name[])
    AND function.prosecdef
    AND function.provolatile = 'v'
    AND owner.rolname = 'periapsis_migrator'
    AND function.proconfig IS NOT DISTINCT FROM
      ARRAY['search_path=pg_catalog, app']::text[];

  SELECT count(*)::integer INTO private_function_count
  FROM pg_catalog.pg_proc AS function
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = function.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
  WHERE namespace.nspname = 'app'
    AND function.proname = 'private_require_platform_identity_permission_v1'
    AND function.prosecdef
    AND function.provolatile = 'v'
    AND owner.rolname = 'periapsis_migrator'
    AND function.proconfig IS NOT DISTINCT FROM
      ARRAY['search_path=pg_catalog, app']::text[];

  SELECT pg_catalog.pg_get_functiondef(
    'app.private_require_platform_identity_permission_v1(uuid,text,text)'::regprocedure
  ) INTO permission_function_definition;

  SELECT count(*)::integer INTO private_projection_function_count
  FROM pg_catalog.pg_proc AS function
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = function.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
  WHERE namespace.nspname = 'app'
    AND function.proname = 'private_platform_auth_provider_document_v1'
    AND function.prosecdef
    AND function.provolatile = 's'
    AND owner.rolname = 'periapsis_migrator'
    AND function.proconfig IS NOT DISTINCT FROM
      ARRAY['search_path=pg_catalog, app']::text[];

  SELECT count(*)::integer INTO private_validator_function_count
  FROM pg_catalog.pg_proc AS function
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = function.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
  WHERE namespace.nspname = 'app'
    AND function.proname = ANY (ARRAY[
      'private_platform_identity_text_is_safe_v1',
      'private_platform_identity_uri_is_canonical_v1'
    ]::name[])
    AND NOT function.prosecdef
    AND function.provolatile = 'i'
    AND owner.rolname = 'periapsis_migrator'
    AND function.proconfig IS NOT DISTINCT FROM
      ARRAY['search_path=pg_catalog, app']::text[];

  SELECT count(*)::integer INTO keyring_function_count
  FROM pg_catalog.pg_proc AS function
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = function.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
  WHERE function.oid =
      'app.verify_identity_keyring_v3(integer[],bytea[],integer)'::regprocedure
    AND namespace.nspname = 'app'
    AND function.prosecdef
    AND function.provolatile = 'v'
    AND owner.rolname = 'periapsis_migrator'
    AND function.proconfig IS NOT DISTINCT FROM
      ARRAY['search_path=pg_catalog, app']::text[];

  SELECT count(*)::integer INTO runtime_surface_function_count
  FROM pg_catalog.pg_proc AS function
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = function.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
  JOIN pg_catalog.pg_language AS language
    ON language.oid = function.prolang
  WHERE function.oid =
      'app.private_runtime_accessible_surface_hash_v1()'::regprocedure
    AND namespace.nspname = 'app'
    AND owner.rolname = 'periapsis_migrator'
    AND language.lanname = 'sql'
    AND function.prokind = 'f'
    AND function.provolatile = 's'
    AND function.prosecdef
    AND NOT function.proisstrict
    AND NOT function.proleakproof
    AND function.proparallel = 'u'
    AND function.pronargs = 0
    AND function.proconfig IS NOT DISTINCT FROM
      ARRAY['search_path=pg_catalog, app']::text[]
    AND pg_catalog.pg_get_function_result(function.oid) = 'text'
    AND (
      SELECT count(*) = 1
         AND coalesce(bool_and(
           function_acl.grantee = function.proowner
           AND function_acl.privilege_type = 'EXECUTE'
           AND NOT function_acl.is_grantable
         ), false)
      FROM pg_catalog.aclexplode(
        coalesce(
          function.proacl,
          pg_catalog.acldefault('f', function.proowner)
        )
      ) AS function_acl
    );

  SELECT app.private_runtime_accessible_surface_hash_v1()
  INTO runtime_accessible_surface_hash;

  binding_extension_function_present := to_regprocedure(
    'app.tenant_platform_identity_binding_schema_readiness_v2()'
  ) IS NOT NULL;
  IF predecessor_count = 0 AND binding_extension_function_present THEN
    EXECUTE
      'SELECT app.tenant_platform_identity_binding_schema_readiness_v2()'
    INTO binding_extension_ready;
  END IF;
  rolling_catalog_state_ready := (
    predecessor_count = 155
    AND protected_trigger_count = 0
    AND runtime_accessible_surface_hash =
      '764fb60e6903f76c4978c521509cd061b9f714103f15fb26c886659be2a6f799'
    AND NOT binding_extension_function_present
  ) OR (
    predecessor_count = 0
    AND protected_trigger_count = 1
    AND runtime_accessible_surface_hash =
      '1499f4b4a551afc3d0845735970dafb0c445fdb135867ef7b0a7df595950f710'
    AND binding_extension_function_present
    AND binding_extension_ready
  );

  -- Catalog attributes alone do not attest SECURITY DEFINER behavior. Seal
  -- every entrypoint and transitive authorization, validation, keyring, and
  -- platform-audit dependency that this slice executes.
  WITH expected_trusted_function(signature, definition_sha256) AS (
    VALUES
      ('app.append_platform_audit_event(uuid,public.audit_actor_type,uuid,text,text,uuid,uuid,uuid,inet,text,text,public.audit_outcome,text,jsonb)', 'edbcc957f075ad76277d0ebf8e66c3fe368ba611ac1b1cf4d5009f2c3bc92b35'),
      ('app.archive_platform_auth_provider_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)', '6eae4dfd3209bff488a1d0f2ada1dd7091580ca3efd87e99e3b5e5e2c69c4e53'),
      ('app.audit_json_document_safe_v1(jsonb,integer,boolean)', '9cfa2575214970c6243f5becf41073f20baa74d8978a909775c95773c9e30b3d'),
      ('app.audit_json_key_value_safe_v1(text,jsonb)', 'c562f65b713527d9dc2783de6511cc3248a8a531c52227bdf8333cb1c287652b'),
      ('app.calculate_platform_audit_event_hash(public.platform_audit_events,character)', '48fa8803541bc42fa222c130e0f09d4b801636e6166a2e83e10902d9f5bc8a59'),
      ('app.context_user_id()', 'c714898ced7fadc8ad5338c9f788a23ab235e77fc75fd98240494c858565714a'),
      ('app.create_platform_auth_provider_v1(uuid,uuid,uuid,public.auth_provider_kind,text,text,text,jsonb,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)', 'c0f3d134967414821412ce88a953ba949b5bd0d890216815bbc9edc2ec3477a6'),
      ('app.get_platform_auth_provider_v1(uuid,uuid,text)', '28eda3f21931b47cfcb5b84f81043ed78b277230f5fa64a8c184004c9b22d6db'),
      ('app.guard_audit_json_documents_v1()', '78545f1e03ac356a9411d7437e3d09736c5becb273c56216f8d21ec405e96643'),
      ('app.list_platform_auth_providers_v1(uuid,text,uuid,integer,boolean)', '13f0d8637daa0412d19a65314f504b9e89abe57f405ed141ef5da23ab417ea5b'),
      ('app.platform_audit_event_payload(public.platform_audit_events)', 'd8cfd44697a9697467c75cbfd6296f576310ecf0c404c3ee250d0013afdaec04'),
      ('app.platform_user_has_permission(uuid,text)', 'ff9cb0904659f9ed73c4a639e9156c586bf8c9f3ed04f7f2fe9b68a533e48239'),
      ('app.private_platform_audit_reason_is_safe_v1(text)', '417139518df0ecd2cc33e1389c0ed9c310cd4795dd0c537e55cc7eec1f5b8779'),
      ('app.private_platform_auth_provider_document_v1(uuid)', 'd2ba18abee04df21eb1cb5601f71ae43d7e398d22f1bc05a23f6e659ebc5523f'),
      ('app.private_platform_identity_text_is_safe_v1(text,boolean)', '4b5f71ad170e7468e83836fc6e48b712541a00154c7ca3cc27b3d1366ded1b38'),
      ('app.private_platform_identity_uri_is_canonical_v1(text,boolean,boolean,integer)', '23097a89561718b3d3d8e2b89c0ea8cf2d8f9bbc045d644f35f2c346979f8da6'),
      ('app.private_platform_lifecycle_reason_is_valid_v1(text)', '15fdcd6289230e46404cc7da5e6c95a5501977ebb47bd68c55125ddd48cf9979'),
      ('app.private_require_platform_identity_permission_v1(uuid,text,text)', '19ae43a1b444eaca2b6ec94e21f8b790d3c61683e3dcac69c6eee8d9fb2cf08e'),
      ('app.private_runtime_accessible_surface_hash_v1()', '2b33d560d29651dd2c9f2a538f0675f13327486ff0ffce1200504ec88fc71137'),
      ('app.reject_platform_audit_event_mutation()', '0bbae020d52d8cc8237178790c5d5336a2eff6dfe284202f6b3d2560cca064ae'),
      ('app.replace_platform_oidc_client_secret_v1(uuid,uuid,uuid,bigint,integer,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)', '1754f565f4dd593eb7394d74af2b2019b13a2fa0e836fc68c028b6d985f0db03'),
      ('app.seal_platform_audit_event()', '91fb962dafb67e82f98b2db610f42f95d3713cee81c5820cf3a4d4aa48530b51'),
      ('app.update_platform_auth_provider_v1(uuid,uuid,bigint,text,text,text,uuid,uuid,uuid,inet,text,text,text)', '15f15e670bb28a50372caa36e07274b7e1994b77744e2f6b4fb4593f081b3b29'),
      ('app.verify_identity_keyring_v1(integer[],bytea[],integer)', '8b2701d9f8084b7231b3d08a011bbb1a8811702176b724ac8e9772774d7ee86e'),
      ('app.verify_identity_keyring_v2(integer[],bytea[],integer)', 'e50e7ebe212990fa853303b28ed718dd0e28a4ce0e07415b48b198388d917165'),
      ('app.verify_identity_keyring_v3(integer[],bytea[],integer)', '16fac37f3436b9e6ed430c4390308baed755409244fe98d6cca1f35ef0ae8f40')
  )
  SELECT count(*)::integer
  INTO trusted_function_definition_mismatch_count
  FROM expected_trusted_function AS expected
  LEFT JOIN pg_catalog.pg_proc AS function
    ON function.oid = pg_catalog.to_regprocedure(expected.signature)
  WHERE CASE
          WHEN function.oid IS NULL THEN NULL
          ELSE encode(
            sha256(convert_to(pg_get_functiondef(function.oid), 'UTF8')),
            'hex'
          )
        END IS DISTINCT FROM expected.definition_sha256;

  WITH expected_platform_audit_trigger(
    trigger_name, enabled_state, definition_sha256
  ) AS (
    VALUES
      ('platform_audit_events_json_documents_guard_v1', 'O', '777027ca72601a55f14081759d70315ea3c3a6941baaa9b0b6c7d6ce3c56f015'),
      ('platform_audit_events_reject_update_delete', 'O', 'd9fabf6113e9a5dd2aade2944f6dcc4763be509bb754a3462a0d3726ab9701fb'),
      ('platform_audit_events_seal_before_insert', 'O', 'f7d7862b857a1aae79cc51d968669190ca1517a8cf83576c961e2f2f542fab41')
  ),
  actual_platform_audit_trigger(
    trigger_name, enabled_state, definition_sha256
  ) AS (
    SELECT trigger.tgname::text,
           trigger.tgenabled::text,
           encode(
             sha256(convert_to(pg_get_triggerdef(trigger.oid, true), 'UTF8')),
             'hex'
           )
    FROM pg_catalog.pg_trigger AS trigger
    WHERE trigger.tgrelid = 'public.platform_audit_events'::regclass
      AND NOT trigger.tgisinternal
  )
  SELECT count(*)::integer INTO platform_audit_trigger_mismatch_count
  FROM (
    (SELECT * FROM expected_platform_audit_trigger
     EXCEPT
     SELECT * FROM actual_platform_audit_trigger)
    UNION ALL
    (SELECT * FROM actual_platform_audit_trigger
     EXCEPT
     SELECT * FROM expected_platform_audit_trigger)
  ) AS mismatch;

  SELECT count(*)::integer INTO protected_acl_mismatch_count
  FROM (VALUES
    ('app.list_platform_auth_providers_v1(uuid,text,uuid,integer,boolean)'::regprocedure),
    ('app.get_platform_auth_provider_v1(uuid,uuid,text)'::regprocedure),
    ('app.create_platform_auth_provider_v1(uuid,uuid,uuid,public.auth_provider_kind,text,text,text,jsonb,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'::regprocedure),
    ('app.update_platform_auth_provider_v1(uuid,uuid,bigint,text,text,text,uuid,uuid,uuid,inet,text,text,text)'::regprocedure),
    ('app.archive_platform_auth_provider_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)'::regprocedure),
    ('app.replace_platform_oidc_client_secret_v1(uuid,uuid,uuid,bigint,integer,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'::regprocedure)
  ) AS protected_function(signature)
  CROSS JOIN (VALUES
    ('periapsis_api', true),
    ('periapsis_worker', false),
    ('periapsis_notifier', false),
    ('periapsis_auditor', false),
    ('periapsis_audit_reader_owner', false),
    ('periapsis_notification_dispatch_owner', false),
    ('periapsis_sla_api_owner', false),
    ('periapsis_sla_worker_owner', false),
    ('periapsis_sla_readiness_owner', false),
    ('periapsis_ticket_saved_view_owner', false),
    ('periapsis_ticket_attribution_owner', false),
    ('periapsis_ticket_sla_projection_owner', false)
  ) AS runtime_role(role_name, expected_execute)
  WHERE has_function_privilege(
    runtime_role.role_name, protected_function.signature, 'EXECUTE'
  ) IS DISTINCT FROM runtime_role.expected_execute;

  SELECT count(*)::integer INTO private_acl_mismatch_count
  FROM (VALUES
    ('app.private_require_platform_identity_permission_v1(uuid,text,text)'::regprocedure),
    ('app.private_platform_auth_provider_document_v1(uuid)'::regprocedure),
    ('app.private_platform_identity_text_is_safe_v1(text,boolean)'::regprocedure),
    ('app.private_platform_identity_uri_is_canonical_v1(text,boolean,boolean,integer)'::regprocedure),
    ('app.private_runtime_accessible_surface_hash_v1()'::regprocedure)
  ) AS private_function(signature)
  CROSS JOIN (VALUES
    ('periapsis_api'), ('periapsis_worker'), ('periapsis_notifier'),
    ('periapsis_auditor'), ('periapsis_audit_reader_owner'),
    ('periapsis_notification_dispatch_owner'), ('periapsis_sla_api_owner'),
    ('periapsis_sla_worker_owner'), ('periapsis_sla_readiness_owner'),
    ('periapsis_ticket_saved_view_owner'),
    ('periapsis_ticket_attribution_owner'),
    ('periapsis_ticket_sla_projection_owner')
  ) AS runtime_role(role_name)
  WHERE has_function_privilege(
    runtime_role.role_name, private_function.signature, 'EXECUTE'
  );

  SELECT count(*)::integer INTO keyring_acl_mismatch_count
  FROM pg_catalog.pg_proc AS function
  CROSS JOIN LATERAL pg_catalog.aclexplode(
    coalesce(
      function.proacl,
      pg_catalog.acldefault('f', function.proowner)
    )
  ) AS function_acl
  WHERE function.oid =
      'app.verify_identity_keyring_v3(integer[],bytea[],integer)'::regprocedure
    AND (
      function_acl.privilege_type <> 'EXECUTE'
      OR function_acl.grantee NOT IN (
        function.proowner,
        (SELECT role.oid FROM pg_catalog.pg_roles AS role
         WHERE role.rolname = 'periapsis_api'),
        (SELECT role.oid FROM pg_catalog.pg_roles AS role
         WHERE role.rolname = 'periapsis_worker')
      )
      OR (
        function_acl.grantee IN (
          (SELECT role.oid FROM pg_catalog.pg_roles AS role
           WHERE role.rolname = 'periapsis_api'),
          (SELECT role.oid FROM pg_catalog.pg_roles AS role
           WHERE role.rolname = 'periapsis_worker')
        )
        AND function_acl.is_grantable
      )
    );

  SELECT count(*)::integer INTO keyring_runtime_acl_mismatch_count
  FROM (VALUES
    ('periapsis_api', true),
    ('periapsis_worker', true),
    ('periapsis_notifier', false),
    ('periapsis_auditor', false),
    ('periapsis_audit_reader_owner', false),
    ('periapsis_notification_dispatch_owner', false),
    ('periapsis_sla_api_owner', false),
    ('periapsis_sla_worker_owner', false),
    ('periapsis_sla_readiness_owner', false),
    ('periapsis_ticket_saved_view_owner', false),
    ('periapsis_ticket_attribution_owner', false),
    ('periapsis_ticket_sla_projection_owner', false)
  ) AS runtime_role(role_name, expected_execute)
  WHERE has_function_privilege(
    runtime_role.role_name,
    'app.verify_identity_keyring_v3(integer[],bytea[],integer)'::regprocedure,
    'EXECUTE'
  ) IS DISTINCT FROM runtime_role.expected_execute;

  SELECT count(*)::integer INTO keyring_acl_entry_count
  FROM pg_catalog.pg_proc AS function
  CROSS JOIN LATERAL pg_catalog.aclexplode(
    coalesce(
      function.proacl,
      pg_catalog.acldefault('f', function.proowner)
    )
  ) AS function_acl
  WHERE function.oid =
      'app.verify_identity_keyring_v3(integer[],bytea[],integer)'::regprocedure
    AND function_acl.privilege_type = 'EXECUTE'
    AND (
      function_acl.grantee = function.proowner
      OR (
        function_acl.grantee IN (
          (SELECT role.oid FROM pg_catalog.pg_roles AS role
           WHERE role.rolname = 'periapsis_api'),
          (SELECT role.oid FROM pg_catalog.pg_roles AS role
           WHERE role.rolname = 'periapsis_worker')
        )
        AND NOT function_acl.is_grantable
      )
    );

  SELECT count(*)::integer INTO legacy_keyring_acl_mismatch_count
  FROM (
    SELECT 1
    FROM (VALUES
      ('app.verify_identity_keyring_v1(integer[],bytea[],integer)'::regprocedure),
      ('app.verify_identity_keyring_v2(integer[],bytea[],integer)'::regprocedure)
    ) AS legacy_verifier(signature)
    JOIN pg_catalog.pg_proc AS function
      ON function.oid = legacy_verifier.signature
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      coalesce(
        function.proacl,
        pg_catalog.acldefault('f', function.proowner)
      )
    ) AS function_acl
    WHERE function_acl.privilege_type <> 'EXECUTE'
       OR function_acl.grantee <> function.proowner
       OR function_acl.is_grantable
    UNION ALL
    SELECT 1
    FROM (VALUES
      ('app.verify_identity_keyring_v1(integer[],bytea[],integer)'::regprocedure),
      ('app.verify_identity_keyring_v2(integer[],bytea[],integer)'::regprocedure)
    ) AS legacy_verifier(signature)
    CROSS JOIN (VALUES
      ('periapsis_api'), ('periapsis_worker'), ('periapsis_notifier'),
      ('periapsis_auditor'), ('periapsis_audit_reader_owner'),
      ('periapsis_notification_dispatch_owner'), ('periapsis_sla_api_owner'),
      ('periapsis_sla_worker_owner'), ('periapsis_sla_readiness_owner'),
      ('periapsis_ticket_saved_view_owner'),
      ('periapsis_ticket_attribution_owner'),
      ('periapsis_ticket_sla_projection_owner')
    ) AS runtime_role(role_name)
    WHERE has_function_privilege(
      runtime_role.role_name, legacy_verifier.signature, 'EXECUTE'
    )
    UNION ALL
    SELECT 1
    FROM (VALUES
      ('app.verify_identity_keyring_v1(integer[],bytea[],integer)'::regprocedure),
      ('app.verify_identity_keyring_v2(integer[],bytea[],integer)'::regprocedure)
    ) AS legacy_verifier(signature)
    WHERE NOT has_function_privilege(
      'periapsis_migrator', legacy_verifier.signature, 'EXECUTE'
    )
  ) AS legacy_keyring_mismatch;

  -- Compare a closed manifest in both directions: missing, changed, and
  -- unexpected catalog entries all make readiness fail.
  WITH expected_catalog_column_base(
    table_name, column_name, data_type, is_not_null
  ) AS (
    VALUES
      ('platform_auth_providers', 'archive_reason', 'text', false),
      ('platform_auth_providers', 'archived_at', 'timestamp with time zone', false),
      ('platform_auth_providers', 'archived_by_user_id', 'uuid', false),
      ('platform_auth_providers', 'created_at', 'timestamp with time zone', true),
      ('platform_auth_providers', 'created_by_user_id', 'uuid', true),
      ('platform_auth_providers', 'description', 'text', true),
      ('platform_auth_providers', 'display_name', 'text', true),
      ('platform_auth_providers', 'enabled', 'boolean', true),
      ('platform_auth_providers', 'id', 'uuid', true),
      ('platform_auth_providers', 'key', 'text', true),
      ('platform_auth_providers', 'kind', 'auth_provider_kind', true),
      ('platform_auth_providers', 'updated_at', 'timestamp with time zone', true),
      ('platform_auth_providers', 'updated_by_user_id', 'uuid', true),
      ('platform_auth_providers', 'version', 'bigint', true),
      ('platform_federated_provider_policies', 'account_mode', 'text', true),
      ('platform_federated_provider_policies', 'assurance_policy_revision', 'bigint', true),
      ('platform_federated_provider_policies', 'configuration_revision', 'bigint', true),
      ('platform_federated_provider_policies', 'created_at', 'timestamp with time zone', true),
      ('platform_federated_provider_policies', 'enabled', 'boolean', true),
      ('platform_federated_provider_policies', 'plan_revision', 'bigint', true),
      ('platform_federated_provider_policies', 'platform_login_enabled', 'boolean', true),
      ('platform_federated_provider_policies', 'provider_id', 'uuid', true),
      ('platform_federated_provider_policies', 'provider_kind', 'auth_provider_kind', true),
      ('platform_federated_provider_policies', 'security_revision', 'bigint', true),
      ('platform_federated_provider_policies', 'updated_at', 'timestamp with time zone', true),
      ('platform_federated_trust_rules', 'created_at', 'timestamp with time zone', true),
      ('platform_federated_trust_rules', 'enabled', 'boolean', true),
      ('platform_federated_trust_rules', 'exact_value', 'text', false),
      ('platform_federated_trust_rules', 'id', 'uuid', true),
      ('platform_federated_trust_rules', 'level', 'text', true),
      ('platform_federated_trust_rules', 'maximum_authentication_age_seconds', 'integer', true),
      ('platform_federated_trust_rules', 'provider_id', 'uuid', true),
      ('platform_federated_trust_rules', 'provider_kind', 'auth_provider_kind', true),
      ('platform_federated_trust_rules', 'required_values', 'text[]', true),
      ('platform_federated_trust_rules', 'retired_at', 'timestamp with time zone', false),
      ('platform_federated_trust_rules', 'revision', 'bigint', true),
      ('platform_identity_provider_commands', 'actor_user_id', 'uuid', true),
      ('platform_identity_provider_commands', 'created_at', 'timestamp with time zone', true),
      ('platform_identity_provider_commands', 'expires_at', 'timestamp with time zone', true),
      ('platform_identity_provider_commands', 'id', 'uuid', true),
      ('platform_identity_provider_commands', 'key_digest', 'bytea', true),
      ('platform_identity_provider_commands', 'operation', 'text', true),
      ('platform_identity_provider_commands', 'request_digest', 'bytea', true),
      ('platform_identity_provider_commands', 'result_provider_id', 'uuid', true),
      ('platform_identity_provider_commands', 'result_version', 'bigint', true),
      ('platform_identity_provider_test_runs', 'actor_user_id', 'uuid', true),
      ('platform_identity_provider_test_runs', 'category', 'text', false),
      ('platform_identity_provider_test_runs', 'completed_at', 'timestamp with time zone', false),
      ('platform_identity_provider_test_runs', 'configuration_revision', 'bigint', true),
      ('platform_identity_provider_test_runs', 'correlation_id', 'uuid', true),
      ('platform_identity_provider_test_runs', 'id', 'uuid', true),
      ('platform_identity_provider_test_runs', 'kind', 'text', true),
      ('platform_identity_provider_test_runs', 'outcome', 'text', false),
      ('platform_identity_provider_test_runs', 'provider_id', 'uuid', true),
      ('platform_identity_provider_test_runs', 'provider_version', 'bigint', true),
      ('platform_identity_provider_test_runs', 'started_at', 'timestamp with time zone', true),
      ('platform_identity_provider_test_runs', 'status', 'text', true),
      ('platform_oidc_claim_rules', 'claim_name', 'text', true),
      ('platform_oidc_claim_rules', 'kind', 'text', true),
      ('platform_oidc_claim_rules', 'profile_field', 'text', false),
      ('platform_oidc_claim_rules', 'provider_id', 'uuid', true),
      ('platform_oidc_claim_rules', 'required', 'boolean', true),
      ('platform_oidc_claim_rules', 'sequence', 'integer', true),
      ('platform_oidc_claim_rules', 'source', 'text', true),
      ('platform_oidc_client_secrets', 'ciphertext', 'bytea', true),
      ('platform_oidc_client_secrets', 'created_at', 'timestamp with time zone', true),
      ('platform_oidc_client_secrets', 'id', 'uuid', true),
      ('platform_oidc_client_secrets', 'key_version', 'integer', true),
      ('platform_oidc_client_secrets', 'nonce', 'bytea', true),
      ('platform_oidc_client_secrets', 'provider_id', 'uuid', true),
      ('platform_oidc_client_secrets', 'retired_at', 'timestamp with time zone', false),
      ('platform_oidc_client_secrets', 'revision', 'bigint', true),
      ('platform_oidc_discovery_snapshots', 'cacheable', 'boolean', true),
      ('platform_oidc_discovery_snapshots', 'client_authentication', 'text', true),
      ('platform_oidc_discovery_snapshots', 'document', 'bytea', true),
      ('platform_oidc_discovery_snapshots', 'document_digest', 'bytea', true),
      ('platform_oidc_discovery_snapshots', 'fresh_until', 'timestamp with time zone', true),
      ('platform_oidc_discovery_snapshots', 'issuer', 'text', true),
      ('platform_oidc_discovery_snapshots', 'must_revalidate', 'boolean', true),
      ('platform_oidc_discovery_snapshots', 'provider_id', 'uuid', true),
      ('platform_oidc_discovery_snapshots', 'retrieved_at', 'timestamp with time zone', true),
      ('platform_oidc_discovery_snapshots', 'revision', 'bigint', true),
      ('platform_oidc_discovery_snapshots', 'signing_algorithms', 'text[]', true),
      ('platform_oidc_jwks_snapshots', 'cacheable', 'boolean', true),
      ('platform_oidc_jwks_snapshots', 'document', 'bytea', true),
      ('platform_oidc_jwks_snapshots', 'document_digest', 'bytea', true),
      ('platform_oidc_jwks_snapshots', 'fresh_until', 'timestamp with time zone', true),
      ('platform_oidc_jwks_snapshots', 'must_revalidate', 'boolean', true),
      ('platform_oidc_jwks_snapshots', 'provider_id', 'uuid', true),
      ('platform_oidc_jwks_snapshots', 'retrieved_at', 'timestamp with time zone', true),
      ('platform_oidc_jwks_snapshots', 'revision', 'bigint', true),
      ('platform_oidc_provider_configurations', 'allow_refresh_token', 'boolean', true),
      ('platform_oidc_provider_configurations', 'client_id', 'text', true),
      ('platform_oidc_provider_configurations', 'client_secret_revision', 'bigint', true),
      ('platform_oidc_provider_configurations', 'created_at', 'timestamp with time zone', true),
      ('platform_oidc_provider_configurations', 'discovery_revision', 'bigint', true),
      ('platform_oidc_provider_configurations', 'extra_scopes', 'text[]', true),
      ('platform_oidc_provider_configurations', 'issuer', 'text', true),
      ('platform_oidc_provider_configurations', 'jwks_revision', 'bigint', true),
      ('platform_oidc_provider_configurations', 'post_logout_redirect_uri', 'text', true),
      ('platform_oidc_provider_configurations', 'provider_id', 'uuid', true),
      ('platform_oidc_provider_configurations', 'provider_kind', 'auth_provider_kind', true),
      ('platform_oidc_provider_configurations', 'redirect_uri', 'text', true),
      ('platform_oidc_provider_configurations', 'updated_at', 'timestamp with time zone', true),
      ('platform_oidc_provider_configurations', 'use_user_info', 'boolean', true),
      ('platform_oidc_provider_configurations', 'version', 'bigint', true),
      ('platform_saml_attribute_rules', 'attribute_name', 'text', true),
      ('platform_saml_attribute_rules', 'attribute_name_format', 'text', true),
      ('platform_saml_attribute_rules', 'kind', 'text', true),
      ('platform_saml_attribute_rules', 'profile_field', 'text', false),
      ('platform_saml_attribute_rules', 'provider_id', 'uuid', true),
      ('platform_saml_attribute_rules', 'required', 'boolean', true),
      ('platform_saml_attribute_rules', 'sequence', 'integer', true),
      ('platform_saml_metadata_snapshots', 'document', 'bytea', true),
      ('platform_saml_metadata_snapshots', 'document_digest', 'bytea', true),
      ('platform_saml_metadata_snapshots', 'maximum_valid_until', 'timestamp with time zone', true),
      ('platform_saml_metadata_snapshots', 'provider_id', 'uuid', true),
      ('platform_saml_metadata_snapshots', 'retrieved_at', 'timestamp with time zone', true),
      ('platform_saml_metadata_snapshots', 'revision', 'bigint', true),
      ('platform_saml_provider_configurations', 'acs_url', 'text', true),
      ('platform_saml_provider_configurations', 'clock_skew_nanoseconds', 'bigint', true),
      ('platform_saml_provider_configurations', 'created_at', 'timestamp with time zone', true),
      ('platform_saml_provider_configurations', 'decryption_key_versions', 'integer[]', true),
      ('platform_saml_provider_configurations', 'encryption_policy', 'text', true),
      ('platform_saml_provider_configurations', 'expected_entity_id', 'text', true),
      ('platform_saml_provider_configurations', 'max_authentication_age_nanoseconds', 'bigint', true),
      ('platform_saml_provider_configurations', 'metadata_revision', 'bigint', true),
      ('platform_saml_provider_configurations', 'provider_id', 'uuid', true),
      ('platform_saml_provider_configurations', 'provider_kind', 'auth_provider_kind', true),
      ('platform_saml_provider_configurations', 'redirect_signature_algorithm', 'text', true),
      ('platform_saml_provider_configurations', 'requested_authn_contexts', 'text[]', true),
      ('platform_saml_provider_configurations', 'signature_policy', 'text', true),
      ('platform_saml_provider_configurations', 'sp_entity_id', 'text', true),
      ('platform_saml_provider_configurations', 'sp_key_revision', 'bigint', true),
      ('platform_saml_provider_configurations', 'subject_attribute_name', 'text', false),
      ('platform_saml_provider_configurations', 'subject_attribute_name_format', 'text', false),
      ('platform_saml_provider_configurations', 'subject_source', 'text', true),
      ('platform_saml_provider_configurations', 'updated_at', 'timestamp with time zone', true),
      ('platform_saml_provider_configurations', 'version', 'bigint', true),
      ('platform_saml_sp_certificates', 'certificate_der', 'bytea', true),
      ('platform_saml_sp_certificates', 'key_id', 'uuid', true),
      ('platform_saml_sp_certificates', 'sequence', 'integer', true),
      ('platform_saml_sp_keys', 'ciphertext', 'bytea', true),
      ('platform_saml_sp_keys', 'created_at', 'timestamp with time zone', true),
      ('platform_saml_sp_keys', 'id', 'uuid', true),
      ('platform_saml_sp_keys', 'key_version', 'integer', true),
      ('platform_saml_sp_keys', 'provider_id', 'uuid', true),
      ('platform_saml_sp_keys', 'retired_at', 'timestamp with time zone', false),
      ('platform_saml_sp_keys', 'revision', 'bigint', true)
  ),
  expected_catalog_column_default(
    table_name, column_name, default_expression
  ) AS (
    VALUES
      ('platform_auth_providers', 'created_at', 'now()'),
      ('platform_auth_providers', 'description', $default$''::text$default$),
      ('platform_auth_providers', 'enabled', 'false'),
      ('platform_auth_providers', 'id', 'uuidv7()'),
      ('platform_auth_providers', 'updated_at', 'now()'),
      ('platform_auth_providers', 'version', '1'),
      ('platform_federated_provider_policies', 'account_mode', $default$'disabled'::text$default$),
      ('platform_federated_provider_policies', 'created_at', 'now()'),
      ('platform_federated_provider_policies', 'enabled', 'false'),
      ('platform_federated_provider_policies', 'platform_login_enabled', 'false'),
      ('platform_federated_provider_policies', 'updated_at', 'now()'),
      ('platform_federated_trust_rules', 'created_at', 'now()'),
      ('platform_federated_trust_rules', 'enabled', 'false'),
      ('platform_federated_trust_rules', 'id', 'uuidv7()'),
      ('platform_federated_trust_rules', 'required_values', 'ARRAY[]::text[]'),
      ('platform_identity_provider_commands', 'created_at', 'now()'),
      ('platform_identity_provider_commands', 'expires_at', $default$now() + '24:00:00'::interval$default$),
      ('platform_identity_provider_commands', 'id', 'uuidv7()'),
      ('platform_identity_provider_test_runs', 'id', 'uuidv7()'),
      ('platform_identity_provider_test_runs', 'started_at', 'now()'),
      ('platform_oidc_claim_rules', 'required', 'false'),
      ('platform_oidc_client_secrets', 'created_at', 'now()'),
      ('platform_oidc_client_secrets', 'id', 'uuidv7()'),
      ('platform_oidc_provider_configurations', 'allow_refresh_token', 'false'),
      ('platform_oidc_provider_configurations', 'created_at', 'now()'),
      ('platform_oidc_provider_configurations', 'extra_scopes', 'ARRAY[]::text[]'),
      ('platform_oidc_provider_configurations', 'provider_kind', $default$'oidc'::auth_provider_kind$default$),
      ('platform_oidc_provider_configurations', 'updated_at', 'now()'),
      ('platform_oidc_provider_configurations', 'use_user_info', 'false'),
      ('platform_oidc_provider_configurations', 'version', '1'),
      ('platform_saml_attribute_rules', 'required', 'false'),
      ('platform_saml_provider_configurations', 'created_at', 'now()'),
      ('platform_saml_provider_configurations', 'provider_kind', $default$'saml'::auth_provider_kind$default$),
      ('platform_saml_provider_configurations', 'updated_at', 'now()'),
      ('platform_saml_provider_configurations', 'version', '1'),
      ('platform_saml_sp_keys', 'created_at', 'now()'),
      ('platform_saml_sp_keys', 'id', 'uuidv7()')
  ),
  expected_catalog_column(
    table_name, column_name, data_type, is_not_null, default_expression,
    uses_type_collation, uses_type_storage, uses_default_compression,
    identity_kind, generated_kind, declared_dimensions,
    inheritance_count, is_local
  ) AS (
    SELECT base.table_name,
           base.column_name,
           base.data_type,
           base.is_not_null,
           expected_default.default_expression,
           true,
           true,
           true,
           ''::text,
           ''::text,
           CASE WHEN base.data_type LIKE '%[]' THEN 1 ELSE 0 END,
           0,
           true
    FROM expected_catalog_column_base AS base
    LEFT JOIN expected_catalog_column_default AS expected_default
      ON expected_default.table_name = base.table_name
     AND expected_default.column_name = base.column_name
  ),
  actual_catalog_column(
    table_name, column_name, data_type, is_not_null, default_expression,
    uses_type_collation, uses_type_storage, uses_default_compression,
    identity_kind, generated_kind, declared_dimensions,
    inheritance_count, is_local
  ) AS (
    SELECT table_row.relname::text,
           column_row.attname::text,
           pg_catalog.replace(
             pg_catalog.format_type(
               column_row.atttypid, column_row.atttypmod
             ),
             'public.',
             ''
           ),
           column_row.attnotnull,
           pg_catalog.replace(
             pg_catalog.pg_get_expr(
               default_row.adbin, default_row.adrelid, true
             ),
             'public.',
             ''
           ),
           column_row.attcollation = column_type.typcollation,
           column_row.attstorage = column_type.typstorage,
           column_row.attcompression = ''::"char",
           column_row.attidentity::text,
           column_row.attgenerated::text,
           column_row.attndims,
           column_row.attinhcount,
           column_row.attislocal
    FROM pg_catalog.pg_class AS table_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = table_row.relnamespace
    JOIN pg_catalog.pg_attribute AS column_row
      ON column_row.attrelid = table_row.oid
    JOIN pg_catalog.pg_type AS column_type
      ON column_type.oid = column_row.atttypid
    LEFT JOIN pg_catalog.pg_attrdef AS default_row
      ON default_row.adrelid = table_row.oid
     AND default_row.adnum = column_row.attnum
    JOIN (
      SELECT DISTINCT expected.table_name
      FROM expected_catalog_column AS expected
    ) AS expected_table ON expected_table.table_name = table_row.relname
    WHERE namespace.nspname = 'public'
      AND table_row.relkind = 'r'
      AND column_row.attnum > 0
      AND NOT column_row.attisdropped
  )
  SELECT count(*)::integer INTO catalog_column_mismatch_count
  FROM (
    (
      SELECT * FROM expected_catalog_column
      EXCEPT
      SELECT * FROM actual_catalog_column
    )
    UNION ALL
    (
      SELECT * FROM actual_catalog_column
      EXCEPT
      SELECT * FROM expected_catalog_column
    )
  ) AS catalog_column_mismatch;

  WITH expected_catalog_constraint(
    table_name, constraint_name, constraint_type, definition
  ) AS (
    VALUES
      ('platform_auth_providers', 'platform_auth_providers_archive_check', 'c', 'CHECK (archived_at IS NULL AND archived_by_user_id IS NULL AND archive_reason IS NULL OR archived_at IS NOT NULL AND archived_by_user_id IS NOT NULL AND archive_reason IS NOT NULL AND NOT enabled AND archived_at >= created_at AND archive_reason = btrim(archive_reason) AND archive_reason <> ''''::text AND octet_length(convert_to(archive_reason, ''UTF8''::name)) <= 2048 AND archive_reason !~ ''[[:cntrl:]]''::text)'),
      ('platform_auth_providers', 'platform_auth_providers_archived_by_user_id_users_id_fk', 'f', 'FOREIGN KEY (archived_by_user_id) REFERENCES users(id) ON DELETE RESTRICT'),
      ('platform_auth_providers', 'platform_auth_providers_created_by_user_id_users_id_fk', 'f', 'FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT'),
      ('platform_auth_providers', 'platform_auth_providers_description_check', 'c', 'CHECK (description = btrim(description) AND char_length(description) <= 1000 AND description !~ ''[[:cntrl:]]''::text)'),
      ('platform_auth_providers', 'platform_auth_providers_display_name_check', 'c', 'CHECK (display_name = btrim(display_name) AND display_name <> ''''::text AND char_length(display_name) <= 120 AND display_name !~ ''[[:cntrl:]]''::text)'),
      ('platform_auth_providers', 'platform_auth_providers_id_kind_key', 'u', 'UNIQUE (id, kind)'),
      ('platform_auth_providers', 'platform_auth_providers_id_uuidv7_check', 'c', 'CHECK ((uuid_extract_version(id) = 7) IS TRUE)'),
      ('platform_auth_providers', 'platform_auth_providers_key_check', 'c', 'CHECK (key = lower(btrim(key)) AND key ~ ''^[a-z][a-z0-9_-]{2,63}$''::text)'),
      ('platform_auth_providers', 'platform_auth_providers_key_key', 'u', 'UNIQUE (key)'),
      ('platform_auth_providers', 'platform_auth_providers_kind_check', 'c', 'CHECK (kind = ANY (ARRAY[''oidc''::auth_provider_kind, ''saml''::auth_provider_kind]))'),
      ('platform_auth_providers', 'platform_auth_providers_lifecycle_check', 'c', 'CHECK (version >= 1 AND version <= 2147483647 AND isfinite(created_at) AND isfinite(updated_at) AND EXTRACT(year FROM (created_at AT TIME ZONE ''UTC''::text)) >= 1970::numeric AND EXTRACT(year FROM (created_at AT TIME ZONE ''UTC''::text)) <= 9999::numeric AND EXTRACT(year FROM (updated_at AT TIME ZONE ''UTC''::text)) >= 1970::numeric AND EXTRACT(year FROM (updated_at AT TIME ZONE ''UTC''::text)) <= 9999::numeric AND updated_at >= created_at AND (archived_at IS NULL OR isfinite(archived_at) AND EXTRACT(year FROM (archived_at AT TIME ZONE ''UTC''::text)) >= 1970::numeric AND EXTRACT(year FROM (archived_at AT TIME ZONE ''UTC''::text)) <= 9999::numeric AND updated_at >= archived_at))'),
      ('platform_auth_providers', 'platform_auth_providers_pkey', 'p', 'PRIMARY KEY (id)'),
      ('platform_auth_providers', 'platform_auth_providers_updated_by_user_id_users_id_fk', 'f', 'FOREIGN KEY (updated_by_user_id) REFERENCES users(id) ON DELETE RESTRICT'),
      ('platform_federated_provider_policies', 'platform_federated_provider_policies_account_check', 'c', 'CHECK (account_mode = ANY (ARRAY[''disabled''::text, ''existing_identity''::text, ''create''::text]))'),
      ('platform_federated_provider_policies', 'platform_federated_provider_policies_kind_check', 'c', 'CHECK (provider_kind = ANY (ARRAY[''oidc''::auth_provider_kind, ''saml''::auth_provider_kind]))'),
      ('platform_federated_provider_policies', 'platform_federated_provider_policies_kind_key', 'u', 'UNIQUE (provider_id, provider_kind)'),
      ('platform_federated_provider_policies', 'platform_federated_provider_policies_login_check', 'c', 'CHECK (NOT platform_login_enabled OR enabled)'),
      ('platform_federated_provider_policies', 'platform_federated_provider_policies_pkey', 'p', 'PRIMARY KEY (provider_id)'),
      ('platform_federated_provider_policies', 'platform_federated_provider_policies_provider_fk', 'f', 'FOREIGN KEY (provider_id, provider_kind) REFERENCES platform_auth_providers(id, kind) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('platform_federated_provider_policies', 'platform_federated_provider_policies_revision_check', 'c', 'CHECK (configuration_revision >= 1 AND configuration_revision <= ''9007199254740991''::bigint AND security_revision >= 1 AND security_revision <= ''9007199254740991''::bigint AND plan_revision >= 1 AND plan_revision <= ''9007199254740991''::bigint AND assurance_policy_revision >= 1 AND assurance_policy_revision <= ''9007199254740991''::bigint)'),
      ('platform_federated_provider_policies', 'platform_federated_provider_policies_timestamp_check', 'c', 'CHECK (updated_at >= created_at)'),
      ('platform_federated_trust_rules', 'platform_federated_trust_rules_id_uuidv7_check', 'c', 'CHECK ((uuid_extract_version(id) = 7) IS TRUE)'),
      ('platform_federated_trust_rules', 'platform_federated_trust_rules_pkey', 'p', 'PRIMARY KEY (id, revision)'),
      ('platform_federated_trust_rules', 'platform_federated_trust_rules_policy_fk', 'f', 'FOREIGN KEY (provider_id, provider_kind) REFERENCES platform_federated_provider_policies(provider_id, provider_kind) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('platform_federated_trust_rules', 'platform_federated_trust_rules_retirement_check', 'c', 'CHECK (retired_at IS NULL OR retired_at >= created_at)'),
      ('platform_federated_trust_rules', 'platform_federated_trust_rules_value_check', 'c', 'CHECK ((provider_kind = ANY (ARRAY[''oidc''::auth_provider_kind, ''saml''::auth_provider_kind])) AND revision >= 1 AND revision <= ''9007199254740991''::bigint AND (level = ANY (ARRAY[''mfa''::text, ''phishing_resistant''::text])) AND maximum_authentication_age_seconds >= 60 AND maximum_authentication_age_seconds <= 2592000 AND cardinality(required_values) <= 128 AND array_position(required_values, NULL::text) IS NULL AND (provider_kind = ''oidc''::auth_provider_kind AND (exact_value IS NOT NULL OR cardinality(required_values) > 0) OR provider_kind = ''saml''::auth_provider_kind AND exact_value IS NOT NULL AND cardinality(required_values) = 0))'),
      ('platform_identity_provider_commands', 'platform_identity_provider_commands_actor_user_id_users_id_fk', 'f', 'FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT'),
      ('platform_identity_provider_commands', 'platform_identity_provider_commands_digest_check', 'c', 'CHECK (octet_length(key_digest) = 32 AND octet_length(request_digest) = 32)'),
      ('platform_identity_provider_commands', 'platform_identity_provider_commands_id_uuidv7_check', 'c', 'CHECK ((uuid_extract_version(id) = 7) IS TRUE)'),
      ('platform_identity_provider_commands', 'platform_identity_provider_commands_operation_check', 'c', 'CHECK (operation = ''provider.create''::text)'),
      ('platform_identity_provider_commands', 'platform_identity_provider_commands_pkey', 'p', 'PRIMARY KEY (id)'),
      ('platform_identity_provider_commands', 'platform_identity_provider_commands_replay_key', 'u', 'UNIQUE (actor_user_id, operation, key_digest)'),
      ('platform_identity_provider_commands', 'platform_identity_provider_commands_result_check', 'c', 'CHECK (result_version = 1)'),
      ('platform_identity_provider_commands', 'platform_identity_provider_commands_result_provider_id_platform', 'f', 'FOREIGN KEY (result_provider_id) REFERENCES platform_auth_providers(id) ON DELETE RESTRICT'),
      ('platform_identity_provider_commands', 'platform_identity_provider_commands_retention_check', 'c', 'CHECK (expires_at > created_at AND expires_at <= (created_at + ''7 days''::interval))'),
      ('platform_identity_provider_test_runs', 'platform_identity_provider_test_runs_actor_user_id_users_id_fk', 'f', 'FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT'),
      ('platform_identity_provider_test_runs', 'platform_identity_provider_test_runs_correlation_key', 'u', 'UNIQUE (correlation_id)'),
      ('platform_identity_provider_test_runs', 'platform_identity_provider_test_runs_id_uuidv7_check', 'c', 'CHECK ((uuid_extract_version(id) = 7) IS TRUE)'),
      ('platform_identity_provider_test_runs', 'platform_identity_provider_test_runs_pkey', 'p', 'PRIMARY KEY (id)'),
      ('platform_identity_provider_test_runs', 'platform_identity_provider_test_runs_provider_id_platform_auth_', 'f', 'FOREIGN KEY (provider_id) REFERENCES platform_auth_providers(id) ON DELETE RESTRICT'),
      ('platform_identity_provider_test_runs', 'platform_identity_provider_test_runs_revision_check', 'c', 'CHECK (provider_version >= 1 AND provider_version <= 2147483647 AND configuration_revision >= 1 AND configuration_revision <= ''9007199254740991''::bigint)'),
      ('platform_identity_provider_test_runs', 'platform_identity_provider_test_runs_value_check', 'c', 'CHECK (((kind = ANY (ARRAY[''configuration''::text, ''connection''::text, ''trust''::text])) AND (status = ANY (ARRAY[''running''::text, ''completed''::text])) AND (status = ''running''::text AND outcome IS NULL AND category IS NULL AND completed_at IS NULL OR status = ''completed''::text AND outcome IS NOT NULL AND category IS NOT NULL AND (outcome = ANY (ARRAY[''success''::text, ''failure''::text, ''inconclusive''::text])) AND (category = ANY (ARRAY[''success''::text, ''cancelled''::text, ''configuration_invalid''::text, ''destination_blocked''::text, ''dns_failed''::text, ''connect_failed''::text, ''connect_timeout''::text, ''tls_failed''::text, ''discovery_unreachable''::text, ''issuer_mismatch''::text, ''jwks_invalid''::text, ''metadata_invalid''::text, ''certificate_expired''::text, ''stale_configuration''::text, ''protocol_failed''::text])) AND (outcome = ''success''::text AND category = ''success''::text OR outcome = ''inconclusive''::text AND category = ''stale_configuration''::text OR outcome = ''failure''::text AND (category <> ALL (ARRAY[''success''::text, ''stale_configuration''::text]))) AND completed_at >= started_at)) IS TRUE)'),
      ('platform_oidc_claim_rules', 'platform_oidc_claim_rules_claim_key', 'u', 'UNIQUE (provider_id, source, claim_name)'),
      ('platform_oidc_claim_rules', 'platform_oidc_claim_rules_configuration_fk', 'f', 'FOREIGN KEY (provider_id) REFERENCES platform_oidc_provider_configurations(provider_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('platform_oidc_claim_rules', 'platform_oidc_claim_rules_pkey', 'p', 'PRIMARY KEY (provider_id, source, sequence)'),
      ('platform_oidc_claim_rules', 'platform_oidc_claim_rules_value_check', 'c', E'CHECK ((source = ANY (ARRAY[''id_token''::text, ''userinfo''::text])) AND sequence >= 0 AND sequence <= 1023 AND (kind = ANY (ARRAY[''scalar''::text, ''profile''::text, ''groups''::text, ''acr''::text, ''amr''::text])) AND char_length(claim_name) >= 1 AND char_length(claim_name) <= 256 AND claim_name ~ ''^[!-~]+$''::text AND claim_name !~ ''["\\\\]''::text AND (kind = ''profile''::text AND profile_field IS NOT NULL AND (profile_field = ANY (ARRAY[''username''::text, ''email''::text, ''display_name''::text])) OR kind <> ''profile''::text AND profile_field IS NULL) AND ((kind <> ALL (ARRAY[''acr''::text, ''amr''::text])) OR claim_name = kind AND NOT required))'),
      ('platform_oidc_client_secrets', 'platform_oidc_client_secrets_configuration_fk', 'f', 'FOREIGN KEY (provider_id) REFERENCES platform_oidc_provider_configurations(provider_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('platform_oidc_client_secrets', 'platform_oidc_client_secrets_envelope_check', 'c', 'CHECK (revision >= 1 AND revision <= ''9007199254740991''::bigint AND key_version >= 1 AND key_version <= 32767 AND octet_length(nonce) = 12 AND octet_length(ciphertext) >= 17 AND octet_length(ciphertext) <= 8208)'),
      ('platform_oidc_client_secrets', 'platform_oidc_client_secrets_id_uuidv7_check', 'c', 'CHECK ((uuid_extract_version(id) = 7) IS TRUE)'),
      ('platform_oidc_client_secrets', 'platform_oidc_client_secrets_keyring_fk', 'f', 'FOREIGN KEY (key_version) REFERENCES identity_keyring_versions(key_version) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('platform_oidc_client_secrets', 'platform_oidc_client_secrets_pkey', 'p', 'PRIMARY KEY (id)'),
      ('platform_oidc_client_secrets', 'platform_oidc_client_secrets_retirement_check', 'c', 'CHECK (retired_at IS NULL OR retired_at >= created_at)'),
      ('platform_oidc_client_secrets', 'platform_oidc_client_secrets_revision_key', 'u', 'UNIQUE (provider_id, revision)'),
      ('platform_oidc_discovery_snapshots', 'platform_oidc_discovery_snapshots_configuration_fk', 'f', 'FOREIGN KEY (provider_id) REFERENCES platform_oidc_provider_configurations(provider_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('platform_oidc_discovery_snapshots', 'platform_oidc_discovery_snapshots_pkey', 'p', 'PRIMARY KEY (provider_id, revision)'),
      ('platform_oidc_discovery_snapshots', 'platform_oidc_discovery_snapshots_value_check', 'c', 'CHECK (revision >= 1 AND revision <= ''9007199254740991''::bigint AND octet_length(document) >= 2 AND octet_length(document) <= 1048576 AND octet_length(document_digest) = 32 AND fresh_until >= retrieved_at AND fresh_until <= (retrieved_at + ''7 days''::interval) AND (cacheable OR must_revalidate AND fresh_until = retrieved_at) AND (client_authentication = ANY (ARRAY[''client_secret_basic''::text, ''client_secret_post''::text])) AND cardinality(signing_algorithms) >= 1 AND cardinality(signing_algorithms) <= 16 AND array_position(signing_algorithms, NULL::text) IS NULL)'),
      ('platform_oidc_jwks_snapshots', 'platform_oidc_jwks_snapshots_configuration_fk', 'f', 'FOREIGN KEY (provider_id) REFERENCES platform_oidc_provider_configurations(provider_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('platform_oidc_jwks_snapshots', 'platform_oidc_jwks_snapshots_pkey', 'p', 'PRIMARY KEY (provider_id, revision)'),
      ('platform_oidc_jwks_snapshots', 'platform_oidc_jwks_snapshots_value_check', 'c', 'CHECK (revision >= 1 AND revision <= ''9007199254740991''::bigint AND octet_length(document) >= 2 AND octet_length(document) <= 1048576 AND octet_length(document_digest) = 32 AND fresh_until >= retrieved_at AND fresh_until <= (retrieved_at + ''7 days''::interval) AND (cacheable OR must_revalidate AND fresh_until = retrieved_at))'),
      ('platform_oidc_provider_configurations', 'platform_oidc_provider_configurations_kind_check', 'c', 'CHECK (provider_kind = ''oidc''::auth_provider_kind)'),
      ('platform_oidc_provider_configurations', 'platform_oidc_provider_configurations_pkey', 'p', 'PRIMARY KEY (provider_id)'),
      ('platform_oidc_provider_configurations', 'platform_oidc_provider_configurations_provider_fk', 'f', 'FOREIGN KEY (provider_id, provider_kind) REFERENCES platform_auth_providers(id, kind) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('platform_oidc_provider_configurations', 'platform_oidc_provider_configurations_revision_check', 'c', 'CHECK (client_secret_revision >= 1 AND client_secret_revision <= ''9007199254740991''::bigint AND discovery_revision >= 1 AND discovery_revision <= ''9007199254740991''::bigint AND jwks_revision >= 1 AND jwks_revision <= ''9007199254740991''::bigint AND version >= 1 AND version <= ''9007199254740991''::bigint)'),
      ('platform_oidc_provider_configurations', 'platform_oidc_provider_configurations_scope_check', 'c', 'CHECK (cardinality(extra_scopes) <= 32 AND array_position(extra_scopes, NULL::text) IS NULL AND array_position(extra_scopes, ''openid''::text) IS NULL AND array_to_string(extra_scopes, '' ''::text) ~ ''^$|^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}( [A-Za-z0-9][A-Za-z0-9._:/-]{0,127})*$''::text)'),
      ('platform_oidc_provider_configurations', 'platform_oidc_provider_configurations_text_check', 'c', 'CHECK (issuer = btrim(issuer) AND issuer ~ ''^https://[^/?#@]+[^#?]*$''::text AND char_length(issuer) >= 1 AND char_length(issuer) <= 4096 AND octet_length(convert_to(client_id, ''UTF8''::name)) >= 1 AND octet_length(convert_to(client_id, ''UTF8''::name)) <= 512 AND client_id = btrim(client_id) AND redirect_uri ~ ''^https://[^/?#@]+''::text AND post_logout_redirect_uri ~ ''^https://[^/?#@]+''::text AND char_length(redirect_uri) >= 1 AND char_length(redirect_uri) <= 4096 AND char_length(post_logout_redirect_uri) >= 1 AND char_length(post_logout_redirect_uri) <= 4096 AND issuer !~ ''[[:cntrl:]]''::text AND client_id !~ ''[[:cntrl:]]''::text AND redirect_uri !~ ''[[:cntrl:]]''::text AND post_logout_redirect_uri !~ ''[[:cntrl:]]''::text)'),
      ('platform_oidc_provider_configurations', 'platform_oidc_provider_configurations_timestamp_check', 'c', 'CHECK (updated_at >= created_at)'),
      ('platform_saml_attribute_rules', 'platform_saml_attribute_rules_configuration_fk', 'f', 'FOREIGN KEY (provider_id) REFERENCES platform_saml_provider_configurations(provider_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('platform_saml_attribute_rules', 'platform_saml_attribute_rules_pkey', 'p', 'PRIMARY KEY (provider_id, sequence)'),
      ('platform_saml_attribute_rules', 'platform_saml_attribute_rules_value_check', 'c', 'CHECK (sequence >= 0 AND sequence <= 1023 AND (kind = ANY (ARRAY[''scalar''::text, ''profile''::text, ''groups''::text])) AND octet_length(convert_to(attribute_name, ''UTF8''::name)) >= 1 AND octet_length(convert_to(attribute_name, ''UTF8''::name)) <= 512 AND octet_length(convert_to(attribute_name_format, ''UTF8''::name)) >= 1 AND octet_length(convert_to(attribute_name_format, ''UTF8''::name)) <= 512 AND attribute_name !~ ''[[:cntrl:]]''::text AND attribute_name_format !~ ''[[:cntrl:]]''::text AND (kind = ''profile''::text AND profile_field IS NOT NULL AND (profile_field = ANY (ARRAY[''username''::text, ''email''::text, ''display_name''::text])) OR kind <> ''profile''::text AND profile_field IS NULL))'),
      ('platform_saml_metadata_snapshots', 'platform_saml_metadata_snapshots_configuration_fk', 'f', 'FOREIGN KEY (provider_id) REFERENCES platform_saml_provider_configurations(provider_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('platform_saml_metadata_snapshots', 'platform_saml_metadata_snapshots_pkey', 'p', 'PRIMARY KEY (provider_id, revision)'),
      ('platform_saml_metadata_snapshots', 'platform_saml_metadata_snapshots_value_check', 'c', 'CHECK (revision >= 1 AND revision <= ''9007199254740991''::bigint AND octet_length(document) >= 1 AND octet_length(document) <= 524288 AND octet_length(document_digest) = 32 AND maximum_valid_until > retrieved_at)'),
      ('platform_saml_provider_configurations', 'platform_saml_provider_configurations_kind_check', 'c', 'CHECK (provider_kind = ''saml''::auth_provider_kind)'),
      ('platform_saml_provider_configurations', 'platform_saml_provider_configurations_pkey', 'p', 'PRIMARY KEY (provider_id)'),
      ('platform_saml_provider_configurations', 'platform_saml_provider_configurations_policy_check', 'c', 'CHECK ((redirect_signature_algorithm = ANY (ARRAY[''http://www.w3.org/2001/04/xmldsig-more#rsa-sha256''::text, ''http://www.w3.org/2001/04/xmldsig-more#rsa-sha384''::text, ''http://www.w3.org/2001/04/xmldsig-more#rsa-sha512''::text, ''http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256''::text, ''http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384''::text, ''http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512''::text])) AND (signature_policy = ANY (ARRAY[''signed_assertion''::text, ''signed_response''::text, ''both''::text])) AND encryption_policy = ''disabled''::text AND cardinality(decryption_key_versions) = 0 AND array_position(decryption_key_versions, NULL::integer) IS NULL AND cardinality(requested_authn_contexts) >= 1 AND cardinality(requested_authn_contexts) <= 32 AND array_position(requested_authn_contexts, NULL::text) IS NULL AND clock_skew_nanoseconds >= 0 AND clock_skew_nanoseconds <= ''300000000000''::bigint AND max_authentication_age_nanoseconds >= ''60000000000''::bigint AND max_authentication_age_nanoseconds <= ''86400000000000''::bigint)'),
      ('platform_saml_provider_configurations', 'platform_saml_provider_configurations_provider_fk', 'f', 'FOREIGN KEY (provider_id, provider_kind) REFERENCES platform_auth_providers(id, kind) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('platform_saml_provider_configurations', 'platform_saml_provider_configurations_revision_check', 'c', 'CHECK (sp_key_revision >= 1 AND sp_key_revision <= ''9007199254740991''::bigint AND metadata_revision >= 1 AND metadata_revision <= ''9007199254740991''::bigint AND version >= 1 AND version <= ''9007199254740991''::bigint)'),
      ('platform_saml_provider_configurations', 'platform_saml_provider_configurations_subject_check', 'c', 'CHECK (subject_source = ''persistent_nameid''::text AND subject_attribute_name IS NULL AND subject_attribute_name_format IS NULL OR subject_source = ''immutable_attribute''::text AND subject_attribute_name IS NOT NULL AND subject_attribute_name_format IS NOT NULL AND octet_length(convert_to(subject_attribute_name, ''UTF8''::name)) >= 1 AND octet_length(convert_to(subject_attribute_name, ''UTF8''::name)) <= 512 AND octet_length(convert_to(subject_attribute_name_format, ''UTF8''::name)) >= 1 AND octet_length(convert_to(subject_attribute_name_format, ''UTF8''::name)) <= 512)'),
      ('platform_saml_provider_configurations', 'platform_saml_provider_configurations_text_check', 'c', 'CHECK (expected_entity_id = btrim(expected_entity_id) AND expected_entity_id ~ ''^[a-z][a-z0-9+.-]*:''::text AND sp_entity_id ~ ''^https://[^/?#@]+''::text AND acs_url ~ ''^https://[^/?#@]+''::text AND octet_length(convert_to(expected_entity_id, ''UTF8''::name)) >= 1 AND octet_length(convert_to(expected_entity_id, ''UTF8''::name)) <= 2048 AND octet_length(convert_to(sp_entity_id, ''UTF8''::name)) >= 1 AND octet_length(convert_to(sp_entity_id, ''UTF8''::name)) <= 2048 AND octet_length(convert_to(acs_url, ''UTF8''::name)) >= 1 AND octet_length(convert_to(acs_url, ''UTF8''::name)) <= 4096 AND expected_entity_id !~ ''[[:cntrl:]]''::text AND sp_entity_id !~ ''[[:cntrl:]]''::text AND acs_url !~ ''[[:cntrl:]]''::text)'),
      ('platform_saml_provider_configurations', 'platform_saml_provider_configurations_timestamp_check', 'c', 'CHECK (updated_at >= created_at)'),
      ('platform_saml_sp_certificates', 'platform_saml_sp_certificates_key_fk', 'f', 'FOREIGN KEY (key_id) REFERENCES platform_saml_sp_keys(id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('platform_saml_sp_certificates', 'platform_saml_sp_certificates_pkey', 'p', 'PRIMARY KEY (key_id, sequence)'),
      ('platform_saml_sp_certificates', 'platform_saml_sp_certificates_value_check', 'c', 'CHECK (sequence >= 0 AND sequence <= 7 AND octet_length(certificate_der) >= 1 AND octet_length(certificate_der) <= 65536)'),
      ('platform_saml_sp_certificates', 'platform_saml_sp_certificates_value_key', 'u', 'UNIQUE (key_id, certificate_der)'),
      ('platform_saml_sp_keys', 'platform_saml_sp_keys_configuration_fk', 'f', 'FOREIGN KEY (provider_id) REFERENCES platform_saml_provider_configurations(provider_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('platform_saml_sp_keys', 'platform_saml_sp_keys_envelope_check', 'c', 'CHECK (revision >= 1 AND revision <= ''9007199254740991''::bigint AND key_version >= 1 AND key_version <= 32767 AND octet_length(ciphertext) >= 17 AND octet_length(ciphertext) <= 131072)'),
      ('platform_saml_sp_keys', 'platform_saml_sp_keys_id_uuidv7_check', 'c', 'CHECK ((uuid_extract_version(id) = 7) IS TRUE)'),
      ('platform_saml_sp_keys', 'platform_saml_sp_keys_keyring_fk', 'f', 'FOREIGN KEY (key_version) REFERENCES identity_keyring_versions(key_version) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('platform_saml_sp_keys', 'platform_saml_sp_keys_pkey', 'p', 'PRIMARY KEY (id)'),
      ('platform_saml_sp_keys', 'platform_saml_sp_keys_retirement_check', 'c', 'CHECK (retired_at IS NULL OR retired_at >= created_at)'),
      ('platform_saml_sp_keys', 'platform_saml_sp_keys_revision_key', 'u', 'UNIQUE (provider_id, revision)')
  ),
  actual_catalog_constraint(
    table_name, constraint_name, constraint_type, definition
  ) AS (
    SELECT table_row.relname::text,
           constraint_row.conname::text,
           constraint_row.contype::text,
           pg_catalog.replace(
             pg_catalog.pg_get_constraintdef(constraint_row.oid, true),
             'public.',
             ''
           )
    FROM pg_catalog.pg_class AS table_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = table_row.relnamespace
    JOIN pg_catalog.pg_constraint AS constraint_row
      ON constraint_row.conrelid = table_row.oid
    JOIN (
      SELECT DISTINCT expected.table_name
      FROM expected_catalog_constraint AS expected
    ) AS expected_table ON expected_table.table_name = table_row.relname
    WHERE namespace.nspname = 'public'
      AND constraint_row.contype IN ('c', 'f', 'p', 'u')
  )
  SELECT count(*)::integer INTO catalog_constraint_mismatch_count
  FROM (
    (
      SELECT * FROM expected_catalog_constraint
      EXCEPT
      SELECT * FROM actual_catalog_constraint
    )
    UNION ALL
    (
      SELECT * FROM actual_catalog_constraint
      EXCEPT
      SELECT * FROM expected_catalog_constraint
    )
  ) AS catalog_constraint_mismatch;

  WITH expected_catalog_index(
    table_name, index_name, definition, is_unique,
    is_valid, is_ready, is_live
  ) AS (
    VALUES
      ('platform_auth_providers', 'platform_auth_providers_active_display_key', 'CREATE UNIQUE INDEX platform_auth_providers_active_display_key ON platform_auth_providers USING btree (display_name) WHERE archived_at IS NULL', true, true, true, true),
      ('platform_auth_providers', 'platform_auth_providers_id_kind_key', 'CREATE UNIQUE INDEX platform_auth_providers_id_kind_key ON platform_auth_providers USING btree (id, kind)', true, true, true, true),
      ('platform_auth_providers', 'platform_auth_providers_key_key', 'CREATE UNIQUE INDEX platform_auth_providers_key_key ON platform_auth_providers USING btree (key)', true, true, true, true),
      ('platform_auth_providers', 'platform_auth_providers_kind_idx', 'CREATE INDEX platform_auth_providers_kind_idx ON platform_auth_providers USING btree (kind, id)', false, true, true, true),
      ('platform_auth_providers', 'platform_auth_providers_pkey', 'CREATE UNIQUE INDEX platform_auth_providers_pkey ON platform_auth_providers USING btree (id)', true, true, true, true),
      ('platform_federated_provider_policies', 'platform_federated_provider_policies_kind_key', 'CREATE UNIQUE INDEX platform_federated_provider_policies_kind_key ON platform_federated_provider_policies USING btree (provider_id, provider_kind)', true, true, true, true),
      ('platform_federated_provider_policies', 'platform_federated_provider_policies_pkey', 'CREATE UNIQUE INDEX platform_federated_provider_policies_pkey ON platform_federated_provider_policies USING btree (provider_id)', true, true, true, true),
      ('platform_federated_trust_rules', 'platform_federated_trust_rules_live_key', 'CREATE UNIQUE INDEX platform_federated_trust_rules_live_key ON platform_federated_trust_rules USING btree (id) WHERE retired_at IS NULL', true, true, true, true),
      ('platform_federated_trust_rules', 'platform_federated_trust_rules_pkey', 'CREATE UNIQUE INDEX platform_federated_trust_rules_pkey ON platform_federated_trust_rules USING btree (id, revision)', true, true, true, true),
      ('platform_federated_trust_rules', 'platform_federated_trust_rules_provider_idx', 'CREATE INDEX platform_federated_trust_rules_provider_idx ON platform_federated_trust_rules USING btree (provider_id, id)', false, true, true, true),
      ('platform_identity_provider_commands', 'platform_identity_provider_commands_expiry_idx', 'CREATE INDEX platform_identity_provider_commands_expiry_idx ON platform_identity_provider_commands USING btree (expires_at)', false, true, true, true),
      ('platform_identity_provider_commands', 'platform_identity_provider_commands_pkey', 'CREATE UNIQUE INDEX platform_identity_provider_commands_pkey ON platform_identity_provider_commands USING btree (id)', true, true, true, true),
      ('platform_identity_provider_commands', 'platform_identity_provider_commands_replay_key', 'CREATE UNIQUE INDEX platform_identity_provider_commands_replay_key ON platform_identity_provider_commands USING btree (actor_user_id, operation, key_digest)', true, true, true, true),
      ('platform_identity_provider_test_runs', 'platform_identity_provider_test_runs_correlation_key', 'CREATE UNIQUE INDEX platform_identity_provider_test_runs_correlation_key ON platform_identity_provider_test_runs USING btree (correlation_id)', true, true, true, true),
      ('platform_identity_provider_test_runs', 'platform_identity_provider_test_runs_pkey', 'CREATE UNIQUE INDEX platform_identity_provider_test_runs_pkey ON platform_identity_provider_test_runs USING btree (id)', true, true, true, true),
      ('platform_identity_provider_test_runs', 'platform_identity_provider_test_runs_provider_idx', 'CREATE INDEX platform_identity_provider_test_runs_provider_idx ON platform_identity_provider_test_runs USING btree (provider_id, started_at, id)', false, true, true, true),
      ('platform_oidc_claim_rules', 'platform_oidc_claim_rules_claim_key', 'CREATE UNIQUE INDEX platform_oidc_claim_rules_claim_key ON platform_oidc_claim_rules USING btree (provider_id, source, claim_name)', true, true, true, true),
      ('platform_oidc_claim_rules', 'platform_oidc_claim_rules_pkey', 'CREATE UNIQUE INDEX platform_oidc_claim_rules_pkey ON platform_oidc_claim_rules USING btree (provider_id, source, sequence)', true, true, true, true),
      ('platform_oidc_client_secrets', 'platform_oidc_client_secrets_pkey', 'CREATE UNIQUE INDEX platform_oidc_client_secrets_pkey ON platform_oidc_client_secrets USING btree (id)', true, true, true, true),
      ('platform_oidc_client_secrets', 'platform_oidc_client_secrets_revision_key', 'CREATE UNIQUE INDEX platform_oidc_client_secrets_revision_key ON platform_oidc_client_secrets USING btree (provider_id, revision)', true, true, true, true),
      ('platform_oidc_discovery_snapshots', 'platform_oidc_discovery_snapshots_pkey', 'CREATE UNIQUE INDEX platform_oidc_discovery_snapshots_pkey ON platform_oidc_discovery_snapshots USING btree (provider_id, revision)', true, true, true, true),
      ('platform_oidc_jwks_snapshots', 'platform_oidc_jwks_snapshots_pkey', 'CREATE UNIQUE INDEX platform_oidc_jwks_snapshots_pkey ON platform_oidc_jwks_snapshots USING btree (provider_id, revision)', true, true, true, true),
      ('platform_oidc_provider_configurations', 'platform_oidc_provider_configurations_pkey', 'CREATE UNIQUE INDEX platform_oidc_provider_configurations_pkey ON platform_oidc_provider_configurations USING btree (provider_id)', true, true, true, true),
      ('platform_saml_attribute_rules', 'platform_saml_attribute_rules_pkey', 'CREATE UNIQUE INDEX platform_saml_attribute_rules_pkey ON platform_saml_attribute_rules USING btree (provider_id, sequence)', true, true, true, true),
      ('platform_saml_metadata_snapshots', 'platform_saml_metadata_snapshots_pkey', 'CREATE UNIQUE INDEX platform_saml_metadata_snapshots_pkey ON platform_saml_metadata_snapshots USING btree (provider_id, revision)', true, true, true, true),
      ('platform_saml_provider_configurations', 'platform_saml_provider_configurations_pkey', 'CREATE UNIQUE INDEX platform_saml_provider_configurations_pkey ON platform_saml_provider_configurations USING btree (provider_id)', true, true, true, true),
      ('platform_saml_sp_certificates', 'platform_saml_sp_certificates_pkey', 'CREATE UNIQUE INDEX platform_saml_sp_certificates_pkey ON platform_saml_sp_certificates USING btree (key_id, sequence)', true, true, true, true),
      ('platform_saml_sp_certificates', 'platform_saml_sp_certificates_value_key', 'CREATE UNIQUE INDEX platform_saml_sp_certificates_value_key ON platform_saml_sp_certificates USING btree (key_id, certificate_der)', true, true, true, true),
      ('platform_saml_sp_keys', 'platform_saml_sp_keys_pkey', 'CREATE UNIQUE INDEX platform_saml_sp_keys_pkey ON platform_saml_sp_keys USING btree (id)', true, true, true, true),
      ('platform_saml_sp_keys', 'platform_saml_sp_keys_revision_key', 'CREATE UNIQUE INDEX platform_saml_sp_keys_revision_key ON platform_saml_sp_keys USING btree (provider_id, revision)', true, true, true, true)
  ),
  actual_catalog_index(
    table_name, index_name, definition, is_unique,
    is_valid, is_ready, is_live
  ) AS (
    SELECT table_row.relname::text,
           index_class.relname::text,
           pg_catalog.replace(
             pg_catalog.pg_get_indexdef(index_class.oid, 0, true),
             'public.',
             ''
           ),
           index_row.indisunique,
           index_row.indisvalid,
           index_row.indisready,
           index_row.indislive
    FROM pg_catalog.pg_class AS table_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = table_row.relnamespace
    JOIN pg_catalog.pg_index AS index_row
      ON index_row.indrelid = table_row.oid
    JOIN pg_catalog.pg_class AS index_class
      ON index_class.oid = index_row.indexrelid
    JOIN (
      SELECT DISTINCT expected.table_name
      FROM expected_catalog_index AS expected
    ) AS expected_table ON expected_table.table_name = table_row.relname
    WHERE namespace.nspname = 'public'
  )
  SELECT count(*)::integer INTO catalog_index_mismatch_count
  FROM (
    (
      SELECT * FROM expected_catalog_index
      EXCEPT
      SELECT * FROM actual_catalog_index
    )
    UNION ALL
    (
      SELECT * FROM actual_catalog_index
      EXCEPT
      SELECT * FROM expected_catalog_index
    )
  ) AS catalog_index_mismatch;


  SELECT count(*)::integer INTO protected_owner_function_count
  FROM (VALUES
    ('app.list_platform_auth_providers_v1(uuid,text,uuid,integer,boolean)'::regprocedure),
    ('app.get_platform_auth_provider_v1(uuid,uuid,text)'::regprocedure),
    ('app.create_platform_auth_provider_v1(uuid,uuid,uuid,public.auth_provider_kind,text,text,text,jsonb,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'::regprocedure),
    ('app.update_platform_auth_provider_v1(uuid,uuid,bigint,text,text,text,uuid,uuid,uuid,inet,text,text,text)'::regprocedure),
    ('app.archive_platform_auth_provider_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)'::regprocedure),
    ('app.replace_platform_oidc_client_secret_v1(uuid,uuid,uuid,bigint,integer,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'::regprocedure)
  ) AS protected_function(signature)
  WHERE has_function_privilege(
    'periapsis_migrator', protected_function.signature, 'EXECUTE'
  );

  SELECT count(*)::integer INTO private_owner_function_count
  FROM (VALUES
    ('app.private_require_platform_identity_permission_v1(uuid,text,text)'::regprocedure),
    ('app.private_platform_auth_provider_document_v1(uuid)'::regprocedure),
    ('app.private_platform_identity_text_is_safe_v1(text,boolean)'::regprocedure),
    ('app.private_platform_identity_uri_is_canonical_v1(text,boolean,boolean,integer)'::regprocedure),
    ('app.private_runtime_accessible_surface_hash_v1()'::regprocedure)
  ) AS private_function(signature)
  WHERE has_function_privilege(
    'periapsis_migrator', private_function.signature, 'EXECUTE'
  );

  SELECT count(*)::integer INTO keyring_owner_function_count
  FROM (VALUES
    ('app.verify_identity_keyring_v3(integer[],bytea[],integer)'::regprocedure)
  ) AS keyring_function(signature)
  WHERE has_function_privilege(
          'periapsis_migrator', keyring_function.signature, 'EXECUTE'
        )
    AND has_function_privilege(
          'periapsis_api', keyring_function.signature, 'EXECUTE'
        )
    AND has_function_privilege(
          'periapsis_worker', keyring_function.signature, 'EXECUTE'
        );

  SELECT count(*)::integer INTO protected_owner_table_count
  FROM (VALUES
    ('platform_auth_providers'),
    ('platform_federated_provider_policies'),
    ('platform_federated_trust_rules'),
    ('platform_identity_provider_commands'),
    ('platform_identity_provider_test_runs'),
    ('platform_oidc_claim_rules'),
    ('platform_oidc_client_secrets'),
    ('platform_oidc_discovery_snapshots'),
    ('platform_oidc_jwks_snapshots'),
    ('platform_oidc_provider_configurations'),
    ('platform_saml_attribute_rules'),
    ('platform_saml_metadata_snapshots'),
    ('platform_saml_provider_configurations'),
    ('platform_saml_sp_certificates'),
    ('platform_saml_sp_keys')
  ) AS protected_table(table_name)
  WHERE has_table_privilege(
          'periapsis_migrator',
          format('public.%I', protected_table.table_name),
          'SELECT'
        )
    AND has_table_privilege(
          'periapsis_migrator',
          format('public.%I', protected_table.table_name),
          'INSERT'
        )
    AND has_table_privilege(
          'periapsis_migrator',
          format('public.%I', protected_table.table_name),
          'UPDATE'
        )
    AND has_table_privilege(
          'periapsis_migrator',
          format('public.%I', protected_table.table_name),
          'DELETE'
        )
    AND has_table_privilege(
          'periapsis_migrator',
          format('public.%I', protected_table.table_name),
          'TRUNCATE'
        )
    AND has_table_privilege(
          'periapsis_migrator',
          format('public.%I', protected_table.table_name),
          'REFERENCES'
        )
    AND has_table_privilege(
          'periapsis_migrator',
          format('public.%I', protected_table.table_name),
          'TRIGGER'
        );

  -- Owner/RLS/function-catalog drift must fail before the SECURITY DEFINER
  -- body touches protected data that a tampered owner could make unreadable.
  IF current_count IS DISTINCT FROM 159
     OR rolling_catalog_state_ready IS DISTINCT FROM true
     OR protected_table_count IS DISTINCT FROM 15
     OR protected_rule_count IS DISTINCT FROM 0
     OR protected_policy_count IS DISTINCT FROM 0
     OR protected_inheritance_count IS DISTINCT FROM 0
     OR protected_toast_mismatch_count IS DISTINCT FROM 0
     OR custom_operator_count IS DISTINCT FROM 0
     OR provider_cast_count IS DISTINCT FROM 0
     OR protected_function_count IS DISTINCT FROM 6
     OR private_function_count IS DISTINCT FROM 1
     OR permission_function_definition NOT LIKE '%tenant_authorization_states%'
     OR permission_function_definition NOT LIKE '%authorization_state.tenant_id = session_tenant_id%'
     OR permission_function_definition NOT LIKE '%tenant.status = ''active''%'
     OR permission_function_definition NOT LIKE '%membership.status = ''active''%'
     OR permission_function_definition NOT LIKE '%FOR SHARE%'
     OR private_projection_function_count IS DISTINCT FROM 1
     OR private_validator_function_count IS DISTINCT FROM 2
     OR runtime_surface_function_count IS DISTINCT FROM 1
     OR protected_acl_mismatch_count IS DISTINCT FROM 0
     OR private_acl_mismatch_count IS DISTINCT FROM 0
     OR protected_owner_function_count IS DISTINCT FROM 6
     OR private_owner_function_count IS DISTINCT FROM 5
     OR protected_owner_table_count IS DISTINCT FROM 15
     OR keyring_function_count IS DISTINCT FROM 1
     OR keyring_acl_mismatch_count IS DISTINCT FROM 0
     OR keyring_runtime_acl_mismatch_count IS DISTINCT FROM 0
     OR keyring_acl_entry_count IS DISTINCT FROM 3
     OR keyring_owner_function_count IS DISTINCT FROM 1
     OR legacy_keyring_acl_mismatch_count IS DISTINCT FROM 0
     OR security_role_mismatch_count IS DISTINCT FROM 0
     OR security_role_membership_mismatch_count IS DISTINCT FROM 0
     OR runtime_login_role_mismatch_count IS DISTINCT FROM 0
     OR schema_acl_mismatch_count IS DISTINCT FROM 0
     OR schema_effective_create_mismatch_count IS DISTINCT FROM 0
     OR database_effective_create_mismatch_count IS DISTINCT FROM 0
     OR default_acl_mismatch_count IS DISTINCT FROM 0
     OR default_acl_row_count IS DISTINCT FROM 1
     OR provider_kind_type_count IS DISTINCT FROM 1
     OR provider_kind_acl_mismatch_count IS DISTINCT FROM 0
     OR provider_kind_enum_mismatch_count IS DISTINCT FROM 0
     OR trusted_function_definition_mismatch_count IS DISTINCT FROM 0
     OR platform_audit_trigger_mismatch_count IS DISTINCT FROM 0
     OR catalog_column_mismatch_count IS DISTINCT FROM 0
     OR catalog_constraint_mismatch_count IS DISTINCT FROM 0
     OR catalog_index_mismatch_count IS DISTINCT FROM 0 THEN
    RETURN false;
  END IF;

  RETURN current_count = 159
     AND rolling_catalog_state_ready
     AND protected_table_count = 15
     AND protected_rule_count = 0
     AND protected_policy_count = 0
     AND protected_inheritance_count = 0
     AND protected_toast_mismatch_count = 0
     AND custom_operator_count = 0
     AND provider_cast_count = 0
     AND protected_function_count = 6
     AND private_function_count = 1
     AND private_projection_function_count = 1
     AND private_validator_function_count = 2
     AND runtime_surface_function_count = 1
     AND protected_acl_mismatch_count = 0
     AND private_acl_mismatch_count = 0
     AND protected_owner_function_count = 6
     AND private_owner_function_count = 5
     AND protected_owner_table_count = 15
     AND keyring_function_count = 1
     AND keyring_acl_mismatch_count = 0
     AND keyring_runtime_acl_mismatch_count = 0
     AND keyring_acl_entry_count = 3
     AND keyring_owner_function_count = 1
     AND legacy_keyring_acl_mismatch_count = 0
     AND security_role_mismatch_count = 0
     AND security_role_membership_mismatch_count = 0
     AND runtime_login_role_mismatch_count = 0
     AND schema_acl_mismatch_count = 0
     AND schema_effective_create_mismatch_count = 0
     AND database_effective_create_mismatch_count = 0
     AND default_acl_mismatch_count = 0
     AND default_acl_row_count = 1
     AND provider_kind_type_count = 1
     AND provider_kind_acl_mismatch_count = 0
     AND provider_kind_enum_mismatch_count = 0
     AND trusted_function_definition_mismatch_count = 0
     AND platform_audit_trigger_mismatch_count = 0
     AND catalog_column_mismatch_count = 0
     AND catalog_constraint_mismatch_count = 0
     AND catalog_index_mismatch_count = 0
     AND NOT EXISTS (
       WITH expected_permission(permission_key) AS (
         VALUES
           ('platform.identity_provider.read'),
           ('platform.identity_provider.manage'),
           ('platform.identity_provider.test'),
           ('platform.identity_binding.read'),
           ('platform.identity_binding.manage'),
           ('platform.identity_policy.read'),
           ('platform.identity_policy.manage'),
           ('platform.identity_account.read'),
           ('platform.identity_account.manage')
       ),
       actual_permission(permission_key) AS (
         SELECT permission.key
         FROM public.platform_permissions AS permission
         WHERE permission.key LIKE 'platform.identity\_%' ESCAPE '\'
       )
       (SELECT * FROM expected_permission
        EXCEPT
        SELECT * FROM actual_permission)
       UNION ALL
       (SELECT * FROM actual_permission
        EXCEPT
        SELECT * FROM expected_permission)
     )
     AND NOT EXISTS (
       WITH expected_grant(role_key, permission_key) AS (
         VALUES
           ('platform_super_admin', 'platform.identity_provider.read'),
           ('platform_super_admin', 'platform.identity_provider.manage'),
           ('platform_super_admin', 'platform.identity_provider.test'),
           ('platform_super_admin', 'platform.identity_binding.read'),
           ('platform_super_admin', 'platform.identity_binding.manage'),
           ('platform_super_admin', 'platform.identity_policy.read'),
           ('platform_super_admin', 'platform.identity_policy.manage'),
           ('platform_super_admin', 'platform.identity_account.read'),
           ('platform_super_admin', 'platform.identity_account.manage')
       ),
       actual_grant(role_key, permission_key) AS (
         SELECT role.key, permission.key
         FROM public.platform_role_permissions AS grant_row
         JOIN public.platform_roles AS role ON role.id = grant_row.role_id
         JOIN public.platform_permissions AS permission
           ON permission.id = grant_row.permission_id
         WHERE permission.key LIKE 'platform.identity\_%' ESCAPE '\'
       )
       (SELECT * FROM expected_grant
        EXCEPT
        SELECT * FROM actual_grant)
       UNION ALL
       (SELECT * FROM actual_grant
        EXCEPT
        SELECT * FROM expected_grant)
     )
     -- Projection values must be accepted byte-for-byte by the Go domain.
     -- PostgreSQL accepts infinity and values beyond JSON's exact-integer
     -- range, so schema shape alone is not enough for startup compatibility.
     AND NOT EXISTS (
       SELECT 1
       FROM ONLY public.platform_auth_providers AS provider
       WHERE provider.version NOT BETWEEN 1 AND 2147483647
          OR NOT isfinite(provider.created_at)
          OR NOT isfinite(provider.updated_at)
          OR provider.created_at < '1970-01-01 00:00:00+00'::timestamptz
          OR provider.updated_at < '1970-01-01 00:00:00+00'::timestamptz
          OR provider.created_at >= '10000-01-01 00:00:00+00'::timestamptz
          OR provider.updated_at >= '10000-01-01 00:00:00+00'::timestamptz
          OR (
            provider.archived_at IS NOT NULL
            AND (
              NOT isfinite(provider.archived_at)
              OR provider.archived_at <
                   '1970-01-01 00:00:00+00'::timestamptz
              OR provider.archived_at >=
                   '10000-01-01 00:00:00+00'::timestamptz
            )
          )
          OR NOT app.private_platform_identity_text_is_safe_v1(
            provider.display_name, true
          )
          OR NOT app.private_platform_identity_text_is_safe_v1(
            provider.description, true
          )
          OR (
            provider.archive_reason IS NOT NULL
            AND NOT app.private_platform_identity_text_is_safe_v1(
              provider.archive_reason, true
            )
          )
     )
     AND NOT EXISTS (
       SELECT 1
       FROM (
         SELECT policy.configuration_revision AS revision
         FROM ONLY public.platform_federated_provider_policies AS policy
         UNION ALL SELECT policy.security_revision
         FROM ONLY public.platform_federated_provider_policies AS policy
         UNION ALL SELECT policy.plan_revision
         FROM ONLY public.platform_federated_provider_policies AS policy
         UNION ALL SELECT policy.assurance_policy_revision
         FROM ONLY public.platform_federated_provider_policies AS policy
         UNION ALL SELECT trust_rule.revision
         FROM ONLY public.platform_federated_trust_rules AS trust_rule
         UNION ALL SELECT test_run.configuration_revision
         FROM ONLY public.platform_identity_provider_test_runs AS test_run
         UNION ALL SELECT configuration.client_secret_revision
         FROM ONLY public.platform_oidc_provider_configurations AS configuration
         UNION ALL SELECT configuration.discovery_revision
         FROM ONLY public.platform_oidc_provider_configurations AS configuration
         UNION ALL SELECT configuration.jwks_revision
         FROM ONLY public.platform_oidc_provider_configurations AS configuration
         UNION ALL SELECT configuration.version
         FROM ONLY public.platform_oidc_provider_configurations AS configuration
         UNION ALL SELECT snapshot.revision
         FROM ONLY public.platform_oidc_discovery_snapshots AS snapshot
         UNION ALL SELECT snapshot.revision
         FROM ONLY public.platform_oidc_jwks_snapshots AS snapshot
         UNION ALL SELECT secret.revision
         FROM ONLY public.platform_oidc_client_secrets AS secret
         UNION ALL SELECT configuration.sp_key_revision
         FROM ONLY public.platform_saml_provider_configurations AS configuration
         UNION ALL SELECT configuration.metadata_revision
         FROM ONLY public.platform_saml_provider_configurations AS configuration
         UNION ALL SELECT configuration.version
         FROM ONLY public.platform_saml_provider_configurations AS configuration
         UNION ALL SELECT snapshot.revision
         FROM ONLY public.platform_saml_metadata_snapshots AS snapshot
         UNION ALL SELECT sp_key.revision
         FROM ONLY public.platform_saml_sp_keys AS sp_key
       ) AS persisted_revision
       WHERE persisted_revision.revision NOT BETWEEN 1 AND 9007199254740991
     )
     AND NOT EXISTS (
       SELECT 1
       FROM ONLY public.platform_identity_provider_commands AS command
       WHERE command.result_version <> 1
     )
     AND NOT EXISTS (
       SELECT 1
       FROM ONLY public.platform_identity_provider_test_runs AS test_run
       WHERE test_run.provider_version NOT BETWEEN 1 AND 2147483647
     )
     AND NOT EXISTS (
       SELECT 1
       FROM ONLY public.platform_oidc_provider_configurations AS configuration
       WHERE NOT app.private_platform_identity_uri_is_canonical_v1(
               configuration.issuer, true, false, 4096
             )
          OR NOT app.private_platform_identity_uri_is_canonical_v1(
               configuration.redirect_uri, true, true, 4096
             )
          OR NOT app.private_platform_identity_uri_is_canonical_v1(
               configuration.post_logout_redirect_uri, true, true, 4096
             )
          OR octet_length(configuration.client_id) NOT BETWEEN 1 AND 512
          OR NOT app.private_platform_identity_text_is_safe_v1(
               configuration.client_id, true
             )
          OR cardinality(configuration.extra_scopes) > 32
          OR EXISTS (
            SELECT 1
            FROM unnest(configuration.extra_scopes) AS scope(value)
            WHERE scope.value !~
                    '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
               OR scope.value = 'openid'
               OR NOT app.private_platform_identity_text_is_safe_v1(
                    scope.value, true
                  )
          )
          OR (
            SELECT count(*) <> count(DISTINCT scope.value COLLATE "C")
            FROM unnest(configuration.extra_scopes) AS scope(value)
          )
          OR configuration.extra_scopes IS DISTINCT FROM ARRAY(
            SELECT scope.value
            FROM unnest(configuration.extra_scopes) AS scope(value)
            ORDER BY scope.value COLLATE "C"
          )
     )
     AND NOT EXISTS (
       SELECT 1
       FROM ONLY public.platform_saml_provider_configurations AS configuration
       WHERE NOT app.private_platform_identity_uri_is_canonical_v1(
               configuration.expected_entity_id, false, true, 2048
             )
          OR NOT app.private_platform_identity_uri_is_canonical_v1(
               configuration.sp_entity_id, true, false, 2048
             )
          OR NOT app.private_platform_identity_uri_is_canonical_v1(
               configuration.acs_url, true, true, 4096
             )
          OR cardinality(configuration.decryption_key_versions) <> 0
          OR cardinality(configuration.requested_authn_contexts)
               NOT BETWEEN 1 AND 32
          OR EXISTS (
            SELECT 1
            FROM unnest(configuration.requested_authn_contexts)
                 AS context(value)
            WHERE NOT app.private_platform_identity_uri_is_canonical_v1(
              context.value, false, true, 2048
            )
          )
          OR (
            SELECT count(*) <> count(DISTINCT context.value COLLATE "C")
            FROM unnest(configuration.requested_authn_contexts)
                 AS context(value)
          )
          OR configuration.requested_authn_contexts IS DISTINCT FROM ARRAY(
            SELECT context.value
            FROM unnest(configuration.requested_authn_contexts)
                 AS context(value)
            ORDER BY context.value COLLATE "C"
          )
          OR (
            configuration.subject_attribute_name IS NOT NULL
            AND (
              octet_length(configuration.subject_attribute_name)
                NOT BETWEEN 1 AND 512
              OR NOT app.private_platform_identity_text_is_safe_v1(
                   configuration.subject_attribute_name, true
                 )
            )
          )
          OR (
            configuration.subject_attribute_name_format IS NOT NULL
            AND NOT app.private_platform_identity_uri_is_canonical_v1(
              configuration.subject_attribute_name_format,
              false, true, 512
            )
          )
     )
     AND NOT EXISTS (
       SELECT 1
       FROM ONLY public.platform_auth_providers AS provider
       LEFT JOIN ONLY public.platform_federated_provider_policies AS policy
         ON policy.provider_id = provider.id
       LEFT JOIN ONLY public.platform_oidc_provider_configurations AS oidc
         ON oidc.provider_id = provider.id
       LEFT JOIN ONLY public.platform_saml_provider_configurations AS saml
         ON saml.provider_id = provider.id
       WHERE provider.enabled
           OR policy.provider_id IS NULL
           OR policy.provider_kind <> provider.kind
           OR policy.enabled
           OR policy.platform_login_enabled
           OR policy.account_mode <> 'disabled'
           OR (provider.kind = 'oidc' AND (oidc.provider_id IS NULL OR saml.provider_id IS NOT NULL))
          OR (provider.kind = 'saml' AND (saml.provider_id IS NULL OR oidc.provider_id IS NOT NULL))
     )
     -- The first OIDC secret written by the sealed ABI is revision 2. For a
     -- live provider, revision 1 means no secret; every later configuration
     -- revision has exactly one matching live envelope. Archive retires it.
     AND NOT EXISTS (
       SELECT 1
       FROM ONLY public.platform_oidc_provider_configurations AS configuration
       JOIN ONLY public.platform_auth_providers AS provider
         ON provider.id = configuration.provider_id
       CROSS JOIN LATERAL (
         SELECT count(*) FILTER (
                  WHERE secret.retired_at IS NULL
                )::integer AS live_count,
                min(secret.revision) AS minimum_revision,
                max(secret.revision) AS maximum_revision,
                min(secret.revision) FILTER (
                  WHERE secret.retired_at IS NULL
                ) AS live_minimum_revision,
                max(secret.revision) FILTER (
                  WHERE secret.retired_at IS NULL
                ) AS live_maximum_revision
         FROM ONLY public.platform_oidc_client_secrets AS secret
         WHERE secret.provider_id = configuration.provider_id
       ) AS secret_state
       WHERE coalesce(secret_state.maximum_revision, 1)
               IS DISTINCT FROM configuration.client_secret_revision
          OR secret_state.minimum_revision < 2
          OR (
            provider.archived_at IS NULL
            AND (
              configuration.client_secret_revision = 1
                AND secret_state.live_count <> 0
              OR configuration.client_secret_revision >= 2
                AND (
                  secret_state.live_count <> 1
                  OR secret_state.live_minimum_revision IS DISTINCT FROM
                       configuration.client_secret_revision
                  OR secret_state.live_maximum_revision IS DISTINCT FROM
                       configuration.client_secret_revision
                )
            )
          )
          OR (
            provider.archived_at IS NOT NULL
            AND secret_state.live_count <> 0
          )
     )
     -- Slice 9A has no SP-key writer and its Go projection deliberately
     -- rejects spKeyPresent=true. Any live SAML key therefore makes the
     -- serving schema semantically incompatible, even for an active provider.
     AND NOT EXISTS (
       SELECT 1
       FROM ONLY public.platform_saml_sp_keys AS sp_key
       WHERE sp_key.retired_at IS NULL
     )
     AND NOT EXISTS (
       SELECT 1
       FROM (VALUES
         ('platform_auth_providers'),
         ('platform_federated_provider_policies'),
         ('platform_federated_trust_rules'),
         ('platform_identity_provider_commands'),
         ('platform_identity_provider_test_runs'),
         ('platform_oidc_claim_rules'),
         ('platform_oidc_client_secrets'),
         ('platform_oidc_discovery_snapshots'),
         ('platform_oidc_jwks_snapshots'),
         ('platform_oidc_provider_configurations'),
         ('platform_saml_attribute_rules'),
         ('platform_saml_metadata_snapshots'),
         ('platform_saml_provider_configurations'),
         ('platform_saml_sp_certificates'),
         ('platform_saml_sp_keys')
       ) AS protected_table(table_name)
       CROSS JOIN (VALUES
         ('periapsis_api'), ('periapsis_worker'), ('periapsis_notifier'),
         ('periapsis_auditor'), ('periapsis_audit_reader_owner'),
         ('periapsis_notification_dispatch_owner'), ('periapsis_sla_api_owner'),
         ('periapsis_sla_worker_owner'), ('periapsis_sla_readiness_owner'),
         ('periapsis_ticket_saved_view_owner'),
         ('periapsis_ticket_attribution_owner'),
         ('periapsis_ticket_sla_projection_owner')
       ) AS runtime_role(role_name)
       WHERE has_table_privilege(
         runtime_role.role_name,
         format('public.%I', protected_table.table_name),
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
     )
     AND NOT EXISTS (
       SELECT 1
       FROM (VALUES
         ('app.list_platform_auth_providers_v1(uuid,text,uuid,integer,boolean)'::regprocedure),
         ('app.get_platform_auth_provider_v1(uuid,uuid,text)'::regprocedure),
         ('app.create_platform_auth_provider_v1(uuid,uuid,uuid,public.auth_provider_kind,text,text,text,jsonb,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'::regprocedure),
         ('app.update_platform_auth_provider_v1(uuid,uuid,bigint,text,text,text,uuid,uuid,uuid,inet,text,text,text)'::regprocedure),
         ('app.archive_platform_auth_provider_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)'::regprocedure),
         ('app.replace_platform_oidc_client_secret_v1(uuid,uuid,uuid,bigint,integer,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'::regprocedure)
       ) AS protected_function(signature)
       JOIN pg_catalog.pg_proc AS function
         ON function.oid = protected_function.signature
       CROSS JOIN LATERAL pg_catalog.aclexplode(
         coalesce(
           function.proacl,
           pg_catalog.acldefault('f', function.proowner)
         )
       ) AS function_acl
       WHERE function_acl.privilege_type <> 'EXECUTE'
          OR function_acl.grantee NOT IN (
            function.proowner,
            (SELECT role.oid FROM pg_catalog.pg_roles AS role
             WHERE role.rolname = 'periapsis_api')
          )
          OR (
            function_acl.grantee = (
              SELECT role.oid FROM pg_catalog.pg_roles AS role
              WHERE role.rolname = 'periapsis_api'
            )
            AND function_acl.is_grantable
          )
     )
     AND NOT EXISTS (
       SELECT 1
       FROM (VALUES
         ('app.list_platform_auth_providers_v1(uuid,text,uuid,integer,boolean)'::regprocedure),
         ('app.get_platform_auth_provider_v1(uuid,uuid,text)'::regprocedure),
         ('app.create_platform_auth_provider_v1(uuid,uuid,uuid,public.auth_provider_kind,text,text,text,jsonb,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'::regprocedure),
         ('app.update_platform_auth_provider_v1(uuid,uuid,bigint,text,text,text,uuid,uuid,uuid,inet,text,text,text)'::regprocedure),
         ('app.archive_platform_auth_provider_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)'::regprocedure),
         ('app.replace_platform_oidc_client_secret_v1(uuid,uuid,uuid,bigint,integer,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'::regprocedure)
       ) AS protected_function(signature)
       JOIN pg_catalog.pg_proc AS function
         ON function.oid = protected_function.signature
       WHERE NOT EXISTS (
         SELECT 1
         FROM pg_catalog.aclexplode(
           coalesce(
             function.proacl,
             pg_catalog.acldefault('f', function.proowner)
           )
         ) AS function_acl
         JOIN pg_catalog.pg_roles AS grantee
           ON grantee.oid = function_acl.grantee
         WHERE grantee.rolname = 'periapsis_api'
           AND function_acl.privilege_type = 'EXECUTE'
           AND NOT function_acl.is_grantable
       )
     )
     AND NOT EXISTS (
       SELECT 1
       FROM (VALUES
         ('app.private_require_platform_identity_permission_v1(uuid,text,text)'::regprocedure),
         ('app.private_platform_auth_provider_document_v1(uuid)'::regprocedure),
         ('app.private_platform_identity_text_is_safe_v1(text,boolean)'::regprocedure),
         ('app.private_platform_identity_uri_is_canonical_v1(text,boolean,boolean,integer)'::regprocedure),
         ('app.private_runtime_accessible_surface_hash_v1()'::regprocedure)
       ) AS private_function(signature)
       JOIN pg_catalog.pg_proc AS function
         ON function.oid = private_function.signature
       CROSS JOIN LATERAL pg_catalog.aclexplode(
         coalesce(
           function.proacl,
           pg_catalog.acldefault('f', function.proowner)
         )
       ) AS function_acl
       WHERE function_acl.privilege_type <> 'EXECUTE'
          OR function_acl.grantee <> function.proowner
     )
     AND NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_class AS table_row
       JOIN pg_catalog.pg_namespace AS namespace
         ON namespace.oid = table_row.relnamespace
       CROSS JOIN LATERAL pg_catalog.aclexplode(
         coalesce(
           table_row.relacl,
           pg_catalog.acldefault('r', table_row.relowner)
         )
       ) AS table_acl
       WHERE namespace.nspname = 'public'
         AND table_row.relname = ANY (ARRAY[
           'platform_auth_providers',
           'platform_federated_provider_policies',
           'platform_federated_trust_rules',
           'platform_identity_provider_commands',
           'platform_identity_provider_test_runs',
           'platform_oidc_claim_rules',
           'platform_oidc_client_secrets',
           'platform_oidc_discovery_snapshots',
           'platform_oidc_jwks_snapshots',
           'platform_oidc_provider_configurations',
           'platform_saml_attribute_rules',
           'platform_saml_metadata_snapshots',
           'platform_saml_provider_configurations',
           'platform_saml_sp_certificates',
           'platform_saml_sp_keys'
         ]::name[])
         AND table_acl.grantee <> table_row.relowner
     )
     AND NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_class AS table_row
       JOIN pg_catalog.pg_namespace AS namespace
         ON namespace.oid = table_row.relnamespace
       JOIN pg_catalog.pg_attribute AS column_row
         ON column_row.attrelid = table_row.oid
       WHERE namespace.nspname = 'public'
         AND table_row.relname = ANY (ARRAY[
           'platform_auth_providers',
           'platform_federated_provider_policies',
           'platform_federated_trust_rules',
           'platform_identity_provider_commands',
           'platform_identity_provider_test_runs',
           'platform_oidc_claim_rules',
           'platform_oidc_client_secrets',
           'platform_oidc_discovery_snapshots',
           'platform_oidc_jwks_snapshots',
           'platform_oidc_provider_configurations',
           'platform_saml_attribute_rules',
           'platform_saml_metadata_snapshots',
           'platform_saml_provider_configurations',
           'platform_saml_sp_certificates',
           'platform_saml_sp_keys'
         ]::name[])
         AND column_row.attnum > 0
         AND NOT column_row.attisdropped
         AND column_row.attacl IS NOT NULL
         AND cardinality(column_row.attacl) > 0
     )
     ;
END;
$function$;
ALTER FUNCTION app.platform_identity_provider_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.platform_identity_provider_schema_readiness_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.platform_identity_provider_schema_readiness_v1()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.seal_schema_compatibility_manifest(
  p_expected_count bigint,
  p_expected_latest_created_at bigint,
  p_expected_latest_hash text,
  p_expected_migration_fingerprint text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
DECLARE
  fingerprint_entries text[];
  appended_created_at bigint[];
  actual_count bigint;
  actual_latest_created_at bigint;
  actual_latest_hash text;
  actual_fingerprint text;
  predecessor_count bigint;
  predecessor_latest_created_at bigint;
  predecessor_latest_hash text;
  predecessor_fingerprint text;
  expected_predecessor_fingerprint text;
  retired_count bigint;
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint, ':'
  );
  IF p_expected_count IS DISTINCT FROM 159
     OR p_expected_latest_created_at IS DISTINCT FROM 1787929625096
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 159
     OR fingerprint_entries[159] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v33 manifest'
      USING ERRCODE = '22023';
  END IF;
  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO appended_created_at
  FROM unnest(fingerprint_entries[156:159]) WITH ORDINALITY
       AS entry(value, ordinality);
  IF appended_created_at IS DISTINCT FROM ARRAY[
       1787854721196, 1787854845465, 1787854846465, 1787929625096
     ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v33 appended sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v33() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v33 manifest does not match the journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v32()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:155], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v32() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 155
     OR predecessor_latest_created_at IS DISTINCT FROM 1787852085088
     OR predecessor_latest_hash IS DISTINCT FROM
          'dc468abe5bc3011e7ce9a740117871a1717de2deae0e01ac860f607391dfa2c6'
     OR predecessor_fingerprint IS DISTINCT FROM
          expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v32 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;

  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v31() AS compatibility;
  IF retired_count IS DISTINCT FROM 0
     OR NOT app.platform_identity_provider_schema_readiness_v1()
     OR NOT app.platform_tenant_lifecycle_schema_readiness_v1()
     OR NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v33()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v33()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v32()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v32()'::regprocedure,
       'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v31()'::regprocedure,
       'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v31()'::regprocedure,
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'schema compatibility v31 remains active or platform identity readiness failed'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;
ALTER FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

-- Advance each existing readiness surface to v33/current + v32/predecessor.
DO $migration$
DECLARE
  readiness_function regprocedure;
  original_definition text;
  rewritten_definition text;
BEGIN
  FOREACH readiness_function IN ARRAY ARRAY[
    'app.federated_authentication_schema_readiness_v1()'::regprocedure,
    'app.identity_mfa_device_management_readiness_v1()'::regprocedure,
    'app.identity_mfa_schema_readiness_v1()'::regprocedure,
    'app.private_sla_schema_readiness_core_v1()'::regprocedure,
    'app.ticket_saved_views_schema_readiness_v1()'::regprocedure,
    'app.ticket_query_projections_readiness_v1()'::regprocedure
  ] LOOP
    SELECT pg_get_functiondef(readiness_function)
    INTO STRICT original_definition;
    IF original_definition NOT LIKE '%app.schema_compatibility_v32()%'
       OR original_definition NOT LIKE '%app.schema_compatibility_v31()%'
       OR original_definition NOT LIKE '%app.schema_compatibility_v30()%'
       OR original_definition NOT LIKE
            '%current_count = 155 AND predecessor_count = 150%' THEN
      RAISE EXCEPTION 'unexpected v32 readiness definition: %',
        readiness_function::text USING ERRCODE = '55000';
    END IF;
    rewritten_definition := replace(
      original_definition,
      'app.schema_compatibility_v32()',
      'app.schema_compatibility_vNEXT()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'app.schema_compatibility_v31()',
      'app.schema_compatibility_v32()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'app.schema_compatibility_v30()',
      'app.schema_compatibility_v31()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'app.schema_compatibility_vNEXT()',
      'app.schema_compatibility_v33()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'current_count = 155 AND predecessor_count = 150',
      'current_count = 159 AND predecessor_count = 155'
    );
    IF rewritten_definition IS NOT DISTINCT FROM original_definition
       OR rewritten_definition NOT LIKE '%app.schema_compatibility_v33()%'
       OR rewritten_definition LIKE '%app.schema_compatibility_v30()%'
       OR rewritten_definition NOT LIKE
            '%current_count = 159 AND predecessor_count = 155%' THEN
      RAISE EXCEPTION 'failed to rebind v33 readiness definition: %',
        readiness_function::text USING ERRCODE = '55000';
    END IF;
    EXECUTE rewritten_definition;
  END LOOP;
END;
$migration$;
--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) TO periapsis_migrator;
