CREATE TABLE "tenant_webhook_url_policies" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"current_version" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_webhook_url_policies_tenant_key" UNIQUE("tenant_id"),
	CONSTRAINT "tenant_webhook_url_policies_tenant_identity_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_webhook_url_policies_identity_check" CHECK ((uuid_extract_version("tenant_webhook_url_policies"."id") = 7) is true
        and "tenant_webhook_url_policies"."current_version" between 1 and 2147483647
        and "tenant_webhook_url_policies"."updated_at" >= "tenant_webhook_url_policies"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_webhook_url_policies" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_webhook_url_policy_commands" (
	"tenant_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"actor_membership_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result_policy_id" uuid NOT NULL,
	"result_version_id" uuid NOT NULL,
	"result_version" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "tenant_webhook_url_policy_commands_pkey" PRIMARY KEY("tenant_id","actor_user_id","operation","key_digest"),
	CONSTRAINT "tenant_webhook_url_policy_commands_envelope_check" CHECK ("tenant_webhook_url_policy_commands"."operation" = 'webhook_url_policy.publish'
        and octet_length("tenant_webhook_url_policy_commands"."key_digest") = 32
        and octet_length("tenant_webhook_url_policy_commands"."request_digest") = 32
        and "tenant_webhook_url_policy_commands"."result_version" between 1 and 2147483647
        and "tenant_webhook_url_policy_commands"."expires_at" > "tenant_webhook_url_policy_commands"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_webhook_url_policy_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_webhook_url_policy_versions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"policy_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"rules" jsonb NOT NULL,
	"semantic_digest" "bytea" NOT NULL,
	"policy_digest" "bytea" NOT NULL,
	"published_by_membership_id" uuid NOT NULL,
	"published_at" timestamp with time zone NOT NULL,
	CONSTRAINT "tenant_webhook_url_policy_versions_coordinate_key" UNIQUE("tenant_id","policy_id","version"),
	CONSTRAINT "tenant_webhook_url_policy_versions_identity_key" UNIQUE("tenant_id","policy_id","id","version"),
	CONSTRAINT "tenant_webhook_url_policy_versions_identity_check" CHECK ((uuid_extract_version("tenant_webhook_url_policy_versions"."id") = 7) is true
        and (uuid_extract_version("tenant_webhook_url_policy_versions"."policy_id") = 7) is true
        and "tenant_webhook_url_policy_versions"."id" <> "tenant_webhook_url_policy_versions"."policy_id"
        and "tenant_webhook_url_policy_versions"."version" between 1 and 2147483647
        and date_trunc('milliseconds', "tenant_webhook_url_policy_versions"."published_at") = "tenant_webhook_url_policy_versions"."published_at"
        and extract(year from "tenant_webhook_url_policy_versions"."published_at" at time zone 'UTC') between 2000 and 9999),
	CONSTRAINT "tenant_webhook_url_policy_versions_document_check" CHECK (jsonb_typeof("tenant_webhook_url_policy_versions"."rules") = 'array'
        and jsonb_array_length("tenant_webhook_url_policy_versions"."rules") <= 256
        and octet_length("tenant_webhook_url_policy_versions"."rules"::text) <= 131072
        and octet_length("tenant_webhook_url_policy_versions"."semantic_digest") = 32
        and octet_length("tenant_webhook_url_policy_versions"."policy_digest") = 32)
);
--> statement-breakpoint
ALTER TABLE "tenant_webhook_url_policy_versions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "webhook_plain_local_runtime_role_opt_ins" (
	"role_name" text PRIMARY KEY NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "webhook_plain_local_runtime_role_opt_ins_role_check" CHECK ("webhook_plain_local_runtime_role_opt_ins"."role_name" in ('periapsis_api_login', 'periapsis_notifier_login'))
);
--> statement-breakpoint
ALTER TABLE "webhook_plain_local_runtime_role_opt_ins" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configuration_versions" DROP CONSTRAINT "tenant_notification_webhook_versions_bounds_check";--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configuration_versions" ADD COLUMN "endpoint_canonical_url" text;--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configuration_versions" ADD COLUMN "endpoint_digest" "bytea";--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configuration_versions" ADD COLUMN "webhook_url_policy_id" uuid;--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configuration_versions" ADD COLUMN "webhook_url_policy_version_id" uuid;--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configuration_versions" ADD COLUMN "webhook_url_policy_version" integer;--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configuration_versions" ADD COLUMN "webhook_url_policy_digest" "bytea";--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configuration_versions" ADD COLUMN "local_development_exemption" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_webhook_url_policies" ADD CONSTRAINT "tenant_webhook_url_policies_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_webhook_url_policies" ADD CONSTRAINT "tenant_webhook_url_policies_current_version_fk" FOREIGN KEY ("tenant_id","id","current_version") REFERENCES "public"."tenant_webhook_url_policy_versions"("tenant_id","policy_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_webhook_url_policy_commands" ADD CONSTRAINT "tenant_webhook_url_policy_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_webhook_url_policy_commands" ADD CONSTRAINT "tenant_webhook_url_policy_commands_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_webhook_url_policy_commands" ADD CONSTRAINT "tenant_webhook_url_policy_commands_membership_fk" FOREIGN KEY ("tenant_id","actor_membership_id","actor_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_webhook_url_policy_commands" ADD CONSTRAINT "tenant_webhook_url_policy_commands_result_fk" FOREIGN KEY ("tenant_id","result_policy_id","result_version_id","result_version") REFERENCES "public"."tenant_webhook_url_policy_versions"("tenant_id","policy_id","id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_webhook_url_policy_versions" ADD CONSTRAINT "tenant_webhook_url_policy_versions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_webhook_url_policy_versions" ADD CONSTRAINT "tenant_webhook_url_policy_versions_publisher_fk" FOREIGN KEY ("tenant_id","published_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "tenant_webhook_url_policy_commands_expiry_idx" ON "tenant_webhook_url_policy_commands" USING btree ("expires_at");--> statement-breakpoint
DO $role$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'periapsis_webhook_url_policy_owner'
  ) THEN
    CREATE ROLE periapsis_webhook_url_policy_owner
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
      NOREPLICATION NOBYPASSRLS;
  END IF;
END
$role$;--> statement-breakpoint
CREATE POLICY "tenant_webhook_url_policies_owner_tenant" ON "tenant_webhook_url_policies" AS PERMISSIVE FOR ALL TO "periapsis_webhook_url_policy_owner" USING ("tenant_webhook_url_policies"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("tenant_webhook_url_policies"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "tenant_webhook_url_policies_dispatch_select" ON "tenant_webhook_url_policies" AS PERMISSIVE FOR SELECT TO "periapsis_notification_dispatch_owner" USING (true);--> statement-breakpoint
CREATE POLICY "tenant_webhook_url_policy_commands_owner_tenant" ON "tenant_webhook_url_policy_commands" AS PERMISSIVE FOR ALL TO "periapsis_webhook_url_policy_owner" USING ("tenant_webhook_url_policy_commands"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("tenant_webhook_url_policy_commands"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "tenant_webhook_url_policy_versions_owner_tenant" ON "tenant_webhook_url_policy_versions" AS PERMISSIVE FOR ALL TO "periapsis_webhook_url_policy_owner" USING ("tenant_webhook_url_policy_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("tenant_webhook_url_policy_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "tenant_webhook_url_policy_versions_dispatch_select" ON "tenant_webhook_url_policy_versions" AS PERMISSIVE FOR SELECT TO "periapsis_notification_dispatch_owner" USING (true);--> statement-breakpoint
CREATE POLICY "webhook_plain_local_runtime_role_opt_ins_api_self" ON "webhook_plain_local_runtime_role_opt_ins" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING ("webhook_plain_local_runtime_role_opt_ins"."role_name" = session_user::text);--> statement-breakpoint
CREATE POLICY "webhook_plain_local_runtime_role_opt_ins_notifier_self" ON "webhook_plain_local_runtime_role_opt_ins" AS PERMISSIVE FOR SELECT TO "periapsis_notifier" USING ("webhook_plain_local_runtime_role_opt_ins"."role_name" = session_user::text);--> statement-breakpoint
CREATE POLICY "webhook_plain_local_runtime_role_opt_ins_owner_self" ON "webhook_plain_local_runtime_role_opt_ins" AS PERMISSIVE FOR SELECT TO "periapsis_webhook_url_policy_owner" USING ("webhook_plain_local_runtime_role_opt_ins"."role_name" = session_user::text);
--> statement-breakpoint
ALTER ROLE periapsis_webhook_url_policy_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
  NOREPLICATION NOBYPASSRLS;--> statement-breakpoint
REVOKE periapsis_webhook_url_policy_owner
FROM periapsis_api, periapsis_worker, periapsis_notifier,
     periapsis_auditor;--> statement-breakpoint

ALTER TABLE public.tenant_webhook_url_policy_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_webhook_url_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_webhook_url_policy_commands FORCE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_plain_local_runtime_role_opt_ins FORCE ROW LEVEL SECURITY;--> statement-breakpoint

ALTER TABLE public.tenant_webhook_url_policy_versions
  OWNER TO periapsis_webhook_url_policy_owner;
ALTER TABLE public.tenant_webhook_url_policies
  OWNER TO periapsis_webhook_url_policy_owner;
ALTER TABLE public.tenant_webhook_url_policy_commands
  OWNER TO periapsis_webhook_url_policy_owner;
ALTER TABLE public.webhook_plain_local_runtime_role_opt_ins
  OWNER TO periapsis_webhook_url_policy_owner;--> statement-breakpoint

REVOKE ALL ON TABLE
  public.tenant_webhook_url_policy_versions,
  public.tenant_webhook_url_policies,
  public.tenant_webhook_url_policy_commands,
  public.webhook_plain_local_runtime_role_opt_ins
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
     periapsis_auditor;--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
  public.tenant_webhook_url_policy_versions,
  public.tenant_webhook_url_policies,
  public.tenant_webhook_url_policy_commands
TO periapsis_webhook_url_policy_owner;--> statement-breakpoint
GRANT SELECT ON TABLE
  public.tenant_webhook_url_policy_versions,
  public.tenant_webhook_url_policies
TO periapsis_notification_dispatch_owner;--> statement-breakpoint
GRANT SELECT ON TABLE public.webhook_plain_local_runtime_role_opt_ins
TO periapsis_api, periapsis_notifier, periapsis_webhook_url_policy_owner;--> statement-breakpoint
GRANT USAGE ON SCHEMA public, app TO periapsis_webhook_url_policy_owner;--> statement-breakpoint

CREATE FUNCTION app.private_webhook_url_policy_hostname_valid_v1(p_hostname text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public, app
AS $function$
  SELECT octet_length(p_hostname) BETWEEN 3 AND 253
    AND p_hostname = lower(p_hostname)
    AND p_hostname ~ '^[a-z0-9.-]+$'
    AND p_hostname ~ '[.]'
    AND p_hostname !~ '[.]$'
    AND p_hostname !~ '[.]localhost$'
    AND p_hostname !~ '(^|[.])(0x[0-9a-f]+|[0-9]+)$'
    AND NOT EXISTS (
      SELECT 1
      FROM regexp_split_to_table(p_hostname, '[.]') AS label(value)
      WHERE label.value !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
    );
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_webhook_url_policy_hostname_valid_v1(text)
  OWNER TO periapsis_webhook_url_policy_owner;
REVOKE ALL ON FUNCTION app.private_webhook_url_policy_hostname_valid_v1(text)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.private_webhook_url_policy_framed_digest_v1(p_parts bytea[])
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  part bytea;
  document bytea := ''::bytea;
BEGIN
  FOREACH part IN ARRAY p_parts LOOP
    IF part IS NULL THEN
      RAISE EXCEPTION 'webhook URL policy digest part is invalid'
        USING ERRCODE = '22023';
    END IF;
    document := document || int4send(octet_length(part)) || part;
  END LOOP;
  RETURN sha256(document);
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_webhook_url_policy_framed_digest_v1(bytea[])
  OWNER TO periapsis_webhook_url_policy_owner;
REVOKE ALL ON FUNCTION app.private_webhook_url_policy_framed_digest_v1(bytea[])
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.private_canonical_webhook_url_policy_rules_v1(p_rules jsonb)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  item jsonb;
  hostname text;
  port_value integer;
  canonical jsonb;
BEGIN
  IF jsonb_typeof(p_rules) <> 'array'
     OR jsonb_array_length(p_rules) > 256
     OR octet_length(p_rules::text) > 131072 THEN
    RAISE EXCEPTION 'webhook URL policy rule document is invalid'
      USING ERRCODE = '22023';
  END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(p_rules) AS entry(value)
  LOOP
    IF jsonb_typeof(item) <> 'object'
       OR NOT (item ?& ARRAY['effect', 'match', 'hostname', 'port'])
       OR item - ARRAY['effect', 'match', 'hostname', 'port']::text[] <> '{}'::jsonb
       OR jsonb_typeof(item -> 'effect') <> 'string'
       OR jsonb_typeof(item -> 'match') <> 'string'
       OR jsonb_typeof(item -> 'hostname') <> 'string'
       OR jsonb_typeof(item -> 'port') <> 'number'
       OR item ->> 'effect' NOT IN ('allow', 'deny')
       OR item ->> 'match' NOT IN ('exact', 'subdomains')
       OR item ->> 'port' !~ '^[1-9][0-9]{0,4}$' THEN
      RAISE EXCEPTION 'webhook URL policy rule is invalid'
        USING ERRCODE = '22023';
    END IF;
    hostname := item ->> 'hostname';
    port_value := (item ->> 'port')::integer;
    IF NOT app.private_webhook_url_policy_hostname_valid_v1(hostname)
       OR port_value NOT BETWEEN 1 AND 65535 THEN
      RAISE EXCEPTION 'webhook URL policy rule host or port is invalid'
        USING ERRCODE = '22023';
    END IF;
  END LOOP;
  SELECT coalesce(jsonb_agg(entry.value ORDER BY
           entry.value ->> 'effect' COLLATE "C",
           entry.value ->> 'match' COLLATE "C",
           entry.value ->> 'hostname' COLLATE "C",
           entry.value ->> 'port' COLLATE "C"),
         '[]'::jsonb)
  INTO canonical
  FROM jsonb_array_elements(p_rules) AS entry(value);
  IF jsonb_array_length(canonical) <> (
    SELECT count(DISTINCT concat_ws(chr(31),
      entry.value ->> 'effect', entry.value ->> 'match',
      entry.value ->> 'hostname', entry.value ->> 'port'))
    FROM jsonb_array_elements(canonical) AS entry(value)
  ) THEN
    RAISE EXCEPTION 'webhook URL policy rules contain duplicates'
      USING ERRCODE = '22023';
  END IF;
  RETURN canonical;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_canonical_webhook_url_policy_rules_v1(jsonb)
  OWNER TO periapsis_webhook_url_policy_owner;
REVOKE ALL ON FUNCTION app.private_canonical_webhook_url_policy_rules_v1(jsonb)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.private_webhook_url_policy_semantic_digest_v1(p_rules jsonb)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  canonical jsonb := app.private_canonical_webhook_url_policy_rules_v1(p_rules);
  item jsonb;
  parts bytea[] := ARRAY[
    convert_to('periapsis.webhook-url-policy-semantics.v1', 'UTF8'),
    convert_to('https', 'UTF8'),
    convert_to('deny', 'UTF8')
  ];
BEGIN
  FOR item IN SELECT value FROM jsonb_array_elements(canonical) AS entry(value)
  LOOP
    parts := array_append(parts,
      convert_to(item ->> 'effect', 'UTF8') || decode('00', 'hex') ||
      convert_to(item ->> 'match', 'UTF8') || decode('00', 'hex') ||
      convert_to(item ->> 'hostname', 'UTF8') || decode('00', 'hex') ||
      convert_to(item ->> 'port', 'UTF8'));
  END LOOP;
  RETURN app.private_webhook_url_policy_framed_digest_v1(parts);
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_webhook_url_policy_semantic_digest_v1(jsonb)
  OWNER TO periapsis_webhook_url_policy_owner;
REVOKE ALL ON FUNCTION app.private_webhook_url_policy_semantic_digest_v1(jsonb)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.private_webhook_url_policy_version_digest_v1(
  p_tenant_id uuid,
  p_policy_id uuid,
  p_version_id uuid,
  p_version integer,
  p_publisher_membership_id uuid,
  p_published_at timestamptz,
  p_semantic_digest bytea
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public, app
AS $function$
  SELECT app.private_webhook_url_policy_framed_digest_v1(ARRAY[
    convert_to('periapsis.webhook-url-policy-version.v1', 'UTF8'),
    convert_to(p_tenant_id::text, 'UTF8'),
    convert_to(p_policy_id::text, 'UTF8'),
    convert_to(p_version_id::text, 'UTF8'),
    convert_to(p_version::text, 'UTF8'),
    convert_to(p_publisher_membership_id::text, 'UTF8'),
    convert_to(to_char(p_published_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), 'UTF8'),
    convert_to(encode(p_semantic_digest, 'hex'), 'UTF8')
  ]);
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_webhook_url_policy_version_digest_v1(
  uuid, uuid, uuid, integer, uuid, timestamptz, bytea
) OWNER TO periapsis_webhook_url_policy_owner;
REVOKE ALL ON FUNCTION app.private_webhook_url_policy_version_digest_v1(
  uuid, uuid, uuid, integer, uuid, timestamptz, bytea
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.private_canonical_webhook_endpoint_v1(
  p_url text,
  p_allow_plain_local boolean DEFAULT false
)
RETURNS TABLE(
  canonical_url text,
  hostname text,
  port integer,
  endpoint_digest bytea,
  local_development boolean
)
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  scheme text;
  remainder text;
  authority text;
  suffix text;
  path_value text;
  query_value text;
  has_query boolean;
  slash_at integer;
  query_at integer;
  boundary integer;
  port_text text;
  local_match text[];
BEGIN
  IF octet_length(p_url) NOT BETWEEN 1 AND 2048
     OR p_url <> btrim(p_url)
     OR p_url ~ '[^ -~]'
     OR position('%' IN p_url) > 0
     OR position('#' IN p_url) > 0
     OR position(chr(92) IN p_url) > 0 THEN
    RAISE EXCEPTION 'webhook endpoint is not canonicalizable'
      USING ERRCODE = '22023';
  END IF;
  scheme := lower(split_part(p_url, '://', 1));
  IF position('://' IN p_url) = 0 OR scheme NOT IN ('https', 'http') THEN
    RAISE EXCEPTION 'webhook endpoint scheme is invalid'
      USING ERRCODE = '22023';
  END IF;
  remainder := substring(p_url FROM length(scheme) + 4);
  slash_at := position('/' IN remainder);
  query_at := position('?' IN remainder);
  boundary := length(remainder) + 1;
  IF slash_at > 0 THEN boundary := least(boundary, slash_at); END IF;
  IF query_at > 0 THEN boundary := least(boundary, query_at); END IF;
  authority := left(remainder, boundary - 1);
  suffix := substring(remainder FROM boundary);
  IF authority = '' OR position('@' IN authority) > 0 THEN
    RAISE EXCEPTION 'webhook endpoint authority is invalid'
      USING ERRCODE = '22023';
  END IF;

  IF scheme = 'http' THEN
    IF NOT p_allow_plain_local THEN
      RAISE EXCEPTION 'plain webhook endpoint is forbidden'
        USING ERRCODE = '42501';
    END IF;
    local_match := regexp_match(
      authority,
      '^(localhost|127[.]0[.]0[.]1|\[::1\])(?::([1-9][0-9]{0,4}))?$'
    );
    IF local_match IS NULL THEN
      RAISE EXCEPTION 'plain webhook endpoint is not exact loopback'
        USING ERRCODE = '42501';
    END IF;
    hostname := CASE local_match[1]
      WHEN '[::1]' THEN '::1' ELSE local_match[1] END;
    port_text := local_match[2];
    port := coalesce(port_text::integer, 80);
    IF port NOT BETWEEN 1 AND 65535 THEN
      RAISE EXCEPTION 'plain webhook endpoint port is invalid'
        USING ERRCODE = '22023';
    END IF;
    local_development := true;
  ELSE
    IF position('[' IN authority) > 0
       OR position(']' IN authority) > 0
       OR position(' ' IN authority) > 0
       OR length(authority) - length(replace(authority, ':', '')) > 1 THEN
      RAISE EXCEPTION 'webhook endpoint authority is ambiguous'
        USING ERRCODE = '22023';
    END IF;
    hostname := lower(split_part(authority, ':', 1));
    port_text := nullif(split_part(authority, ':', 2), '');
    IF NOT app.private_webhook_url_policy_hostname_valid_v1(hostname)
       OR position(':' IN authority) > 0 AND (
         port_text IS NULL OR port_text !~ '^[1-9][0-9]{0,4}$'
         OR port_text IS DISTINCT FROM port_text::integer::text
       ) THEN
      RAISE EXCEPTION 'webhook endpoint host or port is invalid'
        USING ERRCODE = '22023';
    END IF;
    port := coalesce(port_text::integer, 443);
    IF port NOT BETWEEN 1 AND 65535 THEN
      RAISE EXCEPTION 'webhook endpoint port is invalid'
        USING ERRCODE = '22023';
    END IF;
    local_development := false;
  END IF;

  has_query := position('?' IN suffix) > 0;
  IF suffix = '' THEN
    path_value := '/';
    query_value := '';
  ELSIF left(suffix, 1) = '?' THEN
    path_value := '/';
    query_value := substring(suffix FROM 2);
  ELSE
    path_value := split_part(suffix, '?', 1);
    query_value := CASE WHEN has_query
      THEN substring(suffix FROM position('?' IN suffix) + 1) ELSE '' END;
  END IF;
  IF left(path_value, 1) <> '/'
     OR octet_length(path_value) > 1024
     OR octet_length(query_value) > 1024
     OR path_value !~ '^[A-Za-z0-9._~!$&''()*+,;=:@/-]*$'
     OR query_value !~ '^[A-Za-z0-9._~!$&''()*+,;=:@/?-]*$'
     OR EXISTS (
       SELECT 1 FROM regexp_split_to_table(path_value, '/') AS segment(value)
       WHERE segment.value IN ('.', '..')
     ) THEN
    RAISE EXCEPTION 'webhook endpoint path or query is invalid'
      USING ERRCODE = '22023';
  END IF;
  canonical_url := scheme || '://' ||
    CASE WHEN hostname = '::1' THEN '[::1]' ELSE hostname END ||
    CASE WHEN scheme = 'https' AND port = 443 OR scheme = 'http' AND port = 80
      THEN '' ELSE ':' || port::text END || path_value ||
    CASE WHEN has_query THEN '?' || query_value ELSE '' END;
  endpoint_digest := app.private_webhook_url_policy_framed_digest_v1(ARRAY[
    convert_to('periapsis.webhook-endpoint.v1', 'UTF8'),
    convert_to(canonical_url, 'UTF8')
  ]);
  RETURN NEXT;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_canonical_webhook_endpoint_v1(text, boolean)
  OWNER TO periapsis_webhook_url_policy_owner;
REVOKE ALL ON FUNCTION app.private_canonical_webhook_endpoint_v1(text, boolean)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION
  app.private_webhook_url_policy_hostname_valid_v1(text),
  app.private_webhook_url_policy_framed_digest_v1(bytea[]),
  app.private_canonical_webhook_url_policy_rules_v1(jsonb),
  app.private_webhook_url_policy_semantic_digest_v1(jsonb),
  app.private_webhook_url_policy_version_digest_v1(
    uuid, uuid, uuid, integer, uuid, timestamptz, bytea
  ),
  app.private_canonical_webhook_endpoint_v1(text, boolean)
TO periapsis_migrator, periapsis_webhook_url_policy_owner;--> statement-breakpoint

DO $webhook_url_policy_backfill_preflight$
DECLARE
  existing record;
BEGIN
  FOR existing IN
    SELECT version.tenant_id, version.configuration_id, version.version,
           version.endpoint_url
    FROM ONLY public.tenant_notification_webhook_configuration_versions AS version
    ORDER BY version.tenant_id, version.configuration_id, version.version
  LOOP
    PERFORM endpoint.canonical_url
    FROM app.private_canonical_webhook_endpoint_v1(
      existing.endpoint_url, true
    ) AS endpoint;
  END LOOP;
  IF EXISTS (
    WITH canonical AS MATERIALIZED (
      SELECT version.tenant_id, endpoint.hostname, endpoint.port
      FROM ONLY public.tenant_notification_webhook_configuration_versions AS version
      CROSS JOIN LATERAL app.private_canonical_webhook_endpoint_v1(
        version.endpoint_url, true
      ) AS endpoint
      WHERE NOT endpoint.local_development
    )
    SELECT 1 FROM canonical
    GROUP BY canonical.tenant_id
    HAVING count(DISTINCT (canonical.hostname, canonical.port)) > 256
  ) THEN
    RAISE EXCEPTION 'a tenant has more than 256 historical HTTPS webhook endpoints'
      USING ERRCODE = '54000';
  END IF;
END;
$webhook_url_policy_backfill_preflight$;--> statement-breakpoint

WITH canonical AS MATERIALIZED (
  SELECT version.tenant_id, version.configuration_id, version.version,
         version.created_by_membership_id, version.created_at,
         endpoint.hostname, endpoint.port, endpoint.local_development
  FROM ONLY public.tenant_notification_webhook_configuration_versions AS version
  CROSS JOIN LATERAL app.private_canonical_webhook_endpoint_v1(
    version.endpoint_url, true
  ) AS endpoint
), tenant_input AS MATERIALIZED (
  SELECT canonical.tenant_id,
         (array_agg(canonical.created_by_membership_id ORDER BY
           canonical.created_at, canonical.configuration_id,
           canonical.version))[1] AS publisher_membership_id,
         date_trunc('milliseconds', min(canonical.created_at)) AS published_at,
         app.private_canonical_webhook_url_policy_rules_v1(
           coalesce(jsonb_agg(DISTINCT jsonb_build_object(
             'effect', 'allow', 'match', 'exact',
             'hostname', canonical.hostname, 'port', canonical.port
           )) FILTER (WHERE NOT canonical.local_development), '[]'::jsonb)
         ) AS rules
  FROM canonical
  GROUP BY canonical.tenant_id
), identities AS MATERIALIZED (
  SELECT tenant_input.*, uuidv7() AS policy_id, uuidv7() AS version_id
  FROM tenant_input
), digests AS MATERIALIZED (
  SELECT identities.*,
         app.private_webhook_url_policy_semantic_digest_v1(
           identities.rules
         ) AS semantic_digest
  FROM identities
)
INSERT INTO public.tenant_webhook_url_policy_versions (
  id, tenant_id, policy_id, version, rules, semantic_digest,
  policy_digest, published_by_membership_id, published_at
)
SELECT digests.version_id, digests.tenant_id, digests.policy_id, 1,
       digests.rules, digests.semantic_digest,
       app.private_webhook_url_policy_version_digest_v1(
         digests.tenant_id, digests.policy_id, digests.version_id, 1,
         digests.publisher_membership_id, digests.published_at,
         digests.semantic_digest
       ),
       digests.publisher_membership_id, digests.published_at
FROM digests;--> statement-breakpoint

INSERT INTO public.tenant_webhook_url_policies (
  id, tenant_id, current_version, created_at, updated_at
)
SELECT version.policy_id, version.tenant_id, 1,
       version.published_at, version.published_at
FROM ONLY public.tenant_webhook_url_policy_versions AS version
WHERE version.version = 1;--> statement-breakpoint

ALTER TABLE public.tenant_notification_webhook_configuration_versions
  DISABLE TRIGGER tenant_notification_webhook_versions_immutable_v1;--> statement-breakpoint
WITH canonical AS MATERIALIZED (
  SELECT version.tenant_id, version.configuration_id, version.version,
         endpoint.canonical_url, endpoint.endpoint_digest,
         endpoint.local_development
  FROM ONLY public.tenant_notification_webhook_configuration_versions AS version
  CROSS JOIN LATERAL app.private_canonical_webhook_endpoint_v1(
    version.endpoint_url, true
  ) AS endpoint
), pinned AS MATERIALIZED (
  SELECT canonical.*, policy.id AS policy_id,
         policy_version.id AS policy_version_id,
         policy_version.version AS policy_version,
         policy_version.policy_digest
  FROM canonical
  LEFT JOIN ONLY public.tenant_webhook_url_policies AS policy
    ON policy.tenant_id = canonical.tenant_id
  LEFT JOIN ONLY public.tenant_webhook_url_policy_versions AS policy_version
    ON policy_version.tenant_id = policy.tenant_id
   AND policy_version.policy_id = policy.id
   AND policy_version.version = policy.current_version
)
UPDATE ONLY public.tenant_notification_webhook_configuration_versions AS version
SET endpoint_url = pinned.canonical_url,
    endpoint_canonical_url = pinned.canonical_url,
    endpoint_digest = pinned.endpoint_digest,
    webhook_url_policy_id = CASE WHEN pinned.local_development
      THEN NULL ELSE pinned.policy_id END,
    webhook_url_policy_version_id = CASE WHEN pinned.local_development
      THEN NULL ELSE pinned.policy_version_id END,
    webhook_url_policy_version = CASE WHEN pinned.local_development
      THEN NULL ELSE pinned.policy_version END,
    webhook_url_policy_digest = CASE WHEN pinned.local_development
      THEN NULL ELSE pinned.policy_digest END,
    local_development_exemption = pinned.local_development
FROM pinned
WHERE version.tenant_id = pinned.tenant_id
  AND version.configuration_id = pinned.configuration_id
  AND version.version = pinned.version;--> statement-breakpoint
ALTER TABLE public.tenant_notification_webhook_configuration_versions
  ENABLE TRIGGER tenant_notification_webhook_versions_immutable_v1;--> statement-breakpoint

DO $webhook_url_policy_backfill_contract$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenant_notification_webhook_configuration_versions AS version
    WHERE version.endpoint_canonical_url IS NULL
       OR version.endpoint_digest IS NULL
       OR version.endpoint_url IS DISTINCT FROM version.endpoint_canonical_url
       OR NOT version.local_development_exemption AND (
         version.webhook_url_policy_id IS NULL
         OR version.webhook_url_policy_version_id IS NULL
         OR version.webhook_url_policy_version IS NULL
         OR version.webhook_url_policy_digest IS NULL
       )
       OR version.local_development_exemption AND (
         version.webhook_url_policy_id IS NOT NULL
         OR version.webhook_url_policy_version_id IS NOT NULL
         OR version.webhook_url_policy_version IS NOT NULL
         OR version.webhook_url_policy_digest IS NOT NULL
       )
  ) THEN
    RAISE EXCEPTION 'webhook URL policy backfill contract failed'
      USING ERRCODE = '55000';
  END IF;
END;
$webhook_url_policy_backfill_contract$;--> statement-breakpoint

ALTER TABLE public.tenant_notification_webhook_configuration_versions
  ALTER COLUMN endpoint_canonical_url SET NOT NULL,
  ALTER COLUMN endpoint_digest SET NOT NULL;--> statement-breakpoint
ALTER TABLE public.tenant_notification_webhook_configuration_versions
  ADD CONSTRAINT tenant_notification_webhook_versions_url_policy_fk
  FOREIGN KEY (
    tenant_id, webhook_url_policy_id, webhook_url_policy_version_id,
    webhook_url_policy_version
  ) REFERENCES public.tenant_webhook_url_policy_versions(
    tenant_id, policy_id, id, version
  ) ON DELETE RESTRICT NOT VALID;--> statement-breakpoint
ALTER TABLE public.tenant_notification_webhook_configuration_versions
  VALIDATE CONSTRAINT tenant_notification_webhook_versions_url_policy_fk;--> statement-breakpoint
ALTER TABLE public.tenant_notification_webhook_configuration_versions
  ADD CONSTRAINT tenant_notification_webhook_versions_bounds_check CHECK (
    version between 1 and 2147483647
    and btrim(name) <> '' and char_length(name) <= 160
    and octet_length(endpoint_url) between 8 and 2048
    and octet_length(endpoint_canonical_url) between 8 and 2048
    and endpoint_url = endpoint_canonical_url
    and octet_length(endpoint_digest) = 32
    and (
      not local_development_exemption
      and endpoint_canonical_url like 'https://%'
      and webhook_url_policy_id is not null
      and webhook_url_policy_version_id is not null
      and webhook_url_policy_version between 1 and 2147483647
      and octet_length(webhook_url_policy_digest) = 32
      or local_development_exemption
      and endpoint_canonical_url like 'http://%'
      and webhook_url_policy_id is null
      and webhook_url_policy_version_id is null
      and webhook_url_policy_version is null
      and webhook_url_policy_digest is null
    )
    and cardinality(event_types) between 1 and 64
    and signing_secret_version between 1 and 2147483647
    and timeout_ms between 1000 and 120000
  ) NOT VALID;--> statement-breakpoint
ALTER TABLE public.tenant_notification_webhook_configuration_versions
  VALIDATE CONSTRAINT tenant_notification_webhook_versions_bounds_check;--> statement-breakpoint

CREATE FUNCTION app.private_reject_webhook_url_policy_history_change_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  RAISE EXCEPTION 'webhook URL policy history is immutable'
    USING ERRCODE = '55000';
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_reject_webhook_url_policy_history_change_v1()
  OWNER TO periapsis_webhook_url_policy_owner;
REVOKE ALL ON FUNCTION app.private_reject_webhook_url_policy_history_change_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER tenant_webhook_url_policy_versions_immutable_v1
BEFORE UPDATE OR DELETE ON public.tenant_webhook_url_policy_versions
FOR EACH ROW EXECUTE FUNCTION
  app.private_reject_webhook_url_policy_history_change_v1();
CREATE TRIGGER tenant_webhook_url_policy_commands_immutable_v1
BEFORE UPDATE OR DELETE ON public.tenant_webhook_url_policy_commands
FOR EACH ROW EXECUTE FUNCTION
  app.private_reject_webhook_url_policy_history_change_v1();--> statement-breakpoint

CREATE FUNCTION app.private_webhook_url_policy_projection_v1(
  p_tenant_id uuid,
  p_policy_id uuid,
  p_version integer
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_build_object(
    'id', policy.policy_id,
    'versionId', policy.id,
    'tenantId', policy.tenant_id,
    'version', policy.version,
    'scheme', 'https',
    'defaultAction', 'deny',
    'rules', policy.rules,
    'publishedByMembershipId', policy.published_by_membership_id,
    'publishedAt', policy.published_at,
    'digest', encode(policy.policy_digest, 'hex'),
    'semanticDigest', encode(policy.semantic_digest, 'hex')
  )
  FROM ONLY public.tenant_webhook_url_policy_versions AS policy
  WHERE policy.tenant_id = p_tenant_id
    AND policy.policy_id = p_policy_id
    AND policy.version = p_version;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_webhook_url_policy_projection_v1(
  uuid, uuid, integer
) OWNER TO periapsis_webhook_url_policy_owner;
REVOKE ALL ON FUNCTION app.private_webhook_url_policy_projection_v1(
  uuid, uuid, integer
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.private_webhook_url_policy_allows_endpoint_v1(
  p_rules jsonb,
  p_hostname text,
  p_port integer
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
STRICT
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  canonical jsonb := app.private_canonical_webhook_url_policy_rules_v1(p_rules);
BEGIN
  IF NOT app.private_webhook_url_policy_hostname_valid_v1(p_hostname)
     OR p_port NOT BETWEEN 1 AND 65535 THEN
    RAISE EXCEPTION 'webhook endpoint policy coordinates are invalid'
      USING ERRCODE = '22023';
  END IF;
  RETURN NOT EXISTS (
    SELECT 1
    FROM jsonb_array_elements(canonical) AS rule(value)
    WHERE rule.value ->> 'effect' = 'deny'
      AND (rule.value ->> 'port')::integer = p_port
      AND (
        rule.value ->> 'match' = 'exact'
          AND rule.value ->> 'hostname' = p_hostname
        OR rule.value ->> 'match' = 'subdomains'
          AND p_hostname <> rule.value ->> 'hostname'
          AND right(
            p_hostname, length(rule.value ->> 'hostname') + 1
          ) = '.' || (rule.value ->> 'hostname')
      )
  ) AND EXISTS (
    SELECT 1
    FROM jsonb_array_elements(canonical) AS rule(value)
    WHERE rule.value ->> 'effect' = 'allow'
      AND (rule.value ->> 'port')::integer = p_port
      AND (
        rule.value ->> 'match' = 'exact'
          AND rule.value ->> 'hostname' = p_hostname
        OR rule.value ->> 'match' = 'subdomains'
          AND p_hostname <> rule.value ->> 'hostname'
          AND right(
            p_hostname, length(rule.value ->> 'hostname') + 1
          ) = '.' || (rule.value ->> 'hostname')
      )
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_webhook_url_policy_allows_endpoint_v1(
  jsonb, text, integer
) OWNER TO periapsis_webhook_url_policy_owner;
REVOKE ALL ON FUNCTION app.private_webhook_url_policy_allows_endpoint_v1(
  jsonb, text, integer
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.webhook_plain_local_delivery_authorized_v1()
RETURNS TABLE(allowed boolean)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT coalesce(
    current_setting('app.webhook_plain_local_exemption', true) = 'true'
    AND EXISTS (
      SELECT 1
      FROM ONLY public.webhook_plain_local_runtime_role_opt_ins AS opt_in
      WHERE opt_in.role_name = session_user::text
        AND opt_in.enabled
    ),
    false
  );
$function$;--> statement-breakpoint
ALTER FUNCTION app.webhook_plain_local_delivery_authorized_v1()
  OWNER TO periapsis_webhook_url_policy_owner;
REVOKE ALL ON FUNCTION app.webhook_plain_local_delivery_authorized_v1()
  FROM PUBLIC, periapsis_worker, periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.webhook_plain_local_delivery_authorized_v1()
  TO periapsis_api, periapsis_notifier,
     periapsis_notification_admin_owner,
     periapsis_notification_dispatch_owner;--> statement-breakpoint

CREATE FUNCTION app.get_local_webhook_delivery_authorization_v1(
  p_tenant_id uuid
)
RETURNS TABLE(allowed boolean)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  deployment_allowed boolean;
BEGIN
  IF p_tenant_id IS NULL
     OR uuid_extract_version(p_tenant_id) IS DISTINCT FROM 7 THEN
    RAISE EXCEPTION 'local webhook delivery tenant is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.tenant_id', p_tenant_id::text, true);
  SELECT gate.allowed INTO STRICT deployment_allowed
  FROM app.webhook_plain_local_delivery_authorized_v1() AS gate;
  RETURN QUERY SELECT deployment_allowed AND EXISTS (
    SELECT 1 FROM ONLY public.tenants AS tenant
    WHERE tenant.id = p_tenant_id AND tenant.status = 'active'
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.get_local_webhook_delivery_authorization_v1(uuid)
  OWNER TO periapsis_notification_dispatch_owner;
REVOKE ALL ON FUNCTION app.get_local_webhook_delivery_authorization_v1(uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.get_local_webhook_delivery_authorization_v1(uuid)
  TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.private_pin_tenant_notification_webhook_url_policy_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  endpoint record;
  policy_record record;
  local_allowed boolean;
BEGIN
  IF TG_OP <> 'INSERT'
     OR NEW.tenant_id IS DISTINCT FROM context_tenant
     OR NEW.endpoint_url IS NULL
     OR NEW.endpoint_canonical_url IS NOT NULL
     OR NEW.endpoint_digest IS NOT NULL
     OR NEW.webhook_url_policy_id IS NOT NULL
     OR NEW.webhook_url_policy_version_id IS NOT NULL
     OR NEW.webhook_url_policy_version IS NOT NULL
     OR NEW.webhook_url_policy_digest IS NOT NULL
     OR NEW.local_development_exemption THEN
    RAISE EXCEPTION 'webhook configuration URL policy fields are server-owned'
      USING ERRCODE = '42501';
  END IF;

  SELECT canonical.* INTO STRICT endpoint
  FROM app.private_canonical_webhook_endpoint_v1(
    NEW.endpoint_url, true
  ) AS canonical;
  NEW.endpoint_url := endpoint.canonical_url;
  NEW.endpoint_canonical_url := endpoint.canonical_url;
  NEW.endpoint_digest := endpoint.endpoint_digest;

  IF endpoint.local_development THEN
    SELECT local_gate.allowed INTO STRICT local_allowed
    FROM app.webhook_plain_local_delivery_authorized_v1() AS local_gate;
    IF NOT local_allowed THEN
      RAISE EXCEPTION 'plain local webhook delivery is not deployment-authorized'
        USING ERRCODE = '42501';
    END IF;
    NEW.local_development_exemption := true;
    RETURN NEW;
  END IF;

  SELECT state.id AS policy_id,
         state.current_version AS policy_version,
         policy.id AS policy_version_id,
         policy.rules,
         policy.policy_digest
  INTO policy_record
  FROM ONLY public.tenant_webhook_url_policies AS state
  JOIN ONLY public.tenant_webhook_url_policy_versions AS policy
    ON policy.tenant_id = state.tenant_id
   AND policy.policy_id = state.id
   AND policy.version = state.current_version
  WHERE state.tenant_id = context_tenant
  FOR SHARE OF state;
  IF NOT FOUND OR NOT app.private_webhook_url_policy_allows_endpoint_v1(
       policy_record.rules, endpoint.hostname, endpoint.port
     ) THEN
    RAISE EXCEPTION 'webhook endpoint is denied by the current URL policy'
      USING ERRCODE = '42501';
  END IF;
  NEW.webhook_url_policy_id := policy_record.policy_id;
  NEW.webhook_url_policy_version_id := policy_record.policy_version_id;
  NEW.webhook_url_policy_version := policy_record.policy_version;
  NEW.webhook_url_policy_digest := policy_record.policy_digest;
  NEW.local_development_exemption := false;
  RETURN NEW;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_pin_tenant_notification_webhook_url_policy_v1()
  OWNER TO periapsis_webhook_url_policy_owner;
REVOKE ALL ON FUNCTION
  app.private_pin_tenant_notification_webhook_url_policy_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
     periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER tenant_notification_webhook_versions_url_policy_pin_v1
BEFORE INSERT ON public.tenant_notification_webhook_configuration_versions
FOR EACH ROW EXECUTE FUNCTION
  app.private_pin_tenant_notification_webhook_url_policy_v1();--> statement-breakpoint

CREATE FUNCTION app.private_append_webhook_url_policy_audit_v1(
  p_event_id uuid,
  p_policy_id uuid,
  p_prior_version integer,
  p_result_version integer,
  p_result_rule_count integer,
  p_reason text,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_user uuid := app.context_user_id();
BEGIN
  PERFORM app.current_tenant_membership_id();
  IF p_event_id IS NULL OR uuid_extract_version(p_event_id) IS DISTINCT FROM 7
     OR p_policy_id IS NULL OR uuid_extract_version(p_policy_id) IS DISTINCT FROM 7
     OR p_prior_version NOT BETWEEN 0 AND 2147483646
     OR p_result_version IS DISTINCT FROM p_prior_version + 1
     OR p_result_rule_count NOT BETWEEN 0 AND 256
     OR p_reason IS NULL OR p_reason <> btrim(p_reason)
     OR octet_length(p_reason) NOT BETWEEN 1 AND 2048
     OR p_reason ~ '[^ -~]' OR position(',' IN p_reason) > 0
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL
     OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL
     OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR p_user_agent ~ '[[:cntrl:]]'
     OR p_user_agent ~ U&'[\00AD\061C\180E\200B-\200F\202A-\202E\2060-\206F\FEFF]'
     OR p_authentication_method NOT IN (
       'bootstrap_totp', 'totp', 'recovery_code', 'ldap',
       'oidc', 'saml', 'passkey'
     ) THEN
    RAISE EXCEPTION 'webhook URL policy audit envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.audit_events (
    id, tenant_id, sequence, actor_type, actor_user_id,
    action, resource_type, resource_id, request_id, correlation_id,
    ip_address, user_agent, authentication_method, outcome, reason,
    before, after, metadata
  ) VALUES (
    p_event_id, app.context_tenant_id(), 0, 'user', actor_user,
    'tenant.notification.webhook_url_policy.publish',
    'tenant_webhook_url_policy', p_policy_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success', p_reason,
    jsonb_build_object(
      'version', p_prior_version, 'contentRedacted', true
    ),
    jsonb_build_object(
      'version', p_result_version, 'ruleCount', p_result_rule_count,
      'scheme', 'https', 'defaultAction', 'deny',
      'contentRedacted', true
    ),
    jsonb_build_object('projectionVersion', 1, 'contentRedacted', true)
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_append_webhook_url_policy_audit_v1(
  uuid, uuid, integer, integer, integer, text,
  uuid, uuid, inet, text, text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_append_webhook_url_policy_audit_v1(
  uuid, uuid, integer, integer, integer, text,
  uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.private_append_webhook_url_policy_audit_v1(
  uuid, uuid, integer, integer, integer, text,
  uuid, uuid, inet, text, text
) TO periapsis_webhook_url_policy_owner;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION
  app.require_live_audit_session_v1(uuid, uuid),
  app.context_tenant_id(),
  app.context_user_id(),
  app.current_tenant_membership_id(),
  app.current_tenant_human_has_exact_permission_v3(
    text, public.authorization_scope
  ),
  app.lock_current_tenant_authorization_state(),
  app.private_webhook_url_policy_projection_v1(uuid, uuid, integer),
  app.private_webhook_url_policy_allows_endpoint_v1(jsonb, text, integer),
  app.private_canonical_webhook_endpoint_v1(text, boolean)
TO periapsis_webhook_url_policy_owner;--> statement-breakpoint

CREATE FUNCTION app.get_tenant_webhook_url_policy_v1(
  p_session_id uuid,
  p_authentication_method text
)
RETURNS TABLE(policy jsonb)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
BEGIN
  IF app.require_live_audit_session_v1(p_session_id, context_tenant)
       IS DISTINCT FROM p_authentication_method
     OR NOT app.current_tenant_human_has_exact_permission_v3(
       'notification.manage', 'tenant'
     ) THEN
    RAISE EXCEPTION 'tenant notification manage permission is required'
      USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT app.private_webhook_url_policy_projection_v1(
    state.tenant_id, state.id, state.current_version
  )
  FROM ONLY public.tenant_webhook_url_policies AS state
  WHERE state.tenant_id = context_tenant;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'webhook URL policy is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.get_tenant_webhook_url_policy_v1(uuid, text)
  OWNER TO periapsis_webhook_url_policy_owner;
REVOKE ALL ON FUNCTION app.get_tenant_webhook_url_policy_v1(uuid, text)
  FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.get_tenant_webhook_url_policy_v1(uuid, text)
  TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.prepare_publish_tenant_webhook_url_policy_v1(
  p_session_id uuid,
  p_authentication_method text,
  p_key_digest bytea,
  p_request_digest bytea
)
RETURNS TABLE(replayed boolean, policy jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_user uuid := app.context_user_id();
  actor_membership uuid;
  command_record public.tenant_webhook_url_policy_commands%ROWTYPE;
BEGIN
  IF p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32 THEN
    RAISE EXCEPTION 'webhook URL policy command envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.lock_current_tenant_authorization_state();
  IF app.require_live_audit_session_v1(p_session_id, context_tenant)
       IS DISTINCT FROM p_authentication_method
     OR NOT app.current_tenant_human_has_exact_permission_v3(
       'notification.manage', 'tenant'
     ) THEN
    RAISE EXCEPTION 'tenant notification manage permission is required'
      USING ERRCODE = '42501';
  END IF;
  actor_membership := app.current_tenant_membership_id();
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':webhook-url-policy', 0
  ));
  SELECT command.* INTO command_record
  FROM ONLY public.tenant_webhook_url_policy_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_user_id = actor_user
    AND command.operation = 'webhook_url_policy.publish'
    AND command.key_digest = p_key_digest
  FOR SHARE;
  IF FOUND THEN
    IF command_record.request_digest IS DISTINCT FROM p_request_digest
       OR command_record.actor_membership_id IS DISTINCT FROM actor_membership THEN
      RAISE EXCEPTION 'webhook URL policy idempotency key conflicts'
        USING ERRCODE = '23505',
              CONSTRAINT = 'tenant_webhook_url_policy_commands_pkey';
    END IF;
    RETURN QUERY SELECT true,
      app.private_webhook_url_policy_projection_v1(
        context_tenant, command_record.result_policy_id,
        command_record.result_version
      );
    RETURN;
  END IF;
  RETURN QUERY
  SELECT false, app.private_webhook_url_policy_projection_v1(
    state.tenant_id, state.id, state.current_version
  )
  FROM ONLY public.tenant_webhook_url_policies AS state
  WHERE state.tenant_id = context_tenant
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false, NULL::jsonb;
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.prepare_publish_tenant_webhook_url_policy_v1(
  uuid, text, bytea, bytea
) OWNER TO periapsis_webhook_url_policy_owner;
REVOKE ALL ON FUNCTION app.prepare_publish_tenant_webhook_url_policy_v1(
  uuid, text, bytea, bytea
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.prepare_publish_tenant_webhook_url_policy_v1(
  uuid, text, bytea, bytea
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.commit_publish_tenant_webhook_url_policy_v1(
  p_session_id uuid,
  p_authentication_method text,
  p_expected_version integer,
  p_key_digest bytea,
  p_request_digest bytea,
  p_policy_id uuid,
  p_version_id uuid,
  p_rules jsonb,
  p_semantic_digest bytea,
  p_policy_digest bytea,
  p_published_at timestamptz,
  p_reason text,
  p_audit_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_publisher_membership_id uuid
)
RETURNS TABLE(policy jsonb, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_user uuid := app.context_user_id();
  actor_membership uuid;
  operation_at timestamptz := transaction_timestamp();
  canonical_rules jsonb;
  command_record public.tenant_webhook_url_policy_commands%ROWTYPE;
  current_record record;
  result_version integer := p_expected_version + 1;
BEGIN
  canonical_rules := app.private_canonical_webhook_url_policy_rules_v1(p_rules);
  IF p_expected_version NOT BETWEEN 0 AND 2147483646
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_policy_id IS NULL OR uuid_extract_version(p_policy_id) IS DISTINCT FROM 7
     OR p_version_id IS NULL OR uuid_extract_version(p_version_id) IS DISTINCT FROM 7
     OR p_policy_id = p_version_id
     OR p_rules IS DISTINCT FROM canonical_rules
     OR p_semantic_digest IS NULL OR octet_length(p_semantic_digest) <> 32
     OR p_semantic_digest IS DISTINCT FROM
          app.private_webhook_url_policy_semantic_digest_v1(canonical_rules)
     OR p_policy_digest IS NULL OR octet_length(p_policy_digest) <> 32
     OR p_policy_digest IS DISTINCT FROM
          app.private_webhook_url_policy_version_digest_v1(
            context_tenant, p_policy_id, p_version_id, result_version,
            p_publisher_membership_id, p_published_at, p_semantic_digest
          )
     OR p_published_at IS NULL
     OR date_trunc('milliseconds', p_published_at) <> p_published_at
     OR extract(year from p_published_at AT TIME ZONE 'UTC') NOT BETWEEN 2000 AND 9999
     OR p_published_at > operation_at + interval '1 minute'
     OR p_reason IS NULL OR p_reason <> btrim(p_reason)
     OR octet_length(p_reason) NOT BETWEEN 1 AND 2048
     OR p_reason ~ '[^ -~]' OR position(',' IN p_reason) > 0
     OR p_audit_id IS NULL OR uuid_extract_version(p_audit_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL
     OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL
     OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR p_user_agent ~ '[[:cntrl:]]'
     OR p_user_agent ~ U&'[\00AD\061C\180E\200B-\200F\202A-\202E\2060-\206F\FEFF]'
     OR p_publisher_membership_id IS NULL
     OR uuid_extract_version(p_publisher_membership_id) IS DISTINCT FROM 7 THEN
    RAISE EXCEPTION 'webhook URL policy publication is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.lock_current_tenant_authorization_state();
  IF app.require_live_audit_session_v1(p_session_id, context_tenant)
       IS DISTINCT FROM p_authentication_method
     OR NOT app.current_tenant_human_has_exact_permission_v3(
       'notification.manage', 'tenant'
     ) THEN
    RAISE EXCEPTION 'tenant notification manage permission is required'
      USING ERRCODE = '42501';
  END IF;
  actor_membership := app.current_tenant_membership_id();
  IF actor_membership IS DISTINCT FROM p_publisher_membership_id THEN
    RAISE EXCEPTION 'webhook URL policy publisher is not current'
      USING ERRCODE = '42501';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':webhook-url-policy', 0
  ));

  SELECT command.* INTO command_record
  FROM ONLY public.tenant_webhook_url_policy_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_user_id = actor_user
    AND command.operation = 'webhook_url_policy.publish'
    AND command.key_digest = p_key_digest
  FOR SHARE;
  IF FOUND THEN
    IF command_record.request_digest IS DISTINCT FROM p_request_digest
       OR command_record.actor_membership_id IS DISTINCT FROM actor_membership THEN
      RAISE EXCEPTION 'webhook URL policy idempotency key conflicts'
        USING ERRCODE = '23505',
              CONSTRAINT = 'tenant_webhook_url_policy_commands_pkey';
    END IF;
    RETURN QUERY SELECT
      app.private_webhook_url_policy_projection_v1(
        context_tenant, command_record.result_policy_id,
        command_record.result_version
      ), true;
    RETURN;
  END IF;

  SELECT state.id, state.current_version, state.created_at, state.updated_at,
         version.published_at, version.semantic_digest
  INTO current_record
  FROM ONLY public.tenant_webhook_url_policies AS state
  JOIN ONLY public.tenant_webhook_url_policy_versions AS version
    ON version.tenant_id = state.tenant_id
   AND version.policy_id = state.id
   AND version.version = state.current_version
  WHERE state.tenant_id = context_tenant
  FOR UPDATE OF state;

  IF p_expected_version = 0 THEN
    IF FOUND OR result_version <> 1 THEN
      RAISE EXCEPTION 'webhook URL policy changed concurrently'
        USING ERRCODE = '40001';
    END IF;
  ELSE
    IF NOT FOUND
       OR current_record.id IS DISTINCT FROM p_policy_id
       OR current_record.current_version IS DISTINCT FROM p_expected_version THEN
      RAISE EXCEPTION 'webhook URL policy changed concurrently'
        USING ERRCODE = '40001';
    END IF;
    IF current_record.semantic_digest IS NOT DISTINCT FROM p_semantic_digest THEN
      RAISE EXCEPTION 'webhook URL policy publication has no change'
        USING ERRCODE = '23505',
              CONSTRAINT = 'tenant_webhook_url_policy_no_change';
    END IF;
    IF p_published_at < current_record.published_at THEN
      RAISE EXCEPTION 'webhook URL policy publication time regressed'
        USING ERRCODE = '22023';
    END IF;
  END IF;

  INSERT INTO public.tenant_webhook_url_policy_versions (
    id, tenant_id, policy_id, version, rules, semantic_digest,
    policy_digest, published_by_membership_id, published_at
  ) VALUES (
    p_version_id, context_tenant, p_policy_id, result_version,
    canonical_rules, p_semantic_digest, p_policy_digest,
    actor_membership, p_published_at
  );
  IF p_expected_version = 0 THEN
    INSERT INTO public.tenant_webhook_url_policies (
      id, tenant_id, current_version, created_at, updated_at
    ) VALUES (
      p_policy_id, context_tenant, result_version,
      p_published_at, greatest(operation_at, p_published_at)
    );
  ELSE
    UPDATE ONLY public.tenant_webhook_url_policies AS state
    SET current_version = result_version,
        updated_at = greatest(state.updated_at, operation_at, p_published_at)
    WHERE state.tenant_id = context_tenant
      AND state.id = p_policy_id
      AND state.current_version = p_expected_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'webhook URL policy changed concurrently'
        USING ERRCODE = '40001';
    END IF;
  END IF;
  INSERT INTO public.tenant_webhook_url_policy_commands (
    tenant_id, actor_user_id, actor_membership_id, operation,
    key_digest, request_digest, result_policy_id, result_version_id,
    result_version, created_at, expires_at
  ) VALUES (
    context_tenant, actor_user, actor_membership,
    'webhook_url_policy.publish', p_key_digest, p_request_digest,
    p_policy_id, p_version_id, result_version,
    operation_at, operation_at + interval '24 hours'
  );
  PERFORM app.private_append_webhook_url_policy_audit_v1(
    p_audit_id, p_policy_id, p_expected_version, result_version,
    jsonb_array_length(canonical_rules), p_reason,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method
  );
  RETURN QUERY SELECT
    app.private_webhook_url_policy_projection_v1(
      context_tenant, p_policy_id, result_version
    ), false;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.commit_publish_tenant_webhook_url_policy_v1(
  uuid, text, integer, bytea, bytea, uuid, uuid, jsonb,
  bytea, bytea, timestamptz, text, uuid, uuid, uuid, inet, text, uuid
) OWNER TO periapsis_webhook_url_policy_owner;
REVOKE ALL ON FUNCTION app.commit_publish_tenant_webhook_url_policy_v1(
  uuid, text, integer, bytea, bytea, uuid, uuid, jsonb,
  bytea, bytea, timestamptz, text, uuid, uuid, uuid, inet, text, uuid
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.commit_publish_tenant_webhook_url_policy_v1(
  uuid, text, integer, bytea, bytea, uuid, uuid, jsonb,
  bytea, bytea, timestamptz, text, uuid, uuid, uuid, inet, text, uuid
) TO periapsis_api;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION
  app.private_webhook_url_policy_hostname_valid_v1(text),
  app.private_webhook_url_policy_framed_digest_v1(bytea[]),
  app.private_canonical_webhook_url_policy_rules_v1(jsonb),
  app.private_webhook_url_policy_semantic_digest_v1(jsonb),
  app.private_webhook_url_policy_version_digest_v1(
    uuid, uuid, uuid, integer, uuid, timestamptz, bytea
  ),
  app.private_canonical_webhook_endpoint_v1(text, boolean),
  app.private_webhook_url_policy_projection_v1(uuid, uuid, integer),
  app.private_webhook_url_policy_allows_endpoint_v1(jsonb, text, integer)
TO periapsis_notification_dispatch_owner;--> statement-breakpoint

CREATE FUNCTION app.get_current_webhook_url_policy_for_delivery_v1(
  p_tenant_id uuid,
  p_policy_id uuid
)
RETURNS TABLE(policy jsonb)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  ignored text;
BEGIN
  IF p_tenant_id IS NULL
     OR uuid_extract_version(p_tenant_id) IS DISTINCT FROM 7
     OR p_policy_id IS NULL
     OR uuid_extract_version(p_policy_id) IS DISTINCT FROM 7 THEN
    RAISE EXCEPTION 'webhook URL policy delivery coordinate is invalid'
      USING ERRCODE = '22023';
  END IF;
  ignored := set_config('app.tenant_id', p_tenant_id::text, true);
  RETURN QUERY
  SELECT CASE WHEN EXISTS (
      SELECT 1 FROM ONLY public.tenants AS tenant
      WHERE tenant.id = p_tenant_id AND tenant.status = 'active'
    ) THEN app.private_webhook_url_policy_projection_v1(
      state.tenant_id, state.id, state.current_version
    ) ELSE NULL::jsonb END
  FROM (SELECT 1) AS singleton
  LEFT JOIN ONLY public.tenant_webhook_url_policies AS state
    ON state.tenant_id = p_tenant_id AND state.id = p_policy_id;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.get_current_webhook_url_policy_for_delivery_v1(uuid, uuid)
  OWNER TO periapsis_notification_dispatch_owner;
REVOKE ALL ON FUNCTION
  app.get_current_webhook_url_policy_for_delivery_v1(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;
GRANT EXECUTE ON FUNCTION
  app.get_current_webhook_url_policy_for_delivery_v1(uuid, uuid)
TO periapsis_notifier;--> statement-breakpoint

ALTER FUNCTION app.claim_notification_webhook_delivery_batch_v1(
  text, integer, integer, timestamptz
) RENAME TO private_claim_notification_webhook_delivery_batch_legacy_0227;--> statement-breakpoint
REVOKE ALL ON FUNCTION
  app.private_claim_notification_webhook_delivery_batch_legacy_0227(
    text, integer, integer, timestamptz
  )
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
     periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.claim_notification_webhook_delivery_batch_v1(
  p_worker_id text,
  p_limit integer,
  p_lease_duration_ms integer,
  p_now timestamptz
)
RETURNS TABLE(claim jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  legacy_record record;
  configuration_record record;
  endpoint_record record;
  policy_record record;
  local_allowed boolean;
  valid_pin boolean;
  policy_projection jsonb;
  claim_tenant uuid;
  claim_delivery uuid;
  claim_configuration uuid;
  claim_configuration_version integer;
  claim_fence uuid;
BEGIN
  IF p_worker_id IS NULL
     OR p_worker_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
     OR p_limit NOT BETWEEN 1 AND 100
     OR p_lease_duration_ms NOT BETWEEN 5000 AND 300000
     OR p_now IS NULL
     OR p_now < transaction_timestamp() - interval '1 minute'
     OR p_now > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'notification webhook claim input is invalid'
      USING ERRCODE = '22023';
  END IF;
  FOR legacy_record IN
    SELECT legacy.claim
    FROM app.private_claim_notification_webhook_delivery_batch_legacy_0227(
      p_worker_id, p_limit, p_lease_duration_ms, p_now
    ) AS legacy
  LOOP
    valid_pin := false;
    policy_projection := NULL;
    claim_tenant := (legacy_record.claim ->> 'tenantId')::uuid;
    claim_delivery := (legacy_record.claim ->> 'id')::uuid;
    claim_configuration :=
      (legacy_record.claim ->> 'configurationId')::uuid;
    claim_configuration_version :=
      (legacy_record.claim ->> 'configurationVersion')::integer;
    claim_fence := (legacy_record.claim ->> 'fenceToken')::uuid;
    PERFORM set_config('app.tenant_id', claim_tenant::text, true);

    SELECT version.* INTO configuration_record
    FROM ONLY public.tenant_notification_webhook_configuration_versions
      AS version
    WHERE version.tenant_id = claim_tenant
      AND version.configuration_id = claim_configuration
      AND version.version = claim_configuration_version;
    IF FOUND THEN
      SELECT canonical.* INTO endpoint_record
      FROM app.private_canonical_webhook_endpoint_v1(
        configuration_record.endpoint_canonical_url, true
      ) AS canonical;
      valid_pin := configuration_record.endpoint_url
          = endpoint_record.canonical_url
        AND configuration_record.endpoint_canonical_url
          = endpoint_record.canonical_url
        AND configuration_record.endpoint_digest
          = endpoint_record.endpoint_digest;

      IF valid_pin AND configuration_record.local_development_exemption THEN
        SELECT local_gate.allowed INTO STRICT local_allowed
        FROM app.get_local_webhook_delivery_authorization_v1(claim_tenant)
          AS local_gate;
        valid_pin := endpoint_record.local_development AND local_allowed
          AND configuration_record.webhook_url_policy_id IS NULL
          AND configuration_record.webhook_url_policy_version_id IS NULL
          AND configuration_record.webhook_url_policy_version IS NULL
          AND configuration_record.webhook_url_policy_digest IS NULL;
      ELSIF valid_pin AND NOT configuration_record.local_development_exemption
            AND NOT endpoint_record.local_development THEN
        SELECT state.id AS policy_id,
               state.current_version AS policy_version,
               version.id AS policy_version_id,
               version.rules,
               version.policy_digest
        INTO policy_record
        FROM ONLY public.tenant_webhook_url_policies AS state
        JOIN ONLY public.tenant_webhook_url_policy_versions AS version
          ON version.tenant_id = state.tenant_id
         AND version.policy_id = state.id
         AND version.version = state.current_version
        JOIN ONLY public.tenants AS tenant ON tenant.id = state.tenant_id
        WHERE state.tenant_id = claim_tenant
          AND state.id = configuration_record.webhook_url_policy_id
          AND state.current_version
            = configuration_record.webhook_url_policy_version
          AND version.id
            = configuration_record.webhook_url_policy_version_id
          AND version.policy_digest
            = configuration_record.webhook_url_policy_digest
          AND tenant.status = 'active';
        valid_pin := FOUND AND app.private_webhook_url_policy_allows_endpoint_v1(
          policy_record.rules, endpoint_record.hostname, endpoint_record.port
        );
        IF valid_pin THEN
          policy_projection :=
            app.private_webhook_url_policy_projection_v1(
              claim_tenant, policy_record.policy_id,
              policy_record.policy_version
            );
          valid_pin := policy_projection IS NOT NULL;
        END IF;
      ELSE
        valid_pin := false;
      END IF;
    END IF;

    IF valid_pin THEN
      claim := legacy_record.claim || jsonb_build_object(
        'endpointUrl', configuration_record.endpoint_canonical_url,
        'endpointDigest', encode(
          configuration_record.endpoint_digest, 'hex'
        ),
        'policyDigest', CASE
          WHEN configuration_record.webhook_url_policy_digest IS NULL
          THEN NULL
          ELSE encode(configuration_record.webhook_url_policy_digest, 'hex')
        END,
        'localDevelopmentExemption',
          configuration_record.local_development_exemption,
        'urlPolicy', policy_projection
      );
      RETURN NEXT;
    ELSE
      UPDATE public.tenant_notification_delivery_attempts AS attempt
      SET completed_at = p_now,
          outcome = 'fenced',
          failure_class = 'security'
      WHERE attempt.tenant_id = claim_tenant
        AND attempt.delivery_id = claim_delivery
        AND attempt.fence_token = claim_fence
        AND attempt.completed_at IS NULL
        AND attempt.outcome IS NULL;
      UPDATE public.tenant_notification_deliveries AS delivery
      SET status = 'dead_lettered',
          next_attempt_at = NULL,
          lease_owner = NULL,
          fence_token = NULL,
          lease_until = NULL,
          failure_at = p_now,
          failure_class = 'security',
          failure_code = 'configuration_revoked',
          updated_at = p_now
      WHERE delivery.tenant_id = claim_tenant
        AND delivery.id = claim_delivery
        AND delivery.status = 'leased'
        AND delivery.fence_token = claim_fence;
    END IF;
  END LOOP;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.claim_notification_webhook_delivery_batch_v1(
  text, integer, integer, timestamptz
) OWNER TO periapsis_notification_dispatch_owner;
REVOKE ALL ON FUNCTION app.claim_notification_webhook_delivery_batch_v1(
  text, integer, integer, timestamptz
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.claim_notification_webhook_delivery_batch_v1(
  text, integer, integer, timestamptz
) TO periapsis_notifier;--> statement-breakpoint

DO $webhook_url_policy_security_contract$
DECLARE
  relation_name text;
BEGIN
  IF NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_roles AS role
       WHERE role.rolname = 'periapsis_webhook_url_policy_owner'
         AND NOT role.rolcanlogin AND NOT role.rolsuper
         AND NOT role.rolcreatedb AND NOT role.rolcreaterole
         AND NOT role.rolreplication AND NOT role.rolbypassrls
     ) THEN
    RAISE EXCEPTION 'webhook URL policy owner is not least privileged'
      USING ERRCODE = '55000';
  END IF;
  FOREACH relation_name IN ARRAY ARRAY[
    'tenant_webhook_url_policy_versions',
    'tenant_webhook_url_policies',
    'tenant_webhook_url_policy_commands',
    'webhook_plain_local_runtime_role_opt_ins'
  ] LOOP
    IF NOT EXISTS (
         SELECT 1
         FROM pg_catalog.pg_class AS relation
         JOIN pg_catalog.pg_namespace AS namespace
           ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
           AND relation.relname = relation_name
           AND relation.relrowsecurity
           AND relation.relforcerowsecurity
           AND pg_get_userbyid(relation.relowner)
             = 'periapsis_webhook_url_policy_owner'
       ) THEN
      RAISE EXCEPTION 'webhook URL policy table % is not forced-RLS owned',
        relation_name USING ERRCODE = '55000';
    END IF;
  END LOOP;
  IF has_table_privilege(
       'periapsis_api', 'public.tenant_webhook_url_policy_versions', 'SELECT'
     ) OR has_table_privilege(
       'periapsis_api', 'public.tenant_webhook_url_policies', 'SELECT'
     ) OR has_table_privilege(
       'periapsis_api', 'public.tenant_webhook_url_policy_commands', 'SELECT'
     ) OR has_table_privilege(
       'periapsis_notifier', 'public.tenant_webhook_url_policy_commands', 'SELECT'
     ) OR has_table_privilege(
       'periapsis_api', 'public.webhook_plain_local_runtime_role_opt_ins', 'INSERT'
     ) OR has_table_privilege(
       'periapsis_api', 'public.webhook_plain_local_runtime_role_opt_ins', 'UPDATE'
     ) OR has_table_privilege(
       'periapsis_api', 'public.webhook_plain_local_runtime_role_opt_ins', 'DELETE'
     ) OR has_table_privilege(
       'periapsis_notifier', 'public.webhook_plain_local_runtime_role_opt_ins', 'INSERT'
     ) OR has_table_privilege(
       'periapsis_notifier', 'public.webhook_plain_local_runtime_role_opt_ins', 'UPDATE'
     ) OR has_table_privilege(
       'periapsis_notifier', 'public.webhook_plain_local_runtime_role_opt_ins', 'DELETE'
     ) OR has_table_privilege(
       'periapsis_migrator', 'public.webhook_plain_local_runtime_role_opt_ins', 'INSERT'
     ) OR has_table_privilege(
       'periapsis_migrator', 'public.webhook_plain_local_runtime_role_opt_ins', 'UPDATE'
     ) OR has_table_privilege(
       'periapsis_migrator', 'public.webhook_plain_local_runtime_role_opt_ins', 'DELETE'
     ) THEN
    RAISE EXCEPTION 'webhook URL policy direct privileges are too broad'
      USING ERRCODE = '55000';
  END IF;
  IF NOT has_table_privilege(
       'periapsis_api', 'public.webhook_plain_local_runtime_role_opt_ins', 'SELECT'
     ) OR NOT has_table_privilege(
       'periapsis_notifier', 'public.webhook_plain_local_runtime_role_opt_ins', 'SELECT'
     ) OR NOT has_function_privilege(
       'periapsis_api',
       'app.get_tenant_webhook_url_policy_v1(uuid,text)', 'EXECUTE'
     ) OR NOT has_function_privilege(
       'periapsis_api',
       'app.prepare_publish_tenant_webhook_url_policy_v1(uuid,text,bytea,bytea)',
       'EXECUTE'
     ) OR NOT has_function_privilege(
       'periapsis_api',
       'app.commit_publish_tenant_webhook_url_policy_v1(uuid,text,integer,bytea,bytea,uuid,uuid,jsonb,bytea,bytea,timestamptz,text,uuid,uuid,uuid,inet,text,uuid)',
       'EXECUTE'
     ) OR NOT has_function_privilege(
       'periapsis_notifier',
       'app.get_local_webhook_delivery_authorization_v1(uuid)',
       'EXECUTE'
     ) OR NOT has_function_privilege(
       'periapsis_notifier',
       'app.claim_notification_webhook_delivery_batch_v1(text,integer,integer,timestamptz)',
       'EXECUTE'
     ) OR has_function_privilege(
       'periapsis_notifier',
       'app.private_claim_notification_webhook_delivery_batch_legacy_0227(text,integer,integer,timestamptz)',
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'webhook URL policy ABI privilege contract is incomplete'
      USING ERRCODE = '55000';
  END IF;
END;
$webhook_url_policy_security_contract$;--> statement-breakpoint
