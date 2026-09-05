CREATE TYPE "public"."ticket_numbering_period" AS ENUM('annual', 'lifetime');--> statement-breakpoint
CREATE TABLE "tenant_ticket_numbering_commands" (
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"aggregate_kind" "ticket_aggregate_kind" NOT NULL,
	"operation" text NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "tenant_ticket_numbering_commands_pkey" PRIMARY KEY("tenant_id","user_id","aggregate_kind","operation","key_digest"),
	CONSTRAINT "tenant_ticket_numbering_commands_envelope_check" CHECK ("tenant_ticket_numbering_commands"."operation" = 'ticket_numbering.policy.replace'
        and octet_length("tenant_ticket_numbering_commands"."key_digest") = 32
        and octet_length("tenant_ticket_numbering_commands"."request_digest") = 32
        and jsonb_typeof("tenant_ticket_numbering_commands"."result") = 'object'
        and octet_length("tenant_ticket_numbering_commands"."result"::text) <= 8192
        and "tenant_ticket_numbering_commands"."expires_at" > "tenant_ticket_numbering_commands"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_ticket_numbering_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ticket_numbering_policies" (
	"tenant_id" uuid NOT NULL,
	"aggregate_kind" "ticket_aggregate_kind" NOT NULL,
	"current_version" integer NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_ticket_numbering_policies_pkey" PRIMARY KEY("tenant_id","aggregate_kind"),
	CONSTRAINT "tenant_ticket_numbering_policies_revision_check" CHECK ("tenant_ticket_numbering_policies"."current_version" between 1 and 2147483647)
);
--> statement-breakpoint
ALTER TABLE "tenant_ticket_numbering_policies" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ticket_numbering_policy_versions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"aggregate_kind" "ticket_aggregate_kind" NOT NULL,
	"version" integer NOT NULL,
	"prefix" text NOT NULL,
	"separator" text NOT NULL,
	"period" "ticket_numbering_period" NOT NULL,
	"width" integer NOT NULL,
	"start" bigint NOT NULL,
	"namespace_digest" "bytea" NOT NULL,
	"published_by_membership_id" uuid,
	"published_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_ticket_numbering_policy_versions_coordinate_key" UNIQUE("tenant_id","aggregate_kind","version"),
	CONSTRAINT "tenant_ticket_numbering_policy_versions_identity_key" UNIQUE("tenant_id","aggregate_kind","id","version"),
	CONSTRAINT "tenant_ticket_numbering_policy_versions_identity_check" CHECK ((uuid_extract_version("tenant_ticket_numbering_policy_versions"."id") = 7) is true
        and "tenant_ticket_numbering_policy_versions"."version" between 1 and 2147483647
        and ("tenant_ticket_numbering_policy_versions"."version" = 1 or "tenant_ticket_numbering_policy_versions"."published_by_membership_id" is not null)),
	CONSTRAINT "tenant_ticket_numbering_policy_versions_format_check" CHECK ("tenant_ticket_numbering_policy_versions"."prefix" ~ '^[A-Z][A-Z0-9]{0,11}$'
        and "tenant_ticket_numbering_policy_versions"."separator" in ('-', '/', '.', '_')
        and "tenant_ticket_numbering_policy_versions"."width" between 4 and 12
        and "tenant_ticket_numbering_policy_versions"."start" between 1 and repeat('9', "tenant_ticket_numbering_policy_versions"."width")::bigint
        and octet_length("tenant_ticket_numbering_policy_versions"."namespace_digest") = 32)
);
--> statement-breakpoint
ALTER TABLE "tenant_ticket_numbering_policy_versions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ticket_numbering_receipts" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"aggregate_kind" "ticket_aggregate_kind" NOT NULL,
	"aggregate_id" uuid NOT NULL,
	"policy_version_id" uuid NOT NULL,
	"policy_version" integer NOT NULL,
	"namespace_digest" "bytea" NOT NULL,
	"period" integer NOT NULL,
	"sequence" bigint NOT NULL,
	"number" text NOT NULL,
	"allocated_at" timestamp with time zone NOT NULL,
	CONSTRAINT "tenant_ticket_numbering_receipts_aggregate_key" UNIQUE("tenant_id","aggregate_kind","aggregate_id"),
	CONSTRAINT "tenant_ticket_numbering_receipts_number_key" UNIQUE("tenant_id","aggregate_kind","number"),
	CONSTRAINT "tenant_ticket_numbering_receipts_sequence_key" UNIQUE("tenant_id","aggregate_kind","namespace_digest","period","sequence"),
	CONSTRAINT "tenant_ticket_numbering_receipts_identity_check" CHECK ((uuid_extract_version("tenant_ticket_numbering_receipts"."id") = 7) is true
        and (uuid_extract_version("tenant_ticket_numbering_receipts"."aggregate_id") = 7) is true
        and "tenant_ticket_numbering_receipts"."policy_version" between 1 and 2147483647),
	CONSTRAINT "tenant_ticket_numbering_receipts_value_check" CHECK (octet_length("tenant_ticket_numbering_receipts"."namespace_digest") = 32
        and ("tenant_ticket_numbering_receipts"."period" = 0 or "tenant_ticket_numbering_receipts"."period" between 2000 and 9999)
        and "tenant_ticket_numbering_receipts"."sequence" between 1 and 999999999999
        and btrim("tenant_ticket_numbering_receipts"."number") = "tenant_ticket_numbering_receipts"."number"
        and octet_length("tenant_ticket_numbering_receipts"."number") between 6 and 42
        and (
          "tenant_ticket_numbering_receipts"."number" ~ '^[A-Z][A-Z0-9]{0,11}-([0-9]{4}-)?[0-9]{4,12}$'
          or "tenant_ticket_numbering_receipts"."number" ~ '^[A-Z][A-Z0-9]{0,11}/([0-9]{4}/)?[0-9]{4,12}$'
          or "tenant_ticket_numbering_receipts"."number" ~ '^[A-Z][A-Z0-9]{0,11}\.([0-9]{4}\.)?[0-9]{4,12}$'
          or "tenant_ticket_numbering_receipts"."number" ~ '^[A-Z][A-Z0-9]{0,11}_([0-9]{4}_)?[0-9]{4,12}$'
        )
        and "tenant_ticket_numbering_receipts"."number" !~ '[[:cntrl:]]'
        and "tenant_ticket_numbering_receipts"."number" !~ U&'[\202A-\202E\2066-\2069\200E\200F\061C]')
);
--> statement-breakpoint
ALTER TABLE "tenant_ticket_numbering_receipts" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "ticket_number_counters" DROP CONSTRAINT "ticket_number_counters_key";--> statement-breakpoint
ALTER TABLE "alerts" DROP CONSTRAINT "alerts_number_check";--> statement-breakpoint
ALTER TABLE "ticket_number_counters" DROP CONSTRAINT "ticket_number_counters_period_check";--> statement-breakpoint
ALTER TABLE "ticket_number_counters" DROP CONSTRAINT "ticket_number_counters_next_value_check";--> statement-breakpoint
ALTER TABLE "cases" DROP CONSTRAINT "cases_number_check";--> statement-breakpoint
ALTER TABLE "ticket_number_counters" ALTER COLUMN "next_value" SET DATA TYPE bigint;--> statement-breakpoint
ALTER TABLE "ticket_number_counters" ALTER COLUMN "next_value" SET DEFAULT 1;--> statement-breakpoint
ALTER TABLE "ticket_number_counters" ADD COLUMN "namespace_digest" "bytea";--> statement-breakpoint
ALTER TABLE "tenant_ticket_numbering_commands" ADD CONSTRAINT "tenant_ticket_numbering_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ticket_numbering_commands" ADD CONSTRAINT "tenant_ticket_numbering_commands_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ticket_numbering_commands" ADD CONSTRAINT "tenant_ticket_numbering_commands_policy_fk" FOREIGN KEY ("tenant_id","aggregate_kind") REFERENCES "public"."tenant_ticket_numbering_policies"("tenant_id","aggregate_kind") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ticket_numbering_policies" ADD CONSTRAINT "tenant_ticket_numbering_policies_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ticket_numbering_policies" ADD CONSTRAINT "tenant_ticket_numbering_policies_current_version_fk" FOREIGN KEY ("tenant_id","aggregate_kind","current_version") REFERENCES "public"."tenant_ticket_numbering_policy_versions"("tenant_id","aggregate_kind","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ticket_numbering_policy_versions" ADD CONSTRAINT "tenant_ticket_numbering_policy_versions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ticket_numbering_policy_versions" ADD CONSTRAINT "tenant_ticket_numbering_policy_versions_publisher_fk" FOREIGN KEY ("tenant_id","published_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ticket_numbering_receipts" ADD CONSTRAINT "tenant_ticket_numbering_receipts_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ticket_numbering_receipts" ADD CONSTRAINT "tenant_ticket_numbering_receipts_policy_fk" FOREIGN KEY ("tenant_id","aggregate_kind","policy_version_id","policy_version") REFERENCES "public"."tenant_ticket_numbering_policy_versions"("tenant_id","aggregate_kind","id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "tenant_ticket_numbering_commands_expiry_idx" ON "tenant_ticket_numbering_commands" USING btree ("expires_at");--> statement-breakpoint
UPDATE public.ticket_number_counters AS counter
SET namespace_digest = pg_catalog.sha256(
  pg_catalog.convert_to('periapsis/ticket-numbering/namespace/v1', 'UTF8')
  || '\x00'::bytea
  || pg_catalog.convert_to(
       CASE counter.aggregate_kind WHEN 'alert' THEN 'ALT' ELSE 'CAS' END,
       'UTF8'
     )
  || '\x00'::bytea || pg_catalog.convert_to('-', 'UTF8')
  || '\x00'::bytea || pg_catalog.convert_to('annual', 'UTF8')
  || '\x00'::bytea || pg_catalog.convert_to('6', 'UTF8')
)
WHERE counter.namespace_digest IS NULL;--> statement-breakpoint
ALTER TABLE public.ticket_number_counters
  ALTER COLUMN namespace_digest SET NOT NULL;--> statement-breakpoint
ALTER TABLE "ticket_number_counters" ADD CONSTRAINT "ticket_number_counters_key" UNIQUE("tenant_id","aggregate_kind","namespace_digest","period");--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_number_check" CHECK (btrim("alerts"."number") = "alerts"."number"
        and octet_length("alerts"."number") between 6 and 42
        and (
          "alerts"."number" ~ '^[A-Z][A-Z0-9]{0,11}-([0-9]{4}-)?[0-9]{4,12}$'
          or "alerts"."number" ~ '^[A-Z][A-Z0-9]{0,11}/([0-9]{4}/)?[0-9]{4,12}$'
          or "alerts"."number" ~ '^[A-Z][A-Z0-9]{0,11}\.([0-9]{4}\.)?[0-9]{4,12}$'
          or "alerts"."number" ~ '^[A-Z][A-Z0-9]{0,11}_([0-9]{4}_)?[0-9]{4,12}$'
        )
        and "alerts"."number" !~ '[[:cntrl:]]'
        and "alerts"."number" !~ U&'[\202A-\202E\2066-\2069\200E\200F\061C]');--> statement-breakpoint
ALTER TABLE "ticket_number_counters" ADD CONSTRAINT "ticket_number_counters_period_check" CHECK ("ticket_number_counters"."period" = 0 or "ticket_number_counters"."period" between 2000 and 9999);--> statement-breakpoint
ALTER TABLE "ticket_number_counters" ADD CONSTRAINT "ticket_number_counters_next_value_check" CHECK ("ticket_number_counters"."next_value" between 1 and 1000000000000
        and octet_length("ticket_number_counters"."namespace_digest") = 32);--> statement-breakpoint
ALTER TABLE "cases" ADD CONSTRAINT "cases_number_check" CHECK (btrim("cases"."number") = "cases"."number"
        and octet_length("cases"."number") between 6 and 42
        and (
          "cases"."number" ~ '^[A-Z][A-Z0-9]{0,11}-([0-9]{4}-)?[0-9]{4,12}$'
          or "cases"."number" ~ '^[A-Z][A-Z0-9]{0,11}/([0-9]{4}/)?[0-9]{4,12}$'
          or "cases"."number" ~ '^[A-Z][A-Z0-9]{0,11}\.([0-9]{4}\.)?[0-9]{4,12}$'
          or "cases"."number" ~ '^[A-Z][A-Z0-9]{0,11}_([0-9]{4}_)?[0-9]{4,12}$'
        )
        and "cases"."number" !~ '[[:cntrl:]]'
        and "cases"."number" !~ U&'[\202A-\202E\2066-\2069\200E\200F\061C]');--> statement-breakpoint

-- A narrow NOBYPASSRLS owner is the only runtime principal with table DML.
DO $ticket_numbering_owner_role$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'periapsis_ticket_numbering_owner'
  ) THEN
    CREATE ROLE periapsis_ticket_numbering_owner WITH NOINHERIT;
  END IF;
END;
$ticket_numbering_owner_role$;--> statement-breakpoint
ALTER ROLE periapsis_ticket_numbering_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
  NOREPLICATION NOBYPASSRLS;
REVOKE periapsis_ticket_numbering_owner
  FROM periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;--> statement-breakpoint

ALTER TABLE public.tenant_ticket_numbering_policy_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_ticket_numbering_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_ticket_numbering_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_ticket_numbering_commands FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_number_counters FORCE ROW LEVEL SECURITY;--> statement-breakpoint

CREATE POLICY tenant_ticket_numbering_policy_versions_owner_access
  ON public.tenant_ticket_numbering_policy_versions
  AS PERMISSIVE FOR ALL TO periapsis_ticket_numbering_owner
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_ticket_numbering_policies_owner_access
  ON public.tenant_ticket_numbering_policies
  AS PERMISSIVE FOR ALL TO periapsis_ticket_numbering_owner
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_ticket_numbering_receipts_owner_access
  ON public.tenant_ticket_numbering_receipts
  AS PERMISSIVE FOR ALL TO periapsis_ticket_numbering_owner
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_ticket_numbering_commands_owner_access
  ON public.tenant_ticket_numbering_commands
  AS PERMISSIVE FOR ALL TO periapsis_ticket_numbering_owner
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY ticket_number_counters_numbering_owner_access
  ON public.ticket_number_counters
  AS PERMISSIVE FOR ALL TO periapsis_ticket_numbering_owner
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenants_ticket_numbering_owner_select
  ON public.tenants AS PERMISSIVE FOR SELECT TO periapsis_ticket_numbering_owner
  USING (id = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint

ALTER TABLE public.tenant_ticket_numbering_policy_versions OWNER TO periapsis_ticket_numbering_owner;
ALTER TABLE public.tenant_ticket_numbering_policies OWNER TO periapsis_ticket_numbering_owner;
ALTER TABLE public.tenant_ticket_numbering_receipts OWNER TO periapsis_ticket_numbering_owner;
ALTER TABLE public.tenant_ticket_numbering_commands OWNER TO periapsis_ticket_numbering_owner;
ALTER TABLE public.ticket_number_counters OWNER TO periapsis_ticket_numbering_owner;--> statement-breakpoint
REVOKE ALL ON TABLE
  public.tenant_ticket_numbering_policy_versions,
  public.tenant_ticket_numbering_policies,
  public.tenant_ticket_numbering_receipts,
  public.tenant_ticket_numbering_commands,
  public.ticket_number_counters
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
     periapsis_auditor, periapsis_audit_reader_owner;
GRANT ALL ON TABLE
  public.tenant_ticket_numbering_policy_versions,
  public.tenant_ticket_numbering_policies,
  public.tenant_ticket_numbering_receipts,
  public.tenant_ticket_numbering_commands,
  public.ticket_number_counters
TO periapsis_migrator;
GRANT SELECT ON TABLE public.tenants TO periapsis_ticket_numbering_owner;
GRANT USAGE ON SCHEMA public, app TO periapsis_ticket_numbering_owner;--> statement-breakpoint

CREATE FUNCTION app.private_ticket_numbering_namespace_digest_v1(
  p_prefix text,
  p_separator text,
  p_period public.ticket_numbering_period,
  p_width integer
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, public, app
RETURN pg_catalog.sha256(
  pg_catalog.convert_to('periapsis/ticket-numbering/namespace/v1', 'UTF8')
  || '\x00'::bytea || pg_catalog.convert_to(p_prefix, 'UTF8')
  || '\x00'::bytea || pg_catalog.convert_to(p_separator, 'UTF8')
  || '\x00'::bytea || pg_catalog.convert_to(
       CASE p_period WHEN 'annual' THEN 'annual' ELSE 'none' END, 'UTF8'
     )
  || '\x00'::bytea || pg_catalog.convert_to(p_width::text, 'UTF8')
);--> statement-breakpoint
ALTER FUNCTION app.private_ticket_numbering_namespace_digest_v1(
  text, text, public.ticket_numbering_period, integer
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_numbering_namespace_digest_v1(
  text, text, public.ticket_numbering_period, integer
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;
GRANT EXECUTE ON FUNCTION app.private_ticket_numbering_namespace_digest_v1(
  text, text, public.ticket_numbering_period, integer
) TO periapsis_ticket_numbering_owner;
GRANT EXECUTE ON FUNCTION app.context_tenant_id()
  TO periapsis_ticket_numbering_owner;--> statement-breakpoint

ALTER TABLE public.tenant_ticket_numbering_policy_versions
  ADD CONSTRAINT tenant_ticket_numbering_policy_versions_namespace_check
  CHECK (
    namespace_digest = app.private_ticket_numbering_namespace_digest_v1(
      prefix, separator, period, width
    )
  );--> statement-breakpoint

-- Version one is system-authored and therefore remains seedable for a tenant
-- that has no membership yet. Every later version is membership-authored.
CREATE FUNCTION app.private_seed_tenant_ticket_numbering_v1(p_tenant_id uuid)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  tenant_created_at timestamptz;
BEGIN
  IF p_tenant_id IS NULL OR uuid_extract_version(p_tenant_id) IS DISTINCT FROM 7
     OR p_tenant_id IS DISTINCT FROM app.context_tenant_id() THEN
    RAISE EXCEPTION 'ticket numbering seed tenant context is invalid'
      USING ERRCODE = '42501';
  END IF;
  SELECT tenant.created_at INTO tenant_created_at
  FROM ONLY public.tenants AS tenant
  WHERE tenant.id = p_tenant_id;
  IF tenant_created_at IS NULL THEN
    RAISE EXCEPTION 'tenant is required for ticket numbering seed'
      USING ERRCODE = 'P0002';
  END IF;

  INSERT INTO public.tenant_ticket_numbering_policy_versions (
    tenant_id, aggregate_kind, version, prefix, separator, period,
    width, start, namespace_digest, published_by_membership_id,
    published_at
  )
  SELECT p_tenant_id, seed.aggregate_kind, 1, seed.prefix, '-', 'annual',
         6, 1,
         app.private_ticket_numbering_namespace_digest_v1(
           seed.prefix, '-', 'annual', 6
         ),
         NULL, tenant_created_at
  FROM (VALUES
    ('alert'::public.ticket_aggregate_kind, 'ALT'::text),
    ('case'::public.ticket_aggregate_kind, 'CAS'::text)
  ) AS seed(aggregate_kind, prefix)
  ON CONFLICT (tenant_id, aggregate_kind, version) DO NOTHING;

  INSERT INTO public.tenant_ticket_numbering_policies (
    tenant_id, aggregate_kind, current_version, updated_at
  )
  SELECT p_tenant_id, seed.aggregate_kind, 1, tenant_created_at
  FROM (VALUES
    ('alert'::public.ticket_aggregate_kind),
    ('case'::public.ticket_aggregate_kind)
  ) AS seed(aggregate_kind)
  ON CONFLICT (tenant_id, aggregate_kind) DO NOTHING;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_seed_tenant_ticket_numbering_v1(uuid)
  OWNER TO periapsis_ticket_numbering_owner;
REVOKE ALL ON FUNCTION app.private_seed_tenant_ticket_numbering_v1(uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;--> statement-breakpoint

CREATE FUNCTION app.private_seed_tenant_ticket_numbering_trigger_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  prior_tenant text := current_setting('app.tenant_id', true);
BEGIN
  PERFORM set_config('app.tenant_id', NEW.id::text, true);
  PERFORM app.private_seed_tenant_ticket_numbering_v1(NEW.id);
  PERFORM set_config('app.tenant_id', coalesce(prior_tenant, ''), true);
  RETURN NEW;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_seed_tenant_ticket_numbering_trigger_v1()
  OWNER TO periapsis_ticket_numbering_owner;
REVOKE ALL ON FUNCTION app.private_seed_tenant_ticket_numbering_trigger_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;
CREATE TRIGGER tenants_seed_ticket_numbering_v1
AFTER INSERT ON public.tenants
FOR EACH ROW EXECUTE FUNCTION app.private_seed_tenant_ticket_numbering_trigger_v1();--> statement-breakpoint

DO $seed_existing_ticket_numbering$
DECLARE
  tenant_record record;
  prior_tenant text := current_setting('app.tenant_id', true);
BEGIN
  FOR tenant_record IN
    SELECT tenant.id FROM ONLY public.tenants AS tenant
    ORDER BY tenant.id
  LOOP
    PERFORM set_config('app.tenant_id', tenant_record.id::text, true);
    PERFORM app.private_seed_tenant_ticket_numbering_v1(tenant_record.id);
  END LOOP;
  PERFORM set_config('app.tenant_id', coalesce(prior_tenant, ''), true);
END;
$seed_existing_ticket_numbering$;--> statement-breakpoint

-- Legacy v1 rendered exactly six digits. Reject unexpected historical values
-- instead of silently assigning them to a namespace whose renderer disagrees.
DO $validate_legacy_ticket_numbers$
BEGIN
  IF EXISTS (
    SELECT 1 FROM ONLY public.alerts AS alert
    WHERE alert.number !~ '^ALT-[0-9]{4}-[0-9]{6}$'
  ) OR EXISTS (
    SELECT 1 FROM ONLY public.cases AS case_row
    WHERE case_row.number !~ '^CAS-[0-9]{4}-[0-9]{6}$'
  ) OR EXISTS (
    SELECT 1 FROM ONLY public.ticket_number_counters AS counter
    WHERE counter.next_value > 1000000
  ) THEN
    RAISE EXCEPTION 'legacy ticket numbering state is not representable by the default policy'
      USING ERRCODE = '55000';
  END IF;
END;
$validate_legacy_ticket_numbers$;--> statement-breakpoint

INSERT INTO public.tenant_ticket_numbering_receipts (
  tenant_id, aggregate_kind, aggregate_id, policy_version_id,
  policy_version, namespace_digest, period, sequence, number, allocated_at
)
SELECT alert.tenant_id, 'alert'::public.ticket_aggregate_kind,
       alert.id, policy.id, policy.version,
       policy.namespace_digest, split_part(alert.number, '-', 2)::integer,
       split_part(alert.number, '-', 3)::bigint, alert.number, alert.created_at
FROM ONLY public.alerts AS alert
JOIN ONLY public.tenant_ticket_numbering_policy_versions AS policy
  ON policy.tenant_id = alert.tenant_id
 AND policy.aggregate_kind = 'alert' AND policy.version = 1
UNION ALL
SELECT case_row.tenant_id, 'case'::public.ticket_aggregate_kind,
       case_row.id, policy.id, policy.version,
       policy.namespace_digest, split_part(case_row.number, '-', 2)::integer,
       split_part(case_row.number, '-', 3)::bigint, case_row.number,
       case_row.created_at
FROM ONLY public.cases AS case_row
JOIN ONLY public.tenant_ticket_numbering_policy_versions AS policy
  ON policy.tenant_id = case_row.tenant_id
 AND policy.aggregate_kind = 'case' AND policy.version = 1
ON CONFLICT (tenant_id, aggregate_kind, aggregate_id) DO NOTHING;--> statement-breakpoint

INSERT INTO public.ticket_number_counters (
  tenant_id, aggregate_kind, namespace_digest, period, next_value, updated_at
)
SELECT receipt.tenant_id, receipt.aggregate_kind, receipt.namespace_digest,
       receipt.period, max(receipt.sequence) + 1, transaction_timestamp()
FROM ONLY public.tenant_ticket_numbering_receipts AS receipt
GROUP BY receipt.tenant_id, receipt.aggregate_kind,
         receipt.namespace_digest, receipt.period
ON CONFLICT (tenant_id, aggregate_kind, namespace_digest, period)
DO UPDATE SET
  next_value = greatest(
    public.ticket_number_counters.next_value, excluded.next_value
  ),
  updated_at = greatest(
    public.ticket_number_counters.updated_at, excluded.updated_at
  );--> statement-breakpoint

DO $ticket_numbering_seed_contract$
BEGIN
  IF EXISTS (
    SELECT 1 FROM ONLY public.tenants AS tenant
    CROSS JOIN (VALUES
      ('alert'::public.ticket_aggregate_kind),
      ('case'::public.ticket_aggregate_kind)
    ) AS kind(value)
    LEFT JOIN ONLY public.tenant_ticket_numbering_policies AS policy
      ON policy.tenant_id = tenant.id AND policy.aggregate_kind = kind.value
    WHERE policy.tenant_id IS NULL
  ) OR (SELECT count(*) FROM ONLY public.tenant_ticket_numbering_receipts)
       <> (SELECT count(*) FROM ONLY public.alerts)
        + (SELECT count(*) FROM ONLY public.cases) THEN
    RAISE EXCEPTION 'ticket numbering seed contract failed'
      USING ERRCODE = '55000';
  END IF;
END;
$ticket_numbering_seed_contract$;--> statement-breakpoint

CREATE FUNCTION app.private_reject_ticket_numbering_immutable_change_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  RAISE EXCEPTION 'ticket numbering history is immutable'
    USING ERRCODE = '55000';
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_reject_ticket_numbering_immutable_change_v1()
  OWNER TO periapsis_ticket_numbering_owner;
REVOKE ALL ON FUNCTION app.private_reject_ticket_numbering_immutable_change_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;
CREATE TRIGGER tenant_ticket_numbering_policy_versions_immutable_v1
BEFORE UPDATE OR DELETE ON public.tenant_ticket_numbering_policy_versions
FOR EACH ROW EXECUTE FUNCTION app.private_reject_ticket_numbering_immutable_change_v1();
CREATE TRIGGER tenant_ticket_numbering_receipts_immutable_v1
BEFORE UPDATE OR DELETE ON public.tenant_ticket_numbering_receipts
FOR EACH ROW EXECUTE FUNCTION app.private_reject_ticket_numbering_immutable_change_v1();--> statement-breakpoint

CREATE FUNCTION app.private_allocate_ticket_number_v2(
  p_tenant_id uuid,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_aggregate_id uuid,
  p_at timestamp with time zone
)
RETURNS text
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  selected_policy record;
  prior_receipt public.tenant_ticket_numbering_receipts%ROWTYPE;
  allocation_instant timestamp with time zone;
  target_period integer;
  allocated bigint;
  maximum_sequence bigint;
  rendered text;
BEGIN
  IF p_tenant_id IS NULL OR p_aggregate_kind IS NULL OR p_aggregate_id IS NULL
     OR uuid_extract_version(p_tenant_id) IS DISTINCT FROM 7
     OR uuid_extract_version(p_aggregate_id) IS DISTINCT FROM 7
     OR p_at IS NULL OR extract(year FROM p_at AT TIME ZONE 'UTC')
                         NOT BETWEEN 2000 AND 9999
     OR p_tenant_id IS DISTINCT FROM app.context_tenant_id() THEN
    RAISE EXCEPTION 'ticket number allocation inputs are invalid'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM ONLY public.tenants AS tenant
    WHERE tenant.id = p_tenant_id AND tenant.status = 'active'
  ) THEN
    RAISE EXCEPTION 'active tenant is required for ticket number allocation'
      USING ERRCODE = '42501';
  END IF;

  PERFORM pg_advisory_xact_lock(pg_catalog.hashtextextended(
    p_tenant_id::text || ':' || p_aggregate_kind::text || ':'
      || p_aggregate_id::text || ':ticket-number', 0
  ));
  SELECT receipt.* INTO prior_receipt
  FROM ONLY public.tenant_ticket_numbering_receipts AS receipt
  WHERE receipt.tenant_id = p_tenant_id
    AND receipt.aggregate_kind = p_aggregate_kind
    AND receipt.aggregate_id = p_aggregate_id
  FOR SHARE;
  IF FOUND THEN
    RETURN prior_receipt.number;
  END IF;

  SELECT version.id, version.version, version.prefix, version.separator,
         version.period, version.width, version.start,
         version.namespace_digest, version.published_at
    INTO selected_policy
  FROM ONLY public.tenant_ticket_numbering_policies AS state
  JOIN ONLY public.tenant_ticket_numbering_policy_versions AS version
    ON version.tenant_id = state.tenant_id
   AND version.aggregate_kind = state.aggregate_kind
   AND version.version = state.current_version
  WHERE state.tenant_id = p_tenant_id
    AND state.aggregate_kind = p_aggregate_kind
  FOR SHARE OF state, version;
  IF NOT FOUND OR selected_policy.published_at > p_at + interval '1 minute' THEN
    RAISE EXCEPTION 'ticket numbering policy is unavailable at allocation time'
      USING ERRCODE = '55000';
  END IF;

  -- API and database hosts may differ by the accepted one-minute clock skew.
  -- Keep receipts hydratable by the domain model: their allocation timestamp
  -- must never precede the immutable policy publication timestamp.
  allocation_instant := greatest(p_at, selected_policy.published_at);
  IF extract(year FROM allocation_instant AT TIME ZONE 'UTC')
       NOT BETWEEN 2000 AND 9999 THEN
    RAISE EXCEPTION 'ticket number allocation instant is invalid'
      USING ERRCODE = '22023';
  END IF;

  target_period := CASE selected_policy.period
    WHEN 'annual' THEN extract(year FROM allocation_instant AT TIME ZONE 'UTC')::integer
    ELSE 0
  END;
  maximum_sequence := repeat('9', selected_policy.width)::bigint;
  INSERT INTO public.ticket_number_counters (
    tenant_id, aggregate_kind, namespace_digest, period, next_value, updated_at
  ) VALUES (
    p_tenant_id, p_aggregate_kind, selected_policy.namespace_digest,
    target_period, selected_policy.start + 1, transaction_timestamp()
  )
  ON CONFLICT (tenant_id, aggregate_kind, namespace_digest, period)
  DO UPDATE SET
    next_value = greatest(
      public.ticket_number_counters.next_value, selected_policy.start
    ) + 1,
    updated_at = transaction_timestamp()
  WHERE greatest(
    public.ticket_number_counters.next_value, selected_policy.start
  ) <= maximum_sequence
  RETURNING next_value - 1 INTO allocated;
  IF allocated IS NULL OR allocated > maximum_sequence THEN
    RAISE EXCEPTION 'ticket number sequence is exhausted'
      USING ERRCODE = '54000';
  END IF;

  rendered := selected_policy.prefix || selected_policy.separator
    || CASE selected_policy.period WHEN 'annual'
         THEN target_period::text || selected_policy.separator ELSE '' END
    || lpad(allocated::text, selected_policy.width, '0');
  INSERT INTO public.tenant_ticket_numbering_receipts (
    tenant_id, aggregate_kind, aggregate_id, policy_version_id,
    policy_version, namespace_digest, period, sequence, number, allocated_at
  ) VALUES (
    p_tenant_id, p_aggregate_kind, p_aggregate_id, selected_policy.id,
    selected_policy.version, selected_policy.namespace_digest,
    target_period, allocated, rendered, allocation_instant
  );
  RETURN rendered;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_allocate_ticket_number_v2(
  uuid, public.ticket_aggregate_kind, uuid, timestamp with time zone
) OWNER TO periapsis_ticket_numbering_owner;
REVOKE ALL ON FUNCTION app.private_allocate_ticket_number_v2(
  uuid, public.ticket_aggregate_kind, uuid, timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;
GRANT EXECUTE ON FUNCTION app.context_tenant_id()
  TO periapsis_ticket_numbering_owner;--> statement-breakpoint

CREATE FUNCTION app.private_prepare_case_ticket_numbering_v2()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  NEW.number := app.private_allocate_ticket_number_v2(
    NEW.tenant_id, 'case', NEW.id, NEW.created_at
  );
  RETURN NEW;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_prepare_case_ticket_numbering_v2()
  OWNER TO periapsis_ticket_numbering_owner;
REVOKE ALL ON FUNCTION app.private_prepare_case_ticket_numbering_v2()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;
CREATE TRIGGER cases_ticket_numbering_v2
BEFORE INSERT ON public.cases
FOR EACH ROW EXECUTE FUNCTION app.private_prepare_case_ticket_numbering_v2();--> statement-breakpoint

CREATE FUNCTION app.private_reject_ticket_number_update_v2()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NEW.number IS DISTINCT FROM OLD.number THEN
    RAISE EXCEPTION 'ticket number is immutable'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_reject_ticket_number_update_v2()
  OWNER TO periapsis_ticket_numbering_owner;
REVOKE ALL ON FUNCTION app.private_reject_ticket_number_update_v2()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;
CREATE TRIGGER alerts_ticket_number_immutable_v2
BEFORE UPDATE OF number ON public.alerts
FOR EACH ROW EXECUTE FUNCTION app.private_reject_ticket_number_update_v2();
CREATE TRIGGER cases_ticket_number_immutable_v2
BEFORE UPDATE OF number ON public.cases
FOR EACH ROW EXECUTE FUNCTION app.private_reject_ticket_number_update_v2();--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.private_allocate_ticket_number_v2(
  uuid, public.ticket_aggregate_kind, uuid, timestamp with time zone
) TO periapsis_migrator, periapsis_sla_worker_owner;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.prepare_alert_ticketing_defaults_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  requested_workflow_id uuid;
  selected_workflow record;
  initial_state text;
BEGIN
  requested_workflow_id := coalesce(
    NEW.workflow_id,
    nullif(current_setting('app.ticketing_alert_workflow_id', true), '')::uuid
  );
  SELECT workflow.id, workflow.current_version, version.states
    INTO selected_workflow
  FROM public.ticket_workflows AS workflow
  JOIN public.ticket_workflow_versions AS version
    ON version.tenant_id = workflow.tenant_id
   AND version.workflow_id = workflow.id
   AND version.aggregate_kind = workflow.aggregate_kind
   AND version.version = workflow.current_version
  WHERE workflow.tenant_id = NEW.tenant_id
    AND workflow.aggregate_kind = 'alert'
    AND workflow.archived_at IS NULL
    AND (
      requested_workflow_id IS NOT NULL AND workflow.id = requested_workflow_id
      OR requested_workflow_id IS NULL AND workflow.is_default
    );
  IF NOT FOUND THEN
    RAISE EXCEPTION 'published Alert workflow is unavailable'
      USING ERRCODE = '23503';
  END IF;
  SELECT state.value ->> 'key' INTO STRICT initial_state
  FROM jsonb_array_elements(selected_workflow.states) AS state(value)
  WHERE (state.value ->> 'initial')::boolean;

  NEW.workflow_id := selected_workflow.id;
  NEW.workflow_version := selected_workflow.current_version;
  NEW.state_key := initial_state;
  NEW.number := app.private_allocate_ticket_number_v2(
    NEW.tenant_id, 'alert', NEW.id, NEW.created_at
  );
  RETURN NEW;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.prepare_alert_ticketing_defaults_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.prepare_alert_ticketing_defaults_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;--> statement-breakpoint

DO $replace_case_ticket_number_consumers$
DECLARE
  target regprocedure;
  definition text;
  successor text;
  allocation_instant text;
BEGIN
  FOR target, allocation_instant IN
    SELECT candidate.function_id, candidate.instant
    FROM (VALUES
      ('app.create_tenant_case_v1(uuid,uuid,integer,text,text,text,public.alert_severity,text,text,text,text[],jsonb,boolean,timestamp with time zone,uuid,uuid,bytea,bytea,uuid,uuid,inet,text,text)'::regprocedure, 'created_at'::text),
      ('app.commit_tenant_ticket_escalation_v1(uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,inet,text,text)'::regprocedure, 'operation_at'::text),
      ('app.private_commit_tenant_ticket_escalation_v4_base(uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,inet,text,text)'::regprocedure, 'operation_at'::text),
      ('app.private_commit_tenant_ticket_link_v1_base(uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,inet,text,text)'::regprocedure, 'operation_at'::text)
    ) AS candidate(function_id, instant)
  LOOP
    SELECT pg_catalog.pg_get_functiondef(target::oid) INTO STRICT definition;
    successor := pg_catalog.regexp_replace(
      definition,
      'app\.private_next_ticket_number_v1\([[:space:]]*context_tenant,[[:space:]]*''case'',[[:space:]]*'
        || allocation_instant || '[[:space:]]*\)',
      'app.private_allocate_ticket_number_v2(context_tenant, ''case'', p_case_id, '
        || allocation_instant || ')'
    );
    IF successor = definition
       OR pg_catalog.strpos(successor, 'app.private_next_ticket_number_v1(') <> 0
       OR pg_catalog.strpos(successor, 'app.private_allocate_ticket_number_v2(') = 0 THEN
      RAISE EXCEPTION 'ticket number consumer % is not canonical', target
        USING ERRCODE = '55000';
    END IF;
    EXECUTE successor;
  END LOOP;
END;
$replace_case_ticket_number_consumers$;--> statement-breakpoint

-- PostgreSQL row-locking SELECTs require UPDATE privilege and a matching
-- UPDATE policy. These column-only grants preserve the SLA worker definer's
-- existing FOR SHARE revalidation while the false WITH CHECK keeps direct
-- mutations fail-closed.
GRANT UPDATE (id) ON TABLE public.tenant_service_accounts
  TO periapsis_sla_worker_owner;
GRANT UPDATE (id) ON TABLE public.ticket_workflows
  TO periapsis_sla_worker_owner;
GRANT UPDATE (id) ON TABLE public.ticket_workflow_versions
  TO periapsis_sla_worker_owner;--> statement-breakpoint
CREATE POLICY tenant_service_accounts_sla_action_lock_v1
ON public.tenant_service_accounts AS PERMISSIVE FOR UPDATE
TO periapsis_sla_worker_owner
USING (
  tenant_id = app.context_tenant_id() AND archived_at IS NULL
)
WITH CHECK (false);--> statement-breakpoint
CREATE POLICY ticket_workflows_sla_action_lock_v1
ON public.ticket_workflows AS PERMISSIVE FOR UPDATE
TO periapsis_sla_worker_owner
USING (
  tenant_id = app.context_tenant_id() AND archived_at IS NULL
)
WITH CHECK (false);--> statement-breakpoint
CREATE POLICY ticket_workflow_versions_sla_action_lock_v1
ON public.ticket_workflow_versions AS PERMISSIVE FOR UPDATE
TO periapsis_sla_worker_owner
USING (tenant_id = app.context_tenant_id())
WITH CHECK (false);--> statement-breakpoint

DO $replace_sla_system_alert_numbering$
DECLARE
  target constant regprocedure :=
    'app.execute_sla_trigger_action_v1(uuid,uuid,uuid,bigint,bytea,public.sla_trigger_action_kind,timestamp with time zone)'::regprocedure;
  definition text;
  successor text;
  old_activity constant text := $old_activity$
      INSERT INTO public.ticket_activities (
        id, tenant_id, alert_id, sequence, kind, summary,
        actor_principal_kind, origin, details, occurred_at
      ) VALUES (
        uuidv7(), p_tenant_id, effect_id, 1, 'alert.created',
        'Alert created by SLA action', 'system', 'system',
        jsonb_build_object('occurrenceId', occurrence.id,
          'contentRedacted', true), p_applied_at
      );
$old_activity$;
  old_outbox constant text := $old_outbox$
      IF occurrence.allow_recursive_sla THEN
        INSERT INTO public.outbox_events (
          id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
          event_type, schema_version, payload, deduplication_key,
          actor_kind, producer, maximum_audience, occurred_at, available_at
        ) VALUES (
          uuidv7(), p_tenant_id, 'alert', effect_id, 1,
          'sla.alert.created', 1,
          jsonb_build_object('alert_id', effect_id, 'version', 1,
            'source', 'sla-engine'),
          'sla:system-alert:' || occurrence.id::text,
          'system', 'sla-action', 'operator', p_applied_at, p_applied_at
        );
      END IF;
$old_outbox$;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(target::oid) INTO STRICT definition;
  successor := pg_catalog.replace(
    definition,
    'app.private_next_ticket_number_v1(p_tenant_id, ''alert'', p_applied_at)',
    'app.private_allocate_ticket_number_v2(p_tenant_id, ''alert'', effect_id, p_applied_at)'
  );
  successor := pg_catalog.replace(successor, old_activity, E'\n');
  successor := pg_catalog.replace(successor, old_outbox, E'\n');
  IF successor = definition
     OR pg_catalog.strpos(successor, 'app.private_next_ticket_number_v1(') <> 0
     OR pg_catalog.strpos(successor, old_activity) <> 0
     OR pg_catalog.strpos(successor, old_outbox) <> 0
     OR pg_catalog.strpos(successor,
          'app.private_allocate_ticket_number_v2(p_tenant_id, ''alert'', effect_id, p_applied_at)') = 0 THEN
    RAISE EXCEPTION 'SLA system Alert numbering predecessor is not canonical'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE successor;
END;
$replace_sla_system_alert_numbering$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_next_ticket_number_v1(
  p_tenant_id uuid,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_at timestamp with time zone
)
RETURNS text
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  RAISE EXCEPTION 'aggregate-bound ticket number allocator v2 is required'
    USING ERRCODE = '0A000';
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_next_ticket_number_v1(
  uuid, public.ticket_aggregate_kind, timestamp with time zone
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_next_ticket_number_v1(
  uuid, public.ticket_aggregate_kind, timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_ticket_runtime_owner, periapsis_sla_worker_owner;--> statement-breakpoint

DO $ticket_numbering_consumer_contract$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'app'
      AND procedure.proname <> 'private_next_ticket_number_v1'
      AND pg_catalog.strpos(
        procedure.prosrc, 'private_next_ticket_number_v1'
      ) <> 0
  ) THEN
    RAISE EXCEPTION 'a live ticket number consumer still uses allocator v1'
      USING ERRCODE = '55000';
  END IF;
END;
$ticket_numbering_consumer_contract$;--> statement-breakpoint

-- V3 SECURITY DEFINER entry points remain the public Alert ABI. The legacy V1
-- functions are internal implementation details and cannot be invoked by the
-- API login to bypass current validation and replay guards.
REVOKE EXECUTE ON FUNCTION app.create_tenant_alert_as_human_v1(
  text, text, text, public.alert_severity, bytea, bytea,
  uuid, uuid, inet, text, text
) FROM periapsis_api;
REVOKE EXECUTE ON FUNCTION app.create_tenant_alert_as_service_account_v1(
  uuid, bytea, integer, bytea, inet, text, text, text,
  public.alert_severity, bytea, bytea, uuid, uuid, text
) FROM periapsis_api;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION
  app.require_live_audit_session_v1(uuid, uuid),
  app.context_tenant_id(),
  app.context_user_id(),
  app.current_tenant_membership_id(),
  app.current_tenant_human_has_exact_permission_v3(
    text, public.authorization_scope
  ),
  app.lock_current_tenant_authorization_state()
TO periapsis_ticket_numbering_owner;--> statement-breakpoint

CREATE FUNCTION app.get_tenant_ticket_numbering_policy_v1(
  p_session_id uuid,
  p_authentication_method text,
  p_aggregate_kind public.ticket_aggregate_kind
)
RETURNS TABLE(
  version_id uuid,
  tenant_id uuid,
  aggregate_kind public.ticket_aggregate_kind,
  version integer,
  prefix text,
  separator text,
  period public.ticket_numbering_period,
  width integer,
  start bigint,
  published_by_membership_id uuid,
  published_at timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
BEGIN
  IF p_aggregate_kind IS NULL
     OR app.require_live_audit_session_v1(p_session_id, context_tenant)
          IS DISTINCT FROM p_authentication_method
     OR NOT app.current_tenant_human_has_exact_permission_v3(
       'settings.read', 'tenant'
     ) THEN
    RAISE EXCEPTION 'tenant settings read permission is required'
      USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT policy.id, policy.tenant_id, policy.aggregate_kind,
         policy.version, policy.prefix, policy.separator, policy.period,
         policy.width, policy.start, policy.published_by_membership_id,
         policy.published_at
  FROM ONLY public.tenant_ticket_numbering_policies AS state
  JOIN ONLY public.tenant_ticket_numbering_policy_versions AS policy
    ON policy.tenant_id = state.tenant_id
   AND policy.aggregate_kind = state.aggregate_kind
   AND policy.version = state.current_version
  JOIN ONLY public.tenants AS tenant ON tenant.id = state.tenant_id
  WHERE state.tenant_id = context_tenant
    AND state.aggregate_kind = p_aggregate_kind
    AND tenant.status = 'active';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket numbering policy is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.get_tenant_ticket_numbering_policy_v1(
  uuid, text, public.ticket_aggregate_kind
) OWNER TO periapsis_ticket_numbering_owner;
REVOKE ALL ON FUNCTION app.get_tenant_ticket_numbering_policy_v1(
  uuid, text, public.ticket_aggregate_kind
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
       periapsis_audit_reader_owner;
GRANT EXECUTE ON FUNCTION app.get_tenant_ticket_numbering_policy_v1(
  uuid, text, public.ticket_aggregate_kind
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.prepare_replace_tenant_ticket_numbering_policy_v1(
  p_session_id uuid,
  p_authentication_method text,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_key_digest bytea,
  p_request_digest bytea
)
RETURNS TABLE(
  replayed boolean,
  version_id uuid,
  tenant_id uuid,
  aggregate_kind public.ticket_aggregate_kind,
  version integer,
  prefix text,
  separator text,
  period public.ticket_numbering_period,
  width integer,
  start bigint,
  published_by_membership_id uuid,
  published_at timestamptz
)
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
  command_record public.tenant_ticket_numbering_commands%ROWTYPE;
BEGIN
  IF p_aggregate_kind IS NULL
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32 THEN
    RAISE EXCEPTION 'ticket numbering command envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.lock_current_tenant_authorization_state();
  IF app.require_live_audit_session_v1(p_session_id, context_tenant)
       IS DISTINCT FROM p_authentication_method
     OR NOT app.current_tenant_human_has_exact_permission_v3(
       'settings.read', 'tenant'
     ) OR NOT app.current_tenant_human_has_exact_permission_v3(
       'settings.manage', 'tenant'
     ) THEN
    RAISE EXCEPTION 'tenant settings manage permission is required'
      USING ERRCODE = '42501';
  END IF;
  actor_membership := app.current_tenant_membership_id();
  PERFORM pg_advisory_xact_lock(pg_catalog.hashtextextended(
    context_tenant::text || ':' || p_aggregate_kind::text
      || ':ticket-numbering-policy', 0
  ));

  SELECT command.* INTO command_record
  FROM ONLY public.tenant_ticket_numbering_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.user_id = actor_user
    AND command.aggregate_kind = p_aggregate_kind
    AND command.operation = 'ticket_numbering.policy.replace'
    AND command.key_digest = p_key_digest
  FOR SHARE;
  IF FOUND THEN
    IF command_record.request_digest IS DISTINCT FROM p_request_digest
       OR command_record.result ->> 'publishedByMembershipId'
            IS DISTINCT FROM actor_membership::text THEN
      RAISE EXCEPTION 'ticket numbering idempotency key conflicts with a prior request'
        USING ERRCODE = '23505',
              CONSTRAINT = 'tenant_ticket_numbering_commands_pkey';
    END IF;
    RETURN QUERY SELECT
      true,
      (command_record.result ->> 'versionId')::uuid,
      (command_record.result ->> 'tenantId')::uuid,
      (command_record.result ->> 'kind')::public.ticket_aggregate_kind,
      (command_record.result ->> 'version')::integer,
      command_record.result ->> 'prefix',
      command_record.result ->> 'separator',
      (command_record.result ->> 'period')::public.ticket_numbering_period,
      (command_record.result ->> 'width')::integer,
      (command_record.result ->> 'start')::bigint,
      (command_record.result ->> 'publishedByMembershipId')::uuid,
      (command_record.result ->> 'publishedAt')::timestamptz;
    RETURN;
  END IF;

  RETURN QUERY
  SELECT false, policy.id, policy.tenant_id, policy.aggregate_kind,
         policy.version, policy.prefix, policy.separator, policy.period,
         policy.width, policy.start, policy.published_by_membership_id,
         policy.published_at
  FROM ONLY public.tenant_ticket_numbering_policies AS state
  JOIN ONLY public.tenant_ticket_numbering_policy_versions AS policy
    ON policy.tenant_id = state.tenant_id
   AND policy.aggregate_kind = state.aggregate_kind
   AND policy.version = state.current_version
  JOIN ONLY public.tenants AS tenant ON tenant.id = state.tenant_id
  WHERE state.tenant_id = context_tenant
    AND state.aggregate_kind = p_aggregate_kind
    AND tenant.status = 'active'
  FOR UPDATE OF state;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket numbering policy is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.prepare_replace_tenant_ticket_numbering_policy_v1(
  uuid, text, public.ticket_aggregate_kind, bytea, bytea
) OWNER TO periapsis_ticket_numbering_owner;
REVOKE ALL ON FUNCTION app.prepare_replace_tenant_ticket_numbering_policy_v1(
  uuid, text, public.ticket_aggregate_kind, bytea, bytea
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
       periapsis_audit_reader_owner;
GRANT EXECUTE ON FUNCTION app.prepare_replace_tenant_ticket_numbering_policy_v1(
  uuid, text, public.ticket_aggregate_kind, bytea, bytea
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.private_append_ticket_numbering_policy_audit_v1(
  p_event_id uuid,
  p_policy_id uuid,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_prior_version integer,
  p_result_version integer,
  p_period public.ticket_numbering_period,
  p_width integer,
  p_start bigint,
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
     OR p_aggregate_kind IS NULL
     OR p_prior_version NOT BETWEEN 1 AND 2147483646
     OR p_result_version IS DISTINCT FROM p_prior_version + 1
     OR p_period IS NULL OR p_width NOT BETWEEN 4 AND 12
     OR p_start NOT BETWEEN 1 AND repeat('9', p_width)::bigint
     OR p_reason IS NULL OR p_reason <> btrim(p_reason)
     OR octet_length(p_reason) NOT BETWEEN 1 AND 2048
     OR p_reason ~ '[[:cntrl:]]'
     OR p_reason ~ U&'[\00AD\061C\180E\200B-\200F\202A-\202E\2060-\206F\FEFF]'
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR p_authentication_method NOT IN (
       'bootstrap_totp', 'totp', 'recovery_code', 'ldap',
       'oidc', 'saml', 'passkey'
     ) THEN
    RAISE EXCEPTION 'ticket numbering audit envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.audit_events (
    id, tenant_id, sequence, actor_type, actor_user_id,
    action, resource_type, resource_id, request_id, correlation_id,
    ip_address, user_agent, authentication_method, outcome, reason,
    before, after, metadata
  ) VALUES (
    p_event_id, app.context_tenant_id(), 0, 'user', actor_user,
    'tenant.ticket_numbering.policy.replace',
    'tenant_ticket_numbering_policy', p_policy_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success', p_reason,
    jsonb_build_object(
      'kind', p_aggregate_kind, 'version', p_prior_version,
      'formatRedacted', true
    ),
    jsonb_build_object(
      'kind', p_aggregate_kind, 'version', p_result_version,
      'period', p_period, 'width', p_width, 'start', p_start,
      'formatRedacted', true
    ),
    jsonb_build_object('projectionVersion', 1, 'contentRedacted', true)
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_append_ticket_numbering_policy_audit_v1(
  uuid, uuid, public.ticket_aggregate_kind, integer, integer,
  public.ticket_numbering_period, integer, bigint, text, uuid, uuid,
  inet, text, text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_append_ticket_numbering_policy_audit_v1(
  uuid, uuid, public.ticket_aggregate_kind, integer, integer,
  public.ticket_numbering_period, integer, bigint, text, uuid, uuid,
  inet, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;
GRANT EXECUTE ON FUNCTION app.private_append_ticket_numbering_policy_audit_v1(
  uuid, uuid, public.ticket_aggregate_kind, integer, integer,
  public.ticket_numbering_period, integer, bigint, text, uuid, uuid,
  inet, text, text
) TO periapsis_ticket_numbering_owner;--> statement-breakpoint

CREATE FUNCTION app.commit_replace_tenant_ticket_numbering_policy_v1(
  p_session_id uuid,
  p_authentication_method text,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_expected_version integer,
  p_key_digest bytea,
  p_request_digest bytea,
  p_version_id uuid,
  p_result_version integer,
  p_prefix text,
  p_separator text,
  p_period public.ticket_numbering_period,
  p_width integer,
  p_start bigint,
  p_namespace_digest bytea,
  p_published_at timestamptz,
  p_reason text,
  p_audit_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS TABLE(
  version_id uuid,
  tenant_id uuid,
  aggregate_kind public.ticket_aggregate_kind,
  version integer,
  prefix text,
  separator text,
  period public.ticket_numbering_period,
  width integer,
  start bigint,
  published_by_membership_id uuid,
  published_at timestamptz
)
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
  current_record record;
  result_snapshot jsonb;
BEGIN
  IF p_aggregate_kind IS NULL
     OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_result_version IS DISTINCT FROM p_expected_version + 1
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_version_id IS NULL OR uuid_extract_version(p_version_id) IS DISTINCT FROM 7
     OR p_prefix IS NULL OR p_prefix !~ '^[A-Z][A-Z0-9]{0,11}$'
     OR p_separator NOT IN ('-', '/', '.', '_')
     OR p_period IS NULL OR p_width NOT BETWEEN 4 AND 12
     OR p_start NOT BETWEEN 1 AND repeat('9', p_width)::bigint
     OR p_namespace_digest IS NULL OR octet_length(p_namespace_digest) <> 32
     OR p_namespace_digest IS DISTINCT FROM
          app.private_ticket_numbering_namespace_digest_v1(
            p_prefix, p_separator, p_period, p_width
          )
     OR p_published_at IS NULL
     OR p_published_at > operation_at + interval '1 minute'
     OR p_reason IS NULL OR p_reason <> btrim(p_reason)
     OR octet_length(p_reason) NOT BETWEEN 1 AND 2048
     OR p_reason ~ '[[:cntrl:]]'
     OR p_reason ~ U&'[\00AD\061C\180E\200B-\200F\202A-\202E\2060-\206F\FEFF]'
     OR p_audit_id IS NULL OR uuid_extract_version(p_audit_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512 THEN
    RAISE EXCEPTION 'ticket numbering policy replacement is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.lock_current_tenant_authorization_state();
  IF app.require_live_audit_session_v1(p_session_id, context_tenant)
       IS DISTINCT FROM p_authentication_method
     OR NOT app.current_tenant_human_has_exact_permission_v3(
       'settings.read', 'tenant'
     ) OR NOT app.current_tenant_human_has_exact_permission_v3(
       'settings.manage', 'tenant'
     ) THEN
    RAISE EXCEPTION 'tenant settings manage permission is required'
      USING ERRCODE = '42501';
  END IF;
  actor_membership := app.current_tenant_membership_id();
  PERFORM pg_advisory_xact_lock(pg_catalog.hashtextextended(
    context_tenant::text || ':' || p_aggregate_kind::text
      || ':ticket-numbering-policy', 0
  ));
  IF EXISTS (
    SELECT 1 FROM ONLY public.tenant_ticket_numbering_commands AS command
    WHERE command.tenant_id = context_tenant
      AND command.user_id = actor_user
      AND command.aggregate_kind = p_aggregate_kind
      AND command.operation = 'ticket_numbering.policy.replace'
      AND command.key_digest = p_key_digest
  ) THEN
    RAISE EXCEPTION 'ticket numbering command was committed concurrently'
      USING ERRCODE = '40001';
  END IF;

  SELECT state.current_version, policy.prefix, policy.separator,
         policy.period, policy.width, policy.start, policy.published_at
    INTO current_record
  FROM ONLY public.tenant_ticket_numbering_policies AS state
  JOIN ONLY public.tenant_ticket_numbering_policy_versions AS policy
    ON policy.tenant_id = state.tenant_id
   AND policy.aggregate_kind = state.aggregate_kind
   AND policy.version = state.current_version
  JOIN ONLY public.tenants AS tenant ON tenant.id = state.tenant_id
  WHERE state.tenant_id = context_tenant
    AND state.aggregate_kind = p_aggregate_kind
    AND tenant.status = 'active'
  FOR UPDATE OF state;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket numbering policy is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
  IF current_record.current_version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'ticket numbering policy changed concurrently'
      USING ERRCODE = '40001';
  END IF;
  IF current_record.prefix IS NOT DISTINCT FROM p_prefix
     AND current_record.separator IS NOT DISTINCT FROM p_separator
     AND current_record.period IS NOT DISTINCT FROM p_period
     AND current_record.width IS NOT DISTINCT FROM p_width
     AND current_record.start IS NOT DISTINCT FROM p_start THEN
    RAISE EXCEPTION 'ticket numbering policy has no change'
      USING ERRCODE = '23505',
            CONSTRAINT = 'tenant_ticket_numbering_policy_no_change';
  END IF;
  IF p_published_at < current_record.published_at THEN
    RAISE EXCEPTION 'ticket numbering policy publication time regressed'
      USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.tenant_ticket_numbering_policy_versions (
    id, tenant_id, aggregate_kind, version, prefix, separator, period,
    width, start, namespace_digest, published_by_membership_id,
    published_at
  ) VALUES (
    p_version_id, context_tenant, p_aggregate_kind, p_result_version,
    p_prefix, p_separator, p_period, p_width, p_start,
    p_namespace_digest, actor_membership, p_published_at
  );
  UPDATE ONLY public.tenant_ticket_numbering_policies AS state
  SET current_version = p_result_version,
      updated_at = greatest(operation_at, p_published_at)
  WHERE state.tenant_id = context_tenant
    AND state.aggregate_kind = p_aggregate_kind
    AND state.current_version = p_expected_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket numbering policy changed concurrently'
      USING ERRCODE = '40001';
  END IF;

  result_snapshot := jsonb_build_object(
    'schemaVersion', 1,
    'versionId', p_version_id,
    'tenantId', context_tenant,
    'kind', p_aggregate_kind,
    'version', p_result_version,
    'prefix', p_prefix,
    'separator', p_separator,
    'period', p_period,
    'width', p_width,
    'start', p_start,
    'publishedByMembershipId', actor_membership,
    'publishedAt', p_published_at
  );
  INSERT INTO public.tenant_ticket_numbering_commands (
    tenant_id, user_id, aggregate_kind, operation, key_digest,
    request_digest, result, created_at, expires_at
  ) VALUES (
    context_tenant, actor_user, p_aggregate_kind,
    'ticket_numbering.policy.replace', p_key_digest, p_request_digest,
    result_snapshot, operation_at, operation_at + interval '24 hours'
  );
  PERFORM app.private_append_ticket_numbering_policy_audit_v1(
    p_audit_id, p_version_id, p_aggregate_kind, p_expected_version,
    p_result_version, p_period, p_width, p_start, p_reason,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method
  );

  RETURN QUERY SELECT
    p_version_id, context_tenant, p_aggregate_kind, p_result_version,
    p_prefix, p_separator, p_period, p_width, p_start,
    actor_membership, p_published_at;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.commit_replace_tenant_ticket_numbering_policy_v1(
  uuid, text, public.ticket_aggregate_kind, integer, bytea, bytea,
  uuid, integer, text, text, public.ticket_numbering_period, integer,
  bigint, bytea, timestamptz, text, uuid, uuid, uuid, inet, text
) OWNER TO periapsis_ticket_numbering_owner;
REVOKE ALL ON FUNCTION app.commit_replace_tenant_ticket_numbering_policy_v1(
  uuid, text, public.ticket_aggregate_kind, integer, bytea, bytea,
  uuid, integer, text, text, public.ticket_numbering_period, integer,
  bigint, bytea, timestamptz, text, uuid, uuid, uuid, inet, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
       periapsis_audit_reader_owner;
GRANT EXECUTE ON FUNCTION app.commit_replace_tenant_ticket_numbering_policy_v1(
  uuid, text, public.ticket_aggregate_kind, integer, bytea, bytea,
  uuid, integer, text, text, public.ticket_numbering_period, integer,
  bigint, bytea, timestamptz, text, uuid, uuid, uuid, inet, text
) TO periapsis_api;--> statement-breakpoint

DO $ticket_numbering_security_contract$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = 'periapsis_ticket_numbering_owner'
      AND (role.rolcanlogin OR role.rolsuper OR role.rolbypassrls
        OR role.rolcreaterole OR role.rolcreatedb OR role.rolreplication)
  ) OR EXISTS (
    SELECT 1
    FROM (VALUES
      ('tenant_ticket_numbering_policy_versions'),
      ('tenant_ticket_numbering_policies'),
      ('tenant_ticket_numbering_receipts'),
      ('tenant_ticket_numbering_commands'),
      ('ticket_number_counters')
    ) AS expected(table_name)
    WHERE pg_catalog.pg_get_userbyid((
      SELECT relation.relowner
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = relation.relnamespace
      WHERE namespace.nspname = 'public'
        AND relation.relname = expected.table_name
    )) <> 'periapsis_ticket_numbering_owner'
  ) OR EXISTS (
    SELECT 1
    FROM (VALUES
      ('tenant_ticket_numbering_policy_versions'),
      ('tenant_ticket_numbering_policies'),
      ('tenant_ticket_numbering_receipts'),
      ('tenant_ticket_numbering_commands'),
      ('ticket_number_counters')
    ) AS denied(table_name)
    WHERE has_table_privilege('periapsis_api', denied.table_name, 'SELECT')
       OR has_table_privilege('periapsis_api', denied.table_name, 'INSERT')
       OR has_table_privilege('periapsis_api', denied.table_name, 'UPDATE')
       OR has_table_privilege('periapsis_api', denied.table_name, 'DELETE')
  ) THEN
    RAISE EXCEPTION 'ticket numbering security contract failed'
      USING ERRCODE = '55000';
  END IF;
END;
$ticket_numbering_security_contract$;--> statement-breakpoint
