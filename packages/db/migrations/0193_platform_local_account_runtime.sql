CREATE TABLE "platform_local_account_ceremonies" (
	"factor_id" uuid PRIMARY KEY NOT NULL,
	"account_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"purpose" text NOT NULL,
	"version" bigint NOT NULL,
	"factor_revision" bigint NOT NULL,
	"ceremony_token_digest" "bytea" NOT NULL,
	"secret_ciphertext" "bytea" NOT NULL,
	"secret_nonce" "bytea" NOT NULL,
	"secret_aad" "bytea" NOT NULL,
	"key_version" integer NOT NULL,
	"state" text DEFAULT 'pending' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"maximum_attempts" integer DEFAULT 5 NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"confirmed_at" timestamp with time zone,
	"retired_at" timestamp with time zone,
	"failure_reason" text,
	"created_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL,
	CONSTRAINT "platform_local_account_ceremonies_token_key" UNIQUE("ceremony_token_digest"),
	CONSTRAINT "platform_local_account_ceremonies_identity_check" CHECK ((uuid_extract_version("platform_local_account_ceremonies"."factor_id") = 7) is true
        and "platform_local_account_ceremonies"."purpose" in ('invite','recover')
        and "platform_local_account_ceremonies"."version" = 1
        and "platform_local_account_ceremonies"."factor_revision" = 1
        and octet_length("platform_local_account_ceremonies"."ceremony_token_digest") = 32),
	CONSTRAINT "platform_local_account_ceremonies_envelope_check" CHECK (octet_length("platform_local_account_ceremonies"."secret_ciphertext") between 17 and 8192
        and octet_length("platform_local_account_ceremonies"."secret_nonce") = 12
        and octet_length("platform_local_account_ceremonies"."secret_aad") between 1 and 1024
        and "platform_local_account_ceremonies"."key_version" > 0),
	CONSTRAINT "platform_local_account_ceremonies_attempt_check" CHECK ("platform_local_account_ceremonies"."attempts" between 0 and "platform_local_account_ceremonies"."maximum_attempts"
        and "platform_local_account_ceremonies"."maximum_attempts" between 1 and 20),
	CONSTRAINT "platform_local_account_ceremonies_state_check" CHECK (("platform_local_account_ceremonies"."state" = 'pending'
          and "platform_local_account_ceremonies"."confirmed_at" is null and "platform_local_account_ceremonies"."retired_at" is null
          and "platform_local_account_ceremonies"."failure_reason" is null)
        or ("platform_local_account_ceremonies"."state" = 'confirmed'
          and "platform_local_account_ceremonies"."confirmed_at" is not null and "platform_local_account_ceremonies"."retired_at" is null
          and "platform_local_account_ceremonies"."failure_reason" is null)
        or ("platform_local_account_ceremonies"."state" in ('retired','failed')
          and "platform_local_account_ceremonies"."confirmed_at" is null and "platform_local_account_ceremonies"."retired_at" is not null
          and ("platform_local_account_ceremonies"."state" = 'retired') = ("platform_local_account_ceremonies"."failure_reason" is null))),
	CONSTRAINT "platform_local_account_ceremonies_timestamp_check" CHECK (date_trunc('milliseconds', "platform_local_account_ceremonies"."created_at") = "platform_local_account_ceremonies"."created_at"
        and date_trunc('milliseconds', "platform_local_account_ceremonies"."updated_at") = "platform_local_account_ceremonies"."updated_at"
        and date_trunc('milliseconds', "platform_local_account_ceremonies"."expires_at") = "platform_local_account_ceremonies"."expires_at"
        and "platform_local_account_ceremonies"."expires_at" > "platform_local_account_ceremonies"."created_at"
        and "platform_local_account_ceremonies"."updated_at" >= "platform_local_account_ceremonies"."created_at"
        and ("platform_local_account_ceremonies"."confirmed_at" is null
          or "platform_local_account_ceremonies"."confirmed_at" between "platform_local_account_ceremonies"."created_at" and "platform_local_account_ceremonies"."updated_at")
        and ("platform_local_account_ceremonies"."retired_at" is null
          or "platform_local_account_ceremonies"."retired_at" between "platform_local_account_ceremonies"."created_at" and "platform_local_account_ceremonies"."updated_at"))
);
--> statement-breakpoint
ALTER TABLE "platform_local_account_ceremonies" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_local_account_command_receipts" (
	"command_id" uuid PRIMARY KEY NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"actor_session_id" uuid NOT NULL,
	"account_id" uuid NOT NULL,
	"action" text NOT NULL,
	"expected_revision" bigint NOT NULL,
	"idempotency_key_digest" "bytea" NOT NULL,
	"public_request_digest" "bytea" NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"artifact_issued" boolean NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	CONSTRAINT "platform_local_account_command_receipts_replay_key" UNIQUE("actor_user_id","idempotency_key_digest"),
	CONSTRAINT "platform_local_account_command_receipts_identity_check" CHECK ((uuid_extract_version("platform_local_account_command_receipts"."command_id") = 7) is true
        and "platform_local_account_command_receipts"."action" in ('invite','activate','disable','recover','enable','rotate_password')
        and "platform_local_account_command_receipts"."expected_revision" between 0 and 9007199254740990
        and octet_length("platform_local_account_command_receipts"."idempotency_key_digest") = 32
        and octet_length("platform_local_account_command_receipts"."public_request_digest") = 32
        and jsonb_typeof("platform_local_account_command_receipts"."result_snapshot") = 'object'
        and pg_column_size("platform_local_account_command_receipts"."result_snapshot") <= 16384
        and date_trunc('milliseconds', "platform_local_account_command_receipts"."created_at") = "platform_local_account_command_receipts"."created_at")
);
--> statement-breakpoint
ALTER TABLE "platform_local_account_command_receipts" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_local_accounts" (
	"id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"login_identifier_id" uuid NOT NULL,
	"status" text DEFAULT 'invited' NOT NULL,
	"protected_recovery_principal" boolean DEFAULT false NOT NULL,
	"revision" bigint DEFAULT 1 NOT NULL,
	"identity_epoch" bigint DEFAULT 1 NOT NULL,
	"invited_at" timestamp with time zone NOT NULL,
	"activated_at" timestamp with time zone,
	"disabled_at" timestamp with time zone,
	"recovery_started_at" timestamp with time zone,
	"updated_at" timestamp with time zone NOT NULL,
	CONSTRAINT "platform_local_accounts_user_key" UNIQUE("user_id"),
	CONSTRAINT "platform_local_accounts_identifier_key" UNIQUE("login_identifier_id"),
	CONSTRAINT "platform_local_accounts_id_user_key" UNIQUE("id","user_id"),
	CONSTRAINT "platform_local_accounts_id_check" CHECK ((uuid_extract_version("platform_local_accounts"."id") = 7) is true),
	CONSTRAINT "platform_local_accounts_status_check" CHECK ("platform_local_accounts"."status" in ('invited','active','disabled','recovery_restricted')),
	CONSTRAINT "platform_local_accounts_revision_check" CHECK ("platform_local_accounts"."revision" between 1 and 9007199254740991 and "platform_local_accounts"."identity_epoch" between 1 and 9007199254740991),
	CONSTRAINT "platform_local_accounts_lifecycle_check" CHECK (("platform_local_accounts"."status" = 'invited'
          and "platform_local_accounts"."activated_at" is null
          and "platform_local_accounts"."disabled_at" is null
          and "platform_local_accounts"."recovery_started_at" is null)
        or ("platform_local_accounts"."status" = 'active'
          and "platform_local_accounts"."activated_at" is not null
          and "platform_local_accounts"."disabled_at" is null
          and "platform_local_accounts"."recovery_started_at" is null)
        or ("platform_local_accounts"."status" = 'disabled'
          and "platform_local_accounts"."activated_at" is not null
          and "platform_local_accounts"."disabled_at" is not null)
        or ("platform_local_accounts"."status" = 'recovery_restricted'
          and "platform_local_accounts"."activated_at" is not null
          and "platform_local_accounts"."disabled_at" is null
          and "platform_local_accounts"."recovery_started_at" is not null)),
	CONSTRAINT "platform_local_accounts_timestamps_check" CHECK (date_trunc('milliseconds', "platform_local_accounts"."invited_at") = "platform_local_accounts"."invited_at"
        and date_trunc('milliseconds', "platform_local_accounts"."updated_at") = "platform_local_accounts"."updated_at"
        and "platform_local_accounts"."updated_at" >= "platform_local_accounts"."invited_at"
        and ("platform_local_accounts"."activated_at" is null
          or (date_trunc('milliseconds', "platform_local_accounts"."activated_at") = "platform_local_accounts"."activated_at"
            and "platform_local_accounts"."activated_at" between "platform_local_accounts"."invited_at" and "platform_local_accounts"."updated_at"))
        and ("platform_local_accounts"."disabled_at" is null
          or (date_trunc('milliseconds', "platform_local_accounts"."disabled_at") = "platform_local_accounts"."disabled_at"
            and "platform_local_accounts"."disabled_at" between "platform_local_accounts"."invited_at" and "platform_local_accounts"."updated_at"))
        and ("platform_local_accounts"."recovery_started_at" is null
          or (date_trunc('milliseconds', "platform_local_accounts"."recovery_started_at") = "platform_local_accounts"."recovery_started_at"
            and "platform_local_accounts"."recovery_started_at" between "platform_local_accounts"."invited_at" and "platform_local_accounts"."updated_at")))
);
--> statement-breakpoint
ALTER TABLE "platform_local_accounts" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_local_password_history" (
	"account_id" uuid NOT NULL,
	"credential_version" bigint NOT NULL,
	"password_phc" text NOT NULL,
	"changed_at" timestamp with time zone NOT NULL,
	CONSTRAINT "platform_local_password_history_pkey" PRIMARY KEY("account_id","credential_version"),
	CONSTRAINT "platform_local_password_history_value_check" CHECK ("platform_local_password_history"."credential_version" between 1 and 9007199254740991
        and "platform_local_password_history"."password_phc" like '$argon2id$%'
        and octet_length("platform_local_password_history"."password_phc") between 32 and 1024
        and date_trunc('milliseconds', "platform_local_password_history"."changed_at") = "platform_local_password_history"."changed_at")
);
--> statement-breakpoint
ALTER TABLE "platform_local_password_history" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_system_alert_origins" (
	"tenant_id" uuid NOT NULL,
	"alert_id" uuid NOT NULL,
	"source_occurrence_id" uuid NOT NULL,
	"allow_recursive_sla" boolean NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sla_system_alert_origins_pkey" PRIMARY KEY("tenant_id","alert_id"),
	CONSTRAINT "sla_system_alert_origins_source_key" UNIQUE("tenant_id","source_occurrence_id")
);
--> statement-breakpoint
ALTER TABLE "sla_system_alert_origins" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_system_principal_write_capabilities" (
	"backend_pid" integer NOT NULL,
	"transaction_id" bigint NOT NULL,
	"tenant_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sla_system_principal_write_capabilities_pkey" PRIMARY KEY("backend_pid","transaction_id","tenant_id"),
	CONSTRAINT "sla_system_principal_write_capabilities_identity_check" CHECK ("sla_system_principal_write_capabilities"."backend_pid" > 0 and "sla_system_principal_write_capabilities"."transaction_id" > 0)
);
--> statement-breakpoint
ALTER TABLE "sla_system_principal_write_capabilities" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "totp_credentials" DROP CONSTRAINT "totp_credentials_user_key";--> statement-breakpoint
ALTER TABLE "tenant_service_accounts" DROP CONSTRAINT "tenant_service_accounts_archive_check";--> statement-breakpoint
ALTER TABLE "tenant_service_accounts" ALTER COLUMN "created_by_membership_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_service_accounts" ADD COLUMN "system_owned" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "platform_local_account_ceremonies" ADD CONSTRAINT "platform_local_account_ceremonies_account_fk" FOREIGN KEY ("account_id","user_id") REFERENCES "public"."platform_local_accounts"("id","user_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_local_account_command_receipts" ADD CONSTRAINT "platform_local_account_command_receipts_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_local_account_command_receipts" ADD CONSTRAINT "platform_local_account_command_receipts_actor_session_id_auth_sessions_id_fk" FOREIGN KEY ("actor_session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_local_account_command_receipts" ADD CONSTRAINT "platform_local_account_command_receipts_account_id_platform_local_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."platform_local_accounts"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_local_accounts" ADD CONSTRAINT "platform_local_accounts_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_local_accounts" ADD CONSTRAINT "platform_local_accounts_identifier_fk" FOREIGN KEY ("login_identifier_id","user_id") REFERENCES "public"."user_login_identifiers"("id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_local_password_history" ADD CONSTRAINT "platform_local_password_history_account_id_platform_local_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."platform_local_accounts"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_system_alert_origins" ADD CONSTRAINT "sla_system_alert_origins_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_system_alert_origins" ADD CONSTRAINT "sla_system_alert_origins_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_system_alert_origins" ADD CONSTRAINT "sla_system_alert_origins_occurrence_fk" FOREIGN KEY ("tenant_id","source_occurrence_id") REFERENCES "public"."sla_trigger_occurrences"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_system_principal_write_capabilities" ADD CONSTRAINT "sla_system_principal_write_capabilities_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "platform_local_account_ceremonies_pending_key" ON "platform_local_account_ceremonies" USING btree ("account_id") WHERE "platform_local_account_ceremonies"."state" = 'pending';--> statement-breakpoint
CREATE INDEX "platform_local_account_ceremonies_expiry_idx" ON "platform_local_account_ceremonies" USING btree ("state","expires_at","factor_id");--> statement-breakpoint
CREATE INDEX "platform_local_account_command_receipts_account_idx" ON "platform_local_account_command_receipts" USING btree ("account_id","created_at","command_id");--> statement-breakpoint
CREATE INDEX "platform_local_accounts_inventory_idx" ON "platform_local_accounts" USING btree ("status","id");--> statement-breakpoint
CREATE INDEX "platform_local_password_history_recent_idx" ON "platform_local_password_history" USING btree ("account_id","credential_version");--> statement-breakpoint
CREATE UNIQUE INDEX "totp_credentials_user_live_key" ON "totp_credentials" USING btree ("user_id") WHERE "totp_credentials"."disabled_at" is null;--> statement-breakpoint
ALTER TABLE "tenant_service_accounts" ADD CONSTRAINT "tenant_service_accounts_ownership_check" CHECK (("tenant_service_accounts"."system_owned"
          and "tenant_service_accounts"."key" = 'sla_action_runtime'
          and "tenant_service_accounts"."created_by_membership_id" is null)
        or (not "tenant_service_accounts"."system_owned"
          and "tenant_service_accounts"."key" <> 'sla_action_runtime'
          and "tenant_service_accounts"."created_by_membership_id" is not null));--> statement-breakpoint
ALTER TABLE "tenant_service_accounts" ADD CONSTRAINT "tenant_service_accounts_archive_check" CHECK (("tenant_service_accounts"."system_owned"
          and "tenant_service_accounts"."archived_at" is null
          and "tenant_service_accounts"."archived_by_membership_id" is null
          and "tenant_service_accounts"."archive_reason" is null)
        or (not "tenant_service_accounts"."system_owned" and
          (("tenant_service_accounts"."archived_at" is null and "tenant_service_accounts"."archived_by_membership_id" is null and "tenant_service_accounts"."archive_reason" is null)
        or ("tenant_service_accounts"."archived_at" is not null
          and "tenant_service_accounts"."archived_by_membership_id" is not null
          and "tenant_service_accounts"."archive_reason" is not null
          and "tenant_service_accounts"."archived_at" >= "tenant_service_accounts"."created_at"
          and btrim("tenant_service_accounts"."archive_reason") <> ''
          and char_length("tenant_service_accounts"."archive_reason") <= 500
          and "tenant_service_accounts"."archive_reason" !~ '[[:cntrl:]]'))));--> statement-breakpoint
CREATE POLICY "sla_system_alert_origins_worker_tenant" ON "sla_system_alert_origins" AS PERMISSIVE FOR ALL TO "periapsis_worker" USING ("sla_system_alert_origins"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_system_alert_origins"."tenant_id")) WITH CHECK ("sla_system_alert_origins"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_system_alert_origins"."tenant_id"));
--> statement-breakpoint

-- The SLA action identity is infrastructure-owned. A tenant administrator can
-- neither usurp its reserved key nor attach an API credential or delegated
-- role to it. The capability is a real owner-only row bound to backend and
-- transaction; unlike a custom GUC it cannot be forged by a runtime client.
ALTER TABLE public.sla_system_principal_write_capabilities
  OWNER TO periapsis_migrator;
ALTER TABLE public.sla_system_alert_origins OWNER TO periapsis_migrator;
ALTER TABLE public.platform_local_accounts OWNER TO periapsis_migrator;
ALTER TABLE public.platform_local_account_ceremonies
  OWNER TO periapsis_migrator;
ALTER TABLE public.platform_local_account_command_receipts
  OWNER TO periapsis_migrator;
ALTER TABLE public.platform_local_password_history
  OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER TABLE public.sla_system_principal_write_capabilities
  FORCE ROW LEVEL SECURITY;
ALTER TABLE public.sla_system_alert_origins FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_local_accounts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_local_account_ceremonies
  FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_local_account_command_receipts
  FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_local_password_history FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
REVOKE ALL ON TABLE public.sla_system_principal_write_capabilities,
  public.sla_system_alert_origins,
  public.platform_local_accounts,
  public.platform_local_account_ceremonies,
  public.platform_local_account_command_receipts,
  public.platform_local_password_history
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
CREATE POLICY sla_system_principal_capability_owner_v1
ON public.sla_system_principal_write_capabilities
AS PERMISSIVE FOR ALL TO periapsis_migrator
USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY sla_system_alert_origins_owner_v1
ON public.sla_system_alert_origins AS PERMISSIVE FOR ALL
TO periapsis_sla_worker_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
GRANT SELECT, INSERT ON TABLE public.sla_system_alert_origins
TO periapsis_sla_worker_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_sla_system_principal_write_allowed_v1(
  p_tenant_id uuid
)
RETURNS boolean
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.sla_system_principal_write_capabilities AS capability
    WHERE capability.backend_pid = pg_backend_pid()
      AND capability.transaction_id = txid_current()
      AND capability.tenant_id = p_tenant_id
  );
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_sla_system_principal_write_allowed_v1(uuid)
OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_sla_system_principal_write_allowed_v1(uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_guard_sla_system_principal_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  tenant_id uuid := coalesce(NEW.tenant_id, OLD.tenant_id);
  protected_target boolean := false;
BEGIN
  IF TG_TABLE_NAME = 'tenant_service_accounts' THEN
    protected_target := coalesce(NEW.system_owned, false)
      OR coalesce(OLD.system_owned, false)
      OR coalesce(NEW.key, '') = 'sla_action_runtime'
      OR coalesce(OLD.key, '') = 'sla_action_runtime';
  ELSIF TG_TABLE_NAME = 'tenant_api_credentials' THEN
    SELECT account.system_owned INTO protected_target
    FROM public.tenant_service_accounts AS account
    WHERE account.tenant_id = tenant_id
      AND account.id = coalesce(NEW.service_account_id,
                                OLD.service_account_id);
  ELSIF TG_TABLE_NAME = 'tenant_service_account_role_grants' THEN
    SELECT account.system_owned INTO protected_target
    FROM public.tenant_service_accounts AS account
    WHERE account.tenant_id = tenant_id
      AND account.id = coalesce(NEW.service_account_id,
                                OLD.service_account_id);
  ELSE
    RAISE EXCEPTION 'unsupported SLA system-principal guard relation'
      USING ERRCODE = '55000';
  END IF;
  IF coalesce(protected_target, false)
     AND NOT app.private_sla_system_principal_write_allowed_v1(tenant_id) THEN
    RAISE EXCEPTION 'SLA action runtime identity is system-owned'
      USING ERRCODE = '42501';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_sla_system_principal_catalog_ready_v1()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
  SELECT NOT EXISTS (
      SELECT 1 FROM public.tenants AS tenant
      WHERE NOT EXISTS (
        SELECT 1 FROM public.tenant_service_accounts AS account
        WHERE account.tenant_id = tenant.id
          AND account.key = 'sla_action_runtime'
          AND account.system_owned
          AND account.created_by_membership_id IS NULL
          AND account.archived_at IS NULL
      )
    )
    AND NOT EXISTS (
      SELECT 1 FROM public.tenant_service_accounts AS account
      WHERE account.system_owned IS DISTINCT FROM
            (account.key = 'sla_action_runtime'
             AND account.created_by_membership_id IS NULL
             AND account.archived_at IS NULL)
    )
    AND NOT EXISTS (
      SELECT 1
      FROM public.tenant_api_credentials AS credential
      JOIN public.tenant_service_accounts AS account
        ON account.tenant_id = credential.tenant_id
       AND account.id = credential.service_account_id
      WHERE account.system_owned
    )
    AND NOT EXISTS (
      SELECT 1
      FROM public.tenant_service_account_role_grants AS role_grant
      JOIN public.tenant_service_accounts AS account
        ON account.tenant_id = role_grant.tenant_id
       AND account.id = role_grant.service_account_id
      WHERE account.system_owned
    )
    AND NOT EXISTS (
      SELECT 1 FROM public.sla_system_principal_write_capabilities
    );
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_guard_platform_local_account_append_only_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
  RAISE EXCEPTION 'platform local-account evidence is append-only'
    USING ERRCODE = '55000';
END;
$function$;
--> statement-breakpoint
CREATE TRIGGER platform_local_account_receipts_immutable_v1
BEFORE UPDATE OR DELETE ON public.platform_local_account_command_receipts
FOR EACH ROW EXECUTE FUNCTION
  app.private_guard_platform_local_account_append_only_v1();
--> statement-breakpoint
CREATE TRIGGER platform_local_password_history_immutable_v1
BEFORE UPDATE OR DELETE ON public.platform_local_password_history
FOR EACH ROW EXECUTE FUNCTION
  app.private_guard_platform_local_account_append_only_v1();
--> statement-breakpoint

-- Transaction-local forward declarations let this migration close every ACL
-- before defining the larger bodies below. CREATE OR REPLACE preserves the
-- owner and ACL, and the transaction never exposes a declaration stub.
CREATE FUNCTION app.private_platform_local_account_instant_v1(timestamptz)
RETURNS jsonb LANGUAGE sql IMMUTABLE STRICT
AS $stub$ SELECT 'null'::jsonb $stub$;
CREATE FUNCTION app.private_platform_local_account_document_v1(uuid)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
AS $stub$ SELECT 'null'::jsonb $stub$;
CREATE FUNCTION app.private_require_platform_local_account_authority_v1(
  uuid,text,boolean
) RETURNS uuid LANGUAGE sql VOLATILE SECURITY DEFINER
AS $stub$ SELECT NULL::uuid $stub$;
CREATE FUNCTION app.private_platform_local_account_fleet_v1(uuid)
RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER
AS $stub$ SELECT 'null'::jsonb $stub$;
CREATE FUNCTION app.list_platform_local_accounts_v1(
  uuid,text,uuid,integer,boolean
) RETURNS TABLE(document jsonb) LANGUAGE sql VOLATILE SECURITY DEFINER
AS $stub$ SELECT NULL::jsonb WHERE false $stub$;
CREATE FUNCTION app.get_platform_local_account_v1(uuid,uuid,text)
RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER
AS $stub$ SELECT 'null'::jsonb $stub$;
CREATE FUNCTION app.prepare_platform_local_account_transition_v1(
  uuid,text,uuid,text,uuid,uuid,uuid,bigint,bytea,bytea,bytea,timestamptz
) RETURNS TABLE(
  replayed boolean,result jsonb,planning jsonb,password_history text[],
  pending_factor_id uuid,pending_user_id uuid,pending_purpose text,
  pending_version bigint,pending_factor_revision bigint,
  pending_secret_ciphertext bytea,pending_secret_nonce bytea,
  pending_secret_aad bytea,pending_key_version integer,
  pending_expires_at timestamptz,pending_last_accepted_counter bigint
) LANGUAGE sql VOLATILE SECURITY DEFINER AS $stub$
  SELECT NULL::boolean,NULL::jsonb,NULL::jsonb,NULL::text[],NULL::uuid,
    NULL::uuid,NULL::text,NULL::bigint,NULL::bigint,NULL::bytea,NULL::bytea,
    NULL::bytea,NULL::integer,NULL::timestamptz,NULL::bigint WHERE false
$stub$;
CREATE FUNCTION app.apply_platform_local_account_transition_v1(jsonb)
RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER
AS $stub$ SELECT 'null'::jsonb $stub$;
CREATE FUNCTION app.record_platform_local_account_enrollment_failure_v1(jsonb)
RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER
AS $stub$ SELECT NULL::void $stub$;
--> statement-breakpoint

ALTER FUNCTION app.private_sla_system_principal_catalog_ready_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_guard_platform_local_account_append_only_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_local_account_instant_v1(timestamptz)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_local_account_document_v1(uuid)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_require_platform_local_account_authority_v1(
  uuid,text,boolean) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_local_account_fleet_v1(uuid)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.list_platform_local_accounts_v1(
  uuid,text,uuid,integer,boolean) OWNER TO periapsis_migrator;
ALTER FUNCTION app.get_platform_local_account_v1(uuid,uuid,text)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.prepare_platform_local_account_transition_v1(
  uuid,text,uuid,text,uuid,uuid,uuid,bigint,bytea,bytea,bytea,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.apply_platform_local_account_transition_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.record_platform_local_account_enrollment_failure_v1(jsonb)
  OWNER TO periapsis_migrator;
--> statement-breakpoint

REVOKE ALL ON FUNCTION app.private_sla_system_principal_catalog_ready_v1(),
  app.private_guard_platform_local_account_append_only_v1(),
  app.private_platform_local_account_instant_v1(timestamptz),
  app.private_platform_local_account_document_v1(uuid),
  app.private_require_platform_local_account_authority_v1(uuid,text,boolean),
  app.private_platform_local_account_fleet_v1(uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.list_platform_local_accounts_v1(
    uuid,text,uuid,integer,boolean),
  app.get_platform_local_account_v1(uuid,uuid,text),
  app.prepare_platform_local_account_transition_v1(
    uuid,text,uuid,text,uuid,uuid,uuid,bigint,bytea,bytea,bytea,timestamptz),
  app.apply_platform_local_account_transition_v1(jsonb),
  app.record_platform_local_account_enrollment_failure_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.list_platform_local_accounts_v1(
    uuid,text,uuid,integer,boolean),
  app.get_platform_local_account_v1(uuid,uuid,text),
  app.prepare_platform_local_account_transition_v1(
    uuid,text,uuid,text,uuid,uuid,uuid,bigint,bytea,bytea,bytea,timestamptz),
  app.apply_platform_local_account_transition_v1(jsonb),
  app.record_platform_local_account_enrollment_failure_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_sla_system_principal_catalog_ready_v1()
TO periapsis_sla_readiness_owner;
--> statement-breakpoint

COMMENT ON TABLE public.platform_local_accounts IS
  'Safe lifecycle shell for explicitly administered platform-local human accounts; protected password, ceremony, and MFA material is physically separate.';
COMMENT ON TABLE public.platform_local_account_ceremonies IS
  'Encrypted one-time invite/recovery TOTP enrollment envelopes and bounded proof attempt state; no plaintext token or secret is stored.';
COMMENT ON TABLE public.platform_local_account_command_receipts IS
  'Append-only actor-scoped idempotency receipts containing safe projections only; first-response one-time artifacts are never replayed.';
COMMENT ON TABLE public.platform_local_password_history IS
  'Private append-only Argon2id history used only by the transaction-owned Go password verifier; never projected or audited.';
--> statement-breakpoint

CREATE FUNCTION app.platform_local_account_runtime_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET quote_all_identifiers = off
SET TimeZone = 'UTC'
SET DateStyle = 'ISO, YMD'
SET IntervalStyle = 'postgres'
SET extra_float_digits = 3
SET bytea_output = 'hex'
SET standard_conforming_strings = on
SET lc_numeric = 'C'
AS $function$
DECLARE
  relation_name text;
  function_identity text;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'platform_local_accounts','platform_local_account_ceremonies',
    'platform_local_account_command_receipts',
    'platform_local_password_history'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = relation.relnamespace
      WHERE namespace.nspname = 'public'
        AND relation.relname = relation_name
        AND relation.relkind = 'r'
        AND relation.relrowsecurity AND relation.relforcerowsecurity
        AND pg_catalog.pg_get_userbyid(relation.relowner) =
          'periapsis_migrator'
    ) OR has_table_privilege('periapsis_api',
         format('public.%I',relation_name),'SELECT,INSERT,UPDATE,DELETE')
       OR has_table_privilege('periapsis_worker',
         format('public.%I',relation_name),'SELECT,INSERT,UPDATE,DELETE')
       OR has_table_privilege('periapsis_notifier',
         format('public.%I',relation_name),'SELECT,INSERT,UPDATE,DELETE') THEN
      RETURN false;
    END IF;
  END LOOP;
  FOREACH function_identity IN ARRAY ARRAY[
    'app.list_platform_local_accounts_v1(uuid,text,uuid,integer,boolean)',
    'app.get_platform_local_account_v1(uuid,uuid,text)',
    'app.prepare_platform_local_account_transition_v1(uuid,text,uuid,text,uuid,uuid,uuid,bigint,bytea,bytea,bytea,timestamp with time zone)',
    'app.apply_platform_local_account_transition_v1(jsonb)',
    'app.record_platform_local_account_enrollment_failure_v1(jsonb)'
  ] LOOP
    IF to_regprocedure(function_identity) IS NULL
       OR NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_proc AS procedure
         WHERE procedure.oid = to_regprocedure(function_identity)
           AND procedure.prosecdef
           AND pg_catalog.pg_get_userbyid(procedure.proowner) =
             'periapsis_migrator'
       )
       OR NOT has_function_privilege(
         'periapsis_api',function_identity,'EXECUTE')
       OR has_function_privilege(
         'periapsis_worker',function_identity,'EXECUTE')
       OR has_function_privilege(
         'periapsis_notifier',function_identity,'EXECUTE')
       OR EXISTS (
         SELECT 1 FROM pg_catalog.pg_proc AS procedure
         CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(
           procedure.proacl,
           pg_catalog.acldefault('f',procedure.proowner)
         )) AS privilege
         WHERE procedure.oid = to_regprocedure(function_identity)
           AND privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN app.private_sla_system_principal_catalog_ready_v1()
    AND EXISTS (SELECT 1 FROM pg_catalog.pg_trigger AS trigger
      WHERE trigger.tgrelid =
            'public.platform_local_account_command_receipts'::regclass
        AND trigger.tgname = 'platform_local_account_receipts_immutable_v1'
        AND trigger.tgenabled = 'O' AND NOT trigger.tgisinternal)
    AND EXISTS (SELECT 1 FROM pg_catalog.pg_trigger AS trigger
      WHERE trigger.tgrelid =
            'public.platform_local_password_history'::regclass
        AND trigger.tgname = 'platform_local_password_history_immutable_v1'
        AND trigger.tgenabled = 'O' AND NOT trigger.tgisinternal);
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.platform_local_account_runtime_schema_readiness_v1()
OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.platform_local_account_runtime_schema_readiness_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.platform_local_account_runtime_schema_readiness_v1()
TO periapsis_api,periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.apply_platform_local_account_transition_v1(
  p_command jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  actor_id uuid;
  session_id uuid;
  authentication_method text;
  command_id uuid;
  action text;
  account_id uuid;
  new_account_id uuid;
  new_user_id uuid;
  expected_revision bigint;
  applied_at timestamptz;
  display_name text;
  login_identifier text;
  protected_recovery boolean;
  reason text;
  idempotency_digest bytea;
  request_digest bytea;
  audit jsonb;
  plan jsonb;
  issue jsonb;
  confirmed jsonb;
  replacement_phc text;
  prior_receipt public.platform_local_account_command_receipts%ROWTYPE;
  target public.platform_local_accounts%ROWTYPE;
  ceremony public.platform_local_account_ceremonies%ROWTYPE;
  credential public.local_break_glass_credentials%ROWTYPE;
  before_document jsonb;
  after_document jsonb;
  fleet jsonb;
  issue_factor_id uuid;
  issue_user_id uuid;
  issue_account_id uuid;
  issue_purpose text;
  issue_token_digest bytea;
  issue_ciphertext bytea;
  issue_nonce bytea;
  issue_aad bytea;
  issue_key_version integer;
  issue_expires_at timestamptz;
  confirmed_factor_id uuid;
  confirmed_ciphertext bytea;
  confirmed_nonce bytea;
  confirmed_aad bytea;
  confirmed_key_version integer;
  confirmed_counter bigint;
  next_credential_version integer;
  audit_action text;
  artifact_issued boolean := false;
  result jsonb;
BEGIN
  IF p_command IS NULL OR jsonb_typeof(p_command) <> 'object'
     OR pg_column_size(p_command) > 131072
     OR (SELECT count(*) FROM jsonb_object_keys(p_command)) <> 20
     OR EXISTS (
       SELECT 1 FROM jsonb_object_keys(p_command) AS key(name)
       WHERE key.name <> ALL (ARRAY[
         'sessionId','authenticationMethod','commandId','action','accountId',
         'newAccountId','newUserId','expectedRevision','at','displayName',
         'canonicalLoginIdentifier','protectedRecoveryPrincipal','reason',
         'idempotencyKeyDigest','publicRequestDigest','issueEnrollment',
         'replacementPasswordPhc','confirmedFactor','plan','audit'
       ]::text[])
     ) THEN
    RAISE EXCEPTION 'invalid platform local-account command shape'
      USING ERRCODE = '22023';
  END IF;
  BEGIN
    session_id := (p_command ->> 'sessionId')::uuid;
    authentication_method := p_command ->> 'authenticationMethod';
    command_id := (p_command ->> 'commandId')::uuid;
    action := p_command ->> 'action';
    account_id := CASE WHEN p_command -> 'accountId' = 'null'::jsonb
      THEN NULL ELSE (p_command ->> 'accountId')::uuid END;
    new_account_id := CASE WHEN p_command -> 'newAccountId' = 'null'::jsonb
      THEN NULL ELSE (p_command ->> 'newAccountId')::uuid END;
    new_user_id := CASE WHEN p_command -> 'newUserId' = 'null'::jsonb
      THEN NULL ELSE (p_command ->> 'newUserId')::uuid END;
    expected_revision := (p_command ->> 'expectedRevision')::bigint;
    idempotency_digest := decode(p_command ->> 'idempotencyKeyDigest','base64');
    request_digest := decode(p_command ->> 'publicRequestDigest','base64');
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'invalid platform local-account command values'
      USING ERRCODE = '22023';
  END;
  IF uuid_extract_version(session_id) IS DISTINCT FROM 7
     OR uuid_extract_version(command_id) IS DISTINCT FROM 7
     OR action NOT IN (
       'invite','activate','disable','recover','enable','rotate_password'
     )
     OR expected_revision NOT BETWEEN 0 AND 9007199254740990
     OR octet_length(idempotency_digest) <> 32
     OR octet_length(request_digest) <> 32
     OR (action = 'invite' AND (
       account_id IS NOT NULL
       OR uuid_extract_version(new_account_id) IS DISTINCT FROM 7
       OR uuid_extract_version(new_user_id) IS DISTINCT FROM 7
       OR new_account_id = new_user_id OR expected_revision <> 0))
     OR (action <> 'invite' AND (
       uuid_extract_version(account_id) IS DISTINCT FROM 7
       OR new_account_id IS NOT NULL OR new_user_id IS NOT NULL
       OR expected_revision < 1)) THEN
    RAISE EXCEPTION 'invalid platform local-account command identity'
      USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_require_platform_local_account_authority_v1(
    session_id,authentication_method,true
  );
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'platform-local-account-fleet:v1', 1900193
  ));

  -- Replay is resolved before timestamps, generated IDs, replacement material
  -- or audit envelope. A later HTTP retry may legitimately carry fresh audit
  -- context and a newly generated one-time artifact that must not be issued.
  SELECT receipt.* INTO prior_receipt
  FROM public.platform_local_account_command_receipts AS receipt
  WHERE receipt.actor_user_id = actor_id
    AND receipt.idempotency_key_digest = idempotency_digest
  FOR SHARE;
  IF FOUND THEN
    IF prior_receipt.action IS DISTINCT FROM action
       OR prior_receipt.expected_revision IS DISTINCT FROM expected_revision
       OR prior_receipt.public_request_digest IS DISTINCT FROM request_digest
       OR (action <> 'invite'
         AND prior_receipt.account_id IS DISTINCT FROM account_id) THEN
      RAISE EXCEPTION 'platform local-account idempotency conflict'
        USING ERRCODE = '23505';
    END IF;
    RETURN prior_receipt.result_snapshot || jsonb_build_object(
      'replayed',true,'artifactIssued',false
    );
  END IF;

  BEGIN
    applied_at := (p_command ->> 'at')::timestamptz;
    display_name := CASE WHEN p_command -> 'displayName' = 'null'::jsonb
      THEN NULL ELSE p_command ->> 'displayName' END;
    login_identifier := CASE
      WHEN p_command -> 'canonicalLoginIdentifier' = 'null'::jsonb
      THEN NULL ELSE p_command ->> 'canonicalLoginIdentifier' END;
    protected_recovery := CASE
      WHEN p_command -> 'protectedRecoveryPrincipal' = 'null'::jsonb
      THEN NULL ELSE (p_command ->> 'protectedRecoveryPrincipal')::boolean END;
    reason := p_command ->> 'reason';
    issue := p_command -> 'issueEnrollment';
    confirmed := p_command -> 'confirmedFactor';
    plan := p_command -> 'plan';
    audit := p_command -> 'audit';
    replacement_phc := CASE
      WHEN p_command -> 'replacementPasswordPhc' = 'null'::jsonb
      THEN NULL ELSE p_command ->> 'replacementPasswordPhc' END;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'invalid platform local-account protected command'
      USING ERRCODE = '22023';
  END;
  IF applied_at IS NULL OR date_trunc('milliseconds',applied_at) <> applied_at
     OR applied_at NOT BETWEEN transaction_timestamp() - interval '5 minutes'
                           AND transaction_timestamp() + interval '30 seconds'
     OR reason IS NULL OR octet_length(reason) NOT BETWEEN 1 AND 500
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(reason)
     OR jsonb_typeof(plan) <> 'object' OR pg_column_size(plan) > 16384
     OR jsonb_typeof(audit) <> 'object' OR pg_column_size(audit) > 8192
     OR uuid_extract_version((audit ->> 'requestId')::uuid) IS DISTINCT FROM 7
     OR uuid_extract_version((audit ->> 'correlationId')::uuid)
          IS DISTINCT FROM 7
     OR audit ->> 'ipAddress' IS NULL
     OR (audit ->> 'ipAddress')::inet IS NULL
     OR audit ->> 'userAgent' IS NULL
     OR octet_length(audit ->> 'userAgent') NOT BETWEEN 1 AND 512
     OR audit ->> 'userAgent' ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid platform local-account command context'
      USING ERRCODE = '22023';
  END IF;
  IF action = 'invite' THEN
    IF display_name IS NULL OR octet_length(display_name) NOT BETWEEN 1 AND 160
       OR btrim(display_name) <> display_name
       OR display_name ~ '[[:cntrl:]]'
       OR login_identifier IS NULL
       OR login_identifier <> lower(btrim(login_identifier))
       OR octet_length(login_identifier) NOT BETWEEN 3 AND 320
       OR position('@' in login_identifier) <= 1
       OR login_identifier ~ '[[:cntrl:]]'
       OR protected_recovery IS NULL
       OR jsonb_typeof(issue) <> 'object'
       OR confirmed <> 'null'::jsonb OR replacement_phc IS NOT NULL THEN
      RAISE EXCEPTION 'invalid platform local-account invite material'
        USING ERRCODE = '22023';
    END IF;
  ELSE
    IF display_name IS NOT NULL OR login_identifier IS NOT NULL
       OR protected_recovery IS NOT NULL THEN
      RAISE EXCEPTION 'unexpected platform local-account create fields'
        USING ERRCODE = '22023';
    END IF;
    SELECT account.* INTO target
    FROM public.platform_local_accounts AS account
    WHERE account.id = account_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'platform local account does not exist'
        USING ERRCODE = 'P0002';
    END IF;
    IF target.revision IS DISTINCT FROM expected_revision THEN
      RAISE EXCEPTION 'platform local-account revision conflict'
        USING ERRCODE = '40001';
    END IF;
    before_document := app.private_platform_local_account_document_v1(
      target.id
    );
    fleet := app.private_platform_local_account_fleet_v1(target.id);
    IF action IN ('disable','recover')
       AND target.protected_recovery_principal
       AND coalesce((fleet ->> 'currentPrincipalReady')::boolean,false)
       AND (fleet ->> 'otherReadyHumanPrincipals')::integer = 0 THEN
      RAISE EXCEPTION 'platform local-account recovery floor conflict'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  -- The application planner is pure, but the writer independently freezes
  -- its observable core and applies fixed consequences for every transition.
  IF (plan ->> 'action') IS DISTINCT FROM action
     OR (plan ->> 'expectedRevision')::bigint IS DISTINCT FROM
        expected_revision
     OR (plan ->> 'nextRevision')::bigint IS DISTINCT FROM
        (CASE WHEN action = 'invite' THEN 1 ELSE expected_revision + 1 END)
     OR (plan ->> 'nextIdentityEpoch')::bigint IS DISTINCT FROM
        (CASE WHEN action = 'invite' THEN 1 ELSE target.identity_epoch + 1 END)
     OR (plan ->> 'accountId')::uuid IS DISTINCT FROM
        coalesce(account_id,new_account_id)
     OR (plan ->> 'userId')::uuid IS DISTINCT FROM
        coalesce(target.user_id,new_user_id) THEN
    RAISE EXCEPTION 'platform local-account plan does not match locked state'
      USING ERRCODE = '55000';
  END IF;

  IF action IN ('invite','recover') THEN
    BEGIN
      issue_account_id := (issue ->> 'accountId')::uuid;
      issue_user_id := (issue ->> 'userId')::uuid;
      issue_factor_id := (issue ->> 'factorId')::uuid;
      issue_purpose := issue ->> 'purpose';
      issue_token_digest := decode(issue ->> 'ceremonyTokenDigest','base64');
      issue_ciphertext := decode(issue ->> 'ciphertext','base64');
      issue_nonce := decode(issue ->> 'nonce','base64');
      issue_aad := decode(issue ->> 'aad','base64');
      issue_key_version := (issue ->> 'keyVersion')::integer;
      issue_expires_at := (issue ->> 'expiresAt')::timestamptz;
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'invalid platform local-account enrollment envelope'
        USING ERRCODE = '22023';
    END;
    IF jsonb_typeof(issue) <> 'object'
       OR issue_account_id IS DISTINCT FROM coalesce(account_id,new_account_id)
       OR issue_user_id IS DISTINCT FROM coalesce(target.user_id,new_user_id)
       OR uuid_extract_version(issue_factor_id) IS DISTINCT FROM 7
       OR issue_factor_id IN (issue_account_id,issue_user_id)
       OR issue_purpose IS DISTINCT FROM
          (CASE WHEN action = 'invite' THEN 'invite' ELSE 'recover' END)
       OR (issue ->> 'version')::bigint <> 1
       OR (issue ->> 'factorRevision')::bigint <> 1
       OR octet_length(issue_token_digest) <> 32
       OR octet_length(issue_ciphertext) NOT BETWEEN 17 AND 8192
       OR octet_length(issue_nonce) <> 12
       OR octet_length(issue_aad) NOT BETWEEN 1 AND 1024
       OR issue_key_version NOT BETWEEN 1 AND 32767
       OR date_trunc('milliseconds',issue_expires_at) <> issue_expires_at
       OR issue_expires_at <= applied_at
       OR issue_expires_at > applied_at + interval '30 minutes' THEN
      RAISE EXCEPTION 'invalid platform local-account enrollment material'
        USING ERRCODE = '22023';
    END IF;
  ELSIF issue <> 'null'::jsonb THEN
    RAISE EXCEPTION 'unexpected platform local-account enrollment material'
      USING ERRCODE = '22023';
  END IF;

  IF action IN ('activate','rotate_password') THEN
    IF replacement_phc IS NULL
       OR replacement_phc NOT LIKE '$argon2id$%'
       OR octet_length(replacement_phc) NOT BETWEEN 32 AND 1024 THEN
      RAISE EXCEPTION 'invalid platform local-account password envelope'
        USING ERRCODE = '22023';
    END IF;
  ELSIF replacement_phc IS NOT NULL THEN
    RAISE EXCEPTION 'unexpected platform local-account password material'
      USING ERRCODE = '22023';
  END IF;

  IF action = 'invite' THEN
    IF EXISTS (SELECT 1 FROM public.users AS local_user
      WHERE local_user.email = login_identifier)
       OR EXISTS (SELECT 1 FROM public.user_login_identifiers AS identifier
      WHERE identifier.kind = 'local_email'
        AND identifier.canonical_value = login_identifier) THEN
      RAISE EXCEPTION 'platform local-account identifier conflict'
        USING ERRCODE = '23505';
    END IF;
    INSERT INTO public.users (
      id,email,display_name,active,version,authentication_revision,
      created_at,updated_at
    ) VALUES (
      new_user_id,login_identifier,display_name,true,1,1,
      applied_at,applied_at
    );
    INSERT INTO public.user_login_identifiers (
      id,user_id,kind,canonical_value,created_at,updated_at
    ) VALUES (
      uuidv7(),new_user_id,'local_email',login_identifier,
      applied_at,applied_at
    ) RETURNING id INTO account_id;
    INSERT INTO public.platform_local_accounts (
      id,user_id,login_identifier_id,status,protected_recovery_principal,
      revision,identity_epoch,invited_at,updated_at
    ) VALUES (
      new_account_id,new_user_id,account_id,'invited',protected_recovery,
      1,1,applied_at,applied_at
    );
    account_id := new_account_id;
    IF protected_recovery THEN
      INSERT INTO public.user_platform_roles (
        id,user_id,role_id,granted_by_user_id,granted_at
      ) SELECT uuidv7(),new_user_id,role.id,actor_id,applied_at
      FROM public.platform_roles AS role
      WHERE role.key = 'platform_super_admin';
      IF NOT FOUND THEN
        RAISE EXCEPTION 'platform super-administrator role is unavailable'
          USING ERRCODE = '55000';
      END IF;
    END IF;
    INSERT INTO public.platform_local_account_ceremonies (
      factor_id,account_id,user_id,purpose,version,factor_revision,
      ceremony_token_digest,secret_ciphertext,secret_nonce,secret_aad,
      key_version,state,attempts,maximum_attempts,expires_at,
      created_at,updated_at
    ) VALUES (
      issue_factor_id,account_id,new_user_id,'invite',1,1,
      issue_token_digest,issue_ciphertext,issue_nonce,issue_aad,
      issue_key_version,'pending',0,5,issue_expires_at,
      applied_at,applied_at
    );
    artifact_issued := true;
    audit_action := 'platform.local_account.invited';

  ELSE
    SELECT stored.* INTO credential
    FROM public.local_break_glass_credentials AS stored
    WHERE stored.user_id = target.user_id
    FOR UPDATE;
    IF action = 'activate' THEN
      IF target.status NOT IN ('invited','recovery_restricted')
         OR confirmed IS NULL OR jsonb_typeof(confirmed) <> 'object' THEN
        RAISE EXCEPTION 'platform local-account activation conflict'
          USING ERRCODE = '55000';
      END IF;
      SELECT pending.* INTO ceremony
      FROM public.platform_local_account_ceremonies AS pending
      WHERE pending.account_id = target.id AND pending.state = 'pending'
      FOR UPDATE;
      IF NOT FOUND OR ceremony.expires_at <= applied_at
         OR ceremony.attempts >= ceremony.maximum_attempts THEN
        RAISE EXCEPTION 'platform local-account enrollment proof rejected'
          USING ERRCODE = 'P1003';
      END IF;
      BEGIN
        confirmed_factor_id := (confirmed ->> 'factorId')::uuid;
        confirmed_ciphertext := decode(confirmed ->> 'ciphertext','base64');
        confirmed_nonce := decode(confirmed ->> 'nonce','base64');
        confirmed_aad := decode(confirmed ->> 'aad','base64');
        confirmed_key_version := (confirmed ->> 'keyVersion')::integer;
        confirmed_counter := (confirmed ->> 'acceptedCounter')::bigint;
      EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'invalid confirmed platform TOTP factor'
          USING ERRCODE = '22023';
      END;
      IF confirmed_factor_id IS DISTINCT FROM ceremony.factor_id
         OR (confirmed ->> 'revision')::bigint <> ceremony.factor_revision
         OR octet_length(confirmed_ciphertext) NOT BETWEEN 17 AND 8192
         OR octet_length(confirmed_nonce) <> 12
         OR octet_length(confirmed_aad) NOT BETWEEN 1 AND 1024
         OR confirmed_key_version NOT BETWEEN 1 AND 32767
         OR confirmed_counter < 0
         OR confirmed ->> 'encryptionAlgorithm' <> 'aes-256-gcm'
         OR confirmed ->> 'otpAlgorithm' <> 'SHA1'
         OR (confirmed ->> 'digits')::integer <> 6
         OR (confirmed ->> 'periodSeconds')::integer <> 30 THEN
        RAISE EXCEPTION 'invalid confirmed platform TOTP factor'
          USING ERRCODE = '22023';
      END IF;
      UPDATE public.totp_credentials AS old_factor
      SET disabled_at = coalesce(old_factor.disabled_at,applied_at),
          updated_at = greatest(old_factor.updated_at,applied_at)
      WHERE old_factor.user_id = target.user_id
        AND old_factor.disabled_at IS NULL;
      INSERT INTO public.totp_credentials (
        id,user_id,secret_ciphertext,secret_nonce,secret_aad,key_version,
        encryption_algorithm,otp_algorithm,digits,period_seconds,
        confirmed_at,last_accepted_counter,security_revision,
        created_at,updated_at
      ) VALUES (
        confirmed_factor_id,target.user_id,confirmed_ciphertext,
        confirmed_nonce,confirmed_aad,confirmed_key_version,
        'aes-256-gcm','SHA1',6,30,applied_at,confirmed_counter,1,
        applied_at,applied_at
      );
      IF credential.id IS NULL THEN
        next_credential_version := 1;
        INSERT INTO public.local_break_glass_credentials (
          id,user_id,login_identifier_id,password_phc,password_algorithm,
          password_version,must_rotate,changed_at,created_at,updated_at
        ) VALUES (
          uuidv7(),target.user_id,target.login_identifier_id,replacement_phc,
          'argon2id',next_credential_version,false,applied_at,
          applied_at,applied_at
        );
      ELSE
        IF credential.password_version >= 2147483647 THEN
          RAISE EXCEPTION 'platform local credential version is exhausted'
            USING ERRCODE = '22003';
        END IF;
        next_credential_version := credential.password_version + 1;
        UPDATE public.local_break_glass_credentials AS stored
        SET password_phc = replacement_phc,
            password_version = next_credential_version,
            must_rotate = false,disabled_at = NULL,changed_at = applied_at,
            updated_at = applied_at
        WHERE stored.id = credential.id;
      END IF;
      INSERT INTO public.platform_local_password_history (
        account_id,credential_version,password_phc,changed_at
      ) VALUES (
        target.id,next_credential_version,replacement_phc,applied_at
      );
      UPDATE public.user_login_identifiers AS identifier
      SET verified_at = coalesce(identifier.verified_at,applied_at),
          retired_at = NULL,retire_reason = NULL,updated_at = applied_at
      WHERE identifier.id = target.login_identifier_id
        AND identifier.user_id = target.user_id;
      UPDATE public.platform_local_account_ceremonies AS pending
      SET state = 'confirmed',confirmed_at = applied_at,
          updated_at = applied_at
      WHERE pending.factor_id = ceremony.factor_id;
      UPDATE public.platform_local_accounts AS account
      SET status = 'active',revision = account.revision + 1,
          identity_epoch = account.identity_epoch + 1,
          activated_at = coalesce(account.activated_at,applied_at),
          disabled_at = NULL,recovery_started_at = NULL,
          updated_at = applied_at
      WHERE account.id = target.id;
      audit_action := 'platform.local_account.activated';

    ELSIF action = 'disable' THEN
      IF target.status NOT IN ('active','recovery_restricted')
         OR credential.id IS NULL THEN
        RAISE EXCEPTION 'platform local-account disable conflict'
          USING ERRCODE = '55000';
      END IF;
      UPDATE public.local_break_glass_credentials AS stored
      SET disabled_at = coalesce(stored.disabled_at,applied_at),
          updated_at = applied_at
      WHERE stored.id = credential.id;
      UPDATE public.platform_local_accounts AS account
      SET status = 'disabled',revision = account.revision + 1,
          identity_epoch = account.identity_epoch + 1,
          disabled_at = applied_at,updated_at = applied_at
      WHERE account.id = target.id;
      audit_action := 'platform.local_account.disabled';

    ELSIF action = 'recover' THEN
      IF target.status NOT IN ('active','disabled')
         OR credential.id IS NULL THEN
        RAISE EXCEPTION 'platform local-account recovery conflict'
          USING ERRCODE = '55000';
      END IF;
      UPDATE public.platform_local_account_ceremonies AS pending
      SET state = 'retired',retired_at = applied_at,updated_at = applied_at
      WHERE pending.account_id = target.id AND pending.state = 'pending';
      UPDATE public.local_break_glass_credentials AS stored
      SET must_rotate = true,
          disabled_at = coalesce(stored.disabled_at,applied_at),
          updated_at = applied_at
      WHERE stored.id = credential.id;
      UPDATE public.totp_credentials AS factor
      SET disabled_at = coalesce(factor.disabled_at,applied_at),
          updated_at = greatest(factor.updated_at,applied_at)
      WHERE factor.user_id = target.user_id
        AND factor.disabled_at IS NULL;
      UPDATE public.recovery_codes AS recovery
      SET consumed_at = coalesce(recovery.consumed_at,applied_at)
      WHERE recovery.user_id = target.user_id
        AND recovery.consumed_at IS NULL;
      INSERT INTO public.platform_local_account_ceremonies (
        factor_id,account_id,user_id,purpose,version,factor_revision,
        ceremony_token_digest,secret_ciphertext,secret_nonce,secret_aad,
        key_version,state,attempts,maximum_attempts,expires_at,
        created_at,updated_at
      ) VALUES (
        issue_factor_id,target.id,target.user_id,'recover',1,1,
        issue_token_digest,issue_ciphertext,issue_nonce,issue_aad,
        issue_key_version,'pending',0,5,issue_expires_at,
        applied_at,applied_at
      );
      UPDATE public.platform_local_accounts AS account
      SET status = 'recovery_restricted',revision = account.revision + 1,
          identity_epoch = account.identity_epoch + 1,
          disabled_at = NULL,recovery_started_at = applied_at,
          updated_at = applied_at
      WHERE account.id = target.id;
      artifact_issued := true;
      audit_action := 'platform.local_account.recovery_started';

    ELSIF action = 'enable' THEN
      IF target.status <> 'disabled' OR credential.id IS NULL
         OR NOT EXISTS (SELECT 1
           FROM public.totp_credentials AS factor
           WHERE factor.user_id = target.user_id
             AND factor.confirmed_at IS NOT NULL
             AND factor.disabled_at IS NULL
             AND factor.last_accepted_counter IS NOT NULL) THEN
        RAISE EXCEPTION 'platform local-account enable conflict'
          USING ERRCODE = '55000';
      END IF;
      UPDATE public.local_break_glass_credentials AS stored
      SET disabled_at = NULL,must_rotate = false,updated_at = applied_at
      WHERE stored.id = credential.id;
      UPDATE public.platform_local_accounts AS account
      SET status = 'active',revision = account.revision + 1,
          identity_epoch = account.identity_epoch + 1,
          disabled_at = NULL,recovery_started_at = NULL,
          updated_at = applied_at
      WHERE account.id = target.id;
      audit_action := 'platform.local_account.enabled';

    ELSE
      IF action <> 'rotate_password' OR target.status <> 'active'
         OR credential.id IS NULL OR credential.disabled_at IS NOT NULL
         OR credential.password_version >= 2147483647 THEN
        RAISE EXCEPTION 'platform local-account password rotation conflict'
          USING ERRCODE = '55000';
      END IF;
      next_credential_version := credential.password_version + 1;
      UPDATE public.local_break_glass_credentials AS stored
      SET password_phc = replacement_phc,
          password_version = next_credential_version,
          must_rotate = false,changed_at = applied_at,updated_at = applied_at
      WHERE stored.id = credential.id;
      INSERT INTO public.platform_local_password_history (
        account_id,credential_version,password_phc,changed_at
      ) VALUES (
        target.id,next_credential_version,replacement_phc,applied_at
      );
      UPDATE public.platform_local_accounts AS account
      SET revision = account.revision + 1,
          identity_epoch = account.identity_epoch + 1,
          updated_at = applied_at
      WHERE account.id = target.id;
      audit_action := 'platform.local_account.password_rotated';
    END IF;

    IF action IN ('activate','disable','recover','rotate_password') THEN
      UPDATE public.auth_sessions AS session
      SET revoked_at = coalesce(session.revoked_at,
            greatest(applied_at,session.created_at)),
          revoke_reason = coalesce(session.revoke_reason,
            'platform_local_account_' || action)
      WHERE session.user_id = target.user_id
        AND session.revoked_at IS NULL;
    END IF;
    IF action IN ('activate','disable','recover','enable','rotate_password') THEN
      UPDATE public.auth_challenges AS challenge
      SET consumed_at = coalesce(challenge.consumed_at,
            greatest(applied_at,challenge.created_at)),
          last_attempt_at = coalesce(challenge.last_attempt_at,applied_at)
      WHERE challenge.user_id = target.user_id
        AND challenge.consumed_at IS NULL;
      UPDATE public.users AS local_user
      SET authentication_revision = local_user.authentication_revision + 1,
          version = local_user.version + 1,updated_at = applied_at
      WHERE local_user.id = target.user_id
        AND local_user.authentication_revision < 9007199254740991
        AND local_user.version < 2147483647;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'platform local-account user revision is exhausted'
          USING ERRCODE = '22003';
      END IF;
    END IF;
  END IF;

  after_document := app.private_platform_local_account_document_v1(account_id);
  INSERT INTO public.platform_audit_events (
    id,sequence,occurred_at,actor_type,actor_user_id,action,
    resource_type,resource_id,request_id,correlation_id,ip_address,
    user_agent,authentication_method,outcome,reason,before,after,metadata
  ) VALUES (
    command_id,1,applied_at,'user',actor_id,audit_action,
    'platform_local_account',account_id,(audit ->> 'requestId')::uuid,
    (audit ->> 'correlationId')::uuid,(audit ->> 'ipAddress')::inet,
    audit ->> 'userAgent',authentication_method,'success',reason,
    before_document,after_document,jsonb_build_object(
      'commandId',command_id,'action',action,'contentRedacted',true
    )
  );
  result := jsonb_build_object('account',after_document);
  INSERT INTO public.platform_local_account_command_receipts (
    command_id,actor_user_id,actor_session_id,account_id,action,
    expected_revision,idempotency_key_digest,public_request_digest,
    result_snapshot,artifact_issued,created_at
  ) VALUES (
    command_id,actor_id,session_id,account_id,action,expected_revision,
    idempotency_digest,request_digest,result,artifact_issued,applied_at
  );
  RETURN result || jsonb_build_object(
    'replayed',false,'artifactIssued',artifact_issued
  );
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.record_platform_local_account_enrollment_failure_v1(
  p_command jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  session_id uuid;
  authentication_method text;
  account_id uuid;
  expected_revision bigint;
  ceremony_digest bytea;
  failed_at timestamptz;
  pending public.platform_local_account_ceremonies%ROWTYPE;
BEGIN
  IF p_command IS NULL OR jsonb_typeof(p_command) <> 'object'
     OR pg_column_size(p_command) > 8192 THEN
    RAISE EXCEPTION 'invalid platform local enrollment failure request'
      USING ERRCODE = '22023';
  END IF;
  BEGIN
    session_id := (p_command ->> 'sessionId')::uuid;
    authentication_method := p_command ->> 'authenticationMethod';
    account_id := (p_command ->> 'accountId')::uuid;
    expected_revision := (p_command ->> 'expectedRevision')::bigint;
    ceremony_digest := decode(p_command ->> 'ceremonyTokenDigest','base64');
    failed_at := (p_command ->> 'at')::timestamptz;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'invalid platform local enrollment failure values'
      USING ERRCODE = '22023';
  END;
  PERFORM app.private_require_platform_local_account_authority_v1(
    session_id,authentication_method,true
  );
  PERFORM 1 FROM public.platform_local_accounts AS account
  WHERE account.id = account_id AND account.revision = expected_revision
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform local-account revision conflict'
      USING ERRCODE = '40001';
  END IF;
  SELECT ceremony.* INTO pending
  FROM public.platform_local_account_ceremonies AS ceremony
  WHERE ceremony.account_id = account_id AND ceremony.state = 'pending'
  FOR UPDATE;
  IF NOT FOUND OR pending.ceremony_token_digest IS DISTINCT FROM
       ceremony_digest OR pending.expires_at <= failed_at THEN
    RETURN;
  END IF;
  UPDATE public.platform_local_account_ceremonies AS ceremony
  SET attempts = least(ceremony.attempts + 1,ceremony.maximum_attempts),
      state = CASE WHEN ceremony.attempts + 1 >= ceremony.maximum_attempts
        THEN 'failed' ELSE ceremony.state END,
      retired_at = CASE WHEN ceremony.attempts + 1 >=
        ceremony.maximum_attempts THEN failed_at ELSE NULL END,
      failure_reason = CASE WHEN ceremony.attempts + 1 >=
        ceremony.maximum_attempts THEN 'proof_attempts_exhausted' ELSE NULL END,
      updated_at = failed_at
  WHERE ceremony.factor_id = pending.factor_id;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_guard_sla_system_principal_v1()
OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_guard_sla_system_principal_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
CREATE TRIGGER aaa_tenant_service_accounts_sla_system_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_service_accounts
FOR EACH ROW EXECUTE FUNCTION app.private_guard_sla_system_principal_v1();
--> statement-breakpoint
CREATE TRIGGER aaa_tenant_api_credentials_sla_system_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_api_credentials
FOR EACH ROW EXECUTE FUNCTION app.private_guard_sla_system_principal_v1();
--> statement-breakpoint
CREATE TRIGGER aaa_tenant_service_account_roles_sla_system_guard_v1
BEFORE INSERT OR UPDATE OR DELETE
ON public.tenant_service_account_role_grants
FOR EACH ROW EXECUTE FUNCTION app.private_guard_sla_system_principal_v1();
--> statement-breakpoint

CREATE FUNCTION app.private_ensure_sla_system_principal_v1(p_tenant_id uuid)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  account_id uuid;
BEGIN
  IF p_tenant_id IS NULL OR NOT EXISTS (
    SELECT 1 FROM public.tenants AS tenant WHERE tenant.id = p_tenant_id
  ) THEN
    RAISE EXCEPTION 'SLA system-principal tenant does not exist'
      USING ERRCODE = '23503';
  END IF;
  INSERT INTO public.sla_system_principal_write_capabilities (
    backend_pid, transaction_id, tenant_id, created_at
  ) VALUES (
    pg_backend_pid(), txid_current(), p_tenant_id,
    transaction_timestamp()
  ) ON CONFLICT DO NOTHING;
  INSERT INTO public.tenant_service_accounts (
    id, tenant_id, key, display_name, description,
    created_by_membership_id, system_owned, version, created_at, updated_at
  ) VALUES (
    uuidv7(), p_tenant_id, 'sla_action_runtime',
    'SLA action runtime',
    'Protected non-login identity for atomic SLA trigger effects.',
    NULL, true, 1, transaction_timestamp(), transaction_timestamp()
  ) ON CONFLICT (tenant_id, key) DO NOTHING
  RETURNING id INTO account_id;
  IF account_id IS NULL THEN
    SELECT account.id INTO account_id
    FROM public.tenant_service_accounts AS account
    WHERE account.tenant_id = p_tenant_id
      AND account.key = 'sla_action_runtime'
      AND account.system_owned
      AND account.archived_at IS NULL
    FOR SHARE;
  END IF;
  DELETE FROM public.sla_system_principal_write_capabilities AS capability
  WHERE capability.backend_pid = pg_backend_pid()
    AND capability.transaction_id = txid_current()
    AND capability.tenant_id = p_tenant_id;
  IF account_id IS NULL THEN
    RAISE EXCEPTION 'reserved SLA action runtime identity is poisoned'
      USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.tenant_api_credentials AS credential
    WHERE credential.tenant_id = p_tenant_id
      AND credential.service_account_id = account_id
  ) OR EXISTS (
    SELECT 1 FROM public.tenant_service_account_role_grants AS role_grant
    WHERE role_grant.tenant_id = p_tenant_id
      AND role_grant.service_account_id = account_id
  ) THEN
    RAISE EXCEPTION 'SLA action runtime identity has forbidden authority'
      USING ERRCODE = '55000';
  END IF;
  RETURN account_id;
EXCEPTION WHEN OTHERS THEN
  DELETE FROM public.sla_system_principal_write_capabilities AS capability
  WHERE capability.backend_pid = pg_backend_pid()
    AND capability.transaction_id = txid_current()
    AND capability.tenant_id = p_tenant_id;
  RAISE;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_ensure_sla_system_principal_v1(uuid)
OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_ensure_sla_system_principal_v1(uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_seed_sla_system_principal_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.private_ensure_sla_system_principal_v1(NEW.tenant_id);
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_seed_sla_system_principal_v1()
OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_seed_sla_system_principal_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
CREATE TRIGGER tenant_authorization_state_seed_sla_principal_v1
AFTER INSERT ON public.tenant_authorization_states
FOR EACH ROW EXECUTE FUNCTION app.private_seed_sla_system_principal_v1();
--> statement-breakpoint
SELECT app.private_ensure_sla_system_principal_v1(tenant.id)
FROM public.tenants AS tenant ORDER BY tenant.id;
--> statement-breakpoint

CREATE TRIGGER sla_system_alert_origins_immutable_v1
BEFORE UPDATE OR DELETE ON public.sla_system_alert_origins
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_append_only_v1();
--> statement-breakpoint
CREATE FUNCTION app.private_guard_sla_system_alert_recursion_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
BEGIN
  IF NEW.object_type = 'alert' AND EXISTS (
    SELECT 1 FROM public.sla_system_alert_origins AS origin
    WHERE origin.tenant_id = NEW.tenant_id
      AND origin.alert_id = NEW.object_id
      AND NOT origin.allow_recursive_sla
  ) THEN
    RAISE EXCEPTION 'SLA recursion is disabled for this system alert'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_guard_sla_system_alert_recursion_v1()
OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_guard_sla_system_alert_recursion_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
CREATE TRIGGER aaa_sla_instances_system_alert_recursion_v1
BEFORE INSERT OR UPDATE OF tenant_id, object_type, object_id
ON public.sla_instances
FOR EACH ROW EXECUTE FUNCTION app.private_guard_sla_system_alert_recursion_v1();
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_platform_local_account_instant_v1(
  p_value timestamp with time zone
)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT to_jsonb(to_char(p_value AT TIME ZONE 'UTC',
    'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'));
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_platform_local_account_document_v1(
  p_account_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  result jsonb;
BEGIN
  SELECT jsonb_build_object(
    'id', account.id,
    'userId', account.user_id,
    'displayName', local_user.display_name,
    'loginIdentifier', identifier.canonical_value,
    'status', account.status,
    'loginIdentifierStatus', CASE
      WHEN identifier.retired_at IS NOT NULL THEN 'disabled'
      WHEN identifier.verified_at IS NOT NULL THEN 'verified'
      ELSE 'pending' END,
    'credentialStatus', CASE account.status
      WHEN 'invited' THEN 'pending'
      WHEN 'recovery_restricted' THEN 'pending'
      WHEN 'disabled' THEN 'disabled'
      ELSE 'active' END,
    'credentialVersion', coalesce(credential.password_version, 0),
    'confirmedAcceptableFactors', CASE
      WHEN account.status IN ('invited','recovery_restricted') THEN 0
      ELSE (SELECT count(*)
        FROM public.totp_credentials AS factor
        WHERE factor.user_id = account.user_id
          AND factor.confirmed_at IS NOT NULL
          AND factor.disabled_at IS NULL
          AND factor.last_accepted_counter IS NOT NULL)
      END,
    'protectedRecoveryPrincipal', account.protected_recovery_principal,
    'revision', account.revision,
    'identityEpoch', account.identity_epoch,
    'invitedAt', app.private_platform_local_account_instant_v1(
      account.invited_at),
    'activatedAt', CASE WHEN account.activated_at IS NULL THEN 'null'::jsonb
      ELSE app.private_platform_local_account_instant_v1(account.activated_at)
      END,
    'disabledAt', CASE WHEN account.disabled_at IS NULL THEN 'null'::jsonb
      ELSE app.private_platform_local_account_instant_v1(account.disabled_at)
      END,
    'recoveryStartedAt', CASE WHEN account.recovery_started_at IS NULL
      THEN 'null'::jsonb ELSE app.private_platform_local_account_instant_v1(
        account.recovery_started_at) END,
    'updatedAt', app.private_platform_local_account_instant_v1(
      account.updated_at)
  ) INTO result
  FROM public.platform_local_accounts AS account
  JOIN public.users AS local_user ON local_user.id = account.user_id
  JOIN public.user_login_identifiers AS identifier
    ON identifier.id = account.login_identifier_id
   AND identifier.user_id = account.user_id
  LEFT JOIN public.local_break_glass_credentials AS credential
    ON credential.user_id = account.user_id
   AND credential.login_identifier_id = account.login_identifier_id
  WHERE account.id = p_account_id;
  IF result IS NULL THEN
    RAISE EXCEPTION 'platform local account does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN result;
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_require_platform_local_account_authority_v1(
  p_session_id uuid,
  p_authentication_method text,
  p_write boolean
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  read_actor_id uuid;
BEGIN
  IF p_write IS NULL THEN
    RAISE EXCEPTION 'invalid platform local-account authority request'
      USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id,
    CASE WHEN p_write THEN 'platform.identity_account.manage'
         ELSE 'platform.identity_account.read' END,
    p_authentication_method
  );
  IF p_write THEN
    read_actor_id := app.private_require_platform_identity_permission_v1(
      p_session_id,'platform.identity_account.read',p_authentication_method
    );
    IF read_actor_id IS DISTINCT FROM actor_id OR actor_id IS DISTINCT FROM
       app.private_require_recent_local_mfa_policy_session_v1(
         p_session_id,NULL,p_authentication_method
       ) THEN
      RAISE EXCEPTION 'fresh local platform account authority is required'
        USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN actor_id;
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.list_platform_local_accounts_v1(
  p_session_id uuid,
  p_authentication_method text,
  p_after uuid DEFAULT NULL,
  p_limit integer DEFAULT 50,
  p_include_disabled boolean DEFAULT false
)
RETURNS TABLE(document jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101
     OR p_include_disabled IS NULL
     OR (p_after IS NOT NULL
       AND uuid_extract_version(p_after) IS DISTINCT FROM 7) THEN
    RAISE EXCEPTION 'invalid platform local-account list request'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_require_platform_local_account_authority_v1(
    p_session_id,p_authentication_method,false
  );
  RETURN QUERY
  SELECT app.private_platform_local_account_document_v1(account.id)
  FROM public.platform_local_accounts AS account
  WHERE (p_after IS NULL OR account.id > p_after)
    AND (p_include_disabled OR account.status <> 'disabled')
  ORDER BY account.id
  LIMIT p_limit;
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.get_platform_local_account_v1(
  p_session_id uuid,
  p_account_id uuid,
  p_authentication_method text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_account_id IS NULL
     OR uuid_extract_version(p_account_id) IS DISTINCT FROM 7 THEN
    RAISE EXCEPTION 'invalid platform local-account read request'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_require_platform_local_account_authority_v1(
    p_session_id,p_authentication_method,false
  );
  RETURN app.private_platform_local_account_document_v1(p_account_id);
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_platform_local_account_fleet_v1(
  p_account_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  target_ready boolean := false;
  other_ready integer := 0;
BEGIN
  -- Lock every lifecycle row participating in the proof. Concurrent user,
  -- role, credential, identifier or factor retirement must wait until the
  -- protected transition commits or rolls back.
  PERFORM account.id
  FROM public.platform_local_accounts AS account
  JOIN public.users AS local_user ON local_user.id = account.user_id
  JOIN public.user_login_identifiers AS identifier
    ON identifier.id = account.login_identifier_id
   AND identifier.user_id = account.user_id
  JOIN public.local_break_glass_credentials AS credential
    ON credential.user_id = account.user_id
   AND credential.login_identifier_id = account.login_identifier_id
  JOIN public.user_platform_roles AS user_role
    ON user_role.user_id = account.user_id AND user_role.revoked_at IS NULL
  JOIN public.platform_roles AS role
    ON role.id = user_role.role_id AND role.key = 'platform_super_admin'
  JOIN public.totp_credentials AS factor
    ON factor.user_id = account.user_id
   AND factor.confirmed_at IS NOT NULL
   AND factor.disabled_at IS NULL
   AND factor.last_accepted_counter IS NOT NULL
  WHERE account.protected_recovery_principal
  ORDER BY account.id, user_role.id, factor.id
  FOR SHARE OF account,local_user,identifier,credential,user_role,role,factor;

  SELECT EXISTS (
    SELECT 1
    FROM public.platform_local_accounts AS account
    JOIN public.users AS local_user
      ON local_user.id = account.user_id AND local_user.active
    JOIN public.user_login_identifiers AS identifier
      ON identifier.id = account.login_identifier_id
     AND identifier.user_id = account.user_id
     AND identifier.kind = 'local_email'
     AND identifier.verified_at IS NOT NULL
     AND identifier.retired_at IS NULL
    JOIN public.local_break_glass_credentials AS credential
      ON credential.user_id = account.user_id
     AND credential.login_identifier_id = account.login_identifier_id
     AND credential.disabled_at IS NULL AND NOT credential.must_rotate
    JOIN public.user_platform_roles AS user_role
      ON user_role.user_id = account.user_id AND user_role.revoked_at IS NULL
    JOIN public.platform_roles AS role
      ON role.id = user_role.role_id AND role.key = 'platform_super_admin'
    WHERE account.id = p_account_id
      AND account.protected_recovery_principal
      AND account.status = 'active'
      AND EXISTS (SELECT 1 FROM public.totp_credentials AS factor
        WHERE factor.user_id = account.user_id
          AND factor.confirmed_at IS NOT NULL
          AND factor.disabled_at IS NULL
          AND factor.last_accepted_counter IS NOT NULL)
  ) INTO target_ready;
  SELECT count(*) INTO other_ready
  FROM public.platform_local_accounts AS account
  JOIN public.users AS local_user
    ON local_user.id = account.user_id AND local_user.active
  JOIN public.user_login_identifiers AS identifier
    ON identifier.id = account.login_identifier_id
   AND identifier.user_id = account.user_id
   AND identifier.kind = 'local_email'
   AND identifier.verified_at IS NOT NULL
   AND identifier.retired_at IS NULL
  JOIN public.local_break_glass_credentials AS credential
    ON credential.user_id = account.user_id
   AND credential.login_identifier_id = account.login_identifier_id
   AND credential.disabled_at IS NULL AND NOT credential.must_rotate
  WHERE account.id <> p_account_id
    AND account.protected_recovery_principal
    AND account.status = 'active'
    AND EXISTS (SELECT 1
      FROM public.user_platform_roles AS user_role
      JOIN public.platform_roles AS role ON role.id = user_role.role_id
      WHERE user_role.user_id = account.user_id
        AND user_role.revoked_at IS NULL
        AND role.key = 'platform_super_admin')
    AND EXISTS (SELECT 1 FROM public.totp_credentials AS factor
      WHERE factor.user_id = account.user_id
        AND factor.confirmed_at IS NOT NULL
        AND factor.disabled_at IS NULL
        AND factor.last_accepted_counter IS NOT NULL);
  RETURN jsonb_build_object(
    'currentPrincipalReady',target_ready,
    'otherReadyHumanPrincipals',other_ready
  );
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.prepare_platform_local_account_transition_v1(
  p_session_id uuid,
  p_authentication_method text,
  p_command_id uuid,
  p_action text,
  p_account_id uuid,
  p_new_account_id uuid,
  p_new_user_id uuid,
  p_expected_revision bigint,
  p_idempotency_key_digest bytea,
  p_public_request_digest bytea,
  p_ceremony_token_digest bytea,
  p_at timestamp with time zone
)
RETURNS TABLE(
  replayed boolean,
  result jsonb,
  planning jsonb,
  password_history text[],
  pending_factor_id uuid,
  pending_user_id uuid,
  pending_purpose text,
  pending_version bigint,
  pending_factor_revision bigint,
  pending_secret_ciphertext bytea,
  pending_secret_nonce bytea,
  pending_secret_aad bytea,
  pending_key_version integer,
  pending_expires_at timestamp with time zone,
  pending_last_accepted_counter bigint
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  actor_id uuid;
  receipt public.platform_local_account_command_receipts%ROWTYPE;
  account public.platform_local_accounts%ROWTYPE;
  document jsonb;
  fleet jsonb;
  ceremony public.platform_local_account_ceremonies%ROWTYPE;
BEGIN
  IF p_command_id IS NULL
     OR uuid_extract_version(p_command_id) IS DISTINCT FROM 7
     OR p_action NOT IN (
       'invite','activate','disable','recover','enable','rotate_password'
     )
     OR p_expected_revision NOT BETWEEN 0 AND 9007199254740990
     OR p_idempotency_key_digest IS NULL
     OR octet_length(p_idempotency_key_digest) <> 32
     OR p_public_request_digest IS NULL
     OR octet_length(p_public_request_digest) <> 32
     OR p_at IS NULL OR date_trunc('milliseconds',p_at) <> p_at
     OR p_at NOT BETWEEN transaction_timestamp() - interval '5 minutes'
                     AND transaction_timestamp() + interval '30 seconds'
     OR (p_action = 'invite' AND (
       p_account_id <> '00000000-0000-0000-0000-000000000000'::uuid
       OR uuid_extract_version(p_new_account_id) IS DISTINCT FROM 7
       OR uuid_extract_version(p_new_user_id) IS DISTINCT FROM 7
       OR p_expected_revision <> 0))
     OR (p_action <> 'invite' AND (
       uuid_extract_version(p_account_id) IS DISTINCT FROM 7
       OR p_new_account_id <> '00000000-0000-0000-0000-000000000000'::uuid
       OR p_new_user_id <> '00000000-0000-0000-0000-000000000000'::uuid
       OR p_expected_revision < 1))
     OR (p_action = 'activate' AND (
       p_ceremony_token_digest IS NULL
       OR octet_length(p_ceremony_token_digest) <> 32))
     OR (p_action <> 'activate' AND p_ceremony_token_digest IS NOT NULL) THEN
    RAISE EXCEPTION 'invalid platform local-account preparation request'
      USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_require_platform_local_account_authority_v1(
    p_session_id,p_authentication_method,true
  );
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'platform-local-account-fleet:v1', 1900193
  ));
  SELECT command.* INTO receipt
  FROM public.platform_local_account_command_receipts AS command
  WHERE command.actor_user_id = actor_id
    AND command.idempotency_key_digest = p_idempotency_key_digest
  FOR SHARE;
  IF FOUND THEN
    IF receipt.action IS DISTINCT FROM p_action
       OR receipt.expected_revision IS DISTINCT FROM p_expected_revision
       OR receipt.public_request_digest IS DISTINCT FROM
          p_public_request_digest
       OR (p_action <> 'invite'
         AND receipt.account_id IS DISTINCT FROM p_account_id) THEN
      RAISE EXCEPTION 'platform local-account idempotency conflict'
        USING ERRCODE = '23505';
    END IF;
    replayed := true;
    result := receipt.result_snapshot || jsonb_build_object(
      'replayed',true,'artifactIssued',false
    );
    RETURN NEXT;
    RETURN;
  END IF;

  IF p_action = 'invite' THEN
    replayed := false;
    planning := jsonb_build_object(
      'snapshot',jsonb_build_object('status','absent','revision',0,
        'identityEpoch',0),
      'recoveryFleet',jsonb_build_object('currentPrincipalReady',false,
        'otherReadyHumanPrincipals',0),
      'freshLocalMFA',true,'protectedWorkflow',true
    );
    password_history := ARRAY[]::text[];
    RETURN NEXT;
    RETURN;
  END IF;

  SELECT target.* INTO account
  FROM public.platform_local_accounts AS target
  WHERE target.id = p_account_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform local account does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  IF account.revision IS DISTINCT FROM p_expected_revision THEN
    RAISE EXCEPTION 'platform local-account revision conflict'
      USING ERRCODE = '40001';
  END IF;
  document := app.private_platform_local_account_document_v1(account.id);
  fleet := app.private_platform_local_account_fleet_v1(account.id);
  IF p_action IN ('activate','rotate_password') THEN
    PERFORM history.credential_version
    FROM public.platform_local_password_history AS history
    WHERE history.account_id = account.id
    ORDER BY history.credential_version
    FOR SHARE;
    SELECT coalesce(array_agg(history.password_phc
      ORDER BY history.credential_version DESC),ARRAY[]::text[])
    INTO password_history
    FROM public.platform_local_password_history AS history
    WHERE history.account_id = account.id;
  ELSE
    password_history := ARRAY[]::text[];
  END IF;
  IF p_action = 'activate' THEN
    SELECT pending.* INTO ceremony
    FROM public.platform_local_account_ceremonies AS pending
    WHERE pending.account_id = account.id AND pending.state = 'pending'
    FOR UPDATE;
    IF NOT FOUND
       OR ceremony.ceremony_token_digest IS DISTINCT FROM
          p_ceremony_token_digest
       OR ceremony.expires_at <= p_at
       OR ceremony.attempts >= ceremony.maximum_attempts THEN
      RAISE EXCEPTION 'platform local-account enrollment proof rejected'
        USING ERRCODE = 'P1003';
    END IF;
    pending_factor_id := ceremony.factor_id;
    pending_user_id := ceremony.user_id;
    pending_purpose := ceremony.purpose;
    pending_version := ceremony.version;
    pending_factor_revision := ceremony.factor_revision;
    pending_secret_ciphertext := ceremony.secret_ciphertext;
    pending_secret_nonce := ceremony.secret_nonce;
    pending_secret_aad := ceremony.secret_aad;
    pending_key_version := ceremony.key_version;
    pending_expires_at := ceremony.expires_at;
    pending_last_accepted_counter := NULL;
  END IF;
  replayed := false;
  planning := jsonb_build_object(
    'snapshot',jsonb_build_object(
      'accountId',account.id,'userId',account.user_id,
      'revision',account.revision,'identityEpoch',account.identity_epoch,
      'status',account.status,
      'loginIdentifierStatus',document->>'loginIdentifierStatus',
      'credentialStatus',document->>'credentialStatus',
      'confirmedAcceptableFactors',
        (document->>'confirmedAcceptableFactors')::integer,
      'protectedRecoveryPrincipal',account.protected_recovery_principal
    ),
    'recoveryFleet',fleet,
    'freshLocalMFA',true,'protectedWorkflow',true
  );
  RETURN NEXT;
END;
$function$;
