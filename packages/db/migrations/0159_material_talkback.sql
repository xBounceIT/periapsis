CREATE TABLE "tenant_auth_provider_login_keys" (
	"tenant_id" uuid NOT NULL,
	"binding_family" text NOT NULL,
	"binding_id" uuid NOT NULL,
	"key" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_auth_provider_login_keys_pkey" PRIMARY KEY("tenant_id","key"),
	CONSTRAINT "tenant_auth_provider_login_keys_binding_key" UNIQUE("tenant_id","binding_family","binding_id"),
	CONSTRAINT "tenant_auth_provider_login_keys_exact_key" UNIQUE("tenant_id","binding_family","binding_id","key"),
	CONSTRAINT "tenant_auth_provider_login_keys_family_check" CHECK ("tenant_auth_provider_login_keys"."binding_family" in ('tenant_provider', 'platform_provider')),
	CONSTRAINT "tenant_auth_provider_login_keys_binding_uuidv7_check" CHECK ((uuid_extract_version("tenant_auth_provider_login_keys"."binding_id") = 7) is true),
	CONSTRAINT "tenant_auth_provider_login_keys_key_check" CHECK ("tenant_auth_provider_login_keys"."key" = lower(btrim("tenant_auth_provider_login_keys"."key"))
        and "tenant_auth_provider_login_keys"."key" ~ '^[a-z][a-z0-9_-]{2,63}$'),
	CONSTRAINT "tenant_auth_provider_login_keys_timestamp_check" CHECK ("tenant_auth_provider_login_keys"."updated_at" >= "tenant_auth_provider_login_keys"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_auth_provider_login_keys" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_platform_auth_provider_bindings" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"binding_family" text DEFAULT 'platform_provider' NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"key" text NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"profile_priority" integer DEFAULT 100 NOT NULL,
	"auth_revision" bigint DEFAULT 1 NOT NULL,
	"mapping_revision" bigint DEFAULT 1 NOT NULL,
	"current_access_epoch_id" uuid,
	"created_by_user_id" uuid NOT NULL,
	"updated_by_user_id" uuid NOT NULL,
	"archived_at" timestamp with time zone,
	"archived_by_user_id" uuid,
	"archive_reason" text,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_platform_auth_provider_bindings_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_platform_auth_provider_bindings_exact_key" UNIQUE("tenant_id","id","platform_provider_id"),
	CONSTRAINT "tenant_platform_auth_provider_bindings_provider_key" UNIQUE("tenant_id","platform_provider_id"),
	CONSTRAINT "tenant_platform_auth_provider_bindings_login_key" UNIQUE("tenant_id","key"),
	CONSTRAINT "tenant_platform_auth_provider_bindings_login_claim_key" UNIQUE("tenant_id","binding_family","id","key"),
	CONSTRAINT "tenant_platform_auth_provider_bindings_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_platform_auth_provider_bindings"."id") = 7) is true),
	CONSTRAINT "tenant_platform_auth_provider_bindings_family_check" CHECK ("tenant_platform_auth_provider_bindings"."binding_family" = 'platform_provider'),
	CONSTRAINT "tenant_platform_auth_provider_bindings_key_check" CHECK ("tenant_platform_auth_provider_bindings"."key" = lower(btrim("tenant_platform_auth_provider_bindings"."key"))
        and "tenant_platform_auth_provider_bindings"."key" ~ '^[a-z][a-z0-9_-]{2,63}$'),
	CONSTRAINT "tenant_platform_auth_provider_bindings_priority_check" CHECK ("tenant_platform_auth_provider_bindings"."profile_priority" between 0 and 1000000),
	CONSTRAINT "tenant_platform_auth_provider_bindings_revision_check" CHECK ("tenant_platform_auth_provider_bindings"."auth_revision" between 1 and 9007199254740991
        and "tenant_platform_auth_provider_bindings"."mapping_revision" between 1 and 9007199254740991
        and "tenant_platform_auth_provider_bindings"."version" between 1 and 2147483647),
	CONSTRAINT "tenant_platform_auth_provider_bindings_disabled_check" CHECK (not "tenant_platform_auth_provider_bindings"."enabled" and "tenant_platform_auth_provider_bindings"."current_access_epoch_id" is null),
	CONSTRAINT "tenant_platform_auth_provider_bindings_archive_check" CHECK (("tenant_platform_auth_provider_bindings"."archived_at" is null
          and "tenant_platform_auth_provider_bindings"."archived_by_user_id" is null
          and "tenant_platform_auth_provider_bindings"."archive_reason" is null)
        or ("tenant_platform_auth_provider_bindings"."archived_at" is not null
          and "tenant_platform_auth_provider_bindings"."archived_by_user_id" is not null
          and "tenant_platform_auth_provider_bindings"."archive_reason" is not null
          and not "tenant_platform_auth_provider_bindings"."enabled"
          and "tenant_platform_auth_provider_bindings"."current_access_epoch_id" is null
          and "tenant_platform_auth_provider_bindings"."archived_at" >= "tenant_platform_auth_provider_bindings"."created_at"
          and "tenant_platform_auth_provider_bindings"."archive_reason" = btrim("tenant_platform_auth_provider_bindings"."archive_reason")
          and "tenant_platform_auth_provider_bindings"."archive_reason" <> ''
          and octet_length(convert_to("tenant_platform_auth_provider_bindings"."archive_reason", 'UTF8')) <= 2048
          and "tenant_platform_auth_provider_bindings"."archive_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "tenant_platform_auth_provider_bindings_lifecycle_check" CHECK (isfinite("tenant_platform_auth_provider_bindings"."created_at") and isfinite("tenant_platform_auth_provider_bindings"."updated_at")
        and extract(year from "tenant_platform_auth_provider_bindings"."created_at" at time zone 'UTC') between 1970 and 9999
        and extract(year from "tenant_platform_auth_provider_bindings"."updated_at" at time zone 'UTC') between 1970 and 9999
        and "tenant_platform_auth_provider_bindings"."updated_at" >= "tenant_platform_auth_provider_bindings"."created_at"
        and ("tenant_platform_auth_provider_bindings"."archived_at" is null or (
          isfinite("tenant_platform_auth_provider_bindings"."archived_at")
          and extract(year from "tenant_platform_auth_provider_bindings"."archived_at" at time zone 'UTC') between 1970 and 9999
          and "tenant_platform_auth_provider_bindings"."updated_at" >= "tenant_platform_auth_provider_bindings"."archived_at")))
);
--> statement-breakpoint
ALTER TABLE "tenant_platform_auth_provider_bindings" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_platform_identity_binding_commands" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result_binding_id" uuid NOT NULL,
	"result_version" bigint NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone DEFAULT now() + interval '24 hours' NOT NULL,
	CONSTRAINT "tenant_platform_identity_binding_commands_replay_key" UNIQUE("actor_user_id","operation","key_digest"),
	CONSTRAINT "tenant_platform_identity_binding_commands_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_platform_identity_binding_commands"."id") = 7) is true),
	CONSTRAINT "tenant_platform_identity_binding_commands_operation_check" CHECK ("tenant_platform_identity_binding_commands"."operation" = 'binding.create'),
	CONSTRAINT "tenant_platform_identity_binding_commands_digest_check" CHECK (octet_length("tenant_platform_identity_binding_commands"."key_digest") = 32
        and octet_length("tenant_platform_identity_binding_commands"."request_digest") = 32),
	CONSTRAINT "tenant_platform_identity_binding_commands_result_check" CHECK ("tenant_platform_identity_binding_commands"."result_version" between 1 and 2147483647),
	CONSTRAINT "tenant_platform_identity_binding_commands_retention_check" CHECK ("tenant_platform_identity_binding_commands"."expires_at" > "tenant_platform_identity_binding_commands"."created_at"
        and "tenant_platform_identity_binding_commands"."expires_at" <= "tenant_platform_identity_binding_commands"."created_at" + interval '7 days')
);
--> statement-breakpoint
ALTER TABLE "tenant_platform_identity_binding_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_platform_identity_provider_access_epochs" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"source_id" uuid NOT NULL,
	"sequence" integer NOT NULL,
	"started_by_user_id" uuid NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ended_at" timestamp with time zone,
	"ended_by_user_id" uuid,
	"end_reason" text,
	"version" bigint DEFAULT 1 NOT NULL,
	CONSTRAINT "tenant_platform_identity_provider_access_epochs_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_platform_identity_provider_access_epochs_exact_key" UNIQUE("tenant_id","id","binding_id","platform_provider_id","source_id"),
	CONSTRAINT "tenant_platform_identity_provider_access_epochs_current_key" UNIQUE("tenant_id","id","binding_id","platform_provider_id"),
	CONSTRAINT "tenant_platform_identity_provider_access_epochs_sequence_key" UNIQUE("tenant_id","binding_id","sequence"),
	CONSTRAINT "tenant_platform_identity_provider_access_epochs_source_key" UNIQUE("tenant_id","source_id"),
	CONSTRAINT "tenant_platform_identity_provider_access_epochs_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_platform_identity_provider_access_epochs"."id") = 7) is true),
	CONSTRAINT "tenant_platform_identity_provider_access_epochs_sequence_check" CHECK ("tenant_platform_identity_provider_access_epochs"."sequence" > 0),
	CONSTRAINT "tenant_platform_identity_provider_access_epochs_lifecycle_check" CHECK (("tenant_platform_identity_provider_access_epochs"."ended_at" is null
          and "tenant_platform_identity_provider_access_epochs"."ended_by_user_id" is null
          and "tenant_platform_identity_provider_access_epochs"."end_reason" is null
          and "tenant_platform_identity_provider_access_epochs"."version" = 1)
        or ("tenant_platform_identity_provider_access_epochs"."ended_at" is not null
          and "tenant_platform_identity_provider_access_epochs"."ended_by_user_id" is not null
          and "tenant_platform_identity_provider_access_epochs"."end_reason" is not null
          and "tenant_platform_identity_provider_access_epochs"."ended_at" >= "tenant_platform_identity_provider_access_epochs"."started_at"
          and "tenant_platform_identity_provider_access_epochs"."end_reason" = btrim("tenant_platform_identity_provider_access_epochs"."end_reason")
          and "tenant_platform_identity_provider_access_epochs"."end_reason" <> ''
          and octet_length(convert_to("tenant_platform_identity_provider_access_epochs"."end_reason", 'UTF8')) <= 2048
          and "tenant_platform_identity_provider_access_epochs"."end_reason" !~ '[[:cntrl:]]'
          and "tenant_platform_identity_provider_access_epochs"."version" = 2)),
	CONSTRAINT "tenant_platform_identity_provider_access_epochs_staging_check" CHECK (false)
);
--> statement-breakpoint
ALTER TABLE "tenant_platform_identity_provider_access_epochs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "tenant_auth_provider_bindings" ADD COLUMN "binding_family" text DEFAULT 'tenant_provider' NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_auth_provider_login_keys" ADD CONSTRAINT "tenant_auth_provider_login_keys_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_auth_provider_bindings" ADD CONSTRAINT "tenant_platform_auth_provider_bindings_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_auth_provider_bindings" ADD CONSTRAINT "tenant_platform_auth_provider_bindings_platform_provider_id_platform_auth_providers_id_fk" FOREIGN KEY ("platform_provider_id") REFERENCES "public"."platform_auth_providers"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_auth_provider_bindings" ADD CONSTRAINT "tenant_platform_auth_provider_bindings_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_auth_provider_bindings" ADD CONSTRAINT "tenant_platform_auth_provider_bindings_updated_by_user_id_users_id_fk" FOREIGN KEY ("updated_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_auth_provider_bindings" ADD CONSTRAINT "tenant_platform_auth_provider_bindings_archived_by_user_id_users_id_fk" FOREIGN KEY ("archived_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_auth_provider_bindings" ADD CONSTRAINT "tenant_platform_auth_provider_bindings_provider_fk" FOREIGN KEY ("platform_provider_id") REFERENCES "public"."platform_auth_providers"("id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_identity_binding_commands" ADD CONSTRAINT "tenant_platform_identity_binding_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_identity_binding_commands" ADD CONSTRAINT "tenant_platform_identity_binding_commands_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_identity_binding_commands" ADD CONSTRAINT "tenant_platform_identity_binding_commands_result_fk" FOREIGN KEY ("tenant_id","result_binding_id") REFERENCES "public"."tenant_platform_auth_provider_bindings"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_identity_provider_access_epochs" ADD CONSTRAINT "tenant_platform_identity_provider_access_epochs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_identity_provider_access_epochs" ADD CONSTRAINT "tenant_platform_identity_provider_access_epochs_started_by_user_id_users_id_fk" FOREIGN KEY ("started_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_identity_provider_access_epochs" ADD CONSTRAINT "tenant_platform_identity_provider_access_epochs_ended_by_user_id_users_id_fk" FOREIGN KEY ("ended_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_identity_provider_access_epochs" ADD CONSTRAINT "tenant_platform_identity_provider_access_epochs_binding_fk" FOREIGN KEY ("tenant_id","binding_id","platform_provider_id") REFERENCES "public"."tenant_platform_auth_provider_bindings"("tenant_id","id","platform_provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_identity_provider_access_epochs" ADD CONSTRAINT "tenant_platform_identity_provider_access_epochs_source_fk" FOREIGN KEY ("tenant_id","source_id") REFERENCES "public"."tenant_authorization_sources"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "tenant_auth_provider_login_keys_binding_idx" ON "tenant_auth_provider_login_keys" USING btree ("tenant_id","binding_family","binding_id");--> statement-breakpoint
CREATE INDEX "tenant_platform_auth_provider_bindings_provider_idx" ON "tenant_platform_auth_provider_bindings" USING btree ("platform_provider_id","archived_at","id");--> statement-breakpoint
CREATE INDEX "tenant_platform_auth_provider_bindings_tenant_idx" ON "tenant_platform_auth_provider_bindings" USING btree ("tenant_id","archived_at","id");--> statement-breakpoint
CREATE INDEX "tenant_platform_identity_binding_commands_expiry_idx" ON "tenant_platform_identity_binding_commands" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "tenant_platform_identity_provider_access_epochs_provider_idx" ON "tenant_platform_identity_provider_access_epochs" USING btree ("platform_provider_id","tenant_id","binding_id","sequence");--> statement-breakpoint
ALTER TABLE "tenant_auth_provider_bindings" ADD CONSTRAINT "tenant_auth_provider_bindings_login_claim_key" UNIQUE("tenant_id","binding_family","id","key");--> statement-breakpoint
ALTER TABLE "tenant_auth_provider_bindings" ADD CONSTRAINT "tenant_auth_provider_bindings_family_check" CHECK ("tenant_auth_provider_bindings"."binding_family" = 'tenant_provider');
