CREATE TABLE "platform_identity_provider_commands" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result_provider_id" uuid NOT NULL,
	"result_version" bigint NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone DEFAULT now() + interval '24 hours' NOT NULL,
	CONSTRAINT "platform_identity_provider_commands_replay_key" UNIQUE("actor_user_id","operation","key_digest"),
	CONSTRAINT "platform_identity_provider_commands_id_uuidv7_check" CHECK ((uuid_extract_version("platform_identity_provider_commands"."id") = 7) is true),
	CONSTRAINT "platform_identity_provider_commands_operation_check" CHECK ("platform_identity_provider_commands"."operation" in ('provider.create.oidc', 'provider.create.saml')),
	CONSTRAINT "platform_identity_provider_commands_digest_check" CHECK (octet_length("platform_identity_provider_commands"."key_digest") = 32
        and octet_length("platform_identity_provider_commands"."request_digest") = 32),
	CONSTRAINT "platform_identity_provider_commands_result_check" CHECK ("platform_identity_provider_commands"."result_version" > 0),
	CONSTRAINT "platform_identity_provider_commands_retention_check" CHECK ("platform_identity_provider_commands"."expires_at" > "platform_identity_provider_commands"."created_at"
        and "platform_identity_provider_commands"."expires_at" <= "platform_identity_provider_commands"."created_at" + interval '7 days')
);
--> statement-breakpoint
ALTER TABLE "platform_identity_provider_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_identity_provider_test_runs" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"provider_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"provider_version" bigint NOT NULL,
	"configuration_revision" bigint NOT NULL,
	"kind" text NOT NULL,
	"status" text NOT NULL,
	"outcome" text,
	"category" text,
	"correlation_id" uuid NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone,
	CONSTRAINT "platform_identity_provider_test_runs_correlation_key" UNIQUE("correlation_id"),
	CONSTRAINT "platform_identity_provider_test_runs_id_uuidv7_check" CHECK ((uuid_extract_version("platform_identity_provider_test_runs"."id") = 7) is true),
	CONSTRAINT "platform_identity_provider_test_runs_revision_check" CHECK ("platform_identity_provider_test_runs"."provider_version" > 0 and "platform_identity_provider_test_runs"."configuration_revision" > 0),
	CONSTRAINT "platform_identity_provider_test_runs_value_check" CHECK ("platform_identity_provider_test_runs"."kind" in ('configuration','connection','trust')
        and "platform_identity_provider_test_runs"."status" in ('running','completed')
        and (("platform_identity_provider_test_runs"."status" = 'running'
            and "platform_identity_provider_test_runs"."outcome" is null
            and "platform_identity_provider_test_runs"."category" is null
            and "platform_identity_provider_test_runs"."completed_at" is null)
          or ("platform_identity_provider_test_runs"."status" = 'completed'
            and "platform_identity_provider_test_runs"."outcome" in ('success','failure','inconclusive')
            and "platform_identity_provider_test_runs"."category" in (
              'success','cancelled','configuration_invalid','destination_blocked',
              'dns_failed','connect_failed','connect_timeout','tls_failed',
              'discovery_unreachable','issuer_mismatch','jwks_invalid',
              'metadata_invalid','certificate_expired','stale_configuration',
              'protocol_failed')
            and "platform_identity_provider_test_runs"."completed_at" >= "platform_identity_provider_test_runs"."started_at")))
);
--> statement-breakpoint
ALTER TABLE "platform_identity_provider_test_runs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "platform_identity_provider_commands" ADD CONSTRAINT "platform_identity_provider_commands_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_identity_provider_commands" ADD CONSTRAINT "platform_identity_provider_commands_result_provider_id_platform_auth_providers_id_fk" FOREIGN KEY ("result_provider_id") REFERENCES "public"."platform_auth_providers"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_identity_provider_test_runs" ADD CONSTRAINT "platform_identity_provider_test_runs_provider_id_platform_auth_providers_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."platform_auth_providers"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_identity_provider_test_runs" ADD CONSTRAINT "platform_identity_provider_test_runs_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "platform_identity_provider_commands_expiry_idx" ON "platform_identity_provider_commands" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "platform_identity_provider_test_runs_provider_idx" ON "platform_identity_provider_test_runs" USING btree ("provider_id","started_at","id");