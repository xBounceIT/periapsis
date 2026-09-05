CREATE TABLE "platform_identity_account_commands" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"public_request_digest" "bytea" NOT NULL,
	"result_account_id" uuid NOT NULL,
	"result_version" bigint NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone DEFAULT now() + interval '24 hours' NOT NULL,
	CONSTRAINT "platform_identity_account_commands_replay_key" UNIQUE("actor_user_id","operation","platform_provider_id","key_digest"),
	CONSTRAINT "platform_identity_account_commands_id_uuidv7_check" CHECK ((uuid_extract_version("platform_identity_account_commands"."id") = 7) is true),
	CONSTRAINT "platform_identity_account_commands_operation_check" CHECK ("platform_identity_account_commands"."operation" = 'account.prelink'),
	CONSTRAINT "platform_identity_account_commands_digest_check" CHECK (octet_length("platform_identity_account_commands"."key_digest") = 32
        and octet_length("platform_identity_account_commands"."public_request_digest") = 32),
	CONSTRAINT "platform_identity_account_commands_result_check" CHECK ("platform_identity_account_commands"."result_version" = 1),
	CONSTRAINT "platform_identity_account_commands_retention_check" CHECK ("platform_identity_account_commands"."expires_at" > "platform_identity_account_commands"."created_at"
        and "platform_identity_account_commands"."expires_at" <= "platform_identity_account_commands"."created_at" + interval '7 days')
);
--> statement-breakpoint
ALTER TABLE "platform_identity_account_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "platform_identity_account_commands" ADD CONSTRAINT "platform_identity_account_commands_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_identity_account_commands" ADD CONSTRAINT "platform_identity_account_commands_platform_provider_id_platform_auth_providers_id_fk" FOREIGN KEY ("platform_provider_id") REFERENCES "public"."platform_auth_providers"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_identity_account_commands" ADD CONSTRAINT "platform_identity_account_commands_result_fk" FOREIGN KEY ("platform_provider_id","result_account_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "platform_identity_account_commands_expiry_idx" ON "platform_identity_account_commands" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "platform_identity_account_commands_result_idx" ON "platform_identity_account_commands" USING btree ("platform_provider_id","result_account_id");--> statement-breakpoint
CREATE INDEX "platform_federated_external_identities_live_provider_cursor_idx" ON "platform_federated_external_identities" USING btree ("platform_provider_id","id") WHERE "platform_federated_external_identities"."retired_at" is null;