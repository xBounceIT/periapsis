CREATE TABLE "tenant_saml_logout_commands" (
	"tenant_id" uuid NOT NULL,
	"operation_run_id" uuid NOT NULL,
	"session_id" uuid NOT NULL,
	"expected_version" bigint NOT NULL,
	"request_upstream" boolean NOT NULL,
	"material_id" uuid NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"request_snapshot" jsonb NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"applied_at" timestamp with time zone NOT NULL,
	CONSTRAINT "tenant_saml_logout_commands_pkey" PRIMARY KEY("tenant_id","operation_run_id"),
	CONSTRAINT "tenant_saml_logout_commands_operation_key" UNIQUE("operation_run_id"),
	CONSTRAINT "tenant_saml_logout_commands_identity_check" CHECK ((uuid_extract_version("tenant_saml_logout_commands"."operation_run_id") = 7) is true
        and "tenant_saml_logout_commands"."operation_run_id" <> "tenant_saml_logout_commands"."session_id"
        and "tenant_saml_logout_commands"."operation_run_id" <> "tenant_saml_logout_commands"."material_id"
        and "tenant_saml_logout_commands"."session_id" <> "tenant_saml_logout_commands"."material_id"),
	CONSTRAINT "tenant_saml_logout_commands_value_check" CHECK ("tenant_saml_logout_commands"."expected_version" > 0
        and octet_length("tenant_saml_logout_commands"."request_digest") = 32
        and jsonb_typeof("tenant_saml_logout_commands"."request_snapshot") = 'object'
        and pg_column_size("tenant_saml_logout_commands"."request_snapshot") between 2 and 16384
        and jsonb_typeof("tenant_saml_logout_commands"."result_snapshot") = 'object'
        and pg_column_size("tenant_saml_logout_commands"."result_snapshot") between 2 and 2097152
        and date_trunc('microseconds', "tenant_saml_logout_commands"."applied_at") = "tenant_saml_logout_commands"."applied_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_saml_logout_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "tenant_saml_session_materials" DROP CONSTRAINT "tenant_saml_session_materials_value_check";--> statement-breakpoint
ALTER TABLE "tenant_saml_session_materials" ALTER COLUMN "id" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "tenant_saml_session_materials" ADD COLUMN "aad_version" integer DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_saml_logout_commands" ADD CONSTRAINT "tenant_saml_logout_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_saml_logout_commands" ADD CONSTRAINT "tenant_saml_logout_commands_session_fk" FOREIGN KEY ("tenant_id","session_id") REFERENCES "public"."auth_session_mfa_states"("tenant_id","session_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_authentication_transactions" ADD CONSTRAINT "tenant_federated_authentication_transactions_tenant_operation_key" UNIQUE("tenant_id","operation_run_id");--> statement-breakpoint
ALTER TABLE "tenant_saml_session_materials" ADD CONSTRAINT "tenant_saml_session_materials_tenant_id_key" UNIQUE("tenant_id","id");--> statement-breakpoint
ALTER TABLE "tenant_saml_session_materials" ADD CONSTRAINT "tenant_saml_session_materials_value_check" CHECK ((uuid_extract_version("tenant_saml_session_materials"."id") = 7) is true
        and (("tenant_saml_session_materials"."session_id" is null) <> ("tenant_saml_session_materials"."continuation_id" is null))
        and "tenant_saml_session_materials"."id" <> coalesce("tenant_saml_session_materials"."session_id", "tenant_saml_session_materials"."continuation_id")
        and "tenant_saml_session_materials"."provider_kind" = 'saml'
        and ("tenant_saml_session_materials"."session_index_digest" is null or octet_length("tenant_saml_session_materials"."session_index_digest") = 32)
        and "tenant_saml_session_materials"."aad_version" in (1, 2)
        and "tenant_saml_session_materials"."key_version" between 1 and 32767
        and octet_length("tenant_saml_session_materials"."ciphertext") between 16 and 16384);