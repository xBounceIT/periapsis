ALTER TABLE "tenant_saml_logout_commands" DROP CONSTRAINT "tenant_saml_logout_commands_value_check";--> statement-breakpoint
ALTER TABLE "tenant_saml_logout_commands" ADD CONSTRAINT "tenant_saml_logout_commands_value_check" CHECK ("tenant_saml_logout_commands"."expected_version" > 0
        and octet_length("tenant_saml_logout_commands"."request_digest") = 32
        and jsonb_typeof("tenant_saml_logout_commands"."request_snapshot") = 'object'
        and pg_column_size("tenant_saml_logout_commands"."request_snapshot") between 2 and 16384
        and jsonb_typeof("tenant_saml_logout_commands"."result_snapshot") = 'object'
        and pg_column_size("tenant_saml_logout_commands"."result_snapshot") between 2 and 6291456
        and date_trunc('microseconds', "tenant_saml_logout_commands"."applied_at") = "tenant_saml_logout_commands"."applied_at");