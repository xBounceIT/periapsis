ALTER TABLE "tenant_saml_session_materials" DROP CONSTRAINT "tenant_saml_session_materials_value_check";--> statement-breakpoint
ALTER TABLE "tenant_saml_session_materials" ALTER COLUMN "key_version" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_saml_session_materials" ALTER COLUMN "ciphertext" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_saml_session_materials" ADD CONSTRAINT "tenant_saml_session_materials_value_check" CHECK ((uuid_extract_version("tenant_saml_session_materials"."id") = 7) is true
        and (("tenant_saml_session_materials"."session_id" is null) <> ("tenant_saml_session_materials"."continuation_id" is null))
        and "tenant_saml_session_materials"."id" <> coalesce("tenant_saml_session_materials"."session_id", "tenant_saml_session_materials"."continuation_id")
        and "tenant_saml_session_materials"."provider_kind" = 'saml'
        and ("tenant_saml_session_materials"."session_index_digest" is null or octet_length("tenant_saml_session_materials"."session_index_digest") = 32)
        and "tenant_saml_session_materials"."aad_version" in (1, 2)
        and ("tenant_saml_session_materials"."key_version" is null) = ("tenant_saml_session_materials"."ciphertext" is null)
        and ("tenant_saml_session_materials"."key_version" is null
          or ("tenant_saml_session_materials"."key_version" between 1 and 32767
            and octet_length("tenant_saml_session_materials"."ciphertext") between 16 and 16384)));