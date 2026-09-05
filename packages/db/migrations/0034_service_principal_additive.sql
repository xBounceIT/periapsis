CREATE TYPE "public"."tenant_principal_kind" AS ENUM('human', 'service_account');--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "created_by_membership_id" uuid;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "created_by_service_account_id" uuid;--> statement-breakpoint
ALTER TABLE "tenant_roles" ADD COLUMN "principal_kind" "tenant_principal_kind" DEFAULT 'human' NOT NULL;--> statement-breakpoint
ALTER TABLE "audit_events" ADD COLUMN "actor_service_account_id" uuid;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_tenant_id_key" UNIQUE("tenant_id","id");--> statement-breakpoint
ALTER TABLE "tenant_permissions" ADD CONSTRAINT "tenant_permissions_id_service_account_allowed_key" UNIQUE("id","service_account_allowed");--> statement-breakpoint
ALTER TABLE "tenant_roles" ADD CONSTRAINT "tenant_roles_tenant_id_principal_kind_key" UNIQUE("tenant_id","id","principal_kind");--> statement-breakpoint
ALTER TABLE "tenant_memberships" ADD CONSTRAINT "tenant_memberships_tenant_id_user_id_key" UNIQUE("tenant_id","id","user_id");--> statement-breakpoint
ALTER TABLE "tenant_roles" ADD CONSTRAINT "tenant_roles_protected_principal_kind_check" CHECK ("tenant_roles"."protected_role" is false or "tenant_roles"."principal_kind" = 'human');