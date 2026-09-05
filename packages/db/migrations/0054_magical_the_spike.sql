CREATE TYPE "public"."ldap_mapping_case_mode" AS ENUM('sensitive', 'insensitive');--> statement-breakpoint
CREATE TYPE "public"."ldap_mapping_matcher_type" AS ENUM('exact_dn', 'exact_cn', 'regex');--> statement-breakpoint
CREATE TYPE "public"."ldap_mapping_reconciliation_mode" AS ENUM('additive', 'authoritative');--> statement-breakpoint
ALTER TABLE "tenant_authorization_commands" DROP CONSTRAINT "tenant_authorization_commands_operation_check";--> statement-breakpoint
ALTER TABLE "operator_team_assignment_epochs" ADD CONSTRAINT "operator_team_assignment_epochs_exact_team_key" UNIQUE("tenant_id","id","operator_team_id");--> statement-breakpoint
ALTER TABLE "tenant_authorization_commands" ADD CONSTRAINT "tenant_authorization_commands_operation_check" CHECK ("tenant_authorization_commands"."operation" in (
        'tenant_role.create',
        'tenant_role_grant.create',
        'tenant_security_group.create',
        'tenant_security_group_membership.create',
        'tenant_security_group_role_grant.create',
        'operator_team_assignment.create',
        'operator_team_roster_entry.create',
        'identity_provider.create',
        'identity_provider_binding.create',
        'identity_mapping.create'
      ));