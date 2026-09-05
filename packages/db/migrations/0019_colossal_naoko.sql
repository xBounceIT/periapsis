ALTER TABLE "tenant_authorization_commands" DROP CONSTRAINT "tenant_authorization_commands_operation_check";--> statement-breakpoint
ALTER TABLE "tenant_authorization_commands" ADD CONSTRAINT "tenant_authorization_commands_operation_check" CHECK ("tenant_authorization_commands"."operation" in (
        'tenant_role.create',
        'tenant_role_grant.create',
        'tenant_security_group.create',
        'tenant_security_group_membership.create',
        'tenant_security_group_role_grant.create'
      ));