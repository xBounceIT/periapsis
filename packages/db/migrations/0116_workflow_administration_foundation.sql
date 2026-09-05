CREATE TABLE "ticket_workflow_commands" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"actor_membership_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"action" text NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result_workflow_id" uuid NOT NULL,
	"result_revision" integer NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone DEFAULT now() + interval '24 hours' NOT NULL,
	CONSTRAINT "ticket_workflow_commands_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_workflow_commands_replay_key" UNIQUE("tenant_id","actor_user_id","action","key_digest"),
	CONSTRAINT "ticket_workflow_commands_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_workflow_commands"."id") = 7) is true),
	CONSTRAINT "ticket_workflow_commands_action_check" CHECK ("ticket_workflow_commands"."action" in (
        'create', 'publish', 'update_metadata',
        'set_default', 'archive', 'restore'
      )),
	CONSTRAINT "ticket_workflow_commands_digest_check" CHECK (octet_length("ticket_workflow_commands"."key_digest") = 32
        and octet_length("ticket_workflow_commands"."request_digest") = 32),
	CONSTRAINT "ticket_workflow_commands_result_check" CHECK ("ticket_workflow_commands"."result_revision" > 0
        and jsonb_typeof("ticket_workflow_commands"."result_snapshot") = 'object'
        and pg_column_size("ticket_workflow_commands"."result_snapshot") <= 524288
        and jsonb_array_length(jsonb_path_query_array(
          "ticket_workflow_commands"."result_snapshot", '$.keyvalue().key'
        )) = 16
        and "ticket_workflow_commands"."result_snapshot" ?& array[
          'schemaVersion', 'action', 'workflowId', 'aggregateKind', 'key',
          'displayName', 'description', 'isDefault', 'status', 'revision',
          'currentVersion', 'states', 'transitions', 'createdAt',
          'updatedAt', 'archivedAt'
        ]
        and ("ticket_workflow_commands"."result_snapshot" ->> 'schemaVersion')::integer = 1
        and "ticket_workflow_commands"."result_snapshot" ->> 'action' = "ticket_workflow_commands"."action"
        and "ticket_workflow_commands"."result_snapshot" ->> 'workflowId' = "ticket_workflow_commands"."result_workflow_id"::text
        and ("ticket_workflow_commands"."result_snapshot" ->> 'revision')::integer = "ticket_workflow_commands"."result_revision"
        and "ticket_workflow_commands"."result_snapshot" ->> 'aggregateKind' in ('alert', 'case')
        and "ticket_workflow_commands"."result_snapshot" ->> 'status' in ('active', 'archived')
        and jsonb_typeof("ticket_workflow_commands"."result_snapshot" -> 'states') = 'array'
        and jsonb_typeof("ticket_workflow_commands"."result_snapshot" -> 'transitions') = 'array'),
	CONSTRAINT "ticket_workflow_commands_retention_check" CHECK ("ticket_workflow_commands"."expires_at" > "ticket_workflow_commands"."created_at"
        and "ticket_workflow_commands"."expires_at" <= "ticket_workflow_commands"."created_at" + interval '7 days')
);
--> statement-breakpoint
ALTER TABLE "ticket_workflow_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "ticket_workflows" ADD COLUMN "revision" integer DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "ticket_workflow_commands" ADD CONSTRAINT "ticket_workflow_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_workflow_commands" ADD CONSTRAINT "ticket_workflow_commands_actor_fk" FOREIGN KEY ("tenant_id","actor_membership_id","actor_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_workflow_commands" ADD CONSTRAINT "ticket_workflow_commands_result_fk" FOREIGN KEY ("tenant_id","result_workflow_id") REFERENCES "public"."ticket_workflows"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "ticket_workflow_commands_expiry_idx" ON "ticket_workflow_commands" USING btree ("expires_at");--> statement-breakpoint
ALTER TABLE "ticket_workflows" ADD CONSTRAINT "ticket_workflows_revision_check" CHECK ("ticket_workflows"."revision" > 0);