CREATE TABLE "ticket_comment_commands" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"actor_membership_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result_comment_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ticket_comment_commands_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_comment_commands_replay_key" UNIQUE("tenant_id","actor_membership_id","operation","key_digest"),
	CONSTRAINT "ticket_comment_commands_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_comment_commands"."id") = 7) is true),
	CONSTRAINT "ticket_comment_commands_operation_check" CHECK ("ticket_comment_commands"."operation" in ('alert.comment.create', 'case.comment.create')),
	CONSTRAINT "ticket_comment_commands_digest_check" CHECK (octet_length("ticket_comment_commands"."key_digest") = 32 and octet_length("ticket_comment_commands"."request_digest") = 32)
);
--> statement-breakpoint
ALTER TABLE "ticket_comment_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "ticket_assignment_history" DROP CONSTRAINT "ticket_assignment_history_version_key";--> statement-breakpoint
DROP INDEX "ticket_assignment_history_resource_idx";--> statement-breakpoint
DROP INDEX "ticket_commands_result_idx";--> statement-breakpoint
ALTER TABLE "ticket_assignment_history" ADD COLUMN "alert_id" uuid;--> statement-breakpoint
ALTER TABLE "ticket_assignment_history" ADD COLUMN "case_id" uuid;--> statement-breakpoint
ALTER TABLE "ticket_commands" ADD COLUMN "result_alert_id" uuid;--> statement-breakpoint
ALTER TABLE "ticket_commands" ADD COLUMN "result_case_id" uuid;--> statement-breakpoint
ALTER TABLE "ticket_comment_commands" ADD CONSTRAINT "ticket_comment_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_comment_commands" ADD CONSTRAINT "ticket_comment_commands_actor_membership_fk" FOREIGN KEY ("tenant_id","actor_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_comment_commands" ADD CONSTRAINT "ticket_comment_commands_actor_user_fk" FOREIGN KEY ("tenant_id","actor_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_comment_commands" ADD CONSTRAINT "ticket_comment_commands_result_fk" FOREIGN KEY ("tenant_id","result_comment_id") REFERENCES "public"."ticket_comments"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "ticket_comment_commands_result_idx" ON "ticket_comment_commands" USING btree ("tenant_id","result_comment_id");--> statement-breakpoint
ALTER TABLE "ticket_activities" ADD CONSTRAINT "ticket_activities_actor_service_account_fk" FOREIGN KEY ("tenant_id","actor_service_account_id") REFERENCES "public"."tenant_service_accounts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_assignment_history" ADD CONSTRAINT "ticket_assignment_history_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_assignment_history" ADD CONSTRAINT "ticket_assignment_history_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_commands" ADD CONSTRAINT "ticket_commands_result_alert_fk" FOREIGN KEY ("tenant_id","result_alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_commands" ADD CONSTRAINT "ticket_commands_result_case_fk" FOREIGN KEY ("tenant_id","result_case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE UNIQUE INDEX "ticket_assignment_history_alert_version_key" ON "ticket_assignment_history" USING btree ("tenant_id","alert_id","version") WHERE "ticket_assignment_history"."alert_id" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "ticket_assignment_history_case_version_key" ON "ticket_assignment_history" USING btree ("tenant_id","case_id","version") WHERE "ticket_assignment_history"."case_id" is not null;--> statement-breakpoint
CREATE INDEX "ticket_assignment_history_alert_idx" ON "ticket_assignment_history" USING btree ("tenant_id","alert_id","version");--> statement-breakpoint
CREATE INDEX "ticket_assignment_history_case_idx" ON "ticket_assignment_history" USING btree ("tenant_id","case_id","version");--> statement-breakpoint
CREATE INDEX "ticket_commands_result_alert_idx" ON "ticket_commands" USING btree ("tenant_id","result_alert_id");--> statement-breakpoint
CREATE INDEX "ticket_commands_result_case_idx" ON "ticket_commands" USING btree ("tenant_id","result_case_id");--> statement-breakpoint
ALTER TABLE "ticket_assignment_history" DROP COLUMN "aggregate_kind";--> statement-breakpoint
ALTER TABLE "ticket_assignment_history" DROP COLUMN "aggregate_id";--> statement-breakpoint
ALTER TABLE "ticket_commands" DROP COLUMN "result_aggregate_kind";--> statement-breakpoint
ALTER TABLE "ticket_commands" DROP COLUMN "result_aggregate_id";--> statement-breakpoint
ALTER TABLE "ticket_assignment_history" ADD CONSTRAINT "ticket_assignment_history_resource_check" CHECK (("ticket_assignment_history"."alert_id" is null) <> ("ticket_assignment_history"."case_id" is null));--> statement-breakpoint
ALTER TABLE "ticket_commands" ADD CONSTRAINT "ticket_commands_result_shape_check" CHECK ("ticket_commands"."result_alert_id" is not null or "ticket_commands"."result_case_id" is not null);