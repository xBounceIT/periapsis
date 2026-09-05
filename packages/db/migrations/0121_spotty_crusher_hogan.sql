ALTER TABLE "ticket_workflows" DROP CONSTRAINT "ticket_workflows_timestamps_check";--> statement-breakpoint
ALTER TABLE "ticket_workflows" ADD CONSTRAINT "ticket_workflows_timestamps_check" CHECK ("ticket_workflows"."updated_at" >= "ticket_workflows"."created_at"
        and ("ticket_workflows"."archived_at" is null
          or ("ticket_workflows"."archived_at" >= "ticket_workflows"."created_at"
            and "ticket_workflows"."archived_at" <= "ticket_workflows"."updated_at"
            and not "ticket_workflows"."is_default")));