ALTER TABLE "customer_contact_commands" DROP CONSTRAINT "customer_contact_commands_result_check";--> statement-breakpoint
ALTER TABLE "customer_contact_commands" ADD COLUMN "result_snapshot" jsonb DEFAULT '{"schemaVersion":1,"operation":"legacy.unavailable","projection":"unavailable","resource":null}'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "customer_contact_commands" ADD CONSTRAINT "customer_contact_commands_result_check" CHECK ("customer_contact_commands"."result_version" > 0
        and jsonb_typeof("customer_contact_commands"."result_snapshot") = 'object'
        and pg_column_size("customer_contact_commands"."result_snapshot") <= 524288
        and jsonb_array_length(jsonb_path_query_array(
          "customer_contact_commands"."result_snapshot", '$.keyvalue().key'
        )) = 4
        and "customer_contact_commands"."result_snapshot" ?& array[
          'schemaVersion', 'operation', 'projection', 'resource'
        ]
        and ("customer_contact_commands"."result_snapshot" ->> 'schemaVersion')::integer = 1
        and "customer_contact_commands"."result_snapshot" ->> 'projection' in (
          'operator', 'customer', 'unavailable'
        )
        and (
          ("customer_contact_commands"."result_snapshot" ->> 'projection' = 'unavailable'
            and "customer_contact_commands"."result_snapshot" -> 'resource' = 'null'::jsonb)
          or
          ("customer_contact_commands"."result_snapshot" ->> 'projection' <> 'unavailable'
            and "customer_contact_commands"."result_snapshot" ->> 'operation' = "customer_contact_commands"."operation"
            and jsonb_typeof("customer_contact_commands"."result_snapshot" -> 'resource') = 'object')
        )
        and (
          ("customer_contact_commands"."operation" = 'portal.preference.replace'
            and "customer_contact_commands"."result_snapshot" ->> 'projection' in (
              'customer', 'unavailable'
            ))
          or
          ("customer_contact_commands"."operation" <> 'portal.preference.replace'
            and "customer_contact_commands"."result_snapshot" ->> 'projection' in (
              'operator', 'unavailable'
            ))
        )
        and (
          "customer_contact_commands"."result_snapshot" ->> 'projection' <> 'customer'
          or (
            jsonb_array_length(jsonb_path_query_array(
              "customer_contact_commands"."result_snapshot" -> 'resource', '$.keyvalue().key'
            )) = 13
            and "customer_contact_commands"."result_snapshot" -> 'resource' ?& array[
              'id', 'firstName', 'lastName', 'email', 'phone', 'function',
              'language', 'timezone', 'notificationCategories',
              'notificationWindows', 'emailAllowed', 'active', 'version'
            ]
          )
        ));