ALTER TABLE "customer_contact_commands" DROP CONSTRAINT "customer_contact_commands_result_check";--> statement-breakpoint
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
            and "customer_contact_commands"."result_snapshot" -> 'resource' ->> 'id' = "customer_contact_commands"."result_resource_id"::text
          )
        )
        and (
          "customer_contact_commands"."result_snapshot" ->> 'projection' = 'unavailable'
          and "customer_contact_commands"."result_snapshot" ->> 'operation' = 'legacy.unavailable'
          or "customer_contact_commands"."result_snapshot" ->> 'projection' <> 'unavailable'
          and ("customer_contact_commands"."result_snapshot" #>> '{resource,version}')::integer = "customer_contact_commands"."result_version"
        )
        and (
          "customer_contact_commands"."result_snapshot" ->> 'projection' <> 'operator'
          or "customer_contact_commands"."operation" like 'contact.%'
          and jsonb_array_length(jsonb_path_query_array(
            "customer_contact_commands"."result_snapshot" -> 'resource', '$.keyvalue().key'
          )) = 20
          and "customer_contact_commands"."result_snapshot" -> 'resource' ?& array[
            'firstName', 'lastName', 'email', 'phone', 'function',
            'language', 'timezone', 'escalationPriority', 'contactClass',
            'notificationCategories', 'notificationWindows', 'emailAllowed',
            'active', 'tags', 'linkedMembershipId', 'linkedUserId', 'version',
            'createdAt', 'updatedAt', 'archivedAt'
          ]
          or "customer_contact_commands"."operation" like 'contact_group.%'
          and jsonb_array_length(jsonb_path_query_array(
            "customer_contact_commands"."result_snapshot" -> 'resource', '$.keyvalue().key'
          )) = 11
          and "customer_contact_commands"."result_snapshot" -> 'resource' ?& array[
            'key', 'version', 'name', 'description', 'mode',
            'ruleSchemaVersion', 'rule', 'memberIds', 'createdAt',
            'updatedAt', 'archivedAt'
          ]
          or "customer_contact_commands"."operation" like 'ticket_contact.%'
          and jsonb_array_length(jsonb_path_query_array(
            "customer_contact_commands"."result_snapshot" -> 'resource', '$.keyvalue().key'
          )) = 10
          and "customer_contact_commands"."result_snapshot" -> 'resource' ?& array[
            'ticketKind', 'ticketId', 'contactId', 'role', 'origin',
            'sourceAlertId', 'sourceAlertVersion', 'version', 'createdAt',
            'archivedAt'
          ]
        ));