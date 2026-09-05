-- V47 comment persistence is closed over one canonical set of validators.  The
-- Go-space helper intentionally mirrors unicode.IsSpace as used by
-- strings.TrimSpace; btrim() is not an equivalent Unicode boundary.
CREATE FUNCTION app.private_ticket_comment_go_space_codepoint_v1(p_codepoint integer)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
  SELECT p_codepoint IN (9,10,11,12,13,32,133,160,5760,8232,8233,8239,8287,12288)
    OR p_codepoint BETWEEN 8192 AND 8202
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_comment_scalars_valid_v1(
  p_value text,
  p_allow_multiline boolean
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
  SELECT p_value IS NOT NULL
    AND NOT EXISTS (
      SELECT 1
      FROM generate_series(1, char_length(p_value)) AS position(index)
      CROSS JOIN LATERAL (
        SELECT ascii(substr(p_value, position.index, 1)) AS codepoint
      ) AS scalar
      WHERE scalar.codepoint BETWEEN 0 AND 8
         OR scalar.codepoint BETWEEN 11 AND 31
         OR scalar.codepoint BETWEEN 127 AND 159
         OR scalar.codepoint IN (8206,8207,8234,8235,8236,8237,8238,
                                 8294,8295,8296,8297)
         OR scalar.codepoint IN (9,10) AND NOT p_allow_multiline
    )
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_comment_entities_valid_v1(p_value text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  entity_value text;
  digit_value integer;
  codepoint bigint;
  position integer;
BEGIN
  IF p_value IS NULL OR p_value ~* '&(lrm|rlm|tab|newline);?' THEN
    RETURN false;
  END IF;
  FOR entity_value IN
    SELECT match[1]
    FROM regexp_matches(p_value, '&#([xX][0-9A-Fa-f]{1,8}|[0-9]{1,10});?', 'g') AS match
  LOOP
    codepoint := 0;
    IF left(entity_value,1) IN ('x','X') THEN
      FOR position IN 2..char_length(entity_value) LOOP
        digit_value := strpos('0123456789abcdef', lower(substr(entity_value,position,1))) - 1;
        codepoint := codepoint * 16 + digit_value;
      END LOOP;
    ELSE
      codepoint := entity_value::bigint;
    END IF;
    IF codepoint > 1114111 OR codepoint BETWEEN 55296 AND 57343
       OR codepoint BETWEEN 0 AND 31
       OR codepoint BETWEEN 127 AND 159
       OR codepoint IN (8206,8207,8234,8235,8236,8237,8238,
                        8294,8295,8296,8297) THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN true;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_comment_timestamp_valid_v1(
  p_value timestamp with time zone
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
  SELECT p_value IS NOT NULL
    AND p_value > '-infinity'::timestamp with time zone
    AND p_value < 'infinity'::timestamp with time zone
    AND p_value >= '0001-01-01 00:00:00+00'::timestamp with time zone
    AND p_value < '10000-01-01 00:00:00+00'::timestamp with time zone
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_comment_display_name_valid_v1(p_value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
  SELECT p_value IS NOT NULL
    AND char_length(p_value) BETWEEN 1 AND 200
    AND NOT app.private_ticket_comment_go_space_codepoint_v1(ascii(substr(p_value,1,1)))
    AND NOT app.private_ticket_comment_go_space_codepoint_v1(
      ascii(substr(p_value,char_length(p_value),1))
    )
    AND app.private_ticket_comment_scalars_valid_v1(p_value, false)
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_comment_markdown_valid_v1(p_value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
  SELECT p_value IS NOT NULL
    AND char_length(p_value) BETWEEN 1 AND 20000
    AND NOT app.private_ticket_comment_go_space_codepoint_v1(ascii(substr(p_value,1,1)))
    AND NOT app.private_ticket_comment_go_space_codepoint_v1(
      ascii(substr(p_value,char_length(p_value),1))
    )
    AND app.private_ticket_comment_scalars_valid_v1(p_value, true)
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_comment_filename_valid_v1(p_value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
  SELECT p_value IS NOT NULL
    AND octet_length(p_value) BETWEEN 1 AND 255
    AND p_value NOT IN ('.','..')
    AND strpos(p_value,'/') = 0
    AND strpos(p_value,E'\\') = 0
    AND NOT app.private_ticket_comment_go_space_codepoint_v1(ascii(substr(p_value,1,1)))
    AND NOT app.private_ticket_comment_go_space_codepoint_v1(
      ascii(substr(p_value,char_length(p_value),1))
    )
    AND app.private_ticket_comment_scalars_valid_v1(p_value, false)
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_comment_edit_reason_valid_v1(p_value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
  SELECT p_value IS NOT NULL
    AND char_length(p_value) BETWEEN 1 AND 500
    AND app.private_ticket_comment_scalars_valid_v1(p_value, false)
    AND EXISTS (
      SELECT 1
      FROM generate_series(1, char_length(p_value)) AS position(index)
      WHERE NOT app.private_ticket_comment_go_space_codepoint_v1(
        ascii(substr(p_value,position.index,1))
      )
    )
    AND p_value !~ '<[/]?[A-Za-z]'
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_comment_uuid_array_valid_v1(
  p_values uuid[],
  p_limit integer
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
  SELECT p_values IS NOT NULL
    AND p_limit BETWEEN 0 AND 100
    AND cardinality(p_values) <= p_limit
    AND array_position(p_values,NULL) IS NULL
    AND NOT EXISTS (
      SELECT 1
      FROM generate_subscripts(p_values,1) AS position(index)
      WHERE (uuid_extract_version(p_values[position.index]) = 7) IS NOT TRUE
         OR position.index > array_lower(p_values,1)
            AND p_values[position.index] <= p_values[position.index - 1]
    )
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_comment_html_valid_v1(p_value text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  tag_value text;
  tag_name text;
  tag_stack text[] := ARRAY[]::text[];
  text_value text;
  title_value text;
  authority_value text;
  entity_value text;
  digit_value integer;
  codepoint bigint;
  position integer;
BEGIN
  IF p_value IS NULL OR octet_length(p_value) NOT BETWEEN 1 AND 100000
     OR app.private_ticket_comment_go_space_codepoint_v1(ascii(substr(p_value,1,1)))
     OR app.private_ticket_comment_go_space_codepoint_v1(
          ascii(substr(p_value,char_length(p_value),1))
        )
     OR NOT app.private_ticket_comment_scalars_valid_v1(p_value, true) THEN
    RETURN false;
  END IF;

  FOR tag_value IN
    SELECT match[1]
    FROM regexp_matches(p_value, '<[^>]*>', 'g') AS match
  LOOP
    IF tag_value !~ '^</?(p|strong|em|ul|ol|li|blockquote|pre|code|h[1-6])>$'
       AND tag_value NOT IN ('<br>','<hr>','</a>')
       AND tag_value !~ '^<a href="[^"<>]*"( title="[^"<>]*")?( rel="nofollow noreferrer")?>$' THEN
      RETURN false;
    END IF;
    IF tag_value ~ '^<a href=' THEN
      text_value := substring(tag_value FROM '^<a href="([^"]*)"');
      title_value := substring(tag_value FROM ' title="([^"]*)"');
      IF text_value = ''
         OR octet_length(text_value)<>char_length(text_value)
         OR regexp_replace(text_value,'&amp;','','g') ~ '&'
         OR strpos(text_value,E'\\')>0
         OR text_value ~ '[{}|`^]'
         OR strpos(text_value,'[')>0 OR strpos(text_value,']')>0
         OR text_value ~ '[[:space:]]'
         OR regexp_replace(text_value,'%[0-9A-Fa-f]{2}','','g') ~ '%'
         OR regexp_replace(
              text_value,'&(amp|lt|gt);|&#(34|39);','','g'
            ) ~ '[''"]'
         OR title_value IS NOT NULL AND regexp_replace(
              title_value,'&(amp|lt|gt);|&#(34|39);','','g'
            ) ~ '[''"&]'
         OR char_length(text_value) > 0 AND (
           app.private_ticket_comment_go_space_codepoint_v1(
             ascii(substr(text_value,1,1))
           )
           OR app.private_ticket_comment_go_space_codepoint_v1(
             ascii(substr(text_value,char_length(text_value),1))
           )
         ) THEN
        RETURN false;
      END IF;
      IF text_value ~ '^[A-Za-z][A-Za-z0-9+.-]*:'
         AND text_value !~ '^https?://' THEN
        RETURN false;
      END IF;
      IF text_value !~ '^https?://' AND text_value ~ '^[^/?#]*:' THEN
        RETURN false;
      END IF;
      IF text_value ~ '^//' THEN
        RETURN false;
      END IF;
      IF text_value ~ '^https?://' THEN
        authority_value := substring(text_value FROM '^https?://([^/?#]+)');
        IF authority_value IS NULL OR authority_value = ''
           OR authority_value !~ '^[A-Za-z0-9._~-]+(:[0-9]+)?$' THEN
          RETURN false;
        END IF;
        IF tag_value !~ ' rel="nofollow noreferrer">$' THEN
          RETURN false;
        END IF;
      ELSIF tag_value ~ ' rel=' THEN
        RETURN false;
      END IF;
    END IF;
    IF tag_value NOT IN ('<br>','<hr>') THEN
      tag_name := substring(tag_value FROM '^</?([a-z][a-z0-9]*)');
      IF left(tag_value,2) = '</' THEN
        IF cardinality(tag_stack) = 0
           OR tag_stack[cardinality(tag_stack)] <> tag_name THEN
          RETURN false;
        END IF;
        tag_stack := tag_stack[1:cardinality(tag_stack)-1];
      ELSE
        tag_stack := array_append(tag_stack,tag_name);
      END IF;
    END IF;
  END LOOP;

  IF cardinality(tag_stack) <> 0 THEN
    RETURN false;
  END IF;

  -- Stored HTML must be byte-for-byte canonical sanitizer output.  These are
  -- the only entity spellings emitted by the shared renderer; accepting any
  -- other named/numeric spelling would admit a representation Go rejects.
  IF regexp_replace(
       p_value,'&(amp|lt|gt);|&#(34|39);','','g'
     ) ~ '&(#|[A-Za-z])' THEN
    RETURN false;
  END IF;

  text_value := regexp_replace(p_value, '<[^>]*>', '', 'g');
  IF text_value ~ '[<>]' THEN
    RETURN false;
  END IF;
  IF regexp_replace(
       text_value,'&(amp|lt|gt);|&#(34|39);','','g'
     ) ~ '[''"&]' THEN
    RETURN false;
  END IF;

  -- html.UnescapeString is part of the Go validation boundary.  Decode all
  -- numeric entities sufficiently to reject controls, bidi controls, invalid
  -- scalar values, and UTF-16 surrogates without rejecting harmless forensic
  -- entities such as &#34;.
  FOR entity_value IN
    SELECT match[1]
    FROM regexp_matches(p_value, '&#([xX][0-9A-Fa-f]{1,8}|[0-9]{1,10});?', 'g') AS match
  LOOP
    codepoint := 0;
    IF left(entity_value,1) IN ('x','X') THEN
      FOR position IN 2..char_length(entity_value) LOOP
        digit_value := strpos('0123456789abcdef', lower(substr(entity_value,position,1))) - 1;
        codepoint := codepoint * 16 + digit_value;
      END LOOP;
    ELSE
      codepoint := entity_value::bigint;
    END IF;
    IF codepoint > 1114111 OR codepoint BETWEEN 55296 AND 57343
       OR codepoint BETWEEN 0 AND 31
       OR codepoint BETWEEN 127 AND 159
       OR codepoint IN (8206,8207,8234,8235,8236,8237,8238,
                        8294,8295,8296,8297) THEN
      RETURN false;
    END IF;
  END LOOP;

  IF NOT app.private_ticket_comment_entities_valid_v1(p_value) THEN
    RETURN false;
  END IF;

  text_value := regexp_replace(
    text_value,
    '(&nbsp;?|&#0*160;?|&#[xX]0*[aA]0;?|[[:space:]])',
    '',
    'g'
  );
  RETURN text_value <> '' OR strpos(p_value,'<hr>') > 0;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.private_ticket_comment_go_space_codepoint_v1(integer)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_comment_scalars_valid_v1(text,boolean)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_comment_entities_valid_v1(text)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_comment_timestamp_valid_v1(timestamp with time zone)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_comment_display_name_valid_v1(text)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_comment_markdown_valid_v1(text)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_comment_filename_valid_v1(text)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_comment_edit_reason_valid_v1(text)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_comment_uuid_array_valid_v1(uuid[],integer)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_comment_html_valid_v1(text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_ticket_comment_go_space_codepoint_v1(integer),
  app.private_ticket_comment_scalars_valid_v1(text,boolean),
  app.private_ticket_comment_entities_valid_v1(text),
  app.private_ticket_comment_timestamp_valid_v1(timestamp with time zone),
  app.private_ticket_comment_display_name_valid_v1(text),
  app.private_ticket_comment_markdown_valid_v1(text),
  app.private_ticket_comment_filename_valid_v1(text),
  app.private_ticket_comment_edit_reason_valid_v1(text),
  app.private_ticket_comment_uuid_array_valid_v1(uuid[],integer),
  app.private_ticket_comment_html_valid_v1(text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION
  app.private_ticket_comment_go_space_codepoint_v1(integer),
  app.private_ticket_comment_scalars_valid_v1(text,boolean),
  app.private_ticket_comment_entities_valid_v1(text),
  app.private_ticket_comment_timestamp_valid_v1(timestamp with time zone),
  app.private_ticket_comment_display_name_valid_v1(text),
  app.private_ticket_comment_markdown_valid_v1(text),
  app.private_ticket_comment_filename_valid_v1(text),
  app.private_ticket_comment_edit_reason_valid_v1(text),
  app.private_ticket_comment_uuid_array_valid_v1(uuid[],integer),
  app.private_ticket_comment_html_valid_v1(text)
TO periapsis_ticket_runtime_owner;
--> statement-breakpoint

-- V47 deliberately does not fabricate a frozen representation for legacy
-- bodies outside the new canonical renderer envelope or for legacy mentions
-- that recorded only mutable user IDs.  Abort before touching customer rows;
-- the migration transaction rolls back the validator catalog changes too.
DO $ticket_comment_v47_legacy_preflight$
DECLARE
  incompatible_body_count bigint;
  unresolved_mention_count bigint;
BEGIN
  SELECT count(*) INTO incompatible_body_count
  FROM public.ticket_comments AS comment
  WHERE NOT app.private_ticket_comment_markdown_valid_v1(
          comment.body_markdown
        )
     OR NOT app.private_ticket_comment_html_valid_v1(comment.body_html);
  IF incompatible_body_count<>0 THEN
    RAISE EXCEPTION
      'V47 comment upgrade requires canonical legacy bodies (% rows)',
      incompatible_body_count
      USING ERRCODE='P47B1';
  END IF;
  SELECT count(*) INTO unresolved_mention_count
  FROM public.ticket_comments AS comment
  WHERE cardinality(comment.mentioned_user_ids)<>0;
  IF unresolved_mention_count<>0 THEN
    RAISE EXCEPTION
      'V47 comment upgrade requires frozen legacy mentions (% rows)',
      unresolved_mention_count
      USING ERRCODE='P47M1';
  END IF;
END
$ticket_comment_v47_legacy_preflight$;
--> statement-breakpoint

CREATE TABLE "ticket_comment_escalation_sources" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"copied_comment_id" uuid NOT NULL,
	"source_comment_id" uuid,
	"source_revision" integer,
	"source_alert_id" uuid,
	"destination_case_id" uuid NOT NULL,
	"legacy_unresolved" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	CONSTRAINT "ticket_comment_escalation_sources_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_comment_escalation_sources_copy_key" UNIQUE("tenant_id","copied_comment_id"),
	CONSTRAINT "ticket_comment_escalation_sources_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_comment_escalation_sources"."id") = 7) is true),
	CONSTRAINT "ticket_comment_escalation_sources_shape_check" CHECK (("ticket_comment_escalation_sources"."legacy_unresolved"
          and "ticket_comment_escalation_sources"."source_comment_id" is null
          and "ticket_comment_escalation_sources"."source_revision" is null
          and "ticket_comment_escalation_sources"."source_alert_id" is null)
        or (not "ticket_comment_escalation_sources"."legacy_unresolved"
          and "ticket_comment_escalation_sources"."source_comment_id" is not null
          and "ticket_comment_escalation_sources"."source_revision" between 1 and 2147483647
          and "ticket_comment_escalation_sources"."source_alert_id" is not null)),
	CONSTRAINT "ticket_comment_escalation_sources_timestamp_check" CHECK (app.private_ticket_comment_timestamp_valid_v1("ticket_comment_escalation_sources"."created_at"))
);
--> statement-breakpoint
ALTER TABLE "ticket_comment_escalation_sources" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_comment_idempotency_keys" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"actor_membership_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"source_kind" text NOT NULL,
	"operation" text NOT NULL,
	"request_digest" "bytea",
	"result_comment_id" uuid,
	"result_revision" integer,
	"legacy_ambiguous" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	CONSTRAINT "ticket_comment_idempotency_keys_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_comment_idempotency_keys_replay_key" UNIQUE("tenant_id","actor_membership_id","key_digest"),
	CONSTRAINT "ticket_comment_idempotency_keys_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_comment_idempotency_keys"."id") = 7) is true),
	CONSTRAINT "ticket_comment_idempotency_keys_digest_check" CHECK (octet_length("ticket_comment_idempotency_keys"."key_digest") = 32
        and "ticket_comment_idempotency_keys"."key_digest" <> decode(repeat('00',32),'hex')
        and ("ticket_comment_idempotency_keys"."request_digest" is null
          or octet_length("ticket_comment_idempotency_keys"."request_digest") = 32
            and "ticket_comment_idempotency_keys"."request_digest" <> decode(repeat('00',32),'hex'))),
	CONSTRAINT "ticket_comment_idempotency_keys_shape_check" CHECK (("ticket_comment_idempotency_keys"."legacy_ambiguous"
          and "ticket_comment_idempotency_keys"."source_kind" = 'ambiguous'
          and "ticket_comment_idempotency_keys"."operation" = 'legacy_ambiguous'
          and "ticket_comment_idempotency_keys"."request_digest" is null
          and "ticket_comment_idempotency_keys"."result_comment_id" is null
          and "ticket_comment_idempotency_keys"."result_revision" is null)
        or (not "ticket_comment_idempotency_keys"."legacy_ambiguous"
          and "ticket_comment_idempotency_keys"."source_kind" in ('comment','ticket_action','watcher')
          and "ticket_comment_idempotency_keys"."operation" ~ '^(alert|case|ticket)\.[a-z][a-z0-9_.-]{1,63}$'
          and "ticket_comment_idempotency_keys"."request_digest" is not null
          and (("ticket_comment_idempotency_keys"."source_kind" = 'comment'
              and "ticket_comment_idempotency_keys"."result_comment_id" is not null
              and "ticket_comment_idempotency_keys"."result_revision" between 1 and 2147483647)
            or ("ticket_comment_idempotency_keys"."source_kind" <> 'comment'
              and "ticket_comment_idempotency_keys"."result_comment_id" is null
              and "ticket_comment_idempotency_keys"."result_revision" is null)))),
	CONSTRAINT "ticket_comment_idempotency_keys_timestamp_check" CHECK (app.private_ticket_comment_timestamp_valid_v1("ticket_comment_idempotency_keys"."created_at"))
);
--> statement-breakpoint
ALTER TABLE "ticket_comment_idempotency_keys" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_comment_revision_attachments" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"revision_id" uuid NOT NULL,
	"attachment_id" uuid NOT NULL,
	"original_filename" text NOT NULL,
	"visibility" "ticket_comment_visibility" NOT NULL,
	CONSTRAINT "ticket_comment_revision_attachments_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_comment_revision_attachments_revision_key" UNIQUE("tenant_id","revision_id","attachment_id"),
	CONSTRAINT "ticket_comment_revision_attachments_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_comment_revision_attachments"."id") = 7) is true),
	CONSTRAINT "ticket_comment_revision_attachments_filename_check" CHECK (app.private_ticket_comment_filename_valid_v1("ticket_comment_revision_attachments"."original_filename"))
);
--> statement-breakpoint
ALTER TABLE "ticket_comment_revision_attachments" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_comment_revision_mentions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"revision_id" uuid NOT NULL,
	"mentioned_membership_id" uuid NOT NULL,
	"mentioned_user_id" uuid NOT NULL,
	"display_name" text NOT NULL,
	CONSTRAINT "ticket_comment_revision_mentions_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_comment_revision_mentions_revision_key" UNIQUE("tenant_id","revision_id","mentioned_membership_id"),
	CONSTRAINT "ticket_comment_revision_mentions_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_comment_revision_mentions"."id") = 7) is true),
	CONSTRAINT "ticket_comment_revision_mentions_display_name_check" CHECK (app.private_ticket_comment_display_name_valid_v1("ticket_comment_revision_mentions"."display_name"))
);
--> statement-breakpoint
ALTER TABLE "ticket_comment_revision_mentions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_comment_revisions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"comment_id" uuid NOT NULL,
	"revision" integer NOT NULL,
	"body_markdown" text NOT NULL,
	"body_html" text NOT NULL,
	"reason" text NOT NULL,
	"edited_by_membership_id" uuid NOT NULL,
	"edited_by_user_id" uuid NOT NULL,
	"edited_at" timestamp with time zone NOT NULL,
	CONSTRAINT "ticket_comment_revisions_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_comment_revisions_comment_revision_key" UNIQUE("tenant_id","comment_id","revision"),
	CONSTRAINT "ticket_comment_revisions_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_comment_revisions"."id") = 7) is true),
	CONSTRAINT "ticket_comment_revisions_revision_check" CHECK ("ticket_comment_revisions"."revision" between 1 and 2147483647),
	CONSTRAINT "ticket_comment_revisions_body_check" CHECK (app.private_ticket_comment_markdown_valid_v1("ticket_comment_revisions"."body_markdown")
        and app.private_ticket_comment_html_valid_v1("ticket_comment_revisions"."body_html")),
	CONSTRAINT "ticket_comment_revisions_reason_check" CHECK (("ticket_comment_revisions"."revision" = 1 and "ticket_comment_revisions"."reason" = 'original_comment')
	        or ("ticket_comment_revisions"."revision" > 1
	          and app.private_ticket_comment_edit_reason_valid_v1("ticket_comment_revisions"."reason"))),
	CONSTRAINT "ticket_comment_revisions_timestamp_check" CHECK (app.private_ticket_comment_timestamp_valid_v1("ticket_comment_revisions"."edited_at"))
);
--> statement-breakpoint
ALTER TABLE "ticket_comment_revisions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "ticket_comment_author_snapshots" ADD COLUMN "display_name" text;--> statement-breakpoint
ALTER TABLE "ticket_comment_author_snapshots" ADD COLUMN "origin" text;--> statement-breakpoint
ALTER TABLE "ticket_comment_author_snapshots" ADD COLUMN "editable_until" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "ticket_comment_escalation_sources" ADD CONSTRAINT "ticket_comment_escalation_sources_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_comment_escalation_sources" ADD CONSTRAINT "ticket_comment_escalation_sources_copy_fk" FOREIGN KEY ("tenant_id","copied_comment_id") REFERENCES "public"."ticket_comments"("tenant_id","id") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "ticket_comment_escalation_sources" ADD CONSTRAINT "ticket_comment_escalation_sources_source_revision_fk" FOREIGN KEY ("tenant_id","source_comment_id","source_revision") REFERENCES "public"."ticket_comment_revisions"("tenant_id","comment_id","revision") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "ticket_comment_escalation_sources" ADD CONSTRAINT "ticket_comment_escalation_sources_alert_fk" FOREIGN KEY ("tenant_id","source_alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "ticket_comment_escalation_sources" ADD CONSTRAINT "ticket_comment_escalation_sources_case_fk" FOREIGN KEY ("tenant_id","destination_case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "ticket_comment_idempotency_keys" ADD CONSTRAINT "ticket_comment_idempotency_keys_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_comment_idempotency_keys" ADD CONSTRAINT "ticket_comment_idempotency_keys_actor_fk" FOREIGN KEY ("tenant_id","actor_membership_id","actor_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "ticket_comment_idempotency_keys" ADD CONSTRAINT "ticket_comment_idempotency_keys_result_fk" FOREIGN KEY ("tenant_id","result_comment_id","result_revision") REFERENCES "public"."ticket_comment_revisions"("tenant_id","comment_id","revision") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "ticket_comment_revision_attachments" ADD CONSTRAINT "ticket_comment_revision_attachments_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_comment_revision_attachments" ADD CONSTRAINT "ticket_comment_revision_attachments_revision_fk" FOREIGN KEY ("tenant_id","revision_id") REFERENCES "public"."ticket_comment_revisions"("tenant_id","id") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "ticket_comment_revision_attachments" ADD CONSTRAINT "ticket_comment_revision_attachments_attachment_fk" FOREIGN KEY ("tenant_id","attachment_id") REFERENCES "public"."dfir_attachments"("tenant_id","id") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "ticket_comment_revision_mentions" ADD CONSTRAINT "ticket_comment_revision_mentions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_comment_revision_mentions" ADD CONSTRAINT "ticket_comment_revision_mentions_revision_fk" FOREIGN KEY ("tenant_id","revision_id") REFERENCES "public"."ticket_comment_revisions"("tenant_id","id") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "ticket_comment_revision_mentions" ADD CONSTRAINT "ticket_comment_revision_mentions_membership_fk" FOREIGN KEY ("tenant_id","mentioned_membership_id","mentioned_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "ticket_comment_revisions" ADD CONSTRAINT "ticket_comment_revisions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_comment_revisions" ADD CONSTRAINT "ticket_comment_revisions_comment_fk" FOREIGN KEY ("tenant_id","comment_id") REFERENCES "public"."ticket_comments"("tenant_id","id") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "ticket_comment_revisions" ADD CONSTRAINT "ticket_comment_revisions_editor_fk" FOREIGN KEY ("tenant_id","edited_by_membership_id","edited_by_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
CREATE INDEX "ticket_comment_escalation_sources_source_idx" ON "ticket_comment_escalation_sources" USING btree ("tenant_id","source_comment_id","source_revision");--> statement-breakpoint
CREATE INDEX "ticket_comment_idempotency_keys_result_idx" ON "ticket_comment_idempotency_keys" USING btree ("tenant_id","result_comment_id","result_revision");--> statement-breakpoint
CREATE INDEX "ticket_comment_revisions_history_idx" ON "ticket_comment_revisions" USING btree ("tenant_id","comment_id","revision");--> statement-breakpoint
ALTER TABLE "ticket_comment_author_snapshots" ADD CONSTRAINT "ticket_comment_author_snapshots_origin_check" CHECK ("ticket_comment_author_snapshots"."origin" in ('api','customer_portal','escalation_copy','system')
        and ("ticket_comment_author_snapshots"."origin" <> 'api' or "ticket_comment_author_snapshots"."audience" = 'operator')
        and ("ticket_comment_author_snapshots"."origin" <> 'customer_portal' or "ticket_comment_author_snapshots"."audience" = 'customer')
        and ("ticket_comment_author_snapshots"."origin" <> 'system' or "ticket_comment_author_snapshots"."audience" = 'operator'));--> statement-breakpoint
ALTER TABLE "ticket_comment_author_snapshots" ADD CONSTRAINT "ticket_comment_author_snapshots_display_name_check" CHECK (app.private_ticket_comment_display_name_valid_v1("ticket_comment_author_snapshots"."display_name"));--> statement-breakpoint
ALTER TABLE "ticket_comment_author_snapshots" ADD CONSTRAINT "ticket_comment_author_snapshots_window_check" CHECK (app.private_ticket_comment_timestamp_valid_v1("ticket_comment_author_snapshots"."created_at")
        and app.private_ticket_comment_timestamp_valid_v1("ticket_comment_author_snapshots"."editable_until")
        and "ticket_comment_author_snapshots"."editable_until" = "ticket_comment_author_snapshots"."created_at" + interval '15 minutes');--> statement-breakpoint
ALTER TABLE public.ticket_comment_author_snapshots
  DROP CONSTRAINT ticket_comment_author_snapshots_customer_contact_fk;
ALTER TABLE public.ticket_comment_author_snapshots
  ADD CONSTRAINT ticket_comment_author_snapshots_customer_contact_fk
  FOREIGN KEY (tenant_id,author_contact_id)
  REFERENCES public.customer_contacts(tenant_id,id)
  ON DELETE RESTRICT ON UPDATE RESTRICT;
ALTER TABLE public.ticket_comment_author_snapshots
  ADD CONSTRAINT ticket_comment_author_snapshots_author_fk
  FOREIGN KEY (tenant_id,author_membership_id,author_user_id)
  REFERENCES public.tenant_memberships(tenant_id,id,user_id)
  ON DELETE RESTRICT ON UPDATE RESTRICT;
-- The predecessor API policy remains through this migration so a V46 binary
-- can keep reading its customer-export author projection.  0203 installs the
-- closed V47 reads and atomically performs the owner-only cutover.
CREATE POLICY "ticket_comment_escalation_sources_owner_access" ON "ticket_comment_escalation_sources" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "ticket_comment_idempotency_keys_owner_access" ON "ticket_comment_idempotency_keys" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "ticket_comment_revision_attachments_owner_access" ON "ticket_comment_revision_attachments" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "ticket_comment_revision_mentions_owner_access" ON "ticket_comment_revision_mentions" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "ticket_comment_revisions_owner_access" ON "ticket_comment_revisions" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);
--> statement-breakpoint

-- Retire the role-derived AFTER INSERT classifier.  V47 writers create the
-- author snapshot explicitly from the authenticated route and exact contact
-- relation; the deferred aggregate constraint below rejects missing rows.
DROP TRIGGER ticket_comments_capture_author_snapshot_v1
  ON public.ticket_comments;
--> statement-breakpoint

-- A legacy API row without a comment command is evidence of the inline
-- transition-note path.  It is repaired to the fail-closed immutable system
-- origin.  A customer-classified API row can only be reclassified when the
-- predecessor snapshot already contains the exact contact identity.
ALTER TABLE public.ticket_comments
  DISABLE TRIGGER ticket_comments_immutable_v1;
UPDATE public.ticket_comments AS comment
SET origin = CASE
  WHEN snapshot.audience = 'customer'
       AND snapshot.author_contact_id IS NOT NULL THEN 'customer_portal'
  ELSE 'system'
END
FROM public.ticket_comment_author_snapshots AS snapshot
WHERE snapshot.tenant_id = comment.tenant_id
  AND snapshot.comment_id = comment.id
  AND comment.origin = 'api'
  AND NOT EXISTS (
    SELECT 1
    FROM public.ticket_comment_commands AS command
    WHERE command.tenant_id = comment.tenant_id
      AND command.result_comment_id = comment.id
  );
ALTER TABLE public.ticket_comments
  ENABLE TRIGGER ticket_comments_immutable_v1;
--> statement-breakpoint

UPDATE public.ticket_comment_author_snapshots AS snapshot
SET display_name = identity.display_name,
    origin = comment.origin,
    editable_until = comment.created_at + interval '15 minutes'
FROM public.ticket_comments AS comment
JOIN public.users AS identity ON identity.id = comment.author_user_id
WHERE snapshot.tenant_id = comment.tenant_id
  AND snapshot.comment_id = comment.id
  AND snapshot.author_membership_id = comment.author_membership_id
  AND snapshot.author_user_id = comment.author_user_id;
--> statement-breakpoint

DO $ticket_comment_author_backfill$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.ticket_comments AS comment
    LEFT JOIN public.ticket_comment_author_snapshots AS snapshot
      ON snapshot.tenant_id = comment.tenant_id
     AND snapshot.comment_id = comment.id
    WHERE snapshot.comment_id IS NULL
       OR snapshot.display_name IS NULL
       OR snapshot.origin IS DISTINCT FROM comment.origin
       OR snapshot.author_membership_id IS DISTINCT FROM comment.author_membership_id
       OR snapshot.author_user_id IS DISTINCT FROM comment.author_user_id
       OR snapshot.created_at IS DISTINCT FROM comment.created_at
       OR comment.origin = 'api' AND snapshot.audience <> 'operator'
       OR comment.origin = 'customer_portal' AND (
            snapshot.audience <> 'customer'
            OR snapshot.author_contact_id IS NULL
          )
       OR comment.origin = 'system' AND snapshot.audience <> 'operator'
  ) THEN
    RAISE EXCEPTION 'legacy ticket comment author evidence is incomplete'
      USING ERRCODE = '55000';
  END IF;
END
$ticket_comment_author_backfill$;
--> statement-breakpoint

ALTER TABLE public.ticket_comment_author_snapshots
  ALTER COLUMN display_name SET NOT NULL,
  ALTER COLUMN origin SET NOT NULL,
  ALTER COLUMN editable_until SET NOT NULL;
--> statement-breakpoint

DO $ticket_comment_legacy_body_evidence$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.ticket_comments AS comment
    WHERE NOT app.private_ticket_comment_markdown_valid_v1(
            comment.body_markdown
          )
       OR NOT app.private_ticket_comment_html_valid_v1(comment.body_html)
  ) THEN
    RAISE EXCEPTION
      'legacy ticket comment body has no V47-safe canonical representation'
      USING ERRCODE='55000';
  END IF;
END
$ticket_comment_legacy_body_evidence$;
--> statement-breakpoint

INSERT INTO public.ticket_comment_revisions (
  id, tenant_id, comment_id, revision, body_markdown, body_html, reason,
  edited_by_membership_id, edited_by_user_id, edited_at
)
SELECT uuidv7(), comment.tenant_id, comment.id, 1,
       comment.body_markdown, comment.body_html, 'original_comment',
       comment.author_membership_id, comment.author_user_id,
       comment.created_at
FROM public.ticket_comments AS comment
ORDER BY comment.tenant_id, comment.id;
--> statement-breakpoint

DO $ticket_comment_legacy_mentions_shape$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.ticket_comments AS comment
    WHERE cardinality(comment.mentioned_user_ids)<>0
  ) THEN
    RAISE EXCEPTION
      'legacy ticket comment mentions lack a frozen commit-time identity'
      USING ERRCODE = '55000';
  END IF;
END
$ticket_comment_legacy_mentions_shape$;
--> statement-breakpoint

INSERT INTO public.ticket_comment_revision_mentions (
  id, tenant_id, revision_id, mentioned_membership_id,
  mentioned_user_id, display_name
)
SELECT uuidv7(), comment.tenant_id, revision.id, membership.id,
       membership.user_id, identity.display_name
FROM public.ticket_comments AS comment
JOIN public.ticket_comment_revisions AS revision
  ON revision.tenant_id = comment.tenant_id
 AND revision.comment_id = comment.id
 AND revision.revision = 1
CROSS JOIN LATERAL unnest(comment.mentioned_user_ids)
  AS mentioned(mentioned_user_id)
JOIN public.tenant_memberships AS membership
  ON membership.tenant_id = comment.tenant_id
 AND membership.user_id = mentioned.mentioned_user_id
JOIN public.users AS identity ON identity.id = membership.user_id
ORDER BY comment.tenant_id, comment.id, membership.id;
--> statement-breakpoint

INSERT INTO public.ticket_comment_escalation_sources (
  id, tenant_id, copied_comment_id, source_comment_id, source_revision,
  source_alert_id, destination_case_id, legacy_unresolved, created_at
)
SELECT uuidv7(), comment.tenant_id, comment.id, NULL, NULL, NULL,
       comment.case_id, true, comment.created_at
FROM public.ticket_comments AS comment
WHERE comment.origin = 'escalation_copy'
ORDER BY comment.tenant_id, comment.id;
--> statement-breakpoint

DO $ticket_comment_legacy_escalation_shape$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.ticket_comments AS comment
    WHERE comment.origin = 'escalation_copy'
      AND (comment.visibility <> 'public' OR comment.case_id IS NULL)
  ) THEN
    RAISE EXCEPTION 'legacy escalation comment cannot be safely classified'
      USING ERRCODE = '55000';
  END IF;
END
$ticket_comment_legacy_escalation_shape$;
--> statement-breakpoint

-- Preserve every raw legacy ledger.  Only the normalized reservation is new:
-- one historical command is replayable, while any cross-ledger or
-- cross-operation collision becomes an explicit fail-closed tombstone.
WITH legacy_keys AS (
  SELECT command.tenant_id, command.actor_membership_id,
         command.actor_user_id, command.key_digest, 'comment'::text AS source_kind,
         command.operation, command.request_digest,
         command.result_comment_id, 1::integer AS result_revision,
         command.created_at, 'comment:' || command.id::text AS source_id
  FROM public.ticket_comment_commands AS command
  UNION ALL
  SELECT command.tenant_id, command.actor_membership_id,
         command.actor_user_id, command.key_digest, 'ticket_action',
         command.operation, command.request_digest, NULL, NULL,
         command.created_at, 'ticket_action:' || command.id::text
  FROM public.ticket_commands AS command
  UNION ALL
  SELECT command.tenant_id, command.actor_membership_id,
         command.actor_user_id, command.key_digest, 'watcher',
         CASE WHEN command.alert_id IS NOT NULL THEN 'alert' ELSE 'case' END
           || '.watcher.' || command.action,
         command.request_digest, NULL, NULL,
         command.created_at, 'watcher:' || command.id::text
  FROM public.ticket_watcher_commands AS command
), grouped AS (
  SELECT tenant_id, actor_membership_id, key_digest,
         count(*) AS source_count,
         (array_agg(actor_user_id ORDER BY created_at,source_id))[1] AS actor_user_id,
         (array_agg(source_kind ORDER BY created_at,source_id))[1] AS source_kind,
         (array_agg(operation ORDER BY created_at,source_id))[1] AS operation,
         (array_agg(request_digest ORDER BY created_at,source_id))[1] AS request_digest,
         (array_agg(result_comment_id ORDER BY created_at,source_id))[1] AS result_comment_id,
         (array_agg(result_revision ORDER BY created_at,source_id))[1] AS result_revision,
         min(created_at) AS created_at
  FROM legacy_keys
  GROUP BY tenant_id, actor_membership_id, key_digest
)
INSERT INTO public.ticket_comment_idempotency_keys (
  id, tenant_id, actor_membership_id, actor_user_id, key_digest,
  source_kind, operation, request_digest, result_comment_id, result_revision,
  legacy_ambiguous, created_at
)
SELECT uuidv7(), tenant_id, actor_membership_id, actor_user_id, key_digest,
       CASE WHEN source_count = 1 THEN source_kind ELSE 'ambiguous' END,
       CASE WHEN source_count = 1 THEN operation ELSE 'legacy_ambiguous' END,
       CASE WHEN source_count = 1 THEN request_digest END,
       CASE WHEN source_count = 1 AND source_kind = 'comment'
            THEN result_comment_id END,
       CASE WHEN source_count = 1 AND source_kind = 'comment'
            THEN result_revision END,
       source_count <> 1, created_at
FROM grouped
ORDER BY tenant_id, actor_membership_id, key_digest;
--> statement-breakpoint

ALTER TABLE public.ticket_comment_revisions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_comment_revision_attachments FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_comment_revision_mentions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_comment_idempotency_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_comment_escalation_sources FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_comment_revisions OWNER TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_comment_revision_attachments OWNER TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_comment_revision_mentions OWNER TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_comment_idempotency_keys OWNER TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_comment_escalation_sources OWNER TO periapsis_ticket_runtime_owner;
REVOKE ALL ON TABLE public.ticket_comment_revisions,
  public.ticket_comment_revision_attachments,
  public.ticket_comment_revision_mentions,
  public.ticket_comment_idempotency_keys,
  public.ticket_comment_escalation_sources
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT ALL ON TABLE public.ticket_comment_revisions,
  public.ticket_comment_revision_attachments,
  public.ticket_comment_revision_mentions,
  public.ticket_comment_idempotency_keys,
  public.ticket_comment_escalation_sources
TO periapsis_migrator;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_comment_assert_consistent_v1(
  p_tenant_id uuid,
  p_comment_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  comment_row public.ticket_comments%ROWTYPE;
  snapshot_row public.ticket_comment_author_snapshots%ROWTYPE;
  latest_revision public.ticket_comment_revisions%ROWTYPE;
  revision_count integer;
  minimum_revision integer;
  maximum_revision integer;
  snapshot_count integer;
  provenance_count integer;
  attachment_count integer;
  mention_count integer;
  revision_mentions uuid[];
BEGIN
  SELECT comment.* INTO comment_row
  FROM public.ticket_comments AS comment
  WHERE comment.tenant_id = p_tenant_id AND comment.id = p_comment_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket comment aggregate is missing'
      USING ERRCODE = '23514';
  END IF;

  SELECT count(*) INTO snapshot_count
  FROM public.ticket_comment_author_snapshots AS snapshot
  WHERE snapshot.tenant_id = p_tenant_id
    AND snapshot.comment_id = p_comment_id;
  IF snapshot_count = 1 THEN
    SELECT snapshot.* INTO STRICT snapshot_row
    FROM public.ticket_comment_author_snapshots AS snapshot
    WHERE snapshot.tenant_id = p_tenant_id
      AND snapshot.comment_id = p_comment_id;
  END IF;
  IF snapshot_count <> 1
     OR snapshot_row.author_membership_id IS DISTINCT FROM comment_row.author_membership_id
     OR snapshot_row.author_user_id IS DISTINCT FROM comment_row.author_user_id
     OR snapshot_row.origin IS DISTINCT FROM comment_row.origin
     OR snapshot_row.created_at IS DISTINCT FROM comment_row.created_at
     OR comment_row.origin = 'api' AND snapshot_row.audience <> 'operator'
     OR comment_row.origin = 'customer_portal' AND (
          snapshot_row.audience <> 'customer'
          OR snapshot_row.author_contact_id IS NULL
          OR comment_row.visibility <> 'public'
        )
     OR comment_row.origin = 'system' AND snapshot_row.audience <> 'operator'
     OR comment_row.origin = 'escalation_copy'
        AND comment_row.visibility <> 'public' THEN
    RAISE EXCEPTION 'ticket comment frozen author is inconsistent'
      USING ERRCODE = '23514';
  END IF;

  SELECT count(*), min(revision.revision), max(revision.revision)
  INTO revision_count, minimum_revision, maximum_revision
  FROM public.ticket_comment_revisions AS revision
  WHERE revision.tenant_id = p_tenant_id
    AND revision.comment_id = p_comment_id;
  IF revision_count < 1 OR minimum_revision <> 1
     OR maximum_revision <> revision_count THEN
    RAISE EXCEPTION 'ticket comment revision history is not contiguous'
      USING ERRCODE = '23514';
  END IF;
  SELECT revision.* INTO STRICT latest_revision
  FROM public.ticket_comment_revisions AS revision
  WHERE revision.tenant_id = p_tenant_id
    AND revision.comment_id = p_comment_id
    AND revision.revision = revision_count;

  IF comment_row.revision <> revision_count
     OR comment_row.body_markdown IS DISTINCT FROM latest_revision.body_markdown
     OR comment_row.body_html IS DISTINCT FROM latest_revision.body_html
     OR comment_row.updated_at IS DISTINCT FROM latest_revision.edited_at
     OR revision_count = 1 AND comment_row.updated_at IS DISTINCT FROM comment_row.created_at
     OR revision_count > 1 AND comment_row.updated_at <= comment_row.created_at
     OR revision_count > 1 AND comment_row.updated_at >= snapshot_row.editable_until
     OR EXISTS (
          SELECT 1
          FROM (
            SELECT revision.revision, revision.edited_at,
                   lag(revision.edited_at) OVER (ORDER BY revision.revision) AS prior_edited_at
            FROM public.ticket_comment_revisions AS revision
            WHERE revision.tenant_id = p_tenant_id
              AND revision.comment_id = p_comment_id
          ) AS history
          WHERE history.revision = 1 AND history.edited_at <> comment_row.created_at
             OR history.revision > 1 AND (
                  history.edited_at <= history.prior_edited_at
                  OR history.edited_at >= snapshot_row.editable_until
                )
        )
     OR EXISTS (
          SELECT 1
          FROM public.ticket_comment_revisions AS revision
          WHERE revision.tenant_id = p_tenant_id
            AND revision.comment_id = p_comment_id
            AND (revision.edited_by_membership_id <> snapshot_row.author_membership_id
              OR revision.edited_by_user_id <> snapshot_row.author_user_id)
        ) THEN
    RAISE EXCEPTION 'ticket comment current revision is inconsistent'
      USING ERRCODE = '23514';
  END IF;

  SELECT count(*) INTO attachment_count
  FROM public.ticket_comment_revision_attachments AS relation
  WHERE relation.tenant_id = p_tenant_id
    AND relation.revision_id = latest_revision.id;
  SELECT count(*), coalesce(array_agg(
           relation.mentioned_user_id ORDER BY relation.mentioned_user_id
         ), ARRAY[]::uuid[])
  INTO mention_count, revision_mentions
  FROM public.ticket_comment_revision_mentions AS relation
  WHERE relation.tenant_id = p_tenant_id
    AND relation.revision_id = latest_revision.id;
  IF attachment_count > 20 OR mention_count > 50
     OR revision_mentions IS DISTINCT FROM comment_row.mentioned_user_ids THEN
    RAISE EXCEPTION 'ticket comment revision relations are inconsistent'
      USING ERRCODE = '23514';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.ticket_comment_revisions AS revision
    LEFT JOIN public.ticket_comment_revision_attachments AS attachment
      ON attachment.tenant_id = revision.tenant_id
     AND attachment.revision_id = revision.id
    LEFT JOIN public.ticket_comment_revision_mentions AS mention
      ON mention.tenant_id = revision.tenant_id
     AND mention.revision_id = revision.id
    WHERE revision.tenant_id = p_tenant_id
      AND revision.comment_id = p_comment_id
    GROUP BY revision.id
    HAVING count(DISTINCT attachment.attachment_id) > 20
        OR count(DISTINCT mention.mentioned_membership_id) > 50
  ) OR comment_row.visibility = 'public' AND EXISTS (
    SELECT 1
    FROM public.ticket_comment_revisions AS revision
    JOIN public.ticket_comment_revision_attachments AS attachment
      ON attachment.tenant_id = revision.tenant_id
     AND attachment.revision_id = revision.id
    WHERE revision.tenant_id = p_tenant_id
      AND revision.comment_id = p_comment_id
      AND attachment.visibility <> 'public'
  ) THEN
    RAISE EXCEPTION 'ticket comment historical relations are inconsistent'
      USING ERRCODE = '23514';
  END IF;

  SELECT count(*) INTO provenance_count
  FROM public.ticket_comment_escalation_sources AS source
  WHERE source.tenant_id = p_tenant_id
    AND source.copied_comment_id = p_comment_id;
  IF comment_row.origin = 'escalation_copy' AND provenance_count <> 1
     OR comment_row.origin <> 'escalation_copy' AND provenance_count <> 0 THEN
    RAISE EXCEPTION 'ticket comment escalation provenance is inconsistent'
      USING ERRCODE = '23514';
  END IF;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.guard_ticket_comment_aggregate_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  tenant_id uuid;
  comment_id uuid;
BEGIN
  IF TG_TABLE_NAME = 'ticket_comments' THEN
    tenant_id := coalesce(NEW.tenant_id,OLD.tenant_id);
    comment_id := coalesce(NEW.id,OLD.id);
  ELSIF TG_TABLE_NAME IN (
    'ticket_comment_revisions','ticket_comment_author_snapshots',
    'ticket_comment_escalation_sources'
  ) THEN
    tenant_id := coalesce(NEW.tenant_id,OLD.tenant_id);
    comment_id := CASE TG_TABLE_NAME
      WHEN 'ticket_comment_revisions' THEN coalesce(NEW.comment_id,OLD.comment_id)
      WHEN 'ticket_comment_author_snapshots' THEN coalesce(NEW.comment_id,OLD.comment_id)
      ELSE coalesce(NEW.copied_comment_id,OLD.copied_comment_id)
    END;
  ELSE
    tenant_id := coalesce(NEW.tenant_id,OLD.tenant_id);
    SELECT revision.comment_id INTO STRICT comment_id
    FROM public.ticket_comment_revisions AS revision
    WHERE revision.tenant_id = tenant_id
      AND revision.id = coalesce(NEW.revision_id,OLD.revision_id);
  END IF;
  PERFORM app.private_ticket_comment_assert_consistent_v1(tenant_id,comment_id);
  RETURN NULL;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.guard_ticket_comment_escalation_source_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  valid_source boolean;
BEGIN
  IF NEW.legacy_unresolved THEN
    RETURN NULL;
  END IF;
  SELECT copied.visibility = 'public'
         AND copied.origin = 'escalation_copy'
         AND copied.case_id = NEW.destination_case_id
         AND copied.alert_id IS NULL
         AND copied.revision = 1
         AND source.visibility = 'public'
         AND source.alert_id = NEW.source_alert_id
         AND source.case_id IS NULL
         AND copied_revision.body_markdown = source_revision.body_markdown
         AND copied_revision.body_html = source_revision.body_html
         AND copied_snapshot.audience = source_snapshot.audience
         AND copied_snapshot.author_membership_id = source_snapshot.author_membership_id
         AND copied_snapshot.author_user_id = source_snapshot.author_user_id
         AND copied_snapshot.author_contact_id IS NOT DISTINCT FROM source_snapshot.author_contact_id
         AND copied_snapshot.display_name = source_snapshot.display_name
         AND copied_snapshot.origin = 'escalation_copy'
         AND NEW.created_at = copied.created_at
         AND NOT EXISTS (
           (SELECT relation.attachment_id, relation.original_filename, relation.visibility
            FROM public.ticket_comment_revision_attachments AS relation
            WHERE relation.tenant_id = NEW.tenant_id
              AND relation.revision_id = source_revision.id)
           EXCEPT
           (SELECT relation.attachment_id, relation.original_filename, relation.visibility
            FROM public.ticket_comment_revision_attachments AS relation
            WHERE relation.tenant_id = NEW.tenant_id
              AND relation.revision_id = copied_revision.id)
         )
         AND NOT EXISTS (
           (SELECT relation.attachment_id, relation.original_filename, relation.visibility
            FROM public.ticket_comment_revision_attachments AS relation
            WHERE relation.tenant_id = NEW.tenant_id
              AND relation.revision_id = copied_revision.id)
           EXCEPT
           (SELECT relation.attachment_id, relation.original_filename, relation.visibility
            FROM public.ticket_comment_revision_attachments AS relation
           WHERE relation.tenant_id = NEW.tenant_id
              AND relation.revision_id = source_revision.id)
         )
         AND NOT EXISTS (
           (SELECT relation.mentioned_membership_id, relation.mentioned_user_id,
                   relation.display_name
            FROM public.ticket_comment_revision_mentions AS relation
            WHERE relation.tenant_id = NEW.tenant_id
              AND relation.revision_id = source_revision.id)
           EXCEPT
           (SELECT relation.mentioned_membership_id, relation.mentioned_user_id,
                   relation.display_name
            FROM public.ticket_comment_revision_mentions AS relation
            WHERE relation.tenant_id = NEW.tenant_id
              AND relation.revision_id = copied_revision.id)
         )
         AND NOT EXISTS (
           (SELECT relation.mentioned_membership_id, relation.mentioned_user_id,
                   relation.display_name
            FROM public.ticket_comment_revision_mentions AS relation
            WHERE relation.tenant_id = NEW.tenant_id
              AND relation.revision_id = copied_revision.id)
           EXCEPT
           (SELECT relation.mentioned_membership_id, relation.mentioned_user_id,
                   relation.display_name
            FROM public.ticket_comment_revision_mentions AS relation
            WHERE relation.tenant_id = NEW.tenant_id
              AND relation.revision_id = source_revision.id)
         )
  INTO valid_source
  FROM public.ticket_comments AS copied
  JOIN public.ticket_comment_revisions AS copied_revision
    ON copied_revision.tenant_id = copied.tenant_id
   AND copied_revision.comment_id = copied.id
   AND copied_revision.revision = 1
  JOIN public.ticket_comment_author_snapshots AS copied_snapshot
    ON copied_snapshot.tenant_id = copied.tenant_id
   AND copied_snapshot.comment_id = copied.id
  JOIN public.ticket_comments AS source
    ON source.tenant_id = NEW.tenant_id
   AND source.id = NEW.source_comment_id
  JOIN public.ticket_comment_revisions AS source_revision
    ON source_revision.tenant_id = source.tenant_id
   AND source_revision.comment_id = source.id
   AND source_revision.revision = NEW.source_revision
  JOIN public.ticket_comment_author_snapshots AS source_snapshot
    ON source_snapshot.tenant_id = source.tenant_id
   AND source_snapshot.comment_id = source.id
  WHERE copied.tenant_id = NEW.tenant_id
    AND copied.id = NEW.copied_comment_id;
  IF valid_source IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'ticket comment escalation provenance does not match its aggregates'
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.guard_ticket_comment_attachment_relation_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  valid_relation boolean;
BEGIN
  SELECT attachment.original_filename = NEW.original_filename
         AND attachment.visibility::text = NEW.visibility::text
         AND attachment.scan_state IN ('available','retained')
         AND storage.state IN ('available','retained')
         AND storage.content_sha256 IS NOT NULL
         AND storage.size_bytes IS NOT NULL
         AND (storage.legal_hold OR storage.retention_until IS NULL
              OR storage.retention_until > transaction_timestamp())
         AND (comment.visibility = 'private' OR attachment.visibility = 'public')
         AND (
           comment.alert_id IS NOT NULL
             AND attachment.subject_kind = 'alert'
             AND attachment.alert_id = comment.alert_id
           OR comment.case_id IS NOT NULL AND (
             attachment.subject_kind = 'case'
               AND attachment.case_id = comment.case_id
             OR attachment.subject_kind = 'alert' AND EXISTS (
               SELECT 1
               FROM public.dfir_attachment_case_links AS link
               WHERE link.tenant_id = comment.tenant_id
                 AND link.attachment_id = attachment.id
                 AND link.case_id = comment.case_id
                 AND link.source_alert_id = attachment.alert_id
             )
           )
         )
  INTO valid_relation
  FROM public.ticket_comment_revisions AS revision
  JOIN public.ticket_comments AS comment
    ON comment.tenant_id = revision.tenant_id
   AND comment.id = revision.comment_id
  JOIN public.dfir_attachments AS attachment
    ON attachment.tenant_id = NEW.tenant_id
   AND attachment.id = NEW.attachment_id
  JOIN public.dfir_storage_objects AS storage
    ON storage.tenant_id = attachment.tenant_id
   AND storage.id = attachment.storage_object_id
  WHERE revision.tenant_id = NEW.tenant_id
    AND revision.id = NEW.revision_id
  FOR SHARE OF comment,attachment,storage;
  IF valid_relation IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'ticket comment attachment is not exact and available'
      USING ERRCODE = '23503';
  END IF;
  IF (
    SELECT count(*)
    FROM public.ticket_comment_revision_attachments AS relation
    WHERE relation.tenant_id = NEW.tenant_id
      AND relation.revision_id = NEW.revision_id
  ) >= 20 THEN
    RAISE EXCEPTION 'ticket comment attachment limit exceeded'
      USING ERRCODE = '22023';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.guard_ticket_comment_mention_relation_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  comment_row public.ticket_comments%ROWTYPE;
  direct_candidate boolean;
  copied_candidate boolean;
BEGIN
  SELECT comment.* INTO STRICT comment_row
  FROM public.ticket_comment_revisions AS revision
  JOIN public.ticket_comments AS comment
    ON comment.tenant_id = revision.tenant_id
   AND comment.id = revision.comment_id
  WHERE revision.tenant_id = NEW.tenant_id
    AND revision.id = NEW.revision_id;

  IF (
    SELECT count(*)
    FROM public.ticket_comment_revision_mentions AS relation
    WHERE relation.tenant_id = NEW.tenant_id
      AND relation.revision_id = NEW.revision_id
  ) >= 50 THEN
    RAISE EXCEPTION 'ticket comment mention limit exceeded'
      USING ERRCODE = '22023';
  END IF;

  IF comment_row.origin = 'api' THEN
    SELECT membership.status = 'active'
           AND identity.active
           AND membership.role NOT IN (
             'customer_manager','customer_user','read_only'
           )
           AND identity.display_name = NEW.display_name
           AND app.private_ticket_watcher_user_scope_allows_v1(
             NEW.tenant_id,
             CASE WHEN comment_row.alert_id IS NOT NULL
               THEN 'alert'::public.ticket_aggregate_kind
               ELSE 'case'::public.ticket_aggregate_kind END,
             coalesce(comment_row.alert_id,comment_row.case_id),
             NEW.mentioned_user_id,'read'
           )
    INTO direct_candidate
    FROM public.tenant_memberships AS membership
    JOIN public.users AS identity ON identity.id = membership.user_id
    WHERE membership.tenant_id = NEW.tenant_id
      AND membership.id = NEW.mentioned_membership_id
      AND membership.user_id = NEW.mentioned_user_id;
  ELSIF comment_row.origin = 'escalation_copy' THEN
    SELECT EXISTS (
      SELECT 1
      FROM public.ticket_comment_escalation_sources AS source
      LEFT JOIN public.ticket_comment_revisions AS source_revision
        ON source_revision.tenant_id = source.tenant_id
       AND source_revision.comment_id = source.source_comment_id
       AND source_revision.revision = source.source_revision
      LEFT JOIN public.ticket_comment_revision_mentions AS source_mention
        ON source_mention.tenant_id = source_revision.tenant_id
       AND source_mention.revision_id = source_revision.id
      WHERE source.tenant_id = NEW.tenant_id
        AND source.copied_comment_id = comment_row.id
        AND (source.legacy_unresolved AND EXISTS (
          SELECT 1
          FROM public.tenant_memberships AS membership
          JOIN public.users AS identity ON identity.id = membership.user_id
          WHERE membership.tenant_id = NEW.tenant_id
            AND membership.id = NEW.mentioned_membership_id
            AND membership.user_id = NEW.mentioned_user_id
            AND identity.display_name = NEW.display_name
        ) OR NOT source.legacy_unresolved
          AND source_mention.mentioned_membership_id = NEW.mentioned_membership_id
          AND source_mention.mentioned_user_id = NEW.mentioned_user_id
          AND source_mention.display_name = NEW.display_name)
    ) INTO copied_candidate;
  END IF;
  IF coalesce(direct_candidate,copied_candidate,false) IS NOT TRUE THEN
    RAISE EXCEPTION 'ticket comment mention is not an exact live candidate'
      USING ERRCODE = '23503';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.private_ticket_comment_assert_consistent_v1(uuid,uuid)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_ticket_comment_aggregate_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_ticket_comment_escalation_source_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_ticket_comment_attachment_relation_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_ticket_comment_mention_relation_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_ticket_comment_assert_consistent_v1(uuid,uuid),
  app.guard_ticket_comment_aggregate_v1(),
  app.guard_ticket_comment_escalation_source_v1(),
  app.guard_ticket_comment_attachment_relation_v1(),
  app.guard_ticket_comment_mention_relation_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE TRIGGER ticket_comment_revisions_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_comment_revisions
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('immutable');
CREATE TRIGGER ticket_comment_revision_attachments_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_comment_revision_attachments
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('immutable');
CREATE TRIGGER ticket_comment_revision_attachments_exact_v1
BEFORE INSERT ON public.ticket_comment_revision_attachments
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_comment_attachment_relation_v1();
CREATE TRIGGER ticket_comment_revision_mentions_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_comment_revision_mentions
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('immutable');
CREATE TRIGGER ticket_comment_revision_mentions_exact_v1
BEFORE INSERT ON public.ticket_comment_revision_mentions
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_comment_mention_relation_v1();
CREATE TRIGGER ticket_comment_idempotency_keys_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_comment_idempotency_keys
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('immutable');
CREATE TRIGGER ticket_comment_escalation_sources_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_comment_escalation_sources
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('immutable');
CREATE TRIGGER ticket_comment_author_snapshots_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_comment_author_snapshots
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('immutable');
--> statement-breakpoint

CREATE CONSTRAINT TRIGGER ticket_comments_consistency_v1
AFTER INSERT OR UPDATE OR DELETE ON public.ticket_comments
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_comment_aggregate_v1();
CREATE CONSTRAINT TRIGGER ticket_comment_revisions_consistency_v1
AFTER INSERT OR UPDATE OR DELETE ON public.ticket_comment_revisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_comment_aggregate_v1();
CREATE CONSTRAINT TRIGGER ticket_comment_revision_attachments_consistency_v1
AFTER INSERT OR UPDATE OR DELETE ON public.ticket_comment_revision_attachments
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_comment_aggregate_v1();
CREATE CONSTRAINT TRIGGER ticket_comment_revision_mentions_consistency_v1
AFTER INSERT OR UPDATE OR DELETE ON public.ticket_comment_revision_mentions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_comment_aggregate_v1();
CREATE CONSTRAINT TRIGGER ticket_comment_author_snapshots_consistency_v1
AFTER INSERT OR UPDATE OR DELETE ON public.ticket_comment_author_snapshots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_comment_aggregate_v1();
CREATE CONSTRAINT TRIGGER ticket_comment_escalation_sources_consistency_v1
AFTER INSERT OR UPDATE OR DELETE ON public.ticket_comment_escalation_sources
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_comment_aggregate_v1();
CREATE CONSTRAINT TRIGGER ticket_comment_escalation_sources_exact_v1
AFTER INSERT OR UPDATE ON public.ticket_comment_escalation_sources
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_comment_escalation_source_v1();
--> statement-breakpoint

-- Rolling bridge for the V46 writer ABI.  It materializes the exact V47
-- revision/snapshot aggregate in the same transaction.  0203 retires this
-- bridge only after the v2 closed entry points are installed.
CREATE FUNCTION app.capture_ticket_comment_v47_compat_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  audience_value text := 'operator';
  contact_id uuid;
  display_name text;
  revision_id uuid := uuidv7();
BEGIN
  PERFORM set_config('app.ticket_runtime_write_v1','enabled',true);
  SELECT identity.display_name INTO STRICT display_name
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id = membership.user_id
  WHERE membership.tenant_id = NEW.tenant_id
    AND membership.id = NEW.author_membership_id
    AND membership.user_id = NEW.author_user_id;

  IF NEW.origin = 'customer_portal' THEN
    audience_value := 'customer';
    SELECT contact.id INTO STRICT contact_id
    FROM public.customer_contacts AS contact
    JOIN public.ticket_customer_contacts AS link
      ON link.tenant_id = contact.tenant_id
     AND link.contact_id = contact.id
     AND link.archived_at IS NULL
     AND (link.alert_id = NEW.alert_id OR link.case_id = NEW.case_id)
    WHERE contact.tenant_id = NEW.tenant_id
      AND contact.linked_membership_id = NEW.author_membership_id
      AND contact.linked_user_id = NEW.author_user_id
      AND contact.active AND contact.archived_at IS NULL;
  ELSIF NEW.origin = 'api' AND EXISTS (
    SELECT 1
    FROM public.tenant_memberships AS membership
    WHERE membership.tenant_id = NEW.tenant_id
      AND membership.id = NEW.author_membership_id
      AND membership.role IN ('customer_manager','customer_user','read_only')
  ) THEN
    RAISE EXCEPTION 'customer comments require the portal ABI'
      USING ERRCODE = '42501';
  END IF;

  INSERT INTO public.ticket_comment_author_snapshots (
    tenant_id,comment_id,audience,author_membership_id,author_user_id,
    author_contact_id,display_name,origin,created_at,editable_until
  ) VALUES (
    NEW.tenant_id,NEW.id,audience_value,NEW.author_membership_id,
    NEW.author_user_id,contact_id,display_name,NEW.origin,NEW.created_at,
    NEW.created_at + interval '15 minutes'
  );
  INSERT INTO public.ticket_comment_revisions (
    id,tenant_id,comment_id,revision,body_markdown,body_html,reason,
    edited_by_membership_id,edited_by_user_id,edited_at
  ) VALUES (
    revision_id,NEW.tenant_id,NEW.id,1,NEW.body_markdown,NEW.body_html,
    'original_comment',NEW.author_membership_id,NEW.author_user_id,NEW.created_at
  );
  IF NEW.origin = 'escalation_copy' THEN
    INSERT INTO public.ticket_comment_escalation_sources (
      tenant_id,copied_comment_id,destination_case_id,legacy_unresolved,created_at
    ) VALUES (NEW.tenant_id,NEW.id,NEW.case_id,true,NEW.created_at);
  END IF;
  INSERT INTO public.ticket_comment_revision_mentions (
    tenant_id,revision_id,mentioned_membership_id,mentioned_user_id,display_name
  )
  SELECT NEW.tenant_id,revision_id,membership.id,membership.user_id,
         identity.display_name
  FROM unnest(NEW.mentioned_user_ids) AS mentioned(user_id)
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = NEW.tenant_id
   AND membership.user_id = mentioned.user_id
  JOIN public.users AS identity ON identity.id = membership.user_id
  ORDER BY membership.id;
  RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'legacy comment author evidence is not exact'
    USING ERRCODE = '42501';
END;
$function$;
ALTER FUNCTION app.capture_ticket_comment_v47_compat_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.capture_ticket_comment_v47_compat_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
CREATE TRIGGER ticket_comments_capture_v47_compat_v1
AFTER INSERT ON public.ticket_comments
FOR EACH ROW EXECUTE FUNCTION app.capture_ticket_comment_v47_compat_v1();
--> statement-breakpoint

DO $ticket_comment_backfill_integrity$
DECLARE
  comment_key record;
BEGIN
  FOR comment_key IN
    SELECT comment.tenant_id,comment.id
    FROM public.ticket_comments AS comment
    ORDER BY comment.tenant_id,comment.id
  LOOP
    PERFORM app.private_ticket_comment_assert_consistent_v1(
      comment_key.tenant_id,comment_key.id
    );
  END LOOP;
END
$ticket_comment_backfill_integrity$;
--> statement-breakpoint

CREATE FUNCTION app.capture_ticket_comment_global_action_key_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  source_kind text;
  operation text;
  result_comment_id uuid;
  result_revision integer;
  existing public.ticket_comment_idempotency_keys%ROWTYPE;
BEGIN
  -- A trigger record is table-shaped.  Referencing a field that does not
  -- exist on that table from a single CASE expression can fail while the
  -- expression is prepared even when another branch would win.  Keep each
  -- table shape in a lazily planned PL/pgSQL branch.
  IF TG_TABLE_NAME = 'ticket_commands' THEN
    source_kind := 'ticket_action';
    operation := NEW.operation;
  ELSIF TG_TABLE_NAME = 'ticket_comment_commands' THEN
    source_kind := 'comment';
    operation := NEW.operation;
    result_comment_id := NEW.result_comment_id;
    result_revision := 1;
  ELSIF TG_TABLE_NAME = 'ticket_watcher_commands' THEN
    source_kind := 'watcher';
    operation := CASE WHEN NEW.alert_id IS NOT NULL
      THEN 'alert' ELSE 'case' END || '.watcher.' || NEW.action;
  ELSE
    RAISE EXCEPTION 'global ticket idempotency source is unsupported'
      USING ERRCODE = '55000';
  END IF;
  PERFORM set_config('app.ticket_runtime_write_v1','enabled',true);
  INSERT INTO public.ticket_comment_idempotency_keys (
    tenant_id, actor_membership_id, actor_user_id, key_digest,
    source_kind, operation, request_digest, result_comment_id,
    result_revision, legacy_ambiguous, created_at
  ) VALUES (
    NEW.tenant_id, NEW.actor_membership_id, NEW.actor_user_id, NEW.key_digest,
    source_kind, operation, NEW.request_digest, result_comment_id,
    result_revision, false,
    NEW.created_at
  )
  ON CONFLICT (tenant_id,actor_membership_id,key_digest) DO NOTHING;
  IF NOT FOUND THEN
    SELECT key_row.* INTO STRICT existing
    FROM public.ticket_comment_idempotency_keys AS key_row
    WHERE key_row.tenant_id = NEW.tenant_id
      AND key_row.actor_membership_id = NEW.actor_membership_id
      AND key_row.key_digest = NEW.key_digest
    FOR UPDATE;
    IF existing.legacy_ambiguous
       OR existing.actor_user_id <> NEW.actor_user_id
       OR existing.source_kind <> source_kind
       OR existing.operation <> operation
       OR existing.request_digest <> NEW.request_digest THEN
      RAISE EXCEPTION 'global ticket idempotency key conflicts'
        USING ERRCODE = '23505',
              CONSTRAINT = 'ticket_comment_idempotency_keys_replay_key';
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;
ALTER FUNCTION app.capture_ticket_comment_global_action_key_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.capture_ticket_comment_global_action_key_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
CREATE TRIGGER ticket_commands_capture_global_key_v1
AFTER INSERT ON public.ticket_commands
FOR EACH ROW EXECUTE FUNCTION app.capture_ticket_comment_global_action_key_v1();
CREATE TRIGGER ticket_watcher_commands_capture_global_key_v1
AFTER INSERT ON public.ticket_watcher_commands
FOR EACH ROW EXECUTE FUNCTION app.capture_ticket_comment_global_action_key_v1();
CREATE TRIGGER ticket_comment_commands_capture_global_key_v1
AFTER INSERT ON public.ticket_comment_commands
FOR EACH ROW EXECUTE FUNCTION app.capture_ticket_comment_global_action_key_v1();
