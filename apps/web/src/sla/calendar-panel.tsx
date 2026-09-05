import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
import { Input } from "@periapsis/ui/components/ui/input";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import { FormField } from "../components/form-field";
import { generateUuidV7 } from "../lib/uuid-v7";
import type {
  BusinessCalendar,
  BusinessCalendarWrite,
  CalendarDaySchedule,
  CalendarException,
  CalendarInterval,
  CalendarWeekday,
} from "./model";
import {
  calendarWeekdays,
  normalizeCalendarWrite,
  parseBoundedJson,
} from "./model";
import type { SlaAdminApi } from "./sla-api";
import type { SlaResourceEditorProps } from "./versioned-resource-panel";
import { VersionedResourcePanel } from "./versioned-resource-panel";

interface CalendarDraft {
  exceptionsJson: string;
  id: string;
  key: string;
  keyLocked: boolean;
  label: string;
  timezone: string;
  weeklySchedulesJson: string;
}

export function CalendarPanel({
  api,
  canManage,
  csrfToken,
  tenantId,
}: {
  api: SlaAdminApi;
  canManage: boolean;
  csrfToken: string;
  tenantId: string;
}): React.JSX.Element {
  return (
    <VersionedResourcePanel<BusinessCalendar, CalendarDraft>
      archive={(input) => api.archiveCalendar(input)}
      canManage={canManage}
      create={({ body, ...context }) =>
        api.createCalendar({ ...context, body: calendarWrite(body) })
      }
      csrfToken={csrfToken}
      draftFrom={calendarDraft}
      editor={(props) => <CalendarEditor {...props} />}
      emptyDetail="Publish a versioned business calendar before assigning business-time SLA metrics."
      eyebrow="Timezone / business time"
      get={(input) => api.getCalendar(input)}
      kindLabel="calendar"
      list={(input) => api.listCalendars(input)}
      normalize={normalizeCalendarDraft}
      renderSummary={(calendar) => (
        <small>
          {calendar.timezone} · {calendarWindowCount(calendar)} weekly windows
        </small>
      )}
      tenantId={tenantId}
      version={({ body, ...context }) =>
        api.versionCalendar({ ...context, body: calendarVersionWrite(body) })
      }
    />
  );
}

function CalendarEditor({
  draft,
  disabled,
  setDraft,
}: SlaResourceEditorProps<CalendarDraft>): React.JSX.Element {
  return (
    <div className="sla-form-grid">
      <FormField
        htmlFor="sla-calendar-key"
        label="Stable key"
        hint="Lowercase key; immutable lineage identity."
      >
        <Input
          id="sla-calendar-key"
          required
          maxLength={64}
          disabled={disabled}
          readOnly={draft.keyLocked}
          value={draft.key}
          onChange={(event) =>
            setDraft((current) => ({ ...current, key: event.target.value }))
          }
        />
      </FormField>
      <FormField htmlFor="sla-calendar-name" label="Label">
        <Input
          id="sla-calendar-name"
          required
          maxLength={256}
          disabled={disabled}
          value={draft.label}
          onChange={(event) =>
            setDraft((current) => ({ ...current, label: event.target.value }))
          }
        />
      </FormField>
      <FormField
        htmlFor="sla-calendar-timezone"
        label="IANA timezone"
        hint="DST is evaluated using this pinned timezone version."
      >
        <Input
          id="sla-calendar-timezone"
          required
          maxLength={128}
          disabled={disabled}
          value={draft.timezone}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              timezone: event.target.value,
            }))
          }
        />
      </FormField>
      <div className="sla-form-grid__wide">
        <FormField
          htmlFor="sla-calendar-week"
          label="Weekly windows"
          hint="Canonical weekday array (sunday through saturday). Intervals use minute boundaries 0..1440 and may not overlap."
        >
          <Textarea
            id="sla-calendar-week"
            rows={11}
            spellCheck={false}
            disabled={disabled}
            value={draft.weeklySchedulesJson}
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                weeklySchedulesJson: event.target.value,
              }))
            }
          />
        </FormField>
      </div>
      <div className="sla-form-grid__wide">
        <FormField
          htmlFor="sla-calendar-exceptions"
          label="Holiday and closure exceptions"
          hint="Closed dates have no intervals; replacement-hour dates must contain at least one interval."
        >
          <Textarea
            id="sla-calendar-exceptions"
            rows={8}
            spellCheck={false}
            disabled={disabled}
            value={draft.exceptionsJson}
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                exceptionsJson: event.target.value,
              }))
            }
          />
        </FormField>
      </div>
      <div className="sla-calendar-days" aria-label="Configured weekdays">
        {calendarWeekdays.map((day) => (
          <label key={day}>
            <Checkbox
              checked={hasDay(draft.weeklySchedulesJson, day)}
              disabled
            />
            <span>{day.slice(0, 3)}</span>
          </label>
        ))}
      </div>
    </div>
  );
}

function calendarDraft(calendar?: BusinessCalendar): CalendarDraft {
  const weeklySchedules: CalendarDaySchedule[] = calendar?.weeklySchedules ?? [
    { weekday: "monday", intervals: [{ startMinute: 540, endMinute: 1080 }] },
    { weekday: "tuesday", intervals: [{ startMinute: 540, endMinute: 1080 }] },
    {
      weekday: "wednesday",
      intervals: [{ startMinute: 540, endMinute: 1080 }],
    },
    { weekday: "thursday", intervals: [{ startMinute: 540, endMinute: 1080 }] },
    { weekday: "friday", intervals: [{ startMinute: 540, endMinute: 1080 }] },
  ];
  return {
    id: calendar?.id ?? generateUuidV7(),
    key: calendar?.key ?? "",
    keyLocked: calendar !== undefined,
    label: calendar?.label ?? "",
    timezone: calendar?.timezone ?? "Europe/Rome",
    weeklySchedulesJson: prettyJson(weeklySchedules),
    exceptionsJson: prettyJson(calendar?.exceptions ?? []),
  };
}

function normalizeCalendarDraft(draft: CalendarDraft): CalendarDraft {
  const normalized = normalizeCalendarWrite(calendarWrite(draft));
  return {
    ...draft,
    key: normalized.key,
    label: normalized.label,
    timezone: normalized.timezone,
    weeklySchedulesJson: prettyJson(normalized.weeklySchedules),
    exceptionsJson: prettyJson(normalized.exceptions),
  };
}

function calendarWrite(draft: CalendarDraft): BusinessCalendarWrite {
  return normalizeCalendarWrite({
    id: draft.id,
    key: draft.key,
    label: draft.label,
    timezone: draft.timezone,
    weeklySchedules: parseBoundedJson(
      draft.weeklySchedulesJson,
      "Weekly schedule",
      decodeCalendarSchedule,
    ),
    exceptions: parseBoundedJson(
      draft.exceptionsJson,
      "Calendar exceptions",
      decodeCalendarExceptions,
    ),
  });
}

function calendarWindowCount(calendar: BusinessCalendar): number {
  return calendar.weeklySchedules.reduce(
    (total, schedule) => total + schedule.intervals.length,
    0,
  );
}

function hasDay(source: string, day: CalendarWeekday): boolean {
  try {
    const parsed: unknown = JSON.parse(source);
    if (!Array.isArray(parsed)) return false;
    return parsed.some(
      (schedule) =>
        isRecord(schedule) &&
        schedule["weekday"] === day &&
        Array.isArray(schedule["intervals"]) &&
        schedule["intervals"].length > 0,
    );
  } catch {
    return false;
  }
}

function prettyJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function decodeCalendarSchedule(value: unknown): CalendarDaySchedule[] {
  if (!Array.isArray(value) || !value.every(isCalendarDaySchedule)) {
    throw new TypeError(
      "Weekly schedule must be an array of weekday and interval objects.",
    );
  }
  return value;
}

function decodeCalendarExceptions(value: unknown): CalendarException[] {
  if (!Array.isArray(value) || !value.every(isCalendarException)) {
    throw new TypeError(
      "Calendar exceptions must be an array of date, closed, and interval objects.",
    );
  }
  return value;
}

function isCalendarException(value: unknown): value is CalendarException {
  return (
    isRecord(value) &&
    typeof value["closed"] === "boolean" &&
    typeof value["date"] === "string" &&
    Array.isArray(value["intervals"]) &&
    value["intervals"].every(isCalendarInterval)
  );
}

function isCalendarDaySchedule(value: unknown): value is CalendarDaySchedule {
  return (
    isRecord(value) &&
    isCalendarWeekday(value["weekday"]) &&
    Array.isArray(value["intervals"]) &&
    value["intervals"].every(isCalendarInterval)
  );
}

function isCalendarInterval(value: unknown): value is CalendarInterval {
  return (
    isRecord(value) &&
    typeof value["startMinute"] === "number" &&
    typeof value["endMinute"] === "number"
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isCalendarWeekday(value: unknown): value is CalendarWeekday {
  return (
    typeof value === "string" &&
    calendarWeekdays.some((weekday) => weekday === value)
  );
}

function calendarVersionWrite(
  draft: CalendarDraft,
): Omit<BusinessCalendarWrite, "id"> {
  const value = calendarWrite(draft);
  return {
    key: value.key,
    label: value.label,
    timezone: value.timezone,
    weeklySchedules: value.weeklySchedules,
    exceptions: value.exceptions,
  };
}
