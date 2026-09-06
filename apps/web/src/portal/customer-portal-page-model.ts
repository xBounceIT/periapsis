import type { ContactNotificationWindow } from "@periapsis/contracts";
import {
  ContactApiError,
  type CustomerPortalExportFile,
} from "../contacts/contact-api";

export function saveCustomerPortalExport(file: CustomerPortalExportFile): void {
  const objectURL = URL.createObjectURL(file.blob);
  const anchor = document.createElement("a");
  try {
    anchor.download = file.filename;
    anchor.href = objectURL;
    anchor.rel = "noopener";
    anchor.hidden = true;
    document.body.append(anchor);
    anchor.click();
  } finally {
    anchor.remove();
    globalThis.setTimeout(() => URL.revokeObjectURL(objectURL), 0);
  }
}

export function parseNotificationWindows(
  value: string,
): ContactNotificationWindow[] {
  if (!value.trim()) return [];
  const windows = value
    .split(/\r?\n/u)
    .map((line, index) => {
      const match = /^([1-7])\s+([0-2]\d:[0-5]\d)-([0-2]\d:[0-5]\d)$/u.exec(
        line.trim(),
      );
      if (!match) {
        throw new ContactApiError(
          `Window line ${index + 1} must use “weekday HH:MM-HH:MM”.`,
        );
      }
      const isoWeekday = Number(match[1]);
      const startMinute = minuteOfDay(match[2] ?? "");
      const endMinute = minuteOfDay(match[3] ?? "");
      if (startMinute >= endMinute) {
        throw new ContactApiError(
          `Window line ${index + 1} must end after it starts.`,
        );
      }
      return { endMinute, isoWeekday, startMinute };
    })
    .toSorted(
      (left, right) =>
        left.isoWeekday - right.isoWeekday ||
        left.startMinute - right.startMinute ||
        left.endMinute - right.endMinute,
    );
  for (let index = 1; index < windows.length; index += 1) {
    const previous = windows[index - 1];
    const current = windows[index];
    if (
      previous &&
      current &&
      previous.isoWeekday === current.isoWeekday &&
      current.startMinute < previous.endMinute
    ) {
      throw new ContactApiError(
        `Notification windows overlap on ISO weekday ${current.isoWeekday}.`,
      );
    }
  }
  return windows;
}

export function formatNotificationWindows(
  windows: ContactNotificationWindow[],
): string {
  return windows
    .map(
      (window) =>
        `${window.isoWeekday} ${clock(window.startMinute)}-${clock(window.endMinute)}`,
    )
    .join("\n");
}

function minuteOfDay(value: string): number {
  const [hourText, minuteText] = value.split(":");
  const hour = Number(hourText);
  const minute = Number(minuteText);
  if (!Number.isInteger(hour) || !Number.isInteger(minute) || hour > 23) {
    throw new ContactApiError(
      "Notification window times must be valid local wall-clock times.",
    );
  }
  return hour * 60 + minute;
}

function clock(value: number): string {
  const hours = Math.floor(value / 60)
    .toString()
    .padStart(2, "0");
  const minutes = (value % 60).toString().padStart(2, "0");
  return `${hours}:${minutes}`;
}
