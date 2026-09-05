import { getSystemStatus, type SystemStatus } from "@periapsis/contracts";

export async function loadSystemStatus(): Promise<SystemStatus> {
  const result = await getSystemStatus({ throwOnError: true });
  return result.data;
}

export function formatCheckedAt(isoTimestamp: string, locale: string): string {
  const value = new Date(isoTimestamp);
  if (Number.isNaN(value.valueOf())) {
    return "Check time unavailable";
  }

  return new Intl.DateTimeFormat(locale, {
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    month: "short",
    second: "2-digit",
    timeZoneName: "short",
    year: "numeric",
  }).format(value);
}
