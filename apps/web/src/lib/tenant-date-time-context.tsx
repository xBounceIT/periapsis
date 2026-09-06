import { useMemo, type ReactNode } from "react";
import { parseRfc3339Instant } from "./rfc3339-instant";
import {
  TenantDateTimeContext,
  resolveTenantDateTimePreferences,
  createTenantInstantFormatter,
  useTenantDateTime,
  type TenantDateTimeContextValue,
  type TenantInstantFormatOptions,
} from "./tenant-date-time";

export function TenantDateTimeProvider({
  children,
  locale,
  timeZone,
}: {
  children: ReactNode;
  locale?: string | undefined;
  timeZone?: string | undefined;
}): React.JSX.Element {
  const value = useMemo<TenantDateTimeContextValue>(() => {
    const preferences = resolveTenantDateTimePreferences({ locale, timeZone });
    return {
      ...preferences,
      formatInstant: createTenantInstantFormatter(preferences),
    };
  }, [locale, timeZone]);

  return (
    <TenantDateTimeContext.Provider value={value}>
      {children}
    </TenantDateTimeContext.Provider>
  );
}

export function TenantInstant({
  children,
  value,
  ...options
}: TenantInstantFormatOptions & {
  children?: ReactNode;
  value: string | undefined;
}): React.JSX.Element {
  const dateTime = useTenantDateTime();
  const label = dateTime.formatInstant(value, options);
  if (!value || parseRfc3339Instant(value) === undefined) {
    return (
      <span>
        {children}
        {label}
      </span>
    );
  }
  return (
    <time dateTime={value} title={`Displayed in ${dateTime.timeZone}`}>
      {children}
      {label}
    </time>
  );
}
