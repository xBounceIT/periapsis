import { createContext, useContext, useMemo, type ReactNode } from "react";

import { parseRfc3339Instant } from "./rfc3339-instant";

export const fallbackTenantDateTimePreferences = {
  locale: "en-GB",
  timeZone: "UTC",
} as const;

export interface TenantDateTimePreferences {
  locale: string;
  timeZone: string;
}

export interface TenantInstantFormatOptions {
  emptyLabel?: string;
  invalidLabel?: string;
  precision?: "minute" | "second";
}

interface TenantDateTimeContextValue extends TenantDateTimePreferences {
  formatInstant: (
    value: string | undefined,
    options?: TenantInstantFormatOptions,
  ) => string;
}

function resolveLocale(value: string | undefined): string {
  if (!value || value.length > 35) {
    return fallbackTenantDateTimePreferences.locale;
  }
  try {
    const [canonical] = Intl.getCanonicalLocales(value);
    if (!canonical) return fallbackTenantDateTimePreferences.locale;
    const [supported] = Intl.DateTimeFormat.supportedLocalesOf(canonical, {
      localeMatcher: "lookup",
    });
    return supported ?? fallbackTenantDateTimePreferences.locale;
  } catch {
    return fallbackTenantDateTimePreferences.locale;
  }
}

function resolveTimeZone(value: string | undefined): string {
  if (!value || value.length > 64) {
    return fallbackTenantDateTimePreferences.timeZone;
  }
  try {
    return new Intl.DateTimeFormat("en", { timeZone: value }).resolvedOptions()
      .timeZone;
  } catch {
    return fallbackTenantDateTimePreferences.timeZone;
  }
}

export function resolveTenantDateTimePreferences(input?: {
  locale?: string | undefined;
  timeZone?: string | undefined;
}): TenantDateTimePreferences {
  return {
    locale: resolveLocale(input?.locale),
    timeZone: resolveTimeZone(input?.timeZone),
  };
}

function createTenantInstantFormatter(
  preferences: TenantDateTimePreferences,
): TenantDateTimeContextValue["formatInstant"] {
  const baseOptions = {
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    month: "short",
    timeZone: preferences.timeZone,
    year: "numeric",
  } as const;
  const minuteFormatter = new Intl.DateTimeFormat(
    preferences.locale,
    baseOptions,
  );
  const secondFormatter = new Intl.DateTimeFormat(preferences.locale, {
    ...baseOptions,
    second: "2-digit",
  });

  return (value, options = {}) => {
    if (!value) return options.emptyLabel ?? "Not recorded";
    if (parseRfc3339Instant(value) === undefined) {
      return options.invalidLabel ?? "Invalid server time";
    }
    const formatter =
      options.precision === "second" ? secondFormatter : minuteFormatter;
    return `${formatter.format(new Date(value))} · ${preferences.timeZone}`;
  };
}

const fallbackContext: TenantDateTimeContextValue = {
  ...fallbackTenantDateTimePreferences,
  formatInstant: createTenantInstantFormatter(
    fallbackTenantDateTimePreferences,
  ),
};

const TenantDateTimeContext =
  createContext<TenantDateTimeContextValue>(fallbackContext);

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

export function useTenantDateTime(): TenantDateTimeContextValue {
  return useContext(TenantDateTimeContext);
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

export function formatTenantInstant(
  value: string | undefined,
  preferences?: Partial<TenantDateTimePreferences>,
  options?: TenantInstantFormatOptions,
): string {
  if (!preferences) return fallbackContext.formatInstant(value, options);
  const resolved = resolveTenantDateTimePreferences(preferences);
  return createTenantInstantFormatter(resolved)(value, options);
}
