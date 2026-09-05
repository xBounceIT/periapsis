const rfc3339InstantPattern =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/;

export function parseRfc3339Instant(value: unknown): bigint | undefined {
  if (typeof value !== "string") return undefined;
  const match = rfc3339InstantPattern.exec(value);
  if (!match) return undefined;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] =
    match;
  const fractionText = match[7] ?? "";
  const offsetText = match[8];
  if (
    yearText === undefined ||
    monthText === undefined ||
    dayText === undefined ||
    hourText === undefined ||
    minuteText === undefined ||
    secondText === undefined ||
    offsetText === undefined
  ) {
    return undefined;
  }
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth(year, month) ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return undefined;
  }
  if (offsetText !== "Z") {
    const offsetHour = Number(offsetText.slice(1, 3));
    const offsetMinute = Number(offsetText.slice(4, 6));
    if (offsetHour > 23 || offsetMinute > 59) return undefined;
  }
  if (/[1-9]/.test(fractionText.slice(9))) return undefined;
  const nanosecondFraction = fractionText.slice(0, 9).padEnd(9, "0");
  const millisecondFraction = nanosecondFraction.slice(0, 3);
  const normalized = `${yearText}-${monthText}-${dayText}T${hourText}:${minuteText}:${secondText}.${millisecondFraction}${offsetText}`;
  const epochMilliseconds = Date.parse(normalized);
  if (!Number.isFinite(epochMilliseconds)) return undefined;
  return (
    BigInt(epochMilliseconds) * 1_000_000n + BigInt(nanosecondFraction.slice(3))
  );
}

export function currentInstant(): bigint {
  return BigInt(Date.now()) * 1_000_000n;
}

export function hasInstantReached(
  deadline: bigint,
  now = currentInstant(),
): boolean {
  return deadline <= now;
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}
