const expiryFormatter = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
  timeZoneName: "short",
});

export function formatExpiry(value: string): string {
  const expiry = new Date(value);
  return Number.isNaN(expiry.valueOf())
    ? "soon"
    : expiryFormatter.format(expiry);
}
