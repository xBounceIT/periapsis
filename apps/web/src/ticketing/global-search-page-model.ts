export const maximumSearchLength = 200;

export function canonicalSearch(value: string | null): string {
  if (value === null) return "";
  return Array.from(value.trim()).slice(0, maximumSearchLength).join("");
}
