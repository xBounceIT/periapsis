/** Reads a text control without coercing attacker-injected File values. */
export function readTextField(fields: FormData, name: string): string {
  const value = fields.get(name);
  return typeof value === "string" ? value : "";
}
