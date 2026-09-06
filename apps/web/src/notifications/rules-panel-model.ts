import { safeNotificationError } from "./model";

export function describeRuleError(value: unknown): string {
  return safeNotificationError(value, "The rule could not be saved.");
}
