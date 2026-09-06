import type { NotificationDeliveryDetail } from "@periapsis/contracts";

export function requiresSubmissionUncertainConfirmation(
  delivery: Pick<NotificationDeliveryDetail, "failureClass">,
): boolean {
  return delivery.failureClass === "submission_uncertain";
}
