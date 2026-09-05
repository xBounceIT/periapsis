export class NotificationValidationError extends Error {
  readonly code = "notification_validation_failed";

  constructor(message: string) {
    super(message);
    this.name = "NotificationValidationError";
  }
}

export class NotificationTenantBoundaryError extends Error {
  readonly code = "notification_tenant_boundary";

  constructor() {
    super("notification data crossed a tenant boundary");
    this.name = "NotificationTenantBoundaryError";
  }
}

export class NotificationConflictError extends Error {
  readonly code = "notification_conflict";

  constructor(message = "notification state changed concurrently") {
    super(message);
    this.name = "NotificationConflictError";
  }
}

export class NotificationConfigurationError extends Error {
  readonly code = "notification_configuration_failed";

  constructor(message = "notification configuration is unavailable") {
    super(message);
    this.name = "NotificationConfigurationError";
  }
}

export class NotificationRenderError extends Error {
  readonly code = "notification_render_failed";

  constructor(message: string) {
    super(message);
    this.name = "NotificationRenderError";
  }
}

export type DeliveryFailureClass =
  | "authentication"
  | "connectivity"
  | "rate_limited"
  | "render"
  | "security"
  | "timeout"
  | "tls"
  | "unknown";

export class DeliveryProviderError extends Error {
  readonly failureClass: DeliveryFailureClass;
  readonly retrySafety: "safe" | "uncertain" | "terminal";

  constructor(
    failureClass: DeliveryFailureClass,
    retrySafety: "safe" | "uncertain" | "terminal",
  ) {
    super("delivery provider failed");
    this.name = "DeliveryProviderError";
    this.failureClass = failureClass;
    this.retrySafety = retrySafety;
  }
}
