import {
  loadNotifierTelemetryConfiguration,
  startNotifierTelemetry,
} from "../telemetry.js";

export const disabledTestTracing = startNotifierTelemetry(
  loadNotifierTelemetryConfiguration("test", "test", {
    OTEL_SDK_DISABLED: "true",
  }),
  { error() {} },
);
