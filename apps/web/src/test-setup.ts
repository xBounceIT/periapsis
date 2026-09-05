// oxlint-disable-next-line import/no-unassigned-import -- Installs DOM matchers for every test.
import "@testing-library/jest-dom/vitest";

class TestResizeObserver implements ResizeObserver {
  disconnect(): void {}

  observe(): void {}

  unobserve(): void {}
}

globalThis.ResizeObserver = TestResizeObserver;

if (typeof globalThis.Element !== "undefined") {
  Object.defineProperty(globalThis.Element.prototype, "scrollIntoView", {
    configurable: true,
    value(): void {},
  });
}
