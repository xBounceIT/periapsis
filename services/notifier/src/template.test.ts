import { describe, expect, it } from "vitest";

import {
  NotificationRenderError,
  NotificationValidationError,
} from "./errors.js";
import {
  createNotificationTemplate,
  renderNotificationTemplate,
  rollbackNotificationTemplate,
  type NotificationTemplateInput,
} from "./template.js";
import { id } from "./test/fixtures.js";

describe("sandboxed notification templates", () => {
  it("supports bounded conditions and loops while auto-escaping dynamic data", () => {
    const template = createNotificationTemplate(templateInput());
    const rendered = renderNotificationTemplate(
      template,
      {
        alert: { title: "<img src=x onerror=alert(1)>", tags: ["one", "two"] },
        links: { alert: "https://portal.example.test/alerts/1" },
      },
      { audience: "operator" },
    );

    expect(rendered.subject).toBe("Alert <img src=x onerror=alert(1)>");
    expect(rendered.html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(rendered.html).toContain("one");
    expect(rendered.html).toContain("two");
    expect(rendered.html).toContain(
      'href="https://portal.example.test/alerts/1"',
    );
    expect(rendered.html).toContain("color:#b91c1c");
    expect(rendered.plainText).toContain("Alert: <img src=x onerror=alert(1)>");
  });

  it("removes active HTML, event handlers, and unsafe dynamic URLs", () => {
    const input = templateInput();
    input.html = `<script>steal()</script><iframe src="https://evil.example"></iframe><form><input></form><a onclick="steal()" href="{{links.alert}}">open</a>`;
    const template = createNotificationTemplate(input);
    const rendered = renderNotificationTemplate(
      template,
      { links: { alert: "javascript:alert(1)" } },
      { audience: "operator" },
    );
    expect(rendered.html).not.toMatch(
      /script|iframe|form|input|onclick|javascript/iu,
    );
    expect(rendered.html).toContain("<a>open</a>");
  });

  it("rejects escape bypasses, helpers, prototype paths, unsafe CSS, and malformed blocks", () => {
    const invalid: Array<(input: NotificationTemplateInput) => void> = [
      (input) => {
        input.html = "{{{alert.title}}}";
      },
      (input) => {
        input.html = "{{lookup alert secret}}";
      },
      (input) => {
        input.html = "{{alert.__proto__.polluted}}";
      },
      (input) => {
        input.html = "{{#if alert.title}}missing close";
      },
      (input) => {
        input.css =
          ".hero { background: url(https://evil.example/tracker.png) }";
      },
      (input) => {
        input.css = "@import 'https://evil.example/style.css';";
      },
      (input) => {
        input.css = String.raw`.hero { background-color: u\72l(https://evil.example/pixel) }`;
      },
    ];
    for (const mutate of invalid) {
      const input = templateInput();
      mutate(input);
      expect(() => createNotificationTemplate(input)).toThrow(
        NotificationValidationError,
      );
    }
  });

  it("fails closed on oversized loops, subject injection, output limits, and forged aggregates", () => {
    const template = createNotificationTemplate(templateInput());
    expect(() =>
      renderNotificationTemplate(
        template,
        {
          alert: {
            title: "safe",
            tags: Array.from({ length: 101 }, () => "x"),
          },
          links: {},
        },
        { audience: "operator" },
      ),
    ).toThrow(NotificationValidationError);
    expect(() =>
      renderNotificationTemplate(
        template,
        {
          alert: { title: "header\r\nBcc: victim@example.com", tags: [] },
          links: {},
        },
        { audience: "operator" },
      ),
    ).toThrow(NotificationRenderError);
    expect(() =>
      renderNotificationTemplate(
        template,
        {
          alert: {
            title: "safe",
            tags: Array.from({ length: 100 }, () => "x".repeat(100)),
          },
          links: {},
        },
        { audience: "operator", maximumOutputBytes: 1_024 },
      ),
    ).toThrow(NotificationRenderError);
    expect(() =>
      renderNotificationTemplate(
        { ...template },
        { alert: { title: "safe", tags: [] }, links: {} },
        { audience: "operator" },
      ),
    ).toThrow(NotificationValidationError);
  });

  it("rolls back only within the exact tenant/template lineage", () => {
    const v1 = createNotificationTemplate(templateInput());
    const nextInput = templateInput();
    nextInput.version = 2;
    nextInput.subject = "Changed {{alert.title}}";
    const v2 = createNotificationTemplate(nextInput);
    const v3 = rollbackNotificationTemplate(v2, v1, 3);
    expect(v3.version).toBe(3);
    expect(v3.subject).toBe(v1.subject);
    expect(() => rollbackNotificationTemplate(v2, v1, 4)).toThrow(
      NotificationValidationError,
    );
    expect(() => rollbackNotificationTemplate({ ...v2 }, v1, 3)).toThrow(
      NotificationValidationError,
    );
  });

  it("preserves readable block boundaries in generated plaintext", () => {
    const input = templateInput();
    input.html =
      "<h1>{{alert.title}}</h1><p>First line<br>Second line</p><ul><li>One</li><li>Two</li></ul>";
    const rendered = renderNotificationTemplate(
      createNotificationTemplate(input),
      { alert: { title: "Critical" } },
      { audience: "operator" },
    );
    expect(rendered.plainText).toBe(
      "Critical\nFirst line\nSecond line\nOne\nTwo",
    );
  });

  it("never evaluates context accessors during rendering", () => {
    const alert = {};
    let executed = false;
    Object.defineProperty(alert, "title", {
      enumerable: true,
      get() {
        executed = true;
        return "secret";
      },
    });
    expect(() =>
      renderNotificationTemplate(
        createNotificationTemplate(templateInput()),
        { alert },
        { audience: "operator" },
      ),
    ).toThrow(NotificationValidationError);
    expect(executed).toBe(false);
  });
});

function templateInput(): NotificationTemplateInput {
  return {
    id: id(50),
    tenantId: id(2),
    key: "critical_alert",
    name: "Critical alert",
    language: "en-US",
    version: 1,
    subject: "Alert {{alert.title}}",
    html: `<div class="hero"><p>Alert: {{alert.title}}</p>{{#if alert.tags}}<ul>{{#each alert.tags}}<li>{{this}}</li>{{/each}}</ul>{{/if}}<a href="{{links.alert}}">Open</a></div>`,
    css: ".hero { color: #b91c1c; font-weight: 600 }",
  };
}
