import { performance } from "node:perf_hooks";

import juice from "juice";
import sanitizeHtml from "sanitize-html";

import {
  NotificationRenderError,
  NotificationValidationError,
} from "./errors.js";
import {
  canonicalizeNotificationContext,
  isContextObject,
  type ContextValue,
  type NotificationAudience,
} from "./event.js";
import {
  requireInteger,
  requireKey,
  requireText,
  requireUuidV7,
} from "./validation.js";

export interface NotificationTemplateInput {
  id: string;
  tenantId: string;
  key: string;
  name: string;
  language: string;
  version: number;
  subject: string;
  html: string;
  plainText?: string;
  css?: string;
}

export interface NotificationTemplate {
  readonly id: string;
  readonly tenantId: string;
  readonly key: string;
  readonly name: string;
  readonly language: string;
  readonly version: number;
  readonly subject: string;
  readonly html: string;
  readonly plainText?: string;
  readonly css: string;
  readonly placeholders: readonly string[];
}

export interface RenderTemplateOptions {
  audience: NotificationAudience;
  timeoutMs?: number;
  maximumOutputBytes?: number;
}

export interface RenderedNotification {
  readonly subject: string;
  readonly html: string;
  readonly plainText: string;
}

type TemplateNode =
  | { readonly kind: "text"; readonly value: string }
  | { readonly kind: "variable"; readonly path: string }
  | {
      readonly kind: "if";
      readonly path: string;
      readonly truthy: readonly TemplateNode[];
      readonly falsy: readonly TemplateNode[];
    }
  | {
      readonly kind: "each";
      readonly path: string;
      readonly children: readonly TemplateNode[];
    };

interface CompiledTemplate {
  readonly subject: readonly TemplateNode[];
  readonly html: readonly TemplateNode[];
  readonly plainText?: readonly TemplateNode[];
}

const compiledTemplates = new WeakMap<NotificationTemplate, CompiledTemplate>();
const authenticTemplates = new WeakSet<NotificationTemplate>();
const allowedPathRoots = new Set([
  "tenant",
  "alert",
  "case",
  "actor",
  "assignee",
  "operatorTeam",
  "contact",
  "comment",
  "sla",
  "task",
  "links",
  "evidence",
]);
const allowedTags = [
  "a",
  "b",
  "blockquote",
  "br",
  "code",
  "div",
  "em",
  "h1",
  "h2",
  "h3",
  "hr",
  "li",
  "ol",
  "p",
  "pre",
  "span",
  "strong",
  "table",
  "tbody",
  "td",
  "th",
  "thead",
  "tr",
  "u",
  "ul",
];
const allowedCssProperties = [
  "background-color",
  "border",
  "border-bottom",
  "border-collapse",
  "border-color",
  "border-left",
  "border-radius",
  "border-right",
  "border-style",
  "border-top",
  "border-width",
  "color",
  "display",
  "font-family",
  "font-size",
  "font-style",
  "font-weight",
  "height",
  "letter-spacing",
  "line-height",
  "margin",
  "margin-bottom",
  "margin-left",
  "margin-right",
  "margin-top",
  "max-width",
  "padding",
  "padding-bottom",
  "padding-left",
  "padding-right",
  "padding-top",
  "text-align",
  "text-decoration",
  "vertical-align",
  "white-space",
  "width",
];

export function createNotificationTemplate(
  input: NotificationTemplateInput,
): NotificationTemplate {
  requireUuidV7(input.id, "template.id");
  requireUuidV7(input.tenantId, "template.tenantId");
  const key = requireKey(input.key, "template.key");
  const name = requireText(input.name, "template.name", 160);
  const language = canonicalLanguage(input.language);
  requireInteger(input.version, "template.version", 1, 2_147_483_647);
  const subject = requireText(input.subject, "template.subject", 998);
  const html = requireText(input.html, "template.html", 128 * 1_024, {
    allowNewlines: true,
  });
  const plainText =
    input.plainText === undefined
      ? undefined
      : requireText(input.plainText, "template.plainText", 128 * 1_024, {
          allowEmpty: true,
          allowNewlines: true,
        });
  const css = sanitizeCss(input.css ?? "");
  const subjectNodes = compileTemplate(subject, "subject");
  const htmlNodes = compileTemplate(html, "html");
  const plainNodes =
    plainText === undefined
      ? undefined
      : compileTemplate(plainText, "plainText");
  const placeholders = Object.freeze(
    [...collectPlaceholders(subjectNodes, htmlNodes, plainNodes)].toSorted(
      (left, right) => left.localeCompare(right),
    ),
  );
  const template = Object.freeze({
    id: input.id,
    tenantId: input.tenantId,
    key,
    name,
    language,
    version: input.version,
    subject,
    html,
    ...(plainText === undefined ? {} : { plainText }),
    css,
    placeholders,
  });
  compiledTemplates.set(
    template,
    Object.freeze({
      subject: subjectNodes,
      html: htmlNodes,
      ...(plainNodes === undefined ? {} : { plainText: plainNodes }),
    }),
  );
  authenticTemplates.add(template);
  return template;
}

export function rollbackNotificationTemplate(
  current: NotificationTemplate,
  target: NotificationTemplate,
  nextVersion: number,
): NotificationTemplate {
  if (
    !authenticTemplates.has(current) ||
    !authenticTemplates.has(target) ||
    current.id !== target.id ||
    current.tenantId !== target.tenantId ||
    current.key !== target.key ||
    target.version >= current.version ||
    nextVersion !== current.version + 1
  ) {
    throw new NotificationValidationError("template rollback pins are invalid");
  }
  return createNotificationTemplate({
    id: current.id,
    tenantId: current.tenantId,
    key: current.key,
    name: target.name,
    language: target.language,
    version: nextVersion,
    subject: target.subject,
    html: target.html,
    ...(target.plainText === undefined ? {} : { plainText: target.plainText }),
    css: target.css,
  });
}

export function renderNotificationTemplate(
  template: NotificationTemplate,
  context: Readonly<Record<string, ContextValue>>,
  options: RenderTemplateOptions,
): RenderedNotification {
  const compiled = compiledTemplates.get(template);
  if (compiled === undefined) {
    throw new NotificationValidationError(
      "template was not created by the notification domain",
    );
  }
  if (options.audience !== "operator" && options.audience !== "customer") {
    throw new NotificationValidationError("template audience is unsupported");
  }
  const timeoutMs = options.timeoutMs ?? 100;
  const maximumOutputBytes = options.maximumOutputBytes ?? 256 * 1_024;
  requireInteger(timeoutMs, "render.timeoutMs", 1, 5_000);
  requireInteger(
    maximumOutputBytes,
    "render.maximumOutputBytes",
    1_024,
    1024 * 1_024,
  );
  const state: RenderState = {
    deadline: performance.now() + timeoutMs,
    maximumOutputBytes,
    outputBytes: 0,
    iterations: 0,
  };
  const safeContext = canonicalizeNotificationContext(context);
  const subject = renderNodes(
    compiled.subject,
    safeContext,
    undefined,
    "subject",
    state,
  );
  if (/\r|\n/u.test(subject) || Buffer.byteLength(subject) > 998) {
    throw new NotificationRenderError("rendered subject is invalid");
  }
  const rawHtml = renderNodes(
    compiled.html,
    safeContext,
    undefined,
    "html",
    state,
  );
  const initialHtml = sanitizeRenderedHtml(rawHtml, false);
  checkDeadline(state);
  const inlined =
    template.css.length === 0
      ? initialHtml
      : juice(initialHtml, {
          extraCss: template.css,
          applyStyleTags: false,
          removeStyleTags: true,
          preserveFontFaces: false,
          preserveKeyFrames: false,
          preserveMediaQueries: false,
          preservePseudos: false,
          insertPreservedExtraCss: false,
        });
  checkDeadline(state);
  const html = sanitizeRenderedHtml(inlined, true);
  assertOutputSize(html, maximumOutputBytes, "html");
  const plainText =
    compiled.plainText === undefined
      ? htmlToPlainText(html)
      : renderNodes(
          compiled.plainText,
          safeContext,
          undefined,
          "plainText",
          state,
        );
  assertOutputSize(plainText, maximumOutputBytes, "plainText");
  return Object.freeze({ subject, html, plainText });
}

interface RenderState {
  readonly deadline: number;
  readonly maximumOutputBytes: number;
  outputBytes: number;
  iterations: number;
}

function renderNodes(
  nodes: readonly TemplateNode[],
  root: Readonly<Record<string, ContextValue>>,
  current: ContextValue | undefined,
  channel: "subject" | "html" | "plainText",
  state: RenderState,
): string {
  const output: string[] = [];
  for (const node of nodes) {
    checkDeadline(state);
    switch (node.kind) {
      case "text":
        appendOutput(output, node.value, state);
        break;
      case "variable": {
        const value = readTemplatePath(node.path, root, current);
        if (value === undefined || value === null) break;
        if (typeof value === "object") {
          throw new NotificationRenderError(
            `placeholder ${node.path} is not scalar`,
          );
        }
        const rendered = String(value);
        appendOutput(
          output,
          channel === "html" ? escapeHtml(rendered) : rendered,
          state,
        );
        break;
      }
      case "if": {
        const value = readTemplatePath(node.path, root, current);
        appendOutput(
          output,
          renderNodes(
            truthy(value) ? node.truthy : node.falsy,
            root,
            current,
            channel,
            state,
          ),
          state,
          false,
        );
        break;
      }
      case "each": {
        const value = readTemplatePath(node.path, root, current);
        if (value === undefined || value === null) break;
        if (!Array.isArray(value)) {
          throw new NotificationRenderError(
            `loop ${node.path} is not an array`,
          );
        }
        if (value.length > 100) {
          throw new NotificationRenderError(
            `loop ${node.path} exceeds its iteration limit`,
          );
        }
        for (const item of value) {
          state.iterations += 1;
          if (state.iterations > 1_000) {
            throw new NotificationRenderError(
              "template exceeds its total iteration limit",
            );
          }
          appendOutput(
            output,
            renderNodes(node.children, root, item, channel, state),
            state,
            false,
          );
        }
        break;
      }
    }
  }
  return output.join("");
}

function appendOutput(
  output: string[],
  value: string,
  state: RenderState,
  count = true,
): void {
  if (count) state.outputBytes += Buffer.byteLength(value);
  if (state.outputBytes > state.maximumOutputBytes) {
    throw new NotificationRenderError("template output exceeds its size limit");
  }
  output.push(value);
}

function truthy(value: ContextValue | undefined): boolean {
  return (
    value !== undefined &&
    value !== null &&
    value !== false &&
    value !== "" &&
    value !== 0 &&
    (!Array.isArray(value) || value.length > 0)
  );
}

function readTemplatePath(
  path: string,
  root: Readonly<Record<string, ContextValue>>,
  current: ContextValue | undefined,
): ContextValue | undefined {
  const segments = path.split(".");
  let value: ContextValue | undefined;
  if (segments[0] === "this") {
    value = current;
    segments.shift();
  } else {
    value = root;
  }
  for (const segment of segments) {
    if (!isContextObject(value)) return undefined;
    value = Object.prototype.hasOwnProperty.call(value, segment)
      ? value[segment]
      : undefined;
  }
  return value;
}

function compileTemplate(
  source: string,
  field: string,
): readonly TemplateNode[] {
  if (source.includes("{{{") || source.includes("}}}")) {
    throw new NotificationValidationError(
      `${field} cannot disable auto-escaping`,
    );
  }
  const tokens: Array<{ kind: "text" | "directive"; value: string }> = [];
  const matcher = /\x7b\x7b([\s\S]*?)\x7d\x7d/gu;
  let cursor = 0;
  let match: RegExpExecArray | null;
  while ((match = matcher.exec(source)) !== null) {
    if (match.index > cursor)
      tokens.push({ kind: "text", value: source.slice(cursor, match.index) });
    tokens.push({ kind: "directive", value: (match[1] ?? "").trim() });
    cursor = matcher.lastIndex;
    if (tokens.length > 1_024) {
      throw new NotificationValidationError(
        `${field} has too many template tokens`,
      );
    }
  }
  if (cursor < source.length)
    tokens.push({ kind: "text", value: source.slice(cursor) });
  if (
    tokens.some(
      (token) =>
        token.kind === "text" &&
        (token.value.includes("{{") || token.value.includes("}}")),
    )
  ) {
    throw new NotificationValidationError(
      `${field} contains an unterminated template token`,
    );
  }
  const parsed = parseSequence(tokens, 0, 0);
  if (parsed.stop !== undefined || parsed.next !== tokens.length) {
    throw new NotificationValidationError(
      `${field} contains an unmatched block marker`,
    );
  }
  return parsed.nodes;
}

function parseSequence(
  tokens: readonly { kind: "text" | "directive"; value: string }[],
  start: number,
  depth: number,
): { nodes: readonly TemplateNode[]; next: number; stop?: string } {
  if (depth > 8)
    throw new NotificationValidationError("template block nesting is too deep");
  const nodes: TemplateNode[] = [];
  for (let index = start; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (token.kind === "text") {
      nodes.push(Object.freeze({ kind: "text", value: token.value }));
      continue;
    }
    if (
      token.value === "else" ||
      token.value === "/if" ||
      token.value === "/each"
    ) {
      return {
        nodes: Object.freeze(nodes),
        next: index + 1,
        stop: token.value,
      };
    }
    if (token.value.startsWith("#if ")) {
      const path = canonicalTemplatePath(token.value.slice(4));
      const truthyBranch = parseSequence(tokens, index + 1, depth + 1);
      let falsyBranch: readonly TemplateNode[] = Object.freeze([]);
      let next = truthyBranch.next;
      if (truthyBranch.stop === "else") {
        const parsedFalsy = parseSequence(tokens, truthyBranch.next, depth + 1);
        if (parsedFalsy.stop !== "/if") {
          throw new NotificationValidationError("if block is not closed");
        }
        falsyBranch = parsedFalsy.nodes;
        next = parsedFalsy.next;
      } else if (truthyBranch.stop !== "/if") {
        throw new NotificationValidationError("if block is not closed");
      }
      nodes.push(
        Object.freeze({
          kind: "if",
          path,
          truthy: truthyBranch.nodes,
          falsy: falsyBranch,
        }),
      );
      index = next - 1;
      continue;
    }
    if (token.value.startsWith("#each ")) {
      const path = canonicalTemplatePath(token.value.slice(6));
      const branch = parseSequence(tokens, index + 1, depth + 1);
      if (branch.stop !== "/each") {
        throw new NotificationValidationError("each block is not closed");
      }
      nodes.push(Object.freeze({ kind: "each", path, children: branch.nodes }));
      index = branch.next - 1;
      continue;
    }
    if (
      token.value.startsWith("#") ||
      token.value.startsWith("/") ||
      token.value === ""
    ) {
      throw new NotificationValidationError(
        "template directive is unsupported",
      );
    }
    nodes.push(
      Object.freeze({
        kind: "variable",
        path: canonicalTemplatePath(token.value),
      }),
    );
  }
  return { nodes: Object.freeze(nodes), next: tokens.length };
}

function canonicalTemplatePath(input: string): string {
  requireText(input, "template placeholder", 256);
  const segments = input.split(".");
  const isCurrent = segments[0] === "this";
  if (
    segments.length > 10 ||
    (!isCurrent && !allowedPathRoots.has(segments[0] ?? "")) ||
    (isCurrent &&
      segments.length > 1 &&
      !segments.slice(1).every(validPathSegment)) ||
    (!isCurrent && !segments.every(validPathSegment))
  ) {
    throw new NotificationValidationError(
      "template placeholder is not allowlisted",
    );
  }
  return input;
}

function validPathSegment(segment: string): boolean {
  return (
    /^[A-Za-z][A-Za-z0-9_-]{0,63}$/u.test(segment) &&
    !["constructor", "prototype", "__proto__"].includes(segment)
  );
}

function collectPlaceholders(
  ...roots: Array<readonly TemplateNode[] | undefined>
): ReadonlySet<string> {
  const result = new Set<string>();
  const visit = (nodes: readonly TemplateNode[]): void => {
    for (const node of nodes) {
      if (node.kind === "variable") result.add(node.path);
      if (node.kind === "if") {
        result.add(node.path);
        visit(node.truthy);
        visit(node.falsy);
      }
      if (node.kind === "each") {
        result.add(node.path);
        visit(node.children);
      }
    }
  };
  for (const root of roots) if (root !== undefined) visit(root);
  return result;
}

function canonicalLanguage(input: string): string {
  requireText(input, "template.language", 35);
  if (!/^[a-z]{2,3}(?:-[A-Z][a-z]{3})?(?:-[A-Z]{2}|-[0-9]{3})?$/u.test(input)) {
    throw new NotificationValidationError(
      "template.language must be a canonical language tag",
    );
  }
  return input;
}

function sanitizeCss(input: string): string {
  const css = requireText(input, "template.css", 32 * 1_024, {
    allowEmpty: true,
    allowNewlines: true,
  });
  const stripped = css.replaceAll(/\/\*[\s\S]*?\*\//gu, "");
  if (
    /@|\\|url\s*\(|expression\s*\(|javascript\s*:|data\s*:|behavior\s*:|-moz-binding|[<>]/iu.test(
      stripped,
    )
  ) {
    throw new NotificationValidationError(
      "template.css contains an unsafe construct",
    );
  }
  for (const declarationBlock of stripped.matchAll(
    /\x7b([^\x7b\x7d]*)\x7d/gu,
  )) {
    const declarations = declarationBlock[1] ?? "";
    for (const declaration of declarations.split(";")) {
      if (declaration.trim() === "") continue;
      const separator = declaration.indexOf(":");
      const property = declaration.slice(0, separator).trim().toLowerCase();
      const value = declaration.slice(separator + 1).trim();
      if (
        separator <= 0 ||
        !allowedCssProperties.includes(property) ||
        value.length === 0 ||
        /[{}]/u.test(value)
      ) {
        throw new NotificationValidationError(
          "template.css contains an unsupported declaration",
        );
      }
    }
  }
  const withoutBlocks = stripped
    .replaceAll(/\x7b[^\x7b\x7d]*\x7d/gu, "")
    .trim();
  if (/[{}]/u.test(withoutBlocks)) {
    throw new NotificationValidationError("template.css is malformed");
  }
  return stripped.trim();
}

function sanitizeRenderedHtml(input: string, allowStyles: boolean): string {
  return sanitizeHtml(input, {
    allowedTags,
    allowedAttributes: {
      a: ["href", "title"],
      td: ["colspan", "rowspan", ...(allowStyles ? ["style"] : [])],
      th: ["colspan", "rowspan", ...(allowStyles ? ["style"] : [])],
      "*": allowStyles ? ["style"] : ["class", "id"],
    },
    allowedSchemes: ["https", "mailto"],
    allowProtocolRelative: false,
    allowedStyles: allowStyles
      ? {
          "*": Object.fromEntries(
            allowedCssProperties.map((property) => [
              property,
              [
                /^(?!.*(?:\\|url|expression|javascript|data\s*:))[\s\S]{1,256}$/iu,
              ],
            ]),
          ),
        }
      : undefined,
    disallowedTagsMode: "discard",
    enforceHtmlBoundary: true,
    parser: { lowerCaseAttributeNames: true, lowerCaseTags: true },
  });
}

function htmlToPlainText(input: string): string {
  const withBoundaries = input
    .replaceAll(/<br\s*\/?>/giu, "\n")
    .replaceAll(
      /<\/\s*(?:blockquote|div|h[1-6]|li|ol|p|pre|table|tr|ul)\s*>/giu,
      "\n",
    )
    .replaceAll(/<\/\s*(?:td|th)\s*>/giu, "\t");
  return (
    sanitizeHtml(withBoundaries, {
      allowedTags: [],
      allowedAttributes: {},
      textFilter: (text) => text,
    })
      // Decode one sanitizer-escaped layer in a single pass: replacing &amp;
      // first would incorrectly decode literal text such as "&amp;lt;" twice.
      .replaceAll(/&(?:nbsp|amp|lt|gt|quot|#39);/gu, (entity) => {
        switch (entity) {
          case "&nbsp;":
            return " ";
          case "&amp;":
            return "&";
          case "&lt;":
            return "<";
          case "&gt;":
            return ">";
          case "&quot;":
            return '"';
          case "&#39;":
            return "'";
          default:
            return entity;
        }
      })
      .replaceAll(/[ \t]+\n/gu, "\n")
      .replaceAll(/\n[ \t]+/gu, "\n")
      .replaceAll(/\n{3,}/gu, "\n\n")
      .trim()
  );
}

function escapeHtml(input: string): string {
  return input
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function assertOutputSize(value: string, maximum: number, field: string): void {
  if (Buffer.byteLength(value) > maximum) {
    throw new NotificationRenderError(`${field} output exceeds its size limit`);
  }
}

function checkDeadline(state: RenderState): void {
  if (performance.now() > state.deadline) {
    throw new NotificationRenderError(
      "template rendering exceeded its deadline",
    );
  }
}
