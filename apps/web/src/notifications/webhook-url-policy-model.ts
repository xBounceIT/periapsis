import type {
  WebhookUrlPolicy,
  WebhookUrlPolicyEffect,
  WebhookUrlPolicyMatch,
  WebhookUrlPolicyRuleWrite,
} from "@periapsis/contracts";

export interface WebhookUrlPolicyRuleDraft {
  effect: WebhookUrlPolicyEffect;
  hostname: string;
  match: WebhookUrlPolicyMatch;
  port: string;
}

export interface WebhookUrlPolicyPreview {
  allowed: boolean;
  reason: "allowed_by_rule" | "denied_by_rule" | "default_deny" | "invalid";
  ruleIndex?: number;
}

const canonicalHostnamePattern =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/u;
const safeURLPattern =
  /^https:\/\/[A-Za-z0-9.-]+(?::[1-9][0-9]{0,4})?(?:\/[A-Za-z0-9\-._~!$&'()*+,;=:@/]*)?(?:\?[A-Za-z0-9\-._~!$&'()*+,;=:@/?]*)?$/u;

export function webhookUrlPolicyDraft(
  policy: WebhookUrlPolicy | null,
): WebhookUrlPolicyRuleDraft[] {
  if (policy === null) {
    return [{ effect: "allow", match: "exact", hostname: "", port: "443" }];
  }
  return policy.rules.map((rule) => ({
    effect: rule.effect,
    match: rule.match,
    hostname: rule.hostname,
    port: String(rule.port),
  }));
}

export function prepareWebhookUrlPolicyRules(
  drafts: readonly WebhookUrlPolicyRuleDraft[],
): WebhookUrlPolicyRuleWrite[] {
  if (drafts.length > 256) {
    throw new TypeError("A webhook URL policy can contain at most 256 rules.");
  }
  const records = new Set<string>();
  const rules = drafts.map((draft) => {
    const port = Number(draft.port);
    if (
      (draft.effect !== "allow" && draft.effect !== "deny") ||
      (draft.match !== "exact" && draft.match !== "subdomains") ||
      draft.hostname.length === 0 ||
      draft.hostname.length > 253 ||
      draft.hostname !== draft.hostname.trim() ||
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65_535
    ) {
      throw new TypeError("Every webhook URL policy rule must be complete.");
    }
    const record = `${draft.effect}\0${draft.match}\0${draft.hostname.toLowerCase()}\0${String(port)}`;
    if (records.has(record)) {
      throw new TypeError("Webhook URL policy rules must be unique.");
    }
    records.add(record);
    return {
      effect: draft.effect,
      match: draft.match,
      hostname: draft.hostname,
      port,
    } satisfies WebhookUrlPolicyRuleWrite;
  });
  return rules;
}

export function previewWebhookUrlPolicy(
  drafts: readonly WebhookUrlPolicyRuleDraft[],
  endpointInput: string,
): WebhookUrlPolicyPreview {
  const endpoint = previewEndpoint(endpointInput);
  if (endpoint === null) return { allowed: false, reason: "invalid" };
  let rules: WebhookUrlPolicyRuleWrite[];
  try {
    rules = prepareWebhookUrlPolicyRules(drafts);
  } catch {
    return { allowed: false, reason: "invalid" };
  }
  for (const effect of ["deny", "allow"] as const) {
    const index = rules.findIndex(
      (rule) =>
        rule.effect === effect &&
        rule.port === endpoint.port &&
        (rule.match === "exact"
          ? endpoint.hostname === rule.hostname.toLowerCase()
          : endpoint.hostname !== rule.hostname.toLowerCase() &&
            endpoint.hostname.endsWith(`.${rule.hostname.toLowerCase()}`)),
    );
    if (index >= 0) {
      return {
        allowed: effect === "allow",
        reason: effect === "allow" ? "allowed_by_rule" : "denied_by_rule",
        ruleIndex: index,
      };
    }
  }
  return { allowed: false, reason: "default_deny" };
}

function previewEndpoint(
  input: string,
): Readonly<{ hostname: string; port: number }> | null {
  if (
    input.length === 0 ||
    input.length > 2048 ||
    input !== input.trim() ||
    input !== input.normalize("NFC") ||
    input.includes("%") ||
    input.includes("\\") ||
    input.includes("#") ||
    hasDotPathSegment(input) ||
    !safeURLPattern.test(input)
  ) {
    return null;
  }
  try {
    const parsed = new URL(input);
    const hostname = parsed.hostname.toLowerCase();
    const port = parsed.port === "" ? 443 : Number(parsed.port);
    if (
      parsed.protocol !== "https:" ||
      parsed.username !== "" ||
      parsed.password !== "" ||
      !canonicalHostnamePattern.test(hostname) ||
      hostname.endsWith(".localhost") ||
      looksLikeIPAddress(hostname) ||
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65_535
    ) {
      return null;
    }
    return { hostname, port };
  } catch {
    return null;
  }
}

function hasDotPathSegment(input: string): boolean {
  const authorityStart = input.indexOf("://") + 3;
  const pathStart = input.indexOf("/", authorityStart);
  if (pathStart < 0) return false;
  const queryStart = input.indexOf("?", pathStart);
  const rawPath = input.slice(
    pathStart,
    queryStart < 0 ? input.length : queryStart,
  );
  return rawPath
    .split("/")
    .some((segment) => segment === "." || segment === "..");
}

function looksLikeIPAddress(hostname: string): boolean {
  if (hostname.includes(":")) return true;
  const labels = hostname.split(".");
  const last = labels.at(-1);
  return last === undefined || /^(?:[0-9]+|0x[0-9a-f]+)$/iu.test(last);
}
