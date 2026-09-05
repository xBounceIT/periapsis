import {
  isPlatformAuditReasonHeader,
  isPlatformHttpsUri,
  isPlatformUnicodeScalarText,
  platformUtf8ByteLength,
} from "../lib/platform-auth-provider-validation";

const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export interface PlatformIdentityAccountPrelinkDraft {
  readonly auditReason: string;
  readonly subject: string;
  readonly userId: string;
}

export interface PlatformIdentityAccountPrelinkConfirmation {
  readonly subject: string;
  readonly userId: string;
}

export function validatePlatformIdentityAccountPrelinkIssuer(
  issuer: string,
): readonly string[] {
  return isPlatformHttpsUri(issuer, false, 2048)
    ? []
    : [
        "Enter the exact canonical HTTPS OIDC issuer without credentials, query parameters, or a fragment.",
      ];
}

export function validatePlatformIdentityAccountPrelinkDraft(
  draft: PlatformIdentityAccountPrelinkDraft,
): readonly string[] {
  const errors: string[] = [];
  if (!uuidV7Pattern.test(draft.userId)) {
    errors.push("Enter the exact UUIDv7 of an existing platform user.");
  }
  if (
    draft.subject === "" ||
    !isPlatformUnicodeScalarText(draft.subject) ||
    platformUtf8ByteLength(draft.subject) > 1024 ||
    hasForbiddenSubjectCodePoint(draft.subject)
  ) {
    errors.push(
      "Enter the exact OIDC subject using 1–1024 UTF-8 bytes without control or direction characters.",
    );
  }
  if (!isPlatformAuditReasonHeader(draft.auditReason)) {
    errors.push(
      "Enter a visible ASCII audit reason without commas, leading or trailing spaces, secrets, claims, or customer data.",
    );
  }
  return errors;
}

export function validatePlatformIdentityAccountPrelinkConfirmation(
  draft: PlatformIdentityAccountPrelinkDraft,
  confirmation: PlatformIdentityAccountPrelinkConfirmation,
): readonly string[] {
  const errors: string[] = [];
  if (confirmation.userId !== draft.userId) {
    errors.push(
      "Re-enter the exact platform user ID to confirm the authentication target.",
    );
  }
  if (confirmation.subject !== draft.subject) {
    errors.push(
      "Re-enter the exact case-sensitive OIDC subject to confirm its permanent reservation.",
    );
  }
  return errors;
}

function hasForbiddenSubjectCodePoint(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint === undefined ||
      codePoint <= 0x1f ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      codePoint === 0x061c ||
      codePoint === 0x200e ||
      codePoint === 0x200f ||
      (codePoint >= 0x202a && codePoint <= 0x202e) ||
      (codePoint >= 0x2066 && codePoint <= 0x2069)
    ) {
      return true;
    }
  }
  return false;
}

export function validatePlatformIdentityAccountRetirement(
  accountId: string,
  confirmation: string,
  auditReason: string,
): readonly string[] {
  const errors: string[] = [];
  if (!uuidV7Pattern.test(accountId) || confirmation !== accountId) {
    errors.push(
      "Enter the exact account ID to confirm irreversible retirement.",
    );
  }
  if (!isPlatformAuditReasonHeader(auditReason)) {
    errors.push(
      "Enter a visible ASCII audit reason without commas, leading or trailing spaces, secrets, claims, or customer data.",
    );
  }
  return errors;
}
