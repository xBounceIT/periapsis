export const mfaSecurityRouteDescriptor = {
  label: "Security",
  path: "/account/security",
  requiresActiveTenant: true,
} as const;

export type MfaDeviceKind = "passkey" | "totp";
export type MfaDeviceStatus = "active" | "clone_suspected" | "revoked";

export interface MfaDeviceView {
  readonly backedUp: boolean;
  readonly backupEligible: boolean;
  readonly createdAt: string;
  readonly discoverable: boolean;
  readonly displayName: string;
  readonly id: string;
  readonly kind: MfaDeviceKind;
  readonly lastUsedAt?: string;
  readonly revokedAt?: string;
  readonly status: MfaDeviceStatus;
  readonly transports: readonly string[];
  readonly version: number;
}

export interface MfaDevicePageView {
  readonly items: readonly MfaDeviceView[];
  readonly nextCursor?: string;
}

export interface MfaDeviceMutationView {
  readonly currentSessionRevoked: boolean;
  readonly device: MfaDeviceView;
}

export const mfaDeviceEtag = (device: MfaDeviceView): string =>
  `"v${device.version}"`;
