import { constants } from "node:fs";
import { open, realpath, stat } from "node:fs/promises";
import { resolve, sep } from "node:path";

import { NotificationValidationError } from "./errors.js";
import { requireKey } from "./validation.js";

const maximumSecretBytes = 64 * 1_024;

// Standalone bounded file reader retained for deployment-owned bootstrap
// material. Notification provider secrets are never resolved by logical file
// reference; they arrive as database envelopes and are decrypted by the
// notification keyring.
export class FileSecretResolver {
  readonly #root: string;

  private constructor(root: string) {
    this.#root = root;
  }

  static async create(directory: string): Promise<FileSecretResolver> {
    const root = await realpath(resolve(directory));
    const details = await stat(root);
    if (!details.isDirectory()) {
      throw new NotificationValidationError(
        "SMTP secret root must be a directory",
      );
    }
    return new FileSecretResolver(root);
  }

  async read(reference: string, signal: AbortSignal): Promise<Uint8Array> {
    requireKey(reference, "secret reference", 255);
    if (signal.aborted) throw signal.reason;
    const target = await realpath(resolve(this.#root, reference));
    if (!isInside(this.#root, target)) {
      throw new NotificationValidationError(
        "secret reference escaped its configured root",
      );
    }
    return readBoundedSecretFile(target, signal);
  }
}

export async function readBoundedSecretFile(
  path: string,
  signal: AbortSignal,
  maximumBytes = maximumSecretBytes,
): Promise<Uint8Array> {
  if (
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    maximumBytes > maximumSecretBytes
  ) {
    throw new NotificationValidationError("secret size limit is invalid");
  }
  if (signal.aborted) throw signal.reason;
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const handle = await open(resolve(path), constants.O_RDONLY | noFollow);
  try {
    const details = await handle.stat();
    if (!details.isFile() || details.size < 1 || details.size > maximumBytes) {
      throw new NotificationValidationError(
        "secret file is empty, oversized, or not regular",
      );
    }
    const buffer = await handle.readFile({ signal });
    if (buffer.byteLength !== details.size) {
      buffer.fill(0);
      throw new NotificationValidationError(
        "secret file changed while it was being read",
      );
    }
    const endsWithCrLf =
      buffer.byteLength >= 2 &&
      buffer[buffer.byteLength - 2] === 0x0d &&
      buffer[buffer.byteLength - 1] === 0x0a;
    const endsWithLf = buffer[buffer.byteLength - 1] === 0x0a;
    const length = endsWithCrLf
      ? buffer.byteLength - 2
      : endsWithLf
        ? buffer.byteLength - 1
        : buffer.byteLength;
    if (length === 0 || buffer.subarray(0, length).includes(0)) {
      buffer.fill(0);
      throw new NotificationValidationError("secret file content is invalid");
    }
    const result = new Uint8Array(buffer.subarray(0, length));
    buffer.fill(0);
    return result;
  } finally {
    await handle.close();
  }
}

function isInside(root: string, target: string): boolean {
  const comparisonRoot =
    process.platform === "win32" ? root.toLowerCase() : root;
  const comparisonTarget =
    process.platform === "win32" ? target.toLowerCase() : target;
  return (
    comparisonTarget === comparisonRoot ||
    comparisonTarget.startsWith(`${comparisonRoot}${sep}`)
  );
}
