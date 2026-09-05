import type {
  DfirAttachmentUploadRequest,
  DfirPreparedUpload,
} from "@periapsis/contracts";

export const singlePutMaximumBytes = 5_000_000_000;

export type AttachmentUploadIntent = Omit<
  DfirAttachmentUploadRequest,
  "contentType" | "originalFilename" | "sizeBytes"
>;

export function buildAttachmentUploadRequest(
  intent: AttachmentUploadIntent,
  file: File,
): DfirAttachmentUploadRequest {
  if (
    !Number.isSafeInteger(file.size) ||
    file.size < 1 ||
    file.size > singlePutMaximumBytes
  ) {
    throw new Error("The file size is outside the single-upload limit.");
  }
  if (
    file.name.length < 1 ||
    file.name.length > 1_024 ||
    hasForbiddenFilenameCharacter(file.name)
  ) {
    throw new Error("The file name is invalid.");
  }
  const contentType = file.type || "application/octet-stream";
  if (contentType.length < 3 || contentType.length > 512) {
    throw new Error("The file content type is invalid.");
  }
  return {
    ...intent,
    originalFilename: file.name,
    sizeBytes: file.size,
    contentType,
  };
}

function hasForbiddenFilenameCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (
      value[index] === "/" ||
      value[index] === "\\" ||
      codeUnit <= 0x1f ||
      codeUnit === 0x7f
    ) {
      return true;
    }
  }
  return false;
}

// Browsers calculate Content-Length from the File body and forbid scripts from
// setting it. Validate the signed invariant, then omit only that header from
// the Fetch headers so the user agent emits the exact same value.
export function browserUploadHeaders(
  prepared: DfirPreparedUpload,
  file: File,
): Headers {
  if (prepared.method !== "PUT") {
    throw new Error("The upload capability is invalid.");
  }
  const expected = String(file.size);
  const result = new Headers();
  const seen = new Set<string>();
  let contentLengthBound = false;
  let metadataBound = false;
  let declaredMimeBound = false;
  let createOnlyBound = false;
  const declaredMime = file.type || "application/octet-stream";
  for (const header of prepared.headers) {
    const name = header.name.toLowerCase();
    if (seen.has(name)) throw new Error("The upload capability is ambiguous.");
    seen.add(name);
    if (name === "content-length") {
      if (header.value !== expected)
        throw new Error("The upload capability size does not match the file.");
      contentLengthBound = true;
      continue;
    }
    if (name === "x-amz-meta-periapsis-expected-size") {
      if (header.value !== expected)
        throw new Error("The upload capability size does not match the file.");
      metadataBound = true;
    }
    if (name === "x-amz-meta-periapsis-declared-mime") {
      if (header.value !== declaredMime)
        throw new Error(
          "The upload capability content type does not match the file.",
        );
      declaredMimeBound = true;
    }
    if (name === "if-none-match") {
      if (header.value !== "*")
        throw new Error("The upload capability is not create-only.");
      createOnlyBound = true;
    }
    result.set(header.name, header.value);
  }
  if (
    !contentLengthBound ||
    !metadataBound ||
    !declaredMimeBound ||
    !createOnlyBound
  ) {
    throw new Error("The upload capability is missing a required binding.");
  }
  return result;
}
