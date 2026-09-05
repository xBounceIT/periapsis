import type { DfirPreparedUpload } from "@periapsis/contracts";
import { describe, expect, it } from "vitest";

import {
  browserUploadHeaders,
  buildAttachmentUploadRequest,
} from "./upload-request";

const intent = {
  attachmentId: "018f0000-0000-7000-8000-000000000001",
  storageObjectId: "018f0000-0000-7000-8000-000000000002",
  subject: {
    kind: "case" as const,
    id: "018f0000-0000-7000-8000-000000000003",
  },
  classification: "internal" as const,
  requestedVisibility: "private" as const,
};

const preparedUpload = (
  headers: DfirPreparedUpload["headers"],
): DfirPreparedUpload => ({
  attachment: {
    id: intent.attachmentId,
    tenantId: "018f0000-0000-7000-8000-000000000004",
    subject: intent.subject,
    storageObjectId: intent.storageObjectId,
    originalFilename: "capture.bin",
    visibility: "private",
    uploadedBy: "018f0000-0000-7000-8000-000000000005",
    uploadedAt: "2026-08-25T18:00:00Z",
    scanState: "pending_upload",
  },
  method: "PUT",
  uploadUrl: "https://storage.invalid/capability",
  headers,
  expiresAt: "2026-08-25T18:15:00Z",
});

describe("DFIR exact-size upload", () => {
  it("binds the API request to File.size", () => {
    const file = new File(["forensic payload"], "capture.bin", {
      type: "application/octet-stream",
    });
    const request = buildAttachmentUploadRequest(intent, file);

    expect(request).toMatchObject({
      originalFilename: "capture.bin",
      contentType: "application/octet-stream",
      sizeBytes: file.size,
    });
    expect("maximumBytes" in request).toBe(false);
  });

  it.each(["missing", "oversized", "truncated", "duplicate"])(
    "rejects a %s signed size boundary",
    (variant) => {
      const file = new File(["payload"], "capture.bin", {
        type: "application/octet-stream",
      });
      const headers = [
        { name: "Content-Length", value: String(file.size) },
        { name: "If-None-Match", value: "*" },
        {
          name: "X-Amz-Meta-Periapsis-Expected-Size",
          value: String(file.size),
        },
        {
          name: "X-Amz-Meta-Periapsis-Declared-Mime",
          value: file.type,
        },
      ];
      if (variant === "missing") headers.shift();
      if (variant === "oversized") headers[0]!.value = String(file.size + 1);
      if (variant === "truncated") headers[0]!.value = String(file.size - 1);
      if (variant === "duplicate")
        headers.push({ name: "content-length", value: String(file.size) });
      const prepared = preparedUpload(headers);

      expect(() => browserUploadHeaders(prepared, file)).toThrow();
    },
  );

  it.each(["missing", "wrong", "duplicate"])(
    "rejects a %s create-only condition",
    (variant) => {
      const file = new File(["payload"], "capture.bin", {
        type: "application/octet-stream",
      });
      const headers = [
        { name: "Content-Length", value: String(file.size) },
        { name: "If-None-Match", value: "*" },
        {
          name: "X-Amz-Meta-Periapsis-Expected-Size",
          value: String(file.size),
        },
        {
          name: "X-Amz-Meta-Periapsis-Declared-Mime",
          value: file.type,
        },
      ];
      if (variant === "missing") headers.splice(1, 1);
      if (variant === "wrong") headers[1]!.value = '"stale-etag"';
      if (variant === "duplicate")
        headers.push({ name: "if-none-match", value: "*" });

      expect(() =>
        browserUploadHeaders(preparedUpload(headers), file),
      ).toThrow();
    },
  );

  it("lets the browser derive Content-Length after exact validation", () => {
    const file = new File(["payload"], "capture.bin", {
      type: "application/octet-stream",
    });
    const prepared = preparedUpload([
      { name: "Content-Length", value: String(file.size) },
      { name: "Content-Type", value: file.type },
      { name: "If-None-Match", value: "*" },
      {
        name: "X-Amz-Meta-Periapsis-Expected-Size",
        value: String(file.size),
      },
      {
        name: "X-Amz-Meta-Periapsis-Declared-Mime",
        value: file.type,
      },
    ]);

    const headers = browserUploadHeaders(prepared, file);
    expect(headers.has("Content-Length")).toBe(false);
    expect(headers.get("Content-Type")).toBe(file.type);
    expect(headers.get("If-None-Match")).toBe("*");
    expect(headers.get("X-Amz-Meta-Periapsis-Declared-Mime")).toBe(file.type);
  });

  it.each(["missing", "wrong", "duplicate"])(
    "rejects a %s signed declared MIME binding",
    (variant) => {
      const file = new File(["payload"], "capture.txt", {
        type: "text/plain",
      });
      const headers = [
        { name: "Content-Length", value: String(file.size) },
        { name: "If-None-Match", value: "*" },
        {
          name: "X-Amz-Meta-Periapsis-Expected-Size",
          value: String(file.size),
        },
        { name: "X-Amz-Meta-Periapsis-Declared-Mime", value: file.type },
      ];
      if (variant === "missing") headers.pop();
      if (variant === "wrong") headers.at(-1)!.value = "application/pdf";
      if (variant === "duplicate")
        headers.push({
          name: "x-amz-meta-periapsis-declared-mime",
          value: file.type,
        });

      expect(() =>
        browserUploadHeaders(preparedUpload(headers), file),
      ).toThrow();
    },
  );
});
