import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const contractPath = resolve(
  repositoryRoot,
  "services/api/internal/contract/openapi.json",
);
const sdkPath = resolve(
  repositoryRoot,
  "packages/contracts/generated/typescript/sdk.gen.ts",
);

const contract = JSON.parse(readFileSync(contractPath, "utf8"));
const suppressedAuthOperations = [];
const supportedBrowserCookieSecurity = new Set([
  JSON.stringify([{ federatedContinuationCookie: [] }]),
  JSON.stringify([{ logoutContinuationCookie: [] }]),
]);
for (const pathItem of Object.values(contract.paths ?? {})) {
  for (const operation of Object.values(pathItem ?? {})) {
    const mode = operation?.["x-periapsis-generated-auth"];
    if (mode !== "explicit" && mode !== "browser-cookie") continue;
    if (
      typeof operation.operationId !== "string" ||
      operation.operationId === ""
    ) {
      throw new Error(
        "explicit generated auth operation is missing operationId",
      );
    }
    if (
      mode === "explicit" &&
      (!Array.isArray(operation.security) || operation.security.length < 2)
    ) {
      throw new Error(
        `${operation.operationId} must declare mutually exclusive security alternatives`,
      );
    }
    if (
      mode === "browser-cookie" &&
      !supportedBrowserCookieSecurity.has(JSON.stringify(operation.security))
    ) {
      throw new Error(
        `${operation.operationId} must declare exactly one supported browser-continuation cookie`,
      );
    }
    suppressedAuthOperations.push(operation.operationId);
  }
}
if (suppressedAuthOperations.length === 0) {
  throw new Error("no generated auth suppression operations were declared");
}

let sdk = readFileSync(sdkPath, "utf8");
for (const operationId of suppressedAuthOperations) {
  sdk = removeGeneratedSecurity(sdk, operationId);
}
writeFileSync(sdkPath, sdk, "utf8");

function removeGeneratedSecurity(source, operationId) {
  const declaration = `export const ${operationId} =`;
  const declarationStart = source.indexOf(declaration);
  if (
    declarationStart < 0 ||
    source.indexOf(declaration, declarationStart + 1) >= 0
  ) {
    throw new Error(
      `${operationId} must have exactly one generated declaration`,
    );
  }
  const operationEnd = source.indexOf("\n});", declarationStart);
  if (operationEnd < 0) {
    throw new Error(`${operationId} generated declaration is not terminated`);
  }
  const securityLabel = source.indexOf("security:", declarationStart);
  if (securityLabel < 0 || securityLabel >= operationEnd) {
    throw new Error(
      `${operationId} generated declaration has no security field`,
    );
  }
  const propertyStart = source.lastIndexOf("\n", securityLabel) + 1;
  const arrayStart = source.indexOf("[", securityLabel);
  if (arrayStart < 0 || arrayStart >= operationEnd) {
    throw new Error(`${operationId} generated security field is not an array`);
  }
  const arrayEnd = matchingArrayEnd(source, arrayStart, operationEnd);
  let propertyEnd = arrayEnd + 1;
  if (source[propertyEnd] !== ",") {
    throw new Error(
      `${operationId} generated security field has no trailing comma`,
    );
  }
  propertyEnd += 1;
  if (source.startsWith("\r\n", propertyEnd)) propertyEnd += 2;
  else if (source[propertyEnd] === "\n") propertyEnd += 1;
  else
    throw new Error(
      `${operationId} generated security field has no line ending`,
    );
  return source.slice(0, propertyStart) + source.slice(propertyEnd);
}

function matchingArrayEnd(source, start, limit) {
  let depth = 0;
  let quote = "";
  let escaped = false;
  for (let index = start; index < limit; index += 1) {
    const character = source[index];
    if (quote !== "") {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      continue;
    }
    if (character === "'" || character === '"' || character === "`") {
      quote = character;
    } else if (character === "[") {
      depth += 1;
    } else if (character === "]") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  throw new Error("generated security array is not closed");
}
