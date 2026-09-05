import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { relative, resolve } from "node:path";

export function inventory(root, targets) {
  const files = targets.flatMap((target) =>
    collectFiles(resolve(root, target)),
  );
  return new Map(
    files
      .toSorted()
      .map((file) => [
        relative(root, file).replaceAll("\\", "/"),
        createHash("sha256").update(readFileSync(file)).digest("hex"),
      ]),
  );
}

export function changedFiles(before, after) {
  const paths = new Set([...before.keys(), ...after.keys()]);
  return [...paths]
    .filter((path) => before.get(path) !== after.get(path))
    .toSorted();
}

function collectFiles(path) {
  if (!existsSync(path)) {
    return [];
  }
  if (!statSync(path).isDirectory()) {
    return [path];
  }
  return readdirSync(path, { withFileTypes: true }).flatMap((entry) => {
    const child = resolve(path, entry.name);
    return entry.isDirectory() ? collectFiles(child) : [child];
  });
}
