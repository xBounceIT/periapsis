import { readFile } from "node:fs/promises";
import { join } from "node:path";

// Text-only source contracts inspect both fragments. This is not a Compose
// merge implementation and its output must never be deployed as YAML. The real
// CLI independently checks include, interpolation and the merged model.
export async function readDevelopmentComposeSources(root) {
  const entry = await readFile(
    join(root, "deploy/compose/compose.yaml"),
    "utf8",
  );
  const lines = entry
    .replaceAll("\r\n", "\n")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
  if (
    lines.join("\n") !==
    "name: periapsis\ninclude:\n- path: [./compose.base.yaml, ./compose.tls.yaml]"
  ) {
    throw new Error(
      "The default Compose entry must load only base and local TLS fragments",
    );
  }
  const fragments = await Promise.all(
    ["deploy/compose/compose.base.yaml", "deploy/compose/compose.tls.yaml"].map(
      (path) => readFile(join(root, path), "utf8"),
    ),
  );
  return fragments.join("\n");
}

export async function readDevelopmentCaddySources(root) {
  return (
    await Promise.all(
      [
        "deploy/compose/edge/Caddyfile",
        "deploy/compose/edge/storage-cors.caddy",
      ].map((path) => readFile(join(root, path), "utf8")),
    )
  ).join("\n");
}
