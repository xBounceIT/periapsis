import assert from "node:assert/strict";
import { verifyPortableJavaScriptArtifact } from "./portable-database-artifact.mjs";

try {
  assert.equal(process.argv.length, 3, "Expected the deployed notifier root");
  const result = verifyPortableJavaScriptArtifact(process.argv[2]);
  process.stdout.write(
    `${JSON.stringify({ portableNotifierArtifact: true, ...result })}\n`,
  );
} catch {
  process.stderr.write("Notifier artifact portability verification failed.\n");
  process.exitCode = 1;
}
