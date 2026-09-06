import assert from "node:assert/strict";
import {
  closeSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  readSync,
  realpathSync,
} from "node:fs";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";

// This reviewed export has no architecture-specific runtime dependencies. Any
// dependency change requires explicit portability review before native building.
const productionPackages = new Map([
  ["@opentelemetry/api", "1.9.1"],
  ["drizzle-orm", "0.45.2"],
  ["postgres", "3.4.9"],
]);
const nativeExtension =
  /\.(?:node|so(?:\.\d+)*|dll|dylib|exe|o|obj|a|lib|wasm|zip|gz|tgz|tar|xz|bz2|zst)$/iu;
const binaryMagic = new Set([
  "7f454c46", // ELF, including extensionless executables/shared objects.
  "feedface",
  "cefaedfe",
  "feedfacf",
  "cffaedfe", // Mach-O.
  "cafebabe",
  "bebafeca",
  "cafebabf",
  "bfbafeca", // Universal Mach-O.
  "0061736d", // WebAssembly is not part of this JavaScript-only export.
  "4243c0de", // LLVM bitcode.
  "504b0304",
  "504b0506",
  "504b0708", // ZIP archives must not conceal native files.
  "28b52ffd", // Zstandard.
]);

function confined(root, target) {
  const path = relative(root, target);
  return path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path);
}

function inspectFile(path) {
  const descriptor = openSync(path, "r");
  const header = Buffer.alloc(8);
  let length;
  try {
    length = readSync(descriptor, header, 0, header.length, 0);
  } finally {
    closeSync(descriptor);
  }
  assert.ok(
    !binaryMagic.has(header.subarray(0, 4).toString("hex")) &&
      !(length >= 2 && header[0] === 0x4d && header[1] === 0x5a) &&
      !(length >= 2 && header[0] === 0x1f && header[1] === 0x8b) &&
      header.subarray(0, 3).toString("ascii") !== "BZh" &&
      header.subarray(0, 6).toString("hex") !== "fd377a585a00" &&
      header.toString("ascii") !== "!<arch>\n",
    "Native or opaque binary payload is forbidden",
  );
}

function inspectTree(input, { dependencies }) {
  const root = resolve(input);
  assert.ok(
    lstatSync(root).isDirectory(),
    "Artifact root must be a real directory",
  );
  assert.equal(
    realpathSync(root),
    root,
    "Artifact root must not traverse symlinks",
  );
  const pending = [root];
  const found = new Map();
  const packageRoots = [];
  const regularFiles = [];
  let files = 0;
  let links = 0;
  while (pending.length > 0) {
    const path = pending.pop();
    const details = lstatSync(path);
    if (!details.isDirectory()) {
      assert.ok(
        !nativeExtension.test(path),
        "Native artifact extension is forbidden",
      );
    }
    if (details.isSymbolicLink()) {
      const target = readlinkSync(path);
      assert.ok(!isAbsolute(target), "Absolute artifact links are forbidden");
      assert.ok(
        confined(root, realpathSync(path)),
        "Artifact link escapes its root",
      );
      links += 1;
    } else if (details.isDirectory()) {
      pending.push(...readdirSync(path).map((name) => join(path, name)));
    } else {
      assert.ok(details.isFile(), "Special artifact files are forbidden");
      inspectFile(path);
      regularFiles.push(path);
      files += 1;
      if (dependencies && basename(path) === "package.json") {
        const manifest = JSON.parse(readFileSync(path, "utf8"));
        for (const key of ["os", "cpu", "libc", "gypfile", "bin"]) {
          assert.ok(
            !(key in manifest),
            "Platform-specific production package metadata",
          );
        }
        // The pinned postgres/types package.json contains development metadata,
        // not an installed dependency. It must still live inside a reviewed package.
        if (manifest.name === undefined) continue;
        assert.ok(
          productionPackages.has(manifest.name),
          "Unreviewed production dependency",
        );
        assert.equal(
          productionPackages.get(manifest.name),
          manifest.version,
          "Unreviewed production dependency or version",
        );
        assert.ok(
          !found.has(manifest.name),
          "Duplicate installed production package",
        );
        assert.ok(
          dirname(path)
            .replaceAll("\\", "/")
            .endsWith(`/node_modules/${manifest.name}`),
          "Unexpected installed package location",
        );
        packageRoots.push(dirname(path));
        found.set(manifest.name, manifest.version);
      }
    }
  }
  assert.ok(files > 0, "Artifact must contain actual files");
  if (dependencies) {
    assert.deepEqual(
      [...found].toSorted(),
      [...productionPackages].toSorted(),
      "Expected exactly the three reviewed production packages",
    );
    const metadata = new Set([
      ".modules.yaml",
      ".package-map.json",
      ".pnpm/lock.yaml",
    ]);
    for (const path of regularFiles) {
      assert.ok(
        metadata.has(relative(root, path).replaceAll("\\", "/")) ||
          packageRoots.some((packageRoot) => confined(packageRoot, path)),
        "Unowned production dependency file",
      );
    }
  }
  return { files, links };
}

export function verifyPortableDatabaseArtifact(modulesRoot, compiledRoot) {
  return {
    dependencies: inspectTree(modulesRoot, { dependencies: true }),
    compiled: inspectTree(compiledRoot, { dependencies: false }),
  };
}

if (import.meta.main) {
  try {
    assert.equal(
      process.argv.length,
      4,
      "Expected production dependencies and compiled output roots",
    );
    const result = verifyPortableDatabaseArtifact(
      process.argv[2],
      process.argv[3],
    );
    process.stdout.write(
      `${JSON.stringify({ portableDatabaseArtifact: true, ...result })}\n`,
    );
  } catch {
    process.stderr.write(
      "Database artifact portability verification failed.\n",
    );
    process.exitCode = 1;
  }
}
