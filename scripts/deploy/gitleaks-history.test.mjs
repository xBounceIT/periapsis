import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { inflateRawSync } from "node:zlib";

const root = fileURLToPath(new URL("../../", import.meta.url));
const reviewedCommit = "3d452510f185151f60263d004fe16a7d539f7655";
const reviewedIgnoreSha256 =
  "b35a9edb198c64780f2fed4d2142a5bef1710a22dd3acba988642863dca7f3d7";
const ignorePath = join(root, ".gitleaksignore");
const ignoreSource = (await readFile(ignorePath, "utf8")).replaceAll(
  "\r\n",
  "\n",
);
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function parseReview(source) {
  const result = [];
  let evidence;
  for (const line of source.split("\n")) {
    if (line.startsWith("# reviewed-lines:")) {
      const match =
        /^# reviewed-lines: ([1-9]\d*)-([1-9]\d*); sha256: ([a-f0-9]{64})$/u.exec(
          line,
        );
      assert.ok(match, "Invalid historical evidence comment");
      evidence = {
        start: Number(match[1]),
        end: Number(match[2]),
        sha256: match[3],
      };
      continue;
    }
    if (line === "" || line.startsWith("#")) continue;
    const match =
      /^([a-f0-9]{40}):([a-zA-Z0-9_./-]+):(generic-api-key|private-key):([1-9]\d*)$/u.exec(
        line,
      );
    assert.ok(
      match,
      "Only exact commit:file:rule:line fingerprints are permitted",
    );
    const [, commit, file, rule, lineNumber] = match;
    assert.equal(
      commit,
      reviewedCommit,
      "New historical exceptions need explicit review",
    );
    assert.ok(!file.startsWith("/") && !file.split("/").includes(".."));
    assert.ok(
      evidence,
      "Every exception must pin its reviewed historical source",
    );
    assert.equal(evidence.start, Number(lineNumber));
    assert.ok(
      evidence.end >= evidence.start && evidence.end - evidence.start < 50,
    );
    result.push({ fingerprint: line, commit, file, rule, ...evidence });
    evidence = undefined;
  }
  assert.equal(
    new Set(result.map((entry) => entry.fingerprint)).size,
    result.length,
  );
  return result;
}

const entries = parseReview(ignoreSource);

function coordinates(findings) {
  return findings
    .map((finding) => `${finding.File}:${finding.RuleID}:${finding.StartLine}`)
    .toSorted();
}

// The pinned generic-api-key rule requires entropy >= 3.5 and has a stopword
// allowlist. These are its only all-hex stopwords (v8.30.1/config/gitleaks.toml).
// Qualify the ephemeral controls, never weaken or override the scanner's rule.
const genericHexStopwords = [
  "000000",
  "6fe4476ee5a1832882e326b506d14126",
  "aaaaaa",
  "dead",
  "feed",
];
const controlMinimumEntropy = 3.75;
const controlSamplingLimit = 32;

function entropy(value) {
  const counts = new Map();
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }
  return [...counts.values()].reduce((total, count) => {
    const probability = count / value.length;
    return total - probability * Math.log2(probability);
  }, 0);
}

function qualifiesGenericControl(value) {
  return (
    /^[a-f0-9]{64}$/u.test(value) &&
    entropy(value) >= controlMinimumEntropy &&
    !genericHexStopwords.some((stopword) => value.includes(stopword))
  );
}

function freshGenericControl(sample = randomBytes) {
  for (let attempt = 0; attempt < controlSamplingLimit; attempt += 1) {
    const value = sample(32).toString("hex");
    if (qualifiesGenericControl(value)) return value;
  }
  throw new Error("Unable to sample a qualified ephemeral scanner control");
}

const balancedHex = "0123456789abcdef".repeat(4);

test("generic controls reject low entropy and retain margin over the pinned 3.5 threshold", () => {
  assert.equal(entropy(balancedHex), 4);
  const thresholdHex = `${"0123".repeat(8)}${"456789ab".repeat(4)}`;
  assert.equal(entropy(thresholdHex), 3.5);
  assert.ok(!qualifiesGenericControl(thresholdHex));
  const minimumHex = `${"0123".repeat(8)}${"4567".repeat(4)}${"89abcdef".repeat(2)}`;
  assert.equal(entropy(minimumHex), controlMinimumEntropy);
  assert.ok(qualifiesGenericControl(minimumHex));
  assert.ok(qualifiesGenericControl(balancedHex));
  let samples = 0;
  assert.equal(
    freshGenericControl((size) => {
      assert.equal(size, 32);
      return Buffer.from(++samples === 1 ? thresholdHex : balancedHex, "hex");
    }),
    balancedHex,
  );
  assert.equal(samples, 2);
});

for (const stopword of genericHexStopwords) {
  test(`generic controls reject the pinned hex stopword ${stopword}`, () => {
    const candidate = `${stopword}${balancedHex.slice(stopword.length)}`;
    assert.ok(entropy(candidate) >= controlMinimumEntropy);
    assert.ok(!qualifiesGenericControl(candidate));
    let samples = 0;
    assert.equal(
      freshGenericControl(() =>
        Buffer.from(++samples === 1 ? candidate : balancedHex, "hex"),
      ),
      balancedHex,
    );
    assert.equal(samples, 2);
  });
}

test("generic control sampling fails closed after a bounded number of unsuitable samples", () => {
  let samples = 0;
  assert.throws(
    () =>
      freshGenericControl((size) => {
        samples += 1;
        return Buffer.alloc(size);
      }),
    /Unable to sample a qualified ephemeral scanner control/u,
  );
  assert.equal(samples, controlSamplingLimit);
  assert.ok(!qualifiesGenericControl(balancedHex.toUpperCase()));
  assert.ok(!qualifiesGenericControl(balancedHex.slice(1)));
});

test("historical Gitleaks review is the exact 40-fingerprint inventory for 41 findings", () => {
  assert.equal(sha256(ignoreSource), reviewedIgnoreSha256);
  assert.equal(entries.length, 40);
  assert.equal(
    entries.filter((entry) => entry.rule === "private-key").length,
    1,
  );
  assert.equal(
    entries.filter((entry) => entry.file.endsWith("api.gen.go")).length,
    3,
  );
});

for (const [name, change] of [
  [
    "commitless global exception",
    (source) => source.replace(`${reviewedCommit}:`, ""),
  ],
  ["path wildcard", (source) => source.replace("apps/web/", "apps/*/")],
  [
    "different commit",
    (source) => source.replace(reviewedCommit, "a".repeat(40)),
  ],
  [
    "unattested exception",
    (source) => source.replace(/^# reviewed-lines:.*\n/mu, ""),
  ],
  ["duplicate exception", (source) => `${source}\n${source}`],
]) {
  test(`historical review rejects a ${name}`, () => {
    assert.throws(() => parseReview(change(ignoreSource)));
  });
}

// The CI secret job must supply its checksum-verified pinned binary. Ordinary
// source-only unit runs do not claim to execute this integration gate.
const binary = process.env.PERIAPSIS_GITLEAKS_BINARY;
test(
  "Gitleaks 8.30.1 verifies historical source and still detects fresh secrets at every excepted coordinate",
  {
    skip: binary
      ? false
      : "Set PERIAPSIS_GITLEAKS_BINARY to the verified Gitleaks 8.30.1 executable",
  },
  async (t) => {
    assert.ok(
      isAbsolute(binary),
      "The verified Gitleaks binary path must be absolute",
    );
    const parent = await mkdtemp(join(tmpdir(), "periapsis-gitleaks-history-"));
    const repository = join(parent, "repository");
    const globalConfig = join(parent, "empty.gitconfig");
    await writeFile(globalConfig, "", { flag: "wx", mode: 0o600 });
    const environment = {
      ...process.env,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: globalConfig,
      GIT_AUTHOR_DATE: "2026-09-06T00:00:00Z",
      GIT_COMMITTER_DATE: "2026-09-06T00:00:00Z",
    };
    t.after(async () => {
      // Only this mkdtemp-owned directory can be removed, never a configured repo.
      const owned = relative(resolve(tmpdir()), resolve(parent));
      assert.ok(
        owned.startsWith("periapsis-gitleaks-history-") &&
          !owned.includes("..") &&
          !isAbsolute(owned),
      );
      await rm(parent, { recursive: true, force: true });
    });
    function run(command, args, cwd = root, expectedStatus = 0) {
      const result = spawnSync(command, args, {
        cwd,
        env: environment,
        encoding: "utf8",
        maxBuffer: 30_000_000,
        timeout: command === binary ? 125_000 : 30_000,
        windowsHide: true,
      });
      // Do not include raw scanner/Git output in failures: a positive control
      // deliberately contains fresh, ephemeral, non-service credential material.
      assert.ok(
        !result.error && result.signal === null,
        "Child command must finish without a timeout or signal",
      );
      assert.equal(
        result.status,
        expectedStatus,
        "Unexpected child command exit status; raw output withheld",
      );
      return result.stdout;
    }
    assert.equal(run(binary, ["version"]).trim(), "8.30.1");
    const initialHead = run("git", ["rev-parse", "HEAD"]).trim();
    const sources = new Map();
    for (const entry of entries) {
      if (!sources.has(entry.file)) {
        sources.set(
          entry.file,
          run("git", ["show", `${entry.commit}:${entry.file}`]),
        );
      }
      const excerpt = sources
        .get(entry.file)
        .split("\n")
        .slice(entry.start - 1, entry.end)
        .join("\n");
      assert.equal(
        sha256(excerpt),
        entry.sha256,
        `Historical source attestation failed: ${entry.file}:${entry.start}`,
      );
    }
    const generated = sources.get("services/api/internal/contract/api.gen.go");
    const compressed = /var swaggerSpec = \[\]string\{([\s\S]*?)\n\}/u.exec(
      generated,
    );
    assert.ok(
      compressed,
      "Historical generated source must contain the actual embedded contract",
    );
    const encoded = [...compressed[1].matchAll(/"([A-Za-z0-9+/=]+)"/gu)]
      .map((match) => match[1])
      .join("");
    const decoded = inflateRawSync(Buffer.from(encoded, "base64"), {
      maxOutputLength: 20_000_000,
    });
    const spec = JSON.parse(decoded);
    assert.equal(spec.openapi, "3.1.0");
    assert.equal(Object.keys(spec.paths).length, 360);
    assert.equal(
      sha256(decoded),
      "0343824c930de31260957c38d15fe3380ffc42fa86d98f31cb65e13fa127a49c",
    );
    for (const entry of entries.filter((candidate) =>
      candidate.file.endsWith("api.gen.go"),
    )) {
      const offset =
        generated
          .split("\n")
          .slice(0, entry.start - 1)
          .join("\n").length + 1;
      assert.ok(
        offset > compressed.index &&
          offset < compressed.index + compressed[0].length,
      );
    }

    await mkdir(repository, { mode: 0o700 });
    run("git", ["init", "--initial-branch=codex/gitleaks-test"], repository);
    run(
      "git",
      ["config", "user.name", "Periapsis scanner fixture"],
      repository,
    );
    run(
      "git",
      ["config", "user.email", "scanner-fixture@example.invalid"],
      repository,
    );
    run("git", ["config", "commit.gpgsign", "false"], repository);
    run("git", ["config", "core.autocrlf", "false"], repository);

    async function writeFreshControls(privateKeyType) {
      const files = new Map();
      for (const entry of entries) {
        let content = files.get(entry.file);
        if (!content) {
          content = [];
          files.set(entry.file, content);
        }
        while (content.length < entry.start - 1) content.push("");
        const value =
          entry.rule === "private-key"
            ? generateKeyPairSync("rsa", {
                modulusLength: 2048,
                privateKeyEncoding: { type: privateKeyType, format: "pem" },
                publicKeyEncoding: { type: "spki", format: "pem" },
              }).privateKey.trimEnd()
            : `api_key = "${freshGenericControl()}"`;
        content.splice(entry.start - 1, 1, ...value.split("\n"));
      }
      await Promise.all(
        [...files].map(async ([file, lines]) => {
          const path = join(repository, file);
          await mkdir(dirname(path), { recursive: true, mode: 0o700 });
          await writeFile(path, `${lines.join("\n")}\n`, { mode: 0o600 });
        }),
      );
    }

    let scanOrdinal = 0;
    async function scan(cwd, expectedStatus, selectedIgnore = ignorePath) {
      const report = join(parent, `scan-${++scanOrdinal}.json`);
      run(
        binary,
        [
          "git",
          ".",
          "--redact",
          "--no-banner",
          "--timeout",
          "120",
          "--log-opts=--all",
          "--report-format=json",
          `--report-path=${report}`,
          `--gitleaks-ignore-path=${selectedIgnore}`,
        ],
        cwd,
        expectedStatus,
      );
      return JSON.parse(await readFile(report, "utf8"));
    }
    const expectedCoordinates = entries
      .map((entry) => `${entry.file}:${entry.rule}:${entry.start}`)
      .toSorted();
    await writeFreshControls("pkcs8");
    run("git", ["add", "."], repository);
    run(
      "git",
      ["commit", "-m", "Create ephemeral positive scanner controls"],
      repository,
    );
    const firstCommit = run("git", ["rev-parse", "HEAD"], repository).trim();
    assert.notEqual(firstCommit, reviewedCommit);
    const firstFindings = await scan(repository, 1);
    assert.deepEqual(coordinates(firstFindings), expectedCoordinates);
    assert.ok(firstFindings.every((finding) => finding.Commit === firstCommit));

    // Prove exact fingerprints work in isolation, then replace every value at
    // the same path/rule/line in a second commit. None may inherit the exception.
    const controlIgnore = join(parent, "control.gitleaksignore");
    await writeFile(
      controlIgnore,
      `${ignoreSource}\n${firstFindings.map((finding) => finding.Fingerprint).join("\n")}\n`,
      { mode: 0o600 },
    );
    assert.deepEqual(await scan(repository, 0, controlIgnore), []);
    // Change PEM serialization too so both boundary markers appear in the new
    // Git patch. Gitleaks' zero-context diff scan cannot reconstruct a PEM whose
    // unchanged BEGIN/END markers are absent from the changed lines. This test
    // proves commit-scoped ignore behavior, not whole-file secret detection.
    await writeFreshControls("pkcs1");
    run("git", ["add", "."], repository);
    run(
      "git",
      ["commit", "-m", "Replace every control at its original coordinate"],
      repository,
    );
    const secondCommit = run("git", ["rev-parse", "HEAD"], repository).trim();
    assert.notEqual(secondCommit, firstCommit);
    const secondFindings = await scan(repository, 1, controlIgnore);
    assert.deepEqual(coordinates(secondFindings), expectedCoordinates);
    assert.ok(
      secondFindings.every((finding) => finding.Commit === secondCommit),
    );

    assert.deepEqual(await scan(root, 0), []);
    assert.equal(run("git", ["rev-parse", "HEAD"]).trim(), initialHead);
    assert.equal(
      sha256((await readFile(ignorePath, "utf8")).replaceAll("\r\n", "\n")),
      reviewedIgnoreSha256,
    );
    t.diagnostic(
      "40 historical source spans attested; 40 fresh positives; exact control ignore 0; 40 replacement positives; actual repository history 0. All child commands terminal; ephemeral fixtures removed on completion.",
    );
  },
);
