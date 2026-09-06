# Contract generation

OpenAPI is canonical; do not edit generated clients by hand. Run
`pnpm --filter @periapsis/contracts generate`, then
`pnpm --filter @periapsis/contracts verify:generated` to check reproducibility.

The pinned Hey API 0.99.0 generator runs with this package's TypeScript 6 toolchain.
Generation applies `scripts/harden-generated-params.mjs` before the existing
explicit-auth postprocessor. The params postprocessor checks the complete upstream
template's LF-normalized SHA-256 and fails if it changes. A generator upgrade must
review the new template and update the regression proof; it must not bypass the pin.

## Generated parameter dictionaries

The upstream [prototype-substitution advisory](https://github.com/hey-api/hey-api/security/advisories/GHSA-hhx9-57xq-r5rw)
is fixed for fresh dictionaries in the pinned version. Local runtime tests also
cover aggregate mappings that replace a slot with a caller-owned ordinary object.
The repository postprocessor validates actual slot names and rejects `__proto__`,
`constructor`, and `prototype` as per-field destinations. On the first field write,
caller records are copied into owned null-prototype dictionaries. A subsequent
rejection therefore cannot leave earlier field writes on a shared caller object.
Slot selection uses an explicit four-case switch for both reads and replacements;
untrusted selectors never index the outer parameter object or its prototype.

Whole bodies (including scalar, array, FormData and ordinary JSON bodies) remain
unchanged when no per-field write is requested. Literal property names inside such
JSON bodies are data, not parameter destinations. Mixing per-field writes into a
scalar, array or non-plain object is unsupported and fails explicitly. This helper
is exported by the generated client but currently is not called by generated SDK
operations; the regression proves the helper boundary, not a remotely reachable
application exploit or a server-side authorization check.

`pretest` exercises the actual generated TypeScript plus the pinned upstream
template, all four slots, mapped/extra keys, shared-object ownership and ordinary
serialization. Run it with `pnpm --filter @periapsis/contracts pretest`.
