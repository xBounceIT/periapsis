# Code-scanning remediation, 2026-09-06

Scope: the 25 open CodeQL alerts retrieved from `xBounceIT/periapsis` on `main`.
The reverse-proxy deployment was published first as `ff5b800`; this remediation
does not change deployment settings, migration history, authentication protocols,
or dependency versions. Alert closure must be checked against a fresh analysis
after publication, not inferred from passing unit tests.

| Alerts              | Remediation and evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| #1                  | Replace the notifier's nested CSS-remainder quantifier with an equivalent linear brace scan. Near-limit unmatched-brace inputs exercise the real template validator under a V8 execution deadline, so a synchronous regression cannot hang the test worker.                                                                                                                                                                                                                                                 |
| #2                  | Select the outbound web-proxy endpoint exclusively from the configured API URL; request data supplies only the routed path/query. Real HTTP fixtures prove absolute/network-path requests cannot select another listener, escaped query bytes survive, and upstream redirects are not followed. This makes an existing routed boundary explicit; it is not evidence of a previously demonstrated remote host escape.                                                                                        |
| #5                  | Decode sanitizer-produced entities in a single pass. Literal nested entity strings now remain literal in generated plaintext rather than being decoded twice. HTML sanitization/escaping remains unchanged.                                                                                                                                                                                                                                                                                                 |
| #6                  | Reproduce prototype substitution when the generated helper receives caller-owned aggregate parameter records. The pinned generation pipeline now validates slots/keys and uses copy-on-write null-prototype dictionaries. Tests cover all four slots, caller/global prototype integrity and ordinary whole-body behavior. See the [generator policy](../../packages/contracts/README.md); generated SDK operations currently do not call this exported helper, so no remote application exploit is claimed. |
| #7–8                | Hash the same operation, NUL separator and canonical JSON incrementally instead of calculating a potentially overflowing allocation capacity. Regression fingerprints remain byte-identical.                                                                                                                                                                                                                                                                                                                |
| #9                  | Bound cache-control seconds before the signed duration conversion/multiplication and reject negative local caps; retain existing positive caps and flooring behavior.                                                                                                                                                                                                                                                                                                                                       |
| #10–14              | Check the existing exact API/worker bounds before narrowing integers. The original API loader already rejected invalid values before returning configuration; this makes local conversion safety explicit rather than asserting a previously exploitable configuration bypass.                                                                                                                                                                                                                              |
| #16–21              | Share canonical return-path validation with explicit second-byte guards and decoded-path control/backslash rejection. Raw `//` and `/\\` were already blocked; regression tests additionally demonstrate and close previously accepted `%5C`, `%00`, `%0A` and `%0D` path forms across starts, callbacks and persistence boundaries. No double decoding or query reinterpretation is introduced.                                                                                                            |
| #3, #4, #15, #22–25 | Preserve the verified checksum/encrypted-envelope and contextually encoded response behavior. The [per-alert triage report](code-scanning-triage.md) records why these seven findings are false positives and the focused regression evidence. The user authorized per-alert dismissal with those explanations; no rule exclusions or blanket suppressions are introduced.                                                                                                                                  |

## Verification boundary

Final CodeQL analyses of implementation commit `de3b093` in
[run 34051313196](https://github.com/xBounceIT/periapsis/actions/runs/34051313196)
completed without analysis errors for Go, JavaScript/TypeScript and Actions.
GitHub reports **0 open alerts, 18 fixed and 7 dismissed as documented false
positives**. The following documentation-only checkpoint records those results;
it does not change the analyzed application or generated code.

The first post-publication scan of `00a73a0` resolved 17 findings; only #6 remained
open after the seven authorized false-positive dismissals. Its remaining path
treated a computed slot read as potentially selecting `Object.prototype`, despite
the runtime slot allowlist. The follow-up makes all four slot reads/replacements
explicit literal property accesses, preserves copy-on-write and key validation,
and adds caller-ownership, property-descriptor and non-coercion regressions. No additional bypass was
reproduced and the alert is not dismissed or suppressed.

Focused Go package tests/vet, web HTTP tests, template tests and generated-client
runtime/reproducibility checks pass locally. Root `pnpm verify` exited successfully,
but included cached Go packages: fresh CI exposes an existing Compose-contract
failure and a separate Mailpit connection failure, both also present on baseline
`ff5b800`. The dated `TASKS.md` entry tracks those explicitly, separately from
CodeQL. No local PostgreSQL runtime, production-network, container-deployment or
end-to-end browser rollout was run for this security-remediation slice.
