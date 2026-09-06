# CodeQL context triage: seven hash/response-writer alerts

Reviewed 2026-09-06. This report covers exactly **seven** alerts in
`xBounceIT/periapsis`: **#3, #4, #15, #22, #23, #24 and #25**. Their retrieved
instances refer to commit `068a44d385d11f890aa1f4faab000fad67655da3`.
The conclusions below are scoped to those reported flows, not a general security
certification. The alerts remain open; this change neither dismisses them nor
suppresses CodeQL rules. Production algorithms, schema/receipt ABIs and response
bytes are unchanged.

## Findings and recommendations

| Alert                                                                   | Reported sink                                                 | Verified context                                                                                                                                                                                                                   | Recommendation                                                                                                                                                         |
| ----------------------------------------------------------------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [#3](https://github.com/xBounceIT/periapsis/security/code-scanning/3)   | `schema-compatibility-v51-manifest.test.ts:124`, SHA-256      | `readRoutine` extracts committed SQL source; the reported calls at 639/643 hash predecessor/repaired function bodies against exact release pins. No credential is hashed.                                                          | False positive: source-integrity checksum, not password storage. Preserve published hashes.                                                                            |
| [#4](https://github.com/xBounceIT/periapsis/security/code-scanning/4)   | `platform-oidc-binding-authentication-runtime.ts:61`, SHA-256 | `bytes(label)` derives deterministic fixture bytes from a fixed namespace and scenario labels. The reported `prepareAttempt` calls use the literal evidence-cap/continuation scenario labels; they do not accept a human password. | False positive: synthetic SQL-runtime fixture material. Do not replace protocol-shaped digests with password hashes or copy this deterministic helper into production. |
| [#15](https://github.com/xBounceIT/periapsis/security/code-scanning/15) | `notification_repository.go:208`, SHA-256                     | The input is a domain-separated idempotency document. Its SMTP `password` field contains the `ProtectedSecret` envelope, while retain/remove fields are booleans. Plaintext is encrypted before the repository receives it.        | False positive: request fingerprint over encrypted material, not a password verifier. Preserve the receipt protocol.                                                   |
| [#22](https://github.com/xBounceIT/periapsis/security/code-scanning/22) | `httpserver/handler.go:1260`, `statusRecorder.Write`          | Transparent status/access-log wrapper; decoder results are serialized by the JSON/Problem Details boundary.                                                                                                                        | False positive for the reported JSON flow; retain contextual encoding at the renderer.                                                                                 |
| [#23](https://github.com/xBounceIT/periapsis/security/code-scanning/23) | API `telemetry/http.go:80`, `traceResponseWriter.Write`       | Transparent tracing wrapper around the same API response.                                                                                                                                                                          | Same scoped classification as #22; do not HTML-escape arbitrary response bytes.                                                                                        |
| [#24](https://github.com/xBounceIT/periapsis/security/code-scanning/24) | API `telemetry/metrics.go:243`, `metricResponseWriter.Write`  | Transparent metrics wrapper around the same API response, not the Prometheus renderer itself.                                                                                                                                      | Same scoped classification as #22.                                                                                                                                     |
| [#25](https://github.com/xBounceIT/periapsis/security/code-scanning/25) | Worker `telemetry/http.go:80`, `traceResponseWriter.Write`    | Generic response forwarding. The alert lists API decoder sources, although the worker has no Go import of the API service. The wrapper does not choose HTML or alter the declared response format.                                 | False positive for this reported sink/flow; preserve byte transparency and the handler's media type.                                                                   |

## Response boundary evidence

The reported API sources are `decodeJSONBody` in `auth_handlers.go:578` and
`decodeAuthorizationBodyWithControls` in `tenant_authorization_handlers.go:725`.
They parse request JSON. The response renderers in `handler.go` set
`application/problem+json; charset=utf-8` (`writeProblem`, 1320) or
`application/json; charset=utf-8` (`writeJSON`, 1337) before writing status/body.
Both use the standard `json.Encoder` without disabling HTML escaping.
`securityHeadersMiddleware` sets `X-Content-Type-Options: nosniff` and the
restrictive API CSP before routing. JSON escaping is the serializer's default,
not a guarantee inferred from the alert status; see the
[Go encoder documentation](https://pkg.go.dev/encoding/json#Encoder.SetEscapeHTML).

`response_content_type_test.go` exercises both actual decoders, success and
failure, with HTML metacharacters. The responses traverse the actual enabled
tracing, access-log/status and metrics wrappers in Router order. It asserts the
media types, status, nosniff, CSP, no-store Problem Details, escaped wire bytes
and unchanged decoded JSON value. Tracing exports only to an owned loopback
collector with bounded shutdown. Additional cases preserve explicit/implicit
status and exact plaintext, Prometheus, SSE and deliberately supplied HTML bytes.
The HTML case tests transparency, not the safety of arbitrary HTML input.

`http_response_format_test.go` separately exercises the worker's enabled tracing
wrapper with JSON, Problem Details, plaintext, metrics and SSE under explicit and
implicit statuses. These tests deliberately do not introduce blanket
`html.EscapeString` calls: that would corrupt JSON/streaming/metrics formats and
legitimate separately rendered HTML without repairing a renderer boundary.

## Hash boundary evidence

For #3, `migration()` reads exact committed SQL bytes and `readRoutine()` returns
the declaration/body. The historical manifest tests assert pinned SHA-256 values
and the byte-preserving SAML repair. Human password handling is unrelated to this
source checksum.

For #4, the inspected helper is confined to a fresh-database test executable.
`prepareAttempt()` passes namespaced fixed-label digests for the receipt, network,
account, state, browser and nonce coordinates. The three reported calls create
the `platform-mfa-evidence-cap-1023`, `platform-mfa-evidence-cap-1024` and
`platform-mfa-continuation` scenarios. No password input or password-verification
operation exists in this helper. This review did not rerun that PostgreSQL suite;
its analysis is source-based, not a new database-runtime result.

For #15, `notification/smtp_service.go:237` calls `protectSecret` before producing
`SMTPPersistedWrite`. `notification/secret.go:214` uses purpose-separated
AES-256-GCM with a CSPRNG nonce and authenticated ownership/context. Repository
`protectedNotificationSecretPayload` at 363 serializes only identity/version/kind,
key version, nonce and ciphertext. `smtpNotificationPayload` at 349 embeds that
envelope in the request document; `notificationMutationDigests` at 199 hashes the
serialized document with the existing scope/actor/operation domain separation.
The schema keeps SMTP password-secret references and encrypted secret-version
rows separately from command `request_digest` fields.

`notification_repository_digest_test.go` uses the real keyring with ephemeral
random material. It proves the exact six-field envelope, absence of plaintext in
the serialized request, authenticated decryption, unchanged receipt bytes and
scope/actor/operation separation. Mutating nonce, ciphertext, key version or
retain/remove flags changes the request digest without changing the idempotency
key digest. Its replay assertion concerns the same persisted request document;
it does not claim a new end-to-end SMTP administration retry/database test.

Human-selected local passwords retain the separate Argon2id boundary in
`authentication/security.go` and ADR-0005. SMTP credentials must be recoverable
for outbound authentication, unlike local password verifiers; this distinction
matches [OWASP's hashing-versus-encryption guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#hashing-vs-encryption).

## Focused verification

All commands below passed locally; none starts PostgreSQL or changes GitHub alert
state:

```text
# services/api
go test ./internal/httpserver -run TestResponseWrappers -count=1 -timeout=90s
go test ./internal/postgres -run TestNotificationMutationDigestBinds -count=1 -timeout=90s
go test ./internal/authentication -run TestPasswordManagerUsesBoundedArgon2idProfile -count=1 -timeout=60s
go vet ./internal/httpserver ./internal/postgres
# services/worker
go test ./internal/telemetry -run TestTraceResponseWriterPreserves -count=1 -timeout=60s
go vet ./internal/telemetry
# repository root: existing historical manifest, unchanged
corepack pnpm --filter @periapsis/db exec vitest run tests/schema-compatibility-v51-manifest.test.ts --reporter=dot
```

The unchanged V51 manifest passed all 16 tests. The three new Go test files cover
four top-level tests. A fresh CodeQL analysis may continue to report these
contextual false positives; only a separately authorized, per-alert disposition
should change their GitHub state. No rule disablement, filename exclusion, API
renaming to evade analysis, or cryptographic substitution was introduced.
