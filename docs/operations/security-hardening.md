# Supply-chain and runtime hardening

## Release evidence

For every immutable application digest retain:

- source revision and reproducible build invocation;
- OCI platform list for `linux/amd64` and `linux/arm64`;
- SPDX or CycloneDX SBOM;
- vulnerability scan result and approved, expiring exceptions;
- secret scan result;
- image configuration proving numeric non-root user;
- signature/provenance when the registry supports verification;
- rendered Compose/Swarm/Kubernetes validation evidence.

CI action references are full commit SHAs. Tool/container versions are explicit and must be
updated through reviewed dependency maintenance. A tag is not an immutable production
release reference; deployment overlays/stacks use registry digests.

Critical/high vulnerabilities fail release unless a security owner documents that the
component is unreachable/not present in the final image, attaches VEX-equivalent evidence,
sets an expiry, and tracks remediation. `ignore-unfixed` is not a blanket policy. Scanner
database download failures fail closed rather than producing a green result.

## Runtime verification

At image build and after orchestration, prove UID is 10001, root filesystem is read-only,
only `/tmp`/declared data mounts are writable, capabilities are empty, privilege escalation
is denied, seccomp is RuntimeDefault, and health/shutdown work. Test both supported
architectures before release.

NetworkPolicy/overlay separation is defense in depth; backend authorization and PostgreSQL
RLS remain mandatory. Verify actual egress/ingress with disposable probes after every CNI,
ingress, firewall, or service-endpoint change.

## Secret scanning scope

Scan the full Git history on protected branches plus the workspace diff on pull requests.
If a secret is detected, revoke/rotate it first, then remove it from history through the
approved incident procedure. Deleting a line or marking it false-positive does not revoke
the credential. Test fixtures use generated ephemeral values and never customer data.
