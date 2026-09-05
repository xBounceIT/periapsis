# Deployment validation

`validate-manifests.mjs` is a dependency-free source-contract check. It verifies required
deployment surfaces, worker LDAP configuration parity, hardened Kubernetes workload
markers, fail-closed production CIDRs, absence of obvious inline secret material/latest
tags, valid JSON assets, and full-SHA GitHub Action references.

Run locally with:

```text
node --test scripts/deploy/validate-manifests.test.mjs
node scripts/deploy/validate-manifests.mjs
```

It complements, rather than replaces, Compose/Swarm parsing, Kustomize rendering,
Kubernetes schema/server dry-run, Prometheus/Collector validation, container startup, and
security scanners in CI.
