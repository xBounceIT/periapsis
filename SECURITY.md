# Security policy

## Supported versions

Security fixes are applied to the latest released minor version. The repository is pre-release until the acceptance gates in `TASKS.md` are complete.

## Reporting a vulnerability

Do not open a public issue. Send a private report to the security contact configured by the deploying organization and include:

- affected version or commit;
- reproduction steps with synthetic data;
- impact and tenant-boundary implications;
- suggested remediation, if known.

Do not include credentials, tokens, SAML assertions, email bodies, evidence, or customer identifiers. Operators should rotate any secret that may have entered a report.

## Deployment baseline

- terminate TLS at a trusted ingress and enable only secure cookies;
- mount master keys and service credentials from Docker/Kubernetes secrets;
- use distinct PostgreSQL roles for migration, API, worker, notifier, and audit readers;
- keep Swagger disabled or access-controlled on public production ingress;
- run immutable, non-root images with read-only filesystems and dropped capabilities;
- configure external PostgreSQL backups and versioned object-storage retention;
- review audit-chain verification and security alerts on a scheduled basis.

The initial threat model is maintained in `docs/threat-model.md`.
