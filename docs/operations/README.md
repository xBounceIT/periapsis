# Operations index

- [Deployment and secret integration](deployment.md)
- [Migration, bootstrap, and upgrades](migration-bootstrap-upgrade.md)
- [Platform tenant lifecycle](tenant-lifecycle.md)
- [Backup and restore](backup-restore.md)
- [DFIR evidence storage and malware scanning](dfir-evidence-storage.md)
- [Observability](observability.md)
- [Ticketing performance gates](performance-gates.md)
- [Alert response](incident-response.md)
- [Supply-chain and runtime hardening](security-hardening.md)
- [Release acceptance evidence](../release-acceptance.md)

Every procedure is tenant-safe by default: normal runtime identities remain subject to
application authorization and PostgreSQL RLS, migrations run as a separate one-shot
identity, and operational access is reason-bearing, time-bounded, and audited by the
platform/provider. Do not paste secrets or customer content into tickets, terminals,
dashboards, traces, or command history.
