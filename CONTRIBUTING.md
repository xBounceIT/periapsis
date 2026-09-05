# Contributing

Periapsis accepts changes as small, verifiable vertical slices.

1. Read `AGENTS.md`, `TASKS.md`, and the relevant ADRs.
2. Create a focused branch and update tests with the implementation.
3. Run `make verify`; run integration and security suites for database or authorization changes.
4. Update OpenAPI before HTTP implementation and Drizzle schema before migrations.
5. Document security-relevant decisions in an ADR and operational debt in `TASKS.md`.
6. Keep generated changes in the same commit as their canonical source.

Commit messages use an imperative summary. Pull requests must describe behavior, tests, tenant/security impact, migrations, rollback, and any remaining risk.
