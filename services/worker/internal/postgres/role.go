package postgres

import (
	"context"
	"errors"
)

const runtimeRoleQuery = `
SELECT current_user, role.rolsuper, role.rolcreatedb, role.rolcreaterole,
       role.rolreplication, role.rolbypassrls,
       pg_has_role(current_user, 'periapsis_worker', 'member'),
       ARRAY(
         SELECT candidate.rolname
         FROM pg_catalog.pg_roles AS candidate
         WHERE candidate.rolname <> current_user
           AND candidate.rolname <> 'periapsis_worker'
           AND pg_has_role(current_user, candidate.rolname, 'member')
         ORDER BY candidate.rolname
       )::text[]
FROM pg_catalog.pg_roles AS role
WHERE role.rolname = current_user
`

// ValidateRuntimeDatabaseRole rejects database identities with authority beyond
// the dedicated worker group before the process starts background work.
func ValidateRuntimeDatabaseRole(ctx context.Context, pool SchemaQuerier) error {
	var role runtimeRoleMetadata
	err := pool.QueryRow(ctx, runtimeRoleQuery).Scan(
		&role.name,
		&role.superuser,
		&role.createDB,
		&role.createRole,
		&role.replication,
		&role.bypassRLS,
		&role.workerMember,
		&role.incompatibleMemberships,
	)
	if err != nil {
		return errors.New("validate worker database role")
	}
	if err := validateRuntimeRoleMetadata(role); err != nil {
		return errors.New("database connection is not a least-privileged worker role")
	}
	return nil
}

type runtimeRoleMetadata struct {
	name                    string
	superuser               bool
	createDB                bool
	createRole              bool
	replication             bool
	bypassRLS               bool
	workerMember            bool
	incompatibleMemberships []string
}

func validateRuntimeRoleMetadata(role runtimeRoleMetadata) error {
	if role.name == "" || role.superuser || role.createDB || role.createRole ||
		role.replication || role.bypassRLS || !role.workerMember ||
		len(role.incompatibleMemberships) != 0 {
		return errors.New("runtime role has incompatible authority")
	}
	return nil
}
