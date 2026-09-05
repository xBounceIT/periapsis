package postgres

import "testing"

func TestValidateRuntimeRoleMetadataRequiresDedicatedWorkerAuthority(t *testing.T) {
	valid := runtimeRoleMetadata{name: "periapsis_worker_login", workerMember: true}
	if err := validateRuntimeRoleMetadata(valid); err != nil {
		t.Fatalf("valid worker role rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*runtimeRoleMetadata)
	}{
		{name: "missing identity", mutate: func(role *runtimeRoleMetadata) { role.name = "" }},
		{name: "superuser", mutate: func(role *runtimeRoleMetadata) { role.superuser = true }},
		{name: "create database", mutate: func(role *runtimeRoleMetadata) { role.createDB = true }},
		{name: "create role", mutate: func(role *runtimeRoleMetadata) { role.createRole = true }},
		{name: "replication", mutate: func(role *runtimeRoleMetadata) { role.replication = true }},
		{name: "bypass RLS", mutate: func(role *runtimeRoleMetadata) { role.bypassRLS = true }},
		{name: "missing worker membership", mutate: func(role *runtimeRoleMetadata) { role.workerMember = false }},
		{name: "extra API membership", mutate: func(role *runtimeRoleMetadata) {
			role.incompatibleMemberships = []string{"periapsis_api"}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata := valid
			test.mutate(&metadata)
			if err := validateRuntimeRoleMetadata(metadata); err == nil {
				t.Fatal("incompatible worker role accepted")
			}
		})
	}
}
