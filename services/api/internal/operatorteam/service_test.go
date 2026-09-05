package operatorteam

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

var (
	serviceTestNow       = time.Date(2026, 8, 24, 12, 0, 0, 123456000, time.UTC)
	serviceTestTenantID  = serviceTestID(1)
	serviceTestTeamID    = serviceTestID(2)
	serviceTestEpochID   = serviceTestID(3)
	serviceTestRosterID  = serviceTestID(4)
	serviceTestMemberID  = serviceTestID(5)
	serviceTestUserID    = serviceTestID(6)
	serviceTestSessionID = serviceTestID(7)
	serviceTestSourceID  = serviceTestID(8)
	serviceTestRequestID = serviceTestID(9)
)

func TestPlatformOperatorTeamLifecycle(t *testing.T) {
	t.Run("list and get require read and preserve bounded pagination", func(t *testing.T) {
		first := serviceTestTeam(serviceTestID(20))
		second := serviceTestTeam(serviceTestID(21))
		repository := &stubRepository{teams: []OperatorTeam{first, second}, team: first}
		service := serviceTestService(t, repository)
		session := serviceTestPlatformSession(authorization.PermissionPlatformOperatorTeamRead)

		page, err := service.ListOperatorTeams(context.Background(), session, ListOperatorTeamsInput{
			PageInput: PageInput{Limit: 1},
		})
		if err != nil {
			t.Fatalf("ListOperatorTeams() error = %v", err)
		}
		if len(page.Items) != 1 || page.Items[0].ID != first.ID || page.NextCursor == nil || *page.NextCursor != first.ID {
			t.Fatalf("ListOperatorTeams() page = %#v", page)
		}
		if repository.listTeamsParams.Limit != 2 {
			t.Fatalf("repository limit = %d, want 2", repository.listTeamsParams.Limit)
		}

		got, err := service.GetOperatorTeam(context.Background(), session, first.ID)
		if err != nil || got.ID != first.ID {
			t.Fatalf("GetOperatorTeam() = %#v, %v", got, err)
		}
	})

	t.Run("create binds idempotent payload and generated identity", func(t *testing.T) {
		createdID := serviceTestID(30)
		created := serviceTestTeam(createdID)
		created.Key = "blue_team"
		created.Name = "Blue Team"
		created.Description = "Primary operators"
		createdBy := serviceTestUserID
		created.CreatedByUserID = &createdBy
		repository := &stubRepository{createTeamResult: IdempotentCreateResult[OperatorTeam]{Value: created}}
		service := serviceTestService(t, repository)
		service.newID = func() (uuid.UUID, error) { return createdID, nil }

		got, err := service.CreateOperatorTeam(
			context.Background(),
			serviceTestPlatformSession(authorization.PermissionPlatformOperatorTeamManage),
			CreateOperatorTeamInput{
				Key: "blue_team", Name: "  Blue Team  ", Description: " Primary operators ",
				IdempotencyKey: "platform-team-0001", Audit: serviceTestAudit(),
			},
		)
		if err != nil || got.ID != createdID {
			t.Fatalf("CreateOperatorTeam() = %#v, %v", got, err)
		}
		params := repository.createTeamParams
		if params.OperatorTeamID != createdID || params.Name != "Blue Team" ||
			params.Description != "Primary operators" || params.OccurredAt != serviceTestNow {
			t.Fatalf("CreateOperatorTeam params = %#v", params)
		}
	})

	t.Run("exact create replay returns the archived original without recreating it", func(t *testing.T) {
		originalID := serviceTestID(31)
		archived := serviceTestTeam(originalID)
		createdBy := serviceTestUserID
		archivedAt := serviceTestNow.Add(-30 * time.Minute)
		archiveReason := "Team retired"
		archived.CreatedByUserID = &createdBy
		archived.State = OperatorTeamStateArchived
		archived.ArchivedAt = &archivedAt
		archived.ArchivedByUserID = &createdBy
		archived.ArchiveReason = &archiveReason
		archived.Version = 2
		archived.UpdatedAt = serviceTestNow
		repository := &stubRepository{createTeamResult: IdempotentCreateResult[OperatorTeam]{Value: archived, Replayed: true}}
		service := serviceTestService(t, repository)
		service.newID = func() (uuid.UUID, error) { return serviceTestID(32), nil }

		got, err := service.CreateOperatorTeam(
			context.Background(),
			serviceTestPlatformSession(authorization.PermissionPlatformOperatorTeamManage),
			CreateOperatorTeamInput{
				Key: "red_team", Name: "Red Team", Description: "Incident responders",
				IdempotencyKey: "platform-team-0001", Audit: serviceTestAudit(),
			},
		)
		if err != nil || got.ID != originalID || got.State != OperatorTeamStateArchived {
			t.Fatalf("CreateOperatorTeam() replay = %#v, %v", got, err)
		}
	})

	t.Run("patch requires the strong version", func(t *testing.T) {
		current := serviceTestTeam(serviceTestTeamID)
		updated := current
		updated.Name = "Updated team"
		updated.Version = 2
		updated.UpdatedAt = serviceTestNow
		repository := &stubRepository{team: current, patchTeam: updated}
		service := serviceTestService(t, repository)
		version := int64(1)
		name := " Updated team "

		got, err := service.PatchOperatorTeam(
			context.Background(),
			serviceTestPlatformSession(authorization.PermissionPlatformOperatorTeamManage),
			serviceTestTeamID,
			PatchOperatorTeamInput{Name: &name, ExpectedVersion: &version, Audit: serviceTestAudit()},
		)
		if err != nil || got.Version != 2 || repository.patchTeamParams.Name == nil || *repository.patchTeamParams.Name != "Updated team" {
			t.Fatalf("PatchOperatorTeam() = %#v, %v; params = %#v", got, err, repository.patchTeamParams)
		}
	})

	t.Run("archive refuses an active tenant assignment", func(t *testing.T) {
		current := serviceTestTeam(serviceTestTeamID)
		current.ActiveAssignmentCount = 1
		repository := &stubRepository{team: current}
		service := serviceTestService(t, repository)
		version := current.Version

		err := service.ArchiveOperatorTeam(
			context.Background(),
			serviceTestPlatformSession(authorization.PermissionPlatformOperatorTeamManage),
			serviceTestTeamID,
			ArchiveOperatorTeamInput{Reason: "Tenant relationships remain active", ExpectedVersion: &version, Audit: serviceTestAudit()},
		)
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("ArchiveOperatorTeam() error = %v, want conflict", err)
		}
		if repository.archiveTeamCalls != 0 {
			t.Fatal("archive repository reached with an active assignment")
		}
	})

	t.Run("archive preserves the transactional race conflict", func(t *testing.T) {
		current := serviceTestTeam(serviceTestTeamID)
		repository := &stubRepository{team: current, archiveTeamErr: ErrConflict}
		service := serviceTestService(t, repository)
		version := current.Version

		err := service.ArchiveOperatorTeam(
			context.Background(),
			serviceTestPlatformSession(authorization.PermissionPlatformOperatorTeamManage),
			serviceTestTeamID,
			ArchiveOperatorTeamInput{Reason: " Team retired ", ExpectedVersion: &version, Audit: serviceTestAudit()},
		)
		if !errors.Is(err, ErrConflict) || repository.archiveTeamCalls != 1 {
			t.Fatalf("ArchiveOperatorTeam() error = %v, calls = %d", err, repository.archiveTeamCalls)
		}
		if repository.archiveTeamParams.Reason != "Team retired" {
			t.Fatalf("archive reason = %q, want normalized reason", repository.archiveTeamParams.Reason)
		}
	})
}

func TestPlatformOperatorTeamDeniesBeforeRepository(t *testing.T) {
	repository := &stubRepository{}
	service := serviceTestService(t, repository)

	_, err := service.ListOperatorTeams(context.Background(), serviceTestPlatformSession(), ListOperatorTeamsInput{})
	if !errors.Is(err, ErrForbidden) || repository.listTeamsCalls != 0 {
		t.Fatalf("ListOperatorTeams() error = %v, calls = %d", err, repository.listTeamsCalls)
	}
	badSession := serviceTestPlatformSession(authorization.PermissionPlatformOperatorTeamRead)
	badSession.ID = uuid.Nil
	_, err = service.GetOperatorTeam(context.Background(), badSession, serviceTestTeamID)
	if !errors.Is(err, ErrForbidden) || repository.getTeamCalls != 0 {
		t.Fatalf("GetOperatorTeam() error = %v, calls = %d", err, repository.getTeamCalls)
	}
}

func TestTenantAssignmentUseCases(t *testing.T) {
	t.Run("list and get use tenant and exact-team read scopes", func(t *testing.T) {
		assignment := serviceTestAssignment(serviceTestEpochID, AssignmentStateActive)
		repository := &stubRepository{assignments: []TenantAssignment{assignment}, assignment: assignment}
		service := serviceTestService(t, repository)

		repository.authority = serviceTestAuthority(authorization.ScopedPermission{
			Permission: authorization.TenantPermissionOperatorTeamRead,
			Scope:      authorization.ScopeTenant,
		})
		page, err := service.ListTenantAssignments(
			context.Background(), serviceTestActor(), serviceTestTenantID, ListTenantAssignmentsInput{},
		)
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("ListTenantAssignments() = %#v, %v", page, err)
		}

		repository.authority = serviceTestAuthority(authorization.ScopedPermission{
			Permission: authorization.TenantPermissionOperatorTeamRead,
			Scope:      authorization.ScopeOperatorTeam,
		})
		repository.authority.OperatorTeamRelationships = []authorization.OperatorTeamRelationship{{
			OperatorTeamID: serviceTestTeamID, AssignmentEpochID: serviceTestEpochID,
		}}
		got, err := service.GetTenantAssignment(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID,
		)
		if err != nil || got.EpochID != serviceTestEpochID {
			t.Fatalf("GetTenantAssignment() = %#v, %v", got, err)
		}
	})

	t.Run("start creates a fresh epoch", func(t *testing.T) {
		freshEpochID := serviceTestID(40)
		assignment := serviceTestAssignment(freshEpochID, AssignmentStateActive)
		repository := &stubRepository{
			authority: serviceTestAuthority(authorization.ScopedPermission{
				Permission: authorization.TenantPermissionOperatorTeamManage,
				Scope:      authorization.ScopeTenant,
			}),
			startAssignmentResult: IdempotentCreateResult[TenantAssignment]{Value: assignment},
		}
		service := serviceTestService(t, repository)
		service.newID = func() (uuid.UUID, error) { return freshEpochID, nil }

		got, err := service.StartTenantAssignment(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID,
			StartTenantAssignmentInput{Reason: " Tenant contract ", IdempotencyKey: "tenant-assign-0001", Audit: serviceTestAudit()},
		)
		if err != nil || got.EpochID != freshEpochID || repository.startAssignmentParams.EpochID != freshEpochID {
			t.Fatalf("StartTenantAssignment() = %#v, %v; params = %#v", got, err, repository.startAssignmentParams)
		}
	})

	t.Run("exact start replay returns the ended epoch and never reopens it", func(t *testing.T) {
		ended := serviceTestAssignment(serviceTestEpochID, AssignmentStateEnded)
		repository := &stubRepository{
			authority: serviceTestAuthority(authorization.ScopedPermission{
				Permission: authorization.TenantPermissionOperatorTeamManage,
				Scope:      authorization.ScopeTenant,
			}),
			startAssignmentResult: IdempotentCreateResult[TenantAssignment]{Value: ended, Replayed: true},
		}
		service := serviceTestService(t, repository)
		service.newID = func() (uuid.UUID, error) { return serviceTestID(41), nil }

		got, err := service.StartTenantAssignment(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID,
			StartTenantAssignmentInput{Reason: "Tenant contract", IdempotencyKey: "tenant-assign-0001", Audit: serviceTestAudit()},
		)
		if err != nil || got.EpochID != serviceTestEpochID || got.State != AssignmentStateEnded {
			t.Fatalf("StartTenantAssignment() = %#v, %v", got, err)
		}
		if repository.startAssignmentCalls != 1 {
			t.Fatalf("StartTenantAssignment repository calls = %d, want 1", repository.startAssignmentCalls)
		}
	})

	t.Run("end requires role grant before loading state", func(t *testing.T) {
		repository := &stubRepository{authority: serviceTestAuthority(authorization.ScopedPermission{
			Permission: authorization.TenantPermissionOperatorTeamManage,
			Scope:      authorization.ScopeTenant,
		})}
		service := serviceTestService(t, repository)
		version := int64(1)

		err := service.EndTenantAssignment(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID,
			EndTenantAssignmentInput{Reason: "Contract ended", ExpectedVersion: &version, Audit: serviceTestAudit()},
		)
		if !errors.Is(err, ErrForbidden) || repository.getAssignmentCalls != 0 || repository.endAssignmentCalls != 0 {
			t.Fatalf("EndTenantAssignment() error = %v, get calls = %d, end calls = %d", err, repository.getAssignmentCalls, repository.endAssignmentCalls)
		}
	})

	t.Run("end forwards the exact epoch and strong version", func(t *testing.T) {
		assignment := serviceTestAssignment(serviceTestEpochID, AssignmentStateActive)
		repository := &stubRepository{
			authority: serviceTestAuthority(
				authorization.ScopedPermission{Permission: authorization.TenantPermissionOperatorTeamManage, Scope: authorization.ScopeTenant},
				authorization.ScopedPermission{Permission: authorization.TenantPermissionRoleGrant, Scope: authorization.ScopeTenant},
			),
			assignment: assignment,
		}
		service := serviceTestService(t, repository)
		version := assignment.Version

		err := service.EndTenantAssignment(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID,
			EndTenantAssignmentInput{Reason: " Contract ended ", ExpectedVersion: &version, Audit: serviceTestAudit()},
		)
		if err != nil || repository.endAssignmentCalls != 1 ||
			repository.endAssignmentParams.EpochID != serviceTestEpochID ||
			repository.endAssignmentParams.ExpectedVersion != version {
			t.Fatalf("EndTenantAssignment() error = %v; params = %#v", err, repository.endAssignmentParams)
		}
	})
}

func TestTenantAuthorityProjectionCannotSpoofAnotherHuman(t *testing.T) {
	repository := &stubRepository{authority: serviceTestAuthority(authorization.ScopedPermission{
		Permission: authorization.TenantPermissionOperatorTeamRead,
		Scope:      authorization.ScopeTenant,
	})}
	repository.authority.Principal.ID = serviceTestID(77)
	service := serviceTestService(t, repository)

	_, err := service.ListTenantAssignments(
		context.Background(), serviceTestActor(), serviceTestTenantID, ListTenantAssignmentsInput{},
	)
	if !errors.Is(err, ErrUnavailable) || repository.listAssignmentsCalls != 0 {
		t.Fatalf("ListTenantAssignments() error = %v, list calls = %d", err, repository.listAssignmentsCalls)
	}
}

func TestExactOperatorTeamScopeRejectsAStaleAssignmentEpochBeforeRepository(t *testing.T) {
	staleEpochID := serviceTestID(78)
	exactAuthority := func(permission authorization.TenantPermission, additional ...authorization.ScopedPermission) authorization.TenantAuthority {
		permissions := append([]authorization.ScopedPermission{{
			Permission: permission, Scope: authorization.ScopeOperatorTeam,
		}}, additional...)
		authority := serviceTestAuthority(permissions...)
		authority.OperatorTeamRelationships = []authorization.OperatorTeamRelationship{{
			OperatorTeamID: serviceTestTeamID, AssignmentEpochID: staleEpochID,
		}}
		return authority
	}

	t.Run("get assignment", func(t *testing.T) {
		repository := &stubRepository{authority: exactAuthority(authorization.TenantPermissionOperatorTeamRead)}
		service := serviceTestService(t, repository)

		_, err := service.GetTenantAssignment(
			context.Background(), serviceTestActor(), serviceTestTenantID,
			serviceTestTeamID, serviceTestEpochID,
		)
		if !errors.Is(err, ErrForbidden) || repository.getAssignmentCalls != 0 {
			t.Fatalf("GetTenantAssignment() error=%v get calls=%d", err, repository.getAssignmentCalls)
		}
	})

	t.Run("list roster", func(t *testing.T) {
		repository := &stubRepository{authority: exactAuthority(
			authorization.TenantPermissionOperatorTeamRead,
			authorization.ScopedPermission{
				Permission: authorization.TenantPermissionUserRead, Scope: authorization.ScopeTenant,
			},
		)}
		service := serviceTestService(t, repository)

		_, err := service.ListRosterEntries(
			context.Background(), serviceTestActor(), serviceTestTenantID,
			serviceTestTeamID, serviceTestEpochID, ListRosterEntriesInput{},
		)
		if !errors.Is(err, ErrForbidden) || repository.getAssignmentCalls != 0 || repository.listRosterCalls != 0 {
			t.Fatalf("ListRosterEntries() error=%v assignment calls=%d roster calls=%d", err, repository.getAssignmentCalls, repository.listRosterCalls)
		}
	})

	t.Run("add roster entry", func(t *testing.T) {
		repository := &stubRepository{authority: exactAuthority(
			authorization.TenantPermissionOperatorTeamRosterManage,
			authorization.ScopedPermission{
				Permission: authorization.TenantPermissionRoleGrant, Scope: authorization.ScopeTenant,
			},
		)}
		service := serviceTestService(t, repository)

		_, err := service.AddRosterEntry(
			context.Background(), serviceTestActor(), serviceTestTenantID,
			serviceTestTeamID, serviceTestEpochID,
			AddRosterEntryInput{
				MembershipID: serviceTestMemberID, Reason: "On-call",
				IdempotencyKey: "stale-epoch-add-0001", Audit: serviceTestAudit(),
			},
		)
		if !errors.Is(err, ErrForbidden) || repository.getAssignmentCalls != 0 || repository.addRosterCalls != 0 {
			t.Fatalf("AddRosterEntry() error=%v assignment calls=%d add calls=%d", err, repository.getAssignmentCalls, repository.addRosterCalls)
		}
	})

	t.Run("revoke roster entry", func(t *testing.T) {
		repository := &stubRepository{authority: exactAuthority(
			authorization.TenantPermissionOperatorTeamRosterManage,
			authorization.ScopedPermission{
				Permission: authorization.TenantPermissionRoleGrant, Scope: authorization.ScopeTenant,
			},
		)}
		service := serviceTestService(t, repository)
		entry := serviceTestRosterEntry(
			serviceTestRosterID,
			serviceTestAssignment(serviceTestEpochID, AssignmentStateActive),
		)
		entityTag := serviceTestRosterEntityTag(t, entry)

		err := service.RevokeRosterEntry(
			context.Background(), serviceTestActor(), serviceTestTenantID,
			serviceTestTeamID, serviceTestEpochID, serviceTestRosterID,
			RevokeRosterEntryInput{
				Reason: "Rotation", ExpectedEntityTag: &entityTag, Audit: serviceTestAudit(),
			},
		)
		if !errors.Is(err, ErrForbidden) || repository.getAssignmentCalls != 0 ||
			repository.getRosterCalls != 0 || repository.revokeRosterCalls != 0 {
			t.Fatalf(
				"RevokeRosterEntry() error=%v assignment calls=%d roster calls=%d revoke calls=%d",
				err, repository.getAssignmentCalls, repository.getRosterCalls, repository.revokeRosterCalls,
			)
		}
	})
}

func TestRosterUseCases(t *testing.T) {
	t.Run("list returns the exact epoch roster", func(t *testing.T) {
		assignment := serviceTestAssignment(serviceTestEpochID, AssignmentStateActive)
		entry := serviceTestRosterEntry(serviceTestRosterID, assignment)
		repository := &stubRepository{
			authority:     serviceTestRosterReadAuthority(),
			assignment:    assignment,
			rosterEntries: []RosterEntry{entry},
		}
		service := serviceTestService(t, repository)

		page, err := service.ListRosterEntries(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID,
			ListRosterEntriesInput{},
		)
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != serviceTestRosterID {
			t.Fatalf("ListRosterEntries() = %#v, %v", page, err)
		}
	})

	t.Run("tenant reader can inspect an ended epoch without reviving its historical edge", func(t *testing.T) {
		assignment := serviceTestAssignment(serviceTestEpochID, AssignmentStateEnded)
		entry := serviceTestRosterEntry(serviceTestRosterID, assignment)
		entry.State = RosterEntryStateExpired
		repository := &stubRepository{
			authority: serviceTestAuthority(
				authorization.ScopedPermission{Permission: authorization.TenantPermissionOperatorTeamRead, Scope: authorization.ScopeTenant},
				authorization.ScopedPermission{Permission: authorization.TenantPermissionUserRead, Scope: authorization.ScopeTenant},
			),
			assignment:    assignment,
			rosterEntries: []RosterEntry{entry},
		}
		service := serviceTestService(t, repository)

		page, err := service.ListRosterEntries(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID,
			ListRosterEntriesInput{},
		)
		if err != nil || len(page.Items) != 1 || page.Items[0].State != RosterEntryStateExpired {
			t.Fatalf("ListRosterEntries() ended history = %#v, %v", page, err)
		}
	})

	t.Run("list rejects an active edge whose assignment already ended", func(t *testing.T) {
		assignment := serviceTestAssignment(serviceTestEpochID, AssignmentStateEnded)
		entry := serviceTestRosterEntry(serviceTestRosterID, assignment)
		repository := &stubRepository{
			authority: serviceTestAuthority(
				authorization.ScopedPermission{Permission: authorization.TenantPermissionOperatorTeamRead, Scope: authorization.ScopeTenant},
				authorization.ScopedPermission{Permission: authorization.TenantPermissionUserRead, Scope: authorization.ScopeTenant},
			),
			assignment:    assignment,
			rosterEntries: []RosterEntry{entry},
		}
		service := serviceTestService(t, repository)

		_, err := service.ListRosterEntries(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID,
			ListRosterEntriesInput{},
		)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("ListRosterEntries() active ended edge error = %v, want unavailable", err)
		}
	})

	t.Run("tenant reader can inspect a generically expired edge for a suspended membership", func(t *testing.T) {
		assignment := serviceTestAssignment(serviceTestEpochID, AssignmentStateActive)
		entry := serviceTestRosterEntry(serviceTestRosterID, assignment)
		entry.Member.Status = authorization.MembershipStatusSuspended
		entry.State = RosterEntryStateExpired
		repository := &stubRepository{
			authority:     serviceTestRosterReadAuthority(),
			assignment:    assignment,
			rosterEntries: []RosterEntry{entry},
		}
		service := serviceTestService(t, repository)

		page, err := service.ListRosterEntries(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID,
			ListRosterEntriesInput{},
		)
		if err != nil || len(page.Items) != 1 || page.Items[0].State != RosterEntryStateExpired {
			t.Fatalf("ListRosterEntries() suspended membership = %#v, %v", page, err)
		}
	})

	t.Run("list also requires tenant user read before loading the epoch", func(t *testing.T) {
		repository := &stubRepository{
			authority: serviceTestTeamAuthority(authorization.TenantPermissionOperatorTeamRead),
		}
		service := serviceTestService(t, repository)

		_, err := service.ListRosterEntries(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID,
			ListRosterEntriesInput{},
		)
		if !errors.Is(err, ErrForbidden) || repository.getAssignmentCalls != 0 || repository.listRosterCalls != 0 {
			t.Fatalf("ListRosterEntries() error = %v, assignment calls = %d, roster calls = %d", err, repository.getAssignmentCalls, repository.listRosterCalls)
		}
	})

	t.Run("list rejects a row from a different epoch", func(t *testing.T) {
		assignment := serviceTestAssignment(serviceTestEpochID, AssignmentStateActive)
		wrong := serviceTestRosterEntry(serviceTestRosterID, assignment)
		wrong.AssignmentEpochID = serviceTestID(51)
		repository := &stubRepository{
			authority:     serviceTestRosterReadAuthority(),
			assignment:    assignment,
			rosterEntries: []RosterEntry{wrong},
		}
		service := serviceTestService(t, repository)

		_, err := service.ListRosterEntries(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID,
			ListRosterEntriesInput{},
		)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("ListRosterEntries() error = %v, want unavailable", err)
		}
	})

	t.Run("add requires roster manage and role grant before epoch state", func(t *testing.T) {
		repository := &stubRepository{authority: serviceTestTeamAuthority(authorization.TenantPermissionOperatorTeamRosterManage)}
		service := serviceTestService(t, repository)

		_, err := service.AddRosterEntry(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID,
			AddRosterEntryInput{
				MembershipID: serviceTestMemberID, Reason: "On-call", IdempotencyKey: "roster-entry-0001", Audit: serviceTestAudit(),
			},
		)
		if !errors.Is(err, ErrForbidden) || repository.getAssignmentCalls != 0 || repository.addRosterCalls != 0 {
			t.Fatalf("AddRosterEntry() error = %v, get calls = %d, add calls = %d", err, repository.getAssignmentCalls, repository.addRosterCalls)
		}
	})

	t.Run("add normalizes expiry and binds the exact epoch", func(t *testing.T) {
		assignment := serviceTestAssignment(serviceTestEpochID, AssignmentStateActive)
		expiresAt := serviceTestNow.Add(time.Hour).In(time.FixedZone("plus-two", 2*60*60))
		entry := serviceTestRosterEntry(serviceTestRosterID, assignment)
		normalizedExpiry := expiresAt.UTC()
		entry.Provenance.ExpiresAt = &normalizedExpiry
		repository := &stubRepository{
			authority: serviceTestAuthority(
				authorization.ScopedPermission{Permission: authorization.TenantPermissionOperatorTeamRosterManage, Scope: authorization.ScopeOperatorTeam},
				authorization.ScopedPermission{Permission: authorization.TenantPermissionRoleGrant, Scope: authorization.ScopeTenant},
			),
			assignment:      assignment,
			addRosterResult: IdempotentCreateResult[RosterEntry]{Value: entry},
		}
		repository.authority.OperatorTeamRelationships = []authorization.OperatorTeamRelationship{{
			OperatorTeamID: serviceTestTeamID, AssignmentEpochID: serviceTestEpochID,
		}}
		service := serviceTestService(t, repository)
		service.newID = func() (uuid.UUID, error) { return serviceTestRosterID, nil }

		got, err := service.AddRosterEntry(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID,
			AddRosterEntryInput{
				MembershipID: serviceTestMemberID, Reason: "On-call", ExpiresAt: &expiresAt,
				IdempotencyKey: "roster-entry-0001", Audit: serviceTestAudit(),
			},
		)
		if err != nil || got.ID != serviceTestRosterID || repository.addRosterParams.AssignmentEpochID != serviceTestEpochID ||
			repository.addRosterParams.ExpiresAt == nil || repository.addRosterParams.ExpiresAt.Location() != time.UTC {
			t.Fatalf("AddRosterEntry() = %#v, %v; params = %#v", got, err, repository.addRosterParams)
		}
	})

	t.Run("add replay returns the current expired representation after the epoch ended", func(t *testing.T) {
		assignment := serviceTestAssignment(serviceTestEpochID, AssignmentStateEnded)
		entry := serviceTestRosterEntry(serviceTestRosterID, assignment)
		entry.State = RosterEntryStateExpired
		repository := &stubRepository{
			authority: serviceTestAuthority(
				authorization.ScopedPermission{Permission: authorization.TenantPermissionOperatorTeamRosterManage, Scope: authorization.ScopeTenant},
				authorization.ScopedPermission{Permission: authorization.TenantPermissionRoleGrant, Scope: authorization.ScopeTenant},
			),
			assignment:      assignment,
			addRosterResult: IdempotentCreateResult[RosterEntry]{Value: entry, Replayed: true},
		}
		service := serviceTestService(t, repository)
		service.newID = func() (uuid.UUID, error) { return serviceTestID(52), nil }

		got, err := service.AddRosterEntry(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID,
			AddRosterEntryInput{
				MembershipID: serviceTestMemberID, Reason: "On-call", IdempotencyKey: "roster-entry-replay-0001", Audit: serviceTestAudit(),
			},
		)
		if err != nil || got.ID != serviceTestRosterID || got.State != RosterEntryStateExpired ||
			repository.addRosterCalls != 1 {
			t.Fatalf("AddRosterEntry() replay = %#v, %v; calls=%d", got, err, repository.addRosterCalls)
		}
	})

	t.Run("sub-microsecond expiry fails before repository", func(t *testing.T) {
		repository := &stubRepository{}
		service := serviceTestService(t, repository)
		expiresAt := serviceTestNow.Add(time.Hour + time.Nanosecond)

		_, err := service.AddRosterEntry(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID,
			AddRosterEntryInput{
				MembershipID: serviceTestMemberID, Reason: "On-call", ExpiresAt: &expiresAt,
				IdempotencyKey: "roster-entry-0001", Audit: serviceTestAudit(),
			},
		)
		if !errors.Is(err, ErrInvalidInput) || repository.resolveCalls != 0 || repository.addRosterCalls != 0 {
			t.Fatalf("AddRosterEntry() error = %v, resolve calls = %d, add calls = %d", err, repository.resolveCalls, repository.addRosterCalls)
		}
	})

	t.Run("revoke requires role grant before loading the roster", func(t *testing.T) {
		repository := &stubRepository{authority: serviceTestTeamAuthority(authorization.TenantPermissionOperatorTeamRosterManage)}
		service := serviceTestService(t, repository)
		entityTag := serviceTestRosterEntityTag(t, serviceTestRosterEntry(
			serviceTestRosterID,
			serviceTestAssignment(serviceTestEpochID, AssignmentStateActive),
		))

		err := service.RevokeRosterEntry(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID, serviceTestRosterID,
			RevokeRosterEntryInput{Reason: "Rotation", ExpectedEntityTag: &entityTag, Audit: serviceTestAudit()},
		)
		if !errors.Is(err, ErrForbidden) || repository.getRosterCalls != 0 || repository.revokeRosterCalls != 0 {
			t.Fatalf("RevokeRosterEntry() error = %v, get calls = %d, revoke calls = %d", err, repository.getRosterCalls, repository.revokeRosterCalls)
		}
	})

	t.Run("revoke forwards exact epoch and strong version", func(t *testing.T) {
		assignment := serviceTestAssignment(serviceTestEpochID, AssignmentStateActive)
		entry := serviceTestRosterEntry(serviceTestRosterID, assignment)
		repository := &stubRepository{
			authority: serviceTestAuthority(
				authorization.ScopedPermission{Permission: authorization.TenantPermissionOperatorTeamRosterManage, Scope: authorization.ScopeTenant},
				authorization.ScopedPermission{Permission: authorization.TenantPermissionRoleGrant, Scope: authorization.ScopeTenant},
			),
			assignment:  assignment,
			rosterEntry: entry,
		}
		service := serviceTestService(t, repository)
		entityTag := serviceTestRosterEntityTag(t, entry)

		err := service.RevokeRosterEntry(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID, serviceTestRosterID,
			RevokeRosterEntryInput{Reason: " Rotation ", ExpectedEntityTag: &entityTag, Audit: serviceTestAudit()},
		)
		if err != nil || repository.revokeRosterCalls != 1 ||
			repository.revokeRosterParams.AssignmentEpochID != serviceTestEpochID ||
			repository.revokeRosterParams.ExpectedEntityTag != entityTag {
			t.Fatalf("RevokeRosterEntry() error = %v; params = %#v", err, repository.revokeRosterParams)
		}
	})

	t.Run("revoke rejects a stale same-version representation tag", func(t *testing.T) {
		assignment := serviceTestAssignment(serviceTestEpochID, AssignmentStateActive)
		entry := serviceTestRosterEntry(serviceTestRosterID, assignment)
		stale := entry
		stale.Provenance.Reason = "Earlier representation"
		entityTag := serviceTestRosterEntityTag(t, stale)
		repository := &stubRepository{
			authority: serviceTestAuthority(
				authorization.ScopedPermission{Permission: authorization.TenantPermissionOperatorTeamRosterManage, Scope: authorization.ScopeTenant},
				authorization.ScopedPermission{Permission: authorization.TenantPermissionRoleGrant, Scope: authorization.ScopeTenant},
			),
			assignment:  assignment,
			rosterEntry: entry,
		}
		service := serviceTestService(t, repository)

		err := service.RevokeRosterEntry(
			context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID, serviceTestRosterID,
			RevokeRosterEntryInput{Reason: "Rotation", ExpectedEntityTag: &entityTag, Audit: serviceTestAudit()},
		)
		if !errors.Is(err, ErrPreconditionFailed) || repository.revokeRosterCalls != 0 {
			t.Fatalf("RevokeRosterEntry() error = %v, revoke calls = %d", err, repository.revokeRosterCalls)
		}
	})
}

func TestVersionedMutationsRequirePreconditions(t *testing.T) {
	repository := &stubRepository{}
	service := serviceTestService(t, repository)
	name := "New name"

	_, err := service.PatchOperatorTeam(
		context.Background(),
		serviceTestPlatformSession(authorization.PermissionPlatformOperatorTeamManage),
		serviceTestTeamID,
		PatchOperatorTeamInput{Name: &name, Audit: serviceTestAudit()},
	)
	if !errors.Is(err, ErrPreconditionRequired) || repository.getTeamCalls != 0 {
		t.Fatalf("PatchOperatorTeam() error = %v, get calls = %d", err, repository.getTeamCalls)
	}

	err = service.RevokeRosterEntry(
		context.Background(), serviceTestActor(), serviceTestTenantID, serviceTestTeamID, serviceTestEpochID, serviceTestRosterID,
		RevokeRosterEntryInput{Reason: "Rotation", Audit: serviceTestAudit()},
	)
	if !errors.Is(err, ErrPreconditionRequired) || repository.resolveCalls != 0 || repository.getRosterCalls != 0 {
		t.Fatalf("RevokeRosterEntry() error = %v, resolve calls = %d, get calls = %d", err, repository.resolveCalls, repository.getRosterCalls)
	}
}

func TestArchiveOperatorTeamRejectsUnsafeReasonBeforeRepository(t *testing.T) {
	repository := &stubRepository{}
	service := serviceTestService(t, repository)
	version := int64(1)

	err := service.ArchiveOperatorTeam(
		context.Background(),
		serviceTestPlatformSession(authorization.PermissionPlatformOperatorTeamManage),
		serviceTestTeamID,
		ArchiveOperatorTeamInput{Reason: "unsafe\nreason", ExpectedVersion: &version, Audit: serviceTestAudit()},
	)
	if !errors.Is(err, ErrInvalidInput) || repository.getTeamCalls != 0 || repository.archiveTeamCalls != 0 {
		t.Fatalf("ArchiveOperatorTeam() error = %v, get calls = %d, archive calls = %d", err, repository.getTeamCalls, repository.archiveTeamCalls)
	}
}

func serviceTestService(t *testing.T, repository *stubRepository) *Service {
	t.Helper()
	service, err := NewService(repository)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	service.now = func() time.Time { return serviceTestNow }
	service.newID = func() (uuid.UUID, error) { return serviceTestID(90), nil }
	return service
}

func serviceTestID(value int) uuid.UUID {
	return uuid.MustParse(fmt.Sprintf("00000000-0000-7000-8000-%012d", value))
}

func serviceTestAudit() authorization.AuditContext {
	return authorization.AuditContext{RequestID: serviceTestRequestID, UserAgent: "operator-team-test"}
}

func serviceTestPlatformSession(permissions ...authorization.Permission) authentication.Session {
	return authentication.Session{
		ID:                   serviceTestSessionID,
		User:                 authentication.User{ID: serviceTestUserID, DisplayName: "Platform admin"},
		Permissions:          permissions,
		AuthenticationMethod: "totp",
	}
}

func serviceTestActor() authorization.Actor {
	return authorization.Actor{
		UserID: serviceTestUserID, SessionID: serviceTestSessionID,
		ActiveTenantID: serviceTestTenantID, AuthenticationMethod: "totp",
	}
}

func serviceTestAuthority(permissions ...authorization.ScopedPermission) authorization.TenantAuthority {
	return authorization.TenantAuthority{
		TenantID:     serviceTestTenantID,
		Principal:    authorization.TenantPrincipal{ID: serviceTestUserID, Kind: authorization.PrincipalKindHuman},
		MembershipID: serviceTestMemberID, MembershipStatus: authorization.MembershipStatusActive,
		LegacyRole:  authorization.LegacyMembershipRoleTenantAdmin,
		Permissions: permissions, EvaluatedAt: serviceTestNow,
	}
}

func serviceTestTeamAuthority(permission authorization.TenantPermission) authorization.TenantAuthority {
	authority := serviceTestAuthority(authorization.ScopedPermission{Permission: permission, Scope: authorization.ScopeOperatorTeam})
	authority.OperatorTeamRelationships = []authorization.OperatorTeamRelationship{{
		OperatorTeamID: serviceTestTeamID, AssignmentEpochID: serviceTestEpochID,
	}}
	return authority
}

func serviceTestRosterReadAuthority() authorization.TenantAuthority {
	authority := serviceTestAuthority(
		authorization.ScopedPermission{Permission: authorization.TenantPermissionOperatorTeamRead, Scope: authorization.ScopeOperatorTeam},
		authorization.ScopedPermission{Permission: authorization.TenantPermissionUserRead, Scope: authorization.ScopeTenant},
	)
	authority.OperatorTeamRelationships = []authorization.OperatorTeamRelationship{{
		OperatorTeamID: serviceTestTeamID, AssignmentEpochID: serviceTestEpochID,
	}}
	return authority
}

func serviceTestTeam(id uuid.UUID) OperatorTeam {
	return OperatorTeam{
		OperatorTeamSummary: OperatorTeamSummary{ID: id, Key: "red_team", Name: "Red Team", State: OperatorTeamStateActive},
		Description:         "Incident responders", Version: 1,
		CreatedAt: serviceTestNow.Add(-24 * time.Hour), UpdatedAt: serviceTestNow.Add(-time.Hour),
	}
}

func serviceTestAssignment(epochID uuid.UUID, state AssignmentState) TenantAssignment {
	assignment := TenantAssignment{
		EpochID: epochID, TenantID: serviceTestTenantID,
		OperatorTeam: OperatorTeamSummary{ID: serviceTestTeamID, Key: "red_team", Name: "Red Team", State: OperatorTeamStateActive},
		State:        state, StartedAt: serviceTestNow.Add(-12 * time.Hour), StartedByUserID: serviceTestUserID,
		StartReason: "Tenant contract", Version: 1, UpdatedAt: serviceTestNow.Add(-time.Hour),
	}
	if state == AssignmentStateEnded {
		endedAt := serviceTestNow.Add(-2 * time.Hour)
		endedBy := serviceTestUserID
		reason := "Contract ended"
		assignment.EndedAt = &endedAt
		assignment.EndedByUserID = &endedBy
		assignment.EndReason = &reason
		assignment.Version = 2
	}
	return assignment
}

func serviceTestRosterEntry(id uuid.UUID, assignment TenantAssignment) RosterEntry {
	grantor := serviceTestUserID
	sourceID := serviceTestSourceID
	return RosterEntry{
		ID: id, TenantID: assignment.TenantID, AssignmentEpochID: assignment.EpochID,
		OperatorTeamID: assignment.OperatorTeam.ID,
		Member: TenantMember{
			MembershipID: serviceTestMemberID, UserID: serviceTestID(10),
			DisplayName: "Operator", Status: authorization.MembershipStatusActive,
		},
		Provenance: authorization.AuthorizationEdgeProvenance{
			SourceKind: authorization.AuthorizationSourceManual, SourceID: &sourceID,
			GrantedByUserID: &grantor, GrantedAt: serviceTestNow.Add(-time.Hour), Reason: "On-call",
		},
		State: RosterEntryStateActive, Version: 1, UpdatedAt: serviceTestNow,
		ManagedByOperatorTeamAPI: true,
	}
}

func serviceTestRosterEntityTag(t *testing.T, entry RosterEntry) string {
	t.Helper()
	entityTag, err := RosterEntryEntityTag(entry)
	if err != nil {
		t.Fatalf("RosterEntryEntityTag() error = %v", err)
	}
	return entityTag
}

type stubRepository struct {
	authority    authorization.TenantAuthority
	resolveErr   error
	resolveCalls int

	teams             []OperatorTeam
	team              OperatorTeam
	createTeamResult  IdempotentCreateResult[OperatorTeam]
	patchTeam         OperatorTeam
	listTeamsParams   ListOperatorTeamsParams
	createTeamParams  CreateOperatorTeamParams
	patchTeamParams   PatchOperatorTeamParams
	archiveTeamParams ArchiveOperatorTeamParams
	listTeamsCalls    int
	getTeamCalls      int
	archiveTeamCalls  int
	archiveTeamErr    error

	assignments           []TenantAssignment
	assignment            TenantAssignment
	startAssignmentResult IdempotentCreateResult[TenantAssignment]
	startAssignmentParams StartTenantAssignmentParams
	endAssignmentParams   EndTenantAssignmentParams
	getAssignmentCalls    int
	startAssignmentCalls  int
	endAssignmentCalls    int
	listAssignmentsCalls  int

	rosterEntries      []RosterEntry
	rosterEntry        RosterEntry
	addRosterResult    IdempotentCreateResult[RosterEntry]
	addRosterParams    AddRosterEntryParams
	revokeRosterParams RevokeRosterEntryParams
	getRosterCalls     int
	listRosterCalls    int
	addRosterCalls     int
	revokeRosterCalls  int
}

func (r *stubRepository) ResolveAuthority(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
	r.resolveCalls++
	return r.authority, r.resolveErr
}

func (r *stubRepository) ListOperatorTeams(_ context.Context, params ListOperatorTeamsParams) ([]OperatorTeam, error) {
	r.listTeamsCalls++
	r.listTeamsParams = params
	return r.teams, nil
}

func (r *stubRepository) GetOperatorTeam(context.Context, GetOperatorTeamParams) (OperatorTeam, error) {
	r.getTeamCalls++
	return r.team, nil
}

func (r *stubRepository) CreateOperatorTeam(_ context.Context, params CreateOperatorTeamParams) (IdempotentCreateResult[OperatorTeam], error) {
	r.createTeamParams = params
	return r.createTeamResult, nil
}

func (r *stubRepository) PatchOperatorTeam(_ context.Context, params PatchOperatorTeamParams) (OperatorTeam, error) {
	r.patchTeamParams = params
	return r.patchTeam, nil
}

func (r *stubRepository) ArchiveOperatorTeam(_ context.Context, params ArchiveOperatorTeamParams) error {
	r.archiveTeamCalls++
	r.archiveTeamParams = params
	return r.archiveTeamErr
}

func (r *stubRepository) ListTenantAssignments(context.Context, ListTenantAssignmentsParams) ([]TenantAssignment, error) {
	r.listAssignmentsCalls++
	return r.assignments, nil
}

func (r *stubRepository) GetTenantAssignment(context.Context, GetTenantAssignmentParams) (TenantAssignment, error) {
	r.getAssignmentCalls++
	return r.assignment, nil
}

func (r *stubRepository) StartTenantAssignment(_ context.Context, params StartTenantAssignmentParams) (IdempotentCreateResult[TenantAssignment], error) {
	r.startAssignmentCalls++
	r.startAssignmentParams = params
	return r.startAssignmentResult, nil
}

func (r *stubRepository) EndTenantAssignment(_ context.Context, params EndTenantAssignmentParams) error {
	r.endAssignmentCalls++
	r.endAssignmentParams = params
	return nil
}

func (r *stubRepository) ListRosterEntries(context.Context, ListRosterEntriesParams) ([]RosterEntry, error) {
	r.listRosterCalls++
	return r.rosterEntries, nil
}

func (r *stubRepository) GetRosterEntry(context.Context, GetRosterEntryParams) (RosterEntry, error) {
	r.getRosterCalls++
	return r.rosterEntry, nil
}

func (r *stubRepository) AddRosterEntry(_ context.Context, params AddRosterEntryParams) (IdempotentCreateResult[RosterEntry], error) {
	r.addRosterCalls++
	r.addRosterParams = params
	return r.addRosterResult, nil
}

func (r *stubRepository) RevokeRosterEntry(_ context.Context, params RevokeRosterEntryParams) error {
	r.revokeRosterCalls++
	r.revokeRosterParams = params
	return nil
}
