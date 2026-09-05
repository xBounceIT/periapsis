package operatorteam

import "testing"

func TestRosterEntryEntityTagExcludesRepositoryOwnership(t *testing.T) {
	assignment := serviceTestAssignment(serviceTestEpochID, AssignmentStateActive)
	entry := serviceTestRosterEntry(serviceTestRosterID, assignment)
	managed, err := RosterEntryEntityTag(entry)
	if err != nil {
		t.Fatalf("managed entity tag: %v", err)
	}
	entry.ManagedByOperatorTeamAPI = false
	unmanaged, err := RosterEntryEntityTag(entry)
	if err != nil {
		t.Fatalf("unmanaged entity tag: %v", err)
	}
	if managed != unmanaged {
		t.Fatalf("repository-only ownership changed public entity tag: %q != %q", managed, unmanaged)
	}
}
