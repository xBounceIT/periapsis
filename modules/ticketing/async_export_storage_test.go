package ticketing

import "testing"

func TestTicketExportArtifactObjectKeysAreCanonicalAndFailClosed(t *testing.T) {
	tenantID := storageTestEntityID(t, 211)
	jobID := storageTestEntityID(t, 212)
	artifactID := storageTestEntityID(t, 213)
	temporary, final, err := TicketExportArtifactObjectKeys(tenantID, jobID, artifactID)
	if err != nil {
		t.Fatal(err)
	}
	base := "ticket-exports/v1/" + tenantID.String() + "/" + jobID.String()
	if temporary != base+"/temporary/"+artifactID.String()+".csv" ||
		final != base+"/artifacts/"+artifactID.String()+".csv" {
		t.Fatalf("object keys = (%q, %q)", temporary, final)
	}
	if _, _, err := TicketExportArtifactObjectKeys(EntityID{}, jobID, artifactID); err == nil {
		t.Fatal("zero tenant ID produced an object key")
	}
}

func storageTestEntityID(t *testing.T, suffix byte) EntityID {
	t.Helper()
	value := [16]byte{0x01, 0x9b, 0x11, 0x22, 0x33, 0x44, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, suffix}
	id, err := NewEntityID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
