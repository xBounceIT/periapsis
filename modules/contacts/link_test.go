package contacts

import "testing"

func TestTicketContactLinksPinEscalationProvenance(t *testing.T) {
	t.Parallel()
	tenant, alertID, caseID, contactID := testID(1), testID(2), testID(3), testID(4)
	provenance, err := NewEscalationProvenance(alertID, 17)
	if err != nil {
		t.Fatal(err)
	}
	link, err := NewTicketContactLink(testID(5), tenant, TicketCase, caseID, contactID,
		RoleEscalation, OriginEscalationCopy, &provenance, testInstant(8))
	if err != nil {
		t.Fatal(err)
	}
	if link.Provenance().SourceAlertVersion() != 17 || link.Origin() != OriginEscalationCopy {
		t.Fatalf("link = %s", link)
	}
	archived, err := ArchiveTicketContactLink(link, 1, testInstant(9))
	if err != nil {
		t.Fatal(err)
	}
	if archived.Version() != 2 || archived.ArchivedAt() == nil {
		t.Fatalf("archive = %s", archived)
	}
	if _, err := ArchiveTicketContactLink(archived, 2, testInstant(10)); err != ErrInvalidTarget {
		t.Fatalf("second archive error = %v", err)
	}
}

func TestTicketContactLinkRejectsAmbiguousOrigins(t *testing.T) {
	t.Parallel()
	tenant, alertID, contactID := testID(1), testID(2), testID(3)
	provenance, _ := NewEscalationProvenance(alertID, 1)
	for _, test := range []struct {
		kind       TicketKind
		origin     LinkOrigin
		provenance *EscalationProvenance
	}{
		{TicketAlert, OriginEscalationCopy, &provenance},
		{TicketCase, OriginEscalationCopy, nil},
		{TicketAlert, OriginManual, &provenance},
		{TicketKind(255), OriginManual, nil},
	} {
		if _, err := NewTicketContactLink(testID(4), tenant, test.kind, alertID, contactID,
			RolePrimary, test.origin, test.provenance, testInstant(8)); err != ErrInvalidTarget {
			t.Fatalf("shape %#v error = %v", test, err)
		}
	}
}

func TestCommentAuthorSnapshotIsClosedAndRedacted(t *testing.T) {
	t.Parallel()
	membership, user, contact := testID(1), testID(2), testID(3)
	customer, err := NewCommentAuthorSnapshot(AuthorCustomer, membership, user, &contact)
	if err != nil {
		t.Fatal(err)
	}
	if customer.ContactID() == nil || *customer.ContactID() != contact || customer.Audience() != AuthorCustomer {
		t.Fatalf("customer snapshot = %s", customer)
	}
	if _, err := NewCommentAuthorSnapshot(AuthorCustomer, membership, user, nil); err != ErrResolutionDenied {
		t.Fatalf("missing contact error = %v", err)
	}
	if _, err := NewCommentAuthorSnapshot(AuthorOperator, membership, user, &contact); err != ErrResolutionDenied {
		t.Fatalf("operator/contact mix error = %v", err)
	}
	if _, err := NewCommentAuthorSnapshot(AuthorAudience(255), membership, user, nil); err != ErrResolutionDenied {
		t.Fatalf("unknown audience error = %v", err)
	}
}
