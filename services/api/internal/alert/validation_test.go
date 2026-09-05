package alert

import "testing"

func TestValidStoredTicketNumberSupportsConfiguredGrammar(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"ALT-2026-000001",
		"CAS-2026-000001",
		"IR_0042",
		"A1/2026/000000000001",
		"SECINC.9999.9999",
	} {
		if !validStoredTicketNumber(value) {
			t.Errorf("validStoredTicketNumber(%q) = false, want true", value)
		}
	}
}

func TestValidStoredTicketNumberRejectsUnsafeOrAmbiguousShapes(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"",
		"alt-2026-000001",
		"ALT-26-000001",
		"ALT-2026/000001",
		"ALT--000001",
		"ALT-2026-001",
		"ALT-2026-0000000000001",
		"ALT-2026-0000\n01",
		"ALT-2026-0000\u202e01",
		"1ALT-2026-000001",
		"TOO-LONG-PREFIX-2026-000001",
	} {
		if validStoredTicketNumber(value) {
			t.Errorf("validStoredTicketNumber(%q) = true, want false", value)
		}
	}
}
