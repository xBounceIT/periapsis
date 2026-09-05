package ticketing

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func FuzzNewKeyCanonicalASCII(f *testing.F) {
	for _, seed := range []string{
		"valid_key",
		"status.closed",
		"a",
		"",
		"UPPER",
		"équipe",
		"a/b",
		"a\x00b",
		strings.Repeat("a", maxKeyBytes+1),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		key, err := NewKey(input)
		if err != nil {
			return
		}
		if key.String() != input || !validKey(input) || len(input) == 0 || len(input) > maxKeyBytes {
			t.Fatalf("accepted noncanonical key %q", input)
		}
	})
}

func FuzzCommentDraftRejectsUnsafeTextAndRedacts(f *testing.F) {
	for _, seed := range []string{
		"ordinary Markdown **body**",
		"<img src=x onerror=alert(1)>",
		"line one\nline two",
		"embedded\x00nul",
		"\u202eevil.txt",
		" javascript:alert(1) ",
		string([]byte{0xff, 0xfe}),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		comment, err := NewCommentDraft(PrincipalOperator, CommentPrivate, input)
		if err != nil {
			return
		}
		if !utf8.ValidString(input) || strings.TrimSpace(input) != input || strings.ContainsAny(input, "<>") {
			t.Fatalf("accepted unsafe comment %q", input)
		}
		for _, character := range input {
			if character != '\n' && character != '\t' &&
				(unicode.IsControl(character) || isDirectionalControl(character)) {
				t.Fatalf("accepted unsafe character %U", character)
			}
		}
		rendered := fmt.Sprint(comment)
		if len(input) >= 8 && strings.Contains(rendered, input) || !strings.Contains(rendered, "REDACTED") {
			t.Fatalf("comment formatting leaked input: %q", rendered)
		}
	})
}

func FuzzPrivateCommentProjectionNeverFailsOpen(f *testing.F) {
	workflow := alertWorkflowFixture(f)
	ticket := mustTicket(f, workflow, fixtureID(301), "new", 1, true, Assignment{})
	for _, seed := range []uint8{0, 1, 2, 3, 4, 5, 6, 7, 127, 255} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw uint8) {
		channel := ProjectionChannel(raw)
		allowed := CanProjectComment(workflow, ticket, CommentPrivate, channel)
		if allowed != (channel == ProjectionOperator) {
			t.Fatalf("private projection for channel %d = %t", raw, allowed)
		}
	})
}

func FuzzClosedEnumsNeverAdmitUnknownValues(f *testing.F) {
	for _, seed := range []uint8{0, 1, 2, 4, 12, 14, 15, 127, 255} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw uint8) {
		permission := Permission(raw)
		if validPermission(permission) != (raw >= uint8(PermissionAlertCreate) && raw <= uint8(PermissionPortalCommentPublic)) {
			t.Fatalf("permission closure mismatch for %d", raw)
		}
		if raw > uint8(PermissionPortalCommentPublic) || raw == 0 {
			if _, err := ParsePermission(permission.String()); err == nil {
				t.Fatalf("unknown permission %d round-tripped", raw)
			}
		}
	})
}

func FuzzTransitionKeyAndTargetMustMatchThePinnedEdge(f *testing.F) {
	workflow := alertWorkflowFixture(f)
	ticket := mustTicket(f, workflow, fixtureID(301), "new", 4, true, Assignment{})
	authority := authorityFixture(f, fixtureID(101))
	comment, err := NewCommentDraft(PrincipalOperator, CommentPrivate, "Required reason")
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][2]string{
		{"new_to_triage", "triage"},
		{"new_to_triage", "closed"},
		{"triage_to_closed", "closed"},
		{"unknown_transition", "triage"},
		{"", "triage"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, transitionValue, targetValue string) {
		transition, transitionErr := NewKey(transitionValue)
		target, targetErr := NewKey(targetValue)
		if transitionErr != nil || targetErr != nil {
			return
		}
		command, commandErr := NewTransitionCommand(
			ticket.Tenant(), ticket.ID(), ticket.Version(), transition, target, &comment,
			[]Key{mustKey(t, "classification")},
		)
		if commandErr != nil {
			return
		}
		decision := PlanTransition(workflow, ticket, command, authority)
		_, allowed := decision.Plan()
		wantAllowed := transitionValue == "new_to_triage" && targetValue == "triage"
		if allowed != wantAllowed {
			t.Fatalf("transition %q to %q allowed=%t, want %t (%s)", transitionValue, targetValue, allowed, wantAllowed, decision)
		}
	})
}
