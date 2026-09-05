package ticketing

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestExplicitTicketBulkSelectionIsCanonicalAndVersionPinned(t *testing.T) {
	first, err := NewTicketBulkTargetPin(fixtureID(100), 8)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewTicketBulkTargetPin(fixtureID(101), 3)
	if err != nil {
		t.Fatal(err)
	}

	selection, err := NewExplicitTicketBulkSelection([]TicketBulkTargetPin{second, first})
	if err != nil {
		t.Fatal(err)
	}
	targets := selection.ExplicitTargets()
	if selection.Source() != TicketBulkSelectionExplicit || selection.TargetCount() != 2 ||
		len(targets) != 2 || targets[0] != first || targets[1] != second ||
		selection.TargetSetDigest() == ([32]byte{}) || selection.QueryDigest() != ([32]byte{}) ||
		selection.SavedView() != nil {
		t.Fatalf("selection = %#v, targets = %#v", selection, targets)
	}

	reordered, err := NewExplicitTicketBulkSelection([]TicketBulkTargetPin{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if reordered.TargetSetDigest() != selection.TargetSetDigest() {
		t.Fatal("canonical target digest depends on caller order")
	}

	targets[0] = second
	if selection.ExplicitTargets()[0] != first {
		t.Fatal("explicit targets escaped by reference")
	}

	differentVersion, _ := NewTicketBulkTargetPin(first.ID(), first.Version()+1)
	differentSelection, err := NewExplicitTicketBulkSelection([]TicketBulkTargetPin{differentVersion, second})
	if err != nil {
		t.Fatal(err)
	}
	if differentSelection.TargetSetDigest() == selection.TargetSetDigest() {
		t.Fatal("target digest did not bind the selected version")
	}
}

func TestTicketBulkSelectionRejectsAmbiguousOrUnboundedTargets(t *testing.T) {
	target, _ := NewTicketBulkTargetPin(fixtureID(110), 2)
	otherVersion, _ := NewTicketBulkTargetPin(target.ID(), 3)
	if _, err := NewExplicitTicketBulkSelection(nil); !errors.Is(err, ErrInvalidTicketBulkOperation) {
		t.Fatalf("empty selection error = %v", err)
	}
	if _, err := NewExplicitTicketBulkSelection([]TicketBulkTargetPin{target, otherVersion}); !errors.Is(err, ErrInvalidTicketBulkOperation) {
		t.Fatalf("duplicate ticket error = %v", err)
	}

	tooMany := make([]TicketBulkTargetPin, TicketBulkMaximumExplicitRows+1)
	for index := range tooMany {
		pin, err := NewTicketBulkTargetPin(fixtureID(uint16(1_000+index)), 1)
		if err != nil {
			t.Fatal(err)
		}
		tooMany[index] = pin
	}
	if _, err := NewExplicitTicketBulkSelection(tooMany); !errors.Is(err, ErrInvalidTicketBulkOperation) {
		t.Fatalf("oversized selection error = %v", err)
	}

	if _, err := NewTicketBulkTargetPin(EntityID{}, 1); !errors.Is(err, ErrInvalidTicketBulkOperation) {
		t.Fatalf("invalid ID error = %v", err)
	}
	if _, err := NewTicketBulkTargetPin(fixtureID(111), 0); !errors.Is(err, ErrInvalidTicketBulkOperation) {
		t.Fatalf("zero version error = %v", err)
	}
}

func TestQueryTicketBulkSelectionPinsEffectiveQueryAndSavedView(t *testing.T) {
	view, err := NewTicketBulkSavedViewPin(fixtureID(120), fixtureID(121), 7, [32]byte{3})
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewQueryTicketBulkSelection([32]byte{1}, [32]byte{2}, 100_000, &view)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Source() != TicketBulkSelectionQuery || selection.TargetCount() != 100_000 ||
		selection.QueryDigest() != ([32]byte{1}) || selection.TargetSetDigest() != ([32]byte{2}) ||
		selection.ExplicitTargets() != nil || selection.SavedView() == nil || *selection.SavedView() != view {
		t.Fatalf("selection = %#v", selection)
	}

	returned := selection.SavedView()
	*returned = TicketBulkSavedViewPin{}
	if selection.SavedView() == nil || *selection.SavedView() != view {
		t.Fatal("saved-view pin escaped by reference")
	}

	for _, test := range []struct {
		name      string
		query     [32]byte
		targets   [32]byte
		count     uint32
		savedView *TicketBulkSavedViewPin
	}{
		{name: "zero query", targets: [32]byte{2}, count: 1},
		{name: "zero target set", query: [32]byte{1}, count: 1},
		{name: "empty", query: [32]byte{1}, targets: [32]byte{2}},
		{name: "too many", query: [32]byte{1}, targets: [32]byte{2}, count: TicketBulkMaximumTargets + 1},
		{name: "invalid view", query: [32]byte{1}, targets: [32]byte{2}, count: 1, savedView: &TicketBulkSavedViewPin{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewQueryTicketBulkSelection(test.query, test.targets, test.count, test.savedView); !errors.Is(err, ErrInvalidTicketBulkOperation) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestTicketBulkMutationsExpandThroughSingleTicketCommands(t *testing.T) {
	tenant := fixtureID(130)
	target, _ := NewTicketBulkTargetPin(fixtureID(131), 11)
	team := fixtureID(132)
	assignee := fixtureID(133)

	transition, err := NewTicketBulkTransition(mustKey(t, "triage_to_closed"), mustKey(t, "closed"))
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := NewTicketBulkAssignment(team, &assignee)
	if err != nil {
		t.Fatal(err)
	}
	transfer, err := NewTicketBulkTransfer(team, nil)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := NewTicketBulkClaim(team)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name     string
		mutation TicketBulkMutation
		action   Action
		assert   func(testing.TB, TicketBulkCommand)
	}{
		{
			name: "transition", mutation: transition, action: ActionTransition,
			assert: func(t testing.TB, command TicketBulkCommand) {
				value, ok := command.TransitionCommand()
				if !ok || value.target.tenant != tenant || value.target.ticket != target.ID() ||
					value.target.expectedVersion != target.Version() || value.transition != mustKey(t, "triage_to_closed") ||
					value.to != mustKey(t, "closed") || value.comment != nil || len(value.providedCustomFields) != 0 {
					t.Fatalf("transition command = %#v", value)
				}
			},
		},
		{
			name: "assign", mutation: assignment, action: ActionAssign,
			assert: func(t testing.TB, command TicketBulkCommand) {
				value, ok := command.AssignCommand()
				if !ok || value.target.expectedVersion != 11 || !value.hasAssignee || value.assignee != assignee {
					t.Fatalf("assign command = %#v", value)
				}
			},
		},
		{
			name: "transfer", mutation: transfer, action: ActionTransfer,
			assert: func(t testing.TB, command TicketBulkCommand) {
				value, ok := command.TransferCommand()
				if !ok || value.target.expectedVersion != 11 || value.hasAssignee || value.team != team {
					t.Fatalf("transfer command = %#v", value)
				}
			},
		},
		{
			name: "claim", mutation: claim, action: ActionClaim,
			assert: func(t testing.TB, command TicketBulkCommand) {
				value, ok := command.ClaimCommand()
				if !ok || value.target.expectedVersion != 11 || value.team != team {
					t.Fatalf("claim command = %#v", value)
				}
			},
		},
		{
			name: "release", mutation: NewTicketBulkRelease(), action: ActionRelease,
			assert: func(t testing.TB, command TicketBulkCommand) {
				value, ok := command.ReleaseCommand()
				if !ok || value.target.expectedVersion != 11 {
					t.Fatalf("release command = %#v", value)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			command, err := test.mutation.CommandFor(tenant, target)
			if err != nil {
				t.Fatal(err)
			}
			if command.Action() != test.action {
				t.Fatalf("action = %s", command.Action())
			}
			test.assert(t, command)
		})
	}
}

func TestTicketBulkDefinitionBindsOwnerKindPermissionAndProjection(t *testing.T) {
	target, _ := NewTicketBulkTargetPin(fixtureID(140), 4)
	selection, _ := NewExplicitTicketBulkSelection([]TicketBulkTargetPin{target})
	mutation, _ := NewTicketBulkAssignment(fixtureID(141), nil)
	input := TicketBulkDefinitionInput{
		ID: fixtureID(142), Tenant: fixtureID(143), Requester: fixtureID(144),
		OwnerMembership: fixtureID(145), Kind: AggregateCase,
		Selection: selection, Mutation: mutation,
		ProjectionVersion: TicketBulkProjectionVersion, MaximumAttempts: TicketBulkMaximumAttempts,
	}
	definition, err := NewTicketBulkDefinition(input)
	if err != nil {
		t.Fatal(err)
	}
	if definition.RequiredPermission() != PermissionCaseTransfer || definition.Selection().TargetCount() != 1 ||
		definition.Mutation().Action() != ActionAssign || ValidateTicketBulkDefinition(definition) != nil {
		t.Fatalf("definition = %#v", definition)
	}

	view, _ := NewTicketBulkSavedViewPin(fixtureID(146), fixtureID(147), 1, [32]byte{4})
	query, _ := NewQueryTicketBulkSelection([32]byte{1}, [32]byte{2}, 1, &view)
	input.Selection = query
	if _, err := NewTicketBulkDefinition(input); !errors.Is(err, ErrInvalidTicketBulkOperation) {
		t.Fatalf("foreign view owner error = %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*TicketBulkDefinitionInput)
	}{
		{name: "unknown kind", mutate: func(value *TicketBulkDefinitionInput) { value.Kind = 0 }},
		{name: "unknown projection", mutate: func(value *TicketBulkDefinitionInput) { value.ProjectionVersion++ }},
		{name: "zero attempts", mutate: func(value *TicketBulkDefinitionInput) { value.MaximumAttempts = 0 }},
		{name: "too many attempts", mutate: func(value *TicketBulkDefinitionInput) { value.MaximumAttempts++ }},
		{name: "invalid selection", mutate: func(value *TicketBulkDefinitionInput) { value.Selection = TicketBulkSelection{} }},
		{name: "invalid mutation", mutate: func(value *TicketBulkDefinitionInput) { value.Mutation = TicketBulkMutation{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := input
			candidate.Selection = selection
			test.mutate(&candidate)
			if _, err := NewTicketBulkDefinition(candidate); !errors.Is(err, ErrInvalidTicketBulkOperation) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestTicketBulkDiagnosticsAreBoundedAndRedacted(t *testing.T) {
	target, _ := NewTicketBulkTargetPin(fixtureID(150), 3)
	selection, _ := NewExplicitTicketBulkSelection([]TicketBulkTargetPin{target})
	mutation, _ := NewTicketBulkAssignment(fixtureID(151), entityPointer(fixtureID(152)))
	input := TicketBulkDefinitionInput{
		ID: fixtureID(153), Tenant: fixtureID(154), Requester: fixtureID(155),
		OwnerMembership: fixtureID(156), Kind: AggregateAlert,
		Selection: selection, Mutation: mutation,
		ProjectionVersion: TicketBulkProjectionVersion, MaximumAttempts: 2,
	}
	definition, _ := NewTicketBulkDefinition(input)
	values := []string{
		fmt.Sprintf("%v", target), fmt.Sprintf("%#v", target),
		fmt.Sprintf("%v", selection), fmt.Sprintf("%#v", selection),
		fmt.Sprintf("%v", mutation), fmt.Sprintf("%#v", mutation),
		fmt.Sprintf("%v", input), fmt.Sprintf("%#v", input),
		fmt.Sprintf("%v", definition), fmt.Sprintf("%#v", definition),
	}
	for _, value := range values {
		for _, secret := range []string{
			target.ID().String(), fixtureID(151).String(), fixtureID(152).String(),
			definition.ID().String(), definition.Tenant().String(), definition.Requester().String(),
			definition.OwnerMembership().String(),
		} {
			if strings.Contains(value, secret) {
				t.Fatalf("diagnostic %q exposed %q", value, secret)
			}
		}
	}
}

func FuzzExplicitTicketBulkSelectionCanonicalDigest(f *testing.F) {
	f.Add(uint16(1), uint16(2), uint64(1), uint64(2), false)
	f.Add(uint16(9), uint16(9), uint64(4), uint64(5), true)
	f.Fuzz(func(t *testing.T, leftSequence, rightSequence uint16, leftVersion, rightVersion uint64, reverse bool) {
		left, leftErr := NewTicketBulkTargetPin(fixtureID(leftSequence), leftVersion)
		right, rightErr := NewTicketBulkTargetPin(fixtureID(rightSequence), rightVersion)
		if leftErr != nil || rightErr != nil {
			return
		}
		ordered := []TicketBulkTargetPin{left, right}
		if reverse {
			ordered[0], ordered[1] = ordered[1], ordered[0]
		}
		selection, err := NewExplicitTicketBulkSelection(ordered)
		if left.ID() == right.ID() {
			if !errors.Is(err, ErrInvalidTicketBulkOperation) {
				t.Fatalf("duplicate target error = %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		reordered, err := NewExplicitTicketBulkSelection([]TicketBulkTargetPin{right, left})
		if err != nil {
			t.Fatal(err)
		}
		if selection.TargetSetDigest() != reordered.TargetSetDigest() ||
			!validTicketBulkSelection(selection) {
			t.Fatalf("canonical selection drift: %#v %#v", selection, reordered)
		}
	})
}
