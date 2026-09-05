package ticketing

import (
	"testing"
)

func fixtureID(sequence uint16) EntityID {
	var raw [16]byte
	raw[0] = byte(sequence >> 8)
	raw[1] = byte(sequence)
	for index := 2; index < len(raw); index++ {
		raw[index] = byte(index) ^ byte(sequence)
	}
	raw[6] = raw[6]&0x0f | 0x70
	raw[8] = raw[8]&0x3f | 0x80
	id, err := NewEntityID(raw)
	if err != nil {
		panic(err)
	}
	return id
}

func mustKey(t testing.TB, value string) Key {
	t.Helper()
	key, err := NewKey(value)
	if err != nil {
		t.Fatalf("NewKey(%q): %v", value, err)
	}
	return key
}

func mustEffects(t testing.TB, optional ...Effect) EffectPlan {
	t.Helper()
	effects := []Effect{EffectActivity, EffectAudit}
	effects = append(effects, optional...)
	plan, err := NewEffectPlan(effects...)
	if err != nil {
		t.Fatalf("NewEffectPlan: %v", err)
	}
	return plan
}

func mustStateAction(t testing.TB, action Action, effects EffectPlan) StateAction {
	t.Helper()
	result, err := NewStateAction(action, effects)
	if err != nil {
		t.Fatalf("NewStateAction(%s): %v", action, err)
	}
	return result
}

func alertWorkflowFixture(t testing.TB) WorkflowDefinition {
	t.Helper()
	basic := mustEffects(t)
	full := mustEffects(t, EffectSLA, EffectNotification)
	newKey := mustKey(t, "new")
	triageKey := mustKey(t, "triage")
	closedKey := mustKey(t, "closed")
	newState, err := NewStateDefinition(newKey, true, false, VisibilityCustomer, []StateAction{
		mustStateAction(t, ActionTransfer, full),
		mustStateAction(t, ActionCreate, basic),
		mustStateAction(t, ActionEscalate, full),
		mustStateAction(t, ActionRelease, full),
		mustStateAction(t, ActionClaim, full),
		mustStateAction(t, ActionAssign, full),
	})
	if err != nil {
		t.Fatal(err)
	}
	triageState, err := NewStateDefinition(triageKey, false, false, VisibilityInternal, []StateAction{
		mustStateAction(t, ActionAssign, full),
		mustStateAction(t, ActionClaim, full),
		mustStateAction(t, ActionRelease, full),
		mustStateAction(t, ActionTransfer, full),
		mustStateAction(t, ActionEscalate, full),
	})
	if err != nil {
		t.Fatal(err)
	}
	closedState, err := NewStateDefinition(closedKey, false, true, VisibilityCustomer, nil)
	if err != nil {
		t.Fatal(err)
	}
	senior := mustKey(t, "senior_analyst")
	classification := mustKey(t, "classification")
	toTriage, err := NewTransitionDefinition(
		mustKey(t, "new_to_triage"),
		newKey,
		triageKey,
		true,
		false,
		[]Key{senior},
		[]Permission{PermissionAlertUpdate},
		[]Key{classification},
		full,
	)
	if err != nil {
		t.Fatal(err)
	}
	toClosed, err := NewTransitionDefinition(
		mustKey(t, "triage_to_closed"), triageKey, closedKey, true, false, nil, nil, nil, full,
	)
	if err != nil {
		t.Fatal(err)
	}
	reopen, err := NewTransitionDefinition(
		mustKey(t, "reopen_triage"), closedKey, triageKey, true, true, []Key{senior}, nil, nil, full,
	)
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := NewWorkflowDefinition(
		fixtureID(10),
		AggregateAlert,
		3,
		[]StateDefinition{triageState, closedState, newState},
		[]TransitionDefinition{reopen, toClosed, toTriage},
	)
	if err != nil {
		t.Fatalf("NewWorkflowDefinition(alert): %v", err)
	}
	return workflow
}

func caseWorkflowFixture(t testing.TB) WorkflowDefinition {
	t.Helper()
	basic := mustEffects(t)
	full := mustEffects(t, EffectSLA, EffectNotification)
	openKey := mustKey(t, "open")
	closedKey := mustKey(t, "closed")
	openState, err := NewStateDefinition(openKey, true, false, VisibilityCustomer, []StateAction{
		mustStateAction(t, ActionCreate, basic),
		mustStateAction(t, ActionAssign, full),
		mustStateAction(t, ActionClaim, full),
		mustStateAction(t, ActionRelease, full),
		mustStateAction(t, ActionTransfer, full),
		mustStateAction(t, ActionLink, full),
	})
	if err != nil {
		t.Fatal(err)
	}
	closedState, err := NewStateDefinition(closedKey, false, true, VisibilityInternal, nil)
	if err != nil {
		t.Fatal(err)
	}
	closeTransition, err := NewTransitionDefinition(
		mustKey(t, "close_case"), openKey, closedKey, true, false, nil, []Permission{PermissionCaseUpdate}, nil, full,
	)
	if err != nil {
		t.Fatal(err)
	}
	reopen, err := NewTransitionDefinition(mustKey(t, "reopen_case"), closedKey, openKey, true, true, nil, nil, nil, full)
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := NewWorkflowDefinition(
		fixtureID(11),
		AggregateCase,
		7,
		[]StateDefinition{closedState, openState},
		[]TransitionDefinition{reopen, closeTransition},
	)
	if err != nil {
		t.Fatalf("NewWorkflowDefinition(case): %v", err)
	}
	return workflow
}

func authorityFixture(t testing.TB, actor EntityID) AuthorizationSnapshot {
	t.Helper()
	pairOne, err := NewRosterPair(fixtureID(201), actor)
	if err != nil {
		t.Fatal(err)
	}
	pairTwo, err := NewRosterPair(fixtureID(202), actor)
	if err != nil {
		t.Fatal(err)
	}
	other := fixtureID(102)
	if actor == other {
		other = fixtureID(103)
	}
	pairOther, err := NewRosterPair(fixtureID(202), other)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthorizationSnapshot(
		fixtureID(1),
		actor,
		PrincipalOperator,
		true,
		[]Key{mustKey(t, "senior_analyst")},
		knownPermissions[:],
		[]EntityID{fixtureID(202), fixtureID(201)},
		[]EntityID{fixtureID(202), fixtureID(201)},
		[]RosterPair{pairOther, pairTwo, pairOne},
	)
	if err != nil {
		t.Fatalf("NewAuthorizationSnapshot: %v", err)
	}
	return authority
}

func authorityFrom(
	t testing.TB,
	base AuthorizationSnapshot,
	principal PrincipalKind,
	tenantAccess bool,
	roles []Key,
	permissions []Permission,
	claimTeams []EntityID,
	manageTeams []EntityID,
	roster []RosterPair,
) AuthorizationSnapshot {
	t.Helper()
	authority, err := NewAuthorizationSnapshot(
		base.Tenant(),
		base.Actor(),
		principal,
		tenantAccess,
		roles,
		permissions,
		claimTeams,
		manageTeams,
		roster,
	)
	if err != nil {
		t.Fatalf("NewAuthorizationSnapshot: %v", err)
	}
	return authority
}

func mustTicket(
	t testing.TB,
	workflow WorkflowDefinition,
	id EntityID,
	state string,
	version uint64,
	customerVisible bool,
	assignment Assignment,
) TicketSnapshot {
	t.Helper()
	ticket, err := NewTicketSnapshot(
		workflow,
		fixtureID(1),
		id,
		mustKey(t, state),
		version,
		customerVisible,
		assignment,
	)
	if err != nil {
		t.Fatalf("NewTicketSnapshot: %v", err)
	}
	return ticket
}
