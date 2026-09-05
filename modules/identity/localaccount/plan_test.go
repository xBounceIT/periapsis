package localaccount

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

var localTestNow = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func TestInvitePlanCreatesNoCredentialOrTokenMaterial(t *testing.T) {
	snapshot := Snapshot{}
	command := validCommandFor(ActionInvite, 0)
	command.NewAccountID = localID(1)
	command.NewUserID = localID(2)
	plan, err := BuildPlan(snapshot, RecoveryFleet{}, command)
	if err != nil {
		t.Fatal(err)
	}
	if plan.From != StatusAbsent || plan.To != StatusInvited || plan.NextRevision != 1 ||
		plan.NextIdentityEpoch != 1 || !plan.IssueInvitation || plan.IssueRecoveryContinuation ||
		plan.AccountID != command.NewAccountID || plan.UserID != command.NewUserID ||
		plan.Audit != AuditInvited {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestActivateRequiresVerifiedIdentifierCredentialAndFactor(t *testing.T) {
	snapshot := readySnapshot(StatusInvited)
	command := validCommandFor(ActionActivate, snapshot.Revision)
	plan, err := BuildPlan(snapshot, RecoveryFleet{}, command)
	if err != nil {
		t.Fatal(err)
	}
	if plan.To != StatusActive || plan.NextIdentityEpoch != snapshot.IdentityEpoch+1 ||
		!plan.RetireChallenges || plan.RevokeSessions {
		t.Fatalf("plan = %#v", plan)
	}

	for name, mutate := range map[string]func(*Snapshot){
		"identifier pending": func(value *Snapshot) { value.LoginIdentifier = LoginIdentifierPending },
		"credential pending": func(value *Snapshot) { value.Credential = CredentialPending },
		"no factor":          func(value *Snapshot) { value.ConfirmedAcceptableFactors = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := snapshot
			mutate(&invalid)
			if _, invalidErr := BuildPlan(invalid, RecoveryFleet{}, command); invalidErr == nil {
				t.Fatal("activation prerequisite was bypassed")
			}
		})
	}
	unauthorized := command
	unauthorized.FreshLocalMFA = false
	if _, err := BuildPlan(snapshot, RecoveryFleet{}, unauthorized); err == nil {
		t.Fatal("activation without fresh factor proof was planned")
	}
}

func TestDisableAndRecoverPreserveLastRecoveryPrincipal(t *testing.T) {
	for _, action := range []Action{ActionDisable, ActionRecover} {
		t.Run(fmt.Sprint(action), func(t *testing.T) {
			snapshot := readySnapshot(StatusActive)
			snapshot.ProtectedRecoveryPrincipal = true
			command := validCommandFor(action, snapshot.Revision)
			fleet := RecoveryFleet{CurrentPrincipalReady: true}
			if _, err := BuildPlan(snapshot, fleet, command); err == nil {
				t.Fatal("last recovery principal was removable")
			}
			fleet.OtherReadyHumanPrincipals = 1
			plan, err := BuildPlan(snapshot, fleet, command)
			if err != nil {
				t.Fatal(err)
			}
			if !plan.RevokeSessions || !plan.RetireChallenges || !plan.RecheckRecoveryFloor {
				t.Fatalf("missing consequences: %#v", plan)
			}
			if action == ActionDisable && !plan.DisableCredential {
				t.Fatalf("disable did not disable the credential: %#v", plan)
			}
			if action == ActionRecover && (!plan.IssueRecoveryContinuation || !plan.RotateCredential ||
				!plan.RevokeFactors || !plan.RetireRecoverySets || plan.To != StatusRecoveryRestricted) {
				t.Fatalf("incomplete recovery plan: %#v", plan)
			}
		})
	}
}

func TestEnableRequiresDisabledCredentialAndReadyFactor(t *testing.T) {
	snapshot := readySnapshot(StatusDisabled)
	snapshot.Credential = CredentialDisabled
	plan, err := BuildPlan(snapshot, RecoveryFleet{}, validCommandFor(ActionEnable, snapshot.Revision))
	if err != nil {
		t.Fatal(err)
	}
	if plan.From != StatusDisabled || plan.To != StatusActive || !plan.EnableCredential ||
		plan.DisableCredential || plan.RotateCredential || plan.RevokeSessions ||
		!plan.RetireChallenges || !plan.RecheckRecoveryFloor || plan.Audit != AuditEnabled {
		t.Fatalf("plan = %#v", plan)
	}

	for name, mutate := range map[string]func(*Snapshot){
		"credential already active": func(value *Snapshot) { value.Credential = CredentialActive },
		"identifier disabled":       func(value *Snapshot) { value.LoginIdentifier = LoginIdentifierDisabled },
		"factor unavailable":        func(value *Snapshot) { value.ConfirmedAcceptableFactors = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := snapshot
			mutate(&invalid)
			if _, invalidErr := BuildPlan(invalid, RecoveryFleet{}, validCommandFor(ActionEnable, invalid.Revision)); invalidErr == nil {
				t.Fatal("unsafe enable was planned")
			}
		})
	}
}

func TestPasswordRotationKeepsAccountActiveAndRevokesOldSessions(t *testing.T) {
	snapshot := readySnapshot(StatusActive)
	plan, err := BuildPlan(snapshot, RecoveryFleet{}, validCommandFor(ActionRotatePassword, snapshot.Revision))
	if err != nil {
		t.Fatal(err)
	}
	if plan.From != StatusActive || plan.To != StatusActive || !plan.RotateCredential ||
		!plan.RevokeSessions || !plan.RetireChallenges || !plan.RecheckRecoveryFloor ||
		plan.EnableCredential || plan.DisableCredential || plan.Audit != AuditPasswordRotated {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestRecoveryFleetCannotHideTheCurrentReadyProtectedPrincipal(t *testing.T) {
	snapshot := readySnapshot(StatusActive)
	snapshot.ProtectedRecoveryPrincipal = true
	command := validCommandFor(ActionDisable, snapshot.Revision)
	if _, err := BuildPlan(snapshot, RecoveryFleet{OtherReadyHumanPrincipals: 1}, command); err == nil {
		t.Fatal("inconsistent recovery-fleet projection was accepted")
	}
	if _, err := BuildPlan(snapshot, RecoveryFleet{
		CurrentPrincipalReady: true, OtherReadyHumanPrincipals: 1,
	}, command); err != nil {
		t.Fatalf("exact recovery fleet was rejected: %v", err)
	}
}

func TestRecoveryActivationRevokesOldRestrictedSessions(t *testing.T) {
	snapshot := readySnapshot(StatusRecoveryRestricted)
	plan, err := BuildPlan(snapshot, RecoveryFleet{}, validCommandFor(ActionActivate, snapshot.Revision))
	if err != nil {
		t.Fatal(err)
	}
	if plan.To != StatusActive || !plan.RevokeSessions || !plan.RetireChallenges {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestPlansArePureAndRejectStaleOrUnauthorizedCommands(t *testing.T) {
	snapshot := readySnapshot(StatusActive)
	original := snapshot
	command := validCommandFor(ActionDisable, snapshot.Revision)
	for name, mutate := range map[string]func(*Command){
		"stale revision": func(value *Command) { value.ExpectedRevision-- },
		"no local MFA":   func(value *Command) { value.FreshLocalMFA = false },
		"unprotected":    func(value *Command) { value.ProtectedWorkflow = false },
		"blank reason":   func(value *Command) { value.Reason = "" },
		"control reason": func(value *Command) { value.Reason = "bad\nreason" },
		"new IDs": func(value *Command) {
			value.NewAccountID = localID(9)
			value.NewUserID = localID(10)
		},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := command
			mutate(&invalid)
			if _, err := BuildPlan(snapshot, RecoveryFleet{OtherReadyHumanPrincipals: 1}, invalid); err == nil {
				t.Fatal("invalid command was planned")
			}
		})
	}
	if !reflect.DeepEqual(snapshot, original) {
		t.Fatal("pure planner mutated its input")
	}
}

func TestLifecycleRejectsInvalidSourceStatesAndVersionOverflow(t *testing.T) {
	tests := []struct {
		status Status
		action Action
	}{
		{StatusAbsent, ActionActivate},
		{StatusInvited, ActionDisable},
		{StatusDisabled, ActionActivate},
		{StatusRecoveryRestricted, ActionRecover},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%d_to_%d", test.status, test.action), func(t *testing.T) {
			var snapshot Snapshot
			if test.status != StatusAbsent {
				snapshot = readySnapshot(test.status)
			}
			command := validCommandFor(test.action, snapshot.Revision)
			if _, err := BuildPlan(snapshot, RecoveryFleet{OtherReadyHumanPrincipals: 1}, command); err == nil {
				t.Fatal("invalid lifecycle edge was planned")
			}
		})
	}

	snapshot := readySnapshot(StatusActive)
	snapshot.Revision = maximumPersistentRevision
	command := validCommandFor(ActionDisable, snapshot.Revision)
	if _, err := BuildPlan(snapshot, RecoveryFleet{OtherReadyHumanPrincipals: 1}, command); err == nil {
		t.Fatal("revision overflow was accepted")
	}
	snapshot = readySnapshot(StatusActive)
	snapshot.IdentityEpoch = maximumPersistentRevision
	command = validCommandFor(ActionDisable, snapshot.Revision)
	if _, err := BuildPlan(snapshot, RecoveryFleet{OtherReadyHumanPrincipals: 1}, command); err == nil {
		t.Fatal("identity epoch overflow was accepted")
	}
}

func TestReasonRejectsInvisibleFormatCharacters(t *testing.T) {
	snapshot := readySnapshot(StatusActive)
	command := validCommandFor(ActionRotatePassword, snapshot.Revision)
	command.Reason = "rotate\u200bpassword"
	if _, err := BuildPlan(snapshot, RecoveryFleet{}, command); err == nil {
		t.Fatal("format-control reason was accepted")
	}
}

func TestPlanFormattingRedactsReason(t *testing.T) {
	canary := "customer-sensitive-recovery-reason"
	snapshot := readySnapshot(StatusActive)
	command := validCommandFor(ActionDisable, snapshot.Revision)
	command.Reason = canary
	plan, err := BuildPlan(snapshot, RecoveryFleet{OtherReadyHumanPrincipals: 1}, command)
	if err != nil {
		t.Fatal(err)
	}
	if formatted := fmt.Sprintf("%#v", plan); strings.Contains(formatted, canary) {
		t.Fatalf("reason leaked: %s", formatted)
	}
	commandFormatted := fmt.Sprintf("%#v", command)
	if strings.Contains(commandFormatted, canary) {
		t.Fatalf("command reason leaked: %s", commandFormatted)
	}
}

func FuzzBuildPlanNeverAcceptsControlReasons(f *testing.F) {
	f.Add("security recovery", uint8(ActionRecover))
	f.Add("bad\nreason", uint8(ActionDisable))
	f.Fuzz(func(t *testing.T, reason string, rawAction uint8) {
		snapshot := readySnapshot(StatusActive)
		command := validCommandFor(Action(rawAction), snapshot.Revision)
		command.Reason = reason
		plan, err := BuildPlan(snapshot, RecoveryFleet{OtherReadyHumanPrincipals: 1}, command)
		if err != nil {
			return
		}
		for _, character := range reason {
			if character < 0x20 || character == 0x7f || unicode.In(character, unicode.Cf) {
				t.Fatalf("control reason accepted in %#v", plan)
			}
		}
	})
}

func readySnapshot(status Status) Snapshot {
	return Snapshot{
		AccountID: localID(1), UserID: localID(2), Revision: 4, IdentityEpoch: 6, Status: status,
		LoginIdentifier: LoginIdentifierVerified, Credential: CredentialActive,
		ConfirmedAcceptableFactors: 1,
	}
}

func validCommandFor(action Action, revision uint64) Command {
	return Command{
		Action: action, ExpectedRevision: revision, ActorID: localID(8), At: localTestNow,
		Reason: "protected identity workflow", FreshLocalMFA: true, ProtectedWorkflow: true,
	}
}

func localID(value byte) identity.EntityID {
	var id identity.EntityID
	id[15] = value
	return id
}
