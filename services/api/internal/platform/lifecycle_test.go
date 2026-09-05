package platform

import (
	"errors"
	"math"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

func TestPlanTenantLifecycleChangeBuildsClosedTransitions(t *testing.T) {
	tenantID := mustPlatformUUIDv7(t)
	tests := []struct {
		name     string
		current  TenantLifecycleStatus
		target   TenantLifecycleStatus
		action   TenantLifecycleAction
		expected int32
	}{
		{
			name: "suspend", current: TenantLifecycleActive,
			target: TenantLifecycleSuspended, action: TenantLifecycleSuspend, expected: 7,
		},
		{
			name: "reactivate", current: TenantLifecycleSuspended,
			target: TenantLifecycleActive, action: TenantLifecycleReactivate, expected: 13,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := PlanTenantLifecycleChange(
				tenantID, test.current, test.expected, test.expected, test.target,
				"Approved change request SEC-2048",
			)
			if err != nil {
				t.Fatalf("PlanTenantLifecycleChange() error = %v", err)
			}
			if plan.TenantID() != tenantID || plan.Action() != test.action ||
				plan.Previous() != test.current || plan.Next() != test.target ||
				plan.ExpectedVersion() != test.expected || plan.NextVersion() != test.expected+1 ||
				plan.Reason() != "Approved change request SEC-2048" {
				t.Fatalf("PlanTenantLifecycleChange() = %#v", plan)
			}
			if err := ValidateTenantLifecyclePlan(plan); err != nil {
				t.Fatalf("ValidateTenantLifecyclePlan() error = %v", err)
			}
		})
	}
}

func TestTenantLifecycleCommandIsCanonicalAndRedacted(t *testing.T) {
	tenantID := mustPlatformUUIDv7(t)
	reason := "customer-sensitive suspension reason"
	command, err := NewTenantLifecycleCommand(
		tenantID, TenantLifecycleSuspended, 17, reason,
	)
	if err != nil {
		t.Fatalf("NewTenantLifecycleCommand() error = %v", err)
	}
	if command.TenantID() != tenantID || command.Target() != TenantLifecycleSuspended ||
		command.ExpectedVersion() != 17 || command.Reason() != reason {
		t.Fatalf("NewTenantLifecycleCommand() = %#v", command)
	}
	if err := ValidateTenantLifecycleCommand(command); err != nil {
		t.Fatalf("ValidateTenantLifecycleCommand() error = %v", err)
	}
	for _, diagnostic := range []string{command.String(), command.GoString()} {
		if strings.Contains(diagnostic, tenantID.String()) || strings.Contains(diagnostic, reason) ||
			!strings.Contains(diagnostic, "[REDACTED]") {
			t.Fatalf("diagnostic was not redacted: %s", diagnostic)
		}
	}

	plan, err := PlanTenantLifecycleCommand(TenantLifecycleActive, 17, command)
	if err != nil || plan.TenantID() != tenantID || plan.NextVersion() != 18 {
		t.Fatalf("PlanTenantLifecycleCommand() = %#v, %v", plan, err)
	}
}

func TestValidateTenantLifecycleCommandRejectsTampering(t *testing.T) {
	command, err := NewTenantLifecycleCommand(
		mustPlatformUUIDv7(t), TenantLifecycleSuspended, 4, "Approved",
	)
	if err != nil {
		t.Fatalf("NewTenantLifecycleCommand() error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*TenantLifecycleCommand)
	}{
		{name: "tenant", mutate: func(value *TenantLifecycleCommand) { value.tenantID = uuid.Nil }},
		{name: "target", mutate: func(value *TenantLifecycleCommand) { value.target = "deleted" }},
		{name: "version", mutate: func(value *TenantLifecycleCommand) { value.expectedVersion = math.MaxInt32 }},
		{name: "reason", mutate: func(value *TenantLifecycleCommand) { value.reason += " " }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := command
			test.mutate(&candidate)
			if err := ValidateTenantLifecycleCommand(candidate); !errors.Is(err, ErrInvalidTenantLifecycle) {
				t.Fatalf("ValidateTenantLifecycleCommand() error = %v", err)
			}
		})
	}
}

func TestPlanTenantLifecycleChangeRejectsInvalidOrStaleCommands(t *testing.T) {
	tenantID := mustPlatformUUIDv7(t)
	v4 := uuid.New()
	tests := []struct {
		name            string
		tenantID        uuid.UUID
		current         TenantLifecycleStatus
		currentVersion  int32
		expectedVersion int32
		target          TenantLifecycleStatus
		reason          string
		want            error
	}{
		{name: "nil tenant", current: TenantLifecycleActive, currentVersion: 1, expectedVersion: 1, target: TenantLifecycleSuspended, reason: "change", want: ErrInvalidTenantLifecycle},
		{name: "uuid v4", tenantID: v4, current: TenantLifecycleActive, currentVersion: 1, expectedVersion: 1, target: TenantLifecycleSuspended, reason: "change", want: ErrInvalidTenantLifecycle},
		{name: "unknown current state", tenantID: tenantID, current: "pending", currentVersion: 1, expectedVersion: 1, target: TenantLifecycleSuspended, reason: "change", want: ErrInvalidTenantLifecycle},
		{name: "unknown target state", tenantID: tenantID, current: TenantLifecycleActive, currentVersion: 1, expectedVersion: 1, target: "deleted", reason: "change", want: ErrInvalidTenantLifecycle},
		{name: "zero current version", tenantID: tenantID, current: TenantLifecycleActive, expectedVersion: 1, target: TenantLifecycleSuspended, reason: "change", want: ErrInvalidTenantLifecycle},
		{name: "zero expected version", tenantID: tenantID, current: TenantLifecycleActive, currentVersion: 1, target: TenantLifecycleSuspended, reason: "change", want: ErrInvalidTenantLifecycle},
		{name: "stale expected version", tenantID: tenantID, current: TenantLifecycleActive, currentVersion: 2, expectedVersion: 1, target: TenantLifecycleSuspended, reason: "change", want: ErrTenantLifecycleConflict},
		{name: "active no change", tenantID: tenantID, current: TenantLifecycleActive, currentVersion: 1, expectedVersion: 1, target: TenantLifecycleActive, reason: "change", want: ErrTenantLifecycleNoChange},
		{name: "suspended no change", tenantID: tenantID, current: TenantLifecycleSuspended, currentVersion: 1, expectedVersion: 1, target: TenantLifecycleSuspended, reason: "change", want: ErrTenantLifecycleNoChange},
		{name: "version overflow", tenantID: tenantID, current: TenantLifecycleActive, currentVersion: math.MaxInt32, expectedVersion: math.MaxInt32, target: TenantLifecycleSuspended, reason: "change", want: ErrInvalidTenantLifecycle},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := PlanTenantLifecycleChange(
				test.tenantID, test.current, test.currentVersion, test.expectedVersion,
				test.target, test.reason,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("PlanTenantLifecycleChange() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestTenantLifecycleReasonIsCanonicalAndSafeForAudit(t *testing.T) {
	valid := []string{
		"Approved by SOC lead",
		strings.Repeat("a", maximumTenantLifecycleReasonBytes),
		"Motivo verificato — ticket SEC-2048",
	}
	for _, value := range valid {
		if !validTenantLifecycleReason(value) {
			t.Fatalf("validTenantLifecycleReason(%q) = false", value)
		}
	}

	invalidUTF8 := string([]byte{0xff})
	invalid := []string{
		"",
		" leading",
		"trailing ",
		"line\nbreak",
		"tab\tcharacter",
		"nul\x00character",
		"spoof\u202etext",
		"hidden\u200btext",
		"joined\u200dtext",
		strings.Repeat("a", maximumTenantLifecycleReasonBytes+1),
		invalidUTF8,
	}
	for _, value := range invalid {
		if validTenantLifecycleReason(value) {
			t.Fatalf("validTenantLifecycleReason(%q) = true", value)
		}
	}
}

func TestValidateTenantLifecyclePlanRejectsTampering(t *testing.T) {
	tenantID := mustPlatformUUIDv7(t)
	valid, err := PlanTenantLifecycleChange(
		tenantID, TenantLifecycleActive, 4, 4, TenantLifecycleSuspended, "Approved",
	)
	if err != nil {
		t.Fatalf("PlanTenantLifecycleChange() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*TenantLifecyclePlan)
	}{
		{name: "tenant", mutate: func(plan *TenantLifecyclePlan) { plan.tenantID = uuid.Nil }},
		{name: "action", mutate: func(plan *TenantLifecyclePlan) { plan.action = TenantLifecycleReactivate }},
		{name: "previous", mutate: func(plan *TenantLifecyclePlan) { plan.previous = TenantLifecycleSuspended }},
		{name: "next", mutate: func(plan *TenantLifecyclePlan) { plan.next = TenantLifecycleActive }},
		{name: "expected version", mutate: func(plan *TenantLifecyclePlan) { plan.expectedVersion++ }},
		{name: "next version", mutate: func(plan *TenantLifecyclePlan) { plan.nextVersion++ }},
		{name: "reason", mutate: func(plan *TenantLifecyclePlan) { plan.reason += " " }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if err := ValidateTenantLifecyclePlan(candidate); !errors.Is(err, ErrInvalidTenantLifecycle) {
				t.Fatalf("ValidateTenantLifecyclePlan() error = %v", err)
			}
		})
	}
}

func TestTenantLifecyclePlanDiagnosticsAreRedacted(t *testing.T) {
	tenantID := mustPlatformUUIDv7(t)
	reason := "customer-sensitive suspension reason"
	plan, err := PlanTenantLifecycleChange(
		tenantID, TenantLifecycleActive, 1, 1, TenantLifecycleSuspended, reason,
	)
	if err != nil {
		t.Fatalf("PlanTenantLifecycleChange() error = %v", err)
	}
	for _, diagnostic := range []string{plan.String(), plan.GoString()} {
		if strings.Contains(diagnostic, tenantID.String()) || strings.Contains(diagnostic, reason) ||
			!strings.Contains(diagnostic, "[REDACTED]") {
			t.Fatalf("diagnostic was not redacted: %s", diagnostic)
		}
	}
}

func FuzzTenantLifecycleReasonValidation(f *testing.F) {
	for _, seed := range []string{
		"Approved change",
		" leading",
		"line\nbreak",
		"spoof\u202etext",
		string([]byte{0xff}),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		if !validTenantLifecycleReason(value) {
			return
		}
		if value == "" || !utf8.ValidString(value) || len(value) > maximumTenantLifecycleReasonBytes ||
			strings.TrimSpace(value) != value {
			t.Fatalf("accepted non-canonical reason %q", value)
		}
		for _, character := range value {
			if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
				t.Fatalf("accepted unsafe reason %q", value)
			}
		}
	})
}

func mustPlatformUUIDv7(t *testing.T) uuid.UUID {
	t.Helper()
	identifier, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7() error = %v", err)
	}
	return identifier
}
