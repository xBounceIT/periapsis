package ticketing

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestTicketBulkProgressAccountsEveryResultCategoryExactly(t *testing.T) {
	progress, err := NewTicketBulkProgress(9)
	if err != nil {
		t.Fatalf("NewTicketBulkProgress() error = %v", err)
	}
	results := []TicketBulkTargetResult{
		TicketBulkTargetSucceeded,
		TicketBulkTargetNoChange,
		TicketBulkTargetVersionConflict,
		TicketBulkTargetNotFoundOrHidden,
		TicketBulkTargetAuthorizationDenied,
		TicketBulkTargetRejected,
		TicketBulkTargetCancelled,
		TicketBulkTargetAuthorizationRevoked,
		TicketBulkTargetInternalFailure,
	}
	for index, result := range results {
		progress, err = progress.WithResult(result)
		if err != nil {
			t.Fatalf("WithResult(%s) error = %v", result, err)
		}
		if progress.Processed() != uint32(index+1) || progress.Count(result) != 1 {
			t.Fatalf("progress after %s = %#v", result, progress.Snapshot())
		}
	}
	if !progress.Complete() || progress.Remaining() != 0 {
		t.Fatalf("complete progress = %#v", progress.Snapshot())
	}
	if _, err := progress.WithResult(TicketBulkTargetSucceeded); !errors.Is(err, ErrTicketBulkProgressFull) {
		t.Fatalf("WithResult() full error = %v", err)
	}
}

func TestTicketBulkProgressFinalizersAccountTheExactRemainder(t *testing.T) {
	for _, result := range []TicketBulkTargetResult{
		TicketBulkTargetCancelled,
		TicketBulkTargetAuthorizationRevoked,
		TicketBulkTargetInternalFailure,
	} {
		t.Run(result.String(), func(t *testing.T) {
			progress, _ := NewTicketBulkProgress(100_000)
			for index := 0; index < 3; index++ {
				progress, _ = progress.WithResult(TicketBulkTargetSucceeded)
			}
			progress, err := progress.WithRemainder(result)
			if err != nil {
				t.Fatalf("WithRemainder(%s) error = %v", result, err)
			}
			if !progress.Complete() || progress.Processed() != 100_000 ||
				progress.Count(TicketBulkTargetSucceeded) != 3 || progress.Count(result) != 99_997 {
				t.Fatalf("finalized progress = %#v", progress.Snapshot())
			}
		})
	}
}

func TestTicketBulkProgressRejectsInvalidSnapshotsAndResults(t *testing.T) {
	invalid := []TicketBulkProgressSnapshot{
		{},
		{Total: TicketBulkMaximumTargets + 1},
		{Total: 1, Succeeded: 2},
		{Total: math.MaxUint32, InternalFailure: math.MaxUint32},
		{Total: 2, Succeeded: math.MaxUint32, Rejected: math.MaxUint32},
	}
	for _, snapshot := range invalid {
		if _, err := RestoreTicketBulkProgress(snapshot); !errors.Is(err, ErrInvalidTicketBulkProgress) {
			t.Fatalf("RestoreTicketBulkProgress(%#v) error = %v", snapshot, err)
		}
	}

	progress, _ := NewTicketBulkProgress(2)
	for _, result := range []TicketBulkTargetResult{0, 255} {
		if _, err := progress.WithResult(result); !errors.Is(err, ErrInvalidTicketBulkProgress) {
			t.Fatalf("WithResult(%d) error = %v", result, err)
		}
	}
	for _, result := range []TicketBulkTargetResult{
		TicketBulkTargetSucceeded,
		TicketBulkTargetNoChange,
		TicketBulkTargetVersionConflict,
		TicketBulkTargetNotFoundOrHidden,
		TicketBulkTargetAuthorizationDenied,
		TicketBulkTargetRejected,
	} {
		if _, err := progress.WithRemainder(result); !errors.Is(err, ErrInvalidTicketBulkProgress) {
			t.Fatalf("WithRemainder(%s) error = %v", result, err)
		}
	}
}

func TestTicketBulkProgressWorkerAndControlCategoriesAreDisjoint(t *testing.T) {
	for result := TicketBulkTargetSucceeded; result <= TicketBulkTargetInternalFailure; result++ {
		worker := WorkerTicketBulkTargetResult(result)
		control := ticketBulkRemainderResult(result)
		if worker == control {
			t.Fatalf("result %s worker=%t control=%t", result, worker, control)
		}
	}
}

func TestTicketBulkProgressDiagnosticsDoNotExposeCategoryBreakdown(t *testing.T) {
	progress, _ := RestoreTicketBulkProgress(TicketBulkProgressSnapshot{
		Total: 10, AuthorizationDenied: 3, NotFoundOrHidden: 2,
	})
	for _, diagnostic := range []string{
		progress.String(), progress.GoString(), progress.Snapshot().String(), progress.Snapshot().GoString(),
	} {
		if !strings.Contains(diagnostic, "[REDACTED]") || strings.Contains(diagnostic, "authorization_denied") {
			t.Fatalf("diagnostic was not redacted: %s", diagnostic)
		}
	}
}

func FuzzRestoreTicketBulkProgressNeverAcceptsOverflow(f *testing.F) {
	f.Add(uint32(1), uint32(0), uint32(0))
	f.Add(uint32(10), uint32(5), uint32(5))
	f.Add(uint32(1), uint32(math.MaxUint32), uint32(math.MaxUint32))
	f.Fuzz(func(t *testing.T, total, succeeded, rejected uint32) {
		progress, err := RestoreTicketBulkProgress(TicketBulkProgressSnapshot{
			Total: total, Succeeded: succeeded, Rejected: rejected,
		})
		if err != nil {
			return
		}
		if progress.Total() == 0 || progress.Total() > TicketBulkMaximumTargets ||
			progress.Processed() > progress.Total() {
			t.Fatalf("accepted invalid progress %#v", progress.Snapshot())
		}
	})
}
