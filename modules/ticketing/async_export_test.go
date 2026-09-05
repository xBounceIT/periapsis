package ticketing

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTicketExportDefinitionEnforcesAudienceAndBounds(t *testing.T) {
	base := ticketExportDefinitionFixture(t, TicketExportAudienceOperator)
	viewDigest := base.QueryDigest
	view, err := NewTicketExportSavedViewPin(fixtureID(20), base.OwnerMembership, 4, viewDigest)
	if err != nil {
		t.Fatal(err)
	}
	base.QuerySource, base.SavedView = TicketExportQuerySavedView, &view
	if _, err := NewTicketExportDefinition(base); err != nil {
		t.Fatalf("valid operator saved-view definition: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*TicketExportDefinitionInput)
	}{
		{name: "operator contact", mutate: func(input *TicketExportDefinitionInput) { input.CustomerContact = entityPointer(fixtureID(21)) }},
		{name: "foreign saved view owner", mutate: func(input *TicketExportDefinitionInput) {
			pin, _ := NewTicketExportSavedViewPin(fixtureID(20), fixtureID(22), 4, input.QueryDigest)
			input.SavedView = &pin
		}},
		{name: "saved view digest drift", mutate: func(input *TicketExportDefinitionInput) {
			pin, _ := NewTicketExportSavedViewPin(fixtureID(20), input.OwnerMembership, 4, [32]byte{9})
			input.SavedView = &pin
		}},
		{name: "unbounded rows", mutate: func(input *TicketExportDefinitionInput) { input.MaximumRows = TicketExportOperatorMaximumRows + 1 }},
		{name: "unbounded bytes", mutate: func(input *TicketExportDefinitionInput) { input.MaximumBytes = TicketExportOperatorMaximumBytes + 1 }},
		{name: "zero catalog pin", mutate: func(input *TicketExportDefinitionInput) { input.CatalogDigest = [32]byte{} }},
		{name: "unknown projection", mutate: func(input *TicketExportDefinitionInput) { input.ProjectionVersion++ }},
		{name: "unknown format", mutate: func(input *TicketExportDefinitionInput) { input.Format++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			test.mutate(&input)
			if _, err := NewTicketExportDefinition(input); !errors.Is(err, ErrInvalidTicketExport) {
				t.Fatalf("NewTicketExportDefinition() error = %v", err)
			}
		})
	}

	customer := ticketExportDefinitionFixture(t, TicketExportAudienceCustomer)
	if _, err := NewTicketExportDefinition(customer); err != nil {
		t.Fatalf("valid customer definition: %v", err)
	}
	for _, mutate := range []func(*TicketExportDefinitionInput){
		func(input *TicketExportDefinitionInput) { input.CustomerContact = nil },
		func(input *TicketExportDefinitionInput) { input.Comments = TicketExportCommentsPublicAndPrivate },
		func(input *TicketExportDefinitionInput) { input.MaximumRows = TicketExportCustomerMaximumRows + 1 },
		func(input *TicketExportDefinitionInput) { input.MaximumBytes = TicketExportCustomerMaximumBytes + 1 },
		func(input *TicketExportDefinitionInput) {
			pin, _ := NewTicketExportSavedViewPin(fixtureID(23), input.OwnerMembership, 1, input.QueryDigest)
			input.QuerySource, input.SavedView = TicketExportQuerySavedView, &pin
		},
	} {
		input := customer
		mutate(&input)
		if _, err := NewTicketExportDefinition(input); !errors.Is(err, ErrInvalidTicketExport) {
			t.Fatalf("unsafe customer definition error = %v", err)
		}
	}
}

func TestTicketExportLifecycleUsesCASAndClaimFencing(t *testing.T) {
	now := ticketExportInstant()
	definition := mustTicketExportDefinition(t, TicketExportAudienceOperator)
	created, err := PlanTicketExportCreation(definition, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	job := created.Next()
	if job.State() != TicketExportPending || job.Revision() != 1 || job.Attempts() != 0 {
		t.Fatalf("created job = %s", job)
	}

	worker, fence := fixtureID(30), [32]byte{1, 2, 3}
	claimed, err := PlanTicketExportClaim(job, worker, fence, now, now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	running := claimed.Next()
	if running.State() != TicketExportRunning || running.Revision() != 2 || running.Attempts() != 1 {
		t.Fatalf("claimed job = %s", running)
	}
	staleFence := fence
	staleFence[0]++
	artifact, _ := NewTicketExportArtifact(fixtureID(31), [32]byte{8}, 10, 1_024, now.Add(12*time.Hour))
	if _, err := PlanTicketExportSuccess(running, worker, staleFence, artifact, now.Add(time.Minute)); !errors.Is(err, ErrTicketExportFenceMismatch) {
		t.Fatalf("stale fence success error = %v", err)
	}
	if _, err := PlanTicketExportCancellation(running, running.Revision()-1, now.Add(time.Minute)); !errors.Is(err, ErrTicketExportConflict) {
		t.Fatalf("stale cancellation CAS error = %v", err)
	}

	cancelPlan, err := PlanTicketExportCancellation(running, running.Revision(), now.Add(time.Minute))
	if err != nil || cancelPlan.Next().State() != TicketExportCancellationRequested {
		t.Fatalf("request cancellation = (%s, %v)", cancelPlan.Next(), err)
	}
	if _, err := PlanTicketExportSuccess(cancelPlan.Next(), worker, fence, artifact, now.Add(2*time.Minute)); !errors.Is(err, ErrTicketExportCancelled) {
		t.Fatalf("success after cancellation error = %v", err)
	}
	if _, err := PlanTicketExportCancellationAcknowledgement(
		cancelPlan.Next(), worker, fence, running.Lease().ExpiresAt(),
	); !errors.Is(err, ErrTicketExportFenceMismatch) {
		t.Fatalf("expired-fence acknowledgement error = %v", err)
	}
	ack, err := PlanTicketExportCancellationAcknowledgement(
		cancelPlan.Next(), worker, fence, now.Add(2*time.Minute),
	)
	if err != nil || ack.Next().State() != TicketExportCancelledState || ack.Next().Lease() != nil {
		t.Fatalf("cancellation acknowledgement = (%s, %v)", ack.Next(), err)
	}
	if _, err := PlanTicketExportCancellation(ack.Next(), ack.Next().Revision(), now.Add(3*time.Minute)); !errors.Is(err, ErrTicketExportTerminal) {
		t.Fatalf("terminal cancellation error = %v", err)
	}
}

func TestTicketExportRetryReclaimAndAttemptCeiling(t *testing.T) {
	now := ticketExportInstant()
	definition := mustTicketExportDefinition(t, TicketExportAudienceOperator)
	created, _ := PlanTicketExportCreation(definition, now, now.Add(24*time.Hour))
	job := created.Next()
	worker, fence := fixtureID(40), [32]byte{1}
	claimed, _ := PlanTicketExportClaim(job, worker, fence, now, now.Add(time.Minute))
	retryAt := now.Add(2 * time.Minute)
	tooSoon := now.Add(30*time.Second + time.Microsecond)
	if _, err := PlanTicketExportFailure(
		claimed.Next(), worker, fence, TicketExportFailureTransientStorage,
		&tooSoon, now.Add(30*time.Second),
	); !errors.Is(err, ErrInvalidTicketExport) {
		t.Fatalf("sub-second retry error = %v", err)
	}
	for _, code := range []TicketExportFailureCode{
		TicketExportFailureAuthorizationRevoked,
		TicketExportFailureLeaseExpired,
		TicketExportFailureExpired,
	} {
		if _, err := PlanTicketExportFailure(
			claimed.Next(), worker, fence, code, nil, now.Add(30*time.Second),
		); !errors.Is(err, ErrInvalidTicketExport) {
			t.Fatalf("worker-only failure %s error = %v", code, err)
		}
	}
	if _, err := PlanTicketExportFailure(
		claimed.Next(), worker, fence, TicketExportFailureOutputLimit,
		&retryAt, now.Add(30*time.Second),
	); !errors.Is(err, ErrInvalidTicketExport) {
		t.Fatalf("non-retryable output limit error = %v", err)
	}
	retry, err := PlanTicketExportFailure(
		claimed.Next(), worker, fence, TicketExportFailureTransientStorage, &retryAt, now.Add(30*time.Second),
	)
	if err != nil || retry.Action() != TicketExportRetry || retry.Next().State() != TicketExportPending {
		t.Fatalf("retry plan = (%s, %v)", retry, err)
	}
	cancelledRetry, err := PlanTicketExportCancellation(
		retry.Next(), retry.Next().Revision(), now.Add(time.Minute),
	)
	if err != nil || cancelledRetry.Next().State() != TicketExportCancelledState ||
		cancelledRetry.Next().FailureCode() != TicketExportFailureNone {
		t.Fatalf("retry cancellation = (%s, %v)", cancelledRetry.Next(), err)
	}
	if _, err := PlanTicketExportClaim(
		retry.Next(), worker, [32]byte{2}, retryAt.Add(-time.Microsecond), retryAt.Add(time.Minute),
	); !errors.Is(err, ErrTicketExportNotClaimable) {
		t.Fatalf("early retry claim error = %v", err)
	}

	job = retry.Next()
	for attempt := uint8(2); attempt <= definition.MaximumAttempts(); attempt++ {
		claimTime := job.AvailableAt()
		newFence := [32]byte{attempt}
		claim, claimErr := PlanTicketExportClaim(job, worker, newFence, claimTime, claimTime.Add(time.Minute))
		if claimErr != nil {
			t.Fatalf("attempt %d claim: %v", attempt, claimErr)
		}
		if attempt == definition.MaximumAttempts() {
			lateRetry := claimTime.Add(2 * time.Minute)
			failed, failureErr := PlanTicketExportFailure(
				claim.Next(), worker, newFence, TicketExportFailureTransientDatabase,
				&lateRetry, claimTime.Add(30*time.Second),
			)
			if failureErr != nil || failed.Action() != TicketExportFail || failed.Next().State() != TicketExportFailed {
				t.Fatalf("terminal attempt = (%s, %v)", failed, failureErr)
			}
			job = failed.Next()
			break
		}
		nextRetry := claimTime.Add(2 * time.Minute)
		failed, failureErr := PlanTicketExportFailure(
			claim.Next(), worker, newFence, TicketExportFailureTransientDatabase,
			&nextRetry, claimTime.Add(30*time.Second),
		)
		if failureErr != nil {
			t.Fatal(failureErr)
		}
		job = failed.Next()
	}
	if job.Attempts() != definition.MaximumAttempts() || job.State() != TicketExportFailed {
		t.Fatalf("attempt ceiling job = %s", job)
	}

	created, _ = PlanTicketExportCreation(definition, now, now.Add(24*time.Hour))
	first, _ := PlanTicketExportClaim(created.Next(), worker, [32]byte{10}, now, now.Add(time.Minute))
	reclaimed, err := PlanTicketExportClaim(
		first.Next(), worker, [32]byte{11}, now.Add(time.Minute), now.Add(2*time.Minute),
	)
	if err != nil || reclaimed.Next().Attempts() != 2 || reclaimed.Next().Lease().Fence() == first.Next().Lease().Fence() {
		t.Fatalf("expired lease reclaim = (%s, %v)", reclaimed.Next(), err)
	}
	if _, err := PlanTicketExportFailure(
		reclaimed.Next(), worker, first.Next().Lease().Fence(), TicketExportFailureInternal,
		nil, now.Add(90*time.Second),
	); !errors.Is(err, ErrTicketExportFenceMismatch) {
		t.Fatalf("superseded fence failure error = %v", err)
	}
	if _, err := PlanTicketExportClaim(
		first.Next(), worker, first.Next().Lease().Fence(),
		now.Add(time.Minute), now.Add(2*time.Minute),
	); !errors.Is(err, ErrInvalidTicketExport) {
		t.Fatalf("reused claim fence error = %v", err)
	}

	released, err := PlanTicketExportLeaseExpiry(first.Next(), now.Add(time.Minute))
	if err != nil || released.Next().State() != TicketExportPending ||
		released.Next().FailureCode() != TicketExportFailureLeaseExpired {
		t.Fatalf("expired lease release = (%s, %v)", released.Next(), err)
	}
	ceilingInput := ticketExportDefinitionFixture(t, TicketExportAudienceOperator)
	ceilingInput.MaximumAttempts = 1
	ceiling, _ := NewTicketExportDefinition(ceilingInput)
	ceilingCreated, _ := PlanTicketExportCreation(ceiling, now, now.Add(time.Hour))
	ceilingClaim, _ := PlanTicketExportClaim(
		ceilingCreated.Next(), worker, [32]byte{12}, now, now.Add(time.Minute),
	)
	terminal, err := PlanTicketExportLeaseExpiry(ceilingClaim.Next(), now.Add(time.Minute))
	if err != nil || terminal.Next().State() != TicketExportFailed ||
		terminal.Next().FailureCode() != TicketExportFailureLeaseExpired {
		t.Fatalf("attempt-ceiling lease expiry = (%s, %v)", terminal.Next(), err)
	}
}

func TestTicketExportArtifactBoundsExpiryAndDefensiveCopies(t *testing.T) {
	now := ticketExportInstant()
	definition := mustTicketExportDefinition(t, TicketExportAudienceCustomer)
	created, _ := PlanTicketExportCreation(definition, now, now.Add(24*time.Hour))
	job := created.Next()
	contact := job.Definition().CustomerContact()
	*contact = fixtureID(99)
	if *job.Definition().CustomerContact() == *contact {
		t.Fatal("customer contact getter leaked mutable job storage")
	}
	snapshot := job.Snapshot()
	restored, err := RestoreTicketExportJob(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	*snapshot.Definition.customerContact = fixtureID(98)
	if *restored.Definition().CustomerContact() == *snapshot.Definition.customerContact {
		t.Fatal("restore retained mutable definition storage")
	}

	worker, fence := fixtureID(50), [32]byte{5}
	claim, _ := PlanTicketExportClaim(job, worker, fence, now, now.Add(5*time.Minute))
	tooLarge, _ := NewTicketExportArtifact(
		fixtureID(51), [32]byte{6}, definition.MaximumRows()+1, 100, now.Add(time.Hour),
	)
	if _, err := PlanTicketExportSuccess(claim.Next(), worker, fence, tooLarge, now.Add(time.Minute)); !errors.Is(err, ErrInvalidTicketExport) {
		t.Fatalf("oversized artifact error = %v", err)
	}
	shortLived, _ := NewTicketExportArtifact(
		fixtureID(53), [32]byte{6}, 1, 100, now.Add(time.Hour),
	)
	if _, err := PlanTicketExportSuccess(claim.Next(), worker, fence, shortLived, now.Add(time.Minute)); !errors.Is(err, ErrInvalidTicketExport) {
		t.Fatalf("artifact retention drift error = %v", err)
	}
	valid, _ := NewTicketExportArtifact(
		fixtureID(52), [32]byte{7}, definition.MaximumRows(), definition.MaximumBytes(), now.Add(24*time.Hour),
	)
	succeeded, err := PlanTicketExportSuccess(claim.Next(), worker, fence, valid, now.Add(time.Minute))
	if err != nil || succeeded.Next().State() != TicketExportSucceeded {
		t.Fatalf("bounded success = (%s, %v)", succeeded.Next(), err)
	}
	artifact := succeeded.Next().Artifact()
	*artifact = TicketExportArtifact{}
	if succeeded.Next().Artifact().ID() != valid.ID() {
		t.Fatal("artifact getter leaked mutable job storage")
	}

	created, _ = PlanTicketExportCreation(definition, now, now.Add(TicketExportMinimumRetention))
	expired, err := PlanTicketExportExpiry(created.Next(), now.Add(TicketExportMinimumRetention))
	if err != nil || expired.Next().State() != TicketExportFailed ||
		expired.Next().FailureCode() != TicketExportFailureExpired {
		t.Fatalf("expiry = (%s, %v)", expired.Next(), err)
	}
}

func TestTicketExportAuthorizationRevocationIsTerminalWithoutDataAuthority(t *testing.T) {
	now := ticketExportInstant()
	definition := mustTicketExportDefinition(t, TicketExportAudienceCustomer)
	created, _ := PlanTicketExportCreation(definition, now, now.Add(time.Hour))
	revoked, err := PlanTicketExportAuthorizationRevocation(created.Next(), now.Add(time.Minute))
	if err != nil || revoked.Next().State() != TicketExportFailed ||
		revoked.Next().FailureCode() != TicketExportFailureAuthorizationRevoked ||
		revoked.Next().Attempts() != 0 || revoked.Next().Lease() != nil || revoked.Next().Artifact() != nil {
		t.Fatalf("pending revocation = (%s, %v)", revoked.Next(), err)
	}
	if _, err := PlanTicketExportAuthorizationRevocation(revoked.Next(), now.Add(2*time.Minute)); !errors.Is(err, ErrTicketExportTerminal) {
		t.Fatalf("terminal revocation error = %v", err)
	}
}

func TestRestoreTicketExportJobRejectsImpossiblePersistenceShapes(t *testing.T) {
	now := ticketExportInstant()
	definition := mustTicketExportDefinition(t, TicketExportAudienceOperator)
	created, _ := PlanTicketExportCreation(definition, now, now.Add(time.Hour))
	initial := created.Next().Snapshot()
	worker, fence := fixtureID(55), [32]byte{5}
	lease, _ := NewTicketExportLease(worker, fence, now, now.Add(time.Minute))
	terminal := now.Add(time.Minute)

	tests := []struct {
		name     string
		snapshot TicketExportJobSnapshot
	}{
		{
			name: "initial revision drift",
			snapshot: func() TicketExportJobSnapshot {
				value := initial
				value.Revision = 2
				return value
			}(),
		},
		{
			name: "claim precedes availability",
			snapshot: TicketExportJobSnapshot{
				Definition: definition, State: TicketExportRunning, Revision: 2, Attempts: 1,
				RequestedAt: now, UpdatedAt: now, AvailableAt: now.Add(time.Minute),
				ExpiresAt: now.Add(time.Hour), Lease: &lease,
			},
		},
		{
			name: "terminal timestamp differs from update",
			snapshot: TicketExportJobSnapshot{
				Definition: definition, State: TicketExportFailed, Revision: 3, Attempts: 1,
				FailureCode: TicketExportFailureInternal, RequestedAt: now,
				UpdatedAt: terminal.Add(time.Minute), AvailableAt: now, ExpiresAt: now.Add(time.Hour),
				TerminalAt: &terminal,
			},
		},
		{
			name: "running update after lease expiry",
			snapshot: TicketExportJobSnapshot{
				Definition: definition, State: TicketExportRunning, Revision: 2, Attempts: 1,
				RequestedAt: now, UpdatedAt: now.Add(2 * time.Minute), AvailableAt: now,
				ExpiresAt: now.Add(time.Hour), Lease: &lease,
			},
		},
		{
			name: "pending retry available before update",
			snapshot: TicketExportJobSnapshot{
				Definition: definition, State: TicketExportPending, Revision: 3, Attempts: 1,
				FailureCode: TicketExportFailureTransientDatabase, RequestedAt: now,
				UpdatedAt: now.Add(2 * time.Minute), AvailableAt: now.Add(time.Minute),
				ExpiresAt: now.Add(time.Hour),
			},
		},
		{
			name: "expired before retention deadline",
			snapshot: TicketExportJobSnapshot{
				Definition: definition, State: TicketExportFailed, Revision: 2,
				FailureCode: TicketExportFailureExpired, RequestedAt: now,
				UpdatedAt: terminal, AvailableAt: now, ExpiresAt: now.Add(time.Hour),
				TerminalAt: &terminal,
			},
		},
		{
			name: "lease expiry below attempt ceiling",
			snapshot: TicketExportJobSnapshot{
				Definition: definition, State: TicketExportFailed, Revision: 3, Attempts: 1,
				FailureCode: TicketExportFailureLeaseExpired, RequestedAt: now,
				UpdatedAt: terminal, AvailableAt: now, ExpiresAt: now.Add(time.Hour),
				TerminalAt: &terminal,
			},
		},
		{
			name: "revocation at retention deadline",
			snapshot: func() TicketExportJobSnapshot {
				expires := now.Add(time.Hour)
				return TicketExportJobSnapshot{
					Definition: definition, State: TicketExportFailed, Revision: 2,
					FailureCode: TicketExportFailureAuthorizationRevoked, RequestedAt: now,
					UpdatedAt: expires, AvailableAt: now, ExpiresAt: expires, TerminalAt: &expires,
				}
			}(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := RestoreTicketExportJob(test.snapshot); !errors.Is(err, ErrInvalidTicketExport) {
				t.Fatalf("RestoreTicketExportJob() error = %v", err)
			}
		})
	}
}

func TestTicketExportDiagnosticsAreRedacted(t *testing.T) {
	input := ticketExportDefinitionFixture(t, TicketExportAudienceCustomer)
	definition, _ := NewTicketExportDefinition(input)
	now := ticketExportInstant()
	plan, _ := PlanTicketExportCreation(definition, now, now.Add(time.Hour))
	lease, _ := NewTicketExportLease(fixtureID(60), [32]byte{9}, now, now.Add(time.Minute))
	artifact, _ := NewTicketExportArtifact(fixtureID(61), [32]byte{8}, 1, 10, now.Add(time.Hour))
	fence := lease.Fence()
	for _, rendered := range []string{
		fmt.Sprintf("%#v", input), fmt.Sprintf("%#v", definition), fmt.Sprintf("%#v", plan.Next()),
		fmt.Sprintf("%#v", plan), fmt.Sprintf("%#v", lease), fmt.Sprintf("%#v", artifact),
	} {
		for _, secret := range []string{
			input.ID.String(), input.Tenant.String(), input.Requester.String(),
			fmt.Sprintf("%x", input.QueryDigest[:]), fmt.Sprintf("%x", fence[:]),
		} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("diagnostic leaked %q: %s", secret, rendered)
			}
		}
	}
}

func FuzzRestoreTicketExportJobFailsClosed(f *testing.F) {
	f.Add(uint8(TicketExportPending), uint64(1), uint8(0), int64(0))
	f.Add(uint8(TicketExportRunning), uint64(2), uint8(1), int64(60))
	f.Fuzz(func(t *testing.T, rawState uint8, revision uint64, attempts uint8, offsetSeconds int64) {
		now := ticketExportInstant()
		definition := mustTicketExportDefinition(t, TicketExportAudienceOperator)
		snapshot := TicketExportJobSnapshot{
			Definition: definition, State: TicketExportState(rawState), Revision: revision,
			Attempts: attempts, RequestedAt: now, UpdatedAt: now,
			AvailableAt: now.Add(time.Duration(offsetSeconds) * time.Second), ExpiresAt: now.Add(time.Hour),
		}
		job, err := RestoreTicketExportJob(snapshot)
		if err == nil && ValidateTicketExportJob(job) != nil {
			t.Fatalf("restored invalid job: %s", job)
		}
	})
}

func ticketExportDefinitionFixture(t testing.TB, audience TicketExportAudience) TicketExportDefinitionInput {
	t.Helper()
	input := TicketExportDefinitionInput{
		ID: fixtureID(10), Tenant: fixtureID(1), Requester: fixtureID(2), OwnerMembership: fixtureID(3),
		Kind: AggregateAlert, Audience: audience, Comments: TicketExportCommentsPublic,
		QuerySource: TicketExportQueryInline, QueryDigest: [32]byte{1}, CatalogDigest: [32]byte{2},
		ProjectionVersion: TicketExportProjectionVersion, Format: TicketExportCSV,
		MaximumRows: 1_000, MaximumBytes: 1024 * 1024, MaximumAttempts: TicketExportMaximumAttempts,
	}
	if audience == TicketExportAudienceCustomer {
		input.CustomerContact = entityPointer(fixtureID(4))
	}
	return input
}

func mustTicketExportDefinition(t testing.TB, audience TicketExportAudience) TicketExportDefinition {
	t.Helper()
	definition, err := NewTicketExportDefinition(ticketExportDefinitionFixture(t, audience))
	if err != nil {
		t.Fatal(err)
	}
	return definition
}

func ticketExportInstant() time.Time {
	return time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
}

func entityPointer(value EntityID) *EntityID { return &value }
